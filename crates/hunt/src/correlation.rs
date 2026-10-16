//! Correlation rules: detections that span multiple events and need
//! aggregation or sequencing that a single-event matcher can't express.
//!
//! These are the signals that make the tool worth more than a Sigma runner over
//! a timeline: mass-rename ransomware bursts, silent background exfil, RDP
//! logon immediately followed by tooling drop. Each is expressed as one of a
//! few correlation *primitives* rather than free-form SQL, so rules stay
//! declarative, reviewable, and safe (no rule can run arbitrary SQL against the
//! case).
//!
//! Each primitive compiles to a parameterized query over the `events` table and
//! yields [`fx_core::Detection`]s with the contributing event ids attached.

use fx_core::{Detection, DetectionEngine, Severity};
use serde::{Deserialize, Serialize};

/// A correlation rule: metadata plus one correlation primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub attack: Vec<String>,
    pub correlation: Correlation,
}

/// The correlation primitives. Deliberately small; each maps to one query
/// shape. Adding a primitive is a considered change, not a config tweak.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Correlation {
    /// Fire when the count of events matching `action_prefix` within a sliding
    /// window of `window_seconds`, grouped by `group_by`, meets `threshold`.
    /// The archetype: N file renames/deletes in M seconds -> ransomware.
    ThresholdWindow {
        action_prefix: String,
        #[serde(default)]
        artefact: Option<String>,
        window_seconds: i64,
        threshold: i64,
        /// Column to group the burst by (e.g. "host"). Empty = whole case.
        #[serde(default)]
        group_by: Option<String>,
    },

    /// Fire when two event classes for the same `join_key` occur within
    /// `within_seconds` of each other, in order (`first` then `second`). The
    /// archetype: RDP logon (first) then a staging/tooling event (second) on
    /// the same host -> hands-on-keyboard lateral movement.
    Sequence {
        first_action_prefix: String,
        second_action_prefix: String,
        within_seconds: i64,
        /// Column both events must share (e.g. "host").
        join_key: String,
    },

    /// Fire on raw-JSON numeric aggregation crossing a threshold — used for the
    /// SRUM silent-exfil signal where the quantity (bytes) lives in `raw`.
    /// Sums `json_field` over rows matching `action_prefix`, grouped by
    /// `group_by`, and fires when the sum exceeds `min_total`.
    RawSumThreshold {
        action_prefix: String,
        json_field: String,
        min_total: i64,
        group_by: String,
    },
}

impl Correlation {
    /// Compile to (sql, description-of-grouping). The SQL must SELECT, in order:
    /// a grouping label, the earliest contributing timestamp, a
    /// comma-separated list of event ids, and a numeric magnitude.
    pub(crate) fn to_sql(&self) -> String {
        match self {
            Correlation::ThresholdWindow {
                action_prefix,
                artefact,
                window_seconds,
                threshold,
                group_by,
            } => {
                let art = artefact
                    .as_ref()
                    .map(|a| format!("AND artefact = '{}'", esc(a)))
                    .unwrap_or_default();
                let grp = group_by.as_deref().filter(|s| !s.is_empty()).map(ident);
                let grp_expr = grp.clone().unwrap_or_else(|| "'*'".to_string());

                // Count, for each matching event, how many matching events in
                // the same group fall within [ts, ts+window]. A RANGE window
                // frame over epoch seconds does this in one pass, no self-join.
                // Then keep windows that reach the threshold and collapse each
                // group to its worst (largest) burst.
                // The window runs in the `windowed` CTE over `matched`, where
                // the group column is already aliased to `grp` — so partition
                // by `grp`, never the original column/expression.
                let partition = if grp.is_some() {
                    "PARTITION BY grp ".to_string()
                } else {
                    String::new()
                };
                // Evidence-id cap. A real mass-rename burst (the exact thing
                // this rule exists to catch) can be hundreds of thousands of
                // events in ONE host group. STRING_AGG over all of them builds a
                // multi-megabyte id string per group, which DuckDB materialises
                // and then Rust splits back into UUIDs — on a big single-host
                // USN journal this looked like a hang. We keep the true burst
                // size as `magnitude` (COUNT, cheap) but only carry a bounded
                // sample of contributing ids as evidence. A few hundred ids is
                // far more than an analyst pivots through; the count tells the
                // real story. `ranked` numbers rows within each qualifying group
                // so the cap is applied in SQL, before any big string is built.
                const ID_SAMPLE_CAP: usize = 500;
                format!(
                    "WITH matched AS (
                        SELECT id, ts, {grp_expr} AS grp,
                               epoch(ts)::BIGINT AS es
                        FROM events
                        WHERE action LIKE '{prefix}%' {art}
                     ),
                     windowed AS (
                        SELECT id, ts, grp,
                               COUNT(*) OVER (
                                 {partition}ORDER BY es
                                 RANGE BETWEEN CURRENT ROW AND {window} FOLLOWING
                               ) AS burst
                        FROM matched
                     ),
                     qualifying AS (
                        SELECT grp, id, ts,
                               MAX(burst) OVER (PARTITION BY grp) AS grp_peak,
                               ROW_NUMBER() OVER (PARTITION BY grp ORDER BY ts) AS rn
                        FROM windowed
                        WHERE burst >= {threshold}
                     )
                     SELECT grp,
                            strftime(MIN(ts), '%Y-%m-%dT%H:%M:%S') AS first_ts,
                            STRING_AGG(CASE WHEN rn <= {cap} THEN id END, ',') AS ids,
                            MAX(grp_peak) AS magnitude
                     FROM qualifying
                     GROUP BY grp",
                    grp_expr = grp_expr,
                    prefix = esc(action_prefix),
                    art = art,
                    partition = partition,
                    window = window_seconds,
                    threshold = threshold,
                    cap = ID_SAMPLE_CAP,
                )
            }

            Correlation::Sequence {
                first_action_prefix,
                second_action_prefix,
                within_seconds,
                join_key,
            } => format!(
                // Pre-filter BOTH sides to the matching actions FIRST, in CTEs, so
                // the join runs on two small sets (the handful of logon / tooling
                // events) instead of self-joining the whole events table. A naive
                // `FROM events a JOIN events b` with the action filters in the
                // ON/WHERE is effectively O(n^2) on a single-host case with
                // millions of rows — it was taking 30+ minutes. With the subsets
                // pre-selected this is a small range join. We keep only the first
                // matching second-event per first-event (MIN(b.id)) so one logon
                // can't fan out into thousands of pairs.
                "WITH first_ev AS (
                     SELECT id, {key} AS k, ts FROM events WHERE action LIKE '{first}%'
                 ),
                 second_ev AS (
                     SELECT id, {key} AS k, ts FROM events WHERE action LIKE '{second}%'
                 )
                 SELECT
                     a.k AS grp,
                     strftime(a.ts, '%Y-%m-%dT%H:%M:%S') AS first_ts,
                     a.id || ',' || MIN(b.id) AS ids,
                     1 AS magnitude
                 FROM first_ev a
                 JOIN second_ev b
                   ON a.k = b.k
                  AND b.ts BETWEEN a.ts AND a.ts + INTERVAL '{within} seconds'
                 GROUP BY a.k, a.ts, a.id",
                key = ident(join_key),
                first = esc(first_action_prefix),
                second = esc(second_action_prefix),
                within = within_seconds,
            ),

            Correlation::RawSumThreshold {
                action_prefix,
                json_field,
                min_total,
                group_by,
            } => {
                // Same evidence-id cap as threshold_window: bound the sampled
                // ids per group so a group with very many contributing rows
                // can't build an unbounded id string. The real magnitude is the
                // SUM, which is unaffected. `ranked` numbers rows per group so
                // the cap is applied in SQL.
                const ID_SAMPLE_CAP: usize = 500;
                format!(
                    "WITH matched AS (
                        SELECT id, ts, {grp} AS grp,
                               CAST(json_extract(raw, '$.{field}') AS BIGINT) AS val
                        FROM events
                        WHERE action LIKE '{prefix}%'
                     ),
                     ranked AS (
                        SELECT grp, id, ts, val,
                               ROW_NUMBER() OVER (PARTITION BY grp ORDER BY ts) AS rn
                        FROM matched
                     )
                     SELECT grp,
                            strftime(MIN(ts), '%Y-%m-%dT%H:%M:%S') AS first_ts,
                            STRING_AGG(CASE WHEN rn <= {cap} THEN id END, ',') AS ids,
                            SUM(val) AS magnitude
                     FROM ranked
                     GROUP BY grp
                     HAVING SUM(val) >= {min}",
                    grp = grouping_expr(group_by),
                    field = esc(json_field),
                    prefix = esc(action_prefix),
                    min = min_total,
                    cap = ID_SAMPLE_CAP,
                )
            }
        }
    }
}

/// Build a Detection from a correlation row. `magnitude` lets the summary be
/// specific ("312 files renamed", "4.5 GB sent").
pub(crate) fn detection_from_row(
    rule: &CorrelationRule,
    grp: &str,
    first_ts: time::OffsetDateTime,
    event_ids: Vec<uuid::Uuid>,
    magnitude: i64,
) -> Detection {
    let summary = match &rule.correlation {
        Correlation::ThresholdWindow { .. } => {
            format!("{} events in a tight window (group: {grp})", magnitude)
        }
        Correlation::Sequence { .. } => {
            format!("sequential activity correlated on {grp}")
        }
        Correlation::RawSumThreshold { .. } => {
            format!("aggregate {} over group {grp}", human_bytes(magnitude))
        }
    };
    Detection {
        id: uuid::Uuid::new_v4(),
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity,
        attack: rule.attack.clone(),
        summary: format!("{}: {}", rule.title, summary),
        event_ids,
        timestamp: first_ts,
        host: if grp == "*" { None } else { Some(grp.to_string()) },
        engine: DetectionEngine::Correlation,
    }
}

fn human_bytes(n: i64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[i])
    }
}

/// A grouping expression: a column name, or a constant when whole-case.
fn grouping_expr(col: &str) -> String {
    if col.is_empty() {
        "'*'".into()
    } else {
        ident(col)
    }
}

/// Whitelist an identifier (column name) to a safe subset — rules can't inject
/// arbitrary SQL through a group_by/join_key.
fn ident(s: &str) -> String {
    const ALLOWED: &[&str] = &[
        "host", "user_name", "user_sid", "artefact", "action", "process_name",
        "target_path",
    ];
    if ALLOWED.contains(&s) {
        s.to_string()
    } else {
        // Fall back to a constant so a bad rule fails closed (matches nothing
        // useful) rather than injecting.
        "'*'".to_string()
    }
}

/// Escape a single-quoted SQL string literal.
fn esc(s: &str) -> String {
    s.replace('\'', "''")
}
