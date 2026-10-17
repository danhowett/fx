//! Read-side queries for the case store. These back the timeline grid, the
//! artefact/status dashboard, and (later) hunt result views. Kept deliberately
//! small and typed; the GUI calls these rather than issuing raw SQL.

use crate::{fmt_ts_helper, CaseStore, StoreError};
use duckdb::params;
use time::OffsetDateTime;

/// A single row for the timeline grid — the lifted columns, not `raw`.
#[derive(Debug, Clone)]
pub struct TimelineRow {
    pub id: String,
    pub ts: String,
    pub ts_kind: String,
    pub artefact: String,
    pub action: String,
    pub host: Option<String>,
    pub user_name: Option<String>,
    pub target_path: Option<String>,
    pub message: String,
    /// Provenance locator: parser/source reference (e.g. "Security#record32950").
    /// Lets the analyst tell apart events that look identical (e.g. the same
    /// log-cleared record collected from two copies of a log).
    pub source_ref: Option<String>,
}

/// A filter for the timeline. All fields optional; `None` means unconstrained.
#[derive(Debug, Default, Clone)]
pub struct TimelineFilter {
    pub after: Option<OffsetDateTime>,
    pub before: Option<OffsetDateTime>,
    pub artefact: Option<String>,
    pub action_prefix: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    /// Substring match against message, target_path, command_line, process and
    /// parent names (case-insensitive).
    pub text: Option<String>,
    /// One of the analyst categories (logon/network/persistence/execution/
    /// filesystem/other). Applied as a SQL predicate so it filters the whole
    /// case, not just a page.
    pub category: Option<String>,
    /// Only events that tripped a rule heuristic (suspicious/anti-forensic/
    /// masquerade/staging). SQL predicate, whole-case.
    pub flagged_only: bool,
    pub limit: usize,
    pub offset: usize,
}

/// The SQL WHERE-fragment (after `WHERE 1=1`) that expresses a derived category,
/// mirroring the GUI's `categorize()`. Kept here so timeline() and
/// count_timeline() stay identical. Returns an empty string for an unknown
/// category (no constraint).
fn category_sql(cat: &str) -> &'static str {
    match cat {
        "logon" => " AND action LIKE 'logon%'",
        "network" => " AND (action LIKE 'network%' OR action LIKE 'browser%' OR action LIKE '%rdp%' OR action LIKE 'remote_access%' OR artefact = 'BrowserHistory' OR artefact = 'RemoteAccess')",
        "persistence" => " AND (action LIKE 'persistence%' OR action LIKE 'service%')",
        "execution" => " AND (action LIKE 'execution%' OR artefact = 'Prefetch' OR artefact = 'UserAssist')",
        "filesystem" => " AND (action LIKE 'file%' OR artefact = 'Mft' OR artefact = 'UsnJrnl')",
        // "other" = none of the above. Negate all the known buckets.
        "other" => " AND NOT (action LIKE 'logon%' OR action LIKE 'network%' OR action LIKE 'browser%' OR action LIKE '%rdp%' OR action LIKE 'remote_access%' OR artefact = 'BrowserHistory' OR artefact = 'RemoteAccess' OR action LIKE 'persistence%' OR action LIKE 'service%' OR action LIKE 'execution%' OR artefact = 'Prefetch' OR artefact = 'UserAssist' OR action LIKE 'file%' OR artefact = 'Mft' OR artefact = 'UsnJrnl')",
        _ => "",
    }
}

/// The SQL WHERE-fragment for the flagged-only filter, mirroring the GUI's
/// `flagged` derivation.
const FLAGGED_SQL: &str = " AND (action LIKE '%suspicious%' OR action LIKE '%anti_forensic%' OR message LIKE '%[ANTI-FORENSIC]%' OR message LIKE '%MASQUERADE%' OR message LIKE '%STAGING%')";

impl CaseStore {
    /// Total event count (for the status bar / paging).
    pub fn event_count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .connection()
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Event counts grouped by artefact, for the dashboard.
    pub fn counts_by_artefact(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let mut stmt = self.connection().prepare(
            "SELECT artefact, COUNT(*) FROM events GROUP BY artefact ORDER BY 2 DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let a: String = r.get(0)?;
                let c: i64 = r.get(1)?;
                Ok((a, c as u64))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Per-day event counts for the activity graph. Returns one row per calendar
    /// day (UTC) that has at least one event, with the total count and how many
    /// of those events tripped a hunt rule ("flagged"). The graph uses the gap
    /// between the two — a tall day that is mostly *un*flagged is exactly the
    /// kind of unexplained activity spike an analyst wants to pivot into.
    ///
    /// The flagged count is computed by flattening the comma-joined `event_ids`
    /// of every detection into a one-column set, then left-joining the day's
    /// events against it. Detections are few, so this stays cheap.
    pub fn daily_activity(&self) -> Result<Vec<DailyActivity>, StoreError> {
        // "flagged" = any event that either tripped a hunt rule OR carries an
        // analyst triage tag that is not a clearance. validated / unconfirmed
        // count toward the flagged base; false_positive / dismissed are analyst
        // clearances and are deliberately excluded, so clearing a false positive
        // lowers the flagged portion. The two id sets are UNIONed and de-duped,
        // so an event that is both rule-flagged and triaged is counted once.
        let sql = "
            WITH flagged_ids AS (
                SELECT DISTINCT UNNEST(string_split(event_ids, ',')) AS eid
                FROM detections
                WHERE event_ids <> ''
                UNION
                SELECT DISTINCT event_id AS eid
                FROM tags
                WHERE tag IN ('triage:validated', 'triage:unconfirmed')
            )
            SELECT
                strftime(e.ts, '%Y-%m-%d')                      AS day,
                COUNT(*)                                        AS total,
                COUNT(CASE WHEN f.eid IS NOT NULL THEN 1 END)   AS flagged
            FROM events e
            LEFT JOIN flagged_ids f ON CAST(e.id AS VARCHAR) = f.eid
            GROUP BY day
            ORDER BY day";
        let mut stmt = self.connection().prepare(sql)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(DailyActivity {
                    day: r.get::<_, String>(0)?,
                    total: r.get::<_, i64>(1)? as u64,
                    flagged: r.get::<_, i64>(2)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Ingest summary: (status, count) so the GUI can show parsed/unsupported/
    /// failed at a glance.
    pub fn ingest_summary(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let mut stmt = self.connection().prepare(
            "SELECT status, COUNT(*) FROM ingest_report GROUP BY status ORDER BY 1",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let s: String = r.get(0)?;
                let c: i64 = r.get(1)?;
                Ok((s, c as u64))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Build the shared WHERE clause (everything after `FROM events WHERE 1=1`)
    /// and its bound parameters, so `timeline()` and `count_timeline()` apply
    /// exactly the same filter. All user values are bound as parameters; the
    /// category/flagged fragments are fixed SQL (no user input interpolated).
    fn build_where(f: &TimelineFilter) -> (String, Vec<Box<dyn duckdb::ToSql>>) {
        let mut sql = String::new();
        let mut binds: Vec<Box<dyn duckdb::ToSql>> = Vec::new();

        if let Some(after) = f.after {
            sql.push_str(" AND ts >= ?");
            binds.push(Box::new(fmt_ts_helper(after)));
        }
        if let Some(before) = f.before {
            sql.push_str(" AND ts < ?");
            binds.push(Box::new(fmt_ts_helper(before)));
        }
        if let Some(a) = &f.artefact {
            sql.push_str(" AND artefact = ?");
            binds.push(Box::new(a.clone()));
        }
        if let Some(p) = &f.action_prefix {
            sql.push_str(" AND action LIKE ?");
            binds.push(Box::new(format!("{p}%")));
        }
        if let Some(h) = &f.host {
            sql.push_str(" AND host = ?");
            binds.push(Box::new(h.clone()));
        }
        if let Some(u) = &f.user {
            sql.push_str(" AND user_name = ?");
            binds.push(Box::new(u.clone()));
        }
        if let Some(t) = &f.text {
            // Case-insensitive match across the fields an analyst searches:
            // message, target path, command line, process and parent names.
            sql.push_str(
                " AND (message ILIKE ? OR target_path ILIKE ? OR command_line ILIKE ? \
                   OR process_name ILIKE ? OR parent_name ILIKE ?)",
            );
            let like = format!("%{t}%");
            for _ in 0..5 {
                binds.push(Box::new(like.clone()));
            }
        }
        if let Some(cat) = &f.category {
            sql.push_str(category_sql(cat));
        }
        if f.flagged_only {
            sql.push_str(FLAGGED_SQL);
        }
        (sql, binds)
    }

    /// Count the events matching a filter (ignoring limit/offset) — for paging
    /// and the "N of M shown" indicator. Runs over the whole case in SQL.
    pub fn count_timeline(&self, f: &TimelineFilter) -> Result<u64, StoreError> {
        let (where_sql, binds) = Self::build_where(f);
        let sql = format!("SELECT COUNT(*) FROM events WHERE 1=1{where_sql}");
        let param_refs: Vec<&dyn duckdb::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let n: i64 = self
            .connection()
            .query_row(&sql, param_refs.as_slice(), |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Query the timeline with a filter. Builds SQL dynamically but binds all
    /// values as parameters (no string interpolation of user input). Category and
    /// flagged-only are applied in SQL too, so a page is a true slice of the
    /// whole matching set (paging with limit/offset is therefore correct).
    pub fn timeline(&self, f: &TimelineFilter) -> Result<Vec<TimelineRow>, StoreError> {
        let (where_sql, binds) = Self::build_where(f);
        let mut sql = format!(
            "SELECT id, strftime(ts, '%Y-%m-%dT%H:%M:%S') AS ts, ts_kind, artefact, action, host, user_name, target_path, message, source_ref
             FROM events WHERE 1=1{where_sql} ORDER BY ts"
        );
        let limit = if f.limit == 0 { 1000 } else { f.limit };
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, f.offset));

        let param_refs: Vec<&dyn duckdb::ToSql> = binds.iter().map(|b| b.as_ref()).collect();

        let mut stmt = self.connection().prepare(&sql)?;
        let rows = stmt
            .query_map(param_refs.as_slice(), |r| {
                Ok(TimelineRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    ts_kind: r.get(2)?,
                    artefact: r.get(3)?,
                    action: r.get(4)?,
                    host: r.get(5)?,
                    user_name: r.get(6)?,
                    target_path: r.get(7)?,
                    message: r.get(8)?,
                    source_ref: r.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Fetch specific events by id, in time order — the "show every event that
    /// matched this IOC" view. Ids are bound as parameters, in chunks.
    pub fn events_by_ids(&self, ids: &[String]) -> Result<Vec<TimelineRow>, StoreError> {
        let mut out = Vec::new();
        for chunk in ids.chunks(500) {
            let marks = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT id, strftime(ts, '%Y-%m-%dT%H:%M:%S') AS ts, ts_kind, artefact, action, host, user_name, target_path, message, source_ref
                 FROM events WHERE CAST(id AS VARCHAR) IN ({marks})"
            );
            let params: Vec<&dyn duckdb::ToSql> = chunk.iter().map(|s| s as &dyn duckdb::ToSql).collect();
            let mut stmt = self.connection().prepare(&sql)?;
            let rows = stmt
                .query_map(params.as_slice(), |r| {
                    Ok(TimelineRow {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        ts_kind: r.get(2)?,
                        artefact: r.get(3)?,
                        action: r.get(4)?,
                        host: r.get(5)?,
                        user_name: r.get(6)?,
                        target_path: r.get(7)?,
                        message: r.get(8)?,
                        source_ref: r.get(9)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            out.extend(rows);
        }
        out.sort_by(|a, b| a.ts.cmp(&b.ts));
        Ok(out)
    }

    /// Fetch the full raw JSON for one event (for the detail pane).
    pub fn raw_json(&self, event_id: &str) -> Result<Option<String>, StoreError> {
        let mut stmt = self
            .connection()
            .prepare("SELECT raw FROM events WHERE id = ?")?;
        let mut rows = stmt.query(params![event_id])?;
        if let Some(row) = rows.next()? {
            let raw: String = row.get(0)?;
            Ok(Some(raw))
        } else {
            Ok(None)
        }
    }

    /// Exfil-volume view: total SRUM network bytes sent/received per process,
    /// highest sent first. This is an early, targeted preview of the Week-4
    /// hunt engine — a process pushing large volumes out is exactly the signal
    /// SRUM preserves after the process is gone. Reads bytes straight from the
    /// events' `raw` JSON (SRUM network rows carry `bytes_sent`/`bytes_recv`).
    pub fn srum_network_totals(&self, limit: usize) -> Result<Vec<SrumNetTotal>, StoreError> {
        let limit = if limit == 0 { 50 } else { limit };
        // DuckDB can read JSON fields directly with the -> / json_extract ops.
        let sql = format!(
            "SELECT
                 json_extract_string(raw, '$.app')  AS app,
                 json_extract_string(raw, '$.user') AS user,
                 SUM(CAST(json_extract(raw, '$.bytes_sent') AS BIGINT)) AS sent,
                 SUM(CAST(json_extract(raw, '$.bytes_recv') AS BIGINT)) AS recv
             FROM events
             WHERE artefact = 'Srum' AND action = 'network.usage'
             GROUP BY app, user
             ORDER BY sent DESC
             LIMIT {limit}"
        );
        let mut stmt = self.connection().prepare(&sql)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SrumNetTotal {
                    app: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    user: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    bytes_sent: r.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                    bytes_recv: r.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

/// One day's bar in the activity graph.
#[derive(Debug, Clone)]
pub struct DailyActivity {
    /// Calendar day, UTC, `YYYY-MM-DD`.
    pub day: String,
    /// All events that day.
    pub total: u64,
    /// Of those, how many tripped a hunt rule.
    pub flagged: u64,
}

/// One row of the SRUM exfil-volume view.
#[derive(Debug, Clone)]
pub struct SrumNetTotal {
    pub app: String,
    pub user: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}
