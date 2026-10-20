//! Allow-list (suppression) of known-benign findings.
//!
//! Suppressing never deletes: matching rows move from `detections` into
//! `suppressed_detections` (tagged with the allow-list entry that hid them), and
//! re-applying the list first moves everything back — so removing an entry
//! restores its findings exactly. Engines that rewrite their findings
//! (`write_detections` / `replace_*`) also clear their own suppressed rows, and
//! the caller re-applies the list afterwards.

use crate::{CaseStore, StoreError};
use duckdb::params;

/// One allow-list entry. `rule_id` is an exact rule id or `*` (any rule);
/// `contains` is a case-insensitive substring of the finding's summary.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AllowEntry {
    pub id: String,
    pub rule_id: String,
    #[serde(default)]
    pub rule_title: String,
    pub contains: String,
    #[serde(default)]
    pub note: String,
    /// "case" (this case only) or "global" (added to every case on this machine).
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub created: String,
}

/// A suppressed finding, for the allow-list review view.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SuppressedRow {
    pub allow_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub summary: String,
    pub ts: String,
    pub engine: String,
}

pub(crate) const SUPPRESS_DDL: &str = "CREATE TABLE IF NOT EXISTS suppressed_detections (
    id UUID, rule_id TEXT, title TEXT, severity TEXT, attack TEXT, summary TEXT,
    event_ids TEXT, ts TIMESTAMP, host TEXT, engine TEXT, detected_utc TIMESTAMP, allow_id TEXT);";

const COLS: &str = "id, rule_id, title, severity, attack, summary, event_ids, ts, host, engine, detected_utc";

/// Event ids referenced by a detections-shaped table, as VARCHAR.
fn ids_of(table: &str) -> String {
    format!(
        "SELECT DISTINCT e FROM (SELECT UNNEST(string_split(replace(event_ids, ' ', ''), ',')) AS e FROM {table} WHERE event_ids <> '') WHERE e <> ''"
    )
}

impl CaseStore {
    pub(crate) fn ensure_suppress_table(&self) -> Result<(), StoreError> {
        self.connection().execute_batch(SUPPRESS_DDL)?;
        Ok(())
    }

    /// Clear suppressed rows for engines about to be rewritten.
    pub(crate) fn clear_suppressed_where(&self, engine_sql: &str) -> Result<(), StoreError> {
        self.ensure_suppress_table()?;
        self.connection().execute_batch(&format!("DELETE FROM suppressed_detections WHERE {engine_sql}"))?;
        Ok(())
    }

    /// Restore everything, then suppress whatever `entries` match. Returns the
    /// number of findings now suppressed per entry id.
    pub fn apply_allowlist(&self, entries: &[AllowEntry]) -> Result<Vec<(String, u64)>, StoreError> {
        self.ensure_suppress_table()?;
        let c = self.connection();
        c.execute_batch("BEGIN TRANSACTION")?;
        let res = (|| -> Result<Vec<(String, u64)>, StoreError> {
            c.execute_batch(&format!(
                "INSERT INTO detections ({COLS}) SELECT {COLS} FROM suppressed_detections;
                 DELETE FROM suppressed_detections;"
            ))?;
            let mut counts = Vec::new();
            for e in entries {
                let needle = e.contains.trim().to_lowercase();
                if needle.is_empty() && e.rule_id.trim() == "*" {
                    counts.push((e.id.clone(), 0)); // refuse to hide everything
                    continue;
                }
                let pred = "(? = '*' OR rule_id = ?) AND contains(lower(summary), ?)";
                let n = c.execute(
                    &format!("INSERT INTO suppressed_detections SELECT {COLS}, ? FROM detections WHERE {pred}"),
                    params![e.id, e.rule_id, e.rule_id, needle],
                )?;
                c.execute(&format!("DELETE FROM detections WHERE {pred}"), params![e.rule_id, e.rule_id, needle])?;
                counts.push((e.id.clone(), n as u64));
            }
            // Auto-set "unconfirmed" triage follows the findings: drop it (when no
            // note was written) from events only suppressed findings point at, and
            // put it back on events a live finding points at.
            c.execute_batch(&format!(
                "DELETE FROM tags WHERE tag = 'triage:unconfirmed' AND (note IS NULL OR note = '')
                   AND CAST(event_id AS VARCHAR) IN ({s})
                   AND CAST(event_id AS VARCHAR) NOT IN ({d});
                 INSERT INTO tags (event_id, tag, note, tagged_utc)
                   SELECT CAST(e AS UUID), 'triage:unconfirmed', NULL, now() FROM ({d}) x
                   WHERE e NOT IN (SELECT CAST(event_id AS VARCHAR) FROM tags WHERE tag LIKE 'triage:%');",
                s = ids_of("suppressed_detections"),
                d = ids_of("detections"),
            ))?;
            Ok(counts)
        })();
        match res {
            Ok(v) => {
                c.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = c.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Findings currently hidden by the allow-list.
    pub fn suppressed(&self) -> Result<Vec<SuppressedRow>, StoreError> {
        self.ensure_suppress_table()?;
        let mut stmt = self.connection().prepare(
            "SELECT allow_id, rule_id, title, severity, summary, strftime(ts, '%Y-%m-%dT%H:%M:%S'), engine
             FROM suppressed_detections ORDER BY allow_id, ts",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SuppressedRow {
                    allow_id: r.get(0)?,
                    rule_id: r.get(1)?,
                    title: r.get(2)?,
                    severity: r.get(3)?,
                    summary: r.get(4)?,
                    ts: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    engine: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Remove every finding (live or suppressed) a given rule produced for an
    /// engine — used when a Sigma rule is disabled. Returns how many went.
    pub fn delete_rule_findings(&self, engine: &str, rule_id: &str) -> Result<u64, StoreError> {
        self.ensure_suppress_table()?;
        let c = self.connection();
        let n = c.execute("DELETE FROM detections WHERE engine = ? AND rule_id = ?", params![engine, rule_id])?;
        c.execute("DELETE FROM suppressed_detections WHERE engine = ? AND rule_id = ?", params![engine, rule_id])?;
        c.execute_batch(&format!(
            "DELETE FROM tags WHERE tag = 'triage:unconfirmed' AND (note IS NULL OR note = '')
               AND CAST(event_id AS VARCHAR) NOT IN ({d})
               AND CAST(event_id AS VARCHAR) NOT IN ({s});",
            d = ids_of("detections"),
            s = ids_of("suppressed_detections"),
        ))?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fx_core::{Detection, DetectionEngine, Severity};
    use uuid::Uuid;

    fn det(rule: &str, summary: &str, ev: Uuid, engine: DetectionEngine) -> Detection {
        Detection {
            id: Uuid::new_v4(),
            rule_id: rule.into(),
            title: rule.into(),
            severity: Severity::Medium,
            attack: vec![],
            summary: summary.into(),
            event_ids: vec![ev],
            timestamp: time::OffsetDateTime::now_utc(),
            host: None,
            engine,
        }
    }

    fn has_triage(store: &CaseStore, id: &Uuid) -> bool {
        store.triage_map().unwrap().iter().any(|t| t.0 == id.to_string())
    }

    #[test]
    fn suppress_restore_and_disable() {
        let dir = std::env::temp_dir().join(format!("fx-allow-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CaseStore::create(&dir.join("c.fxcase"), "t", None, "UTC").unwrap();
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        store
            .write_detections(&[
                det("evtx_odd_place", "Created C:\\Collect\\Logs\\Security.evtx", a, DetectionEngine::SingleEvent),
                det("evtx_odd_place", "Created C:\\Temp\\x.evtx", b, DetectionEngine::SingleEvent),
            ])
            .unwrap();
        store.replace_sigma_detections(&[det("sigma:whoami", "whoami.exe", c, DetectionEngine::Sigma)]).unwrap();
        for id in [a, b, c] {
            store.set_triage_if_absent(&id.to_string(), "unconfirmed", None).unwrap();
        }
        let entry = AllowEntry {
            id: "a1".into(),
            rule_id: "evtx_odd_place".into(),
            rule_title: String::new(),
            contains: "\\COLLECT\\".into(),
            note: "collection copies".into(),
            scope: "case".into(),
            created: String::new(),
        };
        let counts = store.apply_allowlist(&[entry.clone()]).unwrap();
        assert_eq!(counts, vec![("a1".to_string(), 1)]);
        assert_eq!(store.detections().unwrap().len(), 2);
        assert_eq!(store.suppressed().unwrap().len(), 1);
        assert!(!has_triage(&store, &a), "unconfirmed follows the finding");
        // Re-applying is idempotent; an empty list restores everything.
        store.apply_allowlist(&[entry]).unwrap();
        assert_eq!(store.detections().unwrap().len(), 2);
        store.apply_allowlist(&[]).unwrap();
        assert_eq!(store.detections().unwrap().len(), 3);
        assert!(has_triage(&store, &a));
        // A '*' entry with no text never hides everything.
        let all = AllowEntry { id: "x".into(), rule_id: "*".into(), contains: " ".into(), ..Default::default() };
        store.apply_allowlist(&[all]).unwrap();
        assert_eq!(store.detections().unwrap().len(), 3);
        // Disabling a Sigma rule removes its findings and their auto-triage.
        assert_eq!(store.delete_rule_findings("sigma", "sigma:whoami").unwrap(), 1);
        assert_eq!(store.detections().unwrap().len(), 2);
        assert!(!has_triage(&store, &c));
    }
}
