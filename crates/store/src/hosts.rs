//! Multi-host cases.
//!
//! A case can hold several collections (one per machine, or a later
//! re-collection of the same machine). Each ingest run is a *collection*: its
//! evidence, unclassified files and ingest-log rows carry its `collection_id`,
//! and once it has been parsed every event from it gets the collection's host
//! name in `events.host`. That makes "which machine did this come from" a plain
//! column for filtering, hunting and reporting. The event's original record
//! (for example an EVTX `Computer` value) is untouched in `raw`.
//!
//! The host name is taken, in order, from the SYSTEM hive's ComputerName, the
//! host the collection tool named, the most common EVTX Computer value, and
//! finally the collection folder's name. The analyst can rename a host.
//!
//! Older single-host cases have no `collections` rows; they are given one
//! ("legacy") the first time another collection is added.
//!
//! Host *scope*: the GUI can restrict the case-level summaries (counts, the
//! activity graph, host facts, the ingest log, exports and the report) to one
//! host with [`CaseStore::set_host_scope`]. The timeline filter has its own
//! `host` field and doesn't use the scope.

use crate::{fmt_ts_helper, CaseStore, StoreError};
use duckdb::params;
use time::OffsetDateTime;

/// Idempotent: run on create and on open so older case files pick it up.
pub(crate) const HOSTS_DDL: &str = "
CREATE TABLE IF NOT EXISTS collections (
    collection_id  TEXT PRIMARY KEY,
    host           TEXT NOT NULL,
    host_source    TEXT,
    source_root    TEXT,
    ingested_utc   TIMESTAMP NOT NULL
);
ALTER TABLE evidence      ADD COLUMN IF NOT EXISTS collection_id TEXT;
ALTER TABLE unclassified  ADD COLUMN IF NOT EXISTS collection_id TEXT;
ALTER TABLE ingest_report ADD COLUMN IF NOT EXISTS collection_id TEXT;
";

/// One host in the case.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostRow {
    pub host: String,
    /// Where the name came from ("SYSTEM hive ComputerName", "collection tool",
    /// "event logs", "folder name", "renamed by analyst").
    pub host_source: String,
    pub events: u64,
    pub collections: Vec<CollectionRow>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CollectionRow {
    pub collection_id: String,
    pub source_root: String,
    pub ingested_utc: String,
    pub files: u64,
}

/// Why a collection couldn't be added.
pub const DUPLICATE_COLLECTION: &str = "already in this case";

/// Quote a string as a SQL literal (host names come from evidence).
pub(crate) fn sql_lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

impl CaseStore {
    pub(crate) fn ensure_hosts_schema(&self) -> Result<(), StoreError> {
        self.connection().execute_batch(HOSTS_DDL)?;
        self.ensure_undated()?;
        Ok(())
    }

    /// Cases made before v0.1.10 store "no time" as a 1970-01-01 00:00:00
    /// placeholder. Allow NULL times, and turn exactly those placeholders,
    /// from the parsers that used them, into undated events. Real times are
    /// never touched: the MFT and event logs never used the placeholder, so a
    /// genuine (e.g. timestomped) 1970 value there is kept as recorded.
    fn ensure_undated(&self) -> Result<(), StoreError> {
        let c = self.connection();
        let not_null: bool = c
            .query_row(
                "SELECT COUNT(*) FROM duckdb_columns()
                 WHERE table_name = 'events' AND column_name = 'ts' AND NOT is_nullable",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);
        if !not_null {
            return Ok(());
        }
        // DuckDB won't alter a table that has indexes on it: drop every index
        // on the two tables first (build_indexes() recreates fx's own below).
        let mut stmt = c.prepare(
            "SELECT index_name FROM duckdb_indexes()
             WHERE table_name IN ('events', 'detections')",
        )?;
        let indexes: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for ix in indexes {
            c.execute_batch(&format!(
                "DROP INDEX IF EXISTS \"{}\";",
                ix.replace('"', "")
            ))?;
        }
        c.execute_batch(
            "ALTER TABLE events ALTER COLUMN ts DROP NOT NULL;
             ALTER TABLE detections ALTER COLUMN ts DROP NOT NULL;",
        )?;
        c.execute_batch(
            "UPDATE events SET ts = NULL, ts_kind = 'Undated'
             WHERE ts = TIMESTAMP '1970-01-01 00:00:00'
               AND parser IN ('lnk', 'recyclebin', 'usnjrnl', 'scheduled_task', 'defender_log',
                              'registry', 'memory_files', 'pshistory', 'browser_history');
             UPDATE detections SET ts = NULL
             FROM events e
             WHERE detections.event_ids <> ''
               AND e.id = TRY_CAST(trim(split_part(detections.event_ids, ',', 1)) AS UUID)
               AND e.ts IS NULL;",
        )?;
        self.build_indexes()
    }

    // ── Scope ───────────────────────────────────────────────────────────────

    /// Restrict case-level summaries to one host (None = whole case).
    pub fn set_host_scope(&self, host: Option<String>) {
        *self.scope.borrow_mut() = host.filter(|h| !h.is_empty());
    }

    /// Run `f` with the host scope set, restoring "whole case" afterwards.
    pub fn scoped<T>(&self, host: Option<String>, f: impl FnOnce(&Self) -> T) -> T {
        self.set_host_scope(host);
        let out = f(self);
        self.set_host_scope(None);
        out
    }

    pub fn host_scope(&self) -> Option<String> {
        self.scope.borrow().clone()
    }

    /// `AND <col> = '<host>'` for event / detection queries, or "".
    pub(crate) fn scope_host_sql(&self, col: &str) -> String {
        match &*self.scope.borrow() {
            Some(h) => format!(" AND {col} = {}", sql_lit(h)),
            None => String::new(),
        }
    }

    /// `AND collection_id IN (...)` for evidence / unclassified / ingest_report.
    pub(crate) fn scope_collection_sql(&self, col: &str) -> String {
        match &*self.scope.borrow() {
            Some(h) => format!(
                " AND {col} IN (SELECT collection_id FROM collections WHERE host = {})",
                sql_lit(h)
            ),
            None => String::new(),
        }
    }

    // ── Collections ─────────────────────────────────────────────────────────

    /// Give an older single-host case its one collection, so a second can be
    /// added beside it. No-op when the case already has collections or no data.
    pub fn ensure_legacy_collection(&self) -> Result<(), StoreError> {
        let c = self.connection();
        let have: i64 = c.query_row("SELECT COUNT(*) FROM collections", [], |r| r.get(0))?;
        let evidence: i64 = c.query_row(
            "SELECT COUNT(*) FROM evidence WHERE collection_id IS NULL",
            [],
            |r| r.get(0),
        )?;
        if have > 0 || evidence == 0 {
            return Ok(());
        }
        let id = "legacy";
        c.execute(
            "INSERT INTO collections (collection_id, host, host_source, source_root, ingested_utc)
             VALUES (?, '(pending)', NULL, NULL,
                     COALESCE((SELECT MIN(registered_utc) FROM evidence), now()))",
            params![id],
        )?;
        self.claim_unassigned(id)?;
        self.name_collection_host(id, None)?;
        Ok(())
    }

    /// Start a collection before ingesting `source_root`. Refuses a folder
    /// that is already in the case (the same collection added twice would
    /// duplicate every event).
    pub fn begin_collection(&self, source_root: &str) -> Result<String, StoreError> {
        let c = self.connection();
        let norm = normalise_root(source_root);
        let mut stmt =
            c.prepare("SELECT source_root FROM collections WHERE source_root IS NOT NULL")?;
        let roots: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        if roots.iter().any(|r| normalise_root(r) == norm) {
            return Err(StoreError::Refused(format!(
                "this collection folder is {DUPLICATE_COLLECTION}"
            )));
        }
        let id = uuid::Uuid::new_v4().to_string();
        c.execute(
            "INSERT INTO collections (collection_id, host, host_source, source_root, ingested_utc)
             VALUES (?, '(pending)', NULL, ?, ?)",
            params![id, source_root, fmt_ts_helper(OffsetDateTime::now_utc())],
        )?;
        Ok(id)
    }

    /// Tag every evidence / unclassified / ingest-log row without a collection
    /// as belonging to `collection_id` (everything registered by this run).
    pub fn claim_unassigned(&self, collection_id: &str) -> Result<(), StoreError> {
        let c = self.connection();
        for t in ["evidence", "unclassified", "ingest_report"] {
            c.execute(
                &format!("UPDATE {t} SET collection_id = ? WHERE collection_id IS NULL"),
                params![collection_id],
            )?;
        }
        Ok(())
    }

    /// Decide the collection's host name, record it, and stamp it on every
    /// event from the collection. `preferred` (an analyst-supplied name) wins.
    /// Returns (host, merged) — merged is true when that host was already in
    /// the case from an earlier collection.
    pub fn name_collection_host(
        &self,
        collection_id: &str,
        preferred: Option<&str>,
    ) -> Result<(String, bool), StoreError> {
        let c = self.connection();
        let (host, source) = match preferred.map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => (p.to_string(), "named by analyst".to_string()),
            None => self.derive_host_name(collection_id)?,
        };
        let merged: i64 = c.query_row(
            "SELECT COUNT(*) FROM collections WHERE host = ? AND collection_id <> ?",
            params![host, collection_id],
            |r| r.get(0),
        )?;
        c.execute(
            "UPDATE collections SET host = ?, host_source = ? WHERE collection_id = ?",
            params![host, source, collection_id],
        )?;
        // events.host is indexed; drop the index for the bulk update and let
        // build_indexes() recreate it.
        c.execute_batch("DROP INDEX IF EXISTS idx_events_host")?;
        c.execute(
            "UPDATE events SET host = ?
             WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE collection_id = ?)",
            params![host, collection_id],
        )?;
        // Findings made before the relabel (an earlier Sigma run or IOC sweep)
        // still carry the old value; give them their events' host.
        self.sync_detection_hosts()?;
        Ok((host, merged > 0))
    }

    /// Set every finding's host from its (first) event, so findings from runs
    /// made before a host was named or renamed are attributed correctly.
    /// Findings without events keep their host. Cheap: one indexed join.
    pub fn sync_detection_hosts(&self) -> Result<(), StoreError> {
        self.ensure_suppress_table()?;
        for t in ["detections", "suppressed_detections"] {
            self.connection().execute_batch(&format!(
                "UPDATE {t} SET host = e.host
                 FROM events e
                 WHERE {t}.event_ids <> ''
                   AND e.id = TRY_CAST(trim(split_part({t}.event_ids, ',', 1)) AS UUID)
                   AND e.host IS NOT NULL
                   AND {t}.host IS DISTINCT FROM e.host;"
            ))?;
        }
        Ok(())
    }

    fn derive_host_name(&self, collection_id: &str) -> Result<(String, String), StoreError> {
        let c = self.connection();
        let in_coll = "evidence_id IN (SELECT evidence_id FROM evidence WHERE collection_id = ?)";
        // 1. SYSTEM hive ComputerName (current control set first).
        let mut stmt = c.prepare(&format!(
            "SELECT json_extract_string(raw, '$.value'),
                    COALESCE(json_extract_string(raw, '$.control_set'), '')
             FROM events WHERE action = 'host.computer_name' AND {in_coll}"
        ))?;
        let names: Vec<(Option<String>, String)> = stmt
            .query_map(params![collection_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let pick = names
            .iter()
            .filter_map(|(n, cs)| n.clone().filter(|n| !n.trim().is_empty()).map(|n| (n, cs)))
            .min_by_key(|(_, cs)| {
                if cs.eq_ignore_ascii_case("ControlSet001") {
                    0
                } else {
                    1
                }
            });
        if let Some((n, _)) = pick {
            return Ok((n.trim().to_string(), "SYSTEM hive ComputerName".into()));
        }
        // 2. The host the collection tool named.
        let asserted: Option<String> = c
            .query_row(
                "SELECT asserted_host FROM evidence
                 WHERE collection_id = ? AND asserted_host IS NOT NULL AND asserted_host <> ''
                 GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1",
                params![collection_id],
                |r| r.get(0),
            )
            .ok();
        if let Some(a) = asserted {
            return Ok((a, "named by the collection tool".into()));
        }
        // 3. The most common event-log Computer value (short name).
        let evtx: Option<String> = c
            .query_row(
                &format!(
                    "SELECT split_part(host, '.', 1) FROM events
                     WHERE artefact = 'Evtx' AND host IS NOT NULL AND host <> '' AND {in_coll}
                     GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1"
                ),
                params![collection_id],
                |r| r.get(0),
            )
            .ok();
        if let Some(e) = evtx {
            return Ok((e, "event logs (Computer)".into()));
        }
        // 4. The collection folder's name.
        let root: Option<String> = c
            .query_row(
                "SELECT source_root FROM collections WHERE collection_id = ?",
                params![collection_id],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        let folder = root
            .as_deref()
            .map(|r| {
                r.trim_end_matches(['/', '\\'])
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .filter(|s| !s.is_empty());
        if let Some(f) = folder {
            return Ok((f, "collection folder name".into()));
        }
        let n: i64 = c.query_row("SELECT COUNT(*) FROM collections", [], |r| r.get(0))?;
        Ok((format!("Host {n}"), "unnamed".into()))
    }

    /// Hosts in the case with their collections and event counts. A case
    /// without collection records (made before multi-host) reports one host.
    pub fn hosts(&self) -> Result<Vec<HostRow>, StoreError> {
        let c = self.connection();
        let mut stmt = c.prepare(
            "SELECT c.host, COALESCE(c.host_source, ''), c.collection_id, COALESCE(c.source_root, ''),
                    strftime(c.ingested_utc, '%Y-%m-%dT%H:%M:%S'),
                    (SELECT COUNT(*) FROM evidence v WHERE v.collection_id = c.collection_id)
             FROM collections c ORDER BY c.ingested_utc",
        )?;
        let rows: Vec<(String, String, String, String, String, i64)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        let mut counts = std::collections::HashMap::new();
        let mut stmt = c.prepare("SELECT COALESCE(host, ''), COUNT(*) FROM events GROUP BY 1")?;
        for r in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (h, n) = r?;
            counts.insert(h, n as u64);
        }
        let mut out: Vec<HostRow> = Vec::new();
        for (host, src, id, root, ts, files) in rows {
            let coll = CollectionRow {
                collection_id: id,
                source_root: root,
                ingested_utc: ts,
                files: files as u64,
            };
            match out.iter_mut().find(|h| h.host == host) {
                Some(h) => h.collections.push(coll),
                None => out.push(HostRow {
                    events: counts.get(&host).copied().unwrap_or(0),
                    host,
                    host_source: src,
                    collections: vec![coll],
                }),
            }
        }
        Ok(out)
    }

    /// Rename a host everywhere it appears (collections, events, findings).
    pub fn rename_host(&self, old: &str, new: &str) -> Result<(), StoreError> {
        let new = new.trim();
        if new.is_empty() || old == new {
            return Ok(());
        }
        let c = self.connection();
        self.ensure_suppress_table()?;
        c.execute(
            "UPDATE collections SET host = ?, host_source = 'renamed by analyst' WHERE host = ?",
            params![new, old],
        )?;
        c.execute_batch("DROP INDEX IF EXISTS idx_events_host")?;
        c.execute(
            "UPDATE events SET host = ? WHERE host = ?",
            params![new, old],
        )?;
        c.execute(
            "UPDATE detections SET host = ? WHERE host = ?",
            params![new, old],
        )?;
        c.execute(
            "UPDATE suppressed_detections SET host = ? WHERE host = ?",
            params![new, old],
        )?;
        self.sync_detection_hosts()?;
        self.build_indexes()
    }
}

fn normalise_root(p: &str) -> String {
    p.trim()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}
