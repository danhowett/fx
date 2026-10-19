//! The case store: a single DuckDB file holding one case.
//!
//! Responsibilities:
//!   * create/open a case file and apply the schema
//!   * register evidence items (hashed) and unclassified files
//!   * accept a stream of `Event`s via a batched [`EventSink`]
//!   * record the per-artefact ingest report
//!
//! Batching: events are buffered and flushed in transactions of `BATCH` rows.
//! One-INSERT-per-event would not keep up with multi-million-row MFT/UsnJrnl
//! loads. `raw` is written as a JSON string into DuckDB's JSON type.

use crate::evidence::{hash_artefact, hash_unclassified};
use crate::schema::{CASE_KV_DDL, DDL, INDEXES, SCHEMA_VERSION};
use duckdb::{params, Connection};
use fx_core::{Event, EventSink, IdentifiedArtefact, UnclassifiedFile};
use std::path::Path;
use time::OffsetDateTime;
use uuid::Uuid;

pub mod evidence;
pub mod hunt_support;
pub mod query;
pub mod schema;

pub use hunt_support::{CorrelationRow, DetectionRow};
pub use query::{DailyActivity, SrumNetTotal, TimelineFilter, TimelineRow};

const BATCH: usize = 5_000;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("duckdb error: {0}")]
    Db(#[from] duckdb::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("schema version mismatch: case is v{found}, tool expects v{expected}")]
    SchemaMismatch { found: i32, expected: i32 },
}

pub struct CaseStore {
    conn: Connection,
    case_id: Uuid,
}

impl CaseStore {
    /// Create a new case file (fails if it already exists), apply schema, and
    /// write the case_meta row.
    pub fn create(
        path: &Path,
        name: &str,
        examiner: Option<&str>,
        display_tz: &str,
    ) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(DDL)?;

        let case_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        conn.execute(
            "INSERT INTO case_meta
                (case_id, name, examiner, created_utc, schema_version, tool_version, display_timezone)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                case_id.to_string(),
                name,
                examiner,
                fmt_ts(now),
                SCHEMA_VERSION,
                env!("CARGO_PKG_VERSION"),
                display_tz,
            ],
        )?;

        Ok(Self { conn, case_id })
    }

    /// Open an existing case file and validate the schema version.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let (case_id, version): (String, i32) = conn.query_row(
            "SELECT case_id, schema_version FROM case_meta LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::SchemaMismatch {
                found: version,
                expected: SCHEMA_VERSION,
            });
        }
        let case_id = Uuid::parse_str(&case_id).unwrap_or_else(|_| Uuid::nil());
        // Small key/value table for per-case UI state (the saved IOC hunt list
        // and its last results). Created lazily so older case files gain it on
        // open without a schema-version bump.
        conn.execute_batch(CASE_KV_DDL)?;
        Ok(Self { conn, case_id })
    }

    pub fn case_id(&self) -> Uuid {
        self.case_id
    }

    /// Full case metadata for reporting.
    pub fn case_meta(&self) -> Result<CaseMeta, StoreError> {
        let (name, examiner, created, tz): (String, Option<String>, String, String) =
            self.conn.query_row(
                // created_utc is a TIMESTAMP column; format it in SQL. Reading
                // it straight into a String fails ("Invalid column type
                // Timestamp") — this broke the HTML case report.
                "SELECT name, examiner, strftime(created_utc, '%Y-%m-%dT%H:%M:%SZ') AS created_utc,
                        display_timezone FROM case_meta LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        Ok(CaseMeta {
            case_id: self.case_id.to_string(),
            name,
            examiner,
            created_utc: created,
            display_timezone: tz,
        })
    }

    /// Evidence items (hashed source files) for the chain-of-custody section.
    pub fn evidence_list(&self) -> Result<Vec<EvidenceItem>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT source_path, artefact_kind, sha256, size_bytes, id_method, id_confidence
             FROM evidence ORDER BY artefact_kind, source_path",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(EvidenceItem {
                    source_path: r.get(0)?,
                    artefact_kind: r.get(1)?,
                    sha256: r.get(2)?,
                    size_bytes: r.get::<_, i64>(3)? as u64,
                    id_method: r.get(4)?,
                    id_confidence: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Host facts (`host.*` events from the registry) with their source hive,
    /// for the Host panel: (event id, action, raw JSON, source path).
    pub fn host_facts(&self) -> Result<Vec<(String, String, String, String)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT CAST(e.id AS VARCHAR), e.action, CAST(e.raw AS VARCHAR), COALESCE(v.source_path, '')
             FROM events e LEFT JOIN evidence v ON v.evidence_id = e.evidence_id
             WHERE e.action LIKE 'host.%'
             ORDER BY e.ts",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Collection summary: (tool, asserted host, asserted time zone, files,
    /// total bytes, first / last registration time).
    pub fn collection_summary(&self) -> Result<(Option<String>, Option<String>, Option<String>, u64, u64), StoreError> {
        let row = self.conn.query_row(
            "SELECT (SELECT collection_tool FROM evidence WHERE collection_tool IS NOT NULL GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1),
                    (SELECT asserted_host FROM evidence WHERE asserted_host IS NOT NULL GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1),
                    (SELECT asserted_timezone FROM evidence WHERE asserted_timezone IS NOT NULL GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1),
                    COUNT(*), COALESCE(SUM(size_bytes), 0)
             FROM evidence",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? as u64, r.get::<_, i64>(4)? as u64)),
        )?;
        Ok(row)
    }

    /// Count of unclassified files (the "nothing dropped" accounting).
    pub fn unclassified_count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM unclassified", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Shared access to the underlying connection for the read-side query
    /// module (same crate). Not public API beyond the crate's own queries.
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Register an identified artefact as evidence (hashing it), returning its
    /// evidence_id. Call before writing that artefact's events.
    pub fn register_evidence(&self, a: &IdentifiedArtefact) -> Result<Uuid, StoreError> {
        let rec = hash_artefact(a)?;
        let now = OffsetDateTime::now_utc();
        let (tool, host, tz) = match &a.profile_hint {
            Some(h) => (
                h.collection_tool.clone(),
                h.asserted_host.clone(),
                h.asserted_timezone.clone(),
            ),
            None => (None, None, None),
        };
        self.conn.execute(
            "INSERT INTO evidence
                (evidence_id, source_path, absolute_path, artefact_kind, container_format,
                 id_method, id_confidence, size_bytes, sha256,
                 asserted_host, asserted_timezone, collection_tool, registered_utc)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                a.evidence_id.to_string(),
                a.source_path,
                a.path.display().to_string(),
                format!("{:?}", a.artefact),
                format!("{:?}", a.container),
                format!("{:?}", a.method),
                a.confidence,
                rec.size_bytes,
                rec.sha256,
                host,
                tz,
                tool,
                fmt_ts(now),
            ],
        )?;
        Ok(a.evidence_id)
    }

    /// Record an unclassified file (also hashed — it's still evidence).
    pub fn register_unclassified(&self, u: &UnclassifiedFile) -> Result<(), StoreError> {
        let rec = hash_unclassified(u)?;
        self.conn.execute(
            "INSERT INTO unclassified
                (evidence_id, source_path, absolute_path, container, sha256, size_bytes, reason)
             VALUES (?,?,?,?,?,?,?)",
            params![
                u.evidence_id.to_string(),
                u.source_path,
                u.path.display().to_string(),
                format!("{:?}", u.container),
                rec.sha256,
                rec.size_bytes,
                u.reason,
            ],
        )?;
        Ok(())
    }

    /// Build indexes. Call once after the initial bulk ingest for speed.
    pub fn build_indexes(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(INDEXES)?;
        Ok(())
    }

    /// Record one artefact's ingest outcome into the audit table.
    #[allow(clippy::too_many_arguments)]
    /// Set (or replace) the triage state of an event. States are the fixed
    /// triage vocabulary: "unconfirmed", "validated", "false_positive",
    /// "dismissed". A note is optional free text. Using a single logical tag
    /// key per event means each event has exactly one triage state that gets
    /// overwritten, rather than accumulating tags.
    pub fn set_triage(
        &self,
        event_id: &str,
        state: &str,
        note: Option<&str>,
    ) -> Result<(), StoreError> {
        let now = OffsetDateTime::now_utc();
        // Replace any existing triage row for this event.
        self.conn.execute(
            "DELETE FROM tags WHERE event_id = ? AND tag LIKE 'triage:%'",
            params![event_id],
        )?;
        self.conn.execute(
            "INSERT INTO tags (event_id, tag, note, tagged_utc) VALUES (?, ?, ?, ?)",
            params![event_id, format!("triage:{state}"), note, fmt_ts(now)],
        )?;
        Ok(())
    }

    /// Add an analyst label (free-text tag such as "Lateral movement") to an
    /// event. Stored in `tags` as `label:<text>`, alongside triage rows.
    pub fn add_label(&self, event_id: &str, label: &str) -> Result<(), StoreError> {
        let now = OffsetDateTime::now_utc();
        self.conn.execute(
            "INSERT INTO tags (event_id, tag, note, tagged_utc) VALUES (?, ?, NULL, ?) ON CONFLICT DO NOTHING",
            params![event_id, format!("label:{}", label.trim()), fmt_ts(now)],
        )?;
        Ok(())
    }

    /// Remove one analyst label from an event.
    pub fn remove_label(&self, event_id: &str, label: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM tags WHERE event_id = ? AND tag = ?",
            params![event_id, format!("label:{}", label.trim())],
        )?;
        Ok(())
    }

    /// Every (event_id, label) pair in the case.
    pub fn labels(&self) -> Result<Vec<(String, String)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT CAST(event_id AS VARCHAR), substr(tag, 7) FROM tags WHERE tag LIKE 'label:%' ORDER BY tagged_utc",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Read a per-case UI value (see `CASE_KV_DDL`).
    pub fn kv_get(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.conn.execute_batch(CASE_KV_DDL)?;
        let mut stmt = self.conn.prepare("SELECT v FROM case_kv WHERE k = ?")?;
        let mut rows = stmt.query(params![key])?;
        Ok(match rows.next()? { Some(r) => Some(r.get(0)?), None => None })
    }

    /// Write a per-case UI value.
    pub fn kv_set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute_batch(CASE_KV_DDL)?;
        self.conn.execute(
            "INSERT INTO case_kv (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v",
            params![key, value],
        )?;
        Ok(())
    }

    /// Clear an event's triage state entirely.
    pub fn clear_triage(&self, event_id: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM tags WHERE event_id = ? AND tag LIKE 'triage:%'",
            params![event_id],
        )?;
        Ok(())
    }

    /// Map of event_id -> (state, note) for every tagged event, so the GUI can
    /// show badges and filter. States come back without the "triage:" prefix.
    pub fn triage_map(&self) -> Result<Vec<(String, String, Option<String>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, tag, note FROM tags WHERE tag LIKE 'triage:%'",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let id: String = r.get(0)?;
                let tag: String = r.get(1)?;
                let note: Option<String> = r.get(2)?;
                let state = tag.strip_prefix("triage:").unwrap_or(&tag).to_string();
                Ok((id, state, note))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The per-file ingest log: what was ingested and whether it parsed. Powers
    /// the GUI's "Ingest log" view so analysts can see coverage and failures.
    pub fn ingest_log(&self) -> Result<Vec<IngestLogRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT source_path, artefact_kind, status, detail,
                    records_read, events_emitted, warning_count
             FROM ingest_report
             ORDER BY CASE status WHEN 'failed' THEN 0 WHEN 'unsupported' THEN 1 ELSE 2 END,
                      source_path",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(IngestLogRow {
                    source_path: r.get(0)?,
                    artefact_kind: r.get(1)?,
                    status: r.get(2)?,
                    detail: r.get(3)?,
                    records_read: r.get::<_, i64>(4)? as u64,
                    events_emitted: r.get::<_, i64>(5)? as u64,
                    warning_count: r.get::<_, i32>(6)? as u32,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Full detail for every triaged event, joined from the events table — so
    /// exports can include analyst-validated events that no rule fired on, not
    /// just rule detections. Returns (event_id, state, note, ts, host, action,
    /// artefact, message).
    pub fn triaged_events(
        &self,
    ) -> Result<Vec<TriagedEvent>, StoreError> {
        // Reuse the proven per-id lookup (string bind against the UUID column,
        // same path as raw_json which is known to match) rather than a
        // column-to-column JOIN, which can behave differently for UUID types.
        let tags = self.triage_map()?; // (event_id, state, note)
        let mut out = Vec::with_capacity(tags.len());
        let mut stmt = self.conn.prepare(
            "SELECT strftime(ts, '%Y-%m-%dT%H:%M:%S'), host, action, artefact, message
             FROM events WHERE id = ?",
        )?;
        for (event_id, state, note) in tags {
            let mut rows = stmt.query(params![event_id])?;
            if let Some(r) = rows.next()? {
                out.push(TriagedEvent {
                    event_id,
                    state,
                    note,
                    ts: r.get(0)?,
                    host: r.get(1)?,
                    action: r.get(2)?,
                    artefact: r.get(3)?,
                    message: r.get(4)?,
                });
            }
        }
        out.sort_by(|a, b| a.ts.cmp(&b.ts));
        Ok(out)
    }

    /// Count of events in each triage state, for the rail summary.
    pub fn triage_summary(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT tag, COUNT(*) FROM tags WHERE tag LIKE 'triage:%' GROUP BY tag",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let tag: String = r.get(0)?;
                let c: i64 = r.get(1)?;
                Ok((tag.strip_prefix("triage:").unwrap_or(&tag).to_string(), c as u64))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Set triage state only if the event has none yet — used by auto-tagging
    /// so it never overwrites an analyst's manual decision.
    pub fn set_triage_if_absent(
        &self,
        event_id: &str,
        state: &str,
        note: Option<&str>,
    ) -> Result<(), StoreError> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tags WHERE event_id = ? AND tag LIKE 'triage:%'",
            params![event_id],
            |r| r.get(0),
        )?;
        if existing == 0 {
            self.set_triage(event_id, state, note)?;
        }
        Ok(())
    }

    pub fn record_ingest(
        &self,
        source_path: &str,
        artefact_kind: &str,
        status: &str,
        detail: Option<&str>,
        records_read: u64,
        events_emitted: u64,
        warning_count: i32,
    ) -> Result<(), StoreError> {
        let now = OffsetDateTime::now_utc();
        self.conn.execute(
            "INSERT INTO ingest_report
                (id, run_utc, source_path, artefact_kind, status, detail,
                 records_read, events_emitted, warning_count)
             VALUES (?,?,?,?,?,?,?,?,?)",
            params![
                Uuid::new_v4().to_string(),
                fmt_ts(now),
                source_path,
                artefact_kind,
                status,
                detail,
                records_read as i64,
                events_emitted as i64,
                warning_count,
            ],
        )?;
        Ok(())
    }

    /// Open a batched writer for events. Flush or drop it to commit remaining
    /// rows before querying. Takes `&self` — DuckDB's `Connection` serializes
    /// access internally, and the writer only needs a shared reference.
    pub fn event_writer(&self) -> EventWriter<'_> {
        EventWriter {
            conn: &self.conn,
            buf: Vec::with_capacity(BATCH),
        }
    }
}

/// Batched event sink. Buffers up to `BATCH` events then flushes them inside a
/// single transaction with a prepared statement.
pub struct EventWriter<'a> {
    conn: &'a Connection,
    buf: Vec<Event>,
}

impl EventWriter<'_> {
    pub fn flush(&mut self) -> Result<(), StoreError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        // Bulk-load via DuckDB's Appender, NOT row-by-row INSERTs. DuckDB is a
        // columnar/analytical engine: single-row `INSERT ... VALUES` is its
        // slowest path, and a multi-million-row $MFT / $UsnJrnl load that way
        // took many minutes (the "stuck on Ingesting…" hang). The Appender
        // batches columnar chunks internally and is 10–100× faster for bulk
        // loads. Column order below MUST match the `events` table DDL exactly.
        let mut appender = self.conn.appender("events")?;
        for ev in self.buf.drain(..) {
            let proc = ev.process.unwrap_or_default();
            let target = ev.target.unwrap_or_default();
            let net = ev.network.unwrap_or_default();
            appender.append_row(params![
                ev.id.to_string(),
                fmt_ts(ev.timestamp),
                format!("{:?}", ev.timestamp_kind),
                format!("{:?}", ev.artefact),
                ev.action,
                ev.host,
                ev.user.name,
                ev.user.sid,
                ev.user.domain,
                proc.name,
                proc.path,
                proc.pid,
                proc.command_line,
                proc.hash_sha1,
                proc.parent_name,
                target.path,
                target.value_name,
                net.source_ip,
                net.dest_ip,
                net.logon_type,
                ev.message,
                ev.provenance.evidence_id.to_string(),
                ev.provenance.parser,
                ev.provenance.parser_version,
                ev.provenance.source_ref,
                ev.raw.to_string(),
            ])?;
        }
        // Explicitly flush and surface any error before the appender drops —
        // append_row can return Ok for a row that only fails at flush time.
        appender.flush()?;
        Ok(())
    }
}

impl EventSink for EventWriter<'_> {
    fn emit(&mut self, event: Event) {
        self.buf.push(event);
        if self.buf.len() >= BATCH {
            // A flush failure mid-ingest is logged; the orchestrator's
            // per-artefact report still records what happened. We don't panic
            // in a sink.
            if let Err(e) = self.flush() {
                tracing::error!("event flush failed: {e}");
            }
        }
    }
}

impl Drop for EventWriter<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            tracing::error!("event flush on drop failed: {e}");
        }
    }
}

/// DuckDB accepts ISO-8601; format UTC timestamps consistently.
fn fmt_ts(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

/// Crate-visible re-export for the query module.
pub(crate) fn fmt_ts_helper(ts: OffsetDateTime) -> String {
    fmt_ts(ts)
}

/// Case metadata for reporting.
#[derive(Debug, Clone)]
pub struct CaseMeta {
    pub case_id: String,
    pub name: String,
    pub examiner: Option<String>,
    pub created_utc: String,
    pub display_timezone: String,
}

/// One evidence item for the chain-of-custody report section.
#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub source_path: String,
    pub artefact_kind: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub id_method: String,
    pub id_confidence: f32,
}

/// One row of the per-file ingest log.
#[derive(Debug, Clone)]
pub struct IngestLogRow {
    pub source_path: String,
    pub artefact_kind: String,
    pub status: String,
    pub detail: Option<String>,
    pub records_read: u64,
    pub events_emitted: u64,
    pub warning_count: u32,
}

/// A triaged event joined to its event detail — for exporting analyst-validated
/// events that may not correspond to any rule detection.
#[derive(Debug, Clone)]
pub struct TriagedEvent {
    pub event_id: String,
    pub state: String,
    pub note: Option<String>,
    pub ts: String,
    pub host: Option<String>,
    pub action: String,
    pub artefact: String,
    pub message: String,
}

#[cfg(test)]
mod label_kv_tests {
    use super::*;

    #[test]
    fn labels_and_kv_round_trip_and_survive_reopen() {
        let dir = std::env::temp_dir().join(format!("fx-lbl-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.fxcase");
        let id = Uuid::new_v4().to_string();
        {
            let store = CaseStore::create(&path, "t", None, "UTC").unwrap();
            store.add_label(&id, "Lateral movement").unwrap();
            store.add_label(&id, "Lateral movement").unwrap(); // idempotent
            store.add_label(&id, "Patient zero").unwrap();
            store.set_triage(&id, "validated", Some("n")).unwrap();
            store.kv_set("ioc_hunt.list", "evil.example").unwrap();
            store.kv_set("ioc_hunt.list", "evil.example\n1.2.3.4").unwrap();
        }
        let store = CaseStore::open(&path).unwrap();
        let mut l = store.labels().unwrap();
        l.sort();
        assert_eq!(l, vec![(id.clone(), "Lateral movement".into()), (id.clone(), "Patient zero".into())]);
        // Labels never leak into triage, and triage never shows as a label.
        assert_eq!(store.triage_map().unwrap().len(), 1);
        store.remove_label(&id, "Patient zero").unwrap();
        assert_eq!(store.labels().unwrap().len(), 1);
        assert_eq!(store.kv_get("ioc_hunt.list").unwrap().as_deref(), Some("evil.example\n1.2.3.4"));
        assert_eq!(store.kv_get("missing").unwrap(), None);
    }

    /// The "Findings only" predicate and the host-fact queries must bind and
    /// run (DuckDB validates the SQL even on an empty case).
    #[test]
    fn findings_only_and_host_queries_run() {
        let dir = std::env::temp_dir().join(format!("fx-fo-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CaseStore::create(&dir.join("c.fxcase"), "t", None, "UTC").unwrap();
        let mut f = crate::TimelineFilter::default();
        f.flagged_only = true;
        assert_eq!(store.count_timeline(&f).unwrap(), 0);
        assert!(store.timeline(&f).unwrap().is_empty());
        assert!(store.host_facts().unwrap().is_empty());
        let (_, _, _, n, _) = store.collection_summary().unwrap();
        assert_eq!(n, 0);
    }
}

#[cfg(test)]
mod case_meta_tests {
    use super::*;

    /// Regression: case_meta() read the TIMESTAMP created_utc column as a
    /// String and failed, breaking the HTML case report on every case.
    #[test]
    fn case_meta_reads_created_timestamp() {
        let dir = std::env::temp_dir().join(format!("fx-meta-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.fxcase");
        let store = CaseStore::create(&path, "Meta test", Some("A. Analyst"), "UTC").unwrap();
        let meta = store.case_meta().expect("case_meta must succeed");
        assert_eq!(meta.name, "Meta test");
        assert_eq!(meta.examiner.as_deref(), Some("A. Analyst"));
        assert!(meta.created_utc.ends_with('Z') && meta.created_utc.contains('T'), "got {}", meta.created_utc);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
