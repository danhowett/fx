//! Store-side support for the hunt engine.
//!
//! Three things the engine needs from the store:
//!   * stream every event as a full `fx_core::Event` (single-event matching runs
//!     in Rust against the rich event, not a projection);
//!   * execute a correlation rule's SQL and return generic rows;
//!   * persist and read back `Detection`s.
//!
//! Reconstructing `Event` from the row means round-tripping through the stored
//! `raw` JSON where a lifted column would lose fidelity — but for matching we
//! only need the fields `field_value` reads, so we rebuild those from columns
//! and attach `raw` verbatim.

use crate::{fmt_ts_helper, CaseStore, StoreError};
use fx_core::{
    ArtefactKind, Detection, DetectionEngine, Event, NetworkInfo, Principal, ProcessInfo,
    Provenance, Target, TimestampKind,
};
use time::OffsetDateTime;
use uuid::Uuid;

/// A generic correlation result row (see `Correlation::to_sql` contract).
pub struct CorrelationRow {
    pub group: String,
    pub first_ts: OffsetDateTime,
    pub event_ids: Vec<Uuid>,
    pub magnitude: i64,
}

impl CaseStore {
    /// Stream every event through a callback as a reconstructed `Event`. Used by
    /// the single-event rule matcher. Streaming (not collecting) keeps memory
    /// flat across multi-million-row cases.
    pub fn for_each_event(
        &self,
        mut f: impl FnMut(&Event),
    ) -> Result<(), StoreError> {
        let mut stmt = self.connection().prepare(
            "SELECT id, strftime(ts, '%Y-%m-%dT%H:%M:%S') AS ts, ts_kind, artefact, action, host,
                    user_name, user_sid, user_domain,
                    process_name, process_path, process_pid, command_line, process_sha1, parent_name,
                    target_path, target_value, src_ip, dst_ip, logon_type,
                    message, evidence_id, parser, parser_version, source_ref, raw
             FROM events",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let ev = row_to_event(r)?;
            f(&ev);
        }
        Ok(())
    }

    /// Run a correlation rule's SQL, mapping each row to a `CorrelationRow`.
    pub fn run_correlation(&self, sql: &str) -> Result<Vec<CorrelationRow>, StoreError> {
        let mut stmt = self.connection().prepare(sql)?;
        let rows = stmt
            .query_map([], |r| {
                let group: String = r.get(0)?;
                let first_ts: String = r.get(1)?;
                let ids: String = r.get(2)?;
                let magnitude: i64 = r.get::<_, Option<i64>>(3)?.unwrap_or(0);
                Ok((group, first_ts, ids, magnitude))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows
            .into_iter()
            .map(|(group, first_ts, ids, magnitude)| CorrelationRow {
                group,
                first_ts: parse_ts(&first_ts),
                event_ids: ids
                    .split(',')
                    .filter_map(|s| Uuid::parse_str(s.trim()).ok())
                    .collect(),
                magnitude,
            })
            .collect())
    }

    /// Persist detections (replacing any prior run's results for a clean view).
    pub fn write_detections(&self, dets: &[Detection]) -> Result<(), StoreError> {
        self.connection().execute_batch("DELETE FROM detections")?;
        let now = OffsetDateTime::now_utc();
        self.connection().execute_batch("BEGIN TRANSACTION")?;
        {
            let mut stmt = self.connection().prepare(
                "INSERT INTO detections
                    (id, rule_id, title, severity, attack, summary, event_ids, ts, host, engine, detected_utc)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            )?;
            for d in dets {
                stmt.execute(duckdb::params![
                    d.id.to_string(),
                    d.rule_id,
                    d.title,
                    d.severity.as_str(),
                    d.attack.join(","),
                    d.summary,
                    d.event_ids.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(","),
                    fmt_ts_helper(d.timestamp),
                    d.host,
                    match d.engine { DetectionEngine::SingleEvent => "single_event", DetectionEngine::Correlation => "correlation" },
                    fmt_ts_helper(now),
                ])?;
            }
        }
        self.connection().execute_batch("COMMIT")?;
        Ok(())
    }

    /// Read detections back, worst severity first, for the GUI hunt view.
    pub fn detections(&self) -> Result<Vec<DetectionRow>, StoreError> {
        let mut stmt = self.connection().prepare(
            "SELECT rule_id, title, severity, attack, summary, event_ids,
                    strftime(ts, '%Y-%m-%dT%H:%M:%S') AS ts, host, engine
             FROM detections
             ORDER BY CASE severity
                WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                WHEN 'low' THEN 2 ELSE 1 END DESC, ts",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(DetectionRow {
                    rule_id: r.get(0)?,
                    title: r.get(1)?,
                    severity: r.get(2)?,
                    attack: r.get::<_, String>(3)?,
                    summary: r.get(4)?,
                    event_ids: r.get::<_, String>(5)?,
                    ts: r.get(6)?,
                    host: r.get(7)?,
                    engine: r.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// ATT&CK technique -> detection count, for the heatmap.
    pub fn attack_coverage(&self) -> Result<Vec<(String, u64)>, StoreError> {
        // Flatten the comma-separated attack column in Rust; technique counts
        // are small, so read the rows and tally.
        let mut stmt = self
            .connection()
            .prepare("SELECT attack FROM detections WHERE attack <> ''")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
        for row in rows {
            for tech in row.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                *counts.entry(tech.to_string()).or_default() += 1;
            }
        }
        let mut v: Vec<_> = counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        Ok(v)
    }
}

/// A detection as the GUI reads it (flat strings).
#[derive(Debug, Clone)]
pub struct DetectionRow {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub attack: String,
    pub summary: String,
    pub event_ids: String,
    pub ts: String,
    pub host: Option<String>,
    pub engine: String,
}

fn parse_ts(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .or_else(|_| {
            // DuckDB may hand back a space-separated naive timestamp; try that.
            let iso = s.replacen(' ', "T", 1);
            OffsetDateTime::parse(
                &format!("{iso}Z"),
                &time::format_description::well_known::Rfc3339,
            )
        })
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Reconstruct a normalized `Event` from a full events-table row.
fn row_to_event(r: &duckdb::Row) -> Result<Event, StoreError> {
    let artefact = parse_artefact(&r.get::<_, String>(3)?);
    let raw: String = r.get(25)?;
    Ok(Event {
        id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::nil()),
        timestamp: parse_ts(&r.get::<_, String>(1)?),
        timestamp_kind: parse_kind(&r.get::<_, String>(2)?),
        artefact,
        action: r.get(4)?,
        host: r.get(5)?,
        user: Principal {
            name: r.get(6)?,
            sid: r.get(7)?,
            domain: r.get(8)?,
        },
        process: Some(ProcessInfo {
            name: r.get(9)?,
            path: r.get(10)?,
            pid: r.get::<_, Option<i64>>(11)?.map(|v| v as u32),
            command_line: r.get(12)?,
            hash_sha1: r.get(13)?,
            parent_name: r.get(14)?,
            parent_pid: None,
        }),
        target: Some(Target {
            path: r.get(15)?,
            value_name: r.get(16)?,
            hash_sha1: None,
            size: None,
        }),
        network: Some(NetworkInfo {
            source_ip: r.get(17)?,
            dest_ip: r.get(18)?,
            logon_type: r.get::<_, Option<i64>>(19)?.map(|v| v as u8),
        }),
        message: r.get(20)?,
        provenance: Provenance {
            evidence_id: Uuid::parse_str(&r.get::<_, String>(21)?).unwrap_or_else(|_| Uuid::nil()),
            source_path: String::new(),
            parser: r.get(22)?,
            parser_version: r.get(23)?,
            source_ref: r.get(24)?,
        },
        raw: serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null),
    })
}

fn parse_kind(s: &str) -> TimestampKind {
    match s {
        "Created" => TimestampKind::Created,
        "Modified" => TimestampKind::Modified,
        "MetadataChanged" => TimestampKind::MetadataChanged,
        "Accessed" => TimestampKind::Accessed,
        "Executed" => TimestampKind::Executed,
        "Logged" => TimestampKind::Logged,
        "Logon" => TimestampKind::Logon,
        _ => TimestampKind::Recorded,
    }
}

fn parse_artefact(s: &str) -> ArtefactKind {
    // Mirror of the Debug formatting used on write. Unknown -> Unclassified.
    match s {
        "Evtx" => ArtefactKind::Evtx,
        "Mft" => ArtefactKind::Mft,
        "UsnJrnl" => ArtefactKind::UsnJrnl,
        "LogFile" => ArtefactKind::LogFile,
        "Prefetch" => ArtefactKind::Prefetch,
        "Amcache" => ArtefactKind::Amcache,
        "ShimCache" => ArtefactKind::ShimCache,
        "RegistryRun" => ArtefactKind::RegistryRun,
        "RegistryService" => ArtefactKind::RegistryService,
        "UserAssist" => ArtefactKind::UserAssist,
        "ShellBags" => ArtefactKind::ShellBags,
        "BamDam" => ArtefactKind::BamDam,
        "Srum" => ArtefactKind::Srum,
        "ScheduledTask" => ArtefactKind::ScheduledTask,
        "Lnk" => ArtefactKind::Lnk,
        "JumpList" => ArtefactKind::JumpList,
        "Recycle" => ArtefactKind::Recycle,
        "BrowserHistory" => ArtefactKind::BrowserHistory,
        "RegistryGeneric" => ArtefactKind::RegistryGeneric,
        _ => ArtefactKind::Unclassified,
    }
}
