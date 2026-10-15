//! SRUM (System Resource Usage Monitor) parser, reading `SRUDB.dat`.
//!
//! SRUDB.dat is an ESE database. Rather than hand-roll ESE B-tree walking (the
//! risk item flagged in planning), we lean on the `srum-parser` crate, which
//! handles the ESE layer and the per-table record decode, and expose the
//! records we care about on the normalized timeline.
//!
//! Why SRUM matters for financially-motivated actors: the network-usage table
//! records per-application bytes sent/received in ~hourly buckets, and those
//! rows survive after the offending process is gone. That makes SRUM one of
//! the few artefacts that can evidence *exfiltration volume* directly — a
//! process quietly pushing gigabytes out shows up here even if nothing else
//! caught it. App-usage adds foreground/background execution evidence.
//!
//! The app/user IDs in the usage tables are opaque integers; the ID-map table
//! resolves them to executable paths and user SIDs. We parse the ID map first
//! and resolve every emitted event, so a hunt can match on the real path/SID.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome,
    Parser, Principal, ProcessInfo, Provenance, TimestampKind,
};
use serde_json::json;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct SrumParser;

impl Parser for SrumParser {
    fn name(&self) -> &'static str {
        "srum"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Srum]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();
        let path = &artefact.path;

        // NOTE(perf): each `parse_*` call opens and parses SRUDB.dat
        // independently, so this parser opens the ESE file three times (id map,
        // network, app usage). SRUDB.dat is typically only tens of MB, so this
        // is acceptable for Phase 1; if it becomes a bottleneck, a shared ESE
        // handle would need to come from the srum-parser crate (its current
        // public API is per-table, path-based).

        // 1) Build the ID-map lookup first: integer id -> resolved name
        //    (executable path for app ids, SID string for user ids — SRUM
        //    stores both kinds in the same table, keyed by id).
        let id_map: HashMap<i32, String> = match srum_parser::parse_id_map(path) {
            Ok(entries) => entries.into_iter().map(|e| (e.id, e.name)).collect(),
            Err(e) => {
                // Without the map we can still emit, just with id:<n> tokens.
                outcome.warnings.push(fx_core::RecordWarning {
                    source_ref: Some("SruDbIdMapTable".into()),
                    message: format!("id map parse failed ({e}); ids left unresolved"),
                });
                HashMap::new()
            }
        };

        let resolve = |id: i32| -> Option<String> { id_map.get(&id).cloned() };

        // 2) Network usage — the exfil-relevant table.
        match srum_parser::parse_network_usage(path) {
            Ok(records) => {
                for r in records {
                    outcome.records_read += 1;
                    let Some(ts) = chrono_to_offsetdatetime(r.timestamp) else {
                        continue;
                    };
                    let app = resolve(r.app_id).unwrap_or_else(|| format!("app-id:{}", r.app_id));
                    let user_sid =
                        resolve(r.user_id).unwrap_or_else(|| format!("user-id:{}", r.user_id));

                    sink.emit(Event {
                        id: Uuid::new_v4(),
                        timestamp: ts,
                        timestamp_kind: TimestampKind::Recorded,
                        artefact: ArtefactKind::Srum,
                        action: "network.usage".into(),
                        host: None,
                        user: Principal {
                            sid: Some(user_sid.clone()),
                            ..Default::default()
                        },
                        process: Some(ProcessInfo {
                            path: Some(app.clone()),
                            ..Default::default()
                        }),
                        target: None,
                        // Byte volumes live in `raw` (NetworkInfo models IP/
                        // logon metadata, not byte counts); the exfil-totals
                        // query reads bytes_sent/recv straight from raw JSON.
                        network: None,
                        message: format!(
                            "SRUM net: {app} sent {} / recv {} bytes (user {user_sid})",
                            r.bytes_sent, r.bytes_recv
                        ),
                        provenance: Provenance {
                            evidence_id: artefact.evidence_id,
                            source_path: artefact.source_path.clone(),
                            parser: "srum".into(),
                            parser_version: env!("CARGO_PKG_VERSION").into(),
                            source_ref: Some(format!("network#{}", r.auto_inc_id)),
                        },
                        raw: json!({
                            "table": "network_usage",
                            "app": app,
                            "user": user_sid,
                            "bytes_sent": r.bytes_sent,
                            "bytes_recv": r.bytes_recv,
                            "app_id": r.app_id,
                            "user_id": r.user_id,
                        }),
                    });
                    outcome.events_emitted += 1;
                }
            }
            Err(e) => outcome.warnings.push(fx_core::RecordWarning {
                source_ref: Some("network_usage".into()),
                message: format!("network usage parse failed: {e}"),
            }),
        }

        // 3) Application usage — execution evidence (foreground/background).
        match srum_parser::parse_app_usage(path) {
            Ok(records) => {
                for r in records {
                    outcome.records_read += 1;
                    let Some(ts) = chrono_to_offsetdatetime(r.timestamp) else {
                        continue;
                    };
                    let app = resolve(r.app_id).unwrap_or_else(|| format!("app-id:{}", r.app_id));
                    let user_sid =
                        resolve(r.user_id).unwrap_or_else(|| format!("user-id:{}", r.user_id));

                    sink.emit(Event {
                        id: Uuid::new_v4(),
                        timestamp: ts,
                        timestamp_kind: TimestampKind::Executed,
                        artefact: ArtefactKind::Srum,
                        action: "execution.srum_app_usage".into(),
                        host: None,
                        user: Principal {
                            sid: Some(user_sid.clone()),
                            ..Default::default()
                        },
                        process: Some(ProcessInfo {
                            path: Some(app.clone()),
                            ..Default::default()
                        }),
                        target: None,
                        network: None,
                        message: format!("SRUM app usage: {app} (user {user_sid})"),
                        provenance: Provenance {
                            evidence_id: artefact.evidence_id,
                            source_path: artefact.source_path.clone(),
                            parser: "srum".into(),
                            parser_version: env!("CARGO_PKG_VERSION").into(),
                            source_ref: Some(format!("app_usage#{}", r.app_id)),
                        },
                        raw: json!({
                            "table": "app_usage",
                            "app": app,
                            "user": user_sid,
                            "app_id": r.app_id,
                            "user_id": r.user_id,
                        }),
                    });
                    outcome.events_emitted += 1;
                }
            }
            Err(e) => outcome.warnings.push(fx_core::RecordWarning {
                source_ref: Some("app_usage".into()),
                message: format!("app usage parse failed: {e}"),
            }),
        }

        if outcome.events_emitted == 0 && outcome.warnings.is_empty() {
            outcome.warnings.push(fx_core::RecordWarning {
                source_ref: None,
                message: "SRUDB.dat parsed but yielded no network/app-usage rows".into(),
            });
        }

        Ok(outcome)
    }
}

/// Bridge the `srum-core` records' `jiff::Timestamp` to our
/// `time::OffsetDateTime` via unix seconds. Returns None on an out-of-range
/// value.
fn chrono_to_offsetdatetime(dt: jiff::Timestamp) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(dt.as_second()).ok()
}
