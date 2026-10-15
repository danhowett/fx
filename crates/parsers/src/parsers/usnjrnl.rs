//! $UsnJrnl:$J (USN change journal) parser, built on the `usnjrnl` crate.
//!
//! The USN journal records every file-level change on an NTFS volume — create,
//! delete, rename, data-overwrite, stream changes — each with a reason flag and
//! a timestamp. For financially-motivated intrusions this is one of the richest
//! trails available:
//!   * staging: files created/written in Temp/Downloads before exfil
//!   * anti-forensics: mass renames/deletes (ransomware), secure-delete tools
//!   * tooling drop: attacker binaries appearing then being deleted
//!
//! The `usnjrnl` crate handles the two annoying realities of $J files — they're
//! sparse (mostly NUL padding) and sometimes gzipped — so we iterate records.
//!
//! API-surface note: the crate's public record accessors that we rely on across
//! versions are `data.filename()` and `data.reasons()`. Other per-record fields
//! (timestamp, MFT file reference) are read out of the record's serde_json
//! representation, so we don't hard-depend on struct field names that vary by
//! record version (V2/V3). All the version-fragile access is isolated in
//! `record_json` + the field reads in `parse`, the one place to adjust on first
//! build.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Provenance, Target, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct UsnJrnlParser;

impl Parser for UsnJrnlParser {
    fn name(&self) -> &'static str {
        "usnjrnl"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::UsnJrnl]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();

        let reader = usnjrnl::UsnJrnlReader::from(&artefact.path).map_err(|e| {
            ParseError::Malformed(format!("usnjrnl open: {e:?}"))
        })?;

        for entry in reader.into_iter() {
            outcome.records_read += 1;
            let record = match entry {
                Ok(r) => r,
                Err(e) => {
                    outcome.warnings.push(fx_core::RecordWarning {
                        source_ref: None,
                        message: format!("usn record error: {e:?}"),
                    });
                    continue;
                }
            };

            // Real usnjrnl 0.4 accessors: timestamp() -> &DateTime<Utc>,
            // filename() -> &str, reason() -> &UsnReason (Display).
            let filename = record.data.filename().to_string();
            let reasons = record.data.reason().to_string();
            let ts = OffsetDateTime::from_unix_timestamp(record.data.timestamp().timestamp())
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);

            let action = classify_reason(&reasons);
            let anti_forensic = is_anti_forensic(&reasons, &filename);

            let mut message = format!("USN {}: {}", short_reasons(&reasons), filename);
            if anti_forensic {
                message.push_str("  [ANTI-FORENSIC]");
            }

            sink.emit(Event {
                id: Uuid::new_v4(),
                timestamp: ts,
                timestamp_kind: TimestampKind::Recorded,
                artefact: ArtefactKind::UsnJrnl,
                action: action.to_string(),
                host: None,
                user: Default::default(),
                process: None,
                target: Some(Target {
                    path: Some(filename.clone()),
                    ..Default::default()
                }),
                network: None,
                message,
                provenance: Provenance {
                    evidence_id: artefact.evidence_id,
                    source_path: artefact.source_path.clone(),
                    parser: "usnjrnl".into(),
                    parser_version: env!("CARGO_PKG_VERSION").into(),
                    source_ref: None,
                },
                raw: json!({
                    "filename": filename,
                    "reasons": reasons,
                    "anti_forensic": anti_forensic,
                }),
            });
            outcome.events_emitted += 1;
        }

        Ok(outcome)
    }
}

/// Map the USN reason flags string to a normalized action. The `reasons()`
/// accessor returns a human string of the set flags (e.g. "FILE_CREATE",
/// "DATA_OVERWRITE|CLOSE"); we key off the dominant reason.
fn classify_reason(reasons: &str) -> &'static str {
    let r = reasons.to_ascii_uppercase();
    if r.contains("FILE_DELETE") {
        "file.delete"
    } else if r.contains("RENAME_NEW_NAME") {
        "file.rename"
    } else if r.contains("RENAME_OLD_NAME") {
        "file.rename_from"
    } else if r.contains("FILE_CREATE") {
        "file.create"
    } else if r.contains("DATA_OVERWRITE") || r.contains("DATA_EXTEND") || r.contains("DATA_TRUNCATION") {
        "file.data_change"
    } else if r.contains("SECURITY_CHANGE") {
        "file.security_change"
    } else {
        "file.change"
    }
}

/// Compact reason display for the message line.
fn short_reasons(reasons: &str) -> String {
    reasons.replace("USN_REASON_", "")
}

/// Anti-forensics heuristics on a single record. These are intentionally
/// conservative single-record signals; the Week-4 hunt engine will add the
/// windowed "mass rename/delete in N seconds" ransomware detection that needs
/// cross-record aggregation.
fn is_anti_forensic(reasons: &str, filename: &str) -> bool {
    let f = filename.to_ascii_lowercase();
    let r = reasons.to_ascii_uppercase();

    // Known secure-delete / cleanup tool artefacts (SDelete rename pattern uses
    // AAAA... temp names; CCleaner and others leave ZZZZ patterns).
    let sdelete_pattern = f.starts_with("aaaaaaaa") || f.chars().all(|c| c == 'z' || c == '.');

    // Ransomware-adjacent: creation of files with common ransom extensions.
    const RANSOM_EXT: &[&str] = &[
        ".lockbit", ".conti", ".ryk", ".ryuk", ".locky", ".crypt", ".encrypted",
        ".enc", ".readme", ".onion",
    ];
    let ransom_ext = RANSOM_EXT.iter().any(|e| f.ends_with(e));

    (sdelete_pattern && r.contains("RENAME")) || ransom_ext
}
