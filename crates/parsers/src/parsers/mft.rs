//! $MFT parser, built on the `mft` crate (Omer BenAmram).
//!
//! This is the artefact that most stresses the schema: one MFT record carries
//! multiple timestamps ($STANDARD_INFORMATION and $FILE_NAME each have M/A/C/B)
//! and one logical file. We emit a separate normalized [`Event`] per meaningful
//! timestamp, each with the right [`TimestampKind`], all sharing a `source_ref`
//! (the entry number) so the analyst can see they came from one record.
//!
//! Emitting from $SI by default (that's what a standard timeline shows); $FN
//! times are kept in `raw` and can be surfaced for timestomp detection later —
//! $SI vs $FN mismatch is a classic anti-forensics signal we'll hunt on.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Provenance, Target, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct MftParser;

impl Parser for MftParser {
    fn name(&self) -> &'static str {
        "mft"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Mft]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();

        let mut parser = mft::MftParser::from_path(&artefact.path).map_err(|e| ParseError::Io {
            path: artefact.path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
        })?;

        // Collect entries first (releasing the &mut borrow the iterator holds),
        // so we can call get_full_path_for_entry (which also needs &mut) inside
        // the loop without a double mutable borrow.
        let entries: Vec<_> = parser.iter_entries().collect();
        for entry_result in entries {
            outcome.records_read += 1;
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    outcome.warnings.push(fx_core::RecordWarning {
                        source_ref: None,
                        message: format!("mft entry error: {e}"),
                    });
                    continue;
                }
            };

            // Best-effort full path for the entry.
            let path = parser
                .get_full_path_for_entry(&entry)
                .ok()
                .flatten()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();

            // Pull $SI timestamps from the entry's attributes.
            let si = extract_si_times(&entry);

            let emit = |sink: &mut dyn EventSink,
                        ts: Option<OffsetDateTime>,
                        kind: TimestampKind,
                        label: &str,
                        count: &mut u64| {
                if let Some(ts) = ts {
                    sink.emit(Event {
                        id: Uuid::new_v4(),
                        timestamp: ts,
                        timestamp_kind: kind,
                        artefact: ArtefactKind::Mft,
                        action: format!("file.{label}"),
                        host: None,
                        user: Default::default(),
                        process: None,
                        target: Some(Target {
                            path: Some(path.clone()),
                            value_name: None,
                            hash_sha1: None,
                            size: None,
                        }),
                        network: None,
                        message: format!("$SI {label}: {path}"),
                        provenance: Provenance {
                            evidence_id: artefact.evidence_id,
                            source_path: artefact.source_path.clone(),
                            parser: "mft".into(),
                            parser_version: env!("CARGO_PKG_VERSION").into(),
                            source_ref: Some(format!("entry{}", entry.header.record_number)),
                        },
                        raw: json!({
                            "entry": entry.header.record_number,
                            "path": path,
                            "si": si.debug(),
                        }),
                    });
                    *count += 1;
                }
            };

            emit(sink, si.modified, TimestampKind::Modified, "modified", &mut outcome.events_emitted);
            emit(sink, si.accessed, TimestampKind::Accessed, "accessed", &mut outcome.events_emitted);
            emit(sink, si.changed, TimestampKind::MetadataChanged, "metadata_changed", &mut outcome.events_emitted);
            emit(sink, si.born, TimestampKind::Created, "created", &mut outcome.events_emitted);
        }

        Ok(outcome)
    }
}

/// The four $SI timestamps, if present.
#[derive(Default)]
struct SiTimes {
    modified: Option<OffsetDateTime>,
    accessed: Option<OffsetDateTime>,
    changed: Option<OffsetDateTime>,
    born: Option<OffsetDateTime>,
}

impl SiTimes {
    fn debug(&self) -> serde_json::Value {
        json!({
            "modified": self.modified.map(|t| t.to_string()),
            "accessed": self.accessed.map(|t| t.to_string()),
            "changed":  self.changed.map(|t| t.to_string()),
            "born":     self.born.map(|t| t.to_string()),
        })
    }
}

/// Pull $STANDARD_INFORMATION times out of the entry. mft 0.6 exposes
/// attributes as `MftAttributeContent`; the $SI variant is `AttrX10`, whose
/// times are `chrono::DateTime<Utc>` — bridged to `time::OffsetDateTime` via
/// unix seconds.
fn extract_si_times(entry: &mft::entry::MftEntry) -> SiTimes {
    use mft::attribute::MftAttributeContent;
    let conv = |dt: chrono::DateTime<chrono::Utc>| -> Option<OffsetDateTime> {
        OffsetDateTime::from_unix_timestamp(dt.timestamp()).ok()
    };
    let mut out = SiTimes::default();
    for attr in entry.iter_attributes().flatten() {
        if let MftAttributeContent::AttrX10(si) = attr.data {
            out.modified = conv(si.modified);
            out.accessed = conv(si.accessed);
            out.changed = conv(si.mft_modified);
            out.born = conv(si.created);
            break;
        }
    }
    out
}
