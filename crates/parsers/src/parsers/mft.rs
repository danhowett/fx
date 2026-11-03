//! $MFT parser, built on the `mft` crate (Omer BenAmram).
//!
//! This is the artefact that most stresses the schema: one MFT record carries
//! multiple timestamps ($STANDARD_INFORMATION and $FILE_NAME each have M/A/C/B)
//! and one logical file. We emit a separate normalized [`Event`] per meaningful
//! timestamp, each with the right [`TimestampKind`], all sharing a `source_ref`
//! (the entry number) so the analyst can see they came from one record.
//!
//! Events come from $SI (that's what a standard timeline shows), one per
//! M / A / C / B time. Every event's `raw` carries all four $SI times and the
//! four $FILE_NAME ($FN) times of the entry, at full sub-second precision.
//!
//! $SI times are easy for tools to set; $FN times are not. So when an entry's
//! $SI Born is earlier than its $FN Born, fx emits one extra
//! `file.timestomp_suspected` event (timed at the $FN Born, the more reliable
//! creation time). Whole-second $SI times beside fractional $FN times are noted
//! as supporting evidence. The Windows app-package placeholder time
//! (26/10/1985 02:15:00) is excluded: it is set by the platform, not an attacker.

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
            source: std::io::Error::other(e.to_string()),
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

            // $SI and $FN timestamps from the entry's attributes.
            let (si, fn_) = extract_times(&entry);
            let times_json = json!({ "si": si.json(), "fn": fn_.json() });

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
                            "si": times_json["si"],
                            "fn": times_json["fn"],
                        }),
                    });
                    *count += 1;
                }
            };

            emit(
                sink,
                si.modified,
                TimestampKind::Modified,
                "modified",
                &mut outcome.events_emitted,
            );
            emit(
                sink,
                si.accessed,
                TimestampKind::Accessed,
                "accessed",
                &mut outcome.events_emitted,
            );
            emit(
                sink,
                si.changed,
                TimestampKind::MetadataChanged,
                "metadata_changed",
                &mut outcome.events_emitted,
            );
            emit(
                sink,
                si.born,
                TimestampKind::Created,
                "created",
                &mut outcome.events_emitted,
            );

            if let Some(why) = timestomp_signals(&si, &fn_) {
                let when = fn_.born.or(si.born).unwrap_or(fx_core::UNDATED);
                sink.emit(Event {
                    id: Uuid::new_v4(),
                    timestamp: when,
                    timestamp_kind: TimestampKind::Created,
                    artefact: ArtefactKind::Mft,
                    action: "file.timestomp_suspected".into(),
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
                    message: format!(
                        "Possible timestomping: {}: {path}  [ANTI-FORENSIC]",
                        why.join("; ")
                    ),
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
                        "si": times_json["si"],
                        "fn": times_json["fn"],
                        "signals": why,
                        "time_basis": "$FN Born (the $SI Born is earlier)",
                    }),
                });
                outcome.events_emitted += 1;
            }
        }

        Ok(outcome)
    }
}

/// The four M / A / C / B timestamps of one attribute ($SI or $FN), if present.
#[derive(Default)]
struct MacbTimes {
    modified: Option<OffsetDateTime>,
    accessed: Option<OffsetDateTime>,
    changed: Option<OffsetDateTime>,
    born: Option<OffsetDateTime>,
}

impl MacbTimes {
    fn json(&self) -> serde_json::Value {
        let f = |t: &Option<OffsetDateTime>| t.map(|t| t.to_string());
        json!({
            "modified": f(&self.modified),
            "accessed": f(&self.accessed),
            "changed":  f(&self.changed),
            "born":     f(&self.born),
        })
    }
    fn all(&self) -> [Option<OffsetDateTime>; 4] {
        [self.modified, self.accessed, self.changed, self.born]
    }
}

/// chrono -> time, keeping sub-seconds (whole seconds outside chrono's
/// nanosecond range).
fn conv(dt: chrono::DateTime<chrono::Utc>) -> Option<OffsetDateTime> {
    match dt.timestamp_nanos_opt() {
        Some(n) => OffsetDateTime::from_unix_timestamp_nanos(n as i128).ok(),
        None => OffsetDateTime::from_unix_timestamp(dt.timestamp()).ok(),
    }
}

/// $STANDARD_INFORMATION (AttrX10) and $FILE_NAME (AttrX30) times. An entry
/// can hold several $FN attributes (long and 8.3 names); the long (Win32 /
/// POSIX) name's is preferred.
fn extract_times(entry: &mft::entry::MftEntry) -> (MacbTimes, MacbTimes) {
    use mft::attribute::x30::FileNamespace;
    use mft::attribute::MftAttributeContent;
    let mut si = MacbTimes::default();
    let mut fname = MacbTimes::default();
    let mut fn_is_dos = true;
    for attr in entry.iter_attributes().flatten() {
        match attr.data {
            MftAttributeContent::AttrX10(a) => {
                si = MacbTimes {
                    modified: conv(a.modified),
                    accessed: conv(a.accessed),
                    changed: conv(a.mft_modified),
                    born: conv(a.created),
                };
            }
            MftAttributeContent::AttrX30(a) => {
                let dos = matches!(a.namespace, FileNamespace::DOS);
                if fname.born.is_none() || (fn_is_dos && !dos) {
                    fname = MacbTimes {
                        modified: conv(a.modified),
                        accessed: conv(a.accessed),
                        changed: conv(a.mft_modified),
                        born: conv(a.created),
                    };
                    fn_is_dos = dos;
                }
            }
            _ => {}
        }
    }
    (si, fname)
}

/// Timestomping signals for one entry, or None. The deciding signal is a $SI
/// Born earlier than the $FN Born (by more than a second); whole-second $SI
/// times beside fractional $FN times are added as supporting detail.
fn timestomp_signals(si: &MacbTimes, fname: &MacbTimes) -> Option<Vec<String>> {
    let (Some(sb), Some(fb)) = (si.born, fname.born) else {
        return None;
    };
    // Windows app packages carry this fixed placeholder time.
    let appx = time::macros::datetime!(1985-10-26 02:15:00 UTC);
    if si.all().contains(&Some(appx)) {
        return None;
    }
    if sb >= fb - time::Duration::seconds(1) {
        return None;
    }
    let fmt = |t: OffsetDateTime| {
        t.format(time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
        .unwrap_or_default()
    };
    let mut why = vec![format!(
        "$SI Born {} is earlier than $FN Born {}",
        fmt(sb),
        fmt(fb)
    )];
    let whole = |t: &Option<OffsetDateTime>| t.is_some_and(|t| t.nanosecond() == 0);
    if si.all().iter().filter(|t| t.is_some()).all(whole)
        && fname
            .all()
            .iter()
            .any(|t| t.is_some_and(|t| t.nanosecond() != 0))
    {
        why.push("$SI times have no sub-second part but $FN times do".into());
    }
    Some(why)
}

#[cfg(test)]
mod timestomp_tests {
    use super::*;
    use time::macros::datetime;

    fn t(born: OffsetDateTime) -> MacbTimes {
        MacbTimes {
            modified: Some(born),
            accessed: Some(born),
            changed: Some(born),
            born: Some(born),
        }
    }

    #[test]
    fn si_born_before_fn_born_is_flagged() {
        let si = t(datetime!(2019-01-01 00:00:00 UTC));
        let fname = t(datetime!(2026-10-14 11:23:42.123 UTC));
        let why = timestomp_signals(&si, &fname).expect("flagged");
        assert!(why[0].contains("earlier than $FN Born"));
        assert!(why.iter().any(|w| w.contains("sub-second")));
    }

    #[test]
    fn normal_and_appx_entries_are_not_flagged() {
        let same = t(datetime!(2026-10-14 11:23:42.5 UTC));
        assert!(timestomp_signals(&same, &same).is_none());
        // $SI later than $FN (normal: file modified after creation).
        let later = t(datetime!(2026-10-15 09:00:00.25 UTC));
        assert!(timestomp_signals(&later, &same).is_none());
        // App-package placeholder.
        let mut appx = t(datetime!(2026-10-14 11:23:42 UTC));
        appx.modified = Some(datetime!(1985-10-26 02:15:00 UTC));
        appx.born = Some(datetime!(1985-10-26 02:15:00 UTC));
        assert!(timestomp_signals(&appx, &same).is_none());
    }
}
