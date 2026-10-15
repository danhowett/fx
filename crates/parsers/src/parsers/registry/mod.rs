//! Registry parser, built on `notatin` 1.x (Stroz Friedberg).
//!
//! notatin gives us a flat iterator over every key in a hive, each key
//! carrying its full `path` and a `value_iter()`. So rather than navigating a
//! tree, we make ONE pass over the hive and route each key by its path to a
//! set of *extractors*, each responsible for one registry-derived artefact
//! (Run keys, Services, ShimCache, UserAssist, BAM/DAM, RDP...).
//!
//! Each extractor emits normalized events with the right ArtefactKind, so a
//! single SYSTEM or NTUSER hive fans out into services, execution evidence,
//! persistence, etc. — all on the same timeline.
//!
//! The hive's own key LastWrite time is the timestamp for most registry
//! events (persistence, services); artefacts that encode their own timestamps
//! in value data (ShimCache, UserAssist, BAM) override it with the decoded
//! time. Where a key has no meaningful time we fall back to LastWrite and mark
//! the TimestampKind accordingly.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Principal, Provenance, Target, TimestampKind,
};
use notatin::{
    cell_key_node::CellKeyNode,
    parser_builder::ParserBuilder,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

mod extract;

#[derive(Default)]
pub struct RegistryParser;

impl Parser for RegistryParser {
    fn name(&self) -> &'static str {
        "registry"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        // One parser, many emitted artefact kinds. It's registered for the
        // generic registry hive kind and for AmCache (also a hive). The
        // *emitted* events carry more specific kinds (RegistryRun, etc.).
        &[ArtefactKind::RegistryGeneric, ArtefactKind::Amcache]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();

        // Look for sibling transaction logs (.LOG1/.LOG2) next to the hive and
        // apply them — dirty hives are the norm in triage collections, and
        // skipping logs means missing the most recent (often most relevant)
        // changes.
        let logs = sibling_transaction_logs(artefact);

        // notatin's ParserBuilder methods take &mut self and return &mut Self,
        // so we mutate a binding in place rather than reassigning.
        // notatin's ParserBuilder methods require owned, 'static paths
        // (`AsRef<Path> + 'static`), so hand them owned PathBufs, not borrows.
        let mut builder = ParserBuilder::from_path(artefact.path.clone());
        builder.recover_deleted(true);
        for log in logs {
            builder.with_transaction_log(log);
        }
        // Recovery of deleted keys/values is valuable for hunting (attackers
        // clean up), but slower; default on for triage depth.
        let parser = builder
            .build()
            .map_err(|e| ParseError::Malformed(format!("notatin build: {e}")))?;

        let extractors = extract::default_extractors();

        let ctx = Ctx {
            evidence_id: artefact.evidence_id,
            source_path: artefact.source_path.clone(),
        };

        // notatin iterates keys via a ParserIterator constructed from the parser
        // (its Iterator impl yields owned CellKeyNode items).
        use notatin::parser::ParserIterator;
        for key in ParserIterator::new(&parser).iter() {
            outcome.records_read += 1;
            let path = key.path.clone();
            let lastwrite = key_lastwrite(&key);

            for ex in &extractors {
                if ex.matches(&path) {
                    ex.extract(&key, &path, lastwrite, &ctx, sink, &mut outcome);
                }
            }
        }

        Ok(outcome)
    }
}

/// Shared context passed to every extractor for building provenance.
pub(crate) struct Ctx {
    pub evidence_id: Uuid,
    pub source_path: String,
}

impl Ctx {
    pub fn provenance(&self, key_path: &str, value_name: Option<&str>) -> Provenance {
        let source_ref = match value_name {
            Some(v) => format!("{key_path}\\{v}"),
            None => key_path.to_string(),
        };
        Provenance {
            evidence_id: self.evidence_id,
            source_path: self.source_path.clone(),
            parser: "registry".into(),
            parser_version: env!("CARGO_PKG_VERSION").into(),
            source_ref: Some(source_ref),
        }
    }
}

/// Helper used by extractors to build a standard registry event.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_event(
    ctx: &Ctx,
    artefact: ArtefactKind,
    ts: OffsetDateTime,
    ts_kind: TimestampKind,
    action: &str,
    key_path: &str,
    value_name: Option<&str>,
    target_path: Option<String>,
    user: Principal,
    message: String,
    raw: serde_json::Value,
) -> Event {
    Event {
        id: Uuid::new_v4(),
        timestamp: ts,
        timestamp_kind: ts_kind,
        artefact,
        action: action.to_string(),
        host: None,
        user,
        process: None,
        target: target_path.map(|p| Target {
            path: Some(p),
            value_name: value_name.map(str::to_string),
            hash_sha1: None,
            size: None,
        }),
        network: None,
        message,
        provenance: ctx.provenance(key_path, value_name),
        raw,
    }
}

/// Extract a key's LastWrite time. In notatin 1.x this is a raw `u64` FILETIME
/// exposed through the key's `detail` enum; we convert via the shared helper.
/// Keys with an unset/zero time fall back to the Unix epoch (they'll sort to
/// the start of the timeline, clearly distinguishable as "no time").
fn key_lastwrite(key: &CellKeyNode) -> OffsetDateTime {
    let ft: u64 = key.detail.last_key_written_date_and_time();
    fx_core::filetime_to_datetime(ft).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Find `<hive>.LOG1` / `.LOG2` (case-insensitive) beside the hive file.
fn sibling_transaction_logs(artefact: &IdentifiedArtefact) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Some(dir) = artefact.path.parent() else {
        return out;
    };
    let Some(stem) = artefact.path.file_name().and_then(|s| s.to_str()) else {
        return out;
    };
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                let lower = name.to_ascii_lowercase();
                let stem_lower = stem.to_ascii_lowercase();
                if lower == format!("{stem_lower}.log1") || lower == format!("{stem_lower}.log2") {
                    out.push(e.path());
                }
            }
        }
    }
    // LOG1 before LOG2.
    out.sort();
    out
}

/// Pull a single value's content as a display string, by name.
///
/// notatin 1.0.1: a `CellKeyValue` exposes its name via `detail.value_name()`
/// and its decoded content via the inherent `get_content() -> (CellValue,
/// Option<Logs>)`. `CellValue` implements `Display` (REG_SZ etc. render as text;
/// REG_BINARY as hex), and `CellValue::Binary(Vec<u8>)` carries raw bytes. All
/// notatin value access is funnelled through the three helpers below.
pub(crate) fn value_string(key: &CellKeyNode, name: &str) -> Option<String> {
    key.value_iter().find_map(|v| {
        if value_name(&v).eq_ignore_ascii_case(name) {
            Some(value_display(&v))
        } else {
            None
        }
    })
}

/// Iterate all (name, display-string) pairs under a key.
pub(crate) fn value_pairs(key: &CellKeyNode) -> Vec<(String, String)> {
    key.value_iter()
        .map(|v| (value_name(&v), value_display(&v)))
        .collect()
}

/// The value's name.
pub(crate) fn value_name(v: &notatin::cell_key_value::CellKeyValue) -> String {
    v.detail.value_name()
}

/// The value's decoded content as a display string (via CellValue's Display).
pub(crate) fn value_display(v: &notatin::cell_key_value::CellKeyValue) -> String {
    let (cell_value, _logs) = v.get_content();
    cell_value.to_string()
}

/// The value's raw bytes, for artefacts (ShellBags shell-items) that decode a
/// REG_BINARY blob. `get_content` yields `CellValue::Binary(bytes)` for binary
/// values; anything else yields no bytes.
pub(crate) fn value_bytes(v: &notatin::cell_key_value::CellKeyValue) -> Vec<u8> {
    use notatin::cell_value::CellValue;
    let (cell_value, _logs) = v.get_content();
    match cell_value {
        CellValue::Binary(b) => b,
        _ => Vec::new(),
    }
}

/// Debug JSON of a key's values, for the `raw` field.
pub(crate) fn key_raw(path: &str, key: &CellKeyNode) -> serde_json::Value {
    json!({
        "key": path,
        "values": value_pairs(key).into_iter().collect::<std::collections::BTreeMap<_,_>>(),
    })
}
