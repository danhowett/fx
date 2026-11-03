//! `fx-ingest` — the orchestrator.
//!
//! Wires the pipeline end to end and persists into a case store:
//!
//!   scan_collection (identify)
//!        -> register + hash evidence           (fx-store)
//!        -> ParserRegistry dispatch (parse)     (fx-parsers)
//!        -> stream Events into DuckDB           (fx-store EventWriter)
//!        -> record per-artefact ingest report   (fx-store)
//!
//! Guarantees preserved from the pure pipeline:
//!   * per-artefact fault isolation — one bad artefact never aborts the case
//!   * nothing silently dropped — unclassified files are registered too
//!   * full provenance — evidence is hashed and referenced by every event

use fx_core::{EventSink, IdentifiedArtefact};
use fx_identify::{scan_collection, CollectionScan};
use fx_parsers::ParserRegistry;
use fx_store::CaseStore;
use std::path::Path;

/// Per-artefact result of the ingest run (mirrors what's persisted to
/// `ingest_report`, returned in-memory for immediate GUI feedback).
pub struct ArtefactReport {
    pub source_path: String,
    pub artefact: fx_core::ArtefactKind,
    pub status: ArtefactStatus,
    pub records_read: u64,
    pub events_emitted: u64,
    pub warnings: Vec<String>,
}

pub enum ArtefactStatus {
    Parsed,
    Unsupported,
    Failed(String),
    /// Byte-identical (same SHA-256) to a file already parsed in this ingest;
    /// hashed and recorded as evidence, but not parsed again, so its events
    /// aren't duplicated on the timeline. Holds the original's path.
    Duplicate(String),
    /// Not parsed on its own, but its content was used by another artefact —
    /// a registry transaction log (.LOG1/.LOG2) replayed into its hive.
    /// Holds a short explanation.
    Applied(String),
    /// Unsupported, with a reason worth showing (e.g. a transaction log whose
    /// hive isn't in the collection). Shown as "unsupported".
    UnsupportedBecause(String),
}

impl ArtefactStatus {
    fn label(&self) -> &'static str {
        match self {
            ArtefactStatus::Parsed => "parsed",
            ArtefactStatus::Unsupported => "unsupported",
            ArtefactStatus::Failed(_) => "failed",
            ArtefactStatus::Duplicate(_) => "duplicate",
            ArtefactStatus::Applied(_) => "applied",
            ArtefactStatus::UnsupportedBecause(_) => "unsupported",
        }
    }
    fn detail(&self) -> Option<String> {
        match self {
            ArtefactStatus::Failed(m) => Some(m.clone()),
            ArtefactStatus::Duplicate(orig) => {
                Some(format!("identical (SHA-256) to {orig}; not parsed again"))
            }
            ArtefactStatus::Applied(why) | ArtefactStatus::UnsupportedBecause(why) => {
                Some(why.clone())
            }
            _ => None,
        }
    }
}

/// One artefact kind found by [`preview_collection`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct PreviewGroup {
    /// ArtefactKind name, as the rail shows it (e.g. "Evtx").
    pub kind: String,
    pub files: usize,
    pub bytes: u64,
    /// A few of the files, collection-relative, for a quick sanity check.
    pub examples: Vec<String>,
}

/// What fx would ingest from a folder, without ingesting it: shown in the
/// New case window so the analyst can check they picked the right folder.
/// Reads only file headers (the same identification ingest does); no hashing,
/// no parsing, nothing written.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CollectionPreview {
    pub total_files: usize,
    pub total_bytes: u64,
    pub groups: Vec<PreviewGroup>,
    /// Registry .LOG1/.LOG2/.LOG files (replayed into their hive, not parsed alone).
    pub transaction_logs: usize,
    /// Files fx doesn't recognise: still hashed and kept as evidence.
    pub unrecognised: usize,
    /// Collection tool, if one was recognised (e.g. KAPE).
    pub profile: Option<String>,
    /// Host name the collection tool recorded, if any.
    pub host_hint: Option<String>,
    pub errors: Vec<String>,
}

pub fn preview_collection(root: &Path) -> CollectionPreview {
    let scan = scan_collection(root);
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let mut groups: std::collections::BTreeMap<String, PreviewGroup> = Default::default();
    let (mut transaction_logs, mut unrecognised, mut total_bytes) = (0usize, 0usize, 0u64);
    let mut host_hint = None;
    for a in &scan.artefacts {
        let bytes = size(&a.path);
        total_bytes += bytes;
        if host_hint.is_none() {
            host_hint = a
                .profile_hint
                .as_ref()
                .and_then(|h| h.asserted_host.clone())
                .filter(|h| !h.trim().is_empty());
        }
        if a.artefact == fx_core::ArtefactKind::Unclassified {
            if transaction_log_status(a).is_some() {
                transaction_logs += 1;
            } else {
                unrecognised += 1;
            }
            continue;
        }
        let kind = format!("{:?}", a.artefact);
        let g = groups.entry(kind.clone()).or_insert_with(|| PreviewGroup {
            kind,
            files: 0,
            bytes: 0,
            examples: Vec::new(),
        });
        g.files += 1;
        g.bytes += bytes;
        if g.examples.len() < 3 {
            g.examples.push(a.source_path.clone());
        }
    }
    for u in &scan.unclassified {
        unrecognised += 1;
        total_bytes += size(&u.path);
    }
    let mut groups: Vec<PreviewGroup> = groups.into_values().collect();
    groups.sort_by(|a, b| b.files.cmp(&a.files).then(a.kind.cmp(&b.kind)));
    CollectionPreview {
        total_files: scan.artefacts.len() + scan.unclassified.len(),
        total_bytes,
        groups,
        transaction_logs,
        unrecognised,
        profile: scan.profile,
        host_hint,
        errors: scan.errors.into_iter().take(20).collect(),
    }
}

/// What a registry transaction log in the collection means for the case.
/// The registry parser replays `<hive>.LOG1` / `<hive>.LOG2` from the hive's
/// own folder, so a log whose hive sits beside it has already been used.
/// Returns `None` for anything that isn't a registry transaction log.
fn transaction_log_status(artefact: &IdentifiedArtefact) -> Option<ArtefactStatus> {
    if artefact.container != fx_core::ContainerFormat::RegistryHive {
        return None;
    }
    let name = artefact.path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    let (hive_name, ext) = lower.rsplit_once('.')?;
    match ext {
        "log1" | "log2" => {
            let dir = artefact.path.parent()?;
            let hive = std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
                let n = e.file_name().to_str()?.to_string();
                (n.to_ascii_lowercase() == hive_name && e.path().is_file()).then_some(n)
            });
            Some(match hive {
                Some(h) => ArtefactStatus::Applied(format!("transaction log replayed into {h}")),
                None => ArtefactStatus::UnsupportedBecause(format!(
                    "transaction log, but its hive ({hive_name}) isn't in the collection"
                )),
            })
        }
        "log" => Some(ArtefactStatus::UnsupportedBecause(
            "legacy transaction log (.LOG): not replayed".into(),
        )),
        _ => None,
    }
}

pub struct IngestReport {
    pub profile: Option<String>,
    pub artefacts: Vec<ArtefactReport>,
    pub unclassified: usize,
    pub scan_errors: Vec<String>,
    pub total_events: u64,
    /// True when the user cancelled part-way; artefacts already parsed are kept.
    pub cancelled: bool,
    /// The machine this collection came from (see `fx_store::hosts`).
    pub host: Option<String>,
    /// True when that host was already in the case (a re-collection).
    pub merged_host: bool,
    /// Set when the collection was refused (e.g. already in the case); nothing
    /// was ingested.
    pub refused: Option<String>,
}

/// Run the full pipeline over an extracted collection directory, persisting
/// everything into `store`. Works for a new case and for adding another
/// collection (another host) to an existing one.
pub fn ingest_into_store(
    root: &Path,
    registry: &ParserRegistry,
    store: &CaseStore,
) -> IngestReport {
    ingest_collection_as(root, registry, store, None)
}

/// As [`ingest_into_store`], with an analyst-chosen host name (otherwise it
/// is read from the collection).
pub fn ingest_collection_as(
    root: &Path,
    registry: &ParserRegistry,
    store: &CaseStore,
    host_name: Option<&str>,
) -> IngestReport {
    use fx_core::progress;
    let mut report = IngestReport {
        profile: None,
        artefacts: Vec::new(),
        unclassified: 0,
        scan_errors: Vec::new(),
        total_events: 0,
        cancelled: false,
        host: None,
        merged_host: false,
        refused: None,
    };
    // An older single-host case gets its collection record first, so the new
    // collection's rows aren't claimed by it.
    if let Err(e) = store.ensure_legacy_collection() {
        report
            .scan_errors
            .push(format!("prepare case for another host: {e}"));
    }
    let collection = match store.begin_collection(&root.display().to_string()) {
        Ok(id) => id,
        Err(e) => {
            report.refused = Some(e.to_string());
            return report;
        }
    };

    progress::set_phase("Scanning collection");
    let scan: CollectionScan = scan_collection(root);
    report.profile = scan.profile.clone();
    report.artefacts = Vec::with_capacity(scan.artefacts.len());
    report.unclassified = scan.unclassified.len();
    report.scan_errors.extend(scan.errors.clone());

    // Register (and hash) unclassified files first — they're evidence too, and
    // recording them is the "nothing dropped" guarantee made durable.
    for u in &scan.unclassified {
        if let Err(e) = store.register_unclassified(u) {
            report
                .scan_errors
                .push(format!("register unclassified {}: {e}", u.source_path));
        }
    }

    // Parse each identified artefact. Sizes up front so the GUI can show a
    // byte-weighted progress bar (a 2 GB $MFT dwarfs a 4 KB prefetch file).
    let sizes: Vec<u64> = scan
        .artefacts
        .iter()
        .map(|a| std::fs::metadata(&a.path).map(|m| m.len()).unwrap_or(0))
        .collect();
    progress::set_totals(scan.artefacts.len() as u64, sizes.iter().sum());
    progress::set_phase("Hashing and parsing artefacts");
    let mut seen: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    for (artefact, size) in scan.artefacts.iter().zip(&sizes) {
        if progress::cancelled() {
            report.cancelled = true;
            break;
        }
        progress::set_current(&format!(
            "{:?}|{}|{}",
            artefact.artefact, artefact.source_path, size
        ));
        let r = ingest_one(
            artefact,
            registry,
            store,
            &mut report.total_events,
            &mut seen,
        );
        progress::file_done(
            *size,
            r.warnings.len() as u64,
            matches!(r.status, ArtefactStatus::Failed(_)),
        );
        report.artefacts.push(r);
    }

    // Everything registered by this run belongs to this collection.
    if let Err(e) = store.claim_unassigned(&collection) {
        report.scan_errors.push(format!("record collection: {e}"));
    }

    // Artefacts that log host-local time go onto the UTC timeline using the
    // host's own time-zone rule (read from this collection's SYSTEM hive).
    progress::set_phase("Converting local times to UTC");
    match store.host_tz_rule(Some(&collection)) {
        Ok(Some(rule)) => match store.convert_local_times(&rule, Some(&collection)) {
            Ok(n) if n > 0 => {
                tracing::info!("converted {n} local-time events to UTC ({:?})", rule.name)
            }
            Ok(_) => {}
            Err(e) => report
                .scan_errors
                .push(format!("local time conversion: {e}")),
        },
        Ok(None) => tracing::info!("host time zone unknown: local-time artefacts left as logged"),
        Err(e) => report.scan_errors.push(format!("read host time zone: {e}")),
    }

    // Name the host and stamp it on every event from this collection.
    progress::set_phase("Identifying the host");
    match store.name_collection_host(&collection, host_name) {
        Ok((host, merged)) => {
            report.host = Some(host);
            report.merged_host = merged;
        }
        Err(e) => report.scan_errors.push(format!("name host: {e}")),
    }

    // Indexes are cheaper to build once, after the bulk load.
    progress::set_phase("Building indexes");
    if let Err(e) = store.build_indexes() {
        report.scan_errors.push(format!("build indexes: {e}"));
    }

    report
}

fn ingest_one(
    artefact: &IdentifiedArtefact,
    registry: &ParserRegistry,
    store: &CaseStore,
    total: &mut u64,
    seen: &mut std::collections::HashMap<(String, String), String>,
) -> ArtefactReport {
    // Register + hash BEFORE parsing, so even if the parser fails the evidence
    // (with its hash) is on record.
    if let Err(e) = store.register_evidence(artefact) {
        return ArtefactReport {
            source_path: artefact.source_path.clone(),
            artefact: artefact.artefact,
            status: ArtefactStatus::Failed(format!("evidence registration failed: {e}")),
            records_read: 0,
            events_emitted: 0,
            warnings: Vec::new(),
        };
    }

    // Same bytes, same artefact type as a file already parsed -> don't parse
    // again (collections often hold a second copy of an event log or hive).
    if let Ok(Some(sha)) = store.evidence_sha256(&artefact.evidence_id) {
        let key = (sha, format!("{:?}", artefact.artefact));
        if let Some(orig) = seen.get(&key) {
            let r = ArtefactReport {
                source_path: artefact.source_path.clone(),
                artefact: artefact.artefact,
                status: ArtefactStatus::Duplicate(orig.clone()),
                records_read: 0,
                events_emitted: 0,
                warnings: Vec::new(),
            };
            let _ = store.record_ingest(
                &r.source_path,
                &format!("{:?}", r.artefact),
                r.status.label(),
                r.status.detail().as_deref(),
                0,
                0,
                0,
            );
            tracing::info!(
                "duplicate [{:?}] {} (same as {orig})",
                artefact.artefact,
                artefact.source_path
            );
            return r;
        }
        seen.insert(key, artefact.source_path.clone());
    }

    let mut writer = store.event_writer();
    let mut counting = CountingSink {
        inner: &mut writer,
        count: 0,
    };

    // Per-artefact fault isolation must survive a *panic*, not just an Err: the
    // parsers run on attacker-controllable binary artefacts, and a malformed file
    // can trip an out-of-bounds index or a bad slice conversion deep in a parse
    // crate. Without this, one such file would unwind past here and abort the
    // entire ingest. catch_unwind contains it to this artefact, which is then
    // reported as Failed like any other parse error. AssertUnwindSafe is sound
    // here: on a panic we discard `counting`/`writer` state for this artefact and
    // move on (any partial events already emitted are flushed below and the
    // artefact is marked Failed).
    // Progress logging: one line before and after each artefact. If ingest ever
    // stalls, the last "parsing" line with no matching "done" names the file.
    let size = std::fs::metadata(&artefact.path)
        .map(|m| m.len())
        .unwrap_or(0);
    tracing::info!(
        "parsing [{:?}] {} ({:.1} MB)",
        artefact.artefact,
        artefact.source_path,
        size as f64 / 1_048_576.0
    );
    let started = std::time::Instant::now();

    let parse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        registry.parse(artefact, &mut counting)
    }));

    tracing::info!(
        "done    [{:?}] {} — {} events in {:.1}s",
        artefact.artefact,
        artefact.source_path,
        counting.count,
        started.elapsed().as_secs_f64()
    );

    let (status, records_read, events_emitted, warnings) = match parse_result {
        Ok(Ok(Some(outcome))) => (
            ArtefactStatus::Parsed,
            outcome.records_read,
            outcome.events_emitted,
            outcome.warnings.into_iter().map(|w| w.message).collect(),
        ),
        Ok(Ok(None)) => (
            transaction_log_status(artefact).unwrap_or(ArtefactStatus::Unsupported),
            0,
            0,
            Vec::new(),
        ),
        Ok(Err(e)) => (ArtefactStatus::Failed(e.to_string()), 0, 0, Vec::new()),
        Err(panic) => {
            // Recover a readable message from the panic payload.
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "parser panicked on malformed input".to_string());
            tracing::error!("parser panic on {}: {msg}", artefact.source_path);
            (
                ArtefactStatus::Failed(format!("parser panic: {msg}")),
                0,
                0,
                Vec::new(),
            )
        }
    };

    // `counting` holds &mut writer; its borrow ends with this last use.
    let counted = counting.count;
    // Ensure this artefact's events are committed before we write its report.
    if let Err(e) = writer.flush() {
        tracing::error!("flush after {}: {e}", artefact.source_path);
    }
    drop(writer);
    *total += counted;

    let r = ArtefactReport {
        source_path: artefact.source_path.clone(),
        artefact: artefact.artefact,
        status,
        records_read,
        events_emitted,
        warnings,
    };

    if let Err(e) = store.record_ingest(
        &r.source_path,
        &format!("{:?}", r.artefact),
        r.status.label(),
        r.status.detail().as_deref(),
        r.records_read,
        r.events_emitted,
        r.warnings.len() as i32,
    ) {
        tracing::error!("record ingest report for {}: {e}", r.source_path);
    }

    r
}

struct CountingSink<'a> {
    inner: &'a mut dyn EventSink,
    count: u64,
}

impl EventSink for CountingSink<'_> {
    fn emit(&mut self, event: fx_core::Event) {
        self.count += 1;
        fx_core::progress::add_events(1);
        self.inner.emit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_artefact(dir: &Path, name: &str) -> IdentifiedArtefact {
        let path = dir.join(name);
        std::fs::write(&path, b"regf").unwrap();
        IdentifiedArtefact {
            evidence_id: uuid::Uuid::new_v4(),
            path,
            source_path: name.into(),
            container: fx_core::ContainerFormat::RegistryHive,
            artefact: fx_core::ArtefactKind::Unclassified,
            method: fx_core::IdMethod::Content,
            confidence: 0.5,
            profile_hint: None,
        }
    }

    #[test]
    fn transaction_logs_say_whether_their_hive_was_there() {
        let dir = std::env::temp_dir().join(format!("fx-txlog-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SOFTWARE"), b"regf").unwrap();

        let applied = transaction_log_status(&log_artefact(&dir, "SOFTWARE.LOG1"));
        assert!(matches!(&applied, Some(ArtefactStatus::Applied(m)) if m.contains("SOFTWARE")));
        assert_eq!(applied.unwrap().label(), "applied");

        let orphan = transaction_log_status(&log_artefact(&dir, "BBI.LOG2"));
        assert!(
            matches!(&orphan, Some(ArtefactStatus::UnsupportedBecause(m)) if m.contains("bbi"))
        );
        assert_eq!(orphan.unwrap().label(), "unsupported");

        let legacy = transaction_log_status(&log_artefact(&dir, "SOFTWARE.LOG"));
        assert!(matches!(
            legacy,
            Some(ArtefactStatus::UnsupportedBecause(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
