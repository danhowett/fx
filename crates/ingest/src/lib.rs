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
}

impl ArtefactStatus {
    fn label(&self) -> &'static str {
        match self {
            ArtefactStatus::Parsed => "parsed",
            ArtefactStatus::Unsupported => "unsupported",
            ArtefactStatus::Failed(_) => "failed",
        }
    }
    fn detail(&self) -> Option<String> {
        match self {
            ArtefactStatus::Failed(m) => Some(m.clone()),
            _ => None,
        }
    }
}

pub struct IngestReport {
    pub profile: Option<String>,
    pub artefacts: Vec<ArtefactReport>,
    pub unclassified: usize,
    pub scan_errors: Vec<String>,
    pub total_events: u64,
}

/// Run the full pipeline over an extracted collection directory, persisting
/// everything into `store`.
pub fn ingest_into_store(root: &Path, registry: &ParserRegistry, store: &CaseStore) -> IngestReport {
    let scan: CollectionScan = scan_collection(root);

    let mut report = IngestReport {
        profile: scan.profile.clone(),
        artefacts: Vec::with_capacity(scan.artefacts.len()),
        unclassified: scan.unclassified.len(),
        scan_errors: scan.errors.clone(),
        total_events: 0,
    };

    // Register (and hash) unclassified files first — they're evidence too, and
    // recording them is the "nothing dropped" guarantee made durable.
    for u in &scan.unclassified {
        if let Err(e) = store.register_unclassified(u) {
            report.scan_errors.push(format!("register unclassified {}: {e}", u.source_path));
        }
    }

    // Parse each identified artefact.
    for artefact in &scan.artefacts {
        let r = ingest_one(artefact, registry, store, &mut report.total_events);
        report.artefacts.push(r);
    }

    // Indexes are cheaper to build once, after the bulk load.
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

    let mut writer = store.event_writer();
    let mut counting = CountingSink { inner: &mut writer, count: 0 };

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
    let size = std::fs::metadata(&artefact.path).map(|m| m.len()).unwrap_or(0);
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
        Ok(Ok(None)) => (ArtefactStatus::Unsupported, 0, 0, Vec::new()),
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

    let counted = counting.count;
    // `counting` holds &mut writer; end that borrow before we touch writer.
    drop(counting);
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
        self.inner.emit(event);
    }
}
