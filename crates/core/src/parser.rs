//! The parser contract.
//!
//! A [`Parser`] takes ONE identified artefact and emits normalized events.
//! Parsers know nothing about storage, the GUI, the collection format, or each
//! other. They are pure `IdentifiedArtefact -> Vec<Event>` functions with
//! streaming so a 40-million-record $MFT doesn't have to fit in memory.

use crate::event::{ArtefactKind, Event};
use crate::identify::IdentifiedArtefact;
use serde::{Deserialize, Serialize};

/// Errors a parser can raise. A parser failing on one artefact must never
/// abort the whole case — the ingest orchestrator catches these per-artefact.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("i/o error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed artefact: {0}")]
    Malformed(String),
    #[error("unsupported variant: {0}")]
    Unsupported(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Sink for events as a parser produces them. Implemented by the ingest layer
/// (writes to the store) and by tests (collects into a Vec). Keeping this a
/// callback rather than returning `Vec<Event>` is what makes streaming large
/// artefacts possible.
pub trait EventSink {
    fn emit(&mut self, event: Event);
}

impl EventSink for Vec<Event> {
    fn emit(&mut self, event: Event) {
        self.push(event);
    }
}

/// A record-level failure that didn't stop the whole artefact. Parsers report
/// these instead of aborting, so one corrupt EVTX record doesn't lose the
/// other 99,999.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordWarning {
    pub source_ref: Option<String>,
    pub message: String,
}

/// The result of parsing one artefact: how many records were read, and any
/// non-fatal record warnings.
#[derive(Debug, Default)]
pub struct ParseOutcome {
    pub records_read: u64,
    pub events_emitted: u64,
    pub warnings: Vec<RecordWarning>,
}

/// A parser for one artefact family.
pub trait Parser: Send + Sync {
    /// Stable name for provenance (e.g. "evtx", "mft", "amcache").
    fn name(&self) -> &'static str;

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Which artefact kinds this parser handles. The registry uses this to
    /// dispatch; dispatch is driven by identification, never by file
    /// extension or collection layout.
    fn handles(&self) -> &'static [ArtefactKind];

    /// Parse one identified artefact, emitting events into `sink`.
    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError>;
}
