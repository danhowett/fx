//! The parser registry: maps an [`ArtefactKind`] to the parser that handles
//! it. Dispatch is driven entirely by identification — never by file extension
//! or collection layout — which is what makes the tool format-agnostic.

use fx_core::{ArtefactKind, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser};
use std::collections::HashMap;
use std::sync::Arc;

/// Holds all registered parsers and routes artefacts to them.
#[derive(Default)]
pub struct ParserRegistry {
    by_kind: HashMap<ArtefactKind, Arc<dyn Parser>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a parser for every artefact kind it declares it `handles()`.
    pub fn register(&mut self, parser: Arc<dyn Parser>) {
        for kind in parser.handles() {
            if let Some(existing) = self.by_kind.insert(*kind, parser.clone()) {
                tracing::warn!(
                    "parser {} overrode {} for {:?}",
                    parser.name(),
                    existing.name(),
                    kind
                );
            }
        }
    }

    /// The default set of parsers wired up. As Week 2 parsers land, add them
    /// here — this is the one place that knows the full roster.
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(Arc::new(crate::parsers::evtx::EvtxParser::default()));
        r.register(Arc::new(crate::parsers::mft::MftParser::default()));
        r.register(Arc::new(crate::parsers::registry::RegistryParser::default()));
        r.register(Arc::new(crate::parsers::prefetch::PrefetchParser::default()));
        r.register(Arc::new(crate::parsers::srum::SrumParser::default()));
        r.register(Arc::new(crate::parsers::usnjrnl::UsnJrnlParser::default()));
        r.register(Arc::new(crate::parsers::scheduled_task::ScheduledTaskParser::default()));
        r.register(Arc::new(crate::parsers::browser_history::BrowserHistoryParser::default()));
        r.register(Arc::new(crate::parsers::lnk::LnkParser::default()));
        r.register(Arc::new(crate::parsers::recyclebin::RecycleBinParser::default()));
        r.register(Arc::new(crate::parsers::pshistory::PsHistoryParser::default()));
        r.register(Arc::new(crate::parsers::windows_timeline::WindowsTimelineParser::default()));
        // Disk-artefact parser breadth complete.
        r
    }

    pub fn parser_for(&self, kind: ArtefactKind) -> Option<Arc<dyn Parser>> {
        self.by_kind.get(&kind).cloned()
    }

    /// Parse one identified artefact, if a parser is registered for its kind.
    /// Returns `Ok(None)` when no parser handles this kind yet (not an error —
    /// it just means the artefact is identified but unsupported so far, which
    /// the orchestrator records rather than treating as a failure).
    pub fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<Option<ParseOutcome>, ParseError> {
        match self.parser_for(artefact.artefact) {
            Some(p) => p.parse(artefact, sink).map(Some),
            None => Ok(None),
        }
    }
}
