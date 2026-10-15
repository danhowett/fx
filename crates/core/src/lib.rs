//! `fx-core` — the shared foundation: the normalized event schema, the parser
//! contract, and the identification types every other crate builds on.
//!
//! Dependency direction is strict: `core` depends on nothing else in the
//! workspace. `identify`, `parsers`, and `ingest` all depend on `core`, never
//! the reverse. That keeps the schema and the parser contract stable while the
//! layers around them change.

pub mod detection;
pub mod event;
pub mod identify;
pub mod parser;
pub mod time_util;

pub use detection::{Detection, DetectionEngine, Severity};
pub use event::{
    ArtefactKind, Event, NetworkInfo, Principal, ProcessInfo, Provenance, Target, TimestampKind,
};
pub use identify::{
    CollectionProfile, ContainerFormat, IdMethod, IdentifiedArtefact, ProfileHint,
    UnclassifiedFile,
};
pub use parser::{EventSink, ParseError, ParseOutcome, Parser, RecordWarning};
pub use time_util::filetime_to_datetime;
