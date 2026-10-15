//! `fx-parsers` — the artefact parsers and the registry that dispatches to
//! them by identified artefact kind.

pub mod parsers;
pub mod registry;

pub use registry::ParserRegistry;
