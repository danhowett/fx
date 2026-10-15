//! `fx-identify` — the format-agnostic ingestion front door.
//!
//! Turns "a folder of extracted files in whatever layout the collection tool
//! produced" into a clean stream of [`fx_core::IdentifiedArtefact`] plus an
//! explicit unclassified bucket. Content beats layout beats extension; nothing
//! is ever silently dropped.

pub mod identifier;
pub mod profiles;
pub mod signatures;
pub mod walker;

pub use identifier::{identify_file, Identification};
pub use walker::{scan_collection, CollectionScan};
