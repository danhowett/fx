//! Types shared by the identification layer.
//!
//! Two independent questions, deliberately kept separate:
//!   1. What collection format is this? -> [`CollectionProfile`] (layout hint)
//!   2. What is this individual file?   -> [`IdentifiedArtefact`] (parser key)
//!
//! Question 2 must work even when question 1 finds nothing, so a random folder
//! of loose hives with wrong extensions still parses. Content beats layout
//! beats extension.

use crate::event::ArtefactKind;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// The low-level container format of a file, decided by magic bytes. Several
/// artefacts can share one container (all registry hives are `regf`; SRUM,
/// Windows.edb and some AmCache are all `ese`), so container alone does not
/// pick a parser — it narrows the field, then schema/path disambiguates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFormat {
    RegistryHive, // "regf"
    Evtx,         // "ElfFile\0"
    Ese,          // ESE / EDB page signature
    Sqlite,       // "SQLite format 3\0"
    MftRecord,    // "FILE" record
    Prefetch,     // SCCA / MAM (compressed)
    Lnk,          // shell link CLSID header
    UsnJournal,
    Unknown,
}

/// How confident identification is, and by what means. Travels with the
/// artefact into every event's provenance so a hunt hit is fully traceable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdMethod {
    /// Decided by content signature / internal schema. Authoritative.
    Content,
    /// Container decided by content, specific artefact decided by path.
    ContentAndPath,
    /// Only path/filename matched (weak — flag to analyst).
    PathOnly,
}

/// One file that has been identified and is ready to hand to a parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifiedArtefact {
    /// Evidence id assigned when the file was registered into the case.
    pub evidence_id: Uuid,
    /// Absolute path on the analyst machine to the extracted file.
    pub path: PathBuf,
    /// Original path/name as found in the collection (for provenance/display).
    pub source_path: String,
    pub container: ContainerFormat,
    pub artefact: ArtefactKind,
    pub method: IdMethod,
    /// 0.0–1.0 confidence in the artefact classification.
    pub confidence: f32,
    /// Hint from the collection profiler, if any (e.g. asserted host / tz).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_hint: Option<ProfileHint>,
}

/// A file the identifier could not classify. Surfaced to the analyst, never
/// silently dropped — "here are 340 files I couldn't classify" is information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnclassifiedFile {
    pub evidence_id: Uuid,
    pub path: PathBuf,
    pub source_path: String,
    pub container: ContainerFormat,
    pub reason: String,
}

/// Metadata asserted by a recognized collection format. Treated as an
/// assertion to be verified against artefact content, NEVER as ground truth.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileHint {
    pub collection_tool: Option<String>,
    pub tool_version: Option<String>,
    pub asserted_host: Option<String>,
    pub asserted_timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "opt_rfc3339")]
    pub collection_time: Option<time::OffsetDateTime>,
}

/// A profiler that recognizes one collection format (Magnet RESPONSE, KAPE,
/// Velociraptor, CyLR, raw folder...). Enrichment only — the pipeline must
/// fully function when every profiler returns `None`.
pub trait CollectionProfile: Send + Sync {
    fn name(&self) -> &'static str;

    /// Inspect the collection root; return a hint + confidence if it matches.
    fn detect(&self, root: &std::path::Path) -> Option<(ProfileHint, f32)>;
}

mod opt_rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(
        v: &Option<OffsetDateTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(dt) => time::serde::rfc3339::serialize(dt, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => OffsetDateTime::parse(
                &s,
                &time::format_description::well_known::Rfc3339,
            )
            .map(Some)
            .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
