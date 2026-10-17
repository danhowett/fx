//! The normalized event schema.
//!
//! This is the single most important type in the system. Every parser, no
//! matter what artefact it reads, emits a stream of [`Event`]s in this shape.
//! Everything downstream — timelining, hunting, correlation, the GUI — depends
//! only on this, never on the original artefact format.
//!
//! Field names lean on Elastic Common Schema (ECS) conventions where they map
//! cleanly, so that detections (including Sigma) stay portable. Where an
//! artefact carries something that doesn't fit a normalized field, it goes in
//! `raw` — we NEVER discard the original record.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// A single normalized event on the timeline.
///
/// One source record can legitimately produce several events — e.g. an $MFT
/// entry yields up to four (the M, A, C, B timestamps), each a distinct
/// `Event` with a different [`TimestampKind`] but a shared `source_ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Stable unique id for this normalized event.
    pub id: Uuid,

    /// The primary timestamp this event sits at on the timeline (always UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,

    /// What kind of time `timestamp` represents. Critical for forensic
    /// correctness: a file "created" vs "executed" vs "logged" time are not
    /// interchangeable and an analyst must be able to see which is which.
    pub timestamp_kind: TimestampKind,

    /// Which artefact this came from (e.g. `Evtx`, `Mft`, `Amcache`).
    pub artefact: ArtefactKind,

    /// Short machine-readable action, ECS-style dotted form where sensible,
    /// e.g. `process.start`, `file.create`, `logon.success`, `service.install`.
    pub action: String,

    /// Host the event pertains to, if known (from artefact content, not
    /// blindly from a collection manifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Actors and objects. All optional because no single artefact fills them
    /// all; hunts match on whichever subset is present.
    #[serde(default, skip_serializing_if = "Principal::is_empty")]
    pub user: Principal,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,

    /// Filesystem/registry/network target the action acted upon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Target>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,

    /// Human-readable one-line summary for the timeline grid. Parsers build
    /// this; it is for display only and must never be parsed by a hunt.
    pub message: String,

    /// Provenance: how this event came to exist. Non-negotiable for
    /// defensibility — every event can be traced back to a file and a parser.
    pub provenance: Provenance,

    /// The complete original record, losslessly. Anything the normalized
    /// fields above don't capture lives here so nothing is ever lost.
    pub raw: serde_json::Value,
}

/// The meaning of an event's timestamp. Never assume — always label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampKind {
    /// File/registry-key creation ($SI or $FN Born, key LastWrite for new key).
    Created,
    /// Content last modified.
    Modified,
    /// Metadata last changed (MFT $SI C time / ctime).
    MetadataChanged,
    /// Last accessed.
    Accessed,
    /// Program execution time (Prefetch run, AmCache, UserAssist).
    Executed,
    /// Event was logged/recorded (EVTX TimeCreated, journal entry).
    Logged,
    /// Logon/session time.
    Logon,
    /// Time asserted by the artefact but of ambiguous kind; see `action`.
    Recorded,
}

/// The artefact family an event originated from. Drives GUI grouping and lets
/// hunts scope to specific sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtefactKind {
    Evtx,
    Mft,
    UsnJrnl,
    LogFile,
    Prefetch,
    Amcache,
    ShimCache,
    RegistryRun,
    RegistryService,
    UserAssist,
    ShellBags,
    BamDam,
    Srum,
    ScheduledTask,
    Lnk,
    JumpList,
    Recycle,
    BrowserHistory,
    /// PowerShell console history (PSReadLine ConsoleHost_history.txt).
    PsHistory,
    /// Windows Timeline / Activity (ActivitiesCache.db).
    WindowsTimeline,
    /// Remote-access tool logs (AnyDesk, TeamViewer).
    RemoteAccess,
    /// Registry-derived but not one of the specialized views above.
    RegistryGeneric,
    /// Identified container we can read but have no specialized parser for yet.
    Unclassified,
}

/// A user/security principal. Kept as a small struct because SID and name are
/// both independently useful for correlation and often only one is present.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Principal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl Principal {
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.sid.is_none() && self.domain.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
}

/// What the action acted on — a path (file or registry key) or similar object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Target {
    /// Filesystem path or registry key path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// For registry: the value name, if the event is value-level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<u8>,
}

/// Traceability from a normalized event back to the exact byte source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// Evidence item id within the case (a registered source file).
    pub evidence_id: Uuid,
    /// Original path of the source file as it was found in the collection.
    pub source_path: String,
    /// Which parser produced this, and its version — so a re-parse with a
    /// newer parser is distinguishable in the case history.
    pub parser: String,
    pub parser_version: String,
    /// A locator back into the source (record number, offset, key path, etc.)
    /// so an analyst can jump to the exact original record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}
