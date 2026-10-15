//! LNK (`.lnk` shell links) and Jump List parser, built on `lnk-core`.
//!
//! These artefacts answer "what did the user open, and from where" — including
//! files on media that is no longer present. That makes them uniquely valuable:
//!   * `local_base_path` + a REMOVABLE `drive_type` + `drive_serial_number`
//!     proves a file was opened from a specific USB stick, even after it's gone
//!     — classic for data theft / tooling brought in on external media.
//!   * a `CommonNetworkRelativeLink.net_name` proves access to a specific
//!     network share (lateral movement, staging on file servers).
//!   * the three target FILETIMEs and, for automatic jump lists, per-entry MRU
//!     metadata (recency, access count) time-anchor the access.
//!
//! `lnk-core` is panic-free and bounds-checked, which matters because these are
//! attacker-controllable files. It parses `.lnk`, automatic-destinations jump
//! lists (OLE/CFB compound files), and custom-destinations jump lists.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Provenance, Target, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct LnkParser;

impl Parser for LnkParser {
    fn name(&self) -> &'static str {
        "lnk"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Lnk, ArtefactKind::JumpList]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();
        let bytes = std::fs::read(&artefact.path).map_err(|e| ParseError::Io {
            path: artefact.path.display().to_string(),
            source: e,
        })?;

        match artefact.artefact {
            ArtefactKind::Lnk => {
                outcome.records_read = 1;
                match lnk_core::parse_shell_link(&bytes) {
                    Some(link) => {
                        emit_link(&link, artefact, None, "lnk.target", sink, &mut outcome);
                    }
                    None => outcome.warnings.push(fx_core::RecordWarning {
                        source_ref: None,
                        message: "not a valid shell link (bad header/CLSID)".into(),
                    }),
                }
            }
            ArtefactKind::JumpList => {
                parse_jumplist(&bytes, artefact, sink, &mut outcome);
            }
            _ => {}
        }

        Ok(outcome)
    }
}

/// Dispatch a jump list by family (automatic = OLE/CFB, custom = flat).
fn parse_jumplist(
    bytes: &[u8],
    artefact: &IdentifiedArtefact,
    sink: &mut dyn EventSink,
    outcome: &mut ParseOutcome,
) {
    let is_automatic = artefact
        .source_path
        .to_ascii_lowercase()
        .ends_with(".automaticdestinations-ms");

    let filename = artefact
        .path
        .file_name()
        .and_then(|s| s.to_str());

    let jumplist = if is_automatic {
        lnk_core::parse_automatic_destinations(bytes, filename)
    } else {
        lnk_core::parse_custom_destinations(bytes, filename)
    };

    match jumplist {
        Some(jl) => {
            for entry in &jl.entries {
                outcome.records_read += 1;
                // Each entry embeds a shell link; automatic entries also carry
                // DestList MRU metadata (access count, entry number, hostname).
                let mru = entry.destlist.as_ref().map(|d| {
                    json!({
                        "entry_number": d.entry_number,
                        "access_count": d.access_count,
                        "hostname": d.hostname,
                        "pinned": d.pinned,
                        "last_access_unix": d.last_access,
                        "destlist_path": d.path,
                    })
                });
                emit_link(&entry.link, artefact, mru, "jumplist.entry", sink, outcome);
            }
        }
        None => outcome.warnings.push(fx_core::RecordWarning {
            source_ref: None,
            message: "jump list parsed to no entries (malformed or empty)".into(),
        }),
    }
}

/// Emit one normalized event from a parsed shell link, flagging removable-media
/// and network-share origins — the highest-signal facts these artefacts carry.
fn emit_link(
    link: &lnk_core::ShellLink,
    artefact: &IdentifiedArtefact,
    mru: Option<serde_json::Value>,
    action: &str,
    sink: &mut dyn EventSink,
    outcome: &mut ParseOutcome,
) {
    // Prefer the full local base path; fall back to the relative path/name.
    let (target_path, drive_type_num, serial, volume_label) = match &link.link_info {
        Some(info) => {
            let (dt, serial, label) = match &info.volume_id {
                Some(v) => (
                    Some(v.drive_type),
                    Some(format!("{:#010X}", v.drive_serial_number)),
                    v.volume_label.clone(),
                ),
                None => (None, None, None),
            };
            (info.local_base_path.clone(), dt, serial, label)
        }
        None => (None, None, None, None),
    };

    // net_name is Option<String> on CommonNetworkRelativeLink.
    let net_name: Option<String> = link
        .link_info
        .as_ref()
        .and_then(|i| i.common_network_relative_link.as_ref())
        .and_then(|n| n.net_name.clone());

    let display_path = target_path
        .clone()
        .or_else(|| link.string_data.relative_path.clone())
        .or_else(|| net_name.clone())
        .or_else(|| link.string_data.name.clone())
        .unwrap_or_default();

    // Removable-media and network flags — the "why this matters" for triage.
    // drive_type is the numeric [MS-SHLLINK] DriveType (2 = REMOVABLE, 4 = REMOTE).
    let removable = drive_type_num == Some(lnk_core::drive_type::REMOVABLE);
    let is_network =
        net_name.is_some() || drive_type_num == Some(lnk_core::drive_type::REMOTE);

    // Human-readable drive type for display / raw.
    let drive_type = drive_type_num.map(|n| match n {
        lnk_core::drive_type::REMOVABLE => "Removable",
        lnk_core::drive_type::FIXED => "Fixed",
        lnk_core::drive_type::REMOTE => "Remote",
        lnk_core::drive_type::CDROM => "CD-ROM",
        lnk_core::drive_type::RAMDISK => "RAM disk",
        lnk_core::drive_type::NO_ROOT_DIR => "No root dir",
        _ => "Unknown",
    });

    let mut tags = Vec::new();
    if removable {
        tags.push("REMOVABLE-MEDIA");
    }
    if is_network {
        tags.push("NETWORK-SHARE");
    }

    // Target creation time (already Unix seconds from lnk-core; 0 when unset)
    // anchors the event; fall back to epoch when absent.
    let ts = if link.header.creation_time > 0 {
        OffsetDateTime::from_unix_timestamp(link.header.creation_time)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
    } else {
        OffsetDateTime::UNIX_EPOCH
    };

    let mut message = format!("Shell link -> {display_path}");
    if let Some(s) = &serial {
        if removable {
            message.push_str(&format!("  [USB serial {s}]"));
        }
    }
    if let Some(n) = &net_name {
        message.push_str(&format!("  [share {n}]"));
    }
    if !tags.is_empty() {
        message.push_str(&format!("  [{}]", tags.join(", ")));
    }

    let action = if removable {
        "lnk.removable_media"
    } else if is_network {
        "lnk.network_share"
    } else {
        action
    };

    sink.emit(Event {
        id: Uuid::new_v4(),
        timestamp: ts,
        timestamp_kind: TimestampKind::Accessed,
        artefact: artefact.artefact,
        action: action.to_string(),
        host: None,
        user: Default::default(),
        process: None,
        target: Some(Target {
            path: Some(display_path.clone()),
            size: Some(link.header.file_size as u64),
            ..Default::default()
        }),
        network: None,
        message,
        provenance: Provenance {
            evidence_id: artefact.evidence_id,
            source_path: artefact.source_path.clone(),
            parser: "lnk".into(),
            parser_version: env!("CARGO_PKG_VERSION").into(),
            source_ref: Some(display_path.chars().take(200).collect()),
        },
        raw: json!({
            "target_path": target_path,
            "relative_path": link.string_data.relative_path,
            "arguments": link.string_data.arguments,
            "working_dir": link.string_data.working_dir,
            "drive_type": drive_type,
            "drive_serial": serial,
            "volume_label": volume_label,
            "net_name": net_name,
            "file_size": link.header.file_size,
            "removable": removable,
            "network": is_network,
            "mru": mru,
        }),
    });
    outcome.events_emitted += 1;
}
