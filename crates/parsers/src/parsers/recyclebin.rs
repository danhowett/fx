//! Recycle Bin `$I` metadata parser.
//!
//! When a file is sent to the Recycle Bin on Vista+, the shell writes a pair
//! into `$Recycle.Bin\<SID>\`: a `$R…` file with the content and a `$I…` file
//! with the metadata — original path, original size, and deletion time. We
//! parse the `$I` metadata. The forensic value: it records exactly *what was
//! deleted, from where, and when* — an attacker cleaning up tooling or a user
//! removing evidence both leave this trail, and it survives the `$R` content
//! being purged.
//!
//! Two on-disk versions (byte layout per the libyal Recycle.Bin spec):
//!   v1 (pre-Win10): [u64 version=1][u64 size][u64 FILETIME][520B UTF-16LE path]
//!   v2 (Win10+):    [u64 version=2][u64 size][u64 FILETIME][u32 name_len][UTF-16LE path]
//!
//! All reads are bounds-checked: `$I` bytes are attacker-controllable, so a
//! truncated or hostile file yields a warning, never a panic.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Provenance, Target, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct RecycleBinParser;

impl Parser for RecycleBinParser {
    fn name(&self) -> &'static str {
        "recyclebin"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Recycle]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();
        outcome.records_read = 1;

        let bytes = std::fs::read(&artefact.path).map_err(|e| ParseError::Io {
            path: artefact.path.display().to_string(),
            source: e,
        })?;

        let info = match parse_i_file(&bytes) {
            Ok(i) => i,
            Err(e) => {
                outcome.warnings.push(fx_core::RecordWarning {
                    source_ref: None,
                    message: format!("$I parse: {e}"),
                });
                return Ok(outcome);
            }
        };

        let ts = fx_core::filetime_to_datetime(info.deleted_filetime)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);

        sink.emit(Event {
            id: Uuid::new_v4(),
            timestamp: ts,
            timestamp_kind: TimestampKind::Recorded, // deletion time
            artefact: ArtefactKind::Recycle,
            action: "file.recycled".into(),
            host: None,
            user: Default::default(),
            process: None,
            target: Some(Target {
                path: Some(info.original_path.clone()),
                size: Some(info.original_size),
                ..Default::default()
            }),
            network: None,
            message: format!(
                "Deleted to Recycle Bin: {} ({} bytes)",
                info.original_path, info.original_size
            ),
            provenance: Provenance {
                evidence_id: artefact.evidence_id,
                source_path: artefact.source_path.clone(),
                parser: "recyclebin".into(),
                parser_version: env!("CARGO_PKG_VERSION").into(),
                source_ref: Some(info.original_path.chars().take(200).collect()),
            },
            raw: json!({
                "version": info.version,
                "original_path": info.original_path,
                "original_size": info.original_size,
                "deleted_filetime": info.deleted_filetime,
            }),
        });
        outcome.events_emitted += 1;

        Ok(outcome)
    }
}

struct IFile {
    version: u64,
    original_size: u64,
    deleted_filetime: u64,
    original_path: String,
}

fn parse_i_file(b: &[u8]) -> Result<IFile, String> {
    if b.len() < 24 {
        return Err("shorter than the 24-byte header".into());
    }
    let version = read_u64(b, 0)?;
    let original_size = read_u64(b, 8)?;
    let deleted_filetime = read_u64(b, 16)?;

    let original_path = match version {
        1 => {
            // Fixed 520-byte UTF-16LE field at offset 24 (260 wchar_t), NUL-term.
            let field = b.get(24..24 + 520).unwrap_or(&b[24.min(b.len())..]);
            utf16le_to_string(field)
        }
        2 => {
            // u32 char length at 24, then UTF-16LE path at 28.
            let n_chars = read_u32(b, 24)? as usize;
            let byte_len = n_chars.saturating_mul(2);
            let end = (28 + byte_len).min(b.len());
            let field = b.get(28..end).unwrap_or(&[]);
            utf16le_to_string(field)
        }
        other => return Err(format!("unknown $I version {other}")),
    };

    if original_path.is_empty() {
        return Err("empty original path".into());
    }
    Ok(IFile {
        version,
        original_size,
        deleted_filetime,
        original_path,
    })
}

fn read_u64(b: &[u8], off: usize) -> Result<u64, String> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("truncated at offset {off} (need u64)"))
}

fn read_u32(b: &[u8], off: usize) -> Result<u32, String> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("truncated at offset {off} (need u32)"))
}

/// Decode NUL-terminated UTF-16LE.
fn utf16le_to_string(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v2(path: &str, size: u64, ft: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u64.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&ft.to_le_bytes());
        let utf16: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        for u in utf16 {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    #[test]
    fn parses_v2() {
        // 2024-01-01T00:00:00Z FILETIME.
        let ft = 133_484_256_000_000_000u64;
        let raw = build_v2(r"C:\Users\jodell\Documents\secret.docx", 12345, ft);
        let i = parse_i_file(&raw).unwrap();
        assert_eq!(i.version, 2);
        assert_eq!(i.original_size, 12345);
        assert_eq!(i.original_path, r"C:\Users\jodell\Documents\secret.docx");
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_i_file(&[0u8; 10]).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let mut v = vec![0u8; 60];
        v[0] = 9; // bogus version
        assert!(parse_i_file(&v).is_err());
    }
}
