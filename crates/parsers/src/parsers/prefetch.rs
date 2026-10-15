//! Prefetch (.pf) parser.
//!
//! Handles both layouts:
//!   * Win8.1+ `MAM\x04` Xpress-Huffman-compressed wrapper -> decompress via
//!     the `xpress-huffman` crate, then parse the inner SCCA payload.
//!   * Older raw `SCCA` files (v17/23/26) with the signature at offset 4.
//!
//! We hand-roll the SCCA parse (rather than take a heavier framework
//! dependency) so we control version coverage and exactly which fields land on
//! the timeline. Execution evidence is central to hunting: Prefetch gives run
//! count and up to the last 8 execution times per executable, which is prime
//! signal for spotting attacker tooling (LOLBins, ransomware binaries).
//!
//! Emits one `execution.prefetch` event per recorded run time (up to 8), all
//! sharing the executable name and run count, so each execution is a distinct
//! timeline point.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Provenance, Target, TimestampKind,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Default)]
pub struct PrefetchParser;

impl Parser for PrefetchParser {
    fn name(&self) -> &'static str {
        "prefetch"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Prefetch]
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
        outcome.records_read = 1;

        let scca = decompress_if_needed(&bytes)
            .map_err(|e| ParseError::Malformed(format!("prefetch decompress: {e}")))?;

        let info = parse_scca(&scca)
            .map_err(|e| ParseError::Malformed(format!("SCCA parse: {e}")))?;

        for (i, run) in info.run_times.iter().enumerate() {
            // FILETIME 0 means "slot unused" — skip.
            let Some(ts) = fx_core::filetime_to_datetime(*run) else {
                continue;
            };
            sink.emit(Event {
                id: Uuid::new_v4(),
                timestamp: ts,
                timestamp_kind: TimestampKind::Executed,
                artefact: ArtefactKind::Prefetch,
                action: "execution.prefetch".into(),
                host: None,
                user: Default::default(),
                process: Some(fx_core::ProcessInfo {
                    name: Some(info.name.clone()),
                    ..Default::default()
                }),
                target: Some(Target {
                    path: Some(info.name.clone()),
                    ..Default::default()
                }),
                network: None,
                message: format!(
                    "Prefetch: {} executed (run {} of last 8, total runs {})",
                    info.name,
                    i + 1,
                    info.run_count
                ),
                provenance: Provenance {
                    evidence_id: artefact.evidence_id,
                    source_path: artefact.source_path.clone(),
                    parser: "prefetch".into(),
                    parser_version: env!("CARGO_PKG_VERSION").into(),
                    source_ref: Some(format!("{}#run{}", info.name, i)),
                },
                raw: json!({
                    "name": info.name,
                    "run_count": info.run_count,
                    "version": info.version,
                    "run_time_index": i,
                }),
            });
            outcome.events_emitted += 1;
        }

        if outcome.events_emitted == 0 {
            outcome.warnings.push(fx_core::RecordWarning {
                source_ref: Some(info.name.clone()),
                message: "no valid run times decoded".into(),
            });
        }

        Ok(outcome)
    }
}

/// Parsed SCCA fields we care about for the timeline.
struct PrefetchInfo {
    version: u32,
    name: String,
    run_count: u32,
    /// Up to 8 FILETIMEs (100ns since 1601). Older versions store 1.
    run_times: Vec<u64>,
}

const MAM_MAGIC: &[u8; 3] = b"MAM";
const MAM_XPRESS_HUFFMAN: u8 = 0x04;
const SCCA_MAGIC: &[u8; 4] = b"SCCA";

/// If the file is MAM-wrapped, decompress to raw SCCA; otherwise return as-is.
fn decompress_if_needed(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() >= 8 && &bytes[0..3] == MAM_MAGIC {
        if bytes[3] != MAM_XPRESS_HUFFMAN {
            return Err(format!("unsupported MAM compression byte {:#x}", bytes[3]));
        }
        // Header: "MAM\x04" then u32 LE decompressed size, then the stream.
        let decompressed_size =
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let compressed = &bytes[8..];
        xpress_huffman::decompress(compressed, decompressed_size)
            .map_err(|e| format!("xpress-huffman: {e:?}"))
    } else if bytes.len() >= 8 && &bytes[4..8] == SCCA_MAGIC {
        Ok(bytes.to_vec())
    } else {
        Err("not a recognized prefetch (no MAM or SCCA signature)".into())
    }
}

/// Parse the decompressed SCCA payload. Layout differs by version; the header
/// is common: [u32 version][b"SCCA"][u32 file_size][name utf16 * 30]...
///
/// Offsets for run count / run times differ between v23/26 (Win7/8.1), v30
/// (Win10) and v31 (Win11). We branch on version and read the documented
/// offsets. Bounds-checked throughout; a short/truncated file yields an error
/// rather than a panic.
fn parse_scca(buf: &[u8]) -> Result<PrefetchInfo, String> {
    if buf.len() < 8 || &buf[4..8] != SCCA_MAGIC {
        return Err("missing SCCA signature".into());
    }
    let version = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);

    // The executable name is a UTF-16LE string starting at offset 0x10, up to
    // 60 bytes (30 code units), NUL-terminated.
    let name = read_utf16_name(buf, 0x10, 60).unwrap_or_else(|| "<unknown>".into());

    // Run count and run-time offsets by version. These are the documented SCCA
    // offsets; kept in one place so adding a version is a single arm.
    let (run_times_offset, run_times_count, run_count_offset) = match version {
        23 => (0x78, 1, 0x90),          // Win7
        26 => (0x80, 1, 0x98),          // Win8/8.1
        30 => (0x80, 8, 0xD0),          // Win10
        31 => (0x80, 8, 0xD0),          // Win11 (same shape as v30 for these)
        other => return Err(format!("unsupported SCCA version {other}")),
    };

    let run_count = read_u32(buf, run_count_offset).unwrap_or(0);

    let mut run_times = Vec::with_capacity(run_times_count);
    for i in 0..run_times_count {
        if let Some(ft) = read_u64(buf, run_times_offset + i * 8) {
            run_times.push(ft);
        }
    }

    Ok(PrefetchInfo {
        version,
        name,
        run_count,
        run_times,
    })
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8).map(|b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// Read a NUL-terminated UTF-16LE string of at most `max_bytes`.
fn read_utf16_name(buf: &[u8], off: usize, max_bytes: usize) -> Option<String> {
    let slice = buf.get(off..(off + max_bytes).min(buf.len()))?;
    let mut units = Vec::new();
    for pair in slice.chunks_exact(2) {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_prefetch() {
        assert!(decompress_if_needed(&[0u8; 16]).is_err());
    }

    #[test]
    fn reads_utf16_name() {
        // "PF" as UTF-16LE then NUL.
        let buf = {
            let mut v = vec![0u8; 0x10];
            v.extend_from_slice(&[b'P', 0, b'F', 0, 0, 0]);
            v
        };
        assert_eq!(read_utf16_name(&buf, 0x10, 60).as_deref(), Some("PF"));
    }
}
