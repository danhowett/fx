//! Content signatures: decide a file's *container format* from its bytes,
//! independent of extension. This is the authoritative first step — path and
//! filename are only ever used afterwards to disambiguate artefacts that share
//! a container.

use fx_core::ContainerFormat;

/// A magic-byte signature: match `bytes` at `offset`.
struct Signature {
    offset: usize,
    bytes: &'static [u8],
    container: ContainerFormat,
}

/// Ordered signature table. First match wins, so put more specific/!longer
/// signatures before generic ones if they could ever collide.
const SIGNATURES: &[Signature] = &[
    Signature { offset: 0, bytes: b"regf", container: ContainerFormat::RegistryHive },
    Signature { offset: 0, bytes: b"ElfFile\0", container: ContainerFormat::Evtx },
    Signature { offset: 0, bytes: b"SQLite format 3\0", container: ContainerFormat::Sqlite },
    // Prefetch: uncompressed "SCCA" lives at offset 4; Win10+ compressed
    // prefetch starts with "MAM" at offset 0. Handle both.
    Signature { offset: 4, bytes: b"SCCA", container: ContainerFormat::Prefetch },
    Signature { offset: 0, bytes: b"MAM\x04", container: ContainerFormat::Prefetch },
    // MFT records begin with "FILE" (good) or "BAAD" (corrupt but still an MFT
    // record). The identifier treats both as MftRecord.
    Signature { offset: 0, bytes: b"FILE", container: ContainerFormat::MftRecord },
    Signature { offset: 0, bytes: b"BAAD", container: ContainerFormat::MftRecord },
    // LNK: 4-byte header size 0x4C then the shell-link CLSID.
    Signature {
        offset: 0,
        bytes: &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00],
        container: ContainerFormat::Lnk,
    },
    // UsnJrnl:$J has no fixed file magic (it's a sparse stream of records);
    // it's identified by path + record-structure validation, not here.
];

/// ESE / EDB databases carry their signature at offset 4 (0xEF CD AB 89 in the
/// file header). Checked separately because several very different artefacts
/// (SRUM, Windows.edb, some AmCache) are all ESE and need schema-level
/// disambiguation afterwards.
const ESE_MAGIC_OFFSET: usize = 4;
const ESE_MAGIC: [u8; 4] = [0xEF, 0xCD, 0xAB, 0x89];

/// How many bytes we need to sniff any signature. Read at least this many.
pub const SNIFF_LEN: usize = 32;

/// Decide the container format from a byte prefix. Returns `Unknown` if no
/// signature matches — the caller then falls back to path heuristics and,
/// failing that, the unclassified bucket.
pub fn detect_container(prefix: &[u8]) -> ContainerFormat {
    for sig in SIGNATURES {
        let end = sig.offset + sig.bytes.len();
        if prefix.len() >= end && &prefix[sig.offset..end] == sig.bytes {
            return sig.container;
        }
    }
    let ese_end = ESE_MAGIC_OFFSET + ESE_MAGIC.len();
    if prefix.len() >= ese_end && prefix[ESE_MAGIC_OFFSET..ese_end] == ESE_MAGIC {
        return ContainerFormat::Ese;
    }
    ContainerFormat::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_registry_hive() {
        let mut buf = vec![0u8; SNIFF_LEN];
        buf[..4].copy_from_slice(b"regf");
        assert_eq!(detect_container(&buf), ContainerFormat::RegistryHive);
    }

    #[test]
    fn detects_evtx() {
        let mut buf = vec![0u8; SNIFF_LEN];
        buf[..8].copy_from_slice(b"ElfFile\0");
        assert_eq!(detect_container(&buf), ContainerFormat::Evtx);
    }

    #[test]
    fn detects_ese_at_offset_4() {
        let mut buf = vec![0u8; SNIFF_LEN];
        buf[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
        assert_eq!(detect_container(&buf), ContainerFormat::Ese);
    }

    #[test]
    fn detects_prefetch_uncompressed() {
        let mut buf = vec![0u8; SNIFF_LEN];
        buf[4..8].copy_from_slice(b"SCCA");
        assert_eq!(detect_container(&buf), ContainerFormat::Prefetch);
    }

    #[test]
    fn unknown_when_no_match() {
        let buf = vec![0xAAu8; SNIFF_LEN];
        assert_eq!(detect_container(&buf), ContainerFormat::Unknown);
    }
}
