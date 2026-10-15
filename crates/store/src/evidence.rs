//! Evidence registration: hash each source file and record it as a case
//! evidence item before its events are written. The event rows reference the
//! evidence_id, so the chain from a hunt hit back to a hashed source file is
//! unbroken.

use fx_core::{IdentifiedArtefact, UnclassifiedFile};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Registration facts about one source file.
pub struct EvidenceRecord {
    pub sha256: String,
    pub size_bytes: u64,
}

/// Stream a file through SHA-256 without loading it whole — MFTs and SRUM DBs
/// can be large. 1 MiB buffer.
pub fn hash_file(path: &Path) -> std::io::Result<EvidenceRecord> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok(EvidenceRecord {
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes: size,
    })
}

/// Convenience: hash an identified artefact at its on-disk path.
pub fn hash_artefact(a: &IdentifiedArtefact) -> std::io::Result<EvidenceRecord> {
    hash_file(&a.path)
}

/// Convenience: hash an unclassified file.
pub fn hash_unclassified(u: &UnclassifiedFile) -> std::io::Result<EvidenceRecord> {
    hash_file(&u.path)
}
