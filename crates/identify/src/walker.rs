//! Walk an already-extracted collection directory, identify every file, and
//! partition into identified artefacts vs. the unclassified bucket.
//!
//! Phase 1 assumes loose extracted files (optionally inside a flat zip the
//! caller has already unpacked). No VHDX/E01/image mounting — that's a later
//! phase. So this is a straight recursive file walk feeding the identifier.

use crate::identifier::{identify_file, Identification};
use crate::profiles::detect_profile;
use fx_core::{IdentifiedArtefact, UnclassifiedFile};
use std::path::Path;
use walkdir::WalkDir;

/// Everything the identification pass produced for a collection.
#[derive(Default)]
pub struct CollectionScan {
    pub artefacts: Vec<IdentifiedArtefact>,
    pub unclassified: Vec<UnclassifiedFile>,
    /// Non-fatal problems (unreadable files, permission errors) — surfaced,
    /// never silently swallowed.
    pub errors: Vec<String>,
    /// Which collection profile matched, if any (enrichment only).
    pub profile: Option<String>,
}

/// Scan a collection root. Runs collection profiling first (for hints), then
/// identifies every regular file. Profiling never gates identification: if no
/// profile matches, every file is still identified on its own merits.
pub fn scan_collection(root: &Path) -> CollectionScan {
    let mut scan = CollectionScan::default();

    let (hint, profile_name) = match detect_profile(root) {
        Some((name, hint, _conf)) => {
            scan.profile = Some(name.to_string());
            (Some(hint), Some(name))
        }
        None => (None, None),
    };
    let _ = profile_name;

    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                scan.errors.push(format!("walk error: {e}"));
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let source_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        match identify_file(path, &source_path, hint.clone()) {
            Ok(Identification::Known(a)) => scan.artefacts.push(*a),
            Ok(Identification::Unclassified(u)) => scan.unclassified.push(*u),
            Err(e) => scan
                .errors
                .push(format!("read error on {}: {e}", path.display())),
        }
    }

    scan
}
