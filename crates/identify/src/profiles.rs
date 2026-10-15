//! Collection-format profilers. Each recognizes one acquisition tool's layout
//! and returns asserted metadata as a [`ProfileHint`]. This is Layer 1 — a
//! hint, never a gate. The pipeline works with zero matches.
//!
//! IMPORTANT: hints are assertions. `asserted_host` / `asserted_timezone` must
//! be verified against artefact content (SYSTEM hive computer name, etc.)
//! before being trusted. We record, we don't believe.

use fx_core::ProfileHint;
use std::path::Path;

/// Run every profiler; return the highest-confidence match, if any.
pub fn detect_profile(root: &Path) -> Option<(&'static str, ProfileHint, f32)> {
    let profilers: &[&dyn Profiler] = &[&Response, &Kape, &Velociraptor];
    profilers
        .iter()
        .filter_map(|p| p.detect(root).map(|(h, c)| (p.name(), h, c)))
        .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
}

trait Profiler {
    fn name(&self) -> &'static str;
    fn detect(&self, root: &Path) -> Option<(ProfileHint, f32)>;
}

/// Magnet RESPONSE: recognized by its collection metadata/log files and folder
/// tree. (Signature paths are placeholders to fill against a real RESPONSE
/// output during Week 1 — the shape is what matters here.)
struct Response;
impl Profiler for Response {
    fn name(&self) -> &'static str {
        "magnet_response"
    }
    fn detect(&self, root: &Path) -> Option<(ProfileHint, f32)> {
        // e.g. a top-level collection log / metadata json RESPONSE emits.
        let markers = ["RESPONSE", "MagnetRESPONSE", "collection_metadata"];
        if markers.iter().any(|m| child_exists(root, m)) {
            let hint = ProfileHint {
                collection_tool: Some("Magnet RESPONSE".into()),
                ..Default::default()
            };
            return Some((hint, 0.9));
        }
        None
    }
}

/// KAPE: per-target subfolders plus the copy log / SHA1 CSVs KAPE writes.
struct Kape;
impl Profiler for Kape {
    fn name(&self) -> &'static str {
        "kape"
    }
    fn detect(&self, root: &Path) -> Option<(ProfileHint, f32)> {
        let has_kape_log = read_dir_names(root)
            .iter()
            .any(|n| n.ends_with("_kape.txt") || n.contains("CopyLog") || n.contains("_SHA1"));
        if has_kape_log {
            let hint = ProfileHint {
                collection_tool: Some("KAPE".into()),
                ..Default::default()
            };
            return Some((hint, 0.85));
        }
        None
    }
}

/// Velociraptor offline collector: uploads/ tree + collection JSON metadata.
struct Velociraptor;
impl Profiler for Velociraptor {
    fn name(&self) -> &'static str {
        "velociraptor"
    }
    fn detect(&self, root: &Path) -> Option<(ProfileHint, f32)> {
        if child_exists(root, "uploads") && read_dir_names(root).iter().any(|n| n.ends_with(".json"))
        {
            let hint = ProfileHint {
                collection_tool: Some("Velociraptor".into()),
                ..Default::default()
            };
            return Some((hint, 0.8));
        }
        None
    }
}

fn child_exists(root: &Path, name: &str) -> bool {
    root.join(name).exists()
        || read_dir_names(root)
            .iter()
            .any(|n| n.eq_ignore_ascii_case(name))
}

fn read_dir_names(root: &Path) -> Vec<String> {
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}
