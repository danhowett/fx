//! The artefact identifier: turn a walked file into an [`IdentifiedArtefact`]
//! or an [`UnclassifiedFile`].
//!
//! Two-stage rule, always in this order:
//!   1. Container from magic bytes (authoritative, extension-independent).
//!   2. Specific artefact from internal schema and/or path (disambiguates the
//!      many artefacts that share a container).
//!
//! Path is a hint that raises/decides *within* a container class; it never
//! overrides the byte-level container decision. A file only reaches the
//! unclassified bucket after both stages fail — it is never silently dropped.

use crate::signatures::{detect_container, SNIFF_LEN};
use fx_core::{
    ArtefactKind, ContainerFormat, IdMethod, IdentifiedArtefact, ProfileHint, UnclassifiedFile,
};
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

/// Outcome of identifying one file.
pub enum Identification {
    Known(Box<IdentifiedArtefact>),
    Unclassified(Box<UnclassifiedFile>),
}

/// Identify a single already-extracted file.
pub fn identify_file(
    path: &Path,
    source_path: &str,
    profile_hint: Option<ProfileHint>,
) -> std::io::Result<Identification> {
    let evidence_id = Uuid::new_v4();

    // Stage 1: sniff the container from the leading bytes.
    let mut prefix = [0u8; SNIFF_LEN];
    let read = read_prefix(path, &mut prefix)?;
    let container = detect_container(&prefix[..read]);

    let lower = source_path.to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Stage 2: resolve the specific artefact within that container.
    let resolved = match container {
        ContainerFormat::RegistryHive => resolve_registry(&file_name),
        ContainerFormat::Evtx => Some((ArtefactKind::Evtx, IdMethod::Content, 0.99)),
        ContainerFormat::MftRecord => resolve_mft(&file_name),
        ContainerFormat::Prefetch => Some((ArtefactKind::Prefetch, IdMethod::Content, 0.99)),
        ContainerFormat::Lnk => Some((ArtefactKind::Lnk, IdMethod::Content, 0.97)),
        ContainerFormat::Ese => resolve_ese(&file_name),
        ContainerFormat::Sqlite => resolve_sqlite(&file_name),
        ContainerFormat::UsnJournal => Some((ArtefactKind::UsnJrnl, IdMethod::Content, 0.9)),
        ContainerFormat::Unknown => resolve_by_path_only(&lower, &file_name),
    };

    match resolved {
        Some((artefact, method, confidence)) => {
            Ok(Identification::Known(Box::new(IdentifiedArtefact {
                evidence_id,
                path: path.to_path_buf(),
                source_path: source_path.to_string(),
                container,
                artefact,
                method,
                confidence,
                profile_hint,
            })))
        }
        None => Ok(Identification::Unclassified(Box::new(UnclassifiedFile {
            evidence_id,
            path: path.to_path_buf(),
            source_path: source_path.to_string(),
            container,
            reason: format!(
                "container {:?} recognized but no matching artefact rule (name: {})",
                container, file_name
            ),
        }))),
    }
}

fn read_prefix(path: &Path, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut f = std::fs::File::open(path)?;
    let mut filled = 0;
    // Read may return short; loop until buffer full or EOF.
    while filled < buf.len() {
        match f.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// All registry hives are `regf`; the root-key name would confirm, but the
/// filename is a strong, cheap disambiguator we validate against hive content
/// later. Specific hive -> nothing here yet (Week 2 registry parser assigns the
/// specialized RegistryRun/Service/etc. kinds); at identification time we just
/// mark it a registry hive so it dispatches to the registry parser.
fn resolve_registry(name: &str) -> Option<(ArtefactKind, IdMethod, f32)> {
    let known = matches!(
        name,
        "system" | "software" | "sam" | "security" | "default"
            | "ntuser.dat" | "usrclass.dat" | "amcache.hve"
    );
    if name == "amcache.hve" {
        // AmCache is a hive but semantically its own artefact.
        return Some((ArtefactKind::Amcache, IdMethod::ContentAndPath, 0.98));
    }
    let confidence = if known { 0.97 } else { 0.85 };
    let method = if known { IdMethod::ContentAndPath } else { IdMethod::Content };
    Some((ArtefactKind::RegistryGeneric, method, confidence))
}

fn resolve_mft(name: &str) -> Option<(ArtefactKind, IdMethod, f32)> {
    if name == "$mft" || name.ends_with("mft") {
        Some((ArtefactKind::Mft, IdMethod::ContentAndPath, 0.98))
    } else {
        // "FILE" magic but unexpected name — still an MFT record stream.
        Some((ArtefactKind::Mft, IdMethod::Content, 0.85))
    }
}

/// ESE disambiguation by filename as a first pass. Real disambiguation is by
/// table schema (SRUDB tables => SRUM), which the ESE parser confirms; the
/// name gets us to the right parser quickly.
fn resolve_ese(name: &str) -> Option<(ArtefactKind, IdMethod, f32)> {
    match name {
        "srudb.dat" => Some((ArtefactKind::Srum, IdMethod::ContentAndPath, 0.97)),
        "amcache.hve" => Some((ArtefactKind::Amcache, IdMethod::ContentAndPath, 0.95)),
        // webcachev01.dat is legacy IE / old-Edge browsing history in ESE format.
        // We don't parse it yet (post-v0.1 — needs a general ESE container reader,
        // unlike the SRUM-specific srum-parser), so it lands as Unclassified and
        // shows honestly as "unsupported" in the ingest log rather than failing.
        _ => Some((ArtefactKind::Unclassified, IdMethod::Content, 0.5)),
    }
}

fn resolve_sqlite(name: &str) -> Option<(ArtefactKind, IdMethod, f32)> {
    if name == "activitiescache.db" {
        // Windows Timeline — SQLite with a distinctive name. Checked before the
        // generic "history" rule. The parser confirms via the Activity table.
        Some((ArtefactKind::WindowsTimeline, IdMethod::ContentAndPath, 0.9))
    } else if name.contains("history") || name.contains("places") {
        // Chromium "History" (incl. modern Edge, which is Chromium) and Firefox
        // "places.sqlite". NOTE: legacy IE / old-Edge history lives in
        // WebCacheV01.dat, which is ESE, not SQLite — it is handled (currently as
        // Unclassified) in resolve_ese, not here. ESE WebCache parsing is a
        // post-v0.1 item; see resolve_ese.
        Some((ArtefactKind::BrowserHistory, IdMethod::ContentAndPath, 0.8))
    } else {
        // Known-good container, unknown schema — hand on as generic sqlite so
        // it's visible, not dropped.
        Some((ArtefactKind::Unclassified, IdMethod::Content, 0.4))
    }
}

/// Last resort when magic bytes told us nothing: pure path/name heuristics.
/// Weak by definition — always PathOnly, low confidence, flagged for analyst
/// review. Covers artefacts with no fixed file magic (e.g. $UsnJrnl:$J,
/// $LogFile).
fn resolve_by_path_only(lower: &str, name: &str) -> Option<(ArtefactKind, IdMethod, f32)> {
    if name.contains("usnjrnl") || lower.contains("$usnjrnl") || name == "$j" {
        Some((ArtefactKind::UsnJrnl, IdMethod::PathOnly, 0.6))
    } else if name == "$logfile" {
        Some((ArtefactKind::LogFile, IdMethod::PathOnly, 0.6))
    } else if name.ends_with(".evtx") {
        // Extension-only EVTX (e.g. header unreadable) — low confidence.
        Some((ArtefactKind::Evtx, IdMethod::PathOnly, 0.55))
    } else if lower.contains("/tasks/") || lower.contains("\\tasks\\") {
        // Scheduled task definitions live under System32\Tasks\ as extension-
        // less XML. Path is the reliable signal; the parser confirms the <Task>
        // root and skips anything that isn't one.
        Some((ArtefactKind::ScheduledTask, IdMethod::PathOnly, 0.6))
    } else if name.ends_with(".automaticdestinations-ms")
        || name.ends_with(".customdestinations-ms")
    {
        // Jump lists: automatic (OLE/CFB compound) or custom (concatenated
        // shell links). Identified by extension; the parser dispatches on which.
        Some((ArtefactKind::JumpList, IdMethod::PathOnly, 0.9))
    } else if name.starts_with("$i") && (lower.contains("$recycle.bin") || lower.contains("recycle")) {
        // Recycle Bin metadata: $I<id>.<ext> under $Recycle.Bin\<SID>\. The $I
        // prefix plus the recycle-bin path is the reliable signal (there's no
        // strong file magic). The parser validates the version byte.
        Some((ArtefactKind::Recycle, IdMethod::PathOnly, 0.85))
    } else if name == "activitiescache.db" {
        // Windows Timeline (ActivitiesCache.db). SQLite; distinctive filename.
        // The parser confirms by querying the Activity table.
        Some((ArtefactKind::WindowsTimeline, IdMethod::PathOnly, 0.9))
    } else if name.ends_with("consolehost_history.txt")
        || (name.ends_with("_history.txt") && lower.contains("psreadline"))
    {
        // PowerShell console history (PSReadLine). Plain text; the distinctive
        // ConsoleHost_history.txt filename is the signal. `ends_with` also
        // catches collector-renamed per-user copies like
        // jsmith_ConsoleHost_history.txt; the PSReadLine-path variant covers any
        // other rename that keeps the directory.
        Some((ArtefactKind::PsHistory, IdMethod::PathOnly, 0.9))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fxid-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }

    #[test]
    fn identifies_system_hive_by_content_and_name() {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"regf");
        let p = write_temp("SYSTEM", &bytes);
        let id = identify_file(&p, "C:/Windows/System32/config/SYSTEM", None).unwrap();
        match id {
            Identification::Known(a) => {
                assert_eq!(a.container, ContainerFormat::RegistryHive);
                assert_eq!(a.method, IdMethod::ContentAndPath);
            }
            _ => panic!("should be known"),
        }
    }

    #[test]
    fn amcache_hive_maps_to_amcache_artefact() {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"regf");
        let p = write_temp("Amcache.hve", &bytes);
        let id = identify_file(&p, ".../Amcache.hve", None).unwrap();
        match id {
            Identification::Known(a) => assert_eq!(a.artefact, ArtefactKind::Amcache),
            _ => panic!("should be known"),
        }
    }

    #[test]
    fn wrong_extension_still_identified_by_content() {
        // A registry hive misnamed ".txt" must still be caught by magic bytes.
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"regf");
        let p = write_temp("notes.txt", &bytes);
        let id = identify_file(&p, "loose/notes.txt", None).unwrap();
        match id {
            Identification::Known(a) => assert_eq!(a.container, ContainerFormat::RegistryHive),
            _ => panic!("content must beat extension"),
        }
    }

    #[test]
    fn truly_unknown_goes_to_unclassified() {
        let p = write_temp("mystery.bin", &[0x00, 0x11, 0x22, 0x33, 0x44]);
        let id = identify_file(&p, "loose/mystery.bin", None).unwrap();
        assert!(matches!(id, Identification::Unclassified(_)));
    }

    #[test]
    fn jumplist_identified_by_extension() {
        // Automatic-destinations jump lists are OLE/CFB with no magic we sniff;
        // the -ms extension is the reliable path signal.
        let p = write_temp("1b4dd67f29cb1962.automaticDestinations-ms", &[0u8; 32]);
        let id = identify_file(
            &p,
            "AppData/.../1b4dd67f29cb1962.automaticDestinations-ms",
            None,
        )
        .unwrap();
        match id {
            Identification::Known(a) => {
                assert_eq!(a.artefact, ArtefactKind::JumpList);
                assert_eq!(a.method, IdMethod::PathOnly);
            }
            _ => panic!("jump list should be identified by extension"),
        }
    }
}
