//! Per-artefact registry extractors.
//!
//! Each [`Extractor`] owns one registry-derived artefact: it declares which
//! key paths it cares about (`matches`) and turns matching keys into events
//! (`extract`). This keeps the persistence/execution/lateral-movement logic
//! modular and independently testable, and makes adding a new registry
//! artefact a matter of adding one extractor to `default_extractors()`.
//!
//! Coverage here is chosen for financially-motivated actor TTPs:
//!   * Run / RunOnce         — persistence (T1547.001)
//!   * Services              — persistence + lateral tooling (T1543.003)
//!   * AppCompatCache        — execution evidence / defense evasion (T1112)
//!   * UserAssist            — GUI program execution (T1204)
//!   * BAM/DAM               — background activity moderator exec times
//!   * RDP (Terminal Server) — lateral movement config (T1021.001)
//!
//! ShimCache (AppCompatCache) and UserAssist encode their own timestamps and
//! need value-blob decoding; those decoders are stubbed with clear TODOs so
//! the structure is real even where the binary decode is Week-2-continued.

use super::{key_raw, make_event, value_pairs, value_string, Ctx};
use fx_core::{ArtefactKind, EventSink, ParseOutcome, Principal, ProcessInfo, TimestampKind};
use notatin::cell_key_node::CellKeyNode;
use serde_json::json;
use time::OffsetDateTime;

/// One registry-derived artefact.
pub(crate) trait Extractor: Send + Sync {
    /// Does this extractor care about the given key path? Case-insensitive
    /// substring/suffix checks against the notatin full path.
    fn matches(&self, key_path: &str) -> bool;

    /// Emit events for a matching key.
    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    );
}

/// The default set, in no particular order (a key may match several).
pub(crate) fn default_extractors() -> Vec<Box<dyn Extractor>> {
    vec![
        Box::new(RunKeys),
        Box::new(Services),
        Box::new(AppCompatCache),
        Box::new(UserAssist),
        Box::new(BamDam),
        Box::new(RdpConfig),
        Box::new(AmcacheInventoryFile),
        Box::new(AmcacheLegacyFile),
        Box::new(ShellBags),
        Box::new(UsbDevices),
        Box::new(NetworkProfiles),
        Box::new(AutostartExtras),
        Box::new(RunMru),
        Box::new(RdpClientMru),
    ]
}

fn ci_contains(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn ci_ends_with(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().ends_with(&needle.to_ascii_lowercase())
}

// ── Run / RunOnce keys ──────────────────────────────────────────────────────
// Each *value* under a Run key is a persistence entry: name -> command line.
struct RunKeys;
impl Extractor for RunKeys {
    fn matches(&self, p: &str) -> bool {
        ci_ends_with(p, r"\CurrentVersion\Run")
            || ci_ends_with(p, r"\CurrentVersion\RunOnce")
            || ci_ends_with(p, r"\CurrentVersion\RunServices")
            || ci_ends_with(p, r"\CurrentVersion\RunServicesOnce")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        for (name, command) in value_pairs(key) {
            sink.emit(make_event(
                ctx,
                ArtefactKind::RegistryRun,
                lastwrite,
                TimestampKind::Modified, // key LastWrite, not a true exec time
                "persistence.run_key",
                key_path,
                Some(&name),
                Some(command.clone()),
                Principal::default(),
                format!("Run-key persistence: {name} -> {command}"),
                json!({ "key": key_path, "name": name, "command": command }),
            ));
            outcome.events_emitted += 1;
        }
    }
}

// ── Services ────────────────────────────────────────────────────────────────
// Under ...\Services\<Name> with ImagePath / Start / Type. Service install &
// tampering is core to ransomware affiliate tooling (PsExec, Cobalt Strike
// service persistence).
struct Services;
impl Extractor for Services {
    fn matches(&self, p: &str) -> bool {
        // Match the immediate service subkeys, not the Services root itself.
        ci_contains(p, r"\Services\") && !ci_ends_with(p, r"\Services")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        let image = value_string(key, "ImagePath");
        // Only emit for keys that actually look like a service definition.
        if image.is_none() && value_string(key, "Type").is_none() {
            return;
        }
        let start = value_string(key, "Start").unwrap_or_default();
        let name = key_path.rsplit('\\').next().unwrap_or(key_path).to_string();
        sink.emit(make_event(
            ctx,
            ArtefactKind::RegistryService,
            lastwrite,
            TimestampKind::Modified,
            "service.define",
            key_path,
            Some("ImagePath"),
            image.clone(),
            Principal::default(),
            format!(
                "Service {name}: image={} start={start}",
                image.clone().unwrap_or_else(|| "<none>".into())
            ),
            json!({ "key": key_path, "service": name, "image_path": image, "start": start }),
        ));
        outcome.events_emitted += 1;
    }
}

// ── AppCompatCache / ShimCache ──────────────────────────────────────────────
// SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache, value
// "AppCompatCache" — a binary blob of recently-present executables with
// timestamps. High-value execution/presence evidence and a defense-evasion
// signal. The blob format is Windows-version dependent.
struct AppCompatCache;
impl Extractor for AppCompatCache {
    fn matches(&self, p: &str) -> bool {
        ci_ends_with(p, r"\Control\Session Manager\AppCompatCache")
            || ci_ends_with(p, r"\Control\Session Manager\AppCompatibility")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        // TODO(week2-cont): decode the AppCompatCache binary blob per Windows
        // version (Win7/8/10/11 headers differ). For now emit one marker event
        // recording that the cache is present, so it shows on the timeline and
        // the raw blob is retained for the decoder to consume. This keeps the
        // artefact visible and the pipeline honest rather than silently
        // dropping partially-supported data.
        let present = key
            .value_iter()
            .any(|v| super::value_name(&v).eq_ignore_ascii_case("AppCompatCache"));
        if !present {
            return;
        }
        sink.emit(make_event(
            ctx,
            ArtefactKind::ShimCache,
            lastwrite,
            TimestampKind::Recorded,
            "execution.shimcache_present",
            key_path,
            Some("AppCompatCache"),
            None,
            Principal::default(),
            "AppCompatCache present (blob decode pending)".into(),
            key_raw(key_path, key),
        ));
        outcome.events_emitted += 1;
        outcome.warnings.push(fx_core::RecordWarning {
            source_ref: Some(key_path.to_string()),
            message: "AppCompatCache blob not yet decoded; marker event emitted".into(),
        });
    }
}

// ── UserAssist ──────────────────────────────────────────────────────────────
// NTUSER: ...\Explorer\UserAssist\{GUID}\Count — ROT13-encoded program names
// with run counts and last-execution times. GUI execution evidence.
struct UserAssist;
impl Extractor for UserAssist {
    fn matches(&self, p: &str) -> bool {
        ci_contains(p, r"\Explorer\UserAssist\") && ci_ends_with(p, r"\Count")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        for v in key.value_iter() {
            let vname = super::value_name(&v);
            // Value names are ROT13-encoded paths, often prefixed with a
            // KNOWNFOLDERID GUID ({6D809377-...}\app.exe = Program Files).
            let decoded = rot13(&vname);
            if decoded.starts_with("UEME_") {
                continue; // session / control bookkeeping values, not programs
            }
            let path = expand_known_folder(&decoded);
            let stats = decode_userassist(&super::value_bytes(&v));
            // Prefer the decoded last-run FILETIME; many entries (focus-only,
            // never launched via Explorer) have none, so fall back to the key
            // LastWrite and say so in raw.
            let (ts, time_source) = match stats.as_ref().and_then(|s| s.last_run) {
                Some(t) => (t, "last_run"),
                None => (lastwrite, "key_lastwrite"),
            };
            let runs = stats.as_ref().map(|s| s.run_count);
            let mut ev = make_event(
                ctx,
                ArtefactKind::UserAssist,
                ts,
                TimestampKind::Executed,
                "execution.userassist",
                key_path,
                Some(&vname),
                Some(path.clone()),
                Principal::default(),
                match runs {
                    Some(n) => format!("UserAssist: {path} (run {n}×)"),
                    None => format!("UserAssist: {path}"),
                },
                json!({
                    "key": key_path,
                    "encoded": vname,
                    "decoded": decoded,
                    "path": path,
                    "run_count": runs,
                    "focus_count": stats.as_ref().and_then(|s| s.focus_count),
                    "focus_ms": stats.as_ref().and_then(|s| s.focus_ms),
                    "time_source": time_source,
                }),
            );
            ev.process = Some(exe_process(&path));
            sink.emit(ev);
            outcome.events_emitted += 1;
        }
    }
}

// ── BAM / DAM ───────────────────────────────────────────────────────────────
// SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>\<exe path> =
// last-execution FILETIME. Per-user execution evidence with time, keyed by SID
// — excellent for tying activity to an account.
struct BamDam;
impl Extractor for BamDam {
    fn matches(&self, p: &str) -> bool {
        ci_contains(p, r"\bam\") && ci_contains(p, r"\UserSettings\")
            || ci_contains(p, r"\dam\") && ci_contains(p, r"\UserSettings\")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        // The SID is the key segment right after UserSettings\.
        let sid = key_path
            .split(r"\UserSettings\")
            .nth(1)
            .and_then(|rest| rest.split('\\').next())
            .map(str::to_string);

        for v in key.value_iter() {
            let vname = super::value_name(&v);
            // Each value name is an executable path; the first 8 bytes of the
            // data are the last-execution FILETIME.
            if vname.eq_ignore_ascii_case("Version")
                || vname.eq_ignore_ascii_case("SequenceNumber")
            {
                continue;
            }
            let exec_time = filetime_at(&super::value_bytes(&v), 0).unwrap_or(lastwrite);
            let mut ev = make_event(
                ctx,
                ArtefactKind::BamDam,
                exec_time,
                TimestampKind::Executed,
                "execution.bam",
                key_path,
                Some(&vname),
                Some(vname.clone()),
                Principal {
                    sid: sid.clone(),
                    ..Default::default()
                },
                format!(
                    "BAM execution: {} (user {})",
                    vname,
                    sid.clone().unwrap_or_else(|| "?".into())
                ),
                json!({ "key": key_path, "exe": vname, "sid": sid }),
            );
            ev.process = Some(exe_process(&vname));
            sink.emit(ev);
            outcome.events_emitted += 1;
        }
    }
}

// ── RDP / Terminal Server config ────────────────────────────────────────────
// fDenyTSConnections and related values indicate whether RDP is enabled — a
// lateral-movement enabler attackers frequently flip on.
struct RdpConfig;
impl Extractor for RdpConfig {
    fn matches(&self, p: &str) -> bool {
        ci_ends_with(p, r"\Control\Terminal Server")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        if let Some(deny) = value_string(key, "fDenyTSConnections") {
            // "0" means RDP is ENABLED.
            let enabled = deny.trim() == "0";
            sink.emit(make_event(
                ctx,
                ArtefactKind::RegistryGeneric,
                lastwrite,
                TimestampKind::Modified,
                if enabled { "rdp.enabled" } else { "rdp.disabled" },
                key_path,
                Some("fDenyTSConnections"),
                None,
                Principal::default(),
                format!("RDP {} (fDenyTSConnections={deny})", if enabled { "ENABLED" } else { "disabled" }),
                json!({ "key": key_path, "fDenyTSConnections": deny, "rdp_enabled": enabled }),
            ));
            outcome.events_emitted += 1;
        }
    }
}

// ── AmCache: modern schema (Win10 1607+) ────────────────────────────────────
// Root\InventoryApplicationFile\<hash> — one subkey per inventoried file, with
// LowerCaseLongPath, FileId (SHA-1 with a leading 0000), Size, etc. AmCache is
// evidence of *presence*, not proof of execution, but the path+SHA-1 pairing is
// gold: it identifies attacker tooling and enables threat-intel pivots even
// after the binary self-deletes (common for ransomware).
struct AmcacheInventoryFile;
impl Extractor for AmcacheInventoryFile {
    fn matches(&self, p: &str) -> bool {
        ci_contains(p, r"\InventoryApplicationFile\")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        let path = value_string(key, "LowerCaseLongPath").unwrap_or_default();
        if path.is_empty() {
            return; // container/other subkey without a file path
        }
        let sha1 = value_string(key, "FileId")
            .map(|id| strip_amcache_fileid(&id))
            .unwrap_or_default();
        let size = value_string(key, "Size");
        let publisher = value_string(key, "Publisher").unwrap_or_default();

        emit_amcache_file(
            ctx, sink, outcome, key_path, lastwrite, &path, &sha1, size.as_deref(),
            &publisher, "amcache_inventory",
        );
    }
}

// ── AmCache: legacy schema (Win7 / Win8 / Win10 pre-1607) ────────────────────
// Root\File\{VolumeGUID}\<seq> with numbered values: 15 = full path,
// 101 = SHA-1 (same 0000 prefix), 0 = product, 1 = publisher.
struct AmcacheLegacyFile;
impl Extractor for AmcacheLegacyFile {
    fn matches(&self, p: &str) -> bool {
        ci_contains(p, r"\Root\File\") || p.to_ascii_lowercase().contains(r"\file\{")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        let path = value_string(key, "15").unwrap_or_default();
        if path.is_empty() {
            return;
        }
        let sha1 = value_string(key, "101")
            .map(|id| strip_amcache_fileid(&id))
            .unwrap_or_default();
        let publisher = value_string(key, "1").unwrap_or_default();

        emit_amcache_file(
            ctx, sink, outcome, key_path, lastwrite, &path, &sha1, None,
            &publisher, "amcache_legacy",
        );
    }
}

/// Shared emit for both AmCache schemas: one presence event, tagged suspicious
/// where the path warrants it. Baking the two cheapest high-value AmCache
/// triage detections in here means they surface the moment a hive is parsed,
/// before any hunt runs.
#[allow(clippy::too_many_arguments)]
fn emit_amcache_file(
    ctx: &Ctx,
    sink: &mut dyn EventSink,
    outcome: &mut ParseOutcome,
    key_path: &str,
    lastwrite: OffsetDateTime,
    path: &str,
    sha1: &str,
    size: Option<&str>,
    publisher: &str,
    schema: &str,
) {
    let suspicion = amcache_suspicion(path);
    let mut message = format!("AmCache presence: {path}");
    if !sha1.is_empty() {
        message.push_str(&format!(" (SHA1 {sha1})"));
    }
    if let Some(tag) = &suspicion {
        message.push_str(&format!("  [{tag}]"));
    }

    sink.emit(make_event(
        ctx,
        ArtefactKind::Amcache,
        lastwrite,
        // Presence, not execution — Recorded rather than Executed.
        TimestampKind::Recorded,
        if suspicion.is_some() {
            "execution.amcache_suspicious"
        } else {
            "execution.amcache_presence"
        },
        key_path,
        None,
        Some(path.to_string()),
        Principal::default(),
        message,
        json!({
            "schema": schema,
            "path": path,
            "sha1": sha1,
            "size": size,
            "publisher": publisher,
            "suspicion": suspicion,
        }),
    ));
    outcome.events_emitted += 1;
}

/// FileId -> SHA-1: AmCache stores the SHA-1 as a hex string with a leading
/// "0000". Strip those four zeros if present.
fn strip_amcache_fileid(file_id: &str) -> String {
    let t = file_id.trim();
    t.strip_prefix("0000").unwrap_or(t).to_ascii_lowercase()
}

/// The two cheapest, most productive AmCache triage detections for commodity
/// e-crime, per the DFIR literature:
///   * a Windows *system* binary name at a non-System32 path (masquerading,
///     T1036.005)
///   * any executable inventoried from a common staging directory
///     (Temp / Downloads / AppData / ProgramData / $Recycle.Bin, T1204)
fn amcache_suspicion(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let file = lower.rsplit('\\').next().unwrap_or(&lower);

    const SYSTEM_BINARIES: &[&str] = &[
        "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "smss.exe",
        "winlogon.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe",
    ];
    if SYSTEM_BINARIES.contains(&file)
        && !lower.contains(r"\windows\system32\")
        && !lower.contains(r"\windows\syswow64\")
    {
        return Some("MASQUERADE: system binary at non-System32 path".into());
    }

    const STAGING: &[&str] = &[
        r"\temp\", r"\tmp\", r"\downloads\", r"\appdata\", r"\programdata\",
        r"\$recycle.bin\", r"\perflogs\", r"\users\public\",
    ];
    if STAGING.iter().any(|d| lower.contains(d)) {
        return Some("STAGING: executable in common staging directory".into());
    }

    None
}

// ── ShellBags (folder browsing history) ─────────────────────────────────────
// BagMRU tree under NTUSER.DAT (Shell\BagMRU) or UsrClass.dat (Local Settings\
// ...\Shell\BagMRU). Each node key holds REG_BINARY values named "0","1",… —
// one shell item (ITEMIDLIST) per child folder the user browsed. The forensic
// value: an entry exists BECAUSE the folder was navigated to in Explorer, and
// it persists after the folder / volume / USB stick is gone. The key LastWrite
// is when that node was last browsed.
//
// A full libfwsi-grade ITEMIDLIST decode is out of scope; we extract the folder
// name embedded in the shell item (present as readable UTF-16/ASCII in the
// common folder item types) and flag items that reference a drive-letter volume
// or network location — the highest-signal facts for staging / removable-media
// review.
struct ShellBags;
impl Extractor for ShellBags {
    fn matches(&self, p: &str) -> bool {
        ci_contains(p, r"\Shell\BagMRU")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        // Node path of this key under BagMRU ("" for the root, "0\3" for a
        // child). Each numbered value N here is the child node "<node>\N".
        let (bag_root, node) = match key_path.to_ascii_lowercase().find(r"\bagmru") {
            Some(ix) => {
                let end = ix + r"\bagmru".len();
                (key_path[..end].to_string(), key_path[end..].trim_start_matches('\\').to_string())
            }
            None => return,
        };
        for v in key.value_iter() {
            let name = super::value_name(&v);
            // Only numbered slot values hold child shell items.
            if !name.chars().all(|c| c.is_ascii_digit()) || name.is_empty() {
                continue;
            }
            let bytes = super::value_bytes(&v);
            if bytes.len() < 4 {
                continue;
            }
            let child = if node.is_empty() { name.clone() } else { format!("{node}\\{name}") };
            // Parse the shell item properly; items we can't name (GUID-only
            // device / control-panel items) are skipped rather than mis-named.
            let Some(item) = parse_shell_item(&bytes) else { continue };
            let full = shellbag_remember(&ctx.source_path, &bag_root, &child, &item);
            // Roots (This PC, Network…) are remembered for path building but
            // aren't a folder the user browsed, so they don't get an event.
            if item.kind == ShellItemKind::Root {
                continue;
            }
            let folder = full.clone().unwrap_or_else(|| item.name.clone());

            let is_volume = item.kind == ShellItemKind::Volume || looks_like_volume(&folder);
            let mut message = format!("ShellBag (folder browsed): {folder}");
            if is_volume {
                message.push_str("  [VOLUME/REMOVABLE]");
            }

            sink.emit(make_event(
                ctx,
                ArtefactKind::ShellBags,
                lastwrite,
                // The bag records that the folder was browsed at ~LastWrite.
                TimestampKind::Accessed,
                if is_volume { "browse.shellbag_volume" } else { "browse.shellbag" },
                key_path,
                Some(&name),
                Some(folder.clone()),
                Principal::default(),
                message,
                json!({
                    "key": key_path,
                    "slot": name,
                    "node": child,
                    "folder": folder,
                    "item_name": item.name,
                    "item_type": format!("0x{:02x}", item.class),
                    "volume_or_removable": is_volume,
                    "shell_item_bytes": bytes.len(),
                }),
            ));
            outcome.events_emitted += 1;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellItemKind {
    Root,
    Volume,
    Folder,
    Network,
}

#[derive(Debug, Clone)]
struct ShellItem {
    kind: ShellItemKind,
    class: u8,
    name: String,
}

/// Parse one shell item (an ITEMIDLIST entry stored in a BagMRU slot) into a
/// name, following the item's real structure rather than scanning for text:
///
/// * 0x1F root folder: a GUID, mapped to its known name (This PC, Network…)
/// * 0x2X volume: ASCII drive string at offset 3 ("C:\")
/// * 0x3X file entry: 8.3 name at offset 14, long name from the 0xBEEF0004
///   extension block (UTF-16, offset depends on the block version)
/// * 0x4X network location: ASCII path at offset 5 ("\\server\share")
/// * 0x74 delegate (users-files) item: an embedded file entry after "CFSF"
///
/// Scanning the blob for "the longest readable run" (the previous approach)
/// picked up size/attribute bytes decoded as UTF-16, which showed as stray
/// CJK characters before names, or as junk like "F]|lF]Zw." for item types
/// it couldn't read. Unknown or unreadable items now return None.
fn parse_shell_item(b: &[u8]) -> Option<ShellItem> {
    if b.len() < 4 {
        return None;
    }
    let class = b[2];
    let item = |kind, name: String| clean_name(&name).map(|name| ShellItem { kind, class, name });
    match class {
        0x1F => {
            let guid = guid_at(b, 4)?;
            known_folder_name(&guid).and_then(|n| item(ShellItemKind::Root, n.to_string()))
        }
        0x20..=0x2F => {
            let s = ascii_z(b, 3)?;
            let s = s.trim_end_matches('\\');
            if s.len() >= 2 && s.as_bytes()[1] == b':' {
                item(ShellItemKind::Volume, format!("{s}\\"))
            } else {
                None
            }
        }
        0x30..=0x3F | 0xB1 => file_entry_name(b, 0).and_then(|n| item(ShellItemKind::Folder, n)),
        0x40..=0x4F => ascii_z(b, 5).and_then(|n| item(ShellItemKind::Network, n)),
        0x74 => {
            // Delegate item: "CFSF" then an embedded file-entry item.
            let at = find(b, b"CFSF")?;
            let inner = at + 4;
            file_entry_name(b, inner)
                .or_else(|| beef0004_long_name(b))
                .and_then(|n| item(ShellItemKind::Folder, n))
        }
        _ => beef0004_long_name(b).and_then(|n| item(ShellItemKind::Folder, n)),
    }
}

/// File-entry item starting at `base` (its size field). Prefers the long name
/// in the BEEF0004 extension; falls back to the primary (8.3) name.
fn file_entry_name(b: &[u8], base: usize) -> Option<String> {
    let class = *b.get(base + 2)?;
    let unicode = class & 0x04 != 0;
    let off = base + 14;
    let primary = if unicode { utf16_z(b, off) } else { ascii_z(b, off) };
    beef0004_long_name(&b[base..]).or(primary)
}

/// Long name from the first 0xBEEF0004 extension block, if present.
fn beef0004_long_name(b: &[u8]) -> Option<String> {
    let sig = find(b, &[0x04, 0x00, 0xEF, 0xBE])?;
    if sig < 4 {
        return None;
    }
    let ext = sig - 4;
    let size = u16::from_le_bytes([*b.get(ext)?, *b.get(ext + 1)?]) as usize;
    let version = u16::from_le_bytes([*b.get(ext + 2)?, *b.get(ext + 3)?]);
    // Offset of the long name within the block, by extension version
    // (per the libfwsi documentation of the BEEF0004 block).
    let rel = match version {
        3..=6 => 20,
        7 => 38,
        8 => 42,
        v if v >= 9 => 46,
        _ => return None,
    };
    let end = if size >= rel && ext + size <= b.len() { ext + size } else { b.len() };
    utf16_z(&b[..end], ext + rel)
}

/// Reject names that aren't plausible folder names (control characters,
/// decoding replacement characters, or nothing alphanumeric).
fn clean_name(s: &str) -> Option<String> {
    let t = s.trim().trim_matches('\0');
    if t.is_empty()
        || t.chars().any(|c| c.is_control() || c == '\u{FFFD}')
        || !t.chars().any(|c| c.is_alphanumeric())
    {
        return None;
    }
    Some(t.to_string())
}

fn ascii_z(b: &[u8], off: usize) -> Option<String> {
    let rest = b.get(off..)?;
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    let s = &rest[..end];
    if s.is_empty() || !s.iter().all(|&c| (0x20..0x7f).contains(&c)) {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

fn utf16_z(b: &[u8], off: usize) -> Option<String> {
    let mut units = Vec::new();
    let mut i = off;
    while i + 1 < b.len() {
        let u = u16::from_le_bytes([b[i], b[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    if units.is_empty() {
        return None;
    }
    String::from_utf16(&units).ok()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn guid_at(b: &[u8], off: usize) -> Option<String> {
    let g = b.get(off..off + 16)?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    ))
}

/// Root-folder GUIDs seen in BagMRU, mapped to the names Explorer shows.
fn known_folder_name(guid: &str) -> Option<&'static str> {
    Some(match guid {
        "20d04fe0-3aea-1069-a2d8-08002b30309d" => "This PC",
        "208d2c60-3aea-1069-a2d7-08002b30309d" => "Network",
        "f02c1a0d-be21-4350-88b0-7367fc96ef3c" => "Network",
        "59031a47-3f72-44a7-89c5-5595fe6b30ee" => "User folder",
        "031e4825-7b94-4dc3-b131-e946b44c8dd5" => "Libraries",
        "679f85cb-0220-4080-b29b-5540cc05aab6" => "Quick access",
        "645ff040-5081-101b-9f08-00aa002f954e" => "Recycle Bin",
        "21ec2020-3aea-1069-a2dd-08002b30309d" => "Control Panel",
        "26ee0668-a00a-44d7-9371-beb064c98683" => "Control Panel",
        "374de290-123f-4565-9164-39c4925e467b" => "Downloads",
        "b4bfcc3a-db2c-424c-b029-7fe99a87c641" => "Desktop",
        "d3162b92-9365-467a-956b-92703aca08af" => "Documents",
        "088e3905-0323-4b02-9826-5d99428e115f" => "Downloads",
        "24ad3ad4-a569-4530-98e1-ab02f9417aa8" => "Pictures",
        "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de" => "Music",
        "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a" => "Videos",
        "018d5c66-4533-4307-9b53-224de2ed1fe6" => "OneDrive",
        _ => return None,
    })
}

thread_local! {
    /// BagMRU node -> name, per hive, so each slot can be shown as a full
    /// path ("C:\Users\x\AppData\Roaming") instead of just its last folder.
    /// The registry walk visits a key before its subkeys, so a node's parent
    /// is always known by the time the node itself is read.
    static SHELLBAG_NODES: std::cell::RefCell<(String, std::collections::HashMap<String, ShellItem>)> =
        std::cell::RefCell::new((String::new(), std::collections::HashMap::new()));
}

/// Record a node's item and return its full path, built from its ancestors.
/// Roots like "This PC" are omitted when a drive letter follows them.
fn shellbag_remember(source: &str, bag_root: &str, node: &str, item: &ShellItem) -> Option<String> {
    SHELLBAG_NODES.with(|cell| {
        let mut st = cell.borrow_mut();
        if st.0 != source {
            st.0 = source.to_string();
            st.1.clear();
        }
        st.1.insert(format!("{bag_root}|{node}"), item.clone());
        let parts: Vec<&str> = node.split('\\').collect();
        let mut chain: Vec<ShellItem> = Vec::new();
        for i in 1..=parts.len() {
            let key = format!("{bag_root}|{}", parts[..i].join("\\"));
            match st.1.get(&key) {
                Some(it) => chain.push(it.clone()),
                None => return None, // ancestor unknown (e.g. deleted key): name only
            }
        }
        // Drop root items that precede a volume or network path.
        let start = chain
            .iter()
            .rposition(|it| matches!(it.kind, ShellItemKind::Volume | ShellItemKind::Network))
            .unwrap_or(0);
        let mut out = String::new();
        for it in &chain[start..] {
            if out.is_empty() {
                out.push_str(&it.name);
            } else {
                if !out.ends_with('\\') {
                    out.push('\\');
                }
                out.push_str(&it.name);
            }
        }
        Some(out)
    })
}

/// Does the extracted name look like a drive-letter volume (e.g. "E:\" or
/// "C:")? These attest browsing on a specific (possibly removable) volume.
fn looks_like_volume(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

// ── USB / removable-device history (SYSTEM hive) ────────────────────────────
// USBSTOR subkeys record each removable device ever attached: vendor/product in
// the subkey name, and FriendlyName under the instance. High value for data-
// theft cases — complements the LNK/jump-list removable-media flagging.
struct UsbDevices;
impl Extractor for UsbDevices {
    fn matches(&self, p: &str) -> bool {
        // Device instance keys live two levels under USBSTOR:
        //   ...\Enum\USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\<serial>
        ci_contains(p, r"\USBSTOR\") || ci_contains(p, r"\Enum\USB\")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        // Only emit for instance keys that carry a FriendlyName — that's the
        // leaf that represents an actual device, not the Ven/Prod grouping key.
        let friendly = value_string(key, "FriendlyName");
        let Some(friendly) = friendly else { return };
        // The serial/instance id is the last path segment.
        let serial = key_path.rsplit('\\').next().unwrap_or("").to_string();
        // The device descriptor (Ven/Prod) is the parent segment.
        let descriptor = key_path
            .rsplit('\\')
            .nth(1)
            .unwrap_or("")
            .to_string();

        sink.emit(make_event(
            ctx,
            ArtefactKind::RegistryGeneric,
            lastwrite,
            TimestampKind::Modified,
            "device.usb_connected",
            key_path,
            Some(&serial),
            Some(friendly.clone()),
            Principal::default(),
            format!("USB device: {friendly} ({descriptor}) serial {serial}"),
            json!({
                "key": key_path,
                "friendly_name": friendly,
                "descriptor": descriptor,
                "serial": serial,
            }),
        ));
        outcome.events_emitted += 1;
    }
}

// ── Network profiles (SOFTWARE hive) ────────────────────────────────────────
// NetworkList\Profiles subkeys record every network the host joined, with the
// profile (SSID/domain) name and first/last-connected dates. Useful for placing
// a host on a network and spotting rogue/attacker infrastructure.
struct NetworkProfiles;
impl Extractor for NetworkProfiles {
    fn matches(&self, p: &str) -> bool {
        ci_contains(p, r"\NetworkList\Profiles\")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        let name = value_string(key, "ProfileName");
        let Some(name) = name else { return };
        let category = value_string(key, "NameType").unwrap_or_default();
        let managed = value_string(key, "Managed").unwrap_or_default();

        sink.emit(make_event(
            ctx,
            ArtefactKind::RegistryGeneric,
            lastwrite,
            TimestampKind::Modified,
            "network.profile",
            key_path,
            None,
            Some(name.clone()),
            Principal::default(),
            format!("Network profile joined: {name}"),
            json!({
                "key": key_path,
                "profile_name": name,
                "name_type": category,
                "managed": managed,
            }),
        ));
        outcome.events_emitted += 1;
    }
}

// ── Additional autostart / persistence locations (SOFTWARE/SYSTEM) ──────────
// Winlogon Shell/Userinit hijacks, Image File Execution Options debuggers, and
// AppInit_DLLs — classic persistence/evasion spots the Run-key and Services
// extractors don't cover.
struct AutostartExtras;
impl Extractor for AutostartExtras {
    fn matches(&self, p: &str) -> bool {
        ci_ends_with(p, r"\Microsoft\Windows NT\CurrentVersion\Winlogon")
            || ci_contains(p, r"\Image File Execution Options\")
            || ci_ends_with(p, r"\Microsoft\Windows NT\CurrentVersion\Windows")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        // Winlogon Shell/Userinit — only flag when overridden from defaults.
        if ci_ends_with(key_path, r"\Winlogon") {
            for vn in ["Shell", "Userinit"] {
                if let Some(val) = value_string(key, vn) {
                    let suspicious = !is_default_winlogon(vn, &val);
                    sink.emit(make_event(
                        ctx,
                        ArtefactKind::RegistryGeneric,
                        lastwrite,
                        TimestampKind::Modified,
                        if suspicious { "persistence.winlogon_hijack" } else { "registry.winlogon" },
                        key_path,
                        Some(vn),
                        Some(val.clone()),
                        Principal::default(),
                        format!(
                            "Winlogon {vn}: {val}{}",
                            if suspicious { "  [NON-DEFAULT]" } else { "" }
                        ),
                        json!({ "key": key_path, "value": vn, "data": val, "non_default": suspicious }),
                    ));
                    outcome.events_emitted += 1;
                }
            }
        }

        // IFEO Debugger — a debugger value is a classic hijack (sticky-keys etc).
        if ci_contains(key_path, r"\Image File Execution Options\") {
            if let Some(dbg) = value_string(key, "Debugger") {
                let target = key_path.rsplit('\\').next().unwrap_or("").to_string();
                sink.emit(make_event(
                    ctx,
                    ArtefactKind::RegistryGeneric,
                    lastwrite,
                    TimestampKind::Modified,
                    "persistence.ifeo_debugger",
                    key_path,
                    Some("Debugger"),
                    Some(dbg.clone()),
                    Principal::default(),
                    format!("IFEO debugger hijack: {target} -> {dbg}"),
                    json!({ "key": key_path, "image": target, "debugger": dbg }),
                ));
                outcome.events_emitted += 1;
            }
        }

        // AppInit_DLLs — DLLs loaded into every GUI process.
        if ci_ends_with(key_path, r"\CurrentVersion\Windows") {
            if let Some(dlls) = value_string(key, "AppInit_DLLs") {
                if !dlls.trim().is_empty() {
                    sink.emit(make_event(
                        ctx,
                        ArtefactKind::RegistryGeneric,
                        lastwrite,
                        TimestampKind::Modified,
                        "persistence.appinit_dll",
                        key_path,
                        Some("AppInit_DLLs"),
                        Some(dlls.clone()),
                        Principal::default(),
                        format!("AppInit_DLLs persistence: {dlls}"),
                        json!({ "key": key_path, "appinit_dlls": dlls }),
                    ));
                    outcome.events_emitted += 1;
                }
            }
        }
    }
}

/// Is a Winlogon Shell/Userinit value the stock default (so not a hijack)?
fn is_default_winlogon(value_name: &str, data: &str) -> bool {
    let d = data.trim().to_lowercase();
    match value_name {
        "Shell" => d == "explorer.exe",
        "Userinit" => {
            // Default is "...\userinit.exe," (with trailing comma). Treat a value
            // that is ONLY userinit.exe (optionally comma) as default.
            let stripped = d.trim_end_matches(',');
            stripped.ends_with(r"\userinit.exe") || stripped == "userinit.exe"
        }
        _ => false,
    }
}

/// ROT13 for UserAssist value names (letters only; other chars pass through).
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_roundtrip() {
        let original = r"{GUID}\Microsoft.Windows.Explorer";
        assert_eq!(rot13(&rot13(original)), original);
    }

    #[test]
    fn run_key_path_matching() {
        let e = RunKeys;
        assert!(e.matches(r"CsiTool\Microsoft\Windows\CurrentVersion\Run"));
        assert!(e.matches(r"...\CurrentVersion\RunOnce"));
        assert!(!e.matches(r"...\CurrentVersion\Runnable"));
    }

    #[test]
    fn services_excludes_root() {
        let e = Services;
        assert!(e.matches(r"ControlSet001\Services\MyEvilSvc"));
        assert!(!e.matches(r"ControlSet001\Services"));
    }

    #[test]
    fn rdp_only_matches_terminal_server_root() {
        let e = RdpConfig;
        assert!(e.matches(r"ControlSet001\Control\Terminal Server"));
        assert!(!e.matches(r"ControlSet001\Control\Terminal Server\WinStations"));
    }
}

// ── RunMRU ──────────────────────────────────────────────────────────────────
// NTUSER\...\Explorer\RunMRU: commands typed into Win+R. Values a, b, c ...
// hold "command\1"; MRUList orders them most-recent-first. Hands-on-keyboard
// evidence — attackers on an interactive session type cmd, powershell, mstsc,
// UNC paths here. Only the most recent entry's time is known (key LastWrite);
// older entries carry the same timestamp but are tagged with their MRU rank.
// The command lands in process.command_line so every command-line hunt rule
// covers it automatically.
struct RunMru;
impl Extractor for RunMru {
    fn matches(&self, p: &str) -> bool {
        ci_ends_with(p, r"\Explorer\RunMRU")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        let order = value_string(key, "MRUList").unwrap_or_default();
        for (name, data) in value_pairs(key) {
            if name.eq_ignore_ascii_case("MRUList") || name.chars().count() != 1 {
                continue;
            }
            let cmd = strip_mru_suffix(&data);
            if cmd.is_empty() {
                continue;
            }
            let rank = order.find(name.as_str()).map(|i| i + 1);
            let mut ev = make_event(
                ctx,
                ArtefactKind::RegistryGeneric,
                lastwrite,
                TimestampKind::Modified,
                "execution.runmru",
                key_path,
                Some(&name),
                None,
                Principal::default(),
                match rank {
                    Some(1) => format!("Run dialog (most recent): {cmd}"),
                    Some(r) => format!("Run dialog (#{r} most recent): {cmd}"),
                    None => format!("Run dialog: {cmd}"),
                },
                json!({ "key": key_path, "value": name, "command": cmd, "mru_rank": rank,
                        "time_note": "key LastWrite = time of the most recent entry only" }),
            );
            ev.process = Some(ProcessInfo {
                command_line: Some(cmd.clone()),
                name: cmd.split_whitespace().next().map(|s| basename(s).to_string()),
                ..Default::default()
            });
            sink.emit(ev);
            outcome.events_emitted += 1;
        }
    }
}

// ── RDP client MRU ──────────────────────────────────────────────────────────
// NTUSER\Software\Microsoft\Terminal Server Client\Default (MRU0..9) and
// \Servers\<host> (UsernameHint): hosts this user RDP'd OUT to — outbound
// lateral movement from this machine.
struct RdpClientMru;
impl Extractor for RdpClientMru {
    fn matches(&self, p: &str) -> bool {
        ci_ends_with(p, r"\Terminal Server Client\Default")
            || ci_contains(p, r"\Terminal Server Client\Servers\")
    }

    fn extract(
        &self,
        key: &CellKeyNode,
        key_path: &str,
        lastwrite: OffsetDateTime,
        ctx: &Ctx,
        sink: &mut dyn EventSink,
        outcome: &mut ParseOutcome,
    ) {
        if ci_contains(key_path, r"\Servers\") {
            let host = key_path.rsplit('\\').next().unwrap_or(key_path).to_string();
            let user = value_string(key, "UsernameHint");
            sink.emit(make_event(
                ctx,
                ArtefactKind::RegistryGeneric,
                lastwrite,
                TimestampKind::Modified,
                "lateral_movement.rdp_outbound",
                key_path,
                None,
                Some(host.clone()),
                Principal { name: user.clone(), ..Default::default() },
                format!("Outbound RDP to {host}{}", user.as_deref().map(|u| format!(" as {u}")).unwrap_or_default()),
                json!({ "key": key_path, "host": host, "username_hint": user }),
            ));
            outcome.events_emitted += 1;
            return;
        }
        for (name, host) in value_pairs(key) {
            if !name.to_ascii_uppercase().starts_with("MRU") || host.is_empty() {
                continue;
            }
            sink.emit(make_event(
                ctx,
                ArtefactKind::RegistryGeneric,
                lastwrite,
                TimestampKind::Modified,
                "lateral_movement.rdp_outbound",
                key_path,
                Some(&name),
                Some(host.clone()),
                Principal::default(),
                format!("Outbound RDP history ({name}): {host}"),
                json!({ "key": key_path, "value": name, "host": host }),
            ));
            outcome.events_emitted += 1;
        }
    }
}

// ── decoding helpers ────────────────────────────────────────────────────────

/// Decoded UserAssist Count value.
#[derive(Debug, PartialEq)]
pub(crate) struct UserAssistStats {
    pub run_count: u32,
    pub focus_count: Option<u32>,
    pub focus_ms: Option<u32>,
    pub last_run: Option<OffsetDateTime>,
}

/// Win7+ values are 72 bytes: run count @4, focus count @8, focus time (ms) @12,
/// last-run FILETIME @60. XP/2003 values are 16 bytes: run count @4 (offset by
/// 5), FILETIME @8. Anything else is left undecoded.
pub(crate) fn decode_userassist(b: &[u8]) -> Option<UserAssistStats> {
    let u32_at = |o: usize| b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()));
    match b.len() {
        72 => Some(UserAssistStats {
            run_count: u32_at(4)?,
            focus_count: u32_at(8),
            focus_ms: u32_at(12),
            last_run: filetime_at(b, 60),
        }),
        16 => Some(UserAssistStats {
            run_count: u32_at(4)?.saturating_sub(5),
            focus_count: None,
            focus_ms: None,
            last_run: filetime_at(b, 8),
        }),
        _ => None,
    }
}

/// Little-endian FILETIME at `off`, if present and non-zero.
pub(crate) fn filetime_at(b: &[u8], off: usize) -> Option<OffsetDateTime> {
    let ft = u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?);
    fx_core::filetime_to_datetime(ft)
}

/// Replace a leading KNOWNFOLDERID GUID with a readable folder.
pub(crate) fn expand_known_folder(p: &str) -> String {
    const KNOWN: &[(&str, &str)] = &[
        ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "C:\\Windows\\System32"),
        ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "C:\\Windows\\SysWOW64"),
        ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "C:\\Windows"),
        ("{6D809377-6AF0-444B-8957-A3773F02200E}", "C:\\Program Files"),
        ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "C:\\Program Files (x86)"),
        ("{905E63B6-C1BF-494E-B29C-65B732D3D21A}", "C:\\Program Files"),
        ("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs"),
        ("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs"),
        ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "%AppData%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned"),
        ("{374DE290-123F-4565-9164-39C4925E467B}", "%UserProfile%\\Downloads"),
        ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "%UserProfile%\\Desktop"),
        ("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "%UserProfile%\\Documents"),
    ];
    for (guid, folder) in KNOWN {
        if p.len() >= guid.len() && p[..guid.len()].eq_ignore_ascii_case(guid) {
            return format!("{folder}{}", &p[guid.len()..]);
        }
    }
    p.to_string()
}

/// RunMRU values end with "\1" (a flag); drop it.
pub(crate) fn strip_mru_suffix(s: &str) -> String {
    s.strip_suffix("\\1").unwrap_or(s).trim().to_string()
}

fn basename(p: &str) -> &str {
    p.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(p)
}

/// ProcessInfo for an execution artefact that only knows a path, so name-based
/// hunt rules (process.name / filename) match it like any other execution.
fn exe_process(path: &str) -> ProcessInfo {
    ProcessInfo {
        name: Some(basename(path).to_string()),
        path: Some(path.to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    fn ft(y: i32, mo: u8, d: u8) -> u64 {
        let dt = time::Date::from_calendar_date(y, time::Month::try_from(mo).unwrap(), d)
            .unwrap()
            .midnight()
            .assume_utc();
        ((dt.unix_timestamp() as i128 * 10_000_000) + 116_444_736_000_000_000) as u64
    }

    #[test]
    fn userassist_win7_layout() {
        let mut b = vec![0u8; 72];
        b[4..8].copy_from_slice(&7u32.to_le_bytes());
        b[8..12].copy_from_slice(&3u32.to_le_bytes());
        b[12..16].copy_from_slice(&65_000u32.to_le_bytes());
        b[60..68].copy_from_slice(&ft(2026, 2, 11).to_le_bytes());
        let s = decode_userassist(&b).unwrap();
        assert_eq!(s.run_count, 7);
        assert_eq!(s.focus_count, Some(3));
        assert_eq!(s.focus_ms, Some(65_000));
        assert_eq!(s.last_run.unwrap().date().to_string(), "2026-02-11");
    }

    #[test]
    fn userassist_xp_layout_and_zero_time() {
        let mut b = vec![0u8; 16];
        b[4..8].copy_from_slice(&9u32.to_le_bytes());
        let s = decode_userassist(&b).unwrap();
        assert_eq!(s.run_count, 4); // XP stores count + 5
        assert_eq!(s.last_run, None); // zero FILETIME = unknown
        assert!(decode_userassist(&[0u8; 10]).is_none());
    }

    #[test]
    fn shell_items_parse_cleanly() {
        // Volume item: "C:\"
        let mut vol = vec![0x19, 0x00, 0x2F];
        vol.extend_from_slice(b"C:\\\0");
        vol.resize(0x19, 0);
        let v = parse_shell_item(&vol).unwrap();
        assert_eq!(v.name, "C:\\");
        assert_eq!(v.kind, ShellItemKind::Volume);

        // File-entry item: 8.3 name + BEEF0004 v9 long name. The bytes before
        // the names are what the old text-scan mis-decoded as CJK characters.
        let long = "Users";
        let mut fe = vec![0u8, 0, 0x31, 0x00];
        fe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size
        fe.extend_from_slice(&[0x45, 0x58, 0x87, 0x7E]); // FAT datetime (noise)
        fe.extend_from_slice(&[0x11, 0x00]); // attributes
        fe.extend_from_slice(b"Users\0"); // 8.3 name (even length incl NUL)
        let ext_start = fe.len();
        let mut ext = vec![0u8, 0, 0x09, 0x00, 0x04, 0x00, 0xEF, 0xBE];
        ext.extend_from_slice(&[0x45, 0x58, 0x87, 0x7E, 0x45, 0x58, 0x87, 0x7E]); // c/a times
        ext.extend_from_slice(&[0x2E, 0x00]); // identifier
        ext.resize(46, 0x5A); // version-9 fields (noise)
        for u in long.encode_utf16() { ext.extend_from_slice(&u.to_le_bytes()); }
        ext.extend_from_slice(&[0, 0]);
        let el = ext.len() as u16;
        ext[0..2].copy_from_slice(&el.to_le_bytes());
        fe.extend_from_slice(&ext);
        let total = fe.len() as u16;
        fe[0..2].copy_from_slice(&total.to_le_bytes());
        let _ = ext_start;
        let f = parse_shell_item(&fe).unwrap();
        assert_eq!(f.name, "Users");

        // Unknown item with no readable structure is skipped, not mis-named.
        assert!(parse_shell_item(&[0x10, 0x00, 0x00, 0x46, 0x5D, 0x7C, 0x6C, 0x46, 0x5D, 0x5A, 0x77, 0x2E, 0, 0, 0, 0]).is_none());

        // Full path from ancestors: This PC / C:\ / Users -> "C:\Users"
        let mut root = vec![0x14, 0x00, 0x1F, 0x50];
        root.extend_from_slice(&[0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D]);
        let r = parse_shell_item(&root).unwrap();
        assert_eq!(r.name, "This PC");
        shellbag_remember("hive-t", "bag", "0", &r);
        shellbag_remember("hive-t", "bag", "0\\1", &v);
        let p = shellbag_remember("hive-t", "bag", "0\\1\\0", &f).unwrap();
        assert_eq!(p, "C:\\Users");
    }

    #[test]
    fn known_folder_and_mru() {
        assert_eq!(
            expand_known_folder("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"),
            "C:\\Windows\\System32\\cmd.exe"
        );
        assert_eq!(expand_known_folder("C:\\x\\a.exe"), "C:\\x\\a.exe");
        assert_eq!(strip_mru_suffix("powershell -nop\\1"), "powershell -nop");
        assert_eq!(basename("C:\\Tools\\rclone.exe"), "rclone.exe");
    }
}
