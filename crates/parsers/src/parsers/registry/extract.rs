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
use fx_core::{ArtefactKind, EventSink, ParseOutcome, Principal, TimestampKind};
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
            // Value names are ROT13-encoded paths.
            let decoded = rot13(&vname);
            // TODO(week2-cont): decode the Count value blob for run count and
            // the FILETIME last-run. Until then, use the key LastWrite and the
            // decoded name — still a usable execution-evidence timeline entry.
            sink.emit(make_event(
                ctx,
                ArtefactKind::UserAssist,
                lastwrite,
                TimestampKind::Executed,
                "execution.userassist",
                key_path,
                Some(&vname),
                Some(decoded.clone()),
                Principal::default(),
                format!("UserAssist run: {decoded}"),
                json!({ "key": key_path, "encoded": vname, "decoded": decoded }),
            ));
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
            // Each value name is an executable path; data holds a FILETIME.
            // TODO(week2-cont): decode the 8-byte FILETIME from the value data
            // for a precise exec time. Marker uses LastWrite for now.
            if vname.eq_ignore_ascii_case("Version")
                || vname.eq_ignore_ascii_case("SequenceNumber")
            {
                continue;
            }
            sink.emit(make_event(
                ctx,
                ArtefactKind::BamDam,
                lastwrite,
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
            ));
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
            let folder = shell_item_name(&bytes);
            // Skip slots that yielded nothing readable (GUID/control-panel items).
            let Some(folder) = folder else { continue };

            let is_volume = looks_like_volume(&folder);
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
                    "folder": folder,
                    "volume_or_removable": is_volume,
                    "shell_item_bytes": bytes.len(),
                }),
            ));
            outcome.events_emitted += 1;
        }
    }
}

/// Extract a human-readable folder name from a shell-item (ITEMIDLIST) blob.
/// Folder shell items embed the name as ASCII and/or UTF-16LE; we scan for the
/// longest plausible printable run of each and prefer the UTF-16 one (the long
/// name in modern items). Returns None when nothing readable is found (e.g. a
/// GUID/known-folder item), so those slots are skipped rather than mis-named.
fn shell_item_name(bytes: &[u8]) -> Option<String> {
    let utf16 = longest_utf16le(bytes);
    let ascii = longest_ascii(bytes);
    let pick = match (utf16, ascii) {
        (Some(u), Some(a)) => {
            if u.chars().count() >= a.chars().count() {
                u
            } else {
                a
            }
        }
        (Some(u), None) => u,
        (None, Some(a)) => a,
        (None, None) => return None,
    };
    let pick = pick.trim().trim_matches('\0').to_string();
    if pick.chars().count() >= 2 && pick.chars().any(|c| c.is_alphanumeric()) {
        Some(pick)
    } else {
        None
    }
}

/// Longest run of printable ASCII (>=3 chars), a common folder-name encoding.
fn longest_ascii(bytes: &[u8]) -> Option<String> {
    let mut best = String::new();
    let mut cur = String::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.chars().count() > best.chars().count() {
                best = cur.clone();
            }
            cur.clear();
        }
    }
    if cur.chars().count() > best.chars().count() {
        best = cur;
    }
    (best.chars().count() >= 3).then_some(best)
}

/// Longest run of printable UTF-16LE (>=3 chars) — the long name in modern
/// shell items.
fn longest_utf16le(bytes: &[u8]) -> Option<String> {
    let mut best: Vec<u16> = Vec::new();
    let mut cur: Vec<u16> = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        // printable BMP range, excluding controls
        if (0x20..=0xd7ff).contains(&u) && u != 0 {
            cur.push(u);
        } else {
            if cur.len() > best.len() {
                best = cur.clone();
            }
            cur.clear();
        }
        i += 2;
    }
    if cur.len() > best.len() {
        best = cur;
    }
    if best.len() >= 3 {
        Some(String::from_utf16_lossy(&best))
    } else {
        None
    }
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
