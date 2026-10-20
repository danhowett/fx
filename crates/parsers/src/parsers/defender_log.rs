//! Microsoft Defender support log parser — `MPLog-*.log`.
//!
//! Defender writes a diagnostic log under
//! `C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-<date>-<time>.log`
//! (UTF-16). It is not a documented format, but it is forensically valuable
//! and routinely survives when the event logs have been cleared:
//!
//! * **Detections** — lines naming a threat (`Trojan:Win32/Foo!ml`,
//!   `Behavior:Win32/…`, `HackTool:…`) with the resource it was found on
//!   (`file:`, `process:`, `behavior:`, `regkey:`, `cmdline:`).
//! * **Process activity** — the mini-filter performance blocks list each
//!   process Defender scanned on behalf of (`ProcessImageName: x.exe, Pid: …,
//!   MaxTimeFile: \Device\HarddiskVolume3\…`). That is evidence a program ran,
//!   even when Prefetch / Amcache don't have it. Repeats are folded into one
//!   event per (process, file) with a count and first / last time.
//! * **Cloud lookups** — `SDN:Issuing SDN query for <file> (sha1=…, sha2=…)`
//!   records files Defender asked the cloud about, with their hashes, so the
//!   IOC hunt can match a hash list against them.
//!
//! Lines are matched by shape, not by an exact grammar, and anything that
//! doesn't match is ignored, so format drift between Defender versions costs
//! coverage rather than producing wrong events. Lines without their own
//! timestamp take the most recent timestamp seen above them (or the file's
//! modified time).

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser, Principal,
    ProcessInfo, Provenance, Target, TimestampKind,
};
use serde_json::json;
use std::collections::BTreeMap;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use uuid::Uuid;

#[derive(Default)]
pub struct DefenderLogParser;

impl Parser for DefenderLogParser {
    fn name(&self) -> &'static str {
        "defender_log"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::DefenderLog]
    }

    fn parse(&self, artefact: &IdentifiedArtefact, sink: &mut dyn EventSink) -> Result<ParseOutcome, ParseError> {
        let text = crate::parsers::text_decode::read_text_file(&artefact.path)
            .map_err(|e| ParseError::Io { path: artefact.path.display().to_string(), source: e })?;
        let mtime = std::fs::metadata(&artefact.path)
            .and_then(|m| m.modified())
            .map(OffsetDateTime::from)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let mut outcome = ParseOutcome::default();
        for ev in parse_text(&text, mtime) {
            let (ts, kind, action, message, user, process, target, line, raw) = ev;
            sink.emit(Event {
                id: Uuid::new_v4(),
                timestamp: ts,
                timestamp_kind: kind,
                artefact: ArtefactKind::DefenderLog,
                action,
                host: None,
                user: Principal { name: user, ..Default::default() },
                process,
                target,
                network: None,
                message,
                provenance: Provenance {
                    evidence_id: artefact.evidence_id,
                    source_path: artefact.source_path.clone(),
                    parser: "defender_log".into(),
                    parser_version: env!("CARGO_PKG_VERSION").into(),
                    source_ref: Some(format!("line {line}")),
                },
                raw,
            });
            outcome.events_emitted += 1;
        }
        outcome.records_read = text.lines().count() as u64;
        Ok(outcome)
    }
}

type Parsed = (
    OffsetDateTime,
    TimestampKind,
    String,
    String,
    Option<String>,
    Option<ProcessInfo>,
    Option<Target>,
    usize,
    serde_json::Value,
);

/// Parse MPLog text into events (separated from I/O for testing).
pub(crate) fn parse_text(text: &str, fallback: OffsetDateTime) -> Vec<Parsed> {
    let mut out = Vec::new();
    let mut last_ts: Option<OffsetDateTime> = None;
    // (image, file) -> (first ts, last ts, count, first line, pid)
    let mut procs: BTreeMap<(String, String), (OffsetDateTime, OffsetDateTime, u64, usize)> = BTreeMap::new();
    let mut seen_sdn = std::collections::HashSet::new();

    for (i, raw_line) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw_line.trim_matches(|c: char| c == '\u{feff}' || c.is_whitespace() || c == '\0');
        if line.is_empty() {
            continue;
        }
        let (ts_here, rest) = leading_timestamp(line);
        if let Some(t) = ts_here {
            last_ts = Some(t);
        }
        let ts = ts_here.or(last_ts).unwrap_or(fallback);
        let tkind = if ts_here.is_some() || last_ts.is_some() { TimestampKind::Recorded } else { TimestampKind::Modified };

        // ── Process activity (mini-filter performance block) ──────────────
        if let Some(pos) = rest.find("ProcessImageName:") {
            let fields = kv_fields(&rest[pos..]);
            if let Some(image) = fields.get("processimagename").filter(|s| !s.is_empty()) {
                let file = fields.get("maxtimefile").map(|s| device_path(s)).unwrap_or_default();
                let e = procs.entry((image.clone(), file)).or_insert((ts, ts, 0, line_no));
                if ts < e.0 {
                    e.0 = ts;
                }
                if ts > e.1 {
                    e.1 = ts;
                }
                e.2 += 1;
            }
            continue;
        }

        // ── Cloud (SDN) lookups with hashes ──────────────────────────────
        if let Some(pos) = rest.find("SDN query for ") {
            let after = &rest[pos + "SDN query for ".len()..];
            let path_end = after.find(" (").unwrap_or(after.len());
            let path = device_path(after[..path_end].trim());
            let sha1 = hash_after(after, "sha1=");
            let sha256 = hash_after(after, "sha2=").or_else(|| hash_after(after, "sha256="));
            if !path.is_empty() && seen_sdn.insert((path.clone(), sha1.clone())) {
                out.push((
                    ts,
                    tkind,
                    "file.defender_cloud_lookup".into(),
                    format!("Defender cloud lookup: {path}{}", sha1.as_ref().map(|h| format!(" (sha1 {h})")).unwrap_or_default()),
                    None,
                    None,
                    Some(Target { path: Some(path.clone()), value_name: None, hash_sha1: sha1.clone(), size: None }),
                    line_no,
                    json!({"line": line_no, "path": path, "sha1": sha1, "sha256": sha256, "text": rest}),
                ));
            }
            continue;
        }

        // ── Detections ───────────────────────────────────────────────────
        let upper = rest.to_ascii_uppercase();
        if upper.contains("DETECTION") || upper.contains("THREAT") || upper.contains("REMEDIATION") {
            if let Some(threat) = threat_name(rest) {
                let (rtype, resource) = resource(rest);
                let path = resource.as_deref().map(device_path);
                let process = if rtype.as_deref() == Some("process") {
                    path.clone().map(|p| ProcessInfo { name: p.rsplit('\\').next().map(str::to_string), path: Some(p), ..Default::default() })
                } else {
                    None
                };
                let user = field_after(rest, "User:").or_else(|| field_after(rest, "user:"));
                out.push((
                    ts,
                    tkind,
                    "malware.detected".into(),
                    format!(
                        "Defender (MPLog) detection: {threat}{}",
                        path.as_ref().map(|p| format!(" — {}{p}", rtype.as_ref().map(|t| format!("{t}: ")).unwrap_or_default())).unwrap_or_default()
                    ),
                    user,
                    process,
                    path.clone().map(|p| Target { path: Some(p), value_name: None, hash_sha1: None, size: None }),
                    line_no,
                    json!({"line": line_no, "threat": threat, "resource_type": rtype, "resource": path, "text": rest}),
                ));
            }
        }
    }

    for ((image, file), (first, last, count, line)) in procs {
        out.push((
            first,
            TimestampKind::Recorded,
            "execution.defender_mplog".into(),
            format!("Defender saw process {image}{}{}", if count > 1 { format!(" ({count}×, last {})", fmt_ts(last)) } else { String::new() },
                if file.is_empty() { String::new() } else { format!(" — scanning {file}") }),
            None,
            Some(ProcessInfo { name: Some(image.clone()), path: Some(image.clone()), ..Default::default() }),
            (!file.is_empty()).then(|| Target { path: Some(file.clone()), value_name: None, hash_sha1: None, size: None }),
            line,
            json!({"line": line, "process_image": image, "max_time_file": file, "occurrences": count,
                   "first_seen": fmt_ts(first), "last_seen": fmt_ts(last)}),
        ));
    }
    out
}

fn fmt_ts(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

/// A timestamp at the start of the line: `2024-05-01T10:11:12.345Z`,
/// `2024-05-01 10:11:12`, or `05-01-2024 10:11:12`. Returns the rest of the line.
pub(crate) fn leading_timestamp(line: &str) -> (Option<OffsetDateTime>, &str) {
    let b = line.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let s = line.get(r)?;
        s.bytes().all(|c| c.is_ascii_digit()).then(|| s.parse().ok()).flatten()
    };
    let (y, mo, d, tpos) = if b.len() >= 19 && b[4] == b'-' && b[7] == b'-' && (b[10] == b'T' || b[10] == b' ') {
        (digits(0..4), digits(5..7), digits(8..10), 11)
    } else if b.len() >= 19 && b[2] == b'-' && b[5] == b'-' && b[10] == b' ' {
        (digits(6..10), digits(0..2), digits(3..5), 11)
    } else {
        return (None, line);
    };
    let (Some(y), Some(mo), Some(d)) = (y, mo, d) else { return (None, line) };
    let (Some(h), Some(mi), Some(se)) = (digits(tpos..tpos + 2), digits(tpos + 3..tpos + 5), digits(tpos + 6..tpos + 8)) else {
        return (None, line);
    };
    let mut end = tpos + 8;
    let mut ms = 0u32;
    if b.get(end) == Some(&b'.') {
        let start = end + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let frac = &line[start..j.min(start + 3)];
        ms = frac.parse::<u32>().unwrap_or(0) * 10u32.pow(3 - frac.len().min(3) as u32);
        end = j;
    }
    if b.get(end) == Some(&b'Z') {
        end += 1;
    }
    let date = Month::try_from(mo as u8).ok().and_then(|m| Date::from_calendar_date(y as i32, m, d as u8).ok());
    let time = Time::from_hms_milli(h as u8, mi as u8, se as u8, ms as u16).ok();
    match (date, time) {
        (Some(dt), Some(tm)) => (Some(PrimitiveDateTime::new(dt, tm).assume_utc()), line[end..].trim_start()),
        _ => (None, line),
    }
}

/// `Key: value, Key: value` → lower-cased key map. Values run to the next
/// ", Key:" boundary, so paths containing commas survive in most cases.
fn kv_fields(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for part in s.split(", ") {
        if let Some((k, v)) = part.split_once(':') {
            let k = k.trim();
            if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric()) {
                out.insert(k.to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }
    out
}

/// `\Device\HarddiskVolume3\Users\x\a.exe` → `\Users\x\a.exe` (the volume's
/// drive letter isn't recorded); `\\?\C:\x` → `C:\x`; `_C:\x` → `C:\x`.
fn device_path(p: &str) -> String {
    let p = p.trim().trim_matches('"').trim_start_matches('_');
    let p = p.strip_prefix(r"\\?\").unwrap_or(p);
    let lower = p.to_ascii_lowercase();
    if lower.starts_with(r"\device\harddiskvolume") {
        let rest = &p[r"\device\harddiskvolume".len()..];
        let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
        return rest.to_string();
    }
    p.to_string()
}

fn hash_after(s: &str, key: &str) -> Option<String> {
    let lower = s.to_ascii_lowercase();
    let pos = lower.find(key)? + key.len();
    let h: String = s[pos..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (h.len() >= 32).then(|| h.to_ascii_lowercase())
}

fn field_after(s: &str, key: &str) -> Option<String> {
    let pos = s.find(key)? + key.len();
    let v: String = s[pos..].trim_start().chars().take_while(|c| !c.is_whitespace() && *c != ',').collect();
    (!v.is_empty()).then_some(v)
}

/// A Defender threat name: `Category:Platform/Family[.variant][!suffix]`,
/// e.g. `Trojan:Win32/Wacatac.H!ml`, `Behavior:Win32/CobaltStrike.A!sms`.
fn threat_name(s: &str) -> Option<String> {
    for tok in s.split(|c: char| c.is_whitespace() || c == ',' || c == '"' || c == '\'' || c == '(' || c == ')' || c == '[' || c == ']') {
        let Some((cat, rest)) = tok.split_once(':') else { continue };
        let Some((plat, fam)) = rest.split_once('/') else { continue };
        let cat_ok = cat.len() >= 2 && cat.chars().all(|c| c.is_ascii_alphabetic()) && cat.chars().next().map_or(false, |c| c.is_ascii_uppercase());
        let plat_ok = !plat.is_empty() && plat.chars().all(|c| c.is_ascii_alphanumeric()) && plat.chars().next().map_or(false, |c| c.is_ascii_uppercase());
        let fam_ok = !fam.is_empty() && fam.chars().next().map_or(false, |c| c.is_ascii_alphanumeric()) && !fam.contains('\\') && !fam.contains('/');
        // Exclude resource prefixes and URLs (file:C:\…, http://…).
        let lc = cat.to_ascii_lowercase();
        if cat_ok && plat_ok && fam_ok && !matches!(lc.as_str(), "file" | "process" | "behavior_" | "regkey" | "cmdline" | "http" | "https" | "user" | "pid") {
            return Some(tok.trim_end_matches(|c: char| c == '.' || c == ';').to_string());
        }
    }
    None
}

/// The detected resource: (type, value) from `file:…`, `process:…`,
/// `behavior:…`, `regkey:…`, `cmdline:…` (lower-case resource prefixes).
fn resource(s: &str) -> (Option<String>, Option<String>) {
    for key in ["file:", "process:", "regkey:", "cmdline:", "behavior:", "containerfile:", "amsi:"] {
        if let Some(pos) = s.find(key) {
            let v = s[pos + key.len()..].trim_start_matches('_');
            // Stop at the next " key:" field or the end of the line.
            let end = [" pid:", " PID:", " ProcessName:", " User:", " -> ", " (", "  "].iter().filter_map(|m| v.find(m)).min().unwrap_or(v.len());
            let v = v[..end].trim();
            if !v.is_empty() {
                return (Some(key.trim_end_matches(':').to_string()), Some(v.to_string()));
            }
        }
    }
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\u{feff}2024-05-01T10:11:12.345Z Engine:Confirm(Scan)\r\n\
2024-05-01T10:11:13.000Z DETECTION_ADD#1 Trojan:Win32/Wacatac.H!ml file:C:\\Users\\bob\\Downloads\\tool.exe PID:4312\r\n\
2024-05-01T10:11:14.000Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win64/Mimikatz.A process:_C:\\PerfLogs\\m.exe\r\n\
2024-05-01T10:12:00.000Z [Mini-filter] Top processes\r\n\
ProcessImageName: powershell.exe, Pid: 4512, TotalTime: 2032, Count: 50, MaxTime: 100, MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Local\\Temp\\a.ps1, EstimatedImpact: 10%\r\n\
ProcessImageName: powershell.exe, Pid: 4512, TotalTime: 10, Count: 1, MaxTime: 10, MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Local\\Temp\\a.ps1, EstimatedImpact: 1%\r\n\
2024-05-01T10:13:00.000Z SDN:Issuing SDN query for \\Device\\HarddiskVolume3\\Users\\bob\\Downloads\\tool.exe (\\Device\\HarddiskVolume3\\Users\\bob\\Downloads\\tool.exe) (sha1=0123456789abcdef0123456789abcdef01234567, sha2=00aa11bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899)\r\n\
2024-05-01T10:14:00.000Z Visit https://example.com/a:b/c threat feed\r\n";

    #[test]
    fn parses_detections_processes_and_lookups() {
        let ev = parse_text(SAMPLE, OffsetDateTime::UNIX_EPOCH);
        let det: Vec<_> = ev.iter().filter(|e| e.2 == "malware.detected").collect();
        assert_eq!(det.len(), 2, "{:?}", ev.iter().map(|e| &e.3).collect::<Vec<_>>());
        assert!(det[0].3.contains("Trojan:Win32/Wacatac.H!ml"));
        assert_eq!(det[0].6.as_ref().and_then(|t| t.path.clone()).as_deref(), Some(r"C:\Users\bob\Downloads\tool.exe"));
        assert_eq!(det[1].5.as_ref().and_then(|p| p.path.clone()).as_deref(), Some(r"C:\PerfLogs\m.exe"));
        let procs: Vec<_> = ev.iter().filter(|e| e.2 == "execution.defender_mplog").collect();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].8["occurrences"], 2);
        assert_eq!(procs[0].8["max_time_file"], r"\Users\bob\AppData\Local\Temp\a.ps1");
        // Lines without a timestamp inherit the last one seen.
        assert_eq!(fmt_ts(procs[0].0), "2024-05-01T10:12:00Z");
        let sdn: Vec<_> = ev.iter().filter(|e| e.2 == "file.defender_cloud_lookup").collect();
        assert_eq!(sdn.len(), 1);
        assert_eq!(sdn[0].6.as_ref().and_then(|t| t.hash_sha1.clone()).as_deref(), Some("0123456789abcdef0123456789abcdef01234567"));
        assert!(sdn[0].8["sha256"].as_str().unwrap().starts_with("00aa11"));
    }

    #[test]
    fn threat_names_are_strict() {
        assert_eq!(threat_name("x Behavior:Win32/CobaltStrike.A!sms y").as_deref(), Some("Behavior:Win32/CobaltStrike.A!sms"));
        assert_eq!(threat_name("file:C:\\x\\y.exe"), None);
        assert_eq!(threat_name("https://a.b/c"), None);
        assert_eq!(threat_name("Engine:Confirm(Scan)"), None);
    }
}
