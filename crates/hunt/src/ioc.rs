//! IOC sweep: hunt an already-ingested case for an analyst-supplied list of
//! indicators — hashes, IPs, domains, URLs, file names, paths or free text.
//!
//! Post-processing by design: no re-ingest. The list is parsed and typed
//! (defang-aware), then every event is scanned ONCE: each batch of IOCs compiles
//! to a single case-insensitive literal-alternation regex (the regex engine
//! uses an Aho–Corasick / Teddy prefilter for this), so cost grows with the size
//! of the case, not the length of the list.
//!
//! Matched IOCs become findings (engine = ioc), one per indicator, so they flow
//! into triage, exports and the HTML report — and survive re-running the rules.

use fx_core::{Detection, DetectionEngine, Severity};
use fx_store::{CaseStore, StoreError};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

/// Most event ids kept per IOC finding (the total count is always reported).
const EVENT_ID_CAP: usize = 500;
/// IOCs per compiled regex.
const BATCH: usize = 400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Sha256,
    Sha1,
    Md5,
    Ipv4,
    Ipv6,
    Url,
    Email,
    Domain,
    FileName,
    Path,
    Text,
}

impl IocKind {
    pub fn label(self) -> &'static str {
        match self {
            IocKind::Sha256 => "SHA-256",
            IocKind::Sha1 => "SHA-1",
            IocKind::Md5 => "MD5",
            IocKind::Ipv4 => "IPv4",
            IocKind::Ipv6 => "IPv6",
            IocKind::Url => "URL",
            IocKind::Email => "email",
            IocKind::Domain => "domain",
            IocKind::FileName => "file name",
            IocKind::Path => "path",
            IocKind::Text => "text",
        }
    }
    /// Whole-token match required (so 10.0.0.1 doesn't hit 10.0.0.15).
    fn bounded(self) -> bool {
        !matches!(self, IocKind::Path | IocKind::Text | IocKind::Url)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Ioc {
    /// As the analyst supplied it (after defanging).
    pub value: String,
    pub kind: IocKind,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct ParsedIocs {
    pub iocs: Vec<Ioc>,
    /// Lines/tokens that were ignored (too short, comments are not counted).
    pub skipped: Vec<String>,
}

/// Restore defanged indicators: hxxp, [.], (.), {.}, [dot], [:], [://].
fn defang(s: &str) -> String {
    let mut t = s.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string();
    for (a, b) in [
        ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
        ("[:]", ":"), ("[://]", "://"), ("[@]", "@"), ("[at]", "@"),
    ] {
        t = t.replace(a, b);
    }
    let lower = t.to_ascii_lowercase();
    for (a, b) in [("hxxps://", "https://"), ("hxxp://", "http://"), ("hxxps[:]//", "https://"), ("hxxp[:]//", "http://")] {
        if lower.starts_with(a) {
            t = format!("{b}{}", &t[a.len()..]);
            break;
        }
    }
    t
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_ipv4(s: &str) -> bool {
    let p: Vec<&str> = s.split('.').collect();
    p.len() == 4 && p.iter().all(|x| !x.is_empty() && x.len() <= 3 && x.parse::<u8>().is_ok())
}

const FILE_EXTS: &[&str] = &[
    "exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "scr", "msi", "lnk",
    "zip", "rar", "7z", "iso", "img", "jar", "py", "bin", "dat", "tmp", "ocx", "cpl", "wsf", "docm", "xlsm",
];

/// Decide what kind of indicator a (defanged) token is. None = ignore.
pub fn classify(v: &str) -> Option<IocKind> {
    let l = v.to_ascii_lowercase();
    if l.len() < 4 {
        return None;
    }
    if is_hex(&l) {
        match l.len() {
            64 => return Some(IocKind::Sha256),
            40 => return Some(IocKind::Sha1),
            32 => return Some(IocKind::Md5),
            _ => {}
        }
    }
    if l.starts_with("http://") || l.starts_with("https://") || l.starts_with("ftp://") {
        return Some(IocKind::Url);
    }
    let ip_part = l.split(':').next().unwrap_or(&l); // tolerate 1.2.3.4:443
    if is_ipv4(ip_part) && (l == ip_part || l[ip_part.len() + 1..].bytes().all(|b| b.is_ascii_digit())) {
        return Some(IocKind::Ipv4);
    }
    if l.matches(':').count() >= 2 && l.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
        return Some(IocKind::Ipv6);
    }
    if !l.contains(' ') && l.contains('@') {
        let (u, d) = l.split_once('@').unwrap();
        if !u.is_empty() && d.contains('.') {
            return Some(IocKind::Email);
        }
    }
    if l.contains('\\') || l.starts_with('/') || (l.len() > 2 && l.as_bytes()[1] == b':') {
        return Some(IocKind::Path);
    }
    if !l.contains(' ') {
        if let Some((_, ext)) = l.rsplit_once('.') {
            if FILE_EXTS.contains(&ext) {
                return Some(IocKind::FileName);
            }
            let labels: Vec<&str> = l.split('.').collect();
            let tld_ok = ext.len() >= 2 && ext.bytes().all(|b| b.is_ascii_alphabetic());
            let labels_ok = labels.len() >= 2
                && labels.iter().all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
            if tld_ok && labels_ok {
                return Some(IocKind::Domain);
            }
        }
    }
    Some(IocKind::Text)
}

/// Parse a pasted or loaded IOC list. One indicator per line; a line with
/// several strong indicators (hash / IP / domain / URL …) separated by commas,
/// semicolons, tabs or pipes contributes all of them; otherwise the first field
/// is the indicator (so "1.2.3.4, C2 server" yields just the IP). Lines starting
/// with # or // are comments. Duplicates are removed.
pub fn parse_iocs(text: &str) -> ParsedIocs {
    let mut out = ParsedIocs::default();
    let mut seen = std::collections::HashSet::new();
    for raw_line in text.lines() {
        let line = raw_line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let fields: Vec<String> = line
            .split(|c| c == ',' || c == ';' || c == '\t' || c == '|')
            .map(defang)
            .filter(|f| !f.is_empty())
            .collect();
        let typed: Vec<(String, IocKind)> =
            fields.iter().filter_map(|f| classify(f).map(|k| (f.clone(), k))).collect();
        let strong: Vec<(String, IocKind)> =
            typed.iter().filter(|(_, k)| *k != IocKind::Text).cloned().collect();
        let picked: Vec<(String, IocKind)> = if strong.len() >= 2 {
            strong
        } else if let Some(first) = fields.first() {
            match classify(first) {
                Some(k) => vec![(first.clone(), k)],
                None => {
                    out.skipped.push(first.clone());
                    vec![]
                }
            }
        } else {
            vec![]
        };
        for (v, k) in picked {
            let key = (k, v.to_ascii_lowercase());
            if seen.insert(key) {
                out.iocs.push(Ioc { value: v, kind: k });
            }
        }
    }
    out
}

/// Per-IOC sweep result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IocResult {
    pub value: String,
    pub kind: IocKind,
    pub kind_label: &'static str,
    pub events: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// Matching events per artefact type, e.g. {"Evtx": 12, "Mft": 3}.
    pub artefacts: BTreeMap<String, u64>,
}

#[derive(Debug, serde::Serialize)]
pub struct SweepReport {
    pub iocs: usize,
    pub matched: usize,
    pub events_scanned: u64,
    pub skipped: Vec<String>,
    /// Every IOC, matched first (most events first), then the unmatched ones.
    pub results: Vec<IocResult>,
}

struct Acc {
    events: u64,
    first: Option<String>,
    last: Option<String>,
    ids: Vec<Uuid>,
    artefacts: BTreeMap<String, u64>,
}

/// Search forms of an IOC (lower-case). Paths also match their JSON-escaped
/// form (raw records) and the forward-slash, drive-less form the MFT parser
/// stores.
fn variants(ioc: &Ioc) -> Vec<String> {
    let v = ioc.value.to_ascii_lowercase();
    let mut out = vec![v.clone()];
    if ioc.kind == IocKind::Path {
        out.push(v.replace('\\', "\\\\"));
        let slashed = v.replace('\\', "/");
        let no_drive = if slashed.len() > 3 && slashed.as_bytes()[1] == b':' { slashed[3..].to_string() } else { slashed.clone() };
        out.push(slashed);
        out.push(no_drive);
    }
    out.sort();
    out.dedup();
    out
}

fn boundary_ok(text: &str, start: usize, end: usize) -> bool {
    let tok = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.map_or(false, tok) && !after.map_or(false, tok)
}

/// Run the sweep over the open case and replace its IOC findings.
pub fn sweep(store: &CaseStore, parsed: &ParsedIocs) -> Result<SweepReport, StoreError> {
    let iocs = &parsed.iocs;
    // search form -> IOC index
    let mut lookup: HashMap<String, usize> = HashMap::new();
    let mut forms: Vec<(String, usize)> = Vec::new();
    for (i, ioc) in iocs.iter().enumerate() {
        for f in variants(ioc) {
            if lookup.insert(f.clone(), i).is_none() {
                forms.push((f, i));
            }
        }
    }
    // Longest first so that at any position the most specific form wins.
    forms.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    let regexes: Vec<regex::Regex> = forms
        .chunks(BATCH)
        .filter_map(|chunk| {
            let alt = chunk.iter().map(|(f, _)| regex::escape(f)).collect::<Vec<_>>().join("|");
            regex::RegexBuilder::new(&format!("(?i:{alt})"))
                .size_limit(256 << 20)
                .dfa_size_limit(64 << 20)
                .build()
                .ok()
        })
        .collect();

    let mut acc: Vec<Acc> = (0..iocs.len())
        .map(|_| Acc { events: 0, first: None, last: None, ids: Vec::new(), artefacts: BTreeMap::new() })
        .collect();
    let mut scanned = 0u64;
    let mut hit_now: Vec<usize> = Vec::new();

    if !regexes.is_empty() {
        store.for_each_event_text(|id, ts, art, text| {
            scanned += 1;
            hit_now.clear();
            for re in &regexes {
                for m in re.find_iter(text) {
                    let Some(&i) = lookup.get(&m.as_str().to_ascii_lowercase()) else { continue };
                    if iocs[i].kind.bounded() && !boundary_ok(text, m.start(), m.end()) {
                        continue;
                    }
                    if !hit_now.contains(&i) {
                        hit_now.push(i);
                    }
                }
            }
            for &i in &hit_now {
                let a = &mut acc[i];
                a.events += 1;
                if a.first.as_deref().map_or(true, |f| ts < f) {
                    a.first = Some(ts.to_string());
                }
                if a.last.as_deref().map_or(true, |l| ts > l) {
                    a.last = Some(ts.to_string());
                }
                if a.ids.len() < EVENT_ID_CAP {
                    if let Ok(u) = Uuid::parse_str(id) {
                        a.ids.push(u);
                    }
                }
                *a.artefacts.entry(art.to_string()).or_default() += 1;
            }
        })?;
    }

    // Findings: one per matched IOC.
    let mut dets = Vec::new();
    for (ioc, a) in iocs.iter().zip(acc.iter()) {
        if a.events == 0 {
            continue;
        }
        let where_ = a.artefacts.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ");
        let ts = a
            .first
            .as_deref()
            .and_then(|t| time::PrimitiveDateTime::parse(t, &time::format_description::well_known::Iso8601::DEFAULT).ok())
            .map(|p| p.assume_utc())
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        dets.push(Detection {
            id: Uuid::new_v4(),
            rule_id: format!("ioc:{}:{}", ioc.kind.label(), ioc.value.to_ascii_lowercase()),
            title: format!("IOC match: {} ({})", ioc.value, ioc.kind.label()),
            severity: if ioc.kind == IocKind::Text { Severity::Medium } else { Severity::High },
            attack: Vec::new(),
            summary: format!(
                "{} event{} · {} · first {} · last {}",
                a.events,
                if a.events == 1 { "" } else { "s" },
                where_,
                a.first.as_deref().unwrap_or("?"),
                a.last.as_deref().unwrap_or("?")
            ),
            event_ids: a.ids.clone(),
            timestamp: ts,
            host: None,
            engine: DetectionEngine::Ioc,
        });
    }
    store.replace_ioc_detections(&dets)?;

    let mut results: Vec<IocResult> = iocs
        .iter()
        .zip(acc.into_iter())
        .map(|(ioc, a)| IocResult {
            value: ioc.value.clone(),
            kind: ioc.kind,
            kind_label: ioc.kind.label(),
            events: a.events,
            first_seen: a.first,
            last_seen: a.last,
            artefacts: a.artefacts,
        })
        .collect();
    results.sort_by(|a, b| b.events.cmp(&a.events).then(a.value.cmp(&b.value)));
    Ok(SweepReport {
        iocs: iocs.len(),
        matched: dets.len(),
        events_scanned: scanned,
        skipped: parsed.skipped.clone(),
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_and_defangs() {
        let p = parse_iocs(
            "# comment\n\
             44d88612fea8a8f36de82e1278abb02f\n\
             hxxps://evil[.]example[.]com/payload.bin\n\
             185.220.101.4:443, C2 server\n\
             evil[.]example\n\
             mimikatz.exe\n\
             C:\\Users\\Public\\svc.exe\n\
             1.2.3.4,5.6.7.8,bad.example.org\n\
             ab\n\
             Invoke-Mimikatz\n",
        );
        let kinds: Vec<(String, IocKind)> = p.iocs.iter().map(|i| (i.value.clone(), i.kind)).collect();
        assert!(kinds.contains(&("44d88612fea8a8f36de82e1278abb02f".into(), IocKind::Md5)));
        assert!(kinds.contains(&("https://evil.example.com/payload.bin".into(), IocKind::Url)));
        assert!(kinds.contains(&("185.220.101.4:443".into(), IocKind::Ipv4)));
        assert!(kinds.contains(&("evil.example".into(), IocKind::Domain)));
        assert!(kinds.contains(&("mimikatz.exe".into(), IocKind::FileName)));
        assert!(kinds.contains(&("C:\\Users\\Public\\svc.exe".into(), IocKind::Path)));
        assert!(kinds.contains(&("5.6.7.8".into(), IocKind::Ipv4)));
        assert!(kinds.contains(&("bad.example.org".into(), IocKind::Domain)));
        assert!(kinds.contains(&("Invoke-Mimikatz".into(), IocKind::Text)));
        assert!(!kinds.iter().any(|(v, _)| v == "C2 server"), "trailing description must not become an IOC");
        assert!(p.skipped.contains(&"ab".to_string()));
    }

    #[test]
    fn token_boundaries() {
        let t = "dst 10.0.0.15 and 10.0.0.1, notevil.com sub.evil.com";
        let find = |needle: &str| {
            t.match_indices(needle).any(|(s, m)| boundary_ok(t, s, s + m.len()))
        };
        assert!(find("10.0.0.1"));          // the standalone 10.0.0.1
        assert!(!t[..13].contains("10.0.0.1,"));
        assert!(!{ let s = t.find("10.0.0.15").unwrap(); boundary_ok(t, s, s + "10.0.0.1".len()) });
        let s = t.find("evil.com").unwrap(); // first occurrence is inside notevil.com
        assert!(!boundary_ok(t, s, s + 8));
        let s2 = t.rfind("evil.com").unwrap(); // sub.evil.com -> preceded by '.'
        assert!(boundary_ok(t, s2, s2 + 8));
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;
    use fx_core::{ArtefactKind, Event, EventSink, Principal, ProcessInfo, Provenance, Target, TimestampKind};

    fn ev(ts: &str, art: ArtefactKind, msg: &str, cmd: Option<&str>, target: Option<&str>, raw: serde_json::Value) -> Event {
        let t = time::PrimitiveDateTime::parse(ts, &time::format_description::well_known::Iso8601::DEFAULT).unwrap().assume_utc();
        Event {
            id: Uuid::new_v4(), timestamp: t, timestamp_kind: TimestampKind::Logged, artefact: art,
            action: "test.event".into(), host: Some("WKSTN-07".into()), user: Principal::default(),
            process: cmd.map(|c| ProcessInfo { command_line: Some(c.into()), ..Default::default() }),
            target: target.map(|p| Target { path: Some(p.into()), value_name: None, hash_sha1: None, size: None }),
            network: None, message: msg.into(),
            provenance: Provenance { evidence_id: Uuid::nil(), source_path: "x".into(), parser: "t".into(), parser_version: "0".into(), source_ref: None },
            raw,
        }
    }

    #[test]
    fn end_to_end_sweep_and_survives_rehunt() {
        let dir = std::env::temp_dir().join(format!("fx-ioc-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CaseStore::create(&dir.join("c.fxcase"), "ioc", None, "UTC").unwrap();
        {
            let mut w = store.event_writer();
            w.emit(ev("2026-02-10T22:14:05", ArtefactKind::Evtx, "Network connection to 185.220.101.4:51062", None, None, serde_json::json!({})));
            w.emit(ev("2026-02-10T22:15:00", ArtefactKind::Evtx, "conn to 185.220.101.45", None, None, serde_json::json!({}))); // must NOT match .4
            w.emit(ev("2026-02-10T22:16:00", ArtefactKind::BrowserHistory, "visit", None, Some("https://cdn.evil.example/p.bin"), serde_json::json!({})));
            w.emit(ev("2026-02-10T22:17:00", ArtefactKind::BrowserHistory, "visit notevil.example", None, None, serde_json::json!({}))); // must NOT match evil.example
            w.emit(ev("2026-02-10T22:18:00", ArtefactKind::Mft, "$SI created", None, Some("Users/Public/svc.exe"), serde_json::json!({})));
            w.emit(ev("2026-02-10T22:19:00", ArtefactKind::Amcache, "presence", None, None,
                      serde_json::json!({"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"})));
            w.emit(ev("2026-02-10T22:20:00", ArtefactKind::PsHistory, "typed", Some("Invoke-Mimikatz -DumpCreds"), None, serde_json::json!({})));
            w.flush().unwrap();
        }
        let parsed = parse_iocs("185.220.101.4\nevil[.]example\nC:\\Users\\Public\\svc.exe\nDA39A3EE5E6B4B0D3255BFEF95601890AFD80709\ninvoke-mimikatz\nnever-seen.example\n");
        let r = sweep(&store, &parsed).unwrap();
        let by = |v: &str| r.results.iter().find(|x| x.value.eq_ignore_ascii_case(v)).unwrap().events;
        assert_eq!(r.events_scanned, 7);
        assert_eq!(by("185.220.101.4"), 1, "IP must not match 185.220.101.45");
        assert_eq!(by("evil.example"), 1, "domain matches sub.domain but not notevil");
        assert_eq!(by("C:\\Users\\Public\\svc.exe"), 1, "path matches MFT forward-slash form");
        assert_eq!(by("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"), 1, "hash found in raw JSON, case-insensitive");
        assert_eq!(by("invoke-mimikatz"), 1);
        assert_eq!(by("never-seen.example"), 0);
        assert_eq!(r.matched, 5);

        let dets = store.detections().unwrap();
        assert_eq!(dets.iter().filter(|d| d.engine == "ioc").count(), 5);
        // Re-running the rules must keep the IOC findings.
        crate::run(&store, &crate::RuleSet::from_embedded());
        let after = store.detections().unwrap();
        assert_eq!(after.iter().filter(|d| d.engine == "ioc").count(), 5, "rule hunt wiped IOC findings");
        // A new sweep replaces (not duplicates) the IOC findings.
        sweep(&store, &parse_iocs("185.220.101.4\n")).unwrap();
        assert_eq!(store.detections().unwrap().iter().filter(|d| d.engine == "ioc").count(), 1);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
