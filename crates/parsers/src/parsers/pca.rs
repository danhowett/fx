//! Program Compatibility Assistant (PCA) logs — Windows 11 22H2+.
//!
//! `C:\Windows\appcompat\pca\` holds plain-text launch records that survive
//! where Prefetch is disabled (servers, some hardened builds):
//!
//! * `PcaAppLaunchDic.txt` — `<full path>|<last launch, UTC>` per executable
//!   launched from Explorer / the shell.
//! * `PcaGeneralDb0.txt` / `PcaGeneralDb1.txt` — `<time UTC>|<record type>|
//!   <path>|<product>|<company>|<version>|<program id>|<message>` for
//!   compatibility events such as abnormal process exits and installs.
//!
//! Both become execution events with the image path on `process.image`, so
//! the existing execution / tooling rules apply to them.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser, Principal,
    ProcessInfo, Provenance, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct PcaParser;

/// One parsed PCA record.
#[derive(Debug, Clone)]
pub struct PcaRecord {
    pub ts: OffsetDateTime,
    pub action: &'static str,
    pub path: String,
    pub message: String,
    pub line: usize,
    pub raw: serde_json::Value,
}

fn expand_env(p: &str) -> String {
    let l = p.to_ascii_lowercase();
    for (var, val) in [
        ("%programfiles%", r"C:\Program Files"),
        ("%programfiles(x86)%", r"C:\Program Files (x86)"),
        ("%windir%", r"C:\Windows"),
        ("%systemroot%", r"C:\Windows"),
        ("%programdata%", r"C:\ProgramData"),
    ] {
        if l.starts_with(var) {
            return format!("{val}{}", &p[var.len()..]);
        }
    }
    p.to_string()
}

/// Parse either PCA file's text. `general` selects the GeneralDb layout.
pub fn parse_text(text: &str, general: bool) -> Vec<PcaRecord> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        if !general {
            // path|timestamp
            if f.len() < 2 {
                continue;
            }
            let (Some(ts), _) = crate::parsers::defender_log::leading_timestamp(f[f.len() - 1].trim()) else { continue };
            let path = expand_env(f[..f.len() - 1].join("|").trim());
            if path.is_empty() {
                continue;
            }
            out.push(PcaRecord {
                ts,
                action: "execution.pca_launch",
                message: format!("PCA launch: {path}"),
                raw: json!({ "path": path, "source": "PcaAppLaunchDic.txt" }),
                path,
                line: i + 1,
            });
        } else {
            if f.len() < 3 {
                continue;
            }
            let (Some(ts), _) = crate::parsers::defender_log::leading_timestamp(f[0].trim()) else { continue };
            let path = expand_env(f[2].trim());
            if path.is_empty() {
                continue;
            }
            let get = |n: usize| f.get(n).map(|s| s.trim().to_string()).unwrap_or_default();
            let msg = get(7);
            out.push(PcaRecord {
                ts,
                action: "execution.pca_event",
                message: if msg.is_empty() { format!("PCA record: {path}") } else { format!("PCA: {msg}: {path}") },
                raw: json!({ "path": path, "record_type": get(1), "product": get(3), "company": get(4),
                             "version": get(5), "program_id": get(6), "message": msg, "source": "PcaGeneralDb" }),
                path,
                line: i + 1,
            });
        }
    }
    out
}

fn basename(p: &str) -> &str {
    p.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(p)
}

impl Parser for PcaParser {
    fn name(&self) -> &'static str {
        "pca"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Pca]
    }

    fn parse(&self, artefact: &IdentifiedArtefact, sink: &mut dyn EventSink) -> Result<ParseOutcome, ParseError> {
        let text = crate::parsers::text_decode::read_text_file(&artefact.path)
            .map_err(|e| ParseError::Io { path: artefact.path.display().to_string(), source: e })?;
        let general = artefact.source_path.to_ascii_lowercase().contains("pcageneraldb");
        let mut outcome = ParseOutcome::default();
        for r in parse_text(&text, general) {
            outcome.records_read += 1;
            sink.emit(Event {
                id: Uuid::new_v4(),
                timestamp: r.ts,
                timestamp_kind: TimestampKind::Executed,
                artefact: ArtefactKind::Pca,
                action: r.action.into(),
                host: None,
                user: Principal::default(),
                process: Some(ProcessInfo {
                    path: Some(r.path.clone()),
                    name: Some(basename(&r.path).to_string()),
                    ..Default::default()
                }),
                target: None,
                network: None,
                message: r.message,
                provenance: Provenance {
                    evidence_id: artefact.evidence_id,
                    source_path: artefact.source_path.clone(),
                    parser: "pca".into(),
                    parser_version: env!("CARGO_PKG_VERSION").into(),
                    source_ref: Some(format!("line {}", r.line)),
                },
                raw: r.raw,
            });
            outcome.events_emitted += 1;
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_launch_dic() {
        let t = "\u{feff}C:\\Users\\bob\\Downloads\\rclone.exe|2024-05-01 10:11:12.345\r\n%programfiles%\\7-Zip\\7zFM.exe|2024-05-02 08:00:00.000\r\nbroken line\r\n";
        let r = parse_text(t, false);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].path, "C:\\Users\\bob\\Downloads\\rclone.exe");
        assert_eq!(r[0].ts.hour(), 10);
        assert_eq!(r[1].path, "C:\\Program Files\\7-Zip\\7zFM.exe");
        assert_eq!(r[0].action, "execution.pca_launch");
    }

    #[test]
    fn general_db() {
        let t = "2024-05-01 10:11:12.000|2|%windir%\\temp\\x.exe|X Tool|Evil Co|1.0.0|0006abc|Abnormal process exit with code 0xc0000005\n";
        let r = parse_text(t, true);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].path, "C:\\Windows\\temp\\x.exe");
        assert!(r[0].message.contains("Abnormal process exit"));
        assert_eq!(r[0].raw["company"], "Evil Co");
    }
}
