//! Remote-access tool logs: AnyDesk and TeamViewer.
//!
//! Commercial remote-access tools are a staple of ransomware affiliates and
//! eCrime operators — installed for persistence, or abused where already
//! present. Their own logs record who connected, from where, when, and whether
//! files moved, often surviving after the attacker uninstalls the tool.
//!
//! Supported files (identified by name; all plain text, UTF-8 or UTF-16):
//!   * AnyDesk `connection_trace.txt` — one line per session:
//!       `Incoming    2023-06-07, 11:46    User    123456789    987654321`
//!     direction, date, time, auth (User / Passwd / Token / REJECTED),
//!     remote AnyDesk ID, local ID.
//!   * AnyDesk `ad.trace` / `ad_svc.trace` — verbose trace; we keep only the
//!     forensically useful lines (incoming requests, logins with source IP,
//!     accept/reject, file transfers, remote OS / client ID).
//!   * TeamViewer `Connections_incoming.txt` (incoming) and `Connections.txt`
//!     (outgoing) — tab-separated: remote ID, [remote name], start, end,
//!     local user, connection type, session GUID. Dates are `dd-mm-yyyy
//!     HH:MM:SS` in the host's LOCAL time; we store them as-is and flag that
//!     in `raw.time_basis`.

use crate::parsers::text_decode::read_text_file;
use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, NetworkInfo, ParseError, ParseOutcome,
    Parser, Principal, ProcessInfo, Provenance, RecordWarning, Target, TimestampKind,
};
use serde_json::json;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use uuid::Uuid;

#[derive(Default)]
pub struct RemoteAccessParser;

impl Parser for RemoteAccessParser {
    fn name(&self) -> &'static str {
        "remote_access"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::RemoteAccess]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let text = read_text_file(&artefact.path).map_err(|e| ParseError::Io {
            path: artefact.path.display().to_string(),
            source: e,
        })?;
        let name = artefact
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut outcome = ParseOutcome::default();
        let kind = file_kind(&name, &artefact.source_path.to_ascii_lowercase());
        for (line_no, line) in text.lines().enumerate() {
            outcome.records_read += 1;
            let rec = match kind {
                FileKind::AnyDeskConnTrace => parse_anydesk_conn(line),
                FileKind::AnyDeskTrace => parse_anydesk_trace(line),
                FileKind::TeamViewerIncoming => parse_teamviewer(line, true),
                FileKind::TeamViewerOutgoing => parse_teamviewer(line, false),
                FileKind::Unknown => None,
            };
            let Some(rec) = rec else { continue };
            sink.emit(to_event(artefact, &rec, line_no + 1));
            outcome.events_emitted += 1;
        }
        if outcome.events_emitted == 0 && outcome.records_read > 0 {
            outcome.warnings.push(RecordWarning {
                source_ref: None,
                message: "no recognised remote-access session lines in file".into(),
            });
        }
        Ok(outcome)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FileKind {
    AnyDeskConnTrace,
    AnyDeskTrace,
    TeamViewerIncoming,
    TeamViewerOutgoing,
    Unknown,
}

fn file_kind(name: &str, lower_path: &str) -> FileKind {
    if name == "connection_trace.txt" {
        FileKind::AnyDeskConnTrace
    } else if name == "ad.trace" || name == "ad_svc.trace" {
        FileKind::AnyDeskTrace
    } else if name.starts_with("connections_incoming") {
        FileKind::TeamViewerIncoming
    } else if name == "connections.txt" && lower_path.contains("teamviewer") {
        FileKind::TeamViewerOutgoing
    } else {
        FileKind::Unknown
    }
}

/// One normalized remote-access record.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RaRecord {
    pub tool: &'static str,
    pub action: &'static str,
    pub ts: OffsetDateTime,
    pub end: Option<OffsetDateTime>,
    pub remote_id: Option<String>,
    pub remote_name: Option<String>,
    pub source_ip: Option<String>,
    pub user: Option<String>,
    pub detail: String,
    pub local_time: bool,
}

fn to_event(artefact: &IdentifiedArtefact, r: &RaRecord, line_no: usize) -> Event {
    let who = r
        .remote_name
        .clone()
        .or_else(|| r.remote_id.clone())
        .unwrap_or_else(|| "?".into());
    let message = format!("{}: {} ({})", r.tool, r.detail, who);
    Event {
        id: Uuid::new_v4(),
        timestamp: r.ts,
        timestamp_kind: TimestampKind::Logged,
        artefact: ArtefactKind::RemoteAccess,
        action: r.action.to_string(),
        host: None,
        user: Principal { name: r.user.clone(), ..Default::default() },
        process: Some(ProcessInfo {
            name: Some(format!("{}.exe", r.tool)),
            ..Default::default()
        }),
        target: r.remote_id.as_ref().map(|id| Target {
            path: None,
            value_name: Some(id.clone()),
            hash_sha1: None,
            size: None,
        }),
        network: r.source_ip.as_ref().map(|ip| NetworkInfo {
            source_ip: Some(ip.clone()),
            dest_ip: None,
            logon_type: None,
        }),
        message,
        provenance: Provenance {
            evidence_id: artefact.evidence_id,
            source_path: artefact.source_path.clone(),
            parser: "remote_access".into(),
            parser_version: env!("CARGO_PKG_VERSION").into(),
            source_ref: Some(format!("line {line_no}")),
        },
        raw: json!({
            "tool": r.tool,
            "remote_id": r.remote_id,
            "remote_name": r.remote_name,
            "source_ip": r.source_ip,
            "local_user": r.user,
            "end": r.end.map(|t| t.to_string()),
            "detail": r.detail,
            "time_basis": if r.local_time { "host local time (as logged)" } else { "UTC" },
        }),
    }
}

// ── AnyDesk connection_trace.txt ────────────────────────────────────────────

pub(crate) fn parse_anydesk_conn(line: &str) -> Option<RaRecord> {
    let mut it = line.split_whitespace();
    let dir = it.next()?;
    let incoming = match dir.to_ascii_lowercase().as_str() {
        "incoming" => true,
        "outgoing" => false,
        _ => return None,
    };
    let date = it.next()?.trim_end_matches(',');
    let time = it.next()?;
    let ts = ymd_hms(date, time)?;
    let auth = it.next()?.to_string();
    let remote_id = it.next().map(str::to_string);
    let local_id = it.next().map(str::to_string);
    let rejected = auth.eq_ignore_ascii_case("rejected");
    Some(RaRecord {
        tool: "AnyDesk",
        action: match (incoming, rejected) {
            (true, false) => "remote_access.session_incoming",
            (true, true) => "remote_access.session_rejected",
            (false, _) => "remote_access.session_outgoing",
        },
        ts,
        end: None,
        remote_id,
        remote_name: None,
        source_ip: None,
        user: None,
        detail: format!(
            "{} session, auth {auth}{}",
            if incoming { "incoming" } else { "outgoing" },
            local_id.map(|l| format!(", local ID {l}")).unwrap_or_default()
        ),
        local_time: false,
    })
}

// ── AnyDesk ad.trace / ad_svc.trace ─────────────────────────────────────────

/// Interesting trace messages -> (action, label). Matched case-insensitively
/// as substrings of the message part (after the " - " component separator).
const ANYDESK_TRACE_SIGNALS: &[(&str, &str, &str)] = &[
    ("incoming session request", "remote_access.session_request", "incoming session request"),
    ("logged in from", "remote_access.login", "logged in"),
    ("accepting from", "remote_access.session_accepted", "session accepted"),
    ("accept request from", "remote_access.session_accepted", "session accepted"),
    ("rejected", "remote_access.session_rejected", "session rejected"),
    ("preparing files", "remote_access.file_transfer", "file transfer"),
    ("file transfer", "remote_access.file_transfer", "file transfer"),
    ("download started", "remote_access.file_transfer", "file transfer"),
    ("remote os", "remote_access.session_info", "remote OS"),
    ("client-id", "remote_access.session_info", "client ID"),
    ("session stopped", "remote_access.session_end", "session ended"),
];

pub(crate) fn parse_anydesk_trace(line: &str) -> Option<RaRecord> {
    let t = line.trim_start();
    let mut it = t.split_whitespace();
    let level = it.next()?.to_ascii_lowercase();
    if !matches!(level.as_str(), "info" | "warning" | "error" | "debug" | "trace") {
        return None;
    }
    let date = it.next()?;
    let time = it.next()?;
    let ts = ymd_hms(date, time.split('.').next()?)?;
    let msg = t.split_once(" - ").map(|(_, m)| m.trim()).unwrap_or("");
    let lc = msg.to_ascii_lowercase();
    let (_, action, label) = ANYDESK_TRACE_SIGNALS.iter().find(|(k, _, _)| lc.contains(k))?;
    Some(RaRecord {
        tool: "AnyDesk",
        action,
        ts,
        end: None,
        remote_id: first_long_number(msg),
        remote_name: None,
        source_ip: first_ipv4(msg),
        user: None,
        detail: format!("{label}: {}", truncate(msg, 180)),
        local_time: false,
    })
}

// ── TeamViewer Connections_incoming.txt / Connections.txt ───────────────────

pub(crate) fn parse_teamviewer(line: &str, incoming: bool) -> Option<RaRecord> {
    let f: Vec<&str> = line.split('\t').map(str::trim).collect();
    if f.len() < 4 {
        return None;
    }
    // Locate the first two date fields; everything is positioned around them
    // (incoming has a remote-name column before the dates, outgoing doesn't).
    let date_idx: Vec<usize> = (0..f.len()).filter(|&i| dmy_hms(f[i]).is_some()).collect();
    let start_i = *date_idx.first()?;
    let ts = dmy_hms(f[start_i])?;
    let end = date_idx.get(1).and_then(|&i| dmy_hms(f[i]));
    let after = date_idx.get(1).copied().unwrap_or(start_i) + 1;
    let remote_id = f.first().filter(|s| !s.is_empty()).map(|s| s.to_string());
    let remote_name = if start_i >= 2 { Some(f[1].to_string()).filter(|s| !s.is_empty()) } else { None };
    let user = f.get(after).map(|s| s.to_string()).filter(|s| !s.is_empty());
    let conn_type = f.get(after + 1).copied().unwrap_or("");
    let dur = end.map(|e| (e - ts).whole_minutes());
    Some(RaRecord {
        tool: "TeamViewer",
        action: if incoming { "remote_access.session_incoming" } else { "remote_access.session_outgoing" },
        ts,
        end,
        remote_id,
        remote_name,
        source_ip: None,
        user: user.clone(),
        detail: format!(
            "{} {} session{}{}",
            if incoming { "incoming" } else { "outgoing" },
            if conn_type.is_empty() { "" } else { conn_type },
            dur.map(|m| format!(", {m} min")).unwrap_or_default(),
            user.map(|u| format!(", local user {u}")).unwrap_or_default()
        ),
        local_time: true,
    })
}

// ── small helpers ───────────────────────────────────────────────────────────

/// "2023-06-07" + "11:46[:51]" -> UTC datetime.
fn ymd_hms(date: &str, time: &str) -> Option<OffsetDateTime> {
    let d: Vec<&str> = date.split('-').collect();
    if d.len() != 3 {
        return None;
    }
    build(d[0].parse().ok()?, d[1].parse().ok()?, d[2].parse().ok()?, time)
}

/// "07-06-2023 11:46:51" (dd-mm-yyyy) -> datetime.
fn dmy_hms(s: &str) -> Option<OffsetDateTime> {
    let (date, time) = s.split_once(' ')?;
    let d: Vec<&str> = date.split('-').collect();
    if d.len() != 3 || d[2].len() != 4 {
        return None;
    }
    build(d[2].parse().ok()?, d[1].parse().ok()?, d[0].parse().ok()?, time.trim())
}

fn build(y: i32, mo: u8, d: u8, time: &str) -> Option<OffsetDateTime> {
    let t: Vec<&str> = time.split(':').collect();
    if t.len() < 2 {
        return None;
    }
    let h: u8 = t[0].parse().ok()?;
    let m: u8 = t[1].parse().ok()?;
    let s: u8 = t.get(2).and_then(|x| x.parse().ok()).unwrap_or(0);
    let date = Date::from_calendar_date(y, Month::try_from(mo).ok()?, d).ok()?;
    Some(PrimitiveDateTime::new(date, Time::from_hms(h, m, s).ok()?).assume_utc())
}

/// First dotted-quad IPv4 in the text (port suffix stripped).
fn first_ipv4(s: &str) -> Option<String> {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find(|tok| {
            let parts: Vec<&str> = tok.split('.').collect();
            parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
        })
        .map(str::to_string)
}

/// First run of 9+ digits (an AnyDesk ID).
fn first_long_number(s: &str) -> Option<String> {
    s.split(|c: char| !c.is_ascii_digit()).find(|t| t.len() >= 9).map(str::to_string)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n).collect::<String>() + "…" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anydesk_connection_trace() {
        let r = parse_anydesk_conn("Incoming    2023-06-07, 11:46    User          123456789    987654321").unwrap();
        assert_eq!(r.action, "remote_access.session_incoming");
        assert_eq!(r.remote_id.as_deref(), Some("123456789"));
        assert_eq!(r.ts.to_string(), "2023-06-07 11:46:00.0 +00:00:00");
        let rej = parse_anydesk_conn("Incoming\t2023-06-07, 11:50\tREJECTED\t555666777\t987654321").unwrap();
        assert_eq!(rej.action, "remote_access.session_rejected");
        assert!(parse_anydesk_conn("garbage line").is_none());
    }

    #[test]
    fn anydesk_trace_login_with_ip() {
        let l = "   info 2023-06-07 11:46:51.234       back   3584   4012   22   anynet.relay_conn - Logged in from 185.220.101.4:51062 on relay 3e5f4b5c.";
        let r = parse_anydesk_trace(l).unwrap();
        assert_eq!(r.action, "remote_access.login");
        assert_eq!(r.source_ip.as_deref(), Some("185.220.101.4"));
        let req = parse_anydesk_trace("   info 2023-06-07 11:46:50.100  back 1 2  app.backend_session - Incoming session request: Workstation (123456789)").unwrap();
        assert_eq!(req.action, "remote_access.session_request");
        assert_eq!(req.remote_id.as_deref(), Some("123456789"));
        assert!(parse_anydesk_trace("   info 2023-06-07 11:46:50.100  back 1 2  app.ui - painting window").is_none());
    }

    #[test]
    fn teamviewer_incoming_and_outgoing() {
        let r = parse_teamviewer("1234567890\tATTACKER-PC\t07-06-2023 11:46:51\t07-06-2023 12:01:02\tAdministrator\tRemoteControl\t{a-b-c}", true).unwrap();
        assert_eq!(r.remote_id.as_deref(), Some("1234567890"));
        assert_eq!(r.remote_name.as_deref(), Some("ATTACKER-PC"));
        assert_eq!(r.user.as_deref(), Some("Administrator"));
        assert!(r.detail.contains("14 min"));
        assert!(r.local_time);
        let o = parse_teamviewer("998877665\t08-06-2023 09:00:00\t08-06-2023 09:30:00\tbob\tFileTransfer\t{x}", false).unwrap();
        assert_eq!(o.action, "remote_access.session_outgoing");
        assert_eq!(o.remote_name, None);
        assert_eq!(o.user.as_deref(), Some("bob"));
        assert!(o.detail.contains("FileTransfer"));
    }
}
