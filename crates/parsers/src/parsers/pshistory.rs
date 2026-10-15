//! PowerShell console history parser — PSReadLine `ConsoleHost_history.txt`.
//!
//! From PowerShell 5 on Windows 10+, the PSReadLine module saves console
//! command history to a plain-text file, one command per line, appended in
//! execution order (up to 4096 by default), at
//! `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
//! (one per user).
//!
//! Forensic value: it captures the attacker's *literal typed commands* — even
//! when script-block logging and transcripts were disabled, and even for
//! commands that cleared other logs. Each line becomes an event with the
//! command on `process.command_line`, so every PowerShell / LOLBin / ransomware
//! rule in the pack matches it automatically.
//!
//! The file carries no per-line timestamps, so we use the file's modified time
//! as the event time (the best available signal) and preserve execution order
//! via the line number in `source_ref`. Multi-line commands are joined: a
//! PSReadLine continuation is stored with an explicit backtick-newline, which
//! we fold back into one logical command.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    ProcessInfo, Provenance, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct PsHistoryParser;

impl Parser for PsHistoryParser {
    fn name(&self) -> &'static str {
        "pshistory"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::PsHistory]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();

        // PSReadLine history may be UTF-8 or UTF-16; decode by BOM/heuristic so a
        // UTF-16 file isn't rejected by a UTF-8-only read.
        let text = crate::parsers::text_decode::read_text_file(&artefact.path).map_err(|e| {
            ParseError::Io {
                path: artefact.path.display().to_string(),
                source: e,
            }
        })?;

        // The file has no per-line timestamps; use its mtime as the event time.
        let ts = std::fs::metadata(&artefact.path)
            .and_then(|m| m.modified())
            .map(OffsetDateTime::from)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);

        // Try to derive the owning user from the path (…\Users\<name>\AppData…).
        let user = extract_user_from_path(&artefact.source_path);

        for (line_no, command) in logical_commands(&text).into_iter().enumerate() {
            outcome.records_read += 1;
            let trimmed = command.trim();
            if trimmed.is_empty() {
                continue;
            }

            sink.emit(Event {
                id: Uuid::new_v4(),
                timestamp: ts,
                timestamp_kind: TimestampKind::Recorded, // file mtime, not exact exec time
                artefact: ArtefactKind::PsHistory,
                action: "execution.powershell_history".into(),
                host: None,
                user: fx_core::Principal {
                    name: user.clone(),
                    ..Default::default()
                },
                process: Some(ProcessInfo {
                    name: Some("powershell".into()),
                    command_line: Some(trimmed.to_string()),
                    ..Default::default()
                }),
                target: None,
                network: None,
                message: format!("PowerShell history: {}", preview(trimmed)),
                provenance: Provenance {
                    evidence_id: artefact.evidence_id,
                    source_path: artefact.source_path.clone(),
                    parser: "pshistory".into(),
                    parser_version: env!("CARGO_PKG_VERSION").into(),
                    source_ref: Some(format!("line {}", line_no + 1)),
                },
                raw: json!({
                    "command": trimmed,
                    "line": line_no + 1,
                    "user": user,
                }),
            });
            outcome.events_emitted += 1;
        }

        Ok(outcome)
    }
}

/// Fold PSReadLine continuations into logical commands. PSReadLine stores a
/// multi-line command with a trailing backtick before the newline; join those.
fn logical_commands(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(prefix) = line.strip_suffix('`') {
            // continuation — accumulate and keep going
            current.push_str(prefix);
            current.push('\n');
        } else {
            current.push_str(line);
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// First 120 chars of a command, single-lined, for the message.
fn preview(cmd: &str) -> String {
    let one = cmd.replace('\n', " ");
    if one.chars().count() > 120 {
        let t: String = one.chars().take(120).collect();
        format!("{t}…")
    } else {
        one
    }
}

/// Best-effort owning username from a path containing \Users\<name>\.
fn extract_user_from_path(path: &str) -> Option<String> {
    let norm = path.replace('\\', "/").to_lowercase();
    let orig = path.replace('\\', "/");
    let idx = norm.find("/users/")?;
    let after = &orig[idx + "/users/".len()..];
    let name = after.split('/').next()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_simple_commands() {
        let text = "whoami /all\nnet user\nGet-Process lsass\n";
        let cmds = logical_commands(text);
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0], "whoami /all");
        assert_eq!(cmds[2], "Get-Process lsass");
    }

    #[test]
    fn folds_continuations() {
        // a backtick-continued multi-line command
        let text = "Invoke-Command `\n-ComputerName dc01 `\n-ScriptBlock { whoami }\ndir\n";
        let cmds = logical_commands(text);
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].contains("Invoke-Command"));
        assert!(cmds[0].contains("whoami"));
        assert_eq!(cmds[1], "dir");
    }

    #[test]
    fn extracts_user() {
        assert_eq!(
            extract_user_from_path("C/Users/jsmith/AppData/Roaming/.../ConsoleHost_history.txt"),
            Some("jsmith".into())
        );
        // no \Users\ segment -> None
        assert_eq!(extract_user_from_path("C/Windows/System32/foo.txt"), None);
    }
}
