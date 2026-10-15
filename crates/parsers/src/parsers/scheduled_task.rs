//! Scheduled Task parser (`\Windows\System32\Tasks\...` XML definitions).
//!
//! Scheduled tasks are a first-class persistence and execution mechanism
//! (T1053.005) — attackers register tasks that launch payloads at logon, on a
//! schedule, or on an event. The on-disk task is an XML document; the fields
//! that matter for hunting are the Actions/Exec/Command (+ Arguments), the
//! Principal (run-as, especially SYSTEM), and the RegistrationInfo (author and
//! registration date, which time-anchors the persistence).
//!
//! We parse with `roxmltree` (read-only, allocation-light) and are tolerant of
//! the default task XML namespace. A file identified as a task that doesn't
//! actually have a <Task> root is skipped with a warning rather than erroring.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Principal, ProcessInfo, Provenance, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct ScheduledTaskParser;

impl Parser for ScheduledTaskParser {
    fn name(&self) -> &'static str {
        "scheduled_task"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::ScheduledTask]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();
        outcome.records_read = 1;

        // Task XML is frequently UTF-16 (LE, with BOM); read_to_string would
        // reject it and fail every task. Decode by BOM/heuristic instead.
        let text = crate::parsers::text_decode::read_text_file(&artefact.path).map_err(|e| {
            ParseError::Io {
                path: artefact.path.display().to_string(),
                source: e,
            }
        })?;

        let doc = roxmltree::Document::parse(&text)
            .map_err(|e| ParseError::Malformed(format!("task XML: {e}")))?;
        let root = doc.root_element();
        if root.tag_name().name() != "Task" {
            outcome.warnings.push(fx_core::RecordWarning {
                source_ref: None,
                message: format!(
                    "identified as task but root is <{}>, not <Task> — skipped",
                    root.tag_name().name()
                ),
            });
            return Ok(outcome);
        }

        // Local-name lookups ignore the task XML namespace.
        let find = |parent: roxmltree::Node, name: &str| -> Option<String> {
            parent
                .descendants()
                .find(|n| n.tag_name().name() == name)
                .and_then(|n| n.text())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        let command = find(root, "Command");
        let arguments = find(root, "Arguments");
        let author = find(root, "Author");
        let description = find(root, "Description");
        let user_id = find(root, "UserId");
        let run_level = find(root, "RunLevel");
        // The task name is the file name (the XML doesn't always carry it).
        let task_name = artefact
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<task>")
            .to_string();

        // Registration date anchors the persistence in time. Prefer the task
        // XML's own <Date>; if it has none (many system tasks don't), fall back
        // to the task file's modified time, which is far more meaningful on the
        // timeline than dumping every date-less task onto the 1970 epoch. Epoch
        // is only the last resort if even the mtime is unavailable.
        let reg_date = find(root, "Date")
            .as_deref()
            .and_then(parse_task_date)
            .or_else(|| {
                std::fs::metadata(&artefact.path)
                    .and_then(|m| m.modified())
                    .map(OffsetDateTime::from)
                    .ok()
            })
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);

        // Summarize the trigger types present (LogonTrigger, BootTrigger,
        // CalendarTrigger, etc.) — the "when does this run" that matters for
        // triage.
        let triggers: Vec<String> = root
            .descendants()
            .filter(|n| n.tag_name().name().ends_with("Trigger"))
            .map(|n| n.tag_name().name().to_string())
            .collect();

        let full_command = match (&command, &arguments) {
            (Some(c), Some(a)) => Some(format!("{c} {a}")),
            (Some(c), None) => Some(c.clone()),
            _ => None,
        };

        let message = format!(
            "Scheduled task '{}' runs {} (as {}{}){}",
            task_name,
            full_command.clone().unwrap_or_else(|| "<no exec action>".into()),
            user_id.clone().unwrap_or_else(|| "?".into()),
            run_level
                .as_deref()
                .map(|r| if r.eq_ignore_ascii_case("HighestAvailable") { ", elevated" } else { "" })
                .unwrap_or(""),
            if triggers.is_empty() {
                String::new()
            } else {
                format!(" [triggers: {}]", triggers.join(", "))
            },
        );

        sink.emit(Event {
            id: Uuid::new_v4(),
            timestamp: reg_date,
            timestamp_kind: TimestampKind::Created,
            artefact: ArtefactKind::ScheduledTask,
            action: "persistence.scheduled_task".into(),
            host: None,
            user: Principal {
                name: user_id.clone(),
                ..Default::default()
            },
            process: full_command.as_ref().map(|_| ProcessInfo {
                path: command.clone(),
                command_line: full_command.clone(),
                ..Default::default()
            }),
            target: None,
            network: None,
            message,
            provenance: Provenance {
                evidence_id: artefact.evidence_id,
                source_path: artefact.source_path.clone(),
                parser: "scheduled_task".into(),
                parser_version: env!("CARGO_PKG_VERSION").into(),
                source_ref: Some(task_name.clone()),
            },
            raw: json!({
                "task": task_name,
                "command": command,
                "arguments": arguments,
                "author": author,
                "description": description,
                "user_id": user_id,
                "run_level": run_level,
                "triggers": triggers,
            }),
        });
        outcome.events_emitted += 1;

        Ok(outcome)
    }
}

/// Task registration dates are ISO-8601 without a timezone, e.g.
/// `2026-02-11T02:16:40.123456`. Parse leniently: try full RFC3339 first, then
/// append a Z and retry, then date-only.
fn parse_task_date(s: &str) -> Option<OffsetDateTime> {
    use time::format_description::well_known::Rfc3339;
    if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
        return Some(dt);
    }
    // No offset: treat as UTC by appending Z (strip sub-second if it trips the
    // parser).
    let base = s.split('.').next().unwrap_or(s);
    OffsetDateTime::parse(&format!("{base}Z"), &Rfc3339).ok()
}
