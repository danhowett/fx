//! Windows Timeline parser — `ActivitiesCache.db`.
//!
//! Windows 10 1803+ records user activity (apps run, files opened, focus
//! changes) to a per-user SQLite database at
//! `\Users\<name>\AppData\Local\ConnectedDevicesPlatform\{L.<name>|AAD.*}\ActivitiesCache.db`.
//! The `Activity` table is the useful one: each row links an application to a
//! time span, with a JSON `Payload` that usually carries a display name and the
//! **file path or URL** the activity involved.
//!
//! Forensic value: a corroborating record of program execution and file access
//! with precise timing — it often survives when Prefetch/UserAssist have been
//! cleared, and it captures *files opened*, not just programs run.
//!
//! Timestamps (`StartTime`, `EndTime`, `LastModifiedTime`) are Unix epoch
//! seconds, UTC. We emit an execution event per activity at its StartTime (or
//! LastModifiedTime when StartTime is absent), with the resolved app on the
//! process fields and any file path on the target. Opened via immutable
//! read-only SQLite, like the browser parser, to tolerate WAL/locked DBs.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Principal, ProcessInfo, Provenance, Target, TimestampKind,
};
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct WindowsTimelineParser;

impl Parser for WindowsTimelineParser {
    fn name(&self) -> &'static str {
        "windows_timeline"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::WindowsTimeline]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();

        let uri = format!("file:{}?immutable=1&mode=ro", artefact.path.display());
        let conn = rusqlite::Connection::open_with_flags(
            &uri,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| ParseError::Malformed(format!("open sqlite: {e}")))?;

        let user = extract_user_from_path(&artefact.source_path);

        // AppId, ActivityType, Payload, StartTime, EndTime, LastModifiedTime.
        // All time columns are unix epoch seconds (UTC). Column names are stable
        // across 1803+. ActivityStatus/Priority omitted — not needed for triage.
        let sql = "SELECT AppId, ActivityType, Payload, StartTime, EndTime, LastModifiedTime \
                   FROM Activity";
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| ParseError::Malformed(format!("prepare Activity query: {e}")))?;

        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?, // AppId (json)
                r.get::<_, Option<i64>>(1)?,    // ActivityType
                r.get::<_, Option<String>>(2)?, // Payload (json text)
                r.get::<_, Option<i64>>(3)?,    // StartTime
                r.get::<_, Option<i64>>(4)?,    // EndTime
                r.get::<_, Option<i64>>(5)?,    // LastModifiedTime
            ))
        });
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                outcome.warnings.push(fx_core::RecordWarning {
                    source_ref: None,
                    message: format!("query Activity table (not a Timeline DB?): {e}"),
                });
                return Ok(outcome);
            }
        };

        for row in rows {
            outcome.records_read += 1;
            let (app_id, act_type, payload, start, end, last_mod) = match row {
                Ok(v) => v,
                Err(e) => {
                    outcome.warnings.push(fx_core::RecordWarning {
                        source_ref: None,
                        message: format!("Activity row: {e}"),
                    });
                    continue;
                }
            };

            // Event time: prefer StartTime, else LastModifiedTime, else skip.
            let epoch = start.or(last_mod);
            let ts = match epoch.and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok()) {
                Some(t) => t,
                None => continue, // undated rows aren't useful on a timeline
            };

            let app = resolve_app(app_id.as_deref());
            let (display, file_path, uri) = parse_payload(payload.as_deref());
            let type_label = activity_type_label(act_type);

            // Build a human message: prefer the display text, then the app.
            let what = display
                .clone()
                .or_else(|| file_path.clone())
                .or_else(|| uri.clone())
                .or_else(|| app.clone())
                .unwrap_or_else(|| "activity".into());
            let message = format!("Timeline {type_label}: {what}");

            let duration_secs = match (start, end) {
                (Some(s), Some(e)) if e >= s => Some(e - s),
                _ => None,
            };

            sink.emit(Event {
                id: Uuid::new_v4(),
                timestamp: ts,
                timestamp_kind: TimestampKind::Executed,
                artefact: ArtefactKind::WindowsTimeline,
                action: "execution.timeline_activity".into(),
                host: None,
                user: Principal {
                    name: user.clone(),
                    ..Default::default()
                },
                process: Some(ProcessInfo {
                    name: app.as_ref().map(|a| basename(a)),
                    path: app.clone(),
                    ..Default::default()
                }),
                target: file_path.clone().or(uri.clone()).map(|p| Target {
                    path: Some(p),
                    ..Default::default()
                }),
                network: None,
                message,
                provenance: Provenance {
                    evidence_id: artefact.evidence_id,
                    source_path: artefact.source_path.clone(),
                    parser: "windows_timeline".into(),
                    parser_version: env!("CARGO_PKG_VERSION").into(),
                    source_ref: None,
                },
                raw: json!({
                    "app_id": app,
                    "activity_type": act_type,
                    "activity_type_label": type_label,
                    "display_text": display,
                    "file_path": file_path,
                    "uri": uri,
                    "start_time": start,
                    "end_time": end,
                    "last_modified_time": last_mod,
                    "duration_secs": duration_secs,
                    "user": user,
                }),
            });
            outcome.events_emitted += 1;
        }

        Ok(outcome)
    }
}

/// ActivityType → human label. Types per the documented schema; 5 = app in use,
/// 6 = in focus, 2 = notification, 10/11/12 = clipboard/copy-paste. Unknown
/// types pass through as a number.
fn activity_type_label(t: Option<i64>) -> String {
    match t {
        Some(2) => "notification".into(),
        Some(5) => "app-in-use".into(),
        Some(6) => "in-focus".into(),
        Some(10) => "clipboard".into(),
        Some(11) | Some(12) => "copy-paste".into(),
        Some(n) => format!("type-{n}"),
        None => "activity".into(),
    }
}

/// The AppId field is a JSON array of {application, platform} objects. Pull the
/// most useful application string — prefer a Win32 path, else the first entry.
fn resolve_app(app_id: Option<&str>) -> Option<String> {
    let raw = app_id?;
    // Often: [{"application":"C:\\...\\app.exe","platform":"windows_win32"}, ...]
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        if let Some(arr) = v.as_array() {
            // Prefer a win32 application entry (a real path).
            let mut first: Option<String> = None;
            for item in arr {
                let appv = item.get("application").and_then(Value::as_str);
                let plat = item.get("platform").and_then(Value::as_str).unwrap_or("");
                if let Some(a) = appv {
                    if a.is_empty() {
                        continue;
                    }
                    if plat.contains("win32") {
                        return Some(a.to_string());
                    }
                    if first.is_none() {
                        first = Some(a.to_string());
                    }
                }
            }
            return first;
        }
    }
    // Not JSON — return the raw value (older schemas store a plain string).
    if raw.trim().is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

/// The Payload field is JSON (stored as a text/BLOB) with keys that vary by
/// activity type. Extract (displayText, file path, uri) best-effort.
fn parse_payload(payload: Option<&str>) -> (Option<String>, Option<String>, Option<String>) {
    let Some(raw) = payload else {
        return (None, None, None);
    };
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return (None, None, None);
    };
    let get = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);

    let display = get("displayText").or_else(|| get("appDisplayName"));
    // File path can appear under contentUri / 1 (a MS "activity" convention) or
    // in the "description"; URLs under contentUri too.
    let content = get("contentUri").or_else(|| get("description"));
    let (file_path, uri) = match content {
        Some(c) if c.starts_with("http://") || c.starts_with("https://") => (None, Some(c)),
        Some(c) if c.contains(":\\") || c.starts_with("\\\\") || c.starts_with("file:") => {
            (Some(c.replace("file:///", "").replace("file:", "")), None)
        }
        Some(c) => (Some(c), None),
        None => (None, None),
    };
    (display, file_path, uri)
}

fn basename(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
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
    fn resolves_win32_app() {
        let appid = r#"[{"application":"c:\\temp\\evil.exe","platform":"windows_win32"},{"application":"evil","platform":"afs_crossplatform"}]"#;
        assert_eq!(resolve_app(Some(appid)), Some("c:\\temp\\evil.exe".into()));
    }

    #[test]
    fn parses_payload_file_and_display() {
        let p = r#"{"displayText":"report.docx","appDisplayName":"Word","contentUri":"C:\\Users\\x\\report.docx"}"#;
        let (d, f, u) = parse_payload(Some(p));
        assert_eq!(d, Some("report.docx".into()));
        assert_eq!(f, Some("C:\\Users\\x\\report.docx".into()));
        assert_eq!(u, None);
    }

    #[test]
    fn parses_payload_url() {
        let p = r#"{"displayText":"Bing","contentUri":"https://bing.com/x"}"#;
        let (_, f, u) = parse_payload(Some(p));
        assert_eq!(f, None);
        assert_eq!(u, Some("https://bing.com/x".into()));
    }

    #[test]
    fn type_labels() {
        assert_eq!(activity_type_label(Some(5)), "app-in-use");
        assert_eq!(activity_type_label(Some(6)), "in-focus");
        assert_eq!(activity_type_label(Some(99)), "type-99");
    }
}
