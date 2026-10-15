//! Browser history parser — Chromium (`History`) and Firefox (`places.sqlite`).
//!
//! Both are SQLite; we detect which schema is present and read visits and
//! downloads. This is the artefact that lights up the initial-access and
//! exfiltration end of the kill chain: payloads pulled from Discord CDN / MEGA,
//! uploads to web drop services, cloud-console access, and ransomware
//! leak-site visits — several imported IOC rules match precisely on browser
//! visit/download domains and were dormant until this parser existed.
//!
//! Each emitted event carries, in `raw`, the two fields those rules key on:
//!   * `extras.browser_event`  = "visit" | "download"
//!   * `extras.domain`         = the URL host
//! plus the full URL and title. The domain is also lifted into `target.path`
//! so it shows on the timeline and in text search.
//!
//! Timestamp epochs differ and MUST NOT be confused:
//!   * Chromium: microseconds since 1601-01-01 (WebKit/Windows epoch)
//!   * Firefox:  microseconds since 1970-01-01 (Unix epoch)

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser,
    Provenance, Target, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct BrowserHistoryParser;

impl Parser for BrowserHistoryParser {
    fn name(&self) -> &'static str {
        "browser_history"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::BrowserHistory]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();

        // Open read-only. Browser DBs in a live triage are often WAL-mode and
        // may be locked; immutable mode reads the main db file directly and
        // tolerates a missing/locked WAL (we accept slightly stale reads over
        // failing to open — this is triage, not live IR).
        let uri = format!("file:{}?immutable=1&mode=ro", artefact.path.display());
        let conn = rusqlite::Connection::open_with_flags(
            &uri,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| ParseError::Malformed(format!("open sqlite: {e}")))?;

        match detect_schema(&conn) {
            BrowserSchema::Chromium => {
                parse_chromium(&conn, artefact, sink, &mut outcome);
            }
            BrowserSchema::Firefox => {
                parse_firefox(&conn, artefact, sink, &mut outcome);
            }
            BrowserSchema::Unknown => {
                outcome.warnings.push(fx_core::RecordWarning {
                    source_ref: None,
                    message: "SQLite DB identified as browser history but matched \
                              neither Chromium nor Firefox schema — skipped"
                        .into(),
                });
            }
        }

        Ok(outcome)
    }
}

enum BrowserSchema {
    Chromium,
    Firefox,
    Unknown,
}

/// Decide the schema by probing for a signature table of each browser family.
fn detect_schema(conn: &rusqlite::Connection) -> BrowserSchema {
    let has = |t: &str| -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [t],
            |_| Ok(()),
        )
        .is_ok()
    };
    // Chromium history has `urls` + `visits`; Firefox has `moz_places`.
    if has("moz_places") {
        BrowserSchema::Firefox
    } else if has("urls") {
        BrowserSchema::Chromium
    } else {
        BrowserSchema::Unknown
    }
}

// ── Chromium ────────────────────────────────────────────────────────────────
fn parse_chromium(
    conn: &rusqlite::Connection,
    artefact: &IdentifiedArtefact,
    sink: &mut dyn EventSink,
    outcome: &mut ParseOutcome,
) {
    // Visits: join urls to visits for the actual visit time (more accurate than
    // urls.last_visit_time when present, but we use urls.last_visit_time to keep
    // the query simple and robust across Chromium versions).
    let visit_sql = "SELECT url, title, last_visit_time FROM urls WHERE url IS NOT NULL";
    match conn.prepare(visit_sql) {
        Ok(mut stmt) => {
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    r.get::<_, i64>(2)?,
                ))
            });
            if let Ok(rows) = rows {
                for row in rows.flatten() {
                    outcome.records_read += 1;
                    let (url, title, ts_raw) = row;
                    let ts = chromium_time(ts_raw);
                    emit_browser(
                        sink, artefact, outcome, "browser.visit", "visit", &url, &title, ts,
                    );
                }
            }
        }
        Err(e) => outcome.warnings.push(fx_core::RecordWarning {
            source_ref: Some("urls".into()),
            message: format!("chromium visits query failed: {e}"),
        }),
    }

    // Downloads: current_path/target_path + referrer + start_time. The `tab_url`
    // / referrer helps attribute where a payload came from.
    let dl_sql = "SELECT COALESCE(target_path, current_path, ''), \
                  COALESCE(tab_url, referrer, ''), start_time \
                  FROM downloads";
    if let Ok(mut stmt) = conn.prepare(dl_sql) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        }) {
            for row in rows.flatten() {
                outcome.records_read += 1;
                let (file_path, source_url, ts_raw) = row;
                let ts = chromium_time(ts_raw);
                // For a download the "domain" the rules care about is the source
                // URL's host; the saved file path is the target.
                emit_browser(
                    sink, artefact, outcome, "browser.download", "download",
                    &source_url, &file_path, ts,
                );
            }
        }
    }
}

/// Chromium time: microseconds since 1601-01-01 UTC. 0 => unknown.
fn chromium_time(us_since_1601: i64) -> OffsetDateTime {
    if us_since_1601 <= 0 {
        return OffsetDateTime::UNIX_EPOCH;
    }
    // Convert to 100ns since 1601 then reuse the shared FILETIME helper.
    let filetime_100ns = (us_since_1601 as u64).saturating_mul(10);
    fx_core::filetime_to_datetime(filetime_100ns).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

// ── Firefox ─────────────────────────────────────────────────────────────────
fn parse_firefox(
    conn: &rusqlite::Connection,
    artefact: &IdentifiedArtefact,
    sink: &mut dyn EventSink,
    outcome: &mut ParseOutcome,
) {
    // Visits: moz_places holds urls + last_visit_date (microseconds since 1970).
    let visit_sql = "SELECT url, COALESCE(title,''), last_visit_date \
                     FROM moz_places WHERE url IS NOT NULL";
    match conn.prepare(visit_sql) {
        Ok(mut stmt) => {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                ))
            }) {
                for row in rows.flatten() {
                    outcome.records_read += 1;
                    let (url, title, ts_raw) = row;
                    let ts = firefox_time(ts_raw);
                    emit_browser(
                        sink, artefact, outcome, "browser.visit", "visit", &url, &title, ts,
                    );
                }
            }
        }
        Err(e) => outcome.warnings.push(fx_core::RecordWarning {
            source_ref: Some("moz_places".into()),
            message: format!("firefox visits query failed: {e}"),
        }),
    }

    // Downloads live in moz_annos (anno_attribute 'downloads/destinationFileURI')
    // in modern Firefox, joined to moz_places for the source URL. Schema varies
    // across versions; failure here is non-fatal (visits already captured).
    let dl_sql = "SELECT p.url, a.content, p.last_visit_date \
                  FROM moz_annos a JOIN moz_places p ON p.id = a.place_id \
                  JOIN moz_anno_attributes t ON t.id = a.anno_attribute_id \
                  WHERE t.name = 'downloads/destinationFileURI'";
    if let Ok(mut stmt) = conn.prepare(dl_sql) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<i64>>(2)?.unwrap_or(0),
            ))
        }) {
            for row in rows.flatten() {
                outcome.records_read += 1;
                let (source_url, file_uri, ts_raw) = row;
                let ts = firefox_time(ts_raw);
                emit_browser(
                    sink, artefact, outcome, "browser.download", "download",
                    &source_url, &file_uri, ts,
                );
            }
        }
    }
}

/// Firefox time: microseconds since 1970-01-01 UTC. 0 => unknown.
fn firefox_time(us_since_1970: i64) -> OffsetDateTime {
    if us_since_1970 <= 0 {
        return OffsetDateTime::UNIX_EPOCH;
    }
    OffsetDateTime::from_unix_timestamp_nanos((us_since_1970 as i128) * 1000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

// ── shared emit ─────────────────────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
fn emit_browser(
    sink: &mut dyn EventSink,
    artefact: &IdentifiedArtefact,
    outcome: &mut ParseOutcome,
    action: &str,
    event_kind: &str,
    url: &str,
    secondary: &str, // page title for visits; saved file path for downloads
    ts: OffsetDateTime,
) {
    let domain = url_host(url);
    let message = match event_kind {
        "download" => format!("Download from {domain} -> {secondary}"),
        _ => {
            if secondary.is_empty() {
                format!("Visited {url}")
            } else {
                format!("Visited {domain} — {secondary}")
            }
        }
    };

    sink.emit(Event {
        id: Uuid::new_v4(),
        timestamp: ts,
        timestamp_kind: TimestampKind::Accessed,
        artefact: ArtefactKind::BrowserHistory,
        action: action.to_string(),
        host: None,
        user: Default::default(),
        process: None,
        // Domain on target.path so it shows on the timeline and in FTS.
        target: Some(Target {
            path: Some(domain.clone()),
            ..Default::default()
        }),
        network: None,
        message,
        provenance: Provenance {
            evidence_id: artefact.evidence_id,
            source_path: artefact.source_path.clone(),
            parser: "browser_history".into(),
            parser_version: env!("CARGO_PKG_VERSION").into(),
            source_ref: Some(url.chars().take(200).collect()),
        },
        // The fields imported IOC rules key on live under `extras.*`.
        raw: json!({
            "url": url,
            "extras": {
                "browser_event": event_kind,
                "domain": domain,
            },
            "detail": secondary,
        }),
    });
    outcome.events_emitted += 1;
}

/// Extract the host from a URL without a URL-parsing dependency: take the
/// authority between `scheme://` and the next `/`, strip any userinfo and port.
/// Good enough for domain-matching IOC rules; not a full RFC 3986 parser.
fn url_host(url: &str) -> String {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // strip userinfo@
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    // strip :port (but keep IPv6 brackets intact — rare in this context)
    let host = host_port.split(':').next().unwrap_or(host_port);
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host() {
        assert_eq!(url_host("https://cdn.discordapp.com/attachments/x/y.exe"), "cdn.discordapp.com");
        assert_eq!(url_host("http://user:pass@mega.nz:443/file"), "mega.nz");
        assert_eq!(url_host("https://console.aws.amazon.com/"), "console.aws.amazon.com");
        assert_eq!(url_host("notaurl"), "notaurl");
    }

    #[test]
    fn chromium_epoch_differs_from_firefox() {
        // Same instant, different raw encodings must produce ~same datetime.
        // 2024-01-01T00:00:00Z:
        //   firefox us since 1970 = 1704067200_000000
        //   chromium us since 1601 = firefox + 11644473600_000000
        let ff = firefox_time(1_704_067_200_000_000);
        let cr = chromium_time(1_704_067_200_000_000 + 11_644_473_600_000_000);
        assert_eq!(ff.year(), 2024);
        assert_eq!(cr.year(), 2024);
        assert_eq!(ff.unix_timestamp(), cr.unix_timestamp());
    }
}
