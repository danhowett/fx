//! Tauri command layer — the bridge between the web frontend and the Rust
//! forensic core (`fx-store`, `fx-ingest`, `fx-parsers`).
//!
//! Design: the frontend never speaks SQL or touches artefacts. It calls a small
//! set of typed commands that return plain serializable DTOs. All heavy work
//! (ingest, queries) happens here in Rust, off the UI thread. The open case is
//! held in Tauri-managed state behind a mutex.
//!
//! These DTOs ARE the contract the frontend's TypeScript types mirror
//! (`ui/src/contract.ts`). Keep them in sync.

use fx_ingest::ingest_into_store;
use fx_parsers::ParserRegistry;
use fx_store::query::{TimelineFilter, TimelineRow};
use fx_store::{CaseStore, SrumNetTotal};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use time::OffsetDateTime;

/// Managed application state: the currently open case, if any.
#[derive(Default)]
pub struct AppState {
    pub store: Mutex<Option<CaseStore>>,
}

/// A timeline row as the frontend consumes it. Flat, all strings where the UI
/// just displays, so rendering never has to reformat.
#[derive(Debug, Clone, Serialize)]
pub struct EventDto {
    pub id: String,
    pub ts: String,
    pub ts_kind: String,
    pub artefact: String,
    /// Coarse category derived from artefact/action, drives row colour.
    pub category: String,
    pub action: String,
    pub host: Option<String>,
    pub user: Option<String>,
    pub target: Option<String>,
    pub message: String,
    /// True when the event carries a suspicion / anti-forensic marker.
    pub flagged: bool,
    /// Provenance locator (parser/source ref) so identical-looking events are
    /// distinguishable in the detail pane.
    pub source_ref: Option<String>,
}

impl From<TimelineRow> for EventDto {
    fn from(r: TimelineRow) -> Self {
        let category = categorize(&r.artefact, &r.action);
        let flagged = r.action.contains("suspicious")
            || r.action.contains("anti_forensic")
            || r.message.contains("[ANTI-FORENSIC]")
            || r.message.contains("MASQUERADE")
            || r.message.contains("STAGING");
        EventDto {
            id: r.id,
            ts: r.ts,
            ts_kind: r.ts_kind,
            category,
            artefact: r.artefact,
            action: r.action,
            host: r.host,
            user: r.user_name,
            target: r.target_path,
            message: r.message,
            flagged,
            source_ref: r.source_ref,
        }
    }
}

/// Map an artefact + action to one of a small set of analyst-facing categories.
/// Categories (not raw artefact names) drive the timeline's colour language, so
/// an analyst reads "what kind of activity" at a glance.
fn categorize(artefact: &str, action: &str) -> String {
    if action.starts_with("logon") {
        return "logon".into();
    }
    if action.starts_with("network")
        || action.starts_with("browser")
        || action.contains("rdp")
        || artefact == "BrowserHistory"
    {
        return "network".into();
    }
    if action.starts_with("persistence") || action.starts_with("service") {
        return "persistence".into();
    }
    if action.starts_with("execution") || artefact == "Prefetch" || artefact == "UserAssist" {
        return "execution".into();
    }
    if action.starts_with("file") || artefact == "Mft" || artefact == "UsnJrnl" {
        return "filesystem".into();
    }
    "other".into()
}

/// Filters the frontend can set. Mirrors `contract.ts` `FilterInput`.
#[derive(Debug, Default, Deserialize)]
pub struct FilterInput {
    pub after: Option<String>,  // RFC3339
    pub before: Option<String>, // RFC3339
    pub artefact: Option<String>,
    pub category: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub text: Option<String>,
    pub flagged_only: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Dashboard facets shown in the left rail so the analyst sees the shape of the
/// case before filtering.
#[derive(Debug, Serialize)]
pub struct CaseOverview {
    pub case_id: String,
    pub total_events: u64,
    pub by_artefact: Vec<CountRow>,
    pub ingest: Vec<CountRow>,
    pub srum_top_talkers: Vec<SrumRow>,
}

#[derive(Debug, Serialize)]
pub struct CountRow {
    pub label: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct SrumRow {
    pub app: String,
    pub user: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// A detection as the frontend consumes it.
#[derive(Debug, Serialize)]
pub struct DetectionDto {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub attack: Vec<String>,
    pub summary: String,
    pub event_ids: Vec<String>,
    pub ts: String,
    pub host: Option<String>,
    pub engine: String,
}

/// An event's triage state as the frontend consumes it.
#[derive(Debug, Serialize)]
pub struct TriageDto {
    pub event_id: String,
    pub triage_state: String,
    pub note: Option<String>,
    pub ts: Option<String>,
    pub host: Option<String>,
    pub message: Option<String>,
}

impl From<SrumNetTotal> for SrumRow {
    fn from(t: SrumNetTotal) -> Self {
        SrumRow {
            app: t.app,
            user: t.user,
            bytes_sent: t.bytes_sent,
            bytes_recv: t.bytes_recv,
        }
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

/// Open an existing case file. Replaces any currently open case.
#[tauri::command]
pub fn open_case(state: tauri::State<AppState>, path: String) -> Result<CaseOverview, String> {
    let store = CaseStore::open(&PathBuf::from(path)).map_err(|e| e.to_string())?;
    let overview = build_overview(&store).map_err(|e| e.to_string())?;
    *state.store.lock().unwrap() = Some(store);
    Ok(overview)
}

/// Create a new case and ingest a collection directory into it, then open it.
/// Long-running: the frontend shows progress via the returned summary counts.
#[tauri::command]
pub fn ingest_collection(
    state: tauri::State<AppState>,
    collection_dir: String,
    case_path: String,
    case_name: String,
    examiner: Option<String>,
) -> Result<CaseOverview, String> {
    let case_path = PathBuf::from(case_path);
    if case_path.exists() {
        return Err(format!("case file already exists: {}", case_path.display()));
    }
    let mut store = CaseStore::create(&case_path, &case_name, examiner.as_deref(), "UTC")
        .map_err(|e| e.to_string())?;
    let registry = ParserRegistry::with_defaults();
    let _report = ingest_into_store(&PathBuf::from(collection_dir), &registry, &mut store);
    let overview = build_overview(&store).map_err(|e| e.to_string())?;
    *state.store.lock().unwrap() = Some(store);
    Ok(overview)
}

/// Query the timeline with a filter. This is the frontend's workhorse.
#[tauri::command]
pub fn query_timeline(
    state: tauri::State<AppState>,
    filter: FilterInput,
) -> Result<Vec<EventDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;

    let tf = TimelineFilter {
        after: filter.after.as_deref().and_then(parse_rfc3339),
        before: filter.before.as_deref().and_then(parse_rfc3339),
        artefact: filter.artefact,
        action_prefix: None,
        host: filter.host,
        user: filter.user,
        text: filter.text,
        // Category and flagged-only are now applied in SQL (whole-case), so a
        // page is a true slice and paging via limit/offset is correct.
        category: filter.category,
        flagged_only: filter.flagged_only.unwrap_or(false),
        limit: filter.limit.unwrap_or(1000),
        offset: filter.offset.unwrap_or(0),
    };

    let rows = store.timeline(&tf).map_err(|e| e.to_string())?;
    let out: Vec<EventDto> = rows.into_iter().map(EventDto::from).collect();
    Ok(out)
}

/// Count all events matching a filter (ignoring paging) — for the "N of M"
/// indicator and Next/Prev paging. Runs over the whole case in SQL.
#[tauri::command]
pub fn count_timeline(
    state: tauri::State<AppState>,
    filter: FilterInput,
) -> Result<u64, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let tf = TimelineFilter {
        after: filter.after.as_deref().and_then(parse_rfc3339),
        before: filter.before.as_deref().and_then(parse_rfc3339),
        artefact: filter.artefact,
        action_prefix: None,
        host: filter.host,
        user: filter.user,
        text: filter.text,
        category: filter.category,
        flagged_only: filter.flagged_only.unwrap_or(false),
        limit: 0,
        offset: 0,
    };
    store.count_timeline(&tf).map_err(|e| e.to_string())
}

/// Fetch the full raw JSON for one event (right-pane detail).
#[tauri::command]
pub fn event_raw(state: tauri::State<AppState>, event_id: String) -> Result<Option<String>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.raw_json(&event_id).map_err(|e| e.to_string())
}

/// Run the hunt engine over the open case and return the resulting detections
/// (worst-first). Rules are loaded from `rules_dir` (defaults to the shipped
/// pack next to the binary).
#[tauri::command]
pub fn run_hunt(
    state: tauri::State<AppState>,
    rules_dir: Option<String>,
) -> Result<Vec<DetectionDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    // Use the rules compiled into the binary by default (works regardless of
    // where the app is run from). Only load from disk if an explicit dir is
    // passed — which lets power users point at a custom/imported rule folder.
    let rules = match rules_dir {
        Some(dir) if !dir.is_empty() => fx_hunt::RuleSet::load_dir(std::path::Path::new(&dir)),
        _ => fx_hunt::RuleSet::from_embedded(),
    };
    let _ = fx_hunt::run(store, &rules);
    // Auto-triage: every event a finding points at starts as "unconfirmed",
    // unless the analyst has already set a state for it. This gives a worklist
    // to promote/dismiss through.
    if let Ok(dets) = store.detections() {
        for d in &dets {
            for eid in d.event_ids.split(',').filter(|s| !s.trim().is_empty()) {
                let _ = store.set_triage_if_absent(eid.trim(), "unconfirmed", None);
            }
        }
    }
    read_detections(store)
}

/// The per-file ingest log for the current case.
#[derive(Debug, Serialize)]
pub struct IngestLogDto {
    pub source_path: String,
    pub artefact_kind: String,
    pub status: String,
    pub detail: Option<String>,
    pub records_read: u64,
    pub events_emitted: u64,
    pub warning_count: u32,
}

#[tauri::command]
pub fn ingest_log(state: tauri::State<AppState>) -> Result<Vec<IngestLogDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let rows = store.ingest_log().map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| IngestLogDto {
            source_path: r.source_path,
            artefact_kind: r.artefact_kind,
            status: r.status,
            detail: r.detail,
            records_read: r.records_read,
            events_emitted: r.events_emitted,
            warning_count: r.warning_count,
        })
        .collect())
}

/// One day's bar for the activity graph.
#[derive(Debug, Serialize)]
pub struct DailyActivityDto {
    pub day: String,
    pub total: u64,
    pub flagged: u64,
}

/// Per-day event counts (total + flagged) for the activity graph. Lets the
/// analyst see the shape of the whole case at a glance and spot volume spikes
/// that no rule tagged.
#[tauri::command]
pub fn daily_activity(state: tauri::State<AppState>) -> Result<Vec<DailyActivityDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let rows = store.daily_activity().map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| DailyActivityDto {
            day: r.day,
            total: r.total,
            flagged: r.flagged,
        })
        .collect())
}

/// Set an event's triage state (unconfirmed / validated / false_positive /
/// dismissed), with an optional note.
#[tauri::command]
pub fn set_triage(
    state: tauri::State<AppState>,
    event_id: String,
    triage_state: String,
    note: Option<String>,
) -> Result<(), String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.set_triage(&event_id, &triage_state, note.as_deref()).map_err(|e| e.to_string())
}

/// Clear an event's triage state.
#[tauri::command]
pub fn clear_triage(state: tauri::State<AppState>, event_id: String) -> Result<(), String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.clear_triage(&event_id).map_err(|e| e.to_string())
}

/// All triage tags: [{event_id, state, note}], for badges and filtering.
#[tauri::command]
pub fn list_triage(state: tauri::State<AppState>) -> Result<Vec<TriageDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    // Full detail (ts/host/message) so the findings view can render manual
    // findings and filters can use them — not just id/state/note.
    let rows = store.triaged_events().map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|t| TriageDto {
            event_id: t.event_id,
            triage_state: t.state,
            note: t.note,
            ts: Some(t.ts),
            host: t.host,
            message: Some(t.message),
        })
        .collect())
}

/// Read already-computed detections (without re-running).
#[tauri::command]
pub fn hunt_results(state: tauri::State<AppState>) -> Result<Vec<DetectionDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    read_detections(store)
}

/// Export findings to a file. `format` is "csv" or "stix"; `path` is the
/// destination chosen in the GUI save dialog. Returns the number of findings
/// written.
#[tauri::command]
pub fn export_findings(
    state: tauri::State<AppState>,
    format: String,
    path: String,
) -> Result<usize, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let mut dets = read_detections(store)?;
    let triage = store.triage_map().map_err(|e| e.to_string())?;
    let tri_for = |event_ids: &[String]| -> (String, String) {
        for eid in event_ids {
            if let Some((_, st, note)) = triage.iter().find(|(id, _, _)| id == eid) {
                return (st.clone(), note.clone().unwrap_or_default());
            }
        }
        (String::new(), String::new())
    };

    // Merge in analyst-validated events that NO rule fired on, so manual
    // findings land in the export too. Any event already referenced by a rule
    // detection is skipped (it's covered, and carries its triage state already).
    let covered: std::collections::HashSet<&String> =
        dets.iter().flat_map(|d| d.event_ids.iter()).collect();
    let triaged = store.triaged_events().map_err(|e| e.to_string())?;
    let mut manual: Vec<DetectionDto> = triaged
        .into_iter()
        .filter(|t| !covered.contains(&t.event_id))
        .map(|t| DetectionDto {
            rule_id: "manual-triage".into(),
            title: format!("Analyst finding: {}", first_line(&t.message, 80)),
            severity: match t.state.as_str() {
                "validated" => "high",
                "false_positive" | "dismissed" => "info",
                _ => "medium",
            }
            .into(),
            attack: Vec::new(),
            summary: t.message.clone(),
            event_ids: vec![t.event_id.clone()],
            ts: t.ts,
            host: t.host,
            engine: "manual".into(),
        })
        .collect();
    dets.append(&mut manual);

    let content = match format.as_str() {
        "csv" => findings_to_csv(&dets, &tri_for),
        "stix" => findings_to_stix(&dets, &tri_for)?,
        other => return Err(format!("unknown export format: {other}")),
    };
    std::fs::write(&path, content).map_err(|e| format!("write {path}: {e}"))?;
    Ok(dets.len())
}

/// First line of a message, truncated to `max` chars, for a manual finding's
/// title.
fn first_line(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or("").trim();
    if line.chars().count() > max {
        let t: String = line.chars().take(max).collect();
        format!("{t}…")
    } else {
        line.to_string()
    }
}

/// RFC 4180 CSV. One row per finding, with triage state/note columns.
fn findings_to_csv(
    dets: &[DetectionDto],
    tri_for: &dyn Fn(&[String]) -> (String, String),
) -> String {
    fn esc(s: &str) -> String {
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let mut out = String::from(
        "rule_id,title,severity,attack,engine,timestamp_utc,host,triage_state,triage_note,event_ids\n",
    );
    for d in dets {
        let (st, note) = tri_for(&d.event_ids);
        let cols = [
            d.rule_id.clone(),
            d.title.clone(),
            d.severity.clone(),
            d.attack.join(" "),
            d.engine.clone(),
            d.ts.clone(),
            d.host.clone().unwrap_or_default(),
            st,
            note,
            d.event_ids.join(" "),
        ];
        out.push_str(&cols.iter().map(|c| esc(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// STIX 2.1 bundle. Each finding becomes an `indicator`, linked to
/// `attack-pattern` objects for its ATT&CK techniques via `relationship`s.
/// Deterministic UUIDv5 ids keep re-exports stable. Hand-built JSON (no extra
/// deps) — the structure is small and fixed.
fn findings_to_stix(
    dets: &[DetectionDto],
    tri_for: &dyn Fn(&[String]) -> (String, String),
) -> Result<String, String> {
    use std::collections::BTreeMap;
    // Stable namespace for deterministic ids.
    let ns = uuid::Uuid::NAMESPACE_URL;
    let id5 = |kind: &str, seed: &str| -> String {
        format!("{kind}--{}", uuid::Uuid::new_v5(&ns, format!("fx:{kind}:{seed}").as_bytes()))
    };
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let jesc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\t', "\\t");
    let sev_label = |s: &str| match s {
        "critical" => "high",
        "high" => "high",
        "medium" => "medium",
        _ => "low",
    };

    let mut objects: Vec<String> = Vec::new();
    // Dedup attack-pattern objects by technique id.
    let mut patterns: BTreeMap<String, String> = BTreeMap::new();

    for d in dets {
        let (st, note) = tri_for(&d.event_ids);
        let ind_id = id5("indicator", &d.rule_id);
        let ts = normalize_stix_ts(&d.ts, &now);
        let mut desc = d.summary.clone();
        if !st.is_empty() {
            desc.push_str(&format!("  [triage: {st}]"));
        }
        if !note.is_empty() {
            desc.push_str(&format!("  note: {note}"));
        }
        let labels = {
            let mut l = vec![format!("\"{}\"", sev_label(&d.severity))];
            l.push("\"malicious-activity\"".into());
            if !st.is_empty() {
                l.push(format!("\"triage-{}\"", st.replace('_', "-")));
            }
            l.join(", ")
        };
        objects.push(format!(
            "{{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"{id}\",\"created\":\"{now}\",\"modified\":\"{now}\",\"name\":\"{name}\",\"description\":\"{desc}\",\"indicator_types\":[\"malicious-activity\"],\"pattern_type\":\"stix\",\"pattern\":\"[x-fx:rule_id = '{rule}']\",\"valid_from\":\"{vf}\",\"labels\":[{labels}]}}",
            id = ind_id,
            now = now,
            name = jesc(&d.title),
            desc = jesc(&desc),
            rule = jesc(&d.rule_id),
            vf = ts,
            labels = labels,
        ));

        for tech in &d.attack {
            let ap_id = patterns.entry(tech.clone()).or_insert_with(|| {
                let ap_id = id5("attack-pattern", tech);
                objects.push(format!(
                    "{{\"type\":\"attack-pattern\",\"spec_version\":\"2.1\",\"id\":\"{id}\",\"created\":\"{now}\",\"modified\":\"{now}\",\"name\":\"{tech}\",\"external_references\":[{{\"source_name\":\"mitre-attack\",\"external_id\":\"{tech}\"}}]}}",
                    id = ap_id, now = now, tech = jesc(tech)
                ));
                ap_id
            });
            let rel_id = id5("relationship", &format!("{}:{}", d.rule_id, tech));
            objects.push(format!(
                "{{\"type\":\"relationship\",\"spec_version\":\"2.1\",\"id\":\"{id}\",\"created\":\"{now}\",\"modified\":\"{now}\",\"relationship_type\":\"indicates\",\"source_ref\":\"{src}\",\"target_ref\":\"{tgt}\"}}",
                id = rel_id, now = now, src = ind_id, tgt = ap_id
            ));
        }
    }

    let bundle_id = format!("bundle--{}", uuid::Uuid::new_v4());
    Ok(format!(
        "{{\"type\":\"bundle\",\"id\":\"{bundle_id}\",\"objects\":[{}]}}",
        objects.join(",")
    ))
}

/// STIX timestamps must be RFC3339 with a Z. Our stored ts is "YYYY-MM-DDTHH:MM:SS"
/// (no zone); append Z. Fall back to `now` if unparseable.
fn normalize_stix_ts(ts: &str, now: &str) -> String {
    let t = ts.trim();
    if t.is_empty() {
        return now.to_string();
    }
    let t = t.replace(' ', "T");
    if t.ends_with('Z') || t.contains('+') {
        t
    } else {
        format!("{t}Z")
    }
}

fn read_detections(store: &CaseStore) -> Result<Vec<DetectionDto>, String> {
    let rows = store.detections().map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|d| DetectionDto {
            rule_id: d.rule_id,
            title: d.title,
            severity: d.severity,
            attack: d.attack.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            summary: d.summary,
            event_ids: d.event_ids.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            ts: d.ts,
            host: d.host,
            engine: d.engine,
        })
        .collect())
}

fn build_overview(store: &CaseStore) -> Result<CaseOverview, fx_store::StoreError> {
    Ok(CaseOverview {
        case_id: store.case_id().to_string(),
        total_events: store.event_count()?,
        by_artefact: store
            .counts_by_artefact()?
            .into_iter()
            .map(|(label, count)| CountRow { label, count })
            .collect(),
        ingest: store
            .ingest_summary()?
            .into_iter()
            .map(|(label, count)| CountRow { label, count })
            .collect(),
        srum_top_talkers: store
            .srum_network_totals(8)?
            .into_iter()
            .map(SrumRow::from)
            .collect(),
    })
}

fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}
