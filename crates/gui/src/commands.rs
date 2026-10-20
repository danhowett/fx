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
        || action.starts_with("remote_access")
        || artefact == "BrowserHistory"
        || artefact == "RemoteAccess"
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
pub async fn open_case(state: tauri::State<'_, AppState>, path: String) -> Result<CaseOverview, String> {
    let store = CaseStore::open(&PathBuf::from(path)).map_err(|e| e.to_string())?;
    let overview = build_overview(&store).map_err(|e| e.to_string())?;
    *state.store.lock().unwrap() = Some(store);
    Ok(overview)
}

/// Create a new case and ingest a collection directory into it, then open it.
/// Long-running. `async` so Tauri runs it on a worker thread, not the window's
/// main thread — a synchronous command here froze the window ("Not Responding")
/// for the whole ingest even though work was progressing.

/// Run `f` while a ticker thread forwards progress snapshots to the frontend
/// as `fx-progress` events (about 4 per second), plus one final snapshot.
fn with_progress<T>(app: &tauri::AppHandle, f: impl FnOnce() -> T) -> T {
    use tauri::Emitter;
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ticker = {
        let done = done.clone();
        let app = app.clone();
        std::thread::spawn(move || {
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = app.emit("fx-progress", fx_core::progress::snapshot());
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        })
    };
    let out = f();
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = ticker.join();
    let _ = app.emit("fx-progress", fx_core::progress::snapshot());
    out
}

/// Ask the running ingest / detection job to stop at its next safe point.
/// Work already done is kept.
#[tauri::command]
pub async fn cancel_job() -> Result<(), String> {
    fx_core::progress::request_cancel();
    Ok(())
}

/// Latest progress counters (the frontend reads `cancelled` after a job).
#[tauri::command]
pub async fn progress_snapshot() -> Result<fx_core::progress::Snapshot, String> {
    Ok(fx_core::progress::snapshot())
}

#[tauri::command]
pub async fn ingest_collection(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
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
    fx_core::progress::reset();
    let _report = with_progress(&app, || ingest_into_store(&PathBuf::from(collection_dir), &registry, &mut store));
    fx_core::progress::set_phase("Opening case");
    let overview = build_overview(&store).map_err(|e| e.to_string())?;
    *state.store.lock().unwrap() = Some(store);
    Ok(overview)
}

/// Query the timeline with a filter. This is the frontend's workhorse.
#[tauri::command]
pub async fn query_timeline(
    state: tauri::State<'_, AppState>,
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
pub async fn count_timeline(
    state: tauri::State<'_, AppState>,
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
pub async fn event_raw(state: tauri::State<'_, AppState>, event_id: String) -> Result<Option<String>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.raw_json(&event_id).map_err(|e| e.to_string())
}

/// Run the hunt engine over the open case and return the resulting detections
/// (worst-first). Rules are loaded from `rules_dir` (defaults to the shipped
/// pack next to the binary).
#[tauri::command]
pub async fn run_hunt(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
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
    fx_core::progress::reset();
    fx_core::progress::set_phase("Running detections");
    let _ = with_progress(&app, || {
        let r = fx_hunt::run(store, &rules);
        // Auto-triage (every event a finding points at starts as
        // "unconfirmed") and the allow-list, in bulk SQL.
        fx_core::progress::set_phase("Marking findings for review");
        reapply_allowlist(store);
        r
    });
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
pub async fn ingest_log(state: tauri::State<'_, AppState>) -> Result<Vec<IngestLogDto>, String> {
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
pub async fn daily_activity(state: tauri::State<'_, AppState>) -> Result<Vec<DailyActivityDto>, String> {
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
pub async fn set_triage(
    state: tauri::State<'_, AppState>,
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
pub async fn clear_triage(state: tauri::State<'_, AppState>, event_id: String) -> Result<(), String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.clear_triage(&event_id).map_err(|e| e.to_string())
}

/// All triage tags: [{event_id, state, note}], for badges and filtering.
#[tauri::command]
pub async fn list_triage(state: tauri::State<'_, AppState>) -> Result<Vec<TriageDto>, String> {
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
pub async fn hunt_results(state: tauri::State<'_, AppState>) -> Result<Vec<DetectionDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    read_detections(store)
}

/// Export findings to a file. `format` is "csv" or "stix"; `path` is the
/// destination chosen in the GUI save dialog. Returns the number of findings
/// written.
#[tauri::command]
pub async fn export_findings(
    state: tauri::State<'_, AppState>,
    format: String,
    path: String,
    // Triage states to include ("validated", "unconfirmed", "false_positive",
    // "dismissed"). None / empty = everything (the old behaviour). A finding
    // nobody has triaged counts as "unconfirmed", matching what the UI shows.
    states: Option<Vec<String>>,
) -> Result<usize, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let (dets, triage) = collect_findings(store)?;
    let tri_for = |event_ids: &[String]| -> (String, String) {
        for eid in event_ids {
            if let Some((st, note)) = triage.get(eid) {
                return (st.clone(), note.clone());
            }
        }
        (String::new(), String::new())
    };
    let wanted: Option<std::collections::HashSet<String>> =
        states.filter(|v| !v.is_empty()).map(|v| v.into_iter().collect());
    let dets: Vec<DetectionDto> = match &wanted {
        None => dets,
        Some(w) => dets
            .into_iter()
            .filter(|d| w.contains(&effective_state(&tri_for(&d.event_ids).0)))
            .collect(),
    };
    if dets.is_empty() {
        return Err("No findings match the selected triage states.".into());
    }

    let content = match format.as_str() {
        "csv" => findings_to_csv(&dets, &tri_for),
        "stix" => findings_to_stix(&dets, &tri_for)?,
        other => return Err(format!("unknown export format: {other}")),
    };
    std::fs::write(&path, content).map_err(|e| format!("write {path}: {e}"))?;
    Ok(dets.len())
}

/// Per-triage-state finding counts for the export dialog, computed with exactly
/// the same logic as `export_findings` so the numbers shown match the file.
#[derive(serde::Serialize, Default)]
pub struct ExportCounts {
    pub validated: usize,
    pub unconfirmed: usize,
    pub false_positive: usize,
    pub dismissed: usize,
}

#[tauri::command]
pub async fn export_counts(state: tauri::State<'_, AppState>) -> Result<ExportCounts, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let (dets, triage) = collect_findings(store)?;
    let mut c = ExportCounts::default();
    for d in &dets {
        let st = d
            .event_ids
            .iter()
            .find_map(|e| triage.get(e).map(|(s, _)| s.clone()))
            .unwrap_or_default();
        match effective_state(&st).as_str() {
            "validated" => c.validated += 1,
            "false_positive" => c.false_positive += 1,
            "dismissed" => c.dismissed += 1,
            _ => c.unconfirmed += 1,
        }
    }
    Ok(c)
}

/// A finding with no triage tag is shown (and exported) as unconfirmed.
fn effective_state(s: &str) -> String {
    if s.is_empty() { "unconfirmed".into() } else { s.to_string() }
}

/// Rule detections plus analyst-validated events no rule fired on, and an
/// event_id -> (state, note) triage lookup. Shared by export + export_counts.
fn collect_findings(
    store: &CaseStore,
) -> Result<
    (Vec<DetectionDto>, std::collections::HashMap<String, (String, String)>),
    String,
> {
    let mut dets = read_detections(store)?;
    let triage: std::collections::HashMap<String, (String, String)> = store
        .triage_map()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(id, st, note)| (id, (st, note.unwrap_or_default())))
        .collect();

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
    Ok((dets, triage))
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

/// Write the self-contained HTML case report (findings by tactic, ATT&CK
/// matrix, timeline, and the evidence chain-of-custody table with SHA-256s) —
/// the same report as `fx report`. Returns the number of bytes written.
#[tauri::command]
pub async fn export_report(state: tauri::State<'_, AppState>, path: String) -> Result<usize, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let html = fx_hunt::report::generate_report(store).map_err(|e| e.to_string())?;
    std::fs::write(&path, &html).map_err(|e| format!("write {path}: {e}"))?;
    Ok(html.len())
}

// ── IOC sweep ────────────────────────────────────────────────────────────────

/// Live preview of a pasted IOC list: how many indicators of each type were
/// recognised, and how many tokens were ignored. Mirrors exactly what
/// `ioc_sweep` will search for.
#[derive(Serialize)]
pub struct IocPreview {
    pub total: usize,
    pub by_kind: std::collections::BTreeMap<String, usize>,
    pub skipped: usize,
}

#[tauri::command]
pub async fn ioc_preview(text: String) -> Result<IocPreview, String> {
    let p = fx_hunt::ioc::parse_iocs(&text);
    let mut by_kind = std::collections::BTreeMap::new();
    for i in &p.iocs {
        *by_kind.entry(i.kind.label().to_string()).or_insert(0) += 1;
    }
    Ok(IocPreview { total: p.iocs.len(), by_kind, skipped: p.skipped.len() })
}

/// Sweep the open case for the IOC list. Post-processing — no re-ingest.
/// Replaces the case's previous IOC findings; rule detections are untouched.
#[tauri::command]
pub async fn ioc_sweep(
    state: tauri::State<'_, AppState>,
    text: String,
) -> Result<fx_hunt::ioc::SweepReport, String> {
    let parsed = fx_hunt::ioc::parse_iocs(&text);
    if parsed.iocs.is_empty() {
        return Err("No indicators recognised. Paste one per line: hashes, IPs, domains, URLs, file names, paths or text.".into());
    }
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let report = fx_hunt::ioc::sweep(store, &parsed).map_err(|e| e.to_string())?;
    reapply_allowlist(store);
    // Save the list and its results with the case, so the IOC hunt view shows
    // them again next time the case is opened. Best-effort: a failed save must
    // not lose the results the analyst is about to see.
    let _ = store.kv_set("ioc_hunt.list", &text);
    if let Ok(j) = serde_json::to_string(&report) {
        let _ = store.kv_set("ioc_hunt.results", &j);
    }
    Ok(report)
}

/// The IOC hunt list and last results saved with the open case (if any).
#[derive(serde::Serialize)]
pub struct IocSaved {
    pub text: String,
    pub results: Option<serde_json::Value>,
}

#[tauri::command]
pub async fn ioc_saved(state: tauri::State<'_, AppState>) -> Result<IocSaved, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let text = store.kv_get("ioc_hunt.list").map_err(|e| e.to_string())?.unwrap_or_default();
    let results = store
        .kv_get("ioc_hunt.results")
        .map_err(|e| e.to_string())?
        .and_then(|j| serde_json::from_str(&j).ok());
    Ok(IocSaved { text, results })
}

/// Save the IOC hunt list without running it (so edits aren't lost).
#[tauri::command]
pub async fn ioc_save_list(state: tauri::State<'_, AppState>, text: String) -> Result<(), String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.kv_set("ioc_hunt.list", &text).map_err(|e| e.to_string())
}

/// One analyst label on one event.
#[derive(serde::Serialize)]
pub struct LabelDto {
    pub event_id: String,
    pub tag: String,
}

#[tauri::command]
pub async fn list_labels(state: tauri::State<'_, AppState>) -> Result<Vec<LabelDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    Ok(store
        .labels()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(event_id, tag)| LabelDto { event_id, tag })
        .collect())
}

#[tauri::command]
pub async fn add_label(state: tauri::State<'_, AppState>, event_id: String, tag: String) -> Result<(), String> {
    let tag = tag.trim().to_string();
    if tag.is_empty() || tag.len() > 60 {
        return Err("Tags must be 1–60 characters.".into());
    }
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.add_label(&event_id, &tag).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_label(state: tauri::State<'_, AppState>, event_id: String, tag: String) -> Result<(), String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.remove_label(&event_id, &tag).map_err(|e| e.to_string())
}

/// Read an IOC list file (txt / csv / any text; UTF-8 or UTF-16) for the
/// sweep dialog. Capped at 20 MB.
#[tauri::command]
pub async fn read_ioc_file(path: String) -> Result<String, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("{path}: {e}"))?;
    if meta.len() > 20 * 1024 * 1024 {
        return Err("IOC file is larger than 20 MB.".into());
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let u: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let u: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    Ok(text)
}

/// Fetch specific events by id (time-ordered) — used to show every event an
/// IOC matched. Capped so a pathological list can't flood the UI.
#[tauri::command]
pub async fn events_by_ids(
    state: tauri::State<'_, AppState>,
    ids: Vec<String>,
) -> Result<Vec<EventDto>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let ids: Vec<String> = ids.into_iter().take(5000).collect();
    let rows = store.events_by_ids(&ids).map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(EventDto::from).collect())
}

// ── Sigma rules (post-processing, analyst-supplied folder) ──────────────────

/// Sigma folder + filter, as remembered by the GUI.
#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct SigmaConfig {
    pub folder: String,
    #[serde(default)]
    pub filter: fx_hunt::sigma::SigmaFilter,
}

/// Load a Sigma folder and report what would run (no hunt).
#[tauri::command]
pub async fn sigma_preview(config: SigmaConfig) -> Result<fx_hunt::sigma::SigmaLoad, String> {
    let folder = config.folder.clone();
    let filter = config.filter.clone();
    tauri::async_runtime::spawn_blocking(move || fx_hunt::sigma::load_dir(std::path::Path::new(&folder), &filter))
        .await
        .map_err(|e| e.to_string())
}

/// Run a Sigma folder against the open case. Replaces only previous Sigma
/// findings; the built-in rules' and IOC hunt's findings are untouched. The
/// config and results are saved with the case.
#[tauri::command]
pub async fn sigma_hunt(app: tauri::AppHandle, state: tauri::State<'_, AppState>, config: SigmaConfig) -> Result<fx_hunt::SigmaRunReport, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    fx_core::progress::reset();
    fx_core::progress::set_phase("Loading Sigma rules");
    let report = with_progress(&app, || -> Result<fx_hunt::SigmaRunReport, String> {
        let load = fx_hunt::sigma::load_dir(std::path::Path::new(&config.folder), &config.filter);
        if let Some(e) = &load.folder_error {
            return Err(e.clone());
        }
        if load.loaded == 0 {
            return Err(format!(
                "No Sigma rules could be loaded from that folder ({} files, {} filtered out by level/status, {} skipped). Check it's a Sigma rules folder, e.g. rules\\windows from a SigmaHQ release.",
                load.files_seen,
                load.filtered,
                load.skipped_by_reason.values().sum::<usize>()
            ));
        }
        fx_core::progress::set_phase(&format!("Running {} Sigma rules", load.loaded));
        let report = fx_hunt::run_sigma(store, &config.folder, &load);
        // Sigma findings start as "unconfirmed", like rule findings (bulk, with the allow-list).
        fx_core::progress::set_phase("Marking findings for review");
        reapply_allowlist(store);
        Ok(report)
    })?;
    if let Ok(j) = serde_json::to_string(&config) {
        let _ = store.kv_set("sigma.config", &j);
    }
    if let Ok(j) = serde_json::to_string(&report) {
        let _ = store.kv_set("sigma.results", &j);
    }
    Ok(report)
}

/// The Sigma config and last results saved with the open case (if any).
#[derive(serde::Serialize)]
pub struct SigmaSaved {
    pub config: Option<serde_json::Value>,
    pub results: Option<serde_json::Value>,
}

#[tauri::command]
pub async fn sigma_saved(state: tauri::State<'_, AppState>) -> Result<SigmaSaved, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let get = |k: &str| store.kv_get(k).ok().flatten().and_then(|j| serde_json::from_str(&j).ok());
    Ok(SigmaSaved { config: get("sigma.config"), results: get("sigma.results") })
}


// ── Allow-list (suppressed findings) ─────────────────────────────────────────

/// The case's allow-list (kv `allowlist`), re-applied after every hunt so a
/// re-run never resurrects findings the analyst has already ruled benign.
fn allow_entries(store: &CaseStore) -> Vec<fx_store::allowlist::AllowEntry> {
    store.kv_get("allowlist").ok().flatten().and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
}

fn reapply_allowlist(store: &CaseStore) {
    let entries = allow_entries(store);
    if let Err(e) = store.apply_allowlist(&entries) {
        eprintln!("apply allow-list: {e}");
    }
}

#[derive(serde::Serialize)]
pub struct AllowStatus {
    pub entries: Vec<fx_store::allowlist::AllowEntry>,
    pub counts: std::collections::BTreeMap<String, u64>,
    pub suppressed: Vec<fx_store::allowlist::SuppressedRow>,
}

fn allow_status(store: &CaseStore, counts: Vec<(String, u64)>) -> Result<AllowStatus, String> {
    Ok(AllowStatus {
        entries: allow_entries(store),
        counts: counts.into_iter().collect(),
        suppressed: store.suppressed().map_err(|e| e.to_string())?,
    })
}

#[tauri::command]
pub async fn allowlist_get(state: tauri::State<'_, AppState>) -> Result<AllowStatus, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
    for r in store.suppressed().map_err(|e| e.to_string())? {
        *counts.entry(r.allow_id).or_insert(0) += 1;
    }
    allow_status(store, counts.into_iter().collect())
}

/// Replace the case's allow-list and re-apply it (restores anything no longer listed).
#[tauri::command]
pub async fn allowlist_set(
    state: tauri::State<'_, AppState>,
    entries: Vec<fx_store::allowlist::AllowEntry>,
) -> Result<AllowStatus, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let j = serde_json::to_string(&entries).map_err(|e| e.to_string())?;
    store.kv_set("allowlist", &j).map_err(|e| e.to_string())?;
    let counts = store.apply_allowlist(&entries).map_err(|e| e.to_string())?;
    allow_status(store, counts)
}

/// Switch one Sigma rule off for this case: its findings go now, and the
/// saved run summary drops it. (The frontend keeps the machine-wide list of
/// disabled rules and sends it with every Sigma run.)
#[tauri::command]
pub async fn sigma_disable_rule(
    state: tauri::State<'_, AppState>,
    rule_id: String,
) -> Result<Option<serde_json::Value>, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    store.delete_rule_findings("sigma", &rule_id).map_err(|e| e.to_string())?;
    let mut results: Option<serde_json::Value> =
        store.kv_get("sigma.results").ok().flatten().and_then(|j| serde_json::from_str(&j).ok());
    if let Some(r) = results.as_mut() {
        let mut removed = 0u64;
        if let Some(hits) = r.get_mut("hits").and_then(|h| h.as_array_mut()) {
            hits.retain(|h| {
                let hit = h.get("rule_id").and_then(|v| v.as_str()) == Some(rule_id.as_str());
                if hit {
                    removed += h.get("findings").and_then(|v| v.as_u64()).unwrap_or(0);
                }
                !hit
            });
            let n = hits.len();
            r["rules_hit"] = serde_json::json!(n);
        }
        let f = r.get("findings").and_then(|v| v.as_u64()).unwrap_or(0);
        r["findings"] = serde_json::json!(f.saturating_sub(removed));
        let d = r.get("disabled").and_then(|v| v.as_u64()).unwrap_or(0);
        r["disabled"] = serde_json::json!(d + 1);
        let _ = store.kv_set("sigma.results", &r.to_string());
    }
    Ok(results)
}

// ── Host information ─────────────────────────────────────────────────────────

/// One fact with the event it came from (so the UI can open the source).
#[derive(serde::Serialize, Default, Clone)]
pub struct HostSourced<T: serde::Serialize> {
    pub value: T,
    pub event_id: String,
    pub source: String,
}

#[derive(serde::Serialize, Default)]
pub struct HostAccount {
    pub user: String,
    pub rid: Option<u64>,
    pub full_name: Option<String>,
    pub sid: Option<String>,
    pub profile_path: Option<String>,
    pub created: Option<String>,
    pub last_logon: Option<String>,
    pub password_last_set: Option<String>,
    pub logon_count: Option<u64>,
    pub disabled: Option<bool>,
    pub local: bool,
    pub event_id: String,
}

#[derive(serde::Serialize, Default)]
pub struct HostInfoDto {
    pub computer_name: Option<HostSourced<String>>,
    pub domain: Option<HostSourced<String>>,
    pub os: Option<HostSourced<serde_json::Value>>,
    pub timezone: Option<HostSourced<serde_json::Value>>,
    pub last_shutdown: Option<HostSourced<String>>,
    pub interfaces: Vec<HostSourced<serde_json::Value>>,
    pub accounts: Vec<HostAccount>,
    pub collection_tool: Option<String>,
    pub asserted_host: Option<String>,
    pub evidence_files: u64,
    pub evidence_bytes: u64,
    /// Other computer names seen (multi-host collections).
    pub other_names: Vec<String>,
}

/// Aggregate the case's host facts for the Host panel.
#[tauri::command]
pub async fn host_info(state: tauri::State<'_, AppState>) -> Result<HostInfoDto, String> {
    let guard = state.store.lock().unwrap();
    let store = guard.as_ref().ok_or("no case open")?;
    let facts = store.host_facts().map_err(|e| e.to_string())?;
    let mut out = HostInfoDto::default();
    if let Ok((tool, host, _tz, n, bytes)) = store.collection_summary() {
        out.collection_tool = tool;
        out.asserted_host = host;
        out.evidence_files = n;
        out.evidence_bytes = bytes;
    }
    let parsed: Vec<(String, String, serde_json::Value, String)> = facts
        .into_iter()
        .map(|(id, action, raw, src)| (id, action, serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null), src))
        .collect();
    let s = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    // Which control set is current (SYSTEM\Select); facts from the others are
    // older copies and are only used if the current one lacks them.
    let current_cs = parsed.iter().find(|(_, a, _, _)| a == "host.controlset").and_then(|(_, _, r, _)| s(r, "current"));
    let rank = |r: &serde_json::Value| -> u8 {
        match (s(r, "control_set"), &current_cs) {
            (Some(c), Some(cur)) if &c == cur => 0,
            (None, _) => 0,
            _ => 1,
        }
    };
    let pick = |action: &str| -> Option<&(String, String, serde_json::Value, String)> {
        parsed.iter().filter(|(_, a, _, _)| a == action).min_by_key(|(_, _, r, _)| rank(r))
    };
    let sourced = |e: &(String, String, serde_json::Value, String), v: String| HostSourced { value: v, event_id: e.0.clone(), source: e.3.clone() };

    let mut names: Vec<String> = parsed.iter().filter(|(_, a, _, _)| a == "host.computer_name").filter_map(|(_, _, r, _)| s(r, "value")).collect();
    names.sort();
    names.dedup();
    if let Some(e) = pick("host.computer_name") {
        if let Some(v) = s(&e.2, "value") {
            out.other_names = names.into_iter().filter(|n| !n.eq_ignore_ascii_case(&v)).collect();
            out.computer_name = Some(sourced(e, v));
        }
    }
    if let Some(e) = pick("host.tcpip") {
        if let Some(d) = s(&e.2, "domain") {
            out.domain = Some(sourced(e, d));
        }
    }
    if let Some(e) = pick("host.os") {
        out.os = Some(HostSourced { value: e.2.clone(), event_id: e.0.clone(), source: e.3.clone() });
    }
    if let Some(e) = pick("host.timezone") {
        out.timezone = Some(HostSourced { value: e.2.clone(), event_id: e.0.clone(), source: e.3.clone() });
    }
    if let Some(e) = pick("host.shutdown") {
        if let Some(t) = s(&e.2, "time") {
            out.last_shutdown = Some(sourced(e, t));
        }
    }
    // Interfaces: one per GUID, from the current control set where possible.
    let mut seen = std::collections::HashSet::new();
    let mut ifs: Vec<&(String, String, serde_json::Value, String)> = parsed.iter().filter(|(_, a, _, _)| a == "host.interface").collect();
    ifs.sort_by_key(|(_, _, r, _)| rank(r));
    for e in ifs {
        let key = s(&e.2, "guid").unwrap_or_default();
        if seen.insert(key) {
            out.interfaces.push(HostSourced { value: e.2.clone(), event_id: e.0.clone(), source: e.3.clone() });
        }
    }
    // Accounts: local SAM accounts (names + F/V activity, joined by RID) and
    // profile-only users (domain / Microsoft accounts) from ProfileList.
    let mut accts: std::collections::BTreeMap<String, HostAccount> = std::collections::BTreeMap::new();
    for (id, a, r, _) in &parsed {
        let rid = r.get("rid").and_then(|x| x.as_u64());
        match a.as_str() {
            "host.account" | "host.account_activity" => {
                let Some(user) = s(r, "user") else { continue };
                let acc = accts.entry(user.to_ascii_lowercase()).or_insert_with(|| HostAccount { user: user.clone(), local: true, event_id: id.clone(), ..Default::default() });
                acc.rid = acc.rid.or(rid);
                if a == "host.account" {
                    acc.created = s(r, "created");
                } else {
                    acc.full_name = s(r, "full_name").or(acc.full_name.take());
                    acc.last_logon = s(r, "last_logon");
                    acc.password_last_set = s(r, "password_last_set");
                    acc.logon_count = r.get("logon_count").and_then(|x| x.as_u64());
                    acc.disabled = r.get("disabled").and_then(|x| x.as_bool());
                    acc.event_id = id.clone();
                }
            }
            _ => {}
        }
    }
    for (id, a, r, _) in &parsed {
        if a != "host.profile" {
            continue;
        }
        let Some(user) = s(r, "user") else { continue };
        let sid = s(r, "sid");
        let local_rid = sid.as_deref().and_then(|x| x.rsplit('-').next()).and_then(|x| x.parse::<u64>().ok());
        // Match a SAM account by RID first (renamed profiles), else by name.
        let key = accts
            .iter()
            .find(|(_, v)| v.rid.is_some() && v.rid == local_rid)
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| user.to_ascii_lowercase());
        let acc = accts.entry(key).or_insert_with(|| HostAccount { user: user.clone(), local: false, event_id: id.clone(), ..Default::default() });
        acc.sid = sid;
        acc.profile_path = s(r, "path");
    }
    out.accounts = accts.into_values().collect();
    Ok(out)
}
