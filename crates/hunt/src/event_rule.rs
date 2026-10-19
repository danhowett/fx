//! Single-event rules: a focused Sigma-subset that matches ONE normalized
//! event against field conditions.
//!
//! Full Sigma is a large spec; we implement the detection-logic core that
//! actually matters for hunting over our schema: named field conditions with
//! match modifiers (equals / contains / startswith / endswith / regex), a value
//! list treated as OR, and `all` / `any` / `not` composition. Rules are YAML,
//! loaded at runtime, so an analyst adds detections without recompiling.
//!
//! Fields reference the normalized [`fx_core::Event`] via stable dotted names
//! (`action`, `process.command_line`, `target.path`, `user.name`, …), so a rule
//! is portable across every artefact that populates those fields — a
//! command-line rule fires whether the command came from EVTX 4688, a Run key,
//! or a service ImagePath.

use fx_core::{Event, Severity};
use regex::RegexBuilder;
use std::cell::RefCell;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// A single-event detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub attack: Vec<String>,
    /// The match condition tree.
    pub detection: Condition,
    /// Optional: only consider events from these artefacts (perf + precision).
    #[serde(default)]
    pub artefacts: Vec<String>,
    /// Optional self-tests: example events this rule must / must not match.
    /// Checked by the test suite for every embedded rule, so a rule edit that
    /// stops catching its target, or starts catching benign noise, fails CI.
    #[serde(default, skip_serializing_if = "RuleTests::is_empty")]
    pub tests: RuleTests,
}

/// Example events for a rule. Each example is a map of field name → value
/// (the same dotted names rules use, plus `artefact`, e.g. `mft`, `evtx`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleTests {
    #[serde(default, rename = "match")]
    pub should_match: Vec<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub no_match: Vec<std::collections::BTreeMap<String, String>>,
}

impl RuleTests {
    pub fn is_empty(&self) -> bool {
        self.should_match.is_empty() && self.no_match.is_empty()
    }
}

/// Build a synthetic event from a rule-test example (see [`RuleTests`]).
pub fn event_from_example(ex: &std::collections::BTreeMap<String, String>) -> Event {
    use fx_core::{ArtefactKind, ProcessInfo, Provenance, Target, TimestampKind};
    let g = |k: &str| ex.get(k).cloned();
    let artefact: ArtefactKind = g("artefact")
        .and_then(|a| serde_json::from_value(serde_json::Value::String(a.to_ascii_lowercase())).ok())
        .unwrap_or(ArtefactKind::Evtx);
    let has_proc = ["process.name", "process.path", "process.command_line", "process.parent_name", "process.hash_sha1"]
        .iter()
        .any(|k| ex.contains_key(*k));
    let mut raw = serde_json::json!({});
    if let Some(id) = g("event.id") {
        raw["Event"] = serde_json::json!({"System": {"EventID": id.parse::<u64>().unwrap_or(0)}});
    }
    for (k, v) in ex {
        if let Some(x) = k.strip_prefix("extras.") {
            raw["extras"][x] = serde_json::Value::String(v.clone());
        }
    }
    Event {
        id: uuid::Uuid::new_v4(),
        timestamp: time::OffsetDateTime::UNIX_EPOCH,
        timestamp_kind: TimestampKind::Recorded,
        artefact,
        action: g("action").unwrap_or_else(|| "test.event".into()),
        host: g("host"),
        user: fx_core::Principal { name: g("user.name"), sid: g("user.sid"), domain: g("user.domain") },
        process: has_proc.then(|| ProcessInfo {
            name: g("process.name"),
            path: g("process.path"),
            command_line: g("process.command_line"),
            parent_name: g("process.parent_name"),
            hash_sha1: g("process.hash_sha1"),
            ..Default::default()
        }),
        target: g("target.path").or(g("target.value_name")).map(|_| Target {
            path: g("target.path"),
            value_name: g("target.value_name"),
            hash_sha1: None,
            size: None,
        }),
        network: None,
        message: g("message").unwrap_or_default(),
        provenance: Provenance {
            evidence_id: uuid::Uuid::nil(),
            source_path: String::new(),
            parser: "rule-test".into(),
            parser_version: "0".into(),
            source_ref: None,
        },
        raw,
    }
}

/// A boolean tree of field predicates. YAML-friendly: each node is a map with
/// exactly one of the keys `all`, `any`, `not`, or `match`. Represented with
/// adjacent optional fields (via an intermediate) rather than an externally
/// tagged enum, because serde_yaml externally-tagged enums require `!tag`
/// syntax that no analyst would write. `untagged` lets the natural
/// `any: [...]` / `match: {...}` YAML deserialize by structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    All {
        all: Vec<Condition>,
    },
    Any {
        any: Vec<Condition>,
    },
    Not {
        not: Box<Condition>,
    },
    Match {
        #[serde(rename = "match")]
        match_: FieldMatch,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMatch {
    /// Dotted field name into the normalized event (see `field_value`).
    pub field: String,
    #[serde(default)]
    pub op: MatchOp,
    /// One or more values; a list is OR (matches if any value matches).
    #[serde(default)]
    pub values: Vec<String>,
    /// Case-insensitive matching (default true — attacker paths vary in case).
    #[serde(default = "default_true")]
    pub ci: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOp {
    #[default]
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    /// Field is present and non-empty.
    Exists,
}

/// Fields whose value is derived from the stored `raw` JSON (see
/// `field_value`). Reconstructing an `Event` only needs to parse `raw` when a
/// loaded rule references one of these; otherwise the (expensive, per-row) JSON
/// parse can be skipped entirely. On a filesystem-heavy case (millions of USN /
/// MFT events, no EVTX-EventID rules matching them) that parse was pure waste
/// and a large fraction of the single-event pass's time.
pub const RAW_BACKED_FIELDS: &[&str] = &["event.id", "extras.browser_event", "extras.domain"];

impl EventRule {
    /// Does this rule match the given event?
    pub fn matches(&self, ev: &Event) -> bool {
        if !self.artefacts.is_empty() {
            let a = format!("{:?}", ev.artefact);
            if !self.artefacts.iter().any(|x| x.eq_ignore_ascii_case(&a)) {
                return false;
            }
        }
        self.detection.eval(ev)
    }

    /// True if any condition in this rule reads a `raw`-backed field.
    pub fn references_raw(&self) -> bool {
        let mut hit = false;
        self.detection.for_each_field(&mut |f| {
            if RAW_BACKED_FIELDS.contains(&f) || f.starts_with("evtx.") {
                hit = true;
            }
        });
        hit
    }
}

/// Does any rule in the set need the `raw` JSON? Used to decide whether the
/// single-event scan must parse it per row.
pub fn any_rule_needs_raw(rules: &[EventRule]) -> bool {
    rules.iter().any(|r| r.references_raw())
}

impl Condition {
    fn eval(&self, ev: &Event) -> bool {
        match self {
            Condition::All { all } => all.iter().all(|c| c.eval(ev)),
            Condition::Any { any } => any.iter().any(|c| c.eval(ev)),
            Condition::Not { not } => !not.eval(ev),
            Condition::Match { match_ } => match_.eval(ev),
        }
    }

    /// Visit every field name referenced anywhere in this condition tree.
    fn for_each_field(&self, f: &mut impl FnMut(&str)) {
        match self {
            Condition::All { all } => all.iter().for_each(|c| c.for_each_field(f)),
            Condition::Any { any } => any.iter().for_each(|c| c.for_each_field(f)),
            Condition::Not { not } => not.for_each_field(f),
            Condition::Match { match_ } => f(&match_.field),
        }
    }
}

impl FieldMatch {
    fn eval(&self, ev: &Event) -> bool {
        let Some(actual) = field_value(ev, &self.field) else {
            // Exists on an absent field is false; every other op on an absent
            // field is also false.
            return false;
        };
        if matches!(self.op, MatchOp::Exists) {
            return !actual.is_empty();
        }
        // Lower-case the event value ONCE per condition, not once per value.
        let actual_lc = if self.ci { actual.to_ascii_lowercase() } else { actual.clone() };
        self.values
            .iter()
            .any(|want| compare(self.op, &actual, &actual_lc, want, self.ci))
    }
}

thread_local! {
    /// Compiled-regex cache, indexed by case-insensitivity (0 = sensitive,
    /// 1 = insensitive) then pattern. Rules used to compile every regex afresh
    /// for EVERY event it was tested against — on a multi-million-event case
    /// that was ~10^8 regex compilations and the real cause of the
    /// "Running detections…" hang. Now each distinct pattern compiles once.
    /// `None` caches an invalid pattern so it isn't retried per event.
    static REGEX_CACHE: RefCell<[HashMap<String, Option<regex::Regex>>; 2]> =
        RefCell::new([HashMap::new(), HashMap::new()]);
}

fn cached_regex_match(pattern: &str, ci: bool, haystack: &str) -> bool {
    REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let map = &mut cache[ci as usize];
        if let Some(entry) = map.get(pattern) {
            return entry.as_ref().map_or(false, |re| re.is_match(haystack));
        }
        let compiled = RegexBuilder::new(pattern).case_insensitive(ci).build().ok();
        let hit = compiled.as_ref().map_or(false, |re| re.is_match(haystack));
        map.insert(pattern.to_string(), compiled);
        hit
    })
}

/// `actual_lc` is `actual` already lower-cased when `ci` (computed once by the
/// caller); regex matching uses the original text with a case-insensitive
/// compiled pattern instead.
fn compare(op: MatchOp, actual: &str, actual_lc: &str, want: &str, ci: bool) -> bool {
    if let MatchOp::Regex = op {
        return cached_regex_match(want, ci, actual);
    }
    let w_owned;
    let w: &str = if ci {
        w_owned = want.to_ascii_lowercase();
        &w_owned
    } else {
        want
    };
    match op {
        MatchOp::Equals => actual_lc == w,
        MatchOp::Contains => actual_lc.contains(w),
        MatchOp::StartsWith => actual_lc.starts_with(w),
        MatchOp::EndsWith => actual_lc.ends_with(w),
        MatchOp::Exists => !actual_lc.is_empty(),
        MatchOp::Regex => unreachable!(),
    }
}

/// Resolve a dotted field name against a normalized event. This is the stable
/// contract rules are written against; adding a field here makes it available
/// to every rule. String-valued fields only (matching is textual).
fn field_value(ev: &Event, field: &str) -> Option<String> {
    match field {
        "action" => Some(ev.action.clone()),
        "artefact" => Some(format!("{:?}", ev.artefact)),
        "message" => Some(ev.message.clone()),
        "host" => ev.host.clone(),
        "user.name" => ev.user.name.clone(),
        "user.sid" => ev.user.sid.clone(),
        "user.domain" => ev.user.domain.clone(),
        "process.name" => ev.process.as_ref().and_then(|p| p.name.clone()),
        "process.path" => ev.process.as_ref().and_then(|p| p.path.clone()),
        "process.command_line" => ev.process.as_ref().and_then(|p| p.command_line.clone()),
        "process.hash_sha1" => ev.process.as_ref().and_then(|p| p.hash_sha1.clone()),
        "process.parent_name" => ev.process.as_ref().and_then(|p| p.parent_name.clone()),
        "target.path" => ev.target.as_ref().and_then(|t| t.path.clone()),
        "target.value_name" => ev.target.as_ref().and_then(|t| t.value_name.clone()),
        "network.dest_ip" => ev.network.as_ref().and_then(|n| n.dest_ip.clone()),
        "network.source_ip" => ev.network.as_ref().and_then(|n| n.source_ip.clone()),
        // Virtual fields, synthesized so imported rules can match cleanly:
        // `filename` is the basename of whichever path the event carries
        // (process image or target), letting a `filename: mimikatz.exe` rule
        // fire regardless of the full path or which artefact recorded it.
        "filename" => {
            let path = ev
                .process
                .as_ref()
                .and_then(|p| p.path.clone().or_else(|| p.name.clone()))
                .or_else(|| ev.target.as_ref().and_then(|t| t.path.clone()))?;
            let base = path
                .rsplit(|c| c == '\\' || c == '/')
                .next()
                .unwrap_or(&path);
            Some(base.to_string())
        }
        // `event.id` is the EVTX EventID, read from the raw record so rules can
        // match on 4625 / 4672 / 7045 etc. without us pre-mapping every EID.
        "event.id" => ev
            .raw
            .pointer("/Event/System/EventID")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.get("#text").and_then(|t| t.as_u64()))
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .map(|n| n.to_string()),
        // Browser fields imported IOC rules key on, stored under raw.extras by
        // the browser-history parser. Resolving them here is what makes those
        // (previously dormant) rules fire.
        "extras.browser_event" => ev
            .raw
            .pointer("/extras/browser_event")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        "extras.domain" => ev
            .raw
            .pointer("/extras/domain")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        // ── Fields used by converted Sigma rules ───────────────────────────
        // Process image as a Windows path; execution artefacts that record
        // only a file name (Prefetch) get a leading '\' so Sigma's
        // `Image|endswith: '\x.exe'` still matches.
        "image" => win_image(ev.process.as_ref().and_then(|p| p.path.clone().filter(|s| !s.is_empty()).or_else(|| p.name.clone()))),
        "parent_image" => win_image(ev.process.as_ref().and_then(|p| p.parent_name.clone())),
        // File path in Windows form: $MFT stores volume-relative paths with
        // '/', so normalise and assume the system volume.
        "sigma.file_path" => ev.target.as_ref().and_then(|t| t.path.clone()).map(|p| {
            let w = p.replace('/', "\\");
            let b = w.as_bytes();
            if (b.len() > 1 && b[1] == b':') || w.starts_with("\\\\") {
                w
            } else {
                format!("C:\\{}", w.trim_start_matches('\\'))
            }
        }),
        "sigma.registry_path" => ev.provenance.source_ref.as_deref().map(sigma_registry_path),
        // Whole-record text for Sigma keyword searches.
        "evtx.__text" => (!ev.raw.is_null()).then(|| ev.raw.to_string()),
        f if f.starts_with("evtx.") => evtx_field(&ev.raw, &f[5..]),
        _ => None,
    }
}

fn win_image(p: Option<String>) -> Option<String> {
    let p = p?;
    if p.is_empty() {
        return None;
    }
    Some(if p.contains('\\') || p.contains('/') { p.replace('/', "\\") } else { format!("\\{p}") })
}

/// A field from an EVTX record as Sigma names it: System fields (Channel,
/// Provider_Name, Computer) or any EventData / UserData value.
fn evtx_field(raw: &serde_json::Value, name: &str) -> Option<String> {
    let sys = raw.pointer("/Event/System");
    let v = match name {
        "Channel" => sys.and_then(|s| s.get("Channel")).cloned(),
        "Computer" => sys.and_then(|s| s.get("Computer")).cloned(),
        "Provider_Name" => sys
            .and_then(|s| s.pointer("/Provider/#attributes/Name").or_else(|| s.pointer("/Provider/Name")))
            .cloned(),
        _ => raw
            .pointer("/Event/EventData")
            .and_then(|e| e.get(name))
            .or_else(|| {
                // UserData has one wrapper element whose children are the fields.
                raw.pointer("/Event/UserData")
                    .and_then(|u| u.as_object())
                    .and_then(|o| o.values().find_map(|inner| inner.get(name)))
            })
            .cloned(),
    }?;
    json_text(&v)
}

fn json_text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Object(o) => o.get("#text").and_then(json_text),
        serde_json::Value::Array(a) => Some(a.iter().filter_map(json_text).collect::<Vec<_>>().join(" ")),
        serde_json::Value::Null => None,
    }
}

/// fx registry key path (hive-relative, first segment = hive root name) →
/// the HKLM\… / HKU\… form Sigma's TargetObject uses. ControlSet00N becomes
/// CurrentControlSet; the hive is inferred from the first real key.
fn sigma_registry_path(src: &str) -> String {
    let mut parts: Vec<&str> = src.trim_start_matches('\\').split('\\').collect();
    if !parts.is_empty() {
        parts.remove(0); // hive root node name (ROOT, CsiTool, CMI-CreateHive{…})
    }
    let mut rest: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
    if let Some(first) = rest.first_mut() {
        if first.len() == 13 && first.to_ascii_lowercase().starts_with("controlset0") {
            *first = "CurrentControlSet".into();
        }
    }
    let first = rest.first().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let prefix = match first.as_str() {
        "currentcontrolset" | "select" | "setup" | "mounteddevices" | "driverdatabase" => "HKLM\\SYSTEM",
        "software" | "environment" | "console" | "control panel" | "keyboard layout" | "network" | "printers" => "HKU\\S",
        "local settings" => "HKU\\S_Classes",
        "sam" => "HKLM\\SAM",
        "policy" | "policies" if rest.len() > 1 && rest[1].eq_ignore_ascii_case("secrets") => "HKLM\\SECURITY",
        "root" if src.to_ascii_lowercase().contains("inventoryapplication") => "HKLM\\Amcache",
        _ => "HKLM\\SOFTWARE",
    };
    format!("{prefix}\\{}", rest.join("\\"))
}

// ── Compiled rule set ────────────────────────────────────────────────────────
//
// `EventRule::matches` walks every rule for every event and tests each value in
// turn, so cost grows linearly with the number of rules × values. That was fine
// at a few dozen rules, but a large research-derived pack would multiply hunt
// time on multi-million-event cases.
//
// `CompiledRules` evaluates the same rules with the same results, but turns
// every field condition ("leaf") into one regex and, per event field, runs ALL
// leaves for that field as a single `RegexSet` pass. The per-event cost is then
// roughly one scan per distinct field (~a dozen), nearly independent of how many
// rules exist. The boolean all/any/not trees are evaluated afterwards against a
// bitmap of which leaves matched, which is trivially cheap.

/// A rule's condition tree with leaves replaced by indices into the leaf table.
#[derive(Debug, Clone)]
enum CTree {
    All(Vec<CTree>),
    Any(Vec<CTree>),
    Not(Box<CTree>),
    Leaf(usize),
}

impl CTree {
    fn eval(&self, hit: &[bool]) -> bool {
        match self {
            CTree::All(v) => v.iter().all(|c| c.eval(hit)),
            CTree::Any(v) => v.iter().any(|c| c.eval(hit)),
            CTree::Not(c) => !c.eval(hit),
            CTree::Leaf(i) => hit[*i],
        }
    }
}

/// All leaves that read one event field.
struct FieldPlan {
    field: String,
    /// Leaves using `exists` (non-empty check, no regex).
    exists: Vec<usize>,
    /// Leaves matched by regex, in `set` order.
    leaves: Vec<usize>,
    /// One combined matcher for `leaves`; `None` falls back to `singles`.
    set: Option<regex::RegexSet>,
    singles: Vec<regex::Regex>,
}

/// Never matches anything (used for a leaf whose every value failed to compile —
/// the same outcome the per-value path gives an invalid pattern).
const NEVER: &str = r"[^\s\S]";

/// Translate one leaf into a single pattern with the leaf's semantics.
fn leaf_pattern(m: &FieldMatch) -> String {
    let parts: Vec<String> = m
        .values
        .iter()
        .filter_map(|v| match m.op {
            MatchOp::Regex => {
                // Keep only values that compile, as the per-value path ignores
                // invalid ones (they simply never match).
                RegexBuilder::new(v).case_insensitive(m.ci).build().ok()?;
                Some(format!("(?:{v})"))
            }
            MatchOp::Equals => Some(format!(r"\A{}\z", regex::escape(v))),
            MatchOp::Contains => Some(regex::escape(v)),
            MatchOp::StartsWith => Some(format!(r"\A{}", regex::escape(v))),
            MatchOp::EndsWith => Some(format!(r"{}\z", regex::escape(v))),
            MatchOp::Exists => None,
        })
        .collect();
    if parts.is_empty() {
        return NEVER.to_string();
    }
    let flag = if m.ci { "(?i)" } else { "" };
    format!("{flag}(?:{})", parts.join("|"))
}

/// The event-rule set compiled for fast, rule-count-independent evaluation.
pub struct CompiledRules {
    trees: Vec<CTree>,
    /// Per rule: lower-cased artefact names it is limited to (empty = any).
    artefacts: Vec<Vec<String>>,
    fields: Vec<FieldPlan>,
    n_leaves: usize,
}

impl CompiledRules {
    pub fn new(rules: &[EventRule]) -> Self {
        let mut leaves: Vec<FieldMatch> = Vec::new();
        fn build(c: &Condition, leaves: &mut Vec<FieldMatch>) -> CTree {
            match c {
                Condition::All { all } => CTree::All(all.iter().map(|x| build(x, leaves)).collect()),
                Condition::Any { any } => CTree::Any(any.iter().map(|x| build(x, leaves)).collect()),
                Condition::Not { not } => CTree::Not(Box::new(build(not, leaves))),
                Condition::Match { match_ } => {
                    leaves.push(match_.clone());
                    CTree::Leaf(leaves.len() - 1)
                }
            }
        }
        let trees: Vec<CTree> = rules.iter().map(|r| build(&r.detection, &mut leaves)).collect();
        let artefacts = rules
            .iter()
            .map(|r| r.artefacts.iter().map(|a| a.to_ascii_lowercase()).collect())
            .collect();

        // Group leaves by field.
        let mut order: Vec<String> = Vec::new();
        let mut by_field: HashMap<String, (Vec<usize>, Vec<usize>, Vec<String>)> = HashMap::new();
        for (i, m) in leaves.iter().enumerate() {
            if !by_field.contains_key(&m.field) {
                order.push(m.field.clone());
            }
            let e = by_field.entry(m.field.clone()).or_default();
            if matches!(m.op, MatchOp::Exists) {
                e.0.push(i);
            } else {
                e.1.push(i);
                e.2.push(leaf_pattern(m));
            }
        }
        let fields = order
            .into_iter()
            .map(|field| {
                let (exists, idx, pats) = by_field.remove(&field).unwrap();
                let set = regex::RegexSetBuilder::new(&pats)
                    .size_limit(256 << 20)
                    .dfa_size_limit(64 << 20)
                    .build()
                    .ok();
                // Fallback (should not happen: every pattern is pre-validated):
                // compile individually so a pathological set can't disable rules.
                let singles = if set.is_none() {
                    pats.iter()
                        .map(|p| regex::Regex::new(p).unwrap_or_else(|_| regex::Regex::new(NEVER).unwrap()))
                        .collect()
                } else {
                    Vec::new()
                };
                FieldPlan { field, exists, leaves: idx, set, singles }
            })
            .collect();
        CompiledRules { trees, artefacts, fields, n_leaves: leaves.len() }
    }

    /// Indices (into the rule slice passed to `new`) of every rule that
    /// matches `ev`, in rule order. `hit` is a scratch buffer reused across
    /// calls to avoid a per-event allocation.
    pub fn matching(&self, ev: &Event, hit: &mut Vec<bool>, out: &mut Vec<usize>) {
        out.clear();
        hit.clear();
        hit.resize(self.n_leaves, false);
        for fp in &self.fields {
            let Some(v) = field_value(ev, &fp.field) else { continue };
            if !v.is_empty() {
                for &i in &fp.exists {
                    hit[i] = true;
                }
            }
            if fp.leaves.is_empty() {
                continue;
            }
            match &fp.set {
                Some(set) => {
                    for k in set.matches(&v).iter() {
                        hit[fp.leaves[k]] = true;
                    }
                }
                None => {
                    for (k, re) in fp.singles.iter().enumerate() {
                        if re.is_match(&v) {
                            hit[fp.leaves[k]] = true;
                        }
                    }
                }
            }
        }
        let art = format!("{:?}", ev.artefact).to_ascii_lowercase();
        for (r, tree) in self.trees.iter().enumerate() {
            let a = &self.artefacts[r];
            if !a.is_empty() && !a.iter().any(|x| *x == art) {
                continue;
            }
            if tree.eval(hit) {
                out.push(r);
            }
        }
    }
}

// ── Gated rule set ───────────────────────────────────────────────────────────
//
// With thousands of rules (a Sigma pack), most can only ever match one kind of
// event: an EVTX record from one channel with one event ID, a process start,
// an $MFT file record. `GatedRules` reads those constraints out of each rule
// once, then offers each event only the rules that could apply to its
// (artefact, action, event ID). A compiled matcher is built lazily per such
// key and cached, so millions of MFT rows never touch the EVTX-only rules and
// each EVTX record only meets the handful written for its event ID.

#[derive(Default, Clone)]
struct Gate {
    arts: Option<std::collections::HashSet<String>>,
    actions: Option<std::collections::HashSet<String>>,
    eids: Option<std::collections::HashSet<String>>,
}

const ALL_ARTEFACTS: &[&str] = &[
    "Evtx", "Mft", "UsnJrnl", "LogFile", "Prefetch", "Amcache", "ShimCache", "RegistryRun", "RegistryService",
    "UserAssist", "ShellBags", "BamDam", "Srum", "ScheduledTask", "Lnk", "JumpList", "Recycle", "BrowserHistory",
    "PsHistory", "WindowsTimeline", "RemoteAccess", "DefenderLog", "RegistryGeneric", "Unclassified",
];

type Set = std::collections::HashSet<String>;

fn meet(a: Option<Set>, b: Option<Set>) -> Option<Set> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(x.intersection(&y).cloned().collect()),
    }
}
fn join(a: Option<Set>, b: Option<Set>) -> Option<Set> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.union(&y).cloned().collect()),
        _ => None,
    }
}

/// The values a condition tree requires `field` to take, if it pins it down
/// (None = unconstrained). Conservative: anything not provably limited is None.
fn constraint(c: &Condition, field: &str) -> Option<Set> {
    match c {
        Condition::All { all } => all.iter().fold(None, |acc, x| meet(acc, constraint(x, field))),
        Condition::Any { any } => {
            if any.is_empty() {
                return Some(Set::new()); // can never match
            }
            let mut it = any.iter().map(|x| constraint(x, field));
            let first = it.next().unwrap();
            it.fold(first, join)
        }
        Condition::Not { .. } => None,
        Condition::Match { match_ } if match_.field == field => match match_.op {
            MatchOp::Equals => Some(match_.values.iter().map(|v| v.to_ascii_lowercase()).collect()),
            MatchOp::Regex if field == "artefact" => {
                let res: Vec<regex::Regex> = match_
                    .values
                    .iter()
                    .filter_map(|v| RegexBuilder::new(v).case_insensitive(match_.ci).build().ok())
                    .collect();
                Some(ALL_ARTEFACTS.iter().filter(|a| res.iter().any(|r| r.is_match(a))).map(|a| a.to_ascii_lowercase()).collect())
            }
            _ => None,
        },
        Condition::Match { .. } => None,
    }
}

pub struct GatedRules<'a> {
    rules: &'a [EventRule],
    gates: Vec<Gate>,
    cache: std::collections::HashMap<(String, String, String), (CompiledRules, Vec<usize>)>,
    scratch: Vec<usize>,
}

impl<'a> GatedRules<'a> {
    pub fn new(rules: &'a [EventRule]) -> Self {
        let gates = rules
            .iter()
            .map(|r| {
                let mut arts = constraint(&r.detection, "artefact");
                if !r.artefacts.is_empty() {
                    arts = meet(arts, Some(r.artefacts.iter().map(|a| a.to_ascii_lowercase()).collect()));
                }
                Gate { arts, actions: constraint(&r.detection, "action"), eids: constraint(&r.detection, "event.id") }
            })
            .collect();
        GatedRules { rules, gates, cache: Default::default(), scratch: Vec::new() }
    }

    /// Indices of rules matching `ev` (same results as `CompiledRules` over
    /// the whole set).
    pub fn matching(&mut self, ev: &Event, hit: &mut Vec<bool>, out: &mut Vec<usize>) {
        let art = format!("{:?}", ev.artefact).to_ascii_lowercase();
        let action = ev.action.to_ascii_lowercase();
        let eid = if ev.artefact == fx_core::ArtefactKind::Evtx { field_value(ev, "event.id").unwrap_or_default() } else { String::new() };
        let key = (art, action, eid);
        if !self.cache.contains_key(&key) {
            let (a, ac, e) = (&key.0, &key.1, &key.2);
            let idx: Vec<usize> = self
                .gates
                .iter()
                .enumerate()
                .filter(|(_, g)| {
                    g.arts.as_ref().map_or(true, |s| s.contains(a))
                        && g.actions.as_ref().map_or(true, |s| s.contains(ac))
                        && g.eids.as_ref().map_or(true, |s| s.contains(e))
                })
                .map(|(i, _)| i)
                .collect();
            let subset: Vec<EventRule> = idx.iter().map(|&i| self.rules[i].clone()).collect();
            self.cache.insert(key.clone(), (CompiledRules::new(&subset), idx));
        }
        let (compiled, idx) = &self.cache[&key];
        compiled.matching(ev, hit, &mut self.scratch);
        out.clear();
        out.extend(self.scratch.iter().map(|&i| idx[i]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fx_core::{ArtefactKind, Provenance, TimestampKind};
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn ev_with_cmdline(cmd: &str) -> Event {
        Event {
            id: Uuid::new_v4(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            timestamp_kind: TimestampKind::Executed,
            artefact: ArtefactKind::Evtx,
            action: "process.start".into(),
            host: None,
            user: Default::default(),
            process: Some(fx_core::ProcessInfo {
                command_line: Some(cmd.into()),
                ..Default::default()
            }),
            target: None,
            network: None,
            message: String::new(),
            provenance: Provenance {
                evidence_id: Uuid::nil(),
                source_path: String::new(),
                parser: "t".into(),
                parser_version: "0".into(),
                source_ref: None,
            },
            raw: serde_json::Value::Null,
        }
    }

    #[test]
    fn contains_matches_case_insensitive() {
        let m = FieldMatch {
            field: "process.command_line".into(),
            op: MatchOp::Contains,
            values: vec!["delete shadows".into()],
            ci: true,
        };
        assert!(m.eval(&ev_with_cmdline("vssadmin.exe Delete Shadows /all /quiet")));
        assert!(!m.eval(&ev_with_cmdline("notepad.exe readme.txt")));
    }

    #[test]
    fn all_of_requires_both() {
        let rule = Condition::All {
            all: vec![
                Condition::Match {
                    match_: FieldMatch {
                        field: "process.command_line".into(),
                        op: MatchOp::Contains,
                        values: vec!["vssadmin".into()],
                        ci: true,
                    },
                },
                Condition::Match {
                    match_: FieldMatch {
                        field: "process.command_line".into(),
                        op: MatchOp::Contains,
                        values: vec!["delete".into()],
                        ci: true,
                    },
                },
            ],
        };
        assert!(rule.eval(&ev_with_cmdline("vssadmin delete shadows")));
        assert!(!rule.eval(&ev_with_cmdline("vssadmin list shadows")));
    }
}
