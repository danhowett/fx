//! Importer for external IOC packs (MFIRfinder-style JSON) into our native
//! [`EventRule`] format.
//!
//! The two DSLs are close cousins — both match artefact fields with
//! regex/contains/equals plus any/all composition — so the conversion is a
//! faithful structural mapping, not a reinterpretation. What the importer adds
//! is the bridge from the pack's field/source vocabulary to our normalized
//! schema:
//!
//!   * `filename` match      -> a `filename` (basename) EndsWith match
//!   * `regex`/`field_*`     -> our MatchOp equivalents on the mapped field
//!   * `event_id` match      -> an equals match on the virtual `event.id` field
//!   * the pack's `cmdline`  -> our `process.command_line`
//!   * the pack's `path`     -> our `target.path` (with process.path fallback
//!                              handled by rules using `filename`)
//!
//! Rules whose ONLY data sources are ones we can't yet parse (browser, memory)
//! are still imported but flagged, so the analyst knows they won't fire until
//! that parser lands rather than silently getting nothing.

use crate::event_rule::{Condition, EventRule, FieldMatch, MatchOp};
use fx_core::Severity;
use serde::Deserialize;

/// The subset of the external pack we read.
#[derive(Debug, Deserialize)]
pub struct IocPack {
    pub name: String,
    #[serde(default)]
    pub version: String,
    pub rules: Vec<IocRule>,
}

#[derive(Debug, Deserialize)]
pub struct IocRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: String,
    pub attack: IocAttack,
    #[serde(default)]
    pub sources: Vec<String>,
    pub r#match: IocMatch,
}

#[derive(Debug, Deserialize)]
pub struct IocAttack {
    #[serde(default)]
    pub technique: Option<String>,
    #[serde(default)]
    pub sub_technique: Option<String>,
}

/// The pack's match node: either a composite (`any`/`all`) or a leaf with a
/// `type`. Deserialized untagged and normalized in `convert_match`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum IocMatch {
    Any { any: Vec<IocMatch> },
    All { all: Vec<IocMatch> },
    Leaf(IocLeaf),
}

#[derive(Debug, Deserialize)]
pub struct IocLeaf {
    pub r#type: String,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub channel: Option<String>,
}

/// Outcome of importing a pack.
pub struct ImportResult {
    pub rules: Vec<EventRule>,
    /// Rule ids that imported but can't fire yet (only unsupported sources).
    pub dormant: Vec<(String, Vec<String>)>,
    /// Rule ids skipped entirely (unconvertible match), with the reason.
    pub skipped: Vec<(String, String)>,
    /// Regexes we repaired on import, with (rule_id, before, after). Surfaced
    /// so the analyst can see exactly what was changed — we never silently
    /// rewrite a third party's detection logic.
    pub repaired: Vec<(String, String, String)>,
    /// Source-pack ids that collided; (original_id, deduped_id). A real
    /// data-quality issue in packs seen in the wild — recorded so no rule is
    /// lost and the analyst can flag it upstream.
    pub duplicate_ids: Vec<(String, String)>,
}

/// A known-fragile source pattern and its repair. We only touch patterns on
/// this curated list, and every application is recorded in `repaired`. The
/// canonical case: `(\s+-[a-z]+)*` before a required `-e` flag greedily eats
/// the `-enc` itself, so `powershell -nop -w hidden -enc <b64>` — one of the
/// commonest real invocations — silently fails to match.
struct RegexRepair {
    fragile: &'static str,
    fixed: &'static str,
    why: &'static str,
}

const REGEX_REPAIRS: &[RegexRepair] = &[RegexRepair {
    fragile: r"powershell(\.exe)?(\s+-[a-z]+)*\s+-e(c|nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{30,}",
    fixed: r"powershell(\.exe)?\b.*?\s-e(c|nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{30,}",
    why: "greedy flag group consumed -enc; commonest real form (-nop -w hidden -enc) never matched",
}];

/// Apply a repair if the pattern is on the curated list. Returns the possibly-
/// replaced pattern and, if changed, the (before, after, why) for logging.
fn maybe_repair(pattern: &str) -> (String, Option<(String, String, &'static str)>) {
    for r in REGEX_REPAIRS {
        if pattern == r.fragile {
            return (
                r.fixed.to_string(),
                Some((r.fragile.to_string(), r.fixed.to_string(), r.why)),
            );
        }
    }
    (pattern.to_string(), None)
}

/// Sources our current parsers can feed. Anything outside this needs a new
/// parser (memory: process_modules / volatile_processes) before the rule can
/// fire. Browser history is now parsed, so browser_* count as supported.
const SUPPORTED_SOURCES: &[&str] = &[
    "event_log", "prefetch", "amcache", "mft", "usn", "registry",
    "browser_chromium", "browser_firefox",
];

/// Convert a whole pack.
pub fn import_pack(pack: &IocPack) -> ImportResult {
    let mut out = ImportResult {
        rules: Vec::new(),
        dormant: Vec::new(),
        skipped: Vec::new(),
        repaired: Vec::new(),
        duplicate_ids: Vec::new(),
    };

    for r in &pack.rules {
        let mut repairs: Vec<(String, String, &'static str)> = Vec::new();
        let detection = match convert_match(&r.r#match, &mut repairs) {
            Ok(c) => c,
            Err(e) => {
                out.skipped.push((r.id.clone(), e));
                continue;
            }
        };
        for (before, after, _why) in &repairs {
            out.repaired
                .push((r.id.clone(), before.clone(), after.clone()));
        }

        // The source pack can contain duplicate ids (a real data-quality issue
        // seen in the wild); de-duplicate so no rule is silently lost to a
        // filename/id collision. Collisions are recorded so the analyst knows.
        let base_id = format!("ioc_{}", r.id.to_lowercase().replace('-', "_"));
        let id = {
            let n = out
                .rules
                .iter()
                .filter(|x| x.id == base_id || x.id.starts_with(&format!("{base_id}_dup")))
                .count();
            if n == 0 {
                base_id
            } else {
                let deduped = format!("{base_id}_dup{n}");
                out.duplicate_ids.push((r.id.clone(), deduped.clone()));
                deduped
            }
        };

        // Is any of the rule's sources one we can actually parse?
        let unsupported: Vec<String> = r
            .sources
            .iter()
            .filter(|s| !SUPPORTED_SOURCES.contains(&s.as_str()))
            .cloned()
            .collect();
        let has_supported = r
            .sources
            .iter()
            .any(|s| SUPPORTED_SOURCES.contains(&s.as_str()));
        if !r.sources.is_empty() && !has_supported {
            out.dormant.push((r.id.clone(), unsupported));
        }

        let mut attack = Vec::new();
        if let Some(t) = &r.attack.technique {
            attack.push(t.clone());
        }

        out.rules.push(EventRule {
            id,
            title: r.name.clone(),
            description: r.description.clone(),
            severity: map_severity(&r.severity),
            attack,
            detection,
            // We don't constrain by artefact: the pack's per-rule `sources`
            // is advisory, and our field-based matching already scopes
            // correctly (an event_id match only fires on EVTX, a filename
            // match on whatever recorded that path).
            artefacts: Vec::new(),
        });
    }

    out
}

fn map_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

/// Recursively convert a pack match node into our Condition tree.
fn convert_match(
    m: &IocMatch,
    repairs: &mut Vec<(String, String, &'static str)>,
) -> Result<Condition, String> {
    match m {
        IocMatch::Any { any } => Ok(Condition::Any {
            any: any
                .iter()
                .map(|x| convert_match(x, repairs))
                .collect::<Result<_, _>>()?,
        }),
        IocMatch::All { all } => Ok(Condition::All {
            all: all
                .iter()
                .map(|x| convert_match(x, repairs))
                .collect::<Result<_, _>>()?,
        }),
        IocMatch::Leaf(leaf) => {
            convert_leaf(leaf, repairs).map(|match_| Condition::Match { match_ })
        }
    }
}

/// Map one leaf predicate to a FieldMatch on our schema.
fn convert_leaf(
    leaf: &IocLeaf,
    repairs: &mut Vec<(String, String, &'static str)>,
) -> Result<FieldMatch, String> {
    let value_str = |v: &Option<serde_json::Value>| -> Option<String> {
        v.as_ref().map(|x| match x {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    };

    match leaf.r#type.as_str() {
        "regex" => {
            let raw = value_str(&leaf.value).ok_or("regex leaf missing value")?;
            let (pattern, note) = maybe_repair(&raw);
            if let Some((before, after, why)) = note {
                repairs.push((before, after, why));
            }
            Ok(FieldMatch {
                field: map_field(leaf.field.as_deref().unwrap_or("raw")),
                op: MatchOp::Regex,
                values: vec![pattern],
                ci: true,
            })
        }
        "filename" => Ok(FieldMatch {
            field: "filename".into(),
            op: MatchOp::Equals,
            values: vec![value_str(&leaf.value).ok_or("filename leaf missing value")?],
            ci: true,
        }),
        "field_contains" => Ok(FieldMatch {
            field: map_field(leaf.field.as_deref().unwrap_or("raw")),
            op: MatchOp::Contains,
            values: vec![value_str(&leaf.value).ok_or("field_contains missing value")?],
            ci: true,
        }),
        "field_equals" => Ok(FieldMatch {
            field: map_field(leaf.field.as_deref().unwrap_or("raw")),
            op: MatchOp::Equals,
            values: vec![value_str(&leaf.value).ok_or("field_equals missing value")?],
            ci: true,
        }),
        "event_id" => {
            // event_id leaves carry a numeric `value` and a `channel`; we match
            // the id on the virtual `event.id` field. (Channel scoping could be
            // added as an All{} with a channel field later.)
            let id = value_str(&leaf.value).ok_or("event_id missing value")?;
            Ok(FieldMatch {
                field: "event.id".into(),
                op: MatchOp::Equals,
                values: vec![id],
                ci: false,
            })
        }
        other => Err(format!("unsupported match type `{other}`")),
    }
}

/// Translate the pack's field names to our normalized dotted fields.
fn map_field(field: &str) -> String {
    match field {
        "cmdline" => "process.command_line".into(),
        "path" => "target.path".into(),
        "image" => "process.path".into(),
        "raw" => "message".into(), // our closest broad-text field on a lifted event
        // extras.* browser fields have no home until the browser parser exists;
        // keep the dotted name so the rule is honest (it just won't match yet).
        other => other.to_string(),
    }
}

/// Serialize a converted rule to our on-disk YAML format, including the
/// `kind: event` discriminator the loader keys on. A small serde wrapper adds
/// the `kind` field without polluting the runtime `EventRule` struct.
pub fn rule_to_yaml(rule: &EventRule) -> Result<String, serde_yaml::Error> {
    #[derive(serde::Serialize)]
    struct Tagged<'a> {
        kind: &'static str,
        #[serde(flatten)]
        rule: &'a EventRule,
    }
    let header = "# Auto-generated by `fx import-iocs`. Edits may be overwritten on re-import.\n";
    let body = serde_yaml::to_string(&Tagged { kind: "event", rule })?;
    Ok(format!("{header}{body}"))
}
