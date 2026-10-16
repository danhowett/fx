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
            if RAW_BACKED_FIELDS.contains(&f) {
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
        _ => None,
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
