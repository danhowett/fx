//! MITRE ATT&CK Enterprise lookup: technique id -> official name and tactics.
//!
//! Built from MITRE's own STIX data (mitre/cti `enterprise-attack.json`) and
//! embedded at compile time, so every finding — built-in rule, Sigma rule or
//! IOC — gets the same authoritative tactic and technique names. Regenerate
//! `data/attack_enterprise.json` when MITRE publishes a new release.

use std::collections::HashMap;
use std::sync::OnceLock;

const DATA: &str = include_str!("../data/attack_enterprise.json");

#[derive(serde::Deserialize)]
struct Raw {
    modified: String,
    tactics: Vec<String>,
    techniques: HashMap<String, (String, Vec<usize>)>,
}

pub struct AttackMap {
    /// Date of the ATT&CK data (YYYY-MM-DD).
    pub modified: String,
    /// Tactics in MITRE's matrix (kill-chain) order.
    pub tactics: Vec<String>,
    techniques: HashMap<String, (String, Vec<usize>)>,
}

pub fn map() -> &'static AttackMap {
    static M: OnceLock<AttackMap> = OnceLock::new();
    M.get_or_init(|| {
        let r: Raw = serde_json::from_str(DATA).expect("embedded ATT&CK data is valid JSON");
        AttackMap {
            modified: r.modified,
            tactics: r.tactics,
            techniques: r.techniques,
        }
    })
}

fn entry(id: &str) -> Option<&'static (String, Vec<usize>)> {
    let m = map();
    let id = id.trim().to_ascii_uppercase();
    m.techniques
        .get(&id)
        .or_else(|| id.split('.').next().and_then(|p| m.techniques.get(p)))
}

/// Official technique name ("OS Credential Dumping: LSASS Memory").
pub fn technique_name(id: &str) -> Option<&'static str> {
    entry(id).map(|e| e.0.as_str())
}

/// Tactics a technique belongs to, in matrix order (a sub-technique not in
/// the data falls back to its parent).
pub fn tactics_for(id: &str) -> Vec<&'static str> {
    let m = map();
    entry(id)
        .map(|e| {
            e.1.iter()
                .filter_map(|&i| m.tactics.get(i).map(String::as_str))
                .collect()
        })
        .unwrap_or_default()
}

/// Distinct tactics across several techniques, in matrix order.
pub fn tactics_for_all<'a>(ids: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let m = map();
    let mut idx: Vec<usize> = ids
        .into_iter()
        .filter_map(entry)
        .flat_map(|e| e.1.iter().copied())
        .collect();
    idx.sort_unstable();
    idx.dedup();
    idx.into_iter()
        .filter_map(|i| m.tactics.get(i).cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(tactics_for("T1003.001"), vec!["Credential Access"]);
        assert!(technique_name("T1003.001").unwrap().contains("LSASS"));
        assert!(tactics_for("t1053.005").contains(&"Persistence"));
        // Unknown sub-technique falls back to the parent.
        assert_eq!(tactics_for("T1003.999"), vec!["Credential Access"]);
        assert!(tactics_for("T9999").is_empty());
        let all = tactics_for_all(["T1486", "T1003.001", "T1059.001"]);
        assert_eq!(all, vec!["Execution", "Credential Access", "Impact"]);
        assert!(map().techniques.len() > 600);
    }
}
