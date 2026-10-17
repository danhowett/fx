//! The hunt result model.
//!
//! Both detection engines — the single-event (Sigma-style) evaluator and the
//! correlation-rule engine — produce the same [`Detection`]. Keeping one result
//! type means the GUI, the ATT&CK view, and reporting treat a simple field match
//! and a multi-event behavioural chain identically: a hit is a hit, with a
//! severity, a technique mapping, and the events that caused it.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Analyst-facing severity. Ordered so results sort worst-first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Informational => "informational",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// One firing of a hunt rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: Uuid,
    /// Stable id of the rule that fired (e.g. `shadow_copy_deletion`).
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    /// MITRE ATT&CK technique ids, e.g. `["T1490", "T1486"]`. Drives the heatmap.
    #[serde(default)]
    pub attack: Vec<String>,
    /// One-line explanation of why this fired, in analyst language.
    pub summary: String,
    /// The event(s) that triggered the detection — for pivoting back to the
    /// timeline. A single-event rule has one; a correlation rule has many.
    pub event_ids: Vec<Uuid>,
    /// When the detected activity occurred (earliest contributing event).
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Host the activity pertains to, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Which engine produced it — useful for debugging and for the analyst to
    /// know whether it's a point signal or a correlated behaviour.
    pub engine: DetectionEngine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionEngine {
    /// Matched a single event against field conditions (Sigma-style).
    SingleEvent,
    /// Emerged from correlating/aggregating multiple events.
    Correlation,
    /// A match from an analyst-supplied IOC list (post-processing sweep).
    Ioc,
}
