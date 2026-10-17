//! EVTX parser, built on the `evtx` crate (Omer BenAmram).
//!
//! Strategy: parse each record to a JSON value (the crate does the binary XML
//! heavy lifting), keep that whole value in `Event.raw`, and lift the common
//! fields (provider, EventID, TimeCreated, Computer, the Security UserID, and
//! a few high-value EventData fields) into the normalized schema. Channel-
//! specific enrichment (mapping EventID -> action) is a lookup table we grow.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, NetworkInfo, ParseError, ParseOutcome,
    Parser, Principal, ProcessInfo, Provenance, RecordWarning, Target, TimestampKind,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct EvtxParser;

impl Parser for EvtxParser {
    fn name(&self) -> &'static str {
        "evtx"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::Evtx]
    }

    fn parse(
        &self,
        artefact: &IdentifiedArtefact,
        sink: &mut dyn EventSink,
    ) -> Result<ParseOutcome, ParseError> {
        let mut outcome = ParseOutcome::default();

        let mut parser = evtx::EvtxParser::from_path(&artefact.path).map_err(|e| ParseError::Io {
            path: artefact.path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
        })?;

        for record in parser.records_json_value() {
            outcome.records_read += 1;
            match record {
                Ok(rec) => {
                    // rec.data is a serde_json::Value of the whole event.
                    match build_event(artefact, rec.event_record_id, &rec.data) {
                        Some(ev) => {
                            sink.emit(ev);
                            outcome.events_emitted += 1;
                        }
                        None => outcome.warnings.push(RecordWarning {
                            source_ref: Some(rec.event_record_id.to_string()),
                            message: "record missing System/TimeCreated; kept raw only".into(),
                        }),
                    }
                }
                Err(e) => outcome.warnings.push(RecordWarning {
                    source_ref: None,
                    message: format!("record parse error: {e}"),
                }),
            }
        }

        Ok(outcome)
    }
}

/// Lift normalized fields out of the event's JSON. The `evtx` crate emits a
/// shape like `{ "Event": { "System": {...}, "EventData": {...} } }`.
fn build_event(artefact: &IdentifiedArtefact, record_id: u64, data: &Value) -> Option<Event> {
    let system = data.pointer("/Event/System")?;

    let event_id = system
        .get("EventID")
        .and_then(extract_event_id)
        .unwrap_or(0);

    let provider = system
        .pointer("/Provider/#attributes/Name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let computer = system
        .get("Computer")
        .and_then(Value::as_str)
        .map(str::to_string);

    let timestamp = system
        .pointer("/TimeCreated/#attributes/SystemTime")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339)?;

    let user_sid = system
        .pointer("/Security/#attributes/UserID")
        .and_then(Value::as_str)
        .map(str::to_string);

    let c = classify(&provider, event_id, data, user_sid.clone());

    Some(Event {
        id: Uuid::new_v4(),
        timestamp,
        timestamp_kind: TimestampKind::Logged,
        artefact: ArtefactKind::Evtx,
        action: c.action,
        host: computer,
        user: c.user,
        process: c.process,
        target: c.target,
        network: c.network,
        message: c.message,
        provenance: Provenance {
            evidence_id: artefact.evidence_id,
            source_path: artefact.source_path.clone(),
            parser: "evtx".into(),
            parser_version: env!("CARGO_PKG_VERSION").into(),
            source_ref: Some(format!("{}#record{}", provider, record_id)),
        },
        raw: data.clone(),
    })
}

/// EventID can be a bare number or an object `{ "#text": 4624, ... }`.
fn extract_event_id(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.get("#text").and_then(Value::as_u64))
        .or_else(|| {
            v.as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| v.get("#text").and_then(Value::as_str).and_then(|s| s.parse().ok()))
        })
}

fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

/// Coerce an EventData value to a display string regardless of how the evtx
/// crate rendered it: a bare string, a number/bool, or a `{ "#text": ... }`
/// wrapper. Returns None for null/objects/arrays with no usable scalar.
fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(_) => v
            .get("#text")
            .and_then(value_to_string)
            .or_else(|| v.get("Value").and_then(value_to_string)),
        _ => None,
    }
}

/// Structured result of classifying one EVTX record. Beyond the action and
/// display message, it carries the normalized fields lifted from EventData so
/// hunts can match on command lines, IPs, logon types, and target objects —
/// not just the event id.
struct Classified {
    action: String,
    message: String,
    user: Principal,
    process: Option<ProcessInfo>,
    network: Option<NetworkInfo>,
    target: Option<Target>,
}

impl Classified {
    fn new(action: &str, message: String) -> Self {
        Classified {
            action: action.into(),
            message,
            user: Principal::default(),
            process: None,
            network: None,
            target: None,
        }
    }
    fn user(mut self, u: Principal) -> Self {
        self.user = u;
        self
    }
    fn process(mut self, p: ProcessInfo) -> Self {
        self.process = Some(p);
        self
    }
    fn network(mut self, n: NetworkInfo) -> Self {
        self.network = Some(n);
        self
    }
    fn target(mut self, t: Target) -> Self {
        self.target = Some(t);
        self
    }
}

/// Map (provider, event id) to a normalized action, a display message, and the
/// structured fields lifted from EventData. This table is the channel knowledge
/// of the tool; it spans the log sources financially-motivated intrusions
/// actually touch — Security auditing, Sysmon, PowerShell, Terminal Services
/// (RDP), Defender, WMI, Task Scheduler, and SMB/network shares.
///
/// The provider is used to disambiguate ids that collide across channels
/// (e.g. Sysmon 1 vs Security 1). Unmapped ids still produce a usable event
/// with `evtx.eid.N` so nothing is lost.
fn classify(
    provider: &str,
    event_id: u64,
    data: &Value,
    system_sid: Option<String>,
) -> Classified {
    // Read an EventData field as a string. The evtx crate renders values with
    // their native JSON type, so a field like LogonType can arrive as a NUMBER
    // (3) rather than a string ("3"); it can also be nested as
    // {"#text": "3", ...}. Coerce all of these to a string so "(type )" never
    // comes out blank.
    let ed = |k: &str| -> Option<String> {
        let v = data.pointer("/Event/EventData").and_then(|e| e.get(k))?;
        value_to_string(v).filter(|s| !s.is_empty() && s != "-")
    };

    let prov = provider.to_ascii_lowercase();
    let is_sysmon = prov.contains("sysmon");
    let is_pwsh = prov.contains("powershell");
    let is_defender = prov.contains("defender") || prov.contains("windows defender");

    // ── Sysmon (Microsoft-Windows-Sysmon/Operational) ──────────────────────
    if is_sysmon {
        return classify_sysmon(event_id, &ed, system_sid);
    }
    // ── PowerShell (Operational + classic) ─────────────────────────────────
    if is_pwsh {
        return classify_powershell(event_id, &ed, data);
    }
    // ── Defender (Windows Defender/Operational) ────────────────────────────
    if is_defender {
        return classify_defender(event_id, &ed);
    }
    // ── ScreenConnect / ConnectWise Control (Application log) ──────────────
    // The client logs as provider "ScreenConnect Client (<instance id>)" with
    // the useful text in EventData/Data — session connects, file transfers and
    // commands run through the tool. Heavily abused for hands-on access.
    if prov.contains("screenconnect") {
        return classify_screenconnect(provider, data);
    }

    // ── Security auditing + other channels, keyed on id ────────────────────
    match event_id {
        // Logon success / failure / logoff / special privileges.
        4624 => {
            let lt = ed("LogonType").unwrap_or_default();
            Classified::new("logon.success", format!("Successful logon (type {lt})"))
                .user(Principal {
                    name: ed("TargetUserName"),
                    sid: ed("TargetUserSid").or(system_sid),
                    domain: ed("TargetDomainName"),
                })
                .network(NetworkInfo {
                    source_ip: ed("IpAddress"),
                    logon_type: lt.parse().ok(),
                    ..Default::default()
                })
        }
        4625 => {
            let lt = ed("LogonType").unwrap_or_default();
            Classified::new("logon.failure", format!("Failed logon (type {lt})"))
                .user(Principal {
                    name: ed("TargetUserName"),
                    sid: ed("TargetUserSid"),
                    domain: ed("TargetDomainName"),
                })
                .network(NetworkInfo {
                    source_ip: ed("IpAddress"),
                    logon_type: lt.parse().ok(),
                    ..Default::default()
                })
        }
        4634 | 4647 => Classified::new("logon.logoff", "Account logged off".into())
            .user(Principal { name: ed("TargetUserName"), sid: ed("TargetUserSid"), domain: ed("TargetDomainName") }),
        4648 => Classified::new(
            "logon.explicit_credentials",
            format!("Logon with explicit credentials as {}", ed("TargetUserName").unwrap_or_default()),
        )
        .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), domain: ed("SubjectDomainName") })
        .network(NetworkInfo { source_ip: ed("IpAddress"), ..Default::default() }),
        4672 => Classified::new(
            "logon.special_privileges",
            "Special privileges assigned to new logon (admin-equivalent)".into(),
        )
        .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), domain: ed("SubjectDomainName") }),

        // Process creation (Security 4688) with command line when auditing is on.
        4688 => {
            let img = ed("NewProcessName").unwrap_or_default();
            Classified::new("process.start", format!("Process created: {img}"))
                .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), domain: ed("SubjectDomainName") })
                .process(ProcessInfo {
                    name: img.rsplit(['\\', '/']).next().map(str::to_string),
                    path: Some(img),
                    command_line: ed("CommandLine"),
                    parent_name: ed("ParentProcessName"),
                    ..Default::default()
                })
        }

        // Account & group management (rogue-admin creation is core to eCrime).
        4720 => user_mgmt_event("account.created", "User account created", &ed, system_sid),
        4722 => user_mgmt_event("account.enabled", "User account enabled", &ed, system_sid),
        4724 => user_mgmt_event("account.password_reset", "Password reset attempt", &ed, system_sid),
        4725 => user_mgmt_event("account.disabled", "User account disabled", &ed, system_sid),
        4726 => user_mgmt_event("account.deleted", "User account deleted", &ed, system_sid),
        4728 | 4732 | 4756 => Classified::new(
            "account.added_to_privileged_group",
            format!("Member added to security-enabled group {}", ed("TargetUserName").or(ed("GroupName")).unwrap_or_default()),
        )
        .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), ..Default::default() }),
        4738 => user_mgmt_event("account.changed", "User account changed", &ed, system_sid),

        // Service install (System 7045) + service control-manager.
        7045 => Classified::new(
            "service.install",
            format!("Service installed: {} ({})", ed("ServiceName").unwrap_or_default(), ed("ImagePath").unwrap_or_default()),
        )
        .user(Principal { sid: system_sid, ..Default::default() })
        .process(ProcessInfo { path: ed("ImagePath"), command_line: ed("ImagePath"), ..Default::default() })
        .target(Target { path: ed("ServiceName"), ..Default::default() }),
        7040 => Classified::new("service.start_type_changed", "Service start type changed".into())
            .target(Target { path: ed("param1"), ..Default::default() }),
        7036 => Classified::new("service.state_changed", format!("Service state: {}", ed("param1").unwrap_or_default())),

        // Scheduled task auditing (Security 4698/4702) — persistence.
        4698 => Classified::new(
            "persistence.scheduled_task_created",
            format!("Scheduled task created: {}", ed("TaskName").unwrap_or_default()),
        )
        .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), ..Default::default() })
        .target(Target { path: ed("TaskName"), ..Default::default() }),
        4699 => Classified::new("scheduled_task.deleted", format!("Scheduled task deleted: {}", ed("TaskName").unwrap_or_default()))
            .target(Target { path: ed("TaskName"), ..Default::default() }),
        4702 => Classified::new("scheduled_task.updated", format!("Scheduled task updated: {}", ed("TaskName").unwrap_or_default()))
            .target(Target { path: ed("TaskName"), ..Default::default() }),

        // Log tampering / anti-forensics.
        // 1102 / 104 mean "log cleared" ONLY from Microsoft-Windows-Eventlog.
        // Many unrelated providers reuse these ids; matching on the number
        // alone produced hundreds of bogus "log cleared" findings. Other
        // providers' 1102/104 fall through to the generic evtx.eid.N event.
        1102 if prov.contains("eventlog") => Classified::new("defense_evasion.security_log_cleared", "Security event log was CLEARED".into())
            .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserId").or(system_sid), ..Default::default() }),
        104 if prov.contains("eventlog") => Classified::new("defense_evasion.log_cleared", format!("Event log cleared: {}", ed("Channel").unwrap_or_default())),

        // Object access — file shares (lateral movement / staging).
        5140 => Classified::new(
            "network.share_access",
            format!("Network share accessed: {}", ed("ShareName").unwrap_or_default()),
        )
        .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), domain: ed("SubjectDomainName") })
        .network(NetworkInfo { source_ip: ed("IpAddress"), ..Default::default() })
        .target(Target { path: ed("ShareName"), ..Default::default() }),
        5145 => Classified::new(
            "network.share_object_checked",
            format!("Share object access: {}\\{}", ed("ShareName").unwrap_or_default(), ed("RelativeTargetName").unwrap_or_default()),
        )
        .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), ..Default::default() })
        .network(NetworkInfo { source_ip: ed("IpAddress"), ..Default::default() }),

        // RDP / Terminal Services session lifecycle.
        4778 => Classified::new(
            "rdp.session_reconnected",
            format!("RDP session reconnected from {}", ed("ClientAddress").unwrap_or_default()),
        )
        .user(Principal { name: ed("AccountName"), ..Default::default() })
        .network(NetworkInfo { source_ip: ed("ClientAddress"), logon_type: Some(10), ..Default::default() }),
        4779 => Classified::new("rdp.session_disconnected", "RDP session disconnected".into())
            .user(Principal { name: ed("AccountName"), ..Default::default() }),
        21 | 22 | 25 => Classified::new(
            "rdp.session_logon",
            format!("Terminal Services logon from {}", ed("Address").unwrap_or_default()),
        )
        .user(Principal { name: ed("User"), ..Default::default() })
        .network(NetworkInfo { source_ip: ed("Address"), logon_type: Some(10), ..Default::default() }),

        // WMI persistence (WMI-Activity/Operational 5857-5861).
        5857 | 5858 | 5859 | 5860 | 5861 => Classified::new(
            "persistence.wmi_subscription",
            "WMI event-consumer / subscription activity (possible persistence)".into(),
        ),

        // Audit policy tampering.
        4719 => Classified::new("defense_evasion.audit_policy_changed", "System audit policy changed".into())
            .user(Principal { name: ed("SubjectUserName"), sid: ed("SubjectUserSid").or(system_sid), ..Default::default() }),

        _ => Classified::new(
            &format!("evtx.eid.{event_id}"),
            format!("{provider} EventID {event_id}"),
        )
        .user(Principal { sid: system_sid, ..Default::default() }),
    }
}

/// Shared shape for the account-management events.
fn user_mgmt_event(
    action: &str,
    label: &str,
    ed: &dyn Fn(&str) -> Option<String>,
    system_sid: Option<String>,
) -> Classified {
    Classified::new(
        action,
        format!("{label}: {}", ed("TargetUserName").unwrap_or_default()),
    )
    .user(Principal {
        name: ed("SubjectUserName"),
        sid: ed("SubjectUserSid").or(system_sid),
        domain: ed("SubjectDomainName"),
    })
    .target(Target {
        path: ed("TargetUserName"),
        ..Default::default()
    })
}

/// Sysmon operational channel — the richest process/network telemetry when
/// present. IDs per the Sysmon schema.
fn classify_sysmon(
    event_id: u64,
    ed: &dyn Fn(&str) -> Option<String>,
    system_sid: Option<String>,
) -> Classified {
    match event_id {
        1 => {
            let img = ed("Image").unwrap_or_default();
            Classified::new("process.start", format!("Sysmon process create: {img}"))
                .user(Principal { name: ed("User"), ..Default::default() })
                .process(ProcessInfo {
                    name: img.rsplit(['\\', '/']).next().map(str::to_string),
                    path: Some(img),
                    command_line: ed("CommandLine"),
                    hash_sha1: sysmon_sha1(ed),
                    parent_name: ed("ParentImage"),
                    ..Default::default()
                })
        }
        3 => Classified::new(
            "network.connection",
            format!("Sysmon network connection to {}:{}", ed("DestinationIp").unwrap_or_default(), ed("DestinationPort").unwrap_or_default()),
        )
        .user(Principal { name: ed("User"), ..Default::default() })
        .process(ProcessInfo { path: ed("Image"), ..Default::default() })
        .network(NetworkInfo { source_ip: ed("SourceIp"), dest_ip: ed("DestinationIp"), ..Default::default() }),
        7 => Classified::new("process.image_loaded", format!("Sysmon image loaded: {}", ed("ImageLoaded").unwrap_or_default()))
            .process(ProcessInfo { path: ed("Image"), hash_sha1: sysmon_sha1(ed), ..Default::default() })
            .target(Target { path: ed("ImageLoaded"), ..Default::default() }),
        8 => Classified::new(
            "defense_evasion.create_remote_thread",
            format!(
                "Sysmon CreateRemoteThread: {} -> {} (start module {})",
                ed("SourceImage").unwrap_or_else(|| "?".into()),
                ed("TargetImage").unwrap_or_else(|| "?".into()),
                ed("StartModule").unwrap_or_else(|| "?".into())
            ),
        )
            .process(ProcessInfo { path: ed("SourceImage"), ..Default::default() })
            .target(Target { path: ed("TargetImage"), ..Default::default() }),
        10 => Classified::new("credential_access.process_access", format!("Sysmon process access -> {}", ed("TargetImage").unwrap_or_default()))
            .process(ProcessInfo { path: ed("SourceImage"), ..Default::default() })
            .target(Target { path: ed("TargetImage"), ..Default::default() }),
        11 => Classified::new("file.create", format!("Sysmon file created: {}", ed("TargetFilename").unwrap_or_default()))
            .process(ProcessInfo { path: ed("Image"), ..Default::default() })
            .target(Target { path: ed("TargetFilename"), ..Default::default() }),
        12 | 13 | 14 => Classified::new("registry.modified", format!("Sysmon registry event: {}", ed("TargetObject").unwrap_or_default()))
            .process(ProcessInfo { path: ed("Image"), ..Default::default() })
            .target(Target { path: ed("TargetObject"), ..Default::default() }),
        22 => Classified::new("network.dns_query", format!("Sysmon DNS query: {}", ed("QueryName").unwrap_or_default()))
            .process(ProcessInfo { path: ed("Image"), ..Default::default() })
            .target(Target { path: ed("QueryName"), ..Default::default() }),
        23 | 26 => Classified::new("file.delete", format!("Sysmon file delete: {}", ed("TargetFilename").unwrap_or_default()))
            .process(ProcessInfo { path: ed("Image"), ..Default::default() })
            .target(Target { path: ed("TargetFilename"), ..Default::default() }),
        _ => Classified::new(&format!("sysmon.eid.{event_id}"), format!("Sysmon EventID {event_id}"))
            .user(Principal { sid: system_sid, ..Default::default() }),
    }
}

/// Pull the SHA1 out of a Sysmon `Hashes` field like "SHA1=...,MD5=...".
fn sysmon_sha1(ed: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let hashes = ed("Hashes")?;
    hashes.split(',').find_map(|kv| {
        let mut it = kv.splitn(2, '=');
        match (it.next(), it.next()) {
            (Some(k), Some(v)) if k.eq_ignore_ascii_case("SHA1") => Some(v.to_ascii_lowercase()),
            _ => None,
        }
    })
}

/// PowerShell channels. 4104 (script block) carries the actual code; 4103 the
/// pipeline invocation. Both are prime for catching obfuscated/malicious PS.
fn classify_powershell(
    event_id: u64,
    ed: &dyn Fn(&str) -> Option<String>,
    data: &Value,
) -> Classified {
    match event_id {
        4104 => {
            let block = ed("ScriptBlockText")
                .or_else(|| data.pointer("/Event/EventData/ScriptBlockText").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            let preview: String = block.chars().take(120).collect();
            Classified::new("execution.powershell_scriptblock", format!("PowerShell script block: {preview}"))
                // Put the script text on the command line so cmdline rules match it.
                .process(ProcessInfo { name: Some("powershell".into()), command_line: Some(block), ..Default::default() })
        }
        4103 => Classified::new("execution.powershell_pipeline", "PowerShell pipeline execution".into())
            .process(ProcessInfo { name: Some("powershell".into()), command_line: ed("Payload").or_else(|| ed("CommandLine")), ..Default::default() }),
        400 | 403 => Classified::new("execution.powershell_engine", format!("PowerShell engine state: {}", ed("NewEngineState").unwrap_or_default())),
        _ => Classified::new(&format!("powershell.eid.{event_id}"), format!("PowerShell EventID {event_id}")),
    }
}

/// Windows Defender operational channel — detections and, critically for eCrime,
/// tampering (real-time protection disabled, exclusions added).
fn classify_defender(event_id: u64, ed: &dyn Fn(&str) -> Option<String>) -> Classified {
    match event_id {
        1116 | 1015 => Classified::new(
            "malware.detected",
            format!("Defender detection: {}", ed("Threat Name").or(ed("ThreatName")).unwrap_or_default()),
        )
        .target(Target { path: ed("Path").or(ed("Process Name")), ..Default::default() }),
        1117 => Classified::new("malware.action_taken", format!("Defender action on: {}", ed("Threat Name").unwrap_or_default())),
        5001 => Classified::new("defense_evasion.defender_rtp_disabled", "Defender real-time protection DISABLED".into()),
        // 5007 fires on every Defender setting change, including routine
        // platform/signature updates. Only exclusions and protection being
        // switched off are tampering; everything else is ordinary config noise.
        5007 => {
            let new_val = ed("New Value").or(ed("NewValue")).unwrap_or_default();
            let lc = new_val.to_ascii_lowercase();
            if lc.contains("\\exclusions\\") {
                Classified::new("defense_evasion.defender_exclusion_added", format!("Defender exclusion added: {new_val}"))
            } else if lc.contains("disablerealtimemonitoring = 0x1")
                || lc.contains("disableantispyware = 0x1")
                || lc.contains("disablebehaviormonitoring = 0x1")
                || lc.contains("disableioavprotection = 0x1")
                || lc.contains("tamperprotection = 0x0")
            {
                Classified::new("defense_evasion.defender_protection_disabled", format!("Defender protection disabled: {new_val}"))
            } else {
                Classified::new("defender.config_changed", format!("Defender configuration changed: {new_val}"))
            }
        }
        1006 | 1007 => Classified::new("malware.detected", "Defender malware behaviour detected".into()),
        _ => Classified::new(&format!("defender.eid.{event_id}"), format!("Defender EventID {event_id}")),
    }
}

/// ScreenConnect client events. EventData/Data may be a string, an object with
/// `#text`, or an array of strings; flatten it and classify on the text.
fn classify_screenconnect(provider: &str, data: &Value) -> Classified {
    let text = match data.pointer("/Event/EventData/Data") {
        Some(Value::Array(a)) => a.iter().filter_map(value_to_string).collect::<Vec<_>>().join(" | "),
        Some(v) => value_to_string(v).unwrap_or_default(),
        None => String::new(),
    };
    let lc = text.to_ascii_lowercase();
    let action = if lc.contains("transferred files") || lc.contains("file transfer") {
        "remote_access.file_transfer"
    } else if lc.contains("executed command") || lc.contains("ran command") {
        "remote_access.command"
    } else if lc.contains("disconnected") {
        "remote_access.session_end"
    } else if lc.contains("connected") {
        "remote_access.session_incoming"
    } else {
        "remote_access.screenconnect"
    };
    let short: String = text.chars().take(200).collect();
    Classified::new(action, format!("ScreenConnect: {short}"))
        .process(ProcessInfo { name: Some("ScreenConnect.ClientService.exe".into()), ..Default::default() })
        .target(Target { value_name: Some(provider.to_string()), ..Default::default() })
}
