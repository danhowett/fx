//! Lateral movement: which account connected from which machine to which, and
//! how, built from the logon / RDP / share / explicit-credential events already
//! in the case.
//!
//! Each row is one piece of evidence for a connection, seen either on the
//! destination (an inbound logon with a source address) or on the source (an
//! outbound connection: explicit credentials, RDP client history). The GUI
//! groups rows into connections. Source addresses are matched to machines in
//! the case where possible:
//!   * names: a case host's name, or its SYSTEM-hive computer name;
//!   * addresses: a case host's registry interface IPs, and addresses that
//!     logons tie to a workstation name (4624 IpAddress + WorkstationName).
//! Nothing is invented: an address that can't be matched is shown as-is.

use crate::{CaseStore, StoreError};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct LateralEvent {
    /// The event this row comes from (pivot target).
    pub event_id: String,
    /// UTC, `YYYY-MM-DDTHH:MM:SS`.
    pub ts: String,
    /// Connecting machine: a case host name when matched, else the
    /// workstation name or address from the record.
    pub src: String,
    /// True when `src` is a host in this case.
    pub src_in_case: bool,
    /// The address the record gave for the source, if any.
    pub src_addr: Option<String>,
    /// Machine connected to (a case host name when matched).
    pub dst: String,
    pub dst_in_case: bool,
    /// Account used (`DOMAIN\user` when the domain is known).
    pub account: String,
    /// RDP | Network logon | Share access | Explicit credentials.
    pub method: String,
    /// Logon failed (4625): attempts, not access.
    pub failed: bool,
    /// The host whose logs recorded this row (source or destination side).
    pub seen_on: String,
    /// "destination" or "source": which end of the connection logged it.
    pub side: String,
    /// The event's action and message, for the evidence list.
    pub action: String,
    pub message: String,
}

/// Raw candidate row from SQL.
struct Cand {
    id: String,
    ts: String,
    host: String,
    action: String,
    user: Option<String>,
    domain: Option<String>,
    src_ip: Option<String>,
    logon_type: Option<i64>,
    workstation: Option<String>,
    target_server: Option<String>,
    target_user: Option<String>,
    target_domain: Option<String>,
    process: Option<String>,
    rdp_host: Option<String>,
    message: String,
}

fn short(name: &str) -> String {
    name.trim()
        .trim_start_matches("\\\\")
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase()
}

fn is_local_addr(a: &str) -> bool {
    matches!(
        a,
        "" | "-" | "127.0.0.1" | "::1" | "0:0:0:0:0:0:0:1" | "LOCAL" | "0.0.0.0"
    )
}

fn is_noise_account(u: &str) -> bool {
    let l = u.to_ascii_lowercase();
    u.ends_with('$')
        || l == "anonymous logon"
        || l == "system"
        || l == "local service"
        || l == "network service"
        || l.starts_with("dwm-")
        || l.starts_with("umfd-")
}

impl CaseStore {
    pub fn lateral_movement(&self) -> Result<Vec<LateralEvent>, StoreError> {
        let c = self.connection();

        // Names of machines in the case: each collection host, plus the
        // computer name its SYSTEM hive gives.
        let mut name_to_host: HashMap<String, String> = HashMap::new();
        {
            let mut st =
                c.prepare("SELECT DISTINCT host FROM collections WHERE host IS NOT NULL")?;
            for h in st.query_map([], |r| r.get::<_, String>(0))? {
                let h = h?;
                name_to_host.insert(short(&h), h);
            }
            let mut st = c.prepare(
                "SELECT host, json_extract_string(raw, '$.value') FROM events
                 WHERE action = 'host.computer_name' AND host IS NOT NULL",
            )?;
            for r in st.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })? {
                let (h, n) = r?;
                if let Some(n) = n.filter(|n| !n.trim().is_empty()) {
                    name_to_host.entry(short(&n)).or_insert(h);
                }
            }
        }
        let resolve_name = |n: &str| -> Option<String> { name_to_host.get(&short(n)).cloned() };

        // Addresses of machines in the case, from their registry interfaces.
        let mut ip_to_host: HashMap<String, String> = HashMap::new();
        {
            let mut st = c.prepare(
                "SELECT host, json_extract_string(raw, '$.ip') FROM events
                 WHERE action = 'host.interface' AND host IS NOT NULL",
            )?;
            for r in st.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })? {
                let (h, ip) = r?;
                if let Some(ip) = ip.filter(|i| !is_local_addr(i)) {
                    ip_to_host.insert(ip, h);
                }
            }
        }

        let mut st = c.prepare(
            "SELECT CAST(id AS VARCHAR), strftime(ts, '%Y-%m-%dT%H:%M:%S'), COALESCE(host, ''),
                    action, user_name, user_domain, src_ip, logon_type,
                    json_extract_string(raw, '/Event/EventData/WorkstationName'),
                    json_extract_string(raw, '/Event/EventData/TargetServerName'),
                    json_extract_string(raw, '/Event/EventData/TargetUserName'),
                    json_extract_string(raw, '/Event/EventData/TargetDomainName'),
                    COALESCE(json_extract_string(raw, '/Event/EventData/ProcessName'), process_path),
                    json_extract_string(raw, '$.host'),
                    message
             FROM events
             WHERE ts IS NOT NULL AND action IN (
                 'logon.success', 'logon.failure', 'logon.explicit_credentials',
                 'rdp.session_logon', 'rdp.session_reconnected', 'rdp.auth_succeeded',
                 'network.share_access', 'lateral_movement.rdp_outbound')
             ORDER BY ts",
        )?;
        let cands: Vec<Cand> = st
            .query_map([], |r| {
                Ok(Cand {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    host: r.get(2)?,
                    action: r.get(3)?,
                    user: r.get(4)?,
                    domain: r.get(5)?,
                    src_ip: r.get(6)?,
                    logon_type: r.get(7)?,
                    workstation: r.get(8)?,
                    target_server: r.get(9)?,
                    target_user: r.get(10)?,
                    target_domain: r.get(11)?,
                    process: r.get(12)?,
                    rdp_host: r.get(13)?,
                    message: r.get(14)?,
                })
            })?
            .collect::<Result<_, _>>()?;

        // Addresses that logons tie to a workstation name: a host in the case
        // where the name matches one, otherwise the outside machine's name.
        let mut ip_to_name: HashMap<String, String> = HashMap::new();
        for k in &cands {
            if let (Some(ip), Some(ws)) = (&k.src_ip, &k.workstation) {
                let ws = ws.trim();
                if is_local_addr(ip) || ws.is_empty() || ws == "-" {
                    continue;
                }
                if ip_to_host.contains_key(ip) {
                    continue;
                }
                match resolve_name(ws) {
                    Some(h) => {
                        ip_to_host.insert(ip.clone(), h);
                    }
                    None => {
                        ip_to_name.entry(ip.clone()).or_insert_with(|| short(ws));
                    }
                }
            }
        }

        let account = |user: &Option<String>, domain: &Option<String>| -> Option<String> {
            let u = user
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty() && *u != "-")?;
            Some(
                match domain
                    .as_deref()
                    .map(str::trim)
                    .filter(|d| !d.is_empty() && *d != "-")
                {
                    Some(d) => format!("{}\\{u}", d.to_ascii_uppercase()),
                    None => u.to_string(),
                },
            )
        };

        let mut out = Vec::new();
        for k in cands {
            let dst_side = matches!(
                k.action.as_str(),
                "logon.success"
                    | "logon.failure"
                    | "rdp.session_logon"
                    | "rdp.session_reconnected"
                    | "rdp.auth_succeeded"
                    | "network.share_access"
            );
            if dst_side {
                // Inbound: only remote logon types for logon events.
                let lt = k.logon_type.unwrap_or(0);
                if k.action.starts_with("logon.") && !(lt == 3 || lt == 10) {
                    continue;
                }
                let Some(acct) = account(&k.user, &k.domain) else {
                    continue;
                };
                let bare = acct.rsplit('\\').next().unwrap_or(&acct).to_string();
                if is_noise_account(&bare) {
                    continue;
                }
                let addr = k.src_ip.clone().filter(|a| !is_local_addr(a));
                let ws = k
                    .workstation
                    .clone()
                    .filter(|w| !w.trim().is_empty() && w != "-");
                let (src, src_in_case) = match addr.as_ref().and_then(|a| ip_to_host.get(a)) {
                    Some(h) => (h.clone(), true),
                    None => match ws.as_deref().and_then(resolve_name) {
                        Some(h) => (h, true),
                        None => match (&ws, &addr) {
                            (Some(w), _) => (short(w), false),
                            (None, Some(a)) => match ip_to_name.get(a) {
                                Some(n) => (n.clone(), false),
                                None => (a.clone(), false),
                            },
                            (None, None) => continue,
                        },
                    },
                };
                if src_in_case && src == k.host {
                    continue; // the machine talking to itself
                }
                let method = if k.action == "network.share_access" {
                    "Share access"
                } else if k.action.starts_with("rdp.") || lt == 10 {
                    "RDP"
                } else {
                    "Network logon"
                };
                out.push(LateralEvent {
                    event_id: k.id,
                    ts: k.ts,
                    src,
                    src_in_case,
                    src_addr: addr,
                    dst: k.host.clone(),
                    dst_in_case: true,
                    account: acct,
                    method: method.into(),
                    failed: k.action == "logon.failure",
                    seen_on: k.host,
                    side: "destination".into(),
                    action: k.action,
                    message: k.message,
                });
            } else if k.action == "logon.explicit_credentials" {
                // Outbound: this host used other credentials against a server.
                let Some(target) = k.target_server.clone().filter(|t| {
                    let s = short(t);
                    !s.is_empty() && s != "LOCALHOST" && s != "-" && s != short(&k.host)
                }) else {
                    continue;
                };
                let Some(acct) = account(&k.target_user, &k.target_domain) else {
                    continue;
                };
                if is_noise_account(acct.rsplit('\\').next().unwrap_or(&acct)) {
                    continue;
                }
                let (dst, dst_in_case) = match resolve_name(&target) {
                    Some(h) => (h, true),
                    None => (short(&target), false),
                };
                let proc = k.process.unwrap_or_default().to_ascii_lowercase();
                let method = if proc.ends_with("mstsc.exe") {
                    "RDP"
                } else {
                    "Explicit credentials"
                };
                out.push(LateralEvent {
                    event_id: k.id,
                    ts: k.ts,
                    src: k.host.clone(),
                    src_in_case: true,
                    src_addr: None,
                    dst,
                    dst_in_case,
                    account: acct,
                    method: method.into(),
                    failed: false,
                    seen_on: k.host,
                    side: "source".into(),
                    action: k.action,
                    message: k.message,
                });
            } else if k.action == "lateral_movement.rdp_outbound" {
                // RDP client history (NTUSER): a server this user connected to.
                let Some(target) = k.rdp_host.clone().filter(|t| !t.trim().is_empty()) else {
                    continue;
                };
                let (dst, dst_in_case) = match resolve_name(&target)
                    .or_else(|| ip_to_host.get(target.trim()).cloned())
                {
                    Some(h) => (h, true),
                    None => (target.trim().to_string(), false),
                };
                if dst_in_case && dst == k.host {
                    continue;
                }
                out.push(LateralEvent {
                    event_id: k.id,
                    ts: k.ts,
                    src: k.host.clone(),
                    src_in_case: true,
                    src_addr: None,
                    dst,
                    dst_in_case,
                    account: account(&k.user, &k.domain).unwrap_or_else(|| "(user profile)".into()),
                    method: "RDP".into(),
                    failed: false,
                    seen_on: k.host,
                    side: "source".into(),
                    action: k.action,
                    message: k.message,
                });
            }
        }
        Ok(out)
    }
}
