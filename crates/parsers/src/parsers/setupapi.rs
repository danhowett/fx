//! Device installation log — `C:\Windows\INF\setupapi.dev.log`.
//!
//! Each device Windows installs a driver for gets a section:
//!
//! ```text
//! >>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C53000123&0]
//! >>>  Section start 2024/05/01 10:11:12.345
//! ```
//!
//! The section start is the **first time** that device was connected to this
//! host — the classic USB-history anchor that pairs with the USBSTOR registry
//! keys. Times in this log are the host's **local time**, not UTC; fx records
//! them as written and says so in the raw record.
//!
//! Only removable / USB-class devices are emitted (USBSTOR, USB\VID_…, portable
//! devices via WPDBUSENUM, and SCSI disks that are USB-attached); the rest of
//! the log (every driver on the box) is noise for triage.

use fx_core::{
    ArtefactKind, Event, EventSink, IdentifiedArtefact, ParseError, ParseOutcome, Parser, Principal,
    Provenance, Target, TimestampKind,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct SetupApiParser;

#[derive(Debug, Clone)]
pub struct DeviceInstall {
    pub ts: OffsetDateTime,
    pub device_id: String,
    pub kind: &'static str,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub line: usize,
}

fn classify(id: &str) -> Option<&'static str> {
    let u = id.to_ascii_uppercase();
    if u.starts_with("USBSTOR\\") {
        Some("usb_storage")
    } else if u.contains("WPDBUSENUM") || u.starts_with("SWD\\WPDBUSENUM") {
        Some("portable_device")
    } else if u.starts_with("USB\\VID_") {
        Some("usb_device")
    } else if u.starts_with("SCSI\\DISK") && u.contains("USB") {
        Some("usb_storage")
    } else {
        None
    }
}

/// Vendor / product / serial from a USBSTOR id:
/// `USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\SERIAL&0`.
fn usbstor_parts(id: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut parts = id.split('\\');
    let _bus = parts.next();
    let desc = parts.next().unwrap_or("");
    let serial = parts.next().map(|s| s.split('&').next().unwrap_or(s).to_string()).filter(|s| !s.is_empty());
    let field = |pfx: &str| {
        desc.split('&')
            .find(|f| f.len() > pfx.len() && f[..pfx.len()].eq_ignore_ascii_case(pfx))
            .map(|f| f[pfx.len()..].replace('_', " ").trim().to_string())
            .filter(|s| !s.is_empty())
    };
    (field("Ven_"), field("Prod_"), serial)
}

pub fn parse_text(text: &str) -> Vec<DeviceInstall> {
    let mut out = Vec::new();
    let mut pending: Option<(String, &'static str, usize)> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(">>>") {
            let rest = rest.trim();
            if rest.starts_with('[') && rest.to_ascii_lowercase().contains("device install") {
                pending = rest
                    .trim_end_matches(']')
                    .rsplit_once(" - ")
                    .map(|(_, id)| id.trim().to_string())
                    .and_then(|id| classify(&id).map(|k| (id, k, i + 1)));
                continue;
            }
            if let Some(ts_s) = rest.strip_prefix("Section start") {
                if let Some((id, kind, line_no)) = pending.take() {
                    let norm = ts_s.trim().replacen('/', "-", 2);
                    if let (Some(ts), _) = crate::parsers::defender_log::leading_timestamp(&norm) {
                        let (vendor, product, serial) = if kind == "usb_storage" { usbstor_parts(&id) } else { (None, None, None) };
                        let serial = serial.or_else(|| id.rsplit('\\').next().map(str::to_string));
                        out.push(DeviceInstall { ts, device_id: id, kind, vendor, product, serial, line: line_no });
                    }
                }
            }
        } else if t.starts_with("[") && !t.starts_with("[Boot") {
            pending = None;
        }
    }
    out
}

impl Parser for SetupApiParser {
    fn name(&self) -> &'static str {
        "setupapi"
    }

    fn handles(&self) -> &'static [ArtefactKind] {
        &[ArtefactKind::SetupApi]
    }

    fn parse(&self, artefact: &IdentifiedArtefact, sink: &mut dyn EventSink) -> Result<ParseOutcome, ParseError> {
        let text = crate::parsers::text_decode::read_text_file(&artefact.path)
            .map_err(|e| ParseError::Io { path: artefact.path.display().to_string(), source: e })?;
        let mut outcome = ParseOutcome::default();
        for d in parse_text(&text) {
            outcome.records_read += 1;
            let what = match (&d.vendor, &d.product) {
                (Some(v), Some(p)) => format!("{v} {p}"),
                (None, Some(p)) => p.clone(),
                _ => d.device_id.clone(),
            };
            let label = match d.kind {
                "usb_storage" => "USB storage",
                "portable_device" => "Portable device",
                _ => "USB device",
            };
            sink.emit(Event {
                id: Uuid::new_v4(),
                timestamp: d.ts,
                timestamp_kind: TimestampKind::Created,
                artefact: ArtefactKind::SetupApi,
                action: "device.first_install".into(),
                host: None,
                user: Principal::default(),
                process: None,
                target: Some(Target { path: Some(d.device_id.clone()), value_name: None, hash_sha1: None, size: None }),
                network: None,
                message: format!(
                    "{label} first connected: {what}{} (host local time)",
                    d.serial.as_deref().map(|s| format!(", serial {s}")).unwrap_or_default()
                ),
                provenance: Provenance {
                    evidence_id: artefact.evidence_id,
                    source_path: artefact.source_path.clone(),
                    parser: "setupapi".into(),
                    parser_version: env!("CARGO_PKG_VERSION").into(),
                    source_ref: Some(format!("line {}", d.line)),
                },
                raw: json!({ "device_id": d.device_id, "device_class": d.kind, "vendor": d.vendor, "product": d.product,
                             "serial": d.serial, "time_note": "setupapi.dev.log times are the host's local time, recorded as written (not converted to UTC)" }),
            });
            outcome.events_emitted += 1;
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_sections() {
        let t = "[Device Install Log]\n     OS Version = 10.0.19045\n\
>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001231114117284&0]\n\
>>>  Section start 2024/05/01 10:11:12.345\n     dvi: something\n<<<  Section end 2024/05/01 10:11:15.000\n\
>>>  [Device Install (Hardware initiated) - PCI\\VEN_8086&DEV_1234\\3&11583659&0&10]\n\
>>>  Section start 2024/05/01 10:12:00.000\n\
>>>  [Device Install (Hardware initiated) - SWD\\WPDBUSENUM\\_??_USBSTOR#Disk&Ven_SanDisk#4C53&0#{53f56307}]\n\
>>>  Section start 2024/05/01 10:11:20.000\n";
        let r = parse_text(t);
        assert_eq!(r.len(), 2, "PCI device skipped");
        assert_eq!(r[0].vendor.as_deref(), Some("SanDisk"));
        assert_eq!(r[0].product.as_deref(), Some("Ultra"));
        assert_eq!(r[0].serial.as_deref(), Some("4C530001231114117284"));
        assert_eq!(r[0].ts.minute(), 11);
        assert_eq!(r[1].kind, "portable_device");
    }
}
