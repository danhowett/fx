//! End-to-end store test that doesn't require real artefact binaries: create a
//! case, write events directly through the EventWriter, and read them back via
//! the query API. Proves schema + batched writer + read side agree.

use fx_core::{ArtefactKind, Event, EventSink, Provenance, Target, TimestampKind};
use fx_store::query::TimelineFilter;
use fx_store::CaseStore;
use time::OffsetDateTime;
use uuid::Uuid;

fn sample_event(evidence_id: Uuid, action: &str, path: &str) -> Event {
    Event {
        id: Uuid::new_v4(),
        timestamp: OffsetDateTime::now_utc(),
        timestamp_kind: TimestampKind::Executed,
        artefact: ArtefactKind::Prefetch,
        action: action.to_string(),
        host: Some("WORKSTATION01".into()),
        user: Default::default(),
        process: None,
        target: Some(Target { path: Some(path.into()), ..Default::default() }),
        network: None,
        message: format!("{action}: {path}"),
        provenance: Provenance {
            evidence_id,
            source_path: "test/artefact".into(),
            parser: "test".into(),
            parser_version: "0".into(),
            source_ref: None,
        },
        raw: serde_json::json!({"path": path}),
    }
}

#[test]
fn create_write_read_roundtrip() {
    let dir = std::env::temp_dir().join(format!("fxcase-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let case_path = dir.join("test.fxcase");

    let store = CaseStore::create(&case_path, "Test case", Some("analyst"), "UTC").unwrap();
    let evid = Uuid::new_v4();

    {
        let mut writer = store.event_writer();
        for i in 0..10 {
            writer.emit(sample_event(evid, "process.execute", &format!("C:/tmp/tool{i}.exe")));
        }
        writer.flush().unwrap();
    }
    store.build_indexes().unwrap();

    assert_eq!(store.event_count().unwrap(), 10);

    let rows = store
        .timeline(&TimelineFilter { text: Some("tool3".into()), ..Default::default() })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].target_path.as_deref().unwrap().contains("tool3"));

    let by_artefact = store.counts_by_artefact().unwrap();
    assert_eq!(by_artefact[0].0, "Prefetch");
    assert_eq!(by_artefact[0].1, 10);
}

#[test]
fn local_time_events_convert_with_host_rule() {
    use fx_core::tz::{Transition, TzRule};
    let dir = std::env::temp_dir().join(format!("fxcase-tz-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = CaseStore::create(&dir.join("t.fxcase"), "tz", None, "UTC").unwrap();
    let evid = Uuid::new_v4();
    let rule = TzRule {
        name: Some("GMT Standard Time".into()),
        bias: 0,
        standard_bias: 0,
        daylight_bias: -60,
        standard_start: Some(Transition { year: 0, month: 10, day_of_week: 0, day: 5, hour: 2, minute: 0 }),
        daylight_start: Some(Transition { year: 0, month: 3, day_of_week: 0, day: 5, hour: 1, minute: 0 }),
    };
    let mut tz = sample_event(evid, "host.timezone", "SYSTEM");
    tz.raw = serde_json::json!({"fact": "timezone", "control_set": "ControlSet001", "rule": rule});
    let mut usb = sample_event(evid, "device.first_install", "USBSTOR\\Disk");
    usb.timestamp = time::macros::datetime!(2024-07-01 12:00:00 UTC); // as logged, BST
    usb.raw = serde_json::json!({"time_basis": "host local time (as logged)"});
    let usb_id = usb.id;
    let mut utc_ev = sample_event(evid, "process.execute", "C:/x.exe");
    utc_ev.timestamp = time::macros::datetime!(2024-07-01 12:00:00 UTC);
    let utc_id = utc_ev.id;
    {
        let mut w = store.event_writer();
        w.emit(tz);
        w.emit(usb);
        w.emit(utc_ev);
        w.flush().unwrap();
    }
    let r = store.host_tz_rule().unwrap().expect("rule");
    assert_eq!(r.daylight_bias, -60);
    assert_eq!(store.convert_local_times(&r).unwrap(), 1);
    let got = store.events_by_ids(&[usb_id.to_string(), utc_id.to_string()]).unwrap();
    let ts = |id: Uuid| got.iter().find(|e| e.id == id.to_string()).unwrap().ts.clone();
    assert!(ts(usb_id).starts_with("2024-07-01T11:00:00"), "{}", ts(usb_id));
    assert!(ts(utc_id).starts_with("2024-07-01T12:00:00"), "{}", ts(utc_id));
    // Second pass is a no-op (the event is now marked as converted).
    assert_eq!(store.convert_local_times(&r).unwrap(), 0);
}
