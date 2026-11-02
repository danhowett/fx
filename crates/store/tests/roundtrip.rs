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
        target: Some(Target {
            path: Some(path.into()),
            ..Default::default()
        }),
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
            writer.emit(sample_event(
                evid,
                "process.execute",
                &format!("C:/tmp/tool{i}.exe"),
            ));
        }
        writer.flush().unwrap();
    }
    store.build_indexes().unwrap();

    assert_eq!(store.event_count().unwrap(), 10);

    let rows = store
        .timeline(&TimelineFilter {
            text: Some("tool3".into()),
            ..Default::default()
        })
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
        standard_start: Some(Transition {
            year: 0,
            month: 10,
            day_of_week: 0,
            day: 5,
            hour: 2,
            minute: 0,
        }),
        daylight_start: Some(Transition {
            year: 0,
            month: 3,
            day_of_week: 0,
            day: 5,
            hour: 1,
            minute: 0,
        }),
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
    let r = store.host_tz_rule(None).unwrap().expect("rule");
    assert_eq!(r.daylight_bias, -60);
    assert_eq!(store.convert_local_times(&r, None).unwrap(), 1);
    let got = store
        .events_by_ids(&[usb_id.to_string(), utc_id.to_string()])
        .unwrap();
    let ts = |id: Uuid| {
        got.iter()
            .find(|e| e.id == id.to_string())
            .unwrap()
            .ts
            .clone()
    };
    assert!(
        ts(usb_id).starts_with("2024-07-01T11:00:00"),
        "{}",
        ts(usb_id)
    );
    assert!(
        ts(utc_id).starts_with("2024-07-01T12:00:00"),
        "{}",
        ts(utc_id)
    );
    // Second pass is a no-op (the event is now marked as converted).
    assert_eq!(store.convert_local_times(&r, None).unwrap(), 0);
}

#[test]
fn any_text_filter_pages_through_every_match() {
    let dir = std::env::temp_dir().join(format!("fxcase-any-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = CaseStore::create(&dir.join("a.fxcase"), "any", None, "UTC").unwrap();
    let evid = Uuid::new_v4();
    {
        let mut w = store.event_writer();
        for i in 0..1200 {
            let mut e = sample_event(evid, "process.execute", &format!("C:/tmp/tool{i}.exe"));
            if i % 2 == 0 {
                e.raw = serde_json::json!({"note": "contains EvilMarker in raw only"});
            }
            w.emit(e);
        }
        w.flush().unwrap();
    }
    let f = |offset| TimelineFilter {
        any_text: vec!["evilmarker".into()],
        limit: 500,
        offset,
        ..Default::default()
    };
    assert_eq!(
        store.count_timeline(&f(0)).unwrap(),
        600,
        "raw-only matches are found"
    );
    assert_eq!(store.timeline(&f(0)).unwrap().len(), 500);
    assert_eq!(
        store.timeline(&f(500)).unwrap().len(),
        100,
        "matches beyond 500 reachable by paging"
    );
    let none = TimelineFilter {
        any_text: vec!["nothing-here".into()],
        ..Default::default()
    };
    assert_eq!(store.count_timeline(&none).unwrap(), 0);
}

/// Register a tiny real file as evidence (the store hashes it).
fn register(store: &CaseStore, dir: &std::path::Path, name: &str) -> Uuid {
    let path = dir.join(name);
    std::fs::write(&path, name.as_bytes()).unwrap();
    let a = fx_core::IdentifiedArtefact {
        evidence_id: Uuid::new_v4(),
        path,
        source_path: name.into(),
        container: fx_core::ContainerFormat::Evtx,
        artefact: ArtefactKind::Evtx,
        method: fx_core::IdMethod::Content,
        confidence: 1.0,
        profile_hint: None,
    };
    store.register_evidence(&a).unwrap()
}

#[test]
fn two_collections_become_two_hosts() {
    let dir = std::env::temp_dir().join(format!("fxcase-mh-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = CaseStore::create(&dir.join("mh.fxcase"), "MH", None, "UTC").unwrap();

    // Collection 1: named by its SYSTEM hive.
    let c1 = store.begin_collection("D:/cases/WKSTN-07").unwrap();
    let ev1 = register(&store, &dir, "a.evtx");
    {
        let mut w = store.event_writer();
        let mut name = sample_event(ev1, "host.computer_name", "SYSTEM");
        name.raw = serde_json::json!({"value": "WKSTN-07", "control_set": "ControlSet001"});
        w.emit(name);
        for i in 0..3 {
            w.emit(sample_event(
                ev1,
                "process.execute",
                &format!("C:/a{i}.exe"),
            ));
        }
        w.flush().unwrap();
    }
    store.claim_unassigned(&c1).unwrap();
    assert_eq!(
        store.name_collection_host(&c1, None).unwrap(),
        ("WKSTN-07".to_string(), false)
    );

    // The same folder can't be added twice.
    assert!(store.begin_collection("d:\\cases\\WKSTN-07\\").is_err());

    // Collection 2: no hive, so the EVTX Computer value names it.
    let c2 = store.begin_collection("D:/cases/dc").unwrap();
    let ev2 = register(&store, &dir, "b.evtx");
    let mut dc_event = Uuid::nil();
    {
        let mut w = store.event_writer();
        for i in 0..5 {
            let mut e = sample_event(ev2, "process.execute", &format!("C:/b{i}.exe"));
            dc_event = e.id;
            e.artefact = ArtefactKind::Evtx;
            e.host = Some("SRV-DC01.corp.example".into());
            w.emit(e);
        }
        w.flush().unwrap();
    }
    store.claim_unassigned(&c2).unwrap();
    let (h2, merged) = store.name_collection_host(&c2, None).unwrap();
    assert_eq!(h2, "SRV-DC01");
    assert!(!merged);
    store.build_indexes().unwrap();

    let hosts = store.hosts().unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].host, "WKSTN-07");
    assert_eq!(hosts[0].events, 4);
    assert_eq!(hosts[1].events, 5);

    // Scoped summaries see one host; the whole case sees both.
    assert_eq!(store.event_count().unwrap(), 9);
    assert_eq!(
        store
            .scoped(Some("SRV-DC01".into()), |s| s.event_count())
            .unwrap(),
        5
    );
    assert_eq!(
        store
            .scoped(Some("SRV-DC01".into()), |s| s.evidence_list())
            .unwrap()
            .len(),
        1
    );
    let f = TimelineFilter {
        host: Some("WKSTN-07".into()),
        limit: 100,
        ..Default::default()
    };
    assert_eq!(store.count_timeline(&f).unwrap(), 4);

    // A finding made before the host was named (e.g. an earlier Sigma run)
    // carries a stale host; it is re-attributed from its event.
    store
        .replace_sigma_detections(&[fx_core::Detection {
            id: Uuid::new_v4(),
            rule_id: "sigma:x".into(),
            title: "x".into(),
            severity: fx_core::Severity::Medium,
            attack: vec![],
            summary: "x".into(),
            event_ids: vec![dc_event],
            timestamp: OffsetDateTime::now_utc(),
            host: Some("SRV-DC01.corp.example".into()),
            engine: fx_core::DetectionEngine::Sigma,
        }])
        .unwrap();
    store.sync_detection_hosts().unwrap();
    assert_eq!(
        store.detections().unwrap()[0].host.as_deref(),
        Some("SRV-DC01")
    );

    // Rename moves events, collections and findings together.
    store.rename_host("SRV-DC01", "DC01").unwrap();
    let f = TimelineFilter {
        host: Some("DC01".into()),
        limit: 100,
        ..Default::default()
    };
    assert_eq!(store.count_timeline(&f).unwrap(), 5);
    assert_eq!(store.hosts().unwrap()[1].host, "DC01");
    assert_eq!(store.detections().unwrap()[0].host.as_deref(), Some("DC01"));
}

#[test]
fn older_case_gets_a_legacy_collection_before_another_is_added() {
    let dir = std::env::temp_dir().join(format!("fxcase-legacy-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = CaseStore::create(&dir.join("old.fxcase"), "Old", None, "UTC").unwrap();
    let ev = register(&store, &dir, "old.evtx");
    {
        let mut w = store.event_writer();
        w.emit(sample_event(ev, "process.execute", "C:/x.exe"));
        w.flush().unwrap();
    }
    // No collection rows yet (as in a case made before multi-host).
    assert!(store.hosts().unwrap().is_empty());
    store.ensure_legacy_collection().unwrap();
    let hosts = store.hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].events, 1);
    // A new collection doesn't claim the old evidence.
    let c = store.begin_collection("D:/next").unwrap();
    store.claim_unassigned(&c).unwrap();
    assert_eq!(
        store
            .scoped(Some(hosts[0].host.clone()), |s| s.evidence_list())
            .unwrap()
            .len(),
        1
    );
}
