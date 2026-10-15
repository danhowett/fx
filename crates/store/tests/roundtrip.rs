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
