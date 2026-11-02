//! The case report for a multi-host case: a Hosts summary, per-host counts,
//! and a one-host report that covers only that host.
//! Set FX_REPORT_OUT=<dir> to keep the generated HTML for a visual check.

use fx_core::{
    ArtefactKind, ContainerFormat, Detection, DetectionEngine, Event, EventSink, IdMethod,
    IdentifiedArtefact, Provenance, Severity, TimestampKind,
};
use fx_store::CaseStore;
use time::OffsetDateTime;
use uuid::Uuid;

fn event(evidence_id: Uuid, host: &str, msg: &str) -> Event {
    Event {
        id: Uuid::new_v4(),
        timestamp: OffsetDateTime::now_utc(),
        timestamp_kind: TimestampKind::Executed,
        artefact: ArtefactKind::Evtx,
        action: "process.execute".into(),
        host: Some(host.into()),
        user: Default::default(),
        process: None,
        target: None,
        network: None,
        message: msg.into(),
        provenance: Provenance {
            evidence_id,
            source_path: "Security.evtx".into(),
            parser: "test".into(),
            parser_version: "0".into(),
            source_ref: None,
        },
        raw: serde_json::json!({}),
    }
}

fn det(rule: &str, sev: Severity, ev: Uuid, host: &str) -> Detection {
    Detection {
        id: Uuid::new_v4(),
        rule_id: rule.into(),
        title: format!("Rule {rule}"),
        severity: sev,
        attack: vec!["T1059.001".into()],
        summary: format!("{rule} on {host}"),
        event_ids: vec![ev],
        timestamp: OffsetDateTime::now_utc(),
        host: Some(host.into()),
        engine: DetectionEngine::SingleEvent,
    }
}

/// One collection with `n` events, named `host`. Returns an event id.
fn add_host(store: &CaseStore, dir: &std::path::Path, host: &str, n: usize) -> Uuid {
    let c = store.begin_collection(&format!("D:/cases/{host}")).unwrap();
    let path = dir.join(format!("{host}.evtx"));
    std::fs::write(&path, host.as_bytes()).unwrap();
    let ev = store
        .register_evidence(&IdentifiedArtefact {
            evidence_id: Uuid::new_v4(),
            path,
            source_path: format!("{host}/Security.evtx"),
            container: ContainerFormat::Evtx,
            artefact: ArtefactKind::Evtx,
            method: IdMethod::Content,
            confidence: 1.0,
            profile_hint: None,
        })
        .unwrap();
    let mut first = Uuid::nil();
    {
        let mut w = store.event_writer();
        for i in 0..n {
            let e = event(ev, host, &format!("event {i}"));
            if i == 0 {
                first = e.id;
            }
            w.emit(e);
        }
        w.flush().unwrap();
    }
    store.claim_unassigned(&c).unwrap();
    store.name_collection_host(&c, Some(host)).unwrap();
    first
}

#[test]
fn report_summarises_each_host() {
    let dir = std::env::temp_dir().join(format!("fxcase-rep-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = CaseStore::create(&dir.join("r.fxcase"), "Report test", None, "UTC").unwrap();
    let a = add_host(&store, &dir, "DFIR", 6);
    let _b = add_host(&store, &dir, "FIN-WS-022", 3);
    let c = add_host(&store, &dir, "OPS-LT-107", 4);
    store.build_indexes().unwrap();
    store
        .write_detections(&[
            det("r1", Severity::High, a, "DFIR"),
            det("r2", Severity::Medium, a, "DFIR"),
            det("r1", Severity::High, c, "OPS-LT-107"),
        ])
        .unwrap();

    let all = fx_hunt::report::generate_report(&store).unwrap();
    assert!(all.contains("\"hosts\":[{\"host\":\"DFIR\",\"events\":6,\"findings\":2"));
    assert!(all.contains("\"host\":\"FIN-WS-022\",\"events\":3,\"findings\":0"));
    assert!(all.contains("\"hosts\":\"DFIR, FIN-WS-022, OPS-LT-107\""));

    let one = store
        .scoped(Some("OPS-LT-107".into()), fx_hunt::report::generate_report)
        .unwrap();
    assert!(one.contains("\"scope\":\"host\""));
    assert!(one.contains("\"total_findings\":1"));
    assert!(!one.contains("on DFIR"));

    if let Ok(out) = std::env::var("FX_REPORT_OUT") {
        std::fs::write(std::path::Path::new(&out).join("report-all.html"), &all).unwrap();
        std::fs::write(std::path::Path::new(&out).join("report-one.html"), &one).unwrap();
    }
}
