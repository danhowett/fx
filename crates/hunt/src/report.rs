//! Case report generation.
//!
//! Produces a single self-contained HTML file — no external assets, no network
//! — that opens in any browser and prints to PDF. It's an analyst instrument,
//! not a static print-out: a left nav rail (tactics → findings), severity
//! scorecards, a severity-laned timeline, tabbed Findings / ATT&CK / Data
//! views, live filtering, expandable finding cards, and light/dark theming.
//! All rendering happens client-side from an embedded JSON payload, so the file
//! is fully self-contained. The Rust side only gathers the case data.

use fx_store::{CaseStore, StoreError};
use serde::Serialize;

/// ATT&CK technique id -> (tactic, human name).
fn technique_info(tech: &str) -> (&'static str, &'static str) {
    match tech {
        "T1189" => ("Initial Access", "Drive-by / abused file-sharing download"),
        "T1078.004" => ("Initial Access", "Valid cloud accounts"),
        "T1566" => ("Initial Access", "Phishing"),
        "T1190" => ("Initial Access", "Exploit public-facing app"),
        "T1059.001" => ("Execution", "PowerShell"),
        "T1059.003" => ("Execution", "Windows command shell"),
        "T1204" => ("Execution", "User execution"),
        "T1053.005" => ("Persistence", "Scheduled task"),
        "T1543.003" => ("Persistence", "Windows service"),
        "T1547.001" => ("Persistence", "Registry Run keys"),
        "T1546" => ("Persistence", "Event-triggered execution"),
        "T1136" => ("Persistence", "Create account"),
        "T1562.001" => ("Defense Evasion", "Disable/modify tools"),
        "T1036.005" => ("Defense Evasion", "Masquerading"),
        "T1112" => ("Defense Evasion", "Modify registry"),
        "T1070.001" => ("Defense Evasion", "Clear Windows event logs"),
        "T1070" => ("Defense Evasion", "Indicator removal"),
        "T1003" => ("Credential Access", "OS credential dumping"),
        "T1003.001" => ("Credential Access", "LSASS memory"),
        "T1552" => ("Credential Access", "Unsecured credentials"),
        "T1087" => ("Discovery", "Account discovery"),
        "T1018" => ("Discovery", "Remote system discovery"),
        "T1021.001" => ("Lateral Movement", "Remote Desktop Protocol"),
        "T1021.002" => ("Lateral Movement", "SMB/admin shares"),
        "T1570" => ("Lateral Movement", "Lateral tool transfer"),
        "T1005" => ("Collection", "Data from local system"),
        "T1074" => ("Collection", "Data staged"),
        "T1071" => ("Command and Control", "Application-layer protocol"),
        "T1572" => ("Command and Control", "Protocol tunneling"),
        "T1219" => ("Command and Control", "Remote access software"),
        "T1048" => ("Exfiltration", "Exfil over alternative protocol"),
        "T1567" => ("Exfiltration", "Exfil to web service"),
        "T1567.002" => ("Exfiltration", "Exfil to cloud storage"),
        "T1490" => ("Impact", "Inhibit system recovery"),
        "T1486" => ("Impact", "Data encrypted for impact"),
        "T1657" => ("Impact", "Financial theft / extortion"),
        "T1489" => ("Impact", "Service stop"),
        _ => ("Other", "Uncategorized technique"),
    }
}

const TACTIC_ORDER: &[&str] = &[
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact", "Other",
];

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

#[derive(Serialize)]
struct ReportData {
    meta: MetaJson,
    counts: CountsJson,
    findings: Vec<FindingJson>,
    attack: Vec<AttackJson>,
    artefacts: Vec<KvJson>,
    ingest: Vec<KvJson>,
    evidence: Vec<EvidenceJson>,
    tactic_order: Vec<String>,
    generated_utc: String,
}
#[derive(Serialize)]
struct MetaJson { case_id: String, name: String, examiner: String, created_utc: String, timezone: String, verdict: String, verdict_level: String }
#[derive(Serialize)]
struct CountsJson { total_findings: usize, critical: u32, high: u32, medium: u32, low: u32, info: u32, events: u64, evidence_items: usize, unclassified: u64 }
#[derive(Serialize)]
struct FindingJson { rule_id: String, title: String, severity: String, sev_rank: u8, tactic: String, techniques: Vec<TechJson>, summary: String, ts: String, host: String, engine: String }
#[derive(Serialize)]
struct TechJson { id: String, name: String }
#[derive(Serialize)]
struct AttackJson { id: String, name: String, tactic: String, count: u64 }
#[derive(Serialize)]
struct KvJson { label: String, count: u64 }
#[derive(Serialize)]
struct EvidenceJson { source_path: String, artefact: String, sha256: String, size: String, id_method: String, confidence: u32 }

/// Generate the full HTML report for a case.
pub fn generate_report(store: &CaseStore) -> Result<String, StoreError> {
    let meta = store.case_meta()?;
    let detections = store.detections()?;
    let evidence = store.evidence_list()?;
    let total_events = store.event_count()?;
    let by_artefact = store.counts_by_artefact()?;
    let ingest = store.ingest_summary()?;
    let unclassified = store.unclassified_count()?;
    let attack_raw = store.attack_coverage()?;

    let mut counts = CountsJson {
        total_findings: detections.len(),
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
        events: total_events, evidence_items: evidence.len(), unclassified,
    };
    for d in &detections {
        match d.severity.as_str() {
            "critical" => counts.critical += 1,
            "high" => counts.high += 1,
            "medium" => counts.medium += 1,
            "low" => counts.low += 1,
            _ => counts.info += 1,
        }
    }

    let (verdict, verdict_level) = if counts.critical > 0 {
        ("This case contains CRITICAL findings consistent with a completed or in-progress ransomware / eCrime intrusion. Immediate containment and escalation are warranted.", "danger")
    } else if counts.high > 0 {
        ("This case contains HIGH-severity findings indicating likely malicious activity. Prompt investigation is warranted.", "warn")
    } else if !detections.is_empty() {
        ("This case contains findings that merit analyst review. No critical activity was automatically detected.", "info")
    } else {
        ("No automated detections fired against the ingested evidence. This is not proof of a clean host — coverage is limited to the artefacts and rules available.", "info")
    };

    let findings: Vec<FindingJson> = detections.iter().map(|d| {
        let techs: Vec<TechJson> = d.attack.split(',').filter(|s| !s.trim().is_empty()).map(|t| {
            let (_, name) = technique_info(t.trim());
            TechJson { id: t.trim().to_string(), name: name.to_string() }
        }).collect();
        let tactic = techs.first().map(|t| technique_info(&t.id).0.to_string()).unwrap_or_else(|| "Other".to_string());
        FindingJson {
            rule_id: d.rule_id.clone(), title: d.title.clone(), severity: d.severity.clone(),
            sev_rank: severity_rank(&d.severity), tactic, techniques: techs,
            summary: d.summary.clone(), ts: d.ts.clone(),
            host: d.host.clone().unwrap_or_else(|| "—".into()), engine: d.engine.clone(),
        }
    }).collect();

    let attack: Vec<AttackJson> = attack_raw.iter().map(|(id, count)| {
        let (tactic, name) = technique_info(id);
        AttackJson { id: id.clone(), name: name.to_string(), tactic: tactic.to_string(), count: *count }
    }).collect();

    let data = ReportData {
        meta: MetaJson {
            case_id: meta.case_id, name: meta.name,
            examiner: meta.examiner.unwrap_or_else(|| "—".into()),
            created_utc: meta.created_utc, timezone: meta.display_timezone,
            verdict: verdict.into(), verdict_level: verdict_level.into(),
        },
        counts,
        findings,
        attack,
        artefacts: by_artefact.into_iter().map(|(label, count)| KvJson { label, count }).collect(),
        ingest: ingest.into_iter().map(|(label, count)| KvJson { label, count }).collect(),
        evidence: evidence.iter().map(|e| EvidenceJson {
            source_path: e.source_path.clone(), artefact: e.artefact_kind.clone(),
            sha256: e.sha256.clone(), size: human_bytes(e.size_bytes),
            id_method: e.id_method.clone(), confidence: (e.id_confidence * 100.0) as u32,
        }).collect(),
        tactic_order: TACTIC_ORDER.iter().map(|s| s.to_string()).collect(),
        generated_utc: now_utc(),
    };

    let json = serde_json::to_string(&data).map_err(|e| {
        StoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    })?;
    Ok(build_html(&json))
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 { v /= 1024.0; i += 1; }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

fn now_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Build the self-contained interactive HTML report, injecting the case JSON.
fn build_html(json: &str) -> String {
    let safe = json.replace("</", "<\\/");
    TEMPLATE.replace("/*__CASE_DATA__*/", &safe)
}

static TEMPLATE: &str = r##"<!DOCTYPE html><html lang="en" data-theme="midnight"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>fx case report</title>
<style>
:root, html[data-theme="midnight"] {
  --bg:#0d1524; --elev:#151f34; --deep:#243450; --fg:#eef2f8; --dim:#aebdd2; --faint:#7787a0;
  --rule:#2a3a5a; --rule2:#42557d; --accent:#4a9eff; --field:#0f1a2e;
  --crit-bg:#421826; --crit:#ff7d8d; --high-bg:#3d2d10; --high:#f8bd52;
  --med-bg:#14304f; --med:#6fb2ff; --low-bg:#153a24; --low:#5cd98a; --info-bg:#1c2740; --info:#aebdd2;
  --grid:rgba(255,255,255,0.02); --radius:6px; --shadow:0 1px 3px rgba(0,0,0,.35),0 4px 16px rgba(0,0,0,.28);
  --mono:'JetBrains Mono','SF Mono',Consolas,monospace; --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
html[data-theme="daybreak"] {
  --bg:#f7f4ec; --elev:#fbf9f3; --deep:#efe9dc; --fg:#2e3a3a; --dim:#5b6a68; --faint:#8a938c;
  --rule:#e4ddcd; --rule2:#cbc3b0; --accent:#3a7ca5; --field:#fffdf8;
  --crit-bg:#f4e0dc; --crit:#b04a3a; --high-bg:#f6ecd4; --high:#9a6f1e;
  --med-bg:#e2ecf1; --med:#2c6a8f; --low-bg:#e4ecd9; --low:#5a7a3a; --info-bg:#eee9dd; --info:#5b6a68;
  --grid:rgba(0,0,0,0.02); --shadow:0 1px 3px rgba(70,60,40,.06),0 4px 14px rgba(70,60,40,.05);
}
html[data-theme="sunset"] {
  /* Sunset — warm dusk: deep plum/indigo ground, amber & coral accents */
  --bg:#1a1220; --elev:#241830; --deep:#38243f; --fg:#f6e9e4; --dim:#c9a9b8; --faint:#8f7286;
  --rule:#3d2740; --rule2:#5a3a55; --accent:#ff9e64; --field:#170f1d;
  --crit-bg:#4a1526; --crit:#ff6b8a; --high-bg:#4a2a10; --high:#ffb454;
  --med-bg:#2f2145; --med:#c88cff; --low-bg:#153a30; --low:#5cd9a8; --info-bg:#2a1c33; --info:#c9a9b8;
  --grid:rgba(255,190,120,0.025); --shadow:0 1px 3px rgba(0,0,0,.4),0 4px 16px rgba(20,0,10,.3);
}
*{box-sizing:border-box;}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:13.5px;line-height:1.55;-webkit-font-smoothing:antialiased;}
body{background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);background-size:32px 32px;min-height:100vh;}
.mono{font-family:var(--mono);}
a{color:var(--accent);text-decoration:none;}
/* layout */
.app{display:grid;grid-template-columns:250px 1fr;min-height:100vh;}
.rail{background:var(--elev);border-right:1px solid var(--rule);position:sticky;top:0;height:100vh;overflow-y:auto;padding:0;}
.rail .brand{padding:18px 18px 14px;border-bottom:1px solid var(--rule);}
.rail .brand .logo{font-weight:800;font-size:18px;letter-spacing:-.02em;}
.rail .brand .logo .dot{color:var(--accent);}
.rail .brand .ver{font-size:10px;color:var(--faint);letter-spacing:.1em;text-transform:uppercase;margin-top:2px;}
.rail h3{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin:16px 16px 6px;}
.navitem{display:flex;align-items:center;gap:8px;padding:5px 16px;cursor:pointer;font-size:12.5px;color:var(--dim);border-left:2px solid transparent;}
.navitem:hover{background:var(--deep);color:var(--fg);}
.navitem.tactic{color:var(--faint);font-size:10px;letter-spacing:.08em;text-transform:uppercase;margin-top:8px;cursor:default;}
.navitem .cnt{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--faint);}
.navitem .sev-dot{width:7px;height:7px;border-radius:2px;flex:none;}
.main{padding:24px 32px 80px;max-width:1180px;}
/* header */
header{border-bottom:1px solid var(--rule);padding-bottom:22px;margin-bottom:26px;}
.eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);margin-bottom:10px;display:flex;align-items:center;gap:10px;}
.themebtn{margin-left:auto;background:var(--field);border:1px solid var(--rule);color:var(--dim);border-radius:var(--radius);padding:4px 12px;cursor:pointer;font-size:11px;letter-spacing:.05em;}
h1{font-size:27px;margin:0 0 14px;font-weight:700;letter-spacing:-.02em;}
h1 .dot{color:var(--accent);}
.metagrid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px 28px;}
.metagrid .k{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--faint);}
.metagrid .v{font-size:12.5px;}
/* scorecards */
.scores{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0;}
.score{background:var(--elev);border:1px solid var(--rule);border-top-width:3px;border-radius:var(--radius);padding:12px 18px;min-width:104px;}
.score .n{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1.1;}
.score .l{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--faint);margin-top:2px;}
.score.all{border-top-color:var(--accent);}
.score.critical{border-top-color:var(--crit);} .score.critical .n{color:var(--crit);}
.score.high{border-top-color:var(--high);} .score.high .n{color:var(--high);}
.score.medium{border-top-color:var(--med);} .score.medium .n{color:var(--med);}
.score.low{border-top-color:var(--low);} .score.low .n{color:var(--low);}
/* verdict */
.verdict{border-radius:var(--radius);padding:14px 18px;margin:0 0 22px;border-left:4px solid;}
.verdict.danger{background:var(--crit-bg);border-color:var(--crit);}
.verdict.warn{background:var(--high-bg);border-color:var(--high);}
.verdict.info{background:var(--info-bg);border-color:var(--accent);}
/* timeline */
.panel{background:var(--elev);border:1px solid var(--rule);border-radius:var(--radius);padding:16px 18px;margin-bottom:22px;}
.panel h2{font-size:13px;margin:0 0 14px;letter-spacing:.02em;}
.tl{position:relative;height:90px;background:var(--field);border:1px solid var(--rule);border-radius:var(--radius);overflow:hidden;}
.tl .dot{position:absolute;width:9px;height:9px;border-radius:50%;transform:translate(-50%,-50%);cursor:pointer;box-shadow:0 0 0 2px var(--field);}
.tl .dot:hover{width:13px;height:13px;}
.tl-axis{display:flex;justify-content:space-between;font-family:var(--mono);font-size:10px;color:var(--faint);margin-top:6px;}
.dot.critical{background:var(--crit);} .dot.high{background:var(--high);} .dot.medium{background:var(--med);} .dot.low{background:var(--low);} .dot.info{background:var(--info);}
/* tabs */
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--rule);margin-bottom:18px;}
.tab{padding:9px 16px;cursor:pointer;color:var(--dim);font-size:13px;border-bottom:2px solid transparent;display:flex;align-items:center;gap:7px;}
.tab.active{color:var(--fg);border-bottom-color:var(--accent);}
.tab .tc{font-family:var(--mono);font-size:11px;background:var(--deep);color:var(--dim);padding:0 6px;border-radius:10px;}
.tabpanel{display:none;} .tabpanel.active{display:block;}
/* filters */
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;}
.filters input,.filters select{background:var(--field);border:1px solid var(--rule);color:var(--fg);border-radius:var(--radius);padding:6px 10px;font-size:12.5px;font-family:var(--sans);}
.filters input{flex:1;min-width:200px;}
/* findings */
.finding{background:var(--elev);border:1px solid var(--rule);border-left-width:4px;border-radius:0 var(--radius) var(--radius) 0;margin:8px 0;overflow:hidden;}
.finding.critical{border-left-color:var(--crit);} .finding.high{border-left-color:var(--high);}
.finding.medium{border-left-color:var(--med);} .finding.low{border-left-color:var(--low);} .finding.info{border-left-color:var(--info);}
.f-head{display:flex;align-items:center;gap:10px;padding:11px 15px;cursor:pointer;}
.f-head:hover{background:var(--deep);}
.pill{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:4px;color:#fff;}
.pill.critical{background:var(--crit);} .pill.high{background:var(--high);color:#241a04;} .pill.medium{background:var(--med);color:#04121f;} .pill.low{background:var(--low);color:#04180c;} .pill.info{background:var(--faint);}
.f-title{font-weight:600;font-size:14px;}
.f-att{margin-left:auto;display:flex;gap:4px;flex-wrap:wrap;align-items:center;}
.att{font-family:var(--mono);font-size:10px;color:var(--accent);border:1px solid var(--rule);padding:1px 6px;border-radius:4px;}
.f-tactic{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);}
.f-body{padding:0 15px 14px 15px;display:none;border-top:1px solid var(--rule);}
.finding.open .f-body{display:block;}
.f-summary{margin:12px 0;}
.kv-row{display:flex;gap:8px;font-size:12px;padding:3px 0;border-bottom:1px solid var(--rule);}
.kv-row .k{color:var(--faint);min-width:90px;text-transform:uppercase;font-size:10px;letter-spacing:.04em;padding-top:2px;}
.kv-row .v{font-family:var(--mono);word-break:break-all;}
.caret{color:var(--faint);transition:transform .15s;}
.finding.open .caret{transform:rotate(90deg);}
/* attack matrix */
.attgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;}
.attcell{background:var(--elev);border:1px solid var(--rule);border-radius:var(--radius);padding:10px 12px;}
.attcell .name{display:block;margin:4px 0 3px;font-size:12px;}
.attcell .meta{font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:var(--faint);}
.attcell .hits{float:right;font-family:var(--mono);font-size:11px;color:var(--accent);}
/* tables */
h2.sec{font-size:16px;margin:30px 0 14px;padding-bottom:6px;border-bottom:1px solid var(--rule);}
.twocol{display:grid;grid-template-columns:1fr 1fr;gap:28px;}
h4{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--faint);margin:0 0 8px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:5px 8px;border-bottom:1px solid var(--rule);text-align:left;}
th{font-size:10px;text-transform:uppercase;letter-spacing:.03em;color:var(--faint);}
td.r,th.r{text-align:right;} .small{font-size:11px;} .hash{color:var(--faint);word-break:break-all;}
footer{margin-top:36px;padding-top:20px;border-top:1px solid var(--rule);color:var(--faint);font-size:12px;}
.muted{color:var(--faint);}
.empty{color:var(--faint);padding:20px;text-align:center;}
::-webkit-scrollbar{width:10px;height:10px;} ::-webkit-scrollbar-thumb{background:var(--rule);border-radius:5px;border:2px solid var(--elev);}
@media print{
  body{background:#fff;} html[data-theme]{--bg:#fff;--elev:#fff;--fg:#111;--dim:#333;--rule:#ccc;}
  .rail,.themebtn,.filters,.tabs{display:none!important;}
  .app{grid-template-columns:1fr;} .main{max-width:none;padding:0;}
  .finding .f-body{display:block!important;} .tabpanel{display:block!important;}
  .finding,.attcell,.score,.panel{break-inside:avoid;}
}
</style></head><body>
<div class="app">
  <nav class="rail">
    <div class="brand"><div class="logo">fx<span class="dot">.</span></div><div class="ver">case report</div></div>
    <div id="nav"></div>
  </nav>
  <main class="main">
    <header>
      <div class="eyebrow"><span>DFIR</span><span>·</span><span>HUNT REPORT</span>
        <button class="themebtn" id="themebtn">◐ Theme</button></div>
      <h1 id="case-title">fx<span class="dot">.</span></h1>
      <div class="metagrid" id="metagrid"></div>
    </header>
    <div class="scores" id="scores"></div>
    <div class="verdict" id="verdict"></div>
    <div class="panel"><h2>Timeline</h2><div class="tl" id="tl"></div><div class="tl-axis" id="tl-axis"></div></div>
    <div class="verdict info" style="border-left-color:var(--accent)">
      <strong>Hunt output — analyst review required.</strong> Findings are pattern matches against the active rule set. They are investigative leads, not conclusions; corroborate each in context before escalation. Absence of findings is not proof of a clean host.</div>
    <div class="tabs" id="tabs">
      <div class="tab active" data-tab="findings">Findings <span class="tc" id="tc-f"></span></div>
      <div class="tab" data-tab="attack">ATT&amp;CK Matrix <span class="tc" id="tc-a"></span></div>
      <div class="tab" data-tab="data">Data &amp; Evidence</div>
    </div>
    <div class="tabpanel active" id="panel-findings">
      <div class="filters">
        <input id="q" placeholder="Search findings, techniques, hosts…">
        <select id="fsev"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
        <select id="ftac"><option value="">All tactics</option></select>
        <select id="fhost"><option value="">All hosts</option></select>
      </div>
      <div id="findings"></div>
    </div>
    <div class="tabpanel" id="panel-attack"><div class="attgrid" id="attgrid"></div></div>
    <div class="tabpanel" id="panel-data">
      <h2 class="sec">Data analysed</h2>
      <div class="twocol">
        <div><h4>Events by artefact</h4><table id="tbl-art"></table></div>
        <div><h4>Ingest outcome</h4><table id="tbl-ing"></table></div>
      </div>
      <h2 class="sec">Evidence — chain of custody</h2>
      <p class="muted">Every finding traces to one of these source files. SHA-256 recorded at ingest.</p>
      <table id="tbl-ev"><thead><tr><th>Source</th><th>Artefact</th><th class="r">Size</th><th>SHA-256</th><th>Ident.</th></tr></thead><tbody></tbody></table>
    </div>
    <footer>
      <p><strong>Scope &amp; limitations.</strong> This report reflects automated analysis of the artefacts ingested into this case using the rule set active at generation time. Findings are investigative leads to be corroborated by an analyst. Timestamps are UTC unless noted.</p>
      <p class="small" id="genline"></p>
    </footer>
  </main>
</div>
<script id="case-data" type="application/json">/*__CASE_DATA__*/</script>
<script>
const D = JSON.parse(document.getElementById('case-data').textContent);
const esc = s => String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SEVS = ['critical','high','medium','low','info'];

// header + meta
document.getElementById('case-title').innerHTML = 'fx<span class="dot">.</span> ' + esc(D.meta.name);
document.getElementById('metagrid').innerHTML = [
  ['Case ID', D.meta.case_id],['Examiner', D.meta.examiner],['Timezone', D.meta.timezone],
  ['Created', D.meta.created_utc],['Report generated', D.generated_utc],['Events analysed', D.counts.events.toLocaleString()],
].map(([k,v])=>`<div><div class="k">${esc(k)}</div><div class="v mono">${esc(v)}</div></div>`).join('');

// scorecards
const sc = D.counts;
document.getElementById('scores').innerHTML = [
  ['all','All',sc.total_findings],['critical','Critical',sc.critical],['high','High',sc.high],
  ['medium','Medium',sc.medium],['low','Low',sc.low],['info','Info',sc.info],
].map(([c,l,n])=>`<div class="score ${c}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

// verdict
const v=document.getElementById('verdict'); v.className='verdict '+D.meta.verdict_level; v.innerHTML=esc(D.meta.verdict);

// nav rail: tactics -> findings
(function(){
  const byT={}; D.findings.forEach(f=>{(byT[f.tactic]=byT[f.tactic]||[]).push(f);});
  let h='<h3>Findings by tactic</h3>';
  D.tactic_order.forEach(t=>{ if(!byT[t]) return;
    h+=`<div class="navitem tactic">${esc(t)} <span class="cnt">${byT[t].length}</span></div>`;
    byT[t].sort((a,b)=>b.sev_rank-a.sev_rank).forEach(f=>{
      h+=`<div class="navitem" data-jump="${esc(f.rule_id)}"><span class="sev-dot ${f.severity}" style="background:var(--${f.severity})"></span>${esc(f.title)}</div>`;
    });
  });
  document.getElementById('nav').innerHTML=h;
})();

// timeline
(function(){
  const timed = D.findings.map(f=>({f,t:Date.parse((f.ts||'').replace(' ','T')+'Z')})).filter(x=>!isNaN(x.t));
  const tl=document.getElementById('tl');
  if(!timed.length){ tl.innerHTML='<div class="empty">No timed findings</div>'; return; }
  const min=Math.min(...timed.map(x=>x.t)), max=Math.max(...timed.map(x=>x.t)), span=(max-min)||1;
  const lanes={critical:18,high:34,medium:50,low:66,info:82};
  tl.innerHTML=timed.map(({f,t})=>{
    const x=((t-min)/span)*96+2, y=lanes[f.severity]||82;
    return `<div class="dot ${f.severity}" style="left:${x}%;top:${y}%" title="${esc(f.ts)} — ${esc(f.title)}" data-jump="${esc(f.rule_id)}"></div>`;
  }).join('');
  const fmt=ms=>new Date(ms).toISOString().replace('T',' ').slice(0,19);
  document.getElementById('tl-axis').innerHTML=`<span>${fmt(min)}</span><span>${fmt(max)}</span>`;
})();

// tabs
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.tabpanel').forEach(x=>x.classList.remove('active'));
  t.classList.add('active'); document.getElementById('panel-'+t.dataset.tab).classList.add('active');
});
document.getElementById('tc-f').textContent=D.findings.length;
document.getElementById('tc-a').textContent=D.attack.length;

// filters
const hosts=[...new Set(D.findings.map(f=>f.host))].filter(h=>h&&h!=='—');
document.getElementById('fhost').innerHTML='<option value="">All hosts</option>'+hosts.map(h=>`<option>${esc(h)}</option>`).join('');
const tacs=D.tactic_order.filter(t=>D.findings.some(f=>f.tactic===t));
document.getElementById('ftac').innerHTML='<option value="">All tactics</option>'+tacs.map(t=>`<option>${esc(t)}</option>`).join('');

function renderFindings(){
  const q=document.getElementById('q').value.toLowerCase();
  const fs=document.getElementById('fsev').value, ft=document.getElementById('ftac').value, fh=document.getElementById('fhost').value;
  const list=D.findings.filter(f=>{
    if(fs&&f.severity!==fs)return false; if(ft&&f.tactic!==ft)return false; if(fh&&f.host!==fh)return false;
    if(q){ const hay=(f.title+' '+f.summary+' '+f.host+' '+f.techniques.map(t=>t.id+' '+t.name).join(' ')).toLowerCase(); if(!hay.includes(q))return false; }
    return true;
  }).sort((a,b)=>b.sev_rank-a.sev_rank || (a.ts<b.ts?-1:1));
  const el=document.getElementById('findings');
  if(!list.length){ el.innerHTML='<div class="empty">No findings match the current filter.</div>'; return; }
  el.innerHTML=list.map(f=>{
    const atts=f.techniques.map(t=>`<span class="att" title="${esc(t.name)}">${esc(t.id)}</span>`).join('');
    return `<div class="finding ${f.severity}" id="f-${esc(f.rule_id)}">
      <div class="f-head" onclick="this.parentNode.classList.toggle('open')">
        <span class="caret">▸</span><span class="pill ${f.severity}">${f.severity}</span>
        <span class="f-title">${esc(f.title)}</span>
        <span class="f-att"><span class="f-tactic">${esc(f.tactic)}</span>${atts}</span>
      </div>
      <div class="f-body">
        <div class="f-summary">${esc(f.summary)}</div>
        <div class="kv-row"><span class="k">Rule</span><span class="v">${esc(f.rule_id)}</span></div>
        <div class="kv-row"><span class="k">When</span><span class="v">${esc(f.ts)}</span></div>
        <div class="kv-row"><span class="k">Host</span><span class="v">${esc(f.host)}</span></div>
        <div class="kv-row"><span class="k">Engine</span><span class="v">${esc(f.engine)}</span></div>
        <div class="kv-row"><span class="k">ATT&CK</span><span class="v">${f.techniques.map(t=>esc(t.id)+' ('+esc(t.name)+')').join(', ')||'—'}</span></div>
      </div></div>`;
  }).join('');
}
['q','fsev','ftac','fhost'].forEach(id=>document.getElementById(id).addEventListener('input',renderFindings));
renderFindings();

// attack matrix
document.getElementById('attgrid').innerHTML = D.attack.length ? D.attack.map(a=>
  `<div class="attcell"><span class="hits">${a.count}×</span><span class="att">${esc(a.id)}</span><span class="name">${esc(a.name)}</span><span class="meta">${esc(a.tactic)}</span></div>`
).join('') : '<div class="empty">No ATT&CK techniques triggered.</div>';

// data tables
document.getElementById('tbl-art').innerHTML=D.artefacts.map(r=>`<tr><td>${esc(r.label)}</td><td class="r mono">${r.count.toLocaleString()}</td></tr>`).join('');
document.getElementById('tbl-ing').innerHTML=D.ingest.map(r=>`<tr><td>${esc(r.label)}</td><td class="r mono">${r.count}</td></tr>`).join('')+`<tr><td>unclassified files</td><td class="r mono">${D.counts.unclassified}</td></tr>`;
document.querySelector('#tbl-ev tbody').innerHTML=D.evidence.map(e=>`<tr><td class="mono small">${esc(e.source_path)}</td><td>${esc(e.artefact)}</td><td class="r mono small">${esc(e.size)}</td><td class="mono small hash">${esc(e.sha256)}</td><td class="small">${esc(e.id_method)} (${e.confidence}%)</td></tr>`).join('');

// jump-to-finding from nav / timeline
document.addEventListener('click',e=>{
  const j=e.target.closest('[data-jump]'); if(!j)return;
  document.querySelector('.tab[data-tab="findings"]').click();
  document.getElementById('fsev').value='';document.getElementById('ftac').value='';document.getElementById('fhost').value='';document.getElementById('q').value='';
  renderFindings();
  const card=document.getElementById('f-'+j.dataset.jump);
  if(card){card.classList.add('open');card.scrollIntoView({behavior:'smooth',block:'center'});}
});

// theme toggle
// theme switcher — cycle midnight → daybreak → sunset, label the current one
(function(){
  const THEMES=[['midnight','◐ Midnight'],['daybreak','☀ Daybreak'],['sunset','◑ Sunset']];
  const btn=document.getElementById('themebtn'), h=document.documentElement;
  function apply(name){
    h.dataset.theme=name;
    const cur=THEMES.find(t=>t[0]===name)||THEMES[0];
    btn.textContent=cur[1];
  }
  btn.onclick=()=>{
    const i=THEMES.findIndex(t=>t[0]===h.dataset.theme);
    apply(THEMES[(i+1)%THEMES.length][0]);
  };
  apply(h.dataset.theme||'midnight');
})();
document.getElementById('genline').textContent='Generated by fx · self-contained report · print to PDF to archive · '+D.generated_utc;
</script></body></html>"##;
