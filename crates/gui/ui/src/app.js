// fx analyst workspace — application logic.
//
// Talks only to backend.js. Renders three panes: the left rail (case shape +
// facets), the center virtualized timeline (the hero), and the right detail
// pane. The timeline is windowed — only the visible rows are in the DOM — so it
// stays responsive across the millions of events a real case holds.

import { backend } from "./backend.js";

const CATEGORIES = [
  ["execution", "Execution", "var(--cat-execution)"],
  ["persistence", "Persistence", "var(--cat-persistence)"],
  ["filesystem", "Filesystem", "var(--cat-filesystem)"],
  ["network", "Network", "var(--cat-network)"],
  ["logon", "Logon", "var(--cat-logon)"],
];
const CAT_COLOR = Object.fromEntries(CATEGORIES.map(([k, , c]) => [k, c]));

const state = {
  overview: null,
  rows: [],
  detections: [],
  triage: [],        // [{event_id, triage_state, note}]
  view: "timeline", // "timeline" | "hunt"
  huntOnly: null,   // "ioc" = findings view filtered to IOC matches (set by the IOC sweep)
  idFilter: null,   // {label, ids, key}: timeline shows exactly these events (IOC matches); dropped when any other filter changes
  filter: { text: "", category: null, artefact: null, triage: null, flagged_only: false, limit: 5000, offset: 0 },
  selectedId: null,
  rowH: 30,
};

const el = (id) => document.getElementById(id);
const viewport = el("viewport");


async function init() {
  hideOverlay();              // guarantee the overlay starts hidden
  // Escape hatch: clicking the overlay backdrop dismisses it, so a stuck
  // operation can never trap the UI.
  const ov = el("overlay");
  if (ov) ov.addEventListener("click", (e) => { if (e.target === ov) hideOverlay(); });
  wireCaseButtons();          // New / Open case buttons always work
  if (backend.isLive()) {
    // Real app: start empty and wait for the analyst to create or open a case.
    showEmptyState();
    wireEvents();
  } else {
    // Standalone browser preview: load the built-in demo case.
    await loadDemoCase("sample case · WKSTN-07 · demo data");
    wireEvents();
  }
  hideOverlay();              // and hidden again after everything renders
}

/// Show the "no case open" empty state in the main area.
function showEmptyState() {
  el("caseName").textContent = "no case open";
  el("rail").innerHTML = `<section style="padding:24px 16px;color:var(--ink-dim);font-size:13px;line-height:1.6">
    <div style="font-size:15px;color:var(--ink);margin-bottom:10px">Welcome to fx</div>
    <b>+ New case</b> — pick a folder of extracted Windows artefacts (KAPE / RESPONSE / Velociraptor output) and fx will ingest, hunt, and display it.<br><br>
    <b>Open case</b> — reopen a <code>.fxcase</code> you made earlier.
  </section>`;
  el("rows").innerHTML = `<div class="empty"><div class="box">
    <h2>No case open</h2>
    <p>Use <b>+ New case</b> to ingest a triage collection, or <b>Open case</b> to reopen an existing <code>.fxcase</code>.</p>
  </div></div>`;
  el("spTop").style.height = "0px";
  el("spBot").style.height = "0px";
  el("resultCount") && (el("resultCount").textContent = "");
  state.overview = null;
  state.rows = [];
  state.detections = [];
}

/// Render the app from an already-obtained overview (returned by ingest or
/// open_case). Pulls detections and paints rail, timeline, everything.
async function renderCase(overview, label) {
  state.overview = overview;
  el("caseName").textContent = label
    || (backend.isLive() ? `case ${short(overview.case_id)}` : "sample case · demo data");
  state.detections = await backend.huntResults();
  state.triage = (await backend.listTriage()) || [];
  state.view = "timeline";
  renderRail();
  renderToolbar();
  renderStatus();
  await refresh();
}

/// Standalone/demo path: the sample backend's openCase returns a demo overview.
async function loadDemoCase(label) {
  const overview = await backend.openCase("(sample)");
  await renderCase(overview, label);
}

// ── Overlay helpers ──────────────────────────────────────────────────────────
function showOverlay(title, sub) {
  const o = el("overlay"); if (!o) return;
  const t = el("overlayTitle"); if (t) t.textContent = title;
  const s = el("overlaySub"); if (s) s.textContent = sub || "";
  o.classList.add("show");
}
function hideOverlay() { const o = el("overlay"); if (o) o.classList.remove("show"); }

// ── New / Open case button flows ─────────────────────────────────────────────
function wireCaseButtons() {
  const newBtn = el("newCaseBtn");
  const openBtn = el("openCaseBtn");
  if (newBtn) newBtn.addEventListener("click", onNewCase);
  if (openBtn) openBtn.addEventListener("click", onOpenCase);
  const expCsvTop = el("exportCsvTop"), expStixTop = el("exportStixTop");
  if (expCsvTop) expCsvTop.addEventListener("click", () => exportFindings("csv"));
  if (expStixTop) expStixTop.addEventListener("click", () => exportFindings("stix"));
  wireExportMenu();
  const iocBtn = el("iocBtn");
  if (iocBtn) iocBtn.addEventListener("click", () => openIocSweep());
  const expRepTop = el("exportReportTop");
  if (expRepTop) expRepTop.addEventListener("click", () => exportReport());
  // Help modal.
  const helpBtn = el("helpBtn"), helpModal = el("helpModal"), helpClose = el("helpClose");
  if (helpBtn) helpBtn.addEventListener("click", () => { el("helpBody").innerHTML = HELP_HTML; helpModal.classList.add("show"); });
  if (helpClose) helpClose.addEventListener("click", () => helpModal.classList.remove("show"));
  if (helpModal) helpModal.addEventListener("click", (e) => { if (e.target === helpModal) helpModal.classList.remove("show"); });
  wireTheme();
}

async function renderIngestLog() {
  let rows = [];
  try { rows = (await backend.ingestLog()) || []; } catch (e) { rows = []; }
  el("spTop").style.height = "0px";
  el("spBot").style.height = "0px";
  const n = rows.length;
  const by = (s) => rows.filter((r) => r.status === s).length;
  const totalEvents = rows.reduce((a, r) => a + (r.events_emitted || 0), 0);
  el("resultCount").textContent = `${fmt(n)} files ingested`;
  const summary = `<div class="ilog-summary">
    <span><b style="color:#2e9e5b">${fmt(by("parsed"))}</b> parsed</span>
    <span><b style="color:#c99a2e">${fmt(by("unsupported"))}</b> unsupported</span>
    <span><b style="color:var(--alert)">${fmt(by("failed"))}</b> failed</span>
    <span><b>${fmt(totalEvents)}</b> events produced</span>
  </div>`;

  // Group by (artefact, status) so a case with hundreds of LNKs / tasks / Edge
  // DBs reads as a handful of summary rows instead of a wall. Every file is still
  // accounted for (counts are exact) and reachable by expanding its group — the
  // "never silently drop a file" guarantee holds. Failures sort to the top.
  const groups = new Map();
  for (const r of rows) {
    const key = `${r.artefact_kind}\u0000${r.status}`;
    let g = groups.get(key);
    if (!g) { g = { artefact: r.artefact_kind, status: r.status, items: [], events: 0, records: 0, warn: 0 }; groups.set(key, g); }
    g.items.push(r);
    g.events += r.events_emitted || 0;
    g.records += r.records_read || 0;
    g.warn += r.warning_count || 0;
  }
  const statusRank = { failed: 0, unsupported: 1, parsed: 2 };
  const groupList = [...groups.values()].sort((a, b) =>
    (statusRank[a.status] ?? 3) - (statusRank[b.status] ?? 3) ||
    b.items.length - a.items.length ||
    a.artefact.localeCompare(b.artefact));

  let gi = 0;
  const body = groupList.map((g) => {
    const id = `ig${gi++}`;
    // A failed/unsupported group starts expanded (you want to see those); large
    // parsed groups start collapsed.
    const open = g.status !== "parsed" && g.items.length <= 200;
    const children = g.items.map((r) => `
      <tr class="ilog-child ${id}" ${open ? "" : 'style="display:none"'}>
        <td class="src">${escapeHtml(r.source_path)}</td>
        <td class="r">${fmt(r.records_read)}</td>
        <td class="r">${fmt(r.events_emitted)}</td>
        <td class="r">${r.warning_count ? r.warning_count : "—"}</td>
        <td class="detail">${r.detail ? escapeHtml(r.detail) : ""}</td>
      </tr>`).join("");
    return `
      <tr class="ilog-group" data-group="${id}" data-open="${open ? 1 : 0}">
        <td class="gname"><span class="caret">${open ? "▾" : "▸"}</span>
          <span class="st-badge st-${g.status}">${g.status}</span>
          <b>${escapeHtml(g.artefact)}</b>
          <span class="gcount">${fmt(g.items.length)} file${g.items.length === 1 ? "" : "s"}</span>
        </td>
        <td class="r">${fmt(g.records)}</td>
        <td class="r">${fmt(g.events)}</td>
        <td class="r">${g.warn ? g.warn : "—"}</td>
        <td class="detail">${g.status === "failed" ? "click to see the failing files" : ""}</td>
      </tr>
      ${children}`;
  }).join("");

  el("rows").innerHTML = `${summary}<div class="ilog"><table>
    <thead><tr><th>Artefact / source file</th><th class="r">Records</th><th class="r">Events</th><th class="r">Warn</th><th>Detail</th></tr></thead>
    <tbody>${body || '<tr><td colspan="5" style="padding:20px;text-align:center;color:var(--ink-faint)">No ingest log for this case.</td></tr>'}</tbody>
  </table></div>`;

  // Expand/collapse a group on click.
  el("rows").querySelectorAll(".ilog-group").forEach((gr) => {
    gr.addEventListener("click", () => {
      const id = gr.dataset.group;
      const nowOpen = gr.dataset.open !== "1";
      gr.dataset.open = nowOpen ? "1" : "0";
      const caret = gr.querySelector(".caret");
      if (caret) caret.textContent = nowOpen ? "▾" : "▸";
      el("rows").querySelectorAll("." + id).forEach((c) => { c.style.display = nowOpen ? "" : "none"; });
    });
  });
  renderStatus();
}

// ── Activity graph ─────────────────────────────────────────────────────────
// A per-day event-count histogram. The point is to surface volume that NO rule
// tagged: a day with 1000 events when the baseline is ~100 is worth pivoting
// into even if nothing fired. Each bar's height is the day's total; the darker
// base of the bar is the flagged (rule-tripped) portion, so a tall bar that is
// almost entirely light is unexplained activity. Clicking a day pivots the
// timeline to that day's UTC window.
function medianOf(arr) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// Robust spike test: a day is anomalous if its total is both well above the
// median and above median + 3·MAD (median absolute deviation). MAD resists the
// spike itself skewing the threshold the way mean+sd would.
function anomalyThreshold(totals) {
  const med = medianOf(totals);
  const mad = medianOf(totals.map((t) => Math.abs(t - med))) || 1;
  return Math.max(med * 2.5, med + 3 * 1.4826 * mad);
}

async function renderActivityGraph() {
  let days = [];
  try { days = (await backend.dailyActivity()) || []; } catch (e) { days = []; }
  el("spTop").style.height = "0px";
  el("spBot").style.height = "0px";
  closeDetail();

  if (!days.length) {
    el("resultCount").textContent = "";
    el("rows").innerHTML = `<div class="empty"><div class="box"><h2>No activity</h2><p>Open or ingest a case to see its per-day event volume here.</p></div></div>`;
    renderStatus();
    return;
  }

  // Sort strictly by calendar date, defensively — the store already returns
  // ORDER BY day, but a bad/empty day string must never scramble the axis. Days
  // that don't parse are dropped (they can't be placed on a time axis).
  days = days
    .filter((d) => d && /^\d{4}-\d{2}-\d{2}$/.test(d.day))
    .sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));

  if (!days.length) {
    el("resultCount").textContent = "";
    el("rows").innerHTML = `<div class="empty"><div class="box"><h2>No activity</h2><p>No dated events to chart for this case.</p></div></div>`;
    renderStatus();
    return;
  }

  const totals = days.map((d) => d.total);
  const maxT = Math.max(...totals, 1);
  const thresh = anomalyThreshold(totals);
  const med = Math.round(medianOf(totals));
  const spikes = days.filter((d) => d.total >= thresh && d.total > med);
  const grand = totals.reduce((a, b) => a + b, 0);

  // Scale. When the tallest day dwarfs the baseline (e.g. 4000 vs 25), a linear
  // axis renders every quiet day as an invisible sliver. A log axis keeps the
  // baseline readable while the spike still clearly towers: log(25)/log(4217) is
  // ~0.4, so a 25-event day is ~40% the height of a 4217-event day instead of
  // ~0.6%. We only switch to log when the spread warrants it, label the axis so
  // the height is never read as linearly proportional, and give the tallest bar
  // headroom (95%, not 100%) so its value label isn't clipped.
  const useLog = maxT / Math.max(med, 1) >= 6;
  const scaleVal = (v) => (useLog ? Math.log10(v + 1) : v);
  const scaleMax = scaleVal(maxT) || 1;

  el("resultCount").textContent = `${fmt(days.length)} days · ${fmt(grand)} events`;

  // Keep the scale context so the pixel-height pass (layoutActivityChart) can
  // recompute bar heights whenever the pane resizes.
  state._act = { days, maxT, med, thresh, scaleVal, scaleMax };

  // Render the bar shells WITHOUT heights. Percentage heights inside a flex
  // container are unreliable in WebView2 (older Chromium) — a % height against a
  // flex-item parent whose own height came from flex:1 is treated as indefinite,
  // so every bar collapses to its content height. We therefore set every bar's
  // height in PIXELS, in JS, after measuring the chart (layoutActivityChart).
  const firstYear = days[0].day.slice(0, 4);
  const lastYear = days[days.length - 1].day.slice(0, 4);
  const spanYears = firstYear !== lastYear;

  // X-axis labels are thinned to an EVEN stride (~14 across the chart) so they
  // sit horizontally without overlapping and read as a regular time axis. The
  // stride is independent of spikes — a spike shows its event count on top of the
  // bar (actbar-val), not on the date axis — so labels no longer look scattered.
  // Note: only days that actually have events are plotted (quiet days are
  // omitted), so adjacent bars can be non-consecutive dates; the year/month
  // dividers and per-bar hover date make the real spacing clear.
  const labelEvery = Math.max(1, Math.round(days.length / 14));
  let prevMonth = null, prevYear = null;
  const bars = days.map((d, i) => {
    const anom = d.total >= thresh && d.total > med;
    const year = d.day.slice(0, 4);
    const month = d.day.slice(0, 7); // YYYY-MM
    const monthStart = i > 0 && month !== prevMonth;
    const yearStart = i > 0 && year !== prevYear;
    prevMonth = month; prevYear = year;
    const dm = `${d.day.slice(8, 10)}/${d.day.slice(5, 7)}`; // DD/MM (UK)
    const showLabel = i === 0 || i === days.length - 1 || i % labelEvery === 0;
    const label = showLabel ? `<span class="actbar-day">${dm}</span>` : "";
    // A year boundary draws a divider + year caption so a multi-year case reads
    // at a glance.
    const yearMark = yearStart ? `<span class="actbar-year">${year}</span>` : "";
    const title = `${ukDate(d.day)}\n${fmt(d.total)} events${d.flagged ? ` · ${fmt(d.flagged)} flagged` : ""}${anom ? "\n⚠ volume spike vs baseline" : ""}\nclick to pivot the timeline to this day`;
    return `<div class="actbar ${anom ? "anom" : ""} ${monthStart ? "mstart" : ""} ${yearStart ? "ystart" : ""}" data-day="${d.day}" data-total="${d.total}" data-flagged="${d.flagged}" title="${escapeHtml(title)}">
      <div class="actbar-val">${anom ? fmt(d.total) : ""}</div>
      <div class="actbar-col">
        <div class="actbar-flag"></div>
      </div>
      ${yearMark}
      ${label}
    </div>`;
  }).join("");

  const yearNote = spanYears ? `${firstYear}–${lastYear}` : firstYear;
  const spikeNote = spikes.length
    ? `<b style="color:var(--alert)">${spikes.length}</b> volume spike${spikes.length === 1 ? "" : "s"} vs a ~${fmt(med)}/day baseline`
    : `no volume spikes — steady ~${fmt(med)}/day`;

  el("rows").innerHTML = `
    <div class="actwrap">
      <div class="act-head">
        <div class="act-title">Events per day <span class="act-year">${yearNote} · UTC</span></div>
        <div class="act-sub">${spikeNote}. Bar height is the day's total; the darker base is the rule-flagged / validated portion. Click a day to pivot the timeline.</div>
        <div class="act-legend">
          <span><i class="sw sw-total"></i> total</span>
          <span><i class="sw sw-flag"></i> flagged / validated</span>
          <span><i class="sw sw-anom"></i> volume spike</span>
          <span class="act-base">${useLog ? "log-scaled height · " : ""}baseline median ~${fmt(med)}/day</span>
        </div>
      </div>
      <div class="actchart">${bars}</div>
    </div>`;

  el("rows").querySelectorAll(".actbar[data-day]").forEach((bar) => {
    bar.addEventListener("click", () => pivotToDay(bar.dataset.day));
  });
  renderStatus();
  // Two-pass layout: now that the DOM exists, size the wrap and compute every
  // bar's PIXEL height from the measured chart. Double rAF so WebView2 has laid
  // out and the measurements are real.
  layoutActivityChart();
}

// Measure the chart and set pixel heights — on the wrap (fills the viewport) and
// on every bar column (so bar heights don't depend on %-of-flex-parent, which
// WebView2 won't resolve). Runs after layout via double rAF; re-run on resize.
function layoutActivityChart() {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    if (state.view !== "activity" || !state._act) return;
    const wrap = el("rows").querySelector(".actwrap");
    const chart = el("rows").querySelector(".actchart");
    if (!wrap || !chart) return;

    // 1. Wrap fills the visible viewport (pixel height — always definite).
    const wrapH = Math.max(320, viewport.clientHeight - 6);
    wrap.style.setProperty("--act-h", wrapH + "px");

    // 2. Usable bar track = chart's inner height (clientHeight already excludes
    //    the chart's own top/bottom padding, and the day labels are absolutely
    //    positioned so they take no flow height) minus the value-label row above
    //    each column.
    const { scaleVal, scaleMax } = state._act;
    const padTop = 22, padBottom = 26, valRow = 16;
    // clientHeight includes padding; subtract chart padding and the value-label
    // row so the tallest bar fits without overflowing or leaving a gap.
    const trackH = Math.max(40, chart.clientHeight - padTop - padBottom - valRow);

    chart.querySelectorAll(".actbar").forEach((bar) => {
      const total = +bar.dataset.total || 0;
      const flagged = +bar.dataset.flagged || 0;
      const col = bar.querySelector(".actbar-col");
      const flag = bar.querySelector(".actbar-flag");
      const hPx = total ? Math.max(6, Math.round((scaleVal(total) / scaleMax) * trackH)) : 0;
      col.style.height = hPx + "px";
      const flagPx = total ? Math.round((flagged / total) * hPx) : 0;
      if (flag) flag.style.height = flagPx + "px";
    });
    return;
  }));
}

// Pivot the timeline to a single UTC day: set the time-range filter to
// [day 00:00:00, next-day 00:00:00) and switch to the timeline view.
async function pivotToDay(day) {
  if (!day) return;
  state.view = "timeline";
  state.filter.after = day + "T00:00:00Z";
  const next = new Date(day + "T00:00:00Z");
  next.setUTCDate(next.getUTCDate() + 1);
  state.filter.before = next.toISOString().slice(0, 19) + "Z";
  state.filter.offset = 0;
  renderRail();
  renderToolbar();
  await refresh();
}

// In-tool help content (kept in sync with HELP.md shipped for GitHub).
const HELP_HTML = `
  <h3>What is fx?</h3>
  <p>fx is a Windows artefact analysis and threat-hunting tool for DFIR triage. It ingests a folder of <b>already-extracted</b> Windows artefacts (from KAPE, Magnet RESPONSE, Velociraptor, etc.), normalises them onto a single timeline, and runs detection rules focused on the tactics of financially-motivated / ransomware actors.</p>
  <h3>How to use it</h3>
  <ul>
    <li><b>+ New case</b> — pick an artefact folder and where to save the <code>.fxcase</code>; fx ingests, hunts, and displays it.</li>
    <li><b>Open case</b> — reopen a saved <code>.fxcase</code>.</li>
    <li><b>Review findings</b> (rail) — rule detections and your analyst-validated events together. Click a finding to jump to the event, see its raw record, and triage it.</li>
    <li><b>Triage</b> — mark any event Validated / Unconfirmed / False positive / Dismissed, with a note. Filter by state from the rail.</li>
    <li><b>Timeline</b> — filter by activity, artefact, or time range; click an event and use <b>Pivot ±1m/5m/30m/1h</b> to see what happened around it.</li>
    <li><b>Export report</b> — save the self-contained HTML case report (findings, ATT&CK matrix, timeline, evidence chain of custody with SHA-256s). Print it to PDF to archive.</li>
    <li><b>Export CSV / STIX</b> — export findings (rule + analyst) for Excel or a TIP/MISP. Choose which triage states to include (validated / unconfirmed / false positive / dismissed).</li>
    <li><b>Ingest log</b> (rail) — every file ingested and whether it parsed, was unsupported, or failed.</li>
    <li><b>Activity graph</b> (rail) — events-per-day histogram across the whole case. A day far above the baseline is outlined and labelled — the way to spot high-volume activity no rule tagged. Click a day to pivot the timeline to it.</li>
  </ul>
  <h3>What it analyses</h3>
  <p>Parsers: Windows Event Logs (EVTX, ~50 event IDs across Security/Sysmon/PowerShell/Defender/TerminalServices/WMI), MFT, UsnJrnl, registry hives (Run keys, services, ShimCache, UserAssist, BAM/DAM, RDP, Amcache, ShellBags), Prefetch, SRUM, Scheduled Tasks, Browser history, LNK & Jump Lists, Recycle Bin.</p>
  <h3>What it hunts for</h3>
  <p>25 rules: generic ATT&CK techniques (credential dumping, discovery, lateral movement, defense evasion, persistence, LOLBin abuse, suspicious PowerShell) plus behavioural rules for the top 2026 ransomware groups (Qilin, TheGentlemen, Akira, Play/DragonForce, LockBit, INC Ransom, Interlock, Clop and more). Rules match behaviour and tooling, not file hashes.</p>
  <h3>Important</h3>
  <p class="muted">Findings are investigative <b>leads to corroborate</b>, not verdicts. Attribution to a specific group is probabilistic — tooling is shared across crews. Absence of findings is not proof a host is clean. All timestamps are UTC. Point fx at a <b>copy</b> of evidence; originals stay read-only (every source file is SHA-256 hashed at ingest).</p>
`;


// ── Theme switcher (daybreak / slate / midnight) ────────────────────────────
function wireTheme() {
  const THEMES = [
    ["daybreak", "☀ Daybreak"],
    ["slate", "◑ Slate"],
    ["midnight", "◐ Midnight"],
  ];
  const btn = el("themeBtn");
  if (!btn) return;
  const root = document.documentElement;
  const apply = (name) => {
    root.dataset.theme = name;
    const cur = THEMES.find((t) => t[0] === name) || THEMES[0];
    btn.textContent = cur[1];
    try { localStorage.setItem("fx-theme", name); } catch (e) {}
  };
  btn.addEventListener("click", () => {
    const i = THEMES.findIndex((t) => t[0] === root.dataset.theme);
    apply(THEMES[(i + 1) % THEMES.length][0]);
  });
  // Default to Daybreak (light) unless the analyst has chosen otherwise before.
  let saved = "daybreak";
  try { saved = localStorage.getItem("fx-theme") || "daybreak"; } catch (e) {}
  if (saved === "sunset" || saved === "moss") saved = "slate"; // retired themes -> Slate
  apply(saved);
}

async function onNewCase() {
  if (!backend.isLive()) {
    alert("New case ingestion is only available in the desktop app (not the browser preview).");
    return;
  }
  let started = false;
  try {
    const folder = await backend.pickFolder("Choose a folder of extracted artefacts");
    if (!folder) return;                       // cancelled — no overlay shown yet
    const casePath = await backend.pickSaveFile("Save case as…", "case.fxcase");
    if (!casePath) return;                      // cancelled

    started = true;
    showOverlay("Ingesting collection…", "Parsing and hashing artefacts. This can take a few minutes for a full triage set.");
    const overview = await backend.ingest(folder, casePath, baseName(casePath), "analyst");

    showOverlay("Running detections…", "Hunting for financially-motivated-actor TTPs.");
    await backend.runHunt(null);

    hideOverlay();
    await renderCase(overview, `case · ${baseName(casePath)}`);
  } catch (e) {
    alert("Ingest failed:\n" + (e && e.message ? e.message : e));
  } finally {
    hideOverlay();   // never leave the overlay stuck, whatever happened
  }
}

async function onOpenCase() {
  if (!backend.isLive()) {
    alert("Open case is only available in the desktop app (not the browser preview).");
    return;
  }
  try {
    const casePath = await backend.pickOpenFile("Open a .fxcase file");
    if (!casePath) return;
    showOverlay("Opening case…", casePath);
    const overview = await backend.openCase(casePath);
    await renderCase(overview, `case · ${baseName(casePath)}`);
  } catch (e) {
    alert("Could not open case:\n" + (e && e.message ? e.message : e));
  } finally {
    hideOverlay();
  }
}

function baseName(p) {
  return String(p).replace(/\\/g, "/").split("/").pop();
}

// ── Left rail ────────────────────────────────────────────────────────────────
function renderRail() {
  const o = state.overview;
  const artefactFacets = o.by_artefact
    .map((r) => facetRow("artefact", r.label, r.count, catColorForArtefact(r.label)))
    .join("");
  const catFacets = CATEGORIES
    .map(([key, label, color]) => facetRow("category", label, "", color, key))
    .join("");
  const talkers = renderTalkers(o.srum_top_talkers);

  el("rail").innerHTML = `
    <section>
      <div class="metric"><span class="big">${fmt(o.total_events)}</span><span class="lbl">events</span></div>
    </section>
    ${renderFindings()}
    <section class="actlink ${state.view === "activity" ? "active" : ""}" id="activityLink">
      <div class="facet" style="cursor:pointer"><span class="name" style="color:var(--focus)">${state.view === "activity" ? "▾ activity graph" : "▸ activity graph"}</span></div>
      <div class="actlink-sub">events per day · spot untagged spikes</div>
    </section>
    ${renderTriageSummary()}
    <section>
      <h2>Category</h2>
      ${catFacets}
    </section>
    <section>
      <h2>Artefact</h2>
      ${artefactFacets}
    </section>
    <section>
      <h2>Network volume · top talkers</h2>
      ${talkers}
    </section>
    <section>
      <h2>Ingest</h2>
      ${o.ingest.map((r) => `<div class="facet"><span class="name">${r.label}</span><span class="count">${r.count}</span></div>`).join("")}
      <div class="facet" id="ingestLogLink" style="cursor:pointer;color:var(--focus);margin-top:6px"><span class="name" style="color:var(--focus)">▸ view ingest log</span></div>
    </section>`;
}

// Triage summary in the rail: counts per state, click to filter.
const TRI_STATES = [
  ["validated", "Validated", "#2e9e5b"],
  ["unconfirmed", "Unconfirmed", "#c99a2e"],
  ["false_positive", "False positive", "#7a8699"],
  ["dismissed", "Dismissed", "#55607a"],
];
function renderTriageSummary() {
  const t = state.triage || [];
  if (!t.length) return "";
  const counts = {};
  t.forEach((x) => (counts[x.triage_state] = (counts[x.triage_state] || 0) + 1));
  const rows = TRI_STATES.filter(([k]) => counts[k])
    .map(([k, label, color]) => {
      const active = state.filter.triage === k ? "active" : "";
      return `<div class="tri-sum ${active}" data-triage="${k}">
        <span class="dot" style="background:${color}"></span>
        <span class="lbl">${label}</span>
        <span class="cnt">${counts[k]}</span>
      </div>`;
    })
    .join("");
  return `<section><h2>Triage</h2>${rows}</section>`;
}

function facetRow(kind, label, count, color, value) {
  const v = value != null ? value : label;
  const active =
    (kind === "category" && state.filter.category === v) ||
    (kind === "artefact" && state.filter.artefact === v);
  return `<div class="facet ${active ? "active" : ""}" data-kind="${kind}" data-value="${v}">
    <span class="swatch" style="background:${color}"></span>
    <span class="name">${label}</span>
    ${count !== "" ? `<span class="count">${fmt(count)}</span>` : ""}
  </div>`;
}

// Findings: the hunt-result summary, given top billing in the rail because a
// detection is the highest-value thing in a case. Clicking enters the hunt view.
function renderFindings() {
  const d = state.detections || [];
  if (!d.length) return "";
  const bySev = {};
  d.forEach((x) => (bySev[x.severity] = (bySev[x.severity] || 0) + 1));
  const order = ["critical", "high", "medium", "low", "informational"];
  const pills = order
    .filter((s) => bySev[s])
    .map((s) => `<span class="sev-pill sev-${s}">${fmt(bySev[s])} ${s}</span>`)
    .join("");
  const worst = order.find((s) => bySev[s]) || "low";
  const sevColor = { critical: "var(--alert)", high: "#d98c4a", medium: "#d9c04a" }[worst] || "var(--focus)";
  // How much of the list still needs eyes: a detection counts as reviewed once
  // any of its events carries a triage state other than unconfirmed.
  const tri = new Map((state.triage || []).map((t) => [t.event_id, t.triage_state]));
  let reviewed = 0;
  d.forEach((x) => {
    const st = (x.event_ids || []).map((id) => tri.get(id)).find(Boolean);
    if (st && st !== "unconfirmed") reviewed++;
  });
  const toReview = d.length - reviewed;
  const inHunt = state.view === "hunt";
  return `<section class="findings ${inHunt ? "active" : ""}" id="findingsSection">
    <h2>Findings</h2>
    <div class="findings-card" style="--fc-sev:${sevColor}" title="${inHunt ? "Back to the timeline" : "Open the findings list"}">
      <div><span class="fc-count">${fmt(d.length)}</span><span class="fc-lbl">detection${d.length === 1 ? "" : "s"}</span></div>
      <div class="sev-pills" style="margin-top:9px">${pills}</div>
      <div class="fc-tri"><b>${fmt(toReview)}</b> to review · ${fmt(reviewed)} triaged</div>
      <button class="findings-cta" type="button">
        <span>${inHunt ? "Back to timeline" : "Review findings"}</span><span class="arrow">${inHunt ? "←" : "→"}</span>
      </button>
    </div>
  </section>`;
}

function renderTalkers(talkers) {
  if (!talkers || !talkers.length) return `<div class="facet"><span class="name">no SRUM data</span></div>`;
  const max = Math.max(...talkers.map((t) => t.bytes_sent), 1);
  return talkers
    .map((t) => {
      const pct = Math.max(2, Math.round((t.bytes_sent / max) * 100));
      return `<div class="talker">
        <div class="row"><span class="app">${escapeHtml(t.app)}</span><span class="amt">${humanBytes(t.bytes_sent)}↑</span></div>
        <div class="bar"><i style="width:${pct}%"></i></div>
      </div>`;
    })
    .join("");
}

// ── Toolbar ──────────────────────────────────────────────────────────────────
function renderToolbar() {
  const tr = state.filter;
  const hasRange = tr.after || tr.before;
  // The flagged chip and time-range only make sense over the event grid; hide
  // them in the finding / ingest-log / activity views.
  const inHunt = state.view !== "timeline";
  el("toolbar").innerHTML = `
    <span class="chip ${tr.flagged_only ? "on" : ""}" id="flagChip" ${inHunt ? "style=display:none" : ""}>⚑ Flagged only</span>
    <span class="time-range" ${inHunt ? "style=display:none" : ""}>
      <span class="tr-label">from</span>
      <input type="datetime-local" id="trFrom" value="${toLocalInput(tr.after)}" step="1">
      <span class="tr-label">to</span>
      <input type="datetime-local" id="trTo" value="${toLocalInput(tr.before)}" step="1">
      ${hasRange ? `<span class="chip" id="trClear">clear range ✕</span>` : ""}
    </span>
    ${activeFilterChips()}
    <span class="spacer"></span>
    <span class="result-count" id="resultCount"></span>`;

  // Wire the time inputs.
  const from = el("trFrom"), to = el("trTo");
  if (from) from.addEventListener("change", () => { state.filter.after = fromLocalInput(from.value); state.filter.offset = 0; renderToolbar(); refresh(); });
  if (to) to.addEventListener("change", () => { state.filter.before = fromLocalInput(to.value); state.filter.offset = 0; renderToolbar(); refresh(); });
  const clr = el("trClear");
  if (clr) clr.addEventListener("click", () => { state.filter.after = null; state.filter.before = null; state.filter.offset = 0; renderToolbar(); refresh(); });
}

async function exportFindings(format) {
  if (!backend.isLive()) { alert("Export is only available in the desktop app."); return; }
  const hasAny = (state.detections && state.detections.length) || (state.triage && state.triage.length);
  if (!hasAny) { alert("No findings to export. Run a hunt first."); return; }
  try {
    const counts = await backend.exportCounts();
    const states = await chooseExportStates(format, counts);
    if (!states) return; // cancelled
    const path = await backend.pickExportFile(format);
    if (!path) return; // cancelled
    const n = await backend.exportFindings(format, path, states);
    alert(`Exported ${n} finding${n === 1 ? "" : "s"} to:\n${path}`);
  } catch (e) {
    alert("Export failed:\n" + (e && e.message ? e.message : e));
  }
}

// IOC sweep: paste or load an indicator list and hunt the open case for it.
// Post-processing — nothing is re-ingested. Each matched indicator becomes a
// finding (so it can be triaged, exported and reported); a new sweep replaces
// the previous sweep's findings, and re-running the rules keeps them.
let iocPreviewTimer = null;
function openIocSweep() {
  const m = el("iocModal");
  el("iocInput").hidden = false; el("iocResults").hidden = true;
  const ta = el("iocText");
  const preview = async () => {
    const text = ta.value;
    if (!text.trim()) { el("iocPreview").textContent = "No indicators yet."; el("iocGo").disabled = true; el("iocGo").textContent = "Sweep"; return; }
    try {
      const p = await backend.iocPreview(text);
      const kinds = Object.entries(p.by_kind || {}).sort((x, y) => y[1] - x[1]).map(([k, n]) => `${fmt(n)} ${escapeHtml(k)}`).join(" · ");
      el("iocPreview").innerHTML = p.total
        ? `<b>${fmt(p.total)} indicator${p.total === 1 ? "" : "s"}</b>: ${kinds}${p.skipped ? ` <span class="warn">(${p.skipped} too short to search, ignored)</span>` : ""}`
        : `No indicators recognised${p.skipped ? ` (${p.skipped} ignored)` : ""}.`;
      el("iocGo").disabled = !p.total;
      el("iocGo").textContent = p.total ? `Sweep ${fmt(p.total)} indicator${p.total === 1 ? "" : "s"}` : "Sweep";
    } catch (e) { el("iocPreview").textContent = String(e && e.message ? e.message : e); }
  };
  ta.oninput = () => { clearTimeout(iocPreviewTimer); iocPreviewTimer = setTimeout(preview, 180); };
  const close = () => { m.classList.remove("show"); document.removeEventListener("keydown", onKey, true); };
  const onKey = (e) => { if (e.key === "Escape") { e.preventDefault(); close(); } };
  el("iocCancel").onclick = close;
  el("iocClose").onclick = close;
  el("iocAgain").onclick = () => { el("iocResults").hidden = true; el("iocInput").hidden = false; ta.focus(); };
  el("iocFindings").onclick = () => { close(); state.view = "hunt"; state.huntOnly = "ioc"; closeDetail(); renderRail(); renderToolbar(); refresh(); };
  m.onclick = (e) => { if (e.target === m) close(); };
  el("iocLoad").onclick = async () => {
    try {
      const path = await backend.pickIocFile();
      if (!path) return;
      const text = await backend.readIocFile(path);
      ta.value = (ta.value.trim() ? ta.value.trimEnd() + "\n" : "") + text;
      preview();
    } catch (e) { alert("Could not load the file:\n" + (e && e.message ? e.message : e)); }
  };
  el("iocGo").onclick = async () => {
    if (el("iocGo").disabled) return;
    m.classList.remove("show");
    showOverlay("Sweeping for IOCs…", "Searching every event in the case. Large cases take a minute or two.");
    try {
      const r = await backend.iocSweep(ta.value);
      hideOverlay();
      renderIocResults(r);
      m.classList.add("show");
      try { state.detections = (await backend.huntResults()) || []; } catch (e) {}
      renderRail();
      if (state.view === "hunt") refresh();
    } catch (e) {
      hideOverlay(); m.classList.add("show");
      alert("IOC sweep failed:\n" + (e && e.message ? e.message : e));
    }
  };
  document.addEventListener("keydown", onKey, true);
  m.classList.add("show");
  preview();
  ta.focus();
}

function renderIocResults(r) {
  el("iocInput").hidden = true; el("iocResults").hidden = false;
  el("iocSummary").innerHTML = `<b>${fmt(r.matched)}</b> of ${fmt(r.iocs)} indicator${r.iocs === 1 ? "" : "s"} found across ${fmt(r.events_scanned)} events. `
    + (r.matched ? "Each match is now a finding you can triage and export." : "No indicator appears in this case.");
  const hits = r.results.filter((x) => x.events > 0), misses = r.results.filter((x) => !x.events);
  const row = (x) => `<tr class="${x.events ? "hit" : "miss"}"${x.events ? ` data-val="${escapeHtml(x.value)}" title="Show every matching event"` : ""}><td class="v">${escapeHtml(x.value)}</td><td>${escapeHtml(x.kind_label)}</td>`
    + `<td class="n">${x.events ? fmt(x.events) : "—"}</td>`
    + `<td class="ts">${x.first_seen ? escapeHtml(ukDateTime(x.first_seen)) : ""}</td>`
    + `<td class="where">${Object.entries(x.artefacts || {}).map(([k, n]) => `${escapeHtml(k)} ${fmt(n)}`).join(", ")}</td></tr>`;
  el("iocTable").innerHTML = `<thead><tr><th>Indicator</th><th>Type</th><th style="text-align:right">Events</th><th>First seen</th><th>Where</th></tr></thead><tbody>`
    + hits.map(row).join("")
    + (misses.length ? `<tr class="sep" id="iocMissToggle"><td colspan="5">${fmt(misses.length)} not found, click to ${hits.length ? "show" : "hide"}</td></tr>` : "")
    + `</tbody><tbody id="iocMisses"${hits.length ? " hidden" : ""}>${misses.map(row).join("")}</tbody>`;
  const t = el("iocMissToggle");
  if (t) t.onclick = () => { const b = el("iocMisses"); b.hidden = !b.hidden; t.firstChild.textContent = `${fmt(misses.length)} not found, click to ${b.hidden ? "show" : "hide"}`; };
  el("iocFindings").hidden = !r.matched;
  el("iocTable").querySelectorAll("tr.hit[data-val]").forEach((tr) => {
    tr.onclick = () => {
      const v = tr.dataset.val;
      const det = (state.detections || []).find((d) => d.engine === "ioc" && d.rule_id.endsWith(":" + v));
      if (!det || !det.event_ids || !det.event_ids.length) return;
      el("iocModal").classList.remove("show");
      showIocEvents(det);
    };
  });
}

// Show every event an IOC finding matched, in time order, in the timeline.
function showIocEvents(det) {
  const ids = det.event_ids || [];
  if (!ids.length) return;
  const label = det.rule_id.replace(/^ioc:[^:]*:/, "");
  state.view = "timeline";
  state.huntOnly = null;
  state.filter = { text: "", category: null, artefact: null, triage: null, flagged_only: false, limit: 5000, offset: 0 };
  state.idFilter = { label, ids, key: JSON.stringify(state.filter) };
  closeDetail();
  renderRail(); renderToolbar();
  refresh();
}

// Export menu: one top-bar button for all exports. Items keep their original
// ids, so the existing handlers run unchanged; picking one closes the menu.
function wireExportMenu() {
  const wrap = el("exportMenuWrap"), btn = el("exportMenuBtn");
  if (!wrap || !btn) return;
  const close = () => { wrap.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const open = !wrap.classList.contains("open");
    wrap.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", String(open));
    if (open) { const first = wrap.querySelector(".menuitem"); if (first) first.focus(); }
  });
  wrap.querySelectorAll(".menuitem").forEach((it) => it.addEventListener("click", close));
  document.addEventListener("click", (e) => { if (!wrap.contains(e.target)) close(); });
  document.addEventListener("keydown", (e) => {
    if (!wrap.classList.contains("open")) return;
    if (e.key === "Escape") { close(); btn.focus(); }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const items = Array.from(wrap.querySelectorAll(".menuitem"));
      const i = items.indexOf(document.activeElement);
      const n = e.key === "ArrowDown" ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
      items[n].focus(); e.preventDefault();
    }
  });
}

// HTML case report — same output as `fx report`: findings by tactic, ATT&CK
// matrix, timeline and the evidence chain-of-custody table (SHA-256 per file).
async function exportReport() {
  if (!backend.isLive()) { alert("The case report is only available in the desktop app."); return; }
  try {
    const path = await backend.pickExportFile("html");
    if (!path) return; // cancelled
    showOverlay("Building case report…", "Findings, ATT&CK matrix, timeline and evidence hashes.");
    const bytes = await backend.exportReport(path);
    hideOverlay();
    alert(`Case report saved (${humanBytes(bytes)}) to:\n${path}\n\nOpen it in any browser; print to PDF to archive.`);
  } catch (e) {
    hideOverlay();
    alert("Report failed:\n" + (e && e.message ? e.message : e));
  }
}

// Export dialog: pick which triage states go in the file. Resolves to an array
// of state keys, or null if cancelled. Defaults to validated + unconfirmed —
// the findings that still matter — so dismissed / false-positive noise is left
// out of a client-facing export unless the analyst asks for it.
const EXPORT_DEFAULT = ["validated", "unconfirmed"];
const EXPORT_HINTS = {
  validated: "confirmed by an analyst",
  unconfirmed: "not yet reviewed",
  false_positive: "reviewed, benign",
  dismissed: "reviewed, out of scope",
};
function chooseExportStates(format, counts) {
  return new Promise((resolve) => {
    const modal = el("exportModal");
    const label = format === "stix" ? "STIX 2.1" : "CSV";
    el("expTitle").textContent = `Export findings — ${label}`;
    el("expRows").innerHTML = TRI_STATES.map(([k, name, color]) => {
      const n = (counts && counts[k]) || 0;
      const checked = EXPORT_DEFAULT.includes(k) && n > 0 ? "checked" : "";
      return `<label class="exp-row ${n ? "" : "zero"}">
        <input type="checkbox" data-state="${k}" ${checked}>
        <span class="dot" style="background:${color}"></span>
        <span class="lbl">${name}<br><span class="hint">${EXPORT_HINTS[k] || ""}</span></span>
        <span class="cnt">${fmt(n)}</span>
      </label>`;
    }).join("");
    const boxes = () => Array.from(modal.querySelectorAll("input[data-state]"));
    const update = () => {
      const picked = boxes().filter((b) => b.checked).map((b) => b.dataset.state);
      const total = picked.reduce((t, k) => t + ((counts && counts[k]) || 0), 0);
      el("expTotal").textContent = `${fmt(total)} finding${total === 1 ? "" : "s"} selected`;
      el("expGo").textContent = `Export ${fmt(total)}`;
      el("expGo").disabled = total === 0;
    };
    const setTo = (keys) => { boxes().forEach((b) => (b.checked = keys.includes(b.dataset.state))); update(); };
    const close = (result) => {
      modal.classList.remove("show");
      document.removeEventListener("keydown", onKey, true);
      modal.onclick = null;
      resolve(result);
    };
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(null); }
      if (e.key === "Enter" && !el("expGo").disabled) { e.preventDefault(); e.stopPropagation(); el("expGo").click(); }
    };
    modal.onclick = (e) => {
      if (e.target === modal) return close(null);            // backdrop
      if (e.target.closest("input[data-state]")) return update();
      if (e.target.id === "expAll") return setTo(TRI_STATES.map(([k]) => k));
      if (e.target.id === "expNone") return setTo([]);
      if (e.target.id === "expDefault") return setTo(EXPORT_DEFAULT);
      if (e.target.id === "expCancel") return close(null);
      if (e.target.id === "expGo" && !el("expGo").disabled) {
        return close(boxes().filter((b) => b.checked).map((b) => b.dataset.state));
      }
    };
    document.addEventListener("keydown", onKey, true);
    update();
    modal.classList.add("show");
    el("expGo").focus();
  });
}

// Convert stored RFC3339 (UTC) <-> the datetime-local input value.
function toLocalInput(rfc) {
  if (!rfc) return "";
  // rfc like "2020-06-30T14:24:08Z" or "...T14:24:08" — datetime-local wants "YYYY-MM-DDTHH:MM:SS"
  return String(rfc).replace("Z", "").slice(0, 19);
}
function fromLocalInput(v) {
  if (!v) return null;
  // Treat the input as UTC (case timestamps are UTC) and append Z.
  return v.length === 16 ? v + ":00Z" : v + "Z";
}

function activeFilterChips() {
  const chips = [];
  if (state.filter.category) chips.push(clearChip("category", state.filter.category));
  if (state.filter.artefact) chips.push(clearChip("artefact", state.filter.artefact));
  if (state.filter.triage) chips.push(`<span class="chip" data-clear="triage">${state.filter.triage.replace("_"," ")} ✕</span>`);
  return chips.join("");
}
function clearChip(kind, value) {
  return `<span class="chip" data-clear="${kind}">${value} ✕</span>`;
}

// ── Timeline (virtualized) ───────────────────────────────────────────────────
async function refresh() {
  if (el("idfBar") && (state.view !== "timeline" || !state.idFilter)) el("idfBar").hidden = true;
  if (state.view === "hunt") {
    renderHuntView();
    return;
  }
  if (state.view === "ingestlog") {
    await renderIngestLog();
    return;
  }
  if (state.view === "activity") {
    await renderActivityGraph();
    return;
  }
  if (state.idFilter && state.idFilter.key !== JSON.stringify(state.filter)) state.idFilter = null;
  if (!state.idFilter && el("idfBar")) el("idfBar").hidden = true;
  if (state.idFilter) {
    const f = state.idFilter;
    state.rows = await backend.eventsByIds(f.ids);
    state.total = state.rows.length;
    const n = state.rows.length;
    el("resultCount").textContent = `${fmt(n)} event${n === 1 ? "" : "s"}`;
    const bar = el("idfBar");
    bar.innerHTML = `<span class="idf-tag">IOC</span><span class="idf-val" title="${escapeHtml(f.label)}">${escapeHtml(f.label)}</span>`
      + `<span class="idf-n">${fmt(n)} matching event${n === 1 ? "" : "s"}${f.ids.length >= 500 ? " (first 500)" : ""}</span><span class="idf-sp"></span>`
      + `<button class="idf-btn" id="idfBack">Back to IOC matches</button><button class="idf-btn" id="idfClear">Clear filter</button>`;
    bar.hidden = false;
    el("idfBack").onclick = () => { state.idFilter = null; state.view = "hunt"; state.huntOnly = "ioc"; closeDetail(); renderRail(); renderToolbar(); refresh(); };
    el("idfClear").onclick = () => { state.idFilter = null; refresh(); };
    renderStatus();
    renderWindow();
    viewport.scrollTop = 0;
    requestAnimationFrame(() => requestAnimationFrame(calibrateRowHeight));
    return;
  }
  state.rows = await backend.queryTimeline({ ...state.filter });
  // Client-side triage filter (the triage state lives in state.triage). Triage
  // sets are small, so this stays a page-local filter and paging is suppressed
  // while a triage filter is active.
  const triageActive = !!state.filter.triage;
  if (triageActive) {
    const ids = new Set((state.triage || []).filter((t) => t.triage_state === state.filter.triage).map((t) => t.event_id));
    state.rows = state.rows.filter((r) => ids.has(r.id));
  }

  // Total matches across the whole case (SQL COUNT), for the "N–M of TOTAL"
  // indicator and Next/Prev. Skipped under a triage filter (page-local).
  state.total = null;
  if (!triageActive) {
    try { state.total = await backend.countTimeline({ ...state.filter }); } catch (e) { state.total = null; }
  }
  renderResultCount(triageActive);
  renderStatus();
  renderWindow();
  viewport.scrollTop = 0; // a new page starts at the top
  // Calibrate the row height once, after layout. Not re-run during scroll.
  requestAnimationFrame(() => requestAnimationFrame(calibrateRowHeight));
}

// Result-count + paging indicator. Shows the window position within the full
// matching set and Prev/Next when there's more than one page.
function renderResultCount(triageActive) {
  const el0 = el("resultCount");
  if (!el0) return;
  const shown = state.rows.length;
  const limit = state.filter.limit || 1000;
  const offset = state.filter.offset || 0;
  if (triageActive || state.total == null) {
    el0.textContent = `${fmt(shown)} shown`;
    return;
  }
  const total = state.total;
  const from = total === 0 ? 0 : offset + 1;
  const to = offset + shown;
  const hasPrev = offset > 0;
  const hasNext = to < total;
  const pages = hasPrev || hasNext;
  el0.innerHTML =
    `<span class="rc-range">${fmt(from)}–${fmt(to)}</span> of <span class="rc-total">${fmt(total)}</span>` +
    (pages
      ? ` <button class="pg-btn" id="pgPrev" ${hasPrev ? "" : "disabled"}>‹ prev</button>` +
        `<button class="pg-btn" id="pgNext" ${hasNext ? "" : "disabled"}>next ›</button>`
      : "");
  const prev = el("pgPrev"), next = el("pgNext");
  if (prev) prev.addEventListener("click", () => { state.filter.offset = Math.max(0, offset - limit); refresh(); });
  if (next) next.addEventListener("click", () => { state.filter.offset = offset + limit; refresh(); });
}

// The hunt view replaces the virtualized grid with a detections list — few
// enough that no virtualization is needed. Worst-first, each row expandable to
// its ATT&CK techniques and a pivot back to the contributing events.
function renderHuntView() {
  const rules = state.detections || [];
  // Manual findings: triaged events not already covered by a rule detection.
  const covered = new Set(rules.flatMap((d) => d.event_ids || []));
  const manual = (state.triage || [])
    .filter((t) => !covered.has(t.event_id))
    .map((t) => ({
      rule_id: "manual-triage",
      title: "Analyst finding: " + (t.message ? t.message.split("\n")[0].slice(0, 80) : t.event_id),
      severity: t.triage_state === "validated" ? "high" : (t.triage_state === "false_positive" || t.triage_state === "dismissed" ? "info" : "medium"),
      attack: [],
      summary: t.message || "",
      event_ids: [t.event_id],
      ts: t.ts || "",
      host: t.host || null,
      engine: "manual",
    }));
  let d = rules.concat(manual);
  if (state.huntOnly === "ioc") {
    d = rules.filter((x) => x.engine === "ioc");
    el("resultCount").innerHTML = `${fmt(d.length)} IOC match${d.length === 1 ? "" : "es"} <button class="linkbtn" id="huntShowAll">Show all findings</button>`;
    el("huntShowAll").onclick = () => { state.huntOnly = null; renderHuntView(); };
  } else {
    const manualNote = manual.length ? ` (${rules.length} rule + ${manual.length} analyst)` : "";
    el("resultCount").textContent = `${fmt(d.length)} findings${manualNote}`;
  }
  el("spTop").style.height = "0px";
  el("spBot").style.height = "0px";
  el("rows").innerHTML = d.map(huntRowHtml).join("") ||
    `<div class="empty"><div class="box"><h2>No findings</h2><p>No rule detections and nothing triaged yet. Validate events in the timeline to add analyst findings here.</p></div></div>`;
  // Clicking a finding jumps to its event in the timeline + opens the detail
  // pane (raw record + triage buttons live there).
  el("rows").querySelectorAll(".hitrow[data-event]").forEach((row) => {
    row.addEventListener("click", () => {
      const det = row.dataset.rule ? d.find((x) => x.rule_id === row.dataset.rule && x.engine === "ioc") : null;
      if (det) showIocEvents(det); else openFindingEvent(row.dataset.event, row.dataset.ts || "");
    });
  });
  renderStatus();
}

function huntRowHtml(d) {
  const attack = (d.attack || []).map((t) => `<span class="att">${t}</span>`).join("");
  const eng = d.engine === "correlation" ? "correlated" : d.engine === "ioc" ? "IOC match" : "single-event";
  const eid = (d.event_ids && d.event_ids.length) ? d.event_ids[0] : "";
  const tri = eid ? triageStateFor(eid) : "";
  const triBadge = tri ? `<span class="tri-badge ${tri}">${tri.replace("_"," ")}</span>` : "";
  return `<div class="hitrow sev-border-${d.severity}" data-event="${eid}" data-ts="${escapeHtml(d.ts || "")}"${d.engine === "ioc" ? ` data-rule="${escapeHtml(d.rule_id)}"` : ""}>
    <div class="hit-main">
      <span class="sev-tag sev-${d.severity}">${d.severity}</span>
      <span class="hit-title">${escapeHtml(d.title)}</span>
      <span class="hit-att">${triBadge}${attack}</span>
    </div>
    <div class="hit-sub">
      <span class="hit-summary">${escapeHtml(d.summary)}</span>
      <span class="hit-meta">${time(d.ts)} · ${d.host || "—"} · ${eng} · ${d.engine === "ioc" ? "click to show all matching events" : "click to open"} ▸</span>
    </div>
  </div>`;
}

// Jump from a finding to its underlying event: switch to the timeline, find
// the event, select it (which opens the detail pane with raw + triage).
async function openFindingEvent(eventId, findingTs) {
  if (!eventId) {
    // Correlation findings may not carry a single pivot event.
    return;
  }
  state.view = "timeline";

  // The timeline only holds a windowed page (limit rows), so in a multi-million
  // event case the target event is almost never in the first page. Instead of
  // loading from the top and hoping, we find the event's own timestamp and load
  // a tight time-window around it — that page is guaranteed to contain it.
  let ts = await eventTimestamp(eventId);
  if (!ts) ts = normaliseTs(findingTs); // fall back to the detection's ts
  state.filter = { text: "", category: null, artefact: null, triage: null, flagged_only: false, limit: 5000, offset: 0 };

  if (ts) {
    // Anchor the page a short lead-in BEFORE the event (events are ordered by
    // ascending ts, so starting just before it puts the target within the first
    // rows of the page — guaranteed present however busy that day is, unlike a
    // centred window that can overflow the row cap on a high-volume day). The
    // 2-minute lead-in gives a little context above the event.
    state.filter.after = shiftIso(ts, -120);
    renderRail(); renderToolbar();
    await refresh();
    const idx = state.rows.findIndex((r) => r.id === eventId);
    if (idx >= 0) {
      viewport.scrollTop = Math.max(0, idx * state.rowH - viewport.clientHeight / 3);
      renderWindow();
      await select(eventId);
      return;
    }
  }

  // Fallback: no timestamp available. Load unfiltered from the top and try once.
  state.filter.after = null; state.filter.before = null;
  renderRail(); renderToolbar();
  await refresh();
  const idx = state.rows.findIndex((r) => r.id === eventId);
  if (idx >= 0) {
    viewport.scrollTop = Math.max(0, idx * state.rowH - viewport.clientHeight / 3);
    renderWindow();
    await select(eventId);
  } else {
    alert("Couldn't locate this finding's event in the timeline — try searching for it directly from the toolbar.");
  }
}

// Authoritative event timestamp from its raw record (ISO, UTC). Returns "" if
// unavailable (demo mode or missing field).
async function eventTimestamp(eventId) {
  try {
    const raw = await backend.eventRaw(eventId);
    if (!raw) return "";
    // raw is a JSON string; pull the top-level timestamp field.
    const obj = typeof raw === "string" ? JSON.parse(raw) : raw;
    const t = obj && (obj.timestamp || obj.ts || obj.time);
    return normaliseTs(t);
  } catch (e) { return ""; }
}

// Normalise a timestamp to "YYYY-MM-DDTHH:MM:SSZ" for the time filter.
function normaliseTs(t) {
  if (!t) return "";
  let s = String(t).trim();
  if (!s) return "";
  s = s.replace(" ", "T").replace("Z", "");
  // keep to seconds precision
  s = s.slice(0, 19);
  return s.length >= 19 ? s + "Z" : "";
}

// Shift an ISO-UTC timestamp by N seconds, returning the same format.
function shiftIso(iso, deltaSec) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  d.setTime(d.getTime() + deltaSec * 1000);
  return d.toISOString().slice(0, 19) + "Z";
}

function renderWindow() {
  const rowH = state.rowH;
  const total = state.rows.length;
  const scrollTop = viewport.scrollTop;
  const vpH = viewport.clientHeight;
  const overscan = 8;
  const first = Math.max(0, Math.floor(scrollTop / rowH) - overscan);
  const visibleCount = Math.ceil(vpH / rowH) + overscan * 2;
  const last = Math.min(total, first + visibleCount);

  el("spTop").style.height = first * rowH + "px";
  el("spBot").style.height = (total - last) * rowH + "px";

  const frag = [];
  for (let i = first; i < last; i++) frag.push(rowHtml(state.rows[i]));
  el("rows").innerHTML = frag.join("");
}

// Measure the true row height ONCE from a rendered row and, if it differs from
// our assumed 30px, adopt it and re-lay-out. This runs only on (re)load — never
// during scroll. The previous design re-measured on every scroll frame, and in
// WebView2 a transient/fractional measurement mid-flick mutated rowH, which
// collapsed the spacer math and threw the viewport to the bottom. Measuring once
// keeps the row height stable, so scrolling maps 1:1 and never jumps.
function calibrateRowHeight() {
  if (state._rowHCalibrated) return;
  const sample = el("rows").firstElementChild;
  if (!sample) return;
  const measured = Math.round(sample.getBoundingClientRect().height);
  state._rowHCalibrated = true;
  if (measured > 0 && Math.abs(measured - state.rowH) >= 1) {
    state.rowH = measured;
    renderWindow();
  }
}

function rowHtml(e) {
  if (!e) return "";
  const color = CAT_COLOR[e.category] || "var(--cat-other)";
  const sel = e.id === state.selectedId ? "sel" : "";
  const flagged = e.flagged ? "flagged" : "";
  const pill = e.flagged ? `<span class="flag-pill">${tagLabel(e)}</span>` : "";
  const tri = triageStateFor(e.id);
  const triBadge = tri ? `<span class="tri-badge ${tri}">${tri.replace("_"," ").slice(0,4)}</span>` : "";
  // Full message + full UK timestamp on hover, so a truncated row is readable
  // without opening the detail pane.
  const tip = `${time(e.ts)} · ${e.artefact}${e.user ? " · " + e.user : ""}\n${e.message || ""}`;
  return `<div class="evrow ${sel} ${flagged}" data-id="${e.id}" title="${escapeHtml(tip)}">
    <span class="cat-tick" style="background:${color}"></span>
    <span class="c ts">${time(e.ts)}</span>
    <span class="c kind">${e.ts_kind}</span>
    <span class="c art" style="color:${color}">${e.artefact}</span>
    <span class="c user">${e.user ? escapeHtml(e.user) : "—"}</span>
    <span class="c msg">${triBadge}${pill}${escapeHtml(e.message)}</span>
  </div>`;
}

function tagLabel(e) {
  const m = e.message || "";
  const tag = e._tag || "";
  if (m.includes("MASQUERADE") || tag === "MASQUERADE") return "MASQ";
  if (m.includes("STAGING") || tag === "STAGING") return "STAGE";
  if (m.includes("ANTI-FORENSIC") || tag === "ANTI-FORENSIC") return "A-F";
  if (tag === "LEAKSITE") return "LEAK";
  if (tag === "EXFIL") return "EXFIL";
  return "FLAG";
}

// ── Detail pane ──────────────────────────────────────────────────────────────
async function select(id) {
  state.selectedId = id;
  const e = state.rows.find((r) => r.id === id);
  if (!e) return;
  document.querySelectorAll(".evrow").forEach((r) => r.classList.toggle("sel", r.dataset.id === id));
  el("app").classList.add("detail-open");

  const raw = await backend.eventRaw(id);
  el("detail").innerHTML = `
    <div class="detail-head">
      <span class="close" id="detClose">✕</span>
      <div class="action">${e.action}</div>
      <div class="when">${time(e.ts)} · ${e.ts_kind}</div>
    </div>
    <section>
      <h3>Event</h3>
      <dl class="kv">
        <dt>Artefact</dt><dd>${e.artefact}</dd>
        <dt>Category</dt><dd>${e.category}</dd>
        <dt>Host</dt><dd>${e.host || "—"}</dd>
        <dt>User</dt><dd>${e.user ? escapeHtml(e.user) : "—"}</dd>
        ${e.source_ref ? `<dt>Source</dt><dd style="font-family:var(--mono);font-size:11px">${escapeHtml(e.source_ref)}</dd>` : ""}
      </dl>
      <div class="pivot-btns">
        <span class="pivot-label">Pivot around this event:</span>
        <button class="pv-btn" data-pivot="60">±1m</button>
        <button class="pv-btn" data-pivot="300">±5m</button>
        <button class="pv-btn" data-pivot="1800">±30m</button>
        <button class="pv-btn" data-pivot="3600">±1h</button>
      </div>
    </section>
    <section>
      <h3>Triage</h3>
      <div class="triage-btns">
        <button class="tri-btn tri-validated"       data-state="validated">Validated</button>
        <button class="tri-btn tri-unconfirmed"      data-state="unconfirmed">Unconfirmed</button>
        <button class="tri-btn tri-false_positive"   data-state="false_positive">False positive</button>
        <button class="tri-btn tri-dismissed"        data-state="dismissed">Dismissed</button>
        <button class="tri-btn tri-clear"            data-state="">Clear</button>
      </div>
      <textarea id="triNote" class="tri-note" placeholder="Analyst note (optional)…">${escapeHtml(triageNoteFor(id))}</textarea>
    </section>
    ${e.flagged ? `<section><h3>Why flagged</h3><div class="prov-note" style="color:var(--alert)">${escapeHtml(flagReason(e))}</div></section>` : ""}
    <section>
      <h3>Message</h3>
      <div style="font-size:12.5px;line-height:1.6;color:var(--ink)">${escapeHtml(e.message)}</div>
    </section>
    <section>
      <h3>Raw record</h3>
      <pre class="raw">${raw ? escapeHtml(raw) : "no raw record"}</pre>
      <div class="prov-note">Every event traces to a hashed evidence file via its parser and source reference — this is the record as parsed, retained losslessly for defensibility.</div>
    </section>`;
  el("detClose").onclick = closeDetail;

  // Pivot buttons: set a time window around this event and show the timeline.
  document.querySelectorAll("#detail .pv-btn").forEach((btn) => {
    btn.onclick = () => {
      const secs = parseInt(btn.dataset.pivot, 10);
      const t = Date.parse((e.ts || "").replace(" ", "T").replace("Z", "") + "Z");
      if (isNaN(t)) return;
      const iso = (ms) => new Date(ms).toISOString().slice(0, 19) + "Z";
      state.view = "timeline";
      state.filter.after = iso(t - secs * 1000);
      state.filter.before = iso(t + secs * 1000);
      state.filter.category = null; state.filter.artefact = null; state.filter.triage = null;
      state.filter.offset = 0;
      renderRail(); renderToolbar(); refresh();
    };
  });

  // Highlight the current triage state and wire the buttons.
  const cur = triageStateFor(id);
  document.querySelectorAll("#detail .tri-btn").forEach((btn) => {
    if (btn.dataset.state === cur) btn.classList.add("active");
    btn.onclick = async () => {
      const st = btn.dataset.state;
      const note = (el("triNote") && el("triNote").value.trim()) || null;
      try {
        if (st === "") { await backend.clearTriage(id); removeTriage(id); }
        else { await backend.setTriage(id, st, note); upsertTriage(id, st, note); }
        // re-render this event's detail + the rail summary + the row badge
        await select(id);
        renderRail();
        renderWindowIfTimeline();
        if (state.view === "hunt") renderHuntView();
        if (state.view === "activity") renderActivityGraph(); // flagged base reflects triage live
      } catch (err) {
        alert("Could not save triage: " + (err && err.message ? err.message : err));
      }
    };
  });
}

// ── Triage state (client-side cache mirrors the backend) ─────────────────────
function triageStateFor(id) {
  const t = (state.triage || []).find((x) => x.event_id === id);
  return t ? t.triage_state : "";
}
function triageNoteFor(id) {
  const t = (state.triage || []).find((x) => x.event_id === id);
  return t && t.note ? t.note : "";
}
function upsertTriage(id, st, note) {
  state.triage = (state.triage || []).filter((x) => x.event_id !== id);
  state.triage.push({ event_id: id, triage_state: st, note: note || null });
}
function removeTriage(id) {
  state.triage = (state.triage || []).filter((x) => x.event_id !== id);
}
function renderWindowIfTimeline() {
  if (state.view === "timeline") renderWindow();
}
function closeDetail() {
  state.selectedId = null;
  el("app").classList.remove("detail-open");
  document.querySelectorAll(".evrow").forEach((r) => r.classList.remove("sel"));
}
function flagReason(e) {
  const m = e.message || "";
  const tag = e._tag || "";
  if (m.includes("MASQUERADE") || tag === "MASQUERADE")
    return "A Windows system-binary name recorded at a non-System32 path — classic masquerading (T1036.005).";
  if (m.includes("STAGING") || tag === "STAGING")
    return "File in a common staging directory (Temp / Downloads / Public / ProgramData) — a favoured drop location for tooling before use (T1204).";
  if (m.includes("ANTI-FORENSIC") || tag === "ANTI-FORENSIC")
    return "Rename/delete pattern consistent with ransomware encryption or secure-deletion tooling — an anti-forensic signal worth correlating across the surrounding minutes.";
  if (tag === "LEAKSITE")
    return "Browser visited a known ransomware leak-site / negotiation portal — highly unusual on a normal endpoint (T1657).";
  if (tag === "EXFIL")
    return "Browser visited a web file-drop service routinely used for exfiltration (T1567).";
  return "Flagged by a parse-time heuristic — see the raw record for the matching field.";
}

// ── Status bar ───────────────────────────────────────────────────────────────
function renderStatus() {
  const live = backend.isLive();
  el("status").innerHTML = `
    <span class="${live ? "live" : ""}">${live ? "● connected to case store" : "● demo mode — sample data"}</span>
    <span class="sep">│</span>
    <span>${fmt(state.rows.length)} / ${fmt(state.overview ? state.overview.total_events : 0)} events</span>
    <span class="sep">│</span>
    <span>UTC</span>
    <span class="sep">│</span>
    <span>timeline order: ascending</span>`;
}

// ── Events ───────────────────────────────────────────────────────────────────
let _scrollPosTimer = null;
function updateScrollPos() {
  const sp = el("scrollPos");
  if (!sp) return;
  const total = state.rows.length;
  if (!total) { sp.classList.remove("show"); return; }
  // The row nearest the top of the viewport.
  const idx = Math.min(total - 1, Math.max(0, Math.round(viewport.scrollTop / state.rowH)));
  const row = state.rows[idx];
  const date = row && row.ts ? time(row.ts) : "";
  sp.innerHTML = `<span class="sp-row">${fmt(idx + 1)}</span> / ${fmt(total)}${date ? ` · <span class="sp-date">${date}</span>` : ""}`;
  sp.classList.add("show");
  clearTimeout(_scrollPosTimer);
  _scrollPosTimer = setTimeout(() => sp.classList.remove("show"), 900);
}

function wireEvents() {
  let scrollRAF = null;
  viewport.addEventListener("scroll", () => {
    // Only the timeline view is virtualized. In the findings (hunt) view the
    // list is fully rendered, so scrolling must NOT re-render — doing so would
    // replace the findings with timeline rows.
    if (state.view !== "timeline") return;
    if (scrollRAF) return;
    scrollRAF = requestAnimationFrame(() => { renderWindow(); updateScrollPos(); scrollRAF = null; });
  });
  window.addEventListener("resize", () => {
    if (state.view === "timeline") renderWindow();
    else if (state.view === "activity") layoutActivityChart();
  });

  el("rows").addEventListener("click", (e) => {
    const row = e.target.closest(".evrow");
    if (row) select(row.dataset.id);
  });

  el("rail").addEventListener("click", (e) => {
    // Findings section toggles the hunt view.
    if (e.target.closest("#findingsSection")) {
      state.view = state.view === "hunt" ? "timeline" : "hunt";
      state.huntOnly = null;
      closeDetail();
      renderRail();
      renderToolbar();
      refresh();
      return;
    }
    if (e.target.closest("#ingestLogLink")) {
      state.view = state.view === "ingestlog" ? "timeline" : "ingestlog";
      closeDetail();
      renderRail();
      renderToolbar();
      refresh();
      return;
    }
    if (e.target.closest("#activityLink")) {
      state.view = state.view === "activity" ? "timeline" : "activity";
      closeDetail();
      renderRail();
      renderToolbar();
      refresh();
      return;
    }
    // Triage summary row toggles a triage-state filter (in the timeline view).
    const triRow = e.target.closest(".tri-sum");
    if (triRow && triRow.dataset.triage) {
      const v = triRow.dataset.triage;
      state.view = "timeline";
      state.filter.triage = state.filter.triage === v ? null : v;
      state.filter.offset = 0;
      renderRail(); renderToolbar(); refresh();
      return;
    }
    const facet = e.target.closest(".facet");
    if (!facet || !facet.dataset.kind) return;
    const { kind, value } = facet.dataset;
    // toggle — and always drop back to the timeline to show the filtered events
    state.view = "timeline";
    state.filter[kind] = state.filter[kind] === value ? null : value;
    state.filter.offset = 0;
    renderRail(); renderToolbar(); refresh();
  });

  el("toolbar").addEventListener("click", (e) => {
    if (e.target.id === "flagChip") {
      state.filter.flagged_only = !state.filter.flagged_only;
      state.filter.offset = 0;
      renderToolbar(); refresh(); return;
    }
    const clear = e.target.closest("[data-clear]");
    if (clear) {
      state.filter[clear.dataset.clear] = null;
      state.filter.offset = 0;
      renderRail(); renderToolbar(); refresh();
    }
  });

  const search = el("search");
  let deb = null;
  search.addEventListener("input", () => {
    clearTimeout(deb);
    deb = setTimeout(() => {
      state.filter.text = search.value.trim();
      state.filter.offset = 0;
      refresh();
    }, 140);
  });
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); search.focus(); }
    if (e.key === "Escape") closeDetail();
    // Keyboard navigation of the timeline — precise movement through a long list
    // without fighting trackpad momentum. Ignored while typing in a field.
    if (state.view !== "timeline") return;
    const tag = (e.target && e.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    const page = Math.max(1, Math.floor(viewport.clientHeight / state.rowH) - 1);
    const maxTop = Math.max(0, viewport.scrollHeight - viewport.clientHeight);
    let handled = true;
    switch (e.key) {
      case "PageDown": viewport.scrollTop = Math.min(maxTop, viewport.scrollTop + page * state.rowH); break;
      case "PageUp":   viewport.scrollTop = Math.max(0, viewport.scrollTop - page * state.rowH); break;
      case "Home":     viewport.scrollTop = 0; break;
      case "End":      viewport.scrollTop = maxTop; break;
      case "ArrowDown": viewport.scrollTop = Math.min(maxTop, viewport.scrollTop + state.rowH); break;
      case "ArrowUp":   viewport.scrollTop = Math.max(0, viewport.scrollTop - state.rowH); break;
      default: handled = false;
    }
    if (handled) { e.preventDefault(); renderWindow(); updateScrollPos(); }
  });
}

// ── helpers ──────────────────────────────────────────────────────────────────
// Display timestamps in UK format: DD/MM/YYYY HH:MM:SS. Input is the stored
// UTC value ("YYYY-MM-DDTHH:MM:SS" or "...Z"); storage/sorting/filtering all
// stay ISO — only the display changes. All times are UTC.
function time(iso) {
  if (!iso) return "";
  const s = String(iso).replace("Z", "");
  const [datePart, timePart = ""] = s.split("T");
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(datePart);
  const uk = m ? `${m[3]}/${m[2]}/${m[1]}` : datePart;
  return timePart ? `${uk} ${timePart}` : uk;
}
// UK date only, from a YYYY-MM-DD string.
function ukDate(ymd) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(ymd || ""));
  return m ? `${m[3]}/${m[2]}/${m[1]}` : String(ymd || "");
}
function ukDateTime(ts) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/.exec(String(ts || ""));
  return m ? `${m[3]}/${m[2]}/${m[1]} ${m[4]}:${m[5]}` : String(ts || "");
}
function short(id) { return (id || "").slice(0, 8); }
function fmt(n) { return (n ?? 0).toLocaleString("en-GB"); }
function humanBytes(n) {
  const u = ["B","KB","MB","GB","TB"]; let v = n, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${n} B` : `${v.toFixed(1)} ${u[i]}`;
}
function catColorForArtefact(art) {
  const map = { Prefetch:"execution", UserAssist:"execution", Amcache:"execution", BamDam:"execution",
    RegistryRun:"persistence", RegistryService:"persistence",
    Mft:"filesystem", UsnJrnl:"filesystem", Srum:"network", RegistryGeneric:"network", Evtx:"logon" };
  return CAT_COLOR[map[art]] || "var(--cat-other)";
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}

// Start the app only after every top-level const/function above is
// defined — init() transitively uses consts like TRI_STATES/HELP_HTML,
// which would throw a temporal-dead-zone ReferenceError if run earlier.
init();
