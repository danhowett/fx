# fx — architecture & internals

This document is the deeper technical reference behind the
[README](README.md): design principles, data flow, crate layout, the hunt
engine, and per-artefact coverage notes. For *using* fx see [`HELP.md`](HELP.md)
and [`RUNBOOK.md`](RUNBOOK.md); for *building* it see [`INSTALL.md`](INSTALL.md).

---

## Design principles (locked)

1. **Content beats layout beats extension.** A file's type is decided by magic
   bytes first; path/name only disambiguates artefacts that share a container
   (all registry hives are `regf`; SRUM/Windows.edb/some AmCache are all ESE).
2. **Never trust a manifest as fact.** Collection-format metadata (host,
   timezone, time) is recorded as an *assertion* and verified against artefact
   content — never believed blindly.
3. **Never silently drop a file.** Anything unidentified goes to a visible
   unclassified bucket. "340 files I couldn't classify" is information.
4. **One normalized schema.** Every parser emits `fx_core::Event`; everything
   downstream depends only on that, never on artefact format.
5. **Per-artefact fault isolation.** One malformed artefact never aborts a case.
6. **Provenance on every event.** Each event traces back to a file, a parser
   (with version), and a record locator.

---

## Data flow

```
extracted collection dir (any layout)
        │
        ▼
fx-identify: scan_collection
   ├─ profiles.rs   Layer 1 — collection format (hint, never a gate)
   ├─ signatures.rs magic-byte container detection (authoritative)
   ├─ identifier.rs container + schema/path -> IdentifiedArtefact
   └─ walker.rs     recursive walk, partitions known vs unclassified
        │  Vec<IdentifiedArtefact>  (+ unclassified bucket)
        ▼
fx-parsers: ParserRegistry  (dispatch keyed on ArtefactKind — NOT extension)
   └─ parsers/{evtx,mft,...}  each: IdentifiedArtefact -> Vec<Event>
        │  stream of fx_core::Event
        ▼
fx-ingest: orchestrator
   register+hash evidence -> dispatch+parse -> stream events -> ingest report
        │
        ▼
fx-store: one DuckDB .fxcase file
   evidence (hashed) · events (timeline) · unclassified · ingest_report · tags
        │
        ▼
   query API  →  timeline / dashboard / hunts  →  GUI
```

---

## Crate layout

- **`fx-core`** — schema (`Event`), parser contract (`Parser`, `EventSink`),
  identification types (`IdentifiedArtefact`, `CollectionProfile`). Depends on
  nothing else in the workspace.
- **`fx-identify`** — magic-byte signatures, artefact identifier, collection
  profilers, directory walker.
- **`fx-parsers`** — concrete parsers + the dispatch registry.
- **`fx-store`** — DuckDB case container: schema, evidence hashing, batched event
  writer, read-side queries.
- **`fx-ingest`** — end-to-end orchestrator (identify → hash → parse → persist).
- **`fx-hunt`** — the two detection engines and the rule pack.
- **`fx-cli`** — the `fx` binary.
- **`fx-gui`** — the Tauri v2 desktop app.

Dependency direction is strict and one-way: everything points at `fx-core`.

---

## Hunt engine (`crates/hunt`)

The differentiator. Two engines, one `fx_core::Detection` result:

**Single-event rules** — a focused Sigma-subset (field conditions with
equals/contains/startswith/endswith/regex + all/any/not) matched in Rust over a
streamed pass of the events table. Rules reference stable dotted field names
(`process.command_line`, `target.path`, `action`…) so one rule fires across
every artefact that populates that field.

**Correlation rules** — behaviours a single event can't express, compiled to
windowed SQL over a small set of safe primitives:

- `threshold_window` — N events in M seconds, grouped (mass-rename ransomware).
- `sequence` — A-then-B within a window on a shared key (RDP logon then tooling).
- `raw_sum_threshold` — aggregate a numeric field from `raw` JSON past a
  threshold (SRUM silent exfil).

Rules **can't run arbitrary SQL** — group/join columns are whitelisted, so a bad
rule fails closed. Rules are YAML, loaded at runtime (`crates/hunt/rules/`), so
analysts extend coverage without a rebuild.

### A note on correlation performance

The `sequence` primitive pre-filters **both** sides to the matching actions in
CTEs first, then range-joins the two small sets — rather than self-joining the
whole `events` table with the action filters in the `ON`/`WHERE`. On a
single-host case with millions of rows the naïve self-join is effectively
O(n²) and took 30+ minutes; the CTE form runs in ~1 second.

### Importing external IOC packs (`fx import-iocs`)

The importer converts an MFIRfinder-style JSON pack into native rules:

```
fx import-iocs pack.json crates/hunt/rules/imported/
fx hunt case.fxcase --rules crates/hunt/rules/imported/
```

Validated against a real financially-motivated-actor pack (initial access →
impact), mapping the pack's `regex` / `filename` / `field_contains` /
`field_equals` / `event_id` primitives onto the normalized schema. The import is
defensive and transparent — it **surfaces** rather than hides the issues it
finds (fragile greedy-regex repair with a logged change set, rules dormant until
a parser lands, duplicate rule ids de-duplicated). An independent pack
converging on the same field model is a good sign the normalized schema is
right.

---

## EVTX channel coverage

The EVTX parser maps event ids across the log sources financially-motivated
intrusions actually touch, and lifts EventData into the normalized fields hunts
match on (so a command-line rule fires whether the command came from Security
4688, Sysmon 1, or a PowerShell script block):

| Channel | High-value ids | Normalized signal |
|---------|----------------|-------------------|
| Security auditing | 4624/4625/4634/4648/4672 | logon success/failure/logoff/explicit-creds/admin-privs (+ source IP, logon type) |
| Security auditing | 4688 | process creation with **command line** |
| Security auditing | 4720/4722/4724-4726/4728/4732/4738/4756 | account & privileged-group management (rogue admins) |
| Security auditing | 4698/4699/4702 | scheduled-task create/delete/update |
| Security auditing | 4778/4779 | RDP session reconnect/disconnect (+ client IP) |
| Security auditing | 5140/5145 | network-share access (lateral movement / staging) |
| Security auditing | 1102 / 4719 | security-log cleared / audit-policy changed (anti-forensics) |
| System (SCM) | 7045/7040/7036 | service install / start-type / state change |
| Sysmon | 1,3,7,8,10,11,12-14,22,23 | process, network, image-load, remote-thread, **lsass access**, file, registry, DNS (+ SHA1) |
| PowerShell | 4103/4104 | pipeline + **script-block text** (obfuscated PS) |
| Windows Defender | 1116/1117/5001/5007 | detection + **tampering** (RTP off, exclusions) |
| Terminal Services | 21/22/25 | RDP logon (+ source address) |
| WMI-Activity | 5857-5861 | WMI subscription persistence |

Unmapped ids are not lost — they produce `evtx.eid.N` events with the raw record
retained, so a rule can still match on `event.id` or `message`.

---

## Registry coverage

One pass over a hive routes each key to modular extractors:

| Extractor       | Artefact / signal                     | ATT&CK        |
|-----------------|---------------------------------------|---------------|
| Run/RunOnce     | autostart persistence                 | T1547.001     |
| Services        | service persistence + lateral tooling | T1543.003     |
| AppCompatCache  | execution/presence (blob decode TODO) | T1112         |
| UserAssist      | GUI program execution (ROT13 names)   | T1204         |
| BAM/DAM         | per-user execution times, keyed by SID| —             |
| RDP config      | fDenyTSConnections lateral-move enabler| T1021.001    |

Adding a registry artefact = adding one `Extractor` to `default_extractors()`.

---

## AmCache & USN coverage

AmCache is presence evidence (path + SHA-1) that survives binary self-deletion —
prime for identifying ransomware tooling and pivoting to threat intel. Two
triage detections fire at parse time: a system-binary name at a non-System32
path (masquerade, T1036.005) and any executable inventoried from a staging
directory (Temp/Downloads/AppData/ProgramData/$Recycle.Bin, T1204).

`$UsnJrnl` is the file-level change trail: create/delete/rename/data-change with
reason flags, catching staging and cleanup even when the files are long gone,
plus single-record anti-forensic flags (SDelete pattern, ransomware extensions).

---

## SRUM silent-exfil signal

SRUM preserves outbound volume per process even after the process is gone, so a
quiet gigabyte-scale exfil shows up when nothing else caught it. The strong
financially-motivated-actor signature combines three SRUM inputs: for a given
(app, ~hour interval), background CPU cycles > 0 **and** app-timeline focus time
== 0 **and** large outbound bytes — i.e. no user at the keyboard,
background-only execution, big transfer out.

---

## Case store notes

- A case is one DuckDB file (`.fxcase`). Events stream in via a batched
  appender-style writer (5k-row transactions) so multi-million-row MFT/UsnJrnl
  loads keep up.
- Timestamps are stored **UTC**. RFC3339 strings are cast to DuckDB `TIMESTAMP`
  on insert (tz-naive — fine because storage is UTC by contract); the analyst's
  display timezone lives in `case_meta.display_timezone`.
- Evidence (and unclassified files) are **SHA-256 hashed at registration**;
  every event references its `evidence_id`, so a hunt hit traces back to a hashed
  source file.

---

## GUI (`crates/gui`)

A Tauri v2 desktop shell. The Rust side (`src/commands.rs`) exposes typed
commands over `fx-store` / `fx-ingest` (`open_case`, `ingest_collection`,
`query_timeline`, `event_raw`, …). The frontend (`ui/`) is a **dependency-free,
build-step-free** web app that renders a dense DFIR analyst workspace and detects
the Tauri bridge at runtime — with no bridge (a plain browser) it serves
representative sample data, so the UI is fully exercisable without the Rust
build.

The frontend is **embedded into the `fx-gui` binary at compile time**, so there's
no separate asset to ship — and why contributors must force a recompile after
editing `ui/` (see [`INSTALL.md`](INSTALL.md) → *Updating a source build*).

Design language is deliberate for the subject: a calm desaturated ink palette
for long reading sessions (not terminal-green), a *categorical* colour system
where each activity type — execution / persistence / filesystem / network /
logon — carries one restrained hue, monospace used only where character
alignment aids scanning, and a single alert hue reserved for flagged
(suspicious / anti-forensic) events. The timeline is windowed (only visible rows
in the DOM), so it stays responsive across the millions of events a real case
holds.

Preview the frontend alone, no Rust build:
```
cd crates/gui/ui && python3 -m http.server 8099   # open localhost:8099
```
