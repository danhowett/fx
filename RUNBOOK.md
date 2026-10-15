# fx — Operator Runbook

How to build the tool, prepare evidence, and run a case end to end. Written for
a DFIR analyst who has the tool source but hasn't run it before.

---

## 1. What you need (prerequisites)

**Build machine** (to compile the tool once):

- **Rust toolchain, 1.81 or newer.** Install from <https://rustup.rs>. Verify:
  ```
  rustc --version      # must be >= 1.81.0
  cargo --version
  ```
  > Why 1.81+: some dependencies (the LNK/jump-list reader, and transitive
  > crates) require it. An older toolchain will fail to compile.

- **A C toolchain** (for the bundled DuckDB and SQLite):
  - Linux: `sudo apt install build-essential`
  - macOS: `xcode-select --install`
  - Windows: the "Desktop development with C++" workload from the Visual Studio
    Build Tools.

- **Disk space:** ~3–4 GB for the build (DuckDB compiles from source the first
  time; subsequent builds are fast).

**For the GUI only** (optional — the CLI needs none of this):

- **Linux:** WebKitGTK + GTK dev libraries —
  `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev`
- **macOS / Windows:** nothing extra (uses the OS web view).

**No network is required at analysis time.** The tool is fully offline; only the
one-time build downloads crates.

---

## 2. Build it (once)

From the repo root:

```
# Core tool + CLI (no GUI libraries needed):
cargo build --release

# The CLI binary is now at:
#   target/release/fx
```

Optional — the desktop GUI (needs the WebKit/GTK libraries above):

```
cargo build --release -p fx-gui
# or, with the Tauri CLI installed (cargo install tauri-cli):
cargo tauri build
```

Sanity check the CLI:

```
./target/release/fx
# prints the usage/help
```

> Tip: put the binary on your path, e.g. `cp target/release/fx ~/.local/bin/`,
> so you can just type `fx`.

---

## 3. Prepare the evidence

fx ingests a **directory of already-extracted Windows artefact files** — it does
**not** mount disk images or E01s (that's a later phase). In practice you point
it at the output of a triage collector.

**Supported input:** a folder (optionally the unzipped output of a collection
tool) containing any mix of:

| Artefact | Typical file(s) |
|----------|-----------------|
| Event logs | `*.evtx` (from `Windows\System32\winevt\Logs`) |
| MFT / journal | `$MFT`, `$UsnJrnl:$J` (or `$J`) |
| Registry | `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `Amcache.hve`, … |
| Execution | `*.pf` (Prefetch), `SRUDB.dat` (SRUM) |
| Persistence | Scheduled task XML under `…\Tasks\` |
| Shell activity | `*.lnk`, `*.automaticDestinations-ms`, `*.customDestinations-ms` |
| Browser | Chromium `History`, Firefox `places.sqlite` |

**How to collect** (any of these works — fx identifies files by content, so the
exact layout doesn't matter):

- **Magnet RESPONSE**, **KAPE**, **Velociraptor offline collector**, **CyLR** —
  run the tool's standard triage target, then unzip its output.
- Or hand-copy the files above off a mounted image into a folder.

fx works out what each file is by its bytes (not its extension or path), so a
hive renamed `notes.txt` is still parsed, and files it can't classify are
recorded (not silently dropped) — you'll see the count in the report.

> **Chain of custody:** fx SHA-256-hashes every source file at ingest and records
> it. Keep your original collection read-only; point fx at a copy.

---

## 4. Run a case (CLI)

The whole workflow is four commands. Assume your extracted evidence is in
`./triage/WKSTN-07/`.

### 4.1 Ingest → create the case

```
fx ingest ./triage/WKSTN-07 WKSTN-07.fxcase \
    --name "IR-2026-014 · WKSTN-07" \
    --examiner "J. Odell"
```

This identifies every file, hashes it, parses it, and writes everything into a
single case file `WKSTN-07.fxcase` (a DuckDB database). It prints a summary:
how many artefacts parsed, how many events, how many files were unclassified.

### 4.2 Look at what came in (optional)

```
fx summary WKSTN-07.fxcase
```

Shows event counts per artefact, the ingest outcome, and the top SRUM network
"talkers" (a quick exfil-volume gut-check).

### 4.3 Hunt → run detections

```
fx hunt WKSTN-07.fxcase --rules crates/hunt/rules
```

Runs the rule pack (single-event + correlation rules) and stores the findings in
the case. Prints each detection worst-first with its ATT&CK mapping, and an
ATT&CK coverage tally.

> **Add more rules:** see §6 to import an external IOC pack. Point `--rules` at
> whichever directory holds the rules you want to run.

### 4.4 Report → produce the deliverable

```
fx report WKSTN-07.fxcase WKSTN-07-report.html
```

Writes a self-contained HTML report: executive summary, findings grouped along
the kill chain, ATT&CK coverage, data-analysed breakdown, and the evidence
chain-of-custody table with SHA-256s. Open it in any browser; use the browser's
**Print → Save as PDF** to archive a fixed copy.

---

## 5. Run a case (GUI)

If you built `fx-gui`:

```
./target/release/fx-gui        # or launch the bundled app
```

1. **Open** a `.fxcase` you already ingested (or ingest a collection from the
   UI).
2. The **timeline** is the centre pane — scroll, filter by activity category or
   artefact, full-text search, and click **Flagged only** to collapse to the
   events that matter.
3. Click any event to see its full raw record and provenance on the right.
4. Click **Findings** in the left rail to switch to the hunt view — detections
   worst-first, each with ATT&CK tags, one click back to the timeline.

The GUI and CLI read the same `.fxcase` file, so you can ingest on the command
line and review in the GUI, or vice versa.

---

## 6. Import an external IOC pack (optional)

To fold a third-party rule pack (MFIRfinder-style JSON) into your detections:

```
fx import-iocs pack.json crates/hunt/rules/imported/
fx hunt WKSTN-07.fxcase --rules crates/hunt/rules/imported/
```

The importer converts each rule, and reports transparently: which rules were
imported, which are **dormant** (need an artefact fx doesn't parse yet, e.g.
memory), any **fragile regexes it repaired**, and any **duplicate ids** it had to
de-conflict. Nothing is changed silently.

---

## 7. End-to-end example

```
# 1. Build (once)
cargo build --release
cp target/release/fx ~/.local/bin/

# 2. Collect triage with your tool of choice, unzip to ./triage/WKSTN-07/

# 3. Run the case
fx ingest ./triage/WKSTN-07 WKSTN-07.fxcase --name "IR-2026-014" --examiner "J. Odell"
fx hunt   WKSTN-07.fxcase --rules crates/hunt/rules
fx report WKSTN-07.fxcase WKSTN-07-report.html

# 4. Open WKSTN-07-report.html in a browser, review, Print → Save as PDF.
```

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `cargo build` fails on a dependency needing `edition2024` | Toolchain too old — `rustup update` to 1.81+. |
| Build fails linking DuckDB/SQLite | Missing C toolchain — install build-essential / Xcode CLT / VS Build Tools (§1). |
| GUI build fails on `webkit2gtk` | Missing GUI libraries — install them (§1) or just use the CLI. |
| `fx ingest` reports many "unclassified" files | Normal — those are files fx didn't recognise (fonts, logs, etc.). They're recorded, not lost. |
| A rule doesn't fire | Check `fx hunt` output for its rule id; imported rules may be **dormant** if they need an artefact type not yet parsed (memory, etc.). |
| Timestamps look off by hours | All storage is UTC by design; the display timezone is a case setting. |

---

## 9. What this tool does and doesn't do (scope)

**Does:** ingest extracted Windows artefacts from any collection layout, normalise
them onto one timeline, hunt financially-motivated-actor TTPs (single-event +
correlation rules, ATT&CK-mapped), import external IOC packs, and produce a
defensible HTML/PDF case report with chain of custody.

**Doesn't (yet):** mount disk images/E01s (feed it extracted files), parse memory
(no live-process / loaded-module artefacts), or parse a handful of niche
artefacts. Absence of findings is never proof of a clean host — it reflects the
artefacts and rules available. Findings are investigative leads to be
corroborated by an analyst.
