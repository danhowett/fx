<h1 align="center">fx</h1>

<p align="center"><b>Windows artefact analysis &amp; threat hunting — local, offline, hunting-first.</b></p>

<p align="center"><i>Early developer preview · v0.1</i></p>

---

fx is a Rust, local-desktop forensic **triage and threat-hunting** tool for
Windows artefacts, oriented toward the TTPs of financially-motivated threat
actors — ransomware affiliates and e-crime intrusion sets. Think Axiom / EnCase
/ X-Ways in spirit, but **hunting-first**, **format-agnostic on input**, and
**fully offline**.

Point it at a folder of extracted Windows artefacts — from KAPE, Magnet
RESPONSE, Velociraptor, CyLR, or a raw copy — and fx:

1. **Identifies** every file by content (magic bytes), not by extension.
2. **Normalises** everything onto one timeline (`fx_core::Event`).
3. **Hunts** with behaviour-based rules (generic ATT&CK techniques + the top
   ransomware crews' TTPs), embedded in the binary.
4. Lets you **triage, pivot, visualise per-day activity, and export** findings —
   with the SHA-256-hashed evidence behind every result.

> ⚠️ fx is a **triage aid**. Findings are investigative **leads to corroborate**,
> not verdicts; **absence of findings is not proof a host is clean.**

---

## Get it

| | |
|---|---|
| **Run it** | Download `fx-gui.exe` (desktop) and/or `fx.exe` (CLI) from the [**Releases**](../../releases) page. Rules are embedded — nothing else needed. |
| **Build it** | See [**`INSTALL.md`**](INSTALL.md) — step by step from a bare machine. A normal clone builds with no dependency fiddling (`Cargo.lock` is committed; `nom` is pinned). |
| **Learn it** | [**`HELP.md`**](HELP.md) — every view and feature. · [**`RUNBOOK.md`**](RUNBOOK.md) — end-to-end operator workflow. · [**`ARCHITECTURE.md`**](ARCHITECTURE.md) — how it's built. |

> **Antivirus note:** fx is an unsigned binary carrying hunt rules that name
> offensive tools. Defender / EDR may quarantine it — expected for a DFIR tool.
> See [`INSTALL.md`](INSTALL.md).

---

## Before you start — what to download

**Running the prebuilt binary?** You need almost nothing:

- **`fx.exe`** (CLI) — nothing else.
- **`fx-gui.exe`** (desktop app) — also needs the **Edge WebView2 runtime**.
  Windows 10 / 11 already have it; **Windows Server usually doesn't** —
  [download it here](https://developer.microsoft.com/microsoft-edge/webview2/)
  (*Evergreen Standalone Installer*).

**Building from source?** Install these three first — they are one-time, per
machine, and the build will fail without them:

| # | Prerequisite | Why | Get it |
|---|--------------|-----|--------|
| 1 | **Rust toolchain** (1.81 or newer) | compiles fx | <https://rustup.rs> — run `rustup-init.exe`, accept defaults, then **open a new terminal** |
| 2 | **C/C++ build tools** | DuckDB & SQLite compile from source | **Windows:** [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/) → *Build Tools* → **"Desktop development with C++"** workload · **Linux:** `sudo apt install build-essential` · **macOS:** `xcode-select --install` |
| 3 | **Web view** (GUI only) | renders the desktop UI | **Windows / macOS:** the OS web view (install [WebView2](https://developer.microsoft.com/microsoft-edge/webview2/) on Windows Server) · **Linux:** `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev` |

After installing Rust, confirm it's on your PATH in a **fresh** terminal:

```
rustc --version      # must be 1.81 or newer
cargo --version
```

> Only the one-time build needs the network (to fetch crates). **Analysis is
> fully offline** — no network, no telemetry.

Full step-by-step, including a troubleshooting table, is in
[**`INSTALL.md`**](INSTALL.md).

---

## Screenshots

### Findings view
Rule detections and analyst-validated events together, worst-first, each
ATT&CK-mapped and one click from the underlying evidence.

![Findings view](docs/screenshot-findings.png)

### Activity graph
Per-day event-count histogram across the whole case — spot high-volume days that
no rule tagged, then click a day to pivot the timeline to it.

![Activity graph](docs/screenshot-graph.png)

### Artefact timeline
Every artefact normalised onto one timeline: filter, full-text search, pivot
around any event, and triage inline.

![Artefact timeline](docs/screenshot-timeline.png)

---

## Highlights

- **Broad artefact coverage** — EVTX, `$MFT`, registry hives, Prefetch, SRUM,
  `$UsnJrnl`, scheduled tasks, browser history (Chromium / Edge / Firefox),
  LNK / jump-lists, PowerShell console history, Windows Timeline, ShellBags,
  Recycle Bin, USB / device, network-profile & autostart registry keys,
  Run-dialog (RunMRU) and outbound-RDP history, and **remote-access tool logs**
  (AnyDesk, TeamViewer, ScreenConnect).
- **Behaviour-based hunt engine** — single-event (Sigma-subset) **and**
  correlation rules, all ATT&CK-mapped and embedded in the binary. Includes
  per-group rules for the top ransomware crews (Qilin, Akira, Play/DragonForce,
  LockBit, INC, Interlock, Clop…).
- **Built for real case sizes** — a virtualised timeline stays responsive across
  **millions of events**; correlation runs in seconds, not minutes.
- **Triage & pivot** — tag events, filter by category / artefact / flagged,
  full-text search, pivot the timeline around any event or day.
- **IOC hunt** — paste, load or drop an indicator list (hashes, IPs, domains,
  URLs, paths, defanged or not) and hunt the whole case for it, post-processing,
  in one pass. The list and results are saved with the case; every match becomes
  a triageable, exportable finding.
- **Tags** — right-click any event to tag it from a preset list or a new tag of
  your own; filter the timeline by tag from the rail.
- **Per-day activity graph** — surface untagged volume spikes no rule flagged.
- **Export** — CSV / STIX, plus a self-contained interactive **HTML / PDF case
  report** with a chain-of-custody evidence table.
- **Offline & provenance-first** — no network at analysis time; every event
  traces back to a hashed source file, a parser, and a record locator.

---

## What it's hunting (the adversary model)

fx targets the **modern ransomware / eCrime intrusion**, across the full kill
chain. The densest, highest-severity coverage is in the two phases that matter
most for these actors:

- **Credential Access** — LSASS dumping, mimikatz, NTDS.dit / DCSync, Veeam
  credential theft.
- **Impact** — shadow-copy deletion, BYOVD EDR-kill, safe-boot tricks,
  mass-encryption bursts, leak-site visits.

Rules are **YAML, loaded at runtime** (`crates/hunt/rules/`), so you extend
coverage without a rebuild. fx can also absorb external IOC packs
(`fx import-iocs`). A sample of the shipped signals:

| Rule | Engine | ATT&CK | Signal |
|------|--------|--------|--------|
| shadow_copy_deletion | single | T1490 | vssadmin / wbadmin / bcdedit backup destruction |
| system_binary_masquerade | single | T1036.005 | system-binary name at non-System32 path |
| offensive_tooling | single | T1003 / T1021.002 / T1567.002 | mimikatz / PsExec / Cobalt Strike / rclone |
| defender_tampering | single | T1562.001 | Defender disable / exclusions |
| mass_rename_ransomware | correlation | T1486 | N file renames in M seconds (USN) |
| srum_bulk_exfil | correlation | T1048 / T1567 | large outbound bytes per process (SRUM) |
| rdp_then_tooling | correlation | T1021.001 | RDP logon then tooling on same host |
| suspicious_scheduled_task | single | T1053.005 | task launching from staging dir / LOLBin |

For the full engine design, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Quick start (CLI)

```bash
# Ingest an extracted collection into a new case file
fx ingest C:\evidence\host01_triage host01.fxcase --name "IR-2026-014" --examiner "A. Analyst"

# Summarise the case
fx summary host01.fxcase

# Hunt with the embedded rule pack (or point at your own)
fx hunt host01.fxcase
fx hunt host01.fxcase --rules C:\my\rules

# Write a self-contained HTML case report (print to PDF to archive)
fx report host01.fxcase report.html
```

Or launch **`fx-gui`** for the three-pane analyst workspace. With no case open
it loads representative sample data, so you can explore the UI before loading
real evidence.

---

## Scope

**In (today):** loose **extracted** artefact files (EVTX, `$MFT`, AmCache,
registry hives, `$UsnJrnl`, `$LogFile`, Prefetch, SRUM, tasks, LNK, browser
history…), in whatever layout the collection tool produced.

**Out (later phases):**

- **Legacy IE / old-Edge history** (`WebCacheV01.dat`, ESE) — modern
  Chromium / Edge / Firefox history already parses.
- **Disk-image input** — mounting E01 / VHDX / raw images.
- **Memory forensics** — live-process / loaded-module artefacts.

Broader parser coverage, full-text indexing, and richer reporting are ongoing.

---

## Licence

**Source-available.** Free for **any use, including paid IR / forensic
engagements** — you simply can't **resell fx itself** (as a product or hosted
service) without a commercial agreement. See [`LICENSE`](LICENSE). This is **not**
an OSI open-source licence.

---

<p align="center"><sub>fx is a triage and hunting aid. It supports analyst judgement; it does not replace it.</sub></p>
