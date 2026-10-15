# Installing fx — step by step

This guide takes a **bare machine** to a working fx install. Follow the path
that matches you:

- **Option A — prebuilt binary.** You just want to run fx. Fastest; no compiler.
- **Option B — build from source.** You want to review, modify, or run on a
  platform with no prebuilt binary. ~15–30 min of mostly one-time setup.

> **Read this first — antivirus.** fx is an **unsigned** binary that reads
> forensic artefacts and carries hunt rules that name offensive tooling
> (mimikatz, Cobalt Strike, PsExec, rclone…). Windows Defender / your EDR may
> quarantine it on download or first run. **This is expected for a DFIR tool.**
> Either add a Defender exclusion for your fx folder, or build from source and
> approve your own binary through your change process. If `fx-gui.exe` vanishes
> right after download, that's AV — it wasn't a failed download.

---

## Option A — Prebuilt binary (fastest)

### A1. Download

From the repo's **Releases** page, download:

- `fx-gui.exe` — the desktop app (most analysts want this), **and/or**
- `fx.exe` — the command-line tool.

The hunt rules are **embedded in both binaries**, so you don't need anything
else to start. (Only grab the `crates/hunt/rules/` folder if you plan to point
the CLI at a modified rule pack — see the README.)

### A2. One prerequisite for the GUI — WebView2

`fx-gui.exe` renders its interface with the **Edge WebView2 runtime**.

- **Windows 10 / 11:** almost always already present — try running fx first.
- **Windows Server:** usually **not** present — install it.

Install it one of two ways:

- Download the *Evergreen Standalone Installer* from
  <https://developer.microsoft.com/microsoft-edge/webview2/> and run it, **or**
- From an admin PowerShell: `choco install microsoft-edge-webview2-runtime -y`

`fx.exe` (CLI) needs no runtime.

### A3. Run

- Double-click `fx-gui.exe`, **or**
- From a terminal in the download folder: `.\fx.exe` (prints usage).

That's it. **fx is fully offline at analysis time** — no network, no telemetry,
no cloud. Skip to [First run](#first-run--sanity-check).

---

## Option B — Build from source

### B1. Prerequisites (one time per machine)

You need three things: the **Rust toolchain**, a **C/C++ compiler** (DuckDB and
SQLite compile from source), and — for the GUI — a **web view**.

#### Rust (1.81 or newer)

- Download and run `rustup-init.exe` from <https://rustup.rs> — accept the
  defaults (option 1).
- **Open a new terminal** (so `PATH` picks up cargo), then verify:
  ```
  rustc --version
  ```
  It must be **1.81 or newer**. If it's older, run `rustup update`.

#### A C/C++ toolchain

| OS | Install |
|----|---------|
| **Windows** | *Build Tools for Visual Studio* with the **"Desktop development with C++"** workload. Download from <https://visualstudio.microsoft.com/downloads/> → *Tools for Visual Studio* → *Build Tools*. Headless install below. |
| **Linux** | `sudo apt install build-essential` |
| **macOS** | `xcode-select --install` |

Windows headless (CI / Server):
```
vs_BuildTools.exe --quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
```

#### Web view (GUI only)

| OS | Install |
|----|---------|
| **Windows / macOS** | Uses the OS web view. On **Windows Server** install WebView2 — see [A2](#a2-one-prerequisite-for-the-gui--webview2). |
| **Linux** | `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev` |

> Only the **one-time build** needs the network (to fetch crates from
> crates.io). Once built, fx is offline at analysis time.

### B2. Get the source

**From a release source archive:** download and extract it. You get a
`forensic-tool/` folder — `cd` into it.

**From git:**
```
git clone https://github.com/<owner>/fx.git
cd fx
```

Either way, you should now be in the folder that contains `Cargo.toml`,
`Cargo.lock`, and the `crates/` directory.

### B3. Build

> **Always build with `--locked`.** The committed `Cargo.lock` pins the exact
> dependency graph — most importantly `nom` at 7.1.3 (see the note below).
> `--locked` tells Cargo to honour it and fail loudly rather than silently
> re-resolving.

**CLI (`fx`)** — no GUI libraries needed:
```
cargo build --release --locked
# → target/release/fx  (fx.exe on Windows)
```

**Desktop GUI (`fx-gui`)**:
```
cargo build --release --locked -p fx-gui --features tauri/custom-protocol
# → target/release/fx-gui  (fx-gui.exe on Windows)
```

The **first build is long** — DuckDB compiles from source, so expect many
`Compiling …` lines over several minutes (5–15 min is normal on a fresh
machine). Later builds are fast.

> #### The `nom` build failure — and why this repo doesn't hit it
>
> The registry parser `notatin` needs `nom` **7**, but its manifest allows
> `nom >=6` with **no upper bound**. Left to its own devices Cargo pulls
> `nom` **8**, which **fails to compile** with errors like
> `expected function, found Choice<…>`.
>
> This repo **commits `Cargo.lock` with `nom` pinned at 7.1.3**, so a normal
> clone + `--locked` build is correct out of the box. You only hit the failure
> if the lock goes missing or you run `cargo update`. If that happens and
> `nom` 8 reappears, collapse it back with one command and rebuild:
> ```
> cargo update -p nom@8.0.0 --precise 7.1.3
> ```
> You should see `Removing nom v8.0.0`. (If only one `nom` is present, drop the
> `@8.0.0`.)

### B4. Run

```
./target/release/fx-gui          # desktop app
./target/release/fx              # CLI (prints usage)
```

On Windows, `.\target\release\fx-gui.exe`.

---

## First run — sanity check

The CLI with no arguments prints its usage — that confirms the binary runs:
```
fx
```

Ingest an extracted collection into a new case file, then summarise it:
```
fx ingest C:\evidence\host01_triage host01.fxcase --name "IR-2026-014" --examiner "A. Analyst"
fx summary host01.fxcase
```

Or just launch `fx-gui` — with no case open it loads representative **sample
data**, so you can click around the three-pane workspace before you have real
evidence loaded.

See **`RUNBOOK.md`** for the full build → ingest → hunt → report workflow with a
worked example.

---

## Updating a source build (contributors only)

The GUI frontend (HTML/JS under `crates/gui/ui/`) is **embedded into the
`fx-gui` binary at compile time**, and Cargo does **not** always notice edits to
those files. After changing any frontend file, force the GUI crate to recompile
so the new UI is re-embedded:

```powershell
# Windows — close the running app first (it locks the .exe)
Get-Process fx-gui -ErrorAction SilentlyContinue | Stop-Process -Force
(Get-Item crates\gui\src\main.rs).LastWriteTime = Get-Date   # force re-embed
cargo build --release --locked -p fx-gui --features tauri/custom-protocol
```

A **real** rebuild prints `Compiling fx-gui …` and takes ~20 s. A 0.x-second
`Finished` with **no** `Compiling` line means the UI was **not** re-embedded —
run the `touch`/`LastWriteTime` line above and rebuild. If it's still stubborn:
```powershell
cargo clean -p fx-gui
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `error: expected function, found Choice<…>` (in `notatin`) | `nom` 8 got pulled. Build with `--locked`; if needed, `cargo update -p nom@8.0.0 --precise 7.1.3`. |
| `fx-gui.exe` disappears after download | Antivirus quarantine — expected. Add a Defender exclusion for the fx folder (see top of this file). |
| GUI launches to a blank / white window | WebView2 missing (common on Windows Server). Install it — [A2](#a2-one-prerequisite-for-the-gui--webview2). |
| `link.exe not found` / `cc not found` on build | C/C++ toolchain missing — [B1](#a-cc-toolchain). |
| `cargo` not recognised after installing Rust | Open a **new** terminal so `PATH` is refreshed. |
| Edited the UI but it didn't change | The frontend is embedded — force a re-embed (see *Updating a source build*). |
| Linux GUI build fails on `webkit2gtk` | `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev`. |

---

## Reminders

- **Work on a copy.** Point fx at a **copy** of your triage data and keep
  originals read-only. fx SHA-256-hashes every source file at ingest for chain
  of custody.
- **`0 detections` on a clean host is the correct result** — absence of findings
  is not proof a host is clean.
- **Findings are leads to corroborate, not verdicts.**
- **All timestamps are UTC.**
