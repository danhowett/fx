# fx — Windows Artefact Analysis & Threat Hunting

fx is a Windows DFIR triage tool. It ingests a folder of **already-extracted**
Windows artefacts, normalises them onto a single timeline, hunts for the tactics
of financially-motivated / ransomware actors, and lets an analyst triage and
export the findings — all from a self-contained desktop app.

> **In one line:** point it at a triage collection, and it tells you what
> happened on the host and what looks malicious — with the evidence behind every
> finding.

---

## What it is

- A **single desktop application** (plus an optional CLI). No server, no cloud,
  no external dependencies at analysis time — everything runs locally against a
  case file.
- Built for **triage and hunting**, not full disk forensics: it works on
  extracted artefacts, not raw disk images.
- Focused on **financially-motivated / ransomware intrusions** — the rules and
  parsers are chosen around that threat model.

## What it analyses

fx identifies each file by **content** (not extension or path), so any
collection layout works. Each parser lifts the artefact into a normalised event
(timestamp, host, user, process, target, network fields) so detection rules and
the timeline can work across artefact types uniformly.

### Windows Event Logs (EVTX)

Around 50 event IDs are mapped to normalised actions, with EventData lifted into
structured fields (command lines, IPs, hashes, logon types, target objects) —
so a rule matching a command line fires whether the command came from Security
4688, Sysmon 1, or a PowerShell script block.

| Channel | Event IDs | What it surfaces |
|---------|-----------|------------------|
| Security — logon | 4624, 4625, 4634/4647, 4648, 4672 | logon success/failure/logoff, explicit-credential logon, special-privilege (admin) logon — with source IP and logon type |
| Security — process | 4688 | process creation **with command line** and parent |
| Security — accounts | 4720, 4722, 4724, 4725, 4726, 4728/4732/4756, 4738 | account create/enable/disable/delete, password reset, **adds to privileged groups**, account change |
| Security — tasks | 4698, 4699, 4702 | scheduled task created / deleted / updated |
| Security — shares | 5140, 5145 | network-share access and share-object access (staging / lateral movement) |
| Security — anti-forensics | 1102, 4719 | **security log cleared**, audit-policy changed |
| System — services (SCM) | 7045, 7040, 7036 | service installed, start-type changed, state changed |
| Terminal Services / RDP | 21, 22, 25, 4778, 4779 | RDP session logon / reconnect / disconnect — with client address |
| WMI-Activity | 5857–5861 | WMI event-consumer / subscription persistence |
| Sysmon | 1, 3, 7, 8, 10, 11, 12–14, 22, 23/26 | process create (+ hashes), network connection, image load, CreateRemoteThread, **process access to LSASS**, file create, registry events, DNS query, file delete |
| PowerShell | 4104, 4103, 400/403 | **script-block text**, pipeline execution, engine state |
| Windows Defender | detection + tamper events | malware detections, real-time-protection disable, exclusion changes |

Event IDs not explicitly mapped are still ingested as generic `evtx.eid.<N>`
events with the full raw record retained, so nothing is lost and rules can still
match on `event.id` or `message`.

### File system (NTFS)

| Artefact | What it surfaces |
|----------|------------------|
| `$MFT` | file records with `$STANDARD_INFORMATION` MACB timestamps and full paths |
| `$UsnJrnl:$J` | change-journal entries — create / delete / rename / data-change, with reason flags (flags SDelete and ransomware-extension patterns) |

### Registry

Hives are parsed with transaction-log (`.LOG1`/`.LOG2`) replay, and deleted keys
are recovered where possible. Extractors:

| Extractor | Key / data |
|-----------|-----------|
| Run keys | `...\CurrentVersion\Run` / `RunOnce` (autostart persistence) |
| Services | service definitions and image paths |
| ShimCache (AppCompatCache) | presence marker only for now — full blob decoding is planned |
| UserAssist | GUI program execution: ROT13-decoded path (known-folder GUIDs expanded), **run count**, focus count/time, and the **last-run time** |
| BAM / DAM | per-user program **last-execution time** (decoded FILETIME), keyed by SID |
| RunMRU | commands typed into the **Run dialog (Win+R)**, in most-recent-first order — hands-on-keyboard evidence; each lands on the command-line field so command-line rules apply |
| RDP client MRU | `Terminal Server Client\Default` / `\Servers` — hosts this user **RDP'd out to**, with the username hint |
| RDP config | terminal-server settings, saved connections |
| Amcache | `InventoryApplicationFile` + legacy `Root\File` — program presence, SHA-1, with parse-time masquerade / staging flags |
| ShellBags | folder-browsing history from BagMRU (NTUSER + UsrClass), flags volume/removable references |
| USB / device history | USBSTOR / USB enum — every removable device attached (friendly name, vendor/product descriptor, serial) for data-theft attribution |
| Network profiles | `NetworkList\Profiles` — every network the host joined (profile name, type, managed/unmanaged) |
| Autostart (extra) | Winlogon Shell/Userinit (flags non-default **hijacks**), Image File Execution Options **debuggers**, and **AppInit_DLLs** — persistence/evasion spots beyond Run keys & services |

### Execution & usage

| Artefact | What it surfaces |
|----------|------------------|
| Prefetch (`.pf`) | executable name, run count, up to 8 last-run times (SCCA v23/26/30/31, MAM-decompressed) |
| SRUM (`SRUDB.dat`) | per-process network bytes sent/received (exfil signal) and application usage, resolved via the SRUM ID map |

### Persistence & user activity

| Artefact | What it surfaces |
|----------|------------------|
| PowerShell history | PSReadLine `ConsoleHost_history.txt` — the user's literal typed console commands, in order. Each becomes an event on the command-line field, so PowerShell/LOLBin/ransomware rules match it even when script-block logging was disabled |
| Windows Timeline | `ActivitiesCache.db` — apps run and **files opened** (with the executable path and file/URL from the activity payload) and their timing; corroborates execution and survives when Prefetch/UserAssist were cleared |
| Scheduled Tasks (XML) | task command, run-as principal (flags elevation), triggers, registration date |
| Browser history | Chromium + Firefox — visits and downloads, with domain and event type |
| LNK & Jump Lists | shell-link targets; auto/custom jump lists; flags **removable-media** (USB serial) and **network-share** (UNC) origins; MRU metadata |
| Recycle Bin (`$I`) | original path, original size, and deletion time of deleted files (both format versions) |

### Remote-access tools

Commercial remote-access tools are a staple of ransomware affiliates. Their own
logs record who connected, from where, when, and whether files moved — often
surviving after the tool is uninstalled.

| Artefact | What it surfaces |
|----------|------------------|
| AnyDesk `connection_trace.txt` | every incoming / outgoing / **rejected** session: time, auth type, remote AnyDesk ID |
| AnyDesk `ad.trace` / `ad_svc.trace` | session requests, logins **with source IP**, accept/reject, file transfers, remote OS / client ID |
| TeamViewer `Connections_incoming.txt` / `Connections.txt` | incoming and outgoing sessions: remote ID and name, start/end (duration), local user, connection type. Times are as logged (host local time) |
| ScreenConnect (Application event log) | client session connects/disconnects, **file transfers** and **commands run** through the tool |

Every source file is **SHA-256 hashed at ingest** for chain of custody, and the
per-file **ingest log** records whether each parsed, was unsupported, or failed
(with the failure reason).

## What it hunts for

**26 detection rules**, matching behaviour and tooling — **not file hashes**
(which rotate constantly). Two layers:

**Generic ATT&CK technique rules** — credential dumping (LSASS, SAM/NTDS,
DCSync), discovery / reconnaissance, lateral movement (PsExec / WMI / WinRM),
defense evasion (log clearing, AV tampering, shadow-copy deletion), persistence
(Run keys / services / WMI / scheduled tasks), LOLBin abuse, suspicious
PowerShell, and suspicious process lineage.

**Ransomware group behavioural rules** — the most active 2026 groups by victim
volume: Qilin, TheGentlemen, Akira, Play / DragonForce, LockBit, INC Ransom
(incl. Lynx / Sinobi), Interlock, and Clop. These key on each group's
distinctive tradecraft — tool names, command-line patterns, BYOVD drivers,
RMM / tunnel / exfil stacks, and ransom-note filenames.

Detections come from two engines: **single-event** (one event matches a rule)
and **correlation** (a pattern across events, e.g. mass file-rename bursts or
bulk SRUM exfil).

## The workflow

1. **New case** — pick an artefact folder (KAPE, Magnet RESPONSE, Velociraptor,
   CyLR, or a raw copy) and where to save the `.fxcase`. fx ingests, hunts, and
   displays it automatically.
2. **Review findings** — *view all findings* shows rule detections **and** your
   own analyst-validated events together. Click any finding to jump to the
   event, read its raw record, and triage it.
3. **Triage** — mark any event **Validated / Unconfirmed / False positive /
   Dismissed**, with a free-text note. Findings auto-start as Unconfirmed. Filter
   the timeline by triage state from the rail.
4. **Pivot** — on any event, use **Pivot ±1m / 5m / 30m / 1h** to see everything
   around it; or set an explicit time range in the toolbar.
5. **Export** — everything lives under the **Export ▾** menu in the top bar:
   **CSV** (Excel / sharing) or **STIX 2.1** (TIP / MISP). A
   dialog lets you choose which triage states to include — **Validated**,
   **Unconfirmed**, **False positive**, **Dismissed** — with a live count for
   each. It defaults to validated + unconfirmed, so reviewed noise stays out of
   a client-facing export. Exports carry triage state and analyst notes.
   **Export report** saves the self-contained HTML case report — findings by
   ATT&CK tactic, severity scorecards, timeline, ATT&CK matrix, and the
   **evidence chain-of-custody table** (every ingested file with its SHA-256).
   Open it in any browser; print to PDF to archive. (CLI equivalent:
   `fx report case.fxcase report.html`.)
6. **IOC sweep** — click **IOC sweep** in the top bar, then paste an indicator
   list or load one from a file (`.txt`, `.csv`, a threat-intel export…). fx
   recognises SHA-256 / SHA-1 / MD5 hashes, IPv4 / IPv6, domains, URLs, email
   addresses, file names, full paths and free text — one or more per line, `#`
   comments ignored, and **defanged values are refanged** (`hxxp://`,
   `evil[.]com`, `1.2.3[.]4`). A live preview counts what was recognised before
   you run it. The sweep searches **every event in the open case, including the
   raw record**, in a single pass — no re-ingest, so it works on a case processed
   weeks ago. Matching is token-aware: `1.2.3.4` won't hit `1.2.3.45`, and
   `evil.com` hits `cdn.evil.com` but not `notevil.com`; paths match whether the
   artefact stored `C:\x\y`, `C:/x/y` or `/x/y`. The results table shows each
   indicator's hit count, first sighting and which artefacts it appeared in.
   **Each matched indicator becomes a finding** (*IOC match*, High; free text is
   Medium) that you triage, export and report like any other — the report groups
   them under **IOC matches**. Running a new sweep replaces the previous sweep's
   findings; re-running the rule hunt keeps them.
7. **Ingest log** — from the rail, see every file ingested and whether it parsed,
   was unsupported, or failed (with the failure reason).
8. **Activity graph** — from the rail, a per-day event-count histogram across the
   whole case. It surfaces volume that **no rule tagged**: a day whose event
   count stands well above the baseline is outlined and labelled, so a quiet
   ~25-event baseline with one 800-event day jumps straight out. The darker base
   of each bar is the **flagged** portion — events that tripped a rule *or* that
   you've triaged as Validated / Unconfirmed; it updates live as you triage. A
   tall, mostly-light bar is unexplained activity worth a look. Height switches
   to a log scale when one day dwarfs the rest, so baseline days stay visible.
   **Click a day to pivot** the timeline to that day.

## Navigating the timeline

- **Scroll** or use the mouse wheel; a floating readout shows your position
  (row *N* of total, and the UTC timestamp there) so you never lose your place.
- **Keyboard:** `PageUp` / `PageDown` move a screen at a time, `Home` / `End`
  jump to the first / last event, `↑` / `↓` nudge one row. Precise movement
  through a long list without fighting trackpad momentum.
- **Dates** are shown throughout in UK format (`DD/MM/YYYY HH:MM:SS`), always
  **UTC**. (Raw records and CSV/STIX exports keep ISO `YYYY-MM-DD` for
  machine interchange.)

## Themes

Three themes via the toolbar: **Daybreak** (light), **Midnight** (dark), and
**Slate** (a mid-tone grey-blue between the two).

---

## Important — how to read the output

- **Findings are investigative leads to corroborate, not verdicts.** Review each
  in context before acting.
- **Group attribution is probabilistic.** Tooling is shared and copied across
  crews, so a group rule firing means *"behaviour consistent with"* that group —
  a strong lead toward eCrime ransomware activity, not proof of a specific actor.
- **Absence of findings is not proof a host is clean.** Coverage is limited to
  the artefacts ingested and the rules available.
- **All timestamps are UTC.**
- **Point fx at a copy of the evidence.** Keep originals read-only; fx hashes
  every source file at ingest for chain of custody.

## Known issues (v0.1)

- **Triage counts may differ by a few between the summary rail and the timeline
  filter.** The left-hand triage summary counts every live triaged event in the
  case; the timeline's triage filter can only match events in the rows it has
  loaded, so on very large cases the two numbers can disagree by a handful. This
  is cosmetic — the underlying triage data and all exports use the full set and
  are correct.

## Building & running

See `INSTALL.md` (Windows / Windows Server) and `RUNBOOK.md` for the
step-by-step build and daily workflow. In short:

```powershell
cargo update -p nom --precise 7.1.3
cargo build --release -p fx-gui --features tauri/custom-protocol
.\target\release\fx-gui.exe
```

Requires Rust 1.81+, the Visual Studio C++ Build Tools, and (for the GUI on
Windows Server) the WebView2 runtime.

---

*fx is a triage and hunting aid. It supports analyst judgement; it does not
replace it.*
