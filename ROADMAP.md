# fx roadmap

fx is in **public beta**. It works on real triage collections today, but a
"1.0" is a promise about accuracy, compatibility and trust, so these are the
things that need to be true first. Feedback from real collections is the
fastest way to get there: please open an issue with what you ran, which
collection tool produced it, and what looked wrong.

## Road to 1.0

### Proven on real data
- [ ] Run against collections from KAPE, Velociraptor, Magnet RESPONSE and CyLR,
      on Windows 10, Windows 11 and Windows Server
- [ ] Confirm the v0.1.6 / v0.1.7 parsers on real artefacts: user activity
      (NTUSER.DAT), PCA, setupapi, pagefile / swapfile carving, Defender MPLog
- [ ] Allow-list and Sigma runs on a multi-million-event case
- [ ] Multi-host cases (v0.1.10) on real collections: host naming, per-host time
      zones, and adding a host to a case made by an earlier version
- [ ] Lateral movement (v0.1.12) on real multi-host collections: source
      matching by name and address, RDP / SMB / PsExec patterns, noise filtering

### Accuracy
- [x] Duplicate findings: byte-identical files are parsed once, Sigma rules load once per id
- [x] Tighten the scheduled-task rule: `rundll32` / `regsvr32` only when the DLL
      sits outside System32 / SysWOW64 or uses script / URL tricks
- [x] Convert local-time sources (setupapi, TeamViewer) to UTC using the
      analysed host's own time-zone rule, keeping the original value
- [x] Optional display time zone (UTC / host local)
- [x] No invented times: records without a time are "no timestamp" (Undated), never 01/01/1970
- [x] $MFT $FN times alongside $SI, and a $SI-before-$FN timestomping check (timeline event, not a finding)
- [x] One rule can't flood a case: at most 1,000 findings per rule per run
- [x] TerminalServices RDP session events (21 / 22 / 25) read their source address and user from UserData

### Compatibility
- [ ] Versioned case-file schema with an upgrade path, and a test that opens
      case files made by earlier versions

### Trustworthy builds
- [ ] Release builds produced by GitHub Actions from the tagged source
      (workflow added; tick once the first release has built cleanly)
- [ ] SHA-256 checksums published with every release (same workflow)
- [ ] Code signing (reduces antivirus quarantines)

### Documentation
- [ ] Refresh "Known issues" in HELP.md and add a short "what fx is not"
- [ ] Consistent "Parses / Look for" notes for every artefact in the rail

## After 1.0 (ideas, not promises)
- Multi-host, phase 3: lateral-movement links (a logon on one host from another
  host's IP opens that host's events at that moment) and a spread view (which
  hosts each finding or IOC reached, and when it was first seen on each)
- Hibernation file decompression, so `hiberfil.sys` can be searched like the pagefile
- More artefacts: User Access Logging (servers), IIS logs, Windows Firewall log,
  Windows Error Reporting, WMI persistence (`OBJECTS.DATA`)
- Tags in exports and the HTML report
- Decode at ingest: run Decode on every encoded PowerShell command and script
  block and raise its findings automatically
