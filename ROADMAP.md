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

### Accuracy
- [x] Duplicate findings: byte-identical files are parsed once, Sigma rules load once per id
- [ ] Tighten the scheduled-task rule: `rundll32` / `regsvr32` only when the DLL
      sits outside System32 / SysWOW64 or uses script / URL tricks (built-in
      Windows tasks currently match)
- [x] Convert local-time sources (setupapi, TeamViewer) to UTC using the
      analysed host's own time-zone rule, keeping the original value
- [x] Optional display time zone (UTC / host local)

### Compatibility
- [ ] Versioned case-file schema with an upgrade path, and a test that opens
      case files made by earlier versions

### Trustworthy builds
- [ ] Release builds produced by GitHub Actions from the tagged source
- [ ] SHA-256 checksums published with every release
- [ ] Code signing (reduces antivirus quarantines)

### Documentation
- [ ] Refresh "Known issues" in HELP.md and add a short "what fx is not"
- [ ] Consistent "Parses / Look for" notes for every artefact in the rail

## After 1.0 (ideas, not promises)
- Hibernation file decompression, so `hiberfil.sys` can be searched like the pagefile
- More artefacts: User Access Logging (servers), IIS logs, Windows Firewall log,
  Windows Error Reporting, WMI persistence (`OBJECTS.DATA`)
- Tags in exports and the HTML report
