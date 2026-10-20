//! `fx` — command-line entry point.
//!
//! Phase-1 usage:
//!   fx ingest <collection_dir> <case_file.fxcase> [--name NAME] [--examiner WHO]
//!   fx summary <case_file.fxcase>
//!
//! Deliberately tiny: it exists to drive and smoke-test the pipeline before the
//! Tauri GUI lands. The GUI will call the same fx-ingest / fx-store APIs.

use fx_ingest::{ingest_into_store, ArtefactStatus};
use fx_parsers::ParserRegistry;
use fx_store::CaseStore;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> anyhow::Result<ExitCode> {
    let cmd = args.get(1).map(String::as_str);
    match cmd {
        Some("ingest") => cmd_ingest(&args[2..]),
        Some("summary") => cmd_summary(&args[2..]),
        Some("hunt") => cmd_hunt(&args[2..]),
        Some("report") => cmd_report(&args[2..]),
        Some("import-iocs") => cmd_import_iocs(&args[2..]),
        _ => {
            eprintln!(
                "usage:\n  fx ingest <collection_dir> <case.fxcase> [--name N] [--examiner W]\n  fx summary <case.fxcase>\n  fx hunt <case.fxcase> [--rules DIR] [--sigma DIR [--sigma-level medium] [--sigma-status stable,test]]\n  fx report <case.fxcase> <out.html>     write an HTML case report\n  fx import-iocs <pack.json> <out_dir>   convert an external IOC pack to rules"
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_ingest(args: &[String]) -> anyhow::Result<ExitCode> {
    let collection = PathBuf::from(args.first().ok_or_else(|| anyhow::anyhow!("missing collection dir"))?);
    let case_path = PathBuf::from(args.get(1).ok_or_else(|| anyhow::anyhow!("missing case file"))?);

    let mut name = "Untitled case".to_string();
    let mut examiner: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => { name = args.get(i + 1).cloned().unwrap_or(name); i += 2; }
            "--examiner" => { examiner = args.get(i + 1).cloned(); i += 2; }
            other => { anyhow::bail!("unknown flag: {other}"); }
        }
    }

    if case_path.exists() {
        anyhow::bail!("case file already exists: {}", case_path.display());
    }

    let mut store = CaseStore::create(&case_path, &name, examiner.as_deref(), "UTC")?;
    let registry = ParserRegistry::with_defaults();

    println!("Ingesting {} ...", collection.display());
    let report = ingest_into_store(&collection, &registry, &mut store);

    if let Some(p) = &report.profile {
        println!("Detected collection profile: {p}");
    }
    println!(
        "\nParsed {} artefacts, {} events, {} unclassified files.",
        report.artefacts.len(),
        report.total_events,
        report.unclassified
    );

    let (mut parsed, mut unsupported, mut failed) = (0, 0, 0);
    for a in &report.artefacts {
        match &a.status {
            ArtefactStatus::Parsed => parsed += 1,
            ArtefactStatus::Unsupported => unsupported += 1,
            ArtefactStatus::Failed(msg) => {
                failed += 1;
                eprintln!("  FAILED {}: {msg}", a.source_path);
            }
        }
    }
    println!("  parsed={parsed} unsupported={unsupported} failed={failed}");

    if !report.scan_errors.is_empty() {
        eprintln!("\nScan errors ({}):", report.scan_errors.len());
        for e in &report.scan_errors {
            eprintln!("  {e}");
        }
    }

    println!("\nCase written to {}", case_path.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_summary(args: &[String]) -> anyhow::Result<ExitCode> {
    let case_path = PathBuf::from(args.first().ok_or_else(|| anyhow::anyhow!("missing case file"))?);
    let store = CaseStore::open(&case_path)?;

    println!("Case: {}", store.case_id());
    println!("Total events: {}", store.event_count()?);

    println!("\nEvents by artefact:");
    for (artefact, count) in store.counts_by_artefact()? {
        println!("  {artefact:<18} {count}");
    }

    println!("\nIngest outcomes:");
    for (status, count) in store.ingest_summary()? {
        println!("  {status:<12} {count}");
    }

    // Early hunt preview: top SRUM network talkers by bytes sent.
    let net = store.srum_network_totals(10)?;
    if !net.is_empty() {
        println!("\nSRUM network usage — top talkers by bytes sent:");
        for t in net {
            println!(
                "  {:>12} sent  {:>12} recv   {}  (user {})",
                human_bytes(t.bytes_sent),
                human_bytes(t.bytes_recv),
                t.app,
                t.user
            );
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Compact human-readable byte formatting for the CLI.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn truncate_str(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn cmd_import_iocs(args: &[String]) -> anyhow::Result<ExitCode> {
    let pack_path = PathBuf::from(args.first().ok_or_else(|| anyhow::anyhow!("missing pack.json"))?);
    let out_dir = PathBuf::from(args.get(1).ok_or_else(|| anyhow::anyhow!("missing out_dir"))?);
    std::fs::create_dir_all(&out_dir)?;

    let text = std::fs::read_to_string(&pack_path)?;
    let pack: fx_hunt::import::IocPack = serde_json::from_str(&text)?;
    println!("Importing {} v{} ({} rules)", pack.name, pack.version, pack.rules.len());

    let result = fx_hunt::import::import_pack(&pack);

    // Write each converted rule as an individual YAML file (kind: event) so it
    // drops straight into the same rules dir the hunt engine loads.
    let mut written = 0;
    for rule in &result.rules {
        let yaml = fx_hunt::import::rule_to_yaml(rule)?;
        let path = out_dir.join(format!("{}.yml", rule.id));
        std::fs::write(&path, yaml)?;
        written += 1;
    }

    println!("\nConverted {written} rules -> {}", out_dir.display());
    if !result.repaired.is_empty() {
        println!("\nRepaired {} fragile regex(es) (transparent — logged here):", result.repaired.len());
        for (id, before, after) in &result.repaired {
            println!("  {id}");
            println!("    before: {}", truncate_str(before, 80));
            println!("    after:  {}", truncate_str(after, 80));
        }
    }
    if !result.dormant.is_empty() {
        println!("\n{} rule(s) imported but DORMANT — need a parser we don't have yet:", result.dormant.len());
        for (id, sources) in &result.dormant {
            println!("  {id}  (needs: {})", sources.join(", "));
        }
    }
    if !result.skipped.is_empty() {
        println!("\n{} rule(s) skipped (unconvertible):", result.skipped.len());
        for (id, why) in &result.skipped {
            println!("  {id}: {why}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_report(args: &[String]) -> anyhow::Result<ExitCode> {
    let case_path = PathBuf::from(args.first().ok_or_else(|| anyhow::anyhow!("missing case file"))?);
    let out_path = PathBuf::from(
        args.get(1)
            .cloned()
            .unwrap_or_else(|| "case-report.html".into()),
    );

    let store = CaseStore::open(&case_path)?;
    let html = fx_hunt::report::generate_report(&store)?;
    std::fs::write(&out_path, html)?;

    println!("Report written to {}", out_path.display());
    println!("Open it in a browser; use the browser's Print → Save as PDF to archive.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_hunt(args: &[String]) -> anyhow::Result<ExitCode> {
    let case_path = PathBuf::from(args.first().ok_or_else(|| anyhow::anyhow!("missing case file"))?);

    // Default rule dir sits next to the hunt crate; overridable with --rules.
    let mut rules_dir = PathBuf::from("crates/hunt/rules");
    let mut sigma_dir: Option<PathBuf> = None;
    let mut sigma_filter = fx_hunt::sigma::SigmaFilter::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules" => {
                rules_dir = PathBuf::from(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            "--sigma" => {
                sigma_dir = Some(PathBuf::from(args.get(i + 1).cloned().unwrap_or_default()));
                i += 2;
            }
            "--sigma-level" => {
                sigma_filter.min_level = args.get(i + 1).cloned().unwrap_or_else(|| "medium".into());
                i += 2;
            }
            "--sigma-status" => {
                sigma_filter.statuses = args.get(i + 1).map(|s| s.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();
                i += 2;
            }
            other => anyhow::bail!("unknown flag: {other}"),
        }
    }

    let store = CaseStore::open(&case_path)?;
    let rules = fx_hunt::RuleSet::load_dir(&rules_dir);
    if !rules.load_errors.is_empty() {
        for e in &rules.load_errors {
            eprintln!("  rule load: {e}");
        }
    }
    println!(
        "Loaded {} rules ({} single-event, {} correlation) from {}",
        rules.len(),
        rules.event_rules.len(),
        rules.correlation_rules.len(),
        rules_dir.display()
    );

    let report = fx_hunt::run(&store, &rules);
    for e in &report.errors {
        eprintln!("  hunt error: {e}");
    }

    // Optional community Sigma rules, run on top of the built-in pack. A
    // missing or empty folder is reported and the built-in results stand.
    if let Some(dir) = &sigma_dir {
        let load = fx_hunt::sigma::load_dir(dir, &sigma_filter);
        if let Some(e) = &load.folder_error {
            eprintln!("  sigma: {e} (built-in rules only)");
        } else {
            println!(
                "Sigma: {} rules loaded from {} ({} files, {} filtered by level/status, {} skipped)",
                load.loaded,
                dir.display(),
                load.files_seen,
                load.filtered,
                load.skipped_by_reason.values().sum::<usize>()
            );
            for (reason, n) in &load.skipped_by_reason {
                println!("    skipped {n:>4}  {reason}");
            }
            let sr = fx_hunt::run_sigma(&store, &dir.to_string_lossy(), &load);
            for e in &sr.errors {
                eprintln!("  sigma error: {e}");
            }
            println!("Sigma: {} findings from {} rules", sr.findings, sr.rules_hit);
            for h in sr.hits.iter().take(40) {
                println!("    [{:<8}] {:<60} {:>5} finding(s)", h.level.to_uppercase(), h.title, h.findings);
            }
        }
    }
    // Re-apply the case's allow-list (set in the GUI) so known-benign findings
    // stay suppressed after a re-hunt.
    let allow: Vec<fx_store::allowlist::AllowEntry> = store
        .kv_get("allowlist")?
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    if !allow.is_empty() {
        let counts = store.apply_allowlist(&allow)?;
        let n: u64 = counts.iter().map(|c| c.1).sum();
        println!("Allow-list: {} entries, {n} finding(s) suppressed", allow.len());
    }
    println!("\n{} detections from {} rules:\n", report.detections, report.rules_run);

    for d in store.detections()? {
        let host = d.host.unwrap_or_else(|| "-".into());
        println!(
            "  [{:<8}] {:<38} {}  ({}, {})",
            d.severity.to_uppercase(),
            d.title,
            d.summary,
            host,
            d.attack
        );
    }

    let cov = store.attack_coverage()?;
    if !cov.is_empty() {
        println!("\nATT&CK coverage:");
        for (tech, count) in cov {
            println!("  {tech:<12} {count}");
        }
    }

    Ok(ExitCode::SUCCESS)
}
