//! `fx-gui` — Tauri desktop shell for the forensic tool.
//!
//! Thin: it owns the window, registers the command handlers, and holds the open
//! case in managed state. All real work lives in the `fx-*` crates.

mod commands;

use commands::AppState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::open_case,
            commands::ingest_collection,
            commands::cancel_job,
            commands::progress_snapshot,
            commands::query_timeline,
            commands::count_timeline,
            commands::event_raw,
            commands::run_hunt,
            commands::hunt_results,
            commands::set_triage,
            commands::clear_triage,
            commands::list_triage,
            commands::export_findings,
            commands::export_counts,
            commands::export_report,
            commands::ioc_preview,
            commands::ioc_sweep,
            commands::read_ioc_file,
            commands::events_by_ids,
            commands::ioc_saved,
            commands::ioc_save_list,
            commands::list_labels,
            commands::add_label,
            commands::remove_label,
            commands::sigma_preview,
            commands::sigma_hunt,
            commands::sigma_saved,
            commands::host_info,
            commands::ingest_log,
            commands::daily_activity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running fx-gui");
}
