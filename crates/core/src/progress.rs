//! Process-wide progress counters for long-running work (ingest, detections).
//!
//! fx runs one long job at a time, so a single global set of atomics is enough:
//! the worker bumps counters as it goes, and the GUI polls a [`Snapshot`] on a
//! timer and forwards it to the frontend. Workers check [`cancelled`] at safe
//! points (between files, per scanned event) and stop early when it is set.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
struct State {
    phase: Mutex<String>,
    current: Mutex<String>,
    files_done: AtomicU64,
    files_total: AtomicU64,
    bytes_done: AtomicU64,
    bytes_total: AtomicU64,
    events: AtomicU64,
    scanned: AtomicU64,
    scan_total: AtomicU64,
    work_done: AtomicU64,
    work_total: AtomicU64,
    warnings: AtomicU64,
    failed: AtomicU64,
    cancel: AtomicBool,
}

fn st() -> &'static State {
    static S: OnceLock<State> = OnceLock::new();
    S.get_or_init(State::default)
}

/// A point-in-time copy of the counters, ready to serialise.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Snapshot {
    pub phase: String,
    pub current: String,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub events: u64,
    pub scanned: u64,
    pub scan_total: u64,
    /// Cost-weighted scan progress (rows × rules that can apply to them), so
    /// the bar tracks real work rather than raw row count.
    pub work_done: u64,
    pub work_total: u64,
    pub warnings: u64,
    pub failed: u64,
    pub cancelled: bool,
}

/// Reset everything (including the cancel flag) at the start of a job.
pub fn reset() {
    let s = st();
    *s.phase.lock().unwrap() = String::new();
    *s.current.lock().unwrap() = String::new();
    for a in [&s.files_done, &s.files_total, &s.bytes_done, &s.bytes_total, &s.events, &s.scanned, &s.scan_total, &s.work_done, &s.work_total, &s.warnings, &s.failed] {
        a.store(0, Relaxed);
    }
    s.cancel.store(false, Relaxed);
}

pub fn set_phase(p: &str) {
    *st().phase.lock().unwrap() = p.to_string();
    set_current("");
}
pub fn set_current(c: &str) {
    *st().current.lock().unwrap() = c.to_string();
}
pub fn set_totals(files: u64, bytes: u64) {
    st().files_total.store(files, Relaxed);
    st().bytes_total.store(bytes, Relaxed);
}
pub fn file_done(bytes: u64, warnings: u64, failed: bool) {
    let s = st();
    s.files_done.fetch_add(1, Relaxed);
    s.bytes_done.fetch_add(bytes, Relaxed);
    s.warnings.fetch_add(warnings, Relaxed);
    if failed {
        s.failed.fetch_add(1, Relaxed);
    }
}
#[inline]
pub fn add_events(n: u64) {
    st().events.fetch_add(n, Relaxed);
}
/// Start a scan pass over `total` events (one per detection engine run).
pub fn start_scan(total: u64) {
    st().scanned.store(0, Relaxed);
    st().scan_total.store(total, Relaxed);
    st().work_done.store(0, Relaxed);
    st().work_total.store(0, Relaxed);
}
/// Set the cost-weighted total for the current scan (see `Snapshot::work_total`).
pub fn set_work_total(total: u64) {
    st().work_total.store(total, Relaxed);
}
#[inline]
pub fn add_work(n: u64) {
    st().work_done.fetch_add(n, Relaxed);
}
#[inline]
pub fn add_scanned(n: u64) {
    st().scanned.fetch_add(n, Relaxed);
}
pub fn request_cancel() {
    st().cancel.store(true, Relaxed);
}
#[inline]
pub fn cancelled() -> bool {
    st().cancel.load(Relaxed)
}

pub fn snapshot() -> Snapshot {
    let s = st();
    Snapshot {
        phase: s.phase.lock().unwrap().clone(),
        current: s.current.lock().unwrap().clone(),
        files_done: s.files_done.load(Relaxed),
        files_total: s.files_total.load(Relaxed),
        bytes_done: s.bytes_done.load(Relaxed),
        bytes_total: s.bytes_total.load(Relaxed),
        events: s.events.load(Relaxed),
        scanned: s.scanned.load(Relaxed),
        scan_total: s.scan_total.load(Relaxed),
        work_done: s.work_done.load(Relaxed),
        work_total: s.work_total.load(Relaxed),
        warnings: s.warnings.load(Relaxed),
        failed: s.failed.load(Relaxed),
        cancelled: s.cancel.load(Relaxed),
    }
}
