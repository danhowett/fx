//! Concrete artefact parsers. Each is self-contained and depends only on
//! `fx-core` + its backing parse crate.

pub mod browser_history;
pub mod evtx;
pub mod lnk;
pub mod text_decode;
pub mod mft;
pub mod prefetch;
pub mod pshistory;
pub mod windows_timeline;
pub mod recyclebin;
pub mod remote_access;
pub mod registry;
pub mod scheduled_task;
pub mod srum;
pub mod usnjrnl;
