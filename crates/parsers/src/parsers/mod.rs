//! Concrete artefact parsers. Each is self-contained and depends only on
//! `fx-core` + its backing parse crate.

pub mod browser_history;
pub mod defender_log;
pub mod evtx;
pub mod lnk;
pub mod text_decode;
pub mod memory_files;
pub mod mft;
pub mod pca;
pub mod prefetch;
pub mod pshistory;
pub mod windows_timeline;
pub mod recyclebin;
pub mod remote_access;
pub mod registry;
pub mod scheduled_task;
pub mod setupapi;
pub mod srum;
pub mod usnjrnl;
