//! Agent orchestration support: durable sessions, task memory with visible
//! compaction history, and pre-turn workspace snapshots that turn whatever an
//! agent wrote into a reviewable, revertible change set.

pub mod memory;
pub mod snapshot;
pub mod store;

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
