//! Append-only audit log of every authorization decision.

use crate::policy::{Capability, Origin, Target};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "reason", rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    AllowedEscalated,
    Denied(String),
    EscalationApproved,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: String,
    pub target: Target,
    pub capability: Option<Capability>,
    /// Truncated to 512 chars; callers must not put secrets in summaries.
    pub summary: String,
    pub origin: Origin,
    pub outcome: Outcome,
}

impl AuditEvent {
    pub fn new(target: &Target, capability: Option<Capability>, summary: &str, origin: &Origin, outcome: Outcome) -> Self {
        let at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let mut summary: String = summary.chars().take(512).collect();
        summary = summary.replace(['\r', '\n'], " ");
        Self { at, target: target.clone(), capability, summary, origin: origin.clone(), outcome }
    }
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
    fn recent(&self, limit: usize) -> Vec<AuditEvent>;
    /// `Some(problem)` when events are not being persisted.
    fn health(&self) -> Option<String> {
        None
    }
}

/// In-memory sink (tests, and the UI's recent-events view).
#[derive(Default)]
pub struct MemoryAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAudit {
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().clone()
    }
}

impl AuditSink for MemoryAudit {
    fn record(&self, event: AuditEvent) {
        let mut v = self.events.lock();
        v.push(event);
        if v.len() > 10_000 {
            v.drain(..1_000);
        }
    }
    fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let v = self.events.lock();
        v.iter().rev().take(limit).cloned().collect()
    }
}

/// JSONL file sink plus an in-memory tail for the UI.
///
/// Never silently drops events: if the file cannot be opened or written (for
/// example briefly locked by antivirus), events are queued in memory and the
/// file is re-opened on the next event; queued lines are written first, in
/// order. [`AuditSink::health`] reports when events are not yet on disk.
pub struct FileAudit {
    path: PathBuf,
    tail: MemoryAudit,
    state: Mutex<FileState>,
}

struct FileState {
    file: Option<std::fs::File>,
    pending: std::collections::VecDeque<String>,
    dropped: usize,
    last_error: Option<String>,
}

const MAX_PENDING: usize = 10_000;

fn open_append(path: &PathBuf) -> std::io::Result<std::fs::File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl FileAudit {
    /// Open, failing if the file cannot be opened right now.
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        let a = Self::open_resilient(path);
        if a.state.lock().file.is_none() {
            return Err(std::io::Error::other(a.state.lock().last_error.clone().unwrap_or_default()));
        }
        Ok(a)
    }

    /// Always succeeds; retries the file on every event if it cannot be opened now.
    pub fn open_resilient(path: PathBuf) -> Self {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Reload the most recent events so the UI shows history across restarts.
        let tail = MemoryAudit::default();
        if let Ok(text) = std::fs::read_to_string(&path) {
            let lines: Vec<&str> = text.lines().collect();
            for l in &lines[lines.len().saturating_sub(1000)..] {
                if let Ok(e) = serde_json::from_str::<AuditEvent>(l) {
                    tail.record(e);
                }
            }
        }
        let (file, last_error) = match open_append(&path) {
            Ok(f) => (Some(f), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Self { path, tail, state: Mutex::new(FileState { file, pending: Default::default(), dropped: 0, last_error }) }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    fn persist(&self, line: String) {
        let mut st = self.state.lock();
        st.pending.push_back(line);
        if st.pending.len() > MAX_PENDING {
            st.pending.pop_front();
            st.dropped += 1;
        }
        if st.file.is_none() {
            match open_append(&self.path) {
                Ok(f) => st.file = Some(f),
                Err(e) => {
                    st.last_error = Some(e.to_string());
                    return;
                }
            }
        }
        while let Some(l) = st.pending.front().cloned() {
            let res = {
                let f = st.file.as_mut().unwrap();
                writeln!(f, "{l}").and_then(|_| f.flush())
            };
            match res {
                Ok(()) => {
                    st.pending.pop_front();
                }
                Err(e) => {
                    st.last_error = Some(e.to_string());
                    st.file = None;
                    return;
                }
            }
        }
        st.last_error = None;
    }
}

impl AuditSink for FileAudit {
    fn record(&self, event: AuditEvent) {
        if let Ok(line) = serde_json::to_string(&event) {
            self.persist(line);
        }
        self.tail.record(event);
    }
    fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        self.tail.recent(limit)
    }
    fn health(&self) -> Option<String> {
        let st = self.state.lock();
        if st.dropped > 0 {
            Some(format!("{} audit events were lost because the log file could not be written", st.dropped))
        } else if !st.pending.is_empty() {
            Some(format!("{} audit events not yet written to {}: {}", st.pending.len(), self.path.display(), st.last_error.clone().unwrap_or_default()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_audit_appends_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let a = FileAudit::open(p.clone()).unwrap();
        a.record(AuditEvent::new(&Target::Gateway, Some(Capability::Read), "line1\nline2", &Origin::User, Outcome::Allowed));
        a.record(AuditEvent::new(&Target::Gateway, None, "x", &Origin::User, Outcome::Denied("no".into())));
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("line1 line2"));
        assert_eq!(a.recent(1)[0].summary, "x");
        drop(a);
        let reopened = FileAudit::open(p).unwrap();
        assert_eq!(reopened.recent(10).len(), 2, "history reloads on reopen");
    }

    #[test]
    fn queues_when_file_unavailable_then_flushes_in_order() {
        let dir = tempfile::tempdir().unwrap();
        // A directory at the log path makes opening fail.
        let p = dir.path().join("audit.jsonl");
        std::fs::create_dir_all(&p).unwrap();
        let a = FileAudit::open_resilient(p.clone());
        assert!(FileAudit::open(p.clone()).is_err());
        a.record(AuditEvent::new(&Target::Gateway, None, "first", &Origin::User, Outcome::Allowed));
        a.record(AuditEvent::new(&Target::Gateway, None, "second", &Origin::User, Outcome::Allowed));
        assert!(a.health().unwrap().contains("2 audit events not yet written"));
        std::fs::remove_dir(&p).unwrap();
        a.record(AuditEvent::new(&Target::Gateway, None, "third", &Origin::User, Outcome::Allowed));
        assert_eq!(a.health(), None);
        let text = std::fs::read_to_string(&p).unwrap();
        let order: Vec<&str> = text.lines().map(|l| if l.contains("first") { "1" } else if l.contains("second") { "2" } else { "3" }).collect();
        assert_eq!(order, vec!["1", "2", "3"]);
    }
}
