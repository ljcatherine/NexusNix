//! Reviewable change sets: AI or user proposed edits shown as hunks that can be
//! accepted or rejected individually, per file, or as a whole. Accepting writes
//! through the workspace (grant-checked); the original is kept for rollback.

use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HunkState {
    Pending,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hunk {
    /// 0-based line range in the original replaced by `new_lines`.
    pub old_start: usize,
    pub old_len: usize,
    pub old_lines: Vec<String>,
    pub new_lines: Vec<String>,
    pub state: HunkState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileChange {
    pub rel: String,
    /// `None` when the file is newly created.
    pub original: Option<String>,
    pub proposed: Option<String>,
    pub hunks: Vec<Hunk>,
    /// Who produced it (e.g. "codex", "claude", "user").
    pub author: String,
}

fn split_keep(s: &str) -> Vec<String> {
    s.split_inclusive('\n').map(str::to_string).collect()
}

impl FileChange {
    pub fn new(rel: &str, original: Option<String>, proposed: Option<String>, author: &str) -> Self {
        let a = original.clone().unwrap_or_default();
        let b = proposed.clone().unwrap_or_default();
        let diff = TextDiff::from_lines(&a, &b);
        let mut hunks = Vec::new();
        for group in diff.grouped_ops(0) {
            let (mut old_start, mut old_len) = (usize::MAX, 0);
            let mut old_lines = Vec::new();
            let mut new_lines = Vec::new();
            for op in &group {
                for change in diff.iter_changes(op) {
                    match change.tag() {
                        ChangeTag::Delete => {
                            let idx = change.old_index().unwrap_or(0);
                            old_start = old_start.min(idx);
                            old_len += 1;
                            old_lines.push(change.value().to_string());
                        }
                        ChangeTag::Insert => new_lines.push(change.value().to_string()),
                        ChangeTag::Equal => {}
                    }
                }
                if old_start == usize::MAX {
                    old_start = op.old_range().start;
                }
            }
            if old_start == usize::MAX {
                old_start = 0;
            }
            hunks.push(Hunk { old_start, old_len, old_lines, new_lines, state: HunkState::Pending });
        }
        Self { rel: rel.into(), original, proposed, hunks, author: author.into() }
    }

    pub fn set_all(&mut self, state: HunkState) {
        for h in &mut self.hunks {
            h.state = state;
        }
    }

    pub fn is_resolved(&self) -> bool {
        self.hunks.iter().all(|h| h.state != HunkState::Pending)
    }

    pub fn stats(&self) -> (usize, usize) {
        self.hunks.iter().fold((0, 0), |(a, d), h| (a + h.new_lines.len(), d + h.old_lines.len()))
    }

    /// The text that results from applying only accepted hunks to the original.
    /// Returns `None` if the outcome is "file should not exist".
    pub fn result(&self) -> Option<String> {
        if self.original.is_none() && self.hunks.iter().all(|h| h.state != HunkState::Accepted) {
            return None;
        }
        if self.proposed.is_none() && self.hunks.iter().all(|h| h.state == HunkState::Accepted) {
            return None;
        }
        let orig = split_keep(self.original.as_deref().unwrap_or(""));
        let mut out = String::new();
        let mut i = 0;
        for h in &self.hunks {
            while i < h.old_start && i < orig.len() {
                out.push_str(&orig[i]);
                i += 1;
            }
            if h.state == HunkState::Accepted {
                for l in &h.new_lines {
                    out.push_str(l);
                }
            } else {
                for l in &h.old_lines {
                    out.push_str(l);
                }
            }
            i += h.old_len;
        }
        while i < orig.len() {
            out.push_str(&orig[i]);
            i += 1;
        }
        Some(out)
    }

    /// Unified diff of original → proposed (for patch export).
    pub fn unified(&self) -> String {
        let a = self.original.clone().unwrap_or_default();
        let b = self.proposed.clone().unwrap_or_default();
        TextDiff::from_lines(&a, &b)
            .unified_diff()
            .context_radius(3)
            .header(&format!("a/{}", self.rel), &format!("b/{}", self.rel))
            .to_string()
    }
}

/// A set of file changes from one agent turn or inline edit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeSet {
    pub id: String,
    pub title: String,
    pub files: Vec<FileChange>,
}

impl ChangeSet {
    pub fn new(title: &str, files: Vec<FileChange>) -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), title: title.into(), files }
    }
    pub fn patch(&self) -> String {
        self.files.iter().map(FileChange::unified).collect::<Vec<_>>().join("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_accept_applies_only_selected_hunks() {
        let a = "one\ntwo\nthree\nfour\nfive\nsix\nseven\n";
        let b = "ONE\ntwo\nthree\nfour\nfive\nsix\nSEVEN\neight\n";
        let mut c = FileChange::new("f.txt", Some(a.into()), Some(b.into()), "codex");
        assert_eq!(c.hunks.len(), 2);
        c.hunks[0].state = HunkState::Accepted;
        c.hunks[1].state = HunkState::Rejected;
        assert_eq!(c.result().unwrap(), "ONE\ntwo\nthree\nfour\nfive\nsix\nseven\n");
        c.set_all(HunkState::Accepted);
        assert_eq!(c.result().unwrap(), b);
        c.set_all(HunkState::Rejected);
        assert_eq!(c.result().unwrap(), a);
    }

    #[test]
    fn pure_insertion_and_new_file() {
        let mut c = FileChange::new("f", Some("a\nc\n".into()), Some("a\nb\nc\n".into()), "u");
        c.set_all(HunkState::Accepted);
        assert_eq!(c.result().unwrap(), "a\nb\nc\n");
        let mut n = FileChange::new("n", None, Some("x\n".into()), "u");
        assert_eq!(n.result(), None);
        n.set_all(HunkState::Accepted);
        assert_eq!(n.result().unwrap(), "x\n");
        let mut d = FileChange::new("d", Some("x\n".into()), None, "u");
        d.set_all(HunkState::Accepted);
        assert_eq!(d.result(), None);
    }

    #[test]
    fn unified_patch_has_headers() {
        let c = FileChange::new("src/a.rs", Some("a\n".into()), Some("b\n".into()), "u");
        let p = c.unified();
        assert!(p.contains("--- a/src/a.rs") && p.contains("+b"));
    }
}
