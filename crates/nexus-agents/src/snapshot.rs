//! Workspace snapshots around an agent turn.
//!
//! Before an Agent-mode turn the text files of the workspace are captured in
//! memory (ignore-aware, ≤1 MiB each, ≤256 MiB total). After the turn, the
//! difference becomes a [`ChangeSet`] whose originals are the pre-turn contents,
//! so changes the user already had are not attributed to the agent, and
//! rejecting a hunk restores the pre-turn text.

use nexus_workspaces::changes::{ChangeSet, FileChange};
use nexus_workspaces::tree::{files, ListOptions};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_FILE: u64 = 1024 * 1024;
const MAX_TOTAL: usize = 256 * 1024 * 1024;

pub struct Snapshot {
    root: PathBuf,
    files: BTreeMap<String, String>,
    /// Files skipped (binary/too large) — changes to them are reported, not diffed.
    skipped: Vec<String>,
    pub truncated: bool,
}

impl Snapshot {
    pub fn capture(root: &Path) -> Self {
        let mut map = BTreeMap::new();
        let mut skipped = Vec::new();
        let mut total = 0usize;
        let mut truncated = false;
        for rel in files(root, ListOptions { include_hidden: true, ..Default::default() }) {
            let p = root.join(&rel);
            let Ok(meta) = std::fs::metadata(&p) else { continue };
            if meta.len() > MAX_FILE {
                skipped.push(rel);
                continue;
            }
            match std::fs::read_to_string(&p) {
                Ok(t) => {
                    total += t.len();
                    if total > MAX_TOTAL {
                        truncated = true;
                        break;
                    }
                    map.insert(rel, t);
                }
                Err(_) => skipped.push(rel),
            }
        }
        Self { root: root.to_path_buf(), files: map, skipped, truncated }
    }

    pub fn original(&self, rel: &str) -> Option<&str> {
        self.files.get(rel).map(String::as_str)
    }

    /// Compare with the current workspace.
    pub fn diff(&self, title: &str, author: &str) -> ChangeSet {
        let mut out = Vec::new();
        let now: BTreeMap<String, ()> = files(&self.root, ListOptions { include_hidden: true, ..Default::default() })
            .into_iter()
            .map(|f| (f, ()))
            .collect();
        for (rel, before) in &self.files {
            match std::fs::read_to_string(self.root.join(rel)) {
                Ok(after) if &after != before => out.push(FileChange::new(rel, Some(before.clone()), Some(after), author)),
                Ok(_) => {}
                Err(_) if !self.root.join(rel).exists() => out.push(FileChange::new(rel, Some(before.clone()), None, author)),
                Err(_) => {}
            }
        }
        for rel in now.keys() {
            if !self.files.contains_key(rel) && !self.skipped.contains(rel) {
                if let Ok(after) = std::fs::read_to_string(self.root.join(rel)) {
                    out.push(FileChange::new(rel, None, Some(after), author));
                }
            }
        }
        ChangeSet::new(title, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_workspaces::changes::HunkState;

    #[test]
    fn attributes_only_turn_changes() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::write(r.join("a.txt"), "user edit already here\n").unwrap();
        std::fs::write(r.join("b.txt"), "b\n").unwrap();
        let snap = Snapshot::capture(r);
        // Agent edits:
        std::fs::write(r.join("b.txt"), "B\n").unwrap();
        std::fs::write(r.join("c.txt"), "new\n").unwrap();
        let cs = snap.diff("turn", "codex");
        let names: Vec<_> = cs.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(names, vec!["b.txt", "c.txt"]);
        let mut b = cs.files[0].clone();
        b.set_all(HunkState::Rejected);
        assert_eq!(b.result().unwrap(), "b\n");
    }
}
