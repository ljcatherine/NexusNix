//! Local Git integration via the Git CLI.
//!
//! Operations are a closed enum. Destructive operations (force push, hard reset,
//! branch deletion, clean, discarding changes, rebase) are deliberately absent.
//! Branch switching refuses a dirty working tree. Mutating operations require a
//! `GitWrite` grant; agents only receive one when the workspace policy allows it.

use nexus_security::policy::{Capability, Grant, Target};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git is not installed or not on PATH")]
    NotInstalled,
    #[error("not a git repository")]
    NotARepo,
    #[error("git failed: {0}")]
    Failed(String),
    #[error("not authorized: {0}")]
    Denied(String),
    #[error("refusing: {0}")]
    Refused(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStatus {
    pub path: String,
    /// Index (staged) status char, e.g. 'M', 'A', 'D', '.'.
    pub staged: char,
    /// Worktree status char.
    pub unstaged: char,
    pub untracked: bool,
    pub conflicted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub ahead: u32,
    pub behind: u32,
    pub files: Vec<FileStatus>,
}

impl Status {
    pub fn is_dirty(&self) -> bool {
        !self.files.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub hash: String,
    pub author: String,
    pub time: i64,
    pub subject: String,
}

/// Repository handle bound to a workspace target for grant checks.
pub struct Repo {
    root: PathBuf,
    target: Target,
}

fn git() -> Command {
    let mut c = Command::new("git");
    // Never prompt, never page, never use external diff tools.
    c.env("GIT_TERMINAL_PROMPT", "0").env("GIT_PAGER", "cat").env("LC_ALL", "C");
    // No console window to suppress on Linux (Windows set CREATE_NO_WINDOW);
    // never let git read from the app's stdin either.
    c.stdin(std::process::Stdio::null());
    c
}

impl Repo {
    pub fn discover(path: &Path, target: Target) -> Result<Self, GitError> {
        let out = git()
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .map_err(|_| GitError::NotInstalled)?;
        if !out.status.success() {
            return Err(GitError::NotARepo);
        }
        let root = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        Ok(Self { root, target })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn run(&self, args: &[&str]) -> Result<String, GitError> {
        let out = git()
            .arg("-C")
            .arg(&self.root)
            .args(["-c", "core.quotepath=off", "-c", "color.ui=never"])
            .args(args)
            .output()
            .map_err(|_| GitError::NotInstalled)?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(GitError::Failed(String::from_utf8_lossy(&out.stderr).trim().chars().take(2000).collect()))
        }
    }

    fn check(&self, grant: &Grant, cap: Capability) -> Result<(), GitError> {
        grant.require(cap, &self.target).map_err(|e| GitError::Denied(e.to_string()))
    }

    fn validate_paths(paths: &[&str]) -> Result<(), GitError> {
        for p in paths {
            if p.starts_with('-') || p.contains("..") || p.is_empty() {
                return Err(GitError::Refused(format!("invalid path {p}")));
            }
        }
        Ok(())
    }

    pub fn status(&self, grant: &Grant) -> Result<Status, GitError> {
        self.check(grant, Capability::GitRead)?;
        let text = self.run(&["--no-optional-locks", "status", "--porcelain=v2", "--branch", "-z", "--untracked-files=all"])?;
        Ok(parse_status(&text))
    }

    pub fn diff(&self, grant: &Grant, path: Option<&str>, staged: bool) -> Result<String, GitError> {
        self.check(grant, Capability::GitRead)?;
        let mut args = vec!["--no-optional-locks", "diff", "--no-ext-diff", "--no-color"];
        if staged {
            args.push("--cached");
        }
        if let Some(p) = path {
            Self::validate_paths(&[p])?;
            args.push("--");
            args.push(p);
        }
        self.run(&args)
    }

    /// File contents at HEAD (for gutter diffs and review baselines).
    pub fn show_head(&self, grant: &Grant, path: &str) -> Result<String, GitError> {
        self.check(grant, Capability::GitRead)?;
        Self::validate_paths(&[path])?;
        self.run(&["show", &format!("HEAD:{path}")])
    }

    pub fn log(&self, grant: &Grant, count: u32, path: Option<&str>) -> Result<Vec<Commit>, GitError> {
        self.check(grant, Capability::GitRead)?;
        let n = format!("--max-count={}", count.min(1000));
        let mut args = vec!["log", n.as_str(), "--format=%H%x1f%an%x1f%at%x1f%s"];
        if let Some(p) = path {
            Self::validate_paths(&[p])?;
            args.extend(["--follow", "--", p]);
        }
        let text = self.run(&args)?;
        Ok(text
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split('\u{1f}').collect();
                (f.len() == 4).then(|| Commit { hash: f[0].into(), author: f[1].into(), time: f[2].parse().unwrap_or(0), subject: f[3].into() })
            })
            .collect())
    }

    pub fn blame(&self, grant: &Grant, path: &str) -> Result<String, GitError> {
        self.check(grant, Capability::GitRead)?;
        Self::validate_paths(&[path])?;
        self.run(&["blame", "--date=short", "--", path])
    }

    pub fn branches(&self, grant: &Grant) -> Result<Vec<String>, GitError> {
        self.check(grant, Capability::GitRead)?;
        Ok(self.run(&["branch", "--format=%(refname:short)"])?.lines().map(str::to_string).collect())
    }

    pub fn worktrees(&self, grant: &Grant) -> Result<String, GitError> {
        self.check(grant, Capability::GitRead)?;
        self.run(&["worktree", "list", "--porcelain"])
    }

    pub fn stage(&self, grant: &Grant, paths: &[&str]) -> Result<(), GitError> {
        self.check(grant, Capability::GitWrite)?;
        Self::validate_paths(paths)?;
        let mut args = vec!["add", "--"];
        args.extend_from_slice(paths);
        self.run(&args).map(|_| ())
    }

    /// Unstage only (index change); the working tree is untouched.
    pub fn unstage(&self, grant: &Grant, paths: &[&str]) -> Result<(), GitError> {
        self.check(grant, Capability::GitWrite)?;
        Self::validate_paths(paths)?;
        let mut args = vec!["restore", "--staged", "--"];
        args.extend_from_slice(paths);
        self.run(&args).map(|_| ())
    }

    pub fn commit(&self, grant: &Grant, message: &str) -> Result<String, GitError> {
        self.check(grant, Capability::GitWrite)?;
        if message.trim().is_empty() {
            return Err(GitError::Refused("empty commit message".into()));
        }
        self.run(&["commit", "-m", message])?;
        Ok(self.run(&["rev-parse", "HEAD"])?.trim().to_string())
    }

    pub fn create_branch(&self, grant: &Grant, name: &str) -> Result<(), GitError> {
        self.check(grant, Capability::GitWrite)?;
        self.validate_ref(name)?;
        self.run(&["branch", "--", name]).map(|_| ())
    }

    /// Switch branches only when the working tree is clean.
    pub fn switch(&self, grant: &Grant, read: &Grant, name: &str) -> Result<(), GitError> {
        self.check(grant, Capability::GitWrite)?;
        self.validate_ref(name)?;
        if self.status(read)?.is_dirty() {
            return Err(GitError::Refused("working tree has changes; commit or stash them first".into()));
        }
        self.run(&["switch", "--no-guess", name]).map(|_| ())
    }

    /// New worktree on a new branch, e.g. for an agent to work in isolation.
    pub fn add_worktree(&self, grant: &Grant, dir: &Path, branch: &str) -> Result<(), GitError> {
        self.check(grant, Capability::GitWrite)?;
        self.validate_ref(branch)?;
        if dir.exists() {
            return Err(GitError::Refused("worktree folder already exists".into()));
        }
        let d = dir.to_string_lossy().into_owned();
        self.run(&["worktree", "add", "-b", branch, &d]).map(|_| ())
    }

    /// Non-force push of the current branch. User-only in the UI.
    pub fn push(&self, grant: &Grant) -> Result<String, GitError> {
        self.check(grant, Capability::GitWrite)?;
        if grant.is_agent() {
            return Err(GitError::Refused("agents cannot push".into()));
        }
        self.run(&["push", "--no-force-with-lease"])
    }

    fn validate_ref(&self, name: &str) -> Result<(), GitError> {
        let ok = !name.is_empty()
            && !name.starts_with('-')
            && !name.contains("..")
            && !name.chars().any(|c| c.is_whitespace() || c.is_control() || "~^:?*[\\".contains(c))
            && !name.ends_with(".lock")
            && !name.ends_with('/');
        if ok { Ok(()) } else { Err(GitError::Refused(format!("invalid branch name {name}"))) }
    }
}

pub fn parse_status(z: &str) -> Status {
    let mut st = Status::default();
    let mut recs = z.split('\0').peekable();
    while let Some(rec) = recs.next() {
        if rec.is_empty() {
            continue;
        }
        if let Some(h) = rec.strip_prefix("# ") {
            if let Some(b) = h.strip_prefix("branch.head ") {
                st.branch = (b != "(detached)").then(|| b.to_string());
            } else if let Some(u) = h.strip_prefix("branch.upstream ") {
                st.upstream = Some(u.into());
            } else if let Some(ab) = h.strip_prefix("branch.ab ") {
                for p in ab.split(' ') {
                    if let Some(a) = p.strip_prefix('+') {
                        st.ahead = a.parse().unwrap_or(0);
                    } else if let Some(b) = p.strip_prefix('-') {
                        st.behind = b.parse().unwrap_or(0);
                    }
                }
            }
            continue;
        }
        let mut chars = rec.chars();
        match chars.next() {
            Some('1') => {
                let f: Vec<&str> = rec.splitn(9, ' ').collect();
                if f.len() == 9 {
                    let xy: Vec<char> = f[1].chars().collect();
                    st.files.push(FileStatus { path: f[8].into(), staged: xy[0], unstaged: xy[1], untracked: false, conflicted: false });
                }
            }
            Some('2') => {
                let f: Vec<&str> = rec.splitn(10, ' ').collect();
                if f.len() == 10 {
                    let xy: Vec<char> = f[1].chars().collect();
                    st.files.push(FileStatus { path: f[9].into(), staged: xy[0], unstaged: xy[1], untracked: false, conflicted: false });
                }
                recs.next(); // original path
            }
            Some('u') => {
                let f: Vec<&str> = rec.splitn(11, ' ').collect();
                if let Some(p) = f.get(10) {
                    st.files.push(FileStatus { path: (*p).into(), staged: 'U', unstaged: 'U', untracked: false, conflicted: true });
                }
            }
            Some('?') => st.files.push(FileStatus { path: rec[2..].into(), staged: '.', unstaged: '?', untracked: true, conflicted: false }),
            _ => {}
        }
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_security::audit::MemoryAudit;
    use nexus_security::policy::{Operation, PolicyEngine};
    use std::sync::Arc;

    fn setup() -> Option<(tempfile::TempDir, Repo, PolicyEngine, Target)> {
        let d = tempfile::tempdir().unwrap();
        let ok = git().arg("-C").arg(d.path()).args(["init", "-q", "-b", "main"]).status().ok()?.success();
        if !ok {
            return None;
        }
        for (k, v) in [("user.email", "t@example.com"), ("user.name", "Test")] {
            git().arg("-C").arg(d.path()).args(["config", k, v]).status().ok()?;
        }
        let target = Target::LocalWorkspace { root: d.path().to_string_lossy().into() };
        let repo = Repo::discover(d.path(), target.clone()).ok()?;
        Some((d, repo, PolicyEngine::new(Arc::new(MemoryAudit::default())), target))
    }

    #[test]
    fn status_stage_commit_and_dirty_switch_guard() {
        let Some((d, repo, e, t)) = setup() else { return };
        let r = e.authorize(&Operation::user(t.clone(), Capability::GitRead, "status")).unwrap();
        let w = e.authorize(&Operation::user(t.clone(), Capability::GitWrite, "commit")).unwrap();
        std::fs::write(d.path().join("a.txt"), "1\n").unwrap();
        let st = repo.status(&r).unwrap();
        assert_eq!(st.branch.as_deref(), Some("main"));
        assert!(st.files[0].untracked);
        assert!(repo.stage(&r, &["a.txt"]).is_err(), "read grant cannot stage");
        repo.stage(&w, &["a.txt"]).unwrap();
        assert_eq!(repo.status(&r).unwrap().files[0].staged, 'A');
        let w2 = e.authorize(&Operation::user(t.clone(), Capability::GitWrite, "commit")).unwrap();
        let hash = repo.commit(&w2, "first").unwrap();
        assert_eq!(hash.len(), 40);
        assert_eq!(repo.log(&r, 5, None).unwrap()[0].subject, "first");
        std::fs::write(d.path().join("a.txt"), "2\n").unwrap();
        assert!(repo.diff(&r, Some("a.txt"), false).unwrap().contains("+2"));
        repo.create_branch(&w, "feature").unwrap();
        assert!(matches!(repo.switch(&w, &r, "feature"), Err(GitError::Refused(_))));
        assert!(repo.create_branch(&w, "-D").is_err());
        assert!(repo.stage(&w, &["--all"]).is_err());
        // Agent cannot get a GitWrite grant on a fresh workspace.
        assert!(e.authorize(&Operation::agent(t, Capability::GitWrite, "x", "s", "codex")).is_err());
    }

    #[test]
    fn parses_porcelain_v2() {
        let z = "# branch.oid abc\0# branch.head main\0# branch.upstream origin/main\0# branch.ab +2 -1\01 .M N... 100644 100644 100644 a b src/x.rs\0? new.txt\0";
        let s = parse_status(z);
        assert_eq!((s.ahead, s.behind), (2, 1));
        assert_eq!(s.files.len(), 2);
        assert_eq!(s.files[0].unstaged, 'M');
    }
}
