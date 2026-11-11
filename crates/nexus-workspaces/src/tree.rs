//! Ignore-aware file listing. Honors .gitignore, .ignore, `.cursorignore` and
//! `.nexusignore`, and hides sensitive files from AI-facing listings.

use ignore::WalkBuilder;
use nexus_security::sensitive::is_sensitive_path;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub rel: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub depth: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct ListOptions {
    pub max_entries: usize,
    pub include_hidden: bool,
    /// Exclude sensitive files (always on for AI context).
    pub exclude_sensitive: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self { max_entries: 50_000, include_hidden: false, exclude_sensitive: false }
    }
}

fn walker(root: &Path, opts: &ListOptions) -> WalkBuilder {
    let mut b = WalkBuilder::new(root);
    b.hidden(!opts.include_hidden)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false)
        .add_custom_ignore_filename(".cursorignore")
        .add_custom_ignore_filename(".nexusignore")
        .filter_entry(|e| e.file_name() != ".git");
    b
}

/// All entries (files and dirs) under `root`, sorted dirs-first per folder.
pub fn list(root: &Path, opts: ListOptions) -> Vec<Entry> {
    let mut out = Vec::new();
    for e in walker(root, &opts).build().flatten() {
        if e.depth() == 0 {
            continue;
        }
        let rel = e.path().strip_prefix(root).unwrap_or(e.path()).to_string_lossy().replace('\\', "/");
        if opts.exclude_sensitive && is_sensitive_path(&rel) {
            continue;
        }
        out.push(Entry {
            rel,
            path: e.path().to_path_buf(),
            is_dir: e.file_type().is_some_and(|t| t.is_dir()),
            depth: e.depth(),
        });
        if out.len() >= opts.max_entries {
            break;
        }
    }
    out.sort_by(|a, b| tree_key(a).cmp(&tree_key(b)));
    out
}

fn tree_key(e: &Entry) -> Vec<(u8, String)> {
    let parts: Vec<&str> = e.rel.split('/').collect();
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let is_last = i == parts.len() - 1;
            let dir_rank = if is_last && !e.is_dir { 1 } else { 0 };
            (dir_rank, p.to_lowercase())
        })
        .collect()
}

/// Files only, for quick-open and context selection.
pub fn files(root: &Path, opts: ListOptions) -> Vec<String> {
    list(root, opts).into_iter().filter(|e| !e.is_dir).map(|e| e.rel).collect()
}

/// Subsequence fuzzy match score for quick-open (higher is better).
pub fn fuzzy_score(candidate: &str, query: &str) -> Option<i64> {
    if query.is_empty() {
        return Some(0);
    }
    let c: Vec<char> = candidate.to_lowercase().chars().collect();
    let mut score = 0i64;
    let mut ci = 0;
    let mut last = None;
    for q in query.to_lowercase().chars() {
        let mut found = false;
        while ci < c.len() {
            if c[ci] == q {
                score += 10;
                if last == Some(ci.wrapping_sub(1)) {
                    score += 15;
                }
                if ci == 0 || matches!(c[ci - 1], '/' | '_' | '-' | '.') {
                    score += 20;
                }
                last = Some(ci);
                ci += 1;
                found = true;
                break;
            }
            ci += 1;
        }
        if !found {
            return None;
        }
    }
    let name_start = candidate.rfind('/').map(|i| i + 1).unwrap_or(0);
    if last.is_some_and(|l| l >= name_start) {
        score += 25;
    }
    Some(score - candidate.len() as i64 / 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honors_ignore_files_and_sensitive_filter() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("src")).unwrap();
        std::fs::create_dir_all(r.join("target")).unwrap();
        std::fs::write(r.join(".gitignore"), "target/\n").unwrap();
        std::fs::write(r.join(".cursorignore"), "secret_dir/\n").unwrap();
        std::fs::create_dir_all(r.join("secret_dir")).unwrap();
        std::fs::write(r.join("secret_dir/x.txt"), "").unwrap();
        std::fs::write(r.join("src/main.rs"), "").unwrap();
        std::fs::write(r.join("target/out"), "").unwrap();
        std::fs::write(r.join("server.key"), "").unwrap();
        let all = files(r, ListOptions::default());
        assert!(all.contains(&"src/main.rs".to_string()));
        assert!(!all.iter().any(|f| f.starts_with("target") || f.starts_with("secret_dir")));
        assert!(all.contains(&"server.key".to_string()));
        let safe = files(r, ListOptions { exclude_sensitive: true, ..Default::default() });
        assert!(!safe.contains(&"server.key".to_string()));
    }

    #[test]
    fn fuzzy_prefers_filename_matches() {
        let a = fuzzy_score("crates/nexus-app/src/main.rs", "main").unwrap();
        let b = fuzzy_score("crates/main_helpers/src/lib.rs", "main").unwrap();
        assert!(a > b);
        assert!(fuzzy_score("abc", "abd").is_none());
    }
}
