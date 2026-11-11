//! Workspace-wide text/regex search and replace preview.

use crate::tree::{list, ListOptions};
use regex::{Regex, RegexBuilder};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Query {
    pub pattern: String,
    pub regex: bool,
    pub case_sensitive: bool,
    pub whole_word: bool,
    pub max_results: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub rel: String,
    pub line: usize,
    pub column: usize,
    pub len: usize,
    pub text: String,
}

pub fn compile(q: &Query) -> Result<Regex, regex::Error> {
    let mut p = if q.regex { q.pattern.clone() } else { regex::escape(&q.pattern) };
    if q.whole_word {
        p = format!(r"\b(?:{p})\b");
    }
    RegexBuilder::new(&p).case_insensitive(!q.case_sensitive).size_limit(1 << 22).build()
}

/// Search text files under `root` (respecting ignore files). Skips files over
/// 4 MiB and files that are not valid UTF-8.
pub fn search(root: &Path, q: &Query) -> Result<Vec<Match>, regex::Error> {
    let re = compile(q)?;
    let mut out = Vec::new();
    if q.pattern.is_empty() {
        return Ok(out);
    }
    for e in list(root, ListOptions::default()) {
        if e.is_dir {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&e.path) else { continue };
        if meta.len() > 4 * 1024 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&e.path) else { continue };
        for (i, line) in text.lines().enumerate() {
            for m in re.find_iter(line) {
                out.push(Match {
                    rel: e.rel.clone(),
                    line: i + 1,
                    column: line[..m.start()].chars().count() + 1,
                    len: m.as_str().chars().count(),
                    text: line.chars().take(400).collect(),
                });
                if out.len() >= q.max_results {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}

/// Replacement preview for one file's contents.
pub fn replace_all(text: &str, q: &Query, replacement: &str) -> Result<(String, usize), regex::Error> {
    let re = compile(q)?;
    let n = re.find_iter(text).count();
    let r = if q.regex { re.replace_all(text, replacement) } else { re.replace_all(text, regex::NoExpand(replacement)) };
    Ok((r.into_owned(), n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(p: &str, regex: bool) -> Query {
        Query { pattern: p.into(), regex, case_sensitive: false, whole_word: false, max_results: 100 }
    }

    #[test]
    fn finds_literal_and_regex() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.rs"), "fn main() {}\nlet Main = 1;\n").unwrap();
        assert_eq!(search(d.path(), &q("main", false)).unwrap().len(), 2);
        let r = search(d.path(), &q(r"fn \w+", true)).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].line, r[0].column), (1, 1));
        assert_eq!(search(d.path(), &q("a.b", false)).unwrap().len(), 0);
    }

    #[test]
    fn replace_literal_does_not_expand() {
        let (t, n) = replace_all("a a", &q("a", false), "$1").unwrap();
        assert_eq!((t.as_str(), n), ("$1 $1", 2));
    }
}
