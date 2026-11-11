//! Local workspace path validation (Windows-aware).

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("Path must be relative to the workspace")]
    NotRelative,
    #[error("Path escapes the workspace")]
    Escapes,
    #[error("Path contains a forbidden component: {0}")]
    Forbidden(String),
    #[error("I/O error: {0}")]
    Io(String),
}

const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Lexically validate a workspace-relative path supplied by a user or agent and
/// join it to `root`. Rejects absolute/drive/UNC paths, `..`, NTFS alternate data
/// streams (`:`), reserved device names and control characters.
pub fn join_relative(root: &Path, rel: &str) -> Result<PathBuf, PathError> {
    let rel = rel.replace('\\', "/");
    if rel.is_empty() {
        return Ok(root.to_path_buf());
    }
    if rel.starts_with('/') || rel.chars().nth(1) == Some(':') {
        return Err(PathError::NotRelative);
    }
    let mut out = root.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(PathError::Escapes);
        }
        if part.contains(':') || part.chars().any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*')) {
            return Err(PathError::Forbidden(part.into()));
        }
        let stem = part.split('.').next().unwrap_or("").trim_end().to_ascii_lowercase();
        if RESERVED.contains(&stem.as_str()) || part.ends_with(' ') || part.ends_with('.') {
            return Err(PathError::Forbidden(part.into()));
        }
        out.push(part);
    }
    for c in out.strip_prefix(root).map_err(|_| PathError::Escapes)?.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(PathError::Escapes);
        }
    }
    Ok(out)
}

/// Resolve symlinks/junctions of the deepest existing ancestor and require it to
/// remain inside the canonical root. Use before any write.
pub fn ensure_inside(root: &Path, candidate: &Path) -> Result<(), PathError> {
    let root_c = canon(root)?;
    let mut probe = candidate.to_path_buf();
    loop {
        if probe.exists() {
            let c = canon(&probe)?;
            return if c.starts_with(&root_c) { Ok(()) } else { Err(PathError::Escapes) };
        }
        if !probe.pop() {
            return Err(PathError::Escapes);
        }
    }
}

/// Canonicalize and strip the Windows `\\?\` verbatim prefix.
pub fn canon(p: &Path) -> Result<PathBuf, PathError> {
    let c = std::fs::canonicalize(p).map_err(|e| PathError::Io(e.to_string()))?;
    let s = c.to_string_lossy();
    Ok(PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()))
}

/// Workspace-relative display form with forward slashes.
pub fn relative_display(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_absolute() {
        let root = Path::new("C:/ws");
        for bad in ["../x", "a/../../x", "/etc/passwd", "C:/Windows", "\\\\server\\share", "a/file.txt:stream", "con", "nul.txt", "a/b?", "x. "] {
            assert!(join_relative(root, bad).is_err(), "{bad}");
        }
        assert_eq!(join_relative(root, "src/main.rs").unwrap(), Path::new("C:/ws").join("src").join("main.rs"));
        assert_eq!(join_relative(root, "./a//b").unwrap(), Path::new("C:/ws").join("a").join("b"));
    }

    #[test]
    fn ensure_inside_detects_real_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a")).unwrap();
        assert!(ensure_inside(root, &root.join("a").join("new.txt")).is_ok());
        let outside = tempfile::tempdir().unwrap();
        assert!(ensure_inside(root, outside.path()).is_err());
    }
}
