//! Workspaces: local folders, ignore-aware file trees, search, Debian shadow
//! workspaces and reviewable change sets.

pub mod changes;
pub mod search;
pub mod shadow;
pub mod tree;

use nexus_security::paths::{canon, ensure_inside, join_relative, PathError};
use nexus_security::policy::{Capability, Grant, Target};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Not authorized: {0}")]
    Denied(String),
    #[error("{0}")]
    Other(String),
}

/// A local workspace rooted at a canonical folder.
#[derive(Clone, Debug)]
pub struct Workspace {
    root: PathBuf,
    /// For shadow workspaces: a description of the read-only source.
    pub shadow_of: Option<String>,
}

impl Workspace {
    pub fn open(root: &Path) -> Result<Self, WorkspaceError> {
        let root = canon(root)?;
        if !root.is_dir() {
            return Err(WorkspaceError::Other("Not a folder".into()));
        }
        Ok(Self { root, shadow_of: None })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn name(&self) -> String {
        self.root.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| self.root.display().to_string())
    }

    pub fn target(&self) -> Target {
        Target::LocalWorkspace { root: self.root.to_string_lossy().replace('\\', "/") }
    }

    pub fn resolve(&self, rel: &str) -> Result<PathBuf, WorkspaceError> {
        Ok(join_relative(&self.root, rel)?)
    }

    pub fn read(&self, rel: &str, grant: &Grant) -> Result<String, WorkspaceError> {
        grant.require(Capability::Read, &self.target()).map_err(|e| WorkspaceError::Denied(e.to_string()))?;
        let p = self.resolve(rel)?;
        ensure_inside(&self.root, &p)?;
        Ok(std::fs::read_to_string(p)?)
    }

    /// Write a file atomically (temp file + rename) after checking the grant
    /// and that the resolved path stays inside the root (no symlink escape).
    pub fn write(&self, rel: &str, contents: &str, grant: &Grant) -> Result<(), WorkspaceError> {
        grant.require(Capability::WriteFile, &self.target()).map_err(|e| WorkspaceError::Denied(e.to_string()))?;
        let p = self.resolve(rel)?;
        ensure_inside(&self.root, &p)?;
        write_atomic(&p, contents.as_bytes())?;
        Ok(())
    }
}

/// Write bytes via a sibling temp file and rename, creating parent folders.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("nexus-tmp-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_security::audit::MemoryAudit;
    use nexus_security::policy::{Operation, PolicyEngine};
    use std::sync::Arc;

    #[test]
    fn write_requires_matching_grant() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let engine = PolicyEngine::new(Arc::new(MemoryAudit::default()));
        let read = engine.authorize(&Operation::user(ws.target(), Capability::Read, "a")).unwrap();
        assert!(ws.write("a.txt", "x", &read).is_err());
        let w = engine.authorize(&Operation::user(ws.target(), Capability::WriteFile, "a")).unwrap();
        ws.write("sub/a.txt", "hello", &w).unwrap();
        assert_eq!(ws.read("sub/a.txt", &read).unwrap(), "hello");
        assert!(ws.write("../escape.txt", "x", &w).is_err());
        // Agents are denied write on a fresh local workspace.
        assert!(engine.authorize(&Operation::agent(ws.target(), Capability::WriteFile, "a", "s", "codex")).is_err());
    }
}
