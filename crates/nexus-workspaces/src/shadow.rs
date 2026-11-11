//! Local shadow workspaces for read-only remote sources (Debian).
//!
//! Files are read from the remote with catalog commands, copied into
//! `$XDG_DATA_HOME/nexus-desktop/shadows/<id>` (Windows `%LOCALAPPDATA%\NexusDesktop\shadows\<id>`), and recorded with their remote
//! path and SHA-256. Agents may edit only the local copy. Changes are exported as
//! a patch; nothing is ever written back to the remote by this module.

use crate::{sha256_hex, write_atomic, WorkspaceError};
use nexus_security::paths::join_relative;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEntry {
    pub remote_path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShadowManifest {
    pub host_key: String,
    pub host_label: String,
    pub remote_root: String,
    pub created_at: String,
    /// workspace-relative path -> source record
    pub files: BTreeMap<String, ShadowEntry>,
}

pub struct ShadowWorkspace {
    pub dir: PathBuf,
    pub manifest: ShadowManifest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShadowStatus {
    Unchanged,
    Modified,
    Added,
    Deleted,
}

const MANIFEST: &str = ".nexus-shadow.json";

impl ShadowWorkspace {
    pub fn create(dir: &Path, host_key: &str, host_label: &str, remote_root: &str) -> Result<Self, WorkspaceError> {
        std::fs::create_dir_all(dir)?;
        let created_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let s = Self {
            dir: dir.to_path_buf(),
            manifest: ShadowManifest {
                host_key: host_key.into(),
                host_label: host_label.into(),
                remote_root: remote_root.trim_end_matches('/').into(),
                created_at,
                files: BTreeMap::new(),
            },
        };
        s.save()?;
        std::fs::write(dir.join(".nexusignore"), format!("{MANIFEST}\n"))?;
        Ok(s)
    }

    pub fn load(dir: &Path) -> Result<Self, WorkspaceError> {
        let text = std::fs::read_to_string(dir.join(MANIFEST))?;
        let manifest = serde_json::from_str(&text).map_err(|e| WorkspaceError::Other(e.to_string()))?;
        Ok(Self { dir: dir.to_path_buf(), manifest })
    }

    fn save(&self) -> Result<(), WorkspaceError> {
        let json = serde_json::to_string_pretty(&self.manifest).map_err(|e| WorkspaceError::Other(e.to_string()))?;
        write_atomic(&self.dir.join(MANIFEST), json.as_bytes())?;
        Ok(())
    }

    /// Record a file fetched from the remote. `rel` is relative to the remote root.
    pub fn import(&mut self, rel: &str, bytes: &[u8]) -> Result<(), WorkspaceError> {
        let local = join_relative(&self.dir, rel)?;
        write_atomic(&local, bytes)?;
        self.manifest.files.insert(
            rel.replace('\\', "/"),
            ShadowEntry {
                remote_path: format!("{}/{}", self.manifest.remote_root, rel.trim_start_matches('/')),
                sha256: sha256_hex(bytes),
                size: bytes.len() as u64,
            },
        );
        self.save()
    }

    pub fn status(&self) -> Vec<(String, ShadowStatus)> {
        let mut out = Vec::new();
        for (rel, entry) in &self.manifest.files {
            let p = self.dir.join(rel);
            let st = match std::fs::read(&p) {
                Ok(b) if sha256_hex(&b) == entry.sha256 => ShadowStatus::Unchanged,
                Ok(_) => ShadowStatus::Modified,
                Err(_) => ShadowStatus::Deleted,
            };
            out.push((rel.clone(), st));
        }
        for f in crate::tree::files(&self.dir, Default::default()) {
            if f != MANIFEST && f != ".nexusignore" && !self.manifest.files.contains_key(&f) {
                out.push((f, ShadowStatus::Added));
            }
        }
        out
    }

    /// Unified patch of local edits against the imported originals. The original
    /// text is the imported copy (its hash is in the manifest), so the patch is
    /// reviewable before any separately approved deployment.
    pub fn export_patch(&self, originals: &dyn Fn(&str) -> Option<String>) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Nexus shadow patch for {} ({}) — NOT applied to the remote host.\n",
            self.manifest.host_label, self.manifest.remote_root
        ));
        for (rel, st) in self.status() {
            let original = if st == ShadowStatus::Added { None } else { originals(&rel) };
            let current = std::fs::read_to_string(self.dir.join(&rel)).ok();
            if st != ShadowStatus::Unchanged {
                out.push_str(&crate::changes::FileChange::new(&rel, original, current, "shadow").unified());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_hashes_and_status() {
        let d = tempfile::tempdir().unwrap();
        let mut s = ShadowWorkspace::create(d.path(), "dev-1", "Debian server", "/home/debian/app/").unwrap();
        s.import("src/a.py", b"print(1)\n").unwrap();
        s.import("README", b"r\n").unwrap();
        assert_eq!(s.manifest.files["src/a.py"].remote_path, "/home/debian/app/src/a.py");
        assert!(s.status().iter().all(|(_, st)| *st == ShadowStatus::Unchanged));
        std::fs::write(d.path().join("src/a.py"), "print(2)\n").unwrap();
        std::fs::write(d.path().join("new.txt"), "n\n").unwrap();
        std::fs::remove_file(d.path().join("README")).unwrap();
        let st: BTreeMap<_, _> = s.status().into_iter().collect();
        assert_eq!(st["src/a.py"], ShadowStatus::Modified);
        assert_eq!(st["new.txt"], ShadowStatus::Added);
        assert_eq!(st["README"], ShadowStatus::Deleted);
        let patch = s.export_patch(&|rel| if rel == "src/a.py" { Some("print(1)\n".into()) } else { Some("r\n".into()) });
        assert!(patch.contains("-print(1)") && patch.contains("+print(2)") && patch.contains("NOT applied"));
        let reloaded = ShadowWorkspace::load(d.path()).unwrap();
        assert_eq!(reloaded.manifest.files.len(), 2);
        assert!(s.import("../escape", b"x").is_err());
    }
}
