//! Disposable SSH keys for the in-process mock servers.
//!
//! The Windows repo committed fixed Ed25519 test keys under `tests/fixtures`.
//! This repo never commits SSH private keys, so the same two keys
//! (`server_ed25519`, `client_ed25519`) are generated with OpenSSH's
//! `ssh-keygen` once per test process, in a private temporary directory that
//! is removed when the process exits. They authorize nothing anywhere else.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

fn generate(dir: &Path, name: &str) {
    let out = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", &format!("nexus-test-{name}"), "-f"])
        .arg(dir.join(name))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ssh-keygen (OpenSSH) is needed for the SSH mock tests; it is in the Nix dev shell");
    assert!(out.status.success(), "ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr));
}

pub fn fixture(name: &str) -> PathBuf {
    let dir = DIR.get_or_init(|| {
        let d = tempfile::tempdir().expect("temp dir");
        generate(d.path(), "server_ed25519");
        generate(d.path(), "client_ed25519");
        d
    });
    dir.path().join(name)
}
