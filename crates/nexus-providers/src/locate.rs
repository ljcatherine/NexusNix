//! Locate official CLI binaries.

use std::path::{Path, PathBuf};

fn on_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for n in names {
            let p = dir.join(n);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn home() -> Option<PathBuf> {
    std::env::home_dir().filter(|p| p.is_absolute())
}

/// User-level install locations searched after `PATH` (a desktop session may
/// not inherit the login shell's PATH): `~/.local/bin`, npm's global prefix as
/// set up on NixOS (`~/.npm-global/bin`), `~/.npm/bin`, `~/.nix-profile/bin`,
/// the per-user NixOS profile and the system profile.
fn user_bin_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home() {
        for rel in [".local/bin", ".npm-global/bin", ".npm/bin", ".nix-profile/bin", ".bun/bin", ".volta/bin"] {
            v.push(h.join(rel));
        }
    }
    if let Ok(user) = std::env::var("USER") {
        v.push(PathBuf::from("/etc/profiles/per-user").join(user).join("bin"));
    }
    v.push(PathBuf::from("/run/current-system/sw/bin"));
    v
}

fn in_user_dirs(name: &str) -> Option<PathBuf> {
    user_bin_dirs().into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

/// `codex` CLI: env override, PATH, then user install locations
/// (Windows: the official installer location under `%LOCALAPPDATA%`).
pub fn codex() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NEXUS_CODEX_PATH").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(p);
    }
    on_path(&["codex"]).or_else(|| in_user_dirs("codex"))
}

/// Standalone Claude Code CLI: env override, PATH, `~/.local/bin` (the
/// official native installer), npm global prefixes and Nix profiles.
/// (Windows also searched the copy bundled with the Claude desktop app; the
/// Linux Claude desktop app does not bundle a standalone CLI.)
pub fn claude() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NEXUS_CLAUDE_PATH").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(p);
    }
    on_path(&["claude"]).or_else(|| in_user_dirs("claude"))
}



/// Command builder for provider CLIs (Windows also suppressed a console
/// window and ran `.cmd` shims through `cmd /C`; neither applies on Linux).
pub fn command(program: &Path) -> std::process::Command {
    let mut c = std::process::Command::new(program);
    scrub_agent_env(&mut c);
    c
}

/// Environment variables removed from every provider (agent) process so it
/// does not inherit an SSH agent socket or a Git SSH override from Nexus's
/// environment. On Linux the agent is only reachable through `SSH_AUTH_SOCK`
/// (Windows' OpenSSH agent service used a fixed named pipe that this could not hide).
pub const SCRUBBED_ENV: [&str; 5] = ["SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS"];

pub fn scrub_agent_env(c: &mut std::process::Command) {
    for k in SCRUBBED_ENV {
        c.env_remove(k);
    }
}

#[cfg(test)]
mod scrub_tests {
    #[test]
    fn provider_commands_drop_ssh_agent_variables() {
        let c = super::command(std::path::Path::new("codex"));
        for k in super::SCRUBBED_ENV {
            assert!(c.get_envs().any(|(n, v)| n == k && v.is_none()), "{k} not removed");
        }
    }
}
