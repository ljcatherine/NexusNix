//! SSH key generation using OpenSSH `ssh-keygen` (Windows used its built-in
//! OpenSSH; the Nix package puts OpenSSH on the wrapper's PATH).
//!
//! Keys are written to `~/.ssh/nexus_<name>_ed25519` (+ `.pub`), private key
//! mode 0600 as ssh-keygen creates it, `~/.ssh` 0700.
//! Existing files are never overwritten. The private key never leaves this PC;
//! installing the public key on a server is a change on that server, which the
//! owner performs (for Debian it requires the owner's explicit approval).

use std::path::PathBuf;
use std::process::Command;

pub fn ssh_dir() -> PathBuf {
    nexus_core::platform::ssh_dir()
}

/// Lowercase ASCII slug for file names.
pub fn slug(name: &str) -> String {
    let s: String = name.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let s = s.trim_matches('_').to_string();
    let mut out = String::new();
    for c in s.chars() {
        if !(c == '_' && out.ends_with('_')) {
            out.push(c);
        }
    }
    if out.is_empty() { "device".into() } else { out }
}

pub fn default_path(device_name: &str) -> PathBuf {
    ssh_dir().join(format!("nexus_{}_ed25519", slug(device_name)))
}

fn keygen() -> PathBuf {
    nexus_core::platform::which("ssh-keygen").unwrap_or_else(|| PathBuf::from("ssh-keygen"))
}

/// Generate an Ed25519 key. `passphrase` may be empty (unencrypted key).
/// Returns (private key path, public key line).
pub fn generate(path: &std::path::Path, comment: &str, passphrase: &str) -> Result<(PathBuf, String), String> {
    if path.exists() || path.with_extension("pub").exists() {
        return Err(format!("{} already exists; refusing to overwrite an existing key", path.display()));
    }
    // A new ~/.ssh must be owner-only or OpenSSH refuses to use it.
    if let Some(d) = path.parent().filter(|d| !d.exists()) {
        nexus_core::platform::ensure_private_dir(d).map_err(|e| e.to_string())?;
    }
    let mut cmd = Command::new(keygen());
    cmd.args(["-q", "-t", "ed25519", "-a", "64", "-C", comment, "-N", passphrase, "-f"]).arg(path);
    cmd.stdin(std::process::Stdio::null());
    let out = cmd.output().map_err(|e| format!("could not run ssh-keygen: {e}"))?;
    if !out.status.success() {
        return Err(format!("ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let pubkey = public_key(path).ok_or("public key file missing after generation")?;
    Ok((path.to_path_buf(), pubkey))
}

/// The `.pub` line next to a private key, if present.
pub fn public_key(private: &std::path::Path) -> Option<String> {
    let mut p = private.as_os_str().to_os_string();
    p.push(".pub");
    std::fs::read_to_string(PathBuf::from(p)).ok().map(|s| s.trim().to_string())
}

/// SHA256 fingerprint of a public key line (`ssh-ed25519 AAAA… comment`).
pub fn fingerprint(pub_line: &str) -> Option<String> {
    let b64 = pub_line.split_whitespace().nth(1)?;
    let blob = decode_b64(b64)?;
    Some(nexus_security::hostkeys::HostKeyStore::fingerprint_of(&blob))
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|x| *x == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slug("Debian server"), "debian_server");
        assert_eq!(slug("  NixOS / desktop!! "), "nixos_desktop");
        assert_eq!(slug("***"), "device");
    }

    #[test]
    fn generates_and_refuses_overwrite() {
        let d = std::env::temp_dir().join(format!("nexus-keytest-{}", std::process::id()));
        let p = d.join("k_ed25519");
        let (_, pubk) = match generate(&p, "nexus-test", "") {
            Ok(v) => v,
            Err(e) if e.contains("could not run") => return,
            Err(e) => panic!("{e}"),
        };
        assert!(pubk.starts_with("ssh-ed25519 "));
        assert!(fingerprint(&pubk).unwrap().starts_with("SHA256:"));
        assert!(generate(&p, "again", "").is_err(), "must not overwrite");
        let _ = std::fs::remove_dir_all(d);
    }
}
