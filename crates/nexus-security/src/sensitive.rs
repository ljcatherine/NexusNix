//! Patterns for files that must never be read into AI context or exposed by the
//! remote file reader, regardless of other grants.

/// Returns true if the path (any separator) names a likely secret-bearing file.
pub fn is_sensitive_path(path: &str) -> bool {
    let norm = path.replace('\\', "/").to_ascii_lowercase();
    let name = norm.rsplit('/').next().unwrap_or(&norm);
    let segments: Vec<&str> = norm.split('/').collect();
    if segments.iter().any(|s| matches!(*s, ".ssh" | ".gnupg" | ".aws" | ".kube" | ".docker" | ".password-store")) {
        return true;
    }
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        return !name.ends_with(".example") && !name.ends_with(".sample") && !name.ends_with(".template");
    }
    const EXACT: &[&str] = &[
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys", "known_hosts",
        "credentials", "credentials.json", "auth.json", ".netrc", ".npmrc", ".pypirc",
        "shadow", "gshadow", "secrets.yaml", "secrets.yml", "secrets.json", "tunnel-token",
        ".git-credentials", "keychain", "token", "tokens.json", "cookies.sqlite",
    ];
    if EXACT.contains(&name) {
        return true;
    }
    if name.starts_with("id_") && !name.contains('.') {
        return true;
    }
    const EXT: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ovpn", ".mobileprovision", ".gpg", ".asc"];
    EXT.iter().any(|e| name.ends_with(e)) && !name.ends_with(".pub")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_secrets() {
        for p in ["/home/u/.ssh/config", "C:\\x\\.env", "a/.env.local", "srv/nexus.env", "k/server.key", "id_ed25519", "x/cert.p12", ".git-credentials", "/etc/shadow"] {
            assert!(is_sensitive_path(p), "{p}");
        }
        for p in ["src/main.rs", ".env.example", "id_ed25519.pub", "docs/keys.md", "key.rs"] {
            assert!(!is_sensitive_path(p), "{p}");
        }
    }
}
