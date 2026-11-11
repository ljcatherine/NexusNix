//! What gets shared with AI providers, and how users see it.
//!
//! * Secret scanning (port of the iOS `AISensitiveContentScanner` patterns):
//!   returns categories only, never the matched values.
//! * Project instructions: `AGENTS.md`, `CLAUDE.md`, `.cursorrules`,
//!   `.cursor/rules/*.md(c)`, `.github/copilot-instructions.md`.
//! * Attachments: files are refused when sensitive by name, ignored by the
//!   workspace ignore files, too large, or binary. Every accepted file is listed
//!   in a [`SharingManifest`] that the UI displays before sending.

use nexus_security::sensitive::is_sensitive_path;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretCategory {
    PrivateKey,
    CredentialAssignment,
    RecognizedToken,
}

impl SecretCategory {
    pub fn title(self) -> &'static str {
        match self {
            SecretCategory::PrivateKey => "private-key material",
            SecretCategory::CredentialAssignment => "a credential assignment",
            SecretCategory::RecognizedToken => "a token or access-key pattern",
        }
    }
}

fn patterns() -> &'static [(SecretCategory, Regex)] {
    static P: OnceLock<Vec<(SecretCategory, Regex)>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            (SecretCategory::PrivateKey, Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").unwrap()),
            (
                SecretCategory::CredentialAssignment,
                Regex::new(r#"(?i)\b(?:[A-Z0-9]+_)*(?:PASSWORD|PASSPHRASE|API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|CLIENT[_-]?SECRET|SECRET[_-]?KEY|SECRET_ACCESS_KEY)\s*[:=]\s*["']?[^"'\s,;]{8,}"#).unwrap(),
            ),
            (
                SecretCategory::RecognizedToken,
                Regex::new(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b").unwrap(),
            ),
            (SecretCategory::RecognizedToken, Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b").unwrap()),
        ]
    })
}

/// Categories of likely secrets in `text` (no values are returned).
pub fn scan(text: &str) -> Vec<SecretCategory> {
    let mut out = Vec::new();
    for (c, re) in patterns() {
        if !out.contains(c) && re.is_match(text) {
            out.push(*c);
        }
    }
    out
}

const INSTRUCTION_FILES: &[&str] = &["AGENTS.md", "CLAUDE.md", ".cursorrules", ".github/copilot-instructions.md"];

/// Concatenated project instructions with source headers, capped at 32 KiB.
pub fn project_instructions(root: &Path) -> Option<String> {
    let mut out = String::new();
    let mut files: Vec<std::path::PathBuf> = INSTRUCTION_FILES.iter().map(|f| root.join(f)).collect();
    if let Ok(rd) = std::fs::read_dir(root.join(".cursor").join("rules")) {
        let mut extra: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "md" || e == "mdc")).collect();
        extra.sort();
        files.extend(extra);
    }
    for f in files {
        if let Ok(t) = std::fs::read_to_string(&f) {
            let rel = f.strip_prefix(root).unwrap_or(&f).to_string_lossy().replace('\\', "/");
            out.push_str(&format!("## {rel}\n{t}\n\n"));
        }
    }
    if out.is_empty() {
        return None;
    }
    if out.len() > 32 * 1024 {
        let mut cut = 32 * 1024;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("\n[truncated]");
    }
    Some(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    Sensitive,
    Ignored,
    TooLarge,
    Binary,
    Unreadable,
    ContainsSecrets(Vec<SecretCategory>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedItem {
    pub label: String,
    pub bytes: usize,
}

/// Exactly what is sent to a provider for one turn.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SharingManifest {
    pub provider: String,
    pub items: Vec<SharedItem>,
    pub refused: Vec<(String, Refusal)>,
}

pub const MAX_ATTACHMENT_BYTES: u64 = 512 * 1024;

/// Read a workspace file for attachment, applying every exclusion rule.
/// `allow_secrets` is the user's explicit override after seeing a warning.
pub fn load_attachment(root: &Path, rel: &str, allow_secrets: bool) -> Result<String, Refusal> {
    if is_sensitive_path(rel) {
        return Err(Refusal::Sensitive);
    }
    let path = nexus_security::paths::join_relative(root, rel).map_err(|_| Refusal::Unreadable)?;
    let visible = nexus_workspaces::tree::files(root, Default::default());
    if !visible.iter().any(|f| f == &rel.replace('\\', "/")) {
        return Err(Refusal::Ignored);
    }
    let meta = std::fs::metadata(&path).map_err(|_| Refusal::Unreadable)?;
    if meta.len() > MAX_ATTACHMENT_BYTES {
        return Err(Refusal::TooLarge);
    }
    let bytes = std::fs::read(&path).map_err(|_| Refusal::Unreadable)?;
    if bytes.iter().take(8000).any(|b| *b == 0) {
        return Err(Refusal::Binary);
    }
    let text = String::from_utf8(bytes).map_err(|_| Refusal::Binary)?;
    let secrets = scan(&text);
    if !secrets.is_empty() && !allow_secrets {
        return Err(Refusal::ContainsSecrets(secrets));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_like_ios() {
        assert_eq!(scan("-----BEGIN OPENSSH PRIVATE KEY-----"), vec![SecretCategory::PrivateKey]);
        assert_eq!(scan("API_KEY=abcd1234efgh"), vec![SecretCategory::CredentialAssignment]);
        assert_eq!(scan("token ghp_aaaaaaaaaaaaaaaaaaaaaaaaa"), vec![SecretCategory::RecognizedToken]);
        assert!(scan("let api_key = get();").is_empty());
        assert!(scan("hello world").is_empty());
    }

    #[test]
    fn attachments_apply_all_rules() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::write(r.join(".gitignore"), "build/\n").unwrap();
        std::fs::create_dir_all(r.join("build")).unwrap();
        std::fs::write(r.join("build/x.rs"), "x").unwrap();
        std::fs::write(r.join("a.rs"), "fn a() {}").unwrap();
        std::fs::write(r.join("cfg.rs"), "const PASSWORD: &str = \"hunter22hunter\"; // PASSWORD=hunter22hunter").unwrap();
        std::fs::write(r.join(".env"), "X=1").unwrap();
        std::fs::write(r.join("bin.dat"), [0u8, 1, 2]).unwrap();
        assert!(load_attachment(r, "a.rs", false).is_ok());
        assert_eq!(load_attachment(r, "build/x.rs", false), Err(Refusal::Ignored));
        assert_eq!(load_attachment(r, ".env", false), Err(Refusal::Sensitive));
        assert_eq!(load_attachment(r, "bin.dat", false), Err(Refusal::Binary));
        assert!(matches!(load_attachment(r, "cfg.rs", false), Err(Refusal::ContainsSecrets(_))));
        assert!(load_attachment(r, "cfg.rs", true).is_ok());
        assert_eq!(load_attachment(r, "../x", false), Err(Refusal::Unreadable));
    }

    #[test]
    fn loads_instructions() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("AGENTS.md"), "Be careful.").unwrap();
        let i = project_instructions(d.path()).unwrap();
        assert!(i.contains("## AGENTS.md") && i.contains("Be careful."));
    }
}
