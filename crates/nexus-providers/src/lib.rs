//! AI provider adapters behind a common interface.
//!
//! * [`codex::CodexProvider`] — official `codex app-server` (JSON-RPC over stdio),
//!   authenticated by the Codex CLI's own ChatGPT sign-in.
//! * [`claude::ClaudeCodeProvider`] — official Claude Code CLI in headless
//!   `-p --output-format stream-json` mode, authenticated by `claude auth login`.
//! * [`openai::OpenAiCompatible`] — OpenAI-compatible chat endpoints (OpenAI API,
//!   Anthropic-compatible proxies, PS5LM Plus, local servers). Chat only; no tools.
//!
//! Nexus never reads provider credentials owned by the official CLIs.
//! Providers run work on background threads and report through an [`EventSink`].

pub mod claude;
pub mod codex;
pub mod locate;
pub mod openai;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mode {
    /// Read-only questions; never modifies files or runs mutating commands.
    Ask,
    /// Read-only investigation that produces an implementation plan.
    Plan,
    /// Edits files and (if granted) runs commands inside the workspace.
    Agent,
    /// Like Claude Code's `bypassPermissions`: full read/write/execute/network
    /// with no prompts and no provider sandbox. Only for local workspaces the
    /// user explicitly enabled; Nexus still adds its Debian guardrails.
    Bypass,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Ask => "Ask",
            Mode::Plan => "Plan",
            Mode::Agent => "Agent",
            Mode::Bypass => "Bypass",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Billing {
    /// Uses an existing ChatGPT/Claude subscription through the official client.
    Subscription,
    /// Separately billed API usage.
    ApiMetered,
    /// Local or self-hosted; no provider billing.
    Local,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub modes: Vec<Mode>,
    pub edits_files: bool,
    pub runs_commands: bool,
    pub native_subagents: bool,
    pub resume_sessions: bool,
    pub token_usage: bool,
    pub tool_calling: bool,
    pub billing: Billing,
    pub auth_method: String,
    pub notes: String,
}

/// Result of a real verification (authentication + a supported operation).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Connection {
    /// Never checked.
    Unknown,
    /// The client binary or endpoint was not found.
    NotInstalled(String),
    /// Installed/reachable but not signed in.
    SignedOut(String),
    /// Verified. `detail` describes the account and the operation that passed.
    Connected { detail: String, models: Vec<String> },
    Error(String),
}

impl Connection {
    pub fn is_connected(&self) -> bool {
        matches!(self, Connection::Connected { .. })
    }
    pub fn label(&self) -> String {
        match self {
            Connection::Unknown => "Not checked".into(),
            Connection::NotInstalled(s) => format!("Not installed — {s}"),
            Connection::SignedOut(s) => format!("Signed out — {s}"),
            Connection::Connected { detail, .. } => format!("Connected — {detail}"),
            Connection::Error(e) => format!("Error — {e}"),
        }
    }
}

/// What the workspace policy allows the agent to do during this turn. Computed
/// by the caller from `nexus-security` grants, never by the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicy {
    pub write_files: bool,
    pub run_commands: bool,
    pub network: bool,
}

impl ToolPolicy {
    pub const READ_ONLY: ToolPolicy = ToolPolicy { write_files: false, run_commands: false, network: false };
    /// Mode caps the policy: Ask and Plan are always read-only.
    pub fn for_mode(self, mode: Mode) -> ToolPolicy {
        match mode {
            Mode::Ask | Mode::Plan => ToolPolicy::READ_ONLY,
            Mode::Agent => self,
            // Bypass is only ever full access; the caller decides whether the
            // workspace allows it at all.
            Mode::Bypass => ToolPolicy { write_files: true, run_commands: true, network: true },
        }
    }
}

#[derive(Clone, Debug)]
pub struct TurnRequest {
    pub workspace: PathBuf,
    pub mode: Mode,
    pub prompt: String,
    /// Extra context the user attached (already filtered for sensitive files).
    pub attachments: Vec<Attachment>,
    /// Images and PDFs the user attached (validated by [`media_type`]).
    pub media: Vec<Media>,
    pub resume: Option<String>,
    pub model: Option<String>,
    pub policy: ToolPolicy,
    /// Project instructions (AGENTS.md etc.) — providers that read them natively
    /// may ignore this.
    pub instructions: Option<String>,
    /// Non-negotiable rules from Nexus (e.g. the Debian read-only rule), always
    /// placed first in the prompt.
    pub safety: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attachment {
    pub label: String,
    pub content: String,
}

/// An image or PDF file sent alongside the prompt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Media {
    pub path: PathBuf,
    /// MIME type from the file's magic bytes, e.g. `image/png` or `application/pdf`.
    pub mime: String,
}

impl Media {
    pub fn is_pdf(&self) -> bool {
        self.mime == PDF_MIME
    }
}

pub const PDF_MIME: &str = "application/pdf";
/// Anthropic's per-image and per-PDF request limits (base64 adds a third on top).
pub const MAX_IMAGE_BYTES: u64 = 5 * 1024 * 1024;
pub const MAX_PDF_BYTES: u64 = 32 * 1024 * 1024;

/// MIME type from magic bytes (never trusts the extension). PNG, JPEG, GIF, WebP and PDF only.
pub fn media_type(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if head.starts_with(b"\xFF\xD8\xFF") {
        Some("image/jpeg")
    } else if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        Some("image/webp")
    } else if head.starts_with(b"%PDF-") {
        Some(PDF_MIME)
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PlanStatus {
    Pending,
    InProgress,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    pub step: String,
    pub status: PlanStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ApprovalKind {
    Command { command: String, cwd: String },
    FileChange { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Accept,
    Decline,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Event {
    Session { id: String, model: Option<String> },
    Text(String),
    Reasoning(String),
    Tool { kind: String, title: String, detail: String },
    Plan(Vec<PlanStep>),
    Diff(String),
    Approval { id: String, kind: ApprovalKind },
    Usage { input: u64, output: u64, context_window: Option<u64> },
    Done { summary: Option<String> },
    Error(String),
    Log(String),
}

/// Where providers deliver events. The callback is used to wake the UI.
#[derive(Clone)]
pub struct EventSink {
    tx: Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl EventSink {
    pub fn new(tx: Sender<Event>, wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self { tx, wake }
    }
    pub fn send(&self, e: Event) {
        let _ = self.tx.send(e);
        (self.wake)();
    }
}

/// Control handle for a running turn.
#[derive(Clone)]
pub struct TurnHandle {
    cancelled: Arc<AtomicBool>,
    approvals: Sender<(String, ApprovalDecision)>,
}

impl TurnHandle {
    pub fn new(approvals: Sender<(String, ApprovalDecision)>) -> Self {
        Self { cancelled: Arc::new(AtomicBool::new(false)), approvals }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
    pub fn decide(&self, id: &str, d: ApprovalDecision) {
        let _ = self.approvals.send((id.to_string(), d));
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("{0}")]
    Unavailable(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
}

pub trait Provider: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> String;
    fn capabilities(&self) -> Capabilities;
    /// Blocking; call off the UI thread.
    fn verify(&self) -> Connection;
    /// Starts a turn on a background thread.
    fn start(&self, req: TurnRequest, sink: EventSink) -> Result<TurnHandle, ProviderError>;
    /// Whether the provider accepts (images, PDFs) in a turn.
    fn media_support(&self) -> (bool, bool) {
        (false, false)
    }
}

/// Claude Code deny rules applied in Bypass mode: no remote shells or file
/// copies from agents (protects the read-only Debian server and other hosts).
pub const REMOTE_SHELL_DENY: &[&str] = &[
    "Bash(ssh:*)", "Bash(ssh.exe:*)", "Bash(scp:*)", "Bash(sftp:*)", "Bash(rsync:*)",
    "Bash(plink:*)", "Bash(pscp:*)", "Bash(putty:*)", "Bash(cloudflared:*)", "Bash(sshpass:*)",
];

/// Prompt prefix that states the mode's rules. Provider-side sandboxes enforce
/// them; this text only informs the model.
pub fn mode_preamble(mode: Mode) -> &'static str {
    match mode {
        Mode::Ask => "You are in Ask mode inside Nexus IDE. Answer and explain. Do not modify files or run commands that change state. If a change is useful, show it as a proposed patch in your reply.",
        Mode::Plan => "You are in Plan mode inside Nexus IDE. Inspect the project read-only and produce an implementation plan with these sections: Objective, Relevant files and modules, Proposed architecture, Implementation stages, Expected code modifications, Dependencies, Testing procedures, Security considerations, Risks. Do not modify files.",
        Mode::Agent => "You are in Agent mode inside Nexus IDE. Implement the request within the workspace. All edits are reviewed by the user as diffs afterwards.",
        Mode::Bypass => "You are in Bypass mode inside Nexus IDE: you may read, edit and run commands without asking, like a trusted developer on this PC. Work autonomously until the task is done, verify with builds/tests, and summarise what you changed. Edits inside the workspace are shown to the user as diffs afterwards.",
    }
}

pub fn compose_prompt(req: &TurnRequest) -> String {
    let mut s = String::new();
    if let Some(r) = &req.safety {
        s.push_str(r);
        s.push_str("

");
    }
    s.push_str(mode_preamble(req.mode));
    s.push_str("\n\n");
    if let Some(i) = &req.instructions {
        s.push_str("Project instructions:\n");
        s.push_str(i);
        s.push_str("\n\n");
    }
    for a in &req.attachments {
        s.push_str(&format!("<attachment name=\"{}\">\n{}\n</attachment>\n\n", a.label.replace('"', "'"), a.content));
    }
    s.push_str(&req.prompt);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ask_and_plan_are_always_read_only() {
        let full = ToolPolicy { write_files: true, run_commands: true, network: true };
        assert_eq!(full.for_mode(Mode::Ask), ToolPolicy::READ_ONLY);
        assert_eq!(full.for_mode(Mode::Plan), ToolPolicy::READ_ONLY);
        assert_eq!(full.for_mode(Mode::Agent), full);
        assert_eq!(ToolPolicy::READ_ONLY.for_mode(Mode::Bypass), full);
    }

    #[test]
    fn media_type_uses_magic_bytes() {
        assert_eq!(media_type(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(media_type(b"\xFF\xD8\xFF\xE0"), Some("image/jpeg"));
        assert_eq!(media_type(b"GIF89a"), Some("image/gif"));
        assert_eq!(media_type(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(media_type(b"%PDF-1.7"), Some(PDF_MIME));
        assert_eq!(media_type(b"MZ\x90\0"), None);
        assert_eq!(media_type(b""), None);
    }
}
