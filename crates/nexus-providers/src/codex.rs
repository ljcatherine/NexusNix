//! OpenAI Codex via the official `codex app-server` JSON-RPC protocol (stdio).
//! Schema reference: `docs/protocols/codex-app-server-0.162.1.v2.schema.json`.
//!
//! Mode mapping (enforced by Codex's own sandbox):
//! * Ask/Plan → `sandbox: read-only`, `approvalPolicy: never` (no writes, no
//!   escalation prompts).
//! * Agent → `workspace-write` only when the workspace policy grants file writes,
//!   otherwise `read-only`; `approvalPolicy: untrusted` so every command that
//!   leaves the sandbox is sent to Nexus for approval. Command approvals are
//!   auto-declined when the policy does not grant command execution.

use crate::locate;
use crate::{
    compose_prompt, ApprovalDecision, ApprovalKind, Billing, Capabilities, Connection, Event, EventSink, Mode, PlanStatus,
    PlanStep, Provider, ProviderError, TurnHandle, TurnRequest,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

pub struct CodexProvider;

/// Incoming message classification.
#[derive(Debug, PartialEq)]
pub enum Incoming {
    Response { id: i64, result: Result<Value, String> },
    Request { id: Value, method: String, params: Value },
    Notification { method: String, params: Value },
}

pub fn classify(line: &str) -> Option<Incoming> {
    let v: Value = serde_json::from_str(line).ok()?;
    let method = v.get("method").and_then(Value::as_str).map(str::to_string);
    let id = v.get("id").cloned();
    match (method, id) {
        (Some(m), Some(id)) => Some(Incoming::Request { id, method: m, params: v.get("params").cloned().unwrap_or(Value::Null) }),
        (Some(m), None) => Some(Incoming::Notification { method: m, params: v.get("params").cloned().unwrap_or(Value::Null) }),
        (None, Some(id)) => {
            let id = id.as_i64()?;
            let result = match v.get("error") {
                Some(e) => Err(e.get("message").and_then(Value::as_str).unwrap_or("error").to_string()),
                None => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
            };
            Some(Incoming::Response { id, result })
        }
        _ => None,
    }
}

/// A live app-server connection.
struct Rpc {
    child: Child,
    stdin: Mutex<ChildStdin>,
    next: Mutex<i64>,
    pending: Arc<Mutex<HashMap<i64, Sender<Result<Value, String>>>>>,
}

impl Rpc {
    fn spawn(other: Sender<Incoming>) -> Result<Self, ProviderError> {
        let bin = locate::codex().ok_or_else(|| ProviderError::Unavailable("codex CLI not found".into()))?;
        let mut child = locate::command(&bin)
            .arg("app-server")
            // Desktop-control features are not used by the IDE. Their runtime breaks
            // the Windows sandbox refresh (file lock on node_repl.exe) and they would
            // let an agent drive the desktop, so they are off for Nexus sessions only.
            .args(["--disable", "computer_use", "--disable", "browser_use", "--disable", "browser_use_external", "--disable", "in_app_browser"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| ProviderError::Protocol("no stdin".into()))?;
        let stdout = child.stdout.take().ok_or_else(|| ProviderError::Protocol("no stdout".into()))?;
        let pending: Arc<Mutex<HashMap<i64, Sender<Result<Value, String>>>>> = Arc::default();
        let p2 = pending.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                match classify(&line) {
                    Some(Incoming::Response { id, result }) => {
                        if let Some(tx) = p2.lock().remove(&id) {
                            let _ = tx.send(result);
                        }
                    }
                    Some(other_msg) => {
                        let _ = other.send(other_msg);
                    }
                    None => {}
                }
            }
            // Wake any waiters on exit.
            p2.lock().clear();
        });
        Ok(Self { child, stdin: Mutex::new(stdin), next: Mutex::new(1), pending })
    }

    fn write(&self, v: &Value) -> Result<(), ProviderError> {
        let mut s = self.stdin.lock();
        writeln!(s, "{v}")?;
        s.flush()?;
        Ok(())
    }

    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, ProviderError> {
        let id = {
            let mut n = self.next.lock();
            *n += 1;
            *n
        };
        let (tx, rx) = mpsc::channel();
        self.pending.lock().insert(id, tx);
        self.write(&json!({"id": id, "method": method, "params": params}))?;
        match rx.recv_timeout(timeout) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(ProviderError::Protocol(format!("{method}: {e}"))),
            Err(_) => Err(ProviderError::Protocol(format!("{method}: no response"))),
        }
    }

    fn notify(&self, method: &str, params: Value) -> Result<(), ProviderError> {
        self.write(&json!({"method": method, "params": params}))
    }

    fn respond(&self, id: &Value, result: Value) -> Result<(), ProviderError> {
        self.write(&json!({"id": id, "result": result}))
    }

    fn initialize(&self) -> Result<Value, ProviderError> {
        let r = self.call(
            "initialize",
            json!({"clientInfo": {"name": "nexus_desktop", "title": "Nexus Desktop", "version": env!("CARGO_PKG_VERSION")}}),
            Duration::from_secs(20),
        )?;
        self.notify("initialized", json!({}))?;
        Ok(r)
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Windows sandbox state reported by `windowsSandbox/readiness`
/// (`ready`, `notConfigured`, `updateRequired`).
pub fn windows_sandbox_readiness() -> Result<String, ProviderError> {
    let (tx, _rx) = mpsc::channel();
    let rpc = Rpc::spawn(tx)?;
    rpc.initialize()?;
    let r = rpc.call("windowsSandbox/readiness", json!({}), Duration::from_secs(20))?;
    Ok(r.get("status").and_then(Value::as_str).unwrap_or("unknown").to_string())
}

/// Start Codex's own Windows sandbox setup (`unelevated` needs no admin
/// rights). Waits for `windowsSandbox/setupCompleted`.
pub fn windows_sandbox_setup(cwd: &std::path::Path, elevated: bool) -> Result<(), ProviderError> {
    let (tx, rx) = mpsc::channel();
    let rpc = Rpc::spawn(tx)?;
    rpc.initialize()?;
    let mode = if elevated { "elevated" } else { "unelevated" };
    rpc.call("windowsSandbox/setupStart", json!({"mode": mode, "cwd": cwd.to_string_lossy()}), Duration::from_secs(30))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(600);
    while std::time::Instant::now() < deadline {
        if let Ok(Incoming::Notification { method, params }) = rx.recv_timeout(Duration::from_millis(500)) {
            if method == "windowsSandbox/setupCompleted" {
                return if params.get("success").and_then(Value::as_bool) == Some(true) {
                    Ok(())
                } else {
                    Err(ProviderError::Unavailable(params.get("error").and_then(Value::as_str).unwrap_or("sandbox setup failed").to_string()))
                };
            }
        }
    }
    Err(ProviderError::Protocol("sandbox setup timed out".into()))
}

pub fn describe_account(v: &Value) -> Option<String> {
    let acct = v.get("account")?;
    match acct.get("type")?.as_str()? {
        "chatgpt" => Some(format!(
            "ChatGPT {} ({})",
            acct.get("planType").and_then(Value::as_str).unwrap_or("plan"),
            acct.get("email").and_then(Value::as_str).unwrap_or("signed in")
        )),
        "apiKey" => Some("OpenAI API key (metered)".into()),
        other => Some(other.to_string()),
    }
}

impl Provider for CodexProvider {
    fn id(&self) -> &'static str {
        "codex"
    }
    fn name(&self) -> String {
        "OpenAI Codex".into()
    }
    /// app-server `UserInput` has `localImage` but no document type.
    fn media_support(&self) -> (bool, bool) {
        (true, false)
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            modes: vec![Mode::Ask, Mode::Plan, Mode::Agent, Mode::Bypass],
            edits_files: true,
            runs_commands: true,
            native_subagents: true,
            resume_sessions: true,
            token_usage: true,
            tool_calling: true,
            billing: Billing::Subscription,
            auth_method: "ChatGPT sign-in via the official Codex CLI (`codex login`)".into(),
            notes: "Usage counts against your ChatGPT plan's Codex limits. Sandboxed by Codex; command approvals are routed to Nexus.".into(),
        }
    }

    fn verify(&self) -> Connection {
        if locate::codex().is_none() {
            return Connection::NotInstalled("install the Codex CLI and run `codex login`".into());
        }
        let (tx, _rx) = mpsc::channel();
        let rpc = match Rpc::spawn(tx) {
            Ok(r) => r,
            Err(e) => return Connection::Error(e.to_string()),
        };
        if let Err(e) = rpc.initialize() {
            return Connection::Error(e.to_string());
        }
        let acct = match rpc.call("account/read", json!({"refreshToken": false}), Duration::from_secs(20)) {
            Ok(v) => v,
            Err(e) => return Connection::Error(e.to_string()),
        };
        let Some(detail) = describe_account(&acct) else {
            return Connection::SignedOut("run `codex login` to sign in with ChatGPT".into());
        };
        // A real supported operation beyond auth: list models.
        let models = match rpc.call("model/list", json!({}), Duration::from_secs(30)) {
            Ok(v) => v
                .get("data")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter(|m| !m.get("hidden").and_then(Value::as_bool).unwrap_or(false))
                        .filter_map(|m| m.get("model").and_then(Value::as_str).map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            Err(e) => return Connection::Error(format!("signed in but model/list failed: {e}")),
        };
        Connection::Connected { detail: format!("{detail}; model/list returned {} models", Vec::<String>::len(&models)), models }
    }

    fn start(&self, req: TurnRequest, sink: EventSink) -> Result<TurnHandle, ProviderError> {
        let (msg_tx, msg_rx) = mpsc::channel();
        let rpc = Rpc::spawn(msg_tx)?;
        let (ap_tx, ap_rx) = mpsc::channel();
        let handle = TurnHandle::new(ap_tx);
        let h2 = handle.clone();
        std::thread::spawn(move || {
            if let Err(e) = run_turn(rpc, req, &sink, msg_rx, ap_rx, &h2) {
                sink.send(Event::Error(e.to_string()));
            }
        });
        Ok(handle)
    }
}

fn sandbox_for(req: &TurnRequest) -> &'static str {
    if req.mode == Mode::Bypass {
        return "danger-full-access";
    }
    let p = req.policy.for_mode(req.mode);
    if p.write_files { "workspace-write" } else { "read-only" }
}

fn approval_for(req: &TurnRequest) -> &'static str {
    match req.mode {
        Mode::Ask | Mode::Plan => "never",
        Mode::Agent => "untrusted",
        Mode::Bypass => "never",
    }
}

/// `turn/start` input: the prompt, then each image as a `localImage` path (PDFs are refused upstream).
fn turn_input(req: &TurnRequest) -> Value {
    let mut input = vec![json!({"type": "text", "text": compose_prompt(req)})];
    input.extend(req.media.iter().filter(|m| !m.is_pdf()).map(|m| json!({"type": "localImage", "path": m.path})));
    Value::Array(input)
}

fn run_turn(
    rpc: Rpc,
    req: TurnRequest,
    sink: &EventSink,
    rx: Receiver<Incoming>,
    approvals: Receiver<(String, ApprovalDecision)>,
    handle: &TurnHandle,
) -> Result<(), ProviderError> {
    rpc.initialize()?;
    let cwd = req.workspace.to_string_lossy().to_string();
    let common = json!({
        "cwd": cwd,
        "sandbox": sandbox_for(&req),
        "approvalPolicy": approval_for(&req),
        "model": req.model,
    });
    let thread = if let Some(id) = &req.resume {
        let mut p = common.clone();
        p["threadId"] = json!(id);
        rpc.call("thread/resume", p, Duration::from_secs(60))?
    } else {
        rpc.call("thread/start", common, Duration::from_secs(60))?
    };
    let thread_id = thread
        .pointer("/thread/id")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::Protocol("thread id missing".into()))?
        .to_string();
    sink.send(Event::Session { id: thread_id.clone(), model: thread.get("model").and_then(Value::as_str).map(str::to_string) });
    let turn = rpc.call("turn/start", json!({"threadId": thread_id, "input": turn_input(&req)}), Duration::from_secs(60))?;
    let turn_id = turn.pointer("/turn/id").and_then(Value::as_str).unwrap_or_default().to_string();
    let policy = req.policy.for_mode(req.mode);
    let mut pending_approvals: HashMap<String, Value> = HashMap::new();
    let mut interrupted = false;
    loop {
        if handle.is_cancelled() && !interrupted {
            interrupted = true;
            let _ = rpc.call("turn/interrupt", json!({"threadId": thread_id, "turnId": turn_id}), Duration::from_secs(10));
        }
        while let Ok((id, d)) = approvals.try_recv() {
            if let Some(rid) = pending_approvals.remove(&id) {
                let decision = if d == ApprovalDecision::Accept { "accept" } else { "decline" };
                rpc.respond(&rid, json!({"decision": decision}))?;
            }
        }
        let msg = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(m) => m,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                sink.send(Event::Error("codex app-server exited".into()));
                return Ok(());
            }
        };
        match msg {
            Incoming::Request { id, method, params } => {
                let key = id.to_string();
                match method.as_str() {
                    "item/commandExecution/requestApproval" | "execCommandApproval" => {
                        let command = match params.get("command") {
                            Some(Value::String(s)) => s.clone(),
                            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "),
                            _ => "(command)".into(),
                        };
                        if !policy.run_commands {
                            rpc.respond(&id, json!({"decision": "decline"}))?;
                            sink.send(Event::Log(format!("Declined command (not permitted by workspace policy): {command}")));
                        } else {
                            pending_approvals.insert(key.clone(), id);
                            let cwd = params.get("cwd").and_then(Value::as_str).unwrap_or("").to_string();
                            sink.send(Event::Approval { id: key, kind: ApprovalKind::Command { command, cwd } });
                        }
                    }
                    "item/fileChange/requestApproval" | "applyPatchApproval" => {
                        let grant_root = params.get("grantRoot").and_then(Value::as_str);
                        if !policy.write_files {
                            rpc.respond(&id, json!({"decision": "decline"}))?;
                            sink.send(Event::Log("Declined file change (workspace is read-only for agents)".into()));
                        } else if grant_root.is_some() {
                            // A request to widen the writable root beyond the
                            // workspace goes to the user.
                            pending_approvals.insert(key.clone(), id);
                            let reason = format!("{} (requests write access to {})", params.get("reason").and_then(Value::as_str).unwrap_or("file change"), grant_root.unwrap_or(""));
                            sink.send(Event::Approval { id: key, kind: ApprovalKind::FileChange { reason } });
                        } else {
                            // In-workspace edits are allowed by the workspace grant and
                            // reviewed (and revertible) as hunks after the turn.
                            rpc.respond(&id, json!({"decision": "accept"}))?;
                            sink.send(Event::Log("File change inside the workspace accepted under the workspace grant; review after the turn".into()));
                        }
                    }
                    _ => {
                        // Unknown server requests are refused rather than ignored.
                        rpc.write(&json!({"id": id, "error": {"code": -32601, "message": "not supported by Nexus"}}))?;
                    }
                }
            }
            Incoming::Notification { method, params } => {
                if let Some(done) = handle_notification(&method, &params, sink) {
                    if done {
                        return Ok(());
                    }
                }
            }
            Incoming::Response { .. } => {}
        }
    }
}

/// Map a notification to events. Returns `Some(true)` when the turn ended.
pub fn handle_notification(method: &str, p: &Value, sink: &EventSink) -> Option<bool> {
    match method {
        "item/agentMessage/delta" => sink.send(Event::Text(p.get("delta")?.as_str()?.to_string())),
        "item/reasoning/summaryTextDelta" | "item/reasoning/textDelta" => {
            sink.send(Event::Reasoning(p.get("delta")?.as_str()?.to_string()))
        }
        "item/started" | "item/completed" => {
            let item = p.get("item")?;
            let ty = item.get("type")?.as_str()?;
            let done = method == "item/completed";
            match ty {
                "commandExecution" => {
                    let cmd = item.get("command").map(|c| c.as_str().map(str::to_string).unwrap_or_else(|| c.to_string())).unwrap_or_default();
                    let detail = if done {
                        format!(
                            "exit {}",
                            item.get("exitCode").map(Value::to_string).unwrap_or_else(|| "?".into())
                        )
                    } else {
                        "running".into()
                    };
                    sink.send(Event::Tool { kind: "command".into(), title: cmd, detail });
                }
                "fileChange" if done => {
                    for c in item.get("changes").and_then(Value::as_array).into_iter().flatten() {
                        sink.send(Event::Tool {
                            kind: "edit".into(),
                            title: c.get("path").and_then(Value::as_str).unwrap_or("").into(),
                            detail: c.get("kind").and_then(|k| k.get("type").and_then(Value::as_str).map(str::to_string).or_else(|| k.as_str().map(str::to_string))).unwrap_or_default(),
                        });
                    }
                }
                "mcpToolCall" | "dynamicToolCall" | "webSearch" | "subAgentActivity" | "collabAgentToolCall" if done => {
                    sink.send(Event::Tool { kind: ty.into(), title: item.get("tool").or(item.get("query")).map(|v| v.to_string()).unwrap_or_default(), detail: String::new() })
                }
                "contextCompaction" if done => sink.send(Event::Log("Codex compacted the conversation context".into())),
                _ => {}
            }
        }
        "turn/plan/updated" => {
            let steps = p
                .get("plan")?
                .as_array()?
                .iter()
                .filter_map(|s| {
                    Some(PlanStep {
                        step: s.get("step")?.as_str()?.to_string(),
                        status: match s.get("status").and_then(Value::as_str) {
                            Some("completed") => PlanStatus::Completed,
                            Some("inProgress") | Some("in_progress") => PlanStatus::InProgress,
                            _ => PlanStatus::Pending,
                        },
                    })
                })
                .collect();
            sink.send(Event::Plan(steps));
        }
        "turn/diff/updated" => sink.send(Event::Diff(p.get("diff")?.as_str()?.to_string())),
        "thread/tokenUsage/updated" => {
            let u = p.get("tokenUsage")?;
            let last = u.get("last")?;
            sink.send(Event::Usage {
                input: last.get("inputTokens").and_then(Value::as_u64).unwrap_or(0),
                output: last.get("outputTokens").and_then(Value::as_u64).unwrap_or(0),
                context_window: u.get("modelContextWindow").and_then(Value::as_u64),
            });
        }
        "error" => {
            let msg = p.pointer("/error/message").and_then(Value::as_str).unwrap_or("Codex error").to_string();
            let retry = p.get("willRetry").and_then(Value::as_bool).unwrap_or(false);
            sink.send(if retry { Event::Log(format!("{msg} (retrying)")) } else { Event::Error(msg) });
        }
        "turn/completed" => {
            let status = p.pointer("/turn/status").and_then(Value::as_str).unwrap_or("completed").to_string();
            sink.send(Event::Done { summary: Some(status) });
            return Some(true);
        }
        _ => {}
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sink() -> (EventSink, Receiver<Event>) {
        let (tx, rx) = mpsc::channel();
        (EventSink::new(tx, Arc::new(|| {})), rx)
    }

    #[test]
    fn classifies_messages() {
        assert_eq!(classify(r#"{"id":3,"result":{"ok":true}}"#), Some(Incoming::Response { id: 3, result: Ok(json!({"ok":true})) }));
        assert!(matches!(classify(r#"{"id":"a","method":"item/fileChange/requestApproval","params":{}}"#), Some(Incoming::Request { .. })));
        assert!(matches!(classify(r#"{"method":"turn/started","params":{}}"#), Some(Incoming::Notification { .. })));
        assert!(matches!(classify(r#"{"id":4,"error":{"message":"nope"}}"#), Some(Incoming::Response { result: Err(_), .. })));
        assert_eq!(classify("garbage"), None);
    }

    #[test]
    fn maps_notifications() {
        let (s, rx) = sink();
        handle_notification("item/agentMessage/delta", &json!({"delta":"hi","itemId":"i","threadId":"t","turnId":"u"}), &s);
        handle_notification("turn/plan/updated", &json!({"plan":[{"step":"a","status":"completed"},{"step":"b","status":"inProgress"}]}), &s);
        handle_notification("thread/tokenUsage/updated", &json!({"tokenUsage":{"last":{"inputTokens":10,"outputTokens":5},"total":{},"modelContextWindow":272000}}), &s);
        assert_eq!(handle_notification("turn/completed", &json!({"turn":{"status":"completed"}}), &s), Some(true));
        let ev: Vec<Event> = rx.try_iter().collect();
        assert_eq!(ev[0], Event::Text("hi".into()));
        assert!(matches!(&ev[1], Event::Plan(p) if p.len() == 2 && p[1].status == PlanStatus::InProgress));
        assert_eq!(ev[2], Event::Usage { input: 10, output: 5, context_window: Some(272000) });
        assert!(matches!(ev[3], Event::Done { .. }));
    }

    #[test]
    fn ask_mode_is_read_only_sandbox() {
        let mut r = TurnRequest {
            workspace: ".".into(),
            mode: Mode::Ask,
            prompt: "x".into(),
            attachments: vec![],
            media: vec![],
            resume: None,
            model: None,
            policy: crate::ToolPolicy { write_files: true, run_commands: true, network: false },
            instructions: None,
            safety: None,
        };
        assert_eq!((sandbox_for(&r), approval_for(&r)), ("read-only", "never"));
        r.media = vec![crate::Media { path: "C:/x/a.png".into(), mime: "image/png".into() }];
        let input = turn_input(&r);
        assert_eq!(input[1], json!({"type": "localImage", "path": "C:/x/a.png"}));
        r.media.clear();
        r.mode = Mode::Agent;
        assert_eq!(sandbox_for(&r), "workspace-write");
        r.policy.write_files = false;
        assert_eq!(sandbox_for(&r), "read-only");
        r.mode = Mode::Bypass;
        assert_eq!((sandbox_for(&r), approval_for(&r)), ("danger-full-access", "never"));
    }

    #[test]
    fn describes_chatgpt_account() {
        let d = describe_account(&json!({"account":{"type":"chatgpt","planType":"plus","email":"a@b.c"},"requiresOpenaiAuth":true})).unwrap();
        assert_eq!(d, "ChatGPT plus (a@b.c)");
        assert_eq!(describe_account(&json!({"account":null,"requiresOpenaiAuth":true})), None);
    }
}
