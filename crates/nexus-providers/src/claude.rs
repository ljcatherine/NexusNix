//! Anthropic Claude Code via the official CLI in headless mode:
//! `claude -p --output-format stream-json --verbose --include-partial-messages`.
//! Authentication is the CLI's own (`claude auth login`, Claude Pro/Max account).
//!
//! Mode mapping (enforced by Claude Code's permission system):
//! * Ask → `--permission-mode dontAsk` + read-only `--allowedTools`; edit and
//!   shell tools in `--disallowedTools`.
//! * Plan → `--permission-mode plan` (read-only planning).
//! * Agent → `acceptEdits` when the workspace grants writes (else `dontAsk` with
//!   edit tools disallowed); `Bash` is only allowed when commands are granted.

use crate::locate;
use crate::{
    compose_prompt, Billing, Capabilities, Connection, Event, EventSink, Mode, Provider, ProviderError, TurnHandle, TurnRequest,
};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;

pub struct ClaudeCodeProvider;

const READ_TOOLS: &str = "Read Grep Glob LS WebSearch WebFetch TodoWrite Task";
const EDIT_TOOLS: &str = "Edit MultiEdit Write NotebookEdit";

/// CLI arguments for a turn (prompt is sent on stdin).
pub fn args_for(req: &TurnRequest) -> Vec<String> {
    let p = req.policy.for_mode(req.mode);
    let mut a: Vec<String> = ["-p", "--output-format", "stream-json", "--verbose", "--include-partial-messages"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (mode, mut allowed, mut disallowed) = match req.mode {
        Mode::Ask => ("dontAsk", READ_TOOLS.to_string(), format!("{EDIT_TOOLS} Bash")),
        Mode::Plan => ("plan", READ_TOOLS.to_string(), format!("{EDIT_TOOLS} Bash")),
        Mode::Agent if p.write_files => ("acceptEdits", format!("{READ_TOOLS} {EDIT_TOOLS}"), String::new()),
        Mode::Agent => ("dontAsk", READ_TOOLS.to_string(), EDIT_TOOLS.to_string()),
        // Everything is allowed without prompts, except remote-shell tools:
        // deny rules still apply in bypassPermissions mode.
        Mode::Bypass => ("bypassPermissions", format!("{READ_TOOLS} {EDIT_TOOLS} Bash"), crate::REMOTE_SHELL_DENY.join(" ")),
    };
    if req.mode == Mode::Agent {
        if p.run_commands {
            allowed.push_str(" Bash");
        } else {
            disallowed.push_str(" Bash");
        }
    }
    a.push("--permission-mode".into());
    a.push(mode.into());
    a.push("--allowedTools".into());
    a.push(allowed.trim().into());
    if !disallowed.trim().is_empty() {
        a.push("--disallowedTools".into());
        a.push(disallowed.trim().into());
    }
    if let Some(id) = &req.resume {
        a.push("--resume".into());
        a.push(id.clone());
    }
    if let Some(m) = &req.model {
        a.push("--model".into());
        a.push(m.clone());
    }
    if !req.media.is_empty() {
        a.push("--input-format".into());
        a.push("stream-json".into());
    }
    a
}

/// One stream-json `user` message: images and PDFs as base64 content blocks, then the text.
pub fn user_message(prompt: &str, media: &[crate::Media]) -> std::io::Result<String> {
    use base64::Engine;
    let mut content = Vec::new();
    for m in media {
        let data = base64::engine::general_purpose::STANDARD.encode(std::fs::read(&m.path)?);
        let kind = if m.is_pdf() { "document" } else { "image" };
        content.push(serde_json::json!({"type": kind, "source": {"type": "base64", "media_type": m.mime, "data": data}}));
    }
    content.push(serde_json::json!({"type": "text", "text": prompt}));
    Ok(serde_json::json!({"type": "user", "message": {"role": "user", "content": content}}).to_string() + "\n")
}

/// Map one stream-json line to events. Returns true on the final `result`.
pub fn handle_line(line: &str, sink: &EventSink) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(line) else { return false };
    match v.get("type").and_then(Value::as_str) {
        Some("system") if v.get("subtype").and_then(Value::as_str) == Some("init") => {
            if let Some(id) = v.get("session_id").and_then(Value::as_str) {
                sink.send(Event::Session { id: id.into(), model: v.get("model").and_then(Value::as_str).map(str::to_string) });
            }
        }
        Some("stream_event") => {
            let ev = &v["event"];
            if ev.get("type").and_then(Value::as_str) == Some("content_block_delta") {
                match ev.pointer("/delta/type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(t) = ev.pointer("/delta/text").and_then(Value::as_str) {
                            sink.send(Event::Text(t.into()));
                        }
                    }
                    Some("thinking_delta") => {
                        if let Some(t) = ev.pointer("/delta/thinking").and_then(Value::as_str) {
                            sink.send(Event::Reasoning(t.into()));
                        }
                    }
                    _ => {}
                }
            }
        }
        Some("assistant") => {
            for block in v.pointer("/message/content").and_then(Value::as_array).into_iter().flatten() {
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("tool").to_string();
                    let input = block.get("input").cloned().unwrap_or(Value::Null);
                    let title = input
                        .get("file_path")
                        .or(input.get("command"))
                        .or(input.get("pattern"))
                        .or(input.get("description"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let kind = match name.as_str() {
                        "Edit" | "MultiEdit" | "Write" | "NotebookEdit" => "edit",
                        "Bash" => "command",
                        "Task" => "subagent",
                        "TodoWrite" => "plan",
                        _ => "read",
                    };
                    sink.send(Event::Tool { kind: kind.into(), title: format!("{name} {title}").trim().into(), detail: String::new() });
                }
            }
            if let Some(u) = v.pointer("/message/usage") {
                let input = u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0)
                    + u.get("cache_read_input_tokens").and_then(Value::as_u64).unwrap_or(0)
                    + u.get("cache_creation_input_tokens").and_then(Value::as_u64).unwrap_or(0);
                sink.send(Event::Usage { input, output: u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0), context_window: None });
            }
        }
        Some("user") => {
            for block in v.pointer("/message/content").and_then(Value::as_array).into_iter().flatten() {
                if block.get("type").and_then(Value::as_str) == Some("tool_result") && block.get("is_error").and_then(Value::as_bool) == Some(true) {
                    let text = block.get("content").map(|c| c.as_str().map(str::to_string).unwrap_or_else(|| c.to_string())).unwrap_or_default();
                    sink.send(Event::Log(format!("Tool denied or failed: {}", text.chars().take(300).collect::<String>())));
                }
            }
        }
        Some("result") => {
            let is_err = v.get("is_error").and_then(Value::as_bool).unwrap_or(false);
            let text = v.get("result").and_then(Value::as_str).map(str::to_string);
            if is_err {
                sink.send(Event::Error(text.unwrap_or_else(|| v.get("subtype").map(|s| s.to_string()).unwrap_or_default())));
            }
            sink.send(Event::Done { summary: v.get("subtype").and_then(Value::as_str).map(str::to_string) });
            return true;
        }
        _ => {}
    }
    false
}

impl Provider for ClaudeCodeProvider {
    fn id(&self) -> &'static str {
        "claude"
    }
    fn name(&self) -> String {
        "Claude Code".into()
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
            auth_method: "Claude account sign-in via the official Claude Code CLI (`claude auth login`)".into(),
            notes: "Usage counts against your Claude plan's limits. Headless mode cannot ask interactive permission questions, so tools outside the mode's allow-list are denied.".into(),
        }
    }

    fn media_support(&self) -> (bool, bool) {
        (true, true)
    }

    fn verify(&self) -> Connection {
        let Some(bin) = locate::claude() else {
            return Connection::NotInstalled("install Claude Code and run `claude auth login`".into());
        };
        let out = match locate::command(&bin).args(["auth", "status"]).stdin(Stdio::null()).output() {
            Ok(o) => o,
            Err(e) => return Connection::Error(e.to_string()),
        };
        let v: Value = match serde_json::from_slice(&out.stdout) {
            Ok(v) => v,
            Err(_) => return Connection::Error("unexpected `claude auth status` output".into()),
        };
        if v.get("loggedIn").and_then(Value::as_bool) != Some(true) {
            return Connection::SignedOut("run `claude auth login` (opens the official sign-in)".into());
        }
        let method = v.get("authMethod").and_then(Value::as_str).unwrap_or("account").to_string();
        // A real operation: a minimal headless turn with no tools.
        let res = run_capture(
            &bin,
            &["-p", "--output-format", "json", "--max-turns", "1", "--disallowedTools", "Bash Edit Write Read Grep Glob", "--no-session-persistence"],
            "Reply with exactly: OK",
            Duration::from_secs(90),
        );
        match res {
            Ok(text) => {
                let ok = serde_json::from_str::<Value>(&text)
                    .ok()
                    .filter(|r| r.get("is_error").and_then(Value::as_bool) == Some(false))
                    .is_some();
                if ok {
                    Connection::Connected { detail: format!("{method}; headless test turn succeeded"), models: vec!["sonnet".into(), "opus".into(), "haiku".into()] }
                } else {
                    Connection::Error(format!("signed in but test turn failed: {}", text.chars().take(300).collect::<String>()))
                }
            }
            Err(e) => Connection::Error(e),
        }
    }

    fn start(&self, req: TurnRequest, sink: EventSink) -> Result<TurnHandle, ProviderError> {
        let bin = locate::claude().ok_or_else(|| ProviderError::Unavailable("Claude Code CLI not found".into()))?;
        let prompt = if req.media.is_empty() { compose_prompt(&req) } else { user_message(&compose_prompt(&req), &req.media)? };
        let mut child = locate::command(&bin)
            .args(args_for(&req))
            .current_dir(&req.workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| ProviderError::Protocol("no stdin".into()))?;
        std::thread::spawn(move || {
            let _ = stdin.write_all(prompt.as_bytes());
        });
        let stdout = child.stdout.take().ok_or_else(|| ProviderError::Protocol("no stdout".into()))?;
        let stderr = child.stderr.take();
        let (ap_tx, _ap_rx) = mpsc::channel();
        let handle = TurnHandle::new(ap_tx);
        let h2 = handle.clone();
        let child = std::sync::Arc::new(parking_lot::Mutex::new(child));
        let c2 = child.clone();
        // Cancellation watchdog.
        let h3 = handle.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(200));
            let mut c = c2.lock();
            if matches!(c.try_wait(), Ok(Some(_))) {
                break;
            }
            if h3.is_cancelled() {
                let _ = c.kill();
                break;
            }
        });
        std::thread::spawn(move || {
            let mut finished = false;
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if handle_line(&line, &sink) {
                    finished = true;
                }
            }
            let status = child.lock().wait();
            if !finished {
                let err = stderr
                    .map(|s| BufReader::new(s).lines().map_while(Result::ok).collect::<Vec<_>>().join("\n"))
                    .unwrap_or_default();
                if h2.is_cancelled() {
                    sink.send(Event::Done { summary: Some("cancelled".into()) });
                } else {
                    sink.send(Event::Error(format!(
                        "Claude Code exited ({}) {}",
                        status.map(|s| s.to_string()).unwrap_or_default(),
                        err.chars().take(500).collect::<String>()
                    )));
                }
            }
        });
        Ok(handle)
    }
}

fn run_capture(bin: &std::path::Path, args: &[&str], stdin_text: &str, timeout: Duration) -> Result<String, String> {
    let mut child = locate::command(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut s) = child.stdin.take() {
        let _ = s.write_all(stdin_text.as_bytes());
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(o)) => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToolPolicy;
    use std::sync::Arc;

    fn req(mode: Mode, policy: ToolPolicy) -> TurnRequest {
        TurnRequest { workspace: ".".into(), mode, prompt: "x".into(), attachments: vec![], media: vec![], resume: None, model: None, policy, instructions: None, safety: None }
    }

    #[test]
    fn media_switches_to_stream_json_input_with_base64_blocks() {
        assert!(!args_for(&req(Mode::Ask, ToolPolicy::READ_ONLY)).contains(&"--input-format".to_string()));
        let dir = std::env::temp_dir().join(format!("nexus-media-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (img, pdf) = (dir.join("a.png"), dir.join("b.pdf"));
        std::fs::write(&img, b"\x89PNG\r\n\x1a\nxx").unwrap();
        std::fs::write(&pdf, b"%PDF-1.4 x").unwrap();
        let media = vec![crate::Media { path: img, mime: "image/png".into() }, crate::Media { path: pdf, mime: crate::PDF_MIME.into() }];
        let mut r = req(Mode::Ask, ToolPolicy::READ_ONLY);
        r.media = media.clone();
        assert_eq!(val(&args_for(&r), "--input-format").unwrap(), "stream-json");
        let v: Value = serde_json::from_str(&user_message("hi", &media).unwrap()).unwrap();
        let c = v.pointer("/message/content").unwrap().as_array().unwrap();
        assert_eq!(c[0]["type"], "image");
        assert_eq!(c[0]["source"]["data"], "iVBORw0KGgp4eA==");
        assert_eq!(c[1]["type"], "document");
        assert_eq!(c[1]["source"]["media_type"], "application/pdf");
        assert_eq!(c[2]["text"], "hi");
        std::fs::remove_dir_all(dir).ok();
    }

    fn val(a: &[String], flag: &str) -> Option<String> {
        a.iter().position(|x| x == flag).map(|i| a[i + 1].clone())
    }

    #[test]
    fn ask_and_plan_deny_edits_and_shell() {
        let full = ToolPolicy { write_files: true, run_commands: true, network: true };
        for m in [Mode::Ask, Mode::Plan] {
            let a = args_for(&req(m, full));
            let d = val(&a, "--disallowedTools").unwrap();
            assert!(d.contains("Edit") && d.contains("Write") && d.contains("Bash"), "{m:?}");
            assert!(!val(&a, "--allowedTools").unwrap().contains("Bash"));
            assert_ne!(val(&a, "--permission-mode").unwrap(), "acceptEdits");
        }
        assert_eq!(val(&args_for(&req(Mode::Plan, full)), "--permission-mode").unwrap(), "plan");
    }

    #[test]
    fn agent_follows_workspace_policy() {
        let a = args_for(&req(Mode::Agent, ToolPolicy::READ_ONLY));
        assert_eq!(val(&a, "--permission-mode").unwrap(), "dontAsk");
        assert!(val(&a, "--disallowedTools").unwrap().contains("Write"));
        let b = args_for(&req(Mode::Agent, ToolPolicy { write_files: true, run_commands: false, network: false }));
        assert_eq!(val(&b, "--permission-mode").unwrap(), "acceptEdits");
        assert!(val(&b, "--disallowedTools").unwrap().contains("Bash"));
        let c = args_for(&req(Mode::Agent, ToolPolicy { write_files: true, run_commands: true, network: false }));
        assert!(val(&c, "--allowedTools").unwrap().contains("Bash"));
        assert!(!a.iter().any(|x| x == "bypassPermissions") && !c.iter().any(|x| x == "bypassPermissions"));
    }

    #[test]
    fn bypass_maps_to_bypass_permissions_with_remote_shell_denies() {
        let a = args_for(&req(Mode::Bypass, ToolPolicy::READ_ONLY));
        assert_eq!(val(&a, "--permission-mode").unwrap(), "bypassPermissions");
        let d = val(&a, "--disallowedTools").unwrap();
        for r in ["Bash(ssh:*)", "Bash(scp:*)", "Bash(rsync:*)", "Bash(cloudflared:*)"] {
            assert!(d.contains(r), "{r}");
        }
        assert!(val(&a, "--allowedTools").unwrap().contains("Bash"));
    }

    #[test]
    fn parses_stream_json() {
        let (tx, rx) = mpsc::channel();
        let s = EventSink::new(tx, Arc::new(|| {}));
        handle_line(r#"{"type":"system","subtype":"init","session_id":"abc","model":"claude-sonnet"}"#, &s);
        handle_line(r#"{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hel"}}}"#, &s);
        handle_line(r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Edit","input":{"file_path":"src/a.rs"}}],"usage":{"input_tokens":5,"output_tokens":2}}}"#, &s);
        assert!(handle_line(r#"{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"abc"}"#, &s));
        let ev: Vec<Event> = rx.try_iter().collect();
        assert_eq!(ev[0], Event::Session { id: "abc".into(), model: Some("claude-sonnet".into()) });
        assert_eq!(ev[1], Event::Text("Hel".into()));
        assert!(matches!(&ev[2], Event::Tool { kind, title, .. } if kind == "edit" && title == "Edit src/a.rs"));
        assert!(matches!(ev.last(), Some(Event::Done { .. })));
    }
}
