//! OpenAI-compatible chat providers: OpenAI API (metered), PS5LM Plus / llama.cpp
//! servers on the LAN, LM Studio, Ollama's OpenAI endpoint, other local servers.
//!
//! Chat only: these adapters do not execute tools, so Agent mode is unavailable
//! and the UI says so. TLS is verified by ureq/rustls; cleartext HTTP is allowed
//! only for loopback, private, link-local and Tailscale addresses (same rule as
//! the iOS app and gateway).

use crate::{Billing, Capabilities, Connection, Event, EventSink, Mode, Provider, ProviderError, TurnHandle, TurnRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenAiConfig {
    pub id: String,
    pub name: String,
    /// e.g. `https://api.openai.com/v1` or `http://192.168.1.50:8080/v1`.
    pub base_url: String,
    pub model: String,
    pub billing: Billing,
    /// Credential Manager target holding the API key, if any.
    pub key_target: Option<String>,
}

pub struct OpenAiCompatible {
    pub config: OpenAiConfig,
    /// Resolved at call time from Credential Manager by the app.
    pub api_key: Option<String>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    #[error("URL must start with http:// or https://")]
    Scheme,
    #[error("Cleartext HTTP is only allowed for private network addresses")]
    PublicHttp,
    #[error("URL must not contain credentials, a query or a fragment")]
    Extra,
}

/// Validate a base URL with the private-HTTP rule.
pub fn validate_base_url(url: &str) -> Result<(), UrlError> {
    let (scheme, rest) = url.split_once("://").ok_or(UrlError::Scheme)?;
    if rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err(UrlError::Extra);
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(()),
        "http" => {
            let hostport = rest.split('/').next().unwrap_or("");
            let host = if let Some(h) = hostport.strip_prefix('[') {
                h.split(']').next().unwrap_or("")
            } else {
                hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport)
            };
            if host.eq_ignore_ascii_case("localhost") {
                return Ok(());
            }
            match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => {
                    let o = v4.octets();
                    let tailscale = o[0] == 100 && (64..=127).contains(&o[1]);
                    if v4.is_private() || v4.is_loopback() || v4.is_link_local() || tailscale { Ok(()) } else { Err(UrlError::PublicHttp) }
                }
                Ok(IpAddr::V6(v6)) => {
                    let s = v6.segments()[0];
                    if v6.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80 { Ok(()) } else { Err(UrlError::PublicHttp) }
                }
                Err(_) => Err(UrlError::PublicHttp),
            }
        }
        _ => Err(UrlError::Scheme),
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(1800)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

/// Parse one SSE line of a chat-completions stream.
pub fn parse_sse(line: &str) -> Option<Result<(Option<String>, Option<String>), ()>> {
    let data = line.strip_prefix("data:")?.trim();
    if data == "[DONE]" {
        return Some(Err(()));
    }
    let v: Value = serde_json::from_str(data).ok()?;
    let d = v.pointer("/choices/0/delta")?;
    let text = d.get("content").and_then(Value::as_str).map(str::to_string);
    let reasoning = d.get("reasoning_content").or(d.get("reasoning")).and_then(Value::as_str).map(str::to_string);
    Some(Ok((text, reasoning)))
}

impl OpenAiCompatible {
    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.config.base_url.trim_end_matches('/'), path)
    }
}

impl Provider for OpenAiCompatible {
    fn id(&self) -> &'static str {
        "openai-compatible"
    }
    fn name(&self) -> String {
        self.config.name.clone()
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            modes: vec![Mode::Ask, Mode::Plan],
            edits_files: false,
            runs_commands: false,
            native_subagents: false,
            resume_sessions: false,
            token_usage: true,
            tool_calling: false,
            billing: self.config.billing,
            auth_method: if self.config.key_target.is_some() { "API key (Secret Service keystore)".into() } else { "None".into() },
            notes: "Chat only. Nexus does not give this provider tools, so Agent mode is unavailable. History is kept locally and resent each turn.".into(),
        }
    }

    fn verify(&self) -> Connection {
        if let Err(e) = validate_base_url(&self.config.base_url) {
            return Connection::Error(e.to_string());
        }
        let mut req = agent().get(&self.url("models"));
        if let Some(k) = &self.api_key {
            req = req.header("Authorization", &format!("Bearer {k}"));
        }
        match req.call() {
            Ok(mut r) if r.status() == 200 => {
                let v: Value = r.body_mut().read_json().unwrap_or(Value::Null);
                let models: Vec<String> = v
                    .get("data")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_string)).collect())
                    .unwrap_or_default();
                Connection::Connected { detail: format!("GET /models returned {} models", models.len()), models }
            }
            Ok(r) if r.status() == 401 || r.status() == 403 => Connection::SignedOut(format!("HTTP {}", r.status())),
            Ok(r) => Connection::Error(format!("HTTP {}", r.status())),
            Err(e) => Connection::Error(e.to_string()),
        }
    }

    fn start(&self, req: TurnRequest, sink: EventSink) -> Result<TurnHandle, ProviderError> {
        if req.mode == Mode::Agent {
            return Err(ProviderError::Unavailable(format!("{} is chat-only; Agent mode needs a tool-capable provider", self.config.name)));
        }
        validate_base_url(&self.config.base_url).map_err(|e| ProviderError::Unavailable(e.to_string()))?;
        let url = self.url("chat/completions");
        let key = self.api_key.clone();
        let model = req.model.clone().unwrap_or_else(|| self.config.model.clone());
        let body = json!({
            "model": model,
            "stream": true,
            "stream_options": {"include_usage": true},
            "messages": [
                {"role": "system", "content": crate::mode_preamble(req.mode)},
                {"role": "user", "content": crate::compose_prompt(&TurnRequest { instructions: req.instructions.clone(), ..req.clone() })}
            ]
        });
        let (ap_tx, _) = mpsc::channel();
        let handle = TurnHandle::new(ap_tx);
        let h2 = handle.clone();
        std::thread::spawn(move || {
            let mut r = agent().post(&url).header("Content-Type", "application/json");
            if let Some(k) = &key {
                r = r.header("Authorization", &format!("Bearer {k}"));
            }
            let resp = match r.send(body.to_string()) {
                Ok(resp) => resp,
                Err(e) => return sink.send(Event::Error(e.to_string())),
            };
            if resp.status() != 200 {
                return sink.send(Event::Error(format!("HTTP {}", resp.status())));
            }
            sink.send(Event::Session { id: uuid::Uuid::new_v4().to_string(), model: Some(model) });
            let reader = BufReader::new(resp.into_body().into_reader());
            for line in reader.lines() {
                if h2.is_cancelled() {
                    return sink.send(Event::Done { summary: Some("cancelled".into()) });
                }
                let Ok(line) = line else { break };
                if let Ok(v) = serde_json::from_str::<Value>(line.trim_start_matches("data:").trim()) {
                    if let Some(u) = v.get("usage").filter(|u| !u.is_null()) {
                        sink.send(Event::Usage {
                            input: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
                            output: u.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0),
                            context_window: None,
                        });
                    }
                }
                match parse_sse(&line) {
                    Some(Ok((t, r))) => {
                        if let Some(r) = r {
                            sink.send(Event::Reasoning(r));
                        }
                        if let Some(t) = t {
                            sink.send(Event::Text(t));
                        }
                    }
                    Some(Err(())) => break,
                    None => {}
                }
            }
            sink.send(Event::Done { summary: None });
        });
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_http_rule() {
        for ok in ["https://api.openai.com/v1", "http://192.168.1.50:8080/v1", "http://localhost:1234/v1", "http://100.100.1.2/v1", "http://[::1]:8080/v1", "http://10.0.0.1"] {
            assert!(validate_base_url(ok).is_ok(), "{ok}");
        }
        for bad in ["http://example.com/v1", "http://8.8.8.8/v1", "ftp://x", "https://user:pw@x/v1", "https://x/v1?k=1", "nourl"] {
            assert!(validate_base_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_sse_chunks() {
        assert_eq!(parse_sse(r#"data: {"choices":[{"delta":{"content":"Hi"}}]}"#), Some(Ok((Some("Hi".into()), None))));
        assert_eq!(parse_sse(r#"data: {"choices":[{"delta":{"reasoning_content":"hmm"}}]}"#), Some(Ok((None, Some("hmm".into())))));
        assert_eq!(parse_sse("data: [DONE]"), Some(Err(())));
        assert_eq!(parse_sse(": keepalive"), None);
    }
}
