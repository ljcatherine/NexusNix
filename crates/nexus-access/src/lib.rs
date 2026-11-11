//! Cloudflare Access Managed OAuth for Nexus Desktop (port of the iOS
//! `OIDCFlow` managed-access path).
//!
//! * Discovery from `<resource>/.well-known/oauth-authorization-server`; the
//!   issuer and every endpoint must be HTTPS on the `*.cloudflareaccess.com` issuer host.
//! * Authorization code + PKCE (S256), public client, `resource` indicator.
//! * Redirect `<resource>/oauth2redirect`; the Nexus Worker 302s to
//!   `com.ljcatherine.Nexus:/oauth2redirect?code&state`, which the desktop hands
//!   to Nexus Desktop through a per-user `x-scheme-handler` registration.
//! * Tokens are opaque, sent only as `Authorization: Bearer` to the Worker, and
//!   stored AES-256-GCM-encrypted with a key held in the user's Secret Service
//!   (see `store`; Windows used DPAPI).

pub mod store;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The Nexus Access application (same public native client as the iOS app).
/// Issuer, client id and Worker come from the site file (`nexus_core::site`),
/// never from the source.
pub fn issuer() -> String {
    nexus_core::site::site().access_issuer.trim_end_matches('/').to_string()
}

pub fn client_id() -> String {
    nexus_core::site::site().access_client_id.clone()
}

pub fn resource() -> String {
    nexus_core::site::site().gateway_url()
}

pub const CALLBACK_SCHEME: &str = "com.ljcatherine.Nexus";

pub fn redirect_uri() -> String {
    format!("{}/oauth2redirect", resource())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccessError {
    #[error("Cloudflare Access metadata is invalid or unexpected")]
    Metadata,
    #[error("The sign-in callback was invalid")]
    Callback,
    #[error("The sign-in callback did not match this sign-in attempt")]
    StateMismatch,
    #[error("Cloudflare Access refused sign-in: {0}")]
    Denied(String),
    #[error("Token exchange failed")]
    Token,
    #[error("Network: {0}")]
    Network(String),
    #[error("Cloudflare Access is not configured: set gateway_host, access_issuer and access_client_id in site.json (see docs/site.example.json)")]
    NotConfigured,
    #[error("Not signed in to Cloudflare Access")]
    SignedOut,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.contains('@') || host.is_empty() { None } else { Some(host) }
}

impl Metadata {
    pub fn validate(&self) -> Result<(), AccessError> {
        let ih = host_of(&self.issuer).ok_or(AccessError::Metadata)?;
        let iss = issuer();
        let expected = host_of(&iss).ok_or(AccessError::Metadata)?;
        if self.issuer.trim_end_matches('/') != iss || ih != expected || !ih.ends_with(".cloudflareaccess.com") {
            return Err(AccessError::Metadata);
        }
        for e in [Some(&self.authorization_endpoint), Some(&self.token_endpoint), self.revocation_endpoint.as_ref()].into_iter().flatten() {
            if host_of(e) != Some(ih) {
                return Err(AccessError::Metadata);
            }
        }
        if !self.code_challenge_methods_supported.iter().any(|m| m == "S256") {
            return Err(AccessError::Metadata);
        }
        Ok(())
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

pub fn discover() -> Result<Metadata, AccessError> {
    if client_id().is_empty() {
        return Err(AccessError::NotConfigured);
    }
    let mut r = agent()
        .get(&format!("{}/.well-known/oauth-authorization-server", resource()))
        .header("Accept", "application/json")
        .call()
        .map_err(|e| AccessError::Network(e.to_string()))?;
    if r.status() != 200 {
        return Err(AccessError::Metadata);
    }
    let m: Metadata = r.body_mut().with_config().limit(256_000).read_json().map_err(|_| AccessError::Metadata)?;
    m.validate()?;
    Ok(m)
}

fn random_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("OS random number generator");
    URL_SAFE_NO_PAD.encode(buf)
}

/// One sign-in attempt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
    pub nonce: String,
}

pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

impl Pkce {
    pub fn new() -> Self {
        let verifier = random_b64(48);
        Self { challenge: challenge_for(&verifier), verifier, state: random_b64(24), nonce: random_b64(24) }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'%' => return None,
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn authorization_url(m: &Metadata, p: &Pkce) -> String {
    let (client_id, resource) = (client_id(), resource());
    let _ = &resource;
    let q = [
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("resource", resource.as_str()),
        ("redirect_uri", &redirect_uri()),
        ("scope", "openid offline_access"),
        ("state", &p.state),
        ("nonce", &p.nonce),
        ("code_challenge", &p.challenge),
        ("code_challenge_method", "S256"),
    ];
    let qs: Vec<String> = q.iter().map(|(k, v)| format!("{k}={}", encode(v))).collect();
    format!("{}?{}", m.authorization_endpoint, qs.join("&"))
}

/// Parse `com.ljcatherine.Nexus:/oauth2redirect?code=…&state=…` (or `error=`)
/// and check the state. Returns the authorization code.
pub fn parse_callback(url: &str, expected_state: &str) -> Result<String, AccessError> {
    let url = url.trim();
    let prefix = format!("{}:", CALLBACK_SCHEME.to_ascii_lowercase());
    if url.len() > 12_000 || !url.to_ascii_lowercase().starts_with(&prefix) {
        return Err(AccessError::Callback);
    }
    let rest = &url[prefix.len()..];
    let (path, query) = rest.split_once('?').ok_or(AccessError::Callback)?;
    if path.trim_start_matches('/') != "oauth2redirect" {
        return Err(AccessError::Callback);
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').ok_or(AccessError::Callback)?;
        let v = decode(v).ok_or(AccessError::Callback)?;
        let slot = match k {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
            _ => return Err(AccessError::Callback),
        };
        if slot.is_some() {
            return Err(AccessError::Callback);
        }
        *slot = Some(v);
    }
    if state.as_deref() != Some(expected_state) {
        return Err(AccessError::StateMismatch);
    }
    if let Some(e) = error {
        return Err(AccessError::Denied(e));
    }
    code.filter(|c| !c.is_empty() && c.len() <= 8192).ok_or(AccessError::Callback)
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds.
    pub expires_at: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("expires_at", &self.expires_at).finish_non_exhaustive()
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Session {
    pub fn is_fresh(&self, margin_secs: u64) -> bool {
        self.expires_at > now() + margin_secs
    }
    pub fn expires_in(&self) -> i64 {
        self.expires_at as i64 - now() as i64
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

fn valid_bearer(t: &str) -> bool {
    !t.is_empty() && t.len() <= 16_384 && t.bytes().all(|b| b > 0x20 && b < 0x7f)
}

fn valid_refresh(t: &str) -> bool {
    !t.is_empty() && t.len() <= 16_384 && t.bytes().all(|b| b >= 0x20 && b != 0x7f)
}

pub fn session_from_token_json(body: &str, previous_refresh: Option<&str>) -> Result<Session, AccessError> {
    let r: TokenResponse = serde_json::from_str(body).map_err(|_| AccessError::Token)?;
    if !valid_bearer(&r.access_token) || !r.token_type.eq_ignore_ascii_case("bearer") || !(60..=86_400).contains(&r.expires_in) || r.refresh_token.as_deref().is_some_and(|t| !valid_refresh(t)) {
        return Err(AccessError::Token);
    }
    Ok(Session { access_token: r.access_token, refresh_token: r.refresh_token.or(previous_refresh.map(str::to_string)), expires_at: now() + r.expires_in })
}

fn post_form(url: &str, form: &[(&str, &str)]) -> Result<String, AccessError> {
    let mut r = agent()
        .post(url)
        .header("Accept", "application/json")
        .send_form(form.iter().copied())
        .map_err(|e| AccessError::Network(e.to_string()))?;
    let status = r.status();
    let body = r.body_mut().with_config().limit(256_000).read_to_string().map_err(|_| AccessError::Token)?;
    if status != 200 {
        return Err(AccessError::Token);
    }
    Ok(body)
}

pub fn exchange(m: &Metadata, code: &str, p: &Pkce) -> Result<Session, AccessError> {
    let (client_id, resource) = (client_id(), resource());
    let _ = &resource;
    m.validate()?;
    let redirect = redirect_uri();
    let body = post_form(&m.token_endpoint, &[
        ("grant_type", "authorization_code"),
        ("client_id", client_id.as_str()),
        ("code", code),
        ("redirect_uri", &redirect),
        ("resource", resource.as_str()),
        ("code_verifier", &p.verifier),
    ])?;
    session_from_token_json(&body, None)
}

pub fn refresh(m: &Metadata, s: &Session) -> Result<Session, AccessError> {
    let (client_id, resource) = (client_id(), resource());
    let _ = &resource;
    m.validate()?;
    let rt = s.refresh_token.as_deref().filter(|t| valid_refresh(t)).ok_or(AccessError::SignedOut)?;
    let body = post_form(&m.token_endpoint, &[("grant_type", "refresh_token"), ("client_id", client_id.as_str()), ("resource", resource.as_str()), ("refresh_token", rt)])?;
    session_from_token_json(&body, Some(rt))
}

/// Best-effort RFC 7009 revocation of the refresh token.
pub fn revoke(m: &Metadata, s: &Session) -> Result<(), AccessError> {
    let (client_id, resource) = (client_id(), resource());
    let _ = &resource;
    let (Some(ep), Some(rt)) = (&m.revocation_endpoint, &s.refresh_token) else { return Ok(()) };
    post_form(ep, &[("token", rt), ("token_type_hint", "refresh_token"), ("client_id", client_id.as_str())]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Metadata {
        Metadata {
            issuer: issuer(),
            authorization_endpoint: format!("{}/cdn-cgi/access/oauth/authorization", issuer()),
            token_endpoint: format!("{}/cdn-cgi/access/oauth/token", issuer()),
            revocation_endpoint: Some(format!("{}/cdn-cgi/access/oauth/revoke", issuer())),
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }

    #[test]
    fn pkce_s256_matches_independent_implementation() {
        // Expected value computed with Python hashlib + urlsafe base64 (no padding).
        assert_eq!(challenge_for("dBjftJeZ4CVP-mJ92K9mo9ZAGHnuE1BVf8tPJG3PvHs"), "fEpkjNnxhZTI96LfD-II4CON8COIBawaNbfvt_kzVa8");
        let a = Pkce::new();
        let b = Pkce::new();
        assert_ne!(a.state, b.state);
        assert!(a.verifier.len() >= 43);
    }

    #[test]
    fn metadata_must_be_on_the_access_issuer() {
        assert!(meta().validate().is_ok());
        let mut m = meta();
        m.token_endpoint = "https://evil.example/token".into();
        assert_eq!(m.validate(), Err(AccessError::Metadata));
        let mut m = meta();
        m.issuer = "https://other.cloudflareaccess.com".into();
        assert!(m.validate().is_err());
        let mut m = meta();
        m.code_challenge_methods_supported.clear();
        assert!(m.validate().is_err());
    }

    #[test]
    fn authorization_url_has_all_parameters() {
        let p = Pkce::new();
        let u = authorization_url(&meta(), &p);
        for needle in ["response_type=code", &format!("client_id={}", client_id()), "code_challenge_method=S256", "scope=openid%20offline_access", &format!("state={}", p.state), &format!("redirect_uri=https%3A%2F%2F{}%2Foauth2redirect", nexus_core::site::site().gateway_host), "resource=https%3A%2F%2Fnexus-gateway"] {
            assert!(u.contains(needle), "{needle} in {u}");
        }
    }

    #[test]
    fn callback_parsing() {
        assert_eq!(parse_callback("com.ljcatherine.Nexus:/oauth2redirect?state=abc&code=x%2Fy", "abc").unwrap(), "x/y");
        assert_eq!(parse_callback("com.ljcatherine.nexus:/oauth2redirect?code=c&state=zzz", "abc"), Err(AccessError::StateMismatch));
        assert_eq!(parse_callback("com.ljcatherine.Nexus:/oauth2redirect?state=abc&error=access_denied", "abc"), Err(AccessError::Denied("access_denied".into())));
        assert_eq!(parse_callback("https://evil/oauth2redirect?state=abc&code=c", "abc"), Err(AccessError::Callback));
        assert_eq!(parse_callback("com.ljcatherine.Nexus:/oauth2redirect?state=abc&code=a&code=b", "abc"), Err(AccessError::Callback));
        assert_eq!(parse_callback("com.ljcatherine.Nexus:/other?state=abc&code=a", "abc"), Err(AccessError::Callback));
    }

    #[test]
    fn token_response_validation() {
        let s = session_from_token_json(r#"{"access_token":"abc.def","token_type":"Bearer","expires_in":3600,"refresh_token":"r1"}"#, None).unwrap();
        assert!(s.is_fresh(60));
        assert_eq!(s.refresh_token.as_deref(), Some("r1"));
        let s2 = session_from_token_json(r#"{"access_token":"t","token_type":"bearer","expires_in":600}"#, Some("old")).unwrap();
        assert_eq!(s2.refresh_token.as_deref(), Some("old"));
        assert!(session_from_token_json(r#"{"access_token":"has space","token_type":"Bearer","expires_in":600}"#, None).is_err());
        assert!(session_from_token_json(r#"{"access_token":"t","token_type":"mac","expires_in":600}"#, None).is_err());
        assert!(session_from_token_json(r#"{"access_token":"t","token_type":"Bearer","expires_in":10}"#, None).is_err());
        assert!(!format!("{s:?}").contains("abc.def"), "Debug must not print tokens");
    }
}
