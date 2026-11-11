//! SSH through the Nexus Cloudflare Worker relay (port of the iOS
//! `CloudflareSSHConnector`).
//!
//! `wss://<worker>/v1/ssh/{nixos|debian|debian-ro}` with `Authorization: Bearer <Access token>`
//! and `Sec-WebSocket-Protocol: nexus-ssh-v1`. Binary frames carry the raw SSH
//! stream. The gateway terminates SSH (pre-authenticated, no client key) and
//! opens its own pinned connection to the target, so the Access token never
//! reaches the target host. Nexus pins the relay's SSH host key under
//! `relay:<worker>/<target>` (separate from TLS verification).
//!
//! The returned [`Session`] is the same grant-gated type as direct SSH, so
//! Debian still only receives catalog commands.

use crate::{Session, SshError, Verifier};
use futures_util::{SinkExt, StreamExt};
use nexus_security::hostkeys::HostKeyStore;
use nexus_security::policy::{Capability, Operation, PolicyEngine, Target};
use russh::client;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

pub const SUBPROTOCOL: &str = "nexus-ssh-v1";
pub const TARGETS: [&str; 3] = ["nixos", "debian", "debian-ro"];

pub fn relay_authority(host: &str, target: &str) -> String {
    format!("relay:{}/{}", host.to_ascii_lowercase(), target)
}

fn valid_token(t: &str) -> bool {
    !t.is_empty() && t.len() <= 16_384 && t.bytes().all(|b| b > 0x20 && b < 0x7f)
}

fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Build the upgrade request (scheme `wss` or, for tests only, `ws`).
pub fn request(scheme: &str, host_port: &str, target: &str, token: &str) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, SshError> {
    if !TARGETS.contains(&target) || !valid_token(token) {
        return Err(SshError::Denied("invalid relay target or token".into()));
    }
    let mut req = format!("{scheme}://{host_port}/v1/ssh/{target}").into_client_request().map_err(|e| SshError::Ssh(e.to_string()))?;
    let h = req.headers_mut();
    h.insert("Authorization", HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| SshError::Denied("token".into()))?);
    h.insert("Sec-WebSocket-Protocol", HeaderValue::from_static(SUBPROTOCOL));
    Ok(req)
}

/// Bridge a WebSocket (binary frames) to a byte stream for russh.
#[doc(hidden)]
pub fn bridge<S>(ws: WebSocketStream<S>) -> tokio::io::DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let (mut sink, mut stream) = ws.split();
    let (mut rd, mut wr) = tokio::io::split(theirs);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sink.close().await;
    });
    tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Binary(b)) => {
                    if wr.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                // Text frames are not part of the protocol; ping/pong are handled by tungstenite.
                Ok(_) => {}
            }
        }
        let _ = wr.shutdown().await;
    });
    ours
}

pub struct RelayParams<'a> {
    /// Worker host, e.g. `nexus-gateway.<account>.workers.dev`.
    pub host: &'a str,
    pub relay_target: &'a str,
    pub user: &'a str,
    pub access_token: &'a str,
    /// The device being reached (for grants on the returned session).
    pub target: Target,
}

/// Run SSH over an established, protocol-checked relay WebSocket.
pub async fn connect_over<S>(ws: WebSocketStream<S>, p: &RelayParams<'_>, pins: Arc<Mutex<HostKeyStore>>) -> Result<Session, SshError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let outcome = Arc::new(Mutex::new(None));
    let presented = Arc::new(Mutex::new(None));
    let handler = Verifier { authority: relay_authority(p.host, p.relay_target), pins, outcome: outcome.clone(), presented: presented.clone() };
    let config = Arc::new(client::Config { inactivity_timeout: Some(Duration::from_secs(300)), ..Default::default() });
    let fut = client::connect_stream(config, bridge(ws), handler);
    let mut handle = match tokio::time::timeout(Duration::from_secs(20), fut).await {
        Err(_) => return Err(SshError::Timeout),
        Ok(Err(e)) => return Err(outcome.lock().unwrap().take().unwrap_or_else(|| SshError::Ssh(e.to_string()))),
        Ok(Ok(h)) => h,
    };
    let fingerprint = presented.lock().unwrap().clone().unwrap_or_default();
    // The gateway pre-authenticates relay sessions; it then logs in to the
    // target with its own key. No client key is used here.
    let auth = handle.authenticate_none(p.user).await?;
    if !auth.success() {
        return Err(SshError::AuthFailed);
    }
    Ok(Session { handle, target: p.target.clone(), fingerprint, server_catalog: p.relay_target == "debian-ro" })
}

/// Full relay connection: policy check, TCP, TLS (rustls + webpki roots, ring),
/// WebSocket upgrade with subprotocol check, then SSH.
pub async fn connect(p: RelayParams<'_>, pins: Arc<Mutex<HostKeyStore>>, engine: &PolicyEngine) -> Result<Session, SshError> {
    if !valid_host(p.host) {
        return Err(SshError::Denied("invalid relay host".into()));
    }
    let route = format!("/v1/ssh/{}", p.relay_target);
    let class = nexus_security::gateway::classify("GET", &route);
    if class != nexus_security::gateway::RouteClass::SshRelay {
        return Err(SshError::Denied("relay route not allowed".into()));
    }
    engine
        .authorize(&Operation::user(Target::Gateway, Capability::GatewayRead, format!("GET {route} (SSH relay)")))
        .map_err(|e| SshError::Denied(e.to_string()))?;
    let req = request("wss", p.host, p.relay_target, p.access_token)?;
    let tcp = tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect((p.host, 443))).await.map_err(|_| SshError::Timeout)?.map_err(|e| SshError::Ssh(e.to_string()))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SshError::Ssh(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(p.host.to_string()).map_err(|_| SshError::Denied("invalid relay host".into()))?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls)).connect(name, tcp).await.map_err(|e| SshError::Ssh(format!("TLS: {e}")))?;
    let (ws, resp) = tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::client_async(req, stream))
        .await
        .map_err(|_| SshError::Timeout)?
        .map_err(|e| match &e {
            tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 401 || r.status() == 403 => SshError::Denied("Cloudflare Access sign-in required or expired".into()),
            _ => SshError::Ssh(format!("relay upgrade failed: {e}")),
        })?;
    if resp.headers().get("Sec-WebSocket-Protocol").and_then(|v| v.to_str().ok()) != Some(SUBPROTOCOL) {
        return Err(SshError::Ssh("relay did not accept the nexus-ssh-v1 subprotocol".into()));
    }
    connect_over(ws, &p, pins).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_bearer_and_subprotocol_and_rejects_bad_input() {
        let r = request("wss", "nexus-gateway.example.workers.dev", "debian", "tok123").unwrap();
        assert_eq!(r.uri().to_string(), "wss://nexus-gateway.example.workers.dev/v1/ssh/debian");
        assert_eq!(r.headers()["Authorization"], "Bearer tok123");
        assert_eq!(r.headers()["Sec-WebSocket-Protocol"], SUBPROTOCOL);
        assert!(request("wss", "h", "root", "t").is_err());
        assert!(request("wss", "h", "debian", "bad token").is_err());
        assert!(request("wss", "h", "../x", "t").is_err());
        assert_eq!(relay_authority("Nexus-Gateway.x", "debian"), "relay:nexus-gateway.x/debian");
        assert!(!valid_host("evil.com/path"));
    }
}
