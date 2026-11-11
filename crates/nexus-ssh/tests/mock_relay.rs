//! Cloudflare relay path against a disposable local mock relay:
//! WebSocket server (checks Bearer + `nexus-ssh-v1`) → in-process SSH server
//! (pre-authenticated, like the Nexus gateway). Proves the relay session is
//! host-key pinned under its own authority and still Debian read-only.

use nexus_core::Device;
use nexus_security::audit::MemoryAudit;
use nexus_security::catalog::{CatalogCommand, ReadRoots};
use nexus_security::hostkeys::HostKeyStore;
use nexus_security::policy::{Capability, Operation, PolicyEngine, Target};
use nexus_ssh::relay::{self, RelayParams, SUBPROTOCOL};
use nexus_ssh::SshError;
use russh::keys::HashAlg;
use russh::server::{self, Auth, Msg, Session as SrvSession};
use russh::{Channel, ChannelId};
use std::sync::{Arc, Mutex};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};

const TOKEN: &str = "test-access-token";

mod common;
use common::fixture;

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

struct Gateway {
    log: Log,
}

impl server::Handler for Gateway {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.log.0.lock().unwrap().push(format!("auth_none:{user}"));
        Ok(Auth::Accept)
    }

    async fn channel_open_session(&mut self, _c: Channel<Msg>, reply: server::ChannelOpenHandle, _s: &mut SrvSession) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut SrvSession) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        self.log.0.lock().unwrap().push(format!("exec:{cmd}"));
        session.channel_success(channel)?;
        session.data(channel, b"nexus_metrics\t1\ncpu_count\t8\n".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

async fn start_relay(log: Log) -> u16 {
    let key = russh::keys::load_secret_key(fixture("server_ed25519"), None).unwrap();
    let config = Arc::new(server::Config { keys: vec![key], ..Default::default() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let cfg = config.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let check = |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
                    let auth_ok = req.headers().get("Authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"));
                    let proto_ok = req.headers().get("Sec-WebSocket-Protocol").and_then(|v| v.to_str().ok()) == Some(SUBPROTOCOL);
                    if !auth_ok || !proto_ok {
                        let mut e = ErrorResponse::new(Some("denied".into()));
                        *e.status_mut() = StatusCode::UNAUTHORIZED;
                        return Err(e);
                    }
                    resp.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(resp)
                };
                let Ok(ws) = tokio_tungstenite::accept_hdr_async(sock, check).await else {
                    log.0.lock().unwrap().push("upgrade-denied".into());
                    return;
                };
                let stream = relay::bridge(ws);
                if let Ok(s) = server::run_stream(cfg, stream, Gateway { log }).await {
                    let _ = s.await;
                }
            });
        }
    });
    port
}

fn debian() -> Device {
    Device::suggestions().into_iter().find(|d| d.role == Some(nexus_core::HostRole::Debian)).unwrap()
}

async fn open(port: u16, token: &str, d: &Device, pins: Arc<Mutex<HostKeyStore>>) -> Result<nexus_ssh::Session, SshError> {
    let alias = d.endpoints[0].relay_target.as_deref().unwrap();
    let req = relay::request("ws", &format!("127.0.0.1:{port}"), alias, token)?;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (ws, resp) = tokio_tungstenite::client_async(req, tcp).await.map_err(|e| SshError::Ssh(e.to_string()))?;
    assert_eq!(resp.headers()["Sec-WebSocket-Protocol"], SUBPROTOCOL);
    let p = RelayParams { host: &nexus_core::site::site().gateway_host, relay_target: alias, user: &d.username, access_token: token, target: Target::Host { key: d.id.to_string() } };
    relay::connect_over(ws, &p, pins).await
}

#[tokio::test]
async fn restricted_alias_classifies_debian_and_sends_only_structured_catalog() {
    let log = Log::default();
    let port = start_relay(log.clone()).await;
    let engine = PolicyEngine::new(Arc::new(MemoryAudit::default()));
    let mut d = debian();
    d.name = "Fixture".into();
    d.username = "fixture".into();
    d.role = None;
    d.endpoints[0].relay_target = Some("debian-ro".into());
    engine.register_device(&d);
    let target = Target::Host { key: d.id.to_string() };
    assert!(engine.is_debian(&target));
    let fp = russh::keys::load_secret_key(fixture("server_ed25519"), None).unwrap().public_key().fingerprint(HashAlg::Sha256).to_string();
    let pins = Arc::new(Mutex::new(HostKeyStore::default()));
    pins.lock().unwrap().confirm_first_use(&format!("relay:{}/debian-ro", nexus_core::site::site().gateway_host), &fp).unwrap();
    let session = open(port, TOKEN, &d, pins).await.unwrap();
    let read = engine.authorize(&Operation::user(target.clone(), Capability::Read, "read")).unwrap();
    assert!(matches!(session.sftp_read_only(&read).await, Err(SshError::Denied(_))));
    let grant = engine.authorize(&Operation::user(target, Capability::ExecuteCatalogCommand, "metrics")).unwrap();
    let output = session.run_catalog(&grant, &CatalogCommand::Metrics, &ReadRoots::debian_default()).await.unwrap();
    assert_eq!(output.exit, Some(0));
    session.close().await;
    let entries = log.0.lock().unwrap();
    let requests: Vec<_> = entries.iter().filter_map(|line| line.strip_prefix("exec:")).collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(nexus_security::ro::decode_request(Some(requests[0])).unwrap(), nexus_security::ro::Request::Catalog(CatalogCommand::Metrics));
}

#[tokio::test]
async fn relay_requires_token_pins_host_key_and_stays_read_only() {
    let log = Log::default();
    let port = start_relay(log.clone()).await;
    let audit = Arc::new(MemoryAudit::default());
    let engine = PolicyEngine::new(audit.clone());
    let d = debian();
    engine.register_device(&d);
    let target = Target::Host { key: d.id.to_string() };
    let pins = Arc::new(Mutex::new(HostKeyStore::default()));

    // Wrong token: the upgrade is refused before any SSH happens.
    assert!(open(port, "wrong-token", &d, pins.clone()).await.is_err());

    // First use under the relay authority: refused until confirmed.
    let fp = russh::keys::load_secret_key(fixture("server_ed25519"), None).unwrap().public_key().fingerprint(HashAlg::Sha256).to_string();
    match open(port, TOKEN, &d, pins.clone()).await {
        Err(SshError::UnknownHostKey { authority, fingerprint }) => {
            assert_eq!(authority, format!("relay:{}/debian", nexus_core::site::site().gateway_host));
            assert_eq!(fingerprint, fp);
        }
        other => panic!("expected UnknownHostKey, got {:?}", other.err()),
    }
    pins.lock().unwrap().confirm_first_use(&format!("relay:{}/debian", nexus_core::site::site().gateway_host), &fp).unwrap();
    let s = open(port, TOKEN, &d, pins.clone()).await.expect("relay session");

    // Catalog command works; everything else is refused locally.
    let g = engine.authorize(&Operation::user(target.clone(), Capability::ExecuteCatalogCommand, "metrics")).unwrap();
    let out = s.run_catalog(&g, &CatalogCommand::Metrics, &ReadRoots::debian_default()).await.unwrap();
    assert!(out.text().contains("cpu_count\t8"));
    assert!(engine.authorize(&Operation::user(target.clone(), Capability::ExecuteArbitraryCommand, "id")).is_err());
    assert!(matches!(s.exec_arbitrary(&g, "touch /tmp/x").await, Err(SshError::Denied(_))));
    s.close().await;

    let l = log.0.lock().unwrap().clone();
    let execs: Vec<&String> = l.iter().filter(|x| x.starts_with("exec:")).collect();
    assert_eq!(execs.len(), 1, "only the catalog command reached the relay: {l:?}");
    assert!(execs[0].starts_with("exec:LC_ALL=C timeout"));
    assert!(l.contains(&format!("auth_none:{}", nexus_core::site::site().debian_user)));
    assert!(l.contains(&"upgrade-denied".to_string()));
}
