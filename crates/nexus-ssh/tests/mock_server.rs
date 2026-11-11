//! Debian read-only acceptance tests against a disposable in-process SSH server.
//!
//! The mock server records every exec request and every SFTP/subsystem request
//! it receives. Tests prove that:
//! * first-use host keys are not trusted until confirmed; changed keys abort;
//! * Debian only ever receives fixed catalog commands;
//! * prohibited operations are refused *before* any bytes reach the server
//!   (the recorded command log does not grow), so nothing is partially applied;
//! * a renamed device entry that presents Debian's host key becomes Debian.

use nexus_core::Device;
use nexus_security::audit::MemoryAudit;
use nexus_security::catalog::{CatalogCommand, ReadRoots};
use nexus_security::hostkeys::HostKeyStore;
use nexus_security::policy::{Capability, Operation, PolicyEngine, Target};
use nexus_ssh::{ConnectParams, Session, SshError};
use russh::keys::HashAlg;
use russh::server::{self, Auth, Msg, Session as SrvSession};
use russh::{Channel, ChannelId};
use std::sync::{Arc, Mutex};

mod common;
use common::fixture;

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

struct Srv {
    log: Log,
}

impl server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _user: &str, _key: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
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
        let out = if cmd.contains("nexus_metrics") { "nexus_metrics\t1\ncpu_count\t4\ncpu_utilization\t12.5\n".to_string() } else { "ok\n".to_string() };
        session.data(channel, out.into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut SrvSession) -> Result<(), Self::Error> {
        self.log.0.lock().unwrap().push(format!("subsystem:{name}"));
        session.channel_failure(channel)?;
        Ok(())
    }
}

async fn start_server(log: Log) -> u16 {
    let key = russh::keys::load_secret_key(fixture("server_ed25519"), None).unwrap();
    let config = Arc::new(server::Config { keys: vec![key], ..Default::default() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let cfg = config.clone();
            let h = Srv { log: log.clone() };
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(cfg, sock, h).await {
                    let _ = s.await;
                }
            });
        }
    });
    port
}

fn server_fingerprint() -> String {
    let k = russh::keys::load_secret_key(fixture("server_ed25519"), None).unwrap();
    k.public_key().fingerprint(HashAlg::Sha256).to_string()
}

fn debian_device(port: u16) -> Device {
    let mut d = Device::suggestions().into_iter().find(|d| d.role == Some(nexus_core::HostRole::Debian)).unwrap();
    d.endpoints[0].host = "127.0.0.1".into();
    d.endpoints[0].port = port;
    d.endpoints[0].kind = nexus_core::EndpointKind::Lan;
    d.endpoints[0].relay_target = None;
    d
}

async fn connect(engine: &PolicyEngine, pins: Arc<Mutex<HostKeyStore>>, d: &Device) -> Result<Session, SshError> {
    let key = fixture("client_ed25519");
    let target = Target::Host { key: d.id.to_string() };
    let is_debian = engine.is_debian(&target);
    let e = &d.endpoints[0];
    let server_catalog = d.server_catalog;
    Session::connect(ConnectParams { host: &e.host, port: e.port, user: &d.username, key_path: &key, passphrase: None, target, is_debian, server_catalog }, pins, engine).await
}

#[tokio::test]
async fn server_catalog_devices_receive_structured_requests_only() {
    use nexus_security::ro::{decode_request, Request};
    let log = Log::default();
    let port = start_server(log.clone()).await;
    let engine = PolicyEngine::new(Arc::new(MemoryAudit::default()));
    let mut d = debian_device(port);
    d.server_catalog = true;
    engine.register_device(&d);
    let pins = Arc::new(Mutex::new(HostKeyStore::default()));
    pins.lock().unwrap().confirm_first_use(&d.endpoints[0].authority(), &server_fingerprint()).unwrap();
    let s = connect(&engine, pins, &d).await.unwrap();
    let target = Target::Host { key: d.id.to_string() };
    let read = engine.authorize(&Operation::user(target.clone(), Capability::Read, "read")).unwrap();
    assert!(matches!(s.sftp_read_only(&read).await, Err(SshError::Denied(_))));
    let g = engine.authorize(&Operation::user(target, Capability::ExecuteCatalogCommand, "ls")).unwrap();
    let cmd = CatalogCommand::ListDirectory { path: format!("/home/{}/projects", nexus_core::site::site().debian_user) };
    s.run_catalog(&g, &cmd, &ReadRoots::debian_default()).await.unwrap();
    s.close().await;
    let sent: Vec<String> = log.0.lock().unwrap().iter().filter_map(|l| l.strip_prefix("exec:").map(String::from)).collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(decode_request(Some(&sent[0])).unwrap(), Request::Catalog(cmd));
    assert!(!sent[0].contains(' ') || sent[0].matches(' ').count() == 1, "no shell text: {}", sent[0]);
}

#[tokio::test]
async fn host_key_first_use_then_pinned_then_changed() {
    let log = Log::default();
    let port = start_server(log.clone()).await;
    let engine = PolicyEngine::new(Arc::new(MemoryAudit::default()));
    let d = debian_device(port);
    engine.register_device(&d);
    let pins = Arc::new(Mutex::new(HostKeyStore::default()));
    // First use: refused, fingerprint surfaced, nothing executed.
    match connect(&engine, pins.clone(), &d).await {
        Err(SshError::UnknownHostKey { fingerprint, .. }) => assert_eq!(fingerprint, server_fingerprint()),
        other => panic!("expected UnknownHostKey, got {:?}", other.err()),
    }
    assert!(log.0.lock().unwrap().is_empty());
    // Confirm and connect.
    let authority = d.endpoints[0].authority();
    pins.lock().unwrap().confirm_first_use(&authority, &server_fingerprint()).unwrap();
    let s = connect(&engine, pins.clone(), &d).await.expect("connect after pin");
    s.close().await;
    // Changed key: simulate by pinning a different fingerprint.
    let mut wrong = HostKeyStore::default();
    wrong.confirm_first_use(&authority, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let r = connect(&engine, Arc::new(Mutex::new(wrong)), &d).await;
    assert!(matches!(r, Err(SshError::HostKeyChanged { .. })));
}

#[tokio::test]
async fn debian_receives_only_catalog_commands_and_denials_send_nothing() {
    let log = Log::default();
    let port = start_server(log.clone()).await;
    let audit = Arc::new(MemoryAudit::default());
    let engine = PolicyEngine::new(audit.clone());
    let d = debian_device(port);
    engine.register_device(&d);
    let target = Target::Host { key: d.id.to_string() };
    let pins = Arc::new(Mutex::new(HostKeyStore::default()));
    pins.lock().unwrap().confirm_first_use(&d.endpoints[0].authority(), &server_fingerprint()).unwrap();
    let s = connect(&engine, pins, &d).await.unwrap();
    let roots = ReadRoots::debian_default();

    // Allowed: catalog metrics.
    let g = engine.authorize(&Operation::user(target.clone(), Capability::ExecuteCatalogCommand, "metrics")).unwrap();
    let out = s.run_catalog(&g, &CatalogCommand::Metrics, &roots).await.unwrap();
    let snap = nexus_telemetry::parse(&out.text(), std::time::SystemTime::now()).unwrap();
    assert_eq!(snap.cpu_count, Some(4));
    let before = log.0.lock().unwrap().len();
    assert_eq!(before, 1);

    // Every prohibited capability is denied for user and agent; no grant exists.
    for cap in [Capability::ExecuteArbitraryCommand, Capability::InteractiveShell, Capability::WriteFile, Capability::DeleteFile, Capability::ServiceControl, Capability::GitWrite, Capability::DebugAttach, Capability::GatewayMutation, Capability::ModelControl] {
        assert!(engine.authorize(&Operation::user(target.clone(), cap, "systemctl restart nexus-gateway")).is_err(), "{cap:?}");
        assert!(engine.authorize(&Operation::agent(target.clone(), cap, "rm -rf ~", "s1", "codex")).is_err(), "{cap:?}");
    }

    // A grant for another target cannot be replayed against Debian.
    let other = Target::LocalWorkspace { root: "C:/x".into() };
    let foreign = engine.authorize(&Operation::user(other, Capability::ExecuteArbitraryCommand, "touch /tmp/x")).unwrap();
    assert!(matches!(s.exec_arbitrary(&foreign, "touch /tmp/x").await, Err(SshError::Denied(_))));
    // A catalog grant cannot be used for arbitrary exec.
    let g2 = engine.authorize(&Operation::user(target.clone(), Capability::ExecuteCatalogCommand, "x")).unwrap();
    assert!(matches!(s.exec_arbitrary(&g2, "touch /tmp/x").await, Err(SshError::Denied(_))));
    // Injection through catalog parameters is refused locally.
    assert!(s.run_catalog(&g2, &CatalogCommand::ServiceLogs { unit: "x; rm -rf /".into(), lines: 10 }, &roots).await.is_err());
    assert!(s.run_catalog(&g2, &CatalogCommand::ReadFile { path: "/etc/shadow".into(), max_bytes: 10 }, &roots).await.is_err());
    // SFTP needs a Read grant for this target; a catalog grant is not enough.
    assert!(matches!(s.sftp_read_only(&g2).await, Err(SshError::Denied(_))));

    // Nothing reached the server for any denied operation.
    let after = log.0.lock().unwrap().clone();
    assert_eq!(after.len(), before, "denied operations must not reach the server: {after:?}");
    assert!(after[0].starts_with("exec:LC_ALL=C timeout"));
    // Denials were audited.
    assert!(audit.events().iter().filter(|e| matches!(e.outcome, nexus_security::audit::Outcome::Denied(_))).count() >= 18);
    s.close().await;
}

#[tokio::test]
async fn alias_presenting_debian_key_becomes_debian() {
    let log = Log::default();
    let port = start_server(log.clone()).await;
    let engine = PolicyEngine::new(Arc::new(MemoryAudit::default()));
    let pins = Arc::new(Mutex::new(HostKeyStore::default()));
    // Real Debian entry connects once, recording its key.
    let d = debian_device(port);
    engine.register_device(&d);
    pins.lock().unwrap().confirm_first_use(&d.endpoints[0].authority(), &server_fingerprint()).unwrap();
    connect(&engine, pins.clone(), &d).await.unwrap().close().await;
    // Innocuous alias, different authority (localhost name), same machine/key.
    let mut alias = Device::suggestions().into_iter().find(|d| d.role == Some(nexus_core::HostRole::Nixos)).unwrap();
    alias.name = "Lab box".into();
    alias.username = "admin".into();
    alias.role = Some(nexus_core::HostRole::Other);
    alias.endpoints[0].host = "localhost".into();
    alias.endpoints[0].port = port;
    alias.endpoints[0].kind = nexus_core::EndpointKind::Lan;
    alias.endpoints[0].relay_target = None;
    engine.register_device(&alias);
    let t = Target::Host { key: alias.id.to_string() };
    assert!(!engine.is_debian(&t));
    pins.lock().unwrap().confirm_first_use(&alias.endpoints[0].authority(), &server_fingerprint()).unwrap();
    connect(&engine, pins, &alias).await.unwrap().close().await;
    assert!(engine.is_debian(&t), "alias with Debian's host key must be treated as Debian");
    // Even if the user had granted writes to the alias before, Debian policy now applies.
    assert!(engine.authorize(&Operation::user(t, Capability::WriteFile, "x")).is_err());
}
