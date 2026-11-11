//! Live read-only relay check:
//! `cargo run -p nexus-ssh --example relay_metrics -- <audit-file>`
//! Uses the saved Cloudflare Access session (DPAPI) and the app's pinned relay
//! host keys; refuses to trust an unknown key. Runs only the Metrics catalog
//! command against the Debian relay target.

use nexus_core::Device;
use nexus_security::audit::{AuditSink, FileAudit};
use nexus_security::catalog::{CatalogCommand, ReadRoots};
use nexus_security::hostkeys::HostKeyStore;
use nexus_security::policy::{Capability, Operation, PolicyEngine, Target};
use nexus_ssh::relay::{self, RelayParams};
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    let audit_path = std::path::PathBuf::from(std::env::args().nth(1).expect("audit file path"));
    let audit = Arc::new(FileAudit::open(audit_path).expect("audit"));
    let engine = PolicyEngine::new(audit.clone());
    let appdata = nexus_core::platform::config_dir();
    let pins: HostKeyStore = serde_json::from_str(&std::fs::read_to_string(appdata.join("known_hosts.json")).expect("pins")).expect("pins json");
    let mut session = nexus_access::store::load(&nexus_access::store::default_path()).expect("no saved Access session; sign in in the app first");
    if !session.is_fresh(120) {
        let meta = nexus_access::discover().expect("discovery");
        session = nexus_access::refresh(&meta, &session).expect("refresh");
        nexus_access::store::save(&nexus_access::store::default_path(), &session).expect("save refreshed session");
        println!("refreshed Access token");
    }
    let d = Device::suggestions().into_iter().find(|d| d.role == Some(nexus_core::HostRole::Debian)).unwrap();
    engine.register_device(&d);
    let target = Target::Host { key: d.id.to_string() };
    println!("is_debian={}", engine.is_debian(&target));
    let host = &d.endpoints[0].host;
    let p = RelayParams { host, relay_target: "debian", user: &d.username, access_token: &session.access_token, target: target.clone() };
    let start = std::time::Instant::now();
    let s = match relay::connect(p, Arc::new(Mutex::new(pins)), &engine).await {
        Ok(s) => s,
        Err(e) => {
            println!("CONNECT FAILED: {e}");
            return;
        }
    };
    println!("connected in {:.2}s, relay host key {}", start.elapsed().as_secs_f32(), s.fingerprint);
    let g = engine.authorize(&Operation::user(target.clone(), Capability::ExecuteCatalogCommand, "host metrics")).unwrap();
    match s.run_catalog(&g, &CatalogCommand::Metrics, &ReadRoots::debian_default()).await {
        Ok(out) => match nexus_telemetry::parse(&out.text(), std::time::SystemTime::now()) {
            Ok(m) => println!(
                "METRICS exit={:?} cpu={:?}% cores={:?} mem_used={:?}% disk_used={:?}% uptime_h={:?} load={:?}",
                out.exit,
                m.cpu_percent,
                m.cpu_count,
                m.memory_used_percent().map(|v| (v * 10.0).round() / 10.0),
                m.disk_used_percent().map(|v| (v * 10.0).round() / 10.0),
                m.uptime_secs.map(|u| (u / 3600.0).round()),
                m.load.map(|l| (l.one, l.five, l.fifteen))
            ),
            Err(e) => println!("parse failed: {e}; stdout={:?} stderr={:?}", out.text().chars().take(300).collect::<String>(), String::from_utf8_lossy(&out.stderr)),
        },
        Err(e) => println!("METRICS FAILED: {e}"),
    }
    // Confirm the write paths are still refused on this live session.
    println!("arbitrary exec grant refused: {}", engine.authorize(&Operation::user(target.clone(), Capability::ExecuteArbitraryCommand, "id")).is_err());
    s.close().await;
    println!("audit events: {}", audit.recent(50).len());
}
