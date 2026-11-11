//! Dashboard, Devices, Infrastructure and Settings screens, plus the SSH worker.
//!
//! Every remote action obtains a grant on the UI thread (audited), then runs a
//! catalog command on the shared tokio runtime. Debian only ever receives
//! read-only catalog commands; there is no other remote execution path here.

use crate::app::{NexusApp, Toast};
use crate::settings::{data_dir, local_dir, secrets, Settings};
use egui::{vec2, Align, CornerRadius, Layout, RichText, ScrollArea, Ui};
use nexus_core::{Device, DeviceDocument, Endpoint, EndpointKind, HostRole};
use nexus_providers::Billing;
use nexus_security::catalog::{CatalogCommand, ReadRoots};
use nexus_security::hostkeys::HostKeyStore;
use nexus_security::policy::{Capability, HostPolicy, Operation, PolicyEngine, Target};
use nexus_ssh::{ConnectParams, Session, SshError};
use nexus_telemetry::{format_bytes, History, Sample, Snapshot};
use nexus_ui::{card, icon, icons, secondary, section_title, sparkline, white_a, Tokens};
use nexus_workspaces::shadow::ShadowWorkspace;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfraTab {
    Overview,
    Services,
    Processes,
    Network,
    Files,
    Console,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HostStatus {
    Idle,
    Connecting,
    Online,
    Error(String),
}

#[derive(Default)]
pub struct HostState {
    pub status: Option<HostStatus>,
    pub history: History,
    pub outputs: HashMap<String, String>,
    pub fingerprint: Option<String>,
    pub last_metrics: Option<Instant>,
    pub busy: usize,
    /// Alerts shown for the latest sample (to toast only on change).
    pub alerts: Vec<String>,
}

/// How a device is reached.
enum Route {
    Direct { endpoint: Endpoint, key_path: std::path::PathBuf, passphrase: Option<String> },
    /// Through the Nexus Cloudflare Worker relay (`/v1/ssh/<target>`).
    Relay { host: String, target: String },
}

impl Route {
    /// Key for telemetry history (rates are only computed within one route).
    fn authority(&self) -> String {
        match self {
            Route::Direct { endpoint, .. } => endpoint.authority(),
            Route::Relay { host, target } => nexus_ssh::relay::relay_authority(host, target),
        }
    }
}

enum Job {
    Catalog(CatalogCommand),
    Shadow { root: String },
}

enum JobResult {
    Output { device: String, label: String, text: String },
    Metrics { device: String, authority: String, snapshot: Snapshot },
    Failed { device: String, label: String, error: String },
    HostKey { device: String, authority: String, fingerprint: String },
    Online { device: String, fingerprint: String },
    ShadowReady { path: std::path::PathBuf, files: usize, skipped: usize },
}

pub struct InfraState {
    pub hosts: HashMap<String, HostState>,
    pub selected: usize,
    pub tab: InfraTab,
    pub unit: String,
    pub path: String,
    pub console_cmd: usize,
    pub console_arg: String,
    pub pending_hostkey: Option<(String, String, String, bool)>,
    pub passphrase_prompt: Option<String>,
    pub minecraft_unit: String,
    pub minecraft_confirm: bool,
    pub editing: Option<Device>,
    /// Typed confirmation while unlocking Debian writes.
    pub unlock_prompt: Option<String>,
    /// Result of the last local network probe (shared with the probe thread).
    pub probe: Arc<Mutex<Option<String>>>,
    /// Typed confirmation for `nixos-rebuild switch`.
    pub nixos_switch_prompt: Option<String>,
    pub editing_switch: Option<Device>,
    pins: Arc<Mutex<HostKeyStore>>,
    sessions: Arc<tokio::sync::Mutex<HashMap<String, Arc<Session>>>>,
    tx: Sender<JobResult>,
    rx: Receiver<JobResult>,
    wake: Arc<dyn Fn() + Send + Sync>,
    passphrase: Option<String>,
    open_after: Option<std::path::PathBuf>,
    pub access: crate::access::AccessHandle,
}

fn pins_path() -> std::path::PathBuf {
    data_dir().join("known_hosts.json")
}

impl InfraState {
    pub fn new(_s: &Settings, wake: Arc<dyn Fn() + Send + Sync>, access: crate::access::AccessHandle) -> Self {
        let pins: HostKeyStore = std::fs::read_to_string(pins_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let (tx, rx) = channel();
        Self {
            hosts: HashMap::new(),
            selected: 0,
            tab: InfraTab::Overview,
            unit: String::new(),
            path: format!("/home/{}", nexus_core::site::site().debian_user),
            console_cmd: 0,
            console_arg: String::new(),
            pending_hostkey: None,
            unlock_prompt: None,
            probe: Arc::default(),
            nixos_switch_prompt: None,
            editing_switch: None,
            passphrase_prompt: None,
            minecraft_unit: "minecraft".into(),
            minecraft_confirm: false,
            editing: None,
            pins: Arc::new(Mutex::new(pins)),
            sessions: Arc::default(),
            tx,
            rx,
            wake,
            passphrase: None,
            open_after: None,
            access,
        }
    }

    fn save_pins(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&*self.pins.lock().unwrap()) {
            let _ = nexus_workspaces::write_atomic(&pins_path(), json.as_bytes());
        }
    }

    pub fn host(&mut self, id: &str) -> &mut HostState {
        self.hosts.entry(id.to_string()).or_default()
    }

    /// Queue a job for a device. The grant is obtained here (UI thread).
    fn run(&mut self, rt: &tokio::runtime::Runtime, engine: &PolicyEngine, s: &Settings, device: &Device, job: Job) -> Result<(), String> {
        let target = Target::Host { key: device.id.to_string() };
        let is_debian = engine.is_debian(&target);
        let label = match &job {
            Job::Catalog(c) => c.label(),
            Job::Shadow { root } => format!("shadow import {root}"),
        };
        let grant = engine.authorize(&Operation::user(target.clone(), Capability::ExecuteCatalogCommand, &label)).map_err(|e| e.to_string())?;
        let ordered: Vec<Endpoint> = device.ordered_endpoints().into_iter().cloned().collect();
        let direct = ordered.iter().find(|e| e.kind != EndpointKind::Cloudflare).cloned();
        let relay = ordered
            .iter()
            .find(|e| e.kind == EndpointKind::Cloudflare && e.relay_target.as_deref().is_some_and(|t| nexus_ssh::relay::TARGETS.contains(&t)))
            .cloned();
        let route = match (direct, relay) {
            (Some(endpoint), _) => {
                // Per-device key (with its own optional passphrase), else the global identity.
                let (key_path, passphrase) = match device.key_path.as_deref().filter(|p| !p.trim().is_empty()) {
                    Some(p) => (std::path::PathBuf::from(p), secrets::get(&format!("ssh-passphrase:{}", device.id))),
                    None => {
                        if s.ssh.has_passphrase && self.passphrase.is_none() {
                            self.passphrase = secrets::get("ssh-passphrase");
                        }
                        (std::path::PathBuf::from(&s.ssh.key_path), self.passphrase.clone())
                    }
                };
                if !key_path.is_file() {
                    return Err(format!("SSH key not found at {}. Set it in the device editor or Devices → SSH identity.", key_path.display()));
                }
                Route::Direct { endpoint, key_path, passphrase }
            }
            (None, Some(endpoint)) => {
                if !self.access.signed_in() {
                    return Err("This device is reached through the Cloudflare relay. Sign in to Cloudflare Access in Settings first.".into());
                }
                Route::Relay { host: endpoint.host.clone(), target: endpoint.relay_target.clone().unwrap_or_default() }
            }
            (None, None) => return Err("This device has no usable endpoint. Add a LAN/Tailscale endpoint or a Cloudflare relay endpoint in Devices.".into()),
        };
        let access = self.access.clone();
        let server_catalog = device.server_catalog;
        let user = device.username.clone();
        let dev = device.id.to_string();
        let roots = ReadRoots(if is_debian { ReadRoots::debian_default().0 } else { vec![format!("/home/{user}"), "/var/log".into(), "/srv".into(), "/opt".into(), "/etc/nixos".into()] });
        let tx = self.tx.clone();
        let wake = self.wake.clone();
        let pins = self.pins.clone();
        let sessions = self.sessions.clone();
        let engine = engine.clone();
        self.host(&dev).busy += 1;
        if self.host(&dev).status.is_none() || matches!(self.host(&dev).status, Some(HostStatus::Error(_)) | Some(HostStatus::Idle)) {
            self.host(&dev).status = Some(HostStatus::Connecting);
        }
        rt.spawn(async move {
            let send = |r: JobResult| {
                let _ = tx.send(r);
                wake();
            };
            let session = {
                let mut map = sessions.lock().await;
                match map.get(&dev) {
                    Some(s) => s.clone(),
                    None => {
                        let connected = match &route {
                            Route::Direct { endpoint, key_path, passphrase } => {
                                let p = ConnectParams { host: &endpoint.host, port: endpoint.port, user: &user, key_path, passphrase: passphrase.as_deref(), target: target.clone(), is_debian, server_catalog };
                                Session::connect(p, pins.clone(), &engine).await
                            }
                            Route::Relay { host, target: relay_target } => {
                                let token = match tokio::task::spawn_blocking(move || access.fresh_token()).await {
                                    Ok(Ok(t)) => t,
                                    Ok(Err(e)) => {
                                        send(JobResult::Failed { device: dev.clone(), label, error: e });
                                        return;
                                    }
                                    Err(e) => {
                                        send(JobResult::Failed { device: dev.clone(), label, error: e.to_string() });
                                        return;
                                    }
                                };
                                let p = nexus_ssh::relay::RelayParams { host, relay_target, user: &user, access_token: &token, target: target.clone() };
                                nexus_ssh::relay::connect(p, pins.clone(), &engine).await
                            }
                        };
                        match connected {
                            Ok(s) => {
                                let s = Arc::new(s);
                                send(JobResult::Online { device: dev.clone(), fingerprint: s.fingerprint.clone() });
                                map.insert(dev.clone(), s.clone());
                                s
                            }
                            Err(SshError::UnknownHostKey { authority, fingerprint }) => {
                                send(JobResult::HostKey { device: dev.clone(), authority, fingerprint });
                                return;
                            }
                            Err(e) => {
                                send(JobResult::Failed { device: dev.clone(), label, error: e.to_string() });
                                return;
                            }
                        }
                    }
                }
            };
            let authority = route.authority();
            match job {
                Job::Catalog(cmd) => match session.run_catalog(&grant, &cmd, &roots).await {
                    Ok(out) => {
                        let text = out.text();
                        if cmd == CatalogCommand::Metrics {
                            match nexus_telemetry::parse(&text, SystemTime::now()) {
                                Ok(snapshot) => send(JobResult::Metrics { device: dev, authority, snapshot }),
                                Err(e) => send(JobResult::Failed { device: dev, label, error: e.to_string() }),
                            }
                        } else {
                            let mut t = text;
                            if !out.ok() {
                                t.push_str(&format!("\n[exit {}] {}", out.exit_label(), String::from_utf8_lossy(&out.stderr)));
                            }
                            send(JobResult::Output { device: dev, label, text: t });
                        }
                    }
                    Err(e) => {
                        sessions.lock().await.remove(&dev);
                        send(JobResult::Failed { device: dev, label, error: e.to_string() });
                    }
                },
                Job::Shadow { root } => {
                    let r = shadow_import(&session, &grant, &roots, &dev, &root).await;
                    match r {
                        Ok((path, files, skipped)) => send(JobResult::ShadowReady { path, files, skipped }),
                        Err(e) => send(JobResult::Failed { device: dev, label, error: e }),
                    }
                }
            }
        });
        Ok(())
    }

    pub fn poll(&mut self, _engine: &PolicyEngine, _s: &mut Settings, toasts: &mut Vec<Toast>) {
        while let Ok(r) = self.rx.try_recv() {
            match r {
                JobResult::Online { device, fingerprint } => {
                    let h = self.host(&device);
                    h.status = Some(HostStatus::Online);
                    h.fingerprint = Some(fingerprint);
                }
                JobResult::Metrics { device, authority, snapshot } => {
                    let h = self.host(&device);
                    h.busy = h.busy.saturating_sub(1);
                    h.status = Some(HostStatus::Online);
                    let alerts = snapshot.alerts();
                    h.history.push(Sample { authority, snapshot });
                    h.last_metrics = Some(Instant::now());
                    if !alerts.is_empty() && alerts != h.alerts {
                        toasts.push(Toast { text: format!("Low resources on {}: {}", _s.devices.iter().find(|d| d.id.to_string() == device).map(|d| d.name.as_str()).unwrap_or("device"), alerts.join(", ")), color: _s.tokens.warning(), at: Instant::now() });
                    }
                    h.alerts = alerts;
                }
                JobResult::Output { device, label, text } => {
                    let h = self.host(&device);
                    h.busy = h.busy.saturating_sub(1);
                    h.outputs.insert(label, text);
                }
                JobResult::Failed { device, label, error } => {
                    let h = self.host(&device);
                    h.busy = h.busy.saturating_sub(1);
                    h.status = Some(HostStatus::Error(error.clone()));
                    toasts.push(Toast { text: format!("{label}: {error}"), color: nexus_ui::hex(0xFF93A2), at: Instant::now() });
                }
                JobResult::HostKey { device, authority, fingerprint } => {
                    let h = self.host(&device);
                    h.busy = h.busy.saturating_sub(1);
                    h.status = Some(HostStatus::Idle);
                    self.pending_hostkey = Some((device, authority, fingerprint, false));
                }
                JobResult::ShadowReady { path, files, skipped } => {
                    toasts.push(Toast { text: format!("Shadow workspace ready: {files} files copied ({skipped} skipped). Opening…"), color: nexus_ui::hex(0x7CE8CA), at: Instant::now() });
                    self.open_after = Some(path);
                }
            }
        }
    }
}

impl InfraState {
    /// Forget cached relay connections (after signing out of Access).
    pub fn drop_relay_sessions(&mut self, rt: &tokio::runtime::Runtime) {
        let sessions = self.sessions.clone();
        rt.spawn(async move {
            for (_, s) in sessions.lock().await.drain() {
                s.close().await;
            }
        });
        for h in self.hosts.values_mut() {
            h.status = Some(HostStatus::Idle);
        }
    }

    /// A shadow workspace that finished importing and should be opened.
    pub fn take_open(&mut self) -> Option<std::path::PathBuf> {
        self.open_after.take()
    }
}

async fn shadow_import(session: &Session, grant: &nexus_security::Grant, roots: &ReadRoots, dev: &str, root: &str) -> Result<(std::path::PathBuf, usize, usize), String> {
    let list = session.run_catalog(grant, &CatalogCommand::FindFiles { root: root.into(), max_depth: 8 }, roots).await.map_err(|e| e.to_string())?;
    if !list.ok() {
        return Err(format!("listing failed: {}", String::from_utf8_lossy(&list.stderr)));
    }
    let dir = local_dir().join("shadows").join(format!("{}-{}", &dev[..8.min(dev.len())], &nexus_workspaces::sha256_hex(root.as_bytes())[..10]));
    let label = format!("host {}", &dev[..8.min(dev.len())]);
    let mut shadow = if dir.join(".nexus-shadow.json").exists() { ShadowWorkspace::load(&dir).map_err(|e| e.to_string())? } else { ShadowWorkspace::create(&dir, dev, &label, root).map_err(|e| e.to_string())? };
    let mut files = 0;
    let mut skipped = 0;
    for line in list.text().lines().take(3000) {
        let mut parts = line.split('\t');
        let (Some(rel), Some(size)) = (parts.next(), parts.next()) else { continue };
        let size: u64 = size.parse().unwrap_or(u64::MAX);
        if size > 1024 * 1024 || nexus_security::sensitive::is_sensitive_path(rel) || rel.split('/').any(|s| s == ".." || s.is_empty()) {
            skipped += 1;
            continue;
        }
        let full = format!("{}/{}", root.trim_end_matches('/'), rel);
        match session.run_catalog(grant, &CatalogCommand::ReadFile { path: full, max_bytes: 1024 * 1024 }, roots).await {
            Ok(out) if out.ok() => {
                if shadow.import(rel, &out.stdout).is_ok() {
                    files += 1;
                } else {
                    skipped += 1;
                }
            }
            _ => skipped += 1,
        }
    }
    Ok((dir, files, skipped))
}

fn devices_with_role(s: &Settings, engine: &PolicyEngine) -> Vec<(Device, bool)> {
    s.devices.iter().map(|d| (d.clone(), engine.is_debian(&Target::Host { key: d.id.to_string() }))).collect()
}

fn screen_frame(ui: &mut Ui, title: &str, subtitle: &str, t: &Tokens, add: impl FnOnce(&mut Ui)) {
    let rect = ui.max_rect().shrink2(vec2(12.0, 12.0));
    let mut ui = ui.new_child(egui::UiBuilder::new().max_rect(rect));
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(title).text_style(egui::TextStyle::Heading));
            ui.label(secondary(t, subtitle));
        });
    });
    ui.add_space(10.0);
    ScrollArea::vertical().auto_shrink([false, false]).show(&mut ui, add);
}

// ===================================================================== Dashboard

pub fn dashboard(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    if let Some(p) = app.infra.take_open() {
        app.open_workspace(p);
        return;
    }
    let devs = devices_with_role(&app.s, &app.engine);
    let online = devs.iter().filter(|(d, _)| app.infra.hosts.get(&d.id.to_string()).is_some_and(|h| h.status == Some(HostStatus::Online))).count();
    // Periodic metrics for connected hosts.
    let interval = app.s.telemetry_interval_secs.max(5);
    for (d, _) in &devs {
        let id = d.id.to_string();
        let due = app.infra.hosts.get(&id).is_some_and(|h| h.status == Some(HostStatus::Online) && h.busy == 0 && h.last_metrics.is_none_or(|l| l.elapsed().as_secs() >= interval));
        if due {
            let _ = app.infra.run(&app.rt, &app.engine, &app.s, d, Job::Catalog(CatalogCommand::Metrics));
        }
    }
    ui.ctx().request_repaint_after(std::time::Duration::from_secs(interval));
    screen_frame(ui, "Overview", &format!("{online} of {} devices online", devs.len()), &t, |ui| {
        let mut tiles = Tiles::new(ui, 300.0, 178.0);
        for (d, debian) in &devs {
            let id = d.id.to_string();
            let mut connect = false;
            tiles.tile(ui, &t, |ui| {
                let h = app.infra.hosts.get(&id);
                ui.horizontal(|ui| {
                    let col = match h.and_then(|h| h.status.clone()) {
                        Some(HostStatus::Online) => t.success(),
                        Some(HostStatus::Connecting) => t.accent(),
                        Some(HostStatus::Error(_)) => t.error(),
                        _ => t.text2(),
                    };
                    nexus_ui::dot(ui, col);
                    section_title(ui, &t, &d.name);
                    if *debian {
                        nexus_ui::pill(ui, "read-only", t.warning());
                    }
                });
                ui.add_space(4.0);
                match h.and_then(|h| h.history.latest()) {
                    Some(s) => {
                        ui.horizontal(|ui| {
                            metric(ui, &t, "CPU", s.cpu_percent.map(|v| format!("{v:.0}%")));
                            metric(ui, &t, "Memory", s.memory_used_percent().map(|v| format!("{v:.0}%")));
                            metric(ui, &t, "Disk", s.disk_used_percent().map(|v| format!("{v:.0}%")));
                        });
                        let series = h.unwrap().history.series(|s| s.cpu_percent);
                        sparkline(ui, &series, 100.0, t.accent(), vec2(ui.available_width(), 34.0));
                        if let Some(l) = &s.load {
                            line(ui, &t, format!("load {:.2} {:.2} {:.2} · up {}", l.one, l.five, l.fifteen, s.uptime_secs.map(fmt_uptime).unwrap_or_default()));
                        }
                    }
                    None => {
                        let msg = match h.and_then(|h| h.status.clone()) {
                            Some(HostStatus::Error(e)) => e,
                            Some(HostStatus::Connecting) => "Connecting…".into(),
                            _ => "Not connected. Telemetry uses read-only /proc reads.".into(),
                        };
                        ui.add(egui::Label::new(secondary(&t, msg)).wrap());
                        ui.add_space(6.0);
                        if ui.button("Connect").clicked() {
                            connect = true;
                        }
                    }
                }
            });
            if connect {
                let r = app.infra.run(&app.rt, &app.engine, &app.s, d, Job::Catalog(CatalogCommand::Metrics)).map(|_| String::new());
                app.report(r);
            }
        }
        // AI providers
        tiles.tile(ui, &t, |ui| {
            ui.horizontal(|ui| {
                ui.label(icon(icons::SPARKLE, 15.0).color(t.purple()));
                section_title(ui, &t, "AI providers");
            });
            ui.add_space(4.0);
            for p in app.ai.providers.iter().take(4) {
                ui.horizontal(|ui| {
                    nexus_ui::dot(ui, if p.status.is_connected() { t.success() } else { t.text2() });
                    ui.label(RichText::new(p.provider.name()).size(13.0));
                    let status = if p.checking { "verifying…".to_string() } else { short_status(&p.status) };
                    ui.add(egui::Label::new(secondary(&t, status)).truncate()).on_hover_text(p.status.label());
                });
            }
            if app.ai.providers.len() > 4 {
                line(ui, &t, format!("+{} more in Settings", app.ai.providers.len() - 4));
            }
            ui.add_space(4.0);
            if ui.small_button("Re-verify").clicked() {
                app.ai.verify_all();
            }
        });
        // PS5
        tiles.tile(ui, &t, |ui| {
            ui.horizontal(|ui| {
                ui.label(icon(icons::GAME, 15.0).color(t.accent()));
                section_title(ui, &t, "PS5LM Plus");
            });
            ui.add_space(4.0);
            match app.ai.providers.iter().find(|p| p.key == "ps5lm") {
                Some(p) => {
                    line(ui, &t, short_status(&p.status));
                    if let nexus_providers::Connection::Connected { models, .. } = &p.status {
                        for m in models.iter().take(3) {
                            ui.add(egui::Label::new(RichText::new(m).monospace().size(12.0)).truncate());
                        }
                    }
                    ui.add(egui::Label::new(secondary(&t, "Model load/unload is unavailable: it goes through the read-only Debian gateway.")).wrap());
                }
                None => {
                    ui.add(egui::Label::new(secondary(&t, "Set the PS5LM Plus LAN URL in Settings to check health and list models.")).wrap());
                }
            }
        });
        // Security
        tiles.tile(ui, &t, |ui| {
            ui.horizontal(|ui| {
                ui.label(icon(icons::SHIELD, 15.0).color(t.success()));
                section_title(ui, &t, "Security");
            });
            ui.add_space(4.0);
            let ev = app.audit.recent(1000);
            let denied = ev.iter().filter(|e| matches!(e.outcome, nexus_security::audit::Outcome::Denied(_))).count();
            line(ui, &t, "Debian: read-only, enforced in the Rust backend.".into());
            if let Some(problem) = app.audit.health() {
                ui.add(egui::Label::new(RichText::new(problem).small().color(t.error())).wrap());
            }
            line(ui, &t, format!("{} recent decisions · {denied} denied", ev.len()));
            ui.add_space(6.0);
            if ui.small_button("Open audit log").clicked() {
                app.show_audit = true;
            }
        });
        tiles.finish(ui);
    });
}

/// Uniform tile layout: equal-width columns that fill the row, fixed height,
/// content clipped to the tile so long text can never resize it.
struct Tiles {
    origin: egui::Pos2,
    cols: usize,
    w: f32,
    h: f32,
    gap: f32,
    n: usize,
}

impl Tiles {
    fn new(ui: &Ui, min_w: f32, h: f32) -> Self {
        let gap = 12.0;
        let avail = ui.available_width() - 4.0;
        let cols = (((avail + gap) / (min_w + gap)).floor() as usize).max(1);
        let w = (avail - gap * (cols as f32 - 1.0)) / cols as f32;
        Self { origin: ui.cursor().min, cols, w, h, gap, n: 0 }
    }

    fn tile(&mut self, ui: &mut Ui, t: &Tokens, add: impl FnOnce(&mut Ui)) {
        let (c, r) = (self.n % self.cols, self.n / self.cols);
        self.n += 1;
        let rect = egui::Rect::from_min_size(self.origin + vec2(c as f32 * (self.w + self.gap), r as f32 * (self.h + self.gap)), vec2(self.w, self.h));
        let slot = ui.painter().add(egui::Shape::Noop);
        nexus_ui::paint_glass_under(ui, slot, rect, t);
        let inner = rect.shrink2(vec2(16.0, 14.0));
        let mut child = ui.new_child(egui::UiBuilder::new().max_rect(inner).layout(Layout::top_down(Align::Min)));
        child.set_clip_rect(inner.expand(2.0).intersect(ui.clip_rect()));
        child.set_width(inner.width());
        add(&mut child);
    }

    fn finish(self, ui: &mut Ui) {
        let rows = self.n.div_ceil(self.cols);
        let size = vec2(self.cols as f32 * self.w + (self.cols as f32 - 1.0) * self.gap, rows as f32 * self.h + rows.saturating_sub(1) as f32 * self.gap);
        ui.allocate_rect(egui::Rect::from_min_size(self.origin, size), egui::Sense::hover());
    }
}

/// One truncated secondary-text line (full text on hover).
fn line(ui: &mut Ui, t: &Tokens, text: String) {
    ui.add(egui::Label::new(secondary(t, text.clone())).truncate()).on_hover_text(text);
}

/// Compact provider status, e.g. "Connected · ChatGPT plus".
pub fn short_status(c: &nexus_providers::Connection) -> String {
    match c {
        nexus_providers::Connection::Connected { detail, .. } => {
            let head = detail.split([';', '(']).next().unwrap_or(detail).trim();
            format!("Connected · {head}")
        }
        nexus_providers::Connection::Unknown => "Not checked".into(),
        nexus_providers::Connection::NotInstalled(_) => "Not installed".into(),
        nexus_providers::Connection::SignedOut(_) => "Signed out".into(),
        nexus_providers::Connection::Error(e) => format!("Error · {}", e.chars().take(60).collect::<String>()),
    }
}

fn metric(ui: &mut Ui, t: &Tokens, label: &str, value: Option<String>) {
    ui.vertical(|ui| {
        ui.label(RichText::new(value.unwrap_or_else(|| "—".into())).size(22.0).family(egui::FontFamily::Name("semibold".into())));
        ui.label(secondary(t, label));
    });
    ui.add_space(14.0);
}

fn fmt_uptime(s: f64) -> String {
    let s = s as u64;
    if s > 86400 { format!("{}d {}h", s / 86400, s % 86400 / 3600) } else { format!("{}h {}m", s / 3600, s % 3600 / 60) }
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() > n { format!("{}…", s.chars().take(n).collect::<String>()) } else { s.to_string() }
}

// ===================================================================== Devices

pub fn devices(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    screen_frame(ui, "Devices", "SSH hosts, endpoints and identity", &t, |ui| {
        ui.horizontal(|ui| {
            if ui.add(nexus_ui::AccentButton { text: "Add device", enabled: true }).clicked() {
                app.infra.editing = Some(Device {
                    id: uuid::Uuid::new_v4(),
                    name: "New device".into(),
                    username: String::new(),
                    endpoints: vec![Endpoint { id: uuid::Uuid::new_v4(), host: String::new(), port: 22, kind: EndpointKind::Lan, priority: 0, relay_target: None }],
                    authentication: "ed25519".into(),
                    use_tmux: false,
                    role: Some(HostRole::Other),
                    key_path: None,
                    server_catalog: false,
                    write_key_path: None,
                });
            }
            if ui.button("Import from iOS export…").clicked() {
                if let Some(p) = rfd::FileDialog::new().add_filter("Nexus devices", &["json", "nexusdevices"]).pick_file() {
                    match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|s| DeviceDocument::parse(&s).map_err(|e| e.to_string())) {
                        Ok(doc) => {
                            let n = doc.devices.len();
                            for d in doc.devices {
                                app.engine.register_device(&d);
                                app.s.devices.retain(|x| x.id != d.id);
                                app.s.devices.push(d);
                            }
                            app.s.save();
                            app.toast(format!("Imported {n} device(s)"), t.success());
                        }
                        Err(e) => app.toast(e, t.error()),
                    }
                }
            }
        });
        ui.add_space(8.0);
        let devs = devices_with_role(&app.s, &app.engine);
        let mut remove = None;
        for (d, debian) in &devs {
            card(ui, &t, |ui| {
                ui.set_width(ui.available_width() - 30.0);
                ui.horizontal(|ui| {
                    ui.label(icon(icons::SERVER, 16.0).color(t.accent()));
                    section_title(ui, &t, &d.name);
                    nexus_ui::pill(ui, &d.inferred_role().to_string(), t.accent());
                    if *debian {
                        match app.engine.debian_unlocked_for() {
                            Some(left) => nexus_ui::pill(ui, &format!("Debian · writes unlocked {}:{:02}", left.as_secs() / 60, left.as_secs() % 60), t.error()),
                            None => nexus_ui::pill(ui, "Debian · read-only", t.warning()),
                        };
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button(icon(icons::DELETE, 12.0)).on_hover_text("Remove device").clicked() {
                            remove = Some(d.id);
                        }
                        if ui.small_button("Edit").clicked() {
                            app.infra.editing = Some(d.clone());
                        }
                        if ui.small_button("Open in Infrastructure").clicked() {
                            app.infra.selected = app.s.devices.iter().position(|x| x.id == d.id).unwrap_or(0);
                            app.screen = crate::app::Screen::Infrastructure;
                        }
                        let hint = if *debian { "Owner write session over direct SSH with this device's write key. Needs Debian writes unlocked." } else { "Interactive session over direct SSH. Needs the host policy to grant interactive shell." };
                        if ui.small_button("SFTP").on_hover_text(hint).clicked() {
                            if let Err(e) = open_ssh_terminal(app, d, *debian, true, None) {
                                app.toast(e, t.error());
                            }
                        }
                        if ui.small_button("SSH terminal").on_hover_text(hint).clicked() {
                            if let Err(e) = open_ssh_terminal(app, d, *debian, false, None) {
                                app.toast(e, t.error());
                            }
                        }
                        if !*debian && d.inferred_role() == HostRole::Nixos {
                            if ui.small_button("nixos-rebuild switch…").on_hover_text("Opens an SSH terminal running sudo nixos-rebuild switch after a typed confirmation.").clicked() {
                                app.infra.nixos_switch_prompt = Some(String::new());
                                app.infra.editing_switch = Some(d.clone());
                            }
                            if ui.small_button("dry-build").on_hover_text("SSH terminal running sudo nixos-rebuild dry-build (builds nothing, activates nothing).").clicked() {
                                if let Err(e) = open_ssh_terminal(app, d, false, false, Some("sudo nixos-rebuild dry-build")) {
                                    app.toast(e, t.error());
                                }
                            }
                        }
                        if *debian {
                            if app.engine.debian_unlocked_for().is_some() {
                                if ui.small_button(RichText::new("Lock writes").color(t.error())).clicked() {
                                    app.engine.lock_debian();
                                }
                            } else if ui.small_button("Unlock writes…").on_hover_text("Owner only: allows writes, commands and a shell on Debian for 30 minutes. Agents stay read-only.").clicked() {
                                app.infra.unlock_prompt = Some(String::new());
                            }
                        }
                    });
                });
                ui.label(secondary(&t, format!("user {}", d.username)));
                for e in d.ordered_endpoints() {
                    let pin = app.infra.pins.lock().unwrap().pins().get(&e.authority()).cloned();
                    ui.label(RichText::new(format!("{:?}  {}:{}{}  {}", e.kind, e.host, e.port, e.relay_target.as_ref().map(|r| format!(" → {r}")).unwrap_or_default(), pin.map(|p| format!("pinned {p}")).unwrap_or_else(|| "not pinned".into()))).monospace().size(12.0).color(t.text2()));
                }
                if d.endpoints.iter().all(|e| e.kind == EndpointKind::Cloudflare) {
                    let msg = if app.access.signed_in() { "Reached through the Cloudflare relay (signed in)." } else { "Reached through the Cloudflare relay. Sign in to Cloudflare Access in Settings, or add a LAN/Tailscale endpoint." };
                    ui.label(RichText::new(msg).small().color(if app.access.signed_in() { t.text2() } else { t.warning() }));
                }
            });
            ui.add_space(8.0);
        }
        if let Some(id) = remove {
            app.s.devices.retain(|d| d.id != id);
            app.s.save();
        }
        ui.add_space(8.0);
        card(ui, &t, |ui| {
            ui.set_width(ui.available_width() - 30.0);
            section_title(ui, &t, "SSH identity");
            ui.label(secondary(&t, "Nexus reads your OpenSSH private key from disk when connecting; the key is never copied into settings. A passphrase, if any, is stored in the Secret Service keystore (KWallet or GNOME Keyring)."));
            ui.horizontal(|ui| {
                ui.label("Private key");
                ui.add(egui::TextEdit::singleline(&mut app.s.ssh.key_path).desired_width(420.0));
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        app.s.ssh.key_path = p.to_string_lossy().into();
                    }
                }
            });
            ui.horizontal(|ui| {
                if ui.button(if app.s.ssh.has_passphrase { "Change passphrase…" } else { "Set passphrase…" }).clicked() {
                    app.infra.passphrase_prompt = Some(String::new());
                }
                if app.s.ssh.has_passphrase && ui.button("Remove stored passphrase").clicked() {
                    secrets::delete("ssh-passphrase");
                    app.s.ssh.has_passphrase = false;
                }
                if ui.button("Save").clicked() {
                    app.s.save();
                }
            });
        });
    });
}

// ===================================================================== Infrastructure

const CONSOLE: &[(&str, &str)] = &[
    ("Host metrics", ""),
    ("uname -a", ""),
    ("OS release", ""),
    ("Uptime", ""),
    ("Memory (free -b)", ""),
    ("Disk usage (df)", ""),
    ("Service status", "unit"),
    ("Service logs (journalctl)", "unit"),
    ("User service status", "unit"),
    ("User service logs", "unit"),
    ("Git status", "repo path"),
    ("Git log", "repo path"),
    ("Git diff", "repo path"),
    ("SHA-256 of file", "path"),
];

fn console_command(i: usize, arg: &str) -> CatalogCommand {
    let a = arg.trim().to_string();
    match i {
        0 => CatalogCommand::Metrics,
        1 => CatalogCommand::Uname,
        2 => CatalogCommand::OsRelease,
        3 => CatalogCommand::Uptime,
        4 => CatalogCommand::MemoryInfo,
        5 => CatalogCommand::DiskUsage,
        6 => CatalogCommand::ServiceStatus { unit: a },
        7 => CatalogCommand::ServiceLogs { unit: a, lines: 300 },
        8 => CatalogCommand::UserServiceStatus { unit: a },
        9 => CatalogCommand::UserServiceLogs { unit: a, lines: 300 },
        10 => CatalogCommand::GitStatus { repo: a },
        11 => CatalogCommand::GitLog { repo: a, count: 50 },
        12 => CatalogCommand::GitDiff { repo: a },
        _ => CatalogCommand::HashFile { path: a },
    }
}

pub fn infrastructure(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    if let Some(p) = app.infra.take_open() {
        app.open_workspace(p);
        return;
    }
    let devs = devices_with_role(&app.s, &app.engine);
    if devs.is_empty() {
        screen_frame(ui, "Infrastructure", "No devices configured", &t, |_| {});
        return;
    }
    app.infra.selected = app.infra.selected.min(devs.len() - 1);
    let (dev, debian) = devs[app.infra.selected].clone();
    let id = dev.id.to_string();
    let subtitle = if debian { "Read-only observation. Mutating actions are unavailable by policy." } else { "Read-only observation by default; grant capabilities per host in Settings." };
    screen_frame(ui, "Infrastructure", subtitle, &t, |ui| {
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("infra_host").selected_text(&dev.name).show_ui(ui, |ui| {
                for (i, (d, _)) in devs.iter().enumerate() {
                    ui.selectable_value(&mut app.infra.selected, i, &d.name);
                }
            });
            if debian {
                nexus_ui::pill(ui, "Debian · read-only", t.warning());
            }
            let h = app.infra.hosts.get(&id);
            if let Some(fp) = h.and_then(|h| h.fingerprint.clone()) {
                ui.label(secondary(&t, format!("host key {fp}")));
            }
            if h.is_some_and(|h| h.busy > 0) {
                ui.add(egui::Spinner::new().size(12.0));
            }
        });
        ui.horizontal(|ui| {
            for (tab, l) in [(InfraTab::Overview, "Overview"), (InfraTab::Services, "Services"), (InfraTab::Processes, "Processes"), (InfraTab::Network, "Network"), (InfraTab::Files, "Files"), (InfraTab::Console, "Console")] {
                if ui.add(egui::Button::selectable(app.infra.tab == tab, l)).clicked() {
                    app.infra.tab = tab;
                }
            }
        });
        ui.separator();
        let mut job: Option<Job> = None;
        let outputs = app.infra.hosts.get(&id).map(|h| h.outputs.clone()).unwrap_or_default();
        let out = |k: &CatalogCommand| outputs.get(&k.label()).cloned();
        match app.infra.tab {
            InfraTab::Overview => {
                if ui.button(icon(icons::REFRESH, 13.0)).on_hover_text("Refresh metrics").clicked() {
                    job = Some(Job::Catalog(CatalogCommand::Metrics));
                }
                if let Some(h) = app.infra.hosts.get(&id) {
                    if let Some(s) = h.history.latest() {
                        card(ui, &t, |ui| {
                            ui.set_width(ui.available_width() - 30.0);
                            ui.horizontal(|ui| {
                                metric(ui, &t, "CPU", s.cpu_percent.map(|v| format!("{v:.1}%")));
                                metric(ui, &t, "Cores", s.cpu_count.map(|v| v.to_string()));
                                metric(ui, &t, "Memory", s.memory_used_percent().map(|v| format!("{v:.0}% of {}", format_bytes(s.memory_total.unwrap_or(0) as f64))));
                                metric(ui, &t, "Root disk", s.root_fs.as_ref().map(|f| format!("{} free", format_bytes(f.available as f64))));
                            });
                            ui.label(secondary(&t, "CPU history"));
                            sparkline(ui, &h.history.series(|s| s.cpu_percent), 100.0, t.accent(), vec2(ui.available_width(), 60.0));
                            ui.label(secondary(&t, "Memory history"));
                            sparkline(ui, &h.history.series(|s| s.memory_used_percent()), 100.0, t.purple(), vec2(ui.available_width(), 60.0));
                            for r in h.history.network_rates() {
                                ui.label(RichText::new(format!("{}  ↓ {}/s  ↑ {}/s", r.interface, format_bytes(r.rx_per_sec), format_bytes(r.tx_per_sec))).monospace().size(12.0));
                            }
                            for g in &s.gpus {
                                ui.label(RichText::new(format!("GPU {}  {}%  {}/{} MiB  {}°C", g.index, g.utilization.map(|v| format!("{v:.0}")).unwrap_or("—".into()), g.memory_used_mib.unwrap_or(0), g.memory_total_mib.unwrap_or(0), g.temperature_c.map(|v| format!("{v:.0}")).unwrap_or("—".into()))).monospace().size(12.0));
                            }
                        });
                    } else {
                        ui.label(secondary(&t, "No metrics yet. Press refresh to connect (read-only)."));
                    }
                } else {
                    ui.label(secondary(&t, "Not connected. Press refresh to connect and read metrics (read-only /proc reads)."));
                }
                ui.add_space(8.0);
                card(ui, &t, |ui| {
                    ui.set_width(ui.available_width() - 30.0);
                    ui.horizontal(|ui| {
                        ui.label(icon(icons::GAME, 14.0).color(t.success()));
                        section_title(ui, &t, "Minecraft server");
                    });
                    ui.horizontal(|ui| {
                        ui.label("systemd unit");
                        ui.add(egui::TextEdit::singleline(&mut app.infra.minecraft_unit).desired_width(160.0));
                        if ui.button("Check status").clicked() {
                            job = Some(Job::Catalog(CatalogCommand::ServiceStatus { unit: app.infra.minecraft_unit.clone() }));
                        }
                        if ui.button("Open panel in browser…").clicked() {
                            app.infra.minecraft_confirm = true;
                        }
                    });
                    if let Some(o) = out(&CatalogCommand::ServiceStatus { unit: app.infra.minecraft_unit.clone() }) {
                        ui.label(RichText::new(o).monospace().size(12.0));
                    }
                    ui.label(secondary(&t, "Start/stop/restart are not available in Nexus Desktop while Debian is read-only."));
                });
            }
            InfraTab::Services => {
                ui.horizontal(|ui| {
                    if ui.button("System services").clicked() {
                        job = Some(Job::Catalog(CatalogCommand::ServiceList));
                    }
                    if ui.button("User services").clicked() {
                        job = Some(Job::Catalog(CatalogCommand::UserServiceList));
                    }
                    ui.add_enabled(false, egui::Button::new("Restart")).on_disabled_hover_text(if debian { "Debian is read-only: service control is denied by policy" } else { "Service control is not granted for this host" });
                });
                for (cmd, user) in [(CatalogCommand::ServiceList, false), (CatalogCommand::UserServiceList, true)] {
                    if let Some(o) = out(&cmd) {
                        ui.label(RichText::new(if user { "User services" } else { "System services" }).strong());
                        egui::Grid::new(("svc", user)).striped(true).show(ui, |ui| {
                            for line in o.lines().take(400) {
                                let f: Vec<&str> = line.split_whitespace().collect();
                                if f.len() < 4 {
                                    continue;
                                }
                                let active = f[2] == "active";
                                nexus_ui::dot(ui, if active { t.success() } else if f[2] == "failed" { t.error() } else { t.text2() });
                                if ui.link(f[0]).clicked() {
                                    app.infra.unit = f[0].to_string();
                                    job = Some(Job::Catalog(if user { CatalogCommand::UserServiceLogs { unit: f[0].into(), lines: 200 } } else { CatalogCommand::ServiceLogs { unit: f[0].into(), lines: 200 } }));
                                }
                                ui.label(secondary(&t, format!("{} {}", f[2], f[3])));
                                ui.label(secondary(&t, f[4..].join(" ")));
                                ui.end_row();
                            }
                        });
                    }
                }
                if !app.infra.unit.is_empty() {
                    for c in [CatalogCommand::ServiceLogs { unit: app.infra.unit.clone(), lines: 200 }, CatalogCommand::UserServiceLogs { unit: app.infra.unit.clone(), lines: 200 }] {
                        if let Some(o) = out(&c) {
                            ui.label(RichText::new(format!("Logs: {}", app.infra.unit)).strong());
                            egui::Frame::new().fill(t.editor()).corner_radius(CornerRadius::same(8)).inner_margin(8).show(ui, |ui| {
                                ui.label(RichText::new(o).monospace().size(11.5));
                            });
                        }
                    }
                }
            }
            InfraTab::Processes => {
                if ui.button("Refresh processes").clicked() {
                    job = Some(Job::Catalog(CatalogCommand::ProcessList));
                }
                if let Some(o) = out(&CatalogCommand::ProcessList) {
                    egui::Grid::new("procs").striped(true).show(ui, |ui| {
                        for h in ["PID", "USER", "CPU%", "MEM%", "ELAPSED", "COMMAND"] {
                            ui.label(RichText::new(h).small().color(t.text2()));
                        }
                        ui.end_row();
                        for line in o.lines().take(80) {
                            for f in line.split_whitespace().take(6) {
                                ui.label(RichText::new(f).monospace().size(12.0));
                            }
                            ui.end_row();
                        }
                    });
                    ui.label(secondary(&t, "Killing processes is not available (read-only)."));
                }
            }
            InfraTab::Network => {
                ui.horizontal(|ui| {
                    if ui.button("Addresses").clicked() {
                        job = Some(Job::Catalog(CatalogCommand::NetworkAddresses));
                    }
                    if ui.button("Listening sockets").clicked() {
                        job = Some(Job::Catalog(CatalogCommand::ListeningSockets));
                    }
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Probe from this PC").on_hover_text("DNS lookup and TCP connect to each endpoint, from this PC. Sends nothing over SSH.").clicked() {
                        let eps: Vec<Endpoint> = dev.ordered_endpoints().into_iter().cloned().collect();
                        let slot = app.infra.probe.clone();
                        let wake = app.infra.wake.clone();
                        *slot.lock().unwrap() = Some("Probing…".into());
                        std::thread::spawn(move || {
                            let r = probe_endpoints(&eps, std::time::Duration::from_secs(3));
                            *slot.lock().unwrap() = Some(r);
                            wake();
                        });
                    }
                    ui.label(secondary(&t, "Local diagnostics: name resolution and TCP reachability of the device's endpoints."));
                });
                if let Some(r) = app.infra.probe.lock().unwrap().clone() {
                    egui::Frame::new().fill(t.editor()).corner_radius(CornerRadius::same(8)).inner_margin(8).show(ui, |ui| {
                        ui.label(RichText::new(r).monospace().size(12.0));
                    });
                }
                for c in [CatalogCommand::NetworkAddresses, CatalogCommand::ListeningSockets] {
                    if let Some(o) = out(&c) {
                        egui::Frame::new().fill(t.editor()).corner_radius(CornerRadius::same(8)).inner_margin(8).show(ui, |ui| {
                            ui.label(RichText::new(o).monospace().size(12.0));
                        });
                    }
                }
            }
            InfraTab::Files => {
                ui.horizontal(|ui| {
                    ui.label("Path");
                    let r = ui.add(egui::TextEdit::singleline(&mut app.infra.path).desired_width(360.0));
                    if ui.button("List").clicked() || r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        job = Some(Job::Catalog(CatalogCommand::ListDirectory { path: app.infra.path.clone() }));
                    }
                    if ui.button("Up").clicked() {
                        if let Some((p, _)) = app.infra.path.trim_end_matches('/').rsplit_once('/') {
                            app.infra.path = if p.is_empty() { "/".into() } else { p.into() };
                            job = Some(Job::Catalog(CatalogCommand::ListDirectory { path: app.infra.path.clone() }));
                        }
                    }
                    if ui.button("Open as shadow workspace").on_hover_text("Copy text files (≤1 MB) to a local folder and open it in the IDE. The remote host is never modified; edits stay local and can be exported as a patch.").clicked() {
                        job = Some(Job::Shadow { root: app.infra.path.clone() });
                    }
                });
                ui.label(secondary(&t, format!("Readable roots: {}", if debian { ReadRoots::debian_default().0.join(", ") } else { format!("/home/{}, /var/log, /srv, /opt, /etc/nixos", dev.username) })));
                if let Some(o) = out(&CatalogCommand::ListDirectory { path: app.infra.path.clone() }) {
                    let base = app.infra.path.trim_end_matches('/').to_string();
                    egui::Grid::new("files").striped(true).show(ui, |ui| {
                        for line in o.lines() {
                            let f: Vec<&str> = line.split_whitespace().collect();
                            if f.len() < 7 || f[0].starts_with("total") {
                                continue;
                            }
                            let name = f[6..].join(" ");
                            if name == "." || name == ".." {
                                continue;
                            }
                            let is_dir = f[0].starts_with('d');
                            ui.label(icon(if is_dir { icons::FOLDER } else { icons::FILE }, 12.0).color(t.text2()));
                            if ui.link(&name).clicked() {
                                let full = format!("{base}/{name}");
                                if is_dir {
                                    app.infra.path = full.clone();
                                    job = Some(Job::Catalog(CatalogCommand::ListDirectory { path: full }));
                                } else {
                                    job = Some(Job::Catalog(CatalogCommand::ReadFile { path: full, max_bytes: 2 * 1024 * 1024 }));
                                }
                            }
                            ui.label(secondary(&t, if is_dir { String::new() } else { format_bytes(f[4].parse().unwrap_or(0.0)) }));
                            ui.end_row();
                        }
                    });
                }
                // Opened files go to the IDE read-only.
                let reads: Vec<(String, String)> = outputs.iter().filter(|(k, _)| k.starts_with("read /")).map(|(k, v)| (k[5..].to_string(), v.clone())).collect();
                for (path, text) in reads {
                    let rel = format!("{}:{}", dev.name, path);
                    if !app.ide.docs.iter().any(|d| d.rel == rel) {
                        app.ide.open_virtual(&rel, &text, if debian { "Read-only (Debian)" } else { "Read-only remote file" });
                        app.screen = crate::app::Screen::Ide;
                    }
                    if let Some(h) = app.infra.hosts.get_mut(&id) {
                        h.outputs.remove(&format!("read {path}"));
                    }
                }
            }
            InfraTab::Console => {
                ui.label(secondary(&t, "Restricted observational console: only fixed, reviewed read-only commands. There is no free-text shell for read-only hosts."));
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("console").selected_text(CONSOLE[app.infra.console_cmd].0).show_ui(ui, |ui| {
                        for (i, (n, _)) in CONSOLE.iter().enumerate() {
                            ui.selectable_value(&mut app.infra.console_cmd, i, *n);
                        }
                    });
                    let arg = CONSOLE[app.infra.console_cmd].1;
                    if !arg.is_empty() {
                        ui.add(egui::TextEdit::singleline(&mut app.infra.console_arg).hint_text(arg).desired_width(260.0));
                    }
                    if ui.button("Run").clicked() {
                        let cmd = console_command(app.infra.console_cmd, &app.infra.console_arg);
                        match cmd.render(&ReadRoots::debian_default()) {
                            Err(e) if !matches!(e, nexus_security::catalog::CatalogError::OutsideRoots) || debian => app.toast(format!("Refused: {e}"), t.error()),
                            _ => job = Some(Job::Catalog(cmd)),
                        }
                    }
                });
                let cmd = console_command(app.infra.console_cmd, &app.infra.console_arg);
                if let Ok(line) = cmd.render(&ReadRoots::debian_default()) {
                    ui.label(RichText::new(format!("$ {}", short(&line, 200))).monospace().size(11.0).color(t.text2()));
                }
                if let Some(o) = out(&cmd) {
                    egui::Frame::new().fill(t.editor()).corner_radius(CornerRadius::same(8)).inner_margin(8).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(o).monospace().size(12.0));
                    });
                }
            }
        }
        if let Some(j) = job {
            let r = app.infra.run(&app.rt, &app.engine, &app.s, &dev, j).map(|_| String::new());
            app.report(r);
        }
    });
}

// ===================================================================== Settings

pub fn settings_screen(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    screen_frame(ui, "Settings", &format!("Nexus Desktop {}", env!("CARGO_PKG_VERSION")), &t, |ui| {
        let w = ui.available_width() - 30.0;
        card(ui, &t, |ui| {
            ui.set_width(w);
            section_title(ui, &t, "Appearance");
            let tk = &mut app.s.tokens;
            ui.checkbox(&mut tk.reduce_transparency, "Reduce transparency (solid surfaces)");
            ui.checkbox(&mut tk.reduce_motion, "Reduce motion");
            ui.checkbox(&mut app.s.layout.compact_nav, "Compact navigation");
            ui.add(egui::Slider::new(&mut tk.ui_scale, 0.8..=1.6).text("Interface scale"));
            ui.add(egui::Slider::new(&mut tk.editor_font_size, 10.0..=22.0).text("Editor font size"));
            ui.horizontal(|ui| {
                ui.label("Accent");
                ui.color_edit_button_srgb(&mut tk.accent);
                ui.label("Background");
                ui.color_edit_button_srgb(&mut tk.background);
                if ui.button("Reset to Midnight").clicked() {
                    *tk = Tokens::default();
                }
            });
        });
        ui.add_space(10.0);
        card(ui, &t, |ui| {
            ui.set_width(w);
            ui.horizontal(|ui| {
                ui.label(icon(icons::CLOUD, 15.0).color(t.accent()));
                section_title(ui, &t, "Cloudflare Access");
            });
            ui.label(secondary(&t, "Signs in to the Nexus Worker (the same Access app as the iPhone) so devices with a Cloudflare relay endpoint can be reached without LAN or Tailscale. Your browser handles the login; the token is encrypted with a key kept in your Secret Service keystore (KWallet or GNOME Keyring)."));
            ui.horizontal(|ui| {
                nexus_ui::dot(ui, if app.access.signed_in() { t.success() } else if app.access.waiting() { t.accent() } else { t.text2() });
                ui.label(app.access.status());
                if app.access.busy {
                    ui.add(egui::Spinner::new().size(12.0));
                }
            });
            if let Some(e) = &app.access.last_error {
                ui.label(RichText::new(e).small().color(t.error()));
            }
            ui.horizontal(|ui| {
                if !app.access.signed_in() {
                    if ui.add(nexus_ui::AccentButton { text: if app.access.waiting() { "Open sign-in again" } else { "Sign in with Cloudflare Access" }, enabled: !app.access.busy }).clicked() {
                        if let Err(e) = app.access.start_sign_in() {
                            app.toasts.push(Toast { text: e, color: t.error(), at: Instant::now() });
                        }
                    }
                    if app.access.waiting() && ui.button("Cancel").clicked() {
                        app.access.cancel();
                    }
                } else if ui.button("Sign out").clicked() {
                    app.access.sign_out();
                    app.infra.drop_relay_sessions(&app.rt);
                }
            });
            let mut mem = app.s.access_memory_only;
            if ui.checkbox(&mut mem, "Keep the session in memory only (sign in again after each restart)")
                .on_hover_text("No access-session.bin is kept on disk, so other programs running as you (such as an agent in Bypass mode) cannot read the token from a file. Recommended while Bypass is enabled.")
                .changed()
            {
                match app.access.set_memory_only(mem) {
                    Ok(()) => {
                        app.s.access_memory_only = mem;
                        app.s.save();
                    }
                    Err(e) => app.toasts.push(Toast { text: e, color: t.error(), at: Instant::now() }),
                }
            }
            ui.label(RichText::new(format!("Worker: {}  ·  Issuer: {}", nexus_access::resource(), nexus_access::issuer())).small().color(t.text2()));
            if let Some(e) = nexus_core::site::site_error() {
                ui.label(RichText::new(e).small().color(t.error()));
            } else if nexus_access::client_id().is_empty() {
                ui.label(RichText::new("Not configured: add your Worker and Access values to ~/.config/nexus-desktop/site.json (see docs/site.example.json).").small().color(t.warning()));
            }
        });
        ui.add_space(10.0);
        card(ui, &t, |ui| {
            ui.set_width(w);
            section_title(ui, &t, "App lock");
            crate::lock::settings_ui(app, ui);
        });
        ui.add_space(10.0);
        card(ui, &t, |ui| {
            ui.set_width(w);
            section_title(ui, &t, "AI providers");
            ui.label(secondary(&t, "Codex and Claude Code use their own official sign-in; Nexus never reads their tokens. A provider shows Connected only after authentication and a real operation succeed."));
            let mut verify = None;
            for (i, p) in app.ai.providers.iter().enumerate() {
                let caps = p.provider.capabilities();
                ui.horizontal(|ui| {
                    nexus_ui::dot(ui, if p.status.is_connected() { t.success() } else { t.warning() });
                    ui.label(RichText::new(p.provider.name()).strong());
                    nexus_ui::pill(ui, match caps.billing {
                        Billing::Subscription => "subscription",
                        Billing::ApiMetered => "API (billed)",
                        Billing::Local => "local",
                    }, t.accent());
                    ui.label(secondary(&t, if p.checking { "verifying…".into() } else { p.status.label() }));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Verify").clicked() {
                            verify = Some(i);
                        }
                        match p.key.as_str() {
                            "codex" if ui.small_button("Sign in…").on_hover_text("Runs the official `codex login` in a console window").clicked() => launch_console("codex", &["login"]),
                            "claude" if ui.small_button("Sign in…").on_hover_text("Runs the official `claude auth login` in a console window").clicked() => {
                                match nexus_providers::locate::claude() {
                                    Some(b) => launch_console(&b.to_string_lossy(), &["auth", "login"]),
                                    None => {}
                                }
                            }
                            _ => {}
                        }
                    });
                });
                ui.label(RichText::new(format!("{} · {}", caps.auth_method, caps.notes)).small().color(t.text2()));
                ui.add_space(4.0);
            }
            if let Some(i) = verify {
                app.ai.verify(i);
            }
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("PS5LM Plus URL (OpenAI-compatible, LAN)");
                ui.add(egui::TextEdit::singleline(&mut app.s.ps5_url).hint_text("http://192.168.x.x:8080/v1").desired_width(280.0));
                if ui.button("Apply").clicked() {
                    match nexus_providers::openai::validate_base_url(&app.s.ps5_url) {
                        Ok(()) | Err(_) if app.s.ps5_url.trim().is_empty() => {
                            app.s.save();
                            app.ai.rebuild_providers(&app.s);
                        }
                        Ok(()) => {
                            app.s.save();
                            app.ai.rebuild_providers(&app.s);
                        }
                        Err(e) => app.toast(e.to_string(), t.error()),
                    }
                }
            });
            ui.label(secondary(&t, "Direct LAN access only. Access through the Cloudflare-protected gateway is not implemented yet in Nexus Desktop."));
            ui.separator();
            api_provider_editor(app, ui, &t);
        });
        ui.add_space(10.0);
        card(ui, &t, |ui| {
            ui.set_width(w);
            section_title(ui, &t, "Security and permissions");
            ui.label(secondary(&t, "Debian (and the Nexus gateway it hosts) is permanently read-only in code. Other hosts default to read-only. Local workspaces: you can edit; agents need the toggles in the AI panel."));
            for (k, p) in app.s.policies.clone() {
                ui.label(RichText::new(format!("{k}: user {:?} · agent {:?}", p.user.iter().map(|c| c.label()).collect::<Vec<_>>(), p.agent.iter().map(|c| c.label()).collect::<Vec<_>>())).small().monospace());
            }
            ui.horizontal(|ui| {
                if ui.button("Open audit log").clicked() {
                    app.show_audit = true;
                }
                ui.label(secondary(&t, format!("Data: {}", data_dir().display())));
            });
            ui.horizontal(|ui| {
                ui.label("Telemetry refresh (seconds)");
                ui.add(egui::DragValue::new(&mut app.s.telemetry_interval_secs).range(5..=600));
            });
        });
        if ui.button("Save settings").clicked() {
            app.s.save();
            app.toast("Settings saved", t.success());
        }
    });
}

fn launch_console(program: &str, args: &[&str]) {
    // A new terminal window so the official CLI can run its own interactive
    // sign-in (browser based). Windows used `cmd /C start`.
    let _ = nexus_core::platform::launch_in_terminal_window(program, args);
}

fn api_provider_editor(app: &mut NexusApp, ui: &mut Ui, t: &Tokens) {
    let id = ui.make_persistent_id("new_api_provider");
    let mut draft: (String, String, String, String, bool) = ui.ctx().data_mut(|d| d.get_temp(id)).unwrap_or_else(|| ("OpenAI API".into(), "https://api.openai.com/v1".into(), String::new(), String::new(), true));
    ui.label(RichText::new("Add an API provider (separately billed)").strong());
    ui.label(secondary(t, "For Anthropic's API use https://api.anthropic.com/v1 (OpenAI-compatible endpoint). Keys are stored in the Secret Service keystore (KWallet or GNOME Keyring)."));
    egui::Grid::new("api_prov").show(ui, |ui| {
        ui.label("Name");
        ui.text_edit_singleline(&mut draft.0);
        ui.end_row();
        ui.label("Base URL");
        ui.text_edit_singleline(&mut draft.1);
        ui.end_row();
        ui.label("Model");
        ui.text_edit_singleline(&mut draft.2);
        ui.end_row();
        ui.label("API key");
        ui.add(egui::TextEdit::singleline(&mut draft.3).password(true));
        ui.end_row();
        ui.label("Billing");
        ui.checkbox(&mut draft.4, "Metered API (uncheck for local servers)");
        ui.end_row();
    });
    if ui.button("Add provider").clicked() {
        match nexus_providers::openai::validate_base_url(&draft.1) {
            Ok(()) => {
                let pid = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
                let key_target = (!draft.3.is_empty()).then(|| format!("api-key-{pid}"));
                if let Some(k) = &key_target {
                    if let Err(e) = secrets::set(k, &draft.3) {
                        app.toast(format!("Could not store key: {e}"), t.error());
                        return;
                    }
                }
                app.s.openai_compatible.push(nexus_providers::openai::OpenAiConfig {
                    id: pid,
                    name: draft.0.clone(),
                    base_url: draft.1.clone(),
                    model: draft.2.clone(),
                    billing: if draft.4 { Billing::ApiMetered } else { Billing::Local },
                    key_target,
                });
                app.s.save();
                app.ai.rebuild_providers(&app.s);
                draft.3.clear();
                app.toast("Provider added; verifying…", t.success());
            }
            Err(e) => app.toast(e.to_string(), t.error()),
        }
    }
    let mut remove = None;
    for (i, c) in app.s.openai_compatible.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} — {} ({})", c.name, c.base_url, c.model)).small());
            if ui.small_button("Remove").clicked() {
                remove = Some(i);
            }
        });
    }
    if let Some(i) = remove {
        let c = app.s.openai_compatible.remove(i);
        if let Some(k) = c.key_target {
            secrets::delete(&k);
        }
        app.s.save();
        app.ai.rebuild_providers(&app.s);
    }
    ui.ctx().data_mut(|d| d.insert_temp(id, draft));
}

/// Per-device SSH key: choose a file, or generate a fresh Ed25519 key.
fn key_section(ui: &mut Ui, t: &Tokens, d: &mut Device, toasts: &mut Vec<Toast>) {
    ui.label(RichText::new("SSH key").strong());
    let mut path = d.key_path.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut path).hint_text("uses the global SSH identity").desired_width(360.0));
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new().set_directory(crate::keys::ssh_dir()).pick_file() {
                path = p.to_string_lossy().into();
            }
        }
    });
    d.key_path = Some(path.trim().to_string()).filter(|p| !p.is_empty());
    let form_id = crate::app::gid(("keygen", d.id));
    let mut form: Option<(String, String)> = ui.ctx().data(|m| m.get_temp(form_id));
    let mut close = false;
    match form.as_mut() {
        None => {
            if ui.button("Generate new key…").on_hover_text("Creates a new Ed25519 key pair in your .ssh folder; existing files are never overwritten").clicked() {
                form = Some((String::new(), String::new()));
            }
        }
        Some((pass, confirm)) => {
            egui::Frame::new().fill(white_a(0.04)).corner_radius(CornerRadius::same(8)).inner_margin(8).show(ui, |ui| {
                let target = crate::keys::default_path(&d.name);
                ui.label(secondary(t, format!("New Ed25519 key: {}", target.display())));
                ui.horizontal(|ui| {
                    ui.label("Passphrase");
                    ui.add(egui::TextEdit::singleline(pass).password(true).hint_text("optional, recommended").desired_width(170.0));
                    ui.label("Confirm");
                    ui.add(egui::TextEdit::singleline(confirm).password(true).desired_width(170.0));
                });
                ui.label(RichText::new("A passphrase is saved in the Secret Service keystore (KWallet or GNOME Keyring) so Nexus can unlock the key.").small().color(t.text2()));
                let matches = pass == confirm;
                if !matches {
                    ui.label(RichText::new("Passphrases do not match").small().color(t.error()));
                }
                ui.horizontal(|ui| {
                    if ui.add(nexus_ui::AccentButton { text: "Generate", enabled: matches }).clicked() {
                        let host = nexus_core::platform::hostname().to_lowercase();
                        let comment = format!("nexus-desktop-{}@{host}", crate::keys::slug(&d.name));
                        match crate::keys::generate(&target, &comment, pass) {
                            Ok((p, _)) => {
                                d.key_path = Some(p.to_string_lossy().into());
                                let name = format!("ssh-passphrase:{}", d.id);
                                if pass.is_empty() {
                                    secrets::delete(&name);
                                } else if let Err(e) = secrets::set(&name, pass) {
                                    toasts.push(Toast { text: format!("Key created, but storing the passphrase failed: {e}"), color: t.warning(), at: Instant::now() });
                                }
                                toasts.push(Toast { text: format!("Generated {}", p.display()), color: t.success(), at: Instant::now() });
                                close = true;
                            }
                            Err(e) => toasts.push(Toast { text: e, color: t.error(), at: Instant::now() }),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        }
    }
    match (close, form) {
        (false, Some(f)) => {
            ui.ctx().data_mut(|m| m.insert_temp(form_id, f));
        }
        _ => {
            ui.ctx().data_mut(|m| m.remove_temp::<(String, String)>(form_id));
        }
    }
    // Public key to install on the server.
    if let Some(pk) = d.key_path.as_deref().and_then(|p| crate::keys::public_key(std::path::Path::new(p))) {
        ui.checkbox(&mut d.server_catalog, "Server enforces the read-only catalog (nexus-ro installed for this key)")
            .on_hover_text("Tick only after /usr/local/bin/nexus-ro and the restricted authorized_keys line are installed on the server. Nexus then sends structured nexus-ro/1 requests instead of shell commands over direct SSH, and the server refuses anything else. See docs/proposals/0001-debian-hardening.md.");
        let line = if d.server_catalog { format!("restrict,command=\"/usr/local/bin/nexus-ro\" {pk}") } else { format!("restrict {pk}") };
        egui::Frame::new().fill(t.editor()).corner_radius(CornerRadius::same(8)).inner_margin(8).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Public key").small().color(t.text2()));
                if let Some(fp) = crate::keys::fingerprint(&pk) {
                    ui.label(RichText::new(fp).monospace().size(11.0).color(t.text2()));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.small_button("Copy authorized_keys line").clicked() {
                        ui.ctx().copy_text(line.clone());
                    }
                });
            });
            ui.add(egui::Label::new(RichText::new(&line).monospace().size(11.0)).wrap());
        });
        ui.label(RichText::new("Add this line to ~/.ssh/authorized_keys for the device's user on the server. That is a change on the server, which Nexus does not make for you. `restrict` disables forwarding and PTY allocation; `command=` makes the server run only nexus-ro for this key.").small().color(t.text2()));
    }
}

/// DNS lookup and TCP connect for each endpoint (local only, nothing sent over SSH).
fn probe_endpoints(eps: &[Endpoint], timeout: std::time::Duration) -> String {
    use std::net::{TcpStream, ToSocketAddrs};
    let mut out = String::new();
    for e in eps {
        let t0 = Instant::now();
        let line = match (e.host.as_str(), e.port).to_socket_addrs() {
            Err(err) => format!("{}:{}  DNS failed: {err}", e.host, e.port),
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                let dns_ms = t0.elapsed().as_millis();
                match addrs.first() {
                    None => format!("{}:{}  DNS returned no addresses", e.host, e.port),
                    Some(a) => {
                        let t1 = Instant::now();
                        match TcpStream::connect_timeout(a, timeout) {
                            Ok(_) => format!("{}:{}  {a}  DNS {dns_ms} ms, TCP connected in {} ms", e.host, e.port, t1.elapsed().as_millis()),
                            Err(err) => format!("{}:{}  {a}  DNS {dns_ms} ms, TCP failed: {err}", e.host, e.port),
                        }
                    }
                }
            }
        };
        out.push_str(&format!("{:?}  {line}\n", e.kind));
    }
    if out.is_empty() {
        out.push_str("No endpoints configured.");
    }
    out
}

/// Owner capabilities granted by "Allow SSH and SFTP sessions" on a non-Debian host.
const OWNER_SESSION_CAPS: [Capability; 4] = [Capability::InteractiveShell, Capability::ExecuteArbitraryCommand, Capability::WriteFile, Capability::GitWrite];

/// Debian write key: separate from the restricted catalog key, passphrase required.
fn write_key_section(ui: &mut Ui, t: &Tokens, d: &mut Device, toasts: &mut Vec<Toast>) {
    ui.label(RichText::new("Write key (owner sessions)").strong());
    ui.add(egui::Label::new(RichText::new("Used only for SSH/SFTP terminals while Debian writes are unlocked. Keep it separate from the restricted catalog key above. OpenSSH asks for its passphrase; Nexus never stores it.").small().color(t.text2())).wrap());
    let mut path = d.write_key_path.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut path).hint_text("not set").desired_width(360.0));
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new().set_directory(crate::keys::ssh_dir()).pick_file() {
                path = p.to_string_lossy().into();
            }
        }
    });
    let form_id = crate::app::gid(("writekey", d.id));
    let mut pass: Option<String> = ui.ctx().data(|m| m.get_temp(form_id));
    match pass.as_mut() {
        None => {
            if ui.button("Generate write key…").clicked() {
                ui.ctx().data_mut(|m| m.insert_temp(form_id, String::new()));
            }
        }
        Some(p) => {
            ui.horizontal(|ui| {
                ui.label("Passphrase (required)");
                ui.add(egui::TextEdit::singleline(p).password(true).desired_width(200.0));
                if ui.add_enabled(p.chars().count() >= 8, egui::Button::new("Generate")).clicked() {
                    let file = crate::keys::ssh_dir().join(format!("nexus_{}_write_ed25519", crate::keys::slug(&d.name)));
                    match crate::keys::generate(&file, &format!("nexus-desktop-{}-write", crate::keys::slug(&d.name)), p) {
                        Ok((f, _)) => {
                            path = f.to_string_lossy().into();
                            toasts.push(Toast { text: "Write key generated. Install its public key on the server yourself.".into(), color: t.success(), at: Instant::now() });
                        }
                        Err(e) => toasts.push(Toast { text: e, color: t.error(), at: Instant::now() }),
                    }
                    ui.ctx().data_mut(|m| m.remove_temp::<String>(form_id));
                }
                if ui.button("Cancel").clicked() {
                    ui.ctx().data_mut(|m| m.remove_temp::<String>(form_id));
                }
            });
            if pass.is_some() {
                ui.ctx().data_mut(|m| {
                    if m.get_temp::<String>(form_id).is_some() {
                        m.insert_temp(form_id, pass.clone().unwrap_or_default());
                    }
                });
            }
        }
    }
    d.write_key_path = Some(path.trim().to_string()).filter(|p| !p.is_empty());
    if let Some(pk) = d.write_key_path.as_deref().and_then(|p| crate::keys::public_key(std::path::Path::new(p))) {
        ui.add(egui::Label::new(RichText::new(format!("authorized_keys line: no-agent-forwarding,no-X11-forwarding {pk}")).monospace().size(11.0)).wrap());
    }
}

/// Open `ssh` or `sftp` (OpenSSH; Windows used its built-in OpenSSH) for a device in an IDE terminal tab.
/// Direct endpoints only: the Cloudflare relay stays read-only for Desktop.
/// OpenSSH does its own host-key check (StrictHostKeyChecking=ask) and asks
/// for any key passphrase itself.
fn open_ssh_terminal(app: &mut NexusApp, d: &Device, debian: bool, sftp: bool, remote: Option<&'static str>) -> Result<(), String> {
    let e = d
        .ordered_endpoints()
        .into_iter()
        .find(|e| e.kind != EndpointKind::Cloudflare)
        .ok_or("SSH and SFTP sessions need a LAN or Tailscale endpoint; the Cloudflare relay is read-only for Nexus Desktop.")?
        .clone();
    let key = if debian {
        d.write_key_path.clone().filter(|p| !p.trim().is_empty()).ok_or("Set a separate write key for this device in the device editor first.")?
    } else {
        d.key_path.clone().filter(|p| !p.trim().is_empty()).unwrap_or_else(|| app.s.ssh.key_path.clone())
    };
    if !std::path::Path::new(&key).is_file() {
        return Err(format!("SSH key not found at {key}"));
    }
    // These become OpenSSH arguments: refuse anything that could parse as an option.
    let ok = |s: &str| !s.is_empty() && !s.starts_with('-') && !s.chars().any(|c| c.is_whitespace() || c.is_control() || c == '@');
    if !ok(&e.host) || !ok(&d.username) {
        return Err("Invalid host or user name for an SSH session".into());
    }
    let label = match remote {
        Some(cmd) => format!("{cmd} on {}", e.host),
        None => format!("{} {}@{}", if sftp { "sftp" } else { "ssh" }, d.username, e.host),
    };
    let target = Target::Host { key: d.id.to_string() };
    let cap = if remote.is_some() { Capability::ExecuteArbitraryCommand } else { Capability::InteractiveShell };
    app.engine.authorize(&Operation::user(target, cap, &label)).map_err(|e| e.to_string())?;
    let mut args: Vec<String> = ["-i", key.as_str(), "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=ask"].iter().map(|s| s.to_string()).collect();
    if sftp {
        args.extend(["-P".to_string(), e.port.to_string()]);
    } else {
        args.extend(["-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-p"].iter().map(|s| s.to_string()));
        args.push(e.port.to_string());
    }
    if remote.is_some() {
        args.push("-t".into());
    }
    args.push(format!("{}@{}", d.username, e.host));
    // Fixed command strings only (never user or model text).
    if let Some(cmd) = remote {
        args.push("--".into());
        args.extend(cmd.split(' ').map(String::from));
    }
    // OpenSSH from PATH (the Nix wrapper puts nixpkgs' OpenSSH there).
    let exe = if sftp { "sftp" } else { "ssh" };
    let program = nexus_core::platform::which(exe).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| exe.to_string());
    let cwd = nexus_core::platform::home_dir();
    let id = app.ide.spawn_terminal(nexus_terminal::ShellKind::Custom { program, args, label }, &cwd)?;
    if debian {
        app.ide.debian_terms.push(id);
    }
    app.s.layout.show_bottom = true;
    app.screen = crate::app::Screen::Ide;
    Ok(())
}

// ===================================================================== Modals

pub fn modals(app: &mut NexusApp, ctx: &egui::Context) {
    let t = app.s.tokens.clone();
    // Typed confirmation for nixos-rebuild switch.
    if let (Some(mut typed), Some(d)) = (app.infra.nixos_switch_prompt.clone(), app.infra.editing_switch.clone()) {
        let mut done: Option<bool> = None;
        egui::Modal::new(crate::app::gid("nixos_switch")).show(ctx, |ui| {
            ui.set_width(500.0);
            ui.label(RichText::new(format!("Run nixos-rebuild switch on {}?", d.name)).strong().size(16.0).color(t.warning()));
            ui.add(egui::Label::new(RichText::new("This builds and activates the current configuration on the host, which can restart services. Run dry-build first if unsure. sudo will ask for its password in the terminal.").size(12.5)).wrap());
            ui.label("Type switch to continue:");
            ui.add(egui::TextEdit::singleline(&mut typed).desired_width(160.0)).request_focus();
            ui.horizontal(|ui| {
                if ui.add_enabled(typed.trim() == "switch", egui::Button::new("Open terminal")).clicked() {
                    done = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    done = Some(false);
                }
            });
        });
        match done {
            Some(true) => {
                app.infra.nixos_switch_prompt = None;
                app.infra.editing_switch = None;
                if let Err(e) = open_ssh_terminal(app, &d, false, false, Some("sudo nixos-rebuild switch")) {
                    app.toast(e, t.error());
                }
            }
            Some(false) => {
                app.infra.nixos_switch_prompt = None;
                app.infra.editing_switch = None;
            }
            None => app.infra.nixos_switch_prompt = Some(typed),
        }
    }
    // Owner unlock of Debian writes.
    if let Some(mut typed) = app.infra.unlock_prompt.clone() {
        let mut done: Option<bool> = None;
        egui::Modal::new(crate::app::gid("debian_unlock")).show(ctx, |ui| {
            ui.set_width(540.0);
            ui.label(RichText::new("Unlock Debian writes?").strong().size(16.0).color(t.error()));
            for l in [
                "• For 30 minutes you (not agents) may write files, run commands and open a shell on Debian from Nexus Desktop. Agents in every mode, Bypass included, stay read-only.",
                "• Write sessions use direct SSH (LAN/Tailscale) with the device's separate write key; OpenSSH asks for its passphrase, which Nexus never stores.",
                "• Deleting files and service control still ask for a separate one-time approval.",
                "• Write terminals close when the unlock ends. Every unlock and session is in the audit log.",
            ] {
                ui.add(egui::Label::new(RichText::new(l).size(12.5)).wrap());
            }
            ui.add_space(6.0);
            ui.label(format!("Type {} to continue:", nexus_security::policy::DEBIAN_UNLOCK_PHRASE));
            ui.add(egui::TextEdit::singleline(&mut typed).desired_width(200.0)).request_focus();
            ui.horizontal(|ui| {
                if ui.add_enabled(typed.trim() == nexus_security::policy::DEBIAN_UNLOCK_PHRASE, egui::Button::new(RichText::new("Unlock for 30 minutes").color(t.error()))).clicked() {
                    done = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    done = Some(false);
                }
            });
        });
        match done {
            Some(true) => {
                if let Err(e) = app.engine.unlock_debian(&typed, nexus_security::policy::DEBIAN_UNLOCK_DURATION) {
                    app.toast(e.to_string(), t.error());
                }
                app.infra.unlock_prompt = None;
            }
            Some(false) => app.infra.unlock_prompt = None,
            None => app.infra.unlock_prompt = Some(typed),
        }
    }
    // First-use host key confirmation.
    if let Some((dev, authority, fp, mut verified)) = app.infra.pending_hostkey.clone() {
        let mut decided: Option<bool> = None;
        egui::Modal::new(crate::app::gid("hostkey")).show(ctx, |ui| {
            ui.set_width(520.0);
            ui.label(RichText::new("Verify host key").text_style(egui::TextStyle::Name("title".into())));
            ui.label(format!("First connection to {authority}. The server presented:"));
            ui.label(RichText::new(&fp).monospace().color(t.accent()));
            ui.label(secondary(&t, "Compare it with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the server or another trusted channel. Trust on first use alone cannot prove identity."));
            ui.checkbox(&mut verified, "I verified this fingerprint out of band");
            ui.horizontal(|ui| {
                if ui.add(nexus_ui::AccentButton { text: "Trust and connect", enabled: verified }).clicked() {
                    decided = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    decided = Some(false);
                }
            });
        });
        app.infra.pending_hostkey = Some((dev.clone(), authority.clone(), fp.clone(), verified));
        if let Some(ok) = decided {
            app.infra.pending_hostkey = None;
            if ok {
                let r = app.infra.pins.lock().unwrap().confirm_first_use(&authority, &fp);
                if r.is_ok() {
                    app.infra.save_pins();
                    if let Some(d) = app.s.devices.iter().find(|d| d.id.to_string() == dev).cloned() {
                        let r = app.infra.run(&app.rt, &app.engine, &app.s, &d, Job::Catalog(CatalogCommand::Metrics)).map(|_| String::new());
                        app.report(r);
                    }
                }
            }
        }
    }
    // Passphrase entry.
    if let Some(mut p) = app.infra.passphrase_prompt.clone() {
        let mut done: Option<bool> = None;
        egui::Modal::new(crate::app::gid("passphrase")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.label(RichText::new("SSH key passphrase").text_style(egui::TextStyle::Name("title".into())));
            ui.add(egui::TextEdit::singleline(&mut p).password(true).desired_width(f32::INFINITY));
            ui.label(secondary(&t, "Stored in the Secret Service keystore (KWallet or GNOME Keyring) (service NexusDesktop)."));
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    done = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    done = Some(false);
                }
            });
        });
        match done {
            Some(true) => {
                match secrets::set("ssh-passphrase", &p) {
                    Ok(()) => {
                        app.s.ssh.has_passphrase = true;
                        app.infra.passphrase = Some(p);
                        app.s.save();
                    }
                    Err(e) => app.toast(e, t.error()),
                }
                app.infra.passphrase_prompt = None;
            }
            Some(false) => app.infra.passphrase_prompt = None,
            None => app.infra.passphrase_prompt = Some(p),
        }
    }
    // Device editor.
    if let Some(mut d) = app.infra.editing.clone() {
        let mut done: Option<bool> = None;
        egui::Modal::new(crate::app::gid("device_editor")).show(ctx, |ui| {
            ui.set_width(640.0);
            ui.label(RichText::new("Device").text_style(egui::TextStyle::Name("title".into())));
            egui::Grid::new("dev_form").num_columns(2).spacing(vec2(10.0, 8.0)).show(ui, |ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut d.name);
                ui.end_row();
                ui.label("SSH username");
                ui.text_edit_singleline(&mut d.username);
                ui.end_row();
                ui.label("Role");
                let mut role = d.role.unwrap_or(d.inferred_role());
                egui::ComboBox::from_id_salt("role").selected_text(role.to_string()).show_ui(ui, |ui| {
                    for r in [HostRole::Debian, HostRole::Nixos, HostRole::Windows, HostRole::Other] {
                        ui.selectable_value(&mut role, r, r.to_string());
                    }
                });
                d.role = Some(role);
                ui.end_row();
            });
            if nexus_security::policy::ProtectedRegistry::is_debian_device(&d) {
                ui.add(egui::Label::new(RichText::new("This device is treated as the Debian server: read-only by default and always read-only for agents. You can unlock owner writes for 30 minutes from the device card. Changing the role or name does not lift this once it has been seen.").small().color(t.warning())).wrap());
            }
            ui.separator();
            key_section(ui, &t, &mut d, &mut app.toasts);
            ui.separator();
            if nexus_security::policy::ProtectedRegistry::is_debian_device(&d) {
                write_key_section(ui, &t, &mut d, &mut app.toasts);
            } else {
                let target = Target::Host { key: d.id.to_string() };
                let mut allowed = app.engine.policy(&target).user.contains(&Capability::InteractiveShell);
                if ui.checkbox(&mut allowed, "Allow me to open SSH and SFTP sessions on this host (agents stay read-only)").changed() {
                    let mut p = HostPolicy::read_only();
                    if allowed {
                        p.user.extend(OWNER_SESSION_CAPS);
                    }
                    if app.engine.set_policy(target.clone(), p.clone()).is_ok() {
                        app.s.policies.insert(serde_json::to_string(&target).unwrap_or_default(), p);
                        app.s.save();
                    }
                }
            }
            ui.separator();
            ui.label(RichText::new("Endpoints (tried in order)").strong());
            let mut remove = None;
            for (i, e) in d.endpoints.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt(("kind", i)).selected_text(format!("{:?}", e.kind)).width(90.0).show_ui(ui, |ui| {
                        ui.selectable_value(&mut e.kind, EndpointKind::Lan, "Lan");
                        ui.selectable_value(&mut e.kind, EndpointKind::Tailscale, "Tailscale");
                        ui.selectable_value(&mut e.kind, EndpointKind::Cloudflare, "Cloudflare");
                    });
                    if e.kind == EndpointKind::Cloudflare {
                        let mut rt = e.relay_target.clone().unwrap_or_default();
                        egui::ComboBox::from_id_salt(("relay", i)).selected_text(if rt.is_empty() { "relay target".to_string() } else { rt.clone() }).width(80.0).show_ui(ui, |ui| {
                            for tgt in nexus_ssh::relay::TARGETS {
                                ui.selectable_value(&mut rt, tgt.to_string(), tgt);
                            }
                        });
                        e.relay_target = Some(rt).filter(|r| !r.is_empty());
                        if e.port == 22 {
                            e.port = 443;
                        }
                    }
                    ui.add(egui::TextEdit::singleline(&mut e.host).hint_text("host or IP").desired_width(if e.kind == EndpointKind::Cloudflare { 240.0 } else { 330.0 }));
                    let mut port = e.port as i32;
                    ui.add(egui::DragValue::new(&mut port).range(1..=65535));
                    e.port = port as u16;
                    e.priority = i as i32;
                    if ui.small_button(icon(icons::DELETE, 11.0)).clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(i) = remove {
                d.endpoints.remove(i);
            }
            if ui.small_button("+ endpoint").clicked() {
                d.endpoints.push(Endpoint { id: uuid::Uuid::new_v4(), host: String::new(), port: 22, kind: EndpointKind::Lan, priority: d.endpoints.len() as i32, relay_target: None });
            }
            let valid = d.validate();
            if let Err(e) = &valid {
                ui.label(RichText::new(e.to_string()).small().color(t.error()));
            }
            ui.horizontal(|ui| {
                if ui.add(nexus_ui::AccentButton { text: "Save", enabled: valid.is_ok() }).clicked() {
                    done = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    done = Some(false);
                }
            });
        });
        match done {
            Some(true) => {
                app.engine.register_device(&d);
                match app.s.devices.iter_mut().find(|x| x.id == d.id) {
                    Some(x) => *x = d,
                    None => app.s.devices.push(d),
                }
                app.s.save();
                app.infra.editing = None;
            }
            Some(false) => app.infra.editing = None,
            None => app.infra.editing = Some(d),
        }
    }
    if app.infra.minecraft_confirm {
        egui::Modal::new(crate::app::gid("mc")).show(ctx, |ui| {
            ui.set_width(460.0);
            ui.label(RichText::new("Open the Minecraft panel?").text_style(egui::TextStyle::Name("title".into())));
            ui.label("The panel opens in your web browser behind Cloudflare Access and its own login. Actions taken in the panel (such as power controls) change the Debian server and are outside Nexus Desktop's read-only enforcement.");
            ui.horizontal(|ui| {
                if ui.button("Open in browser").clicked() {
                    let _ = nexus_core::platform::open_url(&format!("{}/", nexus_core::site::site().gateway_url()));
                    app.infra.minecraft_confirm = false;
                }
                if ui.button("Cancel").clicked() {
                    app.infra.minecraft_confirm = false;
                }
            });
        });
    }
    let _ = white_a(0.0);
}

#[cfg(test)]
mod probe_tests {
    #[test]
    fn probe_reports_tcp_success_and_failure_locally() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut ok = nexus_core::Device::suggestions()[0].endpoints[0].clone();
        ok.host = "127.0.0.1".into();
        ok.port = port;
        drop(std::mem::replace(&mut ok.relay_target, None));
        let mut closed = ok.clone();
        drop(l);
        let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ok.port = l2.local_addr().unwrap().port();
        closed.port = port;
        let r = super::probe_endpoints(&[ok, closed], std::time::Duration::from_secs(2));
        let lines: Vec<&str> = r.lines().collect();
        assert!(lines[0].contains("TCP connected"), "{r}");
        assert!(lines[1].contains("TCP failed"), "{r}");
    }
}
