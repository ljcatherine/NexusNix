//! Application shell: navigation, global shortcuts, command palette, toasts.

use crate::ai::AiState;
use crate::ide::IdeState;
use crate::infra::InfraState;
use crate::settings::{data_dir, Settings};
use egui::{pos2, vec2, Align, Align2, Color32, CornerRadius, FontId, Key, KeyboardShortcut, Layout, Modifiers, Rect, RichText, Sense, Ui};
use nexus_security::audit::{AuditSink, FileAudit};
use nexus_security::policy::PolicyEngine;
use nexus_ui::{icons, paint_backdrop, paint_glass, white_a, Tokens};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Devices,
    Ide,
    Infrastructure,
    Settings,
}

impl Screen {
    const ALL: [(Screen, char, &'static str); 5] = [
        (Screen::Dashboard, icons::HOME, "Dashboard"),
        (Screen::Devices, icons::DEVICES, "Devices"),
        (Screen::Ide, icons::CODE, "IDE"),
        (Screen::Infrastructure, icons::NETWORK, "Infrastructure"),
        (Screen::Settings, icons::SETTINGS, "Settings"),
    ];
}

/// Stable global id from a hashable value.
pub fn gid(v: impl std::hash::Hash + std::fmt::Debug) -> egui::Id {
    #[allow(deprecated)]
    egui::Id::new(v)
}

pub struct Toast {
    pub text: String,
    pub color: Color32,
    pub at: Instant,
}

/// Commands available from the palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    OpenFolder,
    QuickOpen,
    Save,
    SaveAll,
    CloseTab,
    ToggleExplorer,
    ToggleAi,
    ToggleBottom,
    NewTerminal,
    WorkspaceSearch,
    SourceControl,
    InlineEdit,
    NewChat,
    RunCheck,
    RunTests,
    SplitEditor,
    CompactNav,
    GoDashboard,
    GoDevices,
    GoIde,
    GoInfra,
    GoSettings,
    VerifyProviders,
    AuditLog,
}

const COMMANDS: &[(Command, &str, &str)] = &[
    (Command::OpenFolder, "Open Folder…", "Ctrl+O"),
    (Command::QuickOpen, "Go to File…", "Ctrl+P"),
    (Command::Save, "Save", "Ctrl+S"),
    (Command::SaveAll, "Save All", "Ctrl+Shift+S"),
    (Command::CloseTab, "Close Editor", "Ctrl+W"),
    (Command::ToggleExplorer, "Toggle Sidebar", "Ctrl+B"),
    (Command::ToggleAi, "Toggle AI Panel", "Ctrl+L"),
    (Command::ToggleBottom, "Toggle Panel", "Ctrl+J"),
    (Command::NewTerminal, "New Terminal", "Ctrl+Shift+`"),
    (Command::WorkspaceSearch, "Search in Workspace", "Ctrl+Shift+F"),
    (Command::SourceControl, "Source Control", "Ctrl+Shift+G"),
    (Command::InlineEdit, "Inline AI Edit", "Ctrl+K"),
    (Command::NewChat, "New Agent Chat", "Ctrl+Shift+L"),
    (Command::RunCheck, "Run Build / Check", "Ctrl+Shift+B"),
    (Command::RunTests, "Run Tests", ""),
    (Command::SplitEditor, "Split Editor", "Ctrl+\\"),
    (Command::CompactNav, "Toggle Compact Navigation", ""),
    (Command::GoDashboard, "Go to Dashboard", "Alt+1"),
    (Command::GoDevices, "Go to Devices", "Alt+2"),
    (Command::GoIde, "Go to IDE", "Alt+3"),
    (Command::GoInfra, "Go to Infrastructure", "Alt+4"),
    (Command::GoSettings, "Go to Settings", "Alt+5"),
    (Command::VerifyProviders, "Verify AI Providers", ""),
    (Command::AuditLog, "Show Security Audit Log", ""),
];

pub struct NexusApp {
    pub s: Settings,
    pub engine: PolicyEngine,
    pub audit: Arc<dyn AuditSink>,
    pub screen: Screen,
    pub ide: IdeState,
    pub ai: AiState,
    pub infra: InfraState,
    pub access: crate::access::Access,
    pub toasts: Vec<Toast>,
    pub rt: tokio::runtime::Runtime,
    palette: Option<(String, usize)>,
    styled_title: bool,
    applied_tokens: Option<String>,
    pub show_audit: bool,
    last_save: Instant,
    frames: u64,
    pub lock: crate::lock::AppLock,
}

impl NexusApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let s = Settings::load();
        nexus_ui::install_fonts(&cc.egui_ctx);
        s.tokens.apply(&cc.egui_ctx);
        // Never fall back to memory-only auditing: the resilient sink queues and
        // retries if the file is temporarily unavailable, and reports it.
        let audit: Arc<dyn AuditSink> = Arc::new(FileAudit::open_resilient(data_dir().join("audit.jsonl")));
        let engine = PolicyEngine::new(audit.clone());
        for d in &s.devices {
            engine.register_device(d);
        }
        for (k, p) in &s.policies {
            if let Ok(t) = serde_json::from_str(k) {
                // Refused (and audited) for Debian/gateway targets.
                let _ = engine.set_policy(t, p.clone());
            }
        }
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("nexus-io").build().expect("tokio runtime");
        let ctx = cc.egui_ctx.clone();
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || ctx.request_repaint());
        let ai = AiState::new(&s, wake.clone());
        let access = crate::access::Access::new(wake.clone(), s.access_memory_only);
        let infra = InfraState::new(&s, wake.clone(), access.handle.clone());
        let ide = IdeState::new(wake);
        let mut app = Self {
            lock: crate::lock::AppLock::new(s.app_lock),
            screen: Screen::Dashboard,
            ide,
            ai,
            infra,
            access,
            toasts: Vec::new(),
            rt,
            palette: None,
            styled_title: false,
            applied_tokens: None,
            show_audit: false,
            last_save: Instant::now(),
            frames: 0,
            engine,
            audit,
            s,
        };
        if let Some(last) = app.s.recent_workspaces.first().cloned() {
            if std::path::Path::new(&last).is_dir() {
                app.open_workspace(std::path::PathBuf::from(last));
                app.screen = Screen::Ide;
            }
        }
        app.ai.verify_all();
        app
    }

    pub fn toast(&mut self, text: impl Into<String>, color: Color32) {
        self.toasts.push(Toast { text: text.into(), color, at: Instant::now() });
    }

    pub fn tokens(&self) -> &Tokens {
        &self.s.tokens
    }

    pub fn open_workspace(&mut self, path: std::path::PathBuf) {
        match self.ide.open_workspace(&path, &self.engine) {
            Ok(()) => {
                self.s.add_recent(&path.to_string_lossy());
                self.s.save();
                self.ai.on_workspace(self.ide.workspace.as_ref());
                self.screen = Screen::Ide;
            }
            Err(e) => self.toast(format!("Could not open folder: {e}"), self.s.tokens.error()),
        }
    }

    pub fn run(&mut self, cmd: Command, ctx: &egui::Context) {
        match cmd {
            Command::OpenFolder => {
                if let Some(p) = rfd::FileDialog::new().set_title("Open Folder").pick_folder() {
                    self.open_workspace(p);
                }
            }
            Command::QuickOpen => {
                self.screen = Screen::Ide;
                self.ide.open_quick_open();
            }
            Command::Save => {
                let r = self.ide.save_active(&self.engine);
                self.report(r);
            }
            Command::SaveAll => {
                let r = self.ide.save_all(&self.engine);
                self.report(r);
            }
            Command::CloseTab => self.ide.close_active(),
            Command::ToggleExplorer => self.s.layout.show_explorer = !self.s.layout.show_explorer,
            Command::ToggleAi => self.s.layout.show_ai = !self.s.layout.show_ai,
            Command::ToggleBottom => self.s.layout.show_bottom = !self.s.layout.show_bottom,
            Command::NewTerminal => {
                self.screen = Screen::Ide;
                self.s.layout.show_bottom = true;
                let r = self.ide.new_terminal(nexus_terminal::ShellKind::Login, &self.engine);
                self.report(r);
            }
            Command::WorkspaceSearch => {
                self.screen = Screen::Ide;
                self.s.layout.show_explorer = true;
                self.ide.left = crate::ide::LeftTab::Search;
            }
            Command::SourceControl => {
                self.screen = Screen::Ide;
                self.s.layout.show_explorer = true;
                self.ide.left = crate::ide::LeftTab::Git;
            }
            Command::InlineEdit => self.ai.begin_inline(&self.ide),
            Command::NewChat => {
                self.s.layout.show_ai = true;
                self.ai.new_chat();
            }
            Command::RunCheck => {
                self.s.layout.show_bottom = true;
                let r = self.ide.run_task(crate::ide::TaskKind::Check, &self.engine);
                self.report(r);
            }
            Command::RunTests => {
                self.s.layout.show_bottom = true;
                let r = self.ide.run_task(crate::ide::TaskKind::Test, &self.engine);
                self.report(r);
            }
            Command::SplitEditor => self.ide.toggle_split(),
            Command::CompactNav => self.s.layout.compact_nav = !self.s.layout.compact_nav,
            Command::GoDashboard => self.screen = Screen::Dashboard,
            Command::GoDevices => self.screen = Screen::Devices,
            Command::GoIde => self.screen = Screen::Ide,
            Command::GoInfra => self.screen = Screen::Infrastructure,
            Command::GoSettings => self.screen = Screen::Settings,
            Command::VerifyProviders => self.ai.verify_all(),
            Command::AuditLog => self.show_audit = true,
        }
        ctx.request_repaint();
    }

    pub fn report(&mut self, r: Result<String, String>) {
        match r {
            Ok(m) if !m.is_empty() => self.toast(m, self.s.tokens.success()),
            Ok(_) => {}
            Err(e) => self.toast(e, self.s.tokens.error()),
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let ctrl = Modifiers::COMMAND;
        let cs = Modifiers::COMMAND | Modifiers::SHIFT;
        let map: &[(Modifiers, Key, Command)] = &[
            (cs, Key::P, Command::QuickOpen), // placeholder replaced below
            (ctrl, Key::O, Command::OpenFolder),
            (cs, Key::S, Command::SaveAll),
            (ctrl, Key::W, Command::CloseTab),
            (ctrl, Key::B, Command::ToggleExplorer),
            (ctrl, Key::L, Command::ToggleAi),
            (ctrl, Key::J, Command::ToggleBottom),
            (cs, Key::F, Command::WorkspaceSearch),
            (cs, Key::G, Command::SourceControl),
            (cs, Key::L, Command::NewChat),
            (cs, Key::B, Command::RunCheck),
            (ctrl, Key::Backslash, Command::SplitEditor),
            (cs, Key::Backtick, Command::NewTerminal),
            (Modifiers::ALT, Key::Num1, Command::GoDashboard),
            (Modifiers::ALT, Key::Num2, Command::GoDevices),
            (Modifiers::ALT, Key::Num3, Command::GoIde),
            (Modifiers::ALT, Key::Num4, Command::GoInfra),
            (Modifiers::ALT, Key::Num5, Command::GoSettings),
        ];
        if ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(cs, Key::P))) {
            self.palette = Some((String::new(), 0));
            return;
        }
        if ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(ctrl, Key::P))) {
            self.run(Command::QuickOpen, ctx);
            return;
        }
        for (m, k, c) in map.iter().skip(1) {
            if ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(*m, *k))) {
                self.run(*c, ctx);
            }
        }
        if ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(ctrl, Key::Backtick))) {
            self.s.layout.show_bottom = !self.s.layout.show_bottom;
        }
        if ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(Modifiers::CTRL, Key::Tab))) {
            self.ide.next_tab(1);
        }
        if ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(Modifiers::CTRL | Modifiers::SHIFT, Key::Tab))) {
            self.ide.next_tab(-1);
        }
    }

    fn nav_rail(&mut self, ui: &mut Ui) {
        let t = self.s.tokens.clone();
        let compact = self.s.layout.compact_nav || self.screen == Screen::Ide && ui.available_width() < 1200.0;
        let w = if compact { 52.0 } else { 86.0 };
        let full = ui.max_rect();
        let rail = Rect::from_min_size(full.min + vec2(8.0, 8.0), vec2(w, full.height() - 16.0));
        paint_glass(ui.painter(), rail, 18.0, &t, false);
        let mut y = rail.top() + 14.0;
        // Brand mark
        ui.painter().text(pos2(rail.center().x, y + 10.0), Align2::CENTER_CENTER, "N", FontId::new(20.0, egui::FontFamily::Name("semibold".into())), t.accent());
        y += 40.0;
        for (screen, glyph, label) in Screen::ALL {
            let h = if compact { 42.0 } else { 56.0 };
            let r = Rect::from_min_size(pos2(rail.left() + 6.0, y), vec2(w - 12.0, h));
            let resp = ui.interact(r, ui.scope_id().with(("nav", label)), Sense::click()).on_hover_text(label);
            let active = self.screen == screen;
            let anim = ui.ctx().animate_bool_with_time(ui.scope_id().with(("nav_a", label)), active, if t.reduce_motion { 0.0 } else { 0.18 });
            if anim > 0.0 {
                ui.painter().rect_filled(r, CornerRadius::same(12), white_a(0.10 * anim));
                ui.painter().rect_filled(Rect::from_min_size(pos2(r.left() - 3.0, r.center().y - 9.0), vec2(3.0, 18.0)), CornerRadius::same(2), t.accent().gamma_multiply(anim));
            } else if resp.hovered() {
                ui.painter().rect_filled(r, CornerRadius::same(12), white_a(0.05));
            }
            let col = if active { t.text() } else { t.text2() };
            let gy = if compact { r.center().y } else { r.top() + 20.0 };
            ui.painter().text(pos2(r.center().x, gy), Align2::CENTER_CENTER, glyph.to_string(), FontId::new(18.0, egui::FontFamily::Name("icons".into())), if active { t.accent() } else { col });
            if !compact {
                ui.painter().text(pos2(r.center().x, r.bottom() - 11.0), Align2::CENTER_CENTER, label, FontId::proportional(10.0), col);
            }
            if resp.clicked() {
                self.screen = screen;
            }
            y += h + 4.0;
        }
        // Bottom: policy shield indicator
        let shield = Rect::from_center_size(pos2(rail.center().x, rail.bottom() - 26.0), vec2(36.0, 36.0));
        let resp = ui.interact(shield, ui.scope_id().with("shield"), Sense::click()).on_hover_text("Debian is read-only. Click for the security audit log.");
        ui.painter().text(shield.center(), Align2::CENTER_CENTER, icons::SHIELD.to_string(), FontId::new(17.0, egui::FontFamily::Name("icons".into())), t.success());
        if resp.clicked() {
            self.show_audit = true;
        }
        ui.advance_cursor_after_rect(Rect::from_min_size(full.min, vec2(w + 16.0, full.height())));
    }

    fn palette_ui(&mut self, ctx: &egui::Context) {
        let Some((mut q, mut sel)) = self.palette.take() else { return };
        let t = self.s.tokens.clone();
        let mut run: Option<Command> = None;
        let mut close = false;
        let screen = ctx.content_rect();
        egui::Area::new(crate::app::gid("palette")).order(egui::Order::Foreground).fixed_pos(pos2(screen.center().x - 300.0, screen.top() + 70.0)).show(ctx, |ui| {
            egui::Frame::popup(ui.style()).fill(t.surface().gamma_multiply(0.98)).corner_radius(CornerRadius::same(14)).inner_margin(10).show(ui, |ui| {
                ui.set_width(600.0);
                let r = ui.add(egui::TextEdit::singleline(&mut q).hint_text("Type a command").desired_width(f32::INFINITY).font(FontId::proportional(15.0)));
                r.request_focus();
                let ql = q.to_lowercase();
                let items: Vec<&(Command, &str, &str)> = COMMANDS.iter().filter(|(_, n, _)| ql.split_whitespace().all(|w| n.to_lowercase().contains(w))).collect();
                if ui.input(|i| i.key_pressed(Key::ArrowDown)) {
                    sel = (sel + 1).min(items.len().saturating_sub(1));
                }
                if ui.input(|i| i.key_pressed(Key::ArrowUp)) {
                    sel = sel.saturating_sub(1);
                }
                ui.add_space(6.0);
                egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                    for (i, (c, name, keys)) in items.iter().enumerate() {
                        let resp = ui.add_sized([ui.available_width(), 28.0], egui::Button::selectable(i == sel, "").frame_when_inactive(false));
                        let rect = resp.rect;
                        ui.painter().text(rect.left_center() + vec2(10.0, 0.0), Align2::LEFT_CENTER, *name, FontId::proportional(13.5), t.text());
                        ui.painter().text(rect.right_center() - vec2(10.0, 0.0), Align2::RIGHT_CENTER, *keys, FontId::monospace(11.5), t.text2());
                        if resp.clicked() {
                            run = Some(*c);
                        }
                    }
                });
                if ui.input(|i| i.key_pressed(Key::Enter)) {
                    run = items.get(sel).map(|x| x.0);
                }
                if ui.input(|i| i.key_pressed(Key::Escape)) {
                    close = true;
                }
            });
        });
        if let Some(c) = run {
            self.run(c, ctx);
        } else if !close {
            self.palette = Some((q, sel));
        }
    }

    fn toasts_ui(&mut self, ctx: &egui::Context) {
        self.toasts.retain(|t| t.at.elapsed().as_secs_f32() < 6.0);
        let screen = ctx.content_rect();
        let t = self.s.tokens.clone();
        for (i, toast) in self.toasts.iter().enumerate() {
            let age = toast.at.elapsed().as_secs_f32();
            let alpha = if t.reduce_motion { 1.0 } else { (age * 6.0).min(1.0).min((6.0 - age) * 2.0).clamp(0.0, 1.0) };
            egui::Area::new(crate::app::gid(("toast", i))).order(egui::Order::Tooltip).anchor(Align2::RIGHT_BOTTOM, vec2(-20.0, -36.0 - i as f32 * 52.0)).show(ctx, |ui| {
                ui.set_opacity(alpha);
                egui::Frame::popup(ui.style()).fill(t.elevated()).corner_radius(CornerRadius::same(12)).show(ui, |ui| {
                    ui.set_max_width(420.0);
                    ui.horizontal(|ui| {
                        nexus_ui::dot(ui, toast.color);
                        ui.label(RichText::new(&toast.text).color(t.text()));
                    });
                });
            });
            let _ = screen;
        }
        if !self.toasts.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }

    /// Self-capture for visual QA: `NEXUS_SCREENSHOT=out.png` with optional
    /// `NEXUS_SCREEN=dashboard|devices|ide|infra|settings` and
    /// `NEXUS_OPEN_FILE=<relative path>` renders, saves a PNG and exits.
    fn capture(&mut self, ctx: &egui::Context) {
        let Ok(out) = std::env::var("NEXUS_SCREENSHOT") else { return };
        self.frames += 1;
        if self.frames == 1 {
            self.screen = match std::env::var("NEXUS_SCREEN").unwrap_or_default().as_str() {
                "devices" => Screen::Devices,
                "ide" => Screen::Ide,
                "infra" => Screen::Infrastructure,
                "settings" => Screen::Settings,
                _ => Screen::Dashboard,
            };
            if let Ok(d) = std::env::var("NEXUS_OPEN_DIR") {
                self.open_workspace(std::path::PathBuf::from(d));
            }
            if let Ok(f) = std::env::var("NEXUS_OPEN_FILE") {
                let _ = self.ide.open_file(&f, &self.engine);
            }
            if std::env::var("NEXUS_BYPASS_PROMPT").is_ok() {
                self.ai.bypass_prompt = Some(String::new());
            }
            if let Ok(u) = std::env::var("NEXUS_EDIT_DEVICE") {
                self.infra.editing = self.s.devices.iter().find(|d| d.username == u).cloned();
            }
            if std::env::var("NEXUS_TERMINAL").is_ok() {
                let _ = self.ide.new_terminal(nexus_terminal::ShellKind::Login, &self.engine);
            }
        }
        ctx.request_repaint();
        let at: u64 = std::env::var("NEXUS_FRAMES").ok().and_then(|v| v.parse().ok()).unwrap_or(90);
        if self.frames == at {
            let c2 = ctx.clone();
            ctx.request_screenshot(move |img| {
                let [w, h] = img.size;
                let bytes: Vec<u8> = img.pixels.iter().flat_map(|p| p.to_array()).collect();
                if let Some(buf) = image::RgbaImage::from_raw(w as u32, h as u32, bytes) {
                    let _ = buf.save(&out);
                }
                c2.send_viewport_cmd(egui::ViewportCommand::Close);
                c2.request_repaint();
            });
        }
    }

    fn audit_ui(&mut self, ctx: &egui::Context) {
        if !self.show_audit {
            return;
        }
        let t = self.s.tokens.clone();
        let events = self.audit.recent(300);
        let mut open = true;
        egui::Window::new("Security audit log").open(&mut open).default_size([760.0, 480.0]).show(ctx, |ui| {
            ui.label(nexus_ui::secondary(&t, "Every authorization decision (allowed and denied). Debian's policy is fixed read-only in code."));
            ui.label(nexus_ui::secondary(&t, format!("Full log: {}", data_dir().join("audit.jsonl").display())));
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("audit").striped(true).num_columns(4).show(ui, |ui| {
                    for e in events {
                        let (txt, col) = match &e.outcome {
                            nexus_security::audit::Outcome::Allowed => ("allowed".to_string(), t.success()),
                            nexus_security::audit::Outcome::AllowedEscalated => ("escalated".to_string(), t.warning()),
                            nexus_security::audit::Outcome::EscalationApproved => ("approved".to_string(), t.warning()),
                            nexus_security::audit::Outcome::Denied(r) => (format!("denied: {r}"), t.error()),
                        };
                        ui.label(RichText::new(e.at.get(11..19).unwrap_or(&e.at)).monospace().color(t.text2()));
                        ui.label(e.capability.map(|c| c.label()).unwrap_or("policy"));
                        ui.label(RichText::new(&e.summary).monospace());
                        ui.label(RichText::new(txt).color(col));
                        ui.end_row();
                    }
                });
            });
        });
        self.show_audit = open;
    }
}

impl eframe::App for NexusApp {
    /// eframe 0.37 runs no `ui` pass while the window is minimised, only this,
    /// so the minimise lock must be applied here as well as in `ui`.
    /// Verified on X11/XWayland (KWin): `minimized` reads `Some(true)` here.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.s.app_lock && ctx.input(|i| i.viewport().minimized) == Some(true) {
            self.lock.lock();
        }
    }

    fn ui(&mut self, ui: &mut Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if !self.styled_title {
            crate::win::style_title_bar(frame);
            self.styled_title = true;
        }
        if self.s.app_lock && ctx.input(|i| i.viewport().minimized) == Some(true) {
            self.lock.lock();
        }
        let tok_key = serde_json::to_string(&self.s.tokens).unwrap_or_default();
        if self.applied_tokens.as_deref() != Some(&tok_key) {
            self.s.tokens.apply(&ctx);
            self.applied_tokens = Some(tok_key);
        }
        self.capture(&ctx);
        self.shortcuts(&ctx);
        self.ai.poll(&mut self.ide, &self.engine, &mut self.toasts, &self.s.tokens);
        self.infra.poll(&self.engine, &mut self.s, &mut self.toasts);
        self.access.poll(&mut self.toasts, self.s.tokens.success(), self.s.tokens.error());
        if self.access.waiting() || self.access.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(400));
        }
        self.ide.poll(&self.s.tokens);
        if self.last_save.elapsed().as_secs() > 10 {
            self.ide.write_recovery();
            self.last_save = Instant::now();
        }

        let t = self.s.tokens.clone();
        paint_backdrop(ui.painter(), ui.max_rect(), &t);
        if self.lock.locked {
            crate::lock::lock_screen(self, ui);
            return;
        }
        let full = ui.max_rect();
        ui.horizontal_top(|ui| {
            ui.set_min_height(full.height());
            self.nav_rail(ui);
            let rest = Rect::from_min_max(pos2(ui.cursor().left(), full.top()), full.max);
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rest).layout(Layout::top_down(Align::Min)));
            match self.screen {
                Screen::Dashboard => crate::infra::dashboard(self, &mut child),
                Screen::Devices => crate::infra::devices(self, &mut child),
                Screen::Ide => crate::ide::ide_screen(self, &mut child),
                Screen::Infrastructure => crate::infra::infrastructure(self, &mut child),
                Screen::Settings => crate::infra::settings_screen(self, &mut child),
            }
        });
        self.palette_ui(&ctx);
        crate::ide::quick_open_ui(self, &ctx);
        crate::ai::inline_ui(self, &ctx);
        crate::ai::bypass_modal(self, &ctx);
        crate::infra::modals(self, &ctx);
        if !self.ide.debian_terms.is_empty() && self.engine.debian_unlocked_for().is_none() {
            let n = self.ide.close_debian_terms();
            if n > 0 {
                self.toast(format!("Debian writes locked; closed {n} write terminal(s)"), self.s.tokens.warning());
            }
        }
        self.audit_ui(&ctx);
        self.toasts_ui(&ctx);
    }

    fn on_exit(&mut self) {
        self.ide.write_recovery();
        self.s.save();
    }
}
