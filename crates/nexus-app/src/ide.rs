//! The IDE screen: explorer, search, source control, editor tabs, bottom panel.

use crate::app::NexusApp;
use crate::settings::local_dir;
use egui::{vec2, Align, Color32, CornerRadius, FontId, Key, Layout, Margin, RichText, Sense, Stroke, Ui};
use nexus_git::{Repo, Status};
use nexus_ide::editor::{self, Diagnostic, Document, GutterMark, Severity};
use nexus_security::policy::{Capability, Operation, PolicyEngine, Target};
use nexus_terminal::{ShellKind, Terminal};
use nexus_ui::{icon, icons, secondary, white_a, Tokens};
use nexus_workspaces::search::{Match, Query};
use nexus_workspaces::shadow::ShadowWorkspace;
use nexus_workspaces::tree::{self, Entry, ListOptions};
use nexus_workspaces::Workspace;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeftTab {
    Explorer,
    Search,
    Git,
    Agents,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BottomTab {
    Terminal,
    Problems,
    Output,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskKind {
    Check,
    Test,
}

pub struct Problem {
    pub rel: String,
    pub line: usize,
    pub col: usize,
    pub severity: Severity,
    pub message: String,
}

pub struct IdeState {
    pub workspace: Option<Workspace>,
    pub shadow: Option<ShadowWorkspace>,
    pub entries: Vec<Entry>,
    pub expanded: HashSet<String>,
    pub docs: Vec<Document>,
    pub active: usize,
    pub split: Option<usize>,
    pub left: LeftTab,
    pub bottom: BottomTab,
    pub terminals: Vec<Terminal>,
    pub active_term: usize,
    next_term_id: u64,
    /// Terminals with write access to Debian; closed when the unlock ends.
    pub debian_terms: Vec<u64>,
    pub query: Query,
    pub replace: String,
    pub results: Vec<Match>,
    pub search_error: Option<String>,
    pub repo: Option<Repo>,
    pub status: Option<Status>,
    pub commit_msg: String,
    pub quick_open: Option<(String, usize)>,
    pub files: Vec<String>,
    pub output: Vec<String>,
    task_rx: Option<Receiver<Option<String>>>,
    pub task_running: Option<String>,
    pub problems: Vec<Problem>,
    /// Files last changed by an AI agent (shown with a marker).
    pub ai_touched: HashSet<String>,
    wake: Arc<dyn Fn() + Send + Sync>,
    pub pending_recovery: Vec<(String, String)>,
}

impl IdeState {
    pub fn new(wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            workspace: None,
            shadow: None,
            entries: Vec::new(),
            expanded: HashSet::new(),
            docs: Vec::new(),
            active: 0,
            split: None,
            left: LeftTab::Explorer,
            bottom: BottomTab::Terminal,
            terminals: Vec::new(),
            active_term: 0,
            next_term_id: 1,
            debian_terms: Vec::new(),
            query: Query { pattern: String::new(), regex: false, case_sensitive: false, whole_word: false, max_results: 2000 },
            replace: String::new(),
            results: Vec::new(),
            search_error: None,
            repo: None,
            status: None,
            commit_msg: String::new(),
            quick_open: None,
            files: Vec::new(),
            output: Vec::new(),
            task_rx: None,
            task_running: None,
            problems: Vec::new(),
            ai_touched: HashSet::new(),
            wake,
            pending_recovery: Vec::new(),
        }
    }

    pub fn target(&self) -> Option<Target> {
        self.workspace.as_ref().map(Workspace::target)
    }

    pub fn open_workspace(&mut self, path: &Path, engine: &PolicyEngine) -> Result<(), String> {
        let ws = Workspace::open(path).map_err(|e| e.to_string())?;
        self.shadow = ShadowWorkspace::load(ws.root()).ok();
        self.docs.clear();
        self.active = 0;
        self.split = None;
        self.expanded.clear();
        self.results.clear();
        self.problems.clear();
        self.repo = Repo::discover(ws.root(), ws.target()).ok();
        self.workspace = Some(ws);
        self.refresh_tree();
        self.refresh_git(engine);
        self.scan_recovery();
        Ok(())
    }

    pub fn refresh_tree(&mut self) {
        if let Some(ws) = &self.workspace {
            self.entries = tree::list(ws.root(), ListOptions { include_hidden: true, ..Default::default() });
            self.entries.retain(|e| !e.rel.starts_with(".git/") && e.rel != ".git");
            self.files = self.entries.iter().filter(|e| !e.is_dir).map(|e| e.rel.clone()).collect();
        }
    }

    pub fn refresh_git(&mut self, engine: &PolicyEngine) {
        let (Some(repo), Some(t)) = (&self.repo, self.target()) else { return };
        if let Ok(g) = engine.authorize(&Operation::user(t, Capability::GitRead, "git status")) {
            self.status = repo.status(&g).ok();
        }
    }

    fn grant(&self, engine: &PolicyEngine, cap: Capability, summary: &str) -> Result<nexus_security::Grant, String> {
        let t = self.target().ok_or("No workspace is open")?;
        engine.authorize(&Operation::user(t, cap, summary)).map_err(|e| e.to_string())
    }

    pub fn open_file(&mut self, rel: &str, engine: &PolicyEngine) -> Result<(), String> {
        if let Some(i) = self.docs.iter().position(|d| d.rel == rel) {
            self.active = i;
            return Ok(());
        }
        let ws = self.workspace.as_ref().ok_or("No workspace is open")?;
        let path = ws.resolve(rel).map_err(|e| e.to_string())?;
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        if meta.len() > 50 * 1024 * 1024 {
            return Err("File is larger than 50 MB".into());
        }
        let g = self.grant(engine, Capability::Read, rel)?;
        let text = ws.read(rel, &g).map_err(|_| "File is not valid UTF-8 text (binary files are not opened)".to_string())?;
        let mut doc = Document::new(rel, Some(path), &text);
        doc.last_disk_hash = Some(nexus_workspaces::sha256_hex(text.as_bytes()));
        self.docs.push(doc);
        self.active = self.docs.len() - 1;
        self.update_gutter(self.active, engine);
        Ok(())
    }

    /// Open a read-only document (remote file, diff, log).
    pub fn open_virtual(&mut self, rel: &str, text: &str, reason: &str) {
        if let Some(i) = self.docs.iter().position(|d| d.rel == rel) {
            self.docs[i].buffer.set_text(text);
            self.docs[i].buffer.mark_saved();
            self.active = i;
            return;
        }
        let mut d = Document::new(rel, None, text);
        d.read_only = true;
        d.read_only_reason = Some(reason.into());
        self.docs.push(d);
        self.active = self.docs.len() - 1;
    }

    pub fn update_gutter(&mut self, idx: usize, engine: &PolicyEngine) {
        let (Some(repo), Some(t)) = (&self.repo, self.target()) else { return };
        let Some(doc) = self.docs.get_mut(idx) else { return };
        if doc.path.is_none() {
            return;
        }
        let Ok(g) = engine.authorize(&Operation::user(t, Capability::GitRead, format!("git show HEAD:{}", doc.rel))) else { return };
        let Some(root_rel) = doc.path.as_ref().and_then(|p| p.strip_prefix(repo.root()).ok()).map(|p| p.to_string_lossy().replace('\\', "/")) else { return };
        let head = match repo.show_head(&g, &root_rel) {
            Ok(h) => h.replace("\r\n", "\n"),
            Err(_) => {
                doc.gutter = (0..doc.buffer.line_count()).map(|l| (l, GutterMark::Added)).collect();
                return;
            }
        };
        let now = doc.buffer.text();
        doc.gutter = gutter_marks(&head, &now);
    }

    pub fn save_active(&mut self, engine: &PolicyEngine) -> Result<String, String> {
        let i = self.active;
        self.save_doc(i, engine)
    }

    fn save_doc(&mut self, i: usize, engine: &PolicyEngine) -> Result<String, String> {
        let Some(doc) = self.docs.get(i) else { return Ok(String::new()) };
        if doc.read_only {
            return Err(doc.read_only_reason.clone().unwrap_or_else(|| "This document is read-only".into()));
        }
        let rel = doc.rel.clone();
        let text = doc.buffer.text_for_save();
        let ws = self.workspace.as_ref().ok_or("No workspace")?;
        // Detect external modification since open/last save.
        if let (Some(p), Some(h)) = (&doc.path, &doc.last_disk_hash) {
            if let Ok(cur) = std::fs::read(p) {
                if &nexus_workspaces::sha256_hex(&cur) != h && nexus_workspaces::sha256_hex(text.as_bytes()) != nexus_workspaces::sha256_hex(&cur) {
                    let changed_by_ai = self.ai_touched.contains(&rel);
                    if !changed_by_ai {
                        return Err(format!("{rel} changed on disk since it was opened. Reload it (close and reopen) before saving to avoid overwriting."));
                    }
                }
            }
        }
        let g = self.grant(engine, Capability::WriteFile, &rel)?;
        ws.write(&rel, &text, &g).map_err(|e| e.to_string())?;
        let doc = &mut self.docs[i];
        doc.buffer.mark_saved();
        doc.last_disk_hash = Some(nexus_workspaces::sha256_hex(text.as_bytes()));
        let _ = std::fs::remove_file(recovery_path(ws.root(), &rel));
        self.update_gutter(i, engine);
        self.refresh_git(engine);
        Ok(format!("Saved {rel}"))
    }

    pub fn save_all(&mut self, engine: &PolicyEngine) -> Result<String, String> {
        let mut n = 0;
        for i in 0..self.docs.len() {
            if self.docs[i].buffer.is_dirty() && !self.docs[i].read_only {
                self.save_doc(i, engine)?;
                n += 1;
            }
        }
        Ok(format!("Saved {n} file(s)"))
    }

    pub fn close_active(&mut self) {
        if self.docs.is_empty() {
            return;
        }
        let i = self.active.min(self.docs.len() - 1);
        if self.docs[i].buffer.is_dirty() {
            // Keep a recovery copy rather than silently discarding edits.
            self.write_recovery();
        }
        self.docs.remove(i);
        if self.split == Some(i) {
            self.split = None;
        }
        self.active = self.active.min(self.docs.len().saturating_sub(1));
    }

    pub fn next_tab(&mut self, d: isize) {
        if !self.docs.is_empty() {
            self.active = ((self.active as isize + d).rem_euclid(self.docs.len() as isize)) as usize;
        }
    }

    pub fn toggle_split(&mut self) {
        self.split = if self.split.is_some() || self.docs.len() < 2 { None } else { Some((self.active + 1) % self.docs.len()) };
    }

    pub fn new_terminal(&mut self, kind: ShellKind, engine: &PolicyEngine) -> Result<String, String> {
        let cwd = self.workspace.as_ref().map(|w| w.root().to_path_buf()).unwrap_or_else(nexus_core::platform::home_dir);
        if let Some(t) = self.target() {
            engine.authorize(&Operation::user(t, Capability::InteractiveShell, kind.label())).map_err(|e| e.to_string())?;
        }
        self.spawn_terminal(kind, &cwd).map(|_| String::new())
    }

    /// Spawn a terminal whose grant the caller has already obtained.
    pub fn spawn_terminal(&mut self, kind: ShellKind, cwd: &std::path::Path) -> Result<u64, String> {
        let id = self.next_term_id;
        self.next_term_id += 1;
        let term = Terminal::spawn(id, kind, cwd, self.wake.clone())?;
        self.terminals.push(term);
        self.active_term = self.terminals.len() - 1;
        self.bottom = BottomTab::Terminal;
        Ok(id)
    }

    /// Kill and remove Debian write terminals (unlock ended or locked).
    pub fn close_debian_terms(&mut self) -> usize {
        let ids = std::mem::take(&mut self.debian_terms);
        let before = self.terminals.len();
        self.terminals.retain(|t| !ids.contains(&t.id));
        self.active_term = self.active_term.min(self.terminals.len().saturating_sub(1));
        before - self.terminals.len()
    }

    pub fn run_task(&mut self, kind: TaskKind, engine: &PolicyEngine) -> Result<String, String> {
        let ws = self.workspace.as_ref().ok_or("Open a folder first")?;
        if self.task_running.is_some() {
            return Err("A task is already running".into());
        }
        let root = ws.root().to_path_buf();
        let (prog, args): (&str, Vec<&str>) = if root.join("Cargo.toml").exists() {
            match kind {
                TaskKind::Check => ("cargo", vec!["check", "--workspace", "--message-format=short"]),
                TaskKind::Test => ("cargo", vec!["test", "--workspace"]),
            }
        } else if root.join("package.json").exists() {
            ("npm", if kind == TaskKind::Check { vec!["run", "build", "--if-present"] } else { vec!["test", "--if-present"] })
        } else if root.join("go.mod").exists() {
            ("go", if kind == TaskKind::Check { vec!["vet", "./..."] } else { vec!["test", "./..."] })
        } else if root.join("pyproject.toml").exists() || root.join("setup.py").exists() {
            ("python", if kind == TaskKind::Check { vec!["-m", "compileall", "-q", "."] } else { vec!["-m", "pytest", "-q"] })
        } else if std::fs::read_dir(&root).map(|d| d.flatten().any(|e| e.path().extension().is_some_and(|x| x == "sln" || x == "csproj"))).unwrap_or(false) {
            ("dotnet", if kind == TaskKind::Check { vec!["build"] } else { vec!["test"] })
        } else {
            return Err("No recognized project (Cargo, npm, Go, Python, .NET) at the workspace root".into());
        };
        let line = format!("{prog} {}", args.join(" "));
        self.grant(engine, Capability::ExecuteArbitraryCommand, &line)?;
        let (tx, rx) = channel();
        let args: Vec<String> = args.into_iter().map(String::from).collect();
        let prog = prog.to_string();
        let wake = self.wake.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut cmd = std::process::Command::new(&prog);
            cmd.args(&args).current_dir(&root).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
            match cmd.spawn() {
                Ok(mut child) => {
                    let err = child.stderr.take();
                    let tx2 = tx.clone();
                    let w2 = wake.clone();
                    let h = std::thread::spawn(move || {
                        if let Some(e) = err {
                            for l in std::io::BufReader::new(e).lines().map_while(Result::ok) {
                                let _ = tx2.send(Some(l));
                                w2();
                            }
                        }
                    });
                    if let Some(o) = child.stdout.take() {
                        for l in std::io::BufReader::new(o).lines().map_while(Result::ok) {
                            let _ = tx.send(Some(l));
                            wake();
                        }
                    }
                    let _ = h.join();
                    let code = child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
                    let _ = tx.send(Some(format!("[process exited with code {code}]")));
                }
                Err(e) => {
                    let _ = tx.send(Some(format!("Failed to start {prog}: {e}")));
                }
            }
            let _ = tx.send(None);
            wake();
        });
        self.output.push(format!("> {line}"));
        self.problems.clear();
        self.task_rx = Some(rx);
        self.task_running = Some(line);
        self.bottom = BottomTab::Output;
        Ok(String::new())
    }

    pub fn poll(&mut self, _t: &Tokens) {
        if let Some(rx) = &self.task_rx {
            let mut done = false;
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Some(l) => {
                        if let Some(p) = parse_problem(&l) {
                            self.problems.push(p);
                        }
                        self.output.push(l);
                    }
                    None => done = true,
                }
            }
            if self.output.len() > 20_000 {
                self.output.drain(..5_000);
            }
            if done {
                self.task_rx = None;
                self.task_running = None;
                if !self.problems.is_empty() {
                    self.bottom = BottomTab::Problems;
                }
                // Attach diagnostics to open docs.
                for d in &mut self.docs {
                    d.diagnostics = self
                        .problems
                        .iter()
                        .filter(|p| p.rel.replace('\\', "/").ends_with(&d.rel))
                        .map(|p| Diagnostic { line: p.line.saturating_sub(1), col: p.col.saturating_sub(1), severity: p.severity, message: p.message.clone() })
                        .collect();
                }
            }
        }
        for t in &mut self.terminals {
            t.poll_exit();
        }
    }

    pub fn open_quick_open(&mut self) {
        if self.workspace.is_some() {
            self.refresh_tree();
            self.quick_open = Some((String::new(), 0));
        }
    }

    pub fn active_doc(&self) -> Option<&Document> {
        self.docs.get(self.active)
    }

    // ---- recovery of unsaved work ----

    pub fn write_recovery(&mut self) {
        let Some(ws) = &self.workspace else { return };
        for d in &self.docs {
            if d.buffer.is_dirty() && d.path.is_some() {
                let p = recovery_path(ws.root(), &d.rel);
                let body = format!("{}\u{0}{}", d.rel, d.buffer.text());
                let _ = nexus_workspaces::write_atomic(&p, body.as_bytes());
            }
        }
    }

    fn scan_recovery(&mut self) {
        self.pending_recovery.clear();
        let Some(ws) = &self.workspace else { return };
        let dir = recovery_dir(ws.root());
        let Ok(rd) = std::fs::read_dir(&dir) else { return };
        for e in rd.flatten() {
            if let Ok(text) = std::fs::read_to_string(e.path()) {
                if let Some((rel, body)) = text.split_once('\u{0}') {
                    self.pending_recovery.push((rel.to_string(), body.to_string()));
                }
            }
        }
    }
}

fn recovery_dir(root: &Path) -> PathBuf {
    local_dir().join("recovery").join(&nexus_workspaces::sha256_hex(root.to_string_lossy().as_bytes())[..16])
}

fn recovery_path(root: &Path, rel: &str) -> PathBuf {
    recovery_dir(root).join(&nexus_workspaces::sha256_hex(rel.as_bytes())[..16])
}

/// Line-level change markers of `now` versus `head`.
pub fn gutter_marks(head: &str, now: &str) -> Vec<(usize, GutterMark)> {
    use similar::{DiffTag, TextDiff};
    let diff = TextDiff::from_lines(head, now);
    let mut out = Vec::new();
    for op in diff.ops() {
        let new = op.new_range();
        match op.tag() {
            DiffTag::Insert => out.extend(new.map(|l| (l, GutterMark::Added))),
            DiffTag::Replace => out.extend(new.map(|l| (l, GutterMark::Modified))),
            DiffTag::Delete => out.push((new.start, GutterMark::Deleted)),
            DiffTag::Equal => {}
        }
    }
    out
}

/// `path:line:col: error|warning[...]: message` (rustc short, gcc, clang, go vet).
pub fn parse_problem(line: &str) -> Option<Problem> {
    let line = line.trim();
    let (sev, idx) = [("error", Severity::Error), ("warning", Severity::Warning)]
        .iter()
        .find_map(|(w, s)| line.find(&format!(": {w}")).map(|i| (*s, i)))?;
    let loc = &line[..idx];
    let rest = &line[idx + 2..];
    let msg = rest.split_once(": ").map(|(_, m)| m).unwrap_or(rest).to_string();
    // Split from the right: file may contain a drive colon.
    let mut parts = loc.rsplitn(3, ':');
    let col = parts.next()?.trim().parse().ok()?;
    let ln = parts.next()?.trim().parse().ok()?;
    let file = parts.next()?.trim().to_string();
    if file.is_empty() {
        return None;
    }
    Some(Problem { rel: file.replace('\\', "/"), line: ln, col, severity: sev, message: msg })
}

// ===================================================================== UI

pub fn ide_screen(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    let full = ui.max_rect().shrink2(vec2(0.0, 8.0));
    let mut ui = ui.new_child(egui::UiBuilder::new().max_rect(egui::Rect::from_min_max(full.min, full.max - vec2(8.0, 0.0))));
    let ui = &mut ui;
    let glass = egui::Frame::new().fill(t.glass()).stroke(Stroke::new(1.0, white_a(0.08))).corner_radius(CornerRadius::same(14)).inner_margin(Margin::same(8));

    // Top toolbar
    egui::Panel::top("ide_toolbar").frame(egui::Frame::new().inner_margin(Margin { left: 4, right: 4, top: 0, bottom: 6 })).show(ui, |ui| {
        ui.horizontal(|ui| {
            if ui.button(icon(icons::SIDEBAR, 14.0)).on_hover_text("Toggle sidebar (Ctrl+B)").clicked() {
                app.s.layout.show_explorer = !app.s.layout.show_explorer;
            }
            let name = app.ide.workspace.as_ref().map(|w| w.name()).unwrap_or_else(|| "No folder open".into());
            ui.label(RichText::new(name).text_style(egui::TextStyle::Name("title".into())));
            if let Some(sh) = &app.ide.shadow {
                nexus_ui::pill(ui, &format!("Shadow of {}:{}", sh.manifest.host_label, sh.manifest.remote_root), t.warning());
            }
            if let Some(st) = &app.ide.status {
                if let Some(b) = &st.branch {
                    ui.label(icon(icons::BRANCH, 12.0).color(t.text2()));
                    ui.label(secondary(&t, format!("{b}{}", if st.is_dirty() { " •" } else { "" })));
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button(icon(icons::SPARKLE, 14.0)).on_hover_text("Toggle AI panel (Ctrl+L)").clicked() {
                    app.s.layout.show_ai = !app.s.layout.show_ai;
                }
                if ui.button(icon(icons::PANEL_BOTTOM, 14.0)).on_hover_text("Toggle panel (Ctrl+J)").clicked() {
                    app.s.layout.show_bottom = !app.s.layout.show_bottom;
                }
                if ui.button(icon(icons::SPLIT, 14.0)).on_hover_text("Split editor (Ctrl+\\)").clicked() {
                    app.ide.toggle_split();
                }
                let running = app.ide.task_running.is_some();
                if ui.add_enabled(!running, egui::Button::new(icon(icons::BUG, 14.0))).on_hover_text("Run tests").clicked() {
                    let r = app.ide.run_task(TaskKind::Test, &app.engine);
                    app.s.layout.show_bottom = true;
                    app.report(r);
                }
                if ui.add_enabled(!running, egui::Button::new(icon(icons::PLAY, 14.0))).on_hover_text("Build / check (Ctrl+Shift+B)").clicked() {
                    let r = app.ide.run_task(TaskKind::Check, &app.engine);
                    app.s.layout.show_bottom = true;
                    app.report(r);
                }
                if ui.button("Open Folder").clicked() {
                    app.run(crate::app::Command::OpenFolder, ui.ctx());
                }
            });
        });
    });

    if app.s.layout.show_explorer {
        let r = egui::Panel::left("ide_left").resizable(true).default_size(app.s.layout.explorer_width).size_range(180.0..=520.0).frame(glass).show(ui, |ui| left_panel(app, ui));
        app.s.layout.explorer_width = r.response.rect.width();
    }
    if app.s.layout.show_ai {
        let r = egui::Panel::right("ide_ai").resizable(true).default_size(app.s.layout.ai_width).size_range(300.0..=760.0).frame(glass).show(ui, |ui| crate::ai::panel(app, ui));
        app.s.layout.ai_width = r.response.rect.width();
    }
    if app.s.layout.show_bottom {
        let r = egui::Panel::bottom("ide_bottom").resizable(true).default_size(app.s.layout.bottom_height).size_range(120.0..=700.0).frame(glass).show(ui, |ui| bottom_panel(app, ui));
        app.s.layout.bottom_height = r.response.rect.height();
    }
    egui::CentralPanel::default().frame(egui::Frame::new().fill(t.editor()).stroke(Stroke::new(1.0, white_a(0.06))).corner_radius(CornerRadius::same(12)).inner_margin(Margin::same(0))).show(ui, |ui| center(app, ui));
}

fn left_panel(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    ui.horizontal(|ui| {
        for (tab, glyph, tip) in [(LeftTab::Explorer, icons::FOLDER, "Explorer"), (LeftTab::Search, icons::SEARCH, "Search (Ctrl+Shift+F)"), (LeftTab::Git, icons::BRANCH, "Source control (Ctrl+Shift+G)"), (LeftTab::Agents, icons::HISTORY, "Agent history")] {
            let sel = app.ide.left == tab;
            if ui.add(egui::Button::selectable(sel, icon(glyph, 15.0).color(if sel { t.accent() } else { t.text2() }))).on_hover_text(tip).clicked() {
                app.ide.left = tab;
            }
        }
    });
    ui.separator();
    match app.ide.left {
        LeftTab::Explorer => explorer(app, ui),
        LeftTab::Search => search_panel(app, ui),
        LeftTab::Git => git_panel(app, ui),
        LeftTab::Agents => crate::ai::history_panel(app, ui),
    }
}

fn explorer(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    if app.ide.workspace.is_none() {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(secondary(&t, "No folder open"));
            if ui.add(nexus_ui::AccentButton { text: "Open Folder", enabled: true }).clicked() {
                app.run(crate::app::Command::OpenFolder, ui.ctx());
            }
            ui.add_space(12.0);
            for r in app.s.recent_workspaces.clone().iter().take(8) {
                if ui.link(r).clicked() {
                    app.open_workspace(PathBuf::from(r));
                }
            }
        });
        return;
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("EXPLORER").small().color(t.text2()));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button(icon(icons::REFRESH, 12.0)).on_hover_text("Refresh").clicked() {
                app.ide.refresh_tree();
                app.ide.refresh_git(&app.engine);
            }
        });
    });
    if !app.ide.pending_recovery.is_empty() {
        egui::Frame::new().fill(t.warning().gamma_multiply(0.12)).corner_radius(CornerRadius::same(8)).inner_margin(6).show(ui, |ui| {
            ui.label(RichText::new(format!("{} unsaved file(s) can be recovered", app.ide.pending_recovery.len())).color(t.warning()));
            let items = app.ide.pending_recovery.clone();
            for (rel, body) in items {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&rel).monospace().small());
                    if ui.small_button("Restore").clicked() {
                        if app.ide.open_file(&rel, &app.engine).is_ok() {
                            let i = app.ide.active;
                            app.ide.docs[i].buffer.set_text(&body);
                        }
                        app.ide.pending_recovery.retain(|(r, _)| r != &rel);
                    }
                });
            }
            if ui.small_button("Dismiss").clicked() {
                app.ide.pending_recovery.clear();
            }
        });
    }
    let git_marks: BTreeMap<String, char> = app
        .ide
        .status
        .as_ref()
        .map(|s| s.files.iter().map(|f| (f.path.clone(), if f.untracked { 'U' } else if f.unstaged != '.' { f.unstaged } else { f.staged })).collect())
        .unwrap_or_default();
    let mut open: Option<String> = None;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let entries = app.ide.entries.clone();
        let mut hidden_prefix: Option<String> = None;
        for e in &entries {
            if let Some(h) = &hidden_prefix {
                if e.rel.starts_with(h) {
                    continue;
                }
                hidden_prefix = None;
            }
            let name = e.rel.rsplit('/').next().unwrap_or(&e.rel);
            let indent = (e.depth.saturating_sub(1)) as f32 * 14.0;
            let expanded = app.ide.expanded.contains(&e.rel);
            let active = app.ide.active_doc().is_some_and(|d| d.rel == e.rel);
            let resp = ui
                .horizontal(|ui| {
                    ui.add_space(indent);
                    let (glyph, col) = if e.is_dir { (if expanded { icons::CHEVRON_DOWN } else { icons::CHEVRON_RIGHT }, t.text2()) } else { (icons::FILE, t.text2().gamma_multiply(0.7)) };
                    ui.label(icon(glyph, 10.0).color(col));
                    let mark = git_marks.get(&e.rel);
                    let mut txt = RichText::new(name).size(13.0);
                    if let Some(m) = mark {
                        txt = txt.color(match m {
                            'U' | 'A' => t.success(),
                            'D' => t.error(),
                            _ => t.warning(),
                        });
                    }
                    let r = ui.add(egui::Button::selectable(active, txt).frame_when_inactive(false));
                    if app.ide.ai_touched.contains(&e.rel) {
                        ui.label(icon(icons::SPARKLE, 10.0).color(t.purple())).on_hover_text("Changed by an AI agent in this session");
                    }
                    r
                })
                .inner;
            if resp.clicked() {
                if e.is_dir {
                    if expanded {
                        app.ide.expanded.remove(&e.rel);
                    } else {
                        app.ide.expanded.insert(e.rel.clone());
                    }
                } else {
                    open = Some(e.rel.clone());
                }
            }
            resp.context_menu(|ui| {
                if !e.is_dir && ui.button("Add to AI context").clicked() {
                    app.ai.attach(&e.rel);
                    ui.close();
                }
                if ui.button("Copy relative path").clicked() {
                    ui.ctx().copy_text(e.rel.clone());
                    ui.close();
                }
                if ui.button("Reveal in File Manager").clicked() {
                    let _ = nexus_core::platform::reveal_in_file_manager(&e.path);
                    ui.close();
                }
            });
            if e.is_dir && !expanded {
                hidden_prefix = Some(format!("{}/", e.rel));
            }
        }
    });
    if let Some(rel) = open {
        let r = app.ide.open_file(&rel, &app.engine).map(|_| String::new());
        app.report(r);
    }
}

fn search_panel(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    let q = &mut app.ide.query;
    let r = ui.add(egui::TextEdit::singleline(&mut q.pattern).hint_text("Search").desired_width(f32::INFINITY));
    ui.horizontal(|ui| {
        ui.toggle_value(&mut q.case_sensitive, "Aa").on_hover_text("Match case");
        ui.toggle_value(&mut q.whole_word, "ab").on_hover_text("Whole word");
        ui.toggle_value(&mut q.regex, ".*").on_hover_text("Regular expression");
    });
    ui.add(egui::TextEdit::singleline(&mut app.ide.replace).hint_text("Replace").desired_width(f32::INFINITY));
    let go = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) || ui.button("Search").clicked();
    if go {
        if let Some(ws) = &app.ide.workspace {
            match nexus_workspaces::search::search(ws.root(), &app.ide.query) {
                Ok(m) => {
                    app.ide.results = m;
                    app.ide.search_error = None;
                }
                Err(e) => app.ide.search_error = Some(e.to_string()),
            }
        }
    }
    if let Some(e) = &app.ide.search_error {
        ui.label(RichText::new(e).color(t.error()).small());
    }
    let files: Vec<String> = {
        let mut v: Vec<String> = app.ide.results.iter().map(|m| m.rel.clone()).collect();
        v.dedup();
        v
    };
    ui.horizontal(|ui| {
        ui.label(secondary(&t, format!("{} results in {} files", app.ide.results.len(), files.len())));
        if !app.ide.results.is_empty() && ui.small_button("Replace all").on_hover_text("Opens each file and replaces in the editor; save to write").clicked() {
            let q = app.ide.query.clone();
            let rep = app.ide.replace.clone();
            let mut total = 0;
            for f in &files {
                if app.ide.open_file(f, &app.engine).is_ok() {
                    let i = app.ide.active;
                    let doc = &mut app.ide.docs[i];
                    if let Ok((new, n)) = nexus_workspaces::search::replace_all(&doc.buffer.text(), &q, &rep) {
                        if n > 0 {
                            doc.buffer.set_text(&new);
                            total += n;
                        }
                    }
                }
            }
            app.toast(format!("Replaced {total} occurrences in editors — review and save"), t.accent());
        }
    });
    let mut goto: Option<(String, usize, usize)> = None;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let mut last = String::new();
        for m in &app.ide.results {
            if m.rel != last {
                ui.label(RichText::new(&m.rel).strong().size(12.5));
                last = m.rel.clone();
            }
            let txt = format!("{:>4}  {}", m.line, m.text.trim());
            if ui.add(egui::Button::selectable(false, RichText::new(txt).monospace().size(12.0)).frame_when_inactive(false)).clicked() {
                goto = Some((m.rel.clone(), m.line - 1, m.column - 1));
            }
        }
    });
    if let Some((rel, l, c)) = goto {
        if app.ide.open_file(&rel, &app.engine).is_ok() {
            let i = app.ide.active;
            app.ide.docs[i].goto_line(l, c);
        }
    }
}

fn git_panel(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    if app.ide.repo.is_none() {
        ui.label(secondary(&t, "This folder is not a Git repository."));
        return;
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("SOURCE CONTROL").small().color(t.text2()));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button(icon(icons::REFRESH, 12.0)).clicked() {
                app.ide.refresh_git(&app.engine);
            }
        });
    });
    let Some(st) = app.ide.status.clone() else {
        ui.label(secondary(&t, "Status unavailable"));
        return;
    };
    ui.label(secondary(&t, format!("{} {}", st.branch.clone().unwrap_or_else(|| "(detached)".into()), if st.ahead + st.behind > 0 { format!("↑{} ↓{}", st.ahead, st.behind) } else { String::new() })));
    ui.add(egui::TextEdit::multiline(&mut app.ide.commit_msg).hint_text("Commit message").desired_rows(2).desired_width(f32::INFINITY));
    let staged: Vec<_> = st.files.iter().filter(|f| f.staged != '.' && !f.untracked).cloned().collect();
    let can_commit = !staged.is_empty() && !app.ide.commit_msg.trim().is_empty();
    if ui.add(nexus_ui::AccentButton { text: &format!("Commit {} staged", staged.len()), enabled: can_commit }).clicked() {
        let repo = app.ide.repo.as_ref().unwrap();
        let res = app.ide.target().ok_or("no workspace".to_string()).and_then(|tg| app.engine.authorize(&Operation::user(tg, Capability::GitWrite, "git commit")).map_err(|e| e.to_string())).and_then(|g| repo.commit(&g, &app.ide.commit_msg).map_err(|e| e.to_string()));
        match res {
            Ok(h) => {
                app.ide.commit_msg.clear();
                app.toast(format!("Committed {}", &h[..8.min(h.len())]), t.success());
            }
            Err(e) => app.toast(e, t.error()),
        }
        app.ide.refresh_git(&app.engine);
    }
    ui.add_space(6.0);
    let mut action: Option<(bool, String)> = None;
    let mut diff: Option<String> = None;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        for (title, list, staged_list) in [("Staged", staged.clone(), true), ("Changes", st.files.iter().filter(|f| f.unstaged != '.' || f.untracked).cloned().collect::<Vec<_>>(), false)] {
            if list.is_empty() {
                continue;
            }
            ui.label(RichText::new(format!("{title} ({})", list.len())).small().color(t.text2()));
            for f in list {
                ui.horizontal(|ui| {
                    let ch = if staged_list { f.staged } else if f.untracked { 'U' } else { f.unstaged };
                    let col = match ch {
                        'A' | 'U' => t.success(),
                        'D' => t.error(),
                        _ => t.warning(),
                    };
                    ui.label(RichText::new(ch.to_string()).monospace().color(col));
                    if app.ide.ai_touched.contains(&f.path) {
                        ui.label(icon(icons::SPARKLE, 10.0).color(t.purple())).on_hover_text("AI-generated change");
                    }
                    if ui.add(egui::Button::selectable(false, RichText::new(&f.path).size(12.5)).frame_when_inactive(false)).clicked() {
                        diff = Some(f.path.clone());
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button(if staged_list { "−" } else { "+" }).on_hover_text(if staged_list { "Unstage" } else { "Stage" }).clicked() {
                            action = Some((!staged_list, f.path.clone()));
                        }
                    });
                });
            }
        }
    });
    if let Some((stage, path)) = action {
        let repo = app.ide.repo.as_ref().unwrap();
        let r = app.ide.target().ok_or("no workspace".to_string()).and_then(|tg| app.engine.authorize(&Operation::user(tg, Capability::GitWrite, format!("git {} {path}", if stage { "add" } else { "restore --staged" }))).map_err(|e| e.to_string())).and_then(|g| if stage { repo.stage(&g, &[&path]) } else { repo.unstage(&g, &[&path]) }.map_err(|e| e.to_string()));
        if let Err(e) = r {
            app.toast(e, t.error());
        }
        app.ide.refresh_git(&app.engine);
    }
    if let Some(path) = diff {
        let repo = app.ide.repo.as_ref().unwrap();
        if let Some(tg) = app.ide.target() {
            if let Ok(g) = app.engine.authorize(&Operation::user(tg, Capability::GitRead, format!("git diff {path}"))) {
                let mut d = repo.diff(&g, Some(&path), false).unwrap_or_default();
                if d.is_empty() {
                    d = repo.diff(&g, Some(&path), true).unwrap_or_default();
                }
                if d.is_empty() {
                    d = format!("(no textual diff for {path}; untracked or binary)");
                }
                app.ide.open_virtual(&format!("{path}.diff"), &d, "Diff view");
            }
        }
    }
}

fn center(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    if crate::ai::review_active(app) {
        crate::ai::review_ui(app, ui);
        return;
    }
    if app.ide.docs.is_empty() {
        welcome(app, ui);
        return;
    }
    // Tabs
    let mut close: Option<usize> = None;
    egui::Frame::new().fill(t.bg().gamma_multiply(0.6)).inner_margin(Margin { left: 6, right: 6, top: 6, bottom: 0 }).show(ui, |ui| {
        egui::ScrollArea::horizontal().id_salt("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, d) in app.ide.docs.iter().enumerate() {
                    let active = i == app.ide.active;
                    let title = format!("{}{}", d.title(), if d.buffer.is_dirty() { " ●" } else { "" });
                    let fill = if active { t.editor() } else { Color32::TRANSPARENT };
                    let r = egui::Frame::new().fill(fill).corner_radius(CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 }).inner_margin(Margin { left: 10, right: 4, top: 5, bottom: 5 }).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if d.read_only {
                                ui.label(icon(icons::LOCK, 10.0).color(t.text2()));
                            }
                            let lbl = ui.add(egui::Label::new(RichText::new(title).size(12.5).color(if active { t.text() } else { t.text2() })).sense(Sense::click()));
                            if lbl.clicked() {
                                app.ide.active = i;
                            }
                            if lbl.middle_clicked() {
                                close = Some(i);
                            }
                            if ui.add(egui::Button::new(icon(icons::CLOSE, 9.0)).frame(false)).clicked() {
                                close = Some(i);
                            }
                        });
                    });
                    if active {
                        let r = r.response.rect;
                        ui.painter().line_segment([r.left_top() + vec2(8.0, 0.5), r.right_top() + vec2(-8.0, 0.5)], Stroke::new(1.5, t.accent()));
                    }
                }
            });
        });
    });
    if let Some(i) = close {
        app.ide.active = i;
        app.ide.close_active();
    }
    if app.ide.docs.is_empty() {
        return;
    }
    let active = app.ide.active.min(app.ide.docs.len() - 1);
    // Breadcrumbs + status
    {
        let d = &app.ide.docs[active];
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            ui.label(secondary(&t, d.rel.replace('/', "  ›  ")));
            if let Some(r) = &d.read_only_reason {
                nexus_ui::pill(ui, r, t.warning());
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(10.0);
                let (l, c) = d.cursor_lc();
                ui.label(secondary(&t, format!("Ln {}, Col {}  ·  {}  ·  {}", l + 1, c + 1, d.language(), if d.buffer.line_ending == "\r\n" { "CRLF" } else { "LF" })));
                if d.buffer.sels.len() > 1 {
                    ui.label(secondary(&t, format!("{} cursors  ·", d.buffer.sels.len())));
                }
            });
        });
    }
    // Find bar
    {
        let d = &mut app.ide.docs[active];
        if d.find.open {
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                let r = ui.add(egui::TextEdit::singleline(&mut d.find.query).hint_text("Find").desired_width(200.0));
                if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    d.find_next(ui.input(|i| i.modifiers.shift));
                    r.request_focus();
                }
                ui.toggle_value(&mut d.find.case_sensitive, "Aa");
                ui.toggle_value(&mut d.find.regex, ".*");
                ui.label(secondary(&t, format!("{} matches", d.find.matches.len())));
                if ui.small_button("↑").clicked() {
                    d.find_next(true);
                }
                if ui.small_button("↓").clicked() {
                    d.find_next(false);
                }
                if !d.read_only {
                    ui.add(egui::TextEdit::singleline(&mut d.find.replace).hint_text("Replace").desired_width(160.0));
                    if ui.small_button("Replace").clicked() {
                        d.replace_current();
                    }
                    if ui.small_button("All").clicked() {
                        d.replace_all();
                    }
                }
                if ui.small_button(icon(icons::CLOSE, 10.0)).clicked() {
                    d.find.open = false;
                }
            });
        }
    }
    let font = app.s.tokens.editor_font_size;
    let split = app.ide.split.filter(|s| *s < app.ide.docs.len() && *s != active);
    let mut outputs = Vec::new();
    if let Some(s) = split {
        let avail = ui.available_rect_before_wrap();
        let half = avail.width() / 2.0;
        let left = egui::Rect::from_min_size(avail.min, vec2(half - 1.0, avail.height()));
        let right = egui::Rect::from_min_max(avail.min + vec2(half + 1.0, 0.0), avail.max);
        let mut lu = ui.new_child(egui::UiBuilder::new().max_rect(left));
        outputs.push((active, editor::show(&mut lu, &mut app.ide.docs[active], &t, font)));
        let mut ru = ui.new_child(egui::UiBuilder::new().max_rect(right));
        outputs.push((s, editor::show(&mut ru, &mut app.ide.docs[s], &t, font)));
        ui.painter().line_segment([avail.center_top(), avail.center_bottom()], Stroke::new(1.0, white_a(0.08)));
        ui.advance_cursor_after_rect(avail);
    } else {
        outputs.push((active, editor::show(ui, &mut app.ide.docs[active], &t, font)));
    }
    for (i, out) in outputs {
        if out.save {
            app.ide.active = i;
            let r = app.ide.save_active(&app.engine);
            app.report(r);
        }
        if out.inline_ai {
            app.ide.active = i;
            app.ai.begin_inline(&app.ide);
        }
        if out.changed && i == app.ide.active {
            // Refresh gutter on idle edits (cheap line diff).
            if let Some(d) = app.ide.docs.get(i) {
                if d.buffer.version % 20 == 0 {
                    app.ide.update_gutter(i, &app.engine);
                }
            }
        }
    }
}

fn welcome(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.22);
        ui.label(RichText::new("Nexus IDE").size(30.0).family(egui::FontFamily::Name("semibold".into())).color(t.text()));
        ui.label(secondary(&t, if app.ide.workspace.is_some() { "Open a file from the explorer (Ctrl+P), or ask the AI panel about this project." } else { "Open a folder, then chat with Codex or Claude Code in the AI panel." }));
        ui.add_space(18.0);
        let w = 300.0;
        ui.allocate_ui(vec2(w, 160.0), |ui| {
            egui::Grid::new("welcome_keys").num_columns(2).spacing(vec2(40.0, 8.0)).show(ui, |ui| {
                for (k, v) in [("Ctrl+P", "Go to file"), ("Ctrl+Shift+P", "Command palette"), ("Ctrl+K", "Inline AI edit"), ("Ctrl+L", "AI panel"), ("Ctrl+`", "Terminal"), ("Ctrl+Shift+F", "Search")] {
                    ui.label(RichText::new(v).color(t.text2()));
                    ui.label(RichText::new(k).monospace().color(t.text()));
                    ui.end_row();
                }
            });
        });
        ui.add_space(14.0);
        if app.ide.workspace.is_none() && ui.add(nexus_ui::AccentButton { text: "Open Folder", enabled: true }).clicked() {
            app.run(crate::app::Command::OpenFolder, ui.ctx());
        }
    });
}

fn bottom_panel(app: &mut NexusApp, ui: &mut Ui) {
    let t = app.s.tokens.clone();
    ui.horizontal(|ui| {
        for (tab, label) in [(BottomTab::Terminal, "Terminal"), (BottomTab::Problems, "Problems"), (BottomTab::Output, "Output")] {
            let txt = match tab {
                BottomTab::Problems if !app.ide.problems.is_empty() => format!("{label} ({})", app.ide.problems.len()),
                _ => label.to_string(),
            };
            if ui.add(egui::Button::selectable(app.ide.bottom == tab, txt)).clicked() {
                app.ide.bottom = tab;
            }
        }
        if let Some(task) = &app.ide.task_running {
            ui.add(egui::Spinner::new().size(12.0));
            ui.label(secondary(&t, task.clone()));
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if app.ide.bottom == BottomTab::Terminal {
                ui.menu_button(icon(icons::ADD, 13.0), |ui| {
                    for k in ShellKind::available() {
                        if ui.button(k.label()).clicked() {
                            let r = app.ide.new_terminal(k, &app.engine);
                            app.report(r);
                            ui.close();
                        }
                    }
                });
                if let Some(term) = app.ide.terminals.get_mut(app.ide.active_term) {
                    ui.add(egui::TextEdit::singleline(&mut term.search).hint_text("Find in terminal").desired_width(140.0));
                    if !term.search.is_empty() {
                        ui.label(secondary(&t, format!("{}", term.search_count())));
                    }
                }
            }
            if app.ide.bottom == BottomTab::Output && ui.small_button("Clear").clicked() {
                app.ide.output.clear();
            }
        });
    });
    match app.ide.bottom {
        BottomTab::Terminal => {
            if app.ide.terminals.is_empty() {
                ui.add_space(8.0);
                if ui.button("Start terminal").clicked() {
                    let r = app.ide.new_terminal(ShellKind::Login, &app.engine);
                    app.report(r);
                }
                return;
            }
            let mut kill: Option<usize> = None;
            ui.horizontal(|ui| {
                for (i, term) in app.ide.terminals.iter().enumerate() {
                    let label = match term.exit {
                        Some(c) => format!("{} (exit {c})", term.title()),
                        None => term.title(),
                    };
                    if ui.add(egui::Button::selectable(i == app.ide.active_term, RichText::new(label).size(12.0))).clicked() {
                        app.ide.active_term = i;
                    }
                    if ui.add(egui::Button::new(icon(icons::CLOSE, 8.0)).frame(false)).clicked() {
                        kill = Some(i);
                    }
                }
            });
            if let Some(i) = kill {
                app.ide.terminals.remove(i);
                app.ide.active_term = app.ide.active_term.min(app.ide.terminals.len().saturating_sub(1));
            }
            let font = (app.s.tokens.editor_font_size - 0.5).max(10.0);
            if let Some(term) = app.ide.terminals.get_mut(app.ide.active_term) {
                nexus_terminal::show(ui, term, &t, font);
            }
        }
        BottomTab::Problems => {
            let mut goto = None;
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                if app.ide.problems.is_empty() {
                    ui.label(secondary(&t, "No problems. Run Build / Check (Ctrl+Shift+B) to collect compiler diagnostics."));
                }
                for p in &app.ide.problems {
                    ui.horizontal(|ui| {
                        let (g, c) = match p.severity {
                            Severity::Error => (icons::ERROR, t.error()),
                            _ => (icons::WARNING, t.warning()),
                        };
                        ui.label(icon(g, 12.0).color(c));
                        if ui.add(egui::Button::selectable(false, RichText::new(format!("{}  {}:{}:{}", p.message, p.rel, p.line, p.col)).size(12.5)).frame_when_inactive(false)).clicked() {
                            goto = Some((p.rel.clone(), p.line, p.col));
                        }
                    });
                }
            });
            if let Some((rel, l, c)) = goto {
                let rel = app.ide.files.iter().find(|f| rel.ends_with(f.as_str()) || f.ends_with(rel.as_str())).cloned().unwrap_or(rel);
                if app.ide.open_file(&rel, &app.engine).is_ok() {
                    let i = app.ide.active;
                    app.ide.docs[i].goto_line(l.saturating_sub(1), c.saturating_sub(1));
                }
            }
        }
        BottomTab::Output => {
            egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                for l in &app.ide.output {
                    ui.label(RichText::new(l).monospace().size(12.0).color(if l.contains("error") { t.error() } else if l.contains("warning") { t.warning() } else { t.text2() }));
                }
            });
        }
    }
}

pub fn quick_open_ui(app: &mut NexusApp, ctx: &egui::Context) {
    let Some((mut q, mut sel)) = app.ide.quick_open.take() else { return };
    let t = app.s.tokens.clone();
    let mut pick: Option<String> = None;
    let mut close = false;
    let screen = ctx.content_rect();
    egui::Area::new(crate::app::gid("quick_open")).order(egui::Order::Foreground).fixed_pos(egui::pos2(screen.center().x - 300.0, screen.top() + 70.0)).show(ctx, |ui| {
        egui::Frame::popup(ui.style()).fill(t.surface().gamma_multiply(0.98)).corner_radius(CornerRadius::same(14)).inner_margin(10).show(ui, |ui| {
            ui.set_width(600.0);
            ui.add(egui::TextEdit::singleline(&mut q).hint_text("Go to file").desired_width(f32::INFINITY).font(FontId::proportional(15.0))).request_focus();
            let mut scored: Vec<(i64, &String)> = app.ide.files.iter().filter_map(|f| tree::fuzzy_score(f, &q).map(|s| (s, f))).collect();
            scored.sort_by(|a, b| b.0.cmp(&a.0));
            scored.truncate(60);
            if ui.input(|i| i.key_pressed(Key::ArrowDown)) {
                sel = (sel + 1).min(scored.len().saturating_sub(1));
            }
            if ui.input(|i| i.key_pressed(Key::ArrowUp)) {
                sel = sel.saturating_sub(1);
            }
            egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                for (i, (_, f)) in scored.iter().enumerate() {
                    let name = f.rsplit('/').next().unwrap_or(f);
                    let r = ui.add_sized([ui.available_width(), 26.0], egui::Button::selectable(i == sel, "").frame_when_inactive(false));
                    ui.painter().text(r.rect.left_center() + vec2(10.0, 0.0), egui::Align2::LEFT_CENTER, name, FontId::proportional(13.5), t.text());
                    ui.painter().text(r.rect.right_center() - vec2(10.0, 0.0), egui::Align2::RIGHT_CENTER, f.as_str(), FontId::proportional(11.5), t.text2());
                    if r.clicked() {
                        pick = Some((*f).clone());
                    }
                }
            });
            if ui.input(|i| i.key_pressed(Key::Enter)) {
                pick = scored.get(sel).map(|x| x.1.clone());
            }
            if ui.input(|i| i.key_pressed(Key::Escape)) {
                close = true;
            }
        });
    });
    if let Some(f) = pick {
        let r = app.ide.open_file(&f, &app.engine).map(|_| String::new());
        app.report(r);
    } else if !close {
        app.ide.quick_open = Some((q, sel));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compiler_output() {
        let p = parse_problem("src/main.rs:3:5: error[E0425]: cannot find value `x` in this scope").unwrap();
        assert_eq!((p.rel.as_str(), p.line, p.col, p.severity), ("src/main.rs", 3, 5, Severity::Error));
        assert_eq!(p.message, "cannot find value `x` in this scope");
        let w = parse_problem("C:\\p\\a.c:10:2: warning: unused variable").unwrap();
        assert_eq!((w.rel.as_str(), w.line), ("C:/p/a.c", 10));
        assert!(parse_problem("   Compiling foo v0.1.0").is_none());
    }

    #[test]
    fn gutter_marks_detect_changes() {
        let m = gutter_marks("a\nb\nc\n", "a\nB\nc\nd\n");
        assert!(m.contains(&(1, GutterMark::Modified)));
        assert!(m.contains(&(3, GutterMark::Added)));
    }
}
