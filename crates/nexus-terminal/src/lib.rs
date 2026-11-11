//! Integrated terminals: a Unix PTY (via portable-pty; Windows used ConPTY)
//! driving an alacritty_terminal emulator, rendered with egui.
//!
//! Shell kinds are local only: the login shell (`$SHELL`), Bash, Zsh, Fish
//! and PowerShell when installed (Windows offered PowerShell, Command Prompt,
//! WSL and Git Bash). SSH sessions are created by the app *only* for hosts
//! whose policy grants `InteractiveShell`; Debian never does (it uses the
//! restricted catalog console).

use alacritty_terminal::event::{Event as TermEvent, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color as AColor, NamedColor, Processor};
use egui::text::{LayoutJob, TextFormat};
use egui::{pos2, vec2, Color32, CornerRadius, Event, FontId, Key, Rect, Sense, Ui};
use nexus_ui::Tokens;
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellKind {
    /// The user's login shell (`$SHELL`, falling back to bash, then `/bin/sh`).
    /// The default, like PowerShell was on Windows.
    Login,
    Bash,
    Zsh,
    Fish,
    /// PowerShell 7 (`pwsh`), when installed.
    PowerShell,
    /// A specific program and arguments (e.g. ssh to an authorized host).
    Custom { program: String, args: Vec<String>, label: String },
}

impl ShellKind {
    pub fn label(&self) -> String {
        match self {
            ShellKind::Login => {
                let p = login_shell();
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "sh".into());
                format!("Shell ({name})")
            }
            ShellKind::Bash => "Bash".into(),
            ShellKind::Zsh => "Zsh".into(),
            ShellKind::Fish => "Fish".into(),
            ShellKind::PowerShell => "PowerShell".into(),
            ShellKind::Custom { label, .. } => label.clone(),
        }
    }

    /// Shells available on this machine (the login shell always first).
    pub fn available() -> Vec<ShellKind> {
        let mut v = vec![ShellKind::Login];
        let login = login_shell();
        for (k, exe) in [(ShellKind::Bash, "bash"), (ShellKind::Zsh, "zsh"), (ShellKind::Fish, "fish"), (ShellKind::PowerShell, "pwsh")] {
            let Some(p) = which(exe) else { continue };
            // Do not list the login shell twice.
            if login.file_name() == p.file_name() {
                continue;
            }
            v.push(k);
        }
        v
    }

    fn command(&self) -> CommandBuilder {
        let shell = |name: &str, args: &[&str]| {
            let mut c = CommandBuilder::new(which(name).unwrap_or_else(|| PathBuf::from(name)));
            c.args(args);
            c
        };
        match self {
            ShellKind::Login => {
                let mut c = CommandBuilder::new(login_shell());
                c.arg("-l");
                c
            }
            ShellKind::Bash => shell("bash", &["-l"]),
            ShellKind::Zsh => shell("zsh", &["-l"]),
            ShellKind::Fish => shell("fish", &["-l"]),
            ShellKind::PowerShell => shell("pwsh", &["-NoLogo"]),
            ShellKind::Custom { program, args, .. } => {
                let mut c = CommandBuilder::new(program);
                c.args(args);
                c
            }
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(name)).find(|p| p.is_file())
}

/// `$SHELL` when it is an absolute path to a file, else bash, else `/bin/sh`.
pub fn login_shell() -> PathBuf {
    std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file())
        .or_else(|| which("bash"))
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

#[derive(Clone)]
struct Listener {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    title: Arc<Mutex<Option<String>>>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl EventListener for Listener {
    fn send_event(&self, event: TermEvent) {
        match event {
            TermEvent::PtyWrite(s) => {
                let _ = self.writer.lock().write_all(s.as_bytes());
            }
            TermEvent::Title(t) => *self.title.lock() = Some(t),
            TermEvent::ResetTitle => *self.title.lock() = None,
            TermEvent::Wakeup => (self.wake)(),
            // Clipboard reads from the remote program are refused (no OSC 52 load).
            _ => {}
        }
    }
}

struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

pub struct Terminal {
    pub id: u64,
    pub kind: ShellKind,
    term: Arc<Mutex<Term<Listener>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    title: Arc<Mutex<Option<String>>>,
    size: (usize, usize),
    pub exit: Option<u32>,
    pub search: String,
    selection: Option<(Point, Point)>,
    /// Commands echoed here are labelled as coming from an agent.
    pub agent_owned: bool,
}

impl Terminal {
    pub fn spawn(id: u64, kind: ShellKind, cwd: &Path, wake: Arc<dyn Fn() + Send + Sync>) -> Result<Self, String> {
        let pty = native_pty_system();
        let pair = pty.openpty(PtySize { rows: 24, cols: 100, pixel_width: 0, pixel_height: 0 }).map_err(|e| e.to_string())?;
        let mut cmd = kind.command();
        cmd.cwd(cwd);
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        // Nexus itself may run through XWayland (see nexus-app main.rs); give
        // the shell the user's real Wayland display back.
        if let Some(w) = std::env::var_os("NEXUS_WAYLAND_DISPLAY") {
            cmd.env("WAYLAND_DISPLAY", w);
            cmd.env_remove("NEXUS_WAYLAND_DISPLAY");
        }
        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
        drop(pair.slave);
        let writer: Arc<Mutex<Box<dyn Write + Send>>> = Arc::new(Mutex::new(pair.master.take_writer().map_err(|e| e.to_string())?));
        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let title = Arc::new(Mutex::new(None));
        let listener = Listener { writer: writer.clone(), title: title.clone(), wake: wake.clone() };
        let config = Config { scrolling_history: 10_000, ..Default::default() };
        let term = Arc::new(Mutex::new(Term::new(config, &Size { cols: 100, rows: 24 }, listener)));
        let t2 = term.clone();
        std::thread::Builder::new()
            .name(format!("nexus-term-{id}"))
            .spawn(move || {
                let mut parser: Processor = Processor::new();
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            parser.advance(&mut *t2.lock(), &buf[..n]);
                            wake();
                        }
                    }
                }
                wake();
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            id,
            kind,
            term,
            writer,
            master: pair.master,
            child,
            title,
            size: (100, 24),
            exit: None,
            search: String::new(),
            selection: None,
            agent_owned: false,
        })
    }

    pub fn title(&self) -> String {
        // Shells often set the title to their own executable path; show the
        // friendly shell name instead of e.g. /nix/store/…-bash/bin/bash.
        match self.title.lock().clone() {
            Some(t) if !t.trim().is_empty() && !looks_like_exe_path(&t) => t,
            _ => self.kind.label(),
        }
    }

    pub fn write(&self, bytes: &[u8]) {
        let _ = self.writer.lock().write_all(bytes);
    }

    pub fn paste(&self, text: &str) {
        let bracketed = self.term.lock().mode().contains(TermMode::BRACKETED_PASTE);
        let clean = text.replace("\r\n", "\r").replace('\n', "\r").replace('\u{1b}', "");
        if bracketed {
            self.write(format!("\x1b[200~{clean}\x1b[201~").as_bytes());
        } else {
            self.write(clean.as_bytes());
        }
    }

    pub fn poll_exit(&mut self) -> Option<u32> {
        if self.exit.is_none() {
            if let Ok(Some(st)) = self.child.try_wait() {
                self.exit = Some(st.exit_code());
            }
        }
        self.exit
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
    }

    fn resize(&mut self, cols: usize, rows: usize) {
        if (cols, rows) == self.size || cols < 2 || rows < 1 {
            return;
        }
        self.size = (cols, rows);
        let _ = self.master.resize(PtySize { rows: rows as u16, cols: cols as u16, pixel_width: 0, pixel_height: 0 });
        self.term.lock().resize(Size { cols, rows });
    }

    /// All text (scrollback + screen), for search and AI context.
    pub fn text(&self, max_lines: usize) -> String {
        let term = self.term.lock();
        let grid = term.grid();
        let top = -(grid.history_size() as i32);
        let bottom = grid.screen_lines() as i32;
        let start = (bottom - max_lines as i32).max(top);
        let mut out = String::new();
        for l in start..bottom {
            let row = &grid[Line(l)];
            let mut s: String = (0..grid.columns()).map(|c| row[Column(c)].c).collect();
            s.truncate(s.trim_end().len());
            out.push_str(&s);
            out.push('\n');
        }
        out
    }

    pub fn search_count(&self) -> usize {
        if self.search.is_empty() {
            return 0;
        }
        let q = self.search.to_lowercase();
        self.text(10_000).to_lowercase().matches(&q).count()
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn looks_like_exe_path(t: &str) -> bool {
    let l = t.trim().to_ascii_lowercase();
    l.ends_with(".exe") || l.contains(":\\windows\\") || l.starts_with("administrator:") || l.starts_with("/nix/store/") || (l.starts_with('/') && !l.contains(' ') && (l.ends_with("/bash") || l.ends_with("/zsh") || l.ends_with("/fish") || l.ends_with("/sh") || l.ends_with("/pwsh")))
}

fn palette(i: usize) -> Color32 {
    const BASE: [u32; 16] = [
        0x1B2233, 0xFF7A8E, 0x7CE8CA, 0xF1C07E, 0x8FB0FF, 0xC9ADFF, 0x7FD6F0, 0xD7DEEE, 0x56627C, 0xFF93A2, 0x9AF0D6, 0xF5D49F, 0xB4CBFF,
        0xDCC8FF, 0xA5E4F5, 0xFFFFFF,
    ];
    if i < 16 {
        return nexus_ui::hex(BASE[i]);
    }
    if i < 232 {
        let i = i - 16;
        let f = |v: usize| if v == 0 { 0 } else { (v * 40 + 55) as u8 };
        return Color32::from_rgb(f(i / 36), f((i / 6) % 6), f(i % 6));
    }
    let g = (8 + (i - 232) * 10) as u8;
    Color32::from_rgb(g, g, g)
}

fn resolve(c: AColor, fg: bool, t: &Tokens) -> Option<Color32> {
    match c {
        AColor::Spec(rgb) => Some(Color32::from_rgb(rgb.r, rgb.g, rgb.b)),
        AColor::Indexed(i) => Some(palette(i as usize)),
        AColor::Named(n) => match n {
            NamedColor::Foreground | NamedColor::BrightForeground => Some(t.text()),
            NamedColor::Background => if fg { Some(t.editor()) } else { None },
            NamedColor::DimForeground => Some(t.text2()),
            NamedColor::Cursor => Some(t.accent()),
            other => {
                let idx = other as usize;
                if idx < 16 { Some(palette(idx)) } else if (idx - 256) < 8 { Some(palette(idx - 256).gamma_multiply(0.7)) } else { Some(t.text()) }
            }
        },
    }
}

/// Render and drive a terminal in the given UI area.
pub fn show(ui: &mut Ui, term: &mut Terminal, t: &Tokens, font_size: f32) {
    let font = FontId::monospace(font_size);
    let row_h = (font_size * 1.35).round();
    let char_w = ui.painter().layout_no_wrap("MMMMMMMMMM".into(), font.clone(), Color32::WHITE).size().x / 10.0;
    let rect = ui.available_rect_before_wrap();
    let id = ui.make_persistent_id(("nexus_term", term.id));
    let resp = ui.interact(rect, id, Sense::click_and_drag());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::ZERO, t.editor());
    let inner = rect.shrink2(vec2(10.0, 6.0));
    let cols = ((inner.width() / char_w).floor() as usize).max(2);
    let rows = ((inner.height() / row_h).floor() as usize).max(1);
    term.resize(cols, rows);

    if resp.clicked() || resp.drag_started() {
        resp.request_focus();
    }
    let focused = resp.has_focus();
    if focused {
        ui.memory_mut(|m| m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true }));
    }
    let cell_at = |p: egui::Pos2, offset: usize| -> Point {
        let c = (((p.x - inner.left()) / char_w).floor().max(0.0) as usize).min(cols - 1);
        let l = (((p.y - inner.top()) / row_h).floor().max(0.0) as usize).min(rows - 1);
        Point::new(Line(l as i32 - offset as i32), Column(c))
    };

    // Scrollback with the wheel.
    if resp.hovered() {
        let dy = ui.input(|i| i.smooth_scroll_delta.y);
        if dy.abs() > 0.5 {
            let lines = (dy / row_h).round() as i32;
            if lines != 0 {
                term.term.lock().scroll_display(Scroll::Delta(lines));
            }
        }
    }

    let offset = term.term.lock().grid().display_offset();
    if let Some(p) = resp.interact_pointer_pos() {
        let pt = cell_at(p, offset);
        if resp.drag_started() {
            term.selection = Some((pt, pt));
        } else if resp.dragged() {
            if let Some(s) = term.selection.as_mut() {
                s.1 = pt;
            }
        } else if resp.clicked() {
            term.selection = None;
        }
    }

    if focused {
        let events = ui.input(|i| i.events.clone());
        let app_cursor = term.term.lock().mode().contains(TermMode::APP_CURSOR);
        for ev in events {
            match ev {
                Event::Text(s) => {
                    term.term.lock().scroll_display(Scroll::Bottom);
                    term.write(s.as_bytes());
                }
                Event::Paste(s) => term.paste(&s),
                Event::Copy => {
                    if let Some(txt) = selected_text(term) {
                        ui.ctx().copy_text(txt);
                    }
                }
                Event::Key { key, pressed: true, modifiers, .. } => {
                    if let Some(bytes) = key_bytes(key, modifiers, app_cursor) {
                        term.term.lock().scroll_display(Scroll::Bottom);
                        term.selection = None;
                        term.write(&bytes);
                    }
                    if modifiers.ctrl && modifiers.shift && key == Key::C {
                        if let Some(txt) = selected_text(term) {
                            ui.ctx().copy_text(txt);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    resp.context_menu(|ui| {
        if ui.button("Copy").clicked() {
            if let Some(txt) = selected_text(term) {
                ui.ctx().copy_text(txt);
            }
            ui.close();
        }
        if ui.button("Clear selection").clicked() {
            term.selection = None;
            ui.close();
        }
    });

    // ---- Paint ----
    let term_lock = term.term.lock();
    let content = term_lock.renderable_content();
    let offset = content.display_offset as i32;
    let sel = term.selection.map(|(a, b)| if (a.line, a.column) <= (b.line, b.column) { (a, b) } else { (b, a) });
    let q = term.search.to_lowercase();
    let mut lines: Vec<Vec<(char, Color32, Option<Color32>, bool, bool)>> = vec![Vec::with_capacity(cols); rows];
    for cell in content.display_iter {
        let vis = cell.point.line.0 + offset;
        if vis < 0 || vis as usize >= rows || cell.point.column.0 >= cols {
            continue;
        }
        let flags = cell.flags;
        if flags.contains(Flags::WIDE_CHAR_SPACER) {
            continue;
        }
        let mut fg = resolve(cell.fg, true, t).unwrap_or(t.text());
        let mut bg = resolve(cell.bg, false, t);
        if flags.contains(Flags::INVERSE) {
            let b = bg.unwrap_or(t.editor());
            bg = Some(fg);
            fg = b;
        }
        if flags.contains(Flags::DIM) {
            fg = fg.gamma_multiply(0.65);
        }
        let row = &mut lines[vis as usize];
        while row.len() < cell.point.column.0 {
            row.push((' ', t.text(), None, false, false));
        }
        let selected = sel.is_some_and(|(a, b)| (cell.point.line, cell.point.column) >= (a.line, a.column) && (cell.point.line, cell.point.column) <= (b.line, b.column));
        row.push((if flags.contains(Flags::HIDDEN) { ' ' } else { cell.c }, fg, bg, flags.intersects(Flags::ITALIC), selected));
    }
    let cursor = content.cursor.point;
    let cursor_visible = content.mode.contains(TermMode::SHOW_CURSOR);
    drop(term_lock);

    for (r, row) in lines.iter().enumerate() {
        let y = inner.top() + r as f32 * row_h;
        // Backgrounds and selection.
        for (c, cell) in row.iter().enumerate() {
            let x = inner.left() + c as f32 * char_w;
            if cell.4 {
                painter.rect_filled(Rect::from_min_size(pos2(x, y), vec2(char_w, row_h)), 0.0, t.accent().gamma_multiply(0.32));
            } else if let Some(bg) = cell.2 {
                painter.rect_filled(Rect::from_min_size(pos2(x, y), vec2(char_w + 0.5, row_h)), 0.0, bg);
            }
        }
        // Search highlights.
        if !q.is_empty() {
            let s: String = row.iter().map(|c| c.0).collect::<String>().to_lowercase();
            let mut from = 0;
            while let Some(i) = s[from..].find(&q) {
                let start = s[..from + i].chars().count();
                let n = q.chars().count();
                painter.rect_filled(
                    Rect::from_min_size(pos2(inner.left() + start as f32 * char_w, y), vec2(n as f32 * char_w, row_h)),
                    CornerRadius::same(2),
                    t.warning().gamma_multiply(0.35),
                );
                from += i + q.len().max(1);
            }
        }
        // Text runs.
        let mut job = LayoutJob::default();
        let mut run = String::new();
        let mut run_fmt: Option<(Color32, bool)> = None;
        for cell in row {
            let fmt = (cell.1, cell.3);
            if run_fmt != Some(fmt) {
                if let Some((col, it)) = run_fmt {
                    job.append(&run, 0.0, TextFormat { font_id: font.clone(), color: col, italics: it, ..Default::default() });
                }
                run.clear();
                run_fmt = Some(fmt);
            }
            run.push(cell.0);
        }
        if let Some((col, it)) = run_fmt {
            job.append(&run, 0.0, TextFormat { font_id: font.clone(), color: col, italics: it, ..Default::default() });
        }
        if !job.text.is_empty() {
            painter.galley(pos2(inner.left(), y + (row_h - font_size * 1.2) / 2.0), painter.layout_job(job), t.text());
        }
    }
    let cv = cursor.line.0 + offset;
    if cursor_visible && cv >= 0 && (cv as usize) < rows {
        let r = Rect::from_min_size(pos2(inner.left() + cursor.column.0 as f32 * char_w, inner.top() + cv as f32 * row_h), vec2(char_w, row_h));
        if focused {
            painter.rect_filled(r, CornerRadius::same(1), t.accent().gamma_multiply(0.75));
        } else {
            painter.rect_stroke(r, CornerRadius::same(1), egui::Stroke::new(1.0, t.accent().gamma_multiply(0.6)), egui::StrokeKind::Inside);
        }
    }
    if let Some(code) = term.poll_exit() {
        let msg = format!("Process exited with code {code}");
        painter.text(rect.right_bottom() - vec2(12.0, 10.0), egui::Align2::RIGHT_BOTTOM, msg, FontId::proportional(12.0), if code == 0 { t.success() } else { t.error() });
    }
    ui.advance_cursor_after_rect(rect);
}

fn selected_text(term: &Terminal) -> Option<String> {
    let (a, b) = term.selection?;
    let (a, b) = if (a.line, a.column) <= (b.line, b.column) { (a, b) } else { (b, a) };
    let lock = term.term.lock();
    let grid = lock.grid();
    let mut out = String::new();
    for l in a.line.0..=b.line.0 {
        let row = &grid[Line(l)];
        let c0 = if l == a.line.0 { a.column.0 } else { 0 };
        let c1 = if l == b.line.0 { b.column.0 } else { grid.columns() - 1 };
        let mut s: String = (c0..=c1.min(grid.columns() - 1)).map(|c| row[Column(c)].c).collect();
        s.truncate(s.trim_end().len());
        out.push_str(&s);
        if l != b.line.0 {
            out.push('\n');
        }
    }
    Some(out)
}

/// Key → bytes for the PTY (xterm conventions).
pub fn key_bytes(key: Key, m: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    let csi = |s: &str| Some(format!("\x1b[{s}").into_bytes());
    let arrow = |c: char| {
        if m.ctrl {
            Some(format!("\x1b[1;5{c}").into_bytes())
        } else if app_cursor {
            Some(format!("\x1bO{c}").into_bytes())
        } else {
            Some(format!("\x1b[{c}").into_bytes())
        }
    };
    if m.ctrl && !m.shift && !m.alt {
        let name = key.name();
        if name.len() == 1 {
            let ch = name.chars().next()?.to_ascii_lowercase();
            if ch.is_ascii_lowercase() {
                return Some(vec![(ch as u8) & 0x1f]);
            }
        }
    }
    match key {
        Key::Enter => Some(b"\r".to_vec()),
        Key::Backspace => Some(if m.ctrl { vec![0x17] } else { vec![0x7f] }),
        Key::Tab => Some(if m.shift { b"\x1b[Z".to_vec() } else { b"\t".to_vec() }),
        Key::Escape => Some(vec![0x1b]),
        Key::ArrowUp => arrow('A'),
        Key::ArrowDown => arrow('B'),
        Key::ArrowRight => arrow('C'),
        Key::ArrowLeft => arrow('D'),
        Key::Home => csi("H"),
        Key::End => csi("F"),
        Key::Delete => csi("3~"),
        Key::Insert => csi("2~"),
        Key::PageUp => csi("5~"),
        Key::PageDown => csi("6~"),
        Key::F1 => Some(b"\x1bOP".to_vec()),
        Key::F2 => Some(b"\x1bOQ".to_vec()),
        Key::F3 => Some(b"\x1bOR".to_vec()),
        Key::F4 => Some(b"\x1bOS".to_vec()),
        Key::F5 => csi("15~"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_encoding() {
        let none = egui::Modifiers::NONE;
        assert_eq!(key_bytes(Key::Enter, none, false).unwrap(), b"\r");
        assert_eq!(key_bytes(Key::ArrowUp, none, false).unwrap(), b"\x1b[A");
        assert_eq!(key_bytes(Key::ArrowUp, none, true).unwrap(), b"\x1bOA");
        assert_eq!(key_bytes(Key::C, egui::Modifiers::CTRL, false).unwrap(), vec![3]);
        assert_eq!(key_bytes(Key::A, none, false), None);
    }

    #[test]
    fn login_shell_is_listed_first_and_titles_hide_paths() {
        assert_eq!(ShellKind::available()[0], ShellKind::Login);
        assert!(looks_like_exe_path("/nix/store/abc-bash-5.3/bin/bash"));
        assert!(looks_like_exe_path("/run/current-system/sw/bin/zsh"));
        assert!(!looks_like_exe_path("user@nixos: ~/Projects"));
        assert!(!looks_like_exe_path("vim /etc/hosts"));
    }

    #[test]
    fn palette_cube() {
        assert_eq!(palette(16), Color32::from_rgb(0, 0, 0));
        assert_eq!(palette(231), Color32::from_rgb(255, 255, 255));
        assert_eq!(palette(232), Color32::from_rgb(8, 8, 8));
    }

    #[test]
    fn spawns_shell_and_reads_output() {
        let dir = std::env::temp_dir();
        // `sh` keeps the test independent of the user's shell configuration.
        let sh = ShellKind::Custom { program: "sh".into(), args: vec![], label: "sh".into() };
        let mut t = match Terminal::spawn(1, sh, &dir, Arc::new(|| {})) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("SKIPPED: no PTY: {e}");
                return;
            }
        };
        t.write(b"echo nexus_ok_42\r");
        let mut found = false;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if t.text(200).contains("nexus_ok_42") {
                found = true;
                break;
            }
        }
        t.write(b"exit 3\r");
        assert!(found, "terminal output: {}", t.text(50));
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if t.poll_exit().is_some() {
                break;
            }
        }
        assert_eq!(t.poll_exit(), Some(3));
    }
}
