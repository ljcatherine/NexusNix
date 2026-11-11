//! The code editor widget (egui). Virtualized: only visible lines are laid out.

use crate::buffer::{Buffer, Selection};
use crate::highlight::{comment_prefix, syntax_for, HighlightCache};
use egui::text::{LayoutJob, TextFormat};
use egui::{pos2, vec2, Align2, Color32, CornerRadius, Event, FontId, Key, Modifiers, Pos2, Rect, Sense, Stroke, StrokeKind, Ui};
use nexus_ui::{white_a, Tokens};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GutterMark {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub line: usize,
    pub col: usize,
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct FindState {
    pub open: bool,
    pub query: String,
    pub case_sensitive: bool,
    pub regex: bool,
    pub replace: String,
    pub matches: Vec<(usize, usize)>,
    pub current: usize,
    computed_for: Option<(u64, String, bool, bool)>,
}

/// An open document.
pub struct Document {
    pub path: Option<PathBuf>,
    /// Workspace-relative display path.
    pub rel: String,
    pub buffer: Buffer,
    pub highlight: HighlightCache,
    pub gutter: Vec<(usize, GutterMark)>,
    pub diagnostics: Vec<Diagnostic>,
    pub find: FindState,
    pub read_only: bool,
    pub read_only_reason: Option<String>,
    pub scroll_to_line: Option<usize>,
    pub comment: &'static str,
    longest_line: (u64, usize),
    pub last_disk_hash: Option<String>,
}

impl Document {
    pub fn new(rel: &str, path: Option<PathBuf>, text: &str) -> Self {
        let first = text.lines().next().unwrap_or("");
        let syntax = syntax_for(rel, first);
        Self {
            path,
            rel: rel.to_string(),
            buffer: Buffer::new(text),
            highlight: HighlightCache::new(syntax),
            gutter: Vec::new(),
            diagnostics: Vec::new(),
            find: FindState::default(),
            read_only: false,
            read_only_reason: None,
            scroll_to_line: None,
            comment: comment_prefix(syntax),
            longest_line: (u64::MAX, 0),
            last_disk_hash: None,
        }
    }

    pub fn title(&self) -> String {
        self.rel.rsplit('/').next().unwrap_or(&self.rel).to_string()
    }

    pub fn language(&self) -> &str {
        self.highlight.syntax_name()
    }

    pub fn cursor_lc(&self) -> (usize, usize) {
        self.buffer.char_to_lc(self.buffer.sels.last().map(|s| s.head).unwrap_or(0))
    }

    pub fn goto_line(&mut self, line: usize, col: usize) {
        let c = self.buffer.lc_to_char(line, col);
        self.buffer.set_caret(c, false);
        self.scroll_to_line = Some(line);
    }

    fn longest(&mut self) -> usize {
        if self.longest_line.0 != self.buffer.version {
            let n = (0..self.buffer.line_count().min(200_000)).map(|i| display_len(&self.buffer.line(i))).max().unwrap_or(0);
            self.longest_line = (self.buffer.version, n);
        }
        self.longest_line.1
    }

    fn refresh_find(&mut self) {
        let key = (self.buffer.version, self.find.query.clone(), self.find.case_sensitive, self.find.regex);
        if self.find.computed_for.as_ref() == Some(&key) {
            return;
        }
        self.find.matches.clear();
        if !self.find.query.is_empty() {
            let pat = if self.find.regex { self.find.query.clone() } else { regex::escape(&self.find.query) };
            if let Ok(re) = regex::RegexBuilder::new(&pat).case_insensitive(!self.find.case_sensitive).build() {
                let text = self.buffer.text();
                for m in re.find_iter(&text).take(50_000) {
                    if m.start() == m.end() {
                        continue;
                    }
                    let a = self.buffer.rope.byte_to_char(m.start());
                    let b = self.buffer.rope.byte_to_char(m.end());
                    self.find.matches.push((a, b));
                }
            }
        }
        self.find.current = self.find.current.min(self.find.matches.len().saturating_sub(1));
        self.find.computed_for = Some(key);
    }

    pub fn find_next(&mut self, back: bool) {
        self.refresh_find();
        if self.find.matches.is_empty() {
            return;
        }
        let caret = self.buffer.sels.last().map(|s| s.end()).unwrap_or(0);
        let idx = if back {
            let start = self.buffer.sels.last().map(|s| s.start()).unwrap_or(0);
            self.find.matches.iter().rposition(|m| m.0 < start).unwrap_or(self.find.matches.len() - 1)
        } else {
            self.find.matches.iter().position(|m| m.0 >= caret).unwrap_or(0)
        };
        self.find.current = idx;
        let (a, b) = self.find.matches[idx];
        self.buffer.sels = vec![Selection { anchor: a, head: b, goal_col: None }];
        self.scroll_to_line = Some(self.buffer.char_to_lc(a).0);
    }

    pub fn replace_current(&mut self) {
        if self.read_only {
            return;
        }
        self.refresh_find();
        let sel = *self.buffer.sels.last().unwrap();
        if self.find.matches.iter().any(|m| *m == (sel.start(), sel.end())) {
            let r = self.find.replace.clone();
            self.buffer.insert_text(&r);
        }
        self.find_next(false);
    }

    pub fn replace_all(&mut self) -> usize {
        if self.read_only {
            return 0;
        }
        self.refresh_find();
        let n = self.find.matches.len();
        if n == 0 {
            return 0;
        }
        self.buffer.sels = self.find.matches.iter().map(|(a, b)| Selection { anchor: *a, head: *b, goal_col: None }).collect();
        let r = self.find.replace.clone();
        self.buffer.replace_selections(crate::buffer::EditKind::Other, |_, _| r.clone());
        n
    }
}

const TAB: usize = 4;

fn display_len(line: &str) -> usize {
    let mut n = 0;
    for ch in line.chars() {
        n = if ch == '\t' { (n / TAB + 1) * TAB } else { n + 1 };
    }
    n
}

/// Display column of char column `c` in `line` (tabs expanded).
fn display_col(line: &str, c: usize) -> usize {
    let mut n = 0;
    for ch in line.chars().take(c) {
        n = if ch == '\t' { (n / TAB + 1) * TAB } else { n + 1 };
    }
    n
}

/// Char column for a display column.
fn char_col(line: &str, dc: usize) -> usize {
    let mut n = 0;
    for (i, ch) in line.chars().enumerate() {
        let w = if ch == '\t' { (n / TAB + 1) * TAB - n } else { 1 };
        if dc < n + w.div_ceil(2).max(1) || dc < n + w && ch != '\t' {
            return i;
        }
        n += w;
    }
    line.chars().count()
}

fn expand_tabs(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut n = 0;
    for ch in line.chars() {
        if ch == '\t' {
            let w = (n / TAB + 1) * TAB - n;
            out.extend(std::iter::repeat_n(' ', w));
            n += w;
        } else {
            out.push(ch);
            n += 1;
        }
    }
    out
}

#[derive(Default)]
pub struct EditorOutput {
    pub changed: bool,
    pub focused: bool,
    /// Ctrl+K pressed: inline AI edit on the current selection.
    pub inline_ai: bool,
    pub save: bool,
}

#[derive(Clone, Copy, Default)]
struct ClickState {
    last_time: f64,
    count: u8,
    last_pos: Option<Pos2>,
}

pub fn show(ui: &mut Ui, doc: &mut Document, t: &Tokens, font_size: f32) -> EditorOutput {
    let mut out = EditorOutput::default();
    let font = FontId::monospace(font_size);
    let row_h = (font_size * 1.55).round();
    let char_w = ui.painter().layout_no_wrap("MMMMMMMMMM".into(), font.clone(), Color32::WHITE).size().x / 10.0;
    let lines = doc.buffer.line_count();
    let digits = lines.to_string().len().max(3) as f32;
    let gutter_w = digits * char_w + 34.0;
    let minimap_w = 72.0;
    let id = ui.make_persistent_id(("nexus_editor", doc.rel.as_str()));

    if let Some(from) = doc.buffer.take_dirty_from() {
        doc.highlight.invalidate_from(from);
        out.changed = true;
    }
    if doc.find.open {
        doc.refresh_find();
    }

    let full = ui.available_rect_before_wrap();
    ui.painter().rect_filled(full, CornerRadius::ZERO, t.editor());
    let text_area = Rect::from_min_max(full.min, pos2(full.right() - minimap_w, full.bottom()));
    let content_w = gutter_w + (doc.longest() as f32 + 8.0) * char_w;
    let content_h = lines as f32 * row_h + full.height() * 0.6;

    let mut scroll = egui::ScrollArea::both().id_salt(id.with("scroll")).auto_shrink([false, false]);
    if let Some(l) = doc.scroll_to_line.take() {
        let cur = ui.ctx().data(|d| d.get_temp::<f32>(id.with("scroll_y"))).unwrap_or(0.0);
        let y = l as f32 * row_h;
        let h = text_area.height();
        if y < cur || y + row_h > cur + h {
            scroll = scroll.vertical_scroll_offset((y - h * 0.35).max(0.0));
        }
    }
    let mut minimap_jump: Option<f32> = None;
    if let Some(y) = ui.ctx().data_mut(|d| d.remove_temp::<f32>(id.with("jump"))) {
        scroll = scroll.vertical_scroll_offset(y);
    }

    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(text_area));
    let scroll_out = scroll.show_viewport(&mut child, |ui, viewport| {
        let (rect, resp) = ui.allocate_exact_size(vec2(content_w.max(viewport.width()), content_h), Sense::click_and_drag());
        let resp = resp.on_hover_cursor(egui::CursorIcon::Text);
        let origin = rect.min;
        let painter = ui.painter_at(ui.clip_rect());
        let first = (viewport.top() / row_h).floor().max(0.0) as usize;
        let last = ((viewport.bottom() / row_h).ceil() as usize + 1).min(lines);
        doc.highlight.ensure(last, |i| doc.buffer.line(i));
        let text_x = origin.x + gutter_w;
        let gutter_x = origin.x + viewport.left();
        let pos_of = |line: usize, dcol: usize| pos2(text_x + dcol as f32 * char_w, origin.y + line as f32 * row_h);

        // ---- Focus & mouse ----
        if resp.clicked() || resp.drag_started() {
            resp.request_focus();
        }
        let focused = resp.has_focus();
        out.focused = focused;
        if focused {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: false })
            });
        }
        let hit = |p: Pos2, buf: &Buffer| -> usize {
            let line = (((p.y - origin.y) / row_h).floor().max(0.0) as usize).min(lines.saturating_sub(1));
            let text = buf.line(line);
            let dc = ((p.x - text_x) / char_w + 0.5).max(0.0) as usize;
            buf.lc_to_char(line, char_col(&text, dc))
        };
        let mods = ui.input(|i| i.modifiers);
        if let Some(p) = resp.interact_pointer_pos() {
            let c = hit(p, &doc.buffer);
            if resp.drag_started() || resp.clicked() {
                let now = ui.input(|i| i.time);
                let mut cs: ClickState = ui.ctx().data(|d| d.get_temp(id.with("clicks"))).unwrap_or_default();
                let near = cs.last_pos.is_some_and(|lp| lp.distance(p) < 6.0);
                cs.count = if now - cs.last_time < 0.4 && near { (cs.count % 3) + 1 } else { 1 };
                cs.last_time = now;
                cs.last_pos = Some(p);
                ui.ctx().data_mut(|d| d.insert_temp(id.with("clicks"), cs));
                if resp.drag_started() || cs.count == 1 {
                    if mods.alt {
                        doc.buffer.add_caret(c);
                    } else {
                        doc.buffer.set_caret(c, mods.shift);
                    }
                }
                if cs.count == 2 {
                    let (a, b) = doc.buffer.word_at(c);
                    doc.buffer.sels = vec![Selection { anchor: a, head: b, goal_col: None }];
                } else if cs.count == 3 {
                    let (l, _) = doc.buffer.char_to_lc(c);
                    let a = doc.buffer.lc_to_char(l, 0);
                    let b = if l + 1 < lines { doc.buffer.lc_to_char(l + 1, 0) } else { doc.buffer.len() };
                    doc.buffer.sels = vec![Selection { anchor: a, head: b, goal_col: None }];
                }
            } else if resp.dragged() {
                if let Some(s) = doc.buffer.sels.last_mut() {
                    s.head = c;
                    s.goal_col = None;
                }
            }
        }

        // ---- Keyboard ----
        let mut moved = false;
        if focused {
            let events = ui.input(|i| i.events.clone());
            for ev in events {
                match ev {
                    Event::Text(s) if !doc.read_only => {
                        if !s.chars().all(char::is_control) {
                            let pair = match s.as_str() {
                                "(" => Some(")"),
                                "[" => Some("]"),
                                "{" => Some("}"),
                                "\"" => Some("\""),
                                _ => None,
                            };
                            let all_sel = doc.buffer.sels.iter().all(|s| !s.is_empty());
                            if let (Some(close), true) = (pair, all_sel) {
                                doc.buffer.replace_selections(crate::buffer::EditKind::Other, |_, sel| format!("{s}{sel}{close}"));
                            } else {
                                // Type over an auto-inserted closer.
                                let skip = doc.buffer.sels.len() == 1 && doc.buffer.sels[0].is_empty() && {
                                    let h = doc.buffer.sels[0].head;
                                    h < doc.buffer.len() && matches!(s.as_str(), ")" | "]" | "}" | "\"") && doc.buffer.rope.char(h).to_string() == s
                                };
                                if skip {
                                    doc.buffer.move_horiz(1, false, false);
                                } else {
                                    doc.buffer.insert_text(&s);
                                }
                            }
                            moved = true;
                        }
                    }
                    Event::Ime(egui::ImeEvent::Commit(s)) if !doc.read_only => {
                        doc.buffer.insert_text(&s);
                        moved = true;
                    }
                    Event::Paste(s) if !doc.read_only => {
                        doc.buffer.insert_text(&s);
                        moved = true;
                    }
                    Event::Copy => {
                        let mut tmp_sels = doc.buffer.sels.clone();
                        if tmp_sels.iter().all(|s| s.is_empty()) {
                            doc.buffer.expand_empty_to_lines();
                            ui.ctx().copy_text(doc.buffer.selected_text());
                            std::mem::swap(&mut doc.buffer.sels, &mut tmp_sels);
                        } else {
                            ui.ctx().copy_text(doc.buffer.selected_text());
                        }
                    }
                    Event::Cut if !doc.read_only => {
                        if doc.buffer.sels.iter().all(|s| s.is_empty()) {
                            doc.buffer.expand_empty_to_lines();
                        }
                        ui.ctx().copy_text(doc.buffer.selected_text());
                        doc.buffer.replace_selections(crate::buffer::EditKind::Other, |_, _| String::new());
                        moved = true;
                    }
                    Event::Key { key, pressed: true, modifiers, .. } => {
                        moved |= handle_key(doc, key, modifiers, &mut out, (text_area.height() / row_h) as isize);
                    }
                    _ => {}
                }
            }
        }

        // ---- Painting ----
        let caret_line = doc.cursor_lc().0;
        // Current line
        if focused || doc.buffer.sels.len() == 1 {
            let y = origin.y + caret_line as f32 * row_h;
            painter.rect_filled(Rect::from_min_size(pos2(gutter_x, y), vec2(viewport.width(), row_h)), 0.0, white_a(0.028));
        }
        // Find matches
        if doc.find.open {
            for (k, (a, b)) in doc.find.matches.iter().enumerate() {
                let (la, ca) = doc.buffer.char_to_lc(*a);
                if la < first || la > last {
                    continue;
                }
                let (lb, cb) = doc.buffer.char_to_lc(*b);
                let line = doc.buffer.line(la);
                let x0 = display_col(&line, ca);
                let x1 = if lb == la { display_col(&line, cb) } else { display_len(&line) };
                let r = Rect::from_min_max(pos_of(la, x0), pos_of(la, x1) + vec2(0.0, row_h));
                let col = if k == doc.find.current { t.warning().gamma_multiply(0.45) } else { t.warning().gamma_multiply(0.18) };
                painter.rect_filled(r, CornerRadius::same(2), col);
            }
        }
        // Selections
        for s in &doc.buffer.sels {
            if s.is_empty() {
                continue;
            }
            let (la, ca) = doc.buffer.char_to_lc(s.start());
            let (lb, cb) = doc.buffer.char_to_lc(s.end());
            for l in la.max(first)..=lb.min(last.saturating_sub(1).max(la)) {
                if l < first || l >= last.max(first + 1) {
                    continue;
                }
                let text = doc.buffer.line(l);
                let x0 = if l == la { display_col(&text, ca) } else { 0 };
                let x1 = if l == lb { display_col(&text, cb) } else { display_len(&text) + 1 };
                let r = Rect::from_min_max(pos_of(l, x0), pos_of(l, x1) + vec2(0.0, row_h));
                painter.rect_filled(r, CornerRadius::same(3), t.accent().gamma_multiply(if focused { 0.30 } else { 0.18 }));
            }
        }
        // Bracket match
        if let Some(s) = doc.buffer.sels.last() {
            if s.is_empty() {
                if let Some((a, b)) = doc.buffer.matching_bracket(s.head) {
                    for c in [a, b] {
                        let (l, cc) = doc.buffer.char_to_lc(c);
                        if l >= first && l < last {
                            let dc = display_col(&doc.buffer.line(l), cc);
                            let r = Rect::from_min_size(pos_of(l, dc), vec2(char_w, row_h));
                            painter.rect_stroke(r, CornerRadius::same(2), Stroke::new(1.0, t.accent().gamma_multiply(0.7)), StrokeKind::Inside);
                        }
                    }
                }
            }
        }
        // Text
        for l in first..last {
            let line = doc.buffer.line(l);
            let shown = expand_tabs(&line);
            let mut job = LayoutJob::default();
            let base = TextFormat { font_id: font.clone(), color: t.text(), ..Default::default() };
            match doc.highlight.line(l) {
                Some(spans) if !spans.is_empty() && !line.contains('\t') => {
                    let mut pos = 0;
                    for (range, color, italic) in spans {
                        if range.start > pos {
                            job.append(&line[pos..range.start], 0.0, base.clone());
                        }
                        let end = range.end.min(line.len());
                        if range.start < end && line.is_char_boundary(range.start) && line.is_char_boundary(end) {
                            job.append(&line[range.start..end], 0.0, TextFormat { color: *color, italics: *italic, ..base.clone() });
                        }
                        pos = end.max(pos);
                    }
                    if pos < line.len() && line.is_char_boundary(pos) {
                        job.append(&line[pos..], 0.0, base.clone());
                    }
                }
                Some(spans) if !spans.is_empty() => {
                    // Tabs present: colour by first span only to keep columns exact.
                    job.append(&shown, 0.0, TextFormat { color: spans[0].1, ..base.clone() });
                }
                _ => job.append(&shown, 0.0, base.clone()),
            }
            let galley = painter.layout_job(job);
            painter.galley(pos_of(l, 0) + vec2(0.0, (row_h - font_size * 1.2) / 2.0), galley, t.text());
            // Indent guides
            let ind = shown.chars().take_while(|c| *c == ' ').count();
            let unit = doc.buffer.indent.chars().count().max(1);
            let mut g = unit;
            while g < ind {
                let x = text_x + g as f32 * char_w;
                painter.line_segment([pos2(x, origin.y + l as f32 * row_h), pos2(x, origin.y + (l + 1) as f32 * row_h)], Stroke::new(1.0, white_a(0.04)));
                g += unit;
            }
        }
        // Diagnostics underline
        for d in &doc.diagnostics {
            if d.line < first || d.line >= last {
                continue;
            }
            let line = doc.buffer.line(d.line);
            let x0 = display_col(&line, d.col);
            let x1 = display_len(&line).max(x0 + 1);
            let y = origin.y + (d.line + 1) as f32 * row_h - 3.0;
            let col = match d.severity {
                Severity::Error => t.error(),
                Severity::Warning => t.warning(),
                Severity::Info => t.accent(),
            };
            let mut pts = Vec::new();
            let mut x = text_x + x0 as f32 * char_w;
            let end = text_x + x1 as f32 * char_w;
            let mut up = true;
            while x < end {
                pts.push(pos2(x, if up { y } else { y + 2.0 }));
                x += 3.0;
                up = !up;
            }
            painter.add(egui::Shape::line(pts, Stroke::new(1.0, col)));
        }
        // Carets
        if focused || !doc.read_only {
            for s in &doc.buffer.sels {
                let (l, c) = doc.buffer.char_to_lc(s.head);
                if l < first || l >= last {
                    continue;
                }
                let dc = display_col(&doc.buffer.line(l), c);
                let p = pos_of(l, dc);
                let col = if focused { t.accent() } else { t.text2().gamma_multiply(0.5) };
                painter.rect_filled(Rect::from_min_size(p + vec2(-0.5, 2.0), vec2(2.0, row_h - 4.0)), CornerRadius::same(1), col);
            }
        }
        // Gutter (drawn last so it covers horizontally scrolled text)
        let gutter_rect = Rect::from_min_size(pos2(gutter_x, origin.y + viewport.top()), vec2(gutter_w - 8.0, viewport.height()));
        painter.rect_filled(gutter_rect, 0.0, t.editor());
        for l in first..last {
            let y = origin.y + l as f32 * row_h;
            let col = if l == caret_line { t.text() } else { t.text2().gamma_multiply(0.55) };
            painter.text(pos2(gutter_x + gutter_w - 22.0, y + row_h / 2.0), Align2::RIGHT_CENTER, (l + 1).to_string(), FontId::monospace(font_size - 1.5), col);
        }
        for (l, m) in &doc.gutter {
            if *l < first || *l >= last {
                continue;
            }
            let y = origin.y + *l as f32 * row_h;
            let (col, h) = match m {
                GutterMark::Added => (t.success(), row_h),
                GutterMark::Modified => (t.accent(), row_h),
                GutterMark::Deleted => (t.error(), 3.0),
            };
            painter.rect_filled(Rect::from_min_size(pos2(gutter_x + gutter_w - 14.0, y + (row_h - h) / 2.0), vec2(3.0, h)), CornerRadius::same(1), col);
        }
        for d in &doc.diagnostics {
            if d.line >= first && d.line < last {
                let y = origin.y + d.line as f32 * row_h + row_h / 2.0;
                let col = match d.severity {
                    Severity::Error => t.error(),
                    Severity::Warning => t.warning(),
                    Severity::Info => t.accent(),
                };
                painter.circle_filled(pos2(gutter_x + 8.0, y), 3.0, col);
            }
        }
        // Hover tooltip for diagnostics
        if let Some(hp) = resp.hover_pos() {
            let line = ((hp.y - origin.y) / row_h).floor() as usize;
            let msgs: Vec<&str> = doc.diagnostics.iter().filter(|d| d.line == line).map(|d| d.message.as_str()).collect();
            if !msgs.is_empty() {
                resp.clone().on_hover_text(msgs.join("\n"));
            }
        }
        // Keep caret visible after keyboard input.
        if moved {
            if let Some(s) = doc.buffer.sels.last() {
                let (l, c) = doc.buffer.char_to_lc(s.head);
                let dc = display_col(&doc.buffer.line(l), c);
                let r = Rect::from_min_size(pos_of(l, dc), vec2(char_w, row_h)).expand2(vec2(char_w * 4.0, row_h));
                ui.scroll_to_rect(r, None);
            }
        }
        if out.changed || moved {
            ui.ctx().request_repaint();
        }
    });
    ui.ctx().data_mut(|d| d.insert_temp(id.with("scroll_y"), scroll_out.state.clamped_offset().y));

    // ---- Minimap ----
    let mm = Rect::from_min_max(pos2(full.right() - minimap_w, full.top()), full.max);
    let p = ui.painter_at(mm);
    p.rect_filled(mm, 0.0, t.editor().gamma_multiply(0.92));
    p.line_segment([mm.left_top(), mm.left_bottom()], Stroke::new(1.0, white_a(0.05)));
    let total = lines.max(1) as f32;
    let scale = (mm.height() / total).min(3.0);
    let step = ((total * scale / mm.height()).ceil() as usize).max(1);
    let mut l = 0;
    while l < lines.min(400_000) {
        let line = doc.buffer.line(l);
        let ind = display_len(&line) - display_len(line.trim_start());
        let len = display_len(line.trim());
        if len > 0 {
            let y = mm.top() + l as f32 * scale;
            let col = doc.highlight.line(l).and_then(|s| s.iter().find(|x| x.0.start >= ind.min(line.len())).map(|x| x.1)).unwrap_or(t.text2());
            p.line_segment(
                [pos2(mm.left() + 6.0 + ind as f32 * 0.6, y), pos2(mm.left() + 6.0 + (ind + len).min(100) as f32 * 0.6, y)],
                Stroke::new(scale.clamp(1.0, 2.0), col.gamma_multiply(0.45)),
            );
        }
        l += step;
    }
    let vis_top = scroll_out.state.clamped_offset().y / row_h;
    let vis_n = text_area.height() / row_h;
    let vr = Rect::from_min_size(pos2(mm.left(), mm.top() + vis_top * scale), vec2(minimap_w, (vis_n * scale).max(8.0)));
    p.rect_filled(vr, CornerRadius::same(2), white_a(0.06));
    let mresp = ui.interact(mm, id.with("minimap"), Sense::click_and_drag());
    if let Some(pp) = mresp.interact_pointer_pos() {
        let line = ((pp.y - mm.top()) / scale - vis_n / 2.0).max(0.0);
        minimap_jump = Some(line * row_h);
    }
    if let Some(y) = minimap_jump {
        ui.ctx().data_mut(|d| d.insert_temp(id.with("jump"), y.min(content_h)));
        ui.ctx().request_repaint();
    }
    ui.advance_cursor_after_rect(full);
    out
}

fn handle_key(doc: &mut Document, key: Key, m: Modifiers, out: &mut EditorOutput, page: isize) -> bool {
    let ro = doc.read_only;
    let b = &mut doc.buffer;
    let cmd = m.command;
    match key {
        Key::ArrowLeft => b.move_horiz(-1, m.shift, cmd),
        Key::ArrowRight => b.move_horiz(1, m.shift, cmd),
        Key::ArrowUp if m.alt && !ro => return false,
        Key::ArrowUp => b.move_vert(-1, m.shift),
        Key::ArrowDown => b.move_vert(1, m.shift),
        Key::PageUp => b.move_vert(-page, m.shift),
        Key::PageDown => b.move_vert(page, m.shift),
        Key::Home if cmd => b.set_caret(0, m.shift),
        Key::End if cmd => {
            let n = b.len();
            b.set_caret(n, m.shift)
        }
        Key::Home => b.home(m.shift),
        Key::End => b.end(m.shift),
        Key::Backspace if !ro => {
            if cmd {
                b.move_horiz(-1, true, true);
            }
            b.backspace()
        }
        Key::Delete if !ro => {
            if cmd {
                b.move_horiz(1, true, true);
            }
            b.delete_forward()
        }
        Key::Enter if !ro && !cmd => b.newline(),
        Key::Tab if !ro => b.indent_lines(m.shift),
        Key::Escape => {
            if b.sels.len() > 1 {
                let last = *b.sels.last().unwrap();
                b.sels = vec![Selection::caret(last.head)];
            } else if doc.find.open {
                doc.find.open = false;
            }
        }
        Key::A if cmd => b.select_all(),
        Key::Z if cmd && m.shift && !ro => {
            b.redo();
        }
        Key::Z if cmd && !ro => {
            b.undo();
        }
        Key::Y if cmd && !ro => {
            b.redo();
        }
        Key::D if cmd => b.select_next_occurrence(),
        Key::Slash if cmd && !ro => {
            let p = doc.comment;
            b.toggle_comment(p);
        }
        Key::F if cmd => {
            doc.find.open = true;
            let sel = b.selected_text();
            if !sel.is_empty() && !sel.contains('\n') {
                doc.find.query = sel;
            }
        }
        Key::F3 => doc.find_next(m.shift),
        Key::K if cmd => out.inline_ai = true,
        Key::S if cmd => out.save = true,
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_display_columns() {
        assert_eq!(display_len("\tab"), 6);
        assert_eq!(display_col("a\tb", 2), 4);
        assert_eq!(expand_tabs("a\tb"), "a   b");
        assert_eq!(char_col("abc", 2), 2);
        assert_eq!(char_col("abc", 10), 3);
    }

    #[test]
    fn find_and_replace_all() {
        let mut d = Document::new("a.rs", None, "let a = a + a;");
        d.find.open = true;
        d.find.query = "a".into();
        d.find.replace = "b".into();
        d.find_next(false);
        assert_eq!(d.find.matches.len(), 3);
        assert_eq!(d.replace_all(), 3);
        assert_eq!(d.buffer.text(), "let b = b + b;");
        d.read_only = true;
        d.find.query = "b".into();
        assert_eq!(d.replace_all(), 0);
    }
}
