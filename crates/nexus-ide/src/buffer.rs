//! Text buffer: rope storage, multi-cursor selections, grouped undo/redo.

use ropey::Rope;

/// A selection: `anchor` stays fixed, `head` is the caret. Char indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub anchor: usize,
    pub head: usize,
    /// Preferred column for vertical movement.
    pub goal_col: Option<usize>,
}

impl Selection {
    pub fn caret(i: usize) -> Self {
        Self { anchor: i, head: i, goal_col: None }
    }
    pub fn start(&self) -> usize {
        self.anchor.min(self.head)
    }
    pub fn end(&self) -> usize {
        self.anchor.max(self.head)
    }
    pub fn is_empty(&self) -> bool {
        self.anchor == self.head
    }
}

#[derive(Clone, Debug)]
struct Edit {
    at: usize,
    removed: String,
    inserted: String,
}

#[derive(Clone, Debug)]
struct UndoGroup {
    edits: Vec<Edit>,
    before: Vec<Selection>,
    after: Vec<Selection>,
    kind: EditKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditKind {
    Typing,
    Delete,
    Other,
}

pub struct Buffer {
    pub rope: Rope,
    pub sels: Vec<Selection>,
    undo: Vec<UndoGroup>,
    redo: Vec<UndoGroup>,
    /// Increments on every change (for caches).
    pub version: u64,
    /// Version at last save.
    pub saved_version: u64,
    /// First line changed since the last `take_dirty_from` call.
    dirty_from: Option<usize>,
    pub line_ending: &'static str,
    pub indent: String,
}

impl Buffer {
    pub fn new(text: &str) -> Self {
        let line_ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let normalized = text.replace("\r\n", "\n");
        let indent = detect_indent(&normalized);
        Self {
            rope: Rope::from_str(&normalized),
            sels: vec![Selection::caret(0)],
            undo: Vec::new(),
            redo: Vec::new(),
            version: 0,
            saved_version: 0,
            dirty_from: Some(0),
            line_ending,
            indent,
        }
    }

    pub fn text(&self) -> String {
        self.rope.to_string()
    }

    /// Text with the file's original line endings, for saving.
    pub fn text_for_save(&self) -> String {
        let t = self.rope.to_string();
        if self.line_ending == "\r\n" { t.replace('\n', "\r\n") } else { t }
    }

    pub fn is_dirty(&self) -> bool {
        self.version != self.saved_version
    }

    pub fn mark_saved(&mut self) {
        self.saved_version = self.version;
    }

    pub fn len(&self) -> usize {
        self.rope.len_chars()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn line_count(&self) -> usize {
        self.rope.len_lines()
    }

    /// Line text without the trailing newline.
    pub fn line(&self, i: usize) -> String {
        if i >= self.rope.len_lines() {
            return String::new();
        }
        let mut s = self.rope.line(i).to_string();
        if s.ends_with('\n') {
            s.pop();
        }
        s
    }

    pub fn line_len(&self, i: usize) -> usize {
        self.line(i).chars().count()
    }

    pub fn char_to_lc(&self, c: usize) -> (usize, usize) {
        let c = c.min(self.len());
        let l = self.rope.char_to_line(c);
        (l, c - self.rope.line_to_char(l))
    }

    pub fn lc_to_char(&self, line: usize, col: usize) -> usize {
        let line = line.min(self.line_count().saturating_sub(1));
        self.rope.line_to_char(line) + col.min(self.line_len(line))
    }

    pub fn take_dirty_from(&mut self) -> Option<usize> {
        self.dirty_from.take()
    }

    fn touch(&mut self, line: usize) {
        self.version += 1;
        self.dirty_from = Some(self.dirty_from.map_or(line, |d| d.min(line)));
    }

    fn apply(&mut self, e: &Edit) {
        let line = self.rope.char_to_line(e.at.min(self.len()));
        let rc = e.removed.chars().count();
        if rc > 0 {
            self.rope.remove(e.at..e.at + rc);
        }
        if !e.inserted.is_empty() {
            self.rope.insert(e.at, &e.inserted);
        }
        self.touch(line);
    }

    /// Replace each selection's range with the text produced by `f` (given the
    /// selection index and selected text). Selections become carets after the
    /// inserted text. Processes from last to first so indices stay valid.
    pub fn replace_selections(&mut self, kind: EditKind, mut f: impl FnMut(usize, &str) -> String) {
        let before = self.sels.clone();
        let mut order: Vec<usize> = (0..self.sels.len()).collect();
        order.sort_by_key(|i| std::cmp::Reverse(self.sels[*i].start()));
        let mut edits = Vec::new();
        let mut new_heads = vec![0usize; self.sels.len()];
        for &i in &order {
            let s = self.sels[i];
            let removed: String = self.rope.slice(s.start()..s.end()).to_string();
            let inserted = f(i, &removed);
            let e = Edit { at: s.start(), removed, inserted };
            self.apply(&e);
            new_heads[i] = s.start() + e.inserted.chars().count();
            // Shift heads of selections already processed (which are after this one).
            let delta = e.inserted.chars().count() as isize - e.removed.chars().count() as isize;
            for &j in &order {
                if j == i {
                    break;
                }
                new_heads[j] = (new_heads[j] as isize + delta) as usize;
            }
            edits.push(e);
        }
        for (i, h) in new_heads.into_iter().enumerate() {
            self.sels[i] = Selection::caret(h);
        }
        self.merge_selections();
        self.push_undo(UndoGroup { edits, before, after: self.sels.clone(), kind });
    }

    fn push_undo(&mut self, g: UndoGroup) {
        self.redo.clear();
        // Coalesce consecutive typing/deleting into one undo step.
        if let Some(last) = self.undo.last_mut() {
            if g.kind != EditKind::Other && last.kind == g.kind && last.after == g.before && g.edits.len() == 1 && last.edits.len() < 64 {
                let only_ws = g.edits[0].inserted.chars().all(char::is_whitespace) && !g.edits[0].inserted.is_empty();
                if !only_ws {
                    last.edits.extend(g.edits);
                    last.after = g.after;
                    return;
                }
            }
        }
        self.undo.push(g);
        if self.undo.len() > 2000 {
            self.undo.remove(0);
        }
    }

    pub fn undo(&mut self) -> bool {
        let Some(g) = self.undo.pop() else { return false };
        for e in g.edits.iter().rev() {
            self.apply(&Edit { at: e.at, removed: e.inserted.clone(), inserted: e.removed.clone() });
        }
        self.sels = g.before.clone();
        self.redo.push(g);
        true
    }

    pub fn redo(&mut self) -> bool {
        let Some(g) = self.redo.pop() else { return false };
        for e in &g.edits {
            self.apply(e);
        }
        self.sels = g.after.clone();
        self.undo.push(g);
        true
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    /// Replace the entire text as one undoable edit (used for accepting AI
    /// changes and formatting).
    pub fn set_text(&mut self, text: &str) {
        let normalized = text.replace("\r\n", "\n");
        let before = self.sels.clone();
        let e = Edit { at: 0, removed: self.rope.to_string(), inserted: normalized };
        self.apply(&e);
        let len = self.len();
        for s in &mut self.sels {
            *s = Selection::caret(s.head.min(len));
        }
        self.push_undo(UndoGroup { edits: vec![e], before, after: self.sels.clone(), kind: EditKind::Other });
    }

    pub fn insert_text(&mut self, t: &str) {
        let kind = if t.chars().count() == 1 { EditKind::Typing } else { EditKind::Other };
        let t = t.replace("\r\n", "\n");
        let lines: Vec<&str> = t.split('\n').collect();
        // Multi-cursor paste: one line per cursor when counts match.
        if self.sels.len() > 1 && lines.len() == self.sels.len() {
            let mut order: Vec<usize> = (0..self.sels.len()).collect();
            order.sort_by_key(|i| self.sels[*i].start());
            let mut map = vec![String::new(); self.sels.len()];
            for (k, i) in order.into_iter().enumerate() {
                map[i] = lines[k].to_string();
            }
            self.replace_selections(kind, |i, _| map[i].clone());
        } else {
            self.replace_selections(kind, |_, _| t.clone());
        }
    }

    /// Enter: newline plus the current line's indentation (and one more level
    /// after an opening bracket or colon).
    pub fn newline(&mut self) {
        let indents: Vec<String> = self
            .sels
            .iter()
            .map(|s| {
                let (l, c) = self.char_to_lc(s.start());
                let line = self.line(l);
                let base: String = line.chars().take_while(|c| *c == ' ' || *c == '\t').collect();
                let before: String = line.chars().take(c).collect();
                let opener = before.trim_end().ends_with(['{', '[', '(', ':']);
                if opener { format!("{base}{}", self.indent) } else { base }
            })
            .collect();
        self.replace_selections(EditKind::Other, |i, _| format!("\n{}", indents[i]));
    }

    pub fn backspace(&mut self) {
        let indent_w = self.indent.chars().count().max(1);
        for i in 0..self.sels.len() {
            let s = self.sels[i];
            if s.is_empty() && s.head > 0 {
                let (l, c) = self.char_to_lc(s.head);
                let line = self.line(l);
                let prefix: String = line.chars().take(c).collect();
                // Remove a whole indent level inside leading whitespace.
                let n = if c > 0 && prefix.chars().all(|ch| ch == ' ') && self.indent.starts_with(' ') {
                    let r = c % indent_w;
                    if r == 0 { indent_w } else { r }
                } else {
                    1
                };
                self.sels[i].anchor = s.head - n.min(s.head);
            }
        }
        self.replace_selections(EditKind::Delete, |_, _| String::new());
    }

    pub fn delete_forward(&mut self) {
        let len = self.len();
        for s in &mut self.sels {
            if s.is_empty() && s.head < len {
                s.anchor = s.head + 1;
            }
        }
        self.replace_selections(EditKind::Delete, |_, _| String::new());
    }

    /// Indent (Tab) or outdent (Shift+Tab) selected lines; plain Tab with a
    /// caret inserts one indent unit.
    pub fn indent_lines(&mut self, outdent: bool) {
        if !outdent && self.sels.iter().all(|s| s.is_empty()) {
            let ind = self.indent.clone();
            self.replace_selections(EditKind::Other, |_, _| ind.clone());
            return;
        }
        let before = self.sels.clone();
        let mut lines: Vec<usize> = Vec::new();
        for s in &self.sels {
            let (a, _) = self.char_to_lc(s.start());
            let (b, bc) = self.char_to_lc(s.end());
            let b = if bc == 0 && b > a { b - 1 } else { b };
            lines.extend(a..=b);
        }
        lines.sort_unstable();
        lines.dedup();
        let mut edits = Vec::new();
        for &l in lines.iter().rev() {
            let at = self.rope.line_to_char(l);
            if outdent {
                let line = self.line(l);
                let n = if line.starts_with('\t') { 1 } else { line.chars().take(self.indent.chars().count()).take_while(|c| *c == ' ').count() };
                if n > 0 {
                    let e = Edit { at, removed: line.chars().take(n).collect(), inserted: String::new() };
                    self.apply(&e);
                    edits.push(e);
                }
            } else {
                let e = Edit { at, removed: String::new(), inserted: self.indent.clone() };
                self.apply(&e);
                edits.push(e);
            }
        }
        // Keep selections covering the same lines.
        let first = *lines.first().unwrap_or(&0);
        let last = *lines.last().unwrap_or(&0);
        self.sels = vec![Selection { anchor: self.rope.line_to_char(first), head: self.lc_to_char(last, usize::MAX), goal_col: None }];
        self.push_undo(UndoGroup { edits, before, after: self.sels.clone(), kind: EditKind::Other });
    }

    /// Toggle a line comment prefix on the selected lines.
    pub fn toggle_comment(&mut self, prefix: &str) {
        let before = self.sels.clone();
        let mut lines: Vec<usize> = Vec::new();
        for s in &self.sels {
            let (a, _) = self.char_to_lc(s.start());
            let (b, _) = self.char_to_lc(s.end());
            lines.extend(a..=b);
        }
        lines.sort_unstable();
        lines.dedup();
        let all_commented = lines.iter().all(|l| {
            let t = self.line(*l);
            t.trim().is_empty() || t.trim_start().starts_with(prefix)
        });
        let mut edits = Vec::new();
        for &l in lines.iter().rev() {
            let t = self.line(l);
            if t.trim().is_empty() {
                continue;
            }
            let ws = t.chars().take_while(|c| c.is_whitespace()).count();
            let at = self.rope.line_to_char(l) + ws;
            let e = if all_commented {
                let rest: String = t.chars().skip(ws).collect();
                let n = if rest.starts_with(&format!("{prefix} ")) { prefix.chars().count() + 1 } else { prefix.chars().count() };
                Edit { at, removed: rest.chars().take(n).collect(), inserted: String::new() }
            } else {
                Edit { at, removed: String::new(), inserted: format!("{prefix} ") }
            };
            self.apply(&e);
            edits.push(e);
        }
        let len = self.len();
        for s in &mut self.sels {
            *s = Selection::caret(s.head.min(len));
        }
        self.push_undo(UndoGroup { edits, before, after: self.sels.clone(), kind: EditKind::Other });
    }

    // ---- cursor movement ----

    pub fn move_horiz(&mut self, delta: isize, select: bool, by_word: bool) {
        let len = self.len();
        for i in 0..self.sels.len() {
            let s = self.sels[i];
            let target = if !select && !s.is_empty() && !by_word {
                if delta < 0 { s.start() } else { s.end() }
            } else if by_word {
                self.word_boundary(s.head, delta > 0)
            } else {
                (s.head as isize + delta).clamp(0, len as isize) as usize
            };
            self.sels[i] = Selection { anchor: if select { s.anchor } else { target }, head: target, goal_col: None };
        }
        self.merge_selections();
    }

    pub fn move_vert(&mut self, delta: isize, select: bool) {
        let lines = self.line_count();
        for i in 0..self.sels.len() {
            let s = self.sels[i];
            let (l, c) = self.char_to_lc(s.head);
            let goal = s.goal_col.unwrap_or(c);
            let nl = (l as isize + delta).clamp(0, lines as isize - 1) as usize;
            let target = if nl == l && delta < 0 {
                0
            } else if nl == l && delta > 0 {
                self.len()
            } else {
                self.lc_to_char(nl, goal)
            };
            self.sels[i] = Selection { anchor: if select { s.anchor } else { target }, head: target, goal_col: Some(goal) };
        }
        self.merge_selections();
    }

    pub fn home(&mut self, select: bool) {
        for i in 0..self.sels.len() {
            let s = self.sels[i];
            let (l, c) = self.char_to_lc(s.head);
            let first = self.line(l).chars().take_while(|c| c.is_whitespace()).count();
            let col = if c == first { 0 } else { first };
            let t = self.lc_to_char(l, col);
            self.sels[i] = Selection { anchor: if select { s.anchor } else { t }, head: t, goal_col: None };
        }
        self.merge_selections();
    }

    pub fn end(&mut self, select: bool) {
        for i in 0..self.sels.len() {
            let s = self.sels[i];
            let (l, _) = self.char_to_lc(s.head);
            let t = self.lc_to_char(l, usize::MAX);
            self.sels[i] = Selection { anchor: if select { s.anchor } else { t }, head: t, goal_col: None };
        }
        self.merge_selections();
    }

    pub fn select_all(&mut self) {
        self.sels = vec![Selection { anchor: 0, head: self.len(), goal_col: None }];
    }

    pub fn set_caret(&mut self, c: usize, select: bool) {
        let c = c.min(self.len());
        let anchor = if select { self.sels[0].anchor } else { c };
        self.sels = vec![Selection { anchor, head: c, goal_col: None }];
    }

    pub fn add_caret(&mut self, c: usize) {
        self.sels.push(Selection::caret(c.min(self.len())));
        self.merge_selections();
    }

    /// Ctrl+D: select the word at the caret, or add the next occurrence of the
    /// current selection as a new selection.
    pub fn select_next_occurrence(&mut self) {
        let last = *self.sels.last().unwrap_or(&Selection::caret(0));
        if last.is_empty() {
            let (a, b) = self.word_at(last.head);
            if let Some(s) = self.sels.last_mut() {
                *s = Selection { anchor: a, head: b, goal_col: None };
            }
            return;
        }
        let needle: String = self.rope.slice(last.start()..last.end()).to_string();
        let text = self.text();
        let from_byte = self.rope.char_to_byte(last.end());
        let found = text[from_byte..].find(&needle).map(|b| b + from_byte).or_else(|| text.find(&needle));
        if let Some(b) = found {
            let a = self.rope.byte_to_char(b);
            let s = Selection { anchor: a, head: a + needle.chars().count(), goal_col: None };
            if !self.sels.contains(&s) {
                self.sels.push(s);
            }
        }
    }

    pub fn selected_text(&self) -> String {
        let mut v: Vec<&Selection> = self.sels.iter().collect();
        v.sort_by_key(|s| s.start());
        v.iter().map(|s| self.rope.slice(s.start()..s.end()).to_string()).collect::<Vec<_>>().join("\n")
    }

    /// Copy/cut of an empty selection takes the whole line.
    pub fn expand_empty_to_lines(&mut self) {
        for i in 0..self.sels.len() {
            let s = self.sels[i];
            if s.is_empty() {
                let (l, _) = self.char_to_lc(s.head);
                let a = self.rope.line_to_char(l);
                let b = if l + 1 < self.line_count() { self.rope.line_to_char(l + 1) } else { self.len() };
                self.sels[i] = Selection { anchor: a, head: b, goal_col: None };
            }
        }
    }

    pub fn word_at(&self, c: usize) -> (usize, usize) {
        let is_w = |ch: char| ch.is_alphanumeric() || ch == '_';
        let len = self.len();
        let mut a = c.min(len);
        while a > 0 && is_w(self.rope.char(a - 1)) {
            a -= 1;
        }
        let mut b = c.min(len);
        while b < len && is_w(self.rope.char(b)) {
            b += 1;
        }
        (a, b)
    }

    fn word_boundary(&self, c: usize, forward: bool) -> usize {
        let len = self.len();
        let class = |ch: char| if ch.is_alphanumeric() || ch == '_' { 2 } else if ch.is_whitespace() { 0 } else { 1 };
        let mut i = c;
        if forward {
            while i < len && class(self.rope.char(i)) == 0 {
                i += 1;
            }
            if i < len {
                let k = class(self.rope.char(i));
                while i < len && class(self.rope.char(i)) == k {
                    i += 1;
                }
            }
        } else {
            while i > 0 && class(self.rope.char(i - 1)) == 0 {
                i -= 1;
            }
            if i > 0 {
                let k = class(self.rope.char(i - 1));
                while i > 0 && class(self.rope.char(i - 1)) == k {
                    i -= 1;
                }
            }
        }
        i
    }

    fn merge_selections(&mut self) {
        if self.sels.len() < 2 {
            return;
        }
        let primary = *self.sels.last().unwrap();
        self.sels.sort_by_key(|s| s.start());
        let mut out: Vec<Selection> = Vec::new();
        for s in self.sels.drain(..) {
            if let Some(last) = out.last_mut() {
                if s.start() < last.end() || (s.start() == last.end() && s.is_empty() && last.is_empty()) {
                    let fwd = last.head >= last.anchor;
                    let (a, b) = (last.start().min(s.start()), last.end().max(s.end()));
                    *last = if fwd { Selection { anchor: a, head: b, goal_col: None } } else { Selection { anchor: b, head: a, goal_col: None } };
                    continue;
                }
            }
            out.push(s);
        }
        // Keep the most recently added selection last (primary).
        if let Some(p) = out.iter().position(|s| s.start() <= primary.head && primary.head <= s.end()) {
            let s = out.remove(p);
            out.push(s);
        }
        self.sels = out;
    }

    /// Matching bracket for the bracket at or before the caret.
    pub fn matching_bracket(&self, c: usize) -> Option<(usize, usize)> {
        let pairs = [('(', ')'), ('[', ']'), ('{', '}')];
        for pos in [c, c.wrapping_sub(1)] {
            if pos >= self.len() {
                continue;
            }
            let ch = self.rope.char(pos);
            for (o, cl) in pairs {
                if ch == o {
                    let mut depth = 0i32;
                    for i in pos..self.len().min(pos + 200_000) {
                        let x = self.rope.char(i);
                        if x == o {
                            depth += 1;
                        } else if x == cl {
                            depth -= 1;
                            if depth == 0 {
                                return Some((pos, i));
                            }
                        }
                    }
                } else if ch == cl {
                    let mut depth = 0i32;
                    let mut i = pos as isize;
                    let stop = pos.saturating_sub(200_000) as isize;
                    while i >= stop {
                        let x = self.rope.char(i as usize);
                        if x == cl {
                            depth += 1;
                        } else if x == o {
                            depth -= 1;
                            if depth == 0 {
                                return Some((i as usize, pos));
                            }
                        }
                        i -= 1;
                    }
                }
            }
        }
        None
    }
}

fn detect_indent(text: &str) -> String {
    let mut spaces = [0usize; 9];
    let mut tabs = 0;
    for line in text.lines().take(2000) {
        if line.starts_with('\t') {
            tabs += 1;
        } else {
            let n = line.chars().take_while(|c| *c == ' ').count();
            if (2..=8).contains(&n) && line.len() > n {
                spaces[n] += 1;
            }
        }
    }
    let sp: usize = spaces.iter().sum();
    if tabs > sp {
        return "\t".into();
    }
    // Prefer the smallest common unit.
    for w in [2, 4, 8] {
        if spaces[w] > 0 && spaces.iter().enumerate().filter(|(i, n)| **n > 0 && i % w != 0).count() == 0 {
            return " ".repeat(w);
        }
    }
    "    ".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_undo_redo_coalesces() {
        let mut b = Buffer::new("");
        for ch in "hello".chars() {
            b.insert_text(&ch.to_string());
        }
        assert_eq!(b.text(), "hello");
        assert!(b.undo());
        assert_eq!(b.text(), "");
        assert!(b.redo());
        assert_eq!(b.text(), "hello");
        assert!(b.is_dirty());
        b.mark_saved();
        assert!(!b.is_dirty());
    }

    #[test]
    fn multi_cursor_insert_and_paste() {
        let mut b = Buffer::new("a\nb\nc\n");
        b.sels = vec![Selection::caret(0), Selection::caret(2), Selection::caret(4)];
        b.insert_text("x");
        assert_eq!(b.text(), "xa\nxb\nxc\n");
        b.insert_text("1\n2\n3");
        assert_eq!(b.text(), "x1a\nx2b\nx3c\n");
        b.undo();
        b.undo();
        assert_eq!(b.text(), "a\nb\nc\n");
    }

    #[test]
    fn newline_auto_indents() {
        let mut b = Buffer::new("fn a() {\n    x\n}\n");
        b.set_caret(b.lc_to_char(0, 8), false);
        b.newline();
        assert_eq!(b.line(1), "    ");
        b.set_caret(b.lc_to_char(2, 5), false);
        b.newline();
        assert_eq!(b.line(3), "    ");
    }

    #[test]
    fn backspace_removes_indent_unit() {
        let mut b = Buffer::new("        x");
        b.indent = "    ".into();
        b.set_caret(8, false);
        b.backspace();
        assert_eq!(b.text(), "    x");
    }

    #[test]
    fn indent_outdent_and_comment() {
        let mut b = Buffer::new("a\nb\n");
        b.indent = "  ".into();
        b.sels = vec![Selection { anchor: 0, head: 3, goal_col: None }];
        b.indent_lines(false);
        assert_eq!(b.text(), "  a\n  b\n");
        b.indent_lines(true);
        assert_eq!(b.text(), "a\nb\n");
        b.sels = vec![Selection { anchor: 0, head: 3, goal_col: None }];
        b.toggle_comment("//");
        assert_eq!(b.text(), "// a\n// b\n");
        b.sels = vec![Selection { anchor: 0, head: 6, goal_col: None }];
        b.toggle_comment("//");
        assert_eq!(b.text(), "a\nb\n");
    }

    #[test]
    fn crlf_roundtrip_and_indent_detection() {
        let b = Buffer::new("a\r\n  b\r\n");
        assert_eq!(b.text(), "a\n  b\n");
        assert_eq!(b.text_for_save(), "a\r\n  b\r\n");
        assert_eq!(b.indent, "  ");
        assert_eq!(Buffer::new("x\n\ty\n").indent, "\t");
    }

    #[test]
    fn ctrl_d_and_brackets() {
        let mut b = Buffer::new("foo bar foo");
        b.set_caret(1, false);
        b.select_next_occurrence();
        assert_eq!(b.selected_text(), "foo");
        b.select_next_occurrence();
        assert_eq!(b.sels.len(), 2);
        let c = Buffer::new("f(a[1]{x})");
        assert_eq!(c.matching_bracket(1), Some((1, 9)));
        assert_eq!(c.matching_bracket(5), Some((3, 5)));
        assert_eq!(c.matching_bracket(6), Some((6, 8)));
    }

    #[test]
    fn vertical_movement_keeps_goal_column() {
        let mut b = Buffer::new("abcdef\nab\nabcdef");
        b.set_caret(5, false);
        b.move_vert(1, false);
        assert_eq!(b.char_to_lc(b.sels[0].head), (1, 2));
        b.move_vert(1, false);
        assert_eq!(b.char_to_lc(b.sels[0].head), (2, 5));
        b.move_horiz(-1, true, true);
        assert_eq!(b.selected_text(), "abcde");
    }
}
