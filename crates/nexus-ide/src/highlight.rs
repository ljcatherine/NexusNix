//! Incremental syntax highlighting with syntect (+ two-face grammars: Nix,
//! TOML, Swift, TypeScript, etc.) and a Midnight theme built from tokens.

use egui::Color32;
use std::str::FromStr;
use std::sync::OnceLock;
use syntect::highlighting::{
    Color, FontStyle, HighlightIterator, HighlightState, Highlighter, ScopeSelectors, StyleModifier, Theme, ThemeItem, ThemeSettings,
};
use syntect::parsing::{ParseState, ScopeStack, SyntaxReference, SyntaxSet};

pub fn syntaxes() -> &'static SyntaxSet {
    static S: OnceLock<SyntaxSet> = OnceLock::new();
    S.get_or_init(two_face::syntax::extra_newlines)
}

fn col(v: u32) -> Color {
    Color { r: (v >> 16) as u8, g: (v >> 8) as u8, b: v as u8, a: 255 }
}

/// Midnight syntax theme — soft, low-glare colours tuned for the opaque
/// `#0A1020` editor surface.
pub fn theme() -> &'static Theme {
    static T: OnceLock<Theme> = OnceLock::new();
    T.get_or_init(|| {
        let item = |sel: &str, fg: u32, style: FontStyle| ThemeItem {
            scope: ScopeSelectors::from_str(sel).unwrap(),
            style: StyleModifier { foreground: Some(col(fg)), background: None, font_style: Some(style) },
        };
        let n = FontStyle::empty();
        Theme {
            name: Some("Nexus Midnight".into()),
            author: None,
            settings: ThemeSettings { foreground: Some(col(0xD7DEEE)), background: Some(col(0x0A1020)), ..Default::default() },
            scopes: vec![
                item("comment, punctuation.definition.comment", 0x5F6E8A, FontStyle::ITALIC),
                item("string, string.quoted, punctuation.definition.string", 0x9FE3C6, n),
                item("constant.numeric, constant.language, constant.character", 0xF1C07E, n),
                item("constant.other, variable.other.constant", 0xF5D49F, n),
                item("keyword, storage.type, storage.modifier, keyword.control", 0xC9ADFF, n),
                item("keyword.operator, punctuation.separator, punctuation.accessor", 0x9AA8C4, n),
                item("entity.name.function, support.function, meta.function-call entity.name", 0x9CBCFF, n),
                item("entity.name.type, entity.name.class, entity.name.struct, entity.name.enum, support.type, support.class, storage.type.rust", 0x7FD6F0, n),
                item("entity.name.tag, meta.tag.sgml", 0xFF9DB0, n),
                item("entity.other.attribute-name", 0xF1C07E, n),
                item("variable.parameter", 0xE7D3FF, n),
                item("variable.language, variable.language.self", 0xFF93A2, FontStyle::ITALIC),
                item("entity.name.namespace, entity.name.module", 0x9FD0FF, n),
                item("meta.attribute, meta.annotation, punctuation.definition.annotation", 0x8F9BB8, n),
                item("support.macro, entity.name.macro", 0x7CE8CA, n),
                item("markup.heading", 0x9CBCFF, FontStyle::BOLD),
                item("markup.bold", 0xE9EDF7, FontStyle::BOLD),
                item("markup.italic", 0xE9EDF7, FontStyle::ITALIC),
                item("markup.inserted", 0x7CE8CA, n),
                item("markup.deleted", 0xFF93A2, n),
                item("invalid", 0xFF6B7F, n),
            ],
        }
    })
}

/// Pick a syntax by file name/extension, with first-line detection fallback.
pub fn syntax_for(path: &str, first_line: &str) -> &'static SyntaxReference {
    let ss = syntaxes();
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or(name);
    ss.find_syntax_by_extension(ext)
        .or_else(|| ss.find_syntax_by_extension(name))
        .or_else(|| match ext.to_ascii_lowercase().as_str() {
            "tsx" | "ts" | "mts" | "cts" => ss.find_syntax_by_name("TypeScript"),
            "jsx" | "mjs" | "cjs" => ss.find_syntax_by_name("JavaScript"),
            "nix" => ss.find_syntax_by_name("Nix"),
            "csproj" | "props" | "targets" | "xaml" => ss.find_syntax_by_extension("xml"),
            "ps1" | "psm1" => ss.find_syntax_by_name("PowerShell"),
            _ => None,
        })
        .or_else(|| ss.find_syntax_by_first_line(first_line))
        .unwrap_or_else(|| ss.find_syntax_plain_text())
}

/// Line-comment prefix for a syntax.
pub fn comment_prefix(syntax: &SyntaxReference) -> &'static str {
    match syntax.name.as_str() {
        "Python" | "Bourne Again Shell (bash)" | "Shell-Unix-Generic" | "YAML" | "TOML" | "Nix" | "Makefile" | "PowerShell" | "Ruby" | "Perl" | "R" | "Dockerfile" | "Git Ignore" => "#",
        "SQL" | "Lua" | "Haskell" => "--",
        "Batch File" => "REM",
        "Lisp" | "Clojure" => ";",
        "HTML" | "XML" | "Markdown" => "<!--",
        _ => "//",
    }
}

pub type Span = (std::ops::Range<usize>, Color32, bool);

/// Per-document highlight cache. `states[i]` is the parser state at the start
/// of line `i`; `spans[i]` the coloured byte ranges of line `i`.
pub struct HighlightCache {
    syntax: &'static SyntaxReference,
    states: Vec<(ParseState, HighlightState)>,
    spans: Vec<Vec<Span>>,
    pub max_lines: usize,
}

impl HighlightCache {
    pub fn new(syntax: &'static SyntaxReference) -> Self {
        Self { syntax, states: Vec::new(), spans: Vec::new(), max_lines: 200_000 }
    }

    pub fn syntax_name(&self) -> &str {
        &self.syntax.name
    }

    pub fn set_syntax(&mut self, s: &'static SyntaxReference) {
        self.syntax = s;
        self.invalidate_from(0);
    }

    pub fn invalidate_from(&mut self, line: usize) {
        // states[line] is the state *before* line `line`, which an edit on or
        // after that line does not change, so keep it to resume from there.
        self.states.truncate(line + 1);
        self.spans.truncate(line);
    }

    /// Ensure lines `..=upto` are highlighted. `line_text(i)` returns line `i`
    /// without newline.
    pub fn ensure(&mut self, upto: usize, line_text: impl Fn(usize) -> String) {
        let hl = Highlighter::new(theme());
        let upto = upto.min(self.max_lines);
        while self.spans.len() <= upto {
            let i = self.spans.len();
            let (mut ps, mut hs) = match self.states.get(i) {
                Some(s) => s.clone(),
                None if i == 0 => (ParseState::new(self.syntax), HighlightState::new(&hl, ScopeStack::new())),
                None => break,
            };
            if self.states.len() == i {
                self.states.push((ps.clone(), hs.clone()));
            }
            let mut text = line_text(i);
            text.push('\n');
            let ops = ps.parse_line(&text, syntaxes()).unwrap_or_default();
            let mut spans = Vec::new();
            let mut pos = 0;
            for (style, piece) in HighlightIterator::new(&mut hs, &ops, &text, &hl) {
                let end = pos + piece.len();
                let end_trim = end.min(text.len() - 1);
                if end_trim > pos {
                    let f = style.foreground;
                    spans.push((pos..end_trim, Color32::from_rgb(f.r, f.g, f.b), style.font_style.contains(FontStyle::ITALIC)));
                }
                pos = end;
            }
            self.spans.push(spans);
            self.states.push((ps, hs));
        }
    }

    pub fn line(&self, i: usize) -> Option<&[Span]> {
        self.spans.get(i).map(Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_languages() {
        for (p, want) in [("a.rs", "Rust"), ("a.py", "Python"), ("a.go", "Go"), ("a.swift", "Swift"), ("a.nix", "Nix"), ("a.ts", "TypeScript"), ("a.toml", "TOML"), ("a.yaml", "YAML"), ("a.cs", "C#"), ("a.cpp", "C++")] {
            assert_eq!(syntax_for(p, "").name, want, "{p}");
        }
        assert_eq!(syntax_for("script", "#!/bin/bash").name, "Bourne Again Shell (bash)");
    }

    #[test]
    fn highlights_incrementally() {
        let lines = ["fn main() {", "    // hi", "    let s = \"x\";", "}"];
        let mut c = HighlightCache::new(syntax_for("a.rs", ""));
        c.ensure(3, |i| lines[i].to_string());
        assert!(c.line(0).unwrap().len() > 1);
        let comment = c.line(1).unwrap().iter().find(|s| s.2).expect("italic comment span");
        assert_eq!(comment.1, Color32::from_rgb(0x5F, 0x6E, 0x8A));
        c.invalidate_from(2);
        assert!(c.line(2).is_none());
        c.ensure(3, |i| lines[i].to_string());
        assert!(c.line(3).is_some());
    }
}
