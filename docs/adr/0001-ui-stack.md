# ADR 0001: UI stack — eframe/egui + wgpu

Date: 2026-11-07 · Status: accepted

## Context
Nexus Desktop needs a native Rust GUI that can host a professional code editor,
dense IDE panels with docking, a terminal emulator, and the Midnight Liquid Glass
look, on Windows x64 with high-DPI and multi-monitor support. Electron is out.

## Options evaluated (crates.io versions checked 2026-11-07)
| Option | Pros | Cons |
|---|---|---|
| **GPUI 0.2.2** (Zed) | Built for a code editor; very fast | Pre-1.0, API driven by Zed's needs, sparse docs, editor component not reusable outside Zed; high churn risk |
| **Slint 1.18** | Mature, declarative, nice styling | Text widgets are not suited for a code editor; custom editor needs low-level drawing that Slint discourages; GPL/royalty licensing to consider |
| **Iced** | Elm architecture, `text_editor` widget | Text editor limited (no multi-cursor/gutter APIs), docking ecosystem thin |
| **eframe/egui 0.37 + egui_dock 0.21** | Mature, MIT/Apache, wgpu on Windows, immediate mode suits dense IDE panels, full custom painting (glass, gradients), docking crate, proven terminal integrations with `alacritty_terminal` | Must write our own code-editor widget; immediate mode needs care for large files (virtualized rendering) |

## Decision
Use **eframe 0.37 (wgpu backend) + egui_dock**. Build a custom virtualized editor
widget over `ropey` with `syntect` (+ `two-face` grammars, includes Nix/TOML)
highlighting cached per line, `alacritty_terminal` for terminal emulation over
ConPTY (`portable-pty`), and `window-vibrancy` for Windows 11 Mica/Acrylic
backdrop where available, falling back to the painted midnight backdrop.

## Consequences
- Editor features (multi-cursor, folding, minimap, LSP UI) are our code; they are
  scheduled in PLAN.md Phase 2/4 rather than inherited.
- Glass is painted (gradient fills, lit edge strokes, soft shadows) — the same
  approach the iOS app uses for cards, which needs no blur.
- Code editor surface is opaque `#0B1120` for contrast, per design requirement.
