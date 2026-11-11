//! Window-frame integration.
//!
//! On Windows this module painted the title bar to match the midnight
//! backdrop through DWM (`DWMWA_USE_IMMERSIVE_DARK_MODE`, caption and border
//! colours). Linux has no client API for a server-side title bar's colours:
//! KWin, Mutter and other compositors draw it from the desktop's own theme
//! (for example Breeze Dark). So this is a deliberate no-op; see
//! `docs/PARITY-LINUX.md`.

pub fn style_title_bar(_frame: &eframe::Frame) {}
