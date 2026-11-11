//! Nexus Desktop entry point.

mod access;
mod ai;
mod app;
mod ide;
mod infra;
mod keys;
mod lock;
mod settings;
mod win;

fn icon() -> Option<egui::IconData> {
    let bytes = include_bytes!("../assets/nexus.png");
    let img = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    Some(egui::IconData { rgba: img.into_raw(), width: w, height: h })
}

/// Display backend choice. The app lock must lock when the window is
/// minimised, and Wayland deliberately does not tell clients that (winit
/// reports `is_minimized() == None` there). So, unless the user opts into
/// native Wayland with `NEXUS_WAYLAND=1`, Nexus runs through XWayland when an
/// X display is available, where minimising is reported as on Windows.
/// Returns true when the X11 backend was forced.
fn choose_backend() -> bool {
    let wayland_opt_in = std::env::var("NEXUS_WAYLAND").is_ok_and(|v| v == "1");
    let has_x = std::env::var_os("DISPLAY").is_some_and(|d| !d.is_empty());
    if !wayland_opt_in && has_x && std::env::var_os("WAYLAND_DISPLAY").is_some() {
        // SAFETY: called first thing in main, before any other thread exists.
        // Terminals restore it for the programs they start (nexus-terminal).
        if let Some(w) = std::env::var_os("WAYLAND_DISPLAY") {
            unsafe { std::env::set_var("NEXUS_WAYLAND_DISPLAY", w) };
        }
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
        return true;
    }
    false
}

fn main() -> eframe::Result {
    // Launched by the com.ljcatherine.Nexus: URL scheme: hand off and exit.
    if access::handle_launch_args() {
        return Ok(());
    }
    choose_backend();
    // Crash log for diagnosis (no secrets are ever in panic messages we create).
    std::panic::set_hook(Box::new(|info| {
        let dir = settings::local_dir();
        let _ = nexus_core::platform::ensure_private_dir(&dir);
        let _ = std::fs::write(dir.join("last-crash.txt"), format!("{info}\n"));
    }));
    // Owner-only (0700) directories before anything (audit log, sessions.db,
    // settings, recovery files) is written into them.
    let _ = nexus_core::platform::ensure_private_dir(&settings::data_dir());
    let _ = nexus_core::platform::ensure_private_dir(&settings::local_dir());
    let s = settings::Settings::load();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Nexus")
        .with_app_id("com.ljcatherine.NexusDesktop")
        .with_inner_size([1480.0, 920.0])
        .with_min_inner_size([960.0, 600.0]);
    if let Some(i) = icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(i));
    }
    let _ = s;
    let options = eframe::NativeOptions { viewport, persist_window: true, ..Default::default() };
    eframe::run_native("Nexus Desktop", options, Box::new(|cc| Ok(Box::new(app::NexusApp::new(cc)))))
}
