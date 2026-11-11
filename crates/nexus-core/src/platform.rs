//! Linux desktop integration shared by the Nexus crates.
//!
//! Replaces the Windows locations and shell calls used by Nexus Desktop on
//! Windows (`%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%`, `rundll32`,
//! `explorer.exe /select`, `cmd /C start`) with their freedesktop.org
//! equivalents: XDG base directories, `xdg-open`, the `FileManager1` D-Bus
//! interface and the user's terminal emulator.
//!
//! Directory names are fixed so the layout is predictable:
//! * config (`settings.json`): `$XDG_CONFIG_HOME/nexus-desktop` (default `~/.config/nexus-desktop`)
//! * data (agents DB, shadows, Access session, crash log, OAuth callback):
//!   `$XDG_DATA_HOME/nexus-desktop` (default `~/.local/share/nexus-desktop`)
//!
//! Unlike the Windows build, nothing falls back to the shared temporary
//! directory: on Linux `/tmp` is world-writable, so a missing home directory
//! falls back to the current directory instead.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Folder name used under the XDG base directories.
pub const APP_DIR: &str = "nexus-desktop";

/// The user's home directory (`$HOME`, then the password database).
pub fn home_dir() -> PathBuf {
    std::env::home_dir().filter(|p| p.is_absolute()).unwrap_or_else(|| PathBuf::from("."))
}

fn xdg(var: &str, default_rel: &str) -> PathBuf {
    // The XDG spec says relative values must be ignored.
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| home_dir().join(default_rel))
}

/// Roaming-settings equivalent of `%APPDATA%\NexusDesktop`.
pub fn config_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join(APP_DIR)
}

/// Machine-local data equivalent of `%LOCALAPPDATA%\NexusDesktop`.
pub fn data_dir() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share").join(APP_DIR)
}

/// The user's OpenSSH directory (`~/.ssh`).
pub fn ssh_dir() -> PathBuf {
    home_dir().join(".ssh")
}

/// Short host name of this machine (Windows used `%COMPUTERNAME%`).
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "linux".into())
}

/// Create `dir` (and parents) and restrict it to the current user (0700).
/// Settings, the agents database and the encrypted Access session live here.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Find an executable on `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| is_executable(p))
}

pub fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Only these URL schemes are handed to the desktop's URL opener.
pub fn is_openable_url(url: &str) -> bool {
    let l = url.to_ascii_lowercase();
    (l.starts_with("https://") || l.starts_with("http://")) && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Open an http(s) URL in the default browser (`xdg-open`), like Windows'
/// `url.dll,FileProtocolHandler` / `cmd /C start`.
pub fn open_url(url: &str) -> Result<(), String> {
    if !is_openable_url(url) {
        return Err("Only http and https links can be opened".into());
    }
    Command::new("xdg-open").arg(url).spawn().map(|_| ()).map_err(|e| format!("could not run xdg-open: {e}"))
}

/// Show a file in the file manager with it selected (Windows: `explorer /select,`).
/// Uses the freedesktop `org.freedesktop.FileManager1.ShowItems` D-Bus call
/// (Dolphin, Nautilus, Nemo, Thunar…), falling back to opening the folder.
pub fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    let abs = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
    let uri = file_uri(&abs);
    let shown = Command::new("dbus-send")
        .args(["--session", "--print-reply", "--dest=org.freedesktop.FileManager1", "/org/freedesktop/FileManager1", "org.freedesktop.FileManager1.ShowItems"])
        .arg(format!("array:string:{uri}"))
        .arg("string:")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if shown {
        return Ok(());
    }
    let dir = if abs.is_dir() { abs.clone() } else { abs.parent().map(Path::to_path_buf).unwrap_or(abs.clone()) };
    Command::new("xdg-open").arg(dir).spawn().map(|_| ()).map_err(|e| format!("could not run xdg-open: {e}"))
}

/// `file://` URI with percent-encoding for everything outside the RFC 3986
/// unreserved set and `/`.
pub fn file_uri(p: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut s = String::from("file://");
    for &b in p.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// Terminal emulators tried, in order, after `$TERMINAL`, by
/// [`launch_in_terminal_window`]. Each entry is (program, argument that
/// precedes the command to run).
pub const TERMINAL_EMULATORS: &[(&str, &str)] = &[
    ("konsole", "-e"),
    ("gnome-terminal", "--"),
    ("kgx", "--"),
    ("xfce4-terminal", "-x"),
    ("kitty", "--"),
    ("alacritty", "-e"),
    ("foot", "--"),
    ("wezterm", "start"),
    ("xterm", "-e"),
];

/// Run `program args…` in a new terminal window, so an official CLI can run
/// its own interactive sign-in (Windows: `cmd /C start "" program args`).
pub fn launch_in_terminal_window(program: &str, args: &[&str]) -> Result<(), String> {
    let mut candidates: Vec<(String, String)> = Vec::new();
    if let Ok(t) = std::env::var("TERMINAL") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            candidates.push((t, "-e".into()));
        }
    }
    candidates.extend(TERMINAL_EMULATORS.iter().map(|(p, a)| (p.to_string(), a.to_string())));
    for (term, sep) in candidates {
        let exe = if term.contains('/') { Some(PathBuf::from(&term)).filter(|p| is_executable(p)) } else { which(&term) };
        let Some(exe) = exe else { continue };
        let mut c = Command::new(exe);
        c.arg(sep).arg(program).args(args);
        if c.spawn().is_ok() {
            return Ok(());
        }
    }
    Err("No terminal emulator found (set $TERMINAL, or install Konsole, GNOME Terminal, kitty, Alacritty, foot or xterm)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_restricted_to_http() {
        assert!(is_openable_url("https://nexus-gateway.example.workers.dev/"));
        assert!(is_openable_url("http://192.168.1.2:8080/"));
        for bad in ["file:///etc/passwd", "javascript:alert(1)", "--help", "https://a b", "https://a\nb", "com.ljcatherine.nexus:/x"] {
            assert!(!is_openable_url(bad), "{bad}");
        }
    }

    #[test]
    fn file_uris_are_percent_encoded() {
        assert_eq!(file_uri(Path::new("/home/u/My Project/a#b.rs")), "file:///home/u/My%20Project/a%23b.rs");
        assert_eq!(file_uri(Path::new("/tmp/x-y_z.~")), "file:///tmp/x-y_z.~");
    }

    #[test]
    fn xdg_dirs_end_in_app_dir() {
        assert!(config_dir().ends_with(APP_DIR));
        assert!(data_dir().ends_with(APP_DIR));
    }

    #[test]
    fn private_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("nexus-core-test-{}", std::process::id()));
        let p = d.join("a").join("b");
        ensure_private_dir(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&d);
    }
}
