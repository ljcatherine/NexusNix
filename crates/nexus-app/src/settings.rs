//! Persisted settings (`$XDG_CONFIG_HOME/nexus-desktop/settings.json`, Windows:
//! `%APPDATA%\NexusDesktop\settings.json`). No secrets are stored here; API
//! keys and SSH passphrases go to the Secret Service keystore (KWallet or GNOME
//! Keyring; Windows: Credential Manager).

use nexus_core::Device;
use nexus_providers::openai::OpenAiConfig;
use nexus_security::policy::HostPolicy;
use nexus_ui::Tokens;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Settings directory (`$XDG_CONFIG_HOME/nexus-desktop`; Windows `%APPDATA%`).
pub fn data_dir() -> PathBuf {
    nexus_core::platform::config_dir()
}

/// Machine-local data (`$XDG_DATA_HOME/nexus-desktop`; Windows `%LOCALAPPDATA%`).
pub fn local_dir() -> PathBuf {
    nexus_core::platform::data_dir()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Layout {
    pub compact_nav: bool,
    pub show_explorer: bool,
    pub show_ai: bool,
    pub show_bottom: bool,
    pub explorer_width: f32,
    pub ai_width: f32,
    pub bottom_height: f32,
}

impl Default for Layout {
    fn default() -> Self {
        Self { compact_nav: false, show_explorer: true, show_ai: true, show_bottom: true, explorer_width: 260.0, ai_width: 400.0, bottom_height: 220.0 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SshIdentity {
    /// Path to an OpenSSH private key file (key material is never copied into settings).
    pub key_path: String,
    /// Whether a passphrase is stored in the Secret Service keystore.
    pub has_passphrase: bool,
}

impl Default for SshIdentity {
    fn default() -> Self {
        Self { key_path: nexus_core::platform::ssh_dir().join("id_ed25519").to_string_lossy().into_owned(), has_passphrase: false }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub tokens: Tokens,
    pub layout: Layout,
    pub recent_workspaces: Vec<String>,
    pub devices: Vec<Device>,
    pub ssh: SshIdentity,
    /// Policies for non-Debian targets, keyed by target JSON. Debian entries are
    /// ignored by the policy engine even if present.
    pub policies: BTreeMap<String, HostPolicy>,
    pub openai_compatible: Vec<OpenAiConfig>,
    pub default_provider: String,
    pub provider_models: BTreeMap<String, String>,
    pub telemetry_interval_secs: u64,
    pub autosave_recovery: bool,
    pub ps5_url: String,
    /// Local workspace roots where Bypass mode was explicitly enabled.
    pub bypass_workspaces: std::collections::BTreeSet<String>,
    /// Keep the Cloudflare Access session in memory only (no
    /// `access-session.bin`), so a same-account process such as a Bypass
    /// agent cannot read it from disk. Sign in again after each restart.
    pub access_memory_only: bool,
    /// Lock at launch and after minimising; unlocked with the iOS app's
    /// one-time passcode (only set after a successful pairing code).
    pub app_lock: bool,
    /// Passcode attempt limiting and replay state (persisted so a restart
    /// does not reset a lockout).
    pub otp_verifier: nexus_security::otp::Verifier,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tokens: Tokens::default(),
            layout: Layout::default(),
            recent_workspaces: Vec::new(),
            devices: Device::suggestions(),
            ssh: SshIdentity::default(),
            policies: BTreeMap::new(),
            openai_compatible: Vec::new(),
            default_provider: "codex".into(),
            provider_models: BTreeMap::new(),
            telemetry_interval_secs: 30,
            autosave_recovery: true,
            ps5_url: String::new(),
            bypass_workspaces: Default::default(),
            access_memory_only: false,
            app_lock: false,
            otp_verifier: Default::default(),
        }
    }
}

impl Settings {
    pub fn path() -> PathBuf {
        data_dir().join("settings.json")
    }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = nexus_core::platform::ensure_private_dir(&data_dir());
            let _ = nexus_workspaces::write_atomic(&Self::path(), json.as_bytes());
        }
    }

    pub fn add_recent(&mut self, path: &str) {
        self.recent_workspaces.retain(|p| p != path);
        self.recent_workspaces.insert(0, path.into());
        self.recent_workspaces.truncate(12);
    }
}

/// Secret Service access (service "NexusDesktop"), via the `keyring` crate's
/// zbus Secret Service store: KWallet on KDE Plasma, GNOME Keyring elsewhere.
/// Windows used Credential Manager with the same service and entry names.
pub mod secrets {
    const SERVICE: &str = "NexusDesktop";

    pub fn set(name: &str, value: &str) -> Result<(), String> {
        keyring::Entry::new(SERVICE, name).and_then(|e| e.set_password(value)).map_err(|e| e.to_string())
    }

    pub fn get(name: &str) -> Option<String> {
        keyring::Entry::new(SERVICE, name).ok()?.get_password().ok()
    }

    pub fn delete(name: &str) {
        if let Ok(e) = keyring::Entry::new(SERVICE, name) {
            let _ = e.delete_credential();
        }
    }
}
