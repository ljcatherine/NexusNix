//! Shared domain types for Nexus Desktop. Wire-compatible with the iOS app's
//! `NexusCore/Device.swift` device configuration JSON.

pub mod platform;
pub mod site;

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Which kind of machine a device is. `Debian` is the protected server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostRole {
    Debian,
    Nixos,
    Windows,
    Ps5,
    #[default]
    Other,
}

impl fmt::Display for HostRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HostRole::Debian => "Debian server",
            HostRole::Nixos => "NixOS desktop",
            HostRole::Windows => "This PC",
            HostRole::Ps5 => "PS5",
            HostRole::Other => "SSH host",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    Lan,
    Tailscale,
    Cloudflare,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub host: String,
    pub port: u16,
    pub kind: EndpointKind,
    #[serde(default)]
    pub priority: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_target: Option<String>,
}

impl Endpoint {
    /// `[host]:port`, lowercased — the key for host-key pins (same as iOS).
    pub fn authority(&self) -> String {
        format!("[{}]:{}", self.host.to_ascii_lowercase(), self.port)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let h = self.host.trim();
        if h.is_empty()
            || self.port == 0
            || h.chars().any(|c| c.is_whitespace() || c.is_control() || c == '/' || c == '@')
        {
            return Err(ConfigError::InvalidEndpoint);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    pub username: String,
    pub endpoints: Vec<Endpoint>,
    #[serde(default = "default_auth")]
    pub authentication: String,
    #[serde(default)]
    pub use_tmux: bool,
    /// Desktop-only. Absent in iOS exports; inferred by [`Device::inferred_role`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<HostRole>,
    /// Desktop-only: OpenSSH private key file for this device. Falls back to the
    /// global SSH identity when absent. Key material is never stored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// Desktop-only: the server runs the `nexus-ro` forced-command helper for
    /// this device's key, so catalog commands are sent as `nexus-ro/1`
    /// requests instead of shell text (direct SSH only; the relay uses the
    /// gateway's own key).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub server_catalog: bool,
    /// Desktop-only: unrestricted key used only for owner write sessions
    /// (SSH/SFTP terminals). Its passphrase is typed into OpenSSH, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_key_path: Option<String>,
}

fn default_auth() -> String {
    "ed25519".into()
}

impl Device {
    pub fn ordered_endpoints(&self) -> Vec<&Endpoint> {
        let mut v: Vec<(usize, &Endpoint)> = self.endpoints.iter().enumerate().collect();
        v.sort_by_key(|(i, e)| (e.priority, *i));
        v.into_iter().map(|(_, e)| e).collect()
    }

    /// The explicit role, else a role inferred the same way the iOS app maps
    /// usernames to Cloudflare relay targets: the site's NixOS and Debian
    /// accounts (`site.json`) or the generic `nixos`/`debian` names.
    pub fn inferred_role(&self) -> HostRole {
        if let Some(r) = self.role {
            return r;
        }
        if site::is_debian_user(&self.username) {
            HostRole::Debian
        } else if site::is_nixos_user(&self.username) {
            HostRole::Nixos
        } else {
            HostRole::Other
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty()
            || self.username.is_empty()
            || self.username.chars().any(char::is_whitespace)
            || self.endpoints.is_empty()
        {
            return Err(ConfigError::InvalidDevice);
        }
        let mut seen = std::collections::HashSet::new();
        for e in &self.endpoints {
            e.validate()?;
            if !seen.insert(e.authority()) {
                return Err(ConfigError::InvalidDevice);
            }
        }
        Ok(())
    }

    /// The two devices the iOS app suggests by default (host and accounts
    /// from the site file, see [`site`]).
    pub fn suggestions() -> Vec<Device> {
        let s = site::site();
        let gw = s.gateway_host.as_str();
        let mk = |name: &str, user: &str, target: &str, role| Device {
            id: Uuid::new_v4(),
            name: name.into(),
            username: user.into(),
            endpoints: vec![Endpoint {
                id: Uuid::new_v4(),
                host: gw.into(),
                port: 443,
                kind: EndpointKind::Cloudflare,
                priority: 0,
                relay_target: Some(target.into()),
            }],
            authentication: default_auth(),
            use_tmux: false,
            role: Some(role),
            key_path: None,
            server_catalog: false,
            write_key_path: None,
        };
        vec![
            mk("NixOS desktop", &s.nixos_user, "nixos", HostRole::Nixos),
            mk("Debian server", &s.debian_user, "debian", HostRole::Debian),
        ]
    }
}

/// The iOS `DeviceConfigurationDocument` (`{"version":1,"devices":[...]}`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceDocument {
    pub version: u32,
    pub devices: Vec<Device>,
}

impl DeviceDocument {
    pub fn parse(json: &str) -> Result<Self, ConfigError> {
        let doc: DeviceDocument =
            serde_json::from_str(json).map_err(|e| ConfigError::Malformed(e.to_string()))?;
        if doc.version != 1 {
            return Err(ConfigError::UnsupportedVersion);
        }
        for d in &doc.devices {
            d.validate()?;
        }
        Ok(doc)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("Enter a hostname or IP address and a port from 1 to 65535.")]
    InvalidEndpoint,
    #[error("A device needs a name, username, and unique connection endpoints.")]
    InvalidDevice,
    #[error("This configuration version is not supported.")]
    UnsupportedVersion,
    #[error("Malformed configuration: {0}")]
    Malformed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ios_export() {
        let json = r#"{"version":1,"devices":[{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","name":"Debian","username":"debian","endpoints":[{"id":"7F9619FF-8B86-D011-B42D-00C04FC964FF","host":"192.168.1.20","port":22,"kind":"lan","priority":0}],"authentication":"ed25519","useTmux":false}]}"#;
        let doc = DeviceDocument::parse(json).unwrap();
        assert_eq!(doc.devices[0].inferred_role(), HostRole::Debian);
        assert_eq!(doc.devices[0].endpoints[0].authority(), "[192.168.1.20]:22");
    }

    #[test]
    fn rejects_duplicate_authority_and_bad_hosts() {
        let mut d = Device::suggestions().remove(0);
        d.endpoints.push(d.endpoints[0].clone());
        assert_eq!(d.validate(), Err(ConfigError::InvalidDevice));
        let mut e = Device::suggestions().remove(0);
        e.endpoints[0].host = "evil host".into();
        assert_eq!(e.validate(), Err(ConfigError::InvalidEndpoint));
    }

    #[test]
    fn ordered_endpoints_stable_by_priority() {
        let mut d = Device::suggestions().remove(0);
        let mut b = d.endpoints[0].clone();
        b.host = "10.0.0.2".into();
        b.priority = -1;
        d.endpoints.push(b);
        assert_eq!(d.ordered_endpoints()[0].host, "10.0.0.2");
    }
}
