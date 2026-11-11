//! Owner-specific deployment values (the "site"), kept out of the source.
//!
//! The Worker host, Cloudflare Access team and client id, and the server
//! account names identify one owner's infrastructure, so they are not
//! committed. They are read once from the first existing file of:
//!
//! 1. `$NEXUS_SITE_FILE`
//! 2. `$XDG_CONFIG_HOME/nexus-desktop/site.json` (default `~/.config/nexus-desktop/site.json`)
//! 3. `/etc/nexus-desktop/site.json` (written by the NixOS module option
//!    `programs.nexus-desktop.site`)
//!
//! Without a file the placeholders below apply: the app runs, but Cloudflare
//! Access sign-in and relay endpoints stay unconfigured. See
//! `docs/site.example.json`.
//!
//! Security: these names only *add* signals. Debian detection
//! (`nexus_security::policy::ProtectedRegistry`) keeps all of its built-in
//! signals (role, name, relay target, host, the generic `debian` username)
//! whether or not a site file exists, so a missing or wrong file can never
//! make the Debian server writable.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Built-in usernames that always map to a role, in addition to the site's.
pub const GENERIC_DEBIAN_USER: &str = "debian";
pub const GENERIC_NIXOS_USER: &str = "nixos";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Site {
    /// Host name of the Nexus Worker (Cloudflare relay and Access resource),
    /// without scheme or path, e.g. `nexus-gateway.<account>.workers.dev`.
    pub gateway_host: String,
    /// Cloudflare Access issuer, `https://<team>.cloudflareaccess.com`.
    pub access_issuer: String,
    /// Public native OAuth client id of the Access application (not a secret,
    /// but specific to one Access account). Empty disables sign-in.
    pub access_client_id: String,
    /// SSH account on the protected Debian server.
    pub debian_user: String,
    /// SSH account on the NixOS desktop.
    pub nixos_user: String,
}

impl Default for Site {
    fn default() -> Self {
        Self {
            gateway_host: "nexus-gateway.example.workers.dev".into(),
            access_issuer: "https://example.cloudflareaccess.com".into(),
            access_client_id: String::new(),
            debian_user: GENERIC_DEBIAN_USER.into(),
            nixos_user: GENERIC_NIXOS_USER.into(),
        }
    }
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !l.starts_with('-') && !l.ends_with('-'))
}

fn valid_user(u: &str) -> bool {
    !u.is_empty() && u.len() <= 32 && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) && !u.starts_with('-')
}

impl Site {
    /// Parse and validate a site file. Invalid values are rejected rather
    /// than half-applied.
    pub fn parse(json: &str) -> Result<Site, String> {
        let s: Site = serde_json::from_str(json).map_err(|e| format!("site.json: {e}"))?;
        if !valid_host(&s.gateway_host) {
            return Err("site.json: gateway_host must be a bare host name".into());
        }
        let issuer_host = s.access_issuer.strip_prefix("https://").unwrap_or("");
        if !valid_host(issuer_host) || !issuer_host.ends_with(".cloudflareaccess.com") {
            return Err("site.json: access_issuer must be https://<team>.cloudflareaccess.com".into());
        }
        if !s.access_client_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("site.json: access_client_id has unexpected characters".into());
        }
        if !valid_user(&s.debian_user) || !valid_user(&s.nixos_user) {
            return Err("site.json: debian_user and nixos_user must be plain account names".into());
        }
        Ok(s)
    }

    /// `https://<gateway_host>`.
    pub fn gateway_url(&self) -> String {
        format!("https://{}", self.gateway_host)
    }

    /// Candidate files, in priority order.
    pub fn candidates() -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Some(p) = std::env::var_os("NEXUS_SITE_FILE").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty()) {
            v.push(p);
        }
        v.push(crate::platform::config_dir().join("site.json"));
        v.push(PathBuf::from("/etc/nexus-desktop/site.json"));
        v
    }

    fn load() -> (Site, Option<String>) {
        for p in Self::candidates() {
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            return match Site::parse(&text) {
                Ok(s) => (s, None),
                Err(e) => (Site::default(), Some(format!("{} ignored: {e}", p.display()))),
            };
        }
        (Site::default(), None)
    }
}

static SITE: OnceLock<(Site, Option<String>)> = OnceLock::new();

/// The site in effect for this process (loaded once).
pub fn site() -> &'static Site {
    &SITE.get_or_init(Site::load).0
}

/// Why the site file was ignored, if it was.
pub fn site_error() -> Option<&'static str> {
    SITE.get_or_init(Site::load).1.as_deref()
}

/// True for the built-in or the site's Debian account name.
pub fn is_debian_user(u: &str) -> bool {
    u.eq_ignore_ascii_case(GENERIC_DEBIAN_USER) || u.eq_ignore_ascii_case(&site().debian_user)
}

/// True for the built-in or the site's NixOS account name.
pub fn is_nixos_user(u: &str) -> bool {
    u.eq_ignore_ascii_case(GENERIC_NIXOS_USER) || u.eq_ignore_ascii_case(&site().nixos_user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_placeholders() {
        let s = Site::default();
        assert!(s.gateway_host.ends_with("example.workers.dev"));
        assert!(s.access_client_id.is_empty());
        assert_eq!(s.gateway_url(), "https://nexus-gateway.example.workers.dev");
        // The generic names always apply, whatever the site file says.
        assert!(is_debian_user("debian") && is_debian_user("DEBIAN") && is_nixos_user("nixos"));
    }

    #[test]
    fn parses_a_full_file_and_rejects_bad_values() {
        let ok = r#"{"gateway_host":"gw.acct.workers.dev","access_issuer":"https://team.cloudflareaccess.com","access_client_id":"0f3c6a1e-1111-2222-3333-444455556666","debian_user":"srv","nixos_user":"me"}"#;
        let s = Site::parse(ok).unwrap();
        assert_eq!((s.debian_user.as_str(), s.nixos_user.as_str()), ("srv", "me"));
        // Missing fields fall back to placeholders.
        assert_eq!(Site::parse(r#"{"debian_user":"srv"}"#).unwrap().gateway_host, Site::default().gateway_host);
        for bad in [
            r#"{"gateway_host":"https://gw.acct.workers.dev"}"#,
            r#"{"gateway_host":"gw.acct.workers.dev/x"}"#,
            r#"{"access_issuer":"http://team.cloudflareaccess.com"}"#,
            r#"{"access_issuer":"https://evil.example.com"}"#,
            r#"{"access_client_id":"a b"}"#,
            r#"{"debian_user":"-oProxyCommand"}"#,
            r#"{"debian_user":"a b"}"#,
            r#"{"unknown":"x"}"#,
            "not json",
        ] {
            assert!(Site::parse(bad).is_err(), "{bad}");
        }
    }
}
