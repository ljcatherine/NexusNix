//! SSH for Nexus Desktop (russh), gated by `nexus-security` grants.
//!
//! * Host keys are verified against [`HostKeyStore`] pins. Unknown keys abort
//!   the connection and surface the fingerprint for explicit confirmation;
//!   changed keys are rejected. A key seen on a Debian connection is recorded
//!   so any other device entry presenting it is treated as Debian.
//! * [`Session::run_catalog`] requires an `ExecuteCatalogCommand` grant and only
//!   accepts a [`CatalogCommand`] — there is no free-text exec for read-only hosts.
//! * [`Session::exec_arbitrary`] requires an `ExecuteArbitraryCommand` grant,
//!   which Debian's policy can never issue.
//! * [`ReadOnlySftp`] exposes list/stat/read only; write methods do not exist on
//!   the type.

use nexus_security::catalog::{CatalogCommand, ReadRoots};
use nexus_security::hostkeys::{HostKeyStore, Verification};
use nexus_security::policy::{Capability, Grant, PolicyEngine, Target};
use parking::Shared;

pub mod relay;
use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

mod parking {
    pub type Shared<T> = std::sync::Arc<std::sync::Mutex<T>>;
}

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("Host key not yet trusted for {authority}: {fingerprint}. Verify it out of band, then confirm.")]
    UnknownHostKey { authority: String, fingerprint: String },
    #[error("HOST KEY CHANGED for {authority}: pinned {pinned}, presented {presented}. Connection refused.")]
    HostKeyChanged { authority: String, pinned: String, presented: String },
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Key error: {0}")]
    Key(String),
    #[error("Not authorized: {0}")]
    Denied(String),
    #[error("Catalog: {0}")]
    Catalog(#[from] nexus_security::catalog::CatalogError),
    #[error("SSH: {0}")]
    Ssh(String),
    #[error("Timed out")]
    Timeout,
}

impl From<russh::Error> for SshError {
    fn from(e: russh::Error) -> Self {
        SshError::Ssh(e.to_string())
    }
}

pub(crate) struct Verifier {
    pub(crate) authority: String,
    pub(crate) pins: Shared<HostKeyStore>,
    pub(crate) outcome: Shared<Option<SshError>>,
    pub(crate) presented: Shared<Option<String>>,
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256).to_string(),
            // Certificates are not used by the owner's hosts; refuse.
            _ => {
                *self.outcome.lock().unwrap() = Some(SshError::Ssh("host certificates are not supported".into()));
                return Ok(false);
            }
        };
        *self.presented.lock().unwrap() = Some(fp.clone());
        let v = self.pins.lock().unwrap().verify(&self.authority, &fp);
        match v {
            Verification::Trusted => Ok(true),
            Verification::FirstUse { fingerprint } => {
                *self.outcome.lock().unwrap() = Some(SshError::UnknownHostKey { authority: self.authority.clone(), fingerprint });
                Ok(false)
            }
            Verification::Changed { pinned, presented } => {
                *self.outcome.lock().unwrap() = Some(SshError::HostKeyChanged { authority: self.authority.clone(), pinned, presented });
                Ok(false)
            }
        }
    }
}

/// Connection parameters for a direct (LAN/Tailscale) endpoint.
pub struct ConnectParams<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub key_path: &'a Path,
    pub passphrase: Option<&'a str>,
    pub target: Target,
    pub is_debian: bool,
    /// The server enforces the catalog with `nexus-ro`: send `nexus-ro/1`
    /// requests instead of shell command lines.
    pub server_catalog: bool,
}

pub struct Session {
    pub(crate) handle: Handle<Verifier>,
    pub(crate) target: Target,
    pub fingerprint: String,
    pub(crate) server_catalog: bool,
}

pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: Option<u32>,
}

impl ExecOutput {
    /// Success: exit 0, or no exit status (the Nexus relay can drop it) with an
    /// empty stderr. A catalog refusal always writes to stderr, so it can never
    /// be mistaken for success when the status is missing.
    pub fn ok(&self) -> bool {
        match self.exit {
            Some(c) => c == 0,
            None => self.stderr.iter().all(|b| b.is_ascii_whitespace()),
        }
    }

    pub fn exit_label(&self) -> String {
        self.exit.map(|c| c.to_string()).unwrap_or_else(|| "unknown".into())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

impl Session {
    pub async fn connect(p: ConnectParams<'_>, pins: Shared<HostKeyStore>, engine: &PolicyEngine) -> Result<Session, SshError> {
        let authority = format!("[{}]:{}", p.host.to_ascii_lowercase(), p.port);
        let outcome = Arc::new(std::sync::Mutex::new(None));
        let presented = Arc::new(std::sync::Mutex::new(None));
        let handler = Verifier { authority, pins, outcome: outcome.clone(), presented: presented.clone() };
        let config = Arc::new(client::Config { inactivity_timeout: Some(Duration::from_secs(300)), ..Default::default() });
        let fut = client::connect(config, (p.host, p.port), handler);
        let mut handle = match tokio::time::timeout(Duration::from_secs(15), fut).await {
            Err(_) => return Err(SshError::Timeout),
            Ok(Err(e)) => return Err(outcome.lock().unwrap().take().unwrap_or_else(|| SshError::Ssh(e.to_string()))),
            Ok(Ok(h)) => h,
        };
        let fingerprint = presented.lock().unwrap().clone().unwrap_or_default();
        // Alias detection: a Debian key marks this target Debian; a Debian
        // connection records its key.
        if p.is_debian {
            engine.record_debian_fingerprint(&fingerprint);
        } else if engine.fingerprint_is_debian(&fingerprint) {
            if let Target::Host { key } = &p.target {
                engine.mark_debian(key);
            }
        }
        let key = russh::keys::load_secret_key(p.key_path, p.passphrase).map_err(|e| SshError::Key(e.to_string()))?;
        let hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
        let auth = handle.authenticate_publickey(p.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await?;
        if !auth.success() {
            return Err(SshError::AuthFailed);
        }
        Ok(Session { handle, target: p.target, fingerprint, server_catalog: p.server_catalog })
    }

    async fn exec_raw(&self, command: &str, timeout: Duration, max: usize) -> Result<ExecOutput, SshError> {
        let mut ch = self.handle.channel_open_session().await?;
        ch.exec(true, command).await?;
        let mut out = ExecOutput { stdout: Vec::new(), stderr: Vec::new(), exit: None };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let msg = match tokio::time::timeout_at(deadline, ch.wait()).await {
                Err(_) => {
                    let _ = ch.close().await;
                    return Err(SshError::Timeout);
                }
                Ok(None) => break,
                Ok(Some(m)) => m,
            };
            match msg {
                ChannelMsg::Data { data } => {
                    if out.stdout.len() < max {
                        out.stdout.extend_from_slice(&data[..data.len().min(max - out.stdout.len())]);
                    }
                }
                ChannelMsg::ExtendedData { data, .. } => {
                    if out.stderr.len() < 64 * 1024 {
                        out.stderr.extend_from_slice(&data[..data.len().min(64 * 1024 - out.stderr.len())]);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => out.exit = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(out)
    }

    /// Run a validated catalog command (the only remote exec on read-only hosts).
    pub async fn run_catalog(&self, grant: &Grant, cmd: &CatalogCommand, roots: &ReadRoots) -> Result<ExecOutput, SshError> {
        grant.require(Capability::ExecuteCatalogCommand, &self.target).map_err(|e| SshError::Denied(e.to_string()))?;
        let line = if self.server_catalog { nexus_security::ro::encode_request(cmd, roots)? } else { cmd.render(roots)? };
        self.exec_raw(&line, Duration::from_secs(40), 16 * 1024 * 1024).await
    }

    /// Arbitrary command; requires an `ExecuteArbitraryCommand` grant, which is
    /// never issued for Debian.
    pub async fn exec_arbitrary(&self, grant: &Grant, command: &str) -> Result<ExecOutput, SshError> {
        grant.require(Capability::ExecuteArbitraryCommand, &self.target).map_err(|e| SshError::Denied(e.to_string()))?;
        if grant.summary() != command {
            return Err(SshError::Denied("grant was issued for a different command".into()));
        }
        self.exec_raw(command, Duration::from_secs(600), 16 * 1024 * 1024).await
    }

    /// Open a read-only SFTP view. Requires a `Read` grant.
    pub async fn sftp_read_only(&self, grant: &Grant) -> Result<ReadOnlySftp, SshError> {
        grant.require(Capability::Read, &self.target).map_err(|e| SshError::Denied(e.to_string()))?;
        if self.server_catalog {
            return Err(SshError::Denied("This key uses the server-enforced catalog for file reads".into()));
        }
        let ch = self.handle.channel_open_session().await?;
        ch.request_subsystem(true, "sftp").await?;
        let sftp = russh_sftp::client::SftpSession::new(ch.into_stream()).await.map_err(|e| SshError::Ssh(e.to_string()))?;
        Ok(ReadOnlySftp { inner: sftp })
    }

    pub async fn close(&self) {
        let _ = self.handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    }
}

#[derive(Clone, Debug)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<u32>,
}

/// SFTP with read operations only. No write/rename/remove/mkdir/setstat
/// methods exist on this type, so read-only callers cannot reach them.
pub struct ReadOnlySftp {
    inner: russh_sftp::client::SftpSession,
}

impl ReadOnlySftp {
    pub async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, SshError> {
        let rd = self.inner.read_dir(path).await.map_err(|e| SshError::Ssh(e.to_string()))?;
        let mut v: Vec<RemoteEntry> = rd
            .map(|e| {
                let m = e.metadata();
                RemoteEntry { name: e.file_name(), is_dir: m.is_dir(), size: m.size.unwrap_or(0), modified: m.mtime }
            })
            .collect();
        v.sort_by(|a, b| (!a.is_dir, a.name.to_lowercase()).cmp(&(!b.is_dir, b.name.to_lowercase())));
        Ok(v)
    }

    /// Read up to `max` bytes of a file (refuses sensitive names).
    pub async fn read(&self, path: &str, max: u64) -> Result<Vec<u8>, SshError> {
        if nexus_security::sensitive::is_sensitive_path(path) {
            return Err(SshError::Denied("sensitive file".into()));
        }
        let meta = self.inner.metadata(path).await.map_err(|e| SshError::Ssh(e.to_string()))?;
        if meta.size.unwrap_or(0) > max {
            return Err(SshError::Denied(format!("file larger than {max} bytes")));
        }
        self.inner.read(path).await.map_err(|e| SshError::Ssh(e.to_string()))
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String, SshError> {
        self.inner.canonicalize(path).await.map_err(|e| SshError::Ssh(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_exit_status_with_stderr_is_failure() {
        let o = |exit, err: &str| ExecOutput { stdout: vec![], stderr: err.as_bytes().to_vec(), exit };
        assert!(o(Some(0), "").ok());
        assert!(!o(Some(3), "").ok());
        assert!(o(None, "").ok());
        assert!(!o(None, "nexus_denied	outside_roots
").ok());
    }
    use nexus_core::Device;
    use nexus_security::audit::MemoryAudit;
    use nexus_security::policy::Operation;

    /// Debian targets can never obtain the grants that the write/exec paths require.
    #[test]
    fn debian_cannot_obtain_exec_or_shell_grants() {
        let engine = PolicyEngine::new(Arc::new(MemoryAudit::default()));
        let d = Device::suggestions().into_iter().find(|d| d.role == Some(nexus_core::HostRole::Debian)).unwrap();
        engine.register_device(&d);
        let t = Target::Host { key: d.id.to_string() };
        for cap in [Capability::ExecuteArbitraryCommand, Capability::InteractiveShell, Capability::WriteFile, Capability::ServiceControl] {
            assert!(engine.authorize(&Operation::user(t.clone(), cap, "rm -rf /tmp/x")).is_err());
        }
        assert!(engine.authorize(&Operation::user(t, Capability::ExecuteCatalogCommand, "metrics")).is_ok());
    }
}
