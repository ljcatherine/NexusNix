//! Encrypted Cloudflare Access session storage
//! (`$XDG_DATA_HOME/nexus-desktop/access-session.bin`).
//!
//! Windows encrypted this file with DPAPI (`CryptProtectData`), so only that
//! Windows user could decrypt it. Linux has no DPAPI; the equivalent here is
//! AES-256-GCM with a random 256-bit key that lives only in the user's Secret
//! Service keystore (KWallet or GNOME Keyring, service `NexusDesktop`, entry
//! `access-session-key`). The file alone is useless without the unlocked
//! keystore, and the token never appears in plaintext on disk. The file is
//! written owner-only (0600) inside an owner-only (0700) directory.
//!
//! File format: `NXS1` magic, 12-byte nonce, ciphertext+tag. The JSON is
//! authenticated with the associated data below so a file cannot be replayed
//! as some other Nexus blob.

use crate::Session;
use std::path::{Path, PathBuf};

pub fn default_path() -> PathBuf {
    nexus_core::platform::data_dir().join("access-session.bin")
}

/// Keystore service and entry name for the file key.
pub const KEY_SERVICE: &str = "NexusDesktop";
pub const KEY_ENTRY: &str = "access-session-key";
const MAGIC: &[u8; 4] = b"NXS1";
const AAD: &[u8] = b"NexusDesktop.CloudflareAccess.v1";

/// Where the 32-byte file key comes from. Production uses the Secret Service;
/// tests use an in-memory key.
pub trait KeySource {
    /// Existing key, if any.
    fn get(&self) -> Option<[u8; 32]>;
    /// Existing key, or a new random one that is stored first.
    fn get_or_create(&self) -> Result<[u8; 32], String>;
}

/// The user's Secret Service keystore (via the `keyring` crate).
pub struct SecretService;

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex_decode(s.trim())?;
    v.try_into().ok()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl KeySource for SecretService {
    fn get(&self) -> Option<[u8; 32]> {
        let e = keyring::Entry::new(KEY_SERVICE, KEY_ENTRY).ok()?;
        hex32(&e.get_password().ok()?)
    }

    fn get_or_create(&self) -> Result<[u8; 32], String> {
        if let Some(k) = self.get() {
            return Ok(k);
        }
        let mut k = [0u8; 32];
        getrandom::fill(&mut k).map_err(|e| e.to_string())?;
        let e = keyring::Entry::new(KEY_SERVICE, KEY_ENTRY).map_err(|e| e.to_string())?;
        e.set_password(&hex_encode(&k)).map_err(|e| format!("Secret Service unavailable: {e}"))?;
        // Read back so a keystore that silently drops writes is detected.
        match self.get() {
            Some(back) if back == k => Ok(k),
            _ => Err("Secret Service did not keep the session key".into()),
        }
    }
}

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let n = aes_gcm::Nonce::try_from(&nonce[..]).map_err(|_| "bad nonce length")?;
    let ct = cipher.encrypt(&n, Payload { msg: plaintext, aad: AAD }).map_err(|_| "encryption failed")?;
    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    if data.len() < 4 + 12 + 16 || &data[..4] != MAGIC {
        return None;
    }
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).ok()?;
    let n = aes_gcm::Nonce::try_from(&data[4..16]).ok()?;
    cipher.decrypt(&n, Payload { msg: &data[16..], aad: AAD }).ok()
}

pub fn save(path: &Path, s: &Session) -> Result<(), String> {
    save_with(&SecretService, path, s)
}

pub fn load(path: &Path) -> Option<Session> {
    load_with(&SecretService, path)
}

pub fn save_with(keys: &dyn KeySource, path: &Path, s: &Session) -> Result<(), String> {
    let json = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    let key = keys.get_or_create()?;
    let enc = seal(&key, &json)?;
    if let Some(d) = path.parent() {
        nexus_core::platform::ensure_private_dir(d).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    write_owner_only(&tmp, &enc).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

pub fn load_with(keys: &dyn KeySource, path: &Path) -> Option<Session> {
    let enc = std::fs::read(path).ok()?;
    let key = keys.get()?;
    let json = open(&key, &enc)?;
    serde_json::from_slice(&json).ok()
}

pub fn clear(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MemKey(RefCell<Option<[u8; 32]>>);
    impl KeySource for MemKey {
        fn get(&self) -> Option<[u8; 32]> {
            *self.0.borrow()
        }
        fn get_or_create(&self) -> Result<[u8; 32], String> {
            let k = self.0.borrow().unwrap_or([7u8; 32]);
            *self.0.borrow_mut() = Some(k);
            Ok(k)
        }
    }

    fn sample() -> Session {
        Session { access_token: "secret-access-token-123".into(), refresh_token: Some("rt".into()), expires_at: 42 }
    }

    #[test]
    fn roundtrip_and_ciphertext_hides_token() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nexus").join("s.bin");
        let keys = MemKey(RefCell::new(None));
        save_with(&keys, &p, &sample()).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"), "token must not appear in plaintext");
        assert_eq!(load_with(&keys, &p).unwrap(), sample());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(p.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        clear(&p);
        assert!(load_with(&keys, &p).is_none());
    }

    #[test]
    fn wrong_key_tampering_and_missing_key_fail_closed() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.bin");
        let keys = MemKey(RefCell::new(None));
        save_with(&keys, &p, &sample()).unwrap();
        let other = MemKey(RefCell::new(Some([9u8; 32])));
        assert!(load_with(&other, &p).is_none());
        assert!(load_with(&MemKey(RefCell::new(None)), &p).is_none());
        let mut raw = std::fs::read(&p).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(&p, &raw).unwrap();
        assert!(load_with(&keys, &p).is_none());
    }

    /// Needs a running Secret Service (KWallet/GNOME Keyring); run with
    /// `cargo test -p nexus-access -- --ignored` in a desktop session.
    #[test]
    #[ignore]
    fn secret_service_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.bin");
        save(&p, &sample()).unwrap();
        assert_eq!(load(&p).unwrap(), sample());
    }
}
