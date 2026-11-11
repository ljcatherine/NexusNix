//! SSH host-key pinning, matching the iOS `HostKeyVerifier` semantics:
//! explicit first-use confirmation, changed keys rejected, rotation only by
//! typing the exact new fingerprint.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    Trusted,
    FirstUse { fingerprint: String },
    Changed { pinned: String, presented: String },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    #[error("A different key is already pinned for this endpoint")]
    AlreadyPinned,
    #[error("Type the exact new fingerprint to confirm rotation")]
    ConfirmationMismatch,
    #[error("No pin exists for this endpoint")]
    NoPin,
    #[error("Pinned key changed since the rotation prompt was shown")]
    StalePin,
}

/// Pins keyed by endpoint authority `[host]:port`. Persisted as JSON in the app
/// data directory (fingerprints are public, not secrets).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostKeyStore {
    pins: BTreeMap<String, String>,
}

impl HostKeyStore {
    /// SHA256 fingerprint in OpenSSH form (`SHA256:<base64 without padding>`).
    pub fn fingerprint_of(public_key_blob: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("SHA256:{}", b64_nopad(&Sha256::digest(public_key_blob)))
    }

    pub fn verify(&self, authority: &str, presented: &str) -> Verification {
        match self.pins.get(authority) {
            None => Verification::FirstUse { fingerprint: presented.into() },
            Some(p) if p == presented => Verification::Trusted,
            Some(p) => Verification::Changed { pinned: p.clone(), presented: presented.into() },
        }
    }

    pub fn confirm_first_use(&mut self, authority: &str, fingerprint: &str) -> Result<(), PinError> {
        if self.pins.contains_key(authority) {
            return Err(PinError::AlreadyPinned);
        }
        self.pins.insert(authority.into(), fingerprint.into());
        Ok(())
    }

    /// Replace a pin after out-of-band verification. `expected_old` is the pin
    /// that was displayed (rechecked to avoid races); `typed` must equal `new`.
    pub fn rotate(&mut self, authority: &str, expected_old: &str, new: &str, typed: &str) -> Result<(), PinError> {
        let cur = self.pins.get(authority).ok_or(PinError::NoPin)?;
        if cur != expected_old {
            return Err(PinError::StalePin);
        }
        if typed.trim() != new {
            return Err(PinError::ConfirmationMismatch);
        }
        self.pins.insert(authority.into(), new.into());
        Ok(())
    }

    pub fn remove(&mut self, authority: &str) {
        self.pins.remove(authority);
    }

    pub fn pins(&self) -> &BTreeMap<String, String> {
        &self.pins
    }
}

fn b64_nopad(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_then_trusted_then_changed() {
        let mut s = HostKeyStore::default();
        let a = "[10.0.0.2]:22";
        assert!(matches!(s.verify(a, "SHA256:x"), Verification::FirstUse { .. }));
        s.confirm_first_use(a, "SHA256:x").unwrap();
        assert_eq!(s.verify(a, "SHA256:x"), Verification::Trusted);
        assert!(matches!(s.verify(a, "SHA256:y"), Verification::Changed { .. }));
        assert_eq!(s.confirm_first_use(a, "SHA256:y"), Err(PinError::AlreadyPinned));
        assert_eq!(s.rotate(a, "SHA256:x", "SHA256:y", "yes"), Err(PinError::ConfirmationMismatch));
        assert_eq!(s.rotate(a, "SHA256:old", "SHA256:y", "SHA256:y"), Err(PinError::StalePin));
        s.rotate(a, "SHA256:x", "SHA256:y", "SHA256:y").unwrap();
        assert_eq!(s.verify(a, "SHA256:y"), Verification::Trusted);
    }

    #[test]
    fn fingerprint_matches_openssh_format() {
        assert_eq!(HostKeyStore::fingerprint_of(b""), "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
    }
}
