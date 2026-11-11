//! Nexus one-time passcode (app unlock code shown by the Nexus iOS app).
//!
//! RFC 6238 TOTP: HMAC-SHA1, 20-second period, T0 = 0, 4 digits (dynamic
//! truncation mod 10^4). The shared secret is 10 random bytes shown as 16
//! RFC 4648 base32 characters (`XXXX-XXXX-XXXX-XXXX`); Nexus Desktop generates
//! it and the owner types it into the iOS app (Services → One Time Passcode).
//! Spec: `docs/OTP.md` (mirrored in the iOS repo).
//!
//! Four digits are guessable, so [`Verifier`] limits attempts: every 5
//! consecutive failures lock entry out for 30 s, doubling up to 15 min, and a
//! code (time step) that unlocked once is never accepted again.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};

pub const PERIOD: u64 = 20;
pub const DIGITS: usize = 4;
pub const SECRET_BYTES: usize = 10;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// New random secret as 16 base32 characters.
pub fn generate_secret() -> String {
    let mut b = [0u8; SECRET_BYTES];
    getrandom::fill(&mut b).expect("OS random number generator");
    base32_encode(&b)
}

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode base32, ignoring case, spaces, dashes and `=` padding.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let v = ALPHABET.iter().position(|&a| a as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// `ABCDEFGHIJKLMNOP` → `ABCD-EFGH-IJKL-MNOP` for display.
pub fn format_secret(s: &str) -> String {
    s.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

fn code_at_step(key: &[u8], step: u64) -> u16 {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 15) as usize;
    let bin = u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff;
    (bin % 10u32.pow(DIGITS as u32)) as u16
}

/// The 4-digit code at `unix` seconds.
pub fn code(key: &[u8], unix: u64) -> u16 {
    code_at_step(key, unix / PERIOD)
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum OtpError {
    #[error("Too many wrong codes. Try again in {0} s.")]
    LockedOut(u64),
    #[error("Enter the 4-digit code from Nexus on your iPhone.")]
    Malformed,
    #[error("That code is wrong or expired.")]
    Wrong,
}

/// Attempt limiting and replay protection. Persist it (settings) so restarting
/// the app does not reset the lockout.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Verifier {
    pub failures: u32,
    pub locked_until: u64,
    pub last_step: Option<u64>,
}

impl Verifier {
    /// Checks `input` against the steps before, at and after `now` (±20 s clock skew).
    pub fn check(&mut self, key: &[u8], input: &str, now: u64) -> Result<(), OtpError> {
        if now < self.locked_until {
            return Err(OtpError::LockedOut(self.locked_until - now));
        }
        let input = input.trim();
        if input.len() != DIGITS || !input.bytes().all(|b| b.is_ascii_digit()) {
            return Err(OtpError::Malformed);
        }
        let n: u16 = input.parse().map_err(|_| OtpError::Malformed)?;
        let cur = now / PERIOD;
        let hit = [cur.saturating_sub(1), cur, cur + 1]
            .into_iter()
            .find(|&s| self.last_step.is_none_or(|l| s > l) && code_at_step(key, s) == n);
        match hit {
            Some(s) => {
                self.last_step = Some(s);
                self.failures = 0;
                self.locked_until = 0;
                Ok(())
            }
            None => {
                self.failures += 1;
                if self.failures % 5 == 0 {
                    let secs = (30u64 << (self.failures / 5 - 1).min(5)).min(15 * 60);
                    self.locked_until = now + secs;
                }
                Err(OtpError::Wrong)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors from an independent Python hmac/hashlib implementation;
    // the iOS tests use the same ones.
    const KEY: &[u8] = b"1234567890";

    #[test]
    fn matches_reference_vectors() {
        assert_eq!(base32_encode(KEY), "GEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode("gezd-gnbv-gy3t-qojq").unwrap(), KEY);
        for (t, c) in [(0, 1490), (59, 2045), (1111111109, 3293), (2000000000, 8631)] {
            assert_eq!(code(KEY, t), c, "t={t}");
        }
    }

    #[test]
    fn secret_round_trips() {
        let s = generate_secret();
        assert_eq!(s.len(), 16);
        assert_eq!(base32_decode(&s).unwrap().len(), SECRET_BYTES);
        assert_eq!(format_secret("ABCDEFGHIJKLMNOP"), "ABCD-EFGH-IJKL-MNOP");
        assert!(base32_decode("not base32!").is_none());
    }

    fn fmt(t: u64) -> String {
        format!("{:04}", code(KEY, t))
    }

    #[test]
    fn verifier_window_replay_and_lockout() {
        let now = 1111111109;
        let mut v = Verifier::default();
        assert_eq!(v.check(KEY, "12", now), Err(OtpError::Malformed));
        // Previous step's code is accepted (clock skew), then never again.
        let (prev, cur) = (fmt(now - PERIOD), fmt(now));
        assert_eq!(v.check(KEY, &prev, now), Ok(()));
        if prev != cur {
            assert_eq!(v.check(KEY, &prev, now), Err(OtpError::Wrong));
        }
        assert_eq!(v.check(KEY, &cur, now), Ok(()));
        // Five wrong codes lock out for 30 s, even for the right code.
        let near: Vec<String> = [now - PERIOD, now, now + PERIOD].map(fmt).to_vec();
        let wrong = (0..10000u16).map(|n| format!("{n:04}")).find(|s| !near.contains(s)).unwrap();
        let mut l = Verifier::default();
        for _ in 0..5 {
            assert_eq!(l.check(KEY, &wrong, now), Err(OtpError::Wrong));
        }
        assert_eq!(l.check(KEY, &cur, now + 1), Err(OtpError::LockedOut(29)));
        assert_eq!(l.check(KEY, &cur, now + 30), Ok(()));
        assert_eq!(l.failures, 0);
        // The next five failures double it.
        for _ in 0..5 {
            let _ = l.check(KEY, &wrong, now + 40);
        }
        assert_eq!(l.locked_until, now + 40 + 30);
    }
}
