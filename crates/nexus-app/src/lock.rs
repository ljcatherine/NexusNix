//! Optional app lock unlocked by the one-time passcode shown in the Nexus iOS
//! app (Services → One Time Passcode). Locks on launch and when the window is
//! minimised. Hides the UI only; running turns, terminals and monitoring
//! continue. It guards against someone at an unlocked PC, not against other
//! programs running as the same Linux user (they could edit settings.json).

use crate::settings::{secrets, Settings};
use nexus_security::otp;

/// Secret Service entry (service `NexusDesktop`) holding the base32 shared
/// secret (Windows: the Credential Manager entry with the same name).
pub const SECRET_NAME: &str = "app-lock-otp-secret";

#[derive(Default)]
pub struct AppLock {
    pub locked: bool,
    pub input: String,
    pub error: Option<String>,
    /// Pairing in progress: (new base32 secret, code typed to confirm it).
    pub pairing: Option<(String, String)>,
    /// Joining with the key of another paired PC: (key typed, code typed).
    /// One iPhone holds one key, so every PC shares it (docs/OTP.md).
    pub joining: Option<(String, String)>,
    /// Showing this PC's key for another PC: (code typed, key once verified).
    pub reveal: Option<(String, Option<String>)>,
}

/// Check a key typed on this PC (from another paired PC) and a current code.
/// Returns the canonical 16-character base32 key and the verifier state.
pub fn verify_existing_key(typed_key: &str, code: &str, now: u64) -> Result<(String, otp::Verifier), String> {
    let key = otp::base32_decode(typed_key).filter(|k| k.len() == otp::SECRET_BYTES).ok_or("That is not a 16-character Nexus key (letters A–Z and digits 2–7).")?;
    let mut v = otp::Verifier::default();
    v.check(&key, code, now).map_err(|e| format!("{e}. Check the key, then enter the code the iPhone shows now."))?;
    Ok((otp::base32_encode(&key), v))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl AppLock {
    pub fn new(enabled: bool) -> Self {
        Self { locked: enabled, ..Default::default() }
    }

    pub fn lock(&mut self) {
        if !self.locked {
            self.locked = true;
            self.input.clear();
            self.error = None;
        }
    }

    /// Check the typed code against the stored secret (caller saves the attempt state).
    pub fn try_unlock(&mut self, s: &mut Settings, secret: Option<String>, now: u64) {
        let Some(key) = secret.as_deref().and_then(otp::base32_decode) else {
            self.error = Some("No passcode secret is stored on this PC. Set app_lock to false in settings.json to recover, then pair again.".into());
            return;
        };
        let r = s.otp_verifier.check(&key, &self.input, now);
        self.input.clear();
        match r {
            Ok(()) => {
                self.locked = false;
                self.error = None;
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Confirm pairing with a code from the iPhone; on success store the secret and enable.
    pub fn confirm_pairing(&mut self, s: &mut Settings, now: u64) -> Result<(), String> {
        let Some((secret, typed)) = self.pairing.clone() else { return Err("Start pairing first.".into()) };
        let key = otp::base32_decode(&secret).ok_or("Invalid secret")?;
        let mut v = otp::Verifier::default();
        v.check(&key, &typed, now).map_err(|e| e.to_string())?;
        self.enable(s, &secret, v)?;
        self.pairing = None;
        Ok(())
    }

    /// Use the key of another PC that is already paired with the iPhone.
    /// Turns the lock on only if the iPhone's current code verifies.
    pub fn confirm_joining(&mut self, s: &mut Settings, now: u64) -> Result<(), String> {
        let Some((typed_key, code)) = self.joining.clone() else { return Err("Start with “Use the key from another PC” first.".into()) };
        let (secret, v) = verify_existing_key(&typed_key, &code, now)?;
        self.enable(s, &secret, v)?;
        self.joining = None;
        Ok(())
    }

    fn enable(&mut self, s: &mut Settings, secret: &str, v: otp::Verifier) -> Result<(), String> {
        secrets::set(SECRET_NAME, secret)?;
        s.otp_verifier = v;
        s.app_lock = true;
        s.save();
        self.error = None;
        Ok(())
    }

    /// Show this PC's key after a current code (so a passer-by at an unlocked
    /// PC cannot copy it without the iPhone). Counts as an attempt; the
    /// caller saves the attempt state.
    pub fn try_reveal(&mut self, s: &mut Settings, secret: Option<String>, now: u64) {
        let Some((code, _)) = self.reveal.clone() else { return };
        let Some(key) = secret.as_deref().and_then(otp::base32_decode) else {
            self.error = Some("No passcode secret is stored on this PC.".into());
            return;
        };
        match s.otp_verifier.check(&key, &code, now) {
            Ok(()) => {
                self.reveal = Some((String::new(), Some(otp::base32_encode(&key))));
                self.error = None;
            }
            Err(e) => {
                self.reveal = Some((String::new(), None));
                self.error = Some(e.to_string());
            }
        }
    }
}

/// Full-window lock screen; the caller draws nothing else while locked.
pub fn lock_screen(app: &mut crate::app::NexusApp, ui: &mut egui::Ui) {
    let t = app.s.tokens.clone();
    let mut submit = false;
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.33);
        ui.label(egui::RichText::new("Nexus Desktop is locked").size(22.0).strong());
        ui.add_space(8.0);
        ui.label(nexus_ui::secondary(&t, "Open Nexus on your iPhone → Services → One Time Passcode and enter the 4-digit code."));
        ui.add_space(14.0);
        let r = ui.add(
            egui::TextEdit::singleline(&mut app.lock.input)
                .char_limit(otp::DIGITS)
                .hint_text("0000")
                .font(egui::TextStyle::Heading)
                .desired_width(120.0),
        );
        r.request_focus();
        app.lock.input.retain(|c| c.is_ascii_digit());
        if app.lock.input.len() == otp::DIGITS && (r.changed() || ui.input(|i| i.key_pressed(egui::Key::Enter))) {
            submit = true;
        }
        ui.add_space(8.0);
        if ui.add_enabled(app.lock.input.len() == otp::DIGITS, egui::Button::new("Unlock")).clicked() {
            submit = true;
        }
        if let Some(e) = &app.lock.error {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(e).color(t.error()));
        }
    });
    if submit {
        app.lock.try_unlock(&mut app.s, secrets::get(SECRET_NAME), now());
        app.s.save(); // persist failures/lockout so a restart does not reset them
    }
    // Lockout countdowns and the 20 s code change need periodic repaints.
    ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
}

/// Settings card contents: pair (enable), disable, re-pair, lock now.
pub fn settings_ui(app: &mut crate::app::NexusApp, ui: &mut egui::Ui) {
    let t = app.s.tokens.clone();
    ui.label(nexus_ui::secondary(&t, "Lock Nexus at launch and after minimising. Unlock with the 4-digit code (changes every 20 s) shown by the Nexus iOS app under Services → One Time Passcode. Running agents, terminals and monitoring keep going while locked."));
    if let Some((mut key, mut code)) = app.lock.joining.clone() {
        ui.add_space(6.0);
        ui.label("Use the same key as your other Nexus PC, so one iPhone code unlocks both.");
        ui.label("1. On the other PC (unlocked): Settings → App lock → Show key for another PC. Type that key here:");
        ui.add(egui::TextEdit::singleline(&mut key).hint_text("ABCD-EFGH-IJKL-MNOP").font(egui::TextStyle::Monospace).desired_width(240.0));
        ui.label("2. Enter the 4-digit code the iPhone shows now:");
        let (mut confirm, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            let r = ui.add(egui::TextEdit::singleline(&mut code).char_limit(otp::DIGITS).hint_text("0000").desired_width(70.0));
            code.retain(|c| c.is_ascii_digit());
            confirm = ui.button("Turn on app lock").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            cancel = ui.button("Cancel").clicked();
        });
        app.lock.joining = (!cancel).then_some((key, code));
        if cancel {
            app.lock.error = None;
        }
        if confirm {
            match app.lock.confirm_joining(&mut app.s, now()) {
                Ok(()) => app.toast("App lock on with the shared key: the same iPhone code unlocks your other PC", t.success()),
                Err(e) => app.lock.error = Some(e),
            }
        }
    } else if let Some((mut code, shown)) = app.lock.reveal.clone() {
        ui.add_space(6.0);
        match shown {
            Some(key) => {
                ui.label("On the other PC: Settings → App lock → Use the key from another PC, and type:");
                ui.label(egui::RichText::new(otp::format_secret(&key)).monospace().size(20.0).strong());
                ui.label(nexus_ui::secondary(&t, "Anyone with this key can make unlock codes. Do not save or share it."));
                if ui.button("Hide key").clicked() {
                    app.lock.reveal = None;
                }
            }
            None => {
                ui.label("Enter the 4-digit code the iPhone shows now to show this PC's key:");
                let (mut go, mut cancel) = (false, false);
                ui.horizontal(|ui| {
                    let r = ui.add(egui::TextEdit::singleline(&mut code).char_limit(otp::DIGITS).hint_text("0000").desired_width(70.0));
                    code.retain(|c| c.is_ascii_digit());
                    go = ui.add_enabled(code.len() == otp::DIGITS, egui::Button::new("Show key")).clicked() || (code.len() == otp::DIGITS && r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                    cancel = ui.button("Cancel").clicked();
                });
                if cancel {
                    app.lock.reveal = None;
                    app.lock.error = None;
                } else {
                    app.lock.reveal = Some((code, None));
                    if go {
                        app.lock.try_reveal(&mut app.s, secrets::get(SECRET_NAME), now());
                        app.s.save();
                    }
                }
            }
        }
    } else if let Some((secret, mut typed)) = app.lock.pairing.clone() {
        ui.add_space(6.0);
        ui.label("1. On your iPhone, open Nexus → Services → One Time Passcode → Pair with Nexus Desktop and enter this key:");
        ui.label(egui::RichText::new(otp::format_secret(&secret)).monospace().size(20.0).strong());
        ui.label("2. Enter the 4-digit code the iPhone now shows:");
        let (mut confirm, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            let r = ui.add(egui::TextEdit::singleline(&mut typed).char_limit(otp::DIGITS).hint_text("0000").desired_width(70.0));
            typed.retain(|c| c.is_ascii_digit());
            confirm = ui.button("Turn on app lock").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            cancel = ui.button("Cancel").clicked();
        });
        app.lock.pairing = (!cancel).then_some((secret, typed));
        if cancel {
            app.lock.error = None;
        }
        if confirm {
            match app.lock.confirm_pairing(&mut app.s, now()) {
                Ok(()) => app.toast("App lock on: enter the iPhone passcode at launch and after minimising", t.success()),
                Err(e) => app.lock.error = Some(e),
            }
        }
    } else {
        ui.horizontal(|ui| {
            if app.s.app_lock {
                ui.label(egui::RichText::new("On").color(t.success()));
                if ui.button("Lock now").clicked() {
                    app.lock.lock();
                }
                if ui.button("Show key for another PC…").on_hover_text("Lets your other Nexus PC use the same key, so one iPhone code unlocks both").clicked() {
                    app.lock.reveal = Some((String::new(), None));
                    app.lock.error = None;
                }
                if ui.button("Pair again…").on_hover_text("New key; the old iPhone pairing and any other PC using the old key stop working").clicked() {
                    app.lock.pairing = Some((otp::generate_secret(), String::new()));
                }
                if ui.button("Turn off").clicked() {
                    app.s.app_lock = false;
                    app.s.save();
                    secrets::delete(SECRET_NAME);
                }
            } else {
                if ui.button("Set up with iPhone…").on_hover_text("New key for the iPhone (replaces any key the iPhone already has)").clicked() {
                    app.lock.pairing = Some((otp::generate_secret(), String::new()));
                    app.lock.error = None;
                }
                if ui.button("Use the key from another PC…").on_hover_text("Your iPhone is already paired with another Nexus PC: share its key").clicked() {
                    app.lock.joining = Some((String::new(), String::new()));
                    app.lock.error = None;
                }
            }
        });
    }
    if let Some(e) = app.lock.error.clone().filter(|_| !app.lock.locked) {
        ui.label(egui::RichText::new(e).color(t.error()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_needs_secret_and_correct_code() {
        let mut s = Settings::default();
        let mut l = AppLock::new(true);
        let secret = "GEZDGNBVGY3TQOJQ".to_string();
        let key = otp::base32_decode(&secret).unwrap();
        let now = 1111111109;
        l.input = "0000".into();
        l.try_unlock(&mut s, None, now);
        assert!(l.locked && l.error.as_deref().unwrap().contains("No passcode secret"));
        l.input = if otp::code(&key, now) == 0 { "0001".into() } else { "0000".into() };
        l.try_unlock(&mut s, Some(secret.clone()), now);
        assert!(l.locked && s.otp_verifier.failures == 1 && l.input.is_empty());
        l.input = format!("{:04}", otp::code(&key, now));
        l.try_unlock(&mut s, Some(secret), now);
        assert!(!l.locked && l.error.is_none() && s.otp_verifier.failures == 0);
    }

    #[test]
    fn existing_key_from_another_pc_is_normalised_and_verified() {
        let secret = "GEZDGNBVGY3TQOJQ";
        let key = otp::base32_decode(secret).unwrap();
        let now = 1111111109;
        let code = format!("{:04}", otp::code(&key, now));
        // As shown on the other PC (dashes) and typed in lower case with spaces.
        let (canon, v) = verify_existing_key(" gezd-gnbv-gy3t-qojq ", &code, now).unwrap();
        assert_eq!(canon, secret);
        // The step used to join is not accepted again (no replay).
        let mut v = v;
        assert!(v.check(&key, &code, now).is_err());
        let wrong = if code == "0000" { "0001" } else { "0000" };
        assert!(verify_existing_key(secret, wrong, now).is_err());
        assert!(verify_existing_key("GEZDGNBV", &code, now).is_err(), "short key");
        assert!(verify_existing_key("GEZDGNBVGY3TQOJQGEZD", &code, now).is_err(), "long key");
        assert!(verify_existing_key("1EZDGNBVGY3TQOJQ", &code, now).is_err(), "not base32");
    }

    #[test]
    fn reveal_needs_a_current_code_and_counts_failures() {
        let mut s = Settings::default();
        let mut l = AppLock::new(false);
        let secret = "GEZDGNBVGY3TQOJQ".to_string();
        let key = otp::base32_decode(&secret).unwrap();
        let now = 2000000000;
        let code = format!("{:04}", otp::code(&key, now));
        let wrong = if code == "0000" { "0001" } else { "0000" };
        l.reveal = Some((wrong.into(), None));
        l.try_reveal(&mut s, Some(secret.clone()), now);
        assert_eq!(l.reveal, Some((String::new(), None)));
        assert!(l.error.is_some() && s.otp_verifier.failures == 1);
        l.reveal = Some((code, None));
        l.try_reveal(&mut s, Some(secret.clone()), now);
        assert_eq!(l.reveal, Some((String::new(), Some(secret))));
        assert!(l.error.is_none() && s.otp_verifier.failures == 0);
    }
}
