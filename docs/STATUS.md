# Nexus Desktop status

> Newest first. Only claims backed by evidence are marked verified.

## 11 November 2026 — owner-specific values moved out of the source

- Owner asked to clean the repo of anything that should not be public. No
  secrets were found (gitleaks over all history: only test vectors). Owner
  infrastructure details were removed from the tree: the Worker host, Access
  issuer and client id, and server account names now come from an ignored
  `site.json` (`nexus_core::site`, `docs/site.example.json`, NixOS option
  `programs.nexus-desktop.site`). Windows-era handoffs, logs and Debian
  proposals were removed (they remain in the private NexusWindows repo).
- Debian detection still uses all built-in signals; the site only adds names.
- **Verified:** 125 tests pass with and without a site file; with the owner's
  file the Settings card shows the real Worker and issuer.
- History: the old development history (which contained those values) was
  replaced by one clean commit and the GitHub repo recreated, so the old
  commits are no longer served. The repo was then made public.

## 11 November 2026 — one passcode key for several PCs

- Owner asked for one code that unlocks both NexusNix and NexusWindows, since
  the iPhone holds only one pairing. Settings → App lock now has **Show key for
  another PC** (shown only after a current iPhone code, which counts as an
  attempt) and **Use the key from another PC** (key must be 10 bytes; turns the
  lock on only if the current code verifies). Nothing changes on the iPhone.
  Same `lock.rs` change in NexusWindows; `docs/OTP.md` updated identically in
  all three repos ("More than one PC").
- **Verified:** 123 workspace tests pass (2 new); the buttons render.
  **Not verified:** sharing a key between two real PCs and a phone.

## 10 November 2026 — Linux/NixOS port (NexusNix), from Windows 0.1.13

- New repo `ljcatherine/NexusNix`, ported from NexusWindows `2e83c4d` (the SSH
  test private keys committed there were left out).
  Every Windows-only API and every gap is in `docs/PARITY-LINUX.md`.
- Linux mechanisms: XDG directories (0700), Secret Service through `keyring`
  (KWallet/GNOME Keyring) in place of Credential Manager, an AES-256-GCM Access
  session file whose key lives in the Secret Service in place of DPAPI,
  `x-scheme-handler` desktop entry in place of the HKCU URL scheme, `xdg-open`,
  FileManager1, Unix PTY shells (login shell, Bash, Zsh, Fish, pwsh), OpenSSH
  from PATH, XDG portal file dialogs, Inter/JetBrains Mono/codicon fonts.
- Nix: `flake.nix` with `nix build` (app + `nexus-ro`, wrapper with runtime
  libraries, fonts, OpenSSH, git, xdg-utils), `nix run`, `nix develop`, overlay
  and a NixOS module `programs.nexus-desktop`.
- OTP: `otp.rs` and `docs/OTP.md` byte-identical to Windows (and OTP.md to iOS);
  same RFC 6238 reference vectors.
- App lock fix found while porting: eframe 0.37 runs only `App::logic` while a
  window is minimised, so the minimise check now also runs there (P24). Nexus
  runs through XWayland by default because Wayland hides minimised state.
- **Verified on NixOS 26.05 / Plasma 6 (Wayland):** `cargo test --workspace`
  121 passed, 1 ignored; the ignored Secret Service round trip passed against
  KWallet; `nix build` passed with the same 121 tests in the sandbox; the app
  launched and rendered the dashboard and the IDE (file, minimap, bash terminal,
  Codex shown Connected); settings/data directories created 0700; with
  `app_lock` on it opened on the lock screen; a probe with the same eframe saw
  `minimized == Some(true)` in `logic` under XWayland.
- **Not verified:** typing a code into the lock screen, phone pairing, the
  minimise relock in the full app (synthetic keyboard input does not reach
  windows on this session), Cloudflare Access sign-in, SSH/SFTP to a real host,
  live provider turns, file dialogs, NixOS module in a system configuration.

## Before 10 November 2026 — Windows history

Nexus Desktop 0.1.0–0.1.13 was developed in the private Windows repo
(`ljcatherine/NexusWindows`), whose `docs/STATUS.md`, `docs/log/`, handoffs and
Debian hardening proposals hold that history. They describe one owner's live
servers, so they are not part of this repo.

## Known limitations (planned work)
- Language Server Protocol (completion, go-to-definition, hover, rename) — not yet;
  diagnostics come from build/check output.
- Debug Adapter Protocol debugging — not yet.
- Code folding, multi-window — not yet. Split view is two editors side by side.
- Cloudflare Access sign-in and SSH relay — done (0.1.3); gateway HTTP API client (PS5LM, search) — not yet.
- Writable remote workspaces on non-Debian hosts — not yet (use shadow workspaces).
- Windows toast notifications, Windows Hello lock — not yet.
- egui renders painted glass (no real backdrop blur), matching the iOS card technique.
