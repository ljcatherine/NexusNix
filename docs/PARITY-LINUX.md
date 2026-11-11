# Feature parity: Nexus Desktop for Windows → Linux (NixOS)

Source: `ljcatherine/NexusWindows` at `2e83c4d` (0.1.13), imported unmodified
as this repo's first commit. Every later commit is the Linux port.
Primary target: NixOS 26.05 with KDE Plasma 6 on Wayland (the owner's machine).

**Status key.** **Same**: identical code on both platforms. **Adapted**: same
behaviour through a Linux mechanism. **Gap**: cannot be 1:1 on Linux; the
difference is described.

**Evidence key.** *test* names the automated test. *run* means exercised by
hand on the owner's NixOS machine in the session that wrote this file (see
`docs/log/2026-11-10.md`). *not run* means nothing beyond compiling.

## Platform mapping (every Windows-only API)

| # | Windows mechanism | Linux replacement | Where | Evidence | Status |
|---|---|---|---|---|---|
| P1 | `%APPDATA%\NexusDesktop` (settings.json, sessions.db, audit.jsonl, known_hosts.json) | `$XDG_CONFIG_HOME/nexus-desktop` (default `~/.config/nexus-desktop`), created 0700 at startup | `nexus_core::platform::config_dir`, `main.rs` | tests `xdg_dirs_end_in_app_dir`, `private_dir_is_owner_only`; run: settings.json, sessions.db, audit.jsonl created in a 0700 directory | Adapted |
| P2 | `%LOCALAPPDATA%\NexusDesktop` (recovery, shadows, Access session, crash log, OAuth callback) | `$XDG_DATA_HOME/nexus-desktop` (default `~/.local/share/nexus-desktop`), 0700 | `nexus_core::platform::data_dir` | same tests; run: created 0700 | Adapted |
| P3 | Fallback to `%TEMP%` when the variables are missing | Fallback to the password-database home, then the current directory. Never `/tmp`, which is world-writable on Linux | `platform::home_dir` | code review | Adapted (stricter) |
| P4 | Windows Credential Manager via `keyring` (service `NexusDesktop`) | Secret Service via the same `keyring` 4 crate (zbus backend): KWallet on Plasma, GNOME Keyring elsewhere. Same service and entry names (`app-lock-otp-secret`, `ssh-passphrase`, `ssh-passphrase:<device>`, API-key targets) | `nexus-app/src/settings.rs::secrets` | test `secret_service_roundtrip` (`--ignored`, needs a desktop session) passed against KWallet | Adapted |
| P5 | DPAPI-encrypted `access-session.bin` (Credential Manager's 2.5 KB limit) | AES-256-GCM file (`NXS1` + nonce + ciphertext, fixed AAD); the 256-bit key lives only in the Secret Service (`access-session-key`). File 0600 in a 0700 directory | `nexus-access/src/store.rs` | tests `roundtrip_and_ciphertext_hides_token`, `wrong_key_tampering_and_missing_key_fail_closed`, `secret_service_roundtrip` | Adapted |
| P6 | URL scheme registration in `HKCU\Software\Classes\com.ljcatherine.Nexus` | `x-scheme-handler/com.ljcatherine.nexus` desktop entry written to `$XDG_DATA_HOME/applications/nexus-desktop-url-handler.desktop` and made default with `xdg-mime`; redone at every sign-in (picks up new Nix store paths). The Nix package and NixOS module also declare the handler | `nexus-app/src/access.rs::register_scheme`, `nix/package.nix`, `nix/module.nix` | tests `scheme_handler_entry_targets_lowercase_mime_and_passes_url`, `exec_quoting_escapes_reserved_characters`; live sign-in not run | Adapted |
| P7 | `rundll32 url.dll,FileProtocolHandler` / `cmd /C start` to open URLs | `xdg-open`, restricted to `http(s)` URLs with no whitespace or control characters | `platform::open_url` | test `urls_are_restricted_to_http` | Adapted (stricter) |
| P8 | `explorer.exe /select,<file>` ("Reveal in File Explorer") | `org.freedesktop.FileManager1.ShowItems` over D-Bus (Dolphin, Nautilus…), fallback `xdg-open` on the folder. Menu label "Reveal in File Manager" | `platform::reveal_in_file_manager` | test `file_uris_are_percent_encoded`; not run in the UI | Adapted |
| P9 | `cmd /C start "" codex login` (new console for CLI sign-in) | New terminal window: `$TERMINAL`, then konsole, gnome-terminal, kgx, xfce4-terminal, kitty, alacritty, foot, wezterm, xterm | `platform::launch_in_terminal_window` | not run | Adapted |
| P10 | `CREATE_NO_WINDOW` on child processes (git, providers, ssh-keygen, tasks) | Not needed (no console windows on Linux). git, ssh-keygen and tasks get `stdin` = `/dev/null` so they never wait on the app's stdin | `nexus-git`, `keys.rs`, `ide.rs` | existing git tests | Adapted |
| P11 | `.cmd` shims run through `cmd /C`, `npm.cmd` | Executables run directly (`npm`, `codex`, `claude`) | `locate.rs`, `ide.rs` | test `provider_commands_drop_ssh_agent_variables` | Adapted |
| P12 | Codex at `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin\codex.exe`; Claude Code at `~/.local/bin/claude.exe`, npm `claude.cmd`, or bundled in the Claude desktop app | `NEXUS_CODEX_PATH` / `NEXUS_CLAUDE_PATH`, `PATH`, then `~/.local/bin`, `~/.npm-global/bin`, `~/.npm/bin`, `~/.nix-profile/bin`, `~/.bun/bin`, `~/.volta/bin`, `/etc/profiles/per-user/$USER/bin`, `/run/current-system/sw/bin` | `nexus-providers/src/locate.rs` | run: the IDE showed Codex "Connected" (found in `~/.npm-global/bin`) | Adapted |
| P13 | Claude CLI bundled inside the Claude desktop app | Not searched: the Linux Claude app ships no standalone CLI | — | — | Gap |
| P14 | Windows OpenSSH (`%SystemRoot%\System32\OpenSSH\ssh.exe`, `sftp.exe`, `ssh-keygen.exe`) | OpenSSH from `PATH`; the Nix wrapper appends nixpkgs' `openssh` so it is always present | `infra.rs::open_ssh_terminal`, `keys.rs` | SSH mock tests use `ssh-keygen`; interactive ssh not run against a host | Adapted |
| P15 | Keys in `%USERPROFILE%\.ssh` | `~/.ssh` (created 0700 if missing; ssh-keygen writes the key 0600) | `keys.rs`, `platform::ssh_dir` | not run in the UI | Adapted |
| P16 | `%COMPUTERNAME%` in generated key comments | `/proc/sys/kernel/hostname` | `platform::hostname` | not run | Adapted |
| P17 | ConPTY shells: PowerShell (default), Command Prompt, WSL, Git Bash | Unix PTY shells: login shell `$SHELL` (default), Bash, Zsh, Fish, PowerShell (`pwsh`) when installed. Shells get `TERM=xterm-256color`, `COLORTERM=truecolor` | `nexus-terminal/src/lib.rs` | tests `spawns_shell_and_reads_output` (real PTY, exit code 3), `login_shell_is_listed_first_and_titles_hide_paths` | Adapted; Command Prompt and WSL are Gaps |
| P18 | DWM dark title bar (caption `#070C18`, border colour) | No client API: KWin/Mutter draw server-side title bars from the desktop theme. No-op | `nexus-app/src/win.rs` | — | Gap |
| P19 | Segoe UI Variable / Segoe UI Semibold / Cascadia Mono | Inter (variable; SemiBold = face 12 of `Inter.ttc`), JetBrains Mono; fallback Noto Sans, DejaVu. The Nix package bundles them via `NEXUS_FONT_DIR` | `nexus-ui::install_fonts` | run: dashboard and IDE screenshots | Adapted (different typeface) |
| P20 | Segoe Fluent Icons code points | VS Code codicons from the Symbols Nerd Font; each constant keeps the Windows code point in a comment | `nexus-ui::icons` | run: dashboard and IDE screenshots | Adapted (different glyph art) |
| P21 | Segoe UI Symbol / Segoe UI Emoji | DejaVu Sans / Noto Emoji (monochrome; egui cannot draw colour-bitmap emoji such as Noto Color Emoji) | `nexus-ui::install_fonts` | — | Adapted |
| P22 | `windows_subsystem = "windows"`, `winresource` (exe icon and version info) | Not applicable. Icon via `.desktop` entry + hicolor PNG/SVG; window icon still set at runtime; app id `com.ljcatherine.NexusDesktop` = `StartupWMClass` | `nix/package.nix` | — | Adapted |
| P23 | WiX MSI, portable zip, `scripts/release.ps1`, Start-menu shortcut | `nix build` package with a desktop entry; `nix run`; NixOS module `programs.nexus-desktop` (optional XDG autostart, off by default like Windows). No GitHub Releases for Linux yet | `flake.nix`, `nix/` | run: `nix build` (121 tests in the sandbox) | Adapted; Linux release artefacts not made |
| P24 | Minimise detection for the app lock (`ViewportInfo.minimized`, checked in `App::ui`) | Two parts. (a) Native Wayland never tells a client it is minimised (winit returns `None`), so Nexus runs through XWayland by default and gives its terminals the real `WAYLAND_DISPLAY` back; `NEXUS_WAYLAND=1` opts into native Wayland, where the lock still applies at launch and with *Lock now* but **not on minimise**. (b) eframe 0.37 runs no `ui` pass while a window is minimised, only `App::logic`, so the upstream check in `ui` never sees `minimized == Some(true)`; the port also checks in `App::logic` | `nexus-app/src/main.rs::choose_backend`, `app.rs::logic`, `nexus-terminal` | run: a probe with the same eframe 0.37 features, minimised by KWin under XWayland, read `Some(true)` in `logic` and never in `ui`; under native Wayland it read `Some(false)` throughout. The full app was not minimised while unlocked (see feature 25) | Adapted; Gap only with `NEXUS_WAYLAND=1` |
| P25 | Codex's Windows sandbox (`windowsSandbox/*` app-server calls, readiness example) | Codex's own Linux sandbox (bubblewrap/Landlock). The `windows_sandbox_*` functions remain but are unused on Linux; the failure hint names the Linux sandbox | `nexus-app/src/ai.rs` | not run | Adapted |
| P26 | Committed disposable Ed25519 test keys (`crates/nexus-ssh/tests/fixtures`) | Generated with `ssh-keygen` per test run in a private temp dir; no private keys in git | `crates/nexus-ssh/tests/common` | SSH mock tests pass | Adapted |
| P27 | Path rules rejecting `C:\…`, `\\server\share`, `con`, `nul.txt`, `a:stream`, trailing dots | Kept exactly. Stricter than Linux needs, but workspaces and agent paths stay portable between the two apps | `nexus-security/src/paths.rs` | existing test | Same |
| P28 | Owner's Worker host, Cloudflare Access issuer and client id, and the Debian/NixOS account names hardcoded in the source | Read from an uncommitted `site.json` (`$NEXUS_SITE_FILE`, `~/.config/nexus-desktop/site.json`, or `/etc/nexus-desktop/site.json` from the NixOS option `programs.nexus-desktop.site`); placeholders otherwise, with Access sign-in disabled until configured. Debian detection keeps every built-in signal and only gains the site's account name. `nexus-ro` defaults its read root to the account's own `$HOME` | `nexus_core::site`, `nexus-access`, `nix/module.nix` | tests `defaults_are_placeholders`, `parses_a_full_file_and_rejects_bad_values`; full suite passes with and without a site file; run: Settings showed the values from `site.json` | Adapted (keeps the repo shareable) |

## Product features (Windows README, `docs/PARITY.md`, Settings)

| # | Feature | Linux implementation | Evidence | Status |
|---|---|---|---|---|
| 1 | One Time Passcode app lock: RFC 6238, HMAC-SHA1, 20 s, 4 digits, ±1 step, no replay, 5 failures → 30 s lockout doubling to 15 min, persisted | `nexus-security/src/otp.rs` byte-identical to Windows; `docs/OTP.md` byte-identical to the iOS and Windows copies; secret in the Secret Service | tests `matches_reference_vectors` (same RFC 6238 vectors), `secret_round_trips`, `verifier_window_replay_and_lockout`; `cmp` of OTP.md with the iOS repo | Same |
| 2 | Pairing (16-char base32 key shown, enabled only after a correct code), lock at launch, lock on minimise, *Lock now* | `nexus-app/src/lock.rs` (only comments changed) | lock unit tests; run: with `app_lock` on and a test secret in KWallet the app opened on the lock screen; typing a code and phone pairing not run (synthetic keyboard input does not reach windows on this Plasma session) | Same; minimise see P24 |
| 2b | One key for several PCs: *Show key for another PC* (after a current code) and *Use the key from another PC* (verified with a current code), so one iPhone code unlocks NexusNix and NexusWindows (`docs/OTP.md`, "More than one PC") | Same code in both repos' `lock.rs` | tests `existing_key_from_another_pc_is_normalised_and_verified`, `reveal_needs_a_current_code_and_counts_failures`; run: buttons render in Settings; not exercised with a phone | Same |
| 3 | Settings (theme tokens, layout, recents, devices, SSH identity, policies, API providers, default provider/models, telemetry interval, autosave recovery, PS5 URL, Bypass workspaces, Access memory-only, app lock, OTP verifier state) | Same `Settings` struct and JSON; only the file location changes (P1). Default SSH key `~/.ssh/id_ed25519` | existing tests | Same |
| 4 | Devices: iOS JSON import, ordered LAN/Tailscale/Cloudflare endpoints, editor | Unchanged | existing tests | Same |
| 5 | Host-key pinning: first-use confirmation, changed-key abort, typed rotation | Unchanged; host-key checks never weakened | mock-server tests | Same |
| 6 | Debian read-only policy engine, catalog console, `nexus-ro` helper, owner 30-minute `unlock debian` | Unchanged; the flake builds `nexus-ro` too | policy, catalog, ro and mock tests | Same |
| 7 | Monitoring: metrics script, parser, history, rates, sparklines, low-resource in-app alerts at 90 % | Unchanged (`nexus-telemetry`) | existing tests; no live host polled here | Same |
| 8 | Services, logs, processes (read-only catalog) | Unchanged | catalog tests | Same |
| 9 | Network probes from this PC (DNS + TCP) | Unchanged (std networking) | not run | Same |
| 10 | SSH/SFTP terminals for allowed hosts; NixOS dry-build and typed-confirmation switch | OpenSSH in an IDE terminal tab (P14, P17) with `StrictHostKeyChecking=ask`, `IdentitiesOnly`, no agent/X11 forwarding | not run against a host | Adapted |
| 11 | Cloudflare Access sign-in (PKCE, Worker redirect, URL scheme, encrypted session, memory-only option, relay) | P5, P6, P7 | unit tests; live sign-in not run | Adapted |
| 12 | Minecraft panel link (opens the Worker URL) | `xdg-open` (P7) | not run | Adapted |
| 13 | IDE: explorer honouring `.gitignore`/`.cursorignore`/`.nexusignore`, tabs, highlighting, multi-cursor, find/replace, minimap, split, Git gutter, quick open, palette, workspace search, recovery | Unchanged | existing tests | Same |
| 14 | Keyboard shortcuts (Ctrl+O/P/S/W/B/L/J/K, Ctrl+Shift+…) | Unchanged; egui maps `COMMAND` to Ctrl on Linux | not run | Same |
| 15 | Source control (status, diff, stage, commit, guarded destructive ops) | Unchanged; git CLI from `PATH` (Nix wrapper appends git) | git tests (real git CLI) | Same |
| 16 | Build/test tasks (cargo, npm, python, dotnet) with Problems list | Unchanged except `npm` instead of `npm.cmd` (P11) | not run | Adapted |
| 17 | Terminals: tabs, search, agent-owned terminals | P17 | PTY test; run: IDE screenshot with a login-shell (bash) terminal tab | Adapted |
| 18 | AI providers: Codex (`codex app-server`), Claude Code (`claude -p` stream-json), OpenAI-compatible, PS5LM; Ask/Plan/Agent/Bypass | Unchanged protocols; binaries located per P12; SSH agent variables still scrubbed | provider mapping tests; no live turn run here | Same |
| 19 | Agents: SQLite sessions, task memory, compaction, snapshots, hunk review, patch export, Ctrl+K inline edit | Unchanged; `sessions.db` under P1 | existing tests | Same |
| 20 | Attachments: images/PDF via picker or drag-and-drop | Picker through the XDG desktop portal (`rfd` `xdg-portal` backend instead of the Win32 dialog) | not run | Adapted |
| 21 | File dialogs (open folder, import devices, choose key, save patch) | XDG desktop portal (needs `xdg-desktop-portal`; the NixOS module enables it) | not run | Adapted |
| 22 | Debian shadow workspaces | Unchanged; stored under P2 | existing tests | Same |
| 23 | Crash log `last-crash.txt` | Under P2, directory 0700 | not run | Same |
| 24 | Window size/position persistence (`persist_window`) | Unchanged (eframe) | not run | Same |
| 25 | Lock on minimise | X11/XWayland default plus the `App::logic` check (P24) | probe only (P24); not exercised end to end in the app | Adapted |

## Genuine gaps (cannot be 1:1)

1. **Title-bar colours** (P18): Linux compositors draw the frame from the desktop theme.
2. **Native-Wayland minimise lock** (P24): Wayland does not expose minimised state. The default XWayland mode keeps the Windows behaviour; native Wayland is opt-in and loses only the on-minimise trigger.
3. **Command Prompt and WSL terminals** (P17): Windows-only programs. PowerShell is offered when `pwsh` is installed.
4. **Claude CLI bundled in the Claude desktop app** (P13): not shipped on Linux.
5. **Codex Windows sandbox setup** (P25): Windows-only API; Codex uses its own Linux sandbox.
6. **Fonts and icons** (P19–P21): Segoe and Cascadia are not redistributable; layout and code points are kept, glyph art differs.
7. **Releases** (P23): Windows publishes MSI/zip/exe via `scripts/release.ps1`; this repo has no Linux release script or GitHub Release yet.

## Finding for the Windows app

P24 (b) is probably not Linux-specific: on Windows too, eframe 0.37 runs only
`App::logic` while minimised, so NexusWindows' check in `App::ui` may never lock
on minimise. NexusWindows' STATUS says the lock was never exercised end to end.
This was not tested on Windows and NexusWindows was not changed.
