# Nexus Desktop for Linux engineering rules

This repo (`ljcatherine/NexusNix`, private) is the Linux/NixOS port of Nexus
Desktop for Windows (`ljcatherine/NexusWindows`, private), itself the companion
to the Nexus iOS app (`ljcatherine/Nexus`). Features and behaviour must match
the Windows app 1:1; every Windows-only API and every deliberate difference is
recorded in `docs/PARITY-LINUX.md`. Keep shared logic identical to NexusWindows
where possible so changes can be carried across. Never modify or publish the
iOS or Windows apps or their releases from here.
Exception (owner, 9 Nov 2026): the owner gave full permission to add the
one-time passcode feature (Services → One Time Passcode, `docs/OTP.md`) to the
iOS app. Changes there follow the iOS repo's own AGENTS.md (local xtool builds,
unsigned releases via its script); nothing else in the iOS app is in scope.

## Read first
- `docs/PARITY-LINUX.md` (Windows → Linux mapping and gaps).
- `docs/STATUS.md` (current verified state) and `docs/log/` (dated development log).
- `docs/PLAN.md`, `docs/PARITY.md`, `docs/SECURITY-MODEL.md`, `docs/adr/`.
- Every design decision, plan and production step is logged under `docs/` —
  append a dated entry to `docs/log/` for each working session and keep
  `docs/STATUS.md` accurate. Never claim validation without evidence.

## Absolute Debian read-only rule (highest priority)
- The Debian server (the owner's `debian_user` in `site.json`, which also hosts the Nexus gateway, orchestrator
  and workspace-agent) is read-only. Do not write files, install packages, change
  configuration, start/stop/restart services, deploy, change firewall/SSH, write
  caches/temp/Git objects, or run anything with persistent effects there without
  the owner's explicit approval of that specific action.
- Enforcement lives in `crates/nexus-security`. Every remote operation must pass
  through `PolicyEngine`; never add a code path that bypasses it. Gateway routes
  that mutate Debian-hosted state are denied by default.
- Owner write access in the app (owner decision, 8 Nov 2026, proposal 0001
  Phase 3): the owner can unlock Debian writes in Nexus Desktop for 30 minutes
  by typing `unlock debian` (`PolicyEngine::unlock_debian`). It covers only
  `DEBIAN_UNLOCKED` (write, arbitrary command, interactive shell, Git write) on
  Debian hosts, over direct SSH with a separate passphrase key Nexus never
  stores. It never applies to agents in any mode, never to the gateway, and
  delete/service control still need single-use escalations. This changes what
  the owner can do in the app, not what AI agents working on this project may
  do: the rules above still bind them.
- Debian terminals use the fixed observational command catalog only — no
  arbitrary shell, no user/model-supplied arguments interpolated into commands.
- Remote Debian workspaces open read-only; edits go to a local shadow workspace.
- Tests for policy must use mocks/disposable environments, never the live server.

## Engineering
- Rust stable (see `rust-toolchain.toml`), workspace in `crates/`.
- Keep transport, domain and UI separate. UI crates must not perform remote I/O
  directly — they go through service crates that enforce policy.
- No fabricated telemetry, provider status or test results. A provider is only
  "connected" after authentication and a real supported operation are verified.
- Use official Codex (`codex app-server`) and Claude Code (`claude -p` stream-json)
  integrations. Never scrape, extract cookies or impersonate official clients.
- Never disable SSH host-key or TLS verification.
- This repo is meant to be shareable: never commit owner-specific values (Worker
  or Access names, client ids, IPs, tailnet names, server accounts, host-key
  fingerprints). They belong in the ignored `site.json` (`nexus_core::site`,
  `docs/site.example.json`) or in the private NexusWindows repo's docs.
- Credentials go in the Secret Service (KWallet / GNOME Keyring) through the
  `keyring` crate, never in files or git. Never commit SSH private keys,
  passwords or certificates; SSH test keys are generated at test time.
- `docs/OTP.md` must stay byte-identical to the iOS and Windows copies, and the
  OTP tests must keep the same RFC 6238 reference vectors.
- Never force-push, reset, delete branches or discard user changes automatically.

## Git and releases
- Repo: private `ljcatherine/NexusNix`, branch `main`. Commit frequently in
  focused commits and push.
- Build and test locally with `nix build` (runs the workspace tests) or
  `nix develop` + `cargo test --workspace`. Do not use GitHub Actions or
  Codemagic. Version follows the workspace `Cargo.toml` (same line as Windows);
  never change major/minor without owner approval. No Linux GitHub Releases yet.
- `reference/` holds a read-only clone of the iOS repo and is git-ignored.
