# Build and release (Linux / NixOS)

## Toolchain
- Nix with flakes. `flake.nix` pins `nixos-26.05`, whose Rust is 1.95; the
  workspace `rust-version` is 1.95 (the Windows repo says 1.99, its MSVC
  toolchain; nothing here needs newer than 1.95).
- No system libraries at build time beyond a C compiler (`ring`, bundled SQLite).
  At run time winit/wgpu `dlopen` libxkbcommon, Vulkan/libGL, Wayland and X11
  libraries; the package wrapper and the dev shell set `LD_LIBRARY_PATH`.

## Commands
```bash
nix build                      # result/bin/nexus-desktop (+ nexus-ro); runs cargo test --workspace first
nix run                        # build and start
nix develop                    # dev shell
cargo test --workspace         # inside nix develop
cargo test -p nexus-access -- --ignored   # Secret Service round trip (needs a desktop session)
nix flake check
```

## Versioning and releases
- Workspace version in `Cargo.toml`, the same line as NexusWindows; bump the
  patch per release; major/minor only with owner approval.
- No Linux release artefacts or GitHub Releases yet (Windows uses
  `scripts/release.ps1` in NexusWindows). No GitHub Actions or Codemagic.

## Visual QA
`NEXUS_SCREENSHOT=out.png NEXUS_SCREEN=ide NEXUS_OPEN_DIR=<folder> NEXUS_OPEN_FILE=<rel> NEXUS_TERMINAL=1 NEXUS_FRAMES=400 NexusDesktop.exe`
(Linux: `… nexus-desktop`) renders, saves a PNG of its own framebuffer and exits.

## Data locations
- `~/.config/nexus-desktop/` (`$XDG_CONFIG_HOME`): `settings.json`, `sessions.db`, `audit.jsonl`, `known_hosts.json`
- `~/.local/share/nexus-desktop/` (`$XDG_DATA_HOME`): `recovery/`, `shadows/`, `access-session.bin`, `last-crash.txt`
- Both directories are created 0700.
- Secrets: Secret Service, service `NexusDesktop` (KWallet / GNOME Keyring).

## nexus-ro (Linux server helper)
- `nix build` also builds `result/bin/nexus-ro` (glibc, dynamically linked to the
  Nix store, so for this machine only). For a static helper to copy to a server use
  `cargo build -p nexus-ro --release --target x86_64-unknown-linux-musl` with a
  musl-capable toolchain (linked with `rust-lld`, `.cargo/config.toml`).
- Test in a disposable Linux environment, never on Debian:
  `sh scripts/test-nexus-ro.sh <copy of the binary in /tmp>`.
- For real SSH acceptance, run `sh scripts/test-nexus-ro-sshd.sh <helper>`
  as root inside a disposable Ubuntu container with `openssh-server` and
  `openssh-sftp-server` installed. Mount the source and helper read-only, use
  `--network none`, and publish no ports. The script generates temporary keys
  and pins the fixture host key. It checks catalog reads and verifies that
  the restricted key cannot start SFTP or download a file through it.
