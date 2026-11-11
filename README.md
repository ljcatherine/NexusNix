<div align="center">

<img src="crates/nexus-app/assets/brand/nexus-icon.svg" width="112" alt="Nexus Orbit N icon">

# Nexus Desktop

**An AI IDE and home-lab control room for Linux and NixOS, in Rust.**<br>
The Linux port of [Nexus Desktop for Windows](https://github.com/ljcatherine/NexusWindows), companion to the [Nexus iPhone app](https://github.com/ljcatherine/Nexus), in the Midnight Liquid Glass design.

[![NixOS 26.05](https://img.shields.io/badge/NixOS-26.05%20flake-0B1430?style=flat-square&logo=nixos&logoColor=9CBCFF&labelColor=070C18)](flake.nix)
[![Rust](https://img.shields.io/badge/Rust-1.95%2B-0B1430?style=flat-square&logo=rust&logoColor=F1C07E&labelColor=070C18)](rust-toolchain.toml)
[![egui](https://img.shields.io/badge/UI-egui%200.37-0B1430?style=flat-square&labelColor=070C18)](crates/nexus-ui)
[![AI](https://img.shields.io/badge/AI-Codex%20%C2%B7%20Claude%20Code-0B1430?style=flat-square&logo=anthropic&logoColor=C9ADFF&labelColor=070C18)](#ai-providers)
[![Private](https://img.shields.io/badge/repo-private-0B1430?style=flat-square&labelColor=070C18)](#)

[**Install**](#install) ·
[Linux parity](docs/PARITY-LINUX.md) ·
[Status](docs/STATUS.md) ·
[Security model](docs/SECURITY-MODEL.md) ·
[iPhone parity](docs/PARITY.md) ·
[Build &amp; release](docs/BUILD-AND-RELEASE.md)

</div>

---

## What it does

<table>
<tr>
<td width="50%" valign="top">

### IDE
Workspace explorer that honours `.gitignore`, `.cursorignore` and `.nexusignore`.
Multi-tab editor with syntax highlighting for 15+ languages, multi-cursor,
find/replace, minimap, split view and a Git gutter. Quick open, command palette,
workspace search, source control, build/test tasks with a Problems list, and
terminals for your login shell, Bash, Zsh, Fish and PowerShell.

</td>
<td width="50%" valign="top">

### AI
**Codex** (official `codex app-server`) and **Claude Code** (official CLI) in
Ask, Plan, Agent and Bypass modes, plus OpenAI-compatible APIs and PS5LM Plus.
Visible context sharing, secret detection, image and PDF attachments,
command approvals, agent edits reviewed hunk by hunk, Ctrl+K inline edits and
resumable sessions with task memory.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Infrastructure
Dashboard with live telemetry and low-resource alerts, devices with pinned SSH
host keys, services, logs, processes and network probes. SSH and SFTP terminals
for hosts you allow, NixOS dry-build and switch, Debian shadow workspaces,
Minecraft and PS5LM status.

</td>
<td width="50%" valign="top">

### Security
Every remote action goes through one policy engine in Rust. Debian is read-only
by default, enforced on the server by the `nexus-ro` helper. The owner can unlock
Debian writes for 30 minutes; agents never can. Optional app lock with a 4-digit
code from the iPhone app.

</td>
</tr>
</table>

## How the pieces fit

```mermaid
flowchart LR
    subgraph PC["Linux PC"]
        D["Nexus Desktop"]
        CX["Codex CLI"]
        CC["Claude Code CLI"]
    end
    P["Nexus iPhone app"]
    N["NixOS host"]
    subgraph DEB["Debian server"]
        RO["nexus-ro helper<br/>read-only catalog"]
        GW["Nexus gateway"]
    end
    CF["Cloudflare Access"]

    D -- "app-server / stream-json" --> CX & CC
    D -- "SSH, pinned host keys" --> N
    D -- "SSH forced command" --> RO
    D -- "relay" --> CF --> GW
    P -. "one-time passcode<br/>(offline, shared key)" .-> D
```

## Install

NixOS, from this private repo. Use a `git+https` URL so Nix fetches through
git's credential helper (run `gh auth login` and `gh auth setup-git` once);
plain `github:` URLs fail for private repos unless Nix has its own
`access-tokens` setting.

```bash
nix run git+https://github.com/ljcatherine/NexusNix
```

```nix
# flake.nix of your NixOS configuration
inputs.nexus-nix.url = "git+https://github.com/ljcatherine/NexusNix";
# …then in a NixOS module:
imports = [ inputs.nexus-nix.nixosModules.default ];
programs.nexus-desktop.enable = true;   # package, desktop entry, sign-in URL handler, portal
```

From a checkout:

```bash
nix build        # ./result/bin/nexus-desktop
nix run
nix develop      # Rust toolchain, OpenSSH, git and the runtime libraries
```

Nexus needs a Secret Service provider (KWallet on Plasma, or GNOME Keyring)
for API keys, SSH passphrases and the app-lock secret, and an XDG desktop portal
for file dialogs. It runs through XWayland by default so the app lock can see
minimising; `NEXUS_WAYLAND=1` selects native Wayland (see
[PARITY-LINUX](docs/PARITY-LINUX.md), P24).

## AI providers

| Provider | Setup | Billing |
|---|---|---|
| **OpenAI Codex** | Install the Codex CLI, run `codex login` | Your ChatGPT plan |
| **Claude Code** | Install Claude Code, run `claude auth login` (or Settings → AI providers → *Sign in…*) | Your Claude Pro/Max plan |
| **OpenAI-compatible** | Settings → AI providers → add an endpoint; keys go to the Secret Service (KWallet / GNOME Keyring) | The API's own billing |
| **PS5LM Plus** | Settings → AI providers → set its LAN URL | Local |

A provider only shows **Connected** after its sign-in and a real test turn both succeed.

## Build from source

> [!NOTE]
> Needs Nix with flakes. Outside Nix: Rust 1.95+, a C compiler, OpenSSH, git, and
> at run time libxkbcommon, Vulkan or libGL, Wayland and X11 libraries.

```bash
nix develop
cargo build --release -p nexus-app      # target/release/NexusDesktop
cargo test --workspace
cargo run -p nexus-app                  # debug run
```

`nix build` runs the whole workspace test suite inside the sandbox before
packaging. Builds are local; no CI.

The app icon is drawn as SVG in [`crates/nexus-app/assets/brand`](crates/nexus-app/assets/brand) and
rendered to `.png` by [`scripts/render-icons.sh`](scripts/render-icons.sh).

## Security

> [!IMPORTANT]
> The Debian server also runs the Nexus gateway, so it is read-only by default.
> That rule is enforced in the Rust backend ([`nexus-security`](crates/nexus-security))
> and on the server ([`nexus-ro`](crates/nexus-ro)), not only in the UI.
> AI agents never get write access to Debian in any mode.

The full model, including the owner's timed Debian unlock and the app lock, is in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) and [docs/OTP.md](docs/OTP.md).

## Project layout

<details>
<summary><b>Crates</b></summary>

| Crate | What it holds |
|---|---|
| [`nexus-app`](crates/nexus-app) | The application |
| [`nexus-ui`](crates/nexus-ui) | Midnight Liquid Glass design system |
| [`nexus-ide`](crates/nexus-ide) | Editor engine and widget |
| [`nexus-terminal`](crates/nexus-terminal) | Unix PTY terminals on `alacritty_terminal` |
| [`nexus-providers`](crates/nexus-providers) | Codex, Claude Code and OpenAI-compatible adapters |
| [`nexus-agents`](crates/nexus-agents) | Sessions (SQLite), snapshots, task memory |
| [`nexus-context`](crates/nexus-context) | Context sharing rules, secret scan, project instructions |
| [`nexus-workspaces`](crates/nexus-workspaces) | Workspaces, search, shadow workspaces, change sets |
| [`nexus-git`](crates/nexus-git) | Guarded Git CLI wrapper |
| [`nexus-security`](crates/nexus-security) | Policy engine, Debian rules, command catalog, audit, host keys, app-lock passcode |
| [`nexus-ro`](crates/nexus-ro) | SSH forced-command helper that enforces the read-only catalog on the server |
| [`nexus-ssh`](crates/nexus-ssh) | Grant-gated SSH and read-only SFTP |
| [`nexus-access`](crates/nexus-access) | Cloudflare Access sign-in for the gateway relay |
| [`nexus-telemetry`](crates/nexus-telemetry) | Metrics parser and history (ported from iOS) |
| [`nexus-core`](crates/nexus-core) | Device model (iOS-compatible JSON), Linux platform integration (XDG paths, xdg-open, file manager, terminal emulator) |

</details>

<details>
<summary><b>Docs</b></summary>

| Doc | About |
|---|---|
| [STATUS](docs/STATUS.md) | What works, what is verified, newest first |
| [PARITY-LINUX](docs/PARITY-LINUX.md) | Every Windows feature mapped to its Linux implementation and test, with the gaps |
| [PARITY](docs/PARITY.md) | Feature-by-feature comparison with the iPhone app |
| [SECURITY-MODEL](docs/SECURITY-MODEL.md) | Threat model and enforcement |
| [OTP](docs/OTP.md) | App-lock passcode spec shared with iOS |
| [PLAN](docs/PLAN.md) · [adr/](docs/adr) | Design decisions |
| [log/](docs/log) | Dated development log |

</details>

<div align="center">
<sub>Nexus Desktop for Linux · private · built locally with Nix</sub>
</div>
