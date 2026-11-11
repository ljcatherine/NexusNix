# Nexus Desktop security model

## Hosts and default policies

| Host | Default policy | Why |
|---|---|---|
| `debian` (the site's `debian_user`; runs nexus-gateway, agent-orchestrator, workspace-agent, Minecraft panel, cloudflared) | **ReadOnly — immutable in code** | Owner's absolute rule. Cannot be loosened from settings; only a per-action `ApprovedEscalation` (single-use, exact operation, logged) can authorize a write. |
| `nixos` (owner desktop, the site's `nixos_user`) | ReadOnly until configured | Write must be granted explicitly per capability. Not granted just because it isn't Debian. |
| `local` (this Windows PC) | Per-workspace grants; new workspaces start with Read + Propose | Agent mode requires an explicit Write/Execute grant on the workspace. |
| other SSH hosts | ReadOnly until configured | Same as NixOS. |
| `ps5` (PS5LM Plus inference) | Inference only | Load/unload/install not exposed unless an authenticated controller supports it and a grant exists. |

## Capabilities

`Read`, `ListDirectory`, `WriteFile`, `DeleteFile`, `ExecuteCatalogCommand`,
`ExecuteArbitraryCommand`, `InteractiveShell`, `ServiceControl`, `GitRead`,
`GitWrite`, `DebugAttach`, `GatewayMutation`, `ModelControl`.

`PolicyEngine::authorize(Operation) -> Result<Grant, Denial>` is the single gate.
`Grant` is a non-cloneable token type with a private constructor; transport
functions that perform remote I/O require a `Grant` argument of the matching
kind, so the type system prevents calling them without a policy decision.

## Debian enforcement layers

1. **Policy engine** (`nexus-security::policy`): any capability other than read,
   list, catalog command and git-read is denied for `debian`. The Debian policy
   is constructed from a constant and the settings loader ignores any stored
   override for it.
2. **Command catalog** (`nexus-security::catalog`): Debian commands come only from
   a fixed list of read-only programs with fixed argument templates. Parameters
   (unit names, line counts, paths) are validated against strict patterns and
   passed as single-quoted POSIX words — never as shell fragments. There is no
   free-text shell for Debian.
3. **SFTP gate**: the SFTP session wrapper exposes only `read_dir`, `metadata`,
   `read` for read-only grants. Write/rename/remove/mkdir/setstat methods are not
   compiled into the read-only handle type.
4. **Gateway route classifier** (`nexus-security::gateway`): every gateway call
   is classified. Because the gateway runs on Debian, routes that persist state
   (`PUT/DELETE /v1/conversations/*`, `POST /v1/nexus/agent-runs*`,
   `POST /v1/nexus/models/*/load`, `/unload`, workspace `tasks`, patch/command
   review/execute) are `GatewayMutation` and denied. Unknown routes are denied.
5. **Workspaces**: Debian workspaces mount read-only; edits go to a local shadow
   workspace recording source path + SHA-256. Patches are exported, never applied
   remotely.
6. **Agents**: tool executors receive the workspace policy, not raw transports.
   Prompt content can never change policy; there is no tool that edits policy.
7. **Git**: Debian Git is limited to read-only subcommands via the catalog
   (`git -C <validated path> status --porcelain`, `log`, `diff`) with
   `GIT_OPTIONAL_LOCKS=0` semantics (`--no-optional-locks`) so Git does not write
   the index.
8. **Audit**: every authorize decision (allow and deny) is appended to a local
   JSONL audit log with a timestamp, host, capability, operation summary, and
   outcome. Secrets are never logged.

## Other controls
- SSH: strict host-key pinning per endpoint authority; first use requires
  explicit confirmation of the SHA256 fingerprint; changed keys are rejected and
  rotation requires typing the new fingerprint.
- TLS: default verification only (rustls / native roots). No bypass exists.
- Paths: workspace-relative paths are normalized; `..`, absolute paths, drive
  prefixes, UNC paths and symlink escapes are rejected.
- Context sharing: files matching sensitive patterns (`.env`, `*.pem`, `id_*`,
  `*.key`, credentials files) and ignore rules are excluded from AI context;
  the UI shows every file sent to a provider.
- Provider tokens are owned by the official CLIs (Codex, Claude Code); Nexus does
  not read them.

## Cloudflare relay path
- The relay route `GET /v1/ssh/{nixos|debian}` is classified `SshRelay` and authorized as a
  gateway read; the device's own policy (Debian: read-only) governs everything sent over it.
- The Access token goes only to the Worker in the WebSocket upgrade; it is never sent to the
  SSH target. Tokens are DPAPI-encrypted for the current Windows user.
- The relay's SSH host key is pinned per target (`relay:<Worker>/<target>`), with the same
  first-use confirmation and changed-key rejection as direct SSH.
- On the relay path the gateway authenticates to the target with its server-held key; Nexus
  Desktop sends no client key. Desktop never opens an interactive shell to Debian.

## Server-enforced catalog (`nexus-ro`)
- Optional per device (direct SSH only). The server's `authorized_keys` line forces
  `/usr/local/bin/nexus-ro`; the client sends `nexus-ro/1 <hex JSON CatalogCommand>`.
- The helper re-validates against its own `--root` list, resolves paths, opens files with
  `O_NOFOLLOW` and checks `/proc/self/fd`, runs fixed argv (no shell except the constant
  metrics script) under `timeout` with a cleared environment and Git config isolation.
- The helper refuses raw SFTP and other non-catalog requests with exit 126
  (`nexus_denied<TAB><tag>`). Desktop also refuses to open SFTP on a session
  configured for the server catalog. File listing and reads use catalog requests.
- It does not cover the Cloudflare relay (the gateway's own key). See proposal 0001.

## Bypass mode (owner-requested)
- Per local workspace, typed confirmation; never available for Host or Gateway targets.
- Codex: `danger-full-access` + `approvalPolicy: never`. Claude Code: `bypassPermissions` with
  deny rules for remote-shell/file-copy tools (deny rules still apply in bypass mode).
- Every turn authorizes and audits WriteFile, DeleteFile, ExecuteArbitraryCommand,
  InteractiveShell and GitWrite for the workspace.
- The Debian rule is sent first in every prompt. This is a guardrail, not a technical
  boundary: a bypass agent has the owner's Windows rights and could use credentials stored on
  this PC. Server-side options that would make it a boundary (not applied; Debian changes):
  1. `command="…/nexus-readonly-catalog",restrict` on the Nexus Desktop key in
     the Debian account's `~/.ssh/authorized_keys`, so that key can only run catalog commands.
  2. An exec allowlist (catalog commands only, no pty/shell) for the `debian` target in the
     gateway SSH relay, so an Access token cannot open a Debian shell.
- Provider processes start without `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `GIT_SSH`,
  `GIT_SSH_COMMAND` or `GIT_ASKPASS`. The Windows OpenSSH agent service uses a fixed named
  pipe and is not affected; it was stopped on the owner's PC on 8 Nov 2026.
- Optional memory-only Cloudflare Access session (offered when enabling Bypass): no
  `access-session.bin` on disk. A same-account process could still read Nexus's memory.

## App lock (0.1.12)

Optional lock at launch and on minimise, unlocked with a 4-digit, 20-second TOTP
shown by the Nexus iOS app (`docs/OTP.md`). Attempt-limited and replay-protected.
It hides the UI from someone at an unlocked PC; it is not a boundary against
same-user programs (they can read Credential Manager or edit settings.json).

## Owner Debian write unlock (0.1.9, proposal 0001 Phase 3)
- Owner decision (8 Nov 2026): owner-only, timed unlock. `PolicyEngine::unlock_debian`
  requires the typed phrase `unlock debian`, lasts 30 minutes, is audited, and can be
  ended with `lock_debian`. While unlocked the owner (Origin::User) on a Debian host
  gets `DEBIAN_UNLOCKED` = write file, arbitrary command, interactive shell, Git write.
- Never for agents (any mode, Bypass included), never for `Target::Gateway`; delete and
  service control still need the single-use escalation. Tested in
  `debian_unlock_is_owner_only_timed_and_never_for_agents`.
- Write sessions are Windows OpenSSH `ssh`/`sftp` in an IDE terminal tab, direct
  LAN/Tailscale endpoints only, with the device's separate `writeKeyPath` key
  (passphrase required at generation, typed into OpenSSH, never stored by Nexus).
  OpenSSH verifies host keys itself (`StrictHostKeyChecking=ask`, user known_hosts),
  not against Nexus pins. Debian write terminals are killed when the unlock ends.
- Not covered: the Cloudflare relay (Desktop's Access identity is confined to
  `debian-ro` by Phase 2b) and a graphical SFTP transfer UI (the SFTP tab is OpenSSH's
  interactive `sftp`).
- Non-Debian hosts: the device editor switch "Allow me to open SSH and SFTP sessions"
  grants the same four capabilities to the owner only; agents keep read-only.
