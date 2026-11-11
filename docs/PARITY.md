# Feature-parity matrix: Nexus iOS → Nexus Desktop

Source of truth: `ljcatherine/Nexus` at commit `2263620` (cloned read-only into
`reference/Nexus`, inspected 2026-11-07). The iOS app was inspected directly, so
this matrix does not rely only on the older handoff docs.

Status key: **Done** = implemented and tested in Nexus Desktop · **Partial** = some
of it implemented, gaps listed · **Planned** = not started · **Blocked (RO)** =
unavailable because it would write to Debian (read-only policy).

| # | iOS capability (evidence) | Windows equivalent | Desktop status |
|---|---|---|---|
| 1 | Device profiles with ordered LAN/Tailscale/Cloudflare endpoints (`NexusCore/Device.swift`) | Same JSON model, `nexus-core::Device`; import from iOS device JSON | Done: model, iOS JSON import, device editor list (endpoint editing form planned) |
| 2 | Ed25519 key import/generation, Keychain storage (`NexusSSH/SSHKeyGenerator`, `KeychainStore`) | Windows Credential Manager via `keyring` | Done: per-device key path, in-app Ed25519 generation, passphrase in Credential Manager; separate Debian write key (0.1.9) |
| 3 | First-use host-key confirmation, changed-key rejection, guarded rotation (`HostKeyVerifier`) | `nexus-security::HostKeyStore` (pin per endpoint authority, typed-fingerprint rotation) | Done: pinning, first-use dialog, changed-key abort (mock-server tested) |
| 4 | Interactive PTY terminal tabs, tmux, search (`TerminalSession`, SwiftTerm) | Local PowerShell/cmd/WSL via ConPTY; SSH PTY for authorized writable hosts | Partial: local PowerShell/cmd/WSL/Git Bash; SSH terminal (Windows OpenSSH) for owner-allowed hosts and unlocked Debian (0.1.9); tmux/search not yet |
| 5 | Debian terminal | **Restricted observational console** (fixed command catalog) because Debian is read-only | Done: catalog + enforcement + tests |
| 6 | Host metrics: CPU, memory, disk, load, uptime, network, NVIDIA (`HostMetricsCommand`) | Same read-only script and parser ported to Rust (`nexus-telemetry`) | Done: parser, rates, dashboard; mock-server tested; live host not yet |
| 7 | Freshness-aware history and rates (`HostMonitorState`, `DashboardHistoryCharts`) | `nexus-telemetry::History` and dashboard sparklines | Partial: history + rates, charts basic |
| 8 | Low-resource notifications | Windows toast | Partial: in-app alert when CPU, memory or disk is at 90% or more (0.1.9); Windows OS toast not yet |
| 9 | SFTP browse/preview/edit/transfer (`SFTPTransport`, `FilesView`) | SFTP browser; Debian read-only (list/read/download only) | Partial: read-only browse/read via catalog; interactive OpenSSH sftp tab for owner-allowed hosts and unlocked Debian (0.1.9); graphical transfers not yet |
| 10 | systemd service list and logs (`ServiceTransport`) | Catalog read-only commands (`systemctl list-units`, `journalctl -u … -n`) | Done: services list, status, logs (read-only) |
| 11 | systemd start/stop/restart | Allowed only on hosts whose policy grants service control | **Blocked (RO)** for agents; owner can use the SSH terminal while Debian writes are unlocked (0.1.9) |
| 12 | Guarded NixOS dry-build/switch | NixOS policy `ServiceControl` + typed confirmation | Partial: dry-build and typed-confirmation switch open an SSH terminal on NixOS hosts with owner sessions allowed (0.1.9) |
| 13 | Network/DNS/TCP diagnostics (`NetworkDiagnosticsView`) | Local Windows probes (DNS, TCP connect) | Partial: DNS lookup and TCP connect probes from this PC per endpoint (0.1.9) |
| 14 | Command recipes with confirmation (`CommandRecipe`) | Recipes run only on hosts allowing arbitrary commands; Debian limited to catalog | Planned |
| 15 | Minecraft panel launcher via Worker (`MinecraftPanelView`) | Open Worker URL in default browser (Access + panel login stay) | Done (with read-only warning) + status via catalog |
| 16 | Cloudflare Access OAuth (PKCE, `NativeOIDCSignIn`) | System-browser PKCE via the Worker redirect and a per-user URL scheme; DPAPI-encrypted tokens | Done (mock-tested; live sign-in pending) |
| 17 | PS5LM Plus chat via gateway, streaming (`AIViews`, `AI.swift`) | `nexus-providers::OpenAiCompatible` (direct LAN or gateway) | Partial: direct LAN OpenAI-compatible chat; gateway path planned |
| 18 | PS5 model list/status (`PS5NexusAPI`) | Read-only routes `GET /v1/nexus/models[/status]` | Partial: LAN `/models` listing; gateway routes classified, client planned |
| 19 | PS5 model load/unload (`PS5NexusModelActivation`) | Mutates Debian gateway journal → requires explicit grant | **Blocked (RO)** by default |
| 20 | Gateway conversation history PUT/DELETE | Writes to Debian | **Blocked (RO)**; local SQLite history instead |
| 21 | Orchestrator agent runs / patch / command review (`PS5Nexus*ReviewView`) | Starting runs writes orchestrator state on Debian | **Blocked (RO)** by default; local agents replace it |
| 22 | Web research `/v1/search`, `/v1/research` | Allowed read (no Debian persistence documented) | Planned |
| 23 | AI attachments (text/CSV/XLSX/PDF/images), secret warning (`AISensitiveContent`) | Context attachments + `nexus-context::secrets` scanner | Partial: file/selection/terminal/problems/git-diff context + secret scan; images (Claude Code, Codex) and PDFs (Claude Code) by picker or drop (0.1.10); CSV/XLSX parsing not yet |
| 24 | Context meter, 85% compaction (`AI.swift`) | `nexus-agents::compaction` with visible summaries | Partial: usage meter, compaction records, task memory |
| 25 | App lock (biometrics) | One-time passcode from the iOS app (replaces Windows Hello) | Partial: 4-digit/20 s TOTP lock on launch and minimise, paired with iOS Services → One Time Passcode (desktop 0.1.12); not yet exercised end to end on a phone |
| 26 | Demo mode | Not ported (desktop uses real or clearly-unavailable states) | Not planned |

## New desktop-only capabilities (IDE)

| Capability | Status |
|---|---|
| Workspace open/explorer honoring .gitignore/.cursorignore/.nexusignore | Done |
| Multi-tab editor, syntax highlighting, undo/redo, find, save, dirty tracking, recovery | Done (folding planned) |
| Workspace search/replace with regex | Done |
| Git status/diff/stage/commit, guarded destructive ops | Done (worktree add, blame, log in API; UI for blame/history planned) |
| Codex provider via official `codex app-server` (ChatGPT login) | Done: verified live (account, models, Ask turn) |
| Claude Code provider via official `claude -p` stream-json | Done: live Bypass/Ask turns verified (0.1.5) |
| Ask / Plan / Agent modes mapped to provider sandbox/permission flags | Done (provider-enforced, mapping tested) |
| Reviewable diffs with hunk accept/reject | Done: per-hunk/file/all accept-reject, revert, patch export |
| Debian shadow workspace with hash manifest + patch export | Done: core + tests |
| LSP, DAP, minimap, multi-cursor | Planned |
