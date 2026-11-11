# Nexus Desktop implementation plan

Evidence base: inspection of `ljcatherine/Nexus@2263620` (SwiftUI app, Go gateway,
Go workspace-agent, Python orchestrator, Cloudflare Worker, PS5LM Plus integration)
on 2026-11-07, plus the locally installed official agent CLIs:
`codex-cli 0.162.1` (logged in with ChatGPT; `codex app-server` JSON-RPC) and
`Claude Code 2.1.317` (`claude -p --output-format stream-json`).

## Key findings that shape the design
1. The Nexus gateway, orchestrator and workspace-agent all **run on Debian**. Any
   gateway call that persists state (conversations, agent runs, model-switch
   journal, patch/command review) is a Debian write, so these are denied by
   default in Nexus Desktop (see SECURITY-MODEL.md). Read routes are reused.
2. The iOS app's telemetry is a fixed read-only `/proc` script over SSH. Its
   output format is ported verbatim so both apps read identical data.
3. The iOS AI never receives shell tools. Desktop agents get local workspace
   tools only under explicit grants; Debian access stays read-only.
4. Codex exposes an official stdio JSON-RPC protocol (`initialize`,
   `account/read`, `thread/start`, `turn/start`, approval server-requests,
   `item/*` streaming notifications) with `sandbox` modes
   `read-only | workspace-write`. Claude Code exposes headless stream-json with
   `--permission-mode` (`plan`, `default`, `acceptEdits`) and `--resume`.
   These map directly onto Ask / Plan / Agent modes.

## Workspace layout (crates/)
| Crate | Responsibility |
|---|---|
| `nexus-core` | Shared domain types: hosts, devices, endpoints, ids |
| `nexus-security` | Policy engine, Debian immutability, command catalog, gateway route classifier, path validation, host-key pins, audit log |
| `nexus-telemetry` | Metrics script + parser, history, rates |
| `nexus-workspaces` | Local workspaces, ignore rules, file tree, search, shadow workspaces |
| `nexus-git` | Git CLI wrapper with guarded operations |
| `nexus-context` | Context selection, sensitive-file and secret detection, compaction records |
| `nexus-providers` | `AgentProvider` trait; Codex app-server, Claude Code, OpenAI-compatible (PS5LM/APIs) adapters |
| `nexus-agents` | Modes, sessions, tool-permission mediation, durable task state (SQLite), diffs/hunks |
| `nexus-ssh` | russh client gated by `Grant`s, catalog exec, read-only SFTP handle |
| `nexus-terminal` | ConPTY local terminals + alacritty_terminal grid |
| `nexus-ide` | Editor buffer, highlighting, tabs, find |
| `nexus-ui` | Midnight Liquid Glass tokens and widgets |
| `nexus-app` | eframe entry point, navigation, panels |

LSP (`nexus-lsp`) and DAP (`nexus-debug`) are added in their phases.

## Milestones
- **M1 Foundation**: docs, workspace, security core with tests, telemetry parser,
  design system, app shell with navigation (Dashboard/Devices/IDE/Infrastructure/Settings).
- **M2 IDE foundation**: explorer, tabs, editor widget, highlighting, search,
  terminal, git panel.
- **M3 Providers**: Codex + Claude Code adapters with real verification, AI panel,
  modes, session persistence.
- **M4 Cursor-style**: inline edit, diff review with hunk accept/reject, context
  attachments & visibility, compaction, agent history, audit view.
- **M5 Infrastructure**: SSH (pinned), catalog console, telemetry dashboard, SFTP
  read-only browser, services/logs, PS5 status, Minecraft launcher, Access OAuth.
- **M6 Polish/packaging**: Mica, animations, accessibility, installer (Inno Setup
  or WiX), portable zip, release script.
- **M7 Validation**: policy attack tests, provider acceptance, read-only live
  checks with owner approval.
