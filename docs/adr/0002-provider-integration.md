# ADR 0002: Subscription-backed providers through official CLIs

Date: 2026-11-07 · Status: accepted

## Decision
- **Codex** is driven through `codex app-server` (stdio JSON-RPC, schema saved in
  `docs/protocols/`). Authentication stays inside the Codex CLI (`codex login` with
  ChatGPT). Nexus calls `account/read` and `model/list` to verify, then
  `thread/start|resume` + `turn/start`, and answers `item/commandExecution/requestApproval`
  and `item/fileChange/requestApproval` server requests.
- **Claude Code** is driven through `claude -p --output-format stream-json --verbose
  --include-partial-messages` with the prompt on stdin. Authentication stays inside the
  CLI (`claude auth login`). Verification = `claude auth status` + one minimal headless
  turn.
- Nexus never reads, copies or forwards either CLI's credentials and does not
  impersonate either client (`clientInfo.name = nexus_desktop`).

## Mode mapping (enforced by each provider's own sandbox/permission system)
| Mode | Codex | Claude Code |
|---|---|---|
| Ask | `sandbox: read-only`, `approvalPolicy: never` | `--permission-mode dontAsk`, read tools only, Edit/Write/Bash disallowed |
| Plan | same as Ask + planning preamble | `--permission-mode plan` |
| Agent | `workspace-write` only if the workspace grants agent writes, else `read-only`; `approvalPolicy: untrusted` → commands routed to Nexus, auto-declined unless the workspace grants agent command execution | `acceptEdits` if writes granted else `dontAsk` with edit tools disallowed; `Bash` allowed only if commands granted |

## Review model
Agent-mode providers write files themselves inside their sandbox. Nexus snapshots the
workspace before the turn and presents the difference as a change set; rejecting a
hunk restores the pre-turn text. This is "review after apply with reliable rollback",
not "approve before write" — stated in the UI.

## Consequences
- Usage counts against the user's ChatGPT/Claude plans; no API billing.
- Provider context cannot be transferred between providers; on a switch Nexus sends its
  task memory and recent messages and says so.
- Native subagents/compaction are the providers' own; Nexus logs the events it sees.
