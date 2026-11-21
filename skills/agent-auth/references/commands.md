---
created_on: 2026-11-21 07:00
last_modified: 2026-11-21 07:00
status: current
---

## Commands

- `agent-auth`: root command; prints help when no subcommand is given.
- `agent-auth provider`: provider command group.
- `agent-auth provider list`: list supported providers (`codex`, `claude`, `agy`), their default and supported methods, logout support, and whether each binary is on `PATH`.
- `agent-auth provider status [PROVIDER]`: inspect authentication status for one provider or all providers when `[PROVIDER]` is omitted.
- `agent-auth provider logout <PROVIDER>`: sign out of `<PROVIDER>` using its native logout command.
- `agent-auth session`: session command group for non-blocking sign-in.
- `agent-auth session start <PROVIDER>`: launch a detached per-session worker, wait for the provider auth URL (and optional user code), print the session snapshot, and exit immediately.
- `agent-auth session submit <SESSION_ID>`: submit user input (authorization code or callback URL) to the active session worker and wait for authentication to finish. When `expected_input.required` is `false` and no input is supplied, falls through to waiting.
- `agent-auth session wait <SESSION_ID>`: wait up to `--timeout` seconds for an active session to complete without pasting input. Returns exit `3` with the current snapshot if still pending.
- `agent-auth session status <SESSION_ID>`: inspect the current snapshot of an active session without blocking.
- `agent-auth session list`: list active sessions and reap stale sockets from exited workers.
- `agent-auth session cancel <SESSION_ID>`: cancel an active session, terminate its child process group, and remove its socket and metadata.
- `agent-auth completion`: shell completion command group.
- `agent-auth completion script <SHELL>`: print a completion script for `<SHELL>` (`bash`, `zsh`, `fish`, or `powershell`).
- `agent-auth skill`: print the offline Skills CLI install command and canonical skill URL identically in human and agent modes. Accepts no positional arguments or command-specific flags.
- `agent-auth help [COMMAND...]`: print help for any command path. `--help` and `-h` print help on every command; agent help starts with the skill alert.

## Global flags

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--json` | bool | false | Print machine-readable JSON envelopes (`schema_version: 1`) |
| `--runtime-dir` | path | unset; uses `AGENT_AUTH_RUNTIME_DIR`, `$XDG_RUNTIME_DIR/agent-auth` on Linux, or `/tmp/agent-auth-<uid>` | Override the private `0700` per-user runtime socket directory |
| `--version` | bool | false | Print raw `0.1.0` and newline |
| `--help`, `-h` | bool | false | Print help without side effects |

## Provider flags

| Flag | Type | Default | Commands | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--provider-bin` | path | unset; resolved from `PATH` | `provider status`, `provider logout`, `session start` | Explicit provider executable path (requires naming `[PROVIDER]` for `provider status`) |
| `--home` | path | unset; inherits native home | `provider status`, `provider logout`, `session start` | Override provider home directory (`HOME`, XDG vars, and `CODEX_HOME`) |
| `--timeout` | uint64 | 15 | `provider status`, `provider logout` | Timeout in seconds for status or logout |

## Session flags

| Flag | Type | Default | Commands | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--method` | string | auto | `session start` | Auth method (`auto`, `device`, or `oauth`); `auto` selects `device` when supported |
| `--ttl` | uint64 | 900 | `session start` | Maximum background session lifetime in seconds |
| `--start-timeout` | uint64 | 20 | `session start` | Startup timeout in seconds while waiting for the auth URL |
| `--console` | bool | false | `session start` | Use Anthropic Console API billing (`claude` only) |
| `--sso` | bool | false | `session start` | Use SSO sign-in (`claude` only) |
| `--email` | string | unset | `session start` | Prefill email address on the login page (`claude` only) |
| `--input` | string | unset | `session submit` | Authorization code or callback URL (conflicts with `--input-stdin`) |
| `--input-stdin` | bool | false | `session submit` | Read authorization code or callback URL from stdin (conflicts with `--input`) |
| `--timeout` | uint64 | 120 | `session submit` | Completion wait timeout in seconds |
| `--timeout` | uint64 | 300 | `session wait` | Wait timeout in seconds |

## Completion flags

- `--no-descriptions` (`bool`, default `false`): omit descriptions from generated completion scripts on `agent-auth completion script <SHELL>`.

## Environment variables

- `AGENT`: `1`, `true`, or `yes` (case-insensitive) enables compact `key:value` agent output and the agent help skill alert.
- `AGENT_AUTH_RUNTIME_DIR`: overrides the default per-user runtime directory for Unix domain sockets (`0700`).
