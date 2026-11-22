`agent-auth` brokers non-blocking OAuth sign-in for AI coding agent harnesses (`codex`, `claude`, and `agy`). It turns blocking CLI login prompts into a split-phase start-and-complete workflow with uniform output across providers and never launches a local browser automatically.

# What It Does

- **Non-blocking sign-in:** Starts authentication, returns the authorization URL (and one-time user code when supported), and exits immediately so agent tool calls never hang.
- **No automatic browser launch:** Suppresses browser openers and uses headless native login paths so authentication works safely on local workstations, SSH hosts, and containers.
- **Consistent interface:** Uses the same commands, session lifecycle, exit codes, and structured output across `codex`, `claude`, and `agy`.
- **Device-code first:** Defaults to device-code authentication whenever a provider supports it (`codex`), while also supporting interactive OAuth code or callback-URL submission.
- **Live status, usage, and cleanup:** Reports provider login status and normalized rate-limit usage quotas across all providers, auto-expires abandoned sessions after their TTL, and terminates child process groups cleanly on completion or cancellation.

# How It Works

- Check whether a provider is already signed in with `agent-auth provider status`, or inspect normalized rate-limit usage across all providers with `agent-auth provider usage`.
- Start a login session with `agent-auth provider login <name>`; the command prints the `session_id`, `auth_url`, optional `user_code`, and expected user action, then exits immediately.
- Open the printed URL in your browser and complete sign-in.
- Finish authentication with `agent-auth session wait <id>` (for device-code or automatic local callbacks) or `agent-auth session submit <id> --input-stdin` (for providers that return a code or landing URL).

# How it Really Works

- `agent-auth provider login` spawns a short-lived detached worker process for that single session and creates a private `0600` Unix domain socket and metadata file in a `0700` per-user runtime directory (`$AGENT_AUTH_RUNTIME_DIR`, `$XDG_RUNTIME_DIR/agent-auth` on Linux, or `/tmp/agent-auth-<uid>`). No permanent system daemon is installed.
- Credentials remain owned by each provider's native CLI and storage; `agent-auth` never writes authorization codes, callback URLs, or OAuth tokens to disk or logs.
- For `codex`, `agent-auth` speaks JSON-RPC to `codex app-server --stdio` (`chatgptDeviceCode` by default, or `chatgpt` with `--method oauth`, strictly validating loopback `http://127.0.0.1:<port>/auth/callback` URLs before replaying them locally, and reading rate limits via `account/rateLimits/read`).
- For `claude`, `agent-auth` runs `claude auth login` with a no-op `BROWSER` opener so no browser opens, captures the manual OAuth URL, and delivers the pasted code over stdin; `provider status` reads `claude auth status`, and `provider usage` queries `get_usage` (`skip_behaviors: true`) over Claude's `stream-json` control channel.
- For `agy` (also accepted as `antigravity`), `agent-auth` runs `agy acp --login` with stdin held open until the code or callback URL is submitted; `provider status` probes `agy -p /usage --output-format json` inside a browser-blocked environment, aborts immediately if `agy` prompts for login, and returns parsed quota buckets when authenticated.
- Every session enforces a hard TTL (default 900 seconds). When a session completes, is cancelled, or expires, the worker terminates its child process group and removes its socket, metadata, and temporary shims.
- Standard output carries results and standard error carries diagnostics. Set `AGENT=1` (or `true`/`yes`) for compact `key:value` lines, or pass `--json` for versioned JSON envelopes (`schema_version: 1`). Home paths are folded to `~` when printed.
- Exit codes are `0` for success, `1` for operational or provider failures, `2` for invalid arguments, `3` when `session wait` times out while login is still pending, and `130` for cancellation.

# Installation

Download the prebuilt archive for your platform from the [latest release](https://github.com/alexgorbatchev/agent-auth-cli/releases/latest), replacing `X.X.X` with the version shown on that page.

```sh
# macOS (Apple Silicon)
curl -sSL https://github.com/alexgorbatchev/agent-auth-cli/releases/latest/download/agent-auth_X.X.X_darwin_arm64.tar.gz \
  | tar -xz -C ~/.local/bin agent-auth
agent-auth --version
```

# Setup

- [Codex CLI](https://developers.openai.com/codex/cli) (`codex` on `PATH`) — required for `codex` provider status, logout, device-code login, and OAuth login.
- [Claude Code](https://code.claude.com/docs/en/quickstart) (`claude` on `PATH`) — required for `claude` provider status, logout, and OAuth login.
- [Antigravity CLI](https://antigravity.google/docs/cli/reference) (`agy` on `PATH`) — required for `agy` / `antigravity` provider status and ACP OAuth login.

# Quick Start

```sh
# Check sign-in status and rate-limit usage across all providers
agent-auth provider status
agent-auth provider usage

# Start a non-blocking Codex device-code login
agent-auth provider login codex

# After approving in your browser, wait for completion
agent-auth session wait <id>

# Start a Claude login and submit the code returned on the callback page
agent-auth provider login claude
agent-auth session submit <id> --input '<code>#<state>'
```

Sample Output:

```text
[PENDING] Session a1b2c3d4e5f60718 (codex, device): awaiting_input
  Auth URL:  https://auth.openai.com/codex/device
  User Code: ABCD-EFGH
  Next:      Open the URL, sign in, and enter the one-time code. Then call `agent-auth session wait <id>`.
  Expires:   2026-11-21T15:15:00Z
```

# Options & Flags

`agent-auth`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--json` | | `false` | Print machine-readable JSON output |
| `--runtime-dir <dir>` | | `$AGENT_AUTH_RUNTIME_DIR` or per-user runtime dir | Override the per-user runtime socket directory |
| `--version` | | `false` | Print the raw version string |
| `--help` | `-h` | `false` | Print command help |

`agent-auth provider status [name]`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--provider-bin <path>` | | lookup on `PATH` | Override the provider CLI executable path |
| `--home <dir>` | | native home | Override the provider home directory |
| `--timeout <sec>` | | `15` | Status check timeout in seconds |

`agent-auth provider usage [name]`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--provider-bin <path>` | | lookup on `PATH` | Override the provider CLI executable path |
| `--home <dir>` | | native home | Override the provider home directory |
| `--timeout <sec>` | | `15` | Usage fetch timeout in seconds |

`agent-auth provider login <name>`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--method <name>` | | `auto` | Authentication method (`auto`, `device`, or `oauth`) |
| `--ttl <sec>` | | `900` | Maximum session lifetime in seconds |
| `--start-timeout <sec>` | | `20` | Startup timeout in seconds while waiting for the auth URL |
| `--provider-bin <path>` | | lookup on `PATH` | Override the provider CLI executable path |
| `--home <dir>` | | native home | Override the provider home directory |
| `--console` | | `false` | Use Anthropic Console API billing (`claude` only) |
| `--sso` | | `false` | Use SSO sign-in (`claude` only) |
| `--email <addr>` | | unset | Prefill email address on the login page (`claude` only) |

`agent-auth provider logout <name>`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--provider-bin <path>` | | lookup on `PATH` | Override the provider CLI executable path |
| `--home <dir>` | | native home | Override the provider home directory |
| `--timeout <sec>` | | `15` | Logout timeout in seconds |

`agent-auth session submit <id>`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--input <text>` | | unset | Authorization code or callback URL from the user |
| `--input-stdin` | | `false` | Read authorization code or callback URL from stdin |
| `--timeout <sec>` | | `120` | Completion wait timeout in seconds |

`agent-auth session wait <id>`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--timeout <sec>` | | `300` | Wait timeout in seconds |

`agent-auth completion script <shell>`

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--no-descriptions` | | `false` | Omit completion descriptions |

# License

[MIT](LICENSE).
