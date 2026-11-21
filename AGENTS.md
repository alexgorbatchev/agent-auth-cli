---
created_on: 2026-11-21 07:00
last_modified: 2026-11-21 07:00
status: current
---

# agent-auth-cli

Rust CLI producing the `agent-auth` binary for non-blocking, split-phase OAuth sign-in across AI coding agent harnesses (`codex`, `claude`, `agy`).

## Commands

- Setup: `just setup`
- Build release binary: `just build` (writes `bin/agent-auth`)
- Run in human mode: `just run provider list`
- Run in agent mode: `just run-ai provider list`
- Format: `just fmt`; check formatting: `just fmt-check`
- Lint: `just lint` (`cargo clippy --all-targets --locked -- -D warnings`)
- Test: `just test`; affected tests only: `just test-affected`
- Coverage: `just coverage` (enforces >=90% line and function coverage)
- Full read-only validation: `just check`

Development requires Rust 1.89+, `just`, `cargo-llvm-cov`, and the `llvm-tools-preview` component.

## Contracts

- **Skill synchronization**: Update `skills/agent-auth/SKILL.md` and `skills/agent-auth/references/` in the same change as any command, argument, option, default, environment variable, output format, or side-effect change. Keep `tests/skill.rs` passing against the live command tree and update `last_modified` metadata.
- **No automatic browser opening**: Never invoke native login subcommands that launch `/usr/bin/open` directly (such as `codex login`). Always use headless native protocols (`codex app-server --stdio`, `agy acp --login`) and run every provider child inside `Sandbox` (`BROWSER`, `NO_BROWSER=1`, `PATH` shims for `open`/`xdg-open`/etc.). Prefer device-code authentication as the default method whenever a provider supports it.
- **Testing and coverage**: Any change to executable behavior must include matching behavioral test updates and satisfy >=90% line and function coverage across non-test source files. Use offline fake provider executables (`--provider-bin`) and isolated system temporary directories for integration tests; never test against real user credentials or allow tests to leak background worker processes or sockets.
- **Home folding**: Route every printed path and diagnostic message through `cli_command_kit::fold_home` / `fold_message` in both human and agent modes while keeping native paths for filesystem and subprocess calls.
- **Secrets hygiene**: Never persist authorization codes or callback URLs to disk, session metadata, or logs. Strictly validate loopback callback URLs before local replay.
- **Public repository hygiene**: Keep issue-tracker numbers, ticket text, and private internal hostnames out of commits, pull requests, and tracked files. Keep `bin/`, `.tmp/`, `.state/`, and `.cache/` ignored. Preserve MIT attribution to `Alex Gorbatchev`.
