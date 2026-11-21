use clap::{Arg, ArgAction, Command};
use cli_command_kit::{HelpOptions, Mode, SkillSource};
use std::path::PathBuf;

pub fn help_options() -> HelpOptions {
    HelpOptions {
        skill: Some(
            SkillSource::new("alexgorbatchev/agent-auth-cli", "main")
                .expect("the fixed skill source names a GitHub repository"),
        ),
        ..Default::default()
    }
}

pub fn command(mode: Mode) -> Command {
    let provider_bin_arg = || {
        Arg::new("provider-bin")
            .long("provider-bin")
            .value_name("path")
            .value_parser(clap::value_parser!(PathBuf))
            .help("Override the provider CLI executable path")
    };
    let home_arg = || {
        Arg::new("home")
            .long("home")
            .value_name("dir")
            .value_parser(clap::value_parser!(PathBuf))
            .help("Override the provider home directory")
    };

    let root = Command::new("agent-auth")
        .about("Non-blocking OAuth login broker for AI coding agent harnesses")
        .disable_version_flag(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("version")
                .long("version")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Print the raw version string"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Print machine-readable JSON output"),
        )
        .arg(
            Arg::new("runtime-dir")
                .long("runtime-dir")
                .value_name("dir")
                .env("AGENT_AUTH_RUNTIME_DIR")
                .global(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Override the per-user runtime socket directory"),
        )
        .subcommand(
            Command::new("provider")
                .about("Inspect and manage supported authentication providers")
                .subcommand_required(true)
                .subcommand(
                    Command::new("list")
                        .about("List supported providers, methods, and binary availability"),
                )
                .subcommand(
                    Command::new("status")
                        .about("Check authentication status for one or all providers")
                        .arg(
                            Arg::new("provider")
                                .value_name("name")
                                .help("Provider ID to inspect (codex, claude, or agy/antigravity); omitted checks all"),
                        )
                        .arg(provider_bin_arg())
                        .arg(home_arg())
                        .arg(
                            Arg::new("timeout")
                                .long("timeout")
                                .value_name("sec")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64))
                                .help("Status check timeout in seconds"),
                        ),
                )
                .subcommand(
                    Command::new("usage")
                        .about("Show usage and rate-limit quotas for one or all providers")
                        .arg(
                            Arg::new("provider")
                                .value_name("name")
                                .help("Provider ID to inspect (codex, claude, or agy/antigravity); omitted checks all"),
                        )
                        .arg(provider_bin_arg())
                        .arg(home_arg())
                        .arg(
                            Arg::new("timeout")
                                .long("timeout")
                                .value_name("sec")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64))
                                .help("Usage fetch timeout in seconds"),
                        ),
                )
                .subcommand(
                    Command::new("logout")
                        .about("Sign out of a provider using its native logout")
                        .arg(
                            Arg::new("provider")
                                .value_name("name")
                                .required(true)
                                .help("Provider ID to sign out"),
                        )
                        .arg(provider_bin_arg())
                        .arg(home_arg())
                        .arg(
                            Arg::new("timeout")
                                .long("timeout")
                                .value_name("sec")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64))
                                .help("Logout timeout in seconds"),
                        ),
                ),
        )
        .subcommand(
            Command::new("session")
                .about("Manage non-blocking OAuth sign-in sessions")
                .subcommand_required(true)
                .subcommand(
                    Command::new("start")
                        .about("Start a non-blocking sign-in session and return the auth URL")
                        .arg(
                            Arg::new("provider")
                                .value_name("provider")
                                .required(true)
                                .help("Provider ID to sign in (codex, claude, or agy/antigravity)"),
                        )
                        .arg(
                            Arg::new("method")
                                .long("method")
                                .value_name("name")
                                .default_value("auto")
                                .value_parser(["auto", "device", "oauth"])
                                .help("Authentication method; auto prefers device when supported"),
                        )
                        .arg(
                            Arg::new("ttl")
                                .long("ttl")
                                .value_name("sec")
                                .default_value("900")
                                .value_parser(clap::value_parser!(u64))
                                .help("Maximum session lifetime in seconds"),
                        )
                        .arg(
                            Arg::new("start-timeout")
                                .long("start-timeout")
                                .value_name("sec")
                                .default_value("20")
                                .value_parser(clap::value_parser!(u64))
                                .help("Startup timeout in seconds while waiting for the auth URL"),
                        )
                        .arg(provider_bin_arg())
                        .arg(home_arg())
                        .arg(
                            Arg::new("console")
                                .long("console")
                                .action(ArgAction::SetTrue)
                                .help("Use Anthropic Console API billing (claude only)"),
                        )
                        .arg(
                            Arg::new("sso")
                                .long("sso")
                                .action(ArgAction::SetTrue)
                                .help("Use SSO sign-in (claude only)"),
                        )
                        .arg(
                            Arg::new("email")
                                .long("email")
                                .value_name("addr")
                                .help("Prefill email address on the login page (claude only)"),
                        ),
                )
                .subcommand(
                    Command::new("submit")
                        .about("Submit user code or callback URL and wait for authentication")
                        .arg(
                            Arg::new("session-id")
                                .value_name("id")
                                .required(true)
                                .help("Active session identifier"),
                        )
                        .arg(
                            Arg::new("input")
                                .long("input")
                                .value_name("text")
                                .conflicts_with("input-stdin")
                                .help("Authorization code or callback URL from the user"),
                        )
                        .arg(
                            Arg::new("input-stdin")
                                .long("input-stdin")
                                .action(ArgAction::SetTrue)
                                .conflicts_with("input")
                                .help("Read authorization code or callback URL from stdin"),
                        )
                        .arg(
                            Arg::new("timeout")
                                .long("timeout")
                                .value_name("sec")
                                .default_value("120")
                                .value_parser(clap::value_parser!(u64))
                                .help("Completion wait timeout in seconds"),
                        ),
                )
                .subcommand(
                    Command::new("wait")
                        .about("Wait for an active session to complete without pasting input")
                        .arg(
                            Arg::new("session-id")
                                .value_name("id")
                                .required(true)
                                .help("Active session identifier"),
                        )
                        .arg(
                            Arg::new("timeout")
                                .long("timeout")
                                .value_name("sec")
                                .default_value("300")
                                .value_parser(clap::value_parser!(u64))
                                .help("Wait timeout in seconds"),
                        ),
                )
                .subcommand(
                    Command::new("status")
                        .about("Inspect the current state of an active session")
                        .arg(
                            Arg::new("session-id")
                                .value_name("id")
                                .required(true)
                                .help("Active session identifier"),
                        ),
                )
                .subcommand(Command::new("list").about("List active authentication sessions"))
                .subcommand(
                    Command::new("cancel")
                        .about("Cancel an active authentication session")
                        .arg(
                            Arg::new("session-id")
                                .value_name("id")
                                .required(true)
                                .help("Active session identifier"),
                        ),
                ),
        )
        .subcommand(
            Command::new("completion")
                .about("Generate shell completion scripts")
                .subcommand_required(true)
                .subcommand(
                    Command::new("script")
                        .about("Print a completion script for the selected shell")
                        .arg(
                            Arg::new("shell")
                                .value_name("shell")
                                .required(true)
                                .value_parser(["bash", "zsh", "fish", "powershell"])
                                .help("Target shell name"),
                        )
                        .arg(
                            Arg::new("no-descriptions")
                                .long("no-descriptions")
                                .action(ArgAction::SetTrue)
                                .help("Omit completion descriptions"),
                        ),
                ),
        )
        .subcommand(
            Command::new("__worker")
                .hide(true)
                .arg(Arg::new("session").long("session").required(true))
                .arg(Arg::new("provider").long("provider").required(true))
                .arg(Arg::new("method").long("method").required(true))
                .arg(
                    Arg::new("ttl")
                        .long("ttl")
                        .default_value("900")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("start-timeout")
                        .long("start-timeout")
                        .default_value("20")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(provider_bin_arg())
                .arg(home_arg())
                .arg(
                    Arg::new("console")
                        .long("console")
                        .action(ArgAction::SetTrue),
                )
                .arg(Arg::new("sso").long("sso").action(ArgAction::SetTrue))
                .arg(Arg::new("email").long("email")),
        )
        .subcommand(
            Command::new("__noop-opener").hide(true).arg(
                Arg::new("args")
                    .num_args(0..)
                    .trailing_var_arg(true)
                    .allow_hyphen_values(true),
            ),
        );

    cli_command_kit::setup(root, mode, &help_options()).expect("fixed command tree is valid")
}
