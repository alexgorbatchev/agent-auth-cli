pub mod command;
pub mod render;

pub use command::{command, help_options};

use crate::{
    error::{AuthError, Result},
    protocol::{
        AuthMethod, AuthMethodChoice, ProviderAuthState, ProviderListReport, ProviderLogoutReport,
        ProviderStatusListReport, ProviderStatusReport, ProviderUsageListReport,
        ProviderUsageReport, ProviderUsageState, SCHEMA_VERSION, SessionListReport, SessionState,
    },
    providers::ProviderRegistry,
    sandbox::{self, Sandbox},
    session::{
        client, store,
        worker::{self, StartSessionOptions, WorkerArgs},
    },
};
use clap::Command;
use cli_command_kit::Mode;
use render::OutputFormat;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{Read, Write},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Environment {
    pub mode: Mode,
    pub home: Option<PathBuf>,
    pub runtime_dir: PathBuf,
    pub worker_exe: PathBuf,
}

impl Environment {
    pub fn read() -> Result<Self> {
        Ok(Self {
            mode: Mode::from_env(),
            home: dirs::home_dir(),
            runtime_dir: store::default_runtime_dir(),
            worker_exe: std::env::current_exe()?,
        })
    }

    pub fn display(&self, value: &str) -> String {
        render::fold_text(value, self.home.as_deref())
    }
}

pub async fn run_from_env() -> i32 {
    let args: Vec<OsString> = std::env::args_os().collect();
    let wants_json = args.iter().any(|a| a == "--json");
    let environment = match Environment::read() {
        Ok(env) => env,
        Err(err) => {
            let format = OutputFormat::resolve(Mode::from_env(), wants_json);
            let _ =
                render::render_error(&mut std::io::stderr(), &err.to_detail(None), format, None);
            return err.exit_code();
        }
    };

    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    match execute_with_io(args, &environment, &mut stdin, &mut stdout).await {
        Ok(code) => code,
        Err(AuthError::Pending(_)) => 3,
        Err(AuthError::Parse(err)) => {
            let text = environment.display(&err.to_string());
            let _ = stderr.write_all(text.as_bytes());
            2
        }
        Err(err) => {
            let format = OutputFormat::resolve(environment.mode, wants_json);
            let detail = err.to_detail(environment.home.as_deref());
            let _ = render::render_error(&mut stderr, &detail, format, environment.home.as_deref());
            err.exit_code()
        }
    }
}

pub async fn execute<I, T>(
    args: I,
    environment: &Environment,
    output: &mut impl Write,
) -> Result<i32>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut empty_stdin = std::io::empty();
    execute_with_io(args, environment, &mut empty_stdin, output).await
}

pub async fn execute_with_io<I, T>(
    args: I,
    environment: &Environment,
    stdin: &mut impl Read,
    output: &mut impl Write,
) -> Result<i32>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let argv: Vec<OsString> = args.into_iter().map(Into::into).collect();
    execute_inner(argv, environment, stdin, output).await
}

async fn execute_inner(
    args: Vec<OsString>,
    environment: &Environment,
    stdin: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<i32> {
    let mut cmd = command(environment.mode);
    let matches = match cmd.try_get_matches_from_mut(args) {
        Ok(m) => m,
        Err(err) if !err.use_stderr() => {
            render::write_folded(output, &err.to_string(), environment.home.as_deref())?;
            return Ok(0);
        }
        Err(err) => return Err(err.into()),
    };

    if matches.get_flag("version") {
        writeln!(output, "{}", env!("CARGO_PKG_VERSION"))?;
        return Ok(0);
    }

    let mut skill_buf = Vec::new();
    if cli_command_kit::write_skill(&cmd, &matches, &help_options(), &mut skill_buf)? {
        output.write_all(&skill_buf)?;
        return Ok(0);
    }

    let format = OutputFormat::resolve(environment.mode, matches.get_flag("json"));
    let runtime_dir = matches
        .get_one::<PathBuf>("runtime-dir")
        .cloned()
        .unwrap_or_else(|| environment.runtime_dir.clone());
    let home_ref = environment.home.as_deref();
    let registry = ProviderRegistry::new();

    match matches.subcommand() {
        Some(("__noop-opener", sub)) => {
            let extra: Vec<OsString> = sub
                .get_many::<String>("args")
                .map(|vals| vals.map(OsString::from).collect())
                .unwrap_or_default();
            Ok(sandbox::run_noop_opener(&extra))
        }
        Some(("__worker", sub)) => {
            let method = AuthMethod::from_str(sub.get_one::<String>("method").unwrap())
                .map_err(AuthError::InvalidInput)?;
            let worker_args = WorkerArgs {
                session_id: sub.get_one::<String>("session").unwrap().clone(),
                runtime_dir,
                provider: sub.get_one::<String>("provider").unwrap().clone(),
                method,
                ttl_secs: *sub.get_one::<u64>("ttl").unwrap(),
                start_timeout_secs: *sub.get_one::<u64>("start-timeout").unwrap(),
                provider_bin: sub.get_one::<PathBuf>("provider-bin").cloned(),
                home: sub.get_one::<PathBuf>("home").cloned(),
                claude_console: sub.get_flag("console"),
                claude_sso: sub.get_flag("sso"),
                claude_email: sub.get_one::<String>("email").cloned(),
            };
            Ok(worker::run_worker(worker_args).await)
        }
        Some(("completion", subject)) => {
            use clap_complete::Generator;
            let leaf = subject.subcommand().unwrap().1;
            let shell: clap_complete::Shell = leaf
                .get_one::<String>("shell")
                .unwrap()
                .parse()
                .map_err(AuthError::InvalidInput)?;
            let mut tree = if leaf.get_flag("no-descriptions") {
                without_descriptions(cmd)
            } else {
                cmd
            };
            tree.set_bin_name("agent-auth");
            tree.build();
            shell.try_generate(&tree, output)?;
            Ok(0)
        }
        Some(("provider", subject)) => match subject.subcommand() {
            Some(("list", _)) => {
                let report = ProviderListReport {
                    schema_version: SCHEMA_VERSION,
                    providers: registry.descriptors(&BTreeMap::new()),
                };
                render::render_provider_list(output, &report, format, home_ref)?;
                Ok(0)
            }
            Some(("status", leaf)) => {
                let explicit_bin = leaf
                    .get_one::<PathBuf>("provider-bin")
                    .map(PathBuf::as_path);
                let home_override = leaf.get_one::<PathBuf>("home").cloned();
                let timeout = Duration::from_secs(*leaf.get_one::<u64>("timeout").unwrap());
                store::ensure_runtime_dir(&runtime_dir)?;
                let sandbox = Arc::new(Sandbox::new_for_exe(
                    &runtime_dir,
                    "status",
                    &environment.worker_exe,
                )?);

                if let Some(provider_id) = leaf.get_one::<String>("provider") {
                    let adapter = registry.get(provider_id)?;
                    let ctx = registry.build_context(
                        adapter.as_ref(),
                        explicit_bin,
                        home_override,
                        sandbox,
                    )?;
                    let report = adapter.status(&ctx, timeout).await?;
                    render::render_provider_status(output, &report, format, home_ref)?;
                    Ok(0)
                } else {
                    if explicit_bin.is_some() {
                        return Err(AuthError::InvalidInput(
                            "--provider-bin requires naming a single provider".into(),
                        ));
                    }
                    let mut reports = Vec::new();
                    for adapter in registry.all() {
                        let report = match registry.build_context(
                            adapter.as_ref(),
                            None,
                            home_override.clone(),
                            Arc::clone(&sandbox),
                        ) {
                            Ok(ctx) => match adapter.status(&ctx, timeout).await {
                                Ok(r) => r,
                                Err(err) => ProviderStatusReport {
                                    schema_version: SCHEMA_VERSION,
                                    provider: adapter.id().to_owned(),
                                    status: ProviderAuthState::Error,
                                    account: None,
                                    error: Some(err.to_detail(home_ref)),
                                },
                            },
                            Err(err) => ProviderStatusReport {
                                schema_version: SCHEMA_VERSION,
                                provider: adapter.id().to_owned(),
                                status: ProviderAuthState::Error,
                                account: None,
                                error: Some(err.to_detail(home_ref)),
                            },
                        };
                        reports.push(report);
                    }
                    let list = ProviderStatusListReport {
                        schema_version: SCHEMA_VERSION,
                        providers: reports,
                    };
                    render::render_provider_status_list(output, &list, format, home_ref)?;
                    Ok(0)
                }
            }
            Some(("usage", leaf)) => {
                let explicit_bin = leaf
                    .get_one::<PathBuf>("provider-bin")
                    .map(PathBuf::as_path);
                let home_override = leaf.get_one::<PathBuf>("home").cloned();
                let timeout = Duration::from_secs(*leaf.get_one::<u64>("timeout").unwrap());
                store::ensure_runtime_dir(&runtime_dir)?;
                let sandbox = Arc::new(Sandbox::new_for_exe(
                    &runtime_dir,
                    "usage",
                    &environment.worker_exe,
                )?);

                if let Some(provider_id) = leaf.get_one::<String>("provider") {
                    let adapter = registry.get(provider_id)?;
                    let ctx = registry.build_context(
                        adapter.as_ref(),
                        explicit_bin,
                        home_override,
                        sandbox,
                    )?;
                    let report = adapter.usage(&ctx, timeout).await?;
                    render::render_provider_usage(output, &report, format, home_ref)?;
                    Ok(0)
                } else {
                    if explicit_bin.is_some() {
                        return Err(AuthError::InvalidInput(
                            "--provider-bin requires naming a single provider".into(),
                        ));
                    }
                    let mut set = tokio::task::JoinSet::new();
                    let fold_home = environment.home.clone();
                    for (idx, adapter) in registry.all().iter().cloned().enumerate() {
                        let ctx_res = registry.build_context(
                            adapter.as_ref(),
                            None,
                            home_override.clone(),
                            Arc::clone(&sandbox),
                        );
                        let fold_home = fold_home.clone();
                        set.spawn(async move {
                            let report = match ctx_res {
                                Ok(ctx) => match adapter.usage(&ctx, timeout).await {
                                    Ok(r) => r,
                                    Err(err) => ProviderUsageReport {
                                        schema_version: SCHEMA_VERSION,
                                        provider: adapter.id().to_owned(),
                                        status: ProviderUsageState::Error,
                                        plan: None,
                                        buckets: Vec::new(),
                                        extra_usage: None,
                                        error: Some(err.to_detail(fold_home.as_deref())),
                                    },
                                },
                                Err(err) => ProviderUsageReport {
                                    schema_version: SCHEMA_VERSION,
                                    provider: adapter.id().to_owned(),
                                    status: ProviderUsageState::Error,
                                    plan: None,
                                    buckets: Vec::new(),
                                    extra_usage: None,
                                    error: Some(err.to_detail(fold_home.as_deref())),
                                },
                            };
                            (idx, report)
                        });
                    }
                    let mut indexed = Vec::new();
                    while let Some(res) = set.join_next().await {
                        if let Ok(pair) = res {
                            indexed.push(pair);
                        }
                    }
                    indexed.sort_by_key(|(idx, _)| *idx);
                    let list = ProviderUsageListReport {
                        schema_version: SCHEMA_VERSION,
                        providers: indexed.into_iter().map(|(_, r)| r).collect(),
                    };
                    render::render_provider_usage_list(output, &list, format, home_ref)?;
                    Ok(0)
                }
            }
            Some(("login", leaf)) => {
                let provider_id = leaf.get_one::<String>("provider").unwrap();
                let adapter = registry.get(provider_id)?;
                let choice = AuthMethodChoice::from_str(leaf.get_one::<String>("method").unwrap())
                    .map_err(AuthError::InvalidInput)?;
                let method = adapter.resolve_method(choice)?;
                let opts = StartSessionOptions {
                    worker_exe: environment.worker_exe.clone(),
                    runtime_dir,
                    provider: adapter.id().to_owned(),
                    method,
                    ttl_secs: *leaf.get_one::<u64>("ttl").unwrap(),
                    start_timeout_secs: *leaf.get_one::<u64>("start-timeout").unwrap(),
                    provider_bin: leaf.get_one::<PathBuf>("provider-bin").cloned(),
                    home: leaf.get_one::<PathBuf>("home").cloned(),
                    claude_console: leaf.get_flag("console"),
                    claude_sso: leaf.get_flag("sso"),
                    claude_email: leaf.get_one::<String>("email").cloned(),
                };
                let snapshot = worker::start_detached_session(&opts).await?;
                render::render_session_snapshot(output, &snapshot, format, home_ref)?;
                Ok(0)
            }
            Some(("logout", leaf)) => {
                let provider_id = leaf.get_one::<String>("provider").unwrap();
                let adapter = registry.get(provider_id)?;
                if !adapter.supports_logout() {
                    let ctx_sandbox = Arc::new(Sandbox::new_for_exe(
                        &runtime_dir,
                        "logout",
                        &environment.worker_exe,
                    )?);
                    let dummy_ctx = crate::providers::ProviderContext {
                        binary: PathBuf::from(adapter.binary_name()),
                        home: None,
                        extra_env: BTreeMap::new(),
                        claude_console: false,
                        claude_sso: false,
                        claude_email: None,
                        sandbox: ctx_sandbox,
                    };
                    adapter.logout(&dummy_ctx, Duration::from_secs(1)).await?;
                }
                let explicit_bin = leaf
                    .get_one::<PathBuf>("provider-bin")
                    .map(PathBuf::as_path);
                let home_override = leaf.get_one::<PathBuf>("home").cloned();
                let timeout = Duration::from_secs(*leaf.get_one::<u64>("timeout").unwrap());
                store::ensure_runtime_dir(&runtime_dir)?;
                let sandbox = Arc::new(Sandbox::new_for_exe(
                    &runtime_dir,
                    "logout",
                    &environment.worker_exe,
                )?);
                let ctx = registry.build_context(
                    adapter.as_ref(),
                    explicit_bin,
                    home_override,
                    sandbox,
                )?;
                adapter.logout(&ctx, timeout).await?;
                let report = ProviderLogoutReport {
                    schema_version: SCHEMA_VERSION,
                    provider: adapter.id().to_owned(),
                    status: "logged_out".into(),
                };
                render::render_provider_logout(output, &report, format, home_ref)?;
                Ok(0)
            }
            _ => unreachable!(),
        },
        Some(("session", subject)) => match subject.subcommand() {
            Some(("submit", leaf)) => {
                let session_id = leaf.get_one::<String>("session-id").unwrap();
                let timeout_secs = *leaf.get_one::<u64>("timeout").unwrap();
                let input = if leaf.get_flag("input-stdin") {
                    let mut buf = String::new();
                    stdin.read_to_string(&mut buf)?;
                    Some(buf)
                } else {
                    leaf.get_one::<String>("input").cloned()
                };
                let snapshot =
                    client::submit_input(&runtime_dir, session_id, input, timeout_secs).await?;
                handle_session_terminal_result(output, snapshot, format, home_ref)
            }
            Some(("wait", leaf)) => {
                let session_id = leaf.get_one::<String>("session-id").unwrap();
                let timeout_secs = *leaf.get_one::<u64>("timeout").unwrap();
                let snapshot = client::wait_session(&runtime_dir, session_id, timeout_secs).await?;
                handle_session_terminal_result(output, snapshot, format, home_ref)
            }
            Some(("status", leaf)) => {
                let session_id = leaf.get_one::<String>("session-id").unwrap();
                let snapshot = client::query_status(&runtime_dir, session_id).await?;
                render::render_session_snapshot(output, &snapshot, format, home_ref)?;
                Ok(0)
            }
            Some(("list", _)) => {
                let sessions = store::list_active_sessions(&runtime_dir).await?;
                let report = SessionListReport {
                    schema_version: SCHEMA_VERSION,
                    sessions,
                };
                render::render_session_list(output, &report, format, home_ref)?;
                Ok(0)
            }
            Some(("cancel", leaf)) => {
                let session_id = leaf.get_one::<String>("session-id").unwrap();
                let snapshot = client::cancel_session(&runtime_dir, session_id).await?;
                render::render_session_snapshot(output, &snapshot, format, home_ref)?;
                Ok(0)
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

fn handle_session_terminal_result(
    output: &mut dyn Write,
    snapshot: crate::protocol::SessionSnapshot,
    format: OutputFormat,
    home: Option<&std::path::Path>,
) -> Result<i32> {
    match snapshot.status {
        SessionState::Authenticated | SessionState::Cancelled => {
            render::render_session_snapshot(output, &snapshot, format, home)?;
            Ok(0)
        }
        SessionState::Failed => {
            let detail = snapshot.error.unwrap_or(crate::protocol::ErrorDetail {
                code: "provider_failed".into(),
                message: format!("{} authentication failed", snapshot.provider),
                retryable: true,
                hint: None,
            });
            Err(AuthError::from_detail(detail))
        }
        SessionState::Expired => Err(AuthError::SessionExpired(snapshot.session_id)),
        SessionState::Starting | SessionState::AwaitingInput | SessionState::Exchanging => {
            render::render_session_snapshot(output, &snapshot, format, home)?;
            Err(AuthError::Pending(Box::new(snapshot)))
        }
    }
}

fn without_descriptions(command: Command) -> Command {
    command
        .about(None::<&'static str>)
        .long_about(None::<&'static str>)
        .mut_args(|argument| {
            argument
                .help(None::<&'static str>)
                .long_help(None::<&'static str>)
        })
        .mut_subcommands(without_descriptions)
}
