use crate::{
    error::{AuthError, Result},
    process,
    protocol::{
        AuthMethod, SCHEMA_VERSION, SessionSnapshot, SessionState, StartupAck, WorkerRequest,
        WorkerResponse, now_rfc3339, rfc3339_after,
    },
    providers::{LoginCommand, ProviderContext, ProviderRegistry},
    sandbox::Sandbox,
    session::store::{self, SessionMeta},
};
use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{mpsc, oneshot, watch},
};

const POST_COMPLETION_GRACE: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct StartSessionOptions {
    pub worker_exe: PathBuf,
    pub runtime_dir: PathBuf,
    pub provider: String,
    pub method: AuthMethod,
    pub ttl_secs: u64,
    pub start_timeout_secs: u64,
    pub provider_bin: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub claude_console: bool,
    pub claude_sso: bool,
    pub claude_email: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WorkerArgs {
    pub session_id: String,
    pub runtime_dir: PathBuf,
    pub provider: String,
    pub method: AuthMethod,
    pub ttl_secs: u64,
    pub start_timeout_secs: u64,
    pub provider_bin: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub claude_console: bool,
    pub claude_sso: bool,
    pub claude_email: Option<String>,
}

/// Spawn a detached background session worker and wait only for the initial auth URL handshake.
pub async fn start_detached_session(opts: &StartSessionOptions) -> Result<SessionSnapshot> {
    store::ensure_runtime_dir(&opts.runtime_dir)?;
    let session_id = store::generate_session_id()?;

    let mut cmd = Command::new(&opts.worker_exe);
    cmd.arg("__worker")
        .arg("--session")
        .arg(&session_id)
        .arg("--runtime-dir")
        .arg(&opts.runtime_dir)
        .arg("--provider")
        .arg(&opts.provider)
        .arg("--method")
        .arg(opts.method.as_str())
        .arg("--ttl")
        .arg(opts.ttl_secs.to_string())
        .arg("--start-timeout")
        .arg(opts.start_timeout_secs.to_string());
    if let Some(bin) = &opts.provider_bin {
        cmd.arg("--provider-bin").arg(bin);
    }
    if let Some(home) = &opts.home {
        cmd.arg("--home").arg(home);
    }
    if opts.claude_console {
        cmd.arg("--console");
    }
    if opts.claude_sso {
        cmd.arg("--sso");
    }
    if let Some(email) = &opts.claude_email {
        cmd.arg("--email").arg(email);
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    process::configure_detached_session(&mut cmd);

    let mut child = cmd.spawn()?;
    let worker_pid = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AuthError::Protocol("worker missing startup stdout pipe".into()))?;

    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let wait_budget = Duration::from_secs(opts.start_timeout_secs.saturating_add(5));
    let read_res = tokio::time::timeout(wait_budget, reader.read_line(&mut line)).await;

    match read_res {
        Ok(Ok(n)) if n > 0 => {
            let ack: StartupAck = serde_json::from_str(line.trim())?;
            match ack {
                StartupAck::Ready(snapshot) => {
                    // Detach cleanly: do NOT wait on child, let worker run in background.
                    Ok(*snapshot)
                }
                StartupAck::Error(detail) => {
                    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                    Err(AuthError::from_detail(detail))
                }
            }
        }
        Ok(Ok(_)) => {
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            Err(AuthError::Protocol(
                "session worker exited before reporting auth URL".into(),
            ))
        }
        Ok(Err(e)) => {
            if let Some(pid) = worker_pid {
                process::terminate_process_group(pid, Duration::from_millis(500)).await;
            }
            Err(AuthError::Io(e))
        }
        Err(_) => {
            if let Some(pid) = worker_pid {
                process::terminate_process_group(pid, Duration::from_millis(500)).await;
            }
            Err(AuthError::Timeout(
                "timed out waiting for session worker startup".into(),
            ))
        }
    }
}

/// Entrypoint for the detached `__worker` process.
pub async fn run_worker(args: WorkerArgs) -> i32 {
    let mut stdout = std::io::stdout();
    match run_worker_inner(args, &mut stdout, true).await {
        Ok(()) => 0,
        Err(err) => {
            let ack = StartupAck::Error(err.to_detail(None));
            if let Ok(line) = serde_json::to_string(&ack) {
                let _ = writeln!(stdout, "{line}");
                let _ = stdout.flush();
            }
            1
        }
    }
}

/// Core worker routine, also callable directly in tests with a custom startup ack sink.
pub async fn run_worker_inner(
    args: WorkerArgs,
    startup_out: &mut impl std::io::Write,
    detach_stdout_after_ack: bool,
) -> Result<()> {
    store::validate_session_id(&args.session_id)?;
    store::ensure_runtime_dir(&args.runtime_dir)?;

    let sock_path = store::socket_path(&args.runtime_dir, &args.session_id);
    if sock_path.exists() {
        let _ = fs::remove_file(&sock_path);
    }

    let listener = bind_private_socket(&sock_path)?;
    let _guard = SessionCleanupGuard {
        runtime_dir: args.runtime_dir.clone(),
        session_id: args.session_id.clone(),
    };

    let registry = ProviderRegistry::new();
    let provider = registry.get(&args.provider)?;
    if !provider.supported_methods().contains(&args.method) {
        return Err(AuthError::UnsupportedMethod {
            provider: provider.id().to_owned(),
            method: args.method.to_string(),
        });
    }

    let sandbox = Arc::new(Sandbox::new_in(&args.runtime_dir, &args.session_id)?);
    let mut ctx = ProviderContext {
        binary: process::require_binary(
            provider.id(),
            args.provider_bin.as_deref(),
            provider.binary_name(),
        )?,
        home: args.home.clone(),
        extra_env: BTreeMap::new(),
        claude_console: args.claude_console,
        claude_sso: args.claude_sso,
        claude_email: args.claude_email.clone(),
        sandbox,
    };
    if let Ok(log) = std::env::var("AGENT_AUTH_NOOP_OPENER_LOG") {
        ctx.extra_env
            .insert("AGENT_AUTH_NOOP_OPENER_LOG".into(), log);
    }

    let active = provider
        .start_session(
            args.method,
            &ctx,
            Duration::from_secs(args.start_timeout_secs),
        )
        .await?;

    let challenge = active.challenge().clone();
    let expires_at_str = rfc3339_after(args.ttl_secs);
    let meta = SessionMeta {
        session_id: args.session_id.clone(),
        provider: provider.id().to_owned(),
        method: args.method,
        worker_pid: std::process::id(),
        created_at: now_rfc3339(),
        expires_at: expires_at_str.clone(),
    };
    store::write_meta(&args.runtime_dir, &meta)?;

    let initial_snapshot = SessionSnapshot {
        schema_version: SCHEMA_VERSION,
        session_id: args.session_id.clone(),
        provider: provider.id().to_owned(),
        method: args.method,
        status: SessionState::AwaitingInput,
        auth_url: Some(challenge.auth_url.clone()),
        user_code: challenge.user_code.clone(),
        expected_input: Some(challenge.expected_input.clone()),
        account: None,
        expires_at: expires_at_str,
        error: None,
    };

    let ack_line = serde_json::to_string(&StartupAck::Ready(Box::new(initial_snapshot.clone())))?;
    writeln!(startup_out, "{ack_line}")?;
    startup_out.flush()?;
    if detach_stdout_after_ack {
        redirect_stdout_to_devnull();
    }

    let (state_tx, state_rx) = watch::channel(initial_snapshot);
    let (cmd_tx, cmd_rx) = mpsc::channel::<LoginCommand>(16);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(4);

    let bg_state_tx = state_tx.clone();
    let provider_handle = tokio::spawn(async move {
        let outcome = active.run(cmd_rx).await;
        bg_state_tx.send_modify(|snap| {
            if snap.status.is_terminal() {
                return;
            }
            match outcome {
                Ok(account) => {
                    snap.status = SessionState::Authenticated;
                    snap.account = Some(account);
                    snap.error = None;
                }
                Err(AuthError::Cancelled) => {
                    snap.status = SessionState::Cancelled;
                    snap.error = None;
                }
                Err(err) => {
                    snap.status = SessionState::Failed;
                    snap.error = Some(err.to_detail(None));
                }
            }
        });
    });

    let ttl_deadline = tokio::time::Instant::now() + Duration::from_secs(args.ttl_secs);
    let ttl_sleep = tokio::time::sleep_until(ttl_deadline);
    tokio::pin!(ttl_sleep);

    let mut post_complete_sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    let mut watch_for_completion = state_rx.clone();

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                if let Ok((stream, _)) = accept_res {
                    let s_tx = state_tx.clone();
                    let s_rx = state_rx.clone();
                    let c_tx = cmd_tx.clone();
                    let sh_tx = shutdown_tx.clone();
                    tokio::spawn(async move {
                        handle_client(stream, s_tx, s_rx, c_tx, sh_tx).await;
                    });
                }
            }
            changed = watch_for_completion.changed(), if post_complete_sleep.is_none() => {
                if changed.is_ok() && watch_for_completion.borrow().status.is_terminal() {
                    let grace_until = (tokio::time::Instant::now() + POST_COMPLETION_GRACE).min(ttl_deadline);
                    post_complete_sleep = Some(Box::pin(tokio::time::sleep_until(grace_until)));
                }
            }
            _ = async {
                if let Some(sleep) = post_complete_sleep.as_mut() {
                    sleep.as_mut().await;
                }
            }, if post_complete_sleep.is_some() => {
                break;
            }
            _ = &mut ttl_sleep => {
                let (reply_tx, reply_rx) = oneshot::channel();
                let _ = cmd_tx.send(LoginCommand::Cancel { reply: reply_tx }).await;
                let _ = tokio::time::timeout(Duration::from_secs(2), reply_rx).await;
                state_tx.send_modify(|snap| {
                    if !snap.status.is_terminal() {
                        snap.status = SessionState::Expired;
                    }
                });
                break;
            }
            _ = shutdown_rx.recv() => {
                // Allow response flush to settle before tearing down socket.
                tokio::time::sleep(Duration::from_millis(50)).await;
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                let (reply_tx, reply_rx) = oneshot::channel();
                let _ = cmd_tx.send(LoginCommand::Cancel { reply: reply_tx }).await;
                let _ = tokio::time::timeout(Duration::from_secs(2), reply_rx).await;
                break;
            }
            _ = async {
                if let Some(sig) = sigterm.as_mut() {
                    sig.recv().await;
                }
            }, if sigterm.is_some() => {
                let (reply_tx, reply_rx) = oneshot::channel();
                let _ = cmd_tx.send(LoginCommand::Cancel { reply: reply_tx }).await;
                let _ = tokio::time::timeout(Duration::from_secs(2), reply_rx).await;
                break;
            }
        }
    }

    drop(cmd_tx);
    let _ = tokio::time::timeout(Duration::from_secs(3), provider_handle).await;
    Ok(())
}

async fn handle_client(
    stream: UnixStream,
    state_tx: watch::Sender<SessionSnapshot>,
    mut state_rx: watch::Receiver<SessionSnapshot>,
    cmd_tx: mpsc::Sender<LoginCommand>,
    shutdown_tx: mpsc::Sender<()>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let Ok(n) = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .unwrap_or(Ok(0))
    else {
        return;
    };
    if n == 0 {
        return;
    }

    let request: WorkerRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = WorkerResponse::Error(AuthError::Json(e).to_detail(None));
            let _ = write_response(&mut write_half, &resp).await;
            return;
        }
    };

    match request {
        WorkerRequest::Status => {
            let snap = state_rx.borrow().clone();
            let _ =
                write_response(&mut write_half, &WorkerResponse::Snapshot(Box::new(snap))).await;
        }
        WorkerRequest::Cancel => {
            let current = state_rx.borrow().clone();
            if !current.status.is_terminal() {
                let (reply_tx, reply_rx) = oneshot::channel();
                let _ = cmd_tx.send(LoginCommand::Cancel { reply: reply_tx }).await;
                let _ = tokio::time::timeout(Duration::from_secs(4), reply_rx).await;
                state_tx.send_modify(|snap| {
                    if !snap.status.is_terminal() {
                        snap.status = SessionState::Cancelled;
                        snap.error = None;
                    }
                });
            }
            let snap = state_rx.borrow().clone();
            let _ =
                write_response(&mut write_half, &WorkerResponse::Snapshot(Box::new(snap))).await;
            let _ = shutdown_tx.send(()).await;
        }
        WorkerRequest::Wait { timeout_secs } => {
            let snap = wait_for_terminal(&mut state_rx, Duration::from_secs(timeout_secs)).await;
            let done = snap.status.is_terminal();
            let _ =
                write_response(&mut write_half, &WorkerResponse::Snapshot(Box::new(snap))).await;
            if done {
                let _ = shutdown_tx.send(()).await;
            }
        }
        WorkerRequest::Submit {
            input,
            timeout_secs,
        } => {
            let current = state_rx.borrow().clone();
            if current.status.is_terminal() {
                let _ = write_response(
                    &mut write_half,
                    &WorkerResponse::Snapshot(Box::new(current)),
                )
                .await;
                let _ = shutdown_tx.send(()).await;
                return;
            }

            let trimmed = input
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);

            let required = current.expected_input.as_ref().is_some_and(|e| e.required);

            if let Some(value) = trimmed {
                let (reply_tx, reply_rx) = oneshot::channel();
                if cmd_tx
                    .send(LoginCommand::Submit {
                        input: value,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    let snap = state_rx.borrow().clone();
                    let _ =
                        write_response(&mut write_half, &WorkerResponse::Snapshot(Box::new(snap)))
                            .await;
                    let _ = shutdown_tx.send(()).await;
                    return;
                }
                match tokio::time::timeout(Duration::from_secs(15), reply_rx).await {
                    Ok(Ok(Ok(()))) => {
                        state_tx.send_modify(|snap| {
                            if !snap.status.is_terminal() {
                                snap.status = SessionState::Exchanging;
                            }
                        });
                    }
                    Ok(Ok(Err(err))) => {
                        let _ = write_response(
                            &mut write_half,
                            &WorkerResponse::Error(err.to_detail(None)),
                        )
                        .await;
                        return;
                    }
                    _ => {
                        let snap = state_rx.borrow().clone();
                        let _ = write_response(
                            &mut write_half,
                            &WorkerResponse::Snapshot(Box::new(snap)),
                        )
                        .await;
                        return;
                    }
                }
            } else if required {
                let err = AuthError::InvalidInput(format!(
                    "provider {} requires input via --input or --input-stdin",
                    current.provider
                ));
                let _ =
                    write_response(&mut write_half, &WorkerResponse::Error(err.to_detail(None)))
                        .await;
                return;
            }

            let snap = wait_for_terminal(&mut state_rx, Duration::from_secs(timeout_secs)).await;
            let done = snap.status.is_terminal();
            let _ =
                write_response(&mut write_half, &WorkerResponse::Snapshot(Box::new(snap))).await;
            if done {
                let _ = shutdown_tx.send(()).await;
            }
        }
    }
}

async fn wait_for_terminal(
    state_rx: &mut watch::Receiver<SessionSnapshot>,
    timeout: Duration,
) -> SessionSnapshot {
    if state_rx.borrow().status.is_terminal() {
        return state_rx.borrow().clone();
    }
    let _ = tokio::time::timeout(timeout, async {
        while state_rx.changed().await.is_ok() {
            if state_rx.borrow().status.is_terminal() {
                break;
            }
        }
    })
    .await;
    state_rx.borrow().clone()
}

async fn write_response(
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &WorkerResponse,
) -> Result<()> {
    let mut line = serde_json::to_string(resp)?;
    line.push('\n');
    write_half.write_all(line.as_bytes()).await?;
    write_half.flush().await?;
    Ok(())
}

fn bind_private_socket(path: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn redirect_stdout_to_devnull() {
    let c_path = std::ffi::CString::new("/dev/null").expect("static path has no NUL");
    // Safety: opening `/dev/null` and dup2-ing onto fd 1 cleanly detaches the startup pipe.
    unsafe {
        let fd = libc::open(c_path.as_ptr(), libc::O_WRONLY);
        if fd >= 0 {
            libc::dup2(fd, libc::STDOUT_FILENO);
            if fd != libc::STDOUT_FILENO {
                libc::close(fd);
            }
        }
    }
}

struct SessionCleanupGuard {
    runtime_dir: PathBuf,
    session_id: String,
}

impl Drop for SessionCleanupGuard {
    fn drop(&mut self) {
        store::remove_session_files(&self.runtime_dir, &self.session_id);
    }
}
