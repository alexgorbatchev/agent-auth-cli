use crate::{
    error::{AuthError, Result},
    process,
    protocol::{
        AccountInfo, AuthChallenge, AuthMethod, ExpectedInput, ExpectedInputKind,
        ProviderAuthState, ProviderStatusReport, SCHEMA_VERSION, UsageBucket,
    },
    providers::{
        ActiveLogin, LoginCommand, ProviderAdapter, ProviderContext, extract_https_url,
        extract_json_object, sanitize_diagnostics, strip_ansi, take_pipe,
    },
};
use async_trait::async_trait;
use serde_json::Value;
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::mpsc,
};

pub struct AgyProvider;

pub struct AgyActiveLogin {
    child: Child,
    stdin: Option<ChildStdin>,
    output_rx: mpsc::Receiver<String>,
    challenge: AuthChallenge,
}

#[async_trait]
impl ActiveLogin for AgyActiveLogin {
    fn challenge(&self) -> &AuthChallenge {
        &self.challenge
    }

    async fn run(
        mut self: Box<Self>,
        mut commands: mpsc::Receiver<LoginCommand>,
    ) -> Result<AccountInfo> {
        let mut logs = Vec::new();
        loop {
            tokio::select! {
                status_res = self.child.wait() => {
                    while let Ok(line) = self.output_rx.try_recv() {
                        logs.push(line);
                    }
                    let exit = status_res?;
                    let combined = logs.join("\n");
                    if exit.success() {
                        let email = parse_agy_auth_email(&combined);
                        return Ok(AccountInfo {
                            email,
                            plan: None,
                            auth_method: Some("google_oauth".into()),
                            workspace: None,
                            usage_buckets: Vec::new(),
                        });
                    }
                    let diag = sanitize_diagnostics(&combined);
                    return Err(AuthError::ProviderFailed {
                        provider: "agy".into(),
                        message: if diag.is_empty() {
                            format!("agy acp --login exited with status {exit}")
                        } else {
                            diag
                        },
                    });
                }
                maybe_line = self.output_rx.recv() => {
                    if let Some(line) = maybe_line {
                        logs.push(line);
                    }
                }
                cmd = commands.recv() => {
                    match cmd {
                        Some(LoginCommand::Submit { input, reply }) => {
                            let res = self.write_code(&input).await;
                            let _ = reply.send(res);
                        }
                        Some(LoginCommand::Cancel { reply }) => {
                            self.stdin.take();
                            if let Some(pid) = self.child.id() {
                                process::terminate_process_group(pid, Duration::from_millis(500)).await;
                            }
                            let _ = self.child.wait().await;
                            let _ = reply.send(Ok(()));
                            return Err(AuthError::Cancelled);
                        }
                        None => {
                            self.stdin.take();
                            if let Some(pid) = self.child.id() {
                                process::terminate_process_group(pid, Duration::from_millis(500)).await;
                            }
                            let _ = self.child.wait().await;
                            return Err(AuthError::Cancelled);
                        }
                    }
                }
            }
        }
    }
}

impl AgyActiveLogin {
    async fn write_code(&mut self, input: &str) -> Result<()> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(AuthError::InvalidInput(
                "agy login requires a non-empty authorization code or landing URL".into(),
            ));
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| AuthError::ProviderFailed {
                provider: "agy".into(),
                message: "agy login stdin is no longer open".into(),
            })?;
        stdin.write_all(trimmed.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl ProviderAdapter for AgyProvider {
    fn id(&self) -> &'static str {
        "agy"
    }

    fn binary_name(&self) -> &'static str {
        "agy"
    }

    fn default_method(&self) -> AuthMethod {
        AuthMethod::Oauth
    }

    fn supported_methods(&self) -> &'static [AuthMethod] {
        &[AuthMethod::Oauth]
    }

    fn supports_logout(&self) -> bool {
        false
    }

    async fn status(
        &self,
        ctx: &ProviderContext,
        timeout: Duration,
    ) -> Result<ProviderStatusReport> {
        let mut cmd = Command::new(&ctx.binary);
        cmd.args(["-p", "/usage", "--output-format", "json"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ctx.apply_env(&mut cmd);
        process::configure_process_group(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(AuthError::ProviderFailed {
                    provider: "agy".into(),
                    message: format!("failed to launch agy status probe: {e}"),
                });
            }
        };
        let pid = child.id();
        let stdout = take_pipe(child.stdout.take(), "agy status stdout")?;
        let stderr = take_pipe(child.stderr.take(), "agy status stderr")?;

        let (tx, mut rx) = mpsc::channel::<(bool, String)>(64);
        let tx_out = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx_out.send((true, line)).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send((false, line)).await.is_err() {
                    break;
                }
            }
        });

        let mut stdout_lines = Vec::new();
        let mut stderr_lines = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;

        let unauthenticated_early = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                if let Some(pid) = pid {
                    process::terminate_process_group(pid, Duration::from_millis(500)).await;
                }
                let _ = child.wait().await;
                return Err(AuthError::Timeout(
                    "agy usage status probe timed out".into(),
                ));
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some((is_stdout, line))) => {
                    if looks_unauthenticated(&line) {
                        if let Some(pid) = pid {
                            process::terminate_process_group(pid, Duration::from_millis(300)).await;
                        }
                        let _ = child.wait().await;
                        break true;
                    }
                    if is_stdout {
                        stdout_lines.push(line);
                    } else {
                        stderr_lines.push(line);
                    }
                }
                Ok(None) => break false,
                Err(_) => {
                    if let Some(pid) = pid {
                        process::terminate_process_group(pid, Duration::from_millis(500)).await;
                    }
                    let _ = child.wait().await;
                    return Err(AuthError::Timeout(
                        "agy usage status probe timed out".into(),
                    ));
                }
            }
        };

        if unauthenticated_early {
            return Ok(ProviderStatusReport {
                schema_version: SCHEMA_VERSION,
                provider: self.id().to_owned(),
                status: ProviderAuthState::Unauthenticated,
                account: None,
                error: None,
            });
        }

        let exit = child.wait().await?;
        let combined_out = stdout_lines.join("\n");
        let combined_err = stderr_lines.join("\n");
        if looks_unauthenticated(&combined_out) || looks_unauthenticated(&combined_err) {
            return Ok(ProviderStatusReport {
                schema_version: SCHEMA_VERSION,
                provider: self.id().to_owned(),
                status: ProviderAuthState::Unauthenticated,
                account: None,
                error: None,
            });
        }
        if exit.success()
            && let Some(report) = parse_agy_usage_status(&combined_out)
        {
            return Ok(report);
        }
        Err(AuthError::ProviderFailed {
            provider: "agy".into(),
            message: sanitize_diagnostics(&format!("{combined_out}\n{combined_err}")),
        })
    }

    async fn logout(&self, _ctx: &ProviderContext, _timeout: Duration) -> Result<()> {
        Err(AuthError::UnsupportedOperation {
            provider: "agy".into(),
            operation: "logout".into(),
            hint: "Run `/logout` inside an interactive `agy` session to sign out.".into(),
        })
    }

    async fn start_session(
        &self,
        _method: AuthMethod,
        ctx: &ProviderContext,
        start_timeout: Duration,
    ) -> Result<Box<dyn ActiveLogin>> {
        let mut cmd = Command::new(&ctx.binary);
        cmd.args(["acp", "--login"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ctx.apply_env(&mut cmd);
        process::configure_process_group(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(AuthError::ProviderFailed {
                    provider: "agy".into(),
                    message: format!("failed to launch agy acp --login: {e}"),
                });
            }
        };
        let stdin = child.stdin.take();
        let stdout = take_pipe(child.stdout.take(), "agy acp --login stdout")?;
        let stderr = take_pipe(child.stderr.take(), "agy acp --login stderr")?;

        let (tx, mut rx) = mpsc::channel::<String>(64);
        let tx_out = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx_out.send(line).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).await.is_err() {
                    break;
                }
            }
        });

        let mut seen = Vec::new();
        let auth_url = tokio::time::timeout(start_timeout, async {
            while let Some(line) = rx.recv().await {
                if let Some(url) = extract_https_url(&line) {
                    return Ok(url);
                }
                seen.push(line);
            }
            Err(AuthError::ProviderFailed {
                provider: "agy".into(),
                message: format!(
                    "agy acp --login exited without printing an auth URL: {}",
                    sanitize_diagnostics(&seen.join("\n"))
                ),
            })
        })
        .await;

        let auth_url = match auth_url {
            Ok(Ok(url)) => url,
            Ok(Err(err)) => {
                if let Some(pid) = child.id() {
                    process::terminate_process_group(pid, Duration::from_millis(500)).await;
                }
                let _ = child.wait().await;
                return Err(err);
            }
            Err(_) => {
                if let Some(pid) = child.id() {
                    process::terminate_process_group(pid, Duration::from_millis(500)).await;
                }
                let _ = child.wait().await;
                return Err(AuthError::Timeout(
                    "timed out waiting for agy auth URL".into(),
                ));
            }
        };

        let challenge = AuthChallenge {
            auth_url,
            user_code: None,
            expected_input: ExpectedInput {
                kind: ExpectedInputKind::CodeOrUrl,
                required: true,
                prompt: "Open the URL, sign in with Google, and paste the authorization code or full landing URL.".into(),
            },
            callback_origin: None,
        };

        Ok(Box::new(AgyActiveLogin {
            child,
            stdin,
            output_rx: rx,
            challenge,
        }))
    }
}

pub(crate) fn looks_unauthenticated(text: &str) -> bool {
    let lower = strip_ansi(text).to_ascii_lowercase();
    lower.contains("authentication required")
        || lower.contains("not authenticated")
        || lower.contains("not signed in")
        || lower.contains("no stored credentials")
}

pub(crate) fn parse_agy_auth_email(raw: &str) -> Option<String> {
    let cleaned = strip_ansi(raw);
    for line in cleaned.lines() {
        if let Some((_, rest)) = line.split_once("authenticated successfully as ") {
            let email = rest.trim().trim_end_matches('.');
            if !email.is_empty() {
                return Some(email.to_owned());
            }
        }
    }
    None
}

pub(crate) fn parse_agy_usage_status(raw: &str) -> Option<ProviderStatusReport> {
    let json_slice = extract_json_object(raw)?;
    let value: Value = serde_json::from_str(json_slice).ok()?;
    let ok = value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("SUCCESS"));
    if !ok {
        return None;
    }
    let mut usage_buckets = Vec::new();
    if let Some(groups) = value
        .pointer("/command/data/groups")
        .and_then(Value::as_array)
    {
        for group in groups {
            if let Some(buckets) = group.get("buckets").and_then(Value::as_array) {
                for bucket in buckets {
                    if let Some(id) = bucket.get("id").and_then(Value::as_str) {
                        usage_buckets.push(UsageBucket {
                            id: id.to_owned(),
                            remaining_fraction: bucket
                                .get("remaining_fraction")
                                .and_then(Value::as_f64),
                            reset_time: bucket
                                .get("reset_time")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                        });
                    }
                }
            }
        }
    }

    Some(ProviderStatusReport {
        schema_version: SCHEMA_VERSION,
        provider: "agy".into(),
        status: ProviderAuthState::Authenticated,
        account: Some(AccountInfo {
            email: None,
            plan: None,
            auth_method: Some("google_oauth".into()),
            workspace: None,
            usage_buckets,
        }),
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agy_usage_buckets_and_auth_email() {
        let raw = r#"{"status":"SUCCESS","command":{"name":"usage","data":{"groups":[{"name":"Gemini","buckets":[{"id":"gemini-weekly","remaining_fraction":0.99,"reset_time":"2026-11-28T14:08:15Z"}]}]}}}"#;
        let report = parse_agy_usage_status(raw).unwrap();
        assert_eq!(report.status, ProviderAuthState::Authenticated);
        let buckets = &report.account.unwrap().usage_buckets;
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].id, "gemini-weekly");
        assert_eq!(buckets[0].remaining_fraction, Some(0.99));
        assert_eq!(
            buckets[0].reset_time.as_deref(),
            Some("2026-11-28T14:08:15Z")
        );

        assert!(parse_agy_usage_status(r#"{"status":"ERROR"}"#).is_none());
        assert!(looks_unauthenticated(
            "Authentication required. Please visit:"
        ));
        assert!(looks_unauthenticated(
            "not authenticated: no stored credentials found"
        ));
        assert!(!looks_unauthenticated("{\"status\":\"SUCCESS\"}"));
        assert_eq!(
            parse_agy_auth_email("OAuth: authenticated successfully as user@example.com\n")
                .as_deref(),
            Some("user@example.com")
        );
        assert!(parse_agy_auth_email("no email here").is_none());
    }
}
