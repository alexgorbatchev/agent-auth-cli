use crate::{
    error::{AuthError, Result},
    process,
    protocol::{
        AccountInfo, AuthChallenge, AuthMethod, ExpectedInput, ExpectedInputKind,
        ProviderAuthState, ProviderStatusReport, SCHEMA_VERSION,
    },
    providers::{
        ActiveLogin, LoginCommand, ProviderAdapter, ProviderContext, extract_https_url,
        extract_json_object, sanitize_diagnostics, take_pipe,
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

pub struct ClaudeProvider;

pub struct ClaudeActiveLogin {
    child: Child,
    stdin: Option<ChildStdin>,
    output_rx: mpsc::Receiver<String>,
    ctx: ProviderContext,
    challenge: AuthChallenge,
}

#[async_trait]
impl ActiveLogin for ClaudeActiveLogin {
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
                    if exit.success() {
                        let account = ClaudeProvider
                            .status(&self.ctx, Duration::from_secs(10))
                            .await
                            .ok()
                            .and_then(|r| r.account)
                            .unwrap_or_else(|| AccountInfo {
                                auth_method: Some("claudeai".into()),
                                ..AccountInfo::default()
                            });
                        return Ok(account);
                    }
                    let diag = sanitize_diagnostics(&logs.join("\n"));
                    return Err(AuthError::ProviderFailed {
                        provider: "claude".into(),
                        message: if diag.is_empty() {
                            format!("claude auth login exited with status {exit}")
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

impl ClaudeActiveLogin {
    async fn write_code(&mut self, input: &str) -> Result<()> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(AuthError::InvalidInput(
                "claude login requires a non-empty authorization code".into(),
            ));
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| AuthError::ProviderFailed {
                provider: "claude".into(),
                message: "claude login stdin is no longer open".into(),
            })?;
        stdin.write_all(trimmed.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl ProviderAdapter for ClaudeProvider {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn binary_name(&self) -> &'static str {
        "claude"
    }

    fn default_method(&self) -> AuthMethod {
        AuthMethod::Oauth
    }

    fn supported_methods(&self) -> &'static [AuthMethod] {
        &[AuthMethod::Oauth]
    }

    fn supports_logout(&self) -> bool {
        true
    }

    async fn status(
        &self,
        ctx: &ProviderContext,
        timeout: Duration,
    ) -> Result<ProviderStatusReport> {
        let mut cmd = Command::new(&ctx.binary);
        cmd.args(["auth", "status"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ctx.apply_env(&mut cmd);
        process::configure_process_group(&mut cmd);
        let child = cmd.spawn()?;
        let pid = child.id();
        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(res) => res?,
            Err(_) => {
                if let Some(pid) = pid {
                    process::terminate_process_group(pid, Duration::from_millis(500)).await;
                }
                return Err(AuthError::Timeout("claude auth status timed out".into()));
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if let Some(parsed) = parse_claude_status(&stdout) {
            return Ok(parsed);
        }
        if output.status.success() {
            return Err(AuthError::Protocol(format!(
                "could not parse claude auth status JSON: {}",
                sanitize_diagnostics(&stdout)
            )));
        }
        Err(AuthError::ProviderFailed {
            provider: "claude".into(),
            message: sanitize_diagnostics(&format!("{stdout}\n{stderr}")),
        })
    }

    async fn logout(&self, ctx: &ProviderContext, timeout: Duration) -> Result<()> {
        let mut cmd = Command::new(&ctx.binary);
        cmd.args(["auth", "logout"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ctx.apply_env(&mut cmd);
        process::configure_process_group(&mut cmd);
        let child = cmd.spawn()?;
        let pid = child.id();
        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(res) => res?,
            Err(_) => {
                if let Some(pid) = pid {
                    process::terminate_process_group(pid, Duration::from_millis(500)).await;
                }
                return Err(AuthError::Timeout("claude auth logout timed out".into()));
            }
        };
        if output.status.success() {
            Ok(())
        } else {
            let msg = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            Err(AuthError::ProviderFailed {
                provider: "claude".into(),
                message: sanitize_diagnostics(&msg),
            })
        }
    }

    async fn start_session(
        &self,
        _method: AuthMethod,
        ctx: &ProviderContext,
        start_timeout: Duration,
    ) -> Result<Box<dyn ActiveLogin>> {
        let mut cmd = Command::new(&ctx.binary);
        cmd.args(["auth", "login"]);
        if ctx.claude_console {
            cmd.arg("--console");
        }
        if ctx.claude_sso {
            cmd.arg("--sso");
        }
        if let Some(email) = &ctx.claude_email {
            cmd.args(["--email", email]);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ctx.apply_env(&mut cmd);
        process::configure_process_group(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(AuthError::ProviderFailed {
                    provider: "claude".into(),
                    message: format!("failed to launch claude auth login: {e}"),
                });
            }
        };
        let stdin = child.stdin.take();
        let stdout = take_pipe(child.stdout.take(), "claude auth login stdout")?;
        let stderr = take_pipe(child.stderr.take(), "claude auth login stderr")?;

        let (tx, mut rx) = mpsc::channel::<String>(64);
        let tx_out = tx.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if tx_out.send(line).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
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
                provider: "claude".into(),
                message: format!(
                    "claude auth login exited without printing an auth URL: {}",
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
                    "timed out waiting for claude auth URL".into(),
                ));
            }
        };

        let challenge = AuthChallenge {
            auth_url,
            user_code: None,
            expected_input: ExpectedInput {
                kind: ExpectedInputKind::Code,
                required: true,
                prompt:
                    "Open the URL, sign in, and paste the authorization code shown on the page."
                        .into(),
            },
            callback_origin: None,
        };

        Ok(Box::new(ClaudeActiveLogin {
            child,
            stdin,
            output_rx: rx,
            ctx: ctx.clone(),
            challenge,
        }))
    }
}

pub(crate) fn parse_claude_status(raw: &str) -> Option<ProviderStatusReport> {
    let json_slice = extract_json_object(raw)?;
    let value: Value = serde_json::from_str(json_slice).ok()?;
    let logged_in = value.get("loggedIn").and_then(Value::as_bool)?;
    let status = if logged_in {
        ProviderAuthState::Authenticated
    } else {
        ProviderAuthState::Unauthenticated
    };
    let account = if logged_in {
        Some(AccountInfo {
            email: value
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_owned),
            plan: value
                .get("subscriptionType")
                .or_else(|| value.get("billingType"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            auth_method: value
                .get("authMethod")
                .and_then(Value::as_str)
                .map(str::to_owned),
            workspace: value
                .get("orgName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            usage_buckets: Vec::new(),
        })
    } else {
        None
    };
    Some(ProviderStatusReport {
        schema_version: SCHEMA_VERSION,
        provider: "claude".into(),
        status,
        account,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_logged_out_and_logged_in_claude_status_with_trailing_noise() {
        let out_raw = "{\r\n\"loggedIn\":false,\r\n\"authMethod\":\"none\"\r\n}\r\nB ";
        let report = parse_claude_status(out_raw).unwrap();
        assert_eq!(report.status, ProviderAuthState::Unauthenticated);
        assert!(report.account.is_none());

        let in_raw = r#"{"loggedIn":true,"authMethod":"claudeai","email":"a@b.com","subscriptionType":"max","orgName":"Team"}"#;
        let report = parse_claude_status(in_raw).unwrap();
        assert_eq!(report.status, ProviderAuthState::Authenticated);
        let acct = report.account.unwrap();
        assert_eq!(acct.email.as_deref(), Some("a@b.com"));
        assert_eq!(acct.plan.as_deref(), Some("max"));
        assert_eq!(acct.workspace.as_deref(), Some("Team"));

        let billing_raw = r#"{"loggedIn":true,"authMethod":"console","billingType":"usage"}"#;
        let report2 = parse_claude_status(billing_raw).unwrap();
        assert_eq!(report2.account.unwrap().plan.as_deref(), Some("usage"));

        assert!(parse_claude_status("garbage").is_none());
    }
}
