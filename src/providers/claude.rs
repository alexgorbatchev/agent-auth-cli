use crate::{
    error::{AuthError, Result},
    process,
    protocol::{
        AccountInfo, AuthChallenge, AuthMethod, ExpectedInput, ExpectedInputKind, ExtraUsageInfo,
        ProviderAuthState, ProviderStatusReport, ProviderUsageReport, ProviderUsageState,
        SCHEMA_VERSION, UsageBucket,
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
        if looks_like_callback_url(trimmed) {
            return Err(AuthError::InvalidInput(
                "claude login does not accept an OAuth callback URL; paste the full `code#state` string shown on the authorization page"
                    .into(),
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

pub(crate) fn looks_like_callback_url(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return true;
    }
    if !trimmed.contains(char::is_whitespace)
        && let Ok(parsed) = url::Url::parse(&format!("https://{trimmed}"))
        && let Some(host) = parsed.host_str()
        && (host.contains('.') || host == "localhost")
    {
        let path = parsed.path().to_ascii_lowercase();
        let has_oauth_path = path.contains("/oauth") || path.contains("callback");
        let has_code_query = parsed.query_pairs().any(|(k, _)| k == "code");
        if has_oauth_path || has_code_query {
            return true;
        }
    }
    false
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

    async fn usage(&self, ctx: &ProviderContext, timeout: Duration) -> Result<ProviderUsageReport> {
        let status = self.status(ctx, timeout).await?;
        if status.status != ProviderAuthState::Authenticated {
            return Ok(ProviderUsageReport {
                schema_version: SCHEMA_VERSION,
                provider: self.id().to_owned(),
                status: ProviderUsageState::Unauthenticated,
                plan: None,
                buckets: Vec::new(),
                extra_usage: None,
                error: None,
            });
        }
        let fallback_plan = status.account.and_then(|a| a.plan);

        let mut cmd = Command::new(&ctx.binary);
        cmd.args([
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--no-session-persistence",
            "--setting-sources",
            "",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        ctx.apply_env(&mut cmd);
        process::configure_process_group(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(AuthError::ProviderFailed {
                    provider: "claude".into(),
                    message: format!("failed to launch claude usage probe: {e}"),
                });
            }
        };
        let pid = child.id();
        let mut stdin = take_pipe(child.stdin.take(), "claude usage stdin")?;
        let stdout = take_pipe(child.stdout.take(), "claude usage stdout")?;
        let mut stderr = take_pipe(child.stderr.take(), "claude usage stderr")?;

        let init_req = serde_json::json!({
            "type": "control_request",
            "request_id": "init-1",
            "request": { "subtype": "initialize" }
        });
        let usage_req = serde_json::json!({
            "type": "control_request",
            "request_id": "usage-1",
            "request": { "subtype": "get_usage", "skip_behaviors": true }
        });
        let payload = format!("{init_req}\n{usage_req}\n");
        if let Err(err) = stdin.write_all(payload.as_bytes()).await {
            if let Some(pid) = pid {
                process::terminate_process_group(pid, Duration::from_millis(300)).await;
            }
            let _ = child.wait().await;
            return Err(AuthError::Io(err));
        }
        let _ = stdin.flush().await;

        let read_fut = async {
            let mut lines = BufReader::new(stdout).lines();
            while let Some(line) = lines.next_line().await? {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(msg) = serde_json::from_str::<Value>(trimmed) else {
                    continue;
                };
                if msg.get("type").and_then(Value::as_str) == Some("control_response")
                    && let Some(resp) = msg.get("response")
                    && resp.get("request_id").and_then(Value::as_str) == Some("usage-1")
                {
                    if resp.get("subtype").and_then(Value::as_str) == Some("error") {
                        let detail = resp
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("claude get_usage failed")
                            .to_owned();
                        return Err(AuthError::ProviderFailed {
                            provider: "claude".into(),
                            message: detail,
                        });
                    }
                    let body = resp.get("response").cloned().unwrap_or(Value::Null);
                    return Ok(parse_claude_usage(&body, fallback_plan));
                }
            }
            let mut err_buf = String::new();
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut err_buf).await;
            Err(AuthError::ProviderFailed {
                provider: "claude".into(),
                message: if err_buf.trim().is_empty() {
                    "claude usage probe exited before answering get_usage".into()
                } else {
                    sanitize_diagnostics(&err_buf)
                },
            })
        };

        let result = tokio::time::timeout(timeout, read_fut).await;
        drop(stdin);
        if let Some(pid) = pid {
            process::terminate_process_group(pid, Duration::from_millis(300)).await;
        }
        let _ = child.wait().await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(AuthError::Timeout("claude usage probe timed out".into())),
        }
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
                    "Open the URL, sign in, and paste the full code#state string shown on the authorization page (not the callback URL)."
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

pub(crate) fn parse_claude_usage(
    body: &Value,
    fallback_plan: Option<String>,
) -> ProviderUsageReport {
    let plan = body
        .get("subscription_type")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or(fallback_plan);
    let available = body
        .get("rate_limits_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let Some(limits) = body.get("rate_limits").filter(|v| v.is_object()) else {
        return ProviderUsageReport {
            schema_version: SCHEMA_VERSION,
            provider: "claude".into(),
            status: ProviderUsageState::Unavailable,
            plan,
            buckets: Vec::new(),
            extra_usage: None,
            error: None,
        };
    };
    if !available && limits.as_object().is_none_or(|m| m.is_empty()) {
        return ProviderUsageReport {
            schema_version: SCHEMA_VERSION,
            provider: "claude".into(),
            status: ProviderUsageState::Unavailable,
            plan,
            buckets: Vec::new(),
            extra_usage: None,
            error: None,
        };
    }

    let mut buckets = Vec::new();
    for (field, id, label, window) in [
        ("five_hour", "claude-5h", "Five Hour Limit", "5h"),
        ("seven_day", "claude-weekly", "Weekly Limit", "weekly"),
        (
            "seven_day_opus",
            "claude-opus-weekly",
            "Opus Weekly Limit",
            "weekly",
        ),
        (
            "seven_day_sonnet",
            "claude-sonnet-weekly",
            "Sonnet Weekly Limit",
            "weekly",
        ),
        (
            "seven_day_oauth_apps",
            "claude-oauth-apps-weekly",
            "OAuth Apps Weekly Limit",
            "weekly",
        ),
    ] {
        if let Some(win) = limits.get(field).filter(|v| v.is_object()) {
            let used_fraction = win
                .get("utilization")
                .and_then(Value::as_f64)
                .map(|p| (p / 100.0).clamp(0.0, 1.0));
            let remaining_fraction = used_fraction.map(|u| (1.0 - u).clamp(0.0, 1.0));
            let reset_time = win
                .get("resets_at")
                .and_then(Value::as_str)
                .map(str::to_owned);
            buckets.push(UsageBucket {
                id: id.into(),
                group: Some("claude".into()),
                label: Some(label.into()),
                window: Some(window.into()),
                used_fraction,
                remaining_fraction,
                reset_time,
            });
        }
    }

    if let Some(scoped) = limits.get("model_scoped").and_then(Value::as_array) {
        for item in scoped {
            let Some(name) = item.get("display_name").and_then(Value::as_str) else {
                continue;
            };
            let slug: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect();
            let used_fraction = item
                .get("utilization")
                .and_then(Value::as_f64)
                .map(|p| (p / 100.0).clamp(0.0, 1.0));
            let remaining_fraction = used_fraction.map(|u| (1.0 - u).clamp(0.0, 1.0));
            let reset_time = item
                .get("resets_at")
                .and_then(Value::as_str)
                .map(str::to_owned);
            buckets.push(UsageBucket {
                id: format!("claude-{slug}-weekly"),
                group: Some("claude".into()),
                label: Some(format!("{name} Weekly Limit")),
                window: Some("weekly".into()),
                used_fraction,
                remaining_fraction,
                reset_time,
            });
        }
    }

    let extra_usage = limits
        .get("extra_usage")
        .filter(|v| v.is_object())
        .map(|ex| {
            let used_fraction = ex
                .get("utilization")
                .and_then(Value::as_f64)
                .map(|p| (p / 100.0).clamp(0.0, 1.0));
            ExtraUsageInfo {
                enabled: ex
                    .get("is_enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                unlimited: false,
                used_credits: ex.get("used_credits").and_then(Value::as_f64),
                monthly_limit: ex.get("monthly_limit").and_then(Value::as_f64),
                balance: None,
                currency: ex
                    .get("currency")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                used_fraction,
            }
        });

    ProviderUsageReport {
        schema_version: SCHEMA_VERSION,
        provider: "claude".into(),
        status: ProviderUsageState::Available,
        plan,
        buckets,
        extra_usage,
        error: None,
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

        let usage_raw = serde_json::json!({
            "subscription_type": "max",
            "rate_limits_available": true,
            "rate_limits": {
                "five_hour": { "utilization": 40.0, "resets_at": "2026-11-21T20:00:00Z" },
                "seven_day": { "utilization": 15.0, "resets_at": "2026-11-28T00:00:00Z" },
                "seven_day_opus": { "utilization": 10.0, "resets_at": "2026-11-28T00:00:00Z" },
                "seven_day_sonnet": { "utilization": 5.0, "resets_at": "2026-11-28T00:00:00Z" },
                "seven_day_oauth_apps": { "utilization": 0.0, "resets_at": "2026-11-28T00:00:00Z" },
                "model_scoped": [
                    { "display_name": "Sonnet 5", "utilization": 20.0, "resets_at": "2026-11-28T00:00:00Z" }
                ],
                "extra_usage": {
                    "is_enabled": true,
                    "monthly_limit": 5000.0,
                    "used_credits": 1200.0,
                    "utilization": 24.0,
                    "currency": "USD"
                }
            }
        });
        let usage = parse_claude_usage(&usage_raw, None);
        assert_eq!(usage.status, ProviderUsageState::Available);
        assert_eq!(usage.plan.as_deref(), Some("max"));
        assert_eq!(usage.buckets.len(), 6);
        assert_eq!(usage.buckets[0].id, "claude-5h");
        assert!((usage.buckets[0].remaining_fraction.unwrap() - 0.60).abs() < 1e-6);
        assert_eq!(usage.buckets[5].id, "claude-sonnet-5-weekly");
        assert!(usage.extra_usage.unwrap().enabled);

        let unavailable = parse_claude_usage(
            &serde_json::json!({"subscription_type": null, "rate_limits_available": false, "rate_limits": null}),
            None,
        );
        assert_eq!(unavailable.status, ProviderUsageState::Unavailable);
    }

    #[test]
    fn detects_claude_oauth_callback_urls_without_rejecting_codes() {
        assert!(looks_like_callback_url(
            "https://platform.claude.com/oauth/code/callback?code=abc&state=def"
        ));
        assert!(looks_like_callback_url(
            "HTTPS://console.anthropic.com/oauth/code/callback?code=abc&state=def"
        ));
        assert!(looks_like_callback_url(
            "http://localhost:54321/callback?code=abc&state=def"
        ));
        assert!(looks_like_callback_url(
            "platform.claude.com/oauth/code/callback?code=abc&state=def"
        ));
        assert!(looks_like_callback_url("localhost:54321/callback?code=abc"));

        assert!(!looks_like_callback_url(""));
        assert!(!looks_like_callback_url("   "));
        assert!(!looks_like_callback_url("good-code#s123"));
        assert!(!looks_like_callback_url("bad-code"));
        assert!(!looks_like_callback_url("AbC123_+/==#XyZ456_+/=="));
    }
}
