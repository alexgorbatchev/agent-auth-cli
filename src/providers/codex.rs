use crate::{
    error::{AuthError, Result},
    process,
    protocol::{
        AccountInfo, AuthChallenge, AuthMethod, ExpectedInput, ExpectedInputKind, ExtraUsageInfo,
        ProviderAuthState, ProviderStatusReport, ProviderUsageReport, ProviderUsageState,
        SCHEMA_VERSION, UsageBucket, format_rfc3339,
    },
    providers::{
        ActiveLogin, LoginCommand, ProviderAdapter, ProviderContext, required_json_str,
        sanitize_diagnostics, take_pipe,
    },
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::mpsc,
};
use url::Url;

pub struct CodexProvider;

struct AppServerClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl AppServerClient {
    async fn spawn(ctx: &ProviderContext) -> Result<Self> {
        let mut cmd = Command::new(&ctx.binary);
        cmd.args(["app-server", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        ctx.apply_env(&mut cmd);
        if let Some(home) = &ctx.home {
            cmd.env("CODEX_HOME", home.join(".codex"));
        }
        process::configure_process_group(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(AuthError::ProviderFailed {
                    provider: "codex".into(),
                    message: format!("failed to launch codex app-server: {e}"),
                });
            }
        };
        let stdin = take_pipe(child.stdin.take(), "codex app-server stdin")?;
        let stdout = take_pipe(child.stdout.take(), "codex app-server stdout")?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    async fn initialize(&mut self, timeout: Duration) -> Result<()> {
        let init_params = json!({
            "clientInfo": {
                "name": "agent-auth",
                "version": env!("CARGO_PKG_VERSION"),
            }
        });
        let _ = self.request("initialize", init_params, timeout).await?;
        self.notify("initialized", json!({})).await
    }

    async fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&payload)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&payload)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;

        let read_fut = async {
            let mut buf = String::new();
            loop {
                buf.clear();
                let n = self.stdout.read_line(&mut buf).await?;
                if n == 0 {
                    return Err(AuthError::ProviderFailed {
                        provider: "codex".into(),
                        message: format!("codex app-server closed stream waiting for {method}"),
                    });
                }
                let trimmed = buf.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let msg: Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if msg.get("id").and_then(Value::as_u64) == Some(id) {
                    if let Some(err) = msg.get("error") {
                        let text = err
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown codex JSON-RPC error")
                            .to_owned();
                        return Err(classify_codex_rpc_error(&text));
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
            }
        };

        tokio::time::timeout(timeout, read_fut)
            .await
            .map_err(|_| AuthError::Timeout(format!("codex app-server timed out on {method}")))?
    }

    async fn read_account(&mut self, timeout: Duration) -> Result<Option<AccountInfo>> {
        let result = self.request("account/read", json!({}), timeout).await?;
        Ok(parse_codex_account(&result))
    }

    async fn shutdown(mut self) {
        if let Some(pid) = self.child.id() {
            process::terminate_process_group(pid, Duration::from_millis(500)).await;
        }
        let _ = self.child.wait().await;
    }
}

pub struct CodexActiveLogin {
    client: AppServerClient,
    login_id: String,
    method: AuthMethod,
    challenge: AuthChallenge,
}

#[async_trait]
impl ActiveLogin for CodexActiveLogin {
    fn challenge(&self) -> &AuthChallenge {
        &self.challenge
    }

    async fn run(
        mut self: Box<Self>,
        mut commands: mpsc::Receiver<LoginCommand>,
    ) -> Result<AccountInfo> {
        let mut line = String::new();
        loop {
            line.clear();
            tokio::select! {
                read_res = self.client.stdout.read_line(&mut line) => {
                    let n = match read_res {
                        Ok(n) => n,
                        Err(e) => {
                            self.client.shutdown().await;
                            return Err(AuthError::Io(e));
                        }
                    };
                    if n == 0 {
                        self.client.shutdown().await;
                        return Err(AuthError::ProviderFailed {
                            provider: "codex".into(),
                            message: "codex app-server exited before login completed".into(),
                        });
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let Ok(msg) = serde_json::from_str::<Value>(trimmed) else {
                        continue;
                    };
                    if msg.get("method").and_then(Value::as_str) == Some("account/login/completed") {
                        let params = msg.get("params").cloned().unwrap_or(Value::Null);
                        let event_id = params.get("loginId").and_then(Value::as_str);
                        if event_id.is_some() && event_id != Some(self.login_id.as_str()) {
                            continue;
                        }
                        let success = params.get("success").and_then(Value::as_bool).unwrap_or(false);
                        if success {
                            let account = self
                                .client
                                .read_account(Duration::from_secs(10))
                                .await
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| AccountInfo {
                                    auth_method: Some("chatgpt".into()),
                                    ..AccountInfo::default()
                                });
                            self.client.shutdown().await;
                            return Ok(account);
                        }
                        let reason = params
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("login failed")
                            .to_owned();
                        self.client.shutdown().await;
                        return Err(AuthError::ProviderFailed {
                            provider: "codex".into(),
                            message: reason,
                        });
                    }
                }
                cmd = commands.recv() => {
                    match cmd {
                        Some(LoginCommand::Submit { input, reply }) => {
                            let res = self.handle_submit(&input).await;
                            let _ = reply.send(res);
                        }
                        Some(LoginCommand::Cancel { reply }) => {
                            let _ = self
                                .client
                                .request(
                                    "account/login/cancel",
                                    json!({ "loginId": self.login_id }),
                                    Duration::from_secs(3),
                                )
                                .await;
                            self.client.shutdown().await;
                            let _ = reply.send(Ok(()));
                            return Err(AuthError::Cancelled);
                        }
                        None => {
                            self.client.shutdown().await;
                            return Err(AuthError::Cancelled);
                        }
                    }
                }
            }
        }
    }
}

impl CodexActiveLogin {
    async fn handle_submit(&self, input: &str) -> Result<()> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        if self.method == AuthMethod::Device {
            return Err(AuthError::InvalidInput(
                "codex device login does not accept pasted input; enter the user_code in your browser and run `agent-auth session wait`".into(),
            ));
        }
        let expected_origin = self
            .challenge
            .callback_origin
            .as_deref()
            .unwrap_or("http://127.0.0.1:1455/auth/callback");
        let parsed = validate_codex_callback_url(trimmed, expected_origin)?;
        replay_local_callback(&parsed).await
    }
}

#[async_trait]
impl ProviderAdapter for CodexProvider {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn binary_name(&self) -> &'static str {
        "codex"
    }

    fn default_method(&self) -> AuthMethod {
        AuthMethod::Device
    }

    fn supported_methods(&self) -> &'static [AuthMethod] {
        &[AuthMethod::Device, AuthMethod::Oauth]
    }

    fn supports_logout(&self) -> bool {
        true
    }

    async fn status(
        &self,
        ctx: &ProviderContext,
        timeout: Duration,
    ) -> Result<ProviderStatusReport> {
        let mut client = AppServerClient::spawn(ctx).await?;
        let init_res = client.initialize(timeout).await;
        if let Err(err) = init_res {
            client.shutdown().await;
            return Err(err);
        }
        let account_res = client.read_account(timeout).await;
        client.shutdown().await;
        let account = account_res?;
        let status = if account.is_some() {
            ProviderAuthState::Authenticated
        } else {
            ProviderAuthState::Unauthenticated
        };
        Ok(ProviderStatusReport {
            schema_version: SCHEMA_VERSION,
            provider: self.id().to_owned(),
            status,
            account,
            error: None,
        })
    }

    async fn usage(&self, ctx: &ProviderContext, timeout: Duration) -> Result<ProviderUsageReport> {
        let mut client = AppServerClient::spawn(ctx).await?;
        if let Err(err) = client.initialize(timeout).await {
            client.shutdown().await;
            return Err(err);
        }
        let account = match client.read_account(timeout).await {
            Ok(acct) => acct,
            Err(err) => {
                client.shutdown().await;
                return Err(err);
            }
        };
        let Some(account) = account else {
            client.shutdown().await;
            return Ok(ProviderUsageReport {
                schema_version: SCHEMA_VERSION,
                provider: self.id().to_owned(),
                status: ProviderUsageState::Unauthenticated,
                plan: None,
                buckets: Vec::new(),
                extra_usage: None,
                error: None,
            });
        };
        if account.auth_method.as_deref() != Some("chatgpt") {
            client.shutdown().await;
            return Ok(ProviderUsageReport {
                schema_version: SCHEMA_VERSION,
                provider: self.id().to_owned(),
                status: ProviderUsageState::Unavailable,
                plan: account.plan,
                buckets: Vec::new(),
                extra_usage: None,
                error: None,
            });
        }
        let limits_res = client
            .request(
                "account/rateLimits/read",
                json!({ "excludeResetCreditDetails": true }),
                timeout,
            )
            .await;
        client.shutdown().await;
        let result = limits_res?;
        Ok(parse_codex_usage(&result, account.plan))
    }

    async fn logout(&self, ctx: &ProviderContext, timeout: Duration) -> Result<()> {
        let mut cmd = Command::new(&ctx.binary);
        cmd.arg("logout")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ctx.apply_env(&mut cmd);
        if let Some(home) = &ctx.home {
            cmd.env("CODEX_HOME", home.join(".codex"));
        }
        process::configure_process_group(&mut cmd);
        let child = cmd.spawn()?;
        let pid = child.id();
        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(res) => res?,
            Err(_) => {
                if let Some(pid) = pid {
                    process::terminate_process_group(pid, Duration::from_millis(500)).await;
                }
                return Err(AuthError::Timeout("codex logout timed out".into()));
            }
        };
        if output.status.success() {
            Ok(())
        } else {
            let msg = format!(
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            Err(AuthError::ProviderFailed {
                provider: "codex".into(),
                message: sanitize_diagnostics(&msg),
            })
        }
    }

    async fn start_session(
        &self,
        method: AuthMethod,
        ctx: &ProviderContext,
        start_timeout: Duration,
    ) -> Result<Box<dyn ActiveLogin>> {
        let mut client = AppServerClient::spawn(ctx).await?;
        if let Err(err) = client.initialize(start_timeout).await {
            client.shutdown().await;
            return Err(err);
        }
        let params = match method {
            AuthMethod::Device => json!({ "type": "chatgptDeviceCode" }),
            AuthMethod::Oauth => json!({ "type": "chatgpt" }),
        };
        let result = match client
            .request("account/login/start", params, start_timeout)
            .await
        {
            Ok(v) => v,
            Err(err) => {
                client.shutdown().await;
                return Err(err);
            }
        };

        let login_id = required_json_str(&result, "loginId", "codex login response")?;

        let challenge = match method {
            AuthMethod::Device => {
                let auth_url =
                    required_json_str(&result, "verificationUrl", "codex device response")?;
                let user_code = required_json_str(&result, "userCode", "codex device response")?;
                AuthChallenge {
                    auth_url,
                    user_code: Some(user_code),
                    expected_input: ExpectedInput {
                        kind: ExpectedInputKind::None,
                        required: false,
                        prompt: "Open the URL, sign in, and enter the one-time code. Then call `agent-auth session wait <session-id>`.".into(),
                    },
                    callback_origin: None,
                }
            }
            AuthMethod::Oauth => {
                let auth_url = required_json_str(&result, "authUrl", "codex oauth response")?;
                let callback_origin = match extract_redirect_uri(&auth_url) {
                    Some(u) => u,
                    None => "http://127.0.0.1:1455/auth/callback".into(),
                };
                AuthChallenge {
                    auth_url,
                    user_code: None,
                    expected_input: ExpectedInput {
                        kind: ExpectedInputKind::CallbackUrlOptional,
                        required: false,
                        prompt: "Open the URL and sign in. On this machine it completes automatically; on another machine, paste the final http://127.0.0.1:1455/auth/callback?... URL back.".into(),
                    },
                    callback_origin: Some(callback_origin),
                }
            }
        };

        Ok(Box::new(CodexActiveLogin {
            client,
            login_id,
            method,
            challenge,
        }))
    }
}

pub(crate) fn parse_codex_usage(
    result: &Value,
    fallback_plan: Option<String>,
) -> ProviderUsageReport {
    let mut snapshots: Vec<(String, &Value)> = Vec::new();
    if let Some(map) = result.get("rateLimitsByLimitId").and_then(Value::as_object) {
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();
        for key in keys {
            if let Some(val) = map.get(key) {
                snapshots.push((key.clone(), val));
            }
        }
    }
    if snapshots.is_empty()
        && let Some(single) = result.get("rateLimits")
        && single.is_object()
    {
        let id = single
            .get("limitId")
            .and_then(Value::as_str)
            .unwrap_or("codex")
            .to_owned();
        snapshots.push((id, single));
    }

    let mut plan = fallback_plan;
    let mut buckets = Vec::new();
    let mut extra_usage = None;

    for (key, snap) in snapshots {
        if plan.is_none() {
            plan = snap
                .get("planType")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        let limit_id = snap
            .get("limitId")
            .and_then(Value::as_str)
            .unwrap_or(key.as_str());
        let group = snap
            .get("limitName")
            .and_then(Value::as_str)
            .unwrap_or(limit_id)
            .to_owned();

        for (slot, field) in [("primary", "primary"), ("secondary", "secondary")] {
            if let Some(win) = snap.get(field).filter(|v| v.is_object()) {
                let mins = win.get("windowDurationMins").and_then(Value::as_u64);
                let window = mins
                    .map(format_window_minutes)
                    .unwrap_or_else(|| slot.into());
                let used_pct = win.get("usedPercent").and_then(Value::as_f64);
                let used_fraction = used_pct.map(|p| (p / 100.0).clamp(0.0, 1.0));
                let remaining_fraction = used_fraction.map(|u| (1.0 - u).clamp(0.0, 1.0));
                let reset_time = win
                    .get("resetsAt")
                    .and_then(Value::as_i64)
                    .and_then(|ts| time::OffsetDateTime::from_unix_timestamp(ts).ok())
                    .map(format_rfc3339);
                let id = format!("{limit_id}-{window}");
                let label = format!("{group} ({window})");
                buckets.push(UsageBucket {
                    id,
                    group: Some(group.clone()),
                    label: Some(label),
                    window: Some(window),
                    used_fraction,
                    remaining_fraction,
                    reset_time,
                });
            }
        }

        if extra_usage.is_none()
            && let Some(credits) = snap.get("credits").filter(|v| v.is_object())
        {
            let has_credits = credits
                .get("hasCredits")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let unlimited = credits
                .get("unlimited")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let balance = credits
                .get("balance")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if has_credits
                || unlimited
                || balance
                    .as_deref()
                    .is_some_and(|b| b != "0" && !b.is_empty())
            {
                extra_usage = Some(ExtraUsageInfo {
                    enabled: has_credits || unlimited,
                    unlimited,
                    used_credits: None,
                    monthly_limit: None,
                    balance,
                    currency: None,
                    used_fraction: None,
                });
            }
        }
    }

    ProviderUsageReport {
        schema_version: SCHEMA_VERSION,
        provider: "codex".into(),
        status: ProviderUsageState::Available,
        plan,
        buckets,
        extra_usage,
        error: None,
    }
}

fn format_window_minutes(mins: u64) -> String {
    match mins {
        300 => "5h".into(),
        1440 => "daily".into(),
        10080 => "weekly".into(),
        m if m > 0 && m.is_multiple_of(1440) => format!("{}d", m / 1440),
        m if m > 0 && m.is_multiple_of(60) => format!("{}h", m / 60),
        m => format!("{m}m"),
    }
}

pub(crate) fn parse_codex_account(result: &Value) -> Option<AccountInfo> {
    let account = result.get("account")?;
    if account.is_null() {
        return None;
    }
    let auth_method = account
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let email = account
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let plan = account
        .get("planType")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let workspace = account
        .get("workspaceName")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(AccountInfo {
        email,
        plan,
        auth_method,
        workspace,
        usage_buckets: Vec::new(),
    })
}

pub(crate) fn classify_codex_rpc_error(message: &str) -> AuthError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("already in use") || lower.contains("address in use") {
        let port = extract_port_from_message(message).unwrap_or(1455);
        return AuthError::CallbackPortInUse {
            provider: "codex".into(),
            port,
        };
    }
    AuthError::ProviderFailed {
        provider: "codex".into(),
        message: message.to_owned(),
    }
}

fn extract_port_from_message(message: &str) -> Option<u16> {
    for token in message.split(|c: char| !c.is_ascii_digit()) {
        if let Ok(port) = token.parse::<u16>()
            && port >= 1024
        {
            return Some(port);
        }
    }
    None
}

pub(crate) fn extract_redirect_uri(auth_url: &str) -> Option<String> {
    let parsed = Url::parse(auth_url).ok()?;
    parsed
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.into_owned())
}

/// Strictly validate a user-pasted Codex callback URL before replaying it locally (SSRF guard).
pub(crate) fn validate_codex_callback_url(raw: &str, expected_redirect_uri: &str) -> Result<Url> {
    let expected = Url::parse(expected_redirect_uri)
        .map_err(|_| AuthError::Protocol("invalid expected redirect_uri".into()))?;
    let expected_port = expected.port_or_known_default().unwrap_or(1455);
    let expected_path = expected.path();

    let url = Url::parse(raw).map_err(|_| {
        AuthError::InvalidInput(
            "callback input must be a valid http://127.0.0.1 callback URL".into(),
        )
    })?;
    if url.scheme() != "http" {
        return Err(AuthError::InvalidInput(
            "callback URL must use http:// loopback scheme".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AuthError::InvalidInput(
            "callback URL must not contain credentials".into(),
        ));
    }
    match url.host_str() {
        Some("127.0.0.1") | Some("localhost") => {}
        _ => {
            return Err(AuthError::InvalidInput(
                "callback URL host must be 127.0.0.1 or localhost".into(),
            ));
        }
    }
    let port = url.port_or_known_default().unwrap_or(0);
    if port != expected_port {
        return Err(AuthError::InvalidInput(format!(
            "callback URL port {port} does not match expected local callback port {expected_port}"
        )));
    }
    if url.path() != expected_path {
        return Err(AuthError::InvalidInput(format!(
            "callback URL path {} does not match expected path {expected_path}",
            url.path()
        )));
    }
    Ok(url)
}

async fn replay_local_callback(url: &Url) -> Result<()> {
    let port = url.port_or_known_default().unwrap_or(1455);
    let mut path_and_query = url.path().to_owned();
    if let Some(q) = url.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| AuthError::Timeout(format!("timed out connecting to 127.0.0.1:{port}")))?
    .map_err(|e| AuthError::ProviderFailed {
        provider: "codex".into(),
        message: format!(
            "could not connect to local codex callback listener on 127.0.0.1:{port}: {e}"
        ),
    })?;

    let req = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut resp)).await;
    let first_line = String::from_utf8_lossy(&resp)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    if first_line.contains(" 200") || first_line.contains(" 302") || first_line.is_empty() {
        Ok(())
    } else {
        Err(AuthError::ProviderFailed {
            provider: "codex".into(),
            message: format!("local callback listener rejected callback: {first_line}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_callback_url_and_blocks_ssrf() {
        let expected = "http://127.0.0.1:1455/auth/callback";
        assert!(
            validate_codex_callback_url(
                "http://127.0.0.1:1455/auth/callback?code=abc&state=xyz",
                expected
            )
            .is_ok()
        );
        assert!(
            validate_codex_callback_url(
                "http://localhost:1455/auth/callback?code=abc&state=xyz",
                expected
            )
            .is_ok()
        );
        for bad in [
            "not-a-url",
            "https://127.0.0.1:1455/auth/callback?code=abc",
            "http://evil.example:1455/auth/callback?code=abc",
            "http://127.0.0.1:9999/auth/callback?code=abc",
            "http://127.0.0.1:1455/other?code=abc",
            "http://user:pass@127.0.0.1:1455/auth/callback?code=abc",
        ] {
            let err = validate_codex_callback_url(bad, expected).unwrap_err();
            assert_eq!(err.code(), "invalid_input", "input {bad} should fail");
        }
    }

    #[test]
    fn parses_account_and_classifies_port_conflict() {
        let res = json!({
            "account": {
                "type": "chatgpt",
                "email": "dev@example.com",
                "planType": "pro",
                "workspaceName": "Acme"
            }
        });
        let info = parse_codex_account(&res).unwrap();
        assert_eq!(info.email.as_deref(), Some("dev@example.com"));
        assert_eq!(info.plan.as_deref(), Some("pro"));
        assert_eq!(info.workspace.as_deref(), Some("Acme"));
        assert!(parse_codex_account(&json!({"account": null})).is_none());

        let err = classify_codex_rpc_error("Port 1455 is already in use");
        assert_eq!(err.code(), "callback_port_in_use");
        let other = classify_codex_rpc_error("backend rejected request");
        assert_eq!(other.code(), "provider_failed");

        let url = "https://auth.openai.com/oauth/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback&state=1";
        assert_eq!(
            extract_redirect_uri(url).as_deref(),
            Some("http://127.0.0.1:1455/auth/callback")
        );

        let usage_raw = json!({
            "rateLimits": {
                "limitId": "codex",
                "limitName": null,
                "planType": "promax",
                "primary": { "usedPercent": 86, "windowDurationMins": 10080, "resetsAt": 1795474367 },
                "secondary": { "usedPercent": 25, "windowDurationMins": 300, "resetsAt": 1795400000 },
                "credits": { "hasCredits": true, "unlimited": false, "balance": "12.50" }
            }
        });
        let usage = parse_codex_usage(&usage_raw, None);
        assert_eq!(usage.status, ProviderUsageState::Available);
        assert_eq!(usage.plan.as_deref(), Some("promax"));
        assert_eq!(usage.buckets.len(), 2);
        assert_eq!(usage.buckets[0].id, "codex-weekly");
        assert!((usage.buckets[0].used_fraction.unwrap() - 0.86).abs() < 1e-6);
        assert!((usage.buckets[0].remaining_fraction.unwrap() - 0.14).abs() < 1e-6);
        assert_eq!(usage.buckets[1].id, "codex-5h");
        assert_eq!(usage.extra_usage.unwrap().balance.as_deref(), Some("12.50"));

        assert_eq!(format_window_minutes(300), "5h");
        assert_eq!(format_window_minutes(1440), "daily");
        assert_eq!(format_window_minutes(10080), "weekly");
        assert_eq!(format_window_minutes(2880), "2d");
        assert_eq!(format_window_minutes(120), "2h");
        assert_eq!(format_window_minutes(45), "45m");
    }
}
