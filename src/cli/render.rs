use crate::{
    error::Result,
    protocol::{
        AccountInfo, ErrorDetail, ErrorEnvelope, ProviderAuthState, ProviderListReport,
        ProviderLogoutReport, ProviderStatusListReport, ProviderStatusReport, SCHEMA_VERSION,
        SessionListReport, SessionSnapshot, SessionState,
    },
};
use cli_command_kit::Mode;
use comfy_table::Table;
use std::{io::Write, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Human,
    Agent,
    Json,
}

impl OutputFormat {
    pub fn resolve(mode: Mode, json: bool) -> Self {
        if json {
            Self::Json
        } else if mode == Mode::Agent {
            Self::Agent
        } else {
            Self::Human
        }
    }
}

pub fn fold_text(text: &str, home: Option<&Path>) -> String {
    match home {
        Some(h) => cli_command_kit::fold_message(text, h),
        None => text.to_owned(),
    }
}

pub fn fold_path(path: &Path, home: Option<&Path>) -> String {
    match home {
        Some(h) => cli_command_kit::fold_home(path, h),
        None => path.display().to_string(),
    }
}

pub fn write_folded(out: &mut dyn Write, text: &str, home: Option<&Path>) -> Result<()> {
    let folded = fold_text(text, home);
    out.write_all(folded.as_bytes())?;
    Ok(())
}

pub fn render_provider_list(
    out: &mut dyn Write,
    report: &ProviderListReport,
    format: OutputFormat,
    home: Option<&Path>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let line = serde_json::to_string(report)?;
            write_folded(out, &format!("{line}\n"), home)
        }
        OutputFormat::Agent => {
            let mut buf = String::new();
            for p in &report.providers {
                let methods: Vec<&str> = p.supported_methods.iter().map(|m| m.as_str()).collect();
                buf.push_str(&format!(
                    "provider:{} binary:{} available:{} default_method:{} methods:{} supports_logout:{}\n",
                    p.id,
                    p.binary,
                    p.available,
                    p.default_method,
                    methods.join(","),
                    p.supports_logout
                ));
            }
            write_folded(out, &buf, home)
        }
        OutputFormat::Human => {
            let mut table = Table::new();
            table.set_header(vec![
                "Provider",
                "Binary",
                "Available",
                "Default Method",
                "Methods",
                "Logout",
            ]);
            for p in &report.providers {
                let methods: Vec<&str> = p.supported_methods.iter().map(|m| m.as_str()).collect();
                table.add_row(vec![
                    p.id.as_str(),
                    p.binary.as_str(),
                    if p.available { "yes" } else { "no" },
                    p.default_method.as_str(),
                    &methods.join(", "),
                    if p.supports_logout { "yes" } else { "no" },
                ]);
            }
            write_folded(out, &format!("{table}\n"), home)
        }
    }
}

pub fn render_provider_status(
    out: &mut dyn Write,
    report: &ProviderStatusReport,
    format: OutputFormat,
    home: Option<&Path>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let line = serde_json::to_string(report)?;
            write_folded(out, &format!("{line}\n"), home)
        }
        OutputFormat::Agent => {
            let mut buf = format!("provider:{}\nstatus:{}\n", report.provider, report.status);
            if let Some(acct) = &report.account {
                append_account_kv(&mut buf, acct);
            }
            if let Some(err) = &report.error {
                buf.push_str(&format!(
                    "error_code:{}\nerror_message:{}\n",
                    err.code, err.message
                ));
            }
            write_folded(out, &buf, home)
        }
        OutputFormat::Human => {
            let tag = match report.status {
                ProviderAuthState::Authenticated => "[OK]",
                ProviderAuthState::Unauthenticated => "[WARN]",
                ProviderAuthState::Error => "[ERR]",
            };
            let mut buf = format!("{tag} {}: {}\n", report.provider, report.status);
            if let Some(acct) = &report.account {
                append_account_human(&mut buf, acct);
            }
            if let Some(err) = &report.error {
                buf.push_str(&format!("  error: {} ({})\n", err.message, err.code));
            }
            write_folded(out, &buf, home)
        }
    }
}

pub fn render_provider_status_list(
    out: &mut dyn Write,
    report: &ProviderStatusListReport,
    format: OutputFormat,
    home: Option<&Path>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let line = serde_json::to_string(report)?;
            write_folded(out, &format!("{line}\n"), home)
        }
        OutputFormat::Agent => {
            let mut buf = String::new();
            for item in &report.providers {
                buf.push_str(&format!(
                    "provider:{} status:{}",
                    item.provider, item.status
                ));
                if let Some(acct) = &item.account {
                    if let Some(email) = &acct.email {
                        buf.push_str(&format!(" email:{email}"));
                    }
                    if let Some(plan) = &acct.plan {
                        buf.push_str(&format!(" plan:{plan}"));
                    }
                    if !acct.usage_buckets.is_empty() {
                        buf.push_str(&format!(" usage_buckets:{}", acct.usage_buckets.len()));
                    }
                }
                if let Some(err) = &item.error {
                    buf.push_str(&format!(" error_code:{}", err.code));
                }
                buf.push('\n');
            }
            write_folded(out, &buf, home)
        }
        OutputFormat::Human => {
            let mut table = Table::new();
            table.set_header(vec!["Provider", "Status", "Account", "Details"]);
            for item in &report.providers {
                let account_col = item
                    .account
                    .as_ref()
                    .and_then(|a| a.email.clone().or_else(|| a.auth_method.clone()))
                    .unwrap_or_else(|| "-".into());
                let details = if let Some(err) = &item.error {
                    err.message.clone()
                } else if let Some(acct) = &item.account {
                    summarize_account_details(acct)
                } else {
                    "-".into()
                };
                table.add_row(vec![
                    item.provider.as_str(),
                    item.status.as_str(),
                    &account_col,
                    &details,
                ]);
            }
            write_folded(out, &format!("{table}\n"), home)
        }
    }
}

pub fn render_provider_logout(
    out: &mut dyn Write,
    report: &ProviderLogoutReport,
    format: OutputFormat,
    home: Option<&Path>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let line = serde_json::to_string(report)?;
            write_folded(out, &format!("{line}\n"), home)
        }
        OutputFormat::Agent => {
            let text = format!("provider:{}\nstatus:{}\n", report.provider, report.status);
            write_folded(out, &text, home)
        }
        OutputFormat::Human => {
            let text = format!("[OK] {}: {}\n", report.provider, report.status);
            write_folded(out, &text, home)
        }
    }
}

pub fn render_session_snapshot(
    out: &mut dyn Write,
    snap: &SessionSnapshot,
    format: OutputFormat,
    home: Option<&Path>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let line = serde_json::to_string(snap)?;
            write_folded(out, &format!("{line}\n"), home)
        }
        OutputFormat::Agent => {
            let mut buf = format!(
                "session_id:{}\nprovider:{}\nmethod:{}\nstatus:{}\n",
                snap.session_id, snap.provider, snap.method, snap.status
            );
            if let Some(url) = &snap.auth_url {
                buf.push_str(&format!("auth_url:{url}\n"));
            }
            if let Some(code) = &snap.user_code {
                buf.push_str(&format!("user_code:{code}\n"));
            }
            if let Some(expected) = &snap.expected_input {
                buf.push_str(&format!(
                    "expected_input:{}\ninput_required:{}\nprompt:{}\n",
                    expected.kind, expected.required, expected.prompt
                ));
            }
            if let Some(acct) = &snap.account {
                append_account_kv(&mut buf, acct);
            }
            buf.push_str(&format!("expires_at:{}\n", snap.expires_at));
            if let Some(err) = &snap.error {
                buf.push_str(&format!(
                    "error_code:{}\nerror_message:{}\n",
                    err.code, err.message
                ));
            }
            write_folded(out, &buf, home)
        }
        OutputFormat::Human => {
            let tag = match snap.status {
                SessionState::Authenticated => "[OK]",
                SessionState::AwaitingInput | SessionState::Starting | SessionState::Exchanging => {
                    "[PENDING]"
                }
                SessionState::Cancelled => "[INFO]",
                SessionState::Failed | SessionState::Expired => "[ERR]",
            };
            let mut buf = format!(
                "{tag} Session {} ({}, {}): {}\n",
                snap.session_id, snap.provider, snap.method, snap.status
            );
            if let Some(url) = &snap.auth_url {
                buf.push_str(&format!("  Auth URL:  {url}\n"));
            }
            if let Some(code) = &snap.user_code {
                buf.push_str(&format!("  User Code: {code}\n"));
            }
            if let Some(expected) = &snap.expected_input
                && !snap.status.is_terminal()
            {
                buf.push_str(&format!("  Next:      {}\n", expected.prompt));
            }
            if let Some(acct) = &snap.account {
                append_account_human(&mut buf, acct);
            }
            buf.push_str(&format!("  Expires:   {}\n", snap.expires_at));
            if let Some(err) = &snap.error {
                buf.push_str(&format!("  Error:     {} ({})\n", err.message, err.code));
            }
            write_folded(out, &buf, home)
        }
    }
}

pub fn render_session_list(
    out: &mut dyn Write,
    report: &SessionListReport,
    format: OutputFormat,
    home: Option<&Path>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let line = serde_json::to_string(report)?;
            write_folded(out, &format!("{line}\n"), home)
        }
        OutputFormat::Agent => {
            if report.sessions.is_empty() {
                return write_folded(out, "sessions:0\n", home);
            }
            let mut buf = String::new();
            for s in &report.sessions {
                buf.push_str(&format!(
                    "session_id:{} provider:{} method:{} status:{} expires_at:{}\n",
                    s.session_id, s.provider, s.method, s.status, s.expires_at
                ));
            }
            write_folded(out, &buf, home)
        }
        OutputFormat::Human => {
            if report.sessions.is_empty() {
                return write_folded(out, "[INFO] No active sessions.\n", home);
            }
            let mut table = Table::new();
            table.set_header(vec![
                "Session ID",
                "Provider",
                "Method",
                "Status",
                "Expires",
            ]);
            for s in &report.sessions {
                table.add_row(vec![
                    s.session_id.as_str(),
                    s.provider.as_str(),
                    s.method.as_str(),
                    s.status.as_str(),
                    s.expires_at.as_str(),
                ]);
            }
            write_folded(out, &format!("{table}\n"), home)
        }
    }
}

pub fn render_error(
    out: &mut dyn Write,
    detail: &ErrorDetail,
    format: OutputFormat,
    home: Option<&Path>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let env = ErrorEnvelope {
                schema_version: SCHEMA_VERSION,
                error: detail.clone(),
            };
            let line = serde_json::to_string(&env)?;
            write_folded(out, &format!("{line}\n"), home)
        }
        OutputFormat::Agent => {
            let mut buf = format!("ERR: {} ({})\n", detail.message, detail.code);
            if let Some(hint) = &detail.hint {
                buf.push_str(&format!("hint:{hint}\n"));
            }
            write_folded(out, &buf, home)
        }
        OutputFormat::Human => {
            let mut buf = format!("[ERROR] {}\n", detail.message);
            if let Some(hint) = &detail.hint {
                buf.push_str(&format!("  Hint: {hint}\n"));
            }
            write_folded(out, &buf, home)
        }
    }
}

fn append_account_kv(buf: &mut String, acct: &AccountInfo) {
    if let Some(email) = &acct.email {
        buf.push_str(&format!("email:{email}\n"));
    }
    if let Some(plan) = &acct.plan {
        buf.push_str(&format!("plan:{plan}\n"));
    }
    if let Some(method) = &acct.auth_method {
        buf.push_str(&format!("auth_method:{method}\n"));
    }
    if let Some(ws) = &acct.workspace {
        buf.push_str(&format!("workspace:{ws}\n"));
    }
    for b in &acct.usage_buckets {
        buf.push_str(&format!(
            "usage_bucket:id={} remaining_fraction={} reset_time={}\n",
            b.id,
            b.remaining_fraction
                .map(|v| format!("{v:.4}"))
                .unwrap_or_else(|| "null".into()),
            b.reset_time.as_deref().unwrap_or("null")
        ));
    }
}

fn append_account_human(buf: &mut String, acct: &AccountInfo) {
    if let Some(email) = &acct.email {
        buf.push_str(&format!("  Account:   {email}\n"));
    }
    if let Some(plan) = &acct.plan {
        buf.push_str(&format!("  Plan:      {plan}\n"));
    }
    if let Some(method) = &acct.auth_method {
        buf.push_str(&format!("  Method:    {method}\n"));
    }
    if let Some(ws) = &acct.workspace {
        buf.push_str(&format!("  Workspace: {ws}\n"));
    }
    for b in &acct.usage_buckets {
        let pct = b
            .remaining_fraction
            .map(|v| format!("{:.0}%", v * 100.0))
            .unwrap_or_else(|| "unknown".into());
        let reset = b.reset_time.as_deref().unwrap_or("unknown");
        buf.push_str(&format!(
            "  Quota {}: {pct} remaining (resets {reset})\n",
            b.id
        ));
    }
}

fn summarize_account_details(acct: &AccountInfo) -> String {
    let mut parts = Vec::new();
    if let Some(plan) = &acct.plan {
        parts.push(format!("plan={plan}"));
    }
    if let Some(ws) = &acct.workspace {
        parts.push(format!("workspace={ws}"));
    }
    if !acct.usage_buckets.is_empty() {
        parts.push(format!("{} quota buckets", acct.usage_buckets.len()));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::UsageBucket;

    #[test]
    fn home_folding_preserves_segment_boundaries() {
        let home = Path::new("/home/dev");
        assert_eq!(fold_path(Path::new("/home/dev"), Some(home)), "~");
        assert_eq!(
            fold_path(Path::new("/home/dev/projects/app"), Some(home)),
            "~/projects/app"
        );
        assert_eq!(
            fold_path(Path::new("/home/developer/app"), Some(home)),
            "/home/developer/app"
        );
        assert_eq!(fold_path(Path::new("/tmp/other"), Some(home)), "/tmp/other");
        assert_eq!(
            fold_text("path=/home/dev/foo sibling=/home/developer/bar", Some(home)),
            "path=~/foo sibling=/home/developer/bar"
        );
    }

    #[test]
    fn renders_all_formats_without_emojis_or_tables_in_agent_mode() {
        let report = ProviderStatusReport {
            schema_version: SCHEMA_VERSION,
            provider: "agy".into(),
            status: ProviderAuthState::Authenticated,
            account: Some(AccountInfo {
                email: None,
                plan: None,
                auth_method: Some("google_oauth".into()),
                workspace: None,
                usage_buckets: vec![
                    UsageBucket {
                        id: "gemini-weekly".into(),
                        remaining_fraction: Some(0.95),
                        reset_time: Some("2026-11-28T14:08:15Z".into()),
                    },
                    UsageBucket {
                        id: "gemini-5h".into(),
                        remaining_fraction: None,
                        reset_time: None,
                    },
                ],
            }),
            error: None,
        };
        let mut agent = Vec::new();
        render_provider_status(&mut agent, &report, OutputFormat::Agent, None).unwrap();
        let agent_s = String::from_utf8(agent).unwrap();
        assert!(agent_s.contains("provider:agy"));
        assert!(agent_s.contains("usage_bucket:id=gemini-weekly"));
        assert!(!agent_s.contains("┌"));

        let mut human = Vec::new();
        render_provider_status(&mut human, &report, OutputFormat::Human, None).unwrap();
        let human_s = String::from_utf8(human).unwrap();
        assert!(human_s.contains("[OK] agy: authenticated"));
        assert!(human_s.contains("95% remaining"));

        let mut json = Vec::new();
        render_provider_status(&mut json, &report, OutputFormat::Json, None).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(val["schema_version"], 1);
        assert_eq!(val["provider"], "agy");

        // Cover status list, logout, session snapshot states, empty agent list, and error rendering
        let err_detail = ErrorDetail {
            code: "provider_failed".into(),
            message: "boom".into(),
            retryable: true,
            hint: Some("retry".into()),
        };
        let list_report = ProviderStatusListReport {
            schema_version: SCHEMA_VERSION,
            providers: vec![
                report.clone(),
                ProviderStatusReport {
                    schema_version: SCHEMA_VERSION,
                    provider: "codex".into(),
                    status: ProviderAuthState::Authenticated,
                    account: Some(AccountInfo {
                        email: Some("a@b.com".into()),
                        plan: Some("pro".into()),
                        auth_method: Some("chatgpt".into()),
                        workspace: Some("Org".into()),
                        usage_buckets: Vec::new(),
                    }),
                    error: None,
                },
                ProviderStatusReport {
                    schema_version: SCHEMA_VERSION,
                    provider: "claude".into(),
                    status: ProviderAuthState::Error,
                    account: None,
                    error: Some(err_detail.clone()),
                },
            ],
        };
        for fmt in [OutputFormat::Human, OutputFormat::Agent, OutputFormat::Json] {
            let mut b = Vec::new();
            render_provider_status_list(&mut b, &list_report, fmt, None).unwrap();
            assert!(!b.is_empty());

            let mut b2 = Vec::new();
            render_provider_status(&mut b2, &list_report.providers[2], fmt, None).unwrap();
            assert!(!b2.is_empty());

            let mut b3 = Vec::new();
            render_provider_logout(
                &mut b3,
                &ProviderLogoutReport {
                    schema_version: SCHEMA_VERSION,
                    provider: "codex".into(),
                    status: "logged_out".into(),
                },
                fmt,
                None,
            )
            .unwrap();
            assert!(!b3.is_empty());

            let mut b4 = Vec::new();
            render_error(&mut b4, &err_detail, fmt, None).unwrap();
            assert!(!b4.is_empty());

            let mut b5 = Vec::new();
            render_session_list(
                &mut b5,
                &SessionListReport {
                    schema_version: SCHEMA_VERSION,
                    sessions: Vec::new(),
                },
                fmt,
                None,
            )
            .unwrap();
            assert!(!b5.is_empty());

            for state in [
                SessionState::AwaitingInput,
                SessionState::Authenticated,
                SessionState::Cancelled,
                SessionState::Failed,
                SessionState::Expired,
            ] {
                let mut b6 = Vec::new();
                render_session_snapshot(
                    &mut b6,
                    &SessionSnapshot {
                        schema_version: SCHEMA_VERSION,
                        session_id: "0123456789abcdef".into(),
                        provider: "codex".into(),
                        method: crate::protocol::AuthMethod::Device,
                        status: state,
                        auth_url: Some("https://example.com".into()),
                        user_code: Some("ABCD-1234".into()),
                        expected_input: Some(crate::protocol::ExpectedInput {
                            kind: crate::protocol::ExpectedInputKind::None,
                            required: false,
                            prompt: "Open URL".into(),
                        }),
                        account: list_report.providers[1].account.clone(),
                        expires_at: "2026-11-28T00:00:00Z".into(),
                        error: (state == SessionState::Failed).then(|| err_detail.clone()),
                    },
                    fmt,
                    None,
                )
                .unwrap();
                assert!(!b6.is_empty());
            }
        }
        assert_eq!(fold_path(Path::new("/tmp/x"), None), "/tmp/x");
    }
}
