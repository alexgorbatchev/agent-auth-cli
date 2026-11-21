pub mod agy;
pub mod claude;
pub mod codex;

use crate::{
    error::{AuthError, Result},
    process,
    protocol::{
        AccountInfo, AuthChallenge, AuthMethod, AuthMethodChoice, ProviderDescriptor,
        ProviderStatusReport,
    },
    sandbox::Sandbox,
};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Debug)]
pub struct ProviderContext {
    pub binary: PathBuf,
    pub home: Option<PathBuf>,
    pub extra_env: BTreeMap<String, String>,
    pub claude_console: bool,
    pub claude_sso: bool,
    pub claude_email: Option<String>,
    pub sandbox: Arc<Sandbox>,
}

impl ProviderContext {
    pub fn apply_env(&self, cmd: &mut tokio::process::Command) {
        self.sandbox.apply_to_command(cmd);
        if let Some(home) = &self.home {
            cmd.env("HOME", home);
            cmd.env("XDG_CONFIG_HOME", home.join(".config"));
            cmd.env("XDG_DATA_HOME", home.join(".local/share"));
            cmd.env("XDG_CACHE_HOME", home.join(".cache"));
        }
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        }
    }
}

pub enum LoginCommand {
    Submit {
        input: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Cancel {
        reply: oneshot::Sender<Result<()>>,
    },
}

#[async_trait]
pub trait ActiveLogin: Send {
    fn challenge(&self) -> &AuthChallenge;

    /// Drive the live provider login session until completion or cancellation,
    /// handling interactive input and cancel requests concurrently.
    async fn run(self: Box<Self>, commands: mpsc::Receiver<LoginCommand>) -> Result<AccountInfo>;
}

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn binary_name(&self) -> &'static str;
    fn default_method(&self) -> AuthMethod;
    fn supported_methods(&self) -> &'static [AuthMethod];
    fn supports_logout(&self) -> bool;

    fn resolve_method(&self, choice: AuthMethodChoice) -> Result<AuthMethod> {
        let method = match choice {
            AuthMethodChoice::Auto => self.default_method(),
            AuthMethodChoice::Device => AuthMethod::Device,
            AuthMethodChoice::Oauth => AuthMethod::Oauth,
        };
        if self.supported_methods().contains(&method) {
            Ok(method)
        } else {
            Err(AuthError::UnsupportedMethod {
                provider: self.id().to_owned(),
                method: method.to_string(),
            })
        }
    }

    async fn status(
        &self,
        ctx: &ProviderContext,
        timeout: Duration,
    ) -> Result<ProviderStatusReport>;

    async fn logout(&self, ctx: &ProviderContext, timeout: Duration) -> Result<()>;

    async fn start_session(
        &self,
        method: AuthMethod,
        ctx: &ProviderContext,
        start_timeout: Duration,
    ) -> Result<Box<dyn ActiveLogin>>;
}

pub struct ProviderRegistry {
    providers: Vec<Arc<dyn ProviderAdapter>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: vec![
                Arc::new(codex::CodexProvider),
                Arc::new(claude::ClaudeProvider),
                Arc::new(agy::AgyProvider),
            ],
        }
    }

    pub fn get(&self, id: &str) -> Result<Arc<dyn ProviderAdapter>> {
        let needle = id.trim().to_ascii_lowercase();
        self.providers
            .iter()
            .find(|p| p.id() == needle)
            .cloned()
            .ok_or_else(|| AuthError::UnsupportedProvider(id.to_owned()))
    }

    pub fn all(&self) -> &[Arc<dyn ProviderAdapter>] {
        &self.providers
    }

    pub fn descriptors(
        &self,
        explicit_bins: &BTreeMap<String, PathBuf>,
    ) -> Vec<ProviderDescriptor> {
        self.providers
            .iter()
            .map(|p| {
                let explicit = explicit_bins.get(p.id()).map(PathBuf::as_path);
                let available = process::resolve_binary(explicit, p.binary_name()).is_some();
                ProviderDescriptor {
                    id: p.id().to_owned(),
                    binary: p.binary_name().to_owned(),
                    available,
                    default_method: p.default_method(),
                    supported_methods: p.supported_methods().to_vec(),
                    supports_logout: p.supports_logout(),
                }
            })
            .collect()
    }

    pub fn build_context(
        &self,
        provider: &dyn ProviderAdapter,
        explicit_bin: Option<&Path>,
        home: Option<PathBuf>,
        sandbox: Arc<Sandbox>,
    ) -> Result<ProviderContext> {
        let binary = process::require_binary(provider.id(), explicit_bin, provider.binary_name())?;
        Ok(ProviderContext {
            binary,
            home,
            extra_env: BTreeMap::new(),
            claude_console: false,
            claude_sso: false,
            claude_email: None,
            sandbox,
        })
    }
}

/// Extract an expected stdio pipe from a spawned child configured with `Stdio::piped()`.
pub(crate) fn take_pipe<T>(pipe: Option<T>, desc: &str) -> Result<T> {
    match pipe {
        Some(p) => Ok(p),
        None => Err(AuthError::Protocol(format!("{desc} pipe unavailable"))),
    }
}

/// Extract a required string field from a JSON object or return a `Protocol` error.
pub(crate) fn required_json_str(value: &serde_json::Value, key: &str, ctx: &str) -> Result<String> {
    match value.get(key).and_then(serde_json::Value::as_str) {
        Some(s) => Ok(s.to_owned()),
        None => Err(AuthError::Protocol(format!("{ctx} missing {key}"))),
    }
}

/// Extract the first `https://` URL from a line of CLI output, stripping trailing punctuation.
pub(crate) fn extract_https_url(line: &str) -> Option<String> {
    let stripped = strip_ansi(line);
    let start = stripped.find("https://")?;
    let rest = &stripped[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']'))
        .unwrap_or(rest.len());
    let candidate = rest[..end].trim_end_matches(['.', ',', ';']);
    url::Url::parse(candidate).ok().map(|u| u.to_string())
}

/// Strip common ANSI CSI/OSC escape sequences so URL and message parsing stays deterministic.
pub(crate) fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Extract the first balanced JSON object `{...}` from noisy terminal output.
pub(crate) fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let bytes = raw.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, &b) in bytes[start..].iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&raw[start..=start + idx]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Keep diagnostic text concise and remove obvious token-like values or blank lines.
pub(crate) fn sanitize_diagnostics(raw: &str) -> String {
    let cleaned = strip_ansi(raw);
    let lines: Vec<&str> = cleaned
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let joined = if lines.len() > 6 {
        lines[lines.len() - 6..].join(" | ")
    } else {
        lines.join(" | ")
    };
    if joined.len() > 400 {
        format!("{}...", &joined[..400])
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_urls_through_ansi_and_punctuation() {
        let line = "\x1b]8;;https://claude.com/cai/oauth/authorize?code=true\x07https://claude.com/cai/oauth/authorize?code=true&state=abc.\x1b]8;;\x07";
        assert_eq!(
            extract_https_url(line).as_deref(),
            Some("https://claude.com/cai/oauth/authorize?code=true&state=abc")
        );
        assert!(extract_https_url("no link here").is_none());
    }

    #[test]
    fn extracts_balanced_json_object_ignoring_trailing_noise() {
        let noisy = "prefix\n{\"loggedIn\":true,\"note\":\"brace } inside\"}\r\nB";
        assert_eq!(
            extract_json_object(noisy),
            Some("{\"loggedIn\":true,\"note\":\"brace } inside\"}")
        );
        assert!(extract_json_object("not json").is_none());
    }

    #[test]
    fn registry_resolves_providers_and_methods() {
        let reg = ProviderRegistry::default();
        assert_eq!(reg.all().len(), 3);
        assert!(take_pipe::<u8>(None, "stdout").is_err());
        assert!(required_json_str(&serde_json::json!({}), "loginId", "codex").is_err());
        let codex = reg.get("CODEX").unwrap();
        assert_eq!(
            codex.resolve_method(AuthMethodChoice::Auto).unwrap(),
            AuthMethod::Device
        );
        assert_eq!(
            codex.resolve_method(AuthMethodChoice::Oauth).unwrap(),
            AuthMethod::Oauth
        );
        let claude = reg.get("claude").unwrap();
        assert_eq!(
            claude.resolve_method(AuthMethodChoice::Auto).unwrap(),
            AuthMethod::Oauth
        );
        assert_eq!(
            claude
                .resolve_method(AuthMethodChoice::Device)
                .unwrap_err()
                .code(),
            "unsupported_method"
        );
        assert_eq!(
            reg.get("unknown").err().unwrap().code(),
            "unsupported_provider"
        );
    }
}
