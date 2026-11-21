use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Device,
    Oauth,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Oauth => "oauth",
        }
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "device" => Ok(Self::Device),
            "oauth" => Ok(Self::Oauth),
            other => Err(format!(
                "invalid auth method {other:?}; expected device or oauth"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthMethodChoice {
    #[default]
    Auto,
    Device,
    Oauth,
}

impl AuthMethodChoice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Device => "device",
            Self::Oauth => "oauth",
        }
    }
}

impl fmt::Display for AuthMethodChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthMethodChoice {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "device" => Ok(Self::Device),
            "oauth" => Ok(Self::Oauth),
            other => Err(format!(
                "invalid method {other:?}; expected auto, device, or oauth"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedInputKind {
    None,
    Code,
    CodeOrUrl,
    CallbackUrlOptional,
}

impl ExpectedInputKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Code => "code",
            Self::CodeOrUrl => "code_or_url",
            Self::CallbackUrlOptional => "callback_url_optional",
        }
    }
}

impl fmt::Display for ExpectedInputKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpectedInput {
    pub kind: ExpectedInputKind,
    pub required: bool,
    pub prompt: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthChallenge {
    pub auth_url: String,
    pub user_code: Option<String>,
    pub expected_input: ExpectedInput,
    pub callback_origin: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Starting,
    AwaitingInput,
    Exchanging,
    Authenticated,
    Failed,
    Expired,
    Cancelled,
}

impl SessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::AwaitingInput => "awaiting_input",
            Self::Exchanging => "exchanging",
            Self::Authenticated => "authenticated",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Authenticated | Self::Failed | Self::Expired | Self::Cancelled
        )
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UsageBucket {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_fraction: Option<f64>,
    pub remaining_fraction: Option<f64>,
    pub reset_time: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtraUsageInfo {
    pub enabled: bool,
    pub unlimited: bool,
    pub used_credits: Option<f64>,
    pub monthly_limit: Option<f64>,
    pub balance: Option<String>,
    pub currency: Option<String>,
    pub used_fraction: Option<f64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderUsageState {
    Available,
    Unauthenticated,
    Unavailable,
    Error,
}

impl ProviderUsageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unauthenticated => "unauthenticated",
            Self::Unavailable => "unavailable",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for ProviderUsageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderUsageReport {
    pub schema_version: u32,
    pub provider: String,
    pub status: ProviderUsageState,
    pub plan: Option<String>,
    pub buckets: Vec<UsageBucket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_usage: Option<ExtraUsageInfo>,
    pub error: Option<ErrorDetail>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderUsageListReport {
    pub schema_version: u32,
    pub providers: Vec<ProviderUsageReport>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub email: Option<String>,
    pub plan: Option<String>,
    pub auth_method: Option<String>,
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usage_buckets: Vec<UsageBucket>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub schema_version: u32,
    pub session_id: String,
    pub provider: String,
    pub method: AuthMethod,
    pub status: SessionState,
    pub auth_url: Option<String>,
    pub user_code: Option<String>,
    pub expected_input: Option<ExpectedInput>,
    pub account: Option<AccountInfo>,
    pub expires_at: String,
    pub error: Option<ErrorDetail>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: String,
    pub aliases: Vec<String>,
    pub binary: String,
    pub available: bool,
    pub default_method: AuthMethod,
    pub supported_methods: Vec<AuthMethod>,
    pub supports_logout: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthState {
    Authenticated,
    Unauthenticated,
    Error,
}

impl ProviderAuthState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::Unauthenticated => "unauthenticated",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for ProviderAuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderStatusReport {
    pub schema_version: u32,
    pub provider: String,
    pub status: ProviderAuthState,
    pub account: Option<AccountInfo>,
    pub error: Option<ErrorDetail>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderListReport {
    pub schema_version: u32,
    pub providers: Vec<ProviderDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderStatusListReport {
    pub schema_version: u32,
    pub providers: Vec<ProviderStatusReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderLogoutReport {
    pub schema_version: u32,
    pub provider: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionListReport {
    pub schema_version: u32,
    pub sessions: Vec<SessionSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub schema_version: u32,
    pub error: ErrorDetail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerRequest {
    Status,
    Submit {
        input: Option<String>,
        timeout_secs: u64,
    },
    Wait {
        timeout_secs: u64,
    },
    Cancel,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum WorkerResponse {
    Snapshot(Box<SessionSnapshot>),
    Error(ErrorDetail),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum StartupAck {
    Ready(Box<SessionSnapshot>),
    Error(ErrorDetail),
}

pub fn format_rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

pub fn now_rfc3339() -> String {
    format_rfc3339(OffsetDateTime::now_utc())
}

pub fn rfc3339_after(secs: u64) -> String {
    let clamped = i64::try_from(secs).unwrap_or(i64::MAX / 2);
    format_rfc3339(OffsetDateTime::now_utc() + Duration::seconds(clamped))
}

pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_and_choice_parse_and_display() {
        assert_eq!(AuthMethod::from_str("device").unwrap(), AuthMethod::Device);
        assert_eq!(AuthMethod::from_str(" OAUTH ").unwrap(), AuthMethod::Oauth);
        assert!(AuthMethod::from_str("token").is_err());
        assert_eq!(AuthMethod::Device.to_string(), "device");
        assert_eq!(AuthMethod::Oauth.to_string(), "oauth");

        assert_eq!(
            AuthMethodChoice::from_str("auto").unwrap(),
            AuthMethodChoice::Auto
        );
        assert_eq!(
            AuthMethodChoice::from_str("device").unwrap(),
            AuthMethodChoice::Device
        );
        assert_eq!(
            AuthMethodChoice::from_str("oauth").unwrap(),
            AuthMethodChoice::Oauth
        );
        assert!(AuthMethodChoice::from_str("other").is_err());
        assert_eq!(AuthMethodChoice::default().to_string(), "auto");
    }

    #[test]
    fn state_and_protocol_serialization_roundtrip() {
        assert!(!SessionState::Starting.is_terminal());
        assert!(!SessionState::AwaitingInput.is_terminal());
        assert!(!SessionState::Exchanging.is_terminal());
        assert!(SessionState::Authenticated.is_terminal());
        assert!(SessionState::Failed.is_terminal());
        assert!(SessionState::Expired.is_terminal());
        assert!(SessionState::Cancelled.is_terminal());
        assert_eq!(SessionState::AwaitingInput.to_string(), "awaiting_input");
        assert_eq!(ExpectedInputKind::CodeOrUrl.to_string(), "code_or_url");
        assert_eq!(
            ProviderAuthState::Authenticated.to_string(),
            "authenticated"
        );

        let snap = SessionSnapshot {
            schema_version: SCHEMA_VERSION,
            session_id: "0123456789abcdef".into(),
            provider: "codex".into(),
            method: AuthMethod::Device,
            status: SessionState::AwaitingInput,
            auth_url: Some("https://auth.openai.com/codex/device".into()),
            user_code: Some("ABCD-EFGH".into()),
            expected_input: Some(ExpectedInput {
                kind: ExpectedInputKind::None,
                required: false,
                prompt: "Open URL".into(),
            }),
            account: None,
            expires_at: rfc3339_after(600),
            error: None,
        };
        let encoded = serde_json::to_string(&StartupAck::Ready(Box::new(snap.clone()))).unwrap();
        let decoded: StartupAck = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, StartupAck::Ready(Box::new(snap)));
        assert!(parse_rfc3339(&now_rfc3339()).is_some());
        assert!(parse_rfc3339("not-a-timestamp").is_none());
    }
}
