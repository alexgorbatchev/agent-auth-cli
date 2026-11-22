use crate::protocol::{ErrorDetail, SessionSnapshot};
use std::path::Path;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("{0}")]
    Parse(#[from] clap::Error),

    #[error("provider {provider} binary {binary} not found on PATH")]
    ProviderNotFound { provider: String, binary: String },

    #[error("unsupported provider: {0}")]
    UnsupportedProvider(String),

    #[error("provider {provider} does not support auth method {method}")]
    UnsupportedMethod { provider: String, method: String },

    #[error("provider {provider} does not support {operation}: {hint}")]
    UnsupportedOperation {
        provider: String,
        operation: String,
        hint: String,
    },

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session expired: {0}")]
    SessionExpired(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("local callback port {port} is already in use for {provider}")]
    CallbackPortInUse { provider: String, port: u16 },

    #[error("{provider} failed: {message}")]
    ProviderFailed { provider: String, message: String },

    #[error("timed out: {0}")]
    Timeout(String),

    #[error("session {} is still awaiting completion", .0.session_id)]
    Pending(Box<SessionSnapshot>),

    #[error("operation cancelled")]
    Cancelled,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Parse(_) => "invalid_arguments",
            Self::ProviderNotFound { .. } => "provider_not_found",
            Self::UnsupportedProvider(_) => "unsupported_provider",
            Self::UnsupportedMethod { .. } => "unsupported_method",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
            Self::SessionNotFound(_) => "session_not_found",
            Self::SessionExpired(_) => "session_expired",
            Self::InvalidInput(_) => "invalid_input",
            Self::CallbackPortInUse { .. } => "callback_port_in_use",
            Self::ProviderFailed { .. } => "provider_failed",
            Self::Timeout(_) => "timeout",
            Self::Pending(_) => "pending",
            Self::Cancelled => "cancelled",
            Self::Io(_) => "io_error",
            Self::Json(_) => "json_error",
            Self::Protocol(_) => "protocol_error",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::SessionExpired(_)
                | Self::InvalidInput(_)
                | Self::CallbackPortInUse { .. }
                | Self::ProviderFailed { .. }
                | Self::Timeout(_)
                | Self::Pending(_)
                | Self::Cancelled
                | Self::Protocol(_)
        )
    }

    pub fn hint(&self) -> Option<String> {
        match self {
            Self::ProviderNotFound { .. } => {
                Some("Install the provider CLI on PATH or pass --provider-bin <path>.".into())
            }
            Self::UnsupportedOperation { hint, .. } => Some(hint.clone()),
            Self::SessionNotFound(_) | Self::SessionExpired(_) => {
                Some("Start a new login with `agent-auth provider login <name>`.".into())
            }
            Self::CallbackPortInUse { .. } => Some(
                "Close the conflicting local login listener or retry with --method device.".into(),
            ),
            Self::Pending(snapshot) => Some(format!(
                "Complete authentication in your browser, then run `agent-auth session wait {}`.",
                snapshot.session_id
            )),
            _ => None,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Parse(_) => 2,
            Self::Pending(_) => 3,
            Self::Cancelled => 130,
            _ => 1,
        }
    }

    pub fn from_detail(detail: ErrorDetail) -> Self {
        match detail.code.as_str() {
            "provider_not_found" => Self::ProviderNotFound {
                provider: String::new(),
                binary: detail.message,
            },
            "unsupported_provider" => Self::UnsupportedProvider(detail.message),
            "unsupported_method" => Self::UnsupportedMethod {
                provider: String::new(),
                method: detail.message,
            },
            "unsupported_operation" => Self::UnsupportedOperation {
                provider: String::new(),
                operation: String::new(),
                hint: detail.hint.unwrap_or(detail.message),
            },
            "session_not_found" => Self::SessionNotFound(detail.message),
            "session_expired" => Self::SessionExpired(detail.message),
            "invalid_input" => Self::InvalidInput(detail.message),
            "callback_port_in_use" => Self::CallbackPortInUse {
                provider: "provider".into(),
                port: 1455,
            },
            "timeout" => Self::Timeout(detail.message),
            "cancelled" => Self::Cancelled,
            "protocol_error" => Self::Protocol(detail.message),
            _ => Self::ProviderFailed {
                provider: "provider".into(),
                message: detail.message,
            },
        }
    }

    pub fn to_detail(&self, home: Option<&Path>) -> ErrorDetail {
        let fold = |s: &str| -> String {
            match home {
                Some(h) => cli_command_kit::fold_message(s, h),
                None => s.to_owned(),
            }
        };
        ErrorDetail {
            code: self.code().to_owned(),
            message: fold(&self.to_string()),
            retryable: self.retryable(),
            hint: self.hint().map(|h| fold(&h)),
        }
    }
}
