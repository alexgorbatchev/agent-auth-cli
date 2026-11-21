use crate::{
    error::{AuthError, Result},
    process,
    protocol::{AuthMethod, SessionSnapshot, parse_rfc3339},
    session::client,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub session_id: String,
    pub provider: String,
    pub method: AuthMethod,
    pub worker_pid: u32,
    pub created_at: String,
    pub expires_at: String,
}

/// Resolve the default short per-user runtime directory for Unix domain sockets.
pub fn default_runtime_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("AGENT_AUTH_RUNTIME_DIR")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    if cfg!(target_os = "linux")
        && let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR")
        && !xdg.trim().is_empty()
    {
        return PathBuf::from(xdg).join("agent-auth");
    }
    // Safety: `geteuid` has no preconditions and always succeeds.
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/agent-auth-{uid}"))
}

/// Create and validate a private `0700` runtime directory owned by the current user (no symlinks).
pub fn ensure_runtime_dir(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(AuthError::InvalidInput(format!(
                "refusing symlinked runtime directory: {}",
                path.display()
            )));
        }
        if !meta.is_dir() {
            return Err(AuthError::InvalidInput(format!(
                "runtime path is not a directory: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }

    let meta = fs::symlink_metadata(path)?;
    // Safety: `geteuid` always succeeds.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(AuthError::InvalidInput(format!(
            "runtime directory {} is not owned by current user",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty()
        || session_id.len() > 64
        || !session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AuthError::InvalidInput(format!(
            "invalid session id {session_id:?}"
        )));
    }
    Ok(())
}

/// Generate a 16-hex-character random session identifier.
pub fn generate_session_id() -> Result<String> {
    let mut bytes = [0u8; 8];
    let mut file = File::open("/dev/urandom")?;
    file.read_exact(&mut bytes)?;
    let mut out = String::with_capacity(16);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

pub fn socket_path(runtime_dir: &Path, session_id: &str) -> PathBuf {
    runtime_dir.join(format!("{session_id}.sock"))
}

pub fn meta_path(runtime_dir: &Path, session_id: &str) -> PathBuf {
    runtime_dir.join(format!("{session_id}.meta.json"))
}

pub fn write_meta(runtime_dir: &Path, meta: &SessionMeta) -> Result<()> {
    let path = meta_path(runtime_dir, &meta.session_id);
    let tmp = runtime_dir.join(format!("{}.meta.tmp", meta.session_id));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    let body = serde_json::to_vec(meta)?;
    file.write_all(&body)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn read_meta(runtime_dir: &Path, session_id: &str) -> Option<SessionMeta> {
    let body = fs::read(meta_path(runtime_dir, session_id)).ok()?;
    serde_json::from_slice(&body).ok()
}

pub fn remove_session_files(runtime_dir: &Path, session_id: &str) {
    let _ = fs::remove_file(socket_path(runtime_dir, session_id));
    let _ = fs::remove_file(meta_path(runtime_dir, session_id));
}

pub fn is_meta_expired(meta: &SessionMeta) -> bool {
    parse_rfc3339(&meta.expires_at).is_some_and(|ts| ts <= OffsetDateTime::now_utc())
}

/// List all live sessions in `runtime_dir`, pruning stale metadata/sockets from dead workers.
pub async fn list_active_sessions(runtime_dir: &Path) -> Result<Vec<SessionSnapshot>> {
    if !runtime_dir.exists() {
        return Ok(Vec::new());
    }
    ensure_runtime_dir(runtime_dir)?;
    let mut ids = Vec::new();
    for entry in fs::read_dir(runtime_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if let Some(id) = name_str.strip_suffix(".meta.json") {
            ids.push(id.to_owned());
        } else if let Some(id) = name_str.strip_suffix(".sock")
            && !meta_path(runtime_dir, id).exists()
        {
            ids.push(id.to_owned());
        }
    }
    ids.sort();
    ids.dedup();

    let mut sessions = Vec::new();
    for id in ids {
        match client::query_status(runtime_dir, &id).await {
            Ok(snapshot) => sessions.push(snapshot),
            Err(_) => {
                let alive = read_meta(runtime_dir, &id)
                    .is_some_and(|m| process::is_process_alive(m.worker_pid));
                if !alive {
                    remove_session_files(runtime_dir, &id);
                }
            }
        }
    }
    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{now_rfc3339, rfc3339_after};

    #[test]
    fn validates_session_ids_and_metadata_roundtrip() {
        assert!(validate_session_id("0123456789abcdef").is_ok());
        assert!(validate_session_id("abc-123_XYZ").is_ok());
        assert!(validate_session_id("").is_err());
        assert!(validate_session_id("../escape").is_err());
        assert!(validate_session_id("a/b").is_err());

        let id = generate_session_id().unwrap();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        ensure_runtime_dir(&rt).unwrap();
        let meta = SessionMeta {
            session_id: id.clone(),
            provider: "codex".into(),
            method: AuthMethod::Device,
            worker_pid: 999_999_999,
            created_at: now_rfc3339(),
            expires_at: rfc3339_after(60),
        };
        write_meta(&rt, &meta).unwrap();
        assert_eq!(read_meta(&rt, &id), Some(meta.clone()));
        assert!(!is_meta_expired(&meta));
        remove_session_files(&rt, &id);
        assert!(read_meta(&rt, &id).is_none());
    }

    #[test]
    fn refuses_symlinked_runtime_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ensure_runtime_dir(&link).unwrap_err();
        assert_eq!(err.code(), "invalid_input");

        let file = tmp.path().join("not-a-dir");
        fs::write(&file, "x").unwrap();
        assert_eq!(
            ensure_runtime_dir(&file).unwrap_err().code(),
            "invalid_input"
        );

        let loose = tmp.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_runtime_dir(&loose).unwrap();
        assert_eq!(
            fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
            0o700
        );

        assert!(!default_runtime_dir().as_os_str().is_empty());
    }
}
