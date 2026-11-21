use crate::error::{AuthError, Result};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

/// Put the spawned child into its own process group (`pgid == pid`).
pub fn configure_process_group(cmd: &mut Command) {
    // Safety: `setpgid(0, 0)` is async-signal-safe per POSIX and executes before `exec`.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Start the spawned child in a new session (`setsid`) so it survives parent exit.
pub fn configure_detached_session(cmd: &mut Command) {
    // Safety: `setsid()` is async-signal-safe per POSIX and executes before `exec`.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Terminate an entire process group (`-pid`), sending `SIGKILL` after `grace`.
pub async fn terminate_process_group(pid: u32, grace: Duration) {
    let Ok(pgid) = i32::try_from(pid) else {
        return;
    };
    if pgid <= 0 {
        return;
    }
    // Safety: negative PID targets the child's process group created via `setpgid(0, 0)`/`setsid`.
    let rc = unsafe { libc::kill(-pgid, libc::SIGTERM) };
    if rc != 0 {
        // Fallback to direct pid in case process never entered its own group.
        // Safety: signaling our child pid with SIGTERM.
        unsafe {
            libc::kill(pgid, libc::SIGTERM);
        }
    }

    let deadline = tokio::time::Instant::now() + grace;
    while tokio::time::Instant::now() < deadline {
        if !is_process_group_alive(pgid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Safety: escalate to SIGKILL on the same process group after grace expires.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
        libc::kill(pgid, libc::SIGKILL);
    }
}

pub fn is_process_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    if raw <= 0 {
        return false;
    }
    // Safety: signal 0 checks process existence without delivering a signal.
    unsafe { libc::kill(raw, 0) == 0 }
}

fn is_process_group_alive(pgid: i32) -> bool {
    // Safety: signal 0 checks whether any member of `-pgid` is still alive.
    unsafe { libc::kill(-pgid, 0) == 0 }
}

/// Resolve an explicit path or locate `default_name` as an executable on `PATH`.
pub fn resolve_binary(explicit: Option<&Path>, default_name: &str) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return is_executable_file(path).then(|| path.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(default_name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

pub fn require_binary(
    provider: &str,
    explicit: Option<&Path>,
    default_name: &str,
) -> Result<PathBuf> {
    resolve_binary(explicit, default_name).ok_or_else(|| AuthError::ProviderNotFound {
        provider: provider.to_owned(),
        binary: explicit
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| default_name.to_owned()),
    })
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn resolves_explicit_and_missing_binaries() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("fake-bin");
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&bin)
            .unwrap();
        assert!(resolve_binary(Some(&bin), "fake-bin").is_none());

        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(resolve_binary(Some(&bin), "fake-bin"), Some(bin.clone()));
        assert!(require_binary("fake", Some(&bin), "fake-bin").is_ok());

        let missing = tmp.path().join("missing-bin");
        let err = require_binary("fake", Some(&missing), "fake-bin").unwrap_err();
        assert_eq!(err.code(), "provider_not_found");
        assert!(resolve_binary(None, "sh").is_some());
        assert!(!is_process_alive(0));
    }

    #[tokio::test]
    async fn terminates_spawned_process_group() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        configure_process_group(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id().unwrap();
        assert!(is_process_alive(pid));
        terminate_process_group(pid, Duration::from_millis(250)).await;
        let _ = child.wait().await;
        assert!(!is_process_alive(pid));

        // Also exercise SIGKILL escalation when child traps SIGTERM
        let mut stubborn = Command::new("sh");
        stubborn.args(["-c", "trap '' TERM; sleep 30"]);
        configure_process_group(&mut stubborn);
        let mut child2 = stubborn.spawn().unwrap();
        let pid2 = child2.id().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        terminate_process_group(pid2, Duration::from_millis(100)).await;
        let _ = child2.wait().await;
        assert!(!is_process_alive(pid2));
    }
}
