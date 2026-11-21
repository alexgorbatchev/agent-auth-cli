use crate::error::Result;
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::process::Command;

const SHIM_COMMANDS: &[&str] = &[
    "browser-noop",
    "open",
    "xdg-open",
    "wslview",
    "sensible-browser",
    "gnome-open",
    "kde-open",
    "termux-open-url",
];

static SANDBOX_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Isolated browser-blocking environment applied to every provider child process.
#[derive(Debug)]
pub struct Sandbox {
    dir: PathBuf,
    browser_bin: PathBuf,
}

impl Sandbox {
    /// Create a temporary `0700` shim directory under `base_dir` pointing at the running executable.
    pub fn new_in(base_dir: &Path, prefix: &str) -> Result<Self> {
        let exe = std::env::current_exe()?;
        Self::new_for_exe(base_dir, prefix, &exe)
    }

    /// Create a temporary `0700` shim directory under `base_dir` pointing at `exe`.
    pub fn new_for_exe(base_dir: &Path, prefix: &str, exe: &Path) -> Result<Self> {
        fs::create_dir_all(base_dir)?;
        let seq = SANDBOX_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = base_dir.join(format!("{prefix}-{pid}-{seq}.shims"));
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;

        let quoted_exe = posix_single_quote(&exe.to_string_lossy());
        let script = format!("#!/bin/sh\nexec {quoted_exe} __noop-opener \"$@\"\n");

        for name in SHIM_COMMANDS {
            let path = dir.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o700)
                .open(&path)?;
            file.write_all(script.as_bytes())?;
        }

        let browser_bin = dir.join("browser-noop");
        Ok(Self { dir, browser_bin })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn browser_bin(&self) -> &Path {
        &self.browser_bin
    }

    /// Apply strict no-browser environment overrides and `PATH` shim precedence to `cmd`.
    pub fn apply_to_command(&self, cmd: &mut Command) {
        cmd.env("BROWSER", &self.browser_bin);
        cmd.env("NO_BROWSER", "1");
        cmd.env_remove("DISPLAY");
        cmd.env_remove("WAYLAND_DISPLAY");

        let mut paths = vec![self.dir.clone()];
        if let Some(existing) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        if let Ok(joined) = std::env::join_paths(paths) {
            cmd.env("PATH", joined);
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Internal no-op browser opener invoked by `BROWSER` and `PATH` shims.
pub fn run_noop_opener(args: &[OsString]) -> i32 {
    if let Ok(log_path) = std::env::var("AGENT_AUTH_NOOP_OPENER_LOG")
        && let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path)
    {
        let joined: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let _ = writeln!(file, "{}", joined.join(" "));
    }
    0
}

fn posix_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creates_shims_applies_env_and_cleans_up_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = Path::new("/tmp/my 'quoted'/agent-auth");
        let shim_dir;
        {
            let sandbox = Sandbox::new_for_exe(tmp.path(), "test", exe).unwrap();
            shim_dir = sandbox.dir().to_path_buf();
            assert!(shim_dir.exists());
            let meta = fs::metadata(&shim_dir).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
            for cmd in SHIM_COMMANDS {
                let p = shim_dir.join(cmd);
                assert!(p.exists());
                let body = fs::read_to_string(&p).unwrap();
                assert!(body.contains("'/tmp/my '\\''quoted'\\''/agent-auth' __noop-opener"));
            }

            let mut cmd = Command::new("sh");
            cmd.env("DISPLAY", ":0");
            cmd.env("WAYLAND_DISPLAY", "wayland-0");
            sandbox.apply_to_command(&mut cmd);
            let std_cmd = cmd.as_std();
            let envs: std::collections::BTreeMap<_, _> = std_cmd
                .get_envs()
                .map(|(k, v)| (k.to_os_string(), v.map(|x| x.to_os_string())))
                .collect();
            assert_eq!(
                envs.get(&OsString::from("BROWSER")).unwrap().as_deref(),
                Some(sandbox.browser_bin().as_os_str())
            );
            assert_eq!(
                envs.get(&OsString::from("NO_BROWSER")).unwrap().as_deref(),
                Some(std::ffi::OsStr::new("1"))
            );
            assert_eq!(envs.get(&OsString::from("DISPLAY")).unwrap(), &None);
            assert_eq!(envs.get(&OsString::from("WAYLAND_DISPLAY")).unwrap(), &None);
            let path_val = envs
                .get(&OsString::from("PATH"))
                .unwrap()
                .as_ref()
                .unwrap()
                .clone();
            let first = std::env::split_paths(&path_val).next().unwrap();
            assert_eq!(first, shim_dir);
        }
        assert!(!shim_dir.exists());
    }

    #[test]
    fn noop_opener_logs_when_configured_and_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("opener.log");
        // Safety: unit test checks single-process env logging synchronously without concurrent env readers.
        unsafe { std::env::set_var("AGENT_AUTH_NOOP_OPENER_LOG", &log) };
        let rc = run_noop_opener(&[OsString::from("https://example.com/auth")]);
        unsafe { std::env::remove_var("AGENT_AUTH_NOOP_OPENER_LOG") };
        assert_eq!(rc, 0);
        let content = fs::read_to_string(&log).unwrap();
        assert_eq!(content.trim(), "https://example.com/auth");
    }
}
