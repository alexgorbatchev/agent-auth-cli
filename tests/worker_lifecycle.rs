use agent_auth_cli::{
    cli::{self, Environment},
    protocol::{AuthMethod, now_rfc3339},
    session::store::{self, SessionMeta},
};
use cli_command_kit::Mode;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
};

fn write_slow_claude(dir: &Path) -> PathBuf {
    let path = dir.join("slow-claude");
    let script = r#"#!/usr/bin/env python3
import sys, time
if sys.argv[1:3] == ["auth", "login"]:
    sys.stdout.write("If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?state=slow\n")
    sys.stdout.flush()
    line = sys.stdin.readline()
    if line.strip() == "ok":
        sys.exit(0)
    time.sleep(30)
    sys.exit(1)
if sys.argv[1:3] == ["auth", "status"]:
    sys.stdout.write('{"loggedIn":true,"authMethod":"claudeai","email":"slow@example.com"}\n')
    sys.exit(0)
sys.exit(0)
"#;
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o755)
        .open(&path)
        .unwrap();
    f.write_all(script.as_bytes()).unwrap();
    path
}

#[tokio::test]
async fn worker_supports_status_list_pending_wait_ttl_expiry_and_stale_reap() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let rt = tmp.path().join("rt");
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let bin = write_slow_claude(tmp.path());

    let env = Environment {
        mode: Mode::Human,
        home: Some(home.clone()),
        runtime_dir: rt.clone(),
        worker_exe: PathBuf::from(env!("CARGO_BIN_EXE_agent-auth")),
    };

    // Empty session list
    let mut out = Vec::new();
    cli::execute(["agent-auth", "session", "list"], &env, &mut out)
        .await
        .unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("No active sessions")
    );

    // Plant a stale dead session metadata file to verify auto-reap + session_expired reporting
    store::ensure_runtime_dir(&rt).unwrap();
    let stale_id = "deadbeef00001111";
    store::write_meta(
        &rt,
        &SessionMeta {
            session_id: stale_id.into(),
            provider: "claude".into(),
            method: AuthMethod::Oauth,
            worker_pid: 999_999_999,
            created_at: now_rfc3339(),
            expires_at: "2000-01-01T00:00:00Z".into(),
        },
    )
    .unwrap();
    let expired_err = cli::execute(
        ["agent-auth", "session", "status", stale_id],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(expired_err.code(), "session_expired");
    assert!(!store::meta_path(&rt, stale_id).exists());

    // Start a session with short TTL=2s and verify list/status/pending-wait/expiry
    let mut out = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "claude",
            "--ttl",
            "2",
            "--provider-bin",
            bin.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--json",
        ],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    let sid = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // session status & session list in Human and Agent modes
    for mode in [Mode::Human, Mode::Agent] {
        let e = Environment {
            mode,
            ..env.clone()
        };
        let mut s_out = Vec::new();
        cli::execute(["agent-auth", "session", "status", &sid], &e, &mut s_out)
            .await
            .unwrap();
        assert!(String::from_utf8(s_out).unwrap().contains(&sid));

        let mut l_out = Vec::new();
        cli::execute(["agent-auth", "session", "list"], &e, &mut l_out)
            .await
            .unwrap();
        assert!(String::from_utf8(l_out).unwrap().contains(&sid));
    }

    // session wait --timeout 1 returns exit 3 (Pending) while keeping session alive
    let mut wait_out = Vec::new();
    let pending_err = cli::execute(
        [
            "agent-auth",
            "session",
            "wait",
            &sid,
            "--timeout",
            "1",
            "--json",
        ],
        &env,
        &mut wait_out,
    )
    .await
    .unwrap_err();
    assert_eq!(pending_err.exit_code(), 3);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wait_out).unwrap()["status"],
        "awaiting_input"
    );

    // Wait past TTL (2s) and confirm worker self-reaped socket & metadata
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!store::socket_path(&rt, &sid).exists());
    assert!(!store::meta_path(&rt, &sid).exists());
}

#[test]
fn compiled_binary_handles_version_help_json_errors_and_exit_codes() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let bin = env!("CARGO_BIN_EXE_agent-auth");

    let ver = Command::new(bin).arg("--version").output().unwrap();
    assert!(ver.status.success());
    assert_eq!(
        String::from_utf8(ver.stdout).unwrap(),
        format!("{}\n", env!("CARGO_PKG_VERSION"))
    );

    let list = Command::new(bin)
        .env("AGENT", "1")
        .args(["provider", "list", "--json"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let val: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(val["schema_version"], 1);

    let bad_arg = Command::new(bin).arg("--unknown-flag").output().unwrap();
    assert_eq!(bad_arg.status.code(), Some(2));

    let missing_session = Command::new(bin)
        .args([
            "--runtime-dir",
            tmp.path().join("rt").to_str().unwrap(),
            "session",
            "status",
            "0123456789abcdef",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_session.status.code(), Some(1));
    assert!(missing_session.stdout.is_empty());
    let err_json: serde_json::Value = serde_json::from_slice(&missing_session.stderr).unwrap();
    assert_eq!(err_json["error"]["code"], "session_not_found");

    // Non-JSON error in Human and Agent modes
    let human_err = Command::new(bin)
        .env_remove("AGENT")
        .args([
            "--runtime-dir",
            tmp.path().join("rt").to_str().unwrap(),
            "session",
            "status",
            "0123456789abcdef",
        ])
        .output()
        .unwrap();
    assert_eq!(human_err.status.code(), Some(1));
    assert!(
        String::from_utf8(human_err.stderr)
            .unwrap()
            .contains("[ERROR]")
    );

    let agent_err = Command::new(bin)
        .env("AGENT", "1")
        .args([
            "--runtime-dir",
            tmp.path().join("rt").to_str().unwrap(),
            "session",
            "status",
            "0123456789abcdef",
        ])
        .output()
        .unwrap();
    assert_eq!(agent_err.status.code(), Some(1));
    assert!(
        String::from_utf8(agent_err.stderr)
            .unwrap()
            .contains("ERR:")
    );

    // All-provider status & usage with an empty PATH (reports error per missing provider cleanly)
    for sub in ["status", "usage"] {
        let all = Command::new(bin)
            .env("PATH", "/nonexistent-dir-for-test")
            .args([
                "--runtime-dir",
                tmp.path().join("rt").to_str().unwrap(),
                "provider",
                sub,
                "--json",
            ])
            .output()
            .unwrap();
        assert!(all.status.success());
        let all_val: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
        assert_eq!(all_val["providers"].as_array().unwrap().len(), 3);
        assert_eq!(all_val["providers"][0]["status"], "error");
    }
}

#[tokio::test]
async fn worker_handles_invalid_ipc_json_and_sigterm_shutdown() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let rt = tmp.path().join("rt");
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let bin = write_slow_claude(tmp.path());
    let env = Environment {
        mode: Mode::Agent,
        home: Some(home.clone()),
        runtime_dir: rt.clone(),
        worker_exe: PathBuf::from(env!("CARGO_BIN_EXE_agent-auth")),
    };

    let mut out = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "claude",
            "--ttl",
            "30",
            "--provider-bin",
            bin.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--json",
        ],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    let sid = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Send malformed JSON over raw Unix socket and confirm structured Error response
    let sock = store::socket_path(&rt, &sid);
    let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"{not-json}\n")
        .await
        .unwrap();
    let mut resp_line = String::new();
    let mut reader = tokio::io::BufReader::new(stream);
    tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut resp_line)
        .await
        .unwrap();
    assert!(resp_line.contains("\"type\":\"error\""));

    // Send SIGTERM to worker PID and verify clean cleanup of socket & metadata
    let meta = store::read_meta(&rt, &sid).unwrap();
    // Safety: signaling our own test worker process with SIGTERM.
    unsafe { libc::kill(meta.worker_pid as i32, libc::SIGTERM) };
    for _ in 0..40 {
        if !store::socket_path(&rt, &sid).exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(!store::socket_path(&rt, &sid).exists());
    assert!(!store::meta_path(&rt, &sid).exists());
}
