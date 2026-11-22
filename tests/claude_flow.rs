use agent_auth_cli::cli::{self, Environment};
use cli_command_kit::Mode;
use std::{
    fs::{self, OpenOptions},
    io::{Cursor, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

fn write_fake_claude(dir: &Path) -> PathBuf {
    let path = dir.join("fake-claude");
    let script = r#"#!/usr/bin/env python3
import json, os, subprocess, sys

home = os.environ["HOME"]
state = os.path.join(home, ".claude-auth.json")
args = sys.argv[1:]

if args[:2] == ["auth", "status"]:
    if os.path.exists(state):
        sys.stdout.write(open(state).read() + "\r\nB ")
    else:
        sys.stdout.write('{"loggedIn":false,"authMethod":"none"}\r\nB ')
    sys.exit(0)

if args[:2] == ["auth", "logout"]:
    if os.path.exists(state):
        os.remove(state)
    sys.exit(0)

if args[:1] == ["-p"]:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        msg = json.loads(raw)
        req = msg.get("request") or {}
        req_id = msg.get("request_id")
        if req.get("subtype") == "initialize":
            sys.stdout.write(json.dumps({"type": "control_response", "response": {"subtype": "success", "request_id": req_id, "response": {}}}) + "\n")
            sys.stdout.flush()
        elif req.get("subtype") == "get_usage":
            if os.path.exists(os.path.join(home, ".claude-no-limits")):
                resp = {"subscription_type": None, "rate_limits_available": False, "rate_limits": None, "behaviors": None}
            else:
                resp = {
                    "subscription_type": "max",
                    "rate_limits_available": True,
                    "rate_limits": {
                        "five_hour": {"utilization": 32.0, "resets_at": "2026-11-21T20:00:00Z"},
                        "seven_day": {"utilization": 12.0, "resets_at": "2026-11-28T00:00:00Z"},
                        "extra_usage": {"is_enabled": False, "monthly_limit": None, "used_credits": None, "utilization": None, "currency": "USD"},
                    },
                    "behaviors": None,
                }
            sys.stdout.write(json.dumps({"type": "control_response", "response": {"subtype": "success", "request_id": req_id, "response": resp}}) + "\n")
            sys.stdout.flush()
    sys.exit(0)

if args[:2] == ["auth", "login"]:
    browser = os.environ.get("BROWSER")
    if browser:
        subprocess.run([browser, "https://claude.com/cai/oauth/authorize?loopback=1"], check=False)
    sys.stdout.write("Opening browser to sign in...\n")
    sys.stdout.write("If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?code=true&state=s123\n")
    sys.stdout.write("Paste code here if prompted > ")
    sys.stdout.flush()
    line = sys.stdin.readline()
    with open(os.path.join(home, ".claude-stdin.log"), "a") as f:
        f.write(line)
    code = line.strip()
    if code == "good-code#s123":
        method = "console" if "--console" in args else "claudeai"
        email = "claude@example.com"
        if "--email" in args:
            email = args[args.index("--email") + 1]
        with open(state, "w") as f:
            json.dump({"loggedIn": True, "authMethod": method, "email": email, "subscriptionType": "max"}, f)
        sys.stdout.write("Login successful.\n")
        sys.exit(0)
    sys.stderr.write("Invalid authorization code.\n")
    sys.exit(1)

sys.exit(2)
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
async fn claude_oauth_suppresses_browser_submits_via_stdin_and_handles_invalid_code() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let bin = write_fake_claude(tmp.path());
    let opener_log = tmp.path().join("opener.log");
    // Safety: isolated integration test records noop-opener invocations to a temp path.
    unsafe { std::env::set_var("AGENT_AUTH_NOOP_OPENER_LOG", &opener_log) };

    let env = Environment {
        mode: Mode::Agent,
        home: Some(home.clone()),
        runtime_dir: tmp.path().join("rt"),
        worker_exe: PathBuf::from(env!("CARGO_BIN_EXE_agent-auth")),
    };

    // Start claude login with optional flags
    let mut out = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "claude",
            "--console",
            "--email",
            "custom@example.com",
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
    let started: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(started["provider"], "claude");
    assert_eq!(started["method"], "oauth");
    assert_eq!(started["expected_input"]["kind"], "code");
    assert_eq!(started["expected_input"]["required"], true);
    assert_eq!(
        started["auth_url"],
        "https://claude.com/cai/oauth/authorize?code=true&state=s123"
    );
    let sid = started["session_id"].as_str().unwrap().to_owned();

    // Confirm browser opener was intercepted by __noop-opener
    let logged = fs::read_to_string(&opener_log).unwrap();
    assert!(logged.contains("https://claude.com/cai/oauth/authorize?loopback=1"));

    // Submitting without input fails cleanly while keeping session alive
    let err = cli::execute(
        ["agent-auth", "session", "submit", &sid],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "invalid_input");

    // Submitting a Claude OAuth callback URL is rejected before writing to stdin,
    // keeps the session awaiting_input, and never leaks submitted credentials.
    let callback_url = "https://platform.claude.com/oauth/code/callback?code=secret-code-123&state=secret-state-456";
    let url_err = cli::execute(
        [
            "agent-auth",
            "session",
            "submit",
            &sid,
            "--input",
            callback_url,
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(url_err.code(), "invalid_input");
    let url_msg = url_err.to_string();
    assert!(
        url_msg.contains("code#state"),
        "unexpected error: {url_msg}"
    );
    assert!(!url_msg.contains("secret-code-123"));
    assert!(!url_msg.contains("secret-state-456"));
    assert!(!url_msg.contains("platform.claude.com"));

    // Session must remain awaiting_input (never exchanging) and nothing written to stdin
    out.clear();
    cli::execute(
        ["agent-auth", "session", "status", &sid, "--json"],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    let still_waiting: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(still_waiting["status"], "awaiting_input");
    assert!(!home.join(".claude-stdin.log").exists());

    // Scheme-less callback URL via --input-stdin is also rejected cleanly
    let mut bad_stdin =
        Cursor::new("platform.claude.com/oauth/code/callback?code=secret-2&state=st-2\n");
    let schemeless_err = cli::execute_with_io(
        ["agent-auth", "session", "submit", &sid, "--input-stdin"],
        &env,
        &mut bad_stdin,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(schemeless_err.code(), "invalid_input");
    let schemeless_msg = schemeless_err.to_string();
    assert!(schemeless_msg.contains("code#state"));
    assert!(!schemeless_msg.contains("secret-2"));
    assert!(!home.join(".claude-stdin.log").exists());

    // Submit valid code#state via --input-stdin on the same session
    out.clear();
    let mut stdin = Cursor::new("good-code#s123\n");
    cli::execute_with_io(
        [
            "agent-auth",
            "session",
            "submit",
            &sid,
            "--input-stdin",
            "--json",
        ],
        &env,
        &mut stdin,
        &mut out,
    )
    .await
    .unwrap();
    let done: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(done["status"], "authenticated");
    assert_eq!(done["account"]["email"], "custom@example.com");
    assert_eq!(done["account"]["auth_method"], "console");
    assert_eq!(
        fs::read_to_string(home.join(".claude-stdin.log")).unwrap(),
        "good-code#s123\n"
    );

    // Verify status, usage & logout
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "status",
            "claude",
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
    let st: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(st["status"], "authenticated");

    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "usage",
            "claude",
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
    let cu: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(cu["status"], "available");
    assert_eq!(cu["plan"], "max");
    assert_eq!(cu["buckets"][0]["id"], "claude-5h");
    assert_eq!(cu["buckets"][1]["id"], "claude-weekly");

    // Unavailable plan rate limits
    fs::write(home.join(".claude-no-limits"), "1").unwrap();
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "usage",
            "claude",
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
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["status"],
        "unavailable"
    );
    fs::remove_file(home.join(".claude-no-limits")).unwrap();

    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "logout",
            "claude",
            "--provider-bin",
            bin.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
        ],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    assert!(String::from_utf8(out).unwrap().contains("logged_out"));

    // Invalid code surfaces provider_failed
    let mut out2 = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "claude",
            "--provider-bin",
            bin.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--json",
        ],
        &env,
        &mut out2,
    )
    .await
    .unwrap();
    let sid2 = serde_json::from_slice::<serde_json::Value>(&out2).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let fail = cli::execute(
        [
            "agent-auth",
            "session",
            "submit",
            &sid2,
            "--input",
            "bad-code",
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(fail.code(), "provider_failed");

    // Start with --sso and cancel cleanly
    let mut out3 = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "claude",
            "--sso",
            "--provider-bin",
            bin.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--json",
        ],
        &env,
        &mut out3,
    )
    .await
    .unwrap();
    let sid3 = serde_json::from_slice::<serde_json::Value>(&out3).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut cancel_out = Vec::new();
    cli::execute(
        ["agent-auth", "session", "cancel", &sid3, "--json"],
        &env,
        &mut cancel_out,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&cancel_out).unwrap()["status"],
        "cancelled"
    );

    // Fake claude exiting without printing a URL surfaces provider_failed
    let bad_bin = tmp.path().join("bad-claude");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o755)
            .open(&bad_bin)
            .unwrap();
        f.write_all(b"#!/bin/sh\necho 'broken output' >&2\nexit 1\n")
            .unwrap();
    }
    let err = cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "claude",
            "--provider-bin",
            bad_bin.to_str().unwrap(),
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "provider_failed");

    let status_err = cli::execute(
        [
            "agent-auth",
            "provider",
            "status",
            "claude",
            "--provider-bin",
            bad_bin.to_str().unwrap(),
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(status_err.code(), "provider_failed");

    let logout_err = cli::execute(
        [
            "agent-auth",
            "provider",
            "logout",
            "claude",
            "--provider-bin",
            bad_bin.to_str().unwrap(),
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(logout_err.code(), "provider_failed");

    unsafe { std::env::remove_var("AGENT_AUTH_NOOP_OPENER_LOG") };
}
