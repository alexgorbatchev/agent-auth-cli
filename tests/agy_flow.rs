use agent_auth_cli::cli::{self, Environment};
use cli_command_kit::Mode;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Instant,
};

fn write_fake_agy(dir: &Path) -> PathBuf {
    let path = dir.join("fake-agy");
    let script = r#"#!/usr/bin/env python3
import json, os, subprocess, sys, time

home = os.environ["HOME"]
state = os.path.join(home, ".agy-auth.txt")
args = sys.argv[1:]

if args[:2] == ["acp", "--login"]:
    sys.stdout.write("Open this link in a browser to log in with Google:\n\n")
    sys.stdout.write("  https://accounts.google.com/o/oauth2/auth?client_id=test&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback&state=st1\n\n")
    sys.stdout.write("Then paste the authorization code, or the full URL of the page you land on, and press Enter:\n")
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        sys.stdout.write("login cancelled: no authorization code was entered\n")
        sys.exit(1)
    val = line.strip()
    if val == "valid-code" or "code=valid-code" in val:
        with open(state, "w") as f:
            f.write("agy-user@example.com")
        sys.stdout.write("OAuth: authenticated successfully as agy-user@example.com\n")
        sys.exit(0)
    sys.stderr.write("OAuth token exchange failed\n")
    sys.exit(1)

if len(args) >= 4 and args[0] == "-p" and args[1] == "/usage":
    if os.path.exists(state):
        payload = {
            "status": "SUCCESS",
            "command": {
                "name": "usage",
                "data": {
                    "groups": [
                        {
                            "name": "Gemini Models",
                            "buckets": [
                                {"id": "gemini-weekly", "remaining_fraction": 0.99, "reset_time": "2026-11-28T14:08:15Z"},
                                {"id": "gemini-5h", "remaining_fraction": 0.95, "reset_time": "2026-11-21T19:08:15Z"},
                            ],
                        }
                    ]
                },
            },
        }
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.exit(0)
    # Simulate real unauthenticated agy: prints auth prompt, tries `open` on PATH, waits 60s!
    sys.stdout.write("Authentication required. Please visit the URL to log in:\n  https://accounts.google.com/o/oauth2/auth\nWaiting for authentication (timeout 60s)...\n")
    sys.stdout.flush()
    subprocess.run(["open", "https://accounts.google.com/o/oauth2/auth"], check=False)
    time.sleep(60)
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
async fn agy_status_aborts_early_without_browser_and_acp_login_accepts_url_and_code() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let bin = write_fake_agy(tmp.path());
    let opener_log = tmp.path().join("agy-opener.log");
    unsafe { std::env::set_var("AGENT_AUTH_NOOP_OPENER_LOG", &opener_log) };

    let env = Environment {
        mode: Mode::Agent,
        home: Some(home.clone()),
        runtime_dir: tmp.path().join("rt"),
        worker_exe: PathBuf::from(env!("CARGO_BIN_EXE_agent-auth")),
    };

    // Unauthenticated status must abort immediately (<< 60s) and never open a real browser
    let t0 = Instant::now();
    let mut out = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "status",
            "agy",
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
    assert!(
        t0.elapsed().as_secs() < 5,
        "agy unauthenticated status must abort early, took {:?}",
        t0.elapsed()
    );
    let st: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(st["status"], "unauthenticated");

    // Start agy acp --login (keeps stdin open!)
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "agy",
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
    assert_eq!(started["provider"], "agy");
    assert_eq!(started["expected_input"]["kind"], "code_or_url");
    assert_eq!(started["expected_input"]["required"], true);
    let sid = started["session_id"].as_str().unwrap().to_owned();

    // Submit full callback URL
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "session",
            "submit",
            &sid,
            "--input",
            "https://antigravity.google/oauth-callback?code=valid-code&state=st1",
            "--json",
        ],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    let done: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(done["status"], "authenticated");
    assert_eq!(done["account"]["email"], "agy-user@example.com");

    // Now status returns authenticated with usage_buckets
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "status",
            "agy",
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
    let authed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(authed["status"], "authenticated");
    let buckets = authed["account"]["usage_buckets"].as_array().unwrap();
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0]["id"], "gemini-weekly");
    assert_eq!(buckets[0]["remaining_fraction"], 0.99);
    assert_eq!(buckets[0]["reset_time"], "2026-11-28T14:08:15Z");

    // Start + invalid code submission -> provider_failed
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "agy",
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
    let sid_bad = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let err = cli::execute(
        [
            "agent-auth",
            "session",
            "submit",
            &sid_bad,
            "--input",
            "nope",
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "provider_failed");

    // Start using `antigravity` alias + cancel cleanly (reports canonical provider `agy`)
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "antigravity",
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
    let started_alias: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(started_alias["provider"], "agy");
    let sid_cancel = started_alias["session_id"].as_str().unwrap().to_owned();
    out.clear();
    cli::execute(
        ["agent-auth", "session", "cancel", &sid_cancel, "--json"],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["status"],
        "cancelled"
    );

    // Status & usage via `antigravity` alias both resolve to `agy`
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "status",
            "antigravity",
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
    let alias_status: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(alias_status["provider"], "agy");
    assert_eq!(alias_status["status"], "authenticated");

    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "usage",
            "antigravity",
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
    let alias_usage: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(alias_usage["provider"], "agy");
    assert_eq!(alias_usage["status"], "available");
    assert_eq!(alias_usage["buckets"][0]["id"], "gemini-weekly");
    assert!((alias_usage["buckets"][0]["used_fraction"].as_f64().unwrap() - 0.01).abs() < 1e-6);

    // Fake agy exiting without URL surfaces provider_failed
    let bad_bin = tmp.path().join("bad-agy");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o755)
            .open(&bad_bin)
            .unwrap();
        f.write_all(b"#!/bin/sh\necho 'broken' >&2\nexit 1\n")
            .unwrap();
    }
    let err = cli::execute(
        [
            "agent-auth",
            "provider",
            "login",
            "agy",
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
            "agy",
            "--provider-bin",
            bad_bin.to_str().unwrap(),
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(status_err.code(), "provider_failed");

    unsafe { std::env::remove_var("AGENT_AUTH_NOOP_OPENER_LOG") };
}
