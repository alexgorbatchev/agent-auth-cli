use agent_auth_cli::cli::{self, Environment};
use cli_command_kit::Mode;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

fn write_fake_codex(dir: &Path) -> PathBuf {
    let path = dir.join("fake-codex");
    let script = r#"#!/usr/bin/env python3
import http.server, json, os, socketserver, sys, threading, time

state_dir = os.environ.get("CODEX_HOME") or os.path.join(os.environ["HOME"], ".codex")
os.makedirs(state_dir, exist_ok=True)
auth_file = os.path.join(state_dir, "auth.json")
cancel_log = os.path.join(state_dir, "cancelled.log")
port_conflict_flag = os.path.join(state_dir, "port_in_use")
fail_login_flag = os.path.join(state_dir, "fail_login")
device_delay_file = os.path.join(state_dir, "device_delay")

if len(sys.argv) >= 2 and sys.argv[1] == "logout":
    if os.path.exists(auth_file):
        os.remove(auth_file)
    sys.exit(0)

if len(sys.argv) >= 2 and sys.argv[1] == "app-server":
    out_lock = threading.Lock()
    def send(obj):
        with out_lock:
            sys.stdout.write(json.dumps(obj) + "\n")
            sys.stdout.flush()

    active_server = None
    active_cancelled = threading.Event()

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        msg = json.loads(raw)
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            send({"id": req_id, "result": {"codexHome": state_dir, "platformFamily": "unix", "platformOs": "macos", "userAgent": "fake"}})
            send({"method": "remoteControl/status/changed", "params": {"status": "disabled"}})
        elif method == "initialized":
            pass
        elif method == "account/read":
            acct = None
            if os.path.exists(auth_file):
                acct = json.loads(open(auth_file).read())
            send({"id": req_id, "result": {"account": acct, "requiresOpenaiAuth": True}})
        elif method == "account/rateLimits/read":
            send({
                "id": req_id,
                "result": {
                    "ordinaryUsageAllowed": True,
                    "rateLimits": {
                        "limitId": "codex",
                        "limitName": None,
                        "planType": "pro",
                        "primary": {"usedPercent": 86, "windowDurationMins": 10080, "resetsAt": 1795474367},
                        "secondary": {"usedPercent": 15, "windowDurationMins": 300, "resetsAt": 1795400000},
                        "credits": {"hasCredits": False, "unlimited": False, "balance": "0"},
                    },
                    "rateLimitsByLimitId": {
                        "codex": {
                            "limitId": "codex",
                            "limitName": None,
                            "planType": "pro",
                            "primary": {"usedPercent": 86, "windowDurationMins": 10080, "resetsAt": 1795474367},
                            "secondary": {"usedPercent": 15, "windowDurationMins": 300, "resetsAt": 1795400000},
                            "credits": {"hasCredits": False, "unlimited": False, "balance": "0"},
                        }
                    },
                },
            })
        elif method == "account/login/start":
            kind = params.get("type")
            if os.path.exists(port_conflict_flag) and kind == "chatgpt":
                send({"id": req_id, "error": {"code": -32000, "message": "Port 1455 is already in use"}})
                continue
            login_id = "login-123"
            active_cancelled.clear()
            if kind == "chatgptDeviceCode":
                send({
                    "id": req_id,
                    "result": {
                        "type": "chatgptDeviceCode",
                        "loginId": login_id,
                        "verificationUrl": "https://auth.openai.com/codex/device",
                        "userCode": "TEST-CODE",
                    },
                })
                delay = float(open(device_delay_file).read().strip()) if os.path.exists(device_delay_file) else 0.15
                def finish_device():
                    if active_cancelled.wait(delay):
                        return
                    if os.path.exists(fail_login_flag):
                        send({"method": "account/login/completed", "params": {"loginId": login_id, "success": False, "error": "device code rejected"}})
                        return
                    with open(auth_file, "w") as f:
                        json.dump({"type": "chatgpt", "email": "device@example.com", "planType": "pro", "workspaceName": "Acme"}, f)
                    send({"method": "account/login/completed", "params": {"loginId": login_id, "success": True, "error": None}})
                threading.Thread(target=finish_device, daemon=True).start()
            elif kind == "chatgpt":
                class Handler(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        if self.path.startswith("/auth/callback") and "code=ok" in self.path:
                            with open(auth_file, "w") as f:
                                json.dump({"type": "chatgpt", "email": "oauth@example.com", "planType": "plus", "workspaceName": None}, f)
                            self.send_response(200)
                            self.end_headers()
                            self.wfile.write(b"ok")
                            threading.Thread(target=lambda: send({"method": "account/login/completed", "params": {"loginId": login_id, "success": True, "error": None}}), daemon=True).start()
                        else:
                            self.send_response(400)
                            self.end_headers()
                    def log_message(self, *args):
                        pass

                server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
                port = server.server_address[1]
                active_server = server
                threading.Thread(target=server.serve_forever, daemon=True).start()
                auth_url = f"https://auth.openai.com/oauth/authorize?response_type=code&redirect_uri=http%3A%2F%2F127.0.0.1%3A{port}%2Fauth%2Fcallback&state=xyz"
                send({"id": req_id, "result": {"type": "chatgpt", "loginId": login_id, "authUrl": auth_url}})
        elif method == "account/login/cancel":
            active_cancelled.set()
            with open(cancel_log, "a") as f:
                f.write(params.get("loginId", "") + "\n")
            if active_server:
                active_server.shutdown()
                active_server = None
            send({"id": req_id, "result": {"status": "canceled"}})
            send({"method": "account/login/completed", "params": {"loginId": params.get("loginId"), "success": False, "error": "canceled"}})
    if active_server:
        active_server.shutdown()
    sys.exit(0)

sys.stderr.write("unexpected codex invocation\n")
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

fn env_for(tmp: &Path, mode: Mode) -> Environment {
    Environment {
        mode,
        home: Some(tmp.join("home")),
        runtime_dir: tmp.join("rt"),
        worker_exe: PathBuf::from(env!("CARGO_BIN_EXE_agent-auth")),
    }
}

#[tokio::test]
async fn codex_device_flow_is_default_completes_in_background_and_checks_status_and_logout() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let bin = write_fake_codex(tmp.path());
    let env = env_for(tmp.path(), Mode::Agent);

    // Unauthenticated status & usage initially
    let mut out = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "status",
            "codex",
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
    assert_eq!(st["status"], "unauthenticated");

    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "usage",
            "codex",
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
    let u0: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(u0["status"], "unauthenticated");

    // Start (defaults to device!)
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "session",
            "start",
            "codex",
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
    assert_eq!(started["provider"], "codex");
    assert_eq!(started["method"], "device");
    assert_eq!(started["status"], "awaiting_input");
    assert_eq!(started["auth_url"], "https://auth.openai.com/codex/device");
    assert_eq!(started["user_code"], "TEST-CODE");
    assert_eq!(started["expected_input"]["kind"], "none");
    assert_eq!(started["expected_input"]["required"], false);
    let sid = started["session_id"].as_str().unwrap().to_owned();

    // Let background device completion happen BEFORE wait is called!
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    out.clear();
    cli::execute(
        ["agent-auth", "session", "wait", &sid, "--json"],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    let done: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(done["status"], "authenticated");
    assert_eq!(done["account"]["email"], "device@example.com");
    assert_eq!(done["account"]["plan"], "pro");
    assert_eq!(done["account"]["workspace"], "Acme");

    // Verify status shows authenticated in both human and agent modes
    for mode in [Mode::Human, Mode::Agent] {
        let mut status_out = Vec::new();
        cli::execute(
            [
                "agent-auth",
                "provider",
                "status",
                "codex",
                "--provider-bin",
                bin.to_str().unwrap(),
                "--home",
                home.to_str().unwrap(),
            ],
            &env_for(tmp.path(), mode),
            &mut status_out,
        )
        .await
        .unwrap();
        let s = String::from_utf8(status_out).unwrap();
        assert!(s.contains("authenticated"));
        assert!(s.contains("device@example.com"));

        let mut usage_out = Vec::new();
        cli::execute(
            [
                "agent-auth",
                "provider",
                "usage",
                "codex",
                "--provider-bin",
                bin.to_str().unwrap(),
                "--home",
                home.to_str().unwrap(),
            ],
            &env_for(tmp.path(), mode),
            &mut usage_out,
        )
        .await
        .unwrap();
        let us = String::from_utf8(usage_out).unwrap();
        assert!(us.contains("codex-weekly"));
        assert!(us.contains("codex-5h"));
    }

    // Usage JSON structure check
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "usage",
            "codex",
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
    let u_json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(u_json["status"], "available");
    assert_eq!(u_json["buckets"].as_array().unwrap().len(), 2);
    assert_eq!(u_json["buckets"][0]["id"], "codex-weekly");

    // Logout
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "provider",
            "logout",
            "codex",
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
    let lo: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(lo["status"], "logged_out");
}

#[tokio::test]
async fn codex_oauth_flow_replays_callback_blocks_ssrf_and_reports_port_conflict() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let bin = write_fake_codex(tmp.path());
    let env = env_for(tmp.path(), Mode::Agent);

    let mut out = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "session",
            "start",
            "codex",
            "--method",
            "oauth",
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
    assert_eq!(started["method"], "oauth");
    assert_eq!(started["expected_input"]["kind"], "callback_url_optional");
    let sid = started["session_id"].as_str().unwrap().to_owned();
    let auth_url = started["auth_url"].as_str().unwrap();
    let parsed = url::Url::parse(auth_url).unwrap();
    let redirect = parsed
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .unwrap()
        .1
        .into_owned();

    // Reject SSRF host while keeping session alive
    let bad = cli::execute(
        [
            "agent-auth",
            "session",
            "submit",
            &sid,
            "--input",
            "http://evil.example:1455/auth/callback?code=ok",
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(bad.code(), "invalid_input");

    // Submit valid loopback callback URL -> replays HTTP GET locally and completes
    out.clear();
    let callback_with_code = format!("{redirect}?code=ok&state=xyz");
    cli::execute(
        [
            "agent-auth",
            "session",
            "submit",
            &sid,
            "--input",
            &callback_with_code,
            "--json",
        ],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    let done: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(done["status"], "authenticated");
    assert_eq!(done["account"]["email"], "oauth@example.com");

    // Port conflict error mapping
    let codex_home = home.join(".codex");
    fs::create_dir_all(&codex_home).unwrap();
    fs::write(codex_home.join("port_in_use"), "1").unwrap();
    let err = cli::execute(
        [
            "agent-auth",
            "session",
            "start",
            "codex",
            "--method",
            "oauth",
            "--provider-bin",
            bin.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "callback_port_in_use");
}

#[tokio::test]
async fn codex_device_rejects_pasted_input_and_supports_clean_cancel() {
    let tmp = tempfile::Builder::new()
        .prefix("aa-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = tmp.path().join("home");
    let codex_home = home.join(".codex");
    fs::create_dir_all(&codex_home).unwrap();
    fs::write(codex_home.join("device_delay"), "30").unwrap();
    let bin = write_fake_codex(tmp.path());
    let env = env_for(tmp.path(), Mode::Agent);

    let mut out = Vec::new();
    cli::execute(
        [
            "agent-auth",
            "session",
            "start",
            "codex",
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
    let sid = started["session_id"].as_str().unwrap().to_owned();

    // Passing non-empty input to device login fails cleanly without killing session
    let err = cli::execute(
        ["agent-auth", "session", "submit", &sid, "--input", "extra"],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "invalid_input");

    // Cancel sends account/login/cancel and cleans up
    out.clear();
    cli::execute(
        ["agent-auth", "session", "cancel", &sid, "--json"],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    let cancelled: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(cancelled["status"], "cancelled");
    let cancel_log = fs::read_to_string(codex_home.join("cancelled.log")).unwrap();
    assert!(cancel_log.contains("login-123"));

    // Empty submit on device login falls through to wait and succeeds
    fs::write(codex_home.join("device_delay"), "0.1").unwrap();
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "session",
            "start",
            "codex",
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
    let sid2 = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    out.clear();
    cli::execute(
        ["agent-auth", "session", "submit", &sid2, "--json"],
        &env,
        &mut out,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["status"],
        "authenticated"
    );

    // Device login failure surfaces provider_failed
    fs::write(codex_home.join("fail_login"), "1").unwrap();
    out.clear();
    cli::execute(
        [
            "agent-auth",
            "session",
            "start",
            "codex",
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
    let sid3 = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let err = cli::execute(
        ["agent-auth", "session", "wait", &sid3],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "provider_failed");
}
