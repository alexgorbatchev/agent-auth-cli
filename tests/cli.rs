use agent_auth_cli::{
    AuthError,
    cli::{self, Environment},
    protocol::{ErrorDetail, SCHEMA_VERSION},
};
use cli_command_kit::Mode;
use std::path::PathBuf;

fn test_env(mode: Mode, dir: &std::path::Path) -> Environment {
    Environment {
        mode,
        home: Some(dir.to_path_buf()),
        runtime_dir: dir.join("rt"),
        worker_exe: PathBuf::from(env!("CARGO_BIN_EXE_agent-auth")),
    }
}

#[test]
fn help_paths_include_agent_alert_and_human_tree_glyphs() {
    for mode in [Mode::Human, Mode::Agent] {
        for path in [
            vec![],
            vec!["provider"],
            vec!["provider", "list"],
            vec!["provider", "status"],
            vec!["provider", "usage"],
            vec!["provider", "logout"],
            vec!["session"],
            vec!["session", "start"],
            vec!["session", "submit"],
            vec!["session", "wait"],
            vec!["session", "status"],
            vec!["session", "list"],
            vec!["session", "cancel"],
            vec!["completion"],
            vec!["completion", "script"],
            vec!["skill"],
            vec!["help"],
            vec!["help", "session"],
        ] {
            let is_help_sub = path.first() == Some(&"help");
            let mut args = vec!["agent-auth"];
            args.extend(path);
            if !is_help_sub {
                args.push("--help");
            }
            let err = cli::command(mode)
                .try_get_matches_from(args.clone())
                .unwrap_err();
            assert!(!err.use_stderr(), "{args:?}: {err}");
            let rendered = err.to_string();
            assert_eq!(
                rendered.starts_with("ALERT: Agents must read `AGENT=1 agent-auth skill`"),
                mode == Mode::Agent
            );
            if mode == Mode::Human && args == vec!["agent-auth", "--help"] {
                assert!(rendered.contains("├─") || rendered.contains("╰─"));
                assert!(rendered.contains("skill"));
                assert!(!rendered.contains("__worker"));
                assert!(!rendered.contains("__noop-opener"));
            }
        }
    }
}

#[tokio::test]
async fn provider_list_and_completion_render_cleanly_in_all_modes() {
    let tmp = tempfile::tempdir().unwrap();
    for mode in [Mode::Human, Mode::Agent] {
        let env = test_env(mode, tmp.path());
        let mut out = Vec::new();
        let rc = cli::execute(["agent-auth", "provider", "list"], &env, &mut out)
            .await
            .unwrap();
        assert_eq!(rc, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("codex"));
        assert!(text.contains("claude"));
        assert!(text.contains("agy"));

        let mut json_out = Vec::new();
        cli::execute(
            ["agent-auth", "provider", "list", "--json"],
            &env,
            &mut json_out,
        )
        .await
        .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
        assert_eq!(val["schema_version"], SCHEMA_VERSION);
        assert_eq!(val["providers"].as_array().unwrap().len(), 3);
        assert_eq!(val["providers"][0]["id"], "codex");
        assert_eq!(val["providers"][0]["default_method"], "device");
        assert_eq!(val["providers"][2]["id"], "agy");
        assert_eq!(val["providers"][2]["aliases"][0], "antigravity");
        assert!(text.contains("antigravity"));
    }

    let env = test_env(Mode::Human, tmp.path());
    for extra in [vec![], vec!["--no-descriptions"]] {
        let mut out = Vec::new();
        let mut args = vec!["agent-auth", "completion", "script", "zsh"];
        args.extend(extra);
        let rc = cli::execute(args, &env, &mut out).await.unwrap();
        assert_eq!(rc, 0);
        assert!(!out.is_empty());
    }
}

#[tokio::test]
async fn error_handling_and_argument_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let env = test_env(Mode::Agent, tmp.path());

    // Unsupported provider
    let err = cli::execute(
        ["agent-auth", "session", "start", "nonexistent"],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "unsupported_provider");
    assert_eq!(err.exit_code(), 1);

    // Unsupported method (device on claude)
    let err = cli::execute(
        [
            "agent-auth",
            "session",
            "start",
            "claude",
            "--method",
            "device",
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "unsupported_method");

    // --provider-bin requires a single provider on provider status and provider usage
    for sub in ["status", "usage"] {
        let err = cli::execute(
            ["agent-auth", "provider", sub, "--provider-bin", "/bin/true"],
            &env,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }

    // Conflicting submit flags
    let err = cli::execute(
        [
            "agent-auth",
            "session",
            "submit",
            "0123456789abcdef",
            "--input",
            "abc",
            "--input-stdin",
        ],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.exit_code(), 2);

    // Missing session
    let err = cli::execute(
        ["agent-auth", "session", "status", "0123456789abcdef"],
        &env,
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "session_not_found");

    // Agy (and its `antigravity` alias) logout returns typed unsupported_operation
    for name in ["agy", "antigravity"] {
        let err = cli::execute(
            ["agent-auth", "provider", "logout", name],
            &env,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), "unsupported_operation");
        assert!(err.hint().unwrap().contains("/logout"));
    }

    // ErrorDetail roundtrip conversions
    for code in [
        "provider_not_found",
        "unsupported_provider",
        "unsupported_method",
        "unsupported_operation",
        "session_not_found",
        "session_expired",
        "invalid_input",
        "callback_port_in_use",
        "timeout",
        "cancelled",
        "protocol_error",
        "provider_failed",
    ] {
        let converted = AuthError::from_detail(ErrorDetail {
            code: code.into(),
            message: "msg".into(),
            retryable: true,
            hint: Some("hint".into()),
        });
        assert_eq!(converted.code(), code);
        let detail = converted.to_detail(Some(tmp.path()));
        assert_eq!(detail.code, code);
    }
}
