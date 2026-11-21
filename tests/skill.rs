use agent_auth_cli::cli::{self, Environment};
use cli_command_kit::Mode;
use std::{io, path::PathBuf};

const INSTALL_TEXT: &str = "Install the agent-auth skill using the Skills CLI:\n\n  npx skills add alexgorbatchev/agent-auth-cli --skill agent-auth\n\nSkill:\n\n  https://github.com/alexgorbatchev/agent-auth-cli/tree/main/skills/agent-auth\n";

struct ClosedWriter;
impl io::Write for ClosedWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn operational_documents_cover_live_command_tree_and_skill_location() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let folder = root.join("skills/agent-auth");
    let skill = std::fs::read_to_string(folder.join("SKILL.md")).unwrap();
    assert!(skill.contains("name: agent-auth\n"));
    assert!(INSTALL_TEXT.contains("--skill agent-auth\n"));
    assert!(INSTALL_TEXT.contains("/skills/agent-auth\n"));

    let mut text = skill;
    for file in ["commands.md", "providers.md", "help.md"] {
        text.push_str(&std::fs::read_to_string(folder.join("references").join(file)).unwrap());
    }
    let omissions =
        cli_command_kit::skill_omissions(&cli::command(Mode::Agent), &cli::help_options(), &text);
    assert!(omissions.is_empty(), "omissions:\n{}", omissions.join("\n"));

    let queries = std::fs::read_to_string(folder.join("references/help.md")).unwrap();
    for line in queries
        .lines()
        .filter(|line| line.starts_with("- `agent-auth "))
    {
        let command = line.trim_start_matches("- `").trim_end_matches('`');
        for mode in [Mode::Human, Mode::Agent] {
            let err = cli::command(mode)
                .try_get_matches_from(command.split_whitespace())
                .unwrap_err();
            assert!(!err.use_stderr(), "{command}: {err}");
            assert_eq!(
                err.to_string()
                    .starts_with("ALERT: Agents must read `AGENT=1 agent-auth skill`"),
                mode == Mode::Agent
            );
        }
    }
}

#[tokio::test]
async fn skill_command_output_is_exact_in_both_modes_and_rejects_extra_args() {
    let tmp = tempfile::tempdir().unwrap();
    for mode in [Mode::Human, Mode::Agent] {
        let env = Environment {
            mode,
            home: Some(tmp.path().to_path_buf()),
            runtime_dir: tmp.path().join("rt"),
            worker_exe: PathBuf::from(env!("CARGO_BIN_EXE_agent-auth")),
        };
        let mut out = Vec::new();
        let rc = cli::execute(["agent-auth", "skill"], &env, &mut out)
            .await
            .unwrap();
        assert_eq!(rc, 0);
        assert_eq!(out, INSTALL_TEXT.as_bytes());
        assert!(!env.runtime_dir.exists());

        out.clear();
        let rc = cli::execute(["agent-auth", "--version"], &env, &mut out)
            .await
            .unwrap();
        assert_eq!(rc, 0);
        assert_eq!(out, format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes());

        assert!(
            cli::execute(["agent-auth", "skill", "extra"], &env, &mut Vec::new())
                .await
                .is_err()
        );
        assert!(
            cli::execute(["agent-auth", "skill"], &env, &mut ClosedWriter)
                .await
                .is_err()
        );
    }
}
