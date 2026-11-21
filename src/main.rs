#[tokio::main(flavor = "current_thread")]
async fn main() {
    let code = agent_auth_cli::cli::run_from_env().await;
    if code != 0 {
        std::process::exit(code);
    }
}
