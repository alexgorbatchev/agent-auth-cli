use crate::{
    error::{AuthError, Result},
    protocol::{SessionSnapshot, WorkerRequest, WorkerResponse},
    session::store,
};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

pub async fn query_status(runtime_dir: &Path, session_id: &str) -> Result<SessionSnapshot> {
    send_request(
        runtime_dir,
        session_id,
        WorkerRequest::Status,
        Duration::from_secs(10),
    )
    .await
}

pub async fn submit_input(
    runtime_dir: &Path,
    session_id: &str,
    input: Option<String>,
    timeout_secs: u64,
) -> Result<SessionSnapshot> {
    send_request(
        runtime_dir,
        session_id,
        WorkerRequest::Submit {
            input,
            timeout_secs,
        },
        Duration::from_secs(timeout_secs.saturating_add(15)),
    )
    .await
}

pub async fn wait_session(
    runtime_dir: &Path,
    session_id: &str,
    timeout_secs: u64,
) -> Result<SessionSnapshot> {
    send_request(
        runtime_dir,
        session_id,
        WorkerRequest::Wait { timeout_secs },
        Duration::from_secs(timeout_secs.saturating_add(15)),
    )
    .await
}

pub async fn cancel_session(runtime_dir: &Path, session_id: &str) -> Result<SessionSnapshot> {
    send_request(
        runtime_dir,
        session_id,
        WorkerRequest::Cancel,
        Duration::from_secs(15),
    )
    .await
}

pub async fn send_request(
    runtime_dir: &Path,
    session_id: &str,
    request: WorkerRequest,
    io_timeout: Duration,
) -> Result<SessionSnapshot> {
    store::validate_session_id(session_id)?;
    let sock = store::socket_path(runtime_dir, session_id);
    let stream = match UnixStream::connect(&sock).await {
        Ok(s) => s,
        Err(_) => {
            if let Some(meta) = store::read_meta(runtime_dir, session_id) {
                let expired = store::is_meta_expired(&meta);
                store::remove_session_files(runtime_dir, session_id);
                if expired {
                    return Err(AuthError::SessionExpired(session_id.to_owned()));
                }
            } else {
                store::remove_session_files(runtime_dir, session_id);
            }
            return Err(AuthError::SessionNotFound(session_id.to_owned()));
        }
    };

    let (read_half, mut write_half) = stream.into_split();
    let mut payload = serde_json::to_string(&request)?;
    payload.push('\n');
    tokio::time::timeout(Duration::from_secs(5), async {
        write_half.write_all(payload.as_bytes()).await?;
        write_half.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| AuthError::Timeout("timed out sending request to session worker".into()))??;

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let n = tokio::time::timeout(io_timeout, reader.read_line(&mut line))
        .await
        .map_err(|_| {
            AuthError::Timeout("timed out waiting for session worker response".into())
        })??;
    if n == 0 {
        return Err(AuthError::Protocol(
            "session worker closed connection without responding".into(),
        ));
    }

    let response: WorkerResponse = serde_json::from_str(line.trim())?;
    match response {
        WorkerResponse::Snapshot(snapshot) => Ok(*snapshot),
        WorkerResponse::Error(detail) => Err(AuthError::from_detail(detail)),
    }
}
