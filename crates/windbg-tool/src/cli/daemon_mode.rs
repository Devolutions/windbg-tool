use anyhow::Context;
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::output::{print_value, OutputOptions};
use super::{run_daemon, DaemonClient, DaemonCommand};

pub(super) async fn run_daemon_command(
    command: DaemonCommand,
    pipe: String,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    match command {
        DaemonCommand::Start { detach } => {
            if detach {
                print_value(ensure_daemon(&pipe).await?, output)
            } else {
                run_daemon(pipe).await
            }
        }
        DaemonCommand::Status => {
            let client = DaemonClient::new(pipe);
            print_value(client.health().await?, output)
        }
        DaemonCommand::Ensure => print_value(ensure_daemon(&pipe).await?, output),
        DaemonCommand::Shutdown => {
            let client = DaemonClient::new(pipe);
            print_value(client.shutdown().await?, output)
        }
    }
}

/// Ensure a long-lived daemon is listening on `pipe`, spawning one if needed.
pub(super) async fn ensure_daemon(pipe: &str) -> anyhow::Result<Value> {
    let client = DaemonClient::new(pipe.to_string());
    if let Ok(health) = client.health().await {
        return Ok(health);
    }

    spawn_daemon(pipe)?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = None;
    while Instant::now() < deadline {
        match client.health().await {
            Ok(health) => return Ok(health),
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("daemon did not become healthy on pipe {pipe}")))
    .with_context(|| format!("ensuring windbg-tool daemon on {pipe}"))
}

fn spawn_daemon(pipe: &str) -> anyhow::Result<()> {
    let daemon_path = daemon_exe_path()?;
    Command::new(&daemon_path)
        .arg("--pipe")
        .arg(pipe)
        .arg("daemon")
        .arg("start")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", daemon_path.display()))?;
    Ok(())
}

fn daemon_exe_path() -> anyhow::Result<PathBuf> {
    std::env::current_exe().context("reading current executable path")
}
