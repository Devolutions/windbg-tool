use anyhow::Context;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
                let client = DaemonClient::new(pipe.clone());
                if let Ok(health) = client.health().await {
                    return print_value(health, output);
                }
                spawn_daemon(&pipe)?;
                let client = DaemonClient::new(pipe);
                print_value(client.health().await?, output)
            } else {
                run_daemon(pipe).await
            }
        }
        DaemonCommand::Status => {
            let client = DaemonClient::new(pipe);
            print_value(client.health().await?, output)
        }
        DaemonCommand::Ensure => {
            let client = DaemonClient::new(pipe.clone());
            if let Ok(health) = client.health().await {
                return print_value(health, output);
            }
            spawn_daemon(&pipe)?;
            let client = DaemonClient::new(pipe);
            print_value(client.health().await?, output)
        }
        DaemonCommand::Shutdown => {
            let client = DaemonClient::new(pipe);
            print_value(client.shutdown().await?, output)
        }
    }
}

fn spawn_daemon(pipe: &str) -> anyhow::Result<()> {
    let daemon_path = daemon_exe_path()?;
    Command::new(&daemon_path)
        .arg("daemon")
        .arg("start")
        .arg("--pipe")
        .arg(pipe)
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
