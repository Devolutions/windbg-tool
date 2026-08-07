use crate::jobs::{self, JobRequest, SweepWatchMemoryJobRequest};
use crate::state::ServiceState;
use crate::tools::{self, ToolCall};
use anyhow::Context;
use rmcp::model::Tool;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::targets::TargetSummary;
use crate::ttd_replay::SessionSummary;

#[derive(Clone)]
pub struct ReplayService {
    state: Arc<Mutex<ServiceState>>,
    started: Instant,
    started_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceHealth {
    pub name: String,
    pub version: String,
    pub pid: u32,
    pub uptime_seconds: u64,
    pub started_unix_ms: u128,
    pub active_sessions: usize,
    pub active_cursors: usize,
    pub active_targets: usize,
    pub active_live_targets: usize,
    pub active_dump_targets: usize,
    pub active_jobs: usize,
}

impl Default for ReplayService {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(ServiceState::default())),
            started: Instant::now(),
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
        }
    }
}

impl ReplayService {
    pub fn list_tools(&self) -> Vec<Tool> {
        tools::definitions()
    }

    pub async fn call_tool(&self, call: ToolCall) -> anyhow::Result<Value> {
        match call.name.as_str() {
            "job_start_watch_memory_sweep" => {
                let request: SweepWatchMemoryJobRequest =
                    serde_json::from_value(call.arguments).context("invalid tool arguments")?;
                return Ok(serde_json::to_value(
                    jobs::start_watch_memory_sweep(self.state.clone(), request).await?,
                )?);
            }
            "job_list" => {
                return Ok(serde_json::to_value(
                    jobs::list_jobs(self.state.clone()).await?,
                )?);
            }
            "job_status" => {
                let request: JobRequest =
                    serde_json::from_value(call.arguments).context("invalid tool arguments")?;
                return Ok(serde_json::to_value(
                    jobs::status(self.state.clone(), request).await?,
                )?);
            }
            "job_result" => {
                let request: JobRequest =
                    serde_json::from_value(call.arguments).context("invalid tool arguments")?;
                return Ok(serde_json::to_value(
                    jobs::result(self.state.clone(), request).await?,
                )?);
            }
            "job_cancel" => {
                let request: JobRequest =
                    serde_json::from_value(call.arguments).context("invalid tool arguments")?;
                return Ok(serde_json::to_value(
                    jobs::cancel(self.state.clone(), request).await?,
                )?);
            }
            _ => {}
        }

        let mut state = self.state.lock().await;
        tools::call(&mut state, call).await
    }

    pub async fn health(&self) -> ServiceHealth {
        let state = self.state.lock().await;
        ServiceHealth {
            name: "windbg-tool-daemon".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            uptime_seconds: self.started.elapsed().as_secs(),
            started_unix_ms: self.started_unix_ms,
            active_sessions: state.ttd.session_count(),
            active_cursors: state.ttd.cursor_count(),
            active_targets: state.targets.target_count(),
            active_live_targets: state.targets.live_target_count(),
            active_dump_targets: state.targets.dump_target_count(),
            active_jobs: state.jobs.job_count(),
        }
    }

    pub async fn sessions(&self) -> Vec<SessionSummary> {
        self.state.lock().await.ttd.session_summaries()
    }

    pub async fn targets(&self) -> anyhow::Result<Vec<TargetSummary>> {
        Ok(self.state.lock().await.targets.list_targets()?.targets)
    }
}
