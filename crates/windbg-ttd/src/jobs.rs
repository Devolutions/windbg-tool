use crate::state::ServiceState;
use crate::ttd_replay::{
    MemoryAccessDirection, MemoryWatchpointRequest, StepDirection, StepKind, StepRequest,
};
use anyhow::{bail, Context};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

pub type JobId = u64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobSummary {
    pub job_id: JobId,
    pub kind: String,
    pub status: JobStatus,
    pub progress_current: u64,
    pub progress_total: Option<u64>,
    pub result_ready: bool,
    pub cancel_requested: bool,
    pub error: Option<String>,
    pub started_unix_ms: u128,
    pub completed_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobListResponse {
    pub jobs: Vec<JobSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobStartedResponse {
    pub job_id: JobId,
    pub job: JobSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobResultResponse {
    pub job_id: JobId,
    pub status: JobStatus,
    pub result_ready: bool,
    pub result: Option<Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct JobRequest {
    pub job_id: JobId,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SweepWatchMemoryJobRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub size: u32,
    pub access: crate::ttd_replay::MemoryAccessMask,
    pub direction: MemoryAccessDirection,
    #[serde(default)]
    pub thread_unique_id: Option<u64>,
    #[serde(default = "default_max_hits")]
    pub max_hits: usize,
}

#[derive(Default)]
pub struct JobRegistry {
    next_job_id: JobId,
    jobs: HashMap<JobId, JobRecord>,
}

struct JobRecord {
    kind: String,
    status: JobStatus,
    progress_current: u64,
    progress_total: Option<u64>,
    result: Option<Value>,
    error: Option<String>,
    cancel_requested: bool,
    started_unix_ms: u128,
    completed_unix_ms: Option<u128>,
}

impl JobRegistry {
    pub fn list(&self) -> JobListResponse {
        let mut jobs = self
            .jobs
            .iter()
            .map(|(job_id, job)| Self::summary(*job_id, job))
            .collect::<Vec<_>>();
        jobs.sort_by_key(|job| job.job_id);
        JobListResponse { jobs }
    }

    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    pub fn start_watch_memory_sweep(
        &mut self,
        request: &SweepWatchMemoryJobRequest,
    ) -> anyhow::Result<JobStartedResponse> {
        if request.max_hits == 0 {
            bail!("max_hits must be greater than zero");
        }
        if request.max_hits > 1024 {
            bail!("max_hits must not exceed 1024");
        }
        if request.direction == MemoryAccessDirection::Unknown {
            bail!("direction must be 'previous' or 'next'");
        }

        self.next_job_id += 1;
        let job_id = self.next_job_id;
        let record = JobRecord {
            kind: "watch_memory_sweep".to_string(),
            status: JobStatus::Running,
            progress_current: 0,
            progress_total: Some(request.max_hits as u64),
            result: None,
            error: None,
            cancel_requested: false,
            started_unix_ms: now_unix_ms(),
            completed_unix_ms: None,
        };
        let summary = Self::summary(job_id, &record);
        self.jobs.insert(job_id, record);
        Ok(JobStartedResponse {
            job_id,
            job: summary,
        })
    }

    pub fn status(&self, request: JobRequest) -> anyhow::Result<JobSummary> {
        let record = self
            .jobs
            .get(&request.job_id)
            .with_context(|| format!("unknown job id: {}", request.job_id))?;
        Ok(Self::summary(request.job_id, record))
    }

    pub fn result(&self, request: JobRequest) -> anyhow::Result<JobResultResponse> {
        let record = self
            .jobs
            .get(&request.job_id)
            .with_context(|| format!("unknown job id: {}", request.job_id))?;
        Ok(JobResultResponse {
            job_id: request.job_id,
            status: record.status,
            result_ready: record.result.is_some(),
            result: record.result.clone(),
            error: record.error.clone(),
        })
    }

    pub fn cancel(&mut self, request: JobRequest) -> anyhow::Result<JobSummary> {
        let record = self
            .jobs
            .get_mut(&request.job_id)
            .with_context(|| format!("unknown job id: {}", request.job_id))?;
        if record.status == JobStatus::Running {
            record.cancel_requested = true;
        }
        Ok(Self::summary(request.job_id, record))
    }

    fn summary(job_id: JobId, job: &JobRecord) -> JobSummary {
        JobSummary {
            job_id,
            kind: job.kind.clone(),
            status: job.status,
            progress_current: job.progress_current,
            progress_total: job.progress_total,
            result_ready: job.result.is_some(),
            cancel_requested: job.cancel_requested,
            error: job.error.clone(),
            started_unix_ms: job.started_unix_ms,
            completed_unix_ms: job.completed_unix_ms,
        }
    }

    fn cancel_requested(&self, job_id: JobId) -> anyhow::Result<bool> {
        Ok(self
            .jobs
            .get(&job_id)
            .with_context(|| format!("unknown job id: {job_id}"))?
            .cancel_requested)
    }

    fn set_progress(
        &mut self,
        job_id: JobId,
        current: u64,
        total: Option<u64>,
    ) -> anyhow::Result<()> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .with_context(|| format!("unknown job id: {job_id}"))?;
        job.progress_current = current;
        job.progress_total = total;
        Ok(())
    }

    fn complete(&mut self, job_id: JobId, result: Value) -> anyhow::Result<()> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .with_context(|| format!("unknown job id: {job_id}"))?;
        job.status = JobStatus::Completed;
        job.result = Some(result);
        job.completed_unix_ms = Some(now_unix_ms());
        Ok(())
    }

    fn fail(&mut self, job_id: JobId, error: anyhow::Error) -> anyhow::Result<()> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .with_context(|| format!("unknown job id: {job_id}"))?;
        job.status = JobStatus::Failed;
        job.error = Some(error.to_string());
        job.completed_unix_ms = Some(now_unix_ms());
        Ok(())
    }

    fn cancel_with_result(&mut self, job_id: JobId, result: Value) -> anyhow::Result<()> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .with_context(|| format!("unknown job id: {job_id}"))?;
        job.status = JobStatus::Cancelled;
        job.result = Some(result);
        job.completed_unix_ms = Some(now_unix_ms());
        Ok(())
    }
}

pub async fn start_watch_memory_sweep(
    state: Arc<Mutex<ServiceState>>,
    request: SweepWatchMemoryJobRequest,
) -> anyhow::Result<JobStartedResponse> {
    let started = {
        let mut state_guard = state.lock().await;
        state_guard.jobs.start_watch_memory_sweep(&request)?
    };
    let job_id = started.job_id;
    tokio::spawn(run_watch_memory_sweep_job(state, job_id, request));
    Ok(started)
}

pub async fn list_jobs(state: Arc<Mutex<ServiceState>>) -> anyhow::Result<JobListResponse> {
    Ok(state.lock().await.jobs.list())
}

pub async fn status(
    state: Arc<Mutex<ServiceState>>,
    request: JobRequest,
) -> anyhow::Result<JobSummary> {
    state.lock().await.jobs.status(request)
}

pub async fn result(
    state: Arc<Mutex<ServiceState>>,
    request: JobRequest,
) -> anyhow::Result<JobResultResponse> {
    state.lock().await.jobs.result(request)
}

pub async fn cancel(
    state: Arc<Mutex<ServiceState>>,
    request: JobRequest,
) -> anyhow::Result<JobSummary> {
    state.lock().await.jobs.cancel(request)
}

async fn run_watch_memory_sweep_job(
    state: Arc<Mutex<ServiceState>>,
    job_id: JobId,
    request: SweepWatchMemoryJobRequest,
) {
    let mut hits = Vec::new();
    let mut seen_positions = BTreeSet::new();
    let mut stop_reason = "max_hits";
    let total = request.max_hits as u64;

    for _ in 0..request.max_hits {
        let mut state_guard = state.lock().await;
        let should_cancel = match state_guard.jobs.cancel_requested(job_id) {
            Ok(value) => value,
            Err(_) => return,
        };
        if should_cancel {
            let _ = state_guard.jobs.cancel_with_result(
                job_id,
                build_sweep_result(&request, &hits, "cancelled", true),
            );
            return;
        }

        let hit = match state_guard.ttd.memory_watchpoint(MemoryWatchpointRequest {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            address: request.address,
            size: request.size,
            access: request.access,
            direction: request.direction,
            thread_unique_id: request.thread_unique_id,
        }) {
            Ok(hit) => hit,
            Err(error) => {
                let _ = state_guard.jobs.fail(job_id, error);
                return;
            }
        };

        let hit_value = match serde_json::to_value(&hit) {
            Ok(value) => value,
            Err(error) => {
                let _ = state_guard.jobs.fail(job_id, error.into());
                return;
            }
        };

        if !hit.found {
            stop_reason = "not_found";
            hits.push(hit_value);
            let _ = state_guard.jobs.complete(
                job_id,
                build_sweep_result(&request, &hits, stop_reason, false),
            );
            return;
        }

        if let Some(sequence) = hit.position.sequence.checked_into() {
            if !seen_positions.insert(sequence) {
                stop_reason = "duplicate_position";
                hits.push(hit_value);
                let _ = state_guard.jobs.complete(
                    job_id,
                    build_sweep_result(&request, &hits, stop_reason, false),
                );
                return;
            }
        }

        hits.push(hit_value);
        let direction = match request.direction {
            MemoryAccessDirection::Previous => StepDirection::Backward,
            _ => StepDirection::Forward,
        };
        if let Err(error) = state_guard.ttd.step(StepRequest {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            direction,
            kind: StepKind::Step,
            count: 1,
        }) {
            let _ = state_guard.jobs.fail(job_id, error);
            return;
        }
        let _ = state_guard
            .jobs
            .set_progress(job_id, hits.len() as u64, Some(total));
    }

    let mut state_guard = state.lock().await;
    let _ = state_guard.jobs.complete(
        job_id,
        build_sweep_result(&request, &hits, stop_reason, false),
    );
}

fn build_sweep_result(
    request: &SweepWatchMemoryJobRequest,
    hits: &[Value],
    stop_reason: &str,
    cancelled: bool,
) -> Value {
    json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "address": request.address,
        "size": request.size,
        "access": request.access,
        "direction": request.direction,
        "thread_unique_id": request.thread_unique_id,
        "max_hits": request.max_hits,
        "hit_count": hits.iter().filter(|hit| hit["found"].as_bool() == Some(true)).count(),
        "stop_reason": stop_reason,
        "cancelled": cancelled,
        "background": true,
        "hits": hits,
    })
}

trait CheckedInto<T> {
    fn checked_into(self) -> Option<T>;
}

impl CheckedInto<u64> for u64 {
    fn checked_into(self) -> Option<u64> {
        Some(self)
    }
}

fn default_max_hits() -> usize {
    16
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
