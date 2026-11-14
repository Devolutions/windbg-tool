//! Action-log summarizer shared by MCP and CLI.

use anyhow::{ensure, Context};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

fn default_max() -> usize {
    20
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DebugLogSummarizeRequest {
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_max")]
    pub max: usize,
}

pub fn debug_log_summarize(request: DebugLogSummarizeRequest) -> anyhow::Result<Value> {
    ensure!(
        request.max <= 10_000,
        "debug_log_summarize max must not exceed 10000"
    );
    let path = request
        .path
        .or_else(action_log_path_from_env)
        .context("debug_log_summarize requires path or WINDBG_TOOL_ACTION_LOG")?;
    let file =
        File::open(&path).with_context(|| format!("opening action log {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut recent = VecDeque::with_capacity(request.max.min(256));
    let mut total = 0_usize;
    let mut failed = 0_usize;
    let mut malformed = 0_usize;
    for line in reader.lines() {
        let line = line.with_context(|| format!("reading action log {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(value) => {
                total += 1;
                if !value["ok"].as_bool().unwrap_or(false) {
                    failed += 1;
                }
                if request.max > 0 {
                    if recent.len() == request.max {
                        recent.pop_front();
                    }
                    recent.push_back(value);
                }
            }
            Err(_) => malformed += 1,
        }
    }
    let recent = Vec::from(recent);
    Ok(json!({
        "schema_version": 1,
        "path": path,
        "total_entries": total,
        "malformed_entries": malformed,
        "failed_entries": failed,
        "returned": recent.len(),
        "limit": request.max,
        "truncated": total > recent.len(),
        "recent": recent
    }))
}

fn action_log_path_from_env() -> Option<PathBuf> {
    std::env::var_os("WINDBG_TOOL_ACTION_LOG")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn summarizes_jsonl_and_counts_failures() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("windbg-tool-action-log-{stamp}.jsonl"));
        {
            let mut file = File::create(&path).unwrap();
            writeln!(file, r#"{{"ok":true,"command":"a"}}"#).unwrap();
            writeln!(file, r#"{{"ok":false,"command":"b"}}"#).unwrap();
            writeln!(file, "not-json").unwrap();
        }
        let summary = debug_log_summarize(DebugLogSummarizeRequest {
            path: Some(path.clone()),
            max: 10,
        })
        .unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(summary["total_entries"], 2);
        assert_eq!(summary["failed_entries"], 1);
        assert_eq!(summary["malformed_entries"], 1);
        assert_eq!(summary["returned"], 2);
    }
}
