#![allow(dead_code)]

use anyhow::{bail, ensure, Context};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use windbg_ttd::ttd_replay::SymbolSettings;

pub const EXPECT_NATIVE_ENV: &str = "TTD_MCP_EXPECT_NATIVE_REPLAY";
const PING_TRACE_ARCHIVE: &str = "traces/ping.7z";
const PING_TRACE_RUN: &str = "traces/ping/ping01.run";

static PING_FIXTURE_EXTRACT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn ping_trace_path() -> anyhow::Result<Option<PathBuf>> {
    if let Some(path) = env::var_os("TTD_TEST_TRACE").map(PathBuf::from) {
        ensure!(
            path.is_file(),
            "TTD_TEST_TRACE does not point to a file: {}",
            path.display()
        );
        return Ok(Some(path));
    }

    let default_trace = workspace_root().join(PING_TRACE_RUN);
    if default_trace.is_file() {
        return Ok(Some(default_trace));
    }

    if !ensure_ping_fixture_extracted()? {
        return Ok(None);
    }

    Ok(default_trace.is_file().then_some(default_trace))
}

pub fn ensure_ping_fixture_extracted() -> anyhow::Result<bool> {
    let fixture_lock = PING_FIXTURE_EXTRACT_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = fixture_lock
        .lock()
        .map_err(|error| anyhow::anyhow!("ping fixture extraction lock is poisoned: {error}"))?;

    let root = workspace_root();
    let default_trace = root.join(PING_TRACE_RUN);
    if default_trace.is_file() {
        return Ok(true);
    }

    let archive_path = root.join(PING_TRACE_ARCHIVE);
    if !archive_path.is_file() {
        eprintln!(
            "ping trace archive is not present at {}; tests can still use TTD_TEST_TRACE",
            archive_path.display()
        );
        return Ok(false);
    }

    let Some(seven_zip) = seven_zip_command() else {
        eprintln!(
            "ping trace archive is present at {}, but no 7z/7zz executable was found; set TTD_TEST_7Z to extract automatically",
            archive_path.display()
        );
        return Ok(false);
    };

    let traces_dir = root.join("traces");
    std::fs::create_dir_all(&traces_dir)
        .with_context(|| format!("creating {}", traces_dir.display()))?;
    let output = Command::new(&seven_zip)
        .arg("x")
        .arg(&archive_path)
        .arg(format!("-o{}", traces_dir.display()))
        .arg("-y")
        .output()
        .with_context(|| format!("running {}", seven_zip.display()))?;

    if !output.status.success() {
        bail!(
            "failed to extract {} with {}\nstdout:\n{}\nstderr:\n{}",
            archive_path.display(),
            seven_zip.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    ensure!(
        default_trace.is_file(),
        "extracted {}, but {} was not created",
        archive_path.display(),
        default_trace.display()
    );

    Ok(true)
}

pub fn ping_symbol_settings(trace_path: &Path) -> SymbolSettings {
    let mut settings = SymbolSettings::default();
    if let Some(trace_dir) = trace_path.parent() {
        let binary_path = trace_dir.join("ping.exe");
        if binary_path.is_file() {
            settings.binary_paths.push(binary_path);
        }
    }
    settings
}

pub fn ping_binary_paths(trace_path: &Path) -> Vec<String> {
    trace_path
        .parent()
        .map(|trace_dir| trace_dir.join("ping.exe"))
        .filter(|binary_path| binary_path.is_file())
        .map(|binary_path| vec![path_string(&binary_path)])
        .unwrap_or_default()
}

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <workspace>/crates/<name>")
        .to_path_buf()
}

pub fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn seven_zip_command() -> Option<PathBuf> {
    if let Some(path) = env::var_os("TTD_TEST_7Z") {
        return Some(PathBuf::from(path));
    }

    ["7z", "7zz"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| Command::new(candidate).arg("i").output().is_ok())
}
