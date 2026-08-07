use anyhow::{bail, ensure, Context};
#[path = "..\\..\\windbg-ttd\\tests\\common\\mod.rs"]
mod common;
use common::{path_string, ping_binary_paths, ping_trace_path};
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
#[test]
fn cli_reuses_trace_session_through_named_pipe_daemon() -> anyhow::Result<()> {
    let pipe = unique_pipe_name();
    let mut daemon = DaemonProcess::start(&pipe)?;
    let ttd = ttd_bin();

    let status = wait_for_status(&ttd, &pipe)?;
    ensure!(
        status["active_sessions"] == 0,
        "new daemon should start without active sessions: {status}"
    );
    let ensured = run_json(&ttd, &pipe, ["daemon".to_string(), "ensure".to_string()])?;
    ensure!(
        ensured["pid"] == status["pid"],
        "daemon ensure should reuse the running daemon: {ensured}"
    );

    let trace_path = std::env::temp_dir().join(format!(
        "windbg-tool-placeholder-{}.run",
        std::process::id()
    ));
    let opened = run_json(&ttd, &pipe, ["open".to_string(), path_string(&trace_path)])?;
    let session_id = opened["session_id"]
        .as_u64()
        .context("open response should include session_id")?;
    let cursor_id = opened["cursor_id"]
        .as_u64()
        .context("open response should include cursor_id")?;

    let status = run_json(&ttd, &pipe, ["daemon".to_string(), "status".to_string()])?;
    ensure!(
        status["active_sessions"].as_u64() == Some(1),
        "daemon should retain loaded sessions across CLI invocations: {status}"
    );
    let sessions = run_json(&ttd, &pipe, ["sessions".to_string()])?;
    ensure!(
        sessions["sessions"].as_array().is_some_and(|items| items
            .iter()
            .any(|session| session["session_id"] == session_id)),
        "sessions command should show the opened session: {sessions}"
    );
    let context = run_json(
        &ttd,
        &pipe,
        [
            "context".to_string(),
            "snapshot".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        context["selected"]["session_id"].as_u64() == Some(session_id)
            && context["selected"]["cursor_id"].as_u64() == Some(cursor_id),
        "context snapshot should preserve the selected session/cursor: {context}"
    );
    ensure!(
        context["trace_info"]["ok"].as_bool() == Some(true)
            && context["capabilities"]["ok"].as_bool() == Some(true),
        "context snapshot should include session-level diagnostics: {context}"
    );
    ensure!(
        context["timeline_summary"].is_object(),
        "context snapshot should include a bounded timeline summary: {context}"
    );
    let symbol_diagnostics = run_json(
        &ttd,
        &pipe,
        [
            "symbols".to_string(),
            "diagnose".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
    )?;
    ensure!(
        symbol_diagnostics["checks"]
            .as_array()
            .is_some_and(|items| items.iter().any(|check| check["id"] == "symbol-path")),
        "symbols diagnose should include symbol-path checks: {symbol_diagnostics}"
    );

    let position = run_json(
        &ttd,
        &pipe,
        [
            "position".to_string(),
            "get".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        position["position"].is_object(),
        "position get should use the cursor created by a prior CLI process: {position}"
    );

    let tools = run_json(&ttd, &pipe, ["tools".to_string()])?;
    ensure!(
        tools["tools"]
            .as_array()
            .is_some_and(|items| items.iter().any(|tool| tool["name"] == "ttd_load_trace")),
        "tools endpoint should expose MCP tool metadata: {tools}"
    );

    let failed = run(
        &ttd,
        &pipe,
        [
            "tool".to_string(),
            "ttd_trace_info".to_string(),
            "--json".to_string(),
            r#"{"session_id":999999}"#.to_string(),
        ],
    )?;
    ensure!(
        !failed.status.success(),
        "unknown session id should produce a non-zero CLI exit status"
    );

    daemon.shutdown(&ttd, &pipe)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn local_discovery_is_complete_without_daemon() -> anyhow::Result<()> {
    let ttd = ttd_bin();
    let tools = run_local_json(&ttd, ["tools".to_string()])?;
    let discover = run_local_json(&ttd, ["discover".to_string()])?;
    let recipes = run_local_json(&ttd, ["recipes".to_string()])?;
    let remote_recipe = run_local_json(
        &ttd,
        ["recipes".to_string(), "remote-debugging".to_string()],
    )?;
    let debug_capabilities =
        run_local_json(&ttd, ["debug".to_string(), "capabilities".to_string()])?;
    let debug_schema = run_local_json(
        &ttd,
        [
            "cli-schema".to_string(),
            "debug".to_string(),
            "snapshot".to_string(),
        ],
    )?;
    let remote_explain = run_local_json(&ttd, ["remote".to_string(), "explain".to_string()])?;
    let remote_doctor = run_local_json(
        &ttd,
        [
            "remote".to_string(),
            "doctor".to_string(),
            "--transport".to_string(),
            "tcp:port=0".to_string(),
        ],
    )?;
    let remote_status = run_local_json(
        &ttd,
        [
            "remote".to_string(),
            "status".to_string(),
            "--transport".to_string(),
            "tcp:port=0".to_string(),
        ],
    )?;
    let remote_plan = run_local_json(
        &ttd,
        [
            "remote".to_string(),
            "plan".to_string(),
            "--server".to_string(),
            "target01".to_string(),
        ],
    )?;
    let remote_connect = run_local_json(
        &ttd,
        [
            "remote".to_string(),
            "connect-command".to_string(),
            "--kind".to_string(),
            "dbgsrv".to_string(),
            "--server".to_string(),
            "target01".to_string(),
        ],
    )?;
    let live_capabilities = run_local_json(&ttd, ["live".to_string(), "capabilities".to_string()])?;
    let breakpoint_capabilities =
        run_local_json(&ttd, ["breakpoint".to_string(), "capabilities".to_string()])?;
    let breakpoint_plan = run_local_json(
        &ttd,
        [
            "breakpoint".to_string(),
            "plan".to_string(),
            "--target".to_string(),
            "1".to_string(),
            "--address".to_string(),
            "0x1000".to_string(),
        ],
    )?;
    let datamodel_capabilities =
        run_local_json(&ttd, ["datamodel".to_string(), "capabilities".to_string()])?;
    let target_capabilities =
        run_local_json(&ttd, ["target".to_string(), "capabilities".to_string()])?;
    let symbol_inspect = run_local_json(
        &ttd,
        [
            "symbols".to_string(),
            "inspect".to_string(),
            path_string(&ttd),
        ],
    )?;
    let symbol_exports = run_local_json(
        &ttd,
        [
            "symbols".to_string(),
            "exports".to_string(),
            path_string(&ttd),
        ],
    )?;
    let source_root =
        std::env::temp_dir().join(format!("windbg-tool-source-resolve-{}", std::process::id()));
    let source_file = source_root.join("src").join("debug").join("sample.cpp");
    std::fs::create_dir_all(
        source_file
            .parent()
            .context("source file should have parent")?,
    )?;
    std::fs::write(&source_file, b"int main() { return 0; }\n")?;
    let source_resolve = run_local_json(
        &ttd,
        [
            "source".to_string(),
            "resolve".to_string(),
            r"C:\agent\work\src\debug\sample.cpp".to_string(),
            "--search-path".to_string(),
            path_string(&source_root),
        ],
    )?;
    let _ = std::fs::remove_dir_all(&source_root);
    let search_order = run_local_json(
        &ttd,
        [
            "module".to_string(),
            "search-order".to_string(),
            "missing-test-dll".to_string(),
            "--app-dir".to_string(),
            path_string(&std::env::temp_dir()),
            "--max-path-dirs".to_string(),
            "2".to_string(),
        ],
    )?;
    let schema = run_local_json(&ttd, ["schema".to_string(), "ttd_read_memory".to_string()])?;
    ensure!(
        schema["name"] == "ttd_read_memory",
        "schema command should return the requested tool metadata: {schema}"
    );
    let trace_list_schema =
        run_local_json(&ttd, ["schema".to_string(), "ttd_trace_list".to_string()])?;
    ensure!(
        trace_list_schema["name"] == "ttd_trace_list",
        "schema command should include trace-list metadata: {trace_list_schema}"
    );
    let index_schema =
        run_local_json(&ttd, ["schema".to_string(), "ttd_index_status".to_string()])?;
    ensure!(
        index_schema["name"] == "ttd_index_status",
        "schema command should include index status metadata: {index_schema}"
    );

    let mapped_tools = discover["tool_command_map"]
        .as_array()
        .context("discover should include tool_command_map")?
        .iter()
        .filter_map(|entry| entry["tool"].as_str())
        .collect::<std::collections::HashSet<_>>();
    let tool_names = tools["tools"]
        .as_array()
        .context("tools output should contain tools array")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<std::collections::HashSet<_>>();
    ensure!(
        discover["command_groups"]["dbgeng"].is_array()
            && discover["command_groups"]["windbg"].is_array()
            && discover["command_groups"]["debug"].is_array()
            && discover["command_groups"]["triage"].is_array()
            && discover["command_groups"]["context"].is_array()
            && discover["command_groups"]["remote"].is_array()
            && discover["command_groups"]["live"].is_array()
            && discover["command_groups"]["breakpoint"].is_array()
            && discover["command_groups"]["datamodel"].is_array()
            && discover["command_groups"]["target"].is_array()
            && discover["command_groups"]["symbols"].is_array()
            && discover["command_groups"]["source"].is_array()
            && discover["command_metadata"]
                .as_array()
                .is_some_and(|items| items
                    .iter()
                    .any(|item| item["command"] == "sweep watch-memory"
                        && item["cost"] == "bounded_high_replay"))
            && discover["command_groups"]["disassembly"].is_array()
            && discover["command_groups"]["object"].is_array(),
        "discover manifest should advertise broader WinDbg command groups: {discover}"
    );
    ensure!(
        discover["action_log"]["enable"].is_string()
            && discover["command_metadata"]
                .as_array()
                .is_some_and(
                    |items| items.iter().any(|item| item["command"] == "debug snapshot"
                        && item["cost"] == "bounded_composite")
                        && items.iter().any(|item| item["command"] == "remote doctor")
                        && items
                            .iter()
                            .any(|item| item["command"] == "debug log summarize")
                ),
        "discover manifest should advertise the agent debug and action-log contracts: {discover}"
    );
    ensure!(
        debug_capabilities["canonical_command"] == "debug capabilities"
            && debug_capabilities["backend_matrix"]
                .as_array()
                .is_some_and(
                    |items| items.iter().any(|item| item["backend"] == "ttd_cursor")
                        && items
                            .iter()
                            .any(|item| item["backend"] == "dbgeng_remote_plan")
                ),
        "debug capabilities should expose the cross-backend matrix: {debug_capabilities}"
    );
    ensure!(
        debug_schema["command"]["path"] == "debug snapshot"
            && debug_schema["command"]["metadata"]["command"] == "debug snapshot",
        "cli-schema should include debug snapshot metadata: {debug_schema}"
    );
    let recipe_items = discover["recipes"]
        .as_array()
        .context("discover should include recipes")?;
    for recipe_id in [
        "diagnostic-technique",
        "remote-debugging",
        "stack-corruption",
        "symbol-health",
        "memory-provenance",
    ] {
        ensure!(
            recipe_items.iter().any(|recipe| recipe["id"] == recipe_id),
            "discover manifest should include recipe {recipe_id}: {discover}"
        );
    }
    ensure!(
        recipes["recipes"]
            .as_array()
            .is_some_and(|items| items.len() >= recipe_items.len()),
        "recipes command should list the manifest recipes: {recipes}"
    );
    ensure!(
        remote_recipe["recipes"]
            .as_array()
            .is_some_and(|items| items.len() == 1 && items[0]["id"] == "remote-debugging"),
        "recipes <id> should filter to the requested recipe: {remote_recipe}"
    );
    ensure!(
        remote_explain["workflows"]
            .as_array()
            .is_some_and(
                |items| items.iter().any(|workflow| workflow["kind"] == "dbgsrv")
                    && items.iter().any(|workflow| workflow["kind"] == "ntsd")
            ),
        "remote explain should compare DbgSrv and NTSD/CDB workflows: {remote_explain}"
    );
    ensure!(
        remote_doctor["schema_version"] == 1
            && remote_doctor["status"]["parsed_tcp_port"].as_u64() == Some(0)
            && remote_doctor["diagnostics"].as_array().is_some_and(|items| items
                .iter()
                .any(|item| item["id"] == "remote.probe.opt_in")),
        "remote doctor should return structured diagnostics without probing by default: {remote_doctor}"
    );
    ensure!(
        remote_status["schema_version"] == 1
            && remote_status["probe"].is_null()
            && remote_status["diagnostics"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["id"] == "remote.probe.opt_in")),
        "remote status should be read-only unless --probe-connect is set: {remote_status}"
    );
    ensure!(
        remote_plan["steps"].as_array().is_some_and(|items| items
            .iter()
            .any(|step| step["id"] == "target_start_server")
            && items.iter().any(|step| step["id"] == "host_connect")),
        "remote plan should generate target and host steps: {remote_plan}"
    );
    ensure!(
        remote_connect["command"]
            .as_array()
            .is_some_and(|items| items.iter().any(|arg| arg == "-premote")
                && items
                    .iter()
                    .any(|arg| arg.as_str() == Some("tcp:port=5005,server=target01"))),
        "remote connect-command should generate a WinDbg -premote command: {remote_connect}"
    );
    ensure!(
        live_capabilities["implemented"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "live launch --command-line <cmd> --end detach|terminate")),
        "live capabilities should advertise the one-shot live launch primitive: {live_capabilities}"
    );
    ensure!(
        breakpoint_capabilities["implemented"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "sweep watch-memory")),
        "breakpoint capabilities should mention sweep watch-memory: {breakpoint_capabilities}"
    );
    ensure!(
        breakpoint_plan["supported"] == true
            && breakpoint_plan["safety"] == "mutating"
            && breakpoint_plan["command"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == "breakpoint")
                    && items.iter().any(|item| item == "set")),
        "breakpoint plan should dry-run a live target code breakpoint: {breakpoint_plan}"
    );
    ensure!(
        datamodel_capabilities["gaps"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .any(|item| item == "DbgEng dx expression evaluation")),
        "datamodel capabilities should identify dx as a gap: {datamodel_capabilities}"
    );
    ensure!(
        target_capabilities["target_kinds"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .any(|item| item["kind"] == "ttd_trace" && item["status"] == "implemented")),
        "target capabilities should distinguish supported target kinds: {target_capabilities}"
    );
    ensure!(
        symbol_inspect["image_symbol_store_key"].is_string(),
        "symbols inspect should report image symbol-store keys: {symbol_inspect}"
    );
    ensure!(
        symbol_exports["total_exports"].is_u64() && symbol_exports["exports"].is_array(),
        "symbols exports should report a structured export list, even when empty: {symbol_exports}"
    );
    ensure!(
        source_resolve["best"]["path"].is_string()
            && source_resolve["best"]["matched_components"]
                .as_u64()
                .unwrap_or_default()
                >= 3,
        "source resolve should find the local file by trailing components: {source_resolve}"
    );
    ensure!(
        search_order["dll"] == "missing-test-dll.dll"
            && search_order["candidates"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
        "module search-order should normalize names and return candidates: {search_order}"
    );
    for tool in tools["tools"]
        .as_array()
        .context("tools output should contain tools array")?
    {
        let name = tool["name"].as_str().context("tool should include name")?;
        ensure!(
            mapped_tools.contains(name),
            "discover manifest should map focused commands for {name}: {discover}"
        );
    }

    let api_capabilities = discover["ttd_api_coverage"]["capabilities"]
        .as_array()
        .context("discover should include ttd_api_coverage capabilities")?;
    ensure!(
        api_capabilities
            .iter()
            .any(|capability| capability["status"] == "gap"),
        "coverage manifest should identify not-yet-exposed TTD API gaps: {discover}"
    );
    ensure!(
        api_capabilities.iter().any(|capability| {
            capability["id"] == "trace_list_packs" && capability["status"] == "implemented"
        }),
        "coverage manifest should mark trace-list packs implemented: {discover}"
    );
    ensure!(
        api_capabilities
            .iter()
            .any(|capability| capability["id"] == "index_operations"
                && capability["status"] == "implemented"),
        "coverage manifest should mark index operations implemented: {discover}"
    );
    for capability in api_capabilities
        .iter()
        .filter(|capability| capability["status"] == "implemented")
    {
        let id = capability["id"]
            .as_str()
            .context("implemented capability should include id")?;
        let mcp_tools = capability["mcp_tools"]
            .as_array()
            .with_context(|| format!("{id} should include mcp_tools"))?;
        ensure!(
            !mcp_tools.is_empty(),
            "implemented capability {id} should map to at least one MCP tool"
        );
        for tool in mcp_tools {
            let tool = tool
                .as_str()
                .with_context(|| format!("{id} MCP tool entry should be a string"))?;
            ensure!(
                tool_names.contains(tool),
                "implemented capability {id} references unknown MCP tool {tool}"
            );
            ensure!(
                mapped_tools.contains(tool),
                "implemented capability {id} references MCP tool {tool} without a focused CLI mapping"
            );
        }

        let commands = capability["cli_commands"]
            .as_array()
            .with_context(|| format!("{id} should include cli_commands"))?;
        ensure!(
            !commands.is_empty(),
            "implemented capability {id} should map to at least one focused CLI command"
        );
    }

    let log_path = std::env::temp_dir().join(format!(
        "windbg-tool-action-log-test-{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log_path);
    let _ = run_local_json_with_env(
        &ttd,
        [
            ("WINDBG_TOOL_ACTION_LOG", path_string(&log_path)),
            ("WINDBG_TOOL_ENVELOPE", "1".to_string()),
        ],
        ["debug".to_string(), "capabilities".to_string()],
    )?;
    let action_log_summary = run_local_json(
        &ttd,
        [
            "debug".to_string(),
            "log".to_string(),
            "summarize".to_string(),
            "--path".to_string(),
            path_string(&log_path),
        ],
    )?;
    let _ = std::fs::remove_file(&log_path);
    ensure!(
        action_log_summary["total_entries"].as_u64() == Some(1)
            && action_log_summary["recent"][0]["command_path"]
                .as_array()
                .is_some_and(|items| items.len() == 2
                    && items[0] == "debug"
                    && items[1] == "capabilities"),
        "action log summary should expose redacted command outcomes: {action_log_summary}"
    );

    Ok(())
}

#[cfg(windows)]
#[test]
fn ping_trace_agent_cli_scenario_uses_long_lived_daemon_session() -> anyhow::Result<()> {
    let Some(trace_path) = ping_trace_path()? else {
        eprintln!("skipping ping CLI daemon scenario: no local trace fixture found");
        return Ok(());
    };

    let pipe = unique_pipe_name();
    let mut daemon = DaemonProcess::start(&pipe)?;
    let ttd = ttd_bin();
    wait_for_status(&ttd, &pipe)?;

    let mut open_args = vec!["open".to_string(), path_string(&trace_path)];
    for binary_path in ping_binary_paths(&trace_path) {
        open_args.push("--binary-path".to_string());
        open_args.push(binary_path);
    }
    open_args.push("--position".to_string());
    open_args.push("50".to_string());
    let opened = run_json_vec(&ttd, &pipe, open_args)?;
    let session_id = opened["session_id"]
        .as_u64()
        .context("open response should include session_id")?;
    ensure!(session_id > 0, "session_id should be non-zero");
    let cursor_id = opened["cursor_id"]
        .as_u64()
        .context("open response should include cursor_id")?;
    ensure!(cursor_id > 0, "cursor_id should be non-zero");

    let extracted_session_id = run_stdout(
        &ttd,
        &pipe,
        vec![
            "--field".to_string(),
            "sessions.0.session_id".to_string(),
            "--raw".to_string(),
            "sessions".to_string(),
        ],
    )?
    .trim()
    .parse::<u64>()
    .context("session_id field should be extractable from sessions")?;
    ensure!(
        extracted_session_id == session_id,
        "field extraction should work on sessions output"
    );

    let info = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "info".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
    )?;
    ensure!(
        info["trace_path"].is_string(),
        "info should include trace_path: {info}"
    );

    let capabilities = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "capabilities".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
    )?;
    ensure!(
        capabilities["features"]["trace_info"] == true,
        "capabilities should report trace_info support: {capabilities}"
    );
    let debug_capabilities = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "debug".to_string(),
            "capabilities".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        debug_capabilities["canonical_command"] == "debug capabilities"
            && debug_capabilities["selected"]["subject"]["kind"] == "ttd_cursor"
            && debug_capabilities["selected"]["matrix"]["operations"]["time_travel"] == "supported",
        "debug capabilities should describe the selected TTD cursor: {debug_capabilities}"
    );
    let debug_snapshot = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "debug".to_string(),
            "snapshot".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--include".to_string(),
            "trace_info".to_string(),
            "--include".to_string(),
            "capabilities".to_string(),
            "--include".to_string(),
            "position".to_string(),
        ],
    )?;
    ensure!(
        debug_snapshot["canonical_command"] == "debug snapshot"
            && debug_snapshot["subject"]["kind"] == "ttd_cursor"
            && debug_snapshot["sections"]["trace_info"]["status"].is_string()
            && debug_snapshot["sections"]["capabilities"]["status"].is_string()
            && debug_snapshot["sections"]["position"]["status"].is_string(),
        "debug snapshot should return sectioned TTD evidence: {debug_snapshot}"
    );
    let symbols_doctor = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "symbols".to_string(),
            "doctor".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        symbols_doctor["schema_version"] == 1
            && symbols_doctor["subject"]["kind"] == "ttd_cursor"
            && symbols_doctor["doctor"]["status"] == "ok"
            && symbols_doctor["doctor"]["value"]["trace_info"]["ok"].is_boolean()
            && symbols_doctor["doctor"]["diagnostics"]
                .as_array()
                .is_some_and(|items| items
                    .iter()
                    .any(|item| item["id"] == "symbols.source.follow_up")),
        "symbols doctor should compose trace and symbol/source diagnostics: {symbols_doctor}"
    );
    let triage = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "triage".to_string(),
            "symbol-health".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        triage["schema_version"] == 1
            && triage["kind"] == "symbol_health"
            && triage["evidence"]["snapshot"]["canonical_command"] == "debug snapshot"
            && triage["hypotheses"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
        "triage symbol-health should include snapshot evidence and hypotheses: {triage}"
    );
    let watchpoint_plan = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "breakpoint".to_string(),
            "plan".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--address".to_string(),
            "0x1000".to_string(),
            "--kind".to_string(),
            "write".to_string(),
            "--size".to_string(),
            "8".to_string(),
            "--direction".to_string(),
            "previous".to_string(),
        ],
    )?;
    ensure!(
        watchpoint_plan["supported"] == true
            && watchpoint_plan["safety"] == "bounded_replay"
            && watchpoint_plan["subject"]["kind"] == "ttd_cursor",
        "breakpoint plan should dry-run TTD watchpoints: {watchpoint_plan}"
    );

    run_json_vec(
        &ttd,
        &pipe,
        vec![
            "position".to_string(),
            "set".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--position".to_string(),
            "50".to_string(),
        ],
    )?;
    run_json_vec(
        &ttd,
        &pipe,
        vec![
            "replay".to_string(),
            "capabilities".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
    )?;
    run_json_vec(
        &ttd,
        &pipe,
        vec![
            "replay".to_string(),
            "to".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--position".to_string(),
            "50".to_string(),
        ],
    )?;
    let sequence = run_stdout(
        &ttd,
        &pipe,
        vec![
            "--field".to_string(),
            "position.sequence".to_string(),
            "--raw".to_string(),
            "position".to_string(),
            "get".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        sequence.trim().parse::<u64>().is_ok(),
        "position sequence should be extractable for agent scripts: {sequence}"
    );

    for args in [
        vec![
            "threads".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
        vec![
            "modules".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
        vec![
            "keyframes".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
        vec![
            "exceptions".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
        vec![
            "events".to_string(),
            "modules".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
        vec![
            "events".to_string(),
            "threads".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
        vec![
            "timeline".to_string(),
            "events".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--max-events".to_string(),
            "32".to_string(),
        ],
    ] {
        run_json_vec(&ttd, &pipe, args)?;
    }

    let tool_info = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "tool".to_string(),
            "ttd_trace_info".to_string(),
            "--json".to_string(),
            format!(r#"{{"session_id":{session_id}}}"#),
        ],
    )?;
    ensure!(
        tool_info["backend"] == info["backend"],
        "generic tool escape hatch should match focused info command"
    );

    if capabilities["native"].as_bool() == Some(true) {
        assert_native_ping_cli_aliases(&ttd, &pipe, session_id, cursor_id, &info)?;
    } else {
        let failed = run_vec(
            &ttd,
            &pipe,
            vec![
                "registers".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
            ],
        )?;
        ensure!(
            !failed.status.success(),
            "native-only register command should fail clearly when native replay is unavailable"
        );
    }

    let closed = run_json_vec(
        &ttd,
        &pipe,
        vec![
            "close".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
    )?;
    ensure!(
        closed["closed"] == true,
        "close command should close the session: {closed}"
    );

    daemon.shutdown(&ttd, &pipe)?;
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn daemon_cli_named_pipe_tests_are_windows_only() {
    eprintln!("skipping named-pipe daemon CLI test on non-Windows");
}

#[cfg(windows)]
struct DaemonProcess {
    child: Child,
}

#[cfg(windows)]
impl DaemonProcess {
    fn start(pipe: &str) -> anyhow::Result<Self> {
        let child = Command::new(ttd_daemon_bin())
            .arg("--pipe")
            .arg(pipe)
            .arg("daemon")
            .arg("start")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawning windbg-tool daemon")?;
        Ok(Self { child })
    }

    fn shutdown(&mut self, ttd: &PathBuf, pipe: &str) -> anyhow::Result<()> {
        let _ = run_json(ttd, pipe, ["daemon".to_string(), "shutdown".to_string()]);
        let _ = self.child.wait();
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for DaemonProcess {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(windows)]
fn wait_for_status(ttd: &PathBuf, pipe: &str) -> anyhow::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = None;
    while Instant::now() < deadline {
        match run_json(ttd, pipe, ["daemon".to_string(), "status".to_string()]) {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("daemon did not start")))
}

#[cfg(windows)]
fn run_json<const N: usize>(ttd: &PathBuf, pipe: &str, args: [String; N]) -> anyhow::Result<Value> {
    let output = run(ttd, pipe, args)?;
    if !output.status.success() {
        bail!(
            "ttd command failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing ttd JSON stdout")
}

#[cfg(windows)]
fn run<const N: usize>(ttd: &PathBuf, pipe: &str, args: [String; N]) -> anyhow::Result<Output> {
    let mut command = Command::new(ttd);
    command.arg("--pipe").arg(pipe);
    for arg in args {
        command.arg(arg);
    }
    command.output().context("running ttd CLI")
}

#[cfg(windows)]
fn run_json_vec(ttd: &PathBuf, pipe: &str, args: Vec<String>) -> anyhow::Result<Value> {
    let output = run_vec(ttd, pipe, args)?;
    if !output.status.success() {
        bail!(
            "ttd command failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing ttd JSON stdout")
}

#[cfg(windows)]
fn run_stdout(ttd: &PathBuf, pipe: &str, args: Vec<String>) -> anyhow::Result<String> {
    let output = run_vec(ttd, pipe, args)?;
    if !output.status.success() {
        bail!(
            "ttd command failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("ttd stdout should be UTF-8")
}

#[cfg(windows)]
fn run_vec(ttd: &PathBuf, pipe: &str, args: Vec<String>) -> anyhow::Result<Output> {
    let mut command = Command::new(ttd);
    command.arg("--pipe").arg(pipe);
    for arg in args {
        command.arg(arg);
    }
    command.output().context("running ttd CLI")
}

#[cfg(windows)]
fn run_local_json<const N: usize>(ttd: &PathBuf, args: [String; N]) -> anyhow::Result<Value> {
    let output = Command::new(ttd)
        .args(args)
        .output()
        .context("running local ttd CLI command")?;
    if !output.status.success() {
        bail!(
            "ttd command failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing local ttd JSON stdout")
}

#[cfg(windows)]
fn run_local_json_with_env<const N: usize, const M: usize>(
    ttd: &PathBuf,
    envs: [(&str, String); M],
    args: [String; N],
) -> anyhow::Result<Value> {
    let mut command = Command::new(ttd);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().context("running local ttd CLI command")?;
    if !output.status.success() {
        bail!(
            "ttd command failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing local ttd JSON stdout")
}

#[cfg(windows)]
fn assert_native_ping_cli_aliases(
    ttd: &PathBuf,
    pipe: &str,
    session_id: u64,
    cursor_id: u64,
    info: &Value,
) -> anyhow::Result<()> {
    let modules = run_json_vec(
        ttd,
        pipe,
        vec![
            "modules".to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ],
    )?;
    ensure!(
        modules["modules"].as_array().is_some_and(|items| items
            .iter()
            .any(|module| module["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe")))),
        "native ping module list should include ping.exe: {modules}"
    );
    run_json_vec(
        ttd,
        pipe,
        vec![
            "module".to_string(),
            "audit".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    let context = run_json_vec(
        ttd,
        pipe,
        vec![
            "context".to_string(),
            "snapshot".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        context["architecture_state"]["ok"].as_bool() == Some(true)
            && context["current_disassembly"]["ok"].as_bool() == Some(true)
            && context["timeline_summary"]["ok"].as_bool() == Some(true),
        "native context snapshot should include architecture, disassembly, and timeline data: {context}"
    );
    let registers = run_json_vec(
        ttd,
        pipe,
        vec![
            "registers".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    if let Some(program_counter) = registers["program_counter"].as_u64() {
        run_json_vec(
            ttd,
            pipe,
            vec![
                "symbols".to_string(),
                "nearest".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                program_counter.to_string(),
            ],
        )?;
    }

    for args in [
        vec![
            "module".to_string(),
            "info".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--name".to_string(),
            "ping.exe".to_string(),
        ],
        vec![
            "cursor".to_string(),
            "modules".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
        vec![
            "active-threads".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
        vec![
            "register-context".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
        vec![
            "architecture".to_string(),
            "state".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
        vec![
            "disasm".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--count".to_string(),
            "4".to_string(),
            "--bytes".to_string(),
            "32".to_string(),
        ],
        vec![
            "stack".to_string(),
            "info".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
        vec![
            "stack".to_string(),
            "read".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--size".to_string(),
            "64".to_string(),
        ],
        vec![
            "stack".to_string(),
            "recover".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--size".to_string(),
            "256".to_string(),
            "--max-candidates".to_string(),
            "8".to_string(),
        ],
        vec![
            "stack".to_string(),
            "backtrace".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--size".to_string(),
            "256".to_string(),
            "--max-frames".to_string(),
            "8".to_string(),
        ],
        vec![
            "step".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
            "--direction".to_string(),
            "forward".to_string(),
            "--kind".to_string(),
            "step".to_string(),
            "--count".to_string(),
            "1".to_string(),
        ],
    ] {
        run_json_vec(ttd, pipe, args)?;
    }

    let command_line = run_json_vec(
        ttd,
        pipe,
        vec![
            "command-line".to_string(),
            "--session".to_string(),
            session_id.to_string(),
            "--cursor".to_string(),
            cursor_id.to_string(),
        ],
    )?;
    ensure!(
        command_line["command_line"].is_string(),
        "command-line alias should return the process command line: {command_line}"
    );

    if let Some(peb_address) = info["peb_address"].as_u64() {
        let peb = peb_address.to_string();
        run_json_vec(
            ttd,
            pipe,
            vec![
                "address".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                peb.clone(),
            ],
        )?;
        for args in [
            vec![
                "memory".to_string(),
                "read".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                peb.clone(),
                "--size".to_string(),
                "16".to_string(),
            ],
            vec![
                "memory".to_string(),
                "range".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                peb.clone(),
                "--max-bytes".to_string(),
                "16".to_string(),
            ],
            vec![
                "memory".to_string(),
                "buffer".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                peb.clone(),
                "--size".to_string(),
                "16".to_string(),
                "--max-ranges".to_string(),
                "8".to_string(),
            ],
            vec![
                "memory".to_string(),
                "strings".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                peb.clone(),
                "--size".to_string(),
                "64".to_string(),
                "--max-strings".to_string(),
                "8".to_string(),
            ],
            vec![
                "memory".to_string(),
                "dps".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                peb.clone(),
                "--size".to_string(),
                "32".to_string(),
            ],
            vec![
                "memory".to_string(),
                "chase".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                peb,
                "--depth".to_string(),
                "1".to_string(),
            ],
        ] {
            run_json_vec(ttd, pipe, args)?;
        }
    }

    if let Some(command_line_address) = command_line["command_line_address"].as_u64() {
        run_json_vec(
            ttd,
            pipe,
            vec![
                "position".to_string(),
                "set".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--position".to_string(),
                serde_json::to_string(&info["lifetime_end"])?,
            ],
        )?;
        let watchpoint = run_json_vec(
            ttd,
            pipe,
            vec![
                "memory".to_string(),
                "watchpoint".to_string(),
                "--session".to_string(),
                session_id.to_string(),
                "--cursor".to_string(),
                cursor_id.to_string(),
                "--address".to_string(),
                command_line_address.to_string(),
                "--size".to_string(),
                "16".to_string(),
                "--access".to_string(),
                "read".to_string(),
                "--direction".to_string(),
                "previous".to_string(),
            ],
        )?;
        ensure!(
            watchpoint["found"].as_bool() == Some(true),
            "command-line watchpoint should find a previous read: {watchpoint}"
        );
    }

    Ok(())
}

#[cfg(windows)]
fn unique_pipe_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(r"\\.\pipe\windbg-tool-test-{}-{nanos}", std::process::id())
}

#[cfg(windows)]
fn ttd_bin() -> PathBuf {
    option_env!("CARGO_BIN_EXE_windbg-tool")
        .map(PathBuf::from)
        .unwrap_or_else(|| sibling_bin("windbg-tool.exe"))
}

#[cfg(windows)]
fn ttd_daemon_bin() -> PathBuf {
    option_env!("CARGO_BIN_EXE_windbg-tool")
        .map(PathBuf::from)
        .unwrap_or_else(|| sibling_bin("windbg-tool.exe"))
}

#[cfg(windows)]
fn sibling_bin(name: &str) -> PathBuf {
    std::env::current_exe()
        .expect("test executable path")
        .parent()
        .and_then(|path| path.parent())
        .expect("test executable should be under target/debug/deps")
        .join(name)
}
