use anyhow::{bail, ensure, Context};
#[path = "..\\..\\windbg-ttd\\tests\\common\\mod.rs"]
mod common;
use common::{path_string, ping_binary_paths, ping_trace_path};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[test]
fn initialize_ping_and_tools_list_roundtrip_over_stdio() -> anyhow::Result<()> {
    let mut client = McpClient::start()?;

    let initialize = client.initialize()?;
    assert_eq!(initialize["result"]["serverInfo"]["name"], "windbg-ttd");
    ensure!(
        initialize["result"]["capabilities"]["tools"].is_object(),
        "initialize result should advertise tools capability: {initialize}"
    );

    let ping = client.request(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "ping",
        "params": {}
    }))?;
    assert_success_id(&ping, 2)?;
    assert_eq!(ping["result"], json!({}));

    let tools = client.request(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list",
        "params": {}
    }))?;
    assert_success_id(&tools, 3)?;
    let tools = tools["result"]["tools"]
        .as_array()
        .context("tools/list result should include a tools array")?;
    let names = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();

    for expected_name in expected_tool_names() {
        ensure!(
            names.contains(expected_name),
            "missing {expected_name} tool"
        );
    }
    for tool in tools {
        assert_tool_schema(tool)?;
    }

    Ok(())
}

#[test]
fn explicit_mcp_subcommand_starts_stdio_server() -> anyhow::Result<()> {
    let mut client = McpClient::start_with_args(["mcp"])?;
    let initialize = client.initialize()?;
    assert_eq!(initialize["result"]["serverInfo"]["name"], "windbg-ttd");
    Ok(())
}

#[test]
fn protocol_errors_use_json_rpc_error_codes() -> anyhow::Result<()> {
    let mut client = McpClient::start()?;
    client.initialize()?;

    let method_not_found = client.request(json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "not/a-method",
        "params": {}
    }))?;
    assert_error_code(&method_not_found, json!(11), -32601)?;

    Ok(())
}

#[test]
fn tool_failures_are_reported_as_mcp_tool_results() -> anyhow::Result<()> {
    let mut client = McpClient::start()?;
    client.initialize()?;

    let response = client.request(json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "ttd_trace_info",
            "arguments": {
                "session_id": 999999
            }
        }
    }))?;

    assert_success_id(&response, 20)?;
    ensure!(
        response["result"]["isError"].as_bool() == Some(true),
        "tool failure should be a tools/call result with isError=true: {response}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .context("tool result should include text content")?;
    ensure!(
        text.contains("unknown session id"),
        "unexpected tool error text: {text}"
    );

    Ok(())
}

#[test]
fn ping_trace_replay_scenario_over_mcp_stdio() -> anyhow::Result<()> {
    let Some(trace_path) = ping_trace_path()? else {
        eprintln!("skipping MCP ping replay scenario: no local trace fixture found");
        return Ok(());
    };

    let mut client = McpClient::start()?;
    client.initialize()?;

    let load_args = ping_load_trace_args(&trace_path);
    let loaded = client.call_tool_json(30, "ttd_load_trace", load_args)?;
    let session_id = loaded["session_id"]
        .as_u64()
        .context("ttd_load_trace response should include a session_id")?;
    ensure!(session_id > 0, "session_id should be non-zero: {loaded}");
    ensure!(
        loaded["trace"]["trace_path"].is_string(),
        "load response should include trace metadata: {loaded}"
    );
    ensure!(
        loaded["symbol_path"].as_str() == Some(""),
        "load response should not configure a DbgEng or TTD srv* path: {loaded}"
    );

    let info = client.call_tool_json(
        31,
        "ttd_trace_info",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        info["backend"].is_string(),
        "trace info should include a backend: {info}"
    );

    let capabilities = client.call_tool_json(
        43,
        "ttd_capabilities",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        capabilities["session_id"] == session_id,
        "capabilities response should echo the session id: {capabilities}"
    );
    ensure!(
        capabilities["backend"] == info["backend"],
        "capabilities response should match trace backend: {capabilities}"
    );
    ensure!(
        capabilities["features"]["trace_info"] == true,
        "capabilities response should mark trace_info as available: {capabilities}"
    );
    ensure!(
        capabilities["features"]["cursor_create"] == true,
        "capabilities response should mark cursor_create as available: {capabilities}"
    );

    let cursor = client.call_tool_json(
        32,
        "ttd_cursor_create",
        json!({
            "session_id": session_id,
        }),
    )?;
    let cursor_id = cursor["cursor_id"]
        .as_u64()
        .context("ttd_cursor_create response should include a cursor_id")?;
    ensure!(cursor_id > 0, "cursor_id should be non-zero: {cursor}");

    let current = client.call_tool_json(
        33,
        "ttd_position_get",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        current["position"].is_object(),
        "position_get should include a position: {current}"
    );

    let midpoint = client.call_tool_json(
        34,
        "ttd_position_set",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "position": 50,
        }),
    )?;
    ensure!(
        midpoint["position"].is_object(),
        "position_set should include a position: {midpoint}"
    );

    if info["backend"] != "ttd-replay-native" {
        ensure!(
            info["warning"].is_string(),
            "non-native MCP replay should explain why native replay is unavailable: {info}"
        );
        let closed = client.call_tool_json(
            35,
            "ttd_close_trace",
            json!({
                "session_id": session_id,
            }),
        )?;
        ensure!(
            closed["closed"] == true,
            "close response should succeed: {closed}"
        );
        return Ok(());
    }

    let modules = client.call_tool_json(
        35,
        "ttd_list_modules",
        json!({
            "session_id": session_id,
        }),
    )?;
    let module_entries = modules["modules"]
        .as_array()
        .context("ttd_list_modules response should include modules")?;
    ensure!(
        module_entries.iter().any(|module| module["name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe"))),
        "native MCP module list should include ping.exe: {modules}"
    );

    let cursor_modules = client.call_tool_json(
        56,
        "ttd_cursor_modules",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        cursor_modules["position"].is_object()
            && cursor_modules["modules"]
                .as_array()
                .is_some_and(|items| items.iter().any(|module| module["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe")))),
        "cursor_modules should include modules loaded at the cursor position: {cursor_modules}"
    );

    let keyframes = client.call_tool_json(
        49,
        "ttd_list_keyframes",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        keyframes["keyframes"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "native MCP keyframe list should include positions: {keyframes}"
    );

    let module_events = client.call_tool_json(
        50,
        "ttd_module_events",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        module_events["events"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "native MCP module events should include load/unload events: {module_events}"
    );

    let thread_events = client.call_tool_json(
        51,
        "ttd_thread_events",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        thread_events["events"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "native MCP thread events should include create/terminate events: {thread_events}"
    );

    let module_info = client.call_tool_json(
        44,
        "ttd_module_info",
        json!({
            "session_id": session_id,
            "name": "ping.exe",
        }),
    )?;
    let ping_base = module_info["module"]["base_address"]
        .as_u64()
        .context("ttd_module_info response should include module base_address")?;
    ensure!(
        module_info["matched_by"] == "name",
        "module_info should report name match: {module_info}"
    );
    ensure!(
        module_info["module"]["name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe")),
        "module_info should return ping.exe: {module_info}"
    );

    let module_by_address = client.call_tool_json(
        45,
        "ttd_module_info",
        json!({
            "session_id": session_id,
            "address": ping_base,
        }),
    )?;
    ensure!(
        module_by_address["matched_by"] == "address",
        "module_info should report address match: {module_by_address}"
    );

    let address_info = client.call_tool_json(
        48,
        "ttd_address_info",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "address": format!("{ping_base:#x}"),
        }),
    )?;
    ensure!(
        address_info["classification"] == "module",
        "address_info should classify ping.exe base as a module address: {address_info}"
    );
    ensure!(
        address_info["module"]["name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe")),
        "address_info should identify ping.exe for its base address: {address_info}"
    );
    ensure!(
        address_info["module"]["rva"] == 0 && address_info["module"]["rva_hex"] == "0x0",
        "address_info should report RVA zero for a module base address: {address_info}"
    );
    ensure!(
        address_info["module"]["module_offset"] == "ping.exe+0x0",
        "address_info should report module+offset coordinates: {address_info}"
    );
    ensure!(
        address_info["position"].is_object()
            && address_info["registers"]["program_counter"]
                .as_u64()
                .is_some_and(|value| value != 0),
        "address_info should include cursor position and register context: {address_info}"
    );

    let active_threads = client.call_tool_json(
        52,
        "ttd_active_threads",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        active_threads["threads"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "active_threads should include at least one active thread: {active_threads}"
    );
    ensure!(
        active_threads["threads"][0]["program_counter"]
            .as_u64()
            .is_some_and(|value| value != 0),
        "active_threads should include runtime PCs: {active_threads}"
    );

    let active_thread_unique_id = active_threads["threads"][0]["thread"]["unique_id"]
        .as_u64()
        .context("active_threads should include a unique thread id")?;
    let thread_position = client.call_tool_json(
        57,
        "ttd_position_set",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "position": 50,
            "thread_unique_id": active_thread_unique_id,
        }),
    )?;
    ensure!(
        thread_position["position"].is_object(),
        "thread-scoped position_set should return the resolved cursor position: {thread_position}"
    );

    let registers = client.call_tool_json(
        36,
        "ttd_registers",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        registers["program_counter"]
            .as_u64()
            .is_some_and(|value| value != 0),
        "register snapshot should include a non-zero program counter: {registers}"
    );
    ensure!(
        registers["stack_pointer"]
            .as_u64()
            .is_some_and(|value| value != 0),
        "register snapshot should include a non-zero stack pointer: {registers}"
    );
    ensure!(
        registers["thread"]["unique_id"] == active_thread_unique_id,
        "thread-scoped position_set should select the requested unique thread id: {registers}"
    );

    let register_context = client.call_tool_json(
        54,
        "ttd_register_context",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        register_context["architecture"] == "x64"
            && register_context["registers"]["rip"] == registers["program_counter"]
            && register_context["registers"]["rsp"] == registers["stack_pointer"],
        "register_context should include full x64 state matching compact registers: {register_context}"
    );
    ensure!(
        register_context["registers"]["xmm"]
            .as_array()
            .is_some_and(|items| items.len() == 16)
            && register_context["registers"]["ymm"]
                .as_array()
                .is_some_and(|items| items.len() == 16),
        "register_context should include XMM/YMM vector register arrays: {register_context}"
    );
    ensure!(
        register_context["registers"]["xmm"][0]["hex"]
            .as_str()
            .is_some_and(|value| value.len() == 32)
            && register_context["registers"]["ymm"][0]["hex"]
                .as_str()
                .is_some_and(|value| value.len() == 64),
        "register_context should include hex-encoded vector register bytes: {register_context}"
    );
    ensure!(
        register_context["module"]["name"]
            .as_str()
            .is_some_and(|name| !name.is_empty()),
        "register_context should include module/RVA coordinates for RIP when available: {register_context}"
    );

    let stack_info = client.call_tool_json(
        46,
        "ttd_stack_info",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        stack_info["stack_pointer"] == registers["stack_pointer"],
        "stack_info should use the same stack pointer as registers: {stack_info}"
    );
    ensure!(
        stack_info["stack_base"]
            .as_u64()
            .is_some_and(|value| value != 0)
            && stack_info["stack_limit"]
                .as_u64()
                .is_some_and(|value| value != 0),
        "stack_info should include non-zero stack bounds: {stack_info}"
    );

    let stack_read = client.call_tool_json(
        47,
        "ttd_stack_read",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "size": 128,
            "decode_pointers": true,
        }),
    )?;
    ensure!(
        stack_read["stack_pointer"] == registers["stack_pointer"],
        "stack_read should report the register stack pointer: {stack_read}"
    );
    ensure!(
        stack_read["bytes_read"]
            .as_u64()
            .is_some_and(|value| value > 0),
        "stack_read should read some stack bytes: {stack_read}"
    );
    ensure!(
        stack_read["encoding"] == "hex" && stack_read["pointer_size"] == 8,
        "stack_read should return hex data and x64 pointer size: {stack_read}"
    );

    let stepped = client.call_tool_json(
        37,
        "ttd_step",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "direction": "forward",
            "kind": "step",
            "count": 1,
        }),
    )?;
    ensure!(
        stepped["position"].is_object(),
        "step response should include the new position: {stepped}"
    );
    ensure!(
        stepped["requested_count"] == 1,
        "step response should echo requested_count: {stepped}"
    );
    ensure!(
        stepped["steps_executed"]
            .as_u64()
            .is_some_and(|value| value <= 1),
        "single-step response should execute at most one step: {stepped}"
    );
    ensure!(
        stepped["stop_reason"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "step response should include a stop reason: {stepped}"
    );

    let command_line = client.call_tool_json(
        38,
        "ttd_command_line",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    let command_line_text = command_line["command_line"]
        .as_str()
        .context("ttd_command_line response should include command_line")?;
    ensure!(
        command_line_text.contains("ping.exe") && command_line_text.contains("google.com"),
        "command line should identify the ping capture: {command_line_text}"
    );

    let peb_address = info["peb_address"]
        .as_u64()
        .context("native trace info should include a PEB address")?;
    let memory = client.call_tool_json(
        39,
        "ttd_read_memory",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "address": peb_address,
            "size": 64,
            "policy": "globally_conservative",
        }),
    )?;
    ensure!(
        memory["policy"] == "globally_conservative",
        "PEB memory read should echo the requested query policy: {memory}"
    );
    ensure!(
        memory["bytes_read"]
            .as_u64()
            .is_some_and(|value| value >= 16),
        "PEB memory read should return at least 16 bytes: {memory}"
    );
    ensure!(
        memory["encoding"] == "hex",
        "memory response should be hex encoded: {memory}"
    );

    let memory_range = client.call_tool_json(
        53,
        "ttd_memory_range",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "address": ping_base,
            "max_bytes": 64,
            "policy": "globally_conservative",
        }),
    )?;
    ensure!(
        memory_range["policy"] == "globally_conservative",
        "memory_range should echo the requested query policy: {memory_range}"
    );
    ensure!(
        memory_range["bytes_available"]
            .as_u64()
            .is_some_and(|value| value > 0),
        "memory_range should report available trace-backed bytes: {memory_range}"
    );
    ensure!(
        memory_range["bytes_returned"]
            .as_u64()
            .is_some_and(|value| value > 0)
            && memory_range["encoding"] == "hex",
        "memory_range should return bounded hex data: {memory_range}"
    );
    ensure!(
        memory_range["module"]["name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe")),
        "memory_range should include module coordinates for ping.exe base: {memory_range}"
    );

    let memory_buffer = client.call_tool_json(
        55,
        "ttd_memory_buffer",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "address": ping_base,
            "size": 64,
            "max_ranges": 8,
            "policy": "globally_aggressive",
        }),
    )?;
    ensure!(
        memory_buffer["policy"] == "globally_aggressive",
        "memory_buffer should echo the requested query policy: {memory_buffer}"
    );
    ensure!(
        memory_buffer["bytes_read"]
            .as_u64()
            .is_some_and(|value| value > 0)
            && memory_buffer["encoding"] == "hex",
        "memory_buffer should return bounded hex data: {memory_buffer}"
    );
    ensure!(
        memory_buffer["ranges"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "memory_buffer should include source ranges: {memory_buffer}"
    );
    ensure!(
        memory_buffer["ranges"][0]["offset"].is_u64()
            && memory_buffer["ranges"][0]["sequence"].is_u64(),
        "memory_buffer source ranges should include offsets and source sequences: {memory_buffer}"
    );

    let command_line_address = command_line["command_line_address"]
        .as_u64()
        .context("ttd_command_line response should include command_line_address")?;
    let end_position = client.call_tool_json(
        40,
        "ttd_position_set",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "position": 100,
        }),
    )?;
    ensure!(
        end_position["position"].is_object(),
        "position_set to trace end should include a position: {end_position}"
    );

    let watchpoint = client.call_tool_json(
        41,
        "ttd_memory_watchpoint",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "address": command_line_address,
            "size": 16,
            "access": "read",
            "direction": "previous",
        }),
    )?;
    ensure!(
        watchpoint["requested_address"] == command_line_address,
        "watchpoint response should echo requested_address: {watchpoint}"
    );
    ensure!(
        watchpoint["requested_size"] == 16,
        "watchpoint response should echo requested_size: {watchpoint}"
    );
    ensure!(
        watchpoint["requested_access"] == "read" && watchpoint["direction"] == "previous",
        "watchpoint response should echo access and direction: {watchpoint}"
    );
    ensure!(
        watchpoint["found"] == true,
        "watchpoint should find a previous command-line buffer read: {watchpoint}"
    );
    ensure!(
        watchpoint["position"].is_object(),
        "watchpoint response should include the new cursor position: {watchpoint}"
    );
    ensure!(
        watchpoint["match_access"] == "read",
        "watchpoint hit should report a read access: {watchpoint}"
    );
    ensure!(
        watchpoint["stop_reason"] == "MemoryWatchpoint",
        "watchpoint hit should report a memory-watchpoint stop: {watchpoint}"
    );

    let closed = client.call_tool_json(
        42,
        "ttd_close_trace",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        closed["closed"] == true,
        "close response should succeed: {closed}"
    );

    Ok(())
}

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpClient {
    fn start() -> anyhow::Result<Self> {
        Self::start_with_args(std::iter::empty::<&str>())
    }

    fn start_with_args<I, S>(args: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut child = Command::new(server_binary())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning windbg-tool")?;
        let stdin = child.stdin.take().context("child stdin was not piped")?;
        let stdout = child.stdout.take().context("child stdout was not piped")?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn notify(&mut self, value: Value) -> anyhow::Result<()> {
        writeln!(self.stdin, "{}", serde_json::to_string(&value)?)?;
        self.stdin.flush()?;
        Ok(())
    }

    fn initialize(&mut self) -> anyhow::Result<Value> {
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "windbg-ttd-test",
                    "version": "0.0.0"
                }
            }
        }))?;
        assert_success_id(&response, 1)?;
        self.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }))?;
        Ok(response)
    }

    fn request(&mut self, value: Value) -> anyhow::Result<Value> {
        self.raw_request(&serde_json::to_string(&value)?)
    }

    fn call_tool_json(&mut self, id: u64, name: &str, arguments: Value) -> anyhow::Result<Value> {
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            }
        }))?;
        assert_success_id(&response, id)?;
        ensure!(
            response["result"]["isError"].as_bool() != Some(true),
            "{name} returned an MCP tool error: {response}"
        );
        parse_tool_json(&response)
    }

    fn raw_request(&mut self, line: &str) -> anyhow::Result<Value> {
        writeln!(self.stdin, "{line}")?;
        self.stdin.flush()?;

        let mut response = String::new();
        let bytes = self.stdout.read_line(&mut response)?;
        ensure!(bytes > 0, "server closed stdout before writing a response");
        serde_json::from_str(response.trim_end()).context("parsing MCP response")
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn server_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_windbg-tool")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut path = std::env::current_exe().expect("current test executable path");
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path.push(format!("windbg-tool{}", std::env::consts::EXE_SUFFIX));
            path
        })
}

fn parse_tool_json(response: &Value) -> anyhow::Result<Value> {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .context("tool result should include text content")?;
    serde_json::from_str(text).context("parsing tool result JSON")
}

fn ping_load_trace_args(trace_path: &Path) -> Value {
    json!({
        "trace_path": path_string(trace_path),
        "symbols": {
            "binary_paths": ping_binary_paths(trace_path),
        }
    })
}

fn expected_tool_names() -> &'static [&'static str] {
    &[
        "ttd_load_trace",
        "ttd_trace_list",
        "ttd_close_trace",
        "ttd_trace_info",
        "ttd_capabilities",
        "ttd_index_status",
        "ttd_index_stats",
        "ttd_build_index",
        "ttd_list_threads",
        "ttd_list_modules",
        "ttd_cursor_modules",
        "ttd_list_keyframes",
        "ttd_module_events",
        "ttd_thread_events",
        "ttd_module_info",
        "ttd_address_info",
        "ttd_active_threads",
        "ttd_list_exceptions",
        "ttd_cursor_create",
        "ttd_position_get",
        "ttd_position_set",
        "ttd_step",
        "ttd_registers",
        "ttd_register_context",
        "ttd_stack_info",
        "ttd_stack_read",
        "ttd_command_line",
        "ttd_read_memory",
        "ttd_memory_range",
        "ttd_memory_buffer",
        "ttd_memory_watchpoint",
    ]
}

fn assert_tool_schema(tool: &Value) -> anyhow::Result<()> {
    let name = tool["name"]
        .as_str()
        .context("tool is missing a string name")?;
    ensure!(
        tool["description"].is_string(),
        "tool is missing a string description: {tool}"
    );
    let schema = &tool["inputSchema"];
    ensure!(
        schema.is_object(),
        "tool is missing an object inputSchema: {tool}"
    );
    ensure!(
        schema["type"] == "object",
        "tool inputSchema should be an object schema: {tool}"
    );
    ensure!(
        schema["properties"].is_object(),
        "tool inputSchema should include object properties: {tool}"
    );
    for required in required_args_for_tool(name)? {
        ensure!(
            schema["required"]
                .as_array()
                .is_some_and(|args| args.iter().any(|arg| arg == required)),
            "tool {name} inputSchema is missing required argument {required}: {tool}"
        );
    }
    Ok(())
}

fn required_args_for_tool(name: &str) -> anyhow::Result<&'static [&'static str]> {
    match name {
        "ttd_load_trace" | "ttd_trace_list" => Ok(&["trace_path"]),
        "ttd_close_trace"
        | "ttd_trace_info"
        | "ttd_capabilities"
        | "ttd_index_status"
        | "ttd_index_stats"
        | "ttd_build_index"
        | "ttd_list_threads"
        | "ttd_list_modules"
        | "ttd_list_keyframes"
        | "ttd_module_events"
        | "ttd_thread_events"
        | "ttd_module_info"
        | "ttd_list_exceptions"
        | "ttd_cursor_create" => Ok(&["session_id"]),
        "ttd_position_get"
        | "ttd_registers"
        | "ttd_register_context"
        | "ttd_active_threads"
        | "ttd_cursor_modules"
        | "ttd_stack_info"
        | "ttd_command_line" => Ok(&["session_id", "cursor_id"]),
        "ttd_address_info" => Ok(&["session_id", "cursor_id", "address"]),
        "ttd_position_set" => Ok(&["session_id", "cursor_id", "position"]),
        "ttd_step" => Ok(&["session_id", "cursor_id"]),
        "ttd_stack_read" => Ok(&["session_id", "cursor_id"]),
        "ttd_read_memory" => Ok(&["session_id", "cursor_id", "address", "size"]),
        "ttd_memory_range" => Ok(&["session_id", "cursor_id", "address"]),
        "ttd_memory_buffer" => Ok(&["session_id", "cursor_id", "address", "size"]),
        "live_launch_session" => Ok(&["command_line"]),
        "live_attach_process" => Ok(&["process_id"]),
        "dump_open_session" => Ok(&["path"]),
        "target_status"
        | "target_close"
        | "target_terminate"
        | "target_continue"
        | "target_step_into"
        | "target_step_over"
        | "target_core_registers"
        | "target_last_event"
        | "target_list_threads"
        | "target_list_modules"
        | "target_list_breakpoints" => Ok(&["target_id"]),
        "target_wait" | "target_continue_wait" => Ok(&["target_id"]),
        "target_read_memory" => Ok(&["target_id", "address", "size"]),
        "target_memory_map" => Ok(&["target_id"]),
        "target_inspect_address" => Ok(&["target_id", "address"]),
        "target_thread_accounting" => Ok(&["target_id"]),
        "target_module_parameters" => Ok(&["target_id", "module_base_addresses"]),
        "target_symbol_entry_range" => Ok(&["target_id", "address"]),
        "target_write_dump" => Ok(&["target_id", "path"]),
        "target_symbol_by_offset" | "target_source_by_offset" => Ok(&["target_id", "address"]),
        "target_stack_trace" => Ok(&["target_id"]),
        "target_thread_context" => Ok(&["target_id", "engine_thread_id"]),
        "target_disassemble" => Ok(&["target_id"]),
        "target_set_breakpoint" => Ok(&["target_id"]),
        "target_set_breakpoint_enabled" | "target_remove_breakpoint" => {
            Ok(&["target_id", "breakpoint_id"])
        }
        "target_evaluate_expression" => Ok(&["target_id", "expression"]),
        "job_start_watch_memory_sweep" => Ok(&[
            "session_id",
            "cursor_id",
            "address",
            "size",
            "access",
            "direction",
        ]),
        "job_list" => Ok(&[]),
        "job_status" | "job_result" | "job_cancel" => Ok(&["job_id"]),
        "ttd_memory_watchpoint" => Ok(&[
            "session_id",
            "cursor_id",
            "address",
            "size",
            "access",
            "direction",
        ]),
        "target_list" => Ok(&[]),
        _ => bail!("unexpected tool listed by server: {name}"),
    }
}

fn assert_success_id(response: &Value, expected_id: u64) -> anyhow::Result<()> {
    ensure!(
        response["jsonrpc"] == "2.0",
        "missing JSON-RPC version: {response}"
    );
    ensure!(
        response["id"] == expected_id,
        "unexpected response id: {response}"
    );
    ensure!(
        response.get("error").is_none(),
        "response should not be an error: {response}"
    );
    ensure!(
        response.get("result").is_some(),
        "response should include a result: {response}"
    );
    Ok(())
}

fn assert_error_code(
    response: &Value,
    expected_id: Value,
    expected_code: i64,
) -> anyhow::Result<()> {
    ensure!(
        response["jsonrpc"] == "2.0",
        "missing JSON-RPC version: {response}"
    );
    ensure!(
        response["id"] == expected_id,
        "unexpected response id: {response}"
    );
    let Some(code) = response["error"]["code"].as_i64() else {
        bail!("response should include an error code: {response}");
    };
    ensure!(
        code == expected_code,
        "expected error code {expected_code}, got {code}: {response}"
    );
    Ok(())
}
