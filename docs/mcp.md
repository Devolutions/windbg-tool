# MCP guide

`windbg-tool.exe mcp` runs the stdio MCP server for the replay surface. The product is named `windbg-tool`, but the MCP server is still commonly configured as `windbg-ttd`, and the replay tools still use `ttd_*` names.

## Daemon-backed sessions

By default, `mcp` ensures the long-lived named-pipe daemon and proxies every tool call through it. That means:

- MCP sessions/targets/jobs are the same objects the CLI sees (`sessions`, `target list`, `job list`)
- MCP reconnects reuse daemon state
- `--pipe` / `WINDBG_TOOL_PIPE` select the daemon instance

Escape hatch for tests/dev only: set `WINDBG_TOOL_MCP_IN_PROCESS=1` to keep an in-process `ReplayService` that is not shared with the CLI.

## Configure the server

```json
{
  "servers": {
    "windbg-ttd": {
      "command": "D:\\dev\\windbg-tool\\target\\debug\\windbg-tool.exe",
      "args": ["mcp"]
    }
  }
}
```

You can also run the server directly:

```powershell
target\debug\windbg-tool.exe mcp
# or with an explicit pipe:
target\debug\windbg-tool.exe --pipe \\.\pipe\windbg-tool-dev mcp
```

## Core concepts

- Prefer composite entrypoints over long primitive chains: `discover`, `ttd_open`, `debug_snapshot`, `triage_run`
- `daemon_health` reports daemon liveness/uptime/session counts
- `session_list` lists daemon-owned TTD sessions and cursors (CLI `sessions`)
- `ttd_open` loads a trace, creates a cursor, and optionally seeks in one call
- `ttd_load_trace` / `ttd_cursor_create` remain available as lower-level primitives
- Most replay tools take both `session_id` and `cursor_id`
- Positions are represented as `{ "sequence": ..., "steps": ... }`, a `HEX:HEX` string, or a percentage for seek operations

## First useful tool flow

1. `discover` (optional catalog/recipes) and `daemon_health` / `session_list`
2. `ttd_open` with `trace_path` (and optional `position` / `symbols`)
3. `debug_snapshot` with the returned `session_id` + `cursor_id`
4. `triage_run` with `kind` such as `crash`, `hang`, or `symbol_health`
5. Drill into analysis tools: `ttd_disassemble`, `ttd_stack_backtrace`, `ttd_memory_strings` / `ttd_memory_dps` / `ttd_memory_chase`, `ttd_timeline_events`, `ttd_exception_focus`, `ttd_module_audit`, `ttd_object_vtable`, `ttd_architecture_state`, `ttd_symbols_nearest`, `symbols_diagnose`, `source_resolve`, `breakpoint_plan`, `ttd_replay_to`, `ttd_watch_memory_sweep`
6. For dumps/remote/live: `dump_triage` / `dump_pool_triage`, `remote_doctor` / `remote_plan`, and `target_*` analysis helpers
7. Fall back to primitives only as needed (`ttd_registers`, `ttd_read_memory`, `ttd_memory_watchpoint`, …)

Example `ttd_open` call:

```json
{
  "name": "ttd_open",
  "arguments": {
    "trace_path": "traces\\ping\\ping01.run",
    "symbols": {
      "binary_paths": ["traces\\ping\\ping.exe"]
    }
  }
}
```

Example follow-up snapshot:

```json
{
  "name": "debug_snapshot",
  "arguments": {
    "session_id": 1,
    "cursor_id": 1
  }
}
```

## Tool families

| Area | Main tools |
| --- | --- |
| Agent entrypoints | `discover`, `recipes_list`, `recipes_get`, `debug_capabilities`, `ttd_open`, `debug_snapshot`, `ttd_context_snapshot`, `triage_run` |
| Daemon and sessions | `daemon_health`, `session_list` |
| Session and metadata | `ttd_load_trace`, `ttd_trace_list`, `ttd_trace_info`, `ttd_close_trace`, `ttd_index_status`, `ttd_index_stats`, `ttd_build_index` |
| Trace inventory | `ttd_list_threads`, `ttd_list_modules`, `ttd_list_keyframes`, `ttd_list_exceptions`, `ttd_module_events`, `ttd_thread_events` |
| Cursor and navigation | `ttd_cursor_create`, `ttd_position_get`, `ttd_position_set`, `ttd_replay_to`, `ttd_step`, `ttd_active_threads` |
| State and memory | `ttd_registers`, `ttd_register_context`, `ttd_command_line`, `ttd_read_memory`, `ttd_memory_range`, `ttd_memory_buffer`, `ttd_memory_watchpoint`, `ttd_watch_memory_sweep` |
| TTD analysis | `ttd_disassemble`, `ttd_stack_recover`, `ttd_stack_backtrace`, `ttd_memory_dump`, `ttd_memory_classify`, `ttd_memory_strings`, `ttd_memory_dps`, `ttd_memory_chase`, `ttd_timeline_events`, `ttd_exception_focus`, `ttd_architecture_state`, `ttd_module_audit`, `ttd_object_vtable`, `ttd_symbols_nearest`, `symbols_diagnose`, `symbols_doctor` |
| Host diagnostics | `module_search_order`, `source_resolve`, `breakpoint_plan`, `pe_inspect`, `pe_exports`, `debug_log_summarize`, `remote_explain`, `remote_doctor`, `remote_status`, `remote_plan`, `remote_server_command`, `remote_connect_command` |
| Live / dump / jobs | `live_launch_session`, `live_attach_process`, `dump_open_session`, `dump_inspect`, `dump_triage`, `dump_pool_triage`, `target_*` (including `target_disassemble_analysis`, `target_memory_*`, `target_stack_recover`), `job_*` |

Host-only workflows remain CLI-first: WinDbg install/update/run, elevated TTD record, long-running `dbgeng server` hosting, and managed/startup-break profilers.

## Symbol settings

`ttd_open` and `ttd_load_trace` accept an optional `symbols` object:

```json
{
  "binary_paths": ["traces\\ping\\ping.exe", "C:\\Windows\\System32"],
  "symbol_paths": ["C:\\symbols"],
  "symcache_dir": ".ttd-symbol-cache"
}
```

Symbol settings use this precedence:

1. Explicit `symbols.symbol_paths` from the request.
2. `_NT_SYMBOL_PATH`, then `_NT_ALT_SYMBOL_PATH`, when no explicit paths are supplied.
3. The module directory, as provided by the Windows symbol handler.

`symbols.symcache_dir` overrides `_NT_SYMCACHE_PATH`; otherwise `_NT_SYMCACHE_PATH` supplies the cache directory. These settings configure local symbol directories only; windbg-tool does not append `srv*` or load `symsrv.dll`.

The same environment resolution is applied to DbgEng live-launch, live-attach, and dump sessions. Their active resolved path is included in the target session summary as `symbol_path`.

## Example prompts

Load and summarize a trace:

```text
Use the windbg-ttd server to load traces\ping\ping01.run with traces\ping\ping.exe as the matching binary path. Summarize the backend, process id, lifetime, thread count, module count, and whether native replay is active.
```

Read the recorded command line:

```text
Load the sample ping trace, create a cursor, and read the recorded process command line.
```

Find an earlier access to a memory range:

```text
Load the trace, create a cursor, move to the end of the trace, and search backward for a read of a known memory range. Report whether a hit was found and where replay stopped.
```

## Practical notes

- Tool results include both JSON text content and MCP `structuredContent`
- Tool failures are returned as MCP tool results with `isError: true`
- Tool definitions include MCP annotations that hint whether a tool is read-only, destructive, idempotent, or open-world
- If native replay is unavailable, some tools return placeholder or empty results with warnings instead of full trace-backed data

## Privacy

TTD traces can include process memory and other sensitive state. Treat `.run`, `.idx`, and `.ttd` files as sensitive local artifacts.

## Next docs

- For the daemon-backed CLI workflow, see [cli.md](cli.md)
- For setup, native dependencies, and local tests, see [development.md](development.md)
