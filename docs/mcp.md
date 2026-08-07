# MCP guide

`windbg-tool.exe mcp` runs the stdio MCP server for the replay surface. The product is named `windbg-tool`, but the MCP server is still commonly configured as `windbg-ttd`, and the replay tools still use `ttd_*` names.

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
```

## Core concepts

- `ttd_load_trace` opens a `.run`, `.idx`, or `.ttd` trace and returns a `session_id`
- `ttd_cursor_create` creates a replay cursor and returns a `cursor_id`
- Most replay tools take both `session_id` and `cursor_id`
- Positions are represented as `{ "sequence": ..., "steps": ... }`, a `HEX:HEX` string, or a percentage for seek operations

## First useful tool flow

1. `ttd_load_trace`
2. `ttd_trace_info`
3. `ttd_cursor_create`
4. `ttd_registers`
5. Optional deeper reads such as `ttd_read_memory`, `ttd_memory_range`, `ttd_memory_watchpoint`, or `ttd_register_context`

Example `ttd_load_trace` call:

```json
{
  "name": "ttd_load_trace",
  "arguments": {
    "trace_path": "traces\\ping\\ping01.run",
    "symbols": {
      "binary_paths": ["traces\\ping\\ping.exe"]
    }
  }
}
```

Then create a cursor:

```json
{
  "name": "ttd_cursor_create",
  "arguments": {
    "session_id": 1
  }
}
```

## Tool families

| Area | Main tools |
| --- | --- |
| Session and metadata | `ttd_load_trace`, `ttd_trace_list`, `ttd_trace_info`, `ttd_close_trace`, `ttd_index_status`, `ttd_index_stats`, `ttd_build_index` |
| Trace inventory | `ttd_list_threads`, `ttd_list_modules`, `ttd_list_keyframes`, `ttd_list_exceptions`, `ttd_module_events`, `ttd_thread_events` |
| Cursor and navigation | `ttd_cursor_create`, `ttd_position_get`, `ttd_position_set`, `ttd_step`, `ttd_active_threads` |
| State and memory | `ttd_registers`, `ttd_register_context`, `ttd_command_line`, `ttd_read_memory`, `ttd_memory_range`, `ttd_memory_buffer`, `ttd_memory_watchpoint` |

## Symbol settings

`ttd_load_trace` accepts an optional `symbols` object:

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
