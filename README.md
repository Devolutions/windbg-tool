# windbg-tool

`windbg-tool` is a Windows-first command-line tool and MCP server for WinDbg-oriented automation. It is centered on Time Travel Debugging (TTD) replay, but it also covers broader WinDbg workflows such as daemon-backed CLI automation, symbol and source diagnostics, disassembly and memory inspection helpers, DbgEng process-server support, remote debugging command generation, and WinDbg install/update/launch.

`windbg-tool` is the product name. You will still see `windbg-ttd` in MCP server configuration and `ttd_*` tool names because the replay/MCP surface grew out of the original TTD-focused implementation.

## What you can do

- Run a stdio MCP server for TTD replay workflows.
- Keep long-lived replay sessions in a local daemon and drive them from the CLI.
- Open traces, create cursors, seek positions, inspect threads/modules/registers/memory, and replay to watchpoints.
- Use higher-level helpers such as `discover`, `recipes`, `debug capabilities`, `debug snapshot`, `triage`, `symbols doctor`, `disasm`, `stack backtrace`, and `memory chase`.
- Plan and diagnose local/remote DbgEng workflows with `remote doctor`, `remote plan`, process-server commands, and WinDbg install/update/launch helpers.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates\windbg-tool` | Main `windbg-tool.exe` CLI application |
| `crates\windbg-ttd` | MCP server, daemon, replay facade, and TTD tool surface |
| `crates\windbg-dbgeng` | DbgEng helpers for live/process-server scenarios |
| `crates\windbg-install` | WinDbg download, update, and launch support |
| `native\ttd-replay-bridge` | Narrow C ABI bridge over the Microsoft TTD Replay API |
| `xtask` | Development workflow commands |
| `docs\architecture.md` | Architecture and implementation notes |

## Build from source

For a local build with the native replay pieces available:

```powershell
cargo xtask doctor
cargo xtask deps
cargo xtask native-build
cargo build -p windbg-tool
```

The built executable is:

```text
target\debug\windbg-tool.exe
```

Release ZIP artifacts are built by the Windows packaging workflow. Run **Windows packages** manually with an unprefixed semantic version such as `0.1.0` to publish the `v0.1.0` GitHub Release. Select **dry_run** to build and validate the packages without creating a tag or release. The release contains `windbg-tool-x64.zip` and `windbg-tool-arm64.zip`.

The local equivalent uses `cargo xtask deps --arch <amd64|arm64>`, `cargo xtask native-build --arch <amd64|arm64> --static-crt`, a release build for the matching MSVC Rust target, and `cargo xtask package --profile release`. Both packages statically link the MSVC runtime and bundle their required TTD, DbgEng, symbol, and native-bridge DLLs.

For deeper setup, test commands, runtime details, and workspace notes, see [the development guide](docs/development.md).

## CLI quick start

Some commands work without loading a trace or starting the daemon:

```powershell
target\debug\windbg-tool.exe discover
target\debug\windbg-tool.exe cli-schema
target\debug\windbg-tool.exe recipes
target\debug\windbg-tool.exe tools
```

For trace-driven work, the common flow is:

```powershell
target\debug\windbg-tool.exe daemon ensure
target\debug\windbg-tool.exe open C:\path\to\trace.run --binary-path C:\path\to\binary.exe
target\debug\windbg-tool.exe sessions
target\debug\windbg-tool.exe debug capabilities --session 1 --cursor 1
target\debug\windbg-tool.exe debug snapshot --session 1 --cursor 1
target\debug\windbg-tool.exe disasm --session 1 --cursor 1
```

`open` is the best starting command for the CLI because it loads the trace, creates a cursor, and returns both `session_id` and `cursor_id`. Most replay commands then use `--session` and `--cursor` (or the short forms `-s` and `-c`).

For AI agents and robust scripts, add `--envelope` or set `WINDBG_TOOL_ENVELOPE=1` to get stable `{ schema_version, ok, data|error }` JSON responses and structured error codes.
Set `WINDBG_TOOL_ACTION_LOG=<path>` to append redacted JSONL command outcomes for handoff/resume workflows, then inspect them with `debug log summarize`.

Representative command areas:

- Discovery: `discover`, `cli-schema`, `recipes`, `tools`, `schema`
- Session and replay: `open`, `load`, `sessions`, `info`, `position set`, `step`, `replay to`
- Agent workflow: `debug capabilities`, `debug snapshot`, `triage crash`, `symbols doctor`, `breakpoint plan`, `debug log summarize`
- Analysis: `symbols diagnose`, `disasm`, `memory dump`, `memory strings`, `memory chase`, `stack recover`, `stack backtrace`
- Platform helpers: `remote explain`, `remote doctor`, `remote plan`, `dbgeng server`, `live launch`, `dump create`, `dump inspect`, `dump triage`, `windbg status`

For a fuller CLI walkthrough, output-shaping flags, and command map, see [the CLI guide](docs/cli.md).

## MCP quick start

Run the MCP server over stdio:

```powershell
target\debug\windbg-tool.exe mcp
```

Example MCP client configuration:

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

The usual MCP flow is:

1. `ttd_load_trace`
2. `ttd_cursor_create`
3. `ttd_trace_info`, `ttd_registers`, `ttd_read_memory`, `ttd_memory_watchpoint`, or related tools

Helpful starting prompt:

```text
Use the windbg-ttd server to load C:\path\to\trace.run with the matching binary path, create a cursor, summarize the trace, and show the current compact register state.
```

For configuration details, session/cursor concepts, symbol settings, and example tool calls/prompts, see [the MCP guide](docs/mcp.md).

## More docs

- [CLI guide](docs/cli.md) - daemon model, CLI workflows, and command groups
- [MCP guide](docs/mcp.md) - MCP configuration, core tool flow, and example prompts
- [Development guide](docs/development.md) - build, native dependencies, symbols, tests, and repository hygiene
- [Architecture notes](docs/architecture.md) - architecture and layering details

## Trace privacy

TTD traces can contain process memory, file paths, registry data, and other sensitive machine state. Treat `.run`, `.idx`, and related replay artifacts as sensitive local files.
