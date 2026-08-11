# windbg-tool

Windows-first CLI and MCP server for WinDbg-oriented debugging workflows.

Use it to:

- **Replay TTD traces** — open a `.run` file, seek to positions, inspect registers/memory, and walk history
- **Triage dumps** — pull exception, stack, module, and symbol evidence from user or kernel dumps
- **Record new traces** — launch a process under Microsoft Time Travel Debugging
- **Drive live probes** — one-shot startup breakpoints, managed breakpoints, and startup profiling
- **Help AI agents** — stable JSON output, recipes, and an MCP server agents can call directly
- **Manage WinDbg** — check status, update, and launch the debugger

`windbg-tool` is the product name. You may still see `windbg-ttd` in MCP configs and `ttd_*` tool names — those are the replay/MCP surface names.

---

## Install

Requires Windows and the [.NET 10 SDK](https://dotnet.microsoft.com/download) or later:

```powershell
dotnet tool install -g Devolutions.WinDbg.Tool
windbg-tool discover
```

Update later with:

```powershell
dotnet tool update -g Devolutions.WinDbg.Tool
```

The package ships signed `win-x64` and `win-arm64` payloads and puts `windbg-tool` on your PATH.

Prefer building from source? See [docs/development.md](docs/development.md).

---

## 5-minute tour

These commands need no daemon and no trace:

```powershell
# What can this install do on this machine?
windbg-tool discover

# Suggested workflows for common debugging jobs
windbg-tool recipes

# Machine-readable command map (great for agents and scripts)
windbg-tool cli-schema
```

For agents and scripts, prefer stable JSON:

```powershell
windbg-tool --compact --envelope discover
```

- `--compact` keeps the payload smaller
- `--envelope` wraps every response as `{ schema_version, ok, data|error }`
- Or set `WINDBG_TOOL_ENVELOPE=1` once for the whole shell

---

## Replay a TTD trace

Typical flow: ensure the local daemon, open a trace, then analyze with the returned session and cursor IDs.

```powershell
# 1. Start or reuse the local daemon
windbg-tool daemon ensure

# 2. Open the trace (creates a session + cursor)
windbg-tool open C:\path\to\trace.run --binary-path C:\path\to\binary.exe

# 3. One-shot context for agents or humans
windbg-tool debug snapshot --session 1 --cursor 1

# 4. Dig in
windbg-tool disasm --session 1 --cursor 1
windbg-tool registers --session 1 --cursor 1
windbg-tool position set --session 1 --cursor 1 --position 50
windbg-tool memory strings --session 1 --cursor 1 --address 0x12345678 --size 256 --encoding both
```

`open` is the best entry point: it loads the trace, creates a cursor, and returns both `session_id` and `cursor_id`. Most replay commands take `--session` / `--cursor` (or `-s` / `-c`).

Useful follow-ups:

| Goal | Command |
| --- | --- |
| List active sessions | `windbg-tool sessions` |
| Trace metadata | `windbg-tool info --session 1` |
| Jump near a failure | `windbg-tool exception focus --session 1 --cursor 1 --index 0` |
| Step / seek | `windbg-tool step ...`, `windbg-tool replay to ...` |
| Stack work | `windbg-tool stack backtrace ...`, `windbg-tool stack recover ...` |
| Pointer chase | `windbg-tool memory chase --session 1 --cursor 1 --address 0x... --depth 8` |
| Symbol health | `windbg-tool symbols doctor --session 1` |

Full CLI map: [docs/cli.md](docs/cli.md).

---

## Record a new trace

Needs the Microsoft TTD recorder (`winget install --id Microsoft.TimeTravelDebugging`) and an elevated terminal (or Windows 11 sudo in **Input Closed** / **Inline** mode).

```powershell
windbg-tool --compact trace record `
  --output C:\traces\app.run `
  --command-line '"C:\apps\MyApp.exe" /quit-after-work'
```

Capture presets:

```powershell
# Keep the earliest startup data (up to 1 GiB)
windbg-tool trace record --profile startup `
  --output C:\traces\app-startup.run `
  --command-line '"C:\apps\MyApp.exe"'

# Keep only the newest data in a rolling window
windbg-tool trace record --profile recent `
  --output C:\traces\app-recent.run `
  --command-line '"C:\apps\MyApp.exe"'
```

Traces can contain process memory and other sensitive state. Treat `.run` / `.idx` files as local secrets.

---

## Triage a dump

Start read-only — no daemon required:

```powershell
windbg-tool --compact --envelope dump triage C:\dumps\failure.dmp --max-frames 32
```

Open the dump for interactive follow-up:

```powershell
windbg-tool daemon ensure
windbg-tool --envelope dump open C:\dumps\failure.dmp
# Use the returned target_id:
windbg-tool --compact --envelope debug snapshot --target <target_id> --max-frames 32
windbg-tool --compact --envelope target threads --target <target_id>
```

Prompt template for an AI agent:

```text
Analyze C:\dumps\failure.dmp with windbg-tool. Start with dump triage, then
open the dump only if targeted follow-up is needed. Summarize evidence from
the exception, stack, symbols, and modules; call out uncertainty and give the
next bounded command that would reduce it.
```

---

## Live debugging helpers

One-shot native startup breakpoint (launch, break, capture JSON, end):

```powershell
windbg-tool --compact live startup-break `
  --command-line '"C:\apps\MyApp.exe"' `
  --module MyApp.exe `
  --module-offset 0x1000 `
  --wait-timeout-ms 10000 `
  --end terminate
```

Also available:

| Command | What it does |
| --- | --- |
| `live managed-break` | Resolve a managed method via CoreCLR DAC and break at its native entry |
| `live startup-profile` | Collect bounded startup lifecycle events without placing breakpoints |
| `live startup-compare` | Diff two startup-profile JSON artifacts offline |
| `live startup-report` | Render a module-load timeline table from a profile artifact |
| `live launch` / `live attach` | Broader live DbgEng session helpers |

See [docs/cli.md](docs/cli.md) for flags, hardware-execute mode, and managed-break safety notes (`--allow-runtime-write` is explicit and intended for approved test VMs).

---

## MCP server (for AI agents)

Run over stdio:

```powershell
windbg-tool mcp
```

Example client config:

```json
{
  "servers": {
    "windbg-ttd": {
      "command": "windbg-tool",
      "args": ["mcp"]
    }
  }
}
```

If you built from source, point `command` at `target\debug\windbg-tool.exe` instead.

Core replay flow inside MCP:

1. `ttd_load_trace` — open a `.run` / `.idx` / `.ttd`
2. `ttd_cursor_create` — get a replay cursor
3. Inspect with `ttd_trace_info`, `ttd_registers`, `ttd_read_memory`, `ttd_memory_watchpoint`, …

Starter prompt:

```text
Use the windbg-ttd server to load C:\path\to\trace.run with the matching binary
path, create a cursor, summarize the trace, and show the current compact
register state.
```

Details and symbol settings: [docs/mcp.md](docs/mcp.md).

---

## Feature map

| Area | Commands |
| --- | --- |
| Discovery | `discover`, `cli-schema`, `recipes`, `tools`, `schema` |
| Sessions & replay | `daemon ensure`, `open`, `load`, `sessions`, `info`, `position set`, `step`, `replay to` |
| Agent workflows | `debug capabilities`, `debug snapshot`, `triage crash`, `symbols doctor`, `breakpoint plan` |
| Analysis | `disasm`, `symbols diagnose` / `inspect` / `exports` / `nearest`, `memory dump` / `strings` / `dps` / `chase`, `stack backtrace` / `recover` |
| Recording | `trace record`, `trace-list` |
| Dumps | `dump triage`, `dump open`, `dump inspect`, `dump create` |
| Live / remote | `live …`, `remote explain` / `doctor` / `plan`, `dbgeng server` |
| WinDbg install | `windbg status`, `windbg update`, `windbg launch` |

### Output shaping for automation

```powershell
# Stable success/error envelope
windbg-tool --envelope --compact debug snapshot -s 1 -c 1

# Append redacted JSONL outcomes for handoff/resume
$env:WINDBG_TOOL_ACTION_LOG = "C:\temp\windbg-tool-actions.jsonl"
windbg-tool debug log summarize
```

---

## Privacy

TTD traces and dumps can contain process memory, file paths, registry data, and other machine state. Treat `.run`, `.idx`, `.ttd`, and dump files as sensitive local artifacts. Do not commit them.

---

## More docs

| Doc | When you need it |
| --- | --- |
| [CLI guide](docs/cli.md) | Full command walkthroughs, live/managed/startup details |
| [MCP guide](docs/mcp.md) | Server config, tool families, example prompts |
| [Development guide](docs/development.md) | Build from source, native deps, tests |
| [Architecture notes](docs/architecture.md) | Layering and implementation design |
