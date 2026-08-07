# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Purpose

`windbg-tool` is a Windows-first Rust workspace for WinDbg automation. The `windbg-tool.exe` executable can run the `windbg-ttd` MCP server, keep long-lived TTD replay sessions in a local daemon, act as an agent-friendly CLI client, start DbgEng process servers, and install/update/launch WinDbg.

This project must use the Time Travel Debugging replay APIs, not the regular live-debugging `cdb` or DbgEng attach flow. DbgEng-related packages can be useful for symbols and debugger-platform support, but core replay should go through the TTD Replay API.

## Current Architecture

- Rust workspace root: `Cargo.toml`.
- TTD crate: `crates/windbg-ttd` (package name `windbg-ttd`).
- CLI application crate: `crates/windbg-tool` (package name `windbg-tool`, binary `windbg-tool.exe`).
- DbgEng helper crate: `crates/windbg-dbgeng`.
- WinDbg installer crate: `crates/windbg-install`.
- Developer workflow crate: `xtask`.
- Native C++ bridge scaffold: `native/ttd-replay-bridge`.
- Runtime/dependency helper script: `scripts/Get-TtdReplayRuntime.ps1`.
- Architecture notes: `docs/architecture.md`.

The intended layering is:

1. Rust MCP server over stdio using the official `rmcp` Rust MCP SDK, plus tool schemas, validation, session ids, and serialization.
2. Safe Rust replay facade for traces, cursors, positions, modules, threads, exceptions, registers, memory reads, and watchpoints.
3. Narrow C ABI C++ bridge over Microsoft's C++ TTD Replay API.

Do not bind Rust directly to TTD C++ vtables, STL helper types, or C++ ownership rules. Keep the native bridge as a small C ABI with opaque handles and plain data structs.

## Current Implementation State

The Rust MCP server uses `rmcp` for stdio MCP protocol handling, advertises tools, and can use the native bridge for trace pack/list enumeration, trace loading with trace-index selection, trace index status/stats/build operations, trace metadata, thread/module/exception/keyframe enumeration, cursor-local module snapshots, module and thread lifecycle event timelines, cursor creation, position get/set including TTD thread-scoped seeking, active-thread snapshots, stepping/tracing, compact and x64 scalar/SIMD cursor register/thread state, bounded guest memory reads with selectable TTD query policies, trace-backed memory range and buffer provenance queries, memory watchpoint replay with full TTD access masks and optional thread filters, and PEB-backed command-line extraction when `ttd_replay_bridge.dll` and TTD runtime DLLs are available. The CLI also has daemon-free `recipes` discovery for TimDbg-inspired diagnostic workflows, `context snapshot` for one-shot agent context capture with architecture/disassembly/nearest-symbol/timeline enrichment from a running daemon session, `remote` helpers that explain and generate DbgSrv versus NTSD/CDB command lines, `symbols diagnose`/`symbols inspect`/`symbols exports`/`symbols nearest` for symbol/binary/PDB/export readiness checks and nearest-export fallback, `source resolve` for trailing-component source path matching, `disasm`/`u` for x64 instruction analysis, `object vtable` for read-only COM/C++ object analysis, `stack recover` for corrupted-stack return-address candidates, and `memory dump`/`memory classify`/`memory strings`/`memory dps`/`memory chase` for string/fill/entropy/pointer/instruction hints, bounded string extraction, dps-style pointer rows, and bounded pointer-chain inspection.

## Build And Check Commands

Run these from the repository root:

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p windbg-tool
```

The runnable debug server is:

```text
target/debug/windbg-tool.exe mcp
```

The same executable also supports:

```text
target/debug/windbg-tool.exe daemon start
target/debug/windbg-tool.exe daemon ensure
target/debug/windbg-tool.exe discover
target/debug/windbg-tool.exe recipes
target/debug/windbg-tool.exe context snapshot --session <id> --cursor <id>
target/debug/windbg-tool.exe remote explain
target/debug/windbg-tool.exe live capabilities
target/debug/windbg-tool.exe live launch --command-line "C:\Windows\System32\notepad.exe" --end detach
target/debug/windbg-tool.exe breakpoint capabilities
target/debug/windbg-tool.exe datamodel capabilities
target/debug/windbg-tool.exe target capabilities --session <id> --cursor <id>
target/debug/windbg-tool.exe symbols diagnose --session <id>
target/debug/windbg-tool.exe symbols inspect <exe-or-dll>
target/debug/windbg-tool.exe symbols exports <exe-or-dll> --filter <name>
target/debug/windbg-tool.exe symbols nearest --session <id> --cursor <id> --address <addr>
target/debug/windbg-tool.exe source resolve <recorded-path> --search-path <source-root>
target/debug/windbg-tool.exe module audit --session <id>
target/debug/windbg-tool.exe module search-order suspicious.dll --app-dir <app-dir>
target/debug/windbg-tool.exe architecture state --session <id> --cursor <id>
target/debug/windbg-tool.exe replay capabilities --session <id>
target/debug/windbg-tool.exe replay to --session <id> --cursor <id> --position 50
target/debug/windbg-tool.exe sweep watch-memory --session <id> --cursor <id> --address <addr> --size 8 --access write --direction previous --max-hits 8
target/debug/windbg-tool.exe timeline events --session <id>
target/debug/windbg-tool.exe disasm --session <id> --cursor <id>
target/debug/windbg-tool.exe object vtable --session <id> --cursor <id> --address <object>
target/debug/windbg-tool.exe stack recover --session <id> --cursor <id>
target/debug/windbg-tool.exe stack backtrace --session <id> --cursor <id>
target/debug/windbg-tool.exe memory strings --session <id> --cursor <id> --address <addr> --size 256 --encoding both
target/debug/windbg-tool.exe memory dps --session <id> --cursor <id> --address <addr> --size 128 --target-info
target/debug/windbg-tool.exe memory chase --session <id> --cursor <id> --address <addr> --depth 8
target/debug/windbg-tool.exe trace-list <trace.ttd>
target/debug/windbg-tool.exe open <trace.run>
target/debug/windbg-tool.exe index status --session <id>
target/debug/windbg-tool.exe dbgeng server --transport tcp:port=5005
target/debug/windbg-tool.exe windbg status
target/debug/windbg-tool.exe windbg update
```

For dependency setup and environment checks:

```powershell
cargo xtask doctor
cargo xtask deps
cargo xtask native-build
```

`cargo xtask deps` restores native NuGet packages into `target/nuget`, stages `dbghelp.dll` and `srcsrv.dll` into `target/symbol-runtime`, stages DbgEng process-server runtime DLLs into `target/dbgeng-runtime`, and downloads `TTDReplay.dll` plus `TTDReplayCPU.dll` into `target/ttd-runtime`.

## Native Dependencies

Native package restore is driven by `native/ttd-replay-bridge/packages.config`.

Important packages:

- `Microsoft.TimeTravelDebugging.Apis` for TTD Replay headers and import libraries.
- `Microsoft.Debugging.Platform.SrcSrv` for source-server support next to symbol acquisition.
- `Microsoft.Debugging.Platform.DbgEng` for DbgEng process-server runtime DLLs, headers, and import libraries.

Runtime replay DLLs come from the WinDbg/TTD distribution, not from the TTD API NuGet package.

## Symbols

`windbg-symbols` resolves public PDBs with the Rust-native `symsrv` crate and hands DbgEng only direct local PDB/image directories. `cargo xtask deps` stages `dbghelp.dll` and `srcsrv.dll` into `target/symbol-runtime`, and stages DbgEng runtime DLLs into `target/dbgeng-runtime`. Preserve support for caller-provided binary paths, local symbol paths, and symbol cache directories. Public Microsoft symbols are enough for module and function names in many Windows binaries; private symbols are not expected for normal tests.

## Good Test Trace Target

The repository keeps a small reusable sample trace as `traces/ping.7z`. Keep the archive trackable, but keep extracted trace contents under `traces/ping/` local-only and ignored. The ping integration test extracts `traces/ping.7z` automatically with `7z` or `7zz`; use `TTD_TEST_7Z` if the extractor is not on `PATH`.

For a simple local TTD capture, prefer an in-box Windows executable with public symbols on the Microsoft symbol server. A good first target is:

```text
C:\Windows\System32\ping.exe 127.0.0.1 -n 3
```

This is easy to obtain, short-lived, deterministic enough for smoke tests, and its public PDBs should be available through `https://msdl.microsoft.com/download/symbols` on supported Windows builds.

If you want an interactive target that stays alive until closed, use:

```text
C:\Windows\System32\notepad.exe
```

Close the program cleanly so TTD finalizes the `.run` and `.idx` files.

## Safety And Repository Hygiene

- Treat `.run`, `.idx`, `.ttd`, `.pdb`, `.dll`, `.exe`, and other generated debugger artifacts as local-only unless the user explicitly asks otherwise.
- Keep reusable test traces compressed as `.7z` archives; do not commit their extracted directories.
- Do not commit downloaded Microsoft runtime binaries or captured traces.
- Keep edits focused. Do not refactor unrelated Rust modules while wiring native replay.
- Read current file contents before editing; this repo may have user or formatter edits between turns.
- Preserve placeholder errors until a real backend is wired, so unsupported tools fail clearly rather than returning misleading data.

## Likely Next Implementation Steps

1. Add symbol/binary/source diagnostics and nearest-symbol helpers.
2. Add instruction-aware disassembly and memory classification commands.
3. Add stack unwind/recovery workflows, including TTD stack-corruption watchpoint scenarios.
4. Improve remote debugging recipes and lifecycle helpers beyond raw DbgSrv launch.
5. Add live DbgEng session support after the daemon abstractions are ready.
