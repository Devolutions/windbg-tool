# Development and advanced setup

This page keeps the deeper setup and contributor-oriented material out of the main README while preserving the details needed to build and work on the project.

## Workspace structure

| Path | Purpose |
| --- | --- |
| `Cargo.toml` | Workspace root |
| `crates\windbg-tool` | Main CLI binary crate |
| `crates\windbg-ttd` | MCP server, daemon, replay facade, and tool definitions |
| `crates\windbg-dbgeng` | DbgEng process-server and live-launch helpers |
| `crates\windbg-install` | WinDbg package install/update/launch support |
| `xtask` | Developer workflow commands |
| `native\ttd-replay-bridge` | C++ bridge to the TTD Replay API |
| `scripts\Get-TtdReplayRuntime.ps1` | Runtime acquisition helper |
| `docs\architecture.md` | Architecture notes and layering details |

## Build and check commands

Run these from the repository root:

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p windbg-tool
```

## Dependency and native setup

Use a Visual Studio Developer PowerShell, or another environment where `nuget`, `cmake`, `msbuild`, and `powershell` are available:

```powershell
cargo xtask doctor
cargo xtask deps
cargo xtask native-build
```

`cargo xtask deps`:

- restores native NuGet packages into `target\nuget`
- stages `dbghelp.dll` and `srcsrv.dll` into `target\symbol-runtime`
- stages DbgEng runtime DLLs into `target\dbgeng-runtime`
- downloads `TTDReplay.dll` and `TTDReplayCPU.dll` into `target\ttd-runtime`

`cargo xtask native-build` configures and builds the TTD bridge under `target\native\ttd-replay-bridge`. The CoreCLR DAC host is implemented in the Rust DbgEng crate and does not require a separately staged bridge DLL.

For release packaging, use explicit target architecture inputs so the Rust binary, native bridge, and staged debugger runtime DLLs all match:

```powershell
$env:RUSTFLAGS = "-C target-feature=+crt-static"
rustup target add x86_64-pc-windows-msvc
cargo xtask deps --arch amd64
cargo xtask native-build --arch amd64 --static-crt
cargo build -p windbg-tool --release --target x86_64-pc-windows-msvc
cargo xtask package --arch amd64 --target x86_64-pc-windows-msvc --profile release --out target\package\windbg-tool-x64
```

Use `--arch arm64` with `--target aarch64-pc-windows-msvc` for the Windows ARM64 package. The CoreCLR DAC bridge currently supports only x64, so ARM64 packages do not include direct managed-break support. Architecture-specific dependency staging uses `target\runtime\<arch>\...`, while the legacy no-argument `cargo xtask deps`, `cargo xtask native-build`, and `cargo xtask package` commands keep using the existing host-architecture directories.

Release packages statically link the MSVC C runtime into Rust code with `RUSTFLAGS=-C target-feature=+crt-static` and into the native bridge with `cargo xtask native-build --static-crt`. WinDbg, DbgEng, symbol, and TTD replay runtime DLLs remain dynamic dependencies and are copied into the package directory.

For a development build that uses architecture-specific staged DbgEng DLLs, set the process-local runtime directory before using a live DbgEng command:

```powershell
$env:WINDBG_DBGENG_RUNTIME_DIR = (Resolve-Path target\runtime\amd64\dbgeng-runtime)
target\debug\windbg-tool.exe live capabilities
```

The live backend securely loads the version-matched `dbgcore.dll`, `dbghelp.dll`, `dbgmodel.dll`, and `dbgeng.dll` set from this directory (or from beside `windbg-tool.exe` in a package) before resolving DbgEng exports. This keeps the executable free of static DbgEng/DbgHelp imports and does not alter global DLL-search or security policy.

For a direct managed breakpoint, the DAC bridge loads `mscordaccore.dll` only from the same directory as the CoreCLR module loaded by the target and requires exact file-version equality. It does not bundle a DAC or SOS. Enabling CLR module/code notifications requires `--allow-runtime-write`: the DAC requests a CLR-owned JIT-notification allocation through `ICLRDataTarget2`, and the bridge uses DbgEng's active process handle with `VirtualAllocEx` before writing CLR debugger-notification state. This is not process hollowing or code injection; run the intentionally target-mutating workflow only in an approved test VM.

## Managed breakpoint fixture

`crates\windbg-tool\tests\fixtures\ManagedBreakpointFixture` is a source-only .NET 10 x64 test target for direct CoreCLR DAC breakpoints. It exercises public, private, and overloaded static methods while `MethodImplOptions.NoInlining` keeps each target observable to the JIT.

```powershell
dotnet build crates\windbg-tool\tests\fixtures\ManagedBreakpointFixture\ManagedBreakpointFixture.csproj -c Release
```

Run the fixture's public/private/overload `live managed-break` commands from [cli.md](cli.md) only in an approved test VM. The overload invocation uses `--signature 00010E0E`, the raw ECMA-335 `MethodDef` signature for `string Overload(string)`. The separate `--hardware-execute` mode is non-invasive: it uses a DbgEng `DEBUG_BREAKPOINT_DATA`/`DEBUG_BREAK_EXECUTE` processor breakpoint, opens the DAC read-only, and rejects `--allow-runtime-write`. It was verified for the native `coreclr!coreclr_execute_assembly` fixture hit, but a managed assembly's DbgEng image-load event precedes its read-only DAC visibility, so it cannot currently prove a private managed-method hit. Do not work around that lifecycle boundary with target writes, JIT forcing, injection, protection changes, or unapproved debugging. RDM continuation is blocked under the current policy: do not launch, attach, or resume it under any breakpoint, and do not seek exclusions or workarounds. Any future RDM work requires a new explicit direction and written approval defining the permitted debugger operations for the test VM and build; do not change Sophos, HitmanPro.Alert, or RDM protections.

## Non-invasive startup-profile fixture

`live startup-profile` validates the event-only DbgEng path without a breakpoint or DAC. It starts at a create-process event and configures only DbgEng lifecycle filters. It performs no target-memory allocation/write, no CLR notification registration, no injection, and no profiling. Run its fixture command from [cli.md](cli.md) before any RDM profile attempt.

The command's phase values are host-monotonic resumed wall time between DbgEng stops, not CPU time or target-internal timestamps. The fixture accepts `--startup-observation-delay-ms 0..10000` so the documented module-plus-quiet test can detach before normal process exit, `--debug-output <text>` to emit at most 256 UTF-16 characters through `OutputDebugStringW` for opt-in callback validation, and `--cpu-burn-ms 1..10000` for thread-accounting validation. A 1200 ms CPU burn produced a validity-gated same-thread user-counter increase of 15,000,000, confirming DbgEng's `KernelTime`/`UserTime` unit is 100 ns before the profiler exposed millisecond projections. Use the debug-output switch only with a non-sensitive fixture string and `--capture-debuggee-output` caps. A `quiet_interval_observed` result means only that no configured lifecycle stop arrived while the target was resumed for that duration; it does not establish application quiescence. Preserve `finish_reason`, `completion`, `coverage`, and incomplete runs when evaluating output. `--capture-stop-context`, `--capture-thread-accounting`, and `--capture-module-provenance` are read-only but opt-in because their queries add observer overhead. `--capture-native-symbol-entry-range` and `--capture-dbgeng-module-parameters` can also cause host-side symbol-resolution I/O through the configured symbol path. `--include-first-chance-exceptions` is also opt-in and bounded by `--max-events`.

The RDM policy remains stricter for all breakpoint/DAC workflows. The event-only profile command can make one bounded RDM launch after the fixture proves its no-write result. Only after that run reaches `exit_process` may it make a small bounded repeated collection; if the initial run is blocked, do not retry or seek an exclusion, protection change, or workaround.

Cross-compiling the ARM64 package from an x64 machine requires the Visual Studio ARM64 MSVC toolset and an `x64_arm64` developer environment for the native bridge and Rust crates that compile C/C++ code.

### Publishing a GitHub Release

Run the **Windows packages** workflow with **Run workflow** and enter an unprefixed semantic version such as `0.1.0`. After both package matrix jobs complete, the workflow creates the `v0.1.0` tag at the commit selected for the dispatch and publishes a GitHub Release containing:

- `windbg-tool-x64.zip`
- `windbg-tool-arm64.zip`

Select **dry_run** to build both ZIPs, validate their contents, validate the version, and confirm that the tag is available without creating a tag or GitHub Release. The workflow rejects existing tags and invalid versions rather than replacing a release. Each ZIP contains the statically linked Rust executable and native bridge plus the required dynamic TTD Replay, DbgEng, and symbol runtime DLLs.

To smoke-test the packaged MCP server:

```powershell
cargo xtask mcp-smoke
```

## Native dependencies

Native package restore is driven by `native\ttd-replay-bridge\packages.config`.

Important packages:

- `Microsoft.TimeTravelDebugging.Apis`
- `Microsoft.Debugging.Platform.SrcSrv`
- `Microsoft.Debugging.Platform.DbgEng`

Runtime replay still depends on `TTDReplay.dll` and `TTDReplayCPU.dll` from the WinDbg/TTD distribution.

## Symbols

TTD replay and DbgEng use local symbol directories. Rust-native symbol retrieval uses the local `.ttd-symbol-cache` directory and does not stage or load `symsrv.dll`.

The project keeps symbol/runtime setup repo-local and process-local. It does not write debugger registry keys or machine-wide symbol environment values. For TTD and DbgEng sessions, explicit paths take precedence over `_NT_SYMBOL_PATH`; `_NT_SYMBOL_PATH` is searched before `_NT_ALT_SYMBOL_PATH`; and explicit cache settings take precedence over `_NT_SYMCACHE_PATH`. If none sets a cache, TTD uses `.ttd-symbol-cache` and DbgEng uses `.windbg-symbol-cache`.

## Sample trace fixture

The repository keeps a reusable sample trace archive at `traces\ping.7z`. Extracted contents under `traces\ping\` are local-only and ignored by git.

After extraction, the fixture layout is:

```text
traces\ping\ping01.run
traces\ping\ping01.idx
traces\ping\ping.exe
```

If `7z` or `7zz` is not on `PATH`, set `TTD_TEST_7Z` to the extractor path.

## Local replay tests

Strict local replay checks:

```powershell
$env:TTD_RUNTIME_DIR = "D:\dev\windbg-tool\target\ttd-runtime"
$env:TTD_MCP_EXPECT_NATIVE_REPLAY = "1"
cargo test -p windbg-ttd --test ping_trace
cargo test -p windbg-tool --test daemon_cli
```

To force a custom trace instead of the committed archive fixture, set `TTD_TEST_TRACE` to a `.run` file path.

## Hygiene and safety

- Treat `.run`, `.idx`, `.ttd`, `.pdb`, `.dll`, and `.exe` artifacts as local-only unless explicitly requested otherwise
- Do not commit extracted traces or downloaded Microsoft runtime binaries
- Keep reusable trace fixtures compressed as `.7z`

## Related docs

- [README.md](../README.md)
- [architecture.md](architecture.md)
- [cli.md](cli.md)
- [mcp.md](mcp.md)
