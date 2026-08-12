# Architecture

`windbg-tool` is a Windows-first WinDbg automation workspace. Its single executable hosts the `windbg-ttd` MCP server/daemon/client commands, plus broader WinDbg helpers such as DbgEng process-server launch, one-shot live DbgEng launch, WinDbg package install/update/launch, local diagnostic recipes, remote debugging command generation, unified trace timelines, target capability discovery, PE/PDB/export symbol readiness diagnostics, source path resolution, explicit architecture-state discovery, x64 disassembly, read-only module/object/vtable inspection, stack recovery, memory classification/string/pointer views, and agent-ready context snapshots.

The TTD replay surface is split into three layers:

1. Rust MCP server over stdio using the official `rmcp` Rust MCP SDK. This owns MCP protocol transport, tool schemas, session ids, validation, symbol-path settings, and packaging workflow.
2. Safe Rust replay facade. This keeps TTD positions, sessions, cursors, memory reads, modules, threads, and exceptions in serializable Rust types.
3. Native C++ replay bridge. This is a narrow C ABI over Microsoft's C++ TTD Replay API from `Microsoft.TimeTravelDebugging.Apis`.

The C++ bridge exists because the public TTD API is C++-oriented. Rust should not bind directly to TTD C++ vtables, STL helpers, or lifetime rules. The bridge exposes opaque handles and simple POD values.

## Dependencies

Build-time SDK inputs come from NuGet:

- `Microsoft.TimeTravelDebugging.Apis` for headers and import libraries.
- `Microsoft.Debugging.Platform.SrcSrv` for source-server support alongside public symbols.
- `Microsoft.Debugging.Platform.DbgEng` for DbgEng process-server headers, import libraries, and redistributable runtime DLLs.

Runtime replay requires `TTDReplay.dll` and `TTDReplayCPU.dll`. Microsoft samples acquire these from the WinDbg/TTD MSIX distribution rather than a separate public NuGet package. Use:

```powershell
cargo xtask deps
```

or run [scripts/Get-TtdReplayRuntime.ps1](../scripts/Get-TtdReplayRuntime.ps1) directly.

The native replay bridge has a CMake project at [native/ttd-replay-bridge/CMakeLists.txt](../native/ttd-replay-bridge/CMakeLists.txt). `cargo xtask native-build` configures it against the restored `Microsoft.TimeTravelDebugging.Apis` package and emits the bridge under `target/native/ttd-replay-bridge`. Release packaging can pass `--arch amd64` or `--arch arm64` plus `--static-crt` so cross-compiled packages use the matching native bridge and statically link the MSVC runtime.

Live managed breakpoints use an in-process Rust CoreCLR DAC host, never the TTD bridge. It loads a version- and architecture-matched `mscordaccore.dll` and implements `ICLRDataTarget2` through typed Rust COM interfaces over DbgEng module, memory, thread, and context services. The CoreCLR COM declarations are the exact prefixes required from the MIT-licensed `clrdata.idl` and `xclrdata.idl` contracts. It uses the Windows metadata bindings to compare exact raw ECMA-335 `MethodDef` signature bytes when the caller selects an overload, while reporting bounded token/signature diagnostics for name matches. It resolves metadata through a method definition, then obtains the matching method instance after code-generation notification; only that instance supplies the JIT-native breakpoint address. Its opt-in `ICLRDataTarget2` implementation uses DbgEng's active process handle solely for the CLR-requested JIT-notification-table allocation; the CLR then owns that allocation. A separate read-only resolver never calls notification registration and can report an existing native method instance, but cannot observe a module or method first registered/JIT-compiled after the stopped native load event. It does not attach `ICorDebug`, load SOS, invoke debugger extension commands, hollow the process, or inject managed code. The target DAC remains runtime-provided and is not redistributed.

`live startup-profile` is intentionally outside that DAC path. It owns a short-lived DbgEng session, begins at a create-process event, applies only DbgEng lifecycle event filters, and accumulates host-monotonic wall time while the target is resumed between observed stops. It can complete at a requested image-load boundary or after a bounded interval without a further configured lifecycle stop; the latter is explicitly an observed lifecycle-quiet interval, not a UI-ready or target-quiescence signal. The profiler records bounded process/thread/module/exception event metadata, lifecycle first/last summaries, ranked fully observed inter-event gaps, optional read-only stop context, and opt-in validity-gated per-thread `IDebugAdvanced2` accounting. The fixture verified that DbgEng `KernelTime` and `UserTime` are 100 ns counters; their per-thread millisecond projections remain separate from lifecycle wall-time phases and do not create causal attribution. Its opt-in host-side output callback captures only bounded debuggee categories and restores the preceding callback/mask; opt-in module provenance reads bounded metadata only from DbgEng-observed absolute image paths. Bounded `IDebugSymbols5` module parameters and native symbol-entry regions are also available for observed bases/instruction addresses; symbol-path resolution is host-side I/O, not target behavior. None is target-memory evidence or a timing source. The profiler does not use DbgEng breakpoint APIs, target-memory APIs, CLR notifications, SOS, a DAC, or a second debugging engine. Its phase derivation accepts only explicit observed lifecycle boundaries and labels the result as wall-clock observation rather than CPU attribution or managed execution evidence. The daemon's `target memory-map` is a separate bounded, direct `IDebugDataSpaces4::QueryVirtual` wrapper for stopped live user-mode targets; it reports partial/unavailable coverage explicitly and does not substitute an OS process-memory API.

Direct `IDebugEventCallbacksWide` payload capture is intentionally not installed yet. The currently staged `windows` projection exposes callback methods as `Result<()>`, which normalizes positive DbgEng execution-status return values. A wrapper that forwarded an existing callback through that surface could therefore silently replace its requested continuation status with `DEBUG_STATUS_NO_CHANGE`. Because DbgEng has one event-callback slot per client, windbg-tool rejects that unsafe multiplexing design rather than replacing or partially forwarding a pre-existing callback. Existing lifecycle payloads remain the bounded `LastEventInformation` records; a future implementation must preserve callback return statuses at the COM ABI boundary and fixture-validate restoration alongside output capture before it can be enabled.

## Symbols

Symbol-server retrieval is Rust-native. `windbg-symbols` prefers a supplied or host-local PE image, then retrieves a missing exact PE image from the Microsoft Symbol Server HTTPS image store using its dump timestamp and `SizeOfImage` key. It bounds, atomically caches, and validates every image before parsing CodeView/RSDS and using the Rust `symsrv` crate to cache the exact PDB. DbgEng then receives only direct local PDB and image directories; it never receives an `srv*` path and has no `symsrv.dll` runtime dependency.

`cargo xtask deps` stages `dbghelp.dll` and `srcsrv.dll` from Microsoft Debugging Platform NuGet packages into `target/symbol-runtime`, and stages DbgEng process-server runtime DLLs into `target/dbgeng-runtime`. Architecture-explicit release staging uses `target/runtime/<arch>/...` to keep x64 and ARM64 DLLs separate. Before binding a staged DbgEng runtime, the tool validates every required companion PE image and rejects malformed or mixed-architecture sets; target status records the selected runtime provenance. Daemon-owned DbgEng clients execute only on a dedicated serialized worker thread. This allows typed step-over, deferred DbgEng symbol-expression code breakpoints, breakpoint enablement changes, and a one-operation `continue-and-wait` with opt-in bounded debuggee output capture. The capture restores the prior DbgEng callback and output mask before returning; it is not continuous output/event streaming. Step-out and callback streaming remain deferred because the projected DbgEng event callback cannot safely preserve callback return-status semantics. Keep this repo-local and process-local; do not set machine-wide `_NT_SYMBOL_PATH` or write debugger registry keys as part of normal server operation.

Callers can provide additional binary paths, symbol paths, and a symbol cache directory when loading a trace. Public symbols are useful for module/function names. Private symbols are needed for richer function signatures and local details.

The Rust facade resolves caller settings into a process-local symbol configuration before opening a trace. That resolved configuration includes the symbol path, image path, cache directory, and symbol runtime directory, and the native bridge open ABI accepts those fields directly.

## Current State

The MCP stdio server is **daemon-backed by default**: it ensures the named-pipe daemon and proxies `tools/list` + `tools/call` through `DaemonClient`, so MCP and CLI share the same sessions, targets, and jobs. Set `WINDBG_TOOL_MCP_IN_PROCESS=1` only for isolated tests.

Investigation logic lives under `crates/windbg-ttd/src/analysis/` and is executed by daemon tools. Both MCP and thin CLI wrappers call the same path for composites (`discover`, `ttd_open`, `debug_snapshot`, `triage_run`, …), TTD analysis (`ttd_disassemble`, stack/memory/timeline helpers, architecture/module/object tools), and PE/symbol diagnostics (`pe_inspect`, `pe_exports`, `ttd_symbols_nearest`, `symbols_diagnose`, `symbols_doctor`).

The native bridge remains the C ABI over Microsoft's TTD Replay API. Low-level primitives still cover load/info/index, modules/threads/exceptions/keyframes, cursor create/seek/step, registers, bounded memory reads/ranges/buffers/watchpoints, and PEB command-line extraction. Platform-host workflows (WinDbg install, process-server hosting, elevated recorders, managed breaks) stay CLI-first and are discoverable with `mcp: false` metadata rather than forced into MCP.

Next steps: deeper PDB line/source diagnostics, real unwind metadata, callback-backed bounded replay sweeps, and richer live output/event capture.
