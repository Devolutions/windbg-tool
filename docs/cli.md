# CLI guide

`windbg-tool.exe` can act as a local discovery tool, a daemon-backed TTD client, a DbgEng helper, and a WinDbg launcher/updater.

## How the CLI is organized

- **Discovery commands** do not require the daemon: `discover`, `cli-schema`, `recipes`, `tools`, `schema`, `trace-list`, `symbols inspect`
- **Replay commands** usually talk to the local daemon and operate on a `session_id` and `cursor_id`
- **Recording commands** use the separately installed Microsoft `TTD.exe` recorder and do not require the daemon
- **Canonical agent debugging commands** start with `debug`, `triage`, `symbols doctor`, and `breakpoint plan`
- **Platform helper commands** cover DbgEng, remote debugging doctors/plans, live-launch probing, and WinDbg installation

## Kernel dump triage

Use the daemon-free, read-only dump triage command to collect DbgEng bugcheck data,
fault disassembly, AMD64 exception-context registers, stack validity, symbol readiness,
driver-evidence provenance, and next diagnostic guidance:

```powershell
target\debug\windbg-tool.exe --compact dump triage C:\Windows\Minidump\example.dmp --max-frames 32
```

`dump inspect` returns the same triage fields for compatibility. The report distinguishes
missing dump content (for example, a partial exception context) from an invalid or truncated
unwind, and never treats a loaded driver or `ntoskrnl.exe` fault location as driver attribution.
Add `--refresh-symbols` only when the configured symbol path may be contacted; the report records
whether DbgEng loaded PDB-backed symbols or only has module-level metadata.

## Common replay workflow

Start or reuse the local daemon:

```powershell
target\debug\windbg-tool.exe daemon ensure
```

Open a trace and create a cursor in one step:

```powershell
target\debug\windbg-tool.exe open C:\path\to\trace.run --binary-path C:\path\to\binary.exe
```

Rediscover active sessions and cursors later:

```powershell
target\debug\windbg-tool.exe sessions
```

Use the returned handles with analysis commands:

```powershell
target\debug\windbg-tool.exe info --session 1
target\debug\windbg-tool.exe debug snapshot --session 1 --cursor 1
target\debug\windbg-tool.exe position set --session 1 --cursor 1 --position 50
target\debug\windbg-tool.exe exception focus --session 1 --cursor 1 --index 0
target\debug\windbg-tool.exe registers --session 1 --cursor 1
target\debug\windbg-tool.exe disasm --session 1 --cursor 1
target\debug\windbg-tool.exe memory strings --session 1 --cursor 1 --address 0x12345678 --size 256 --encoding both
```

`open` is the preferred starting point because it loads the trace, creates a cursor, and optionally seeks to a position in one response. `debug snapshot` is the canonical cross-backend snapshot for agents; `context snapshot` remains available as the legacy TTD-focused snapshot.

## Record a trace

`trace record` launches a target with the Microsoft `TTD.exe` command-line recorder, waits for it to exit, and emits the resulting `.run` path. It uses TTD's documented `-noUI -out <path> -launch <target command line>` invocation; the target command line is passed directly, not through a shell. Because TTD recording requires elevation, it runs TTD directly from an elevated terminal or automatically invokes Windows 11 `sudo` when it is configured for the synchronous **Input Closed** or **Inline** mode. Force New Window mode is rejected because it returns before the recorder completes.

Install the standalone TTD recorder with `winget install --id Microsoft.TimeTravelDebugging`, then open a new elevated terminal so `ttd.exe` is on `PATH`. You can also set `TTD_EXE` or pass `--ttd-exe`. `trace record` always passes TTD's `-accepteula` option.

```powershell
target\debug\windbg-tool.exe --compact trace record `
  --output C:\traces\rdm.run `
  --command-line '"C:\apps\RemoteDesktopManager.exe" /AutoCloseAfter:10'
```

The output directory must already exist and the `.run` path must not already exist. TTD traces include process-memory data and should be handled as sensitive artifacts.

For high-overhead startup captures, first choose a bounded capture strategy:

```powershell
# Preserve the earliest startup data, up to 1 GiB.
target\debug\windbg-tool.exe trace record --profile startup `
  --output C:\traces\rdm-startup.run `
  --command-line '"C:\apps\RemoteDesktopManager.exe" /AutoCloseAfter:10'

# Retain only the newest data in a 2 GiB rolling window.
target\debug\windbg-tool.exe trace record --profile recent `
  --output C:\traces\rdm-recent.run `
  --command-line '"C:\apps\RemoteDesktopManager.exe" /AutoCloseAfter:10'
```

`--max-file-mb <size>` provides a custom cap; add `--ring` to retain the newest data after the cap is reached. `--profile` is a convenience preset and cannot be combined with either custom size option.

Use repeatable `--module <basename>` to ask TTD to record only selected native modules, for example `--module RemoteDesktopManager_x64.exe --module coreclr.dll`. The values must be basenames, not paths. Module filtering is an experiment: managed code often executes as JIT-generated code associated with `coreclr.dll`, so filtering only the application executable can omit needed behavior.

`--replay-cpu-support <default|most-aggressive|...>` forwards TTD's replay CPU compatibility setting. `--num-vcpu <count>` can reduce recorder memory pressure, but TTD warns that lowering it can severely slow recording; do not use it as a performance optimization.

If TTD reports that the target has CET shadow stacks enabled, use `--disable-user-shadow-stack` to launch only that new target process with the official Windows process-creation mitigation set to **always off**, then have TTD attach by PID. This is an explicit, per-process compatibility override; it does not change system policy or the target binary. Attaching begins after process creation, so it can miss the earliest startup instructions.

When using that CET-compatible attach mode, `--record-for-seconds <seconds>` asks TTD to stop recording after the requested window without terminating the target. This bounds a hung or slowed startup capture but necessarily retains the attach-mode earliest-startup limitation. After a successful recording, the result includes trace size, elapsed time, output rate, and parsed `.out` sidecar data such as allocated vCPUs, active threads, simulation duration, and finalization state.

To enable synchronous sudo recording, choose **Input Closed** or **Inline** in **Settings > System > Advanced > Enable sudo**, or from an elevated terminal run:

```powershell
sudo config --enable disableInput
```

## Live startup breakpoints

`live startup-break` is a one-shot native DbgEng workflow: by default it launches at the initial debug break, configures one software code breakpoint, continues the target once, waits for a bounded event, captures JSON context, and then ends the debug session. It does not shell out to CDB or WinDbg.

For a development build with DbgEng staged outside the executable directory, set `WINDBG_DBGENG_RUNTIME_DIR` to the matching `dbgeng-runtime` directory. Packaged builds load the matching DbgEng runtime copied beside `windbg-tool.exe`; both paths use a process-local, dependency-safe loader.

Use a module basename and RVA when the executable is present at the initial break:

```powershell
target\debug\windbg-tool.exe --compact live startup-break `
  --command-line '"C:\Temp\windbg-tool-ttd\rdm\RemoteDesktopManager_x64.exe" /AutoCloseAfter:10' `
  --module RemoteDesktopManager_x64.exe `
  --module-offset 0x1000 `
  --wait-timeout-ms 10000 `
  --end terminate
```

Alternatively specify an absolute `--address`, or a deferred DbgEng `--symbol 'module!symbol'` expression. Deferred symbol breakpoints allow module and symbol loading after process creation. The response includes the initial event, configured breakpoint, an explicit `breakpoint.hit` evidence flag, PID/thread/IP, current module and symbol, core registers, and a bounded stack. A stopped event that does not match the configured breakpoint remains reported as `hit: false`; it is not misrepresented as a breakpoint hit.

Use `--initial-break` when no reliable code breakpoint is available or the host policy rejects breakpoint creation. It captures the initial DbgEng process break without continuing the target and labels that evidence explicitly; it does not claim a code-breakpoint hit.

`--end terminate` is the default for disposable startup probes. Use `--end detach` only when the debuggee should continue after the captured event.

### Non-invasive processor execute breakpoint

`--hardware-execute` switches `live startup-break` to a DbgEng processor breakpoint. It starts from a create-process event (not a software initial break), waits for the requested native module-load event, then creates `DEBUG_BREAKPOINT_DATA` with `DEBUG_BREAK_EXECUTE` and byte size `1`. It does not open the DAC, request CLR notifications, or place a software breakpoint byte in target memory.

The .NET 10.0.9 x64 fixture verified this path against CoreCLR's `coreclr_execute_assembly` export (RVA `0x2F690` for that runtime):

```powershell
$fixture = Resolve-Path crates\windbg-tool\tests\fixtures\ManagedBreakpointFixture
target\debug\windbg-tool.exe --compact live startup-break `
  --command-line "`"$fixture\bin\Release\net10.0\win-x64\ManagedBreakpointFixture.exe`"" `
  --wait-for-module coreclr.dll `
  --module coreclr.dll --module-offset 0x2F690 `
  --hardware-execute --initial-break-timeout-ms 30000 --wait-timeout-ms 30000 `
  --end terminate
```

Use `symbols exports <coreclr.dll> --filter coreclr_execute_assembly` to obtain the RVA for a different CoreCLR version. The validated response had `breakpoint_mode: "hardware_execute"`, `configured.break_type: 1`, `configured.data_access_type: 4`, `configured.data_size: 1`, `configured.match_thread: null`, `configured.id: 0`, and `hit: true`. DbgEng then reported breakpoint ID `0` at `coreclr!coreclr_execute_assembly` with the current instruction pointer equal to the configured address. This is a verified **native** processor-breakpoint hit, not a managed-method hit.

Processor breakpoints are a constrained CPU resource. [Microsoft's processor-breakpoint documentation](https://learn.microsoft.com/windows-hardware/drivers/debugger/processor-breakpoints---ba-breakpoints-) distinguishes them from software breakpoints and permits execute access on code. On x64, DR0 through DR3 provide only four address-register slots per thread context; existing debugger or target users can reduce usable capacity. DbgEng supports an engine-thread filter through [`IDebugBreakpoint2::SetMatchThreadId`](https://learn.microsoft.com/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugbreakpoint2-setmatchthreadid), but this one-shot command deliberately leaves it unset (`match_thread: null`), so any target thread may trigger the breakpoint. A thread filter would not create additional hardware-register capacity.

## Managed CoreCLR DAC breakpoints

`live managed-break` does not load SOS or execute `!bpmd`. It starts with a DbgEng create-process event, stops on CoreCLR and the requested managed module load, dynamically loads the exact x64 `mscordaccore.dll` that is a sibling of the target's loaded `coreclr.dll`, resolves the selected `MethodDef` through the DAC, requests CLR code-generation notification, then creates a DbgEng **code** breakpoint at the DAC-mapped native entry. `managed_breakpoint.hit` is true only when both the DbgEng breakpoint ID and current instruction pointer match that DAC-mapped address.

The DAC host and `ICLRDataTarget2` callback are implemented in-process in Rust. No separate bridge DLL is built, staged, or configured. The target DAC is never bundled: it must exactly match the target CoreCLR architecture and file version.

CLR's notification mechanism writes debugger-notification state into the target. The DAC first requests a small JIT-notification table through `ICLRDataTarget2::AllocVirtual`; the bridge obtains the active target process handle from DbgEng and calls `VirtualAllocEx` only for that CLR-owned allocation. DbgEng then applies its normal code-breakpoint byte at the resolved entry. Therefore `--allow-runtime-write` is explicit and should be used only in an approved test VM. Without it the command fails clearly before any target allocation or write; it does not disable endpoint protection, hollow the process, or silently fall back to SOS.

The bridge resolves metadata through `IXCLRDataMethodDefinition`, then uses the matching `IXCLRDataMethodInstance` after CLR code-generation notification. A definition's representative address is IL, not executable code; the code breakpoint always uses the instance's JIT-native entry address.

### Read-only managed hardware mode

`live managed-break --hardware-execute` is a separate, deliberately restricted path. It is mutually exclusive with `--allow-runtime-write` and performs only a read-only DAC query plus a DbgEng processor execute breakpoint when a native method instance is already available. It does not request module/code notifications, allocate CLR notification state, use `WriteVirtual` or `VirtualAllocEx`, create a software code breakpoint, use SOS, inject code, or force JIT compilation.

The command starts from create-process and native module-load events. It resolves exact private/overload metadata only if CoreCLR has already registered the requested module with the DAC at the native image-load stop. If the selected method already has a native instance, it uses a one-byte `DEBUG_BREAK_EXECUTE` breakpoint at that exact DAC-native address and reports a hit only when DbgEng's breakpoint ID and current instruction pointer both match.

The safe .NET 10.0.9 x64 fixture established that the native `ManagedBreakpointFixture.dll` load event occurs before the module is visible to the read-only DAC. This invocation therefore correctly returned `managed_breakpoint.binding_state: "module_not_observable_without_runtime_write"` and `hit: false`:

```powershell
$fixture = Resolve-Path crates\windbg-tool\tests\fixtures\ManagedBreakpointFixture
target\debug\windbg-tool.exe --compact live managed-break `
  --command-line "`"$fixture\bin\Release\net10.0\win-x64\ManagedBreakpointFixture.exe`"" `
  --managed-module ManagedBreakpointFixture.dll `
  --method ManagedBreakpointFixture.ManagedTargets.PrivateEntry `
  --hardware-execute --initial-break-timeout-ms 30000 --wait-timeout-ms 30000 `
  --end terminate
```

This is an intentional non-hit, not a fallback failure: the tool leaves the process at the module-load stop, then ends the session according to `--end`, rather than continuing to wait for JIT or mutating CLR state. Consequently, the current non-invasive mode cannot prove a private managed-method hit. A later JIT event, tiered recompilation, ReadyToRun indirection, re-JIT, generic instantiation, or unload can create or replace the native entry, and the read-only path has no supported event that tracks those transitions. The verified native `coreclr!coreclr_execute_assembly` hit above does not establish managed-method semantics.

```powershell
target\debug\windbg-tool.exe --compact live managed-break `
  --command-line '"C:\apps\RemoteDesktopManager_x64.exe" /AutoCloseAfter:10' `
  --managed-module RemoteDesktopManager.dll `
  --method Devolutions.RemoteDesktopManager.Program.Main `
  --allow-runtime-write `
  --end terminate
```

The vertical slice resolves regular private methods as normal metadata. An unambiguous fully-qualified metadata name needs no additional selector. For overloads, pass `--signature` with the exact ECMA-335 `MethodDef` signature blob as hexadecimal byte pairs; whitespace, `-`, `_`, and `:` are accepted only as separators. This is not C# syntax. For example, a static `string Overload(string)` method has the blob `00010E0E` (`DEFAULT`, one parameter, `STRING` return, `STRING` parameter), while `string Overload()` is `00000E`. The response reports the selected `signature_hex`, every bounded name-matching candidate's token/signature, and whether candidate output was truncated. C# signatures, generic instantiations, ReadyToRun indirection, tiered recompilation, re-JIT, and unload transitions remain explicit limits.

### Managed breakpoint fixture

`crates\windbg-tool\tests\fixtures\ManagedBreakpointFixture` is a source-only .NET 10 x64 fixture with deterministic no-inline public, private, and overload targets. Its generated `bin` and `obj` directories are ignored. Build it, then run one command per target in an approved test VM:

```powershell
$fixture = Resolve-Path crates\windbg-tool\tests\fixtures\ManagedBreakpointFixture
dotnet build "$fixture\ManagedBreakpointFixture.csproj" -c Release

target\debug\windbg-tool.exe --compact live managed-break `
  --command-line "`"$fixture\bin\Release\net10.0\win-x64\ManagedBreakpointFixture.exe`"" `
  --managed-module ManagedBreakpointFixture.dll `
  --method ManagedBreakpointFixture.ManagedTargets.PublicEntry `
  --allow-runtime-write --end terminate

target\debug\windbg-tool.exe --compact live managed-break `
  --command-line "`"$fixture\bin\Release\net10.0\win-x64\ManagedBreakpointFixture.exe`"" `
  --managed-module ManagedBreakpointFixture.dll `
  --method ManagedBreakpointFixture.ManagedTargets.PrivateEntry `
  --allow-runtime-write --end terminate

target\debug\windbg-tool.exe --compact live managed-break `
  --command-line "`"$fixture\bin\Release\net10.0\win-x64\ManagedBreakpointFixture.exe`"" `
  --managed-module ManagedBreakpointFixture.dll `
  --method ManagedBreakpointFixture.ManagedTargets.Overload `
  --signature 00010E0E `
  --allow-runtime-write --end terminate
```

The last command selects `Overload(string)` rather than `Overload()`. A valid result has `managed_breakpoint.hit: true`, a DbgEng breakpoint ID/current instruction pointer equal to `code_generation.representative_native_entry_address`, and `managed_resolution.method_after_code_generation.token`/`signature_hex` identifying the selected `MethodDef`.

The .NET 10.0.9 x64 fixture was validated with the direct DAC bridge:

| Target | Token | Signature | Hit evidence |
| --- | --- | --- | --- |
| `ManagedTargets.PublicEntry()` | `100663298` | `00000E` | `hit: true`; breakpoint ID `0` and IP matched its native entry |
| private `ManagedTargets.PrivateEntry()` | `100663300` | `00000E` | `hit: true`; breakpoint ID `0` and IP matched its native entry |
| `ManagedTargets.Overload(string)` | `100663302` | `00010E0E` | `hit: true`; breakpoint ID `0`, IP matched native entry, and the selected candidates were `0x06000005:00000E` and `0x06000006:00010E0E` |

## Non-invasive live startup profiling

`live startup-profile` is a one-shot DbgEng lifecycle collector for agent-oriented startup evidence. It launches at a DbgEng `create_process` event, enables only create/exit-process, create/exit-thread, load/unload-module event filters, then resumes the target and records bounded stopped events. It does **not** configure a software or hardware breakpoint, open the DAC, request CLR notifications, allocate or write target memory, inject code, or use a profiler.

The default exception policy does not request first-chance exceptions because managed startup can produce enough expected exceptions to consume the bounded timeline. Use `--include-first-chance-exceptions` only when that additional event volume is justified.

`--capture-debuggee-output` is an opt-in, host-side DbgEng `IDebugOutputCallbacksWide` capture for only the debuggee and debuggee-prompt categories. It is disabled by default because debug strings can contain sensitive content. `--max-output-records`, `--max-output-chars`, and `--max-total-output-chars` independently bound retained records and text; `debuggee_output` reports truncation/drop counts and restores the prior callback and output mask before the run ends. A record's `preceding_event_index` is the latest retained lifecycle event when DbgEng invoked the callback, not a causal association.

The command reports two host-monotonic measures:

- `command_to_create_observed_ms` is the wall time from before DbgEng session creation until windbg-tool observes the create-process event.
- Timeline `resumed_wall_elapsed_ms` and derived `phase_durations` accumulate only while the target is resumed between observed DbgEng stops. This excludes the collector's intentionally stopped filter/configuration/context work, but includes DbgEng scheduling and event-delivery latency.

Neither measure is target CPU time. A module-load timestamp does not identify managed registration, JIT work, or method execution. Repeated runs report min/median/max wall time only for phases whose two event boundaries were observed in runs that reached the requested completion condition; no baseline means the output deliberately does not call a value a regression.

Build and profile the source-only fixture without any DAC or breakpoint workflow:

```powershell
$fixture = Resolve-Path crates\windbg-tool\tests\fixtures\ManagedBreakpointFixture
dotnet build "$fixture\ManagedBreakpointFixture.csproj" -c Release
$report = Join-Path $env:TEMP "windbg-tool-fixture-startup-profile.json"

target\debug\windbg-tool.exe --compact live startup-profile `
  --command-line "`"$fixture\bin\Release\net10.0\win-x64\ManagedBreakpointFixture.exe`" --startup-observation-delay-ms 2000" `
  --phase-module ManagedBreakpointFixture.dll `
  --completion-module ManagedBreakpointFixture.dll `
  --settle-ms 250 `
  --initial-break-timeout-ms 30000 `
  --timeout-ms 30000 `
  --max-events 256 `
  --output $report
```

`--completion-module <basename>` ends an observation at the matching DbgEng image-load event. It is an image-load boundary only: it is not UI-ready, managed registration, JIT completion, or application initialization. Add `--settle-ms 1..60000` to require a target-resumed interval without a further configured lifecycle stop after that load. Any observed lifecycle stop restarts the interval. A `quiet_interval_observed` result establishes only that bounded DbgEng condition; it does not prove target quiescence, CPU idleness, I/O completion, or UI readiness. If process exit, timeout, or the event limit occurs first, the result stays incomplete and never infers quietness.

`--max-events` bounds retained timeline payload rather than forcing a healthy target to terminate. For a full-lifetime profile without `--completion-module`, windbg-tool retains `max_events - 1` entries, disables high-volume thread/module filters, and waits only for `exit_process`, preserving the final exit boundary in the last slot. The result marks this as `coverage.timeline_truncated: true` and lists the DbgEng `timing.tail_filter_commands`; it makes no claim about events omitted during that exit-only tail. A completion-bound profile instead stops as incomplete at its retention limit, because disabling the lifecycle filters would make a quiet interval unknowable. A single completion-bound run defaults to `--end detach`, so the target can finish normally. Repeated runs require the explicit `--end terminate` cleanup mode to prevent overlapping detached targets. A full-lifetime successful run has `finish_reason: "exit_process"`; a module completion has `finish_reason: "completion_module"`; a quiet completion has `finish_reason: "completion_module_quiet_interval"`.

The opt-in `--capture-stop-context` captures bounded read-only register/module/symbol/stack context on selected early stops; it can increase observer overhead and is disabled by default. `--context-on` selects event kinds, defaulting to `load-module`, `create-thread`, `exception`, and `exit-process`; every timeline event has an explicit context status (`not_requested`, `not_selected`, `limit_reached`, `captured`, or `unavailable`). `--capture-native-symbol-entry-range` optionally adds one bounded `IDebugSymbols5` symbol-entry offset-region lookup to each captured context's existing instruction address. The result is native symbol coverage at that address, not a managed method boundary or execution proof. Both that lookup and `--capture-dbgeng-module-parameters` can cause host-side symbol-resolution I/O through the configured symbol path; neither writes target memory.

`--capture-thread-accounting` captures bounded `IDebugAdvanced2::GetSystemObjectInformation` snapshots at selected lifecycle stops. `--thread-accounting-on` defaults to `create-process`, `load-module`, `create-thread`, and `exit-process`; `--max-thread-accounting-snapshots` and `--max-thread-accounting-threads` cap work and JSON. Every returned thread preserves the source validity mask and raw `KernelTime`/`UserTime` values. The fixture's bounded `--cpu-burn-ms` run established that these two counters use 100 ns units, so the output also has millisecond projections and same-engine/system-thread deltas when both snapshots are valid and nondecreasing. Those are per-thread accounting samples only: they do not turn a lifecycle wall-time gap into CPU attribution, identify a managed method, or prove that an OS thread identity was never reused.

`--capture-module-provenance` separately reads bounded host-file metadata only for absolute module image paths DbgEng already observed. Its records include canonical host path, file size/last-write time, PE architecture/image timestamp, CodeView identity, and available Win32 file/product versions. This is host-file metadata, not target-memory evidence or lifecycle timing; it never hashes, verifies signatures, or reads an unobserved path.

The important JSON fields are:

```json
{
  "workflow": "live_startup_profile",
  "target_memory_writes": {
    "requested": false,
    "software_breakpoints": false,
    "hardware_breakpoints": false,
    "dac_bridge": false
  },
  "runs": [{
    "finish_reason": "completion_module_quiet_interval",
    "completion": {
      "status": "quiet_interval_observed",
      "requested_module": "ManagedBreakpointFixture.dll",
      "settle_ms": 250
    },
    "timeline": [{
      "kind": "load_module",
      "observed_elapsed_ms": 41,
      "resumed_wall_elapsed_ms": 10,
      "module": { "basename": "coreclr.dll" }
    }],
    "phase_durations": [{
      "name": "create_process_to_coreclr_load",
      "status": "observed",
      "elapsed_ms": 10
    }],
    "debuggee_output": {
      "status": "captured",
      "records_returned": 1,
      "dropped_record_count": 0
    },
    "module_provenance": {
      "status": "captured",
      "source": "host_file_metadata"
    },
    "dbgeng_module_parameters": {
      "status": "captured",
      "source": "dbgeng_idebugsymbols5_getmoduleparameters"
    },
    "largest_observed_gaps": [{
      "elapsed_ms": 10,
      "detail": "Target-resumed host wall time between adjacent observed lifecycle stops; not CPU time."
    }]
  }],
  "aggregate": {
    "phase_wall_time_ms": [{
      "name": "create_process_to_coreclr_load",
      "sample_count": 3,
      "min_ms": 8,
      "median_ms": 10,
      "max_ms": 13,
      "regression_assessment": { "status": "no_baseline" }
    }]
  }
}
```

Compare independent artifacts with no debugger launch or target interaction:

```powershell
target\debug\windbg-tool.exe --compact live startup-compare `
  --baseline $baselineReport `
  --candidate $candidateReport `
  --max-sequence-events 64
```

The comparator accepts only `live_startup_profile` JSON artifacts up to 16 MiB. It compares observed phase and one-largest-gap wall-time distributions plus bounded lifecycle event/module/exception sequence prefixes. It reports profile and comparison truncation, omits unstable thread IDs, and never labels a difference as a CPU regression or causal explanation.

### Offline startup module timeline

`live startup-report <artifact>` reads one existing `live_startup_profile` JSON artifact and renders its first-observed module loads as a deterministic terminal table. It is strictly offline: it reads only the explicitly supplied regular JSON artifact (up to 16 MiB), does not read the observed module paths, and never launches, attaches, queries, or modifies a target or DbgEng session. The profile artifact remains the source of truth.

```powershell
$artifact = Join-Path $env:TEMP 'windbg-tool-rdm-thread-accounting.json'
target\debug\windbg-tool.exe live startup-report $artifact --run 1
```

Each row represents the first retained DbgEng `load_module` event for one module identity in the selected launch. `OBS/RES ms` contains the launch-relative host-observed and target-resumed host-wall timestamps. `+FIRST ms` is the target-resumed host wall-time delta from the prior first-observed module load before report filters are applied. Neither is CPU, file-I/O, JIT, managed-method, or UI-ready duration.

Use bounded local filters without reopening the artifact in a debugger:

```powershell
# A first-party RDM application-directory view after the runtime has started.
target\debug\windbg-tool.exe live startup-report $artifact `
  --rdm-only --min-resumed-ms 500 --max-rows 32

# Runtime-loader images, retaining the normal terminal summary.
target\debug\windbg-tool.exe live startup-report $artifact --runtime-only

# Full structured rows, including unclipped normalized paths and any captured enrichment.
$report = Join-Path $env:TEMP 'windbg-tool-rdm-module-report.json'
target\debug\windbg-tool.exe --compact live startup-report $artifact `
  --format json --output $report --max-rows 128
```

`--module <substring>` matches a module basename, normalized observed image path, or DbgEng module name case-insensitively. `--runtime-only` selects the transparent runtime/loader name set (`coreclr.dll`, `hostfxr.dll`, `hostpolicy.dll`, `clrjit.dll`, `mscoree.dll`); `--rdm-only` selects normalized observed image paths containing `/RemoteDesktopManager/`. They are labels over observed module identities, not ownership, managed-assembly, CPU, or execution claims. `--run` defaults to run 1 so timestamps from repeated launches are never combined; `--max-rows` defaults to 64 and reports truncation explicitly.

The JSON form includes the table rows, full paths, source artifact/run coverage, completion and process-exit status, copied first-CoreCLR/selected-module milestones, and the artifact's existing ranked gaps. A row includes image size and symbol readiness only when the source profile captured bounded DbgEng module parameters, and host-file provenance only when that source profile captured it. There is no separate MCP tool because this is a local, explicit-file CLI report; agents can use `--format json` or `--output` for the same stable structured data without a target session.

For a daemon-owned stopped target, `target thread-accounting --target <id> --max-threads 32` and MCP `target_thread_accounting` return the same bounded read-only per-thread accounting. `target module-parameters --target <id> --module-base <address>` / MCP `target_module_parameters` accept only 1 through 128 distinct supplied module bases. `target symbol-entry-range --target <id> --address <address>` / MCP `target_symbol_entry_range` return a bounded DbgEng symbol-entry region record for one existing native address. The module and symbol queries are not target writes, but their configured symbol path can produce host-side symbol-resolution I/O.

For a future RDM observation, use the bounded no-breakpoint form only after the fixture command has completed with the expected no-write report:

```powershell
$rdm = 'D:\dev\.copilot\copilot-worktrees\RDM\bookish-winner\Windows\RemoteDesktopManager\Program\bin\Release\net10.0-windows10.0.19041\RemoteDesktopManager_x64.exe'
target\debug\windbg-tool.exe --compact live startup-profile `
  --command-line "`"$rdm`" /AutoCloseAfter:30" `
  --phase-module RemoteDesktopManager.dll `
  --completion-module RemoteDesktopManager.dll `
  --settle-ms 500 `
  --initial-break-timeout-ms 30000 `
  --timeout-ms 30000 `
  --max-events 512 `
  --output (Join-Path $env:TEMP "windbg-tool-rdm-startup-quiet.json")
```

The default detach is intentional for this one completion-bound RDM observation. For a bounded repeated image-load distribution after that initial result, omit `--settle-ms` and use explicit cleanup:

```powershell
target\debug\windbg-tool.exe --compact live startup-profile `
  --command-line "`"$rdm`" /AutoCloseAfter:30" `
  --runs 3 `
  --phase-module RemoteDesktopManager.dll `
  --completion-module RemoteDesktopManager.dll `
  --initial-break-timeout-ms 30000 `
  --timeout-ms 30000 `
  --max-events 128 `
  --end terminate `
  --output (Join-Path $env:TEMP "windbg-tool-rdm-startup-module-runs-3.json")
```

`--end terminate` is explicit cleanup for that repeated command, not a startup boundary or a measurement result. Do not add `live startup-break`, `live managed-break`, DAC options, or an endpoint-security workaround to either RDM command. If the initial safe-mode RDM run is blocked or fails, retain its DbgEng error/event evidence and stop rather than retrying or changing protection policy.

### Observed local RDM lifecycle evidence

The local Release x64 RDM build completed an event-only completion-bound profile with `target_memory_writes.requested: false`, zero structured DbgEng exception stops, and no synthetic `unknown` events. The first single run saw `coreclr.dll` at resumed-wall 438 ms, `RemoteDesktopManager.dll` at 517 ms, later lifecycle events through 534 ms, then an observed 508 ms lifecycle-quiet interval. It detached rather than observing process exit; this is not a UI-ready signal.

The bounded three-run module-boundary collection used explicit `--end terminate` cleanup after each `completion_module` result. It did not observe process exit, so post-module lifetime is intentionally unavailable:

| Observable host-wall phase | Min ms | Median ms | Max ms |
| --- | ---: | ---: | ---: |
| command start to create-process observation | 5 | 5 | 178 |
| create-process to `coreclr.dll` load | 423 | 426 | 427 |
| `coreclr.dll` load to `RemoteDesktopManager.dll` load | 32 | 33 | 34 |
| `hostpolicy.dll` load to `coreclr.dll` load (largest adjacent observed gap) | 189 | 191 | 192 |

The RDM image-load boundary occurred at event index 34 in every repeated sample. A separate 500 ms quiet-bound run reached its 256-event limit after post-module UI/graphics-related loader activity, correctly reporting incomplete rather than claiming startup completion. These are observer wall-clock lifecycle intervals, not CPU samples or proof that a specific RDM phase consumed CPU. The largest gap is a follow-up wall-time investigation candidate only.

### Verified RDM x64 test-VM run

The approved .NET 10.0.9 x64 test VM used this direct, no-SOS invocation:

```powershell
$root = 'C:\Users\Public\windbg-tool-rdm-dac-24dd653'
$env:WINDBG_DBGENG_RUNTIME_DIR = "$root\tool"

& "$root\tool\windbg-tool.exe" --compact live managed-break `
  --command-line "`"$root\rdm\RemoteDesktopManager_x64.exe`" /AutoCloseAfter:60" `
  --managed-module RemoteDesktopManager.dll `
  --method Devolutions.RemoteDesktopManager.Program.Main `
  --allow-runtime-write --initial-break-timeout-ms 30000 --wait-timeout-ms 120000 --end terminate
```

That run reported `workflow: "live_managed_break_dac"`, a matching CoreCLR/DAC file version, `managed_resolution.method_after_code_generation.token: 100663305`, `representative_entry_address: 0x7FFC8ABDA8A0`, and `managed_breakpoint: { kind: "software_code", configured.id: 0, hit: true }`. The final context had `instruction_pointer: 0x7FFC8ABDA8A0` and `current_symbol: RemoteDesktopManager!Devolutions.RemoteDesktopManager.Program.Main(System.String[])`.

The same command with `--method Devolutions.RemoteDesktopManager.Program.ApplyDpiAwarness` proved a private method without reflection or SOS: token `100663306`, native entry and final instruction pointer `0x7FFC8AC09920`, breakpoint ID `0`, and final symbol `RemoteDesktopManager!Devolutions.RemoteDesktopManager.Program.ApplyDpiAwarness()`.

### RDM approval requirement

The prior RDM evidence above was collected in an approved test VM. RDM remains blocked for breakpoint and DAC workflows: do not launch, resume, or attach it under software or hardware breakpoints, CLR notifications, or target-memory writes, and do not seek an exclusion or workaround. The separate `live startup-profile` flow above is limited to lifecycle-event filters and has no target-memory operation; it may be attempted once under the current profiling policy after fixture validation. If that safe mode is blocked, stop rather than retrying. Any future breakpoint/DAC RDM proof requires a new explicit direction plus written approval from the application owner and endpoint-security owner for the designated test VM and RDM build. That approval must state the allowed debugger operations; it does not authorize disabling, weakening, bypassing, or otherwise altering Sophos, HitmanPro.Alert, or RDM protections.

## Daemon-owned live controls

After `live start` or `live attach` returns a target id, use typed DbgEng controls
through the daemon rather than shelling out to CDB:

```powershell
# Create a deferred code breakpoint; module symbols may load later.
target\debug\windbg-tool.exe breakpoint set --target 1 --symbol 'app!EntryPoint'
target\debug\windbg-tool.exe breakpoint disable --target 1 --breakpoint-id 0
target\debug\windbg-tool.exe breakpoint enable --target 1 --breakpoint-id 0

# Step over one instruction, or resume until one bounded stop.
target\debug\windbg-tool.exe target step-over --target 1
target\debug\windbg-tool.exe target continue-wait --target 1 --timeout-ms 5000 `
  --capture-debuggee-output --max-output-records 32 --max-output-chars 512
```

`continue-wait` returns the DbgEng execution status and, when the target stopped,
best-effort stop-event metadata. Its debuggee output capture is opt-in and bounded
by record count and character limits; the preceding DbgEng callback and output mask
are restored before the command returns. It is not a continuous event or output
stream. Step-out remains intentionally unavailable because the typed DbgEng API has
no equivalent execution status.

## AI-oriented DbgEng target inspection

Daemon-owned live and dump targets expose bounded, read-only inspection commands for agent workflows. After `target wait` reports a stop on a live target, use `target event` to identify the DbgEng event that caused it. The response includes the process/thread IDs, event type, and, where DbgEng provides it, a breakpoint ID, exception code/address/first-chance state, module base, or exit code. It does not return unbounded debugger output. Event inspection is unavailable for dump targets because a dump has no live event stream.

```powershell
target\debug\windbg-tool.exe --compact target event --target 1
```

`target threads` returns DbgEng engine thread IDs. Use one of those IDs with `target thread` to capture that thread's core registers, nearest module/symbol, bounded stack, and bounded disassembly. The command restores the previously selected DbgEng thread before returning, so it is safe for agents to inspect worker threads without changing subsequent target commands.

```powershell
target\debug\windbg-tool.exe --compact target threads --target 1
target\debug\windbg-tool.exe --compact target thread --target 1 `
  --engine-thread-id 3 --max-frames 16 --disassembly-count 8
```

`debug snapshot --target <id>` now includes a best-effort `event` section by default for live targets. Use `--exclude event` when an event query is not relevant, or `--include event` to request it alone.

`target memory-map --target <id> --region-limit <1..4096>` and MCP `target_memory_map` query the stopped live user-mode target through `IDebugDataSpaces4::QueryVirtual`; both enforce the same `1..4096` region bound. They do not parse extension output or call `VirtualQueryEx`. The result uses numeric `MEMORY_BASIC_INFORMATION64` fields with `source: "dbgeng_idata_spaces4_query_virtual"`. `status: "bounded"` and `truncated: true` mean the region cap was reached, while `unavailable` or `partial_query_error` explicitly mean that full address-space coverage is not claimed. It is unavailable for dump targets.

## Canonical agent debugging commands

Use `debug capabilities` before choosing actions. With no subject it returns a backend matrix for TTD cursors, daemon-owned live/dump targets, and remote process-server plans. With `--session/--cursor` or `--target`, it includes selected-subject status/evidence where available.

```powershell
target\debug\windbg-tool.exe --compact debug capabilities
target\debug\windbg-tool.exe --compact debug capabilities --session 1 --cursor 1
target\debug\windbg-tool.exe --compact debug capabilities --target 1
```

Use `debug snapshot` for bounded, sectioned context capture. Each section has independent status, duration, truncation, diagnostics, and the primitive follow-up command. TTD subjects use `--session` and `--cursor`; live or dump subjects use `--target`.

```powershell
target\debug\windbg-tool.exe --compact debug snapshot --session 1 --cursor 1 --include stack --include current_disassembly
target\debug\windbg-tool.exe --compact debug snapshot --target 1 --max-frames 16 --max-modules 32
```

Use `triage <kind>` for evidence plus hypotheses rather than a verdict-only answer:

```powershell
target\debug\windbg-tool.exe --compact triage crash --session 1 --cursor 1
target\debug\windbg-tool.exe --compact triage hang --target 1
```

Use `symbols doctor` and `breakpoint plan` when an agent needs to validate names/source paths or dry-run a mutation:

```powershell
target\debug\windbg-tool.exe --compact symbols doctor --session 1 --cursor 1 --address 0x7ff600001000
target\debug\windbg-tool.exe --compact breakpoint plan --target 1 --address 0x7ff600001000
target\debug\windbg-tool.exe --compact breakpoint plan --session 1 --cursor 1 --address 0x12345678 --kind write --size 8 --direction previous
```

## Remote debugging doctors and plans

`remote doctor`, `remote status`, and `remote plan` are read-only helpers for DbgEng process-server style workflows. TCP connect probing is opt-in because it can be visible to network monitoring.

```powershell
target\debug\windbg-tool.exe --compact remote doctor --transport tcp:port=5005
target\debug\windbg-tool.exe --compact remote status --server target-host --transport tcp:port=5005 --probe-connect --timeout-ms 1000
target\debug\windbg-tool.exe --compact remote plan --server target-host --transport tcp:port=5005
```

## Optional agent action log

Set `WINDBG_TOOL_ACTION_LOG` to append one JSONL entry per CLI invocation. By default entries include only the command path, success status, exit code, and duration; raw arguments are redacted. Set `WINDBG_TOOL_ACTION_LOG_FULL=1` only when full command-line logging is safe for your environment.

```powershell
$env:WINDBG_TOOL_ACTION_LOG = "D:\logs\windbg-tool-actions.jsonl"
target\debug\windbg-tool.exe --compact debug capabilities
target\debug\windbg-tool.exe --compact debug log summarize --path D:\logs\windbg-tool-actions.jsonl
```

## Session and cursor basics

- `session_id` identifies the loaded trace
- `cursor_id` identifies a replay cursor inside that trace
- Many commands accept `-s` for `--session` and `-c` for `--cursor`
- `position set` accepts either a structured position, a WinDbg-style `HEX:HEX` string, or a percentage from `0` to `100`
- `exception focus` accepts a zero-based exception index, seeks with the recorded JSON position and owning TTD thread, and reports a pasteable `requested_position_hex`; use it instead of manually transcribing decimal positions from `exceptions`.
- `timeline events` reports `event_counts` before applying its event limit, and limits source payloads. Its `sources` entries report source status and counts; run `modules`, `events modules`, `events threads`, `exceptions`, or `keyframes` for the full metadata list.

## Output shaping

CLI output is JSON by default. These flags make it easier to script:

- `--compact` for single-line JSON
- `--field <dot.path>` to extract one field
- `--raw` to print scalar values without JSON quotes
- `--envelope` or `WINDBG_TOOL_ENVELOPE=1` to wrap success and failure output in a stable agent contract

Example:

```powershell
target\debug\windbg-tool.exe --field session_id --raw open C:\path\to\trace.run
target\debug\windbg-tool.exe --compact registers --session 1 --cursor 1
target\debug\windbg-tool.exe --compact --envelope sessions
```

In envelope mode, successful commands return `{ "schema_version": 1, "ok": true, "data": ... }`. `--field` selects from `data`, so `--envelope --field session_id --raw open ...` still prints the raw session id. Failures return `{ "schema_version": 1, "ok": false, "error": ... }` and ignore `--field`/`--raw` so agents always receive the full error reason.

## Symbol path environment

TTD replay and every DbgEng live-launch, live-attach, and dump session honor local symbol directories from the standard Windows symbol environment. windbg-tool never adds an `srv*` path or loads `symsrv.dll`.

`dump inspect`, `dump triage`, and daemon-backed `dump open` use the Rust-native symbol client by default. They prefer matching `--image-path` and host-local module images, then use the Microsoft Symbol Server HTTPS image-store format to cache a missing exact PE image under `.windbg-symbol-cache`. Every downloaded image is bounded, atomically cached, and validated against the dump module timestamp and image size before its CodeView PDB is resolved. DbgEng receives only direct local PDB and image directories and is forced to reload. Use `--symbol-cache <path>` to choose the cache or `--offline` as a hard no-network mode; an offline image/PDB cache miss is reported explicitly. The JSON response records image and PDB identity, cache, download, validation, and forced-reload status.

Structured error codes use stable exit codes:

| Code | Exit | Retryable |
| --- | ---: | --- |
| `invalid_argument` | 2 | false |
| `daemon_unavailable` | 3 | true |
| `daemon_error` | 4 | depends on cause |
| `session_not_found` | 5 | false |
| `cursor_not_found` | 6 | false |
| `timeout` | 7 | true |
| `tool_error` | 8 | depends on cause |
| `internal` | 1 | false |

Daemon connection failures include the selected pipe and a hint to run `windbg-tool daemon ensure`.

## CLI schema discovery

Use `cli-schema` for machine-readable command paths, arguments, possible values, defaults, conflicts, and command metadata:

```powershell
target\debug\windbg-tool.exe --compact cli-schema
target\debug\windbg-tool.exe --compact cli-schema memory read
```

The schema includes curated metadata where available and inferred metadata for other leaf commands. Bounded collection outputs include additive `returned`, `limit`, and `truncated` fields when the command has a fixed result budget.

## Command groups worth learning first

| Goal | Commands |
| --- | --- |
| Discover capabilities | `discover`, `cli-schema [command...]`, `recipes`, `tools`, `schema <tool>` |
| Canonical agent context | `debug capabilities`, `debug snapshot`, `triage <kind>`, `symbols doctor`, `breakpoint plan`, `debug log summarize` |
| Manage daemon/session state | `daemon ensure`, `daemon status`, `sessions`, `open`, `load`, `close`, `info` |
| Capture a new trace | `trace record --output <trace.run> --command-line <target-command-line>` |
| Move through a trace | `cursor create`, `position get`, `position set`, `step`, `replay to`, `replay watch-memory`, `sweep watch-memory` |
| Inspect trace metadata | `threads`, `modules`, `exceptions`, `keyframes`, `timeline events`, `module info`, `module audit` |
| Inspect runtime state | `registers`, `register-context`, `active-threads`, `command-line`, `architecture state` |
| Inspect code and memory | `disasm`, `memory read`, `memory dump`, `memory strings`, `memory dps`, `memory classify`, `memory chase`, `object vtable` |
| Symbol and source triage | `symbols doctor`, `symbols diagnose`, `symbols inspect`, `symbols exports`, `symbols nearest`, `source resolve` |
| WinDbg, live, dump, and remote helpers | `remote explain`, `remote doctor`, `remote status`, `remote plan`, `remote server-command`, `remote connect-command`, `dbgeng server`, `live capabilities`, `live startup-break`, `live startup-profile`, `live startup-report`, `dump create`, `dump open`, `dump inspect`, `dump triage`, `target event`, `target thread`, `target dump`, `windbg status` |

## Useful non-replay commands

These are good starting points even before you have a trace open:

```powershell
target\debug\windbg-tool.exe discover
target\debug\windbg-tool.exe recipes
target\debug\windbg-tool.exe debug capabilities
target\debug\windbg-tool.exe remote doctor --transport tcp:port=5005
target\debug\windbg-tool.exe symbols inspect C:\Windows\System32\notepad.exe
target\debug\windbg-tool.exe windbg status
```

## Working with multiple workspaces

Use `--pipe \\.\pipe\windbg-tool-custom` or set `WINDBG_TOOL_PIPE` to isolate concurrent daemon instances. The legacy `TTD_MCP_PIPE` variable is also honored.

## Next docs

- For MCP setup and tool flow, see [mcp.md](mcp.md)
- For build, native runtime, and local test details, see [development.md](development.md)
