use crate::pe_symbols::{diagnose_pe, export_symbol_value, read_export_symbols, ExportSymbol};
use anyhow::{bail, ensure, Context};
use clap::{Arg, Args, Command, CommandFactory, Parser, Subcommand, ValueEnum};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter, OpKind, Register,
};
use rmcp::{transport::stdio, ServiceExt};
use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use windbg_ttd::backend::{capability_catalog, capability_contract};
use windbg_ttd::daemon::{default_pipe_name, run_daemon, DaemonClient};
use windbg_ttd::server::TtdMcpServer;
use windbg_ttd::tools::{self, ToolCall};

mod daemon_mode;
mod dispatch;
mod output;
mod platform;
mod remote;

use output::{classify_error, print_failure, print_value, OutputOptions};

#[derive(Debug, Parser)]
#[command(about = "WinDbg Time Travel Debugging MCP server, daemon, and CLI")]
struct Cli {
    #[arg(long, global = true, help = "Windows named pipe path for the daemon")]
    pipe: Option<String>,
    #[arg(long, global = true, help = "Emit compact single-line JSON")]
    compact: bool,
    #[arg(
        long,
        global = true,
        help = "Extract a dot-separated field from the JSON result"
    )]
    field: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Print selected scalar values without JSON quoting"
    )]
    raw: bool,
    #[arg(
        long,
        global = true,
        help = "Wrap command results in a stable {schema_version, ok, data|error} JSON envelope"
    )]
    envelope: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Run the stdio MCP server (also the no-argument default)")]
    Mcp,
    #[command(about = "Show a structured command/tool guide without contacting the daemon")]
    Discover,
    #[command(
        about = "Show TimDbg-inspired diagnostic recipes without contacting the daemon",
        alias = "advise"
    )]
    Recipes(RecipeArgs),
    #[command(about = "Show the JSON schema for one MCP tool without contacting the daemon")]
    Schema(SchemaArgs),
    #[command(
        name = "cli-schema",
        about = "Show machine-readable CLI command and argument schemas without contacting the daemon"
    )]
    CliSchema(CliSchemaArgs),
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    #[command(
        name = "trace-list",
        about = "Enumerate traces in a .run/.idx/.ttd file without opening a session"
    )]
    TraceList(TraceListArgs),
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    #[command(name = "dbgeng")]
    DbgEng {
        #[command(subcommand)]
        command: DbgEngCommand,
    },
    Live {
        #[command(subcommand)]
        command: LiveCommand,
    },
    Dump {
        #[command(subcommand)]
        command: DumpCommand,
    },
    #[command(
        name = "dbgsrv",
        about = "Start a DbgEng process server",
        alias = "debug-server"
    )]
    DbgSrv(DbgEngServerArgs),
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
    Triage {
        #[command(subcommand)]
        command: TriageCommand,
    },
    Windbg {
        #[command(subcommand)]
        command: WindbgCommand,
    },
    #[command(about = "Load a trace, create a cursor, optionally seek, and print both handles")]
    Open(OpenArgs),
    #[command(about = "Load a .run/.idx/.ttd trace into the long-lived daemon")]
    Load(LoadArgs),
    #[command(about = "List daemon-owned trace sessions and cursors", alias = "ls")]
    Sessions,
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
    #[command(about = "Close a daemon-owned trace session")]
    Close(SessionArgs),
    #[command(about = "Show trace metadata for a loaded session")]
    Info(SessionArgs),
    Symbols {
        #[command(subcommand)]
        command: SymbolsCommand,
    },
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    #[command(alias = "arch")]
    Architecture {
        #[command(subcommand)]
        command: ArchitectureCommand,
    },
    #[command(
        about = "Show available backend features for a loaded session",
        alias = "caps"
    )]
    Capabilities(SessionArgs),
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    #[command(about = "List MCP tools and input schemas without contacting the daemon")]
    Tools,
    #[command(about = "Call any MCP tool by name with raw JSON arguments")]
    Tool(ToolArgs),
    #[command(about = "List trace threads")]
    Threads(SessionArgs),
    #[command(about = "List trace modules", alias = "mods")]
    Modules(SessionArgs),
    #[command(about = "List trace keyframes")]
    Keyframes(SessionArgs),
    #[command(about = "List trace exception events")]
    Exceptions(SessionArgs),
    Exception {
        #[command(subcommand)]
        command: ExceptionCommand,
    },
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    Timeline {
        #[command(subcommand)]
        command: TimelineCommand,
    },
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },
    Address(AddressInfoArgs),
    Cursor {
        #[command(subcommand)]
        command: CursorCommand,
    },
    #[command(about = "List active threads at a cursor", alias = "active")]
    ActiveThreads(CursorArgs),
    Position {
        #[command(subcommand)]
        command: PositionCommand,
    },
    #[command(about = "Step or trace a cursor")]
    Step(StepArgs),
    Replay {
        #[command(subcommand)]
        command: ReplayCommand,
    },
    Sweep {
        #[command(subcommand)]
        command: SweepCommand,
    },
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    Breakpoint {
        #[command(subcommand)]
        command: BreakpointCommand,
    },
    Datamodel {
        #[command(subcommand)]
        command: DataModelCommand,
    },
    Target {
        #[command(subcommand)]
        command: TargetCommand,
    },
    #[command(
        about = "Disassemble memory at an address or the current cursor RIP",
        alias = "u"
    )]
    Disasm(DisasmArgs),
    #[command(about = "Read compact register/thread state", alias = "regs")]
    Registers(CursorArgs),
    #[command(
        about = "Read full x64 scalar and vector register context",
        alias = "ctx"
    )]
    RegisterContext(RegisterContextArgs),
    Stack {
        #[command(subcommand)]
        command: StackCommand,
    },
    #[command(about = "Read the process command line", alias = "cmdline")]
    CommandLine(CursorArgs),
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    Object {
        #[command(subcommand)]
        command: ObjectCommand,
    },
    Watchpoint(WatchpointArgs),
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    Start {
        #[arg(
            long,
            help = "Spawn windbg-tool daemon mode and return after it starts"
        )]
        detach: bool,
    },
    Status,
    Ensure,
    Shutdown,
}

#[derive(Debug, Subcommand)]
enum DbgEngCommand {
    #[command(about = "Start a DbgEng user-mode process server and wait for it to exit")]
    Server(DbgEngServerArgs),
}

#[derive(Debug, Subcommand)]
enum LiveCommand {
    #[command(
        about = "Launch a process under DbgEng, wait for the initial event, then detach or terminate"
    )]
    Launch(LiveLaunchArgs),
    #[command(
        about = "Launch under DbgEng, set an address/module-RVA/symbol breakpoint, and emit bounded stop context"
    )]
    StartupBreak(LiveStartupBreakArgs),
    #[command(
        about = "Profile bounded DbgEng lifecycle events with host-monotonic wall-clock timing and no breakpoints"
    )]
    StartupProfile(LiveStartupProfileArgs),
    #[command(
        about = "Compare two bounded live startup-profile JSON artifacts without CPU or causal attribution"
    )]
    StartupCompare(LiveStartupProfileCompareArgs),
    #[command(
        about = "Render a bounded offline module timeline from a live startup-profile JSON artifact"
    )]
    StartupReport(LiveStartupProfileReportArgs),
    #[command(
        about = "Launch .NET under DbgEng, bind the matching CoreCLR DAC, and emit a managed method hit"
    )]
    ManagedBreak(LiveManagedBreakArgs),
    #[command(about = "Launch a process under DbgEng and keep it as a daemon-owned live target")]
    Start(LiveSessionStartArgs),
    #[command(about = "Attach DbgEng to a process and keep it as a daemon-owned live target")]
    Attach(LiveAttachArgs),
    #[command(about = "Show live DbgEng command support and current limitations")]
    Capabilities,
}

#[derive(Debug, Subcommand)]
enum DumpCommand {
    #[command(about = "Open a dump file as a daemon-owned target")]
    Open(DumpOpenArgs),
    #[command(about = "Open and inspect a dump file without the daemon")]
    Inspect(DumpInspectArgs),
    #[command(
        about = "Produce structured bugcheck, context, stack, symbol, and driver triage for a dump"
    )]
    Triage(DumpInspectArgs),
    #[command(
        about = "Produce bounded pool-corruption triage with context, tracker, and evidence grades"
    )]
    PoolTriage(DumpInspectArgs),
    #[command(about = "Create a process dump from a live process id")]
    Create(DumpCreateArgs),
}

#[derive(Debug, Subcommand)]
enum RemoteCommand {
    #[command(about = "Explain remote debugging workflow choices")]
    Explain(RemoteExplainArgs),
    #[command(about = "Generate a target-side remote server command")]
    ServerCommand(RemoteServerCommandArgs),
    #[command(about = "Generate a host-side WinDbg connection command")]
    ConnectCommand(RemoteConnectCommandArgs),
    #[command(about = "Diagnose local readiness and command lines for remote debugging")]
    Doctor(RemoteDoctorArgs),
    #[command(about = "Show remote-debugging prerequisite status and optional reachability")]
    Status(RemoteStatusArgs),
    #[command(
        about = "Generate a lifecycle plan for starting, connecting, verifying, and cleanup"
    )]
    Plan(RemotePlanArgs),
}

#[derive(Debug, Subcommand)]
enum DebugCommand {
    #[command(about = "Show canonical per-backend debugging capability matrix")]
    Capabilities(DebugCapabilitiesArgs),
    #[command(about = "Capture a bounded cross-backend AI-agent debugging snapshot")]
    Snapshot(DebugSnapshotArgs),
    #[command(about = "Read optional agent action logs")]
    Log {
        #[command(subcommand)]
        command: DebugLogCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DebugLogCommand {
    #[command(about = "Summarize recent WINDBG_TOOL_ACTION_LOG JSONL entries")]
    Summarize(DebugLogSummarizeArgs),
}

#[derive(Debug, Subcommand)]
enum TriageCommand {
    #[command(about = "Triage crash evidence from a TTD cursor or daemon-owned target")]
    Crash(TriageArgs),
    #[command(about = "Triage hang evidence from a TTD cursor or daemon-owned target")]
    Hang(TriageArgs),
    #[command(about = "Triage access-violation evidence from a TTD cursor or daemon-owned target")]
    AccessViolation(TriageArgs),
    #[command(
        about = "Triage memory-corruption evidence from available stack/module/memory facts"
    )]
    MemoryCorruption(TriageArgs),
    #[command(about = "Triage loader and suspicious-module evidence")]
    Loader(TriageArgs),
    #[command(about = "Triage symbol and source readiness")]
    SymbolHealth(TriageArgs),
    #[command(about = "Triage deadlock evidence where backend data is available")]
    Deadlock(TriageArgs),
}

#[derive(Debug, Subcommand)]
enum WindbgCommand {
    #[command(about = "Show installed and latest WinDbg package status")]
    Status(WindbgCommonArgs),
    #[command(about = "Download, verify, and extract the latest WinDbg package")]
    Install(WindbgInstallArgs),
    #[command(about = "Install the latest WinDbg package if a newer version is available")]
    Update(WindbgCommonArgs),
    #[command(about = "Print the installed DbgX.Shell.exe path")]
    Path(WindbgCommonArgs),
    #[command(about = "Ensure WinDbg is installed, then run DbgX.Shell.exe")]
    Run(WindbgRunArgs),
}

#[derive(Debug, Subcommand)]
enum ContextCommand {
    #[command(about = "Capture an agent-ready snapshot of daemon/session/cursor state")]
    Snapshot(ContextSnapshotArgs),
}

#[derive(Debug, Subcommand)]
enum SymbolsCommand {
    #[command(about = "Diagnose symbol, binary, and source readiness for a session or module")]
    Diagnose(SymbolDiagnoseArgs),
    #[command(about = "Inspect a local PE image and print symbol-server identities")]
    Inspect(SymbolInspectArgs),
    #[command(about = "List local PE exports with optional filtering")]
    Exports(SymbolExportsArgs),
    #[command(about = "Find the nearest exported symbol for a TTD address")]
    Nearest(SymbolNearestArgs),
    #[command(about = "Diagnose symbol/source readiness for a TTD cursor or daemon-owned target")]
    Doctor(SymbolDoctorArgs),
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    #[command(about = "Resolve a recorded source path under local search roots")]
    Resolve(SourceResolveArgs),
}

#[derive(Debug, Subcommand)]
enum ReplayCommand {
    #[command(about = "Show supported and missing replay-control capabilities")]
    Capabilities(SessionArgs),
    #[command(about = "Seek a cursor to a position, optionally scoped to a TTD thread")]
    To(ReplayToArgs),
    #[command(about = "Replay to the next/previous memory access for an address range")]
    WatchMemory(WatchpointArgs),
}

#[derive(Debug, Subcommand)]
enum SweepCommand {
    #[command(about = "Collect multiple memory watchpoint hits with explicit bounds")]
    WatchMemory(SweepWatchMemoryArgs),
}

#[derive(Debug, Subcommand)]
enum BreakpointCommand {
    #[command(about = "Show breakpoint/watchpoint manager support and current gaps")]
    Capabilities,
    #[command(about = "List live breakpoints for a daemon-owned live target")]
    List(TargetIdArgs),
    #[command(about = "Set a code or data breakpoint for a daemon-owned live target")]
    Set(BreakpointSetArgs),
    #[command(about = "Enable an existing breakpoint for a daemon-owned live target")]
    Enable(BreakpointEnableArgs),
    #[command(about = "Disable an existing breakpoint for a daemon-owned live target")]
    Disable(BreakpointEnableArgs),
    #[command(about = "Remove a breakpoint from a daemon-owned live target")]
    Remove(BreakpointRemoveArgs),
    #[command(about = "Plan a breakpoint or watchpoint without mutating the target")]
    Plan(BreakpointPlanArgs),
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    #[command(about = "List daemon-owned replay jobs")]
    List,
    #[command(about = "Show daemon-owned replay job status")]
    Status(JobIdArgs),
    #[command(about = "Fetch the latest daemon-owned replay job result")]
    Result(JobIdArgs),
    #[command(about = "Request cancellation for a daemon-owned replay job")]
    Cancel(JobIdArgs),
}

#[derive(Debug, Subcommand)]
enum DataModelCommand {
    #[command(about = "Show DbgEng data model / target model support and current gaps")]
    Capabilities,
    #[command(about = "Evaluate a DbgEng expression against a daemon-owned target")]
    Eval(DataModelEvalArgs),
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    #[command(
        about = "Show target-kind capabilities for TTD, live, dump, and future target models"
    )]
    Capabilities(TargetCapabilitiesArgs),
    #[command(about = "List daemon-owned live and dump targets")]
    List,
    #[command(about = "Show status for a daemon-owned target")]
    Status(TargetIdArgs),
    #[command(about = "Close a daemon-owned target")]
    Close(TargetIdArgs),
    #[command(about = "Terminate and close a daemon-owned live target")]
    Terminate(TargetIdArgs),
    #[command(about = "Wait for the next debug event on a daemon-owned live target")]
    Wait(TargetWaitArgs),
    #[command(about = "Continue execution of a daemon-owned live target")]
    Continue(TargetIdArgs),
    #[command(
        about = "Continue a live target and wait for one bounded stop, with optional debuggee output"
    )]
    ContinueWait(TargetContinueWaitArgs),
    #[command(about = "Single-step a daemon-owned live target")]
    Step(TargetIdArgs),
    #[command(about = "Step over one instruction in a daemon-owned live target")]
    StepOver(TargetIdArgs),
    #[command(about = "List threads for a daemon-owned target")]
    Threads(TargetIdArgs),
    #[command(
        about = "Read bounded DbgEng per-thread CPU accounting for a stopped daemon-owned target"
    )]
    ThreadAccounting(TargetThreadAccountingArgs),
    #[command(
        about = "Read bounded DbgEng symbol-readiness parameters for supplied observed module bases"
    )]
    ModuleParameters(TargetModuleParametersArgs),
    #[command(about = "List modules for a daemon-owned target")]
    Modules(TargetIdArgs),
    #[command(about = "Read current thread and instruction offsets for a daemon-owned target")]
    Registers(TargetIdArgs),
    #[command(
        about = "Read the last DbgEng event with bounded exception, breakpoint, module, or exit evidence"
    )]
    Event(TargetIdArgs),
    #[command(about = "Read memory from a daemon-owned target")]
    Memory(TargetMemoryReadArgs),
    #[command(about = "Return a bounded live user-mode virtual-memory map through DbgEng")]
    MemoryMap(TargetMemoryMapArgs),
    #[command(
        about = "Inspect one address through bounded DbgEng translation and virtual-region probes"
    )]
    Address(TargetAddressArgs),
    #[command(about = "Walk the current stack for a daemon-owned target")]
    Stack(TargetStackTraceArgs),
    #[command(
        about = "Inspect one engine thread without leaving it selected after the bounded query"
    )]
    Thread(TargetThreadContextArgs),
    #[command(about = "Disassemble instructions from a daemon-owned target")]
    Disasm(TargetDisasmArgs),
    #[command(about = "Resolve the nearest symbol for a daemon-owned target address")]
    Symbol(TargetAddressArgs),
    #[command(
        about = "Read bounded DbgEng symbol-entry offset regions for an existing native address"
    )]
    SymbolEntryRange(TargetAddressArgs),
    #[command(
        about = "Resolve source file and line information for a daemon-owned target address"
    )]
    Source(TargetAddressArgs),
    #[command(about = "Write a process dump from a daemon-owned live target")]
    Dump(TargetDumpArgs),
}

#[derive(Debug, Subcommand)]
enum ArchitectureCommand {
    #[command(about = "Describe cursor architecture, register model, and helper support")]
    State(ArchitectureStateArgs),
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    #[command(about = "Enumerate traces in a .run/.idx/.ttd file without opening a session")]
    List(TraceListArgs),
    #[command(about = "Launch a process through TTD.exe and wait for its trace to be finalized")]
    Record(TraceRecordArgs),
}

#[derive(Debug, Subcommand)]
enum IndexCommand {
    #[command(about = "Show TTD index status for a loaded session")]
    Status(SessionArgs),
    #[command(about = "Show TTD index file statistics for a loaded session")]
    Stats(SessionArgs),
    #[command(about = "Synchronously build the TTD index for a loaded session")]
    Build(IndexBuildArgs),
}

#[derive(Debug, Subcommand)]
enum EventsCommand {
    Modules(SessionArgs),
    Threads(SessionArgs),
}

#[derive(Debug, Subcommand)]
enum TimelineCommand {
    #[command(about = "Merge trace events into a single chronological timeline")]
    Events(TimelineEventsArgs),
}

#[derive(Debug, Subcommand)]
enum ExceptionCommand {
    #[command(about = "Seek a cursor to an indexed exception event on its owning thread")]
    Focus(ExceptionFocusArgs),
}

#[derive(Debug, Subcommand)]
enum ModuleCommand {
    Info(ModuleInfoArgs),
    #[command(about = "Audit loaded modules for suspicious paths and duplicate names")]
    Audit(ModuleAuditArgs),
    #[command(about = "Explain DLL search-order candidates and risky directories")]
    SearchOrder(ModuleSearchOrderArgs),
}

#[derive(Debug, Subcommand)]
enum CursorCommand {
    Create(SessionArgs),
    Modules(CursorArgs),
}

#[derive(Debug, Subcommand)]
enum PositionCommand {
    Get(CursorArgs),
    Set(PositionSetArgs),
}

#[derive(Debug, Subcommand)]
enum StackCommand {
    Info(CursorArgs),
    Read(StackReadArgs),
    Recover(StackRecoverArgs),
    #[command(
        about = "Build a heuristic backtrace from current PC and recovered stack candidates"
    )]
    Backtrace(StackBacktraceArgs),
}

#[derive(Debug, Subcommand)]
enum MemoryCommand {
    Read(MemoryReadArgs),
    Range(MemoryRangeArgs),
    Buffer(MemoryBufferArgs),
    Dump(MemoryDumpArgs),
    Classify(MemoryClassifyArgs),
    Strings(MemoryStringsArgs),
    Dps(MemoryDpsArgs),
    Chase(MemoryChaseArgs),
    Watchpoint(WatchpointArgs),
}

#[derive(Debug, Subcommand)]
enum ObjectCommand {
    #[command(about = "Read an object vtable pointer and classify vtable entries")]
    Vtable(ObjectVtableArgs),
}

#[derive(Debug, Args)]
struct DbgEngServerArgs {
    #[arg(
        short = 't',
        long,
        help = "DbgEng process-server transport, for example tcp:port=5005"
    )]
    transport: String,
}

#[derive(Debug, Args)]
struct RemoteDoctorArgs {
    #[arg(long, value_enum, default_value_t = RemoteKind::Dbgsrv)]
    kind: RemoteKind,
    #[arg(
        long,
        help = "Target machine name or address for generated host commands"
    )]
    server: Option<String>,
    #[arg(short = 't', long, default_value = "tcp:port=5005")]
    transport: String,
    #[arg(long, help = "Target process id for NTSD/CDB -server attach recipes")]
    pid: Option<u32>,
    #[arg(
        long,
        help = "Target executable or command line for NTSD/CDB -server launch recipes"
    )]
    executable: Option<String>,
    #[arg(long, help = "Run an opt-in bounded TCP connect probe to --server")]
    probe_connect: bool,
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
}

#[derive(Debug, Args)]
struct RemoteStatusArgs {
    #[arg(long, value_enum, default_value_t = RemoteKind::Dbgsrv)]
    kind: RemoteKind,
    #[arg(
        long,
        help = "Target machine name or address for optional connect probe"
    )]
    server: Option<String>,
    #[arg(short = 't', long, default_value = "tcp:port=5005")]
    transport: String,
    #[arg(long, help = "Run an opt-in bounded TCP connect probe to --server")]
    probe_connect: bool,
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
}

#[derive(Debug, Args)]
struct RemotePlanArgs {
    #[arg(long, value_enum, default_value_t = RemoteKind::Dbgsrv)]
    kind: RemoteKind,
    #[arg(
        long,
        help = "Target machine name or address for generated host commands"
    )]
    server: Option<String>,
    #[arg(short = 't', long, default_value = "tcp:port=5005")]
    transport: String,
    #[arg(long, help = "Target process id for NTSD/CDB -server attach recipes")]
    pid: Option<u32>,
    #[arg(
        long,
        help = "Target executable or command line for NTSD/CDB -server launch recipes"
    )]
    executable: Option<String>,
}

#[derive(Debug, Args)]
struct LiveLaunchArgs {
    #[arg(long, help = "Full command line to launch under DbgEng")]
    command_line: String,
    #[arg(long, default_value_t = 5000)]
    initial_break_timeout_ms: u32,
    #[arg(long, default_value = "detach", value_parser = ["detach", "terminate"])]
    end: String,
}

#[derive(Debug, Args)]
struct LiveStartupBreakArgs {
    #[arg(long, help = "Full command line to launch under DbgEng")]
    command_line: String,
    #[arg(
        long,
        conflicts_with_all = ["address", "module", "module_offset", "symbol"],
        help = "Capture the initial DbgEng break without setting a code breakpoint"
    )]
    initial_break: bool,
    #[arg(
        long,
        help = "Use a one-byte DbgEng processor execute breakpoint instead of a software code breakpoint; uses a create-process initial stop and cannot be combined with --initial-break"
    )]
    hardware_execute: bool,
    #[arg(long, help = "Absolute code address for the breakpoint")]
    address: Option<String>,
    #[arg(
        long,
        help = "Loaded module basename or image path for an RVA breakpoint"
    )]
    module: Option<String>,
    #[arg(
        long,
        requires = "module",
        help = "RVA added to --module's loaded base address"
    )]
    module_offset: Option<String>,
    #[arg(
        long,
        help = "DbgEng symbol expression; remains deferred until its module and symbol resolve"
    )]
    symbol: Option<String>,
    #[arg(
        long,
        value_name = "MODULE",
        help = "Stop on a trusted module-load event before configuring the requested code breakpoint"
    )]
    wait_for_module: Option<String>,
    #[arg(long, default_value_t = 5000)]
    initial_break_timeout_ms: u32,
    #[arg(long, default_value_t = 10000)]
    wait_timeout_ms: u32,
    #[arg(long, default_value_t = 16)]
    max_frames: u32,
    #[arg(long, default_value = "terminate", value_parser = ["detach", "terminate"])]
    end: String,
}

#[derive(Debug, Args)]
struct LiveStartupProfileArgs {
    #[arg(long, help = "Full command line to launch under DbgEng")]
    command_line: String,
    #[arg(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..=10),
        help = "Independent bounded launches to collect; stops after the first launch failure"
    )]
    runs: u32,
    #[arg(
        long,
        default_value_t = 30000,
        help = "Maximum time to observe the initial DbgEng create-process event"
    )]
    initial_break_timeout_ms: u32,
    #[arg(
        long,
        default_value_t = 90000,
        help = "Maximum target-resumed wall time for each run after the create-process event"
    )]
    timeout_ms: u32,
    #[arg(
        long,
        default_value_t = 256,
        value_parser = clap::value_parser!(u32).range(2..=1024),
        help = "Maximum DbgEng lifecycle events retained per run"
    )]
    max_events: u32,
    #[arg(
        long,
        value_name = "MODULE",
        help = "Optional application module basename used for observable module-to-exit phases"
    )]
    phase_module: Option<String>,
    #[arg(
        long,
        value_name = "MODULE",
        help = "Finish the startup observation when this module-load event is observed; does not imply UI readiness"
    )]
    completion_module: Option<String>,
    #[arg(
        long,
        value_name = "MILLISECONDS",
        requires = "completion_module",
        value_parser = clap::value_parser!(u32).range(1..=60000),
        help = "After --completion-module, require this much target-resumed time without another configured lifecycle stop before completing; only an observed lifecycle quiet interval"
    )]
    settle_ms: Option<u32>,
    #[arg(
        long,
        help = "Request first-chance exception stops in addition to lifecycle events; can substantially increase event volume"
    )]
    include_first_chance_exceptions: bool,
    #[arg(
        long,
        help = "Attach bounded read-only register/module/symbol/stack context to early observed stops"
    )]
    capture_stop_context: bool,
    #[arg(
        long,
        value_delimiter = ',',
        value_enum,
        requires = "capture_stop_context",
        value_name = "EVENT",
        help = "Comma-separated lifecycle event kinds eligible for read-only context; defaults to load-module,create-thread,exception,exit-process when context capture is enabled"
    )]
    context_on: Vec<StartupProfileContextEvent>,
    #[arg(
        long,
        default_value_t = 8,
        value_parser = clap::value_parser!(u32).range(1..=32),
        help = "Maximum event contexts captured when --capture-stop-context is set"
    )]
    max_context_events: u32,
    #[arg(
        long,
        default_value_t = 8,
        value_parser = clap::value_parser!(u32).range(1..=32),
        help = "Maximum stack frames in each optional stop context"
    )]
    max_frames: u32,
    #[arg(
        long,
        requires = "capture_stop_context",
        help = "Attach one bounded DbgEng symbol-entry range query to each captured stop context; symbol paths can cause host-side resolution I/O"
    )]
    capture_native_symbol_entry_range: bool,
    #[arg(
        long,
        help = "Capture bounded read-only DbgEng per-thread accounting snapshots with raw validity-gated counters"
    )]
    capture_thread_accounting: bool,
    #[arg(
        long,
        value_delimiter = ',',
        value_enum,
        requires = "capture_thread_accounting",
        value_name = "EVENT",
        help = "Comma-separated lifecycle event kinds eligible for thread accounting; defaults to create-process,load-module,create-thread,exit-process when enabled"
    )]
    thread_accounting_on: Vec<StartupProfileContextEvent>,
    #[arg(
        long,
        default_value_t = 8,
        value_parser = clap::value_parser!(u32).range(1..=32),
        requires = "capture_thread_accounting",
        help = "Maximum selected lifecycle stops that collect a thread-accounting snapshot"
    )]
    max_thread_accounting_snapshots: u32,
    #[arg(
        long,
        default_value_t = 32,
        value_parser = clap::value_parser!(u32).range(1..=128),
        requires = "capture_thread_accounting",
        help = "Maximum threads returned in each DbgEng thread-accounting snapshot"
    )]
    max_thread_accounting_threads: u32,
    #[arg(
        long,
        help = "Capture bounded DbgEng debuggee-output callback records; disabled by default because debug strings can contain sensitive content"
    )]
    capture_debuggee_output: bool,
    #[arg(
        long,
        default_value_t = 32,
        value_parser = clap::value_parser!(u32).range(1..=128),
        requires = "capture_debuggee_output",
        help = "Maximum debuggee-output callback records retained"
    )]
    max_output_records: u32,
    #[arg(
        long,
        default_value_t = 512,
        value_parser = clap::value_parser!(u32).range(1..=4096),
        requires = "capture_debuggee_output",
        help = "Maximum UTF-16 characters retained per debuggee-output callback record"
    )]
    max_output_chars: u32,
    #[arg(
        long,
        default_value_t = 8192,
        value_parser = clap::value_parser!(u32).range(1..=32768),
        requires = "capture_debuggee_output",
        help = "Maximum UTF-16 characters retained across all debuggee-output callback records"
    )]
    max_total_output_chars: u32,
    #[arg(
        long,
        help = "Read bounded host-side PE/file metadata only for DbgEng-observed module image paths"
    )]
    capture_module_provenance: bool,
    #[arg(
        long,
        default_value_t = 32,
        value_parser = clap::value_parser!(u32).range(1..=128),
        requires = "capture_module_provenance",
        help = "Maximum unique DbgEng-observed module image paths inspected for host file metadata"
    )]
    max_module_provenance: u32,
    #[arg(
        long,
        help = "Read bounded DbgEng module parameters only for module bases observed in this lifecycle timeline; symbol paths can cause host-side resolution I/O"
    )]
    capture_dbgeng_module_parameters: bool,
    #[arg(
        long,
        default_value_t = 32,
        value_parser = clap::value_parser!(u32).range(1..=128),
        requires = "capture_dbgeng_module_parameters",
        help = "Maximum observed module bases queried through DbgEng IDebugSymbols5"
    )]
    max_dbgeng_module_parameters: u32,
    #[arg(
        long,
        value_name = "PATH",
        help = "Write the complete JSON result to a new file as well as stdout"
    )]
    output: Option<PathBuf>,
    #[arg(
        long,
        default_value = "detach",
        value_parser = ["detach", "terminate"],
        help = "Action if the target has not exited at its completion or time bound; terminate is explicit"
    )]
    end: String,
}

#[derive(Debug, Args)]
struct LiveStartupProfileCompareArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Earlier startup-profile JSON artifact"
    )]
    baseline: PathBuf,
    #[arg(
        long,
        value_name = "PATH",
        help = "Later startup-profile JSON artifact"
    )]
    candidate: PathBuf,
    #[arg(
        long,
        default_value_t = 64,
        value_parser = clap::value_parser!(u32).range(1..=256),
        help = "Maximum retained lifecycle events compared per matched run"
    )]
    max_sequence_events: u32,
}

#[derive(Debug, Args)]
struct LiveStartupProfileReportArgs {
    #[arg(
        value_name = "ARTIFACT",
        help = "Existing live startup-profile JSON artifact to read offline"
    )]
    artifact: PathBuf,
    #[arg(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..=10),
        help = "Recorded run number to render; launch-relative timestamps are never combined across runs"
    )]
    run: u32,
    #[arg(
        long,
        value_name = "SUBSTRING",
        help = "Case-insensitive substring filter for module basename, normalized path, or DbgEng module name"
    )]
    module: Option<String>,
    #[arg(
        long,
        conflicts_with = "rdm_only",
        help = "Keep only modules classified from their observed identity as runtime/loader modules"
    )]
    runtime_only: bool,
    #[arg(
        long,
        conflicts_with = "runtime_only",
        help = "Keep only modules whose normalized observed image path contains /RemoteDesktopManager/"
    )]
    rdm_only: bool,
    #[arg(
        long,
        value_name = "MILLISECONDS",
        help = "Keep only first-observed modules at or after this target-resumed host wall-time timestamp"
    )]
    min_resumed_ms: Option<u64>,
    #[arg(
        long,
        default_value_t = 64,
        value_parser = clap::value_parser!(u32).range(1..=128),
        help = "Maximum filtered module rows returned; the JSON report states whether this bound truncated rows"
    )]
    max_rows: u32,
    #[arg(
        long,
        value_enum,
        default_value_t = StartupProfileReportFormat::Table,
        help = "Terminal output format; JSON preserves unclipped normalized paths and structured enrichment"
    )]
    format: StartupProfileReportFormat,
    #[arg(
        long,
        default_value_t = 56,
        value_parser = clap::value_parser!(u32).range(24..=256),
        help = "Maximum normalized-path width in table output; JSON always includes the full normalized path"
    )]
    path_width: u32,
    #[arg(
        long,
        help = "Omit the concise milestones and largest-observed-gaps tables from terminal table output"
    )]
    no_summary: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Write the complete structured report JSON to a new file without modifying the source artifact"
    )]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum StartupProfileReportFormat {
    Table,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum StartupProfileContextEvent {
    CreateProcess,
    ExitProcess,
    CreateThread,
    ExitThread,
    LoadModule,
    UnloadModule,
    Exception,
}

#[derive(Debug, Args)]
struct LiveManagedBreakArgs {
    #[arg(long, help = "Full command line to launch under DbgEng")]
    command_line: String,
    #[arg(
        long,
        value_name = "MODULE",
        help = "Managed assembly module basename, for example RemoteDesktopManager.dll"
    )]
    managed_module: String,
    #[arg(
        long,
        help = "Fully qualified managed metadata method name, for example Namespace.Type.Method"
    )]
    method: String,
    #[arg(
        long,
        value_name = "HEX",
        help = "Optional exact ECMA-335 MethodDef signature bytes in hexadecimal, for example 00010E0E; required to select an overload"
    )]
    signature: Option<String>,
    #[arg(
        long,
        help = "Allow the matching DAC to write CLR debugger-notification state; use only in an approved test VM"
    )]
    allow_runtime_write: bool,
    #[arg(
        long,
        conflicts_with = "allow_runtime_write",
        help = "Use only read-only DAC queries and a DbgEng processor execute breakpoint; does not register CLR notifications or use a software breakpoint"
    )]
    hardware_execute: bool,
    #[arg(long, default_value_t = 30000)]
    initial_break_timeout_ms: u32,
    #[arg(long, default_value_t = 60000)]
    wait_timeout_ms: u32,
    #[arg(long, default_value_t = 16)]
    max_frames: u32,
    #[arg(long, default_value = "terminate", value_parser = ["detach", "terminate"])]
    end: String,
}

#[derive(Debug, Args, Clone)]
struct TraceRecordArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Output .run trace path; its parent directory must already exist"
    )]
    output: PathBuf,
    #[arg(
        long,
        help = "Full target command line; it is passed directly to TTD.exe without a shell"
    )]
    command_line: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "TTD.exe path; defaults to TTD_EXE or ttd.exe found on PATH"
    )]
    ttd_exe: Option<PathBuf>,
    #[arg(long, help = "Record child processes created by the launch target")]
    children: bool,
    #[arg(
        long = "module",
        value_name = "MODULE",
        help = "Restrict recording to a native module basename; repeat for each module"
    )]
    modules: Vec<String>,
    #[arg(
        long,
        value_name = "MEGABYTES",
        help = "Pass -maxFile to bound the trace size"
    )]
    max_file_mb: Option<u32>,
    #[arg(
        long,
        requires = "max_file_mb",
        help = "Use a fixed-size ring buffer; requires --max-file-mb"
    )]
    ring: bool,
    #[arg(
        long,
        value_enum,
        help = "TTD replay CPU compatibility contract; defaults to TTD's Default mode"
    )]
    replay_cpu_support: Option<TraceReplayCpuSupport>,
    #[arg(
        long,
        value_name = "COUNT",
        help = "Reserve this many TTD virtual CPUs; lower values reduce memory pressure but can slow recording"
    )]
    num_vcpu: Option<u32>,
    #[arg(
        long,
        value_enum,
        conflicts_with_all = ["max_file_mb", "ring"],
        help = "Apply a bounded capture preset: startup retains early trace data; recent retains the newest window"
    )]
    profile: Option<TraceRecordProfile>,
    #[arg(
        long,
        value_name = "SECONDS",
        requires = "disable_user_shadow_stack",
        help = "Stop recording after this duration without terminating the CET-compatible launch target"
    )]
    record_for_seconds: Option<u32>,
    #[arg(
        long,
        help = "Launch only this target with CET user shadow stacks disabled, then record by PID attach"
    )]
    disable_user_shadow_stack: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum TraceRecordProfile {
    Startup,
    Recent,
}

impl TraceRecordProfile {
    fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Recent => "recent",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum TraceReplayCpuSupport {
    Default,
    MostConservative,
    MostAggressive,
    IntelAvxRequired,
    IntelAvx2Required,
}

impl TraceReplayCpuSupport {
    fn ttd_value(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::MostConservative => "MostConservative",
            Self::MostAggressive => "MostAggressive",
            Self::IntelAvxRequired => "IntelAvxRequired",
            Self::IntelAvx2Required => "IntelAvx2Required",
        }
    }
}

#[derive(Debug, Args)]
struct LiveSessionStartArgs {
    #[arg(long, help = "Full command line to launch under DbgEng")]
    command_line: String,
    #[arg(long, default_value_t = 5000)]
    initial_break_timeout_ms: u32,
    #[arg(
        long,
        help = "Stop on DbgEng's create-process event instead of the default software initial-break engine option"
    )]
    create_process_stop: bool,
}

#[derive(Debug, Args)]
struct LiveAttachArgs {
    #[arg(long, help = "Process id to attach under DbgEng")]
    process_id: u32,
    #[arg(long, default_value_t = 5000)]
    initial_break_timeout_ms: u32,
}

#[derive(Debug, Args)]
struct DumpOpenArgs {
    path: PathBuf,
    #[arg(long, value_name = "PATH", default_value = ".windbg-symbol-cache")]
    symbol_cache: PathBuf,
    #[arg(long, value_name = "PATH")]
    image_path: Vec<PathBuf>,
    #[arg(long)]
    offline: bool,
}

#[derive(Debug, Args)]
struct DumpCreateArgs {
    #[arg(long, help = "Process id to dump through DbgEng")]
    process_id: u32,
    #[arg(long, value_name = "PATH", help = "Output .dmp path")]
    output: PathBuf,
    #[arg(long, value_enum, default_value_t = CliDumpKind::Mini)]
    kind: CliDumpKind,
    #[arg(long, help = "Allow replacing an existing dump file")]
    overwrite: bool,
    #[arg(long, default_value_t = 5000)]
    initial_break_timeout_ms: u32,
}

#[derive(Debug, Args)]
struct DumpInspectArgs {
    path: PathBuf,
    #[arg(
        long,
        default_value_t = 8,
        value_parser = clap::value_parser!(u32).range(1..=128),
        help = "Maximum stack frames per bounded dump stack/context walk"
    )]
    max_frames: u32,
    #[arg(
        long,
        help = "Force a local DbgEng symbol reload after Rust-native prefetch"
    )]
    refresh_symbols: bool,
    #[arg(
        long,
        value_name = "PATH",
        default_value = ".windbg-symbol-cache",
        help = "Rust-native symbol cache; DbgEng never treats this as an srv* path"
    )]
    symbol_cache: PathBuf,
    #[arg(
        long,
        value_name = "PATH",
        help = "Additional directory containing matching module images; repeat as needed"
    )]
    image_path: Vec<PathBuf>,
    #[arg(
        long,
        help = "Do not download missing symbols; report cache misses explicitly"
    )]
    offline: bool,
    #[arg(
        long,
        value_name = "ADDRESS",
        help = "Inspect one virtual address through bounded DbgEng mapping and pool-record probes"
    )]
    inspect_address: Option<String>,
    #[arg(
        long,
        value_name = "ADDRESS",
        help = "Known per-CPU pool-tracker table base used to classify --inspect-address or the captured tracker entry"
    )]
    tracker_table_base: Option<String>,
}

#[derive(Debug, Args)]
struct RemoteExplainArgs {
    #[arg(long, value_enum)]
    kind: Option<RemoteKind>,
}

#[derive(Debug, Args)]
struct RemoteServerCommandArgs {
    #[arg(long, value_enum, default_value_t = RemoteKind::Dbgsrv)]
    kind: RemoteKind,
    #[arg(short = 't', long, default_value = "tcp:port=5005")]
    transport: String,
    #[arg(long, help = "Target process id for NTSD/CDB -server attach recipes")]
    pid: Option<u32>,
    #[arg(
        long,
        help = "Target executable or command line for NTSD/CDB -server launch recipes"
    )]
    executable: Option<String>,
}

#[derive(Debug, Args)]
struct RemoteConnectCommandArgs {
    #[arg(long, value_enum, default_value_t = RemoteKind::Dbgsrv)]
    kind: RemoteKind,
    #[arg(long, help = "Target machine name or address")]
    server: String,
    #[arg(short = 't', long, default_value = "tcp:port=5005")]
    transport: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RemoteKind {
    Dbgsrv,
    Ntsd,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliDumpKind {
    Mini,
    Full,
}

#[derive(Debug, Args)]
struct WindbgCommonArgs {
    #[arg(long = "install-dir")]
    install_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Accepted for command symmetry; windbg-tool emits JSON by default"
    )]
    json: bool,
}

#[derive(Debug, Args)]
struct WindbgInstallArgs {
    #[arg(long = "install-dir")]
    install_dir: Option<PathBuf>,
    #[arg(long)]
    force: bool,
    #[arg(
        long,
        help = "Accepted for command symmetry; windbg-tool emits JSON by default"
    )]
    json: bool,
}

#[derive(Debug, Args)]
struct WindbgRunArgs {
    #[arg(long = "install-dir")]
    install_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Accepted for command symmetry; windbg-tool emits JSON by default"
    )]
    json: bool,
    #[arg(last = true, trailing_var_arg = true)]
    args: Vec<String>,
}

#[derive(Debug, Args)]
struct RecipeArgs {
    #[arg(
        help = "Optional recipe id or tag to filter, for example remote-debugging or stack-corruption"
    )]
    topic: Option<String>,
}

#[derive(Debug, Args)]
struct ContextSnapshotArgs {
    #[arg(short = 's', long)]
    session: Option<u64>,
    #[arg(short = 'c', long)]
    cursor: Option<u64>,
}

#[derive(Debug, Args, Clone)]
struct DebugSubjectArgs {
    #[arg(short = 's', long, help = "TTD session id")]
    session: Option<u64>,
    #[arg(short = 'c', long, help = "TTD cursor id")]
    cursor: Option<u64>,
    #[arg(
        short = 't',
        long = "target",
        help = "Daemon-owned live or dump target id"
    )]
    target: Option<u64>,
}

#[derive(Debug, Args)]
struct DebugCapabilitiesArgs {
    #[command(flatten)]
    subject: DebugSubjectArgs,
}

#[derive(Debug, Args)]
struct DebugSnapshotArgs {
    #[command(flatten)]
    subject: DebugSubjectArgs,
    #[arg(long, default_value_t = 16)]
    max_frames: u32,
    #[arg(long, default_value_t = 64)]
    max_modules: usize,
    #[arg(long, default_value_t = 64)]
    max_threads: usize,
    #[arg(long, default_value_t = 8)]
    disasm_count: u32,
    #[arg(long, default_value_t = 2000)]
    section_timeout_ms: u64,
    #[arg(long, help = "Only include these snapshot sections; can be repeated")]
    include: Vec<String>,
    #[arg(long, help = "Exclude these snapshot sections; can be repeated")]
    exclude: Vec<String>,
}

#[derive(Debug, Args)]
struct DebugLogSummarizeArgs {
    #[arg(
        long,
        help = "JSONL action log path; defaults to WINDBG_TOOL_ACTION_LOG"
    )]
    path: Option<PathBuf>,
    #[arg(long, default_value_t = 20)]
    max: usize,
}

#[derive(Debug, Args)]
struct TriageArgs {
    #[command(flatten)]
    subject: DebugSubjectArgs,
    #[arg(long, default_value_t = 16)]
    max_frames: u32,
    #[arg(long, default_value_t = 32)]
    max_modules: usize,
    #[arg(long, default_value_t = 32)]
    max_threads: usize,
}

#[derive(Debug, Args)]
struct SymbolDiagnoseArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(long, help = "Module name to diagnose")]
    name: Option<String>,
    #[arg(long, help = "Address used to select a module")]
    address: Option<String>,
}

#[derive(Debug, Args)]
struct SymbolInspectArgs {
    path: PathBuf,
}

#[derive(Debug, Args)]
struct SymbolExportsArgs {
    path: PathBuf,
    #[arg(
        long,
        help = "Case-insensitive substring filter for export names or forwarders"
    )]
    filter: Option<String>,
    #[arg(long, default_value_t = 256)]
    max: usize,
}

#[derive(Debug, Args)]
struct SymbolNearestArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(
        long,
        help = "Include a bounded export sample from the selected module"
    )]
    include_exports: bool,
}

#[derive(Debug, Args)]
struct SymbolDoctorArgs {
    #[command(flatten)]
    subject: DebugSubjectArgs,
    #[arg(long, help = "Optional address for nearest symbol/source checks")]
    address: Option<String>,
}

#[derive(Debug, Args)]
struct SourceResolveArgs {
    #[arg(
        help = "Recorded source path from a PDB or debugger, for example C:\\build\\src\\foo.cpp"
    )]
    recorded_path: String,
    #[arg(
        long = "search-path",
        short = 'I',
        help = "Local source root to search"
    )]
    search_paths: Vec<PathBuf>,
    #[arg(long, default_value_t = 32)]
    max_candidates: usize,
    #[arg(long, default_value_t = 12)]
    max_depth: usize,
}

#[derive(Debug, Args)]
struct ArchitectureStateArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    thread_id: Option<u32>,
}

#[derive(Debug, Args)]
struct TargetCapabilitiesArgs {
    #[arg(short = 's', long)]
    session: Option<u64>,
    #[arg(short = 'c', long)]
    cursor: Option<u64>,
}

#[derive(Debug, Args)]
struct TargetIdArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
}

#[derive(Debug, Args)]
struct JobIdArgs {
    #[arg(short = 'j', long = "job")]
    job: u64,
}

#[derive(Debug, Args)]
struct TargetWaitArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u32,
}

#[derive(Debug, Args)]
struct TargetContinueWaitArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u32,
    #[arg(
        long,
        help = "Capture bounded debuggee output during this one continue-and-wait operation"
    )]
    capture_debuggee_output: bool,
    #[arg(long, default_value_t = 32, requires = "capture_debuggee_output")]
    max_output_records: u32,
    #[arg(long, default_value_t = 512, requires = "capture_debuggee_output")]
    max_output_chars: u32,
    #[arg(long, default_value_t = 8192, requires = "capture_debuggee_output")]
    max_total_output_chars: u32,
}

#[derive(Debug, Args)]
struct TargetAddressArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long)]
    address: String,
}

#[derive(Debug, Args)]
struct TargetMemoryReadArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
}

#[derive(Debug, Args)]
struct TargetMemoryMapArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(
        long,
        default_value_t = 256,
        value_parser = clap::value_parser!(u32).range(1..=4096),
        help = "Maximum DbgEng virtual-memory regions returned"
    )]
    region_limit: u32,
}

#[derive(Debug, Args)]
struct TargetThreadAccountingArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(
        long,
        default_value_t = 32,
        value_parser = clap::value_parser!(u32).range(1..=128),
        help = "Maximum DbgEng threads returned"
    )]
    max_threads: u32,
}

#[derive(Debug, Args)]
struct TargetModuleParametersArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(
        long = "module-base",
        required = true,
        value_name = "ADDRESS",
        help = "DbgEng-observed module base address; repeat for up to 128 distinct modules"
    )]
    module_bases: Vec<String>,
}

#[derive(Debug, Args)]
struct TargetDumpArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long, value_name = "PATH", help = "Output .dmp path")]
    output: PathBuf,
    #[arg(long, value_enum, default_value_t = CliDumpKind::Mini)]
    kind: CliDumpKind,
    #[arg(long, help = "Allow replacing an existing dump file")]
    overwrite: bool,
}

#[derive(Debug, Args)]
struct TargetStackTraceArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long, default_value_t = 32)]
    max_frames: u32,
}

#[derive(Debug, Args)]
struct TargetThreadContextArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(
        long,
        help = "DbgEng engine thread id returned by `target threads --target <id>`"
    )]
    engine_thread_id: u32,
    #[arg(long, default_value_t = 32)]
    max_frames: u32,
    #[arg(long, default_value_t = 16)]
    disassembly_count: u32,
}

#[derive(Debug, Args)]
struct TargetDisasmArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long)]
    address: Option<String>,
    #[arg(long, default_value_t = 16)]
    count: u32,
}

#[derive(Debug, Args)]
struct BreakpointSetArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long, required_unless_present = "symbol", conflicts_with = "symbol")]
    address: Option<String>,
    #[arg(
        long,
        required_unless_present = "address",
        conflicts_with = "address",
        help = "Deferred DbgEng code-breakpoint expression, for example module!symbol"
    )]
    symbol: Option<String>,
    #[arg(long, default_value = "code", value_parser = ["code", "read", "write", "execute", "read_write"])]
    kind: String,
    #[arg(long)]
    size: Option<u32>,
}

#[derive(Debug, Args)]
struct BreakpointRemoveArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long)]
    breakpoint_id: u32,
}

#[derive(Debug, Args)]
struct BreakpointEnableArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long)]
    breakpoint_id: u32,
}

#[derive(Debug, Args)]
struct BreakpointPlanArgs {
    #[command(flatten)]
    subject: DebugSubjectArgs,
    #[arg(long, help = "Address for the planned breakpoint/watchpoint")]
    address: Option<String>,
    #[arg(long, help = "Symbol expression for future symbol-breakpoint support")]
    symbol: Option<String>,
    #[arg(long, help = "Module constraint for the plan")]
    module: Option<String>,
    #[arg(long, default_value = "code", value_parser = ["code", "read", "write", "execute", "read_write"])]
    kind: String,
    #[arg(long)]
    size: Option<u32>,
    #[arg(long, value_parser = ["previous", "next"])]
    direction: Option<String>,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

#[derive(Debug, Args)]
struct DataModelEvalArgs {
    #[arg(short = 't', long = "target")]
    target: u64,
    #[arg(long)]
    expression: String,
}

#[derive(Debug, Args)]
struct DisasmArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long, help = "Address to disassemble; defaults to current cursor RIP")]
    address: Option<String>,
    #[arg(long, default_value_t = 16)]
    count: u32,
    #[arg(long, default_value_t = 128)]
    bytes: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
    #[arg(long, help = "Thread id used when resolving the default current RIP")]
    thread_id: Option<u32>,
}

#[derive(Debug, Args)]
struct LoadArgs {
    trace_path: PathBuf,
    #[arg(long = "companion-path")]
    companion_path: Option<PathBuf>,
    #[arg(long = "trace-index")]
    trace_index: Option<u32>,
    #[arg(long = "binary-path")]
    binary_paths: Vec<PathBuf>,
    #[arg(long = "symbol-path")]
    symbol_paths: Vec<String>,
    #[arg(long)]
    symcache_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct OpenArgs {
    trace_path: PathBuf,
    #[arg(long = "companion-path")]
    companion_path: Option<PathBuf>,
    #[arg(long = "trace-index")]
    trace_index: Option<u32>,
    #[arg(short = 'b', long = "binary-path")]
    binary_paths: Vec<PathBuf>,
    #[arg(long = "symbol-path")]
    symbol_paths: Vec<String>,
    #[arg(long)]
    symcache_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Optional initial cursor position as HEX:HEX, percent, or JSON object"
    )]
    position: Option<String>,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

#[derive(Debug, Args)]
struct TraceListArgs {
    trace_path: PathBuf,
    #[arg(long = "companion-path")]
    companion_path: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct IndexBuildArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(
        long = "flag",
        value_parser = [
            "delete-existing-unloadable",
            "delete_existing_unloadable",
            "temporary",
            "temporary-index-file",
            "temporary_index_file",
            "self-contained",
            "self_contained",
            "make-self-contained",
            "make_self_contained",
            "all",
            "none"
        ]
    )]
    flags: Vec<String>,
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[arg(short = 's', long)]
    session: u64,
}

#[derive(Debug, Clone, Args)]
struct CursorArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
}

#[derive(Debug, Args)]
struct SchemaArgs {
    tool: String,
}

#[derive(Debug, Args)]
struct CliSchemaArgs {
    #[arg(
        value_name = "COMMAND",
        num_args = 0..,
        trailing_var_arg = true,
        help = "Optional command path to describe, for example: memory read"
    )]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct ToolArgs {
    name: String,
    #[arg(
        long,
        default_value = "{}",
        conflicts_with = "json_file",
        help = "JSON object passed as tool arguments"
    )]
    json: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "Read tool arguments from a JSON file"
    )]
    json_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ModuleInfoArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    address: Option<String>,
}

#[derive(Debug, Args)]
struct TimelineEventsArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(long, value_parser = ["all", "modules", "threads", "exceptions", "keyframes"], default_value = "all")]
    kind: String,
    #[arg(long, default_value_t = 512)]
    max_events: usize,
}

#[derive(Debug, Args)]
struct ExceptionFocusArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(
        long,
        default_value_t = 0,
        help = "Zero-based index from `exceptions --session <id>`"
    )]
    index: usize,
}

#[derive(Debug, Args)]
struct ModuleAuditArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(
        short = 'c',
        long,
        help = "Use cursor-local module state instead of trace-wide modules"
    )]
    cursor: Option<u64>,
    #[arg(long, default_value_t = 32)]
    max_suspicious: usize,
}

#[derive(Debug, Args)]
struct ModuleSearchOrderArgs {
    #[arg(help = "DLL basename, for example foo.dll")]
    dll: String,
    #[arg(
        long,
        help = "Application directory used for application-local DLL probing"
    )]
    app_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Current directory used by unsafe legacy DLL search behavior"
    )]
    current_dir: Option<PathBuf>,
    #[arg(long, help = "Limit PATH directory expansion")]
    max_path_dirs: Option<usize>,
}

#[derive(Debug, Args)]
struct AddressInfoArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
}

#[derive(Debug, Args)]
struct PositionSetArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(
        long,
        help = "Position as HEX:HEX, percent 0-100, or JSON position object"
    )]
    position: String,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

#[derive(Debug, Args)]
struct StepArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long, value_parser = ["forward", "backward"])]
    direction: Option<String>,
    #[arg(long, value_parser = ["step", "trace"])]
    kind: Option<String>,
    #[arg(long)]
    count: Option<u32>,
}

#[derive(Debug, Args)]
struct ReplayToArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    position: String,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

#[derive(Debug, Args)]
struct RegisterContextArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    thread_id: Option<u32>,
}

#[derive(Debug, Args)]
struct StackReadArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    size: Option<u32>,
    #[arg(long)]
    offset_from_sp: Option<i64>,
    #[arg(long)]
    decode_pointers: bool,
}

#[derive(Debug, Args)]
struct StackRecoverArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    size: Option<u32>,
    #[arg(long)]
    offset_from_sp: Option<i64>,
    #[arg(long, default_value_t = 32)]
    max_candidates: usize,
    #[arg(long, default_value_t = 0.50)]
    min_confidence: f64,
    #[arg(
        long,
        help = "Call address classification for each recovered candidate"
    )]
    target_info: bool,
}

#[derive(Debug, Args)]
struct StackBacktraceArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long, default_value_t = 4096)]
    size: u32,
    #[arg(long)]
    offset_from_sp: Option<i64>,
    #[arg(long, default_value_t = 32)]
    max_frames: usize,
    #[arg(long, default_value_t = 0.50)]
    min_confidence: f64,
    #[arg(long, help = "Call address classification for each frame target")]
    target_info: bool,
}

#[derive(Debug, Args)]
struct MemoryReadArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryRangeArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    max_bytes: Option<u32>,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryBufferArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long)]
    max_ranges: Option<u32>,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryClassifyArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryDumpArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, default_value = "db", value_parser = ["db", "dq", "ascii", "utf16"])]
    format: String,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct ObjectVtableArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(
        long,
        help = "Object/interface pointer whose first pointer-sized field is a vtable"
    )]
    address: String,
    #[arg(long, default_value_t = 16)]
    entries: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryStringsArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, default_value = "both", value_parser = ["ascii", "utf16", "both"])]
    encoding: String,
    #[arg(long, default_value_t = 4)]
    min_len: usize,
    #[arg(long, default_value_t = 64)]
    max_strings: usize,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryDpsArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, default_value_t = 8)]
    pointer_size: u32,
    #[arg(long, help = "Classify each non-null pointer target with address info")]
    target_info: bool,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryChaseArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long, default_value_t = 8)]
    depth: u32,
    #[arg(long, default_value_t = 0)]
    offset: u64,
    #[arg(long, default_value_t = 8)]
    pointer_size: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
    #[arg(long, help = "Classify each non-null target address with address info")]
    target_info: bool,
}

#[derive(Debug, Args)]
struct WatchpointArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, value_parser = [
        "read",
        "write",
        "execute",
        "code_fetch",
        "overwrite",
        "data_mismatch",
        "new_data",
        "redundant_data",
        "read_write",
        "all"
    ])]
    access: String,
    #[arg(long, value_parser = ["previous", "next"])]
    direction: String,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

#[derive(Debug, Args)]
struct SweepWatchMemoryArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, value_parser = [
        "read",
        "write",
        "execute",
        "code_fetch",
        "overwrite",
        "data_mismatch",
        "new_data",
        "redundant_data",
        "read_write",
        "all"
    ])]
    access: String,
    #[arg(long, value_parser = ["previous", "next"])]
    direction: String,
    #[arg(long)]
    thread_unique_id: Option<u64>,
    #[arg(long, default_value_t = 16)]
    max_hits: usize,
    #[arg(long, help = "Run the sweep as a daemon-owned background job")]
    background: bool,
}

pub async fn run() -> i32 {
    let started = Instant::now();
    let result = dispatch::run_cli().await;
    let exit_code = match result {
        Ok(()) => 0,
        Err(error) => {
            let output = OutputOptions::from_env_and_args();
            let failure = classify_error(error);
            if let Err(print_error) = print_failure(&failure, &output) {
                eprintln!("Error: {}", failure.message);
                eprintln!("Caused by: {print_error}");
            }
            failure.exit_code()
        }
    };
    if let Err(error) = append_action_log(exit_code, started) {
        eprintln!("Warning: failed to append action log: {error}");
    }
    exit_code
}

async fn target_capabilities_and_print(
    pipe: String,
    args: TargetCapabilitiesArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe.clone());
    let daemon_targets = call_status_value(client.targets().await);
    let selected_ttd = if let Some(session) = args.session {
        let capabilities = call_status_value(
            client
                .call_tool(session_call("ttd_capabilities", SessionArgs { session }))
                .await,
        );
        let architecture = if let Some(cursor) = args.cursor {
            Some(call_status_value(
                client
                    .call_tool(register_context_call(RegisterContextArgs {
                        session,
                        cursor,
                        thread_id: None,
                    }))
                    .await,
            ))
        } else {
            None
        };
        Some(json!({
            "session_id": session,
            "cursor_id": args.cursor,
            "capabilities": capabilities,
            "architecture": architecture
        }))
    } else {
        None
    };

    print_value(
        json!({
            "selected_ttd": selected_ttd,
            "daemon_targets": daemon_targets,
            "backend_contracts": capability_catalog(),
            "target_kinds": [
                {
                    "kind": "ttd_trace",
                    "status": "implemented",
                    "entry": "open/load via daemon",
                    "supports": ["sessions", "cursors", "memory", "registers_x64", "timeline", "watchpoints", "disassembly_x64"]
                },
                {
                    "kind": "live_dbgeng_one_shot",
                    "status": "partial",
                    "entry": ["live launch", "dump create"],
                    "supports": ["launch", "initial_debug_event_status", "detach_or_terminate", "process_dump_create"],
                    "missing": ["persistence", "attach", "interactive session control"]
                },
                {
                    "kind": "live_dbgeng_daemon",
                    "status": "partial",
                    "entry": ["live start", "live attach", "target ..."],
                    "supports": [
                        "launch_or_attach",
                        "session_list",
                        "status",
                        "wait",
                        "continue",
                        "step_into",
                        "registers",
                        "last_event",
                        "memory",
                        "modules",
                        "threads",
                        "thread_context",
                        "stack",
                        "symbol_lookup",
                        "source_lookup",
                        "disassembly",
                        "breakpoints",
                        "expression_evaluation",
                        "dump_write"
                    ],
                    "missing": ["event_streaming", "step_over", "step_out", "symbol_breakpoints", "output_capture"]
                },
                {
                    "kind": "dump",
                    "status": "partial",
                    "entry": ["dump open", "target ..."],
                    "supports": [
                        "dump_open",
                        "status",
                        "memory",
                        "modules",
                        "threads",
                        "registers",
                        "stack",
                        "thread_context",
                        "symbols",
                        "source",
                        "disassembly",
                        "expression_evaluation"
                    ],
                    "missing": ["write_actions", "breakpoint_control", "event_wait"]
                },
                {
                    "kind": "target_model",
                    "status": "partial",
                    "entry": ["datamodel eval"],
                    "missing": ["DbgEng dx object graphs", "TargetModel SDK component hosting"]
                }
            ],
            "service_axes": ["memory", "registers", "modules", "threads", "events", "symbols", "stack", "disassembly", "breakpoints"],
            "notes": [
                "Use this command before assuming a command works across TTD, live, dump, and future target model sessions.",
                "TTD replay remains backed by the TTD Replay API; live/dump work should use DbgEng/DbgHelp abstractions."
            ]
        }),
        output,
    )
}

async fn debug_capabilities_and_print(
    pipe: String,
    args: DebugCapabilitiesArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let subject = resolve_debug_subject(&args.subject, false)?;
    let selected = match subject {
        Some(DebugSubject::Ttd { session, cursor }) => {
            let capabilities = call_status_value(
                client
                    .call_tool(session_call("ttd_capabilities", SessionArgs { session }))
                    .await,
            );
            let architecture = if let Some(cursor) = cursor {
                Some(call_status_value(
                    architecture_state_value(
                        &client,
                        ArchitectureStateArgs {
                            session,
                            cursor,
                            thread_id: None,
                        },
                    )
                    .await,
                ))
            } else {
                None
            };
            Some(json!({
                "subject": debug_subject_value(&DebugSubject::Ttd { session, cursor }),
                "capabilities": capabilities,
                "architecture": architecture,
                "matrix": capability_contract("ttd_cursor")
            }))
        }
        Some(DebugSubject::Target { target }) => {
            let status =
                call_status_value(client.call_tool(target_call("target_status", target)).await);
            let backend = dbgeng_backend_for_status(&status);
            Some(json!({
                "subject": debug_subject_value(&DebugSubject::Target { target }),
                "status": status,
                "matrix": capability_contract(backend)
            }))
        }
        None => None,
    };
    print_value(
        json!({
            "schema_version": 1,
            "canonical_command": "debug capabilities",
            "selected": selected,
            "backend_matrix": capability_catalog(),
            "safe_command_taxonomy": safe_command_taxonomy()
        }),
        output,
    )
}

fn dbgeng_backend_for_status(status: &Value) -> &'static str {
    if status.pointer("/value/target/kind").and_then(Value::as_str) == Some("dump") {
        "dbgeng_dump"
    } else {
        "dbgeng_live"
    }
}

async fn debug_snapshot_and_print(
    pipe: String,
    args: DebugSnapshotArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(debug_snapshot_value(pipe, args).await?, output)
}

fn debug_log_summarize_and_print(
    args: DebugLogSummarizeArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(debug_log_summary_value(args)?, output)
}

async fn debug_snapshot_value(pipe: String, args: DebugSnapshotArgs) -> anyhow::Result<Value> {
    let subject = resolve_debug_subject(&args.subject, true)?
        .context("debug snapshot requires either --target or --session plus --cursor")?;
    match subject {
        DebugSubject::Ttd { session, cursor } => {
            let cursor = cursor.context("debug snapshot requires --cursor with --session")?;
            debug_ttd_snapshot_value(pipe, session, cursor, args).await
        }
        DebugSubject::Target { target } => debug_target_snapshot_value(pipe, target, args).await,
    }
}

async fn debug_ttd_snapshot_value(
    pipe: String,
    session: u64,
    cursor: u64,
    args: DebugSnapshotArgs,
) -> anyhow::Result<Value> {
    let legacy = context_snapshot_value(
        pipe,
        ContextSnapshotArgs {
            session: Some(session),
            cursor: Some(cursor),
        },
    )
    .await?;
    let mut sections = Map::new();
    add_legacy_section(&mut sections, "trace_info", &legacy, "info");
    add_legacy_section(&mut sections, "capabilities", &legacy, "debug capabilities");
    add_legacy_section(&mut sections, "position", &legacy, "position get");
    add_legacy_section(&mut sections, "active_threads", &legacy, "active-threads");
    add_legacy_section(&mut sections, "stack", &legacy, "stack info");
    add_legacy_section(
        &mut sections,
        "architecture_state",
        &legacy,
        "architecture state",
    );
    add_legacy_section(
        &mut sections,
        "current_disassembly",
        &legacy,
        "disasm --session <id> --cursor <id>",
    );
    add_legacy_section(&mut sections, "nearest_symbol", &legacy, "symbols nearest");
    add_legacy_section(&mut sections, "command_line", &legacy, "command-line");
    add_legacy_section(
        &mut sections,
        "timeline_summary",
        &legacy,
        "timeline events",
    );
    filter_sections(&mut sections, &args.include, &args.exclude);
    Ok(json!({
        "schema_version": 1,
        "canonical_command": "debug snapshot",
        "subject": debug_subject_value(&DebugSubject::Ttd { session, cursor: Some(cursor) }),
        "stability": "replayable_cursor",
        "section_timeout_ms": args.section_timeout_ms,
        "sections": sections,
        "diagnostics": [],
        "next_recommended_safe_commands": [
            format!("windbg-tool debug capabilities --session {session} --cursor {cursor}"),
            format!("windbg-tool timeline events --session {session}"),
            format!("windbg-tool stack backtrace --session {session} --cursor {cursor}")
        ],
        "legacy_snapshot": legacy
    }))
}

async fn debug_target_snapshot_value(
    pipe: String,
    target: u64,
    args: DebugSnapshotArgs,
) -> anyhow::Result<Value> {
    let client = DaemonClient::new(pipe);
    let mut sections = Map::new();
    let subject = DebugSubject::Target { target };
    if snapshot_section_enabled(&args, "status") {
        let started = Instant::now();
        sections.insert(
            "status".to_string(),
            composite_section(
                started,
                call_status_value(client.call_tool(target_call("target_status", target)).await),
                Some("target status --target <id>"),
                None,
            ),
        );
    }
    if snapshot_section_enabled(&args, "capabilities") {
        sections.insert(
            "capabilities".to_string(),
            json!({
                "status": "ok",
                "duration_ms": 0,
                "truncated": false,
                "value": {
                    "selection": "target kind is resolved by debug capabilities --target <id>",
                    "candidates": [
                        capability_contract("dbgeng_live"),
                        capability_contract("dbgeng_dump")
                    ]
                },
                "diagnostics": [],
                "command": "debug capabilities --target <id>"
            }),
        );
    }
    if snapshot_section_enabled(&args, "registers") {
        let started = Instant::now();
        sections.insert(
            "registers".to_string(),
            composite_section(
                started,
                call_status_value(
                    client
                        .call_tool(target_call("target_core_registers", target))
                        .await,
                ),
                Some("target registers --target <id>"),
                None,
            ),
        );
    }
    if snapshot_section_enabled(&args, "event") {
        let started = Instant::now();
        sections.insert(
            "event".to_string(),
            composite_section(
                started,
                call_status_value(
                    client
                        .call_tool(target_call("target_last_event", target))
                        .await,
                ),
                Some("target event --target <id>"),
                None,
            ),
        );
    }
    if snapshot_section_enabled(&args, "threads") {
        let started = Instant::now();
        sections.insert(
            "threads".to_string(),
            composite_section(
                started,
                call_status_value(
                    client
                        .call_tool(target_call("target_list_threads", target))
                        .await,
                ),
                Some("target threads --target <id>"),
                Some(args.max_threads),
            ),
        );
    }
    if snapshot_section_enabled(&args, "modules") {
        let started = Instant::now();
        sections.insert(
            "modules".to_string(),
            composite_section(
                started,
                call_status_value(
                    client
                        .call_tool(target_call("target_list_modules", target))
                        .await,
                ),
                Some("target modules --target <id>"),
                Some(args.max_modules),
            ),
        );
    }
    if snapshot_section_enabled(&args, "stack") {
        let started = Instant::now();
        sections.insert(
            "stack".to_string(),
            composite_section(
                started,
                call_status_value(
                    client
                        .call_tool(target_stack_call(TargetStackTraceArgs {
                            target,
                            max_frames: args.max_frames,
                        }))
                        .await,
                ),
                Some("target stack --target <id>"),
                Some(args.max_frames as usize),
            ),
        );
    }
    if snapshot_section_enabled(&args, "disassembly") {
        let started = Instant::now();
        sections.insert(
            "disassembly".to_string(),
            composite_section(
                started,
                call_status_value(
                    client
                        .call_tool(target_disasm_call(TargetDisasmArgs {
                            target,
                            address: None,
                            count: args.disasm_count,
                        })?)
                        .await,
                ),
                Some("target disasm --target <id>"),
                Some(args.disasm_count as usize),
            ),
        );
    }
    if snapshot_section_enabled(&args, "breakpoints") {
        let started = Instant::now();
        sections.insert(
            "breakpoints".to_string(),
            composite_section(
                started,
                call_status_value(
                    client
                        .call_tool(target_call("target_list_breakpoints", target))
                        .await,
                ),
                Some("breakpoint list --target <id>"),
                None,
            ),
        );
    }
    if snapshot_section_enabled(&args, "symbol_source") {
        sections.insert(
            "symbol_source".to_string(),
            symbol_source_doctor_value(&client, &subject, None).await,
        );
    }
    Ok(json!({
        "schema_version": 1,
        "canonical_command": "debug snapshot",
        "subject": debug_subject_value(&subject),
        "stability": "stopped_or_best_effort_live_state",
        "section_timeout_ms": args.section_timeout_ms,
        "sections": sections,
        "diagnostics": [
            diagnostic_item(
                "debug.snapshot.live_consistency",
                "info",
                "Live target sections are best-effort.",
                "If another actor continues or steps the target while the snapshot is collected, sections may describe adjacent target states.",
                "high",
                None,
            )
        ],
        "next_recommended_safe_commands": [
            format!("windbg-tool debug capabilities --target {target}"),
            format!("windbg-tool target stack --target {target}"),
            format!("windbg-tool breakpoint plan --target {target} --address <addr>")
        ]
    }))
}

async fn symbols_doctor_and_print(
    pipe: String,
    args: SymbolDoctorArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let subject = resolve_debug_subject(&args.subject, true)?
        .context("symbols doctor requires either --target or --session plus --cursor")?;
    let address = args
        .address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    print_value(
        json!({
            "schema_version": 1,
            "subject": debug_subject_value(&subject),
            "doctor": symbol_source_doctor_value(&client, &subject, address).await
        }),
        output,
    )
}

async fn triage_and_print(
    pipe: String,
    kind: &'static str,
    args: TriageArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let snapshot = debug_snapshot_value(
        pipe,
        DebugSnapshotArgs {
            subject: args.subject,
            max_frames: args.max_frames,
            max_modules: args.max_modules,
            max_threads: args.max_threads,
            disasm_count: 8,
            section_timeout_ms: 2000,
            include: Vec::new(),
            exclude: Vec::new(),
        },
    )
    .await?;
    print_value(triage_value(kind, snapshot), output)
}

async fn breakpoint_plan_and_print(
    _pipe: String,
    args: BreakpointPlanArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(breakpoint_plan_value(args)?, output)
}

async fn run_mcp_stdio() -> anyhow::Result<()> {
    let server = TtdMcpServer::default();
    let service = server
        .serve(stdio())
        .await
        .context("stdio MCP transport failed")?;
    service
        .waiting()
        .await
        .context("stdio MCP service failed")?;
    Ok(())
}

async fn open_and_print(
    pipe: String,
    args: OpenArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let load = client
        .call_tool(load_call(LoadArgs {
            trace_path: args.trace_path,
            companion_path: args.companion_path,
            trace_index: args.trace_index,
            binary_paths: args.binary_paths,
            symbol_paths: args.symbol_paths,
            symcache_dir: args.symcache_dir,
        }))
        .await?;
    let session_id = load["session_id"]
        .as_u64()
        .context("ttd_load_trace response did not include session_id")?;
    let cursor = client
        .call_tool(session_call(
            "ttd_cursor_create",
            SessionArgs {
                session: session_id,
            },
        ))
        .await?;
    let cursor_id = cursor["cursor_id"]
        .as_u64()
        .context("ttd_cursor_create response did not include cursor_id")?;

    let position = if let Some(position) = args.position {
        Some(
            client
                .call_tool(position_set_call(PositionSetArgs {
                    session: session_id,
                    cursor: cursor_id,
                    position,
                    thread_unique_id: args.thread_unique_id,
                })?)
                .await?,
        )
    } else {
        None
    };

    print_value(
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "load": load,
            "cursor": cursor,
            "position": position,
        }),
        output,
    )
}

async fn context_snapshot_and_print(
    pipe: String,
    args: ContextSnapshotArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(context_snapshot_value(pipe, args).await?, output)
}

async fn context_snapshot_value(pipe: String, args: ContextSnapshotArgs) -> anyhow::Result<Value> {
    let client = DaemonClient::new(pipe.clone());
    let sessions = client.sessions().await?;
    let selected = select_snapshot_handles(&sessions, args)?;
    let mut snapshot = json!({
        "daemon": call_status_value(DaemonClient::new(pipe).health().await),
        "sessions": sessions,
        "selected": selected,
        "recipes": [
            "windbg-tool recipes crash-triage",
            "windbg-tool recipes stack-corruption",
            "windbg-tool recipes symbol-health",
            "windbg-tool recipes memory-provenance"
        ],
    });

    if let Some(session_id) = selected["session_id"].as_u64() {
        snapshot["trace_info"] = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_trace_info",
                    SessionArgs {
                        session: session_id,
                    },
                ))
                .await,
        );
        snapshot["capabilities"] = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_capabilities",
                    SessionArgs {
                        session: session_id,
                    },
                ))
                .await,
        );
        if let Some(cursor_id) = selected["cursor_id"].as_u64() {
            let cursor_args = CursorArgs {
                session: session_id,
                cursor: cursor_id,
            };
            snapshot["position"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_position_get", cursor_args.clone()))
                    .await,
            );
            snapshot["active_threads"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_active_threads", cursor_args.clone()))
                    .await,
            );
            snapshot["stack"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_stack_info", cursor_args.clone()))
                    .await,
            );
            snapshot["architecture_state"] = call_status_value(
                architecture_state_value(
                    &client,
                    ArchitectureStateArgs {
                        session: session_id,
                        cursor: cursor_id,
                        thread_id: None,
                    },
                )
                .await,
            );
            let current_disassembly = call_status_value(
                disasm_value(
                    &client,
                    &DisasmArgs {
                        session: session_id,
                        cursor: cursor_id,
                        address: None,
                        count: 4,
                        bytes: 64,
                        policy: None,
                        thread_id: None,
                    },
                )
                .await,
            );
            let nearest_symbol_args =
                current_disassembly["value"]["address"]
                    .as_u64()
                    .map(|address| SymbolNearestArgs {
                        session: session_id,
                        cursor: cursor_id,
                        address: format!("0x{address:X}"),
                        include_exports: false,
                    });
            snapshot["current_disassembly"] = current_disassembly;
            if let Some(args) = nearest_symbol_args {
                snapshot["nearest_symbol"] =
                    call_status_value(nearest_symbol_value(&client, &args).await);
            }
            snapshot["command_line"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_command_line", cursor_args))
                    .await,
            );
        }
        snapshot["timeline_summary"] = call_status_value(
            timeline_events_value(
                &client,
                &TimelineEventsArgs {
                    session: session_id,
                    kind: "all".to_string(),
                    max_events: 16,
                },
            )
            .await,
        );
    }

    Ok(snapshot)
}

async fn symbols_diagnose_and_print(
    pipe: String,
    args: SymbolDiagnoseArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    if args.name.is_some() && args.address.is_some() {
        bail!("symbols diagnose accepts either --name or --address, not both")
    }
    let client = DaemonClient::new(pipe);
    let trace_info = client
        .call_tool(session_call(
            "ttd_trace_info",
            SessionArgs {
                session: args.session,
            },
        ))
        .await;
    let capabilities = client
        .call_tool(session_call(
            "ttd_capabilities",
            SessionArgs {
                session: args.session,
            },
        ))
        .await;
    let module_scope = symbol_module_scope(&client, &args).await?;
    let checks = symbol_diagnostic_checks(capabilities.as_ref().ok(), &module_scope);
    print_value(
        json!({
            "session_id": args.session,
            "trace_info": call_status_value(trace_info),
            "capabilities": call_status_value(capabilities),
            "module_scope": module_scope,
            "checks": checks,
            "next_steps": [
                "Confirm symbols.symbol_path includes the expected symbol server or private symbol path.",
                "Confirm symbols.image_path includes local binaries when stack walking or disassembly is low fidelity.",
                "Use modules/module info to select a narrower module before future PDB/source diagnostics.",
                "Use windbg-tool recipes symbol-health for the broader TimDbg workflow."
            ]
        }),
        output,
    )
}

async fn symbol_module_scope(
    client: &DaemonClient,
    args: &SymbolDiagnoseArgs,
) -> anyhow::Result<Value> {
    if args.name.is_none() && args.address.is_none() {
        let modules = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_list_modules",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        let pe_diagnostics = modules["value"]["modules"]
            .as_array()
            .map(|modules| session_pe_diagnostics(modules))
            .unwrap_or_else(|| {
                json!({
                    "ok": false,
                    "error": "module list is unavailable"
                })
            });
        return Ok(json!({
            "kind": "session",
            "modules": modules,
            "pe_diagnostics": pe_diagnostics
        }));
    }

    let mut object = session_object(args.session);
    insert_option(&mut object, "name", args.name.clone().map(Value::String));
    insert_option(
        &mut object,
        "address",
        args.address
            .as_deref()
            .map(parse_u64_argument)
            .transpose()?
            .map(Value::from),
    );
    let module = call_status_value(
        client
            .call_tool(ToolCall {
                name: "ttd_module_info".to_string(),
                arguments: Value::Object(object),
            })
            .await,
    );
    let pe_diagnostics = module["value"]["module"]
        .as_object()
        .map(|_| module_pe_diagnostics(&module["value"]["module"]))
        .unwrap_or_else(|| {
            json!({
                "ok": false,
                "error": "module info is unavailable"
            })
        });
    Ok(json!({
        "kind": if args.name.is_some() { "module_name" } else { "module_address" },
        "module": module,
        "pe_diagnostics": pe_diagnostics
    }))
}

fn symbols_exports_and_print(
    args: SymbolExportsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max <= 10_000,
        "symbols exports --max must not exceed 10000"
    );
    let exports = read_export_symbols(&args.path)?;
    let filter = args.filter.as_ref().map(|value| value.to_ascii_lowercase());
    let filtered = filter_exports(&exports, filter.as_deref());
    let values = filtered
        .iter()
        .take(args.max)
        .map(|export| export_symbol_value(export))
        .collect::<Vec<_>>();
    print_value(
        json!({
            "path": args.path,
            "total_exports": exports.len(),
            "filtered_exports": filtered.len(),
            "max": args.max,
            "returned": values.len(),
            "limit": args.max,
            "truncated": filtered.len() > args.max,
            "exports": values,
        }),
        output,
    )
}

async fn symbols_nearest_and_print(
    pipe: String,
    args: SymbolNearestArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(nearest_symbol_value(&client, &args).await?, output)
}

async fn nearest_symbol_value(
    client: &DaemonClient,
    args: &SymbolNearestArgs,
) -> anyhow::Result<Value> {
    let address_info = client
        .call_tool(address_info_call(AddressInfoArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address.clone(),
        }))
        .await?;
    let Some(module) = address_info["module"].as_object() else {
        return Ok(json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": parse_u64_argument(&args.address)?,
            "address_info": address_info,
            "symbol": null,
            "reason": "address did not resolve to a loaded module"
        }));
    };
    let Some(path) = module.get("path").and_then(Value::as_str) else {
        return Ok(json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address_info": address_info,
            "symbol": null,
            "reason": "module path is not available"
        }));
    };
    let rva = module
        .get("rva")
        .and_then(Value::as_u64)
        .context("address_info module did not include an RVA")?;
    let path = PathBuf::from(path);
    let exports = read_export_symbols(&path)?;
    let nearest = nearest_export(&exports, rva as u32);
    let export_sample = args.include_exports.then(|| {
        exports
            .iter()
            .take(64)
            .map(export_symbol_value)
            .collect::<Vec<_>>()
    });
    let nearest_value = nearest.map(|export| {
        let displacement = rva.saturating_sub(export.rva as u64);
        json!({
            "export": export_symbol_value(export),
            "displacement": displacement,
            "displacement_hex": format!("{displacement:X}"),
            "display": export_display_name(export, displacement),
            "confidence": if export.forwarder.is_some() { "forwarder" } else { "export_nearest" }
        })
    });

    Ok(json!({
        "session_id": args.session,
        "cursor_id": args.cursor,
        "address": parse_u64_argument(&args.address)?,
        "address_info": address_info,
        "module_path": path,
        "rva": rva,
        "rva_hex": format!("{rva:X}"),
        "symbol": nearest_value,
        "exports": {
            "count": exports.len(),
            "sample": export_sample,
            "sample_limit": if args.include_exports { 64 } else { 0 },
            "sample_truncated": args.include_exports && exports.len() > 64
        },
        "notes": [
            "Nearest export is not the same as private PDB symbol lookup.",
            "Use this as a low-fidelity fallback when private symbols are unavailable."
        ]
    }))
}

fn session_pe_diagnostics(modules: &[Value]) -> Value {
    const MAX_PARSED_MODULES: usize = 32;

    let mut with_path_count = 0usize;
    let mut local_file_count = 0usize;
    let mut parsed_count = 0usize;
    let mut samples = Vec::new();

    for module in modules {
        let Some(path) = module_path(module) else {
            continue;
        };
        with_path_count += 1;
        let path = PathBuf::from(path);
        if !path.exists() {
            continue;
        }
        local_file_count += 1;
        if samples.len() >= MAX_PARSED_MODULES {
            continue;
        }
        let diagnostic = module_pe_diagnostics(module);
        if diagnostic["ok"].as_bool() == Some(true) {
            parsed_count += 1;
        }
        samples.push(diagnostic);
    }

    json!({
        "ok": true,
        "total_modules": modules.len(),
        "modules_with_path": with_path_count,
        "local_files": local_file_count,
        "parsed_count": parsed_count,
        "sample_limit": MAX_PARSED_MODULES,
        "truncated": local_file_count > MAX_PARSED_MODULES,
        "samples": samples,
        "hint": "Use symbols diagnose --name <module> or --address <addr> for a single-module PE/PDB identity."
    })
}

fn module_pe_diagnostics(module: &Value) -> Value {
    let name = module["name"].as_str().unwrap_or_default();
    let Some(path) = module_path(module) else {
        return json!({
            "ok": false,
            "module": name,
            "reason": "module path is not available"
        });
    };
    let path = PathBuf::from(path);
    if !path.exists() {
        return json!({
            "ok": false,
            "module": name,
            "path": path,
            "reason": "module binary is not available at this path"
        });
    }

    match diagnose_pe(&path) {
        Ok(pe) => json!({
            "ok": true,
            "module": name,
            "path": path,
            "pe": pe
        }),
        Err(error) => json!({
            "ok": false,
            "module": name,
            "path": path,
            "error": error.to_string()
        }),
    }
}

fn module_path(module: &Value) -> Option<&str> {
    module["path"].as_str().filter(|path| !path.is_empty())
}

fn audit_modules(modules: &[Value], max_suspicious: usize) -> Value {
    let mut missing_path = 0usize;
    let mut local_file_missing = 0usize;
    let mut user_writable_path = 0usize;
    let mut temp_path = 0usize;
    let mut network_path = 0usize;
    let mut outside_windows_dir = 0usize;
    let mut suspicious = Vec::new();
    let mut names: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    let windows_dir = std::env::var("WINDIR")
        .or_else(|_| std::env::var("SystemRoot"))
        .unwrap_or_else(|_| String::from(r"C:\Windows"))
        .to_ascii_lowercase();

    for module in modules {
        let name = module["name"].as_str().unwrap_or_default();
        names
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(json!({
                "name": name,
                "path": module_path(module),
                "base_address": module["base_address"],
                "size": module["size"],
            }));

        let mut reasons = Vec::new();
        let Some(path) = module_path(module) else {
            missing_path += 1;
            reasons.push("missing_module_path");
            push_suspicious_module(&mut suspicious, module, reasons, max_suspicious);
            continue;
        };
        let lower = path.to_ascii_lowercase();
        let path_buf = PathBuf::from(path);
        if lower.starts_with(r"\\") {
            network_path += 1;
            reasons.push("network_path");
        }
        if lower.contains(r"\users\") || lower.contains(r"\programdata\") {
            user_writable_path += 1;
            reasons.push("user_or_programdata_path");
        }
        if lower.contains(r"\temp\")
            || lower.contains(r"\tmp\")
            || lower.contains(r"\appdata\local\temp\")
            || lower.contains(r"\downloads\")
        {
            temp_path += 1;
            reasons.push("temp_or_download_path");
        }
        if path_buf.is_absolute() && !lower.starts_with(&windows_dir) {
            outside_windows_dir += 1;
            reasons.push("outside_windows_directory");
        }
        if !path_buf.exists() {
            local_file_missing += 1;
            reasons.push("binary_not_available_locally");
        }
        if !reasons.is_empty() {
            push_suspicious_module(&mut suspicious, module, reasons, max_suspicious);
        }
    }

    let duplicates = names
        .into_iter()
        .filter_map(|(name, instances)| {
            let distinct_paths = instances
                .iter()
                .filter_map(|instance| instance["path"].as_str())
                .map(|path| path.to_ascii_lowercase())
                .collect::<std::collections::BTreeSet<_>>();
            (instances.len() > 1 && distinct_paths.len() > 1).then(|| {
                json!({
                    "name": name,
                    "instances": instances,
                    "distinct_path_count": distinct_paths.len(),
                    "reason": "same module basename loaded from multiple paths"
                })
            })
        })
        .collect::<Vec<_>>();

    json!({
        "summary": {
            "missing_path": missing_path,
            "binary_not_available_locally": local_file_missing,
            "network_path": network_path,
            "user_or_programdata_path": user_writable_path,
            "temp_or_download_path": temp_path,
            "outside_windows_directory": outside_windows_dir,
            "duplicate_name_groups": duplicates.len(),
        },
        "suspicious_modules": suspicious,
        "suspicious_truncated": suspicious.len() >= max_suspicious,
        "duplicate_name_groups": duplicates,
        "safe_next_steps": [
            "Run symbols diagnose for suspicious module paths that are available locally.",
            "Use memory range/classify around unexpected executable addresses.",
            "Use TTD watchpoints to identify writes to suspicious dispatch tables or return addresses."
        ]
    })
}

fn push_suspicious_module(
    suspicious: &mut Vec<Value>,
    module: &Value,
    reasons: Vec<&'static str>,
    max_suspicious: usize,
) {
    if suspicious.len() >= max_suspicious {
        return;
    }
    suspicious.push(json!({
        "name": module["name"],
        "path": module["path"],
        "base_address": module["base_address"],
        "size": module["size"],
        "load_position": module["load_position"],
        "unload_position": module["unload_position"],
        "reasons": reasons,
    }));
}

fn collect_timeline_events(events: &mut Vec<Value>, kind: &str, source: &Value, array_key: &str) {
    let Some(items) = timeline_source_items(source, array_key) else {
        return;
    };
    for item in items {
        let position = item
            .get("position")
            .cloned()
            .or_else(|| {
                item.get("module")
                    .and_then(|module| module.get("load_position"))
                    .cloned()
            })
            .unwrap_or(Value::Null);
        events.push(json!({
            "kind": kind,
            "event_kind": item.get("kind").cloned().unwrap_or(Value::Null),
            "position": position,
            "sequence": position.get("sequence").cloned().unwrap_or(Value::Null),
            "payload": item,
        }));
    }
}

fn collect_keyframe_events(events: &mut Vec<Value>, source: &Value) {
    let Some(items) = timeline_source_items(source, "keyframes") else {
        return;
    };
    for position in items {
        events.push(json!({
            "kind": "keyframe",
            "event_kind": "keyframe",
            "position": position,
            "sequence": position.get("sequence").cloned().unwrap_or(Value::Null),
            "payload": position,
        }));
    }
}

fn timeline_source_items<'a>(source: &'a Value, array_key: &str) -> Option<&'a Vec<Value>> {
    let value = source.get("value")?;
    value
        .get(array_key)
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
}

fn timeline_source_summary(source: &Value, array_key: &str) -> Value {
    if source["ok"].as_bool() != Some(true) {
        return source.clone();
    }

    let item_count = timeline_source_items(source, array_key).map_or(0, Vec::len);
    json!({
        "ok": true,
        "item_count": item_count,
        "items_omitted": true
    })
}

fn timeline_sequence(event: &Value) -> u64 {
    event["sequence"].as_u64().unwrap_or(u64::MAX)
}

fn normalize_dll_name(name: &str) -> anyhow::Result<String> {
    let trimmed = name.trim();
    ensure!(!trimmed.is_empty(), "DLL name must not be empty");
    ensure!(
        !trimmed.contains('\\') && !trimmed.contains('/'),
        "DLL search-order diagnostics require a basename, not a path"
    );
    if Path::new(trimmed).extension().is_some() {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("{trimmed}.dll"))
    }
}

fn search_candidate(order: usize, kind: &str, directory: &Path, dll: &str) -> Value {
    let candidate = directory.join(dll);
    let risk = directory_risk(directory);
    json!({
        "order": order,
        "kind": kind,
        "directory": directory,
        "candidate": candidate,
        "exists": candidate.exists(),
        "risk": risk,
    })
}

fn directory_risk(directory: &Path) -> &'static str {
    let lower = directory.to_string_lossy().to_ascii_lowercase();
    let windows_dir = std::env::var("WINDIR")
        .or_else(|_| std::env::var("SystemRoot"))
        .unwrap_or_else(|_| String::from(r"C:\Windows"))
        .to_ascii_lowercase();
    if lower.starts_with(&windows_dir) {
        "system_controlled"
    } else if lower.starts_with(r"\\") {
        "network_path"
    } else if lower.contains(r"\temp\")
        || lower.contains(r"\tmp\")
        || lower.contains(r"\downloads\")
        || lower.contains(r"\appdata\local\temp\")
    {
        "temp_or_download_path"
    } else if lower.contains(r"\users\") || lower.contains(r"\programdata\") {
        "user_or_programdata_path"
    } else {
        "review_path_acl"
    }
}

fn filter_exports<'a>(exports: &'a [ExportSymbol], filter: Option<&str>) -> Vec<&'a ExportSymbol> {
    exports
        .iter()
        .filter(|export| {
            let Some(filter) = filter else {
                return true;
            };
            export
                .name
                .as_deref()
                .is_some_and(|name| name.to_ascii_lowercase().contains(filter))
                || export
                    .forwarder
                    .as_deref()
                    .is_some_and(|name| name.to_ascii_lowercase().contains(filter))
                || export.ordinal.to_string().contains(filter)
        })
        .collect()
}

fn nearest_export(exports: &[ExportSymbol], rva: u32) -> Option<&ExportSymbol> {
    exports
        .iter()
        .filter(|export| export.forwarder.is_none() && export.rva <= rva)
        .max_by_key(|export| export.rva)
}

fn export_display_name(export: &ExportSymbol, displacement: u64) -> String {
    let name = export
        .name
        .clone()
        .unwrap_or_else(|| format!("#{}", export.ordinal));
    if displacement == 0 {
        name
    } else {
        format!("{name}+0x{displacement:x}")
    }
}

fn symbol_diagnostic_checks(capabilities: Option<&Value>, module_scope: &Value) -> Value {
    let symbols = capabilities.and_then(|value| value.get("symbols"));
    let native = capabilities
        .and_then(|value| value.get("native"))
        .and_then(Value::as_bool);
    let symbol_path = symbols
        .and_then(|value| value.get("symbol_path"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let image_path = symbols
        .and_then(|value| value.get("image_path"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_symbols = symbols
        .and_then(|value| value.get("microsoft_public_symbols"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let binary_path_count = symbols
        .and_then(|value| value.get("binary_path_count"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let module_data_available = module_scope["modules"]["ok"].as_bool() == Some(true)
        || module_scope["module"]["ok"].as_bool() == Some(true);
    let pe_diagnostics = &module_scope["pe_diagnostics"];
    let pe_identity_available = pe_diagnostics["ok"].as_bool() == Some(true)
        && (pe_diagnostics["parsed_count"].as_u64().unwrap_or_default() > 0
            || pe_diagnostics["pe"].is_object());
    let pdb_identity_available = pe_diagnostics["pe"]["codeview"].is_object()
        || pe_diagnostics["samples"].as_array().is_some_and(|samples| {
            samples
                .iter()
                .any(|sample| sample["pe"]["codeview"].is_object())
        });

    json!([
        {
            "id": "native-replay",
            "status": if native == Some(true) { "pass" } else { "warn" },
            "evidence": native,
            "why_it_matters": "Native replay is required for real module inventories and cursor-backed symbol context."
        },
        {
            "id": "symbol-path",
            "status": if symbol_path.is_empty() { "warn" } else { "pass" },
            "evidence": symbol_path,
            "why_it_matters": "DbgHelp/SymSrv need a symbol path before public or private PDBs can be found."
        },
        {
            "id": "microsoft-public-symbols",
            "status": if public_symbols { "pass" } else { "info" },
            "evidence": public_symbols,
            "why_it_matters": "Public Microsoft symbols are enough for many Windows module/function names."
        },
        {
            "id": "binary-path",
            "status": if !image_path.is_empty() || binary_path_count > 0 { "pass" } else { "info" },
            "evidence": {
                "image_path": image_path,
                "binary_path_count": binary_path_count
            },
            "why_it_matters": "Local binaries improve stack walking, disassembly, and symbol-server binary fallback workflows."
        },
        {
            "id": "module-data",
            "status": if module_data_available { "pass" } else { "warn" },
            "evidence": module_scope,
            "why_it_matters": "Module identity is the anchor for timestamp/size/PDB/source diagnostics."
        },
        {
            "id": "pe-image-identity",
            "status": if pe_identity_available { "pass" } else { "info" },
            "evidence": pe_diagnostics,
            "why_it_matters": "PE timestamp and SizeOfImage form the symbol-server key for image/binary lookup."
        },
        {
            "id": "pdb-codeview-identity",
            "status": if pdb_identity_available { "pass" } else { "info" },
            "evidence": pe_diagnostics,
            "why_it_matters": "RSDS GUID plus age form the symbol-server key for PDB lookup."
        },
        {
            "id": "source-fidelity",
            "status": "future",
            "evidence": "PDB source-file and checksum inspection is not implemented yet.",
            "why_it_matters": "Source paths should be resolved with trailing-component matching and verified with hashes where available."
        }
    ])
}

fn source_resolve(args: SourceResolveArgs) -> anyhow::Result<Value> {
    let recorded_components = normalized_components(&PathBuf::from(&args.recorded_path));
    if recorded_components.is_empty() {
        bail!("recorded source path has no usable path components")
    }
    let search_paths = if args.search_paths.is_empty() {
        vec![std::env::current_dir().context("resolving current directory")?]
    } else {
        args.search_paths
    };

    let mut matches = Vec::new();
    let recorded_path = PathBuf::from(&args.recorded_path);
    if recorded_path.exists() {
        matches.push(source_match_value(
            &recorded_path,
            &recorded_components,
            true,
        ));
    }

    for root in &search_paths {
        collect_source_matches(
            root,
            &recorded_components,
            args.max_candidates,
            args.max_depth,
            0,
            &mut matches,
        )?;
    }
    matches.sort_by(|left, right| {
        right["matched_components"]
            .as_u64()
            .cmp(&left["matched_components"].as_u64())
            .then_with(|| left["path"].as_str().cmp(&right["path"].as_str()))
    });
    matches.dedup_by(|left, right| left["path"] == right["path"]);
    if matches.len() > args.max_candidates {
        matches.truncate(args.max_candidates);
    }
    let best = matches.first().cloned();

    Ok(json!({
        "recorded_path": args.recorded_path,
        "recorded_components": recorded_components,
        "search_paths": search_paths,
        "best": best,
        "matches": matches,
        "strategy": "Trailing path-component match, preferring the candidate with the longest matching suffix.",
        "source_hash_verification": "future"
    }))
}

async fn architecture_state_and_print(
    pipe: String,
    args: ArchitectureStateArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(architecture_state_value(&client, args).await?, output)
}

async fn architecture_state_value(
    client: &DaemonClient,
    args: ArchitectureStateArgs,
) -> anyhow::Result<Value> {
    let capabilities = call_status_value(
        client
            .call_tool(session_call(
                "ttd_capabilities",
                SessionArgs {
                    session: args.session,
                },
            ))
            .await,
    );
    let registers = call_status_value(
        client
            .call_tool(cursor_call(
                "ttd_registers",
                CursorArgs {
                    session: args.session,
                    cursor: args.cursor,
                },
            ))
            .await,
    );
    let context = call_status_value(
        client
            .call_tool(register_context_call(RegisterContextArgs {
                session: args.session,
                cursor: args.cursor,
                thread_id: args.thread_id,
            }))
            .await,
    );
    let architecture = context["value"]["architecture"]
        .as_str()
        .or_else(|| capabilities["value"]["architecture"].as_str())
        .unwrap_or("unknown");
    let x64 = architecture.eq_ignore_ascii_case("x64")
        || context["value"]["registers"]["rip"].is_u64()
        || registers["value"]["program_counter"].is_u64();

    Ok(json!({
        "session_id": args.session,
        "cursor_id": args.cursor,
        "thread_id": args.thread_id,
        "architecture": architecture,
        "detected": {
            "x64": x64,
            "source": if context["ok"].as_bool() == Some(true) { "register_context" } else { "capabilities_or_fallback" }
        },
        "supported_helpers": {
            "compact_registers": registers["ok"],
            "x64_register_context": x64 && context["ok"].as_bool() == Some(true),
            "x64_disassembly": x64,
            "stack_info": true,
            "peb_teb_helpers": x64
        },
        "unsupported_or_partial": [
            {
                "architecture": "x86",
                "status": "not_yet_exposed",
                "note": "TTD headers can represent multiple architectures, but the current Rust register/disassembly model is x64-first."
            },
            {
                "architecture": "arm64",
                "status": "not_yet_exposed",
                "note": "ARM64 register and disassembly models need a separate decoder and typed register schema."
            }
        ],
        "capabilities": capabilities,
        "registers": registers,
        "register_context": context,
        "next_steps": [
            "Use register-context for full x64 scalar/SIMD state when available.",
            "Use disasm only when x64_disassembly is true.",
            "Treat unsupported architectures as explicit gaps instead of retrying x64-only commands."
        ]
    }))
}

fn collect_source_matches(
    root: &PathBuf,
    recorded_components: &[String],
    max_candidates: usize,
    max_depth: usize,
    depth: usize,
    matches: &mut Vec<Value>,
) -> anyhow::Result<()> {
    if matches.len() >= max_candidates || depth > max_depth || !root.exists() {
        return Ok(());
    }
    let metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            matches.push(json!({
                "path": root,
                "error": error.to_string()
            }));
            return Ok(());
        }
    };
    if metadata.is_file() {
        let matched = matching_suffix_len(&normalized_components(root), recorded_components);
        if matched > 0 {
            matches.push(source_match_value(root, recorded_components, false));
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            matches.push(json!({
                "path": root,
                "error": error.to_string()
            }));
            return Ok(());
        }
    };
    for entry in entries {
        if matches.len() >= max_candidates {
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                matches.push(json!({ "error": error.to_string() }));
                continue;
            }
        };
        collect_source_matches(
            &entry.path(),
            recorded_components,
            max_candidates,
            max_depth,
            depth + 1,
            matches,
        )?;
    }
    Ok(())
}

fn source_match_value(path: &PathBuf, recorded_components: &[String], direct: bool) -> Value {
    let candidate_components = normalized_components(path);
    let matched_components = matching_suffix_len(&candidate_components, recorded_components);
    json!({
        "path": path,
        "direct": direct,
        "matched_components": matched_components,
        "candidate_components": candidate_components,
    })
}

fn matching_suffix_len(candidate: &[String], recorded: &[String]) -> usize {
    candidate
        .iter()
        .rev()
        .zip(recorded.iter().rev())
        .take_while(|(candidate, recorded)| candidate == recorded)
        .count()
}

fn normalized_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect()
}

fn select_snapshot_handles(sessions: &Value, args: ContextSnapshotArgs) -> anyhow::Result<Value> {
    if args.cursor.is_some() && args.session.is_none() {
        bail!("context snapshot requires --session when --cursor is supplied")
    }
    let session_id = args.session.or_else(|| {
        sessions["sessions"]
            .as_array()
            .and_then(|items| items.first())
            .and_then(|session| session["session_id"].as_u64())
    });
    let cursor_id = args.cursor.or_else(|| {
        let session_id = session_id?;
        sessions["sessions"].as_array()?.iter().find_map(|session| {
            (session["session_id"].as_u64() == Some(session_id))
                .then(|| {
                    session["cursors"]
                        .as_array()
                        .and_then(|cursors| cursors.first())
                        .and_then(|cursor| cursor["cursor_id"].as_u64())
                })
                .flatten()
        })
    });
    Ok(json!({
        "session_id": session_id,
        "cursor_id": cursor_id,
        "selection": if args.session.is_some() || args.cursor.is_some() { "explicit" } else { "first_available" }
    }))
}

fn call_status_value(result: anyhow::Result<Value>) -> Value {
    match result {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
}

#[derive(Debug, Clone)]
enum DebugSubject {
    Ttd { session: u64, cursor: Option<u64> },
    Target { target: u64 },
}

fn resolve_debug_subject(
    args: &DebugSubjectArgs,
    require_cursor: bool,
) -> anyhow::Result<Option<DebugSubject>> {
    if args.target.is_some() && (args.session.is_some() || args.cursor.is_some()) {
        bail!("choose either --target or --session/--cursor, not both");
    }
    if let Some(target) = args.target {
        return Ok(Some(DebugSubject::Target { target }));
    }
    match (args.session, args.cursor) {
        (Some(session), Some(cursor)) => Ok(Some(DebugSubject::Ttd {
            session,
            cursor: Some(cursor),
        })),
        (Some(session), None) if !require_cursor => Ok(Some(DebugSubject::Ttd {
            session,
            cursor: None,
        })),
        (Some(_), None) => bail!("--cursor is required with --session for this command"),
        (None, Some(_)) => bail!("--session is required with --cursor"),
        (None, None) => Ok(None),
    }
}

fn debug_subject_value(subject: &DebugSubject) -> Value {
    match subject {
        DebugSubject::Ttd { session, cursor } => json!({
            "kind": if cursor.is_some() { "ttd_cursor" } else { "ttd_session" },
            "backend": "ttd_replay",
            "ids": {
                "session_id": session,
                "cursor_id": cursor
            },
            "stability": "replayable"
        }),
        DebugSubject::Target { target } => json!({
            "kind": "target",
            "backend": "dbgeng_target",
            "ids": {
                "target_id": target
            },
            "stability": "target_state"
        }),
    }
}

pub(super) fn fix_item(
    description: impl Into<String>,
    command: Option<impl Into<String>>,
) -> Value {
    json!({
        "description": description.into(),
        "command": command.map(Into::into)
    })
}

pub(super) fn diagnostic_item(
    id: impl Into<String>,
    severity: impl Into<String>,
    summary: impl Into<String>,
    detail: impl Into<String>,
    confidence: impl Into<String>,
    fix: Option<Value>,
) -> Value {
    json!({
        "id": id.into(),
        "severity": severity.into(),
        "summary": summary.into(),
        "detail": detail.into(),
        "confidence": confidence.into(),
        "fix": fix
    })
}

fn composite_section(
    started: Instant,
    result: Value,
    command: Option<&str>,
    limit: Option<usize>,
) -> Value {
    let ok = result["ok"].as_bool().unwrap_or(false);
    let value = result.get("value").cloned().unwrap_or(Value::Null);
    let returned = estimate_returned(&value);
    let diagnostics = if ok {
        Vec::new()
    } else {
        vec![diagnostic_item(
            "debug.section.error",
            "warning",
            "Snapshot section failed.",
            result["error"].as_str().unwrap_or("unknown error"),
            "high",
            None,
        )]
    };
    json!({
        "status": if ok { "ok" } else { "error" },
        "duration_ms": started.elapsed().as_millis(),
        "truncated": limit.zip(returned).is_some_and(|(limit, returned)| returned >= limit),
        "returned": returned,
        "limit": limit,
        "value": if ok { value } else { Value::Null },
        "error": if ok { Value::Null } else { result["error"].clone() },
        "diagnostics": diagnostics,
        "command": command
    })
}

fn add_legacy_section(
    sections: &mut Map<String, Value>,
    name: &str,
    legacy: &Value,
    command: &str,
) {
    if let Some(value) = legacy.get(name) {
        let ok = value["ok"].as_bool().unwrap_or(!value.is_null());
        sections.insert(
            name.to_string(),
            json!({
                "status": if ok { "ok" } else { "error" },
                "duration_ms": Value::Null,
                "truncated": value["value"]["truncated"].as_bool().unwrap_or(false),
                "returned": estimate_returned(value.get("value").unwrap_or(value)),
                "limit": Value::Null,
                "value": value.get("value").cloned().unwrap_or_else(|| value.clone()),
                "error": if ok { Value::Null } else { value["error"].clone() },
                "diagnostics": [],
                "command": command
            }),
        );
    }
}

fn estimate_returned(value: &Value) -> Option<usize> {
    if let Some(returned) = value.get("returned").and_then(Value::as_u64) {
        return Some(returned as usize);
    }
    if let Some(array) = value.as_array() {
        return Some(array.len());
    }
    if let Some(object) = value.as_object() {
        for key in [
            "frames",
            "modules",
            "threads",
            "breakpoints",
            "events",
            "instructions",
            "exports",
            "strings",
        ] {
            if let Some(array) = object.get(key).and_then(Value::as_array) {
                return Some(array.len());
            }
        }
    }
    None
}

fn snapshot_section_enabled(args: &DebugSnapshotArgs, name: &str) -> bool {
    (args.include.is_empty() || args.include.iter().any(|item| item == name))
        && !args.exclude.iter().any(|item| item == name)
}

fn filter_sections(sections: &mut Map<String, Value>, include: &[String], exclude: &[String]) {
    if !include.is_empty() {
        sections.retain(|name, _| include.iter().any(|item| item == name));
    }
    if !exclude.is_empty() {
        sections.retain(|name, _| !exclude.iter().any(|item| item == name));
    }
}

fn safe_command_taxonomy() -> Value {
    json!({
        "safe": "Read-only commands that inspect local state, debugger state, or generate command lines.",
        "mutating": "Commands that alter cursor position, target execution, breakpoints, or write dumps.",
        "destructive": "Commands that terminate, close, cancel, or otherwise end target/debugger resources."
    })
}

async fn symbol_source_doctor_value(
    client: &DaemonClient,
    subject: &DebugSubject,
    address: Option<u64>,
) -> Value {
    match subject {
        DebugSubject::Ttd { session, cursor } => {
            let nearest = if let (Some(cursor), Some(address)) = (cursor, address) {
                call_status_value(
                    nearest_symbol_value(
                        client,
                        &SymbolNearestArgs {
                            session: *session,
                            cursor: *cursor,
                            address: format!("0x{address:X}"),
                            include_exports: false,
                        },
                    )
                    .await,
                )
            } else {
                json!({
                    "ok": false,
                    "error": "Pass --cursor and --address for nearest-symbol/source quality checks."
                })
            };
            json!({
                "status": "ok",
                "duration_ms": Value::Null,
                "truncated": false,
                "value": {
                    "trace_info": call_status_value(client.call_tool(session_call("ttd_trace_info", SessionArgs { session: *session })).await),
                    "nearest_symbol": nearest
                },
                "diagnostics": [
                    diagnostic_item(
                        "symbols.source.follow_up",
                        "info",
                        "Use focused symbol/source commands for deeper diagnosis.",
                        "This doctor composes currently available trace and nearest-symbol checks.",
                        "high",
                        Some(fix_item(
                            "Run symbols diagnose or symbols nearest with the current address.",
                            Some("windbg-tool symbols diagnose --session <id>")
                        ))
                    )
                ],
                "command": "symbols doctor"
            })
        }
        DebugSubject::Target { target } => {
            let symbol = if let Some(address) = address {
                call_status_value(
                    client
                        .call_tool(
                            target_address_call(
                                "target_symbol_by_offset",
                                TargetAddressArgs {
                                    target: *target,
                                    address: format!("0x{address:X}"),
                                },
                            )
                            .expect("address was formatted as hex"),
                        )
                        .await,
                )
            } else {
                json!({ "ok": false, "error": "Pass --address for target symbol/source checks." })
            };
            let source = if let Some(address) = address {
                call_status_value(
                    client
                        .call_tool(
                            target_address_call(
                                "target_source_by_offset",
                                TargetAddressArgs {
                                    target: *target,
                                    address: format!("0x{address:X}"),
                                },
                            )
                            .expect("address was formatted as hex"),
                        )
                        .await,
                )
            } else {
                json!({ "ok": false, "error": "Pass --address for target source checks." })
            };
            json!({
                "status": "ok",
                "duration_ms": Value::Null,
                "truncated": false,
                "value": {
                    "symbol": symbol,
                    "source": source
                },
                "diagnostics": [
                    diagnostic_item(
                        "symbols.source.address_optional",
                        "info",
                        "Current-PC symbol/source checks need an address when registers do not expose one.",
                        "Pass --address or use debug snapshot disassembly to identify a program counter.",
                        "medium",
                        Some(fix_item(
                            "Run target registers or target disasm, then pass --address.",
                            Some("windbg-tool symbols doctor --target <id> --address <pc>")
                        ))
                    )
                ],
                "command": "symbols doctor"
            })
        }
    }
}

fn triage_value(kind: &'static str, snapshot: Value) -> Value {
    let mut hypotheses = Vec::new();
    let diagnostics = snapshot["diagnostics"].clone();
    match kind {
        "symbol_health" => hypotheses.push(json!({
            "id": "symbol_health.requires_review",
            "confidence": "medium",
            "summary": "Review symbol_source and nearest_symbol evidence before trusting names or source paths.",
            "supporting_sections": ["symbol_source", "nearest_symbol"]
        })),
        "loader" => hypotheses.push(json!({
            "id": "loader.module_review",
            "confidence": "medium",
            "summary": "Review module paths, duplicate module names, and recently loaded modules for loader anomalies.",
            "supporting_sections": ["modules", "timeline_summary"]
        })),
        "deadlock" | "hang" => hypotheses.push(json!({
            "id": "hang.stack_threads_review",
            "confidence": "low",
            "summary": "Thread and stack evidence can identify waits, but this command does not yet prove lock ownership.",
            "supporting_sections": ["threads", "stack"]
        })),
        "access_violation" | "crash" => hypotheses.push(json!({
            "id": "crash.exception_stack_review",
            "confidence": "medium",
            "summary": "Inspect exception/timeline, current disassembly, stack, and symbol quality before assigning root cause.",
            "supporting_sections": ["timeline_summary", "current_disassembly", "stack", "symbol_source"]
        })),
        "memory_corruption" => hypotheses.push(json!({
            "id": "memory_corruption.needs_watchpoint",
            "confidence": "low",
            "summary": "Snapshot evidence can identify suspicious pointers or stacks; use watchpoint planning before replaying or mutating.",
            "supporting_sections": ["stack", "modules", "disassembly"]
        })),
        _ => {}
    }
    json!({
        "schema_version": 1,
        "kind": kind,
        "evidence": {
            "snapshot": snapshot
        },
        "hypotheses": hypotheses,
        "diagnostics": diagnostics,
        "next_actions": [
            { "safety": "safe", "command": "windbg-tool debug snapshot", "reason": "Refresh bounded evidence." },
            { "safety": "safe", "command": "windbg-tool symbols doctor", "reason": "Validate symbol/source quality." },
            { "safety": "safe", "command": "windbg-tool breakpoint plan", "reason": "Plan breakpoints/watchpoints before mutating the target." }
        ],
        "limitations": [
            "Triage commands report evidence and hypotheses, not final root-cause verdicts.",
            "Backend support varies; inspect debug capabilities for unsupported operations."
        ]
    })
}

fn breakpoint_plan_value(args: BreakpointPlanArgs) -> anyhow::Result<Value> {
    let subject = resolve_debug_subject(&args.subject, false)?
        .context("breakpoint plan requires --target or --session/--cursor")?;
    if args.address.is_none() && args.symbol.is_none() {
        bail!("breakpoint plan requires --address or --symbol");
    }
    let address = args
        .address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    let kind = args.kind.as_str();
    let subject_value = debug_subject_value(&subject);
    let (supported, command, reason, safety) = match (&subject, kind) {
        (DebugSubject::Target { target }, "code") => (
            args.address.is_some(),
            json!(["windbg-tool", "breakpoint", "set", "--target", target, "--address", args.address.clone().unwrap_or_else(|| "<address>".to_string())]),
            if args.symbol.is_some() {
                "Symbol breakpoint setting is not first-class yet; resolve the symbol to an address first."
            } else {
                "DbgEng live targets support code breakpoints by address."
            },
            "mutating",
        ),
        (DebugSubject::Target { .. }, _) => (
            false,
            Value::Null,
            "Data watchpoints are not currently exposed for daemon-owned live targets.",
            "unsupported",
        ),
        (DebugSubject::Ttd { session, cursor }, "write" | "read" | "read_write") => (
            args.address.is_some() && cursor.is_some(),
            json!(["windbg-tool", "replay", "watch-memory", "--session", session, "--cursor", cursor, "--address", args.address.clone().unwrap_or_else(|| "<address>".to_string()), "--size", args.size.unwrap_or(1), "--access", kind, "--direction", args.direction.clone().unwrap_or_else(|| "previous".to_string())]),
            "TTD memory watchpoints replay to the next or previous matching access.",
            "bounded_replay",
        ),
        (DebugSubject::Ttd { .. }, "code" | "execute") => (
            false,
            Value::Null,
            "TTD code breakpoints are not exposed as persistent breakpoints; use position/disassembly/replay commands instead.",
            "unsupported",
        ),
        _ => (
            false,
            Value::Null,
            "Requested breakpoint/watchpoint kind is not supported on this subject.",
            "unsupported",
        ),
    };
    Ok(json!({
        "schema_version": 1,
        "subject": subject_value,
        "request": {
            "address": address.map(|value| format!("0x{value:X}")),
            "symbol": args.symbol,
            "module": args.module,
            "kind": kind,
            "size": args.size,
            "direction": args.direction,
            "thread_unique_id": args.thread_unique_id
        },
        "supported": supported,
        "safety": safety,
        "reason": reason,
        "command": command,
        "diagnostics": if supported {
            Vec::<Value>::new()
        } else {
            vec![diagnostic_item(
                "breakpoint.plan.unsupported",
                "warning",
                "Requested plan is not directly supported.",
                reason,
                "high",
                None,
            )]
        }
    }))
}

fn action_log_path_from_env() -> Option<PathBuf> {
    std::env::var_os("WINDBG_TOOL_ACTION_LOG")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn append_action_log(exit_code: i32, started: Instant) -> anyhow::Result<()> {
    let Some(path) = action_log_path_from_env() else {
        return Ok(());
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating action log directory {}", parent.display()))?;
    }
    let full_args = std::env::var_os("WINDBG_TOOL_ACTION_LOG_FULL").is_some();
    let entry = json!({
        "schema_version": 1,
        "timestamp_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
        "command_path": command_path_from_args(std::env::args().skip(1)),
        "args": if full_args {
            std::env::args().skip(1).collect::<Vec<_>>()
        } else {
            Vec::<String>::new()
        },
        "args_redacted": !full_args,
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "duration_ms": started.elapsed().as_millis()
    });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening action log {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&entry)?)
        .with_context(|| format!("writing action log {}", path.display()))
}

fn command_path_from_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut path = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            break;
        }
        if arg.starts_with("--") {
            if !path.is_empty() {
                break;
            }
            if !arg.contains('=') && option_takes_value(&arg) {
                skip_next = true;
            }
            continue;
        }
        if arg.starts_with('-') {
            if !path.is_empty() {
                break;
            }
            continue;
        }
        path.push(arg);
        if path.len() >= expected_command_path_depth(&path) {
            break;
        }
    }
    path
}

fn expected_command_path_depth(path: &[String]) -> usize {
    match path {
        [] => 1,
        [command] if command_requires_subcommand(command) => 2,
        [command, subcommand] if command == "debug" && subcommand == "log" => 3,
        [command, ..] if command_requires_subcommand(command) => 2,
        _ => 1,
    }
}

fn command_requires_subcommand(command: &str) -> bool {
    matches!(
        command,
        "trace"
            | "daemon"
            | "dbgeng"
            | "live"
            | "dump"
            | "remote"
            | "debug"
            | "triage"
            | "windbg"
            | "context"
            | "symbols"
            | "source"
            | "architecture"
            | "arch"
            | "index"
            | "events"
            | "timeline"
            | "module"
            | "cursor"
            | "position"
            | "replay"
            | "sweep"
            | "job"
            | "breakpoint"
            | "datamodel"
            | "target"
            | "stack"
            | "memory"
            | "object"
    )
}

fn option_takes_value(arg: &str) -> bool {
    !matches!(
        arg,
        "--compact" | "--raw" | "--envelope" | "--probe-connect" | "--background" | "--overwrite"
    )
}

fn debug_log_summary_value(args: DebugLogSummarizeArgs) -> anyhow::Result<Value> {
    let path = args
        .path
        .or_else(action_log_path_from_env)
        .context("debug log summarize requires --path or WINDBG_TOOL_ACTION_LOG")?;
    let file =
        fs::File::open(&path).with_context(|| format!("opening action log {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut malformed = 0_usize;
    for line in reader.lines() {
        let line = line.with_context(|| format!("reading action log {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(value) => entries.push(value),
            Err(_) => malformed += 1,
        }
    }
    let total = entries.len();
    let failed = entries
        .iter()
        .filter(|entry| !entry["ok"].as_bool().unwrap_or(false))
        .count();
    let mut recent = entries.into_iter().rev().take(args.max).collect::<Vec<_>>();
    recent.reverse();
    Ok(json!({
        "schema_version": 1,
        "path": path,
        "total_entries": total,
        "malformed_entries": malformed,
        "failed_entries": failed,
        "returned": recent.len(),
        "limit": args.max,
        "truncated": total > recent.len(),
        "recent": recent
    }))
}

async fn call_and_print(
    pipe: String,
    call: ToolCall,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(client.call_tool(call).await?, output)
}

async fn live_start_and_print(
    pipe: String,
    args: LiveSessionStartArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "live_launch_session".to_string(),
            arguments: json!({
                "command_line": args.command_line,
                "initial_break_timeout_ms": args.initial_break_timeout_ms,
                "create_process_stop": args.create_process_stop,
            }),
        },
        output,
    )
    .await
}

async fn live_attach_and_print(
    pipe: String,
    args: LiveAttachArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "live_attach_process".to_string(),
            arguments: json!({
                "process_id": args.process_id,
                "initial_break_timeout_ms": args.initial_break_timeout_ms,
            }),
        },
        output,
    )
    .await
}

async fn dump_open_and_print(
    pipe: String,
    args: DumpOpenArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "dump_open_session".to_string(),
            arguments: json!({
                "path": args.path,
                "symbol_cache": args.symbol_cache,
                "image_paths": args.image_path,
                "offline": args.offline,
            }),
        },
        output,
    )
    .await
}

async fn target_list_and_print(pipe: String, output: &OutputOptions) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(client.targets().await?, output)
}

async fn start_watch_memory_job_and_print(
    pipe: String,
    args: SweepWatchMemoryArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(pipe, watch_memory_job_call(args)?, output).await
}

fn load_call(args: LoadArgs) -> ToolCall {
    ToolCall {
        name: "ttd_load_trace".to_string(),
        arguments: json!({
            "trace_path": args.trace_path,
            "companion_path": args.companion_path,
            "trace_index": args.trace_index,
            "symbols": {
                "binary_paths": args.binary_paths,
                "symbol_paths": args.symbol_paths,
                "symcache_dir": args.symcache_dir,
            },
        }),
    }
}

fn trace_list_call(args: TraceListArgs) -> ToolCall {
    ToolCall {
        name: "ttd_trace_list".to_string(),
        arguments: json!({
            "trace_path": args.trace_path,
            "companion_path": args.companion_path,
        }),
    }
}

fn index_build_call(args: IndexBuildArgs) -> ToolCall {
    ToolCall {
        name: "ttd_build_index".to_string(),
        arguments: json!({
            "session_id": args.session,
            "flags": args.flags,
        }),
    }
}

fn tool_schema(name: &str) -> anyhow::Result<Value> {
    tools::definitions()
        .into_iter()
        .find(|tool| tool.name.as_ref() == name)
        .map(serde_json::to_value)
        .transpose()?
        .with_context(|| format!("unknown MCP tool: {name}"))
}

fn cli_schema(args: CliSchemaArgs) -> anyhow::Result<Value> {
    let command = Cli::command();
    let metadata = command_metadata();
    if args.command.is_empty() {
        let mut commands = Vec::new();
        collect_leaf_command_schemas(&command, Vec::new(), &metadata, &mut commands);
        let documented = metadata
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["command"].as_str())
                    .count()
            })
            .unwrap_or_default();
        Ok(json!({
            "schema_version": 1,
            "binary": command.get_name(),
            "commands": commands,
            "metadata_coverage": {
                "leaf_commands": commands.len(),
                "documented_commands": documented
            }
        }))
    } else {
        let (selected, path) = resolve_command_path(&command, &args.command)?;
        Ok(json!({
            "schema_version": 1,
            "binary": command.get_name(),
            "command": command_schema(selected, &path, &metadata)
        }))
    }
}

fn collect_leaf_command_schemas(
    command: &Command,
    prefix: Vec<String>,
    metadata: &Value,
    commands: &mut Vec<Value>,
) {
    for subcommand in command.get_subcommands() {
        let mut path = prefix.clone();
        path.push(subcommand.get_name().to_string());
        if subcommand.has_subcommands() {
            collect_leaf_command_schemas(subcommand, path, metadata, commands);
        } else {
            commands.push(command_schema(subcommand, &path, metadata));
        }
    }
}

fn resolve_command_path<'a>(
    command: &'a Command,
    path: &[String],
) -> anyhow::Result<(&'a Command, Vec<String>)> {
    let mut current = command;
    let mut canonical = Vec::new();
    for segment in path {
        let next = current
            .get_subcommands()
            .find(|subcommand| {
                subcommand.get_name() == segment
                    || subcommand.get_all_aliases().any(|alias| alias == segment)
            })
            .with_context(|| format!("unknown CLI command path: {}", path.join(" ")))?;
        canonical.push(next.get_name().to_string());
        current = next;
    }
    Ok((current, canonical))
}

fn command_schema(command: &Command, path: &[String], metadata: &Value) -> Value {
    let path_string = path.join(" ");
    json!({
        "path": path_string,
        "aliases": command.get_visible_aliases().collect::<Vec<_>>(),
        "about": command.get_about().map(ToString::to_string),
        "long_about": command.get_long_about().map(ToString::to_string),
        "arguments": command
            .get_arguments()
            .filter(|arg| !arg.is_hide_set())
            .map(|arg| argument_schema(command, arg))
            .collect::<Vec<_>>(),
        "subcommands": command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name())
            .collect::<Vec<_>>(),
        "metadata": command_metadata_for(metadata, &path_string)
            .unwrap_or_else(|| inferred_command_metadata(command, path))
    })
}

fn argument_schema(command: &Command, arg: &Arg) -> Value {
    let possible_values = arg
        .get_possible_values()
        .into_iter()
        .filter(|value| !value.is_hide_set())
        .map(|value| {
            json!({
                "name": value.get_name(),
                "help": value.get_help().map(ToString::to_string),
                "aliases": value.get_name_and_aliases().skip(1).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    json!({
        "id": arg.get_id().as_str(),
        "kind": if arg.is_positional() { "positional" } else if arg.get_long().is_some() || arg.get_short().is_some() { "option_or_flag" } else { "internal" },
        "long": arg.get_long(),
        "short": arg.get_short().map(|value| value.to_string()),
        "aliases": arg.get_aliases().unwrap_or_default(),
        "help": arg.get_help().map(ToString::to_string),
        "required": arg.is_required_set(),
        "global": arg.is_global_set(),
        "action": format!("{:?}", arg.get_action()),
        "num_args": arg.get_num_args().map(|range| format!("{range:?}")),
        "value_names": arg
            .get_value_names()
            .map(|names| names.iter().map(ToString::to_string).collect::<Vec<_>>())
            .unwrap_or_default(),
        "default_values": arg
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        "possible_values": possible_values,
        "conflicts_with": command
            .get_arg_conflicts_with(arg)
            .into_iter()
            .map(|arg| arg.get_id().as_str())
            .collect::<Vec<_>>()
    })
}

fn command_metadata_for(metadata: &Value, path: &str) -> Option<Value> {
    metadata
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["command"].as_str() == Some(path))
        })
        .cloned()
}

fn inferred_command_metadata(command: &Command, path: &[String]) -> Value {
    let path_string = path.join(" ");
    let first = path.first().map(String::as_str).unwrap_or_default();
    let no_daemon = matches!(
        first,
        "discover" | "cli-schema" | "recipes" | "schema" | "tools" | "remote" | "source"
    ) || matches!(
        path_string.as_str(),
        "symbols inspect"
            | "symbols exports"
            | "dbgeng server"
            | "dbgsrv"
            | "windbg status"
            | "windbg install"
            | "windbg update"
            | "windbg path"
            | "windbg run"
            | "dump inspect"
            | "dump create"
            | "live capabilities"
            | "live launch"
            | "live startup-break"
            | "live startup-profile"
            | "live startup-report"
            | "breakpoint capabilities"
            | "datamodel capabilities"
    );
    let has_session = command.get_arguments().any(|arg| arg.get_id() == "session");
    let has_cursor = command.get_arguments().any(|arg| arg.get_id() == "cursor");
    json!({
        "command": path_string,
        "requires_daemon": !no_daemon,
        "requires_native_ttd": has_session || has_cursor,
        "session_required": has_session,
        "cursor_required": has_cursor,
        "cost": if has_session || has_cursor { "depends_on_trace_and_bounds" } else { "low" },
        "safety": if path_string.contains("terminate") || path_string.contains("remove") || path_string.contains("cancel") {
            "destructive"
        } else if path_string.contains("write") || path_string.contains("dump") || path_string.contains("set") || path_string.contains("continue") || path_string.contains("step") {
            "mutating_or_side_effecting"
        } else {
            "read_only"
        },
        "source": "inferred_from_cli_shape"
    })
}

fn discover_manifest() -> Value {
    json!({
        "name": "windbg-tool",
        "purpose": "Single executable for WinDbg Time Travel Debugging MCP stdio, daemon mode, and CLI commands",
        "daemon": {
            "transport": "HTTP over Windows named pipes",
            "start": "windbg-tool daemon ensure",
            "status": "windbg-tool daemon status",
            "shutdown": "windbg-tool daemon shutdown",
            "pipe_override": "--pipe \\\\.\\pipe\\windbg-tool-custom, WINDBG_TOOL_PIPE, or legacy TTD_MCP_PIPE"
        },
        "output_controls": {
            "default": "pretty JSON",
            "envelope": "--envelope or WINDBG_TOOL_ENVELOPE=1 wraps success and error output in a stable agent contract",
            "compact": "--compact emits single-line JSON",
            "field": "--field path.to.value extracts a JSON field; with --envelope it selects from data",
            "raw": "--raw prints selected scalar fields without JSON quoting; error envelopes remain JSON"
        },
        "error_contract": {
            "envelope": { "schema_version": 1, "ok": false, "error": { "code": "daemon_unavailable", "kind": "daemon_unavailable", "message": "...", "retryable": true, "hint": "..." } },
            "exit_codes": {
                "invalid_argument": 2,
                "daemon_unavailable": 3,
                "daemon_error": 4,
                "session_not_found": 5,
                "cursor_not_found": 6,
                "timeout": 7,
                "tool_error": 8,
                "internal": 1
            }
        },
        "recommended_flow": [
            "windbg-tool daemon ensure",
            "windbg-tool --field session_id --raw open trace.run --binary-path trace.exe",
            "windbg-tool sessions",
            "windbg-tool position set --session <id> --cursor <id> --position 50",
            "windbg-tool registers --session <id> --cursor <id>"
        ],
        "command_groups": {
            "discovery": ["discover", "cli-schema [command...]", "recipes [topic]", "advise [topic]", "tools", "schema <tool>"],
            "daemon": ["daemon ensure", "daemon status", "daemon shutdown", "sessions"],
            "debug": ["debug capabilities", "debug capabilities --session <id> --cursor <id>", "debug capabilities --target <id>", "debug snapshot --session <id> --cursor <id>", "debug snapshot --target <id>", "debug log summarize"],
            "context": ["context snapshot", "context snapshot --session <id> --cursor <id>"],
            "triage": ["triage crash", "triage hang", "triage access-violation", "triage memory-corruption", "triage loader", "triage symbol-health", "triage deadlock"],
            "remote": ["remote explain", "remote doctor", "remote status", "remote plan", "remote server-command", "remote connect-command"],
            "live": [
                "live capabilities",
                "live launch --command-line <cmd> --end detach|terminate",
                "live startup-profile --command-line <cmd> [--runs <count>] [--phase-module <basename>] [--completion-module <basename> [--settle-ms <milliseconds>]]",
                "live startup-compare --baseline <path> --candidate <path>",
                "live startup-report <artifact> [--run <number>] [--format table|json]",
                "live start --command-line <cmd> [--create-process-stop]",
                "live attach --process-id <pid>"
            ],
            "dump": ["dump open <path>", "dump inspect <path>", "dump triage <path>", "dump pool-triage <path>", "dump create --process-id <pid> --output <path>"],
            "job": [
                "job list",
                "job status --job <id>",
                "job result --job <id>",
                "job cancel --job <id>",
                "sweep watch-memory --background"
            ],
            "breakpoint": [
                "breakpoint capabilities",
                "breakpoint list --target <id>",
                "breakpoint set --target <id> --address <addr>",
                "breakpoint remove --target <id> --breakpoint-id <id>",
                "breakpoint plan --target <id> --address <addr>",
                "breakpoint plan --session <id> --cursor <id> --address <addr> --kind write",
                "memory watchpoint",
                "sweep watch-memory"
            ],
            "datamodel": ["datamodel capabilities", "datamodel eval --target <id> --expression <expr>"],
            "target": [
                "target capabilities",
                "target capabilities --session <id> --cursor <id>",
                "target list",
                "target status --target <id>",
                "target close --target <id>",
                "target terminate --target <id>",
                "target wait --target <id>",
                "target continue --target <id>",
                "target step --target <id>",
                "target threads --target <id>",
                "target modules --target <id>",
                "target registers --target <id>",
                "target event --target <id>",
                "target thread --target <id> --engine-thread-id <id>",
                "target memory --target <id> --address <addr> --size <n>",
                "target memory-map --target <id> [--region-limit <n>]",
                "target address --target <id> --address <addr>",
                "target dump --target <id> --output <path>",
                "target stack --target <id>",
                "target disasm --target <id>",
                "target symbol --target <id> --address <addr>",
                "target source --target <id> --address <addr>"
            ],
            "symbols": ["symbols diagnose --session <id>", "symbols doctor --session <id> --cursor <id>", "symbols doctor --target <id> --address <addr>", "symbols diagnose --session <id> --name <module>", "symbols diagnose --session <id> --address <addr>", "symbols inspect <path>", "symbols exports <path>", "symbols nearest --session <id> --cursor <id> --address <addr>"],
            "source": ["source resolve <recorded-path> --search-path <root>"],
            "architecture": ["architecture state --session <id> --cursor <id>", "arch state --session <id> --cursor <id>"],
            "dbgeng": ["dbgeng server --transport <transport>", "dbgsrv --transport <transport>"],
            "windbg": ["windbg status", "windbg install", "windbg update", "windbg path", "windbg run -- <args>"],
            "session": ["open", "load", "close", "info", "capabilities"],
            "index": ["index status", "index stats", "index build"],
            "metadata": ["trace list", "trace-list", "threads", "modules", "keyframes", "exceptions", "events modules", "events threads", "timeline events", "module info", "module audit", "module search-order"],
            "navigation": ["cursor create", "cursor modules", "active-threads", "position get", "position set", "step", "replay capabilities", "replay to", "replay watch-memory", "sweep watch-memory"],
            "state": ["architecture state", "arch state", "registers", "register-context", "stack info", "stack read", "stack recover", "stack backtrace", "command-line", "address"],
            "disassembly": ["disasm --session <id> --cursor <id>", "u --session <id> --cursor <id> --address <addr>"],
            "memory": ["memory read", "memory range", "memory buffer", "memory dump", "memory strings", "memory dps", "memory classify", "memory chase", "memory watchpoint", "watchpoint"],
            "object": ["object vtable --session <id> --cursor <id> --address <object>"],
            "escape_hatch": ["tool <name> --json <object>", "tool <name> --json-file <path>"]
        },
        "tool_command_map": tool_command_map(),
        "command_metadata": command_metadata(),
        "action_log": {
            "enable": "Set WINDBG_TOOL_ACTION_LOG to a JSONL path.",
            "privacy_default": "Logs command path, ok/exit status, and duration; raw arguments are redacted by default.",
            "include_full_args": "Set WINDBG_TOOL_ACTION_LOG_FULL=1 only when full command-line logging is safe.",
            "summarize": "windbg-tool debug log summarize --path <log.jsonl>"
        },
        "recipes": recipes_manifest(),
        "diagnostic_guidance": diagnostic_guidance(),
        "ttd_api_coverage": ttd_api_coverage_manifest(),
        "examples": [
            {
                "goal": "Pick the right debugging workflow for a symptom",
                "command": "windbg-tool recipes diagnostic-technique"
            },
            {
                "goal": "Capture a one-shot agent context summary",
                "command": "windbg-tool debug snapshot --session 1 --cursor 1"
            },
            {
                "goal": "Discover backend-safe debugging operations",
                "command": "windbg-tool debug capabilities"
            },
            {
                "goal": "Diagnose remote-debugging readiness without mutating the remote machine",
                "command": "windbg-tool remote doctor --transport tcp:port=5005"
            },
            {
                "goal": "Plan a live breakpoint or TTD watchpoint before changing debugger state",
                "command": "windbg-tool breakpoint plan --target 1 --address 0x7ff600001000"
            },
            {
                "goal": "Start a DbgEng TCP process server",
                "command": "windbg-tool dbgeng server --transport tcp:port=5005"
            },
            {
                "goal": "Generate host/target remote-debugging commands",
                "command": "windbg-tool remote explain"
            },
            {
                "goal": "Diagnose symbol and binary readiness",
                "command": "windbg-tool symbols diagnose --session 1"
            },
            {
                "goal": "Inspect a PE image for symbol-server keys",
                "command": "windbg-tool symbols inspect C:\\Windows\\System32\\notepad.exe"
            },
            {
                "goal": "Resolve a recorded source path under a local checkout",
                "command": "windbg-tool source resolve C:\\build\\repo\\src\\main.cpp --search-path D:\\src\\repo"
            },
            {
                "goal": "Disassemble at the current TTD cursor instruction pointer",
                "command": "windbg-tool disasm --session 1 --cursor 1 --count 12"
            },
            {
                "goal": "Inspect a COM/C++-style vtable without mutating the target",
                "command": "windbg-tool object vtable --session 1 --cursor 1 --address <object>"
            },
            {
                "goal": "Recover plausible return addresses from stack memory",
                "command": "windbg-tool stack recover --session 1 --cursor 1 --target-info"
            },
            {
                "goal": "Install or update WinDbg in the per-user tool cache",
                "command": "windbg-tool windbg update"
            },
            {
                "goal": "Open a trace and capture handles",
                "command": "windbg-tool --field session_id --raw open traces\\ping\\ping01.run --binary-path traces\\ping\\ping.exe"
            },
            {
                "goal": "Inspect the schema for raw MCP memory reads",
                "command": "windbg-tool schema ttd_read_memory"
            },
            {
                "goal": "Read memory with compact JSON output",
                "command": "windbg-tool --compact memory read --session 1 --cursor 1 --address 0x7ffdf000 --size 64"
            }
        ]
    })
}

fn recipes_value(args: RecipeArgs) -> anyhow::Result<Value> {
    let recipes = recipes_manifest();
    let Some(topic) = args.topic else {
        return Ok(json!({
            "recipes": recipes,
            "usage": "windbg-tool recipes <id-or-tag>",
        }));
    };
    let topic = topic.to_ascii_lowercase();
    let matches = recipes
        .as_array()
        .into_iter()
        .flatten()
        .filter(|recipe| recipe_matches_topic(recipe, &topic))
        .cloned()
        .collect::<Vec<_>>();
    if matches.is_empty() {
        bail!("unknown recipe topic: {topic}")
    }
    Ok(json!({ "recipes": matches }))
}

fn recipe_matches_topic(recipe: &Value, topic: &str) -> bool {
    recipe["id"]
        .as_str()
        .is_some_and(|id| id.eq_ignore_ascii_case(topic))
        || recipe["tags"].as_array().is_some_and(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .any(|tag| tag.eq_ignore_ascii_case(topic))
        })
}

fn diagnostic_guidance() -> Value {
    json!({
        "principles": [
            {
                "id": "lightweight-first",
                "summary": "Start with the cheapest signal that can answer the question.",
                "use_when": ["known failure mode", "customer repro cost is high", "logs already exist"],
                "next_step": "Escalate to dumps, live debugging, or TTD only when logs/traces cannot isolate a time or state."
            },
            {
                "id": "time-vs-space",
                "summary": "Use time-oriented evidence to find when something changed; use space-oriented evidence to explain state at a point.",
                "time_tools": ["logs", "ETW/tracing", "TTD replay", "memory watchpoints"],
                "space_tools": ["crash dumps", "context snapshot", "stack/register/memory inspection"]
            },
            {
                "id": "structured-output",
                "summary": "Prefer JSON commands over terminal text so agent skills can compose results without brittle parsing.",
                "commands": ["discover", "recipes", "context snapshot", "tools", "schema <tool>"]
            }
        ],
        "safety": {
            "code_injection": "Analysis-only in windbg-tool; do not add general-purpose injection automation.",
            "registry_or_admin_changes": "Emit explicit recipes or plans unless a command name clearly states it mutates system state."
        }
    })
}

fn recipes_manifest() -> Value {
    json!([
        {
            "id": "diagnostic-technique",
            "title": "Choose the lightest diagnostic technique that can answer the question",
            "source_posts": ["why-you-should-printf", "first-post"],
            "tags": ["advisor", "logs", "tracing", "dump", "ttd", "live-debugging"],
            "problem": "The user has a symptom but has not chosen whether to use logs, dumps, live debugging, TTD, or remote debugging.",
            "guidance": [
                "Use logs or tracing first when they already contain enough temporal context.",
                "Use dumps when there is a crash/hang anchor point and state-at-time matters most.",
                "Use TTD when the important question is what changed before the anchor point.",
                "Use live or remote debugging when the process must be controlled interactively."
            ],
            "commands": ["windbg-tool discover", "windbg-tool context snapshot", "windbg-tool recipes crash-triage"]
        },
        {
            "id": "remote-debugging",
            "title": "Pick NTSD/CDB remote debugging vs DbgSrv process server",
            "source_posts": ["remote-debugging"],
            "tags": ["remote", "dbgeng", "dbgsrv", "ntsd", "cdb", "windbg"],
            "problem": "An agent needs to debug a target on another machine or in a sensitive desktop/session.",
            "guidance": [
                "Use NTSD/CDB -server when debugger brains, symbols, and extensions should live on the target and latency matters.",
                "Use DbgSrv when the target should stay minimal and symbols/extensions should stay on the host.",
                "Use WinDbg -remote for an existing NTSD/CDB remote session.",
                "Use WinDbg -premote for a DbgSrv process server that will launch or attach from the host side."
            ],
            "commands": [
                "windbg-tool dbgeng server --transport tcp:port=5005",
                "windbg-tool windbg run -- -premote tcp:port=5005,server=<target>",
                "windbg-tool recipes remote-debugging"
            ]
        },
        {
            "id": "crash-triage",
            "title": "Summarize a crash or end-of-trace state",
            "source_posts": ["writing-a-debugger-from-scratch-part-1", "writing-a-debugger-from-scratch-part-2", "debugger-lies-part-1"],
            "tags": ["crash", "triage", "exception", "stack", "registers"],
            "problem": "A trace/session is loaded and the agent needs the first actionable summary.",
            "guidance": [
                "Capture trace info, capabilities, current position, active thread state, registers, stack info, modules, and exceptions.",
                "Treat stack output as evidence, not truth; corrupted stacks can hide callers.",
                "If native replay is unavailable, stop before requesting native-only register/memory commands."
            ],
            "commands": [
                "windbg-tool context snapshot --session <id> --cursor <id>",
                "windbg-tool exceptions --session <id>",
                "windbg-tool registers --session <id> --cursor <id>",
                "windbg-tool stack info --session <id> --cursor <id>"
            ]
        },
        {
            "id": "stack-corruption",
            "title": "Find what overwrote a return address in TTD",
            "source_posts": ["debugger-lies-part-1", "writing-a-debugger-from-scratch-part-5", "writing-a-debugger-from-scratch-part-6"],
            "tags": ["ttd", "stack", "corruption", "watchpoint", "memory"],
            "problem": "The stack looks truncated, impossible, or corrupted near a crash.",
            "guidance": [
                "At the crashing position, identify the suspicious frame and return-address slot.",
                "Seek backward to the function entry if possible.",
                "Use a write watchpoint on the return-address slot to find the overwrite.",
                "Record stop position, thread, instruction, and stack bytes around the write."
            ],
            "commands": [
                "windbg-tool stack recover --session <id> --cursor <id> --target-info",
                "windbg-tool stack backtrace --session <id> --cursor <id> --target-info",
                "windbg-tool stack read --session <id> --cursor <id> --decode-pointers",
                "windbg-tool memory watchpoint --session <id> --cursor <id> --address <rsp> --size 8 --access write --direction next",
                "windbg-tool sweep watch-memory --session <id> --cursor <id> --address <rsp> --size 8 --access write --direction next --max-hits 8"
            ]
        },
        {
            "id": "symbol-health",
            "title": "Diagnose symbol and binary availability",
            "source_posts": ["symbol-indexing", "writing-a-debugger-from-scratch-part-4", "writing-a-debugger-from-scratch-part-8"],
            "tags": ["symbols", "pdb", "source", "binary", "modules"],
            "problem": "Names, stacks, source, or disassembly are missing or low fidelity.",
            "guidance": [
                "Check module timestamp/checksum/size and CodeView RSDS PDB identity when available.",
                "Remember symbol servers can serve binaries as well as PDBs; missing binaries can break stack walking.",
                "Use source path search and source hashes to avoid opening the wrong file."
            ],
            "commands": [
                "windbg-tool symbols diagnose --session <id>",
                "windbg-tool symbols inspect <path-to-exe-or-dll>",
                "windbg-tool symbols exports <path-to-exe-or-dll> --filter <name>",
                "windbg-tool symbols nearest --session <id> --cursor <id> --address <addr>",
                "windbg-tool source resolve <recorded-path> --search-path <checkout-root>",
                "windbg-tool modules --session <id>",
                "windbg-tool module info --session <id> --address <addr>",
                "windbg-tool schema ttd_module_info"
            ]
        },
        {
            "id": "memory-provenance",
            "title": "Classify unknown memory and find where it came from",
            "source_posts": ["writing-a-debugger-from-scratch-part-3", "recognizing-patterns", "useless-x86-trivia"],
            "tags": ["memory", "pointers", "strings", "code", "patterns"],
            "problem": "A byte range is suspicious and needs interpretation.",
            "guidance": [
                "Check whether values look like aligned integers, pointers, UTF-16/ASCII strings, code bytes, or high-entropy data.",
                "Use address classification before assuming a 64-bit value is a pointer, or use memory chase for bounded pointer-chain inspection.",
                "Use TTD memory provenance and watchpoints to connect a suspicious range to writes over time."
            ],
            "commands": [
                "windbg-tool address --session <id> --cursor <id> --address <addr>",
                "windbg-tool memory read --session <id> --cursor <id> --address <addr> --size 128",
                "windbg-tool memory dump --session <id> --cursor <id> --address <addr> --size 128 --format dq",
                "windbg-tool memory classify --session <id> --cursor <id> --address <addr> --size 128",
                "windbg-tool memory chase --session <id> --cursor <id> --address <addr> --depth 8 --target-info",
                "windbg-tool memory range --session <id> --cursor <id> --address <addr>",
                "windbg-tool memory buffer --session <id> --cursor <id> --address <addr> --size <n>"
            ]
        },
        {
            "id": "assembly-or-source",
            "title": "Move between instruction bytes, symbols, and source",
            "source_posts": ["fakers-guide-to-assembly", "writing-a-debugger-from-scratch-part-7", "writing-a-debugger-from-scratch-part-8"],
            "tags": ["assembly", "disassembly", "source", "instructions"],
            "problem": "Source is unavailable, misleading, or insufficient and the agent needs instruction-level truth.",
            "guidance": [
                "Prefer Intel syntax for Windows debugger workflows.",
                "Show instruction bytes, current address, decoded instruction, and nearest symbol together.",
                "When source exists, map both address-to-source and source-to-address; line mappings are not one-to-one."
            ],
            "commands": [
                "windbg-tool disasm --session <id> --cursor <id>",
                "windbg-tool u --session <id> --cursor <id> --address <rip> --count 16",
                "windbg-tool registers --session <id> --cursor <id>",
                "windbg-tool memory read --session <id> --cursor <id> --address <rip> --size 64"
            ]
        },
        {
            "id": "com-vtable",
            "title": "Investigate impossible calls through vtables or COM interfaces",
            "source_posts": ["vtables"],
            "tags": ["com", "vtable", "object", "dynamic-type"],
            "problem": "A call stack or source line appears to call the wrong method.",
            "guidance": [
                "Read the object pointer, then read the first pointer-sized field as the vtable pointer.",
                "Resolve vtable entries to symbols and confirm they live in an expected loaded image.",
                "Suspect interface layout mismatches when method ordinals point to unrelated symbols."
            ],
            "commands": [
                "windbg-tool object vtable --session <id> --cursor <id> --address <object>",
                "windbg-tool memory read --session <id> --cursor <id> --address <object> --size 8",
                "windbg-tool address --session <id> --cursor <id> --address <vtable>",
                "windbg-tool memory read --session <id> --cursor <id> --address <vtable> --size 64"
            ]
        },
        {
            "id": "injection-analysis",
            "title": "Analyze injection-like symptoms without automating injection",
            "source_posts": ["run-my-code"],
            "tags": ["injection", "modules", "memory-protection", "safety"],
            "problem": "A process may have unexpected code, DLLs, hooks, or executable memory.",
            "guidance": [
                "Do not use windbg-tool to inject arbitrary code.",
                "Inventory modules, DLL search-order clues, and executable memory regions.",
                "Classify unbacked executable memory and unexpected loaded modules as evidence for further review."
            ],
            "commands": [
                "windbg-tool modules --session <id>",
                "windbg-tool module audit --session <id>",
                "windbg-tool module search-order suspicious.dll --app-dir <app-dir>",
                "windbg-tool memory range --session <id> --cursor <id> --address <addr>",
                "windbg-tool address --session <id> --cursor <id> --address <addr>"
            ]
        }
    ])
}

fn tool_command_map() -> Value {
    json!([
        { "tool": "ttd_load_trace", "commands": ["load", "open"] },
        { "tool": "ttd_trace_list", "commands": ["trace list", "trace-list"] },
        { "tool": "ttd_close_trace", "commands": ["close"] },
        { "tool": "ttd_trace_info", "commands": ["info"] },
        { "tool": "ttd_capabilities", "commands": ["capabilities", "caps"] },
        { "tool": "ttd_index_status", "commands": ["index status"] },
        { "tool": "ttd_index_stats", "commands": ["index stats"] },
        { "tool": "ttd_build_index", "commands": ["index build"] },
        { "tool": "ttd_list_threads", "commands": ["threads"] },
        { "tool": "ttd_list_modules", "commands": ["modules", "mods"] },
        { "tool": "ttd_cursor_modules", "commands": ["cursor modules"] },
        { "tool": "ttd_list_keyframes", "commands": ["keyframes"] },
        { "tool": "ttd_module_events", "commands": ["events modules"] },
        { "tool": "ttd_thread_events", "commands": ["events threads"] },
        { "tool": "ttd_module_info", "commands": ["module info"] },
        { "tool": "ttd_address_info", "commands": ["address", "memory chase --target-info"] },
        { "tool": "ttd_active_threads", "commands": ["active-threads", "active"] },
        { "tool": "ttd_list_exceptions", "commands": ["exceptions"] },
        { "tool": "ttd_cursor_create", "commands": ["cursor create", "open"] },
        { "tool": "ttd_position_get", "commands": ["position get"] },
        { "tool": "ttd_position_set", "commands": ["position set", "open --position"] },
        { "tool": "ttd_step", "commands": ["step"] },
        { "tool": "ttd_registers", "commands": ["registers", "regs"] },
        { "tool": "ttd_register_context", "commands": ["register-context", "ctx"] },
        { "tool": "ttd_stack_info", "commands": ["stack info"] },
        { "tool": "ttd_stack_read", "commands": ["stack read"] },
        { "tool": "ttd_command_line", "commands": ["command-line", "cmdline"] },
        { "tool": "ttd_read_memory", "commands": ["memory read", "memory dump", "memory strings", "memory dps", "memory classify", "memory chase"] },
        { "tool": "ttd_memory_range", "commands": ["memory range"] },
        { "tool": "ttd_memory_buffer", "commands": ["memory buffer"] },
        { "tool": "ttd_memory_watchpoint", "commands": ["memory watchpoint", "watchpoint"] },
        { "tool": "live_launch_session", "commands": ["live start"] },
        { "tool": "live_attach_process", "commands": ["live attach"] },
        { "tool": "dump_open_session", "commands": ["dump open"] },
        { "tool": "target_write_dump", "commands": ["target dump"] },
        { "tool": "target_list", "commands": ["target list"] },
        { "tool": "target_status", "commands": ["target status"] },
        { "tool": "target_close", "commands": ["target close"] },
        { "tool": "target_terminate", "commands": ["target terminate"] },
        { "tool": "target_wait", "commands": ["target wait"] },
        { "tool": "target_continue", "commands": ["target continue"] },
        { "tool": "target_continue_wait", "commands": ["target continue-wait"] },
        { "tool": "target_step_into", "commands": ["target step"] },
        { "tool": "target_step_over", "commands": ["target step-over"] },
        { "tool": "target_core_registers", "commands": ["target registers"] },
        { "tool": "target_last_event", "commands": ["target event", "debug snapshot --include event"] },
        { "tool": "target_read_memory", "commands": ["target memory"] },
        { "tool": "target_memory_map", "commands": ["target memory-map"] },
        { "tool": "target_inspect_address", "commands": ["target address"] },
        { "tool": "target_list_threads", "commands": ["target threads"] },
        { "tool": "target_thread_accounting", "commands": ["target thread-accounting"] },
        { "tool": "target_module_parameters", "commands": ["target module-parameters"] },
        { "tool": "target_symbol_entry_range", "commands": ["target symbol-entry-range"] },
        { "tool": "target_list_modules", "commands": ["target modules"] },
        { "tool": "target_symbol_by_offset", "commands": ["target symbol"] },
        { "tool": "target_source_by_offset", "commands": ["target source"] },
        { "tool": "target_stack_trace", "commands": ["target stack"] },
        { "tool": "target_thread_context", "commands": ["target thread"] },
        { "tool": "target_disassemble", "commands": ["target disasm"] },
        { "tool": "target_list_breakpoints", "commands": ["breakpoint list"] },
        { "tool": "target_set_breakpoint", "commands": ["breakpoint set"] },
        { "tool": "target_set_breakpoint_enabled", "commands": ["breakpoint enable", "breakpoint disable"] },
        { "tool": "target_remove_breakpoint", "commands": ["breakpoint remove"] },
        { "tool": "target_evaluate_expression", "commands": ["datamodel eval"] },
        { "tool": "job_start_watch_memory_sweep", "commands": ["sweep watch-memory --background"] },
        { "tool": "job_list", "commands": ["job list"] },
        { "tool": "job_status", "commands": ["job status"] },
        { "tool": "job_result", "commands": ["job result"] },
        { "tool": "job_cancel", "commands": ["job cancel"] }
    ])
}

fn command_metadata() -> Value {
    json!([
        {
            "command": "discover",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only"
        },
        {
            "command": "open",
            "requires_daemon": true,
            "requires_native_ttd": "trace-backed sessions require native TTD; placeholder sessions are test-only",
            "session_required": false,
            "cost": "high_initial_load_then_reused",
            "safety": "read_only_trace_load"
        },
        {
            "command": "context snapshot",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": "optional_but_recommended",
            "cost": "medium",
            "safety": "read_only",
            "canonical_command": "debug snapshot"
        },
        {
            "command": "debug capabilities",
            "requires_daemon": "only when selecting a live, dump, or TTD subject",
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only_discovery",
            "canonical_command": "debug capabilities"
        },
        {
            "command": "debug snapshot",
            "requires_daemon": true,
            "requires_native_ttd": "TTD subjects require native replay; live/dump subjects use DbgEng target primitives",
            "session_required": "TTD subjects require --session and --cursor; live/dump subjects require --target",
            "cost": "bounded_composite",
            "safety": "read_only",
            "bounds": ["--max-frames", "--max-modules", "--max-threads", "--disasm-count", "--include", "--exclude"]
        },
        {
            "command": "triage",
            "requires_daemon": true,
            "requires_native_ttd": "depends on selected subject",
            "session_required": "TTD subjects require --session and --cursor; live/dump subjects require --target",
            "cost": "bounded_composite",
            "safety": "read_only_hypothesis_generation",
            "canonical_command": "triage <kind>"
        },
        {
            "command": "remote doctor",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only_local_diagnostics",
            "bounds": ["--probe-connect opt-in", "--timeout-ms"]
        },
        {
            "command": "remote status",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only_local_diagnostics",
            "bounds": ["--probe-connect opt-in", "--timeout-ms"]
        },
        {
            "command": "remote plan",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only_command_generation"
        },
        {
            "command": "symbols doctor",
            "requires_daemon": true,
            "requires_native_ttd": "depends on selected subject",
            "session_required": "TTD subjects require --session and --cursor; live/dump subjects require --target",
            "cost": "low_to_medium",
            "safety": "read_only"
        },
        {
            "command": "breakpoint plan",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": "requires --target or --session/--cursor identifiers",
            "cost": "low",
            "safety": "read_only_planner"
        },
        {
            "command": "debug log summarize",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "local_file_read",
            "safety": "read_only_log_summary",
            "privacy": "Action logging is opt-in through WINDBG_TOOL_ACTION_LOG; full argv logging requires WINDBG_TOOL_ACTION_LOG_FULL=1."
        },
        {
            "command": "timeline events",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cost": "medium",
            "safety": "read_only"
        },
        {
            "command": "register-context",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "low",
            "safety": "read_only",
            "architecture": "x64"
        },
        {
            "command": "disasm",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "low_to_medium",
            "safety": "read_only",
            "architecture": "x64"
        },
        {
            "command": "memory strings",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "bounded_memory_read",
            "safety": "read_only_memory",
            "bounds": ["--size", "--max-strings", "--min-len"]
        },
        {
            "command": "memory dps",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "bounded_memory_read",
            "safety": "read_only_memory",
            "bounds": ["--size", "--pointer-size"]
        },
        {
            "command": "memory watchpoint",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "potentially_high_replay",
            "safety": "read_only_replay_cursor_moves"
        },
        {
            "command": "sweep watch-memory",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "bounded_high_replay",
            "safety": "read_only_replay_cursor_moves",
            "bounds": ["--max-hits"]
        },
        {
            "command": "sweep watch-memory --background",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "daemon_owned_background_replay_job",
            "safety": "read_only_replay_cursor_moves",
            "bounds": ["--max-hits"]
        },
        {
            "command": "symbols inspect",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "local_file_read"
        },
        {
            "command": "windbg install",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "network_and_disk",
            "safety": "downloads_and_extracts_microsoft_signed_package"
        },
        {
            "command": "dbgeng server",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "long_running",
            "safety": "opens_debug_process_server_transport"
        },
        {
            "command": "live launch",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "launches_process",
            "safety": "live_debugging_changes_target_execution_state",
            "bounds": ["--initial-break-timeout-ms", "--end detach|terminate"]
        },
        {
            "command": "live startup-break",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "launches_process_and_waits_for_bounded_debug_event",
            "safety": "live_debugging_changes_target_execution_state",
            "bounds": ["--initial-break-timeout-ms", "--wait-timeout-ms", "--max-frames", "--end detach|terminate"]
        },
        {
            "command": "live startup-profile",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "launches_process_and_collects_bounded_lifecycle_events",
            "safety": "live_debugging_changes_target_execution_state_without_target_memory_writes",
            "bounds": ["--runs 1..10", "--initial-break-timeout-ms", "--timeout-ms", "--max-events", "--completion-module <basename>", "--settle-ms 1..60000 (requires --completion-module)", "--max-context-events", "--context-on", "--max-output-records", "--max-output-chars", "--max-total-output-chars", "--max-module-provenance", "--end detach|terminate"]
        },
        {
            "command": "live startup-compare",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "bounded_local_json_comparison",
            "safety": "read_only_host_artifact",
            "bounds": ["artifacts <= 16 MiB", "--max-sequence-events 1..256"]
        },
        {
            "command": "live startup-report",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "bounded_local_json_report",
            "safety": "read_only_host_artifact",
            "bounds": ["artifact <= 16 MiB", "--run 1..10", "--max-rows 1..128", "--path-width 24..256"]
        },
        {
            "command": "live start",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "launches_process_and_persists_target",
            "safety": "live_debugging_changes_target_execution_state",
            "bounds": ["--initial-break-timeout-ms", "--create-process-stop"]
        },
        {
            "command": "live attach",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "attaches_to_process_and_persists_target",
            "safety": "live_debugging_changes_target_execution_state"
        },
        {
            "command": "dump open",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "opens_dump_and_persists_target",
            "safety": "read_only_dump_analysis"
        },
        {
            "command": "dump inspect",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "opens_dump_and_reads_summary",
            "safety": "read_only_dump_analysis",
            "bounds": ["--max-frames"]
        },
        {
            "command": "dump triage",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "opens_dump_and_performs_bounded_triage",
            "safety": "read_only_dump_analysis",
            "bounds": ["--max-frames"]
        },
        {
            "command": "dump pool-triage",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "opens_dump_and_performs_bounded_pool_tracker_triage",
            "safety": "read_only_dump_analysis",
            "bounds": ["--max-frames"]
        },
        {
            "command": "dump create",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "opens_process_handle_and_writes_dump",
            "safety": "process_snapshot_read",
            "bounds": ["--kind mini|full", "--initial-break-timeout-ms", "--overwrite"]
        },
        {
            "command": "target capabilities",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only_discovery"
        },
        {
            "command": "target list",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only"
        },
        {
            "command": "target status",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only"
        },
        {
            "command": "target memory",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "bounded_memory_read",
            "safety": "read_only_memory",
            "bounds": ["--size"]
        },
        {
            "command": "target memory-map",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "bounded_dbgeng_virtual_memory_query",
            "safety": "read_only_dbgeng_data_space",
            "bounds": ["--region-limit 1..4096"],
            "limitations": ["Live user-mode targets only; bounded, partial, or unavailable coverage is explicit."]
        },
        {
            "command": "target address",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "bounded_dbgeng_address_translation",
            "safety": "read_only_dbgeng_data_space",
            "bounds": ["one canonical virtual address", "at most five physical page-table entry reads"],
            "limitations": ["Captured page-table state is post-bugcheck snapshot evidence, not fault-time transition proof."]
        },
        {
            "command": "target dump",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "writes_dump_from_live_target",
            "safety": "live_debugging_changes_target_execution_state",
            "bounds": ["--kind mini|full", "--overwrite"]
        },
        {
            "command": "target stack",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low_to_medium",
            "safety": "read_only"
        },
        {
            "command": "target disasm",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low_to_medium",
            "safety": "read_only"
        },
        {
            "command": "breakpoint set",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "live_debugging_changes_target_execution_state"
        },
        {
            "command": "datamodel eval",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only"
        },
        {
            "command": "job status",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only"
        },
        {
            "command": "job cancel",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "requests_background_cancellation"
        }
    ])
}

fn ttd_api_coverage_manifest() -> Value {
    json!({
        "source": "Microsoft.TimeTravelDebugging.Apis 0.9.5 TTD Replay headers",
        "statuses": {
            "implemented": "Native bridge, Rust facade, MCP tool, and focused CLI coverage exist.",
            "partial": "Some API coverage exists, but meaningful TTD functionality remains missing.",
            "gap": "No focused native bridge/MCP/CLI coverage yet."
        },
        "capabilities": [
            {
                "id": "trace_session",
                "status": "implemented",
                "ttd_api": ["IReplayEngine::Initialize", "IReplayEngine::Destroy"],
                "native_bridge": ["ttd_mcp_open_trace", "ttd_mcp_close_trace"],
                "mcp_tools": ["ttd_load_trace", "ttd_close_trace", "ttd_capabilities"],
                "cli_commands": ["open", "load", "close", "capabilities", "caps"],
                "notes": "Direct single-trace loading is covered; packed trace enumeration is tracked separately."
            },
            {
                "id": "trace_metadata",
                "status": "implemented",
                "ttd_api": ["GetPebAddress", "GetSystemInfo", "GetFirstPosition", "GetLastPosition", "GetLifetime"],
                "native_bridge": ["ttd_mcp_trace_info"],
                "mcp_tools": ["ttd_trace_info"],
                "cli_commands": ["info"],
                "notes": "Current output includes core metadata and counts, but full system/recording/file metadata is partial."
            },
            {
                "id": "trace_thread_module_exception_lists",
                "status": "implemented",
                "ttd_api": ["GetThreadList", "GetModuleInstanceList", "GetExceptionEventList", "GetKeyframeList", "GetModuleLoadedEventList", "GetModuleUnloadedEventList", "GetThreadCreatedEventList", "GetThreadTerminatedEventList"],
                "native_bridge": ["ttd_mcp_list_threads", "ttd_mcp_list_modules", "ttd_mcp_list_exceptions", "ttd_mcp_list_keyframes", "ttd_mcp_list_module_events", "ttd_mcp_list_thread_events"],
                "mcp_tools": ["ttd_list_threads", "ttd_list_modules", "ttd_list_exceptions", "ttd_list_keyframes", "ttd_module_events", "ttd_thread_events", "ttd_module_info"],
                "cli_commands": ["threads", "modules", "mods", "exceptions", "keyframes", "events modules", "events threads", "timeline events", "module info", "module audit", "symbols exports", "symbols nearest"],
                "notes": "Common trace-wide lists and event lists are covered. Local PE export parsing adds a low-fidelity nearest-export fallback when PDB symbols are unavailable."
            },
            {
                "id": "cursor_navigation",
                "status": "implemented",
                "ttd_api": ["NewCursor", "GetPosition", "SetPosition", "SetPositionOnThread", "ReplayForward", "ReplayBackward"],
                "native_bridge": ["ttd_mcp_new_cursor", "ttd_mcp_cursor_position", "ttd_mcp_set_position", "ttd_mcp_set_position_on_thread", "ttd_mcp_step_cursor"],
                "mcp_tools": ["ttd_cursor_create", "ttd_position_get", "ttd_position_set", "ttd_step", "ttd_active_threads", "ttd_cursor_modules"],
                "cli_commands": ["cursor create", "position get", "position set", "step", "replay capabilities", "replay to", "replay watch-memory", "sweep watch-memory", "active-threads", "active", "cursor modules"],
                "notes": "Basic navigation, replay-to-memory wrappers, and bounded client-side memory sweeps are covered; masks, position watchpoints, native jobs, clear/clone/interrupt remain native bridge gaps."
            },
            {
                "id": "register_state",
                "status": "implemented",
                "ttd_api": ["GetThreadInfo", "GetTebAddress", "GetProgramCounter", "GetStackPointer", "GetFramePointer", "GetBasicReturnValue", "GetCrossPlatformContext", "GetAvxExtendedContext"],
                "native_bridge": ["ttd_mcp_cursor_state", "ttd_mcp_x64_context", "ttd_mcp_active_threads"],
                "mcp_tools": ["ttd_registers", "ttd_register_context", "ttd_active_threads"],
                "cli_commands": ["architecture state", "arch state", "registers", "regs", "register-context", "ctx", "active-threads", "active"],
                "notes": "x64 scalar and SIMD state is covered and architecture support is now explicit; x86/ARM/ARM64 typed models remain gaps."
            },
            {
                "id": "memory_queries",
                "status": "implemented",
                "ttd_api": ["QueryMemoryRange", "QueryMemoryBuffer", "QueryMemoryBufferWithRanges", "QueryMemoryPolicy"],
                "native_bridge": ["ttd_mcp_read_memory", "ttd_mcp_query_memory_range", "ttd_mcp_query_memory_buffer_with_ranges"],
                "mcp_tools": ["ttd_read_memory", "ttd_memory_range", "ttd_memory_buffer", "ttd_address_info"],
                "cli_commands": ["memory read", "memory range", "memory buffer", "memory dump", "memory strings", "memory dps", "memory classify", "memory chase", "address"],
                "notes": "Per-call memory policy is covered; higher-level dump/strings/dps/classify/chase helpers are built on read_memory and address_info. Cursor default memory policy is a gap."
            },
            {
                "id": "stack_process_helpers",
                "status": "implemented",
                "ttd_api": ["GetTebAddress", "GetStackPointer", "QueryMemoryBuffer", "GetPebAddress"],
                "native_bridge": ["ttd_mcp_cursor_state", "ttd_mcp_read_memory", "ttd_mcp_trace_info"],
                "mcp_tools": ["ttd_stack_info", "ttd_stack_read", "ttd_command_line"],
                "cli_commands": ["stack info", "stack read", "stack recover", "stack backtrace", "command-line", "cmdline"],
                "notes": "These are value-added helpers built from lower-level TTD state and memory APIs."
            },
            {
                "id": "memory_watchpoint_first_hit",
                "status": "implemented",
                "ttd_api": ["DataAccessMask", "MemoryWatchpointData", "AddMemoryWatchpoint", "RemoveMemoryWatchpoint", "ReplayForward", "ReplayBackward"],
                "native_bridge": ["ttd_mcp_memory_watchpoint"],
                "mcp_tools": ["ttd_memory_watchpoint"],
                "cli_commands": ["memory watchpoint", "watchpoint"],
                "notes": "First-hit replay is covered with the full TTD DataAccessMask vocabulary and optional thread filters; daemon-owned multi-hit sweep jobs now cover the most common bounded background replay workflow."
            },
            {
                "id": "trace_list_packs",
                "status": "implemented",
                "ttd_api": ["ITraceList::LoadFile", "GetTraceCount", "GetTraceInfo", "OpenTrace"],
                "native_bridge": ["ttd_mcp_list_traces", "ttd_mcp_open_trace_at_index"],
                "mcp_tools": ["ttd_trace_list", "ttd_load_trace"],
                "cli_commands": ["trace list", "trace-list", "load --trace-index", "open --trace-index"],
                "notes": "Covers .ttd packs, companion trace/index handling, and selecting traces by index."
            },
            {
                "id": "index_operations",
                "status": "implemented",
                "ttd_api": ["GetIndexStatus", "GetIndexFileStats", "BuildIndex"],
                "native_bridge": ["ttd_mcp_index_status", "ttd_mcp_index_file_stats", "ttd_mcp_build_index"],
                "mcp_tools": ["ttd_index_status", "ttd_index_stats", "ttd_build_index"],
                "cli_commands": ["index status", "index stats", "index build"],
                "notes": "Synchronous status, stats, and build are covered; daemon-managed background jobs now cover bounded watch-memory sweeps with status, result retrieval, and cancellation."
            },
            {
                "id": "recording_client_timeline",
                "status": "partial",
                "ttd_api": ["GetRecordClientList", "GetCustomEventList", "GetActivityList", "GetIslandList"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["timeline events"],
                "notes": "timeline events merges currently exposed module/thread/exception/keyframe metadata; custom event, activity, island, and record-client payloads still need native bridge coverage."
            },
            {
                "id": "replay_masks_position_watchpoints",
                "status": "partial",
                "ttd_api": ["SetEventMask", "SetGapKindMask", "SetGapEventMask", "SetExceptionMask", "SetReplayFlags", "AddPositionWatchpoint", "RemovePositionWatchpoint", "Clear", "InterruptReplay"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["replay capabilities", "replay to", "replay watch-memory"],
                "notes": "CLI wrappers expose supported position and memory replay operations and report unsupported controls; masks, position watchpoints, clear, and interrupt still need native bridge coverage."
            },
            {
                "id": "callback_sweeps",
                "status": "partial",
                "ttd_api": ["SetMemoryWatchpointCallback", "SetPositionWatchpointCallback", "SetGapEventCallback", "SetReplayProgressCallback", "SetThreadContinuityBreakCallback", "SetFallbackCallback", "SetCallReturnCallback", "SetIndirectJumpCallback", "SetRegisterChangedCallback"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["sweep watch-memory", "breakpoint capabilities"],
                "notes": "sweep watch-memory provides bounded foreground multi-hit collection over first-hit memory watchpoints; native callbacks are still needed for progress, cancellation, call/return traces, jump traces, and register-change traces."
            },
            {
                "id": "module_symbol_enrichment",
                "status": "partial",
                "ttd_api": ["Module::Checksum", "Module::Timestamp"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["symbols diagnose", "symbols inspect", "symbols exports", "symbols nearest"],
                "notes": "Local PE/PDB/export diagnostics and nearest-export fallback are covered; native TraceModule checksum/timestamp fields and true DbgHelp/SymSrv/PDB nearest-symbol/source helpers remain gaps."
            },
            {
                "id": "cursor_lifecycle_and_replay_jobs",
                "status": "gap",
                "ttd_api": ["Cursor::Clone", "Cursor::Clear", "Cursor::InterruptReplay", "ReplayProgressCallback"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": [],
                "notes": "Needed for daemon-owned cancellable replay jobs, progress reporting, cursor cloning, and explicit cursor state clearing."
            }
        ]
    })
}

fn session_call(name: &str, args: SessionArgs) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        arguments: json!({ "session_id": args.session }),
    }
}

fn target_call(name: &str, target: u64) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        arguments: json!({ "target_id": target }),
    }
}

fn target_wait_call(args: TargetWaitArgs) -> ToolCall {
    ToolCall {
        name: "target_wait".to_string(),
        arguments: json!({
            "target_id": args.target,
            "timeout_ms": args.timeout_ms,
        }),
    }
}

fn target_continue_wait_call(args: TargetContinueWaitArgs) -> ToolCall {
    ToolCall {
        name: "target_continue_wait".to_string(),
        arguments: json!({
            "target_id": args.target,
            "timeout_ms": args.timeout_ms,
            "capture_debuggee_output": args.capture_debuggee_output,
            "max_output_records": args.max_output_records,
            "max_output_chars": args.max_output_chars,
            "max_total_output_chars": args.max_total_output_chars,
        }),
    }
}

fn target_memory_call(args: TargetMemoryReadArgs) -> anyhow::Result<ToolCall> {
    Ok(ToolCall {
        name: "target_read_memory".to_string(),
        arguments: json!({
            "target_id": args.target,
            "address": parse_u64_argument(&args.address)?,
            "size": args.size,
        }),
    })
}

fn target_memory_map_call(args: TargetMemoryMapArgs) -> ToolCall {
    ToolCall {
        name: "target_memory_map".to_string(),
        arguments: json!({
            "target_id": args.target,
            "region_limit": args.region_limit,
        }),
    }
}

fn target_address_inspect_call(args: TargetAddressArgs) -> anyhow::Result<ToolCall> {
    Ok(ToolCall {
        name: "target_inspect_address".to_string(),
        arguments: json!({
            "target_id": args.target,
            "address": parse_u64_argument(&args.address)?,
        }),
    })
}

fn target_thread_accounting_call(args: TargetThreadAccountingArgs) -> ToolCall {
    ToolCall {
        name: "target_thread_accounting".to_string(),
        arguments: json!({
            "target_id": args.target,
            "max_threads": args.max_threads,
        }),
    }
}

fn target_module_parameters_call(args: TargetModuleParametersArgs) -> anyhow::Result<ToolCall> {
    ensure!(
        (1..=128).contains(&args.module_bases.len()),
        "target module-parameters requires from 1 through 128 --module-base values"
    );
    let module_base_addresses = args
        .module_bases
        .iter()
        .map(|address| parse_u64_argument(address))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut unique = module_base_addresses.clone();
    unique.sort_unstable();
    unique.dedup();
    ensure!(
        unique.len() == module_base_addresses.len(),
        "target module-parameters requires distinct --module-base values"
    );
    Ok(ToolCall {
        name: "target_module_parameters".to_string(),
        arguments: json!({
            "target_id": args.target,
            "module_base_addresses": module_base_addresses,
        }),
    })
}

fn target_dump_call(args: TargetDumpArgs) -> ToolCall {
    ToolCall {
        name: "target_write_dump".to_string(),
        arguments: json!({
            "target_id": args.target,
            "path": args.output,
            "kind": cli_dump_kind_name(args.kind),
            "overwrite": args.overwrite,
        }),
    }
}

fn target_stack_call(args: TargetStackTraceArgs) -> ToolCall {
    ToolCall {
        name: "target_stack_trace".to_string(),
        arguments: json!({
            "target_id": args.target,
            "max_frames": args.max_frames,
        }),
    }
}

fn target_thread_context_call(args: TargetThreadContextArgs) -> ToolCall {
    ToolCall {
        name: "target_thread_context".to_string(),
        arguments: json!({
            "target_id": args.target,
            "engine_thread_id": args.engine_thread_id,
            "max_frames": args.max_frames,
            "disassembly_count": args.disassembly_count,
        }),
    }
}

fn cli_dump_kind_name(kind: CliDumpKind) -> &'static str {
    match kind {
        CliDumpKind::Mini => "mini",
        CliDumpKind::Full => "full",
    }
}

fn target_disasm_call(args: TargetDisasmArgs) -> anyhow::Result<ToolCall> {
    Ok(ToolCall {
        name: "target_disassemble".to_string(),
        arguments: json!({
            "target_id": args.target,
            "address": args.address.as_deref().map(parse_u64_argument).transpose()?,
            "count": args.count,
        }),
    })
}

fn target_address_call(name: &str, args: TargetAddressArgs) -> anyhow::Result<ToolCall> {
    Ok(ToolCall {
        name: name.to_string(),
        arguments: json!({
            "target_id": args.target,
            "address": parse_u64_argument(&args.address)?,
        }),
    })
}

fn breakpoint_set_call(args: BreakpointSetArgs) -> anyhow::Result<ToolCall> {
    let address = args
        .address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;

    Ok(ToolCall {
        name: "target_set_breakpoint".to_string(),
        arguments: json!({
            "target_id": args.target,
            "address": address,
            "symbol": args.symbol,
            "kind": args.kind,
            "size": args.size,
        }),
    })
}

fn breakpoint_remove_call(args: BreakpointRemoveArgs) -> ToolCall {
    ToolCall {
        name: "target_remove_breakpoint".to_string(),
        arguments: json!({
            "target_id": args.target,
            "breakpoint_id": args.breakpoint_id,
        }),
    }
}

fn breakpoint_enable_call(args: BreakpointEnableArgs, enabled: bool) -> ToolCall {
    ToolCall {
        name: "target_set_breakpoint_enabled".to_string(),
        arguments: json!({
            "target_id": args.target,
            "breakpoint_id": args.breakpoint_id,
            "enabled": enabled,
        }),
    }
}

fn target_eval_call(args: DataModelEvalArgs) -> ToolCall {
    ToolCall {
        name: "target_evaluate_expression".to_string(),
        arguments: json!({
            "target_id": args.target,
            "expression": args.expression,
        }),
    }
}

fn job_call(name: &str, job_id: u64) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        arguments: json!({
            "job_id": job_id,
        }),
    }
}

fn cursor_call(name: &str, args: CursorArgs) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        arguments: cursor_json(args.session, args.cursor),
    }
}

fn cursor_json(session: u64, cursor: u64) -> Value {
    json!({
        "session_id": session,
        "cursor_id": cursor,
    })
}

fn tool_arguments(args: ToolArgs) -> anyhow::Result<Value> {
    let value = if let Some(path) = args.json_file {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading JSON arguments from {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
    } else {
        serde_json::from_str(&args.json).context("parsing --json")?
    };
    ensure_json_object(value)
}

fn module_info_call(args: ModuleInfoArgs) -> anyhow::Result<ToolCall> {
    if args.name.is_none() && args.address.is_none() {
        bail!("module info requires --name or --address")
    }
    let mut object = session_object(args.session);
    insert_option(&mut object, "name", args.name.map(Value::String));
    insert_option(
        &mut object,
        "address",
        args.address
            .as_deref()
            .map(parse_u64_argument)
            .transpose()?
            .map(Value::from),
    );
    Ok(ToolCall {
        name: "ttd_module_info".to_string(),
        arguments: Value::Object(object),
    })
}

async fn module_audit_and_print(
    pipe: String,
    args: ModuleAuditArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_suspicious <= 10_000,
        "module audit --max-suspicious must not exceed 10000"
    );
    let client = DaemonClient::new(pipe);
    let modules = if let Some(cursor) = args.cursor {
        client
            .call_tool(cursor_call(
                "ttd_cursor_modules",
                CursorArgs {
                    session: args.session,
                    cursor,
                },
            ))
            .await?
    } else {
        client
            .call_tool(session_call(
                "ttd_list_modules",
                SessionArgs {
                    session: args.session,
                },
            ))
            .await?
    };
    let module_items = modules["modules"]
        .as_array()
        .context("module list response did not include modules")?;
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "source": if args.cursor.is_some() { "cursor_modules" } else { "trace_modules" },
            "module_count": module_items.len(),
            "audit": audit_modules(module_items, args.max_suspicious),
            "modules": modules,
            "notes": [
                "This is read-only triage based on module paths and load inventory.",
                "Suspicious paths are evidence for review, not proof of injection."
            ]
        }),
        output,
    )
}

async fn timeline_events_and_print(
    pipe: String,
    args: TimelineEventsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(timeline_events_value(&client, &args).await?, output)
}

async fn timeline_events_value(
    client: &DaemonClient,
    args: &TimelineEventsArgs,
) -> anyhow::Result<Value> {
    ensure!(
        args.max_events <= 100_000,
        "timeline events --max-events must not exceed 100000"
    );
    let include = |kind: &str| args.kind == "all" || args.kind == kind;
    let mut events = Vec::new();
    let mut sources = Map::new();

    if include("modules") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_module_events",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_timeline_events(&mut events, "module", &value, "events");
        sources.insert(
            "modules".to_string(),
            timeline_source_summary(&value, "events"),
        );
    }
    if include("threads") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_thread_events",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_timeline_events(&mut events, "thread", &value, "events");
        sources.insert(
            "threads".to_string(),
            timeline_source_summary(&value, "events"),
        );
    }
    if include("exceptions") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_list_exceptions",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_timeline_events(&mut events, "exception", &value, "exceptions");
        sources.insert(
            "exceptions".to_string(),
            timeline_source_summary(&value, "exceptions"),
        );
    }
    if include("keyframes") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_list_keyframes",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_keyframe_events(&mut events, &value);
        sources.insert(
            "keyframes".to_string(),
            timeline_source_summary(&value, "keyframes"),
        );
    }

    events.sort_by(|left, right| {
        timeline_sequence(left)
            .cmp(&timeline_sequence(right))
            .then_with(|| left["kind"].as_str().cmp(&right["kind"].as_str()))
    });
    let total_events = events.len();
    let mut event_counts = Map::new();
    for event in &events {
        if let Some(kind) = event["kind"].as_str() {
            let count = event_counts
                .entry(kind.to_string())
                .or_insert_with(|| Value::from(0_u64));
            *count = Value::from(count.as_u64().unwrap_or(0) + 1);
        }
    }
    if events.len() > args.max_events {
        events.truncate(args.max_events);
    }
    Ok(json!({
        "session_id": args.session,
        "kind": args.kind,
        "total_events": total_events,
        "event_counts": event_counts,
        "max_events": args.max_events,
        "returned": events.len(),
        "limit": args.max_events,
        "truncated": total_events > args.max_events,
        "events": events,
        "sources": Value::Object(sources),
        "unsupported_recording_metadata": [
            "record clients",
            "custom events",
            "activities",
            "islands",
            "bounded user-data payload extraction"
        ],
        "notes": [
            "This timeline merges currently exposed trace metadata.",
            "Sources include only status and item counts; use the corresponding metadata command for full source data.",
            "Recording-client/custom-event/activity/island metadata requires additional native TTD bridge coverage."
        ]
    }))
}

fn module_search_order_and_print(
    args: ModuleSearchOrderArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let dll = normalize_dll_name(&args.dll)?;
    let current_dir = args
        .current_dir
        .unwrap_or(std::env::current_dir().context("resolving current directory")?);
    let windows_dir = PathBuf::from(
        std::env::var("WINDIR")
            .or_else(|_| std::env::var("SystemRoot"))
            .unwrap_or_else(|_| String::from(r"C:\Windows")),
    );
    let system32 = windows_dir.join("System32");
    let system = windows_dir.join("System");
    let max_path_dirs = args.max_path_dirs.unwrap_or(64);

    let mut candidates = Vec::new();
    candidates.push(json!({
        "order": 0,
        "kind": "known_dlls",
        "directory": null,
        "candidate": null,
        "exists": null,
        "risk": "system_controlled",
        "notes": "KnownDLLs are resolved by the loader before filesystem probing when the name is registered."
    }));
    let mut order = 1usize;
    if let Some(app_dir) = args.app_dir {
        candidates.push(search_candidate(
            order,
            "application_directory",
            &app_dir,
            &dll,
        ));
        order += 1;
    }
    for (kind, directory) in [
        ("system32", system32.as_path()),
        ("system", system.as_path()),
        ("windows", windows_dir.as_path()),
        ("current_directory", current_dir.as_path()),
    ] {
        candidates.push(search_candidate(order, kind, directory, &dll));
        order += 1;
    }
    let path_dirs = std::env::var_os("PATH")
        .map(|value| {
            std::env::split_paths(&value)
                .take(max_path_dirs)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for directory in &path_dirs {
        candidates.push(search_candidate(order, "path_directory", directory, &dll));
        order += 1;
    }
    let risky_candidates = candidates
        .iter()
        .filter(|candidate| candidate["risk"] != "system_controlled")
        .count();
    print_value(
        json!({
            "dll": dll,
            "candidate_count": candidates.len(),
            "path_dirs_included": path_dirs.len(),
            "path_dirs_truncated": std::env::var_os("PATH")
                .map(|value| std::env::split_paths(&value).count() > path_dirs.len())
                .unwrap_or(false),
            "risky_candidate_count": risky_candidates,
            "candidates": candidates,
            "notes": [
                "This is a diagnostic model for common user-mode DLL search-order reasoning, not a loader trace.",
                "SafeDllSearchMode, package identity, API sets, manifests, KnownDLLs, SetDllDirectory/AddDllDirectory, and LoadLibrary flags can change real behavior.",
                "Prefer absolute paths or application-local signed dependencies when diagnosing DLL search-order issues."
            ]
        }),
        output,
    )
}

fn address_info_call(args: AddressInfoArgs) -> ToolCall {
    ToolCall {
        name: "ttd_address_info".to_string(),
        arguments: json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": args.address,
        }),
    }
}

fn position_set_call(args: PositionSetArgs) -> anyhow::Result<ToolCall> {
    let position = parse_position_argument(&args.position)?;
    let mut object = cursor_object(args.session, args.cursor);
    object.insert("position".to_string(), position);
    insert_option(
        &mut object,
        "thread_unique_id",
        args.thread_unique_id.map(Value::from),
    );
    Ok(ToolCall {
        name: "ttd_position_set".to_string(),
        arguments: Value::Object(object),
    })
}

fn step_call(args: StepArgs) -> ToolCall {
    let mut object = cursor_object(args.session, args.cursor);
    insert_option(&mut object, "direction", args.direction.map(Value::String));
    insert_option(&mut object, "kind", args.kind.map(Value::String));
    insert_option(&mut object, "count", args.count.map(Value::from));
    ToolCall {
        name: "ttd_step".to_string(),
        arguments: Value::Object(object),
    }
}

fn watch_memory_job_call(args: SweepWatchMemoryArgs) -> anyhow::Result<ToolCall> {
    Ok(ToolCall {
        name: "job_start_watch_memory_sweep".to_string(),
        arguments: json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": parse_u64_argument(&args.address)?,
            "size": args.size,
            "access": args.access,
            "direction": args.direction,
            "thread_unique_id": args.thread_unique_id,
            "max_hits": args.max_hits,
        }),
    })
}

async fn replay_capabilities_and_print(
    pipe: String,
    args: SessionArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let capabilities = client
        .call_tool(session_call("ttd_capabilities", args))
        .await?;
    print_value(
        json!({
            "capabilities": capabilities,
            "supported_controls": [
                "position get",
                "position set",
                "position set --thread-unique-id",
                "step --direction forward|backward --kind step|trace",
                "memory watchpoint --direction next|previous",
                "replay to",
                "replay watch-memory"
            ],
            "unsupported_native_controls": [
                "cursor clone",
                "cursor clear",
                "cursor close",
                "interrupt replay",
                "event masks",
                "gap masks",
                "exception masks",
                "replay flags",
                "position watchpoints",
                "bounded replay-to-position with native stop masks"
            ],
            "notes": [
                "Supported controls are built from currently exposed TTD replay primitives.",
                "Unsupported controls need additional native bridge coverage before they can be safely exposed as real controls."
            ]
        }),
        output,
    )
}

async fn replay_to_and_print(
    pipe: String,
    args: ReplayToArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let before = call_status_value(
        client
            .call_tool(cursor_call(
                "ttd_position_get",
                CursorArgs {
                    session: args.session,
                    cursor: args.cursor,
                },
            ))
            .await,
    );
    let after = client
        .call_tool(position_set_call(PositionSetArgs {
            session: args.session,
            cursor: args.cursor,
            position: args.position.clone(),
            thread_unique_id: args.thread_unique_id,
        })?)
        .await?;
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "requested_position": args.position,
            "thread_unique_id": args.thread_unique_id,
            "before": before,
            "after": after,
            "method": if args.thread_unique_id.is_some() { "set_position_on_thread" } else { "set_position" }
        }),
        output,
    )
}

async fn exception_focus_and_print(
    pipe: String,
    args: ExceptionFocusArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let exceptions = client
        .call_tool(session_call(
            "ttd_list_exceptions",
            SessionArgs {
                session: args.session,
            },
        ))
        .await?;
    let exception_items = exceptions
        .as_array()
        .context("ttd_list_exceptions response did not include an exception array")?;
    let exception = exception_items.get(args.index).cloned().with_context(|| {
        format!(
            "exception index {} is outside the {} recorded exception events",
            args.index,
            exception_items.len()
        )
    })?;
    let requested_position = exception["position"].clone();
    let requested_position_hex = position_hex_text(&requested_position)?;
    let thread_unique_id = exception["thread_unique_id"].as_u64();
    let after = client
        .call_tool(exception_focus_call(args.session, args.cursor, &exception)?)
        .await?;
    let exception_code_hex = exception["code"]
        .as_u64()
        .map(|code| format!("0x{code:08X}"));

    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "exception_index": args.index,
            "exception": exception,
            "exception_code_hex": exception_code_hex,
            "requested_position": requested_position,
            "requested_position_hex": requested_position_hex,
            "thread_unique_id": thread_unique_id,
            "position": after,
            "notes": [
                "This command uses the exception's JSON position directly, avoiding decimal/hexadecimal transcription errors.",
                "When the trace records an owning thread, the cursor seeks on that TTD thread."
            ],
            "next_recommended_safe_commands": [
                format!("windbg-tool registers --session {} --cursor {}", args.session, args.cursor),
                format!("windbg-tool stack backtrace --session {} --cursor {}", args.session, args.cursor),
                format!("windbg-tool disasm --session {} --cursor {}", args.session, args.cursor)
            ]
        }),
        output,
    )
}

fn exception_focus_call(session: u64, cursor: u64, exception: &Value) -> anyhow::Result<ToolCall> {
    let position = exception["position"].clone();
    position_hex_text(&position)?;
    let mut arguments = cursor_object(session, cursor);
    arguments.insert("position".to_string(), position);
    insert_option(
        &mut arguments,
        "thread_unique_id",
        exception["thread_unique_id"].as_u64().map(Value::from),
    );
    Ok(ToolCall {
        name: "ttd_position_set".to_string(),
        arguments: Value::Object(arguments),
    })
}

fn position_hex_text(position: &Value) -> anyhow::Result<String> {
    let sequence = position["sequence"]
        .as_u64()
        .context("position did not include a numeric sequence")?;
    let steps = position["steps"]
        .as_u64()
        .context("position did not include numeric steps")?;
    Ok(format!("{sequence:X}:{steps:X}"))
}

async fn sweep_watch_memory_and_print(
    pipe: String,
    args: SweepWatchMemoryArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_hits > 0,
        "sweep watch-memory max-hits must be greater than zero"
    );
    ensure!(
        args.max_hits <= 1024,
        "sweep watch-memory max-hits must not exceed 1024"
    );
    let client = DaemonClient::new(pipe);
    let mut hits = Vec::new();
    let mut seen_positions = std::collections::BTreeSet::new();
    let mut stop_reason = "max_hits";

    for _ in 0..args.max_hits {
        let hit = client
            .call_tool(watchpoint_call(WatchpointArgs {
                session: args.session,
                cursor: args.cursor,
                address: args.address.clone(),
                size: args.size,
                access: args.access.clone(),
                direction: args.direction.clone(),
                thread_unique_id: args.thread_unique_id,
            })?)
            .await?;
        if hit["found"].as_bool() != Some(true) {
            stop_reason = "not_found";
            hits.push(hit);
            break;
        }
        let sequence = hit["position"]["sequence"].as_u64();
        if let Some(sequence) = sequence {
            if !seen_positions.insert(sequence) {
                stop_reason = "duplicate_position";
                hits.push(hit);
                break;
            }
        }
        hits.push(hit);
        client
            .call_tool(step_call(StepArgs {
                session: args.session,
                cursor: args.cursor,
                direction: Some(match args.direction.as_str() {
                    "previous" => "backward".to_string(),
                    _ => "forward".to_string(),
                }),
                kind: Some("step".to_string()),
                count: Some(1),
            }))
            .await?;
    }

    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": parse_u64_argument(&args.address)?,
            "size": args.size,
            "access": args.access,
            "direction": args.direction,
            "thread_unique_id": args.thread_unique_id,
            "max_hits": args.max_hits,
            "hit_count": hits.iter().filter(|hit| hit["found"].as_bool() == Some(true)).count(),
            "stop_reason": stop_reason,
            "hits": hits,
            "notes": [
                "This is a bounded client-side sweep over first-hit TTD watchpoints.",
                "The command advances one step after each hit to avoid reporting the same position repeatedly.",
                "Use --background to run the same bounded sweep as a daemon-owned job with status, result retrieval, and cancellation."
            ]
        }),
        output,
    )
}

fn register_context_call(args: RegisterContextArgs) -> ToolCall {
    let mut object = cursor_object(args.session, args.cursor);
    insert_option(&mut object, "thread_id", args.thread_id.map(Value::from));
    ToolCall {
        name: "ttd_register_context".to_string(),
        arguments: Value::Object(object),
    }
}

fn stack_read_call(args: StackReadArgs) -> ToolCall {
    let mut object = cursor_object(args.session, args.cursor);
    insert_option(&mut object, "size", args.size.map(Value::from));
    insert_option(
        &mut object,
        "offset_from_sp",
        args.offset_from_sp.map(Value::from),
    );
    if args.decode_pointers {
        object.insert("decode_pointers".to_string(), Value::Bool(true));
    }
    ToolCall {
        name: "ttd_stack_read".to_string(),
        arguments: Value::Object(object),
    }
}

async fn stack_recover_and_print(
    pipe: String,
    args: StackRecoverArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        (0.0..=1.0).contains(&args.min_confidence),
        "min-confidence must be between 0.0 and 1.0"
    );
    ensure!(
        args.max_candidates > 0,
        "max-candidates must be greater than zero"
    );
    ensure!(
        args.max_candidates <= 512,
        "max-candidates must be 512 or less"
    );

    let client = DaemonClient::new(pipe);
    let stack_read = client
        .call_tool(stack_read_call(StackReadArgs {
            session: args.session,
            cursor: args.cursor,
            size: args.size.or(Some(4096)),
            offset_from_sp: args.offset_from_sp,
            decode_pointers: true,
        }))
        .await?;
    let mut candidates =
        recover_stack_candidates(&stack_read, args.max_candidates, args.min_confidence);
    if args.target_info {
        enrich_stack_candidates(&client, args.session, args.cursor, &mut candidates).await;
    }

    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "stack": stack_read,
            "candidates": candidates,
            "heuristics": [
                "Pointer-sized stack values that land inside a loaded module are likely return-address candidates.",
                "Confidence is higher for module hits, aligned stack slots, and values that look like canonical x64 pointers.",
                "This is recovery evidence, not a trusted unwind; validate candidates with symbols, disassembly, and call-site context."
            ],
            "follow_up": [
                "Use disasm --address <candidate> to inspect code near a candidate.",
                "Use memory watchpoint on a corrupted return-address slot to find writes in TTD."
            ]
        }),
        output,
    )
}

async fn stack_backtrace_and_print(
    pipe: String,
    args: StackBacktraceArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_frames > 0,
        "stack backtrace max-frames must be greater than zero"
    );
    ensure!(
        args.max_frames <= 1024,
        "stack backtrace max-frames must not exceed 1024"
    );
    let client = DaemonClient::new(pipe);
    let registers = client
        .call_tool(cursor_call(
            "ttd_registers",
            CursorArgs {
                session: args.session,
                cursor: args.cursor,
            },
        ))
        .await?;
    let stack_read = client
        .call_tool(stack_read_call(StackReadArgs {
            session: args.session,
            cursor: args.cursor,
            size: Some(args.size),
            offset_from_sp: args.offset_from_sp,
            decode_pointers: true,
        }))
        .await?;
    let candidate_budget = args.max_frames.saturating_sub(1);
    let mut candidates =
        recover_stack_candidates(&stack_read, candidate_budget, args.min_confidence);
    if args.target_info {
        enrich_stack_candidates(&client, args.session, args.cursor, &mut candidates).await;
    }
    let mut frames = Vec::new();
    if let Some(pc) = registers["program_counter"].as_u64() {
        let mut current = json!({
            "index": 0,
            "kind": "current_instruction",
            "address": pc,
            "address_hex": format!("0x{pc:016x}"),
            "confidence": 1.0,
            "reasons": ["current_program_counter"],
        });
        if args.target_info {
            current["target_info"] = client
                .call_tool(address_info_call(AddressInfoArgs {
                    session: args.session,
                    cursor: args.cursor,
                    address: pc.to_string(),
                }))
                .await?;
        }
        frames.push(current);
    }
    for (index, candidate) in candidates.into_iter().enumerate() {
        frames.push(json!({
            "index": frames.len(),
            "kind": "recovered_return_address",
            "address": candidate["target"],
            "address_hex": candidate["target_hex"],
            "stack_slot": candidate["slot_address"],
            "stack_slot_hex": candidate["slot_address_hex"],
            "module": candidate["module"],
            "confidence": candidate["confidence"],
            "reasons": candidate["reasons"],
            "target_info": candidate.get("target_info").cloned().unwrap_or(Value::Null),
            "candidate_rank": index,
        }));
    }
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "position": registers["position"],
            "thread": registers["thread"],
            "method": "heuristic_stack_scan",
            "trusted_unwind": false,
            "frames": frames,
            "stack_read": stack_read,
            "warnings": [
                "This is not a DbgHelp/DbgEng unwind and may include false positives.",
                "Use stack recover output, disassembly, symbols, and TTD watchpoints to validate suspicious return-address candidates."
            ]
        }),
        output,
    )
}

fn recover_stack_candidates(
    stack_read: &Value,
    max_candidates: usize,
    min_confidence: f64,
) -> Vec<Value> {
    let mut candidates = stack_read["pointers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pointer| {
            let value = pointer["value"].as_u64()?;
            let slot_address = pointer["address"].as_u64()?;
            let module = pointer["module"].as_str();
            let confidence = stack_candidate_confidence(value, slot_address, module.is_some());
            (confidence >= min_confidence).then(|| {
                json!({
                    "slot_address": slot_address,
                    "slot_address_hex": format!("0x{slot_address:X}"),
                    "offset": pointer["offset"].as_u64().unwrap_or_default(),
                    "target": value,
                    "target_hex": format!("0x{value:X}"),
                    "module": module,
                    "confidence": confidence,
                    "reasons": stack_candidate_reasons(value, slot_address, module.is_some()),
                })
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right["confidence"]
            .as_f64()
            .partial_cmp(&left["confidence"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                left["slot_address"]
                    .as_u64()
                    .cmp(&right["slot_address"].as_u64())
            })
    });
    candidates.truncate(max_candidates);
    candidates
}

fn stack_candidate_confidence(value: u64, slot_address: u64, in_module: bool) -> f64 {
    let mut confidence = 0.15;
    if in_module {
        confidence += 0.55;
    }
    if slot_address.is_multiple_of(8) {
        confidence += 0.10;
    }
    if plausible_x64_pointer(value) {
        confidence += 0.15;
    }
    if value.is_multiple_of(16) {
        confidence += 0.05;
    }
    f64::min(confidence, 1.0)
}

fn stack_candidate_reasons(value: u64, slot_address: u64, in_module: bool) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if in_module {
        reasons.push("target_in_loaded_module");
    }
    if slot_address.is_multiple_of(8) {
        reasons.push("aligned_stack_slot");
    }
    if plausible_x64_pointer(value) {
        reasons.push("canonical_aligned_x64_pointer");
    }
    if value.is_multiple_of(16) {
        reasons.push("target_16_byte_aligned");
    }
    reasons
}

async fn enrich_stack_candidates(
    client: &DaemonClient,
    session: u64,
    cursor: u64,
    candidates: &mut [Value],
) {
    for candidate in candidates {
        let Some(target) = candidate["target"].as_u64() else {
            continue;
        };
        candidate["target_info"] = call_status_value(
            client
                .call_tool(ToolCall {
                    name: "ttd_address_info".to_string(),
                    arguments: json!({
                        "session_id": session,
                        "cursor_id": cursor,
                        "address": target,
                    }),
                })
                .await,
        );
    }
}

fn memory_read_call(args: MemoryReadArgs) -> anyhow::Result<ToolCall> {
    let mut object = cursor_object(args.session, args.cursor);
    object.insert(
        "address".to_string(),
        Value::from(parse_u64_argument(&args.address)?),
    );
    object.insert("size".to_string(), Value::from(args.size));
    insert_option(&mut object, "policy", args.policy.map(Value::String));
    Ok(ToolCall {
        name: "ttd_read_memory".to_string(),
        arguments: Value::Object(object),
    })
}

fn memory_range_call(args: MemoryRangeArgs) -> anyhow::Result<ToolCall> {
    let mut object = cursor_object(args.session, args.cursor);
    object.insert(
        "address".to_string(),
        Value::from(parse_u64_argument(&args.address)?),
    );
    insert_option(&mut object, "max_bytes", args.max_bytes.map(Value::from));
    insert_option(&mut object, "policy", args.policy.map(Value::String));
    Ok(ToolCall {
        name: "ttd_memory_range".to_string(),
        arguments: Value::Object(object),
    })
}

fn memory_buffer_call(args: MemoryBufferArgs) -> anyhow::Result<ToolCall> {
    let mut object = cursor_object(args.session, args.cursor);
    object.insert(
        "address".to_string(),
        Value::from(parse_u64_argument(&args.address)?),
    );
    object.insert("size".to_string(), Value::from(args.size));
    insert_option(&mut object, "max_ranges", args.max_ranges.map(Value::from));
    insert_option(&mut object, "policy", args.policy.map(Value::String));
    Ok(ToolCall {
        name: "ttd_memory_buffer".to_string(),
        arguments: Value::Object(object),
    })
}

fn watchpoint_call(args: WatchpointArgs) -> anyhow::Result<ToolCall> {
    Ok(ToolCall {
        name: "ttd_memory_watchpoint".to_string(),
        arguments: json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": parse_u64_argument(&args.address)?,
            "size": args.size,
            "access": args.access,
            "direction": args.direction,
            "thread_unique_id": args.thread_unique_id,
        }),
    })
}

async fn disasm_and_print(
    pipe: String,
    args: DisasmArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(disasm_value(&client, &args).await?, output)
}

async fn disasm_value(client: &DaemonClient, args: &DisasmArgs) -> anyhow::Result<Value> {
    ensure!(args.count > 0, "count must be greater than zero");
    ensure!(args.count <= 256, "count must be 256 instructions or less");
    ensure!(args.bytes > 0, "bytes must be greater than zero");
    ensure!(args.bytes <= 4096, "bytes must be 4096 or less");

    let (address, context) = disasm_address(client, args).await?;
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: format!("0x{address:X}"),
            size: args.bytes,
            policy: args.policy.clone(),
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    Ok(json!({
        "session_id": args.session,
        "cursor_id": args.cursor,
        "architecture": "x64",
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "context": context,
        "read": read,
        "instructions": disassemble_x64(address, &bytes, args.count as usize),
    }))
}

async fn object_vtable_and_print(
    pipe: String,
    args: ObjectVtableArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(args.entries > 0, "entries must be greater than zero");
    ensure!(args.entries <= 256, "entries must be 256 or less");
    let object_address = parse_u64_argument(&args.address)?;
    let client = DaemonClient::new(pipe);
    let object_read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: format!("0x{object_address:X}"),
            size: 8,
            policy: args.policy.clone(),
        })?)
        .await?;
    let object_bytes = hex_to_bytes(
        object_read["data"]
            .as_str()
            .context("object pointer read did not include hex data")?,
    )?;
    ensure!(
        object_bytes.len() >= 8,
        "object pointer read returned fewer than 8 bytes"
    );
    let vtable_address = u64::from_le_bytes(object_bytes[..8].try_into()?);
    ensure!(vtable_address != 0, "object vtable pointer is null");

    let table_size = args.entries.saturating_mul(8);
    let vtable_read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: format!("0x{vtable_address:X}"),
            size: table_size,
            policy: args.policy,
        })?)
        .await?;
    let vtable_bytes = hex_to_bytes(
        vtable_read["data"]
            .as_str()
            .context("vtable read did not include hex data")?,
    )?;
    let mut entries = Vec::new();
    for (index, chunk) in vtable_bytes.chunks_exact(8).enumerate() {
        let target = u64::from_le_bytes(chunk.try_into()?);
        let target_info = if target == 0 {
            json!({ "ok": false, "error": "null vtable entry" })
        } else {
            call_status_value(
                client
                    .call_tool(ToolCall {
                        name: "ttd_address_info".to_string(),
                        arguments: json!({
                            "session_id": args.session,
                            "cursor_id": args.cursor,
                            "address": target,
                        }),
                    })
                    .await,
            )
        };
        entries.push(json!({
            "index": index,
            "slot_address": vtable_address + (index as u64 * 8),
            "slot_address_hex": format!("0x{:X}", vtable_address + (index as u64 * 8)),
            "target": target,
            "target_hex": format!("0x{target:X}"),
            "plausible_x64_pointer": plausible_x64_pointer(target),
            "target_info": target_info,
        }));
    }

    let vtable_info = call_status_value(
        client
            .call_tool(ToolCall {
                name: "ttd_address_info".to_string(),
                arguments: json!({
                    "session_id": args.session,
                    "cursor_id": args.cursor,
                    "address": vtable_address,
                }),
            })
            .await,
    );
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "object_address": object_address,
            "object_address_hex": format!("0x{object_address:X}"),
            "vtable_address": vtable_address,
            "vtable_address_hex": format!("0x{vtable_address:X}"),
            "object_read": object_read,
            "vtable_read": vtable_read,
            "vtable_info": vtable_info,
            "entries": entries,
            "safety": "read_only_analysis"
        }),
        output,
    )
}

async fn disasm_address(client: &DaemonClient, args: &DisasmArgs) -> anyhow::Result<(u64, Value)> {
    if let Some(address) = args.address.as_deref() {
        return Ok((
            parse_u64_argument(address)?,
            json!({ "source": "explicit" }),
        ));
    }

    let context = client
        .call_tool(register_context_call(RegisterContextArgs {
            session: args.session,
            cursor: args.cursor,
            thread_id: args.thread_id,
        }))
        .await
        .context("resolving current RIP with ttd_register_context")?;
    let rip = context["registers"]["rip"]
        .as_u64()
        .or_else(|| context["rip"].as_u64())
        .context("ttd_register_context response did not include registers.rip")?;
    Ok((
        rip,
        json!({ "source": "cursor_rip", "register_context": context }),
    ))
}

fn disassemble_x64(address: u64, bytes: &[u8], count: usize) -> Vec<Value> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instructions = Vec::new();
    while decoder.can_decode() && instructions.len() < count {
        let instruction = decoder.decode();
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let len = instruction.len();
        let offset = instruction.ip().saturating_sub(address) as usize;
        let end = offset.saturating_add(len).min(bytes.len());
        let instruction_bytes = if offset < bytes.len() {
            bytes[offset..end]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        instructions.push(json!({
            "address": instruction.ip(),
            "address_hex": format!("0x{:X}", instruction.ip()),
            "length": len,
            "bytes": instruction_bytes,
            "text": text,
            "mnemonic": format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
            "flow_control": format!("{:?}", instruction.flow_control()).to_ascii_lowercase(),
            "classification": instruction_classification(&instruction, &text),
            "operands": instruction_operands(&instruction),
        }));
    }
    instructions
}

fn instruction_classification(instruction: &Instruction, text: &str) -> Value {
    let lower = text.to_ascii_lowercase();
    let mut tags = Vec::new();
    match instruction.flow_control() {
        FlowControl::Next => {}
        FlowControl::Call | FlowControl::IndirectCall => tags.push("call"),
        FlowControl::Return => tags.push("return"),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => tags.push("jump"),
        FlowControl::ConditionalBranch => tags.push("conditional_jump"),
        FlowControl::Interrupt | FlowControl::XbeginXabortXend => tags.push("control_transfer"),
        _ => tags.push("control_transfer"),
    }
    if has_memory_operand(instruction) {
        tags.push("memory_access");
    }
    if lower.contains("rsp")
        || lower.contains("rbp")
        || lower.contains("esp")
        || lower.contains("ebp")
    {
        tags.push("stack_related");
    }
    if instruction.memory_segment() == Register::FS || instruction.memory_segment() == Register::GS
    {
        tags.push("teb_tls_segment");
    }
    if lower.contains("int3") || lower == "db 0cch" {
        tags.push("breakpoint");
    }
    if lower.starts_with("syscall") || lower.starts_with("sysenter") {
        tags.push("system_call");
    }
    json!({
        "tags": tags,
        "is_control_flow": instruction.flow_control() != FlowControl::Next,
        "has_memory_operand": has_memory_operand(instruction),
        "is_stack_related": lower.contains("rsp") || lower.contains("rbp") || lower.contains("esp") || lower.contains("ebp"),
    })
}

fn instruction_operands(instruction: &Instruction) -> Vec<Value> {
    (0..instruction.op_count())
        .map(|index| {
            let op_kind = instruction.op_kind(index);
            let mut operand = json!({
                "index": index,
                "kind": format!("{op_kind:?}").to_ascii_lowercase(),
            });
            if is_memory_op_kind(op_kind) {
                operand["memory"] = json!({
                    "segment": register_name(instruction.memory_segment()),
                    "base": register_name(instruction.memory_base()),
                    "index": register_name(instruction.memory_index()),
                    "scale": instruction.memory_index_scale(),
                    "displacement": instruction.memory_displacement64(),
                    "displacement_hex": format!("0x{:X}", instruction.memory_displacement64()),
                });
            }
            operand
        })
        .collect()
}

fn has_memory_operand(instruction: &Instruction) -> bool {
    (0..instruction.op_count()).any(|index| is_memory_op_kind(instruction.op_kind(index)))
}

fn is_memory_op_kind(op_kind: OpKind) -> bool {
    matches!(
        op_kind,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

fn register_name(register: Register) -> Option<String> {
    (register != Register::None).then(|| format!("{register:?}").to_ascii_lowercase())
}

async fn memory_dump_and_print(
    pipe: String,
    args: MemoryDumpArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let format = args.format.clone();
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let address = read["address"].as_u64().unwrap_or_default();
    print_value(
        json!({
            "read": read,
            "dump": memory_dump(address, &bytes, &format)?,
        }),
        output,
    )
}

async fn memory_classify_and_print(
    pipe: String,
    args: MemoryClassifyArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let address = read["address"].as_u64().unwrap_or_default();
    print_value(
        json!({
            "read": read,
            "classification": classify_memory(address, &bytes),
        }),
        output,
    )
}

async fn memory_strings_and_print(
    pipe: String,
    args: MemoryStringsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_strings <= 10_000,
        "memory strings --max-strings must not exceed 10000"
    );
    let client = DaemonClient::new(pipe);
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let address = read["address"].as_u64().unwrap_or_default();
    let mut strings = Vec::new();
    if args.encoding == "ascii" || args.encoding == "both" {
        strings.extend(
            ascii_strings(address, &bytes)
                .into_iter()
                .filter(|item| {
                    item["text"]
                        .as_str()
                        .is_some_and(|text| text.len() >= args.min_len)
                })
                .map(|mut item| {
                    item["encoding"] = Value::String("ascii".to_string());
                    item
                }),
        );
    }
    if args.encoding == "utf16" || args.encoding == "both" {
        strings.extend(
            utf16le_strings(address, &bytes)
                .into_iter()
                .filter(|item| {
                    item["text"]
                        .as_str()
                        .is_some_and(|text| text.len() >= args.min_len)
                })
                .map(|mut item| {
                    item["encoding"] = Value::String("utf16".to_string());
                    item
                }),
        );
    }
    strings.sort_by_key(|item| item["address"].as_u64().unwrap_or(u64::MAX));
    let total_strings = strings.len();
    if strings.len() > args.max_strings {
        strings.truncate(args.max_strings);
    }
    print_value(
        json!({
            "read": read,
            "encoding": args.encoding,
            "min_len": args.min_len,
            "total_strings": total_strings,
            "max_strings": args.max_strings,
            "returned": strings.len(),
            "limit": args.max_strings,
            "truncated": total_strings > args.max_strings,
            "strings": strings,
            "unavailable_bytes": if read["complete"].as_bool() == Some(false) { read["requested_size"].as_u64().unwrap_or_default().saturating_sub(read["bytes_read"].as_u64().unwrap_or_default()) } else { 0 }
        }),
        output,
    )
}

async fn memory_dps_and_print(
    pipe: String,
    args: MemoryDpsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        matches!(args.pointer_size, 4 | 8),
        "memory dps pointer size must be 4 or 8"
    );
    let client = DaemonClient::new(pipe);
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let base = read["address"].as_u64().unwrap_or_default();
    let mut rows = Vec::new();
    for (index, chunk) in bytes.chunks(args.pointer_size as usize).enumerate() {
        if chunk.len() < args.pointer_size as usize {
            break;
        }
        let slot = base + (index as u64 * args.pointer_size as u64);
        let target = read_pointer_value(chunk, args.pointer_size)?;
        let mut row = json!({
            "slot": slot,
            "slot_hex": format!("0x{slot:016x}"),
            "value": target,
            "value_hex": format!("0x{target:016x}"),
            "plausible_x64_pointer": plausible_x64_pointer(target),
            "null": target == 0
        });
        if args.target_info && target != 0 {
            row["target_info"] = call_status_value(
                client
                    .call_tool(address_info_call(AddressInfoArgs {
                        session: args.session,
                        cursor: args.cursor,
                        address: target.to_string(),
                    }))
                    .await,
            );
        }
        rows.push(row);
    }
    print_value(
        json!({
            "read": read,
            "pointer_size": args.pointer_size,
            "row_count": rows.len(),
            "rows": rows
        }),
        output,
    )
}

async fn memory_chase_and_print(
    pipe: String,
    args: MemoryChaseArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.depth > 0,
        "memory chase depth must be greater than zero"
    );
    ensure!(args.depth <= 256, "memory chase depth must not exceed 256");
    ensure!(
        matches!(args.pointer_size, 4 | 8),
        "memory chase pointer size must be 4 or 8"
    );

    let client = DaemonClient::new(pipe);
    let root_address = parse_u64_argument(&args.address)?;
    let mut current = root_address;
    let mut hops = Vec::new();
    let mut stop_reason = "max_depth";

    for depth in 0..args.depth {
        let read_address = current
            .checked_add(args.offset)
            .context("pointer read address overflowed")?;
        let read = client
            .call_tool(memory_read_call(MemoryReadArgs {
                session: args.session,
                cursor: args.cursor,
                address: read_address.to_string(),
                size: args.pointer_size,
                policy: args.policy.clone(),
            })?)
            .await?;
        let data = read["data"]
            .as_str()
            .context("ttd_read_memory response did not include hex data")?;
        let bytes = hex_to_bytes(data)?;
        let target = read_pointer_value(&bytes, args.pointer_size)?;
        let mut hop = json!({
            "index": depth,
            "base_address": current,
            "read_address": read_address,
            "offset": args.offset,
            "pointer_size": args.pointer_size,
            "bytes": data,
            "target": target,
            "target_hex": format!("0x{target:016x}"),
            "null": target == 0,
            "read": read,
        });

        if args.target_info && target != 0 {
            hop["target_info"] = client
                .call_tool(address_info_call(AddressInfoArgs {
                    session: args.session,
                    cursor: args.cursor,
                    address: target.to_string(),
                }))
                .await?;
        }

        hops.push(hop);
        if target == 0 {
            stop_reason = "null_pointer";
            break;
        }
        current = target;
    }

    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "root_address": root_address,
            "offset": args.offset,
            "pointer_size": args.pointer_size,
            "requested_depth": args.depth,
            "stop_reason": stop_reason,
            "hops": hops,
            "notes": [
                "Reads one pointer at base_address + offset per hop.",
                "Pointer chains are evidence, not proof of ownership or object type."
            ]
        }),
        output,
    )
}

fn memory_dump(address: u64, bytes: &[u8], format: &str) -> anyhow::Result<Value> {
    let rows = match format {
        "db" => dump_db_rows(address, bytes),
        "dq" => dump_dq_rows(address, bytes),
        "ascii" => ascii_strings(address, bytes),
        "utf16" => utf16le_strings(address, bytes),
        other => bail!("unsupported memory dump format: {other}"),
    };
    Ok(json!({
        "format": format,
        "rows": rows,
    }))
}

fn dump_db_rows(address: u64, bytes: &[u8]) -> Vec<Value> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let offset = row * 16;
            json!({
                "address": address + offset as u64,
                "offset": offset,
                "bytes": chunk.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>(),
                "ascii": chunk.iter().map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' }).collect::<String>(),
            })
        })
        .collect()
}

fn dump_dq_rows(address: u64, bytes: &[u8]) -> Vec<Value> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let offset = row * 16;
            let qwords = chunk
                .chunks(8)
                .filter(|chunk| chunk.len() == 8)
                .map(|chunk| {
                    let value = u64::from_le_bytes(chunk.try_into().expect("chunk length checked"));
                    json!({
                        "value": value,
                        "hex": format!("0x{value:016X}"),
                        "plausible_x64_pointer": plausible_x64_pointer(value),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "address": address + offset as u64,
                "offset": offset,
                "qwords": qwords,
            })
        })
        .collect()
}

fn classify_memory(address: u64, bytes: &[u8]) -> Value {
    json!({
        "address": address,
        "size": bytes.len(),
        "byte_histogram": byte_histogram_summary(bytes),
        "entropy_bits_per_byte": shannon_entropy(bytes),
        "ascii_strings": ascii_strings(address, bytes),
        "utf16le_strings": utf16le_strings(address, bytes),
        "qwords": qword_values(address, bytes),
        "instruction_hints": instruction_hints(bytes),
        "summary": memory_summary(bytes),
    })
}

fn memory_summary(bytes: &[u8]) -> Vec<&'static str> {
    let mut summary = Vec::new();
    if bytes.is_empty() {
        summary.push("empty");
        return summary;
    }
    let histogram = byte_counts(bytes);
    let zero_ratio = histogram[0] as f64 / bytes.len() as f64;
    let ff_ratio = histogram[0xff] as f64 / bytes.len() as f64;
    let max_ratio = histogram.iter().copied().max().unwrap_or_default() as f64 / bytes.len() as f64;
    let entropy = shannon_entropy(bytes);
    if zero_ratio >= 0.90 {
        summary.push("mostly_zero");
    }
    if ff_ratio >= 0.90 {
        summary.push("mostly_ff");
    }
    if max_ratio >= 0.90 {
        summary.push("repeated_fill_pattern");
    }
    if entropy >= 7.5 {
        summary.push("high_entropy");
    }
    if !ascii_strings(0, bytes).is_empty() {
        summary.push("contains_ascii");
    }
    if !utf16le_strings(0, bytes).is_empty() {
        summary.push("contains_utf16le");
    }
    if qword_values(0, bytes).as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["plausible_x64_pointer"] == true)
    }) {
        summary.push("contains_plausible_pointer");
    }
    if !instruction_hints(bytes).is_empty() {
        summary.push("instruction_like_prefix");
    }
    if summary.is_empty() {
        summary.push("unclassified");
    }
    summary
}

fn byte_histogram_summary(bytes: &[u8]) -> Value {
    let histogram = byte_counts(bytes);
    let mut top = histogram
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(byte, count)| {
            json!({
                "byte": byte,
                "hex": format!("{byte:02X}"),
                "count": count,
            })
        })
        .collect::<Vec<_>>();
    top.sort_by(|left, right| {
        right["count"]
            .as_u64()
            .cmp(&left["count"].as_u64())
            .then_with(|| left["byte"].as_u64().cmp(&right["byte"].as_u64()))
    });
    top.truncate(8);
    json!({
        "unique_bytes": histogram.iter().filter(|count| **count > 0).count(),
        "top": top,
    })
}

fn byte_counts(bytes: &[u8]) -> [usize; 256] {
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    counts
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let counts = byte_counts(bytes);
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn ascii_strings(address: u64, bytes: &[u8]) -> Vec<Value> {
    let mut strings = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            push_ascii_string(address, bytes, begin, index, &mut strings);
        }
    }
    if let Some(begin) = start {
        push_ascii_string(address, bytes, begin, bytes.len(), &mut strings);
    }
    strings
}

fn push_ascii_string(
    address: u64,
    bytes: &[u8],
    begin: usize,
    end: usize,
    strings: &mut Vec<Value>,
) {
    if end.saturating_sub(begin) >= 4 {
        strings.push(json!({
            "address": address + begin as u64,
            "offset": begin,
            "length": end - begin,
            "text": String::from_utf8_lossy(&bytes[begin..end]),
        }));
    }
}

fn utf16le_strings(address: u64, bytes: &[u8]) -> Vec<Value> {
    let mut strings = Vec::new();
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        let begin = index;
        let mut values = Vec::new();
        while index + 1 < bytes.len() {
            let value = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
            let Some(character) = char::from_u32(value as u32) else {
                break;
            };
            if !(character.is_ascii_graphic() || character == ' ') {
                break;
            }
            values.push(value);
            index += 2;
        }
        if values.len() >= 4 {
            strings.push(json!({
                "address": address + begin as u64,
                "offset": begin,
                "code_units": values.len(),
                "text": String::from_utf16_lossy(&values),
            }));
        }
        index = begin + 2;
    }
    strings
}

fn qword_values(address: u64, bytes: &[u8]) -> Value {
    let qwords = bytes
        .chunks_exact(8)
        .take(32)
        .enumerate()
        .map(|(index, chunk)| {
            let value = u64::from_le_bytes(chunk.try_into().expect("chunk size is exact"));
            json!({
                "address": address + (index * 8) as u64,
                "offset": index * 8,
                "value": value,
                "hex": format!("0x{value:016X}"),
                "aligned": value.is_multiple_of(8),
                "plausible_x64_pointer": plausible_x64_pointer(value),
            })
        })
        .collect::<Vec<_>>();
    json!(qwords)
}

fn plausible_x64_pointer(value: u64) -> bool {
    value != 0
        && value.is_multiple_of(8)
        && !(0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&value)
}

fn instruction_hints(bytes: &[u8]) -> Vec<Value> {
    let mut hints = Vec::new();
    if let Some(first) = bytes.first() {
        match *first {
            0x55 => hints.push(json!({"offset": 0, "kind": "push_rbp_prologue"})),
            0x48 | 0x4c => hints.push(json!({"offset": 0, "kind": "x64_rex_prefix"})),
            0xe8 => hints.push(json!({"offset": 0, "kind": "relative_call"})),
            0xe9 | 0xeb => hints.push(json!({"offset": 0, "kind": "relative_jump"})),
            0xc3 | 0xc2 => hints.push(json!({"offset": 0, "kind": "return"})),
            0xcc => hints.push(json!({"offset": 0, "kind": "int3_breakpoint"})),
            _ => {}
        }
    }
    for (offset, window) in bytes.windows(2).take(32).enumerate() {
        if window == [0x0f, 0x05] {
            hints.push(json!({"offset": offset, "kind": "syscall"}));
        }
    }
    hints
}

fn hex_to_bytes(data: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(data.len().is_multiple_of(2), "hex data length must be even");
    (0..data.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&data[index..index + 2], 16)
                .with_context(|| format!("parsing hex byte at offset {index}"))
        })
        .collect()
}

fn read_pointer_value(bytes: &[u8], pointer_size: u32) -> anyhow::Result<u64> {
    match pointer_size {
        4 => {
            ensure!(bytes.len() >= 4, "pointer read returned fewer than 4 bytes");
            let mut value = [0_u8; 4];
            value.copy_from_slice(&bytes[..4]);
            Ok(u32::from_le_bytes(value) as u64)
        }
        8 => {
            ensure!(bytes.len() >= 8, "pointer read returned fewer than 8 bytes");
            let mut value = [0_u8; 8];
            value.copy_from_slice(&bytes[..8]);
            Ok(u64::from_le_bytes(value))
        }
        other => bail!("unsupported pointer size: {other}"),
    }
}

fn session_object(session: u64) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("session_id".to_string(), Value::from(session));
    object
}

fn cursor_object(session: u64, cursor: u64) -> Map<String, Value> {
    let mut object = session_object(session);
    object.insert("cursor_id".to_string(), Value::from(cursor));
    object
}

fn insert_option(object: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        object.insert(key.to_string(), value);
    }
}

fn parse_position_argument(value: &str) -> anyhow::Result<Value> {
    if let Ok(percent) = value.parse::<u8>() {
        return Ok(json!(percent));
    }
    if value.trim_start().starts_with('{') {
        return serde_json::from_str(value).context("parsing JSON position object");
    }
    Ok(json!(value))
}

fn parse_u64_argument(value: &str) -> anyhow::Result<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).context("parsing hexadecimal integer");
    }
    value.parse::<u64>().context("parsing decimal integer")
}

fn ensure_json_object(value: Value) -> anyhow::Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        bail!("tool arguments must be a JSON object")
    }
}

fn query_policy_values() -> [&'static str; 5] {
    [
        "default",
        "thread_local",
        "globally_conservative",
        "globally_aggressive",
        "in_fragment_aggressive",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_debug_subject_exclusively() -> anyhow::Result<()> {
        let subject = resolve_debug_subject(
            &DebugSubjectArgs {
                session: Some(7),
                cursor: Some(9),
                target: None,
            },
            true,
        )?;
        assert!(matches!(
            subject,
            Some(DebugSubject::Ttd {
                session: 7,
                cursor: Some(9)
            })
        ));

        let conflict = resolve_debug_subject(
            &DebugSubjectArgs {
                session: Some(7),
                cursor: None,
                target: Some(3),
            },
            false,
        );
        assert!(conflict.is_err());
        Ok(())
    }

    #[test]
    fn builds_standard_diagnostic_shape() {
        let diagnostic = diagnostic_item(
            "daemon.unavailable",
            "blocker",
            "Daemon is unavailable.",
            "The daemon pipe could not be reached.",
            "high",
            Some(fix_item(
                "Start the daemon.",
                Some("windbg-tool daemon ensure"),
            )),
        );
        assert_eq!(diagnostic["id"], "daemon.unavailable");
        assert_eq!(diagnostic["severity"], "blocker");
        assert_eq!(diagnostic["fix"]["command"], "windbg-tool daemon ensure");
    }

    #[test]
    fn breakpoint_plan_supports_ttd_write_watchpoint() -> anyhow::Result<()> {
        let plan = breakpoint_plan_value(BreakpointPlanArgs {
            subject: DebugSubjectArgs {
                session: Some(1),
                cursor: Some(2),
                target: None,
            },
            address: Some("0x1000".to_string()),
            symbol: None,
            module: None,
            kind: "write".to_string(),
            size: Some(8),
            direction: Some("previous".to_string()),
            thread_unique_id: None,
        })?;
        assert_eq!(plan["supported"], true);
        assert_eq!(plan["safety"], "bounded_replay");
        assert_eq!(plan["request"]["address"], "0x1000");
        Ok(())
    }

    #[test]
    fn exception_focus_uses_json_position_and_owning_thread() -> anyhow::Result<()> {
        let exception = json!({
            "position": { "sequence": 479966, "steps": 0 },
            "thread_unique_id": 13,
            "code": 0xE06D7363u64
        });
        let call = exception_focus_call(7, 9, &exception)?;

        assert_eq!(call.name, "ttd_position_set");
        assert_eq!(call.arguments["session_id"], 7);
        assert_eq!(call.arguments["cursor_id"], 9);
        assert_eq!(call.arguments["position"]["sequence"], 479966);
        assert_eq!(call.arguments["thread_unique_id"], 13);
        assert_eq!(position_hex_text(&exception["position"])?, "752DE:0");
        Ok(())
    }

    #[test]
    fn timeline_source_summary_omits_unbounded_items() {
        let source = json!({
            "ok": true,
            "value": [{ "sequence": 1 }, { "sequence": 2 }]
        });
        let summary = timeline_source_summary(&source, "keyframes");

        assert_eq!(summary["ok"], true);
        assert_eq!(summary["item_count"], 2);
        assert_eq!(summary["items_omitted"], true);
        assert!(summary.get("value").is_none());
    }

    #[test]
    fn timeline_collects_top_level_exception_arrays() {
        let source = json!({
            "ok": true,
            "value": [{
                "position": { "sequence": 479966, "steps": 0 },
                "code": 0xE06D7363u64
            }]
        });
        let mut events = Vec::new();

        collect_timeline_events(&mut events, "exception", &source, "exceptions");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "exception");
        assert_eq!(events[0]["sequence"], 479966);
    }

    #[test]
    fn action_log_command_path_redacts_option_values() {
        let path = command_path_from_args(
            [
                "--compact",
                "debug",
                "snapshot",
                "--session",
                "7",
                "--cursor",
                "9",
            ]
            .into_iter()
            .map(str::to_string),
        );
        assert_eq!(path, vec!["debug", "snapshot"]);

        let path = command_path_from_args(
            ["--compact", "open", "C:\\sensitive\\trace.run"]
                .into_iter()
                .map(str::to_string),
        );
        assert_eq!(path, vec!["open"]);

        let path = command_path_from_args(
            [
                "debug",
                "log",
                "summarize",
                "--path",
                "C:\\logs\\actions.jsonl",
            ]
            .into_iter()
            .map(str::to_string),
        );
        assert_eq!(path, vec!["debug", "log", "summarize"]);
    }

    #[test]
    fn classifies_strings_fill_and_pointers() {
        let bytes = [
            b'H', b'e', b'l', b'l', b'o', 0, 0, 0, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let classification = classify_memory(0x1000, &bytes);
        assert!(
            classification["ascii_strings"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["text"] == "Hello")),
            "{classification}"
        );
        assert!(
            classification["qwords"]
                .as_array()
                .is_some_and(|items| items
                    .iter()
                    .any(|item| item["plausible_x64_pointer"] == true)),
            "{classification}"
        );
    }

    #[test]
    fn parses_hex_bytes_for_memory_classification() -> anyhow::Result<()> {
        assert_eq!(hex_to_bytes("4869ff")?, vec![0x48, 0x69, 0xff]);
        assert!(hex_to_bytes("123").is_err());
        Ok(())
    }

    #[test]
    fn dumps_memory_as_db_and_dq_rows() -> anyhow::Result<()> {
        let bytes = hex_to_bytes("48656c6c6f0000000010400000000000")?;
        let db = memory_dump(0x1000, &bytes, "db")?;
        assert_eq!(db["rows"][0]["ascii"], "Hello.....@.....");
        let dq = memory_dump(0x1000, &bytes, "dq")?;
        assert_eq!(dq["rows"][0]["qwords"].as_array().unwrap().len(), 2);
        Ok(())
    }

    #[test]
    fn reads_little_endian_pointer_values() -> anyhow::Result<()> {
        assert_eq!(
            read_pointer_value(&hex_to_bytes("78563412")?, 4)?,
            0x12345678
        );
        assert_eq!(
            read_pointer_value(&hex_to_bytes("8877665544332211")?, 8)?,
            0x1122334455667788
        );
        assert!(read_pointer_value(&[0, 1, 2], 4).is_err());
        Ok(())
    }

    #[test]
    fn disassembles_and_classifies_x64_instructions() -> anyhow::Result<()> {
        let bytes = hex_to_bytes("554889e5e801000000c3")?;
        let instructions = disassemble_x64(0x140001000, &bytes, 4);
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "call"))),
            "{instructions:?}"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "return"))),
            "{instructions:?}"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "stack_related"))),
            "{instructions:?}"
        );
        Ok(())
    }

    #[test]
    fn recovers_stack_candidates_from_module_pointers() {
        let stack = json!({
            "pointers": [
                {
                    "offset": 0,
                    "address": 0x1000u64,
                    "value": 0x7ff612341000u64,
                    "module": "app.exe"
                },
                {
                    "offset": 8,
                    "address": 0x1008u64,
                    "value": 0x1234u64,
                    "module": null
                }
            ]
        });
        let candidates = recover_stack_candidates(&stack, 8, 0.5);
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0]["module"], "app.exe");
        assert!(
            candidates[0]["reasons"]
                .as_array()
                .is_some_and(|reasons| reasons
                    .iter()
                    .any(|reason| reason == "target_in_loaded_module")),
            "{candidates:?}"
        );
    }

    #[test]
    fn audits_suspicious_module_paths() {
        let modules = vec![
            json!({
                "name": "good.dll",
                "path": r"C:\Windows\System32\good.dll",
                "base_address": 0x1000u64,
                "size": 4096,
                "load_position": null,
                "unload_position": null
            }),
            json!({
                "name": "odd.dll",
                "path": r"C:\Users\user\Downloads\odd.dll",
                "base_address": 0x2000u64,
                "size": 4096,
                "load_position": null,
                "unload_position": null
            }),
            json!({
                "name": "odd.dll",
                "path": r"C:\Temp\odd.dll",
                "base_address": 0x3000u64,
                "size": 4096,
                "load_position": null,
                "unload_position": null
            }),
        ];
        let audit = audit_modules(&modules, 16);
        assert!(
            audit["summary"]["temp_or_download_path"]
                .as_u64()
                .unwrap_or_default()
                >= 2,
            "{audit}"
        );
        assert_eq!(audit["summary"]["duplicate_name_groups"].as_u64(), Some(1));
    }

    #[test]
    fn normalizes_dll_search_order_names() -> anyhow::Result<()> {
        assert_eq!(normalize_dll_name("example")?, "example.dll");
        assert_eq!(normalize_dll_name("example.dll")?, "example.dll");
        assert!(normalize_dll_name(r"C:\temp\example.dll").is_err());
        Ok(())
    }

    #[test]
    fn builds_target_dump_tool_call() {
        let call = target_dump_call(TargetDumpArgs {
            target: 7,
            output: PathBuf::from(r"C:\dumps\app.dmp"),
            kind: CliDumpKind::Full,
            overwrite: true,
        });
        assert_eq!(call.name, "target_write_dump");
        assert_eq!(call.arguments["target_id"], 7);
        assert_eq!(call.arguments["path"], r"C:\dumps\app.dmp");
        assert_eq!(call.arguments["kind"], "full");
        assert_eq!(call.arguments["overwrite"], true);
    }

    #[test]
    fn builds_bounded_target_observability_tool_calls() -> anyhow::Result<()> {
        let accounting = target_thread_accounting_call(TargetThreadAccountingArgs {
            target: 7,
            max_threads: 32,
        });
        assert_eq!(accounting.name, "target_thread_accounting");
        assert_eq!(accounting.arguments["target_id"], 7);
        assert_eq!(accounting.arguments["max_threads"], 32);

        let parameters = target_module_parameters_call(TargetModuleParametersArgs {
            target: 7,
            module_bases: vec!["0x1000".to_string(), "0x2000".to_string()],
        })?;
        assert_eq!(parameters.name, "target_module_parameters");
        assert_eq!(
            parameters.arguments["module_base_addresses"],
            json!([0x1000, 0x2000])
        );
        assert!(target_module_parameters_call(TargetModuleParametersArgs {
            target: 7,
            module_bases: vec!["0x1000".to_string(), "0x1000".to_string()],
        })
        .is_err());
        Ok(())
    }

    #[test]
    fn builds_live_control_tool_calls() -> anyhow::Result<()> {
        let breakpoint = breakpoint_set_call(BreakpointSetArgs {
            target: 7,
            address: None,
            symbol: Some("app!EntryPoint".to_string()),
            kind: "code".to_string(),
            size: None,
        })?;
        assert_eq!(breakpoint.name, "target_set_breakpoint");
        assert_eq!(breakpoint.arguments["address"], Value::Null);
        assert_eq!(breakpoint.arguments["symbol"], "app!EntryPoint");

        let output = target_continue_wait_call(TargetContinueWaitArgs {
            target: 7,
            timeout_ms: 500,
            capture_debuggee_output: true,
            max_output_records: 4,
            max_output_chars: 64,
            max_total_output_chars: 256,
        });
        assert_eq!(output.name, "target_continue_wait");
        assert_eq!(output.arguments["capture_debuggee_output"], true);
        assert_eq!(output.arguments["max_total_output_chars"], 256);

        let disable = breakpoint_enable_call(
            BreakpointEnableArgs {
                target: 7,
                breakpoint_id: 3,
            },
            false,
        );
        assert_eq!(disable.name, "target_set_breakpoint_enabled");
        assert_eq!(disable.arguments["enabled"], false);
        Ok(())
    }

    #[test]
    fn selects_dump_contract_from_wrapped_target_status() {
        let dump_status = json!({
            "ok": true,
            "value": {
                "target": {
                    "kind": "dump"
                }
            }
        });
        assert_eq!(dbgeng_backend_for_status(&dump_status), "dbgeng_dump");

        let live_status = json!({
            "ok": true,
            "value": {
                "target": {
                    "kind": "live"
                }
            }
        });
        assert_eq!(dbgeng_backend_for_status(&live_status), "dbgeng_live");
    }
}
