use anyhow::{bail, ensure, Context};
use clap::{Arg, Args, Command, CommandFactory, Parser, Subcommand, ValueEnum};
use rmcp::{transport::stdio, ServiceExt};
use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use windbg_ttd::analysis::{
    breakpoint_plan as shared_breakpoint_plan,
    debug_capabilities_offline as shared_debug_capabilities_offline,
    debug_log_summarize as shared_debug_log_summarize,
    module_search_order as shared_module_search_order, parse_u64_argument, recipes_manifest,
    recipes_value as shared_recipes_value, source_resolve as shared_source_resolve,
    BreakpointPlanRequest, DebugLogSummarizeRequest, ModuleSearchOrderRequest,
    SourceResolveRequest,
};
use windbg_ttd::backend::capability_catalog;
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
    // Offline catalog does not need the daemon; session/target enrichment does.
    if args.subject.session.is_none() && args.subject.target.is_none() {
        return print_value(shared_debug_capabilities_offline(), output);
    }
    call_and_print(
        pipe,
        ToolCall {
            name: "debug_capabilities".into(),
            arguments: json!({
                "session_id": args.subject.session,
                "cursor_id": args.subject.cursor,
                "target_id": args.subject.target,
            }),
        },
        output,
    )
    .await
}

#[cfg(test)]
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
    DaemonClient::new(pipe)
        .call_tool(ToolCall {
            name: "debug_snapshot".into(),
            arguments: json!({
                "session_id": args.subject.session,
                "cursor_id": args.subject.cursor,
                "target_id": args.subject.target,
                "include": args.include,
                "exclude": args.exclude,
                "max_frames": args.max_frames,
                "max_modules": args.max_modules,
                "max_threads": args.max_threads,
                "disasm_count": args.disasm_count,
                "section_timeout_ms": args.section_timeout_ms,
            }),
        })
        .await
}
async fn symbols_doctor_and_print(
    pipe: String,
    args: SymbolDoctorArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "symbols_doctor".into(),
            arguments: json!({
                "session_id": args.subject.session,
                "cursor_id": args.subject.cursor,
                "target_id": args.subject.target,
                "address": args.address,
            }),
        },
        output,
    )
    .await
}

async fn triage_and_print(
    pipe: String,
    kind: &'static str,
    args: TriageArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "triage_run".into(),
            arguments: json!({
                "kind": kind,
                "session_id": args.subject.session,
                "cursor_id": args.subject.cursor,
                "target_id": args.subject.target,
                "max_frames": args.max_frames,
                "max_modules": args.max_modules,
                "max_threads": args.max_threads,
            }),
        },
        output,
    )
    .await
}
async fn breakpoint_plan_and_print(
    _pipe: String,
    args: BreakpointPlanArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(breakpoint_plan_value(args)?, output)
}

async fn run_mcp_stdio(pipe: String) -> anyhow::Result<()> {
    let server = if prefer_in_process_mcp() {
        TtdMcpServer::local()
    } else {
        daemon_mode::ensure_daemon(&pipe)
            .await
            .with_context(|| format!("MCP requires a healthy daemon on {pipe}"))?;
        TtdMcpServer::daemon(DaemonClient::new(pipe))
    };

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

fn prefer_in_process_mcp() -> bool {
    matches!(
        std::env::var("WINDBG_TOOL_MCP_IN_PROCESS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

async fn open_and_print(
    pipe: String,
    args: OpenArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let mut arguments = json!({
        "trace_path": args.trace_path,
        "companion_path": args.companion_path,
        "trace_index": args.trace_index,
        "thread_unique_id": args.thread_unique_id,
        "symbols": {
            "binary_paths": args.binary_paths,
            "symbol_paths": args.symbol_paths,
            "symcache_dir": args.symcache_dir,
        }
    });
    if let Some(position) = args.position.as_deref() {
        arguments["position"] = parse_position_argument(position)?;
    }
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_open".into(),
            arguments,
        },
        output,
    )
    .await
}

async fn context_snapshot_and_print(
    pipe: String,
    args: ContextSnapshotArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(context_snapshot_value(pipe, args).await?, output)
}

async fn context_snapshot_value(pipe: String, args: ContextSnapshotArgs) -> anyhow::Result<Value> {
    DaemonClient::new(pipe)
        .call_tool(ToolCall {
            name: "ttd_context_snapshot".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
            }),
        })
        .await
}
async fn symbols_diagnose_and_print(
    pipe: String,
    args: SymbolDiagnoseArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "symbols_diagnose".into(),
            arguments: json!({
                "session_id": args.session,
                "name": args.name,
                "address": args.address,
            }),
        },
        output,
    )
    .await
}

fn symbols_inspect_and_print(
    args: SymbolInspectArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(
        windbg_ttd::analysis::pe_inspect(windbg_ttd::analysis::PeInspectRequest {
            path: args.path,
        })?,
        output,
    )
}

fn symbols_exports_and_print(
    args: SymbolExportsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(
        windbg_ttd::analysis::pe_exports(windbg_ttd::analysis::PeExportsRequest {
            path: args.path,
            filter: args.filter,
            max: args.max,
        })?,
        output,
    )
}

async fn symbols_nearest_and_print(
    pipe: String,
    args: SymbolNearestArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_symbols_nearest".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "include_exports": args.include_exports,
            }),
        },
        output,
    )
    .await
}

fn source_resolve(args: SourceResolveArgs) -> anyhow::Result<Value> {
    shared_source_resolve(SourceResolveRequest {
        recorded_path: args.recorded_path,
        search_paths: args.search_paths,
        max_candidates: args.max_candidates,
        max_depth: args.max_depth,
    })
}

async fn architecture_state_and_print(
    pipe: String,
    args: ArchitectureStateArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_architecture_state".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "thread_id": args.thread_id,
            }),
        },
        output,
    )
    .await
}

fn call_status_value(result: anyhow::Result<Value>) -> Value {
    match result {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum DebugSubject {
    Ttd { session: u64, cursor: Option<u64> },
    Target { target: u64 },
}

#[cfg(test)]
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

fn breakpoint_plan_value(args: BreakpointPlanArgs) -> anyhow::Result<Value> {
    shared_breakpoint_plan(BreakpointPlanRequest {
        session_id: args.subject.session,
        cursor_id: args.subject.cursor,
        target_id: args.subject.target,
        address: args.address,
        symbol: args.symbol,
        module: args.module,
        kind: args.kind,
        size: args.size,
        direction: args.direction,
        thread_unique_id: args.thread_unique_id,
    })
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
    shared_debug_log_summarize(DebugLogSummarizeRequest {
        path: args.path,
        max: args.max,
    })
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
    let mut value = shared_recipes_value(args.topic.as_deref())?;
    if args.topic.is_none() {
        value["usage"] = json!("windbg-tool recipes <id-or-tag>");
    }
    Ok(value)
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

fn tool_command_map() -> Value {
    json!([
        { "tool": "discover", "commands": ["discover"] },
        { "tool": "recipes_list", "commands": ["recipes"] },
        { "tool": "recipes_get", "commands": ["recipes <topic>"] },
        { "tool": "debug_capabilities", "commands": ["debug capabilities"] },
        { "tool": "daemon_health", "commands": ["daemon status"] },
        { "tool": "session_list", "commands": ["sessions"] },
        { "tool": "ttd_open", "commands": ["open"] },
        { "tool": "ttd_context_snapshot", "commands": ["context snapshot"] },
        { "tool": "debug_snapshot", "commands": ["debug snapshot"] },
        { "tool": "triage_run", "commands": ["triage crash", "triage hang", "triage access-violation", "triage memory-corruption", "triage loader", "triage symbol-health", "triage deadlock"] },
        { "tool": "daemon_health", "commands": ["daemon status", "daemon ensure"] },
        { "tool": "session_list", "commands": ["sessions"] },
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
                { "tool": "ttd_stack_recover", "commands": ["stack recover"] },
                { "tool": "ttd_stack_backtrace", "commands": ["stack backtrace"] },
                { "tool": "ttd_command_line", "commands": ["command-line", "cmdline"] },
                { "tool": "ttd_read_memory", "commands": ["memory read"] },
                { "tool": "ttd_memory_dump", "commands": ["memory dump"] },
                { "tool": "ttd_memory_classify", "commands": ["memory classify"] },
                { "tool": "ttd_memory_strings", "commands": ["memory strings"] },
                { "tool": "ttd_memory_dps", "commands": ["memory dps"] },
                { "tool": "ttd_memory_chase", "commands": ["memory chase"] },
                { "tool": "ttd_disassemble", "commands": ["disasm", "u"] },
                { "tool": "ttd_timeline_events", "commands": ["timeline events"] },
                { "tool": "ttd_exception_focus", "commands": ["exception focus"] },
                { "tool": "ttd_architecture_state", "commands": ["architecture state"] },
                { "tool": "ttd_module_audit", "commands": ["module audit"] },
                { "tool": "ttd_object_vtable", "commands": ["object vtable"] },
                { "tool": "module_search_order", "commands": ["module search-order"] },
                { "tool": "source_resolve", "commands": ["source resolve"] },
                { "tool": "breakpoint_plan", "commands": ["breakpoint plan"] },
                { "tool": "pe_inspect", "commands": ["symbols inspect"] },
                { "tool": "pe_exports", "commands": ["symbols exports"] },
                { "tool": "ttd_symbols_nearest", "commands": ["symbols nearest"] },
                { "tool": "symbols_diagnose", "commands": ["symbols diagnose"] },
                { "tool": "symbols_doctor", "commands": ["symbols doctor"] },
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
        { "tool": "ttd_watch_memory_sweep", "commands": ["sweep watch-memory"] },
        { "tool": "job_start_watch_memory_sweep", "commands": ["sweep watch-memory --background"] },
        { "tool": "ttd_replay_to", "commands": ["replay to"] },
        { "tool": "dump_inspect", "commands": ["dump inspect"] },
        { "tool": "dump_triage", "commands": ["dump triage"] },
        { "tool": "dump_pool_triage", "commands": ["dump pool-triage"] },
        { "tool": "remote_explain", "commands": ["remote explain"] },
        { "tool": "remote_server_command", "commands": ["remote server-command"] },
        { "tool": "remote_connect_command", "commands": ["remote connect-command"] },
        { "tool": "remote_doctor", "commands": ["remote doctor"] },
        { "tool": "remote_status", "commands": ["remote status"] },
        { "tool": "remote_plan", "commands": ["remote plan"] },
        { "tool": "debug_log_summarize", "commands": ["debug log summarize"] },
        { "tool": "target_disassemble_analysis", "commands": ["target analysis disasm"] },
        { "tool": "target_memory_dump", "commands": ["target analysis memory-dump"] },
        { "tool": "target_memory_classify", "commands": ["target analysis memory-classify"] },
        { "tool": "target_memory_strings", "commands": ["target analysis memory-strings"] },
        { "tool": "target_memory_dps", "commands": ["target analysis memory-dps"] },
        { "tool": "target_memory_chase", "commands": ["target analysis memory-chase"] },
        { "tool": "target_stack_recover", "commands": ["target analysis stack-recover"] },
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
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_module_audit".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "max_suspicious": args.max_suspicious,
            }),
        },
        output,
    )
    .await
}

async fn timeline_events_and_print(
    pipe: String,
    args: TimelineEventsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(
        timeline_events_value(&DaemonClient::new(pipe), &args).await?,
        output,
    )
}

async fn timeline_events_value(
    client: &DaemonClient,
    args: &TimelineEventsArgs,
) -> anyhow::Result<Value> {
    client
        .call_tool(ToolCall {
            name: "ttd_timeline_events".into(),
            arguments: json!({
                "session_id": args.session,
                "kind": args.kind,
                "max_events": args.max_events,
            }),
        })
        .await
}

fn module_search_order_and_print(
    args: ModuleSearchOrderArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    print_value(
        shared_module_search_order(ModuleSearchOrderRequest {
            dll: args.dll,
            app_dir: args.app_dir,
            current_dir: args.current_dir,
            max_path_dirs: args.max_path_dirs,
        })?,
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
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_replay_to".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "position": parse_position_argument(&args.position)?,
                "thread_unique_id": args.thread_unique_id,
            }),
        },
        output,
    )
    .await
}

async fn exception_focus_and_print(
    pipe: String,
    args: ExceptionFocusArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_exception_focus".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "index": args.index,
            }),
        },
        output,
    )
    .await
}

async fn sweep_watch_memory_and_print(
    pipe: String,
    args: SweepWatchMemoryArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_watch_memory_sweep".into(),
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
        },
        output,
    )
    .await
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
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_stack_recover".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "size": args.size,
                "offset_from_sp": args.offset_from_sp,
                "max_candidates": args.max_candidates,
                "min_confidence": args.min_confidence,
                "target_info": args.target_info,
            }),
        },
        output,
    )
    .await
}

async fn stack_backtrace_and_print(
    pipe: String,
    args: StackBacktraceArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_stack_backtrace".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "size": args.size,
                "offset_from_sp": args.offset_from_sp,
                "max_frames": args.max_frames,
                "min_confidence": args.min_confidence,
                "target_info": args.target_info,
            }),
        },
        output,
    )
    .await
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
    print_value(disasm_value(&DaemonClient::new(pipe), &args).await?, output)
}

async fn disasm_value(client: &DaemonClient, args: &DisasmArgs) -> anyhow::Result<Value> {
    client
        .call_tool(ToolCall {
            name: "ttd_disassemble".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "count": args.count,
                "bytes": args.bytes,
                "policy": args.policy,
                "thread_id": args.thread_id,
            }),
        })
        .await
}

async fn object_vtable_and_print(
    pipe: String,
    args: ObjectVtableArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_object_vtable".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "entries": args.entries,
                "policy": args.policy,
            }),
        },
        output,
    )
    .await
}

async fn memory_dump_and_print(
    pipe: String,
    args: MemoryDumpArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_memory_dump".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "size": args.size,
                "policy": args.policy,
                "format": args.format,
            }),
        },
        output,
    )
    .await
}

async fn memory_classify_and_print(
    pipe: String,
    args: MemoryClassifyArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_memory_classify".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "size": args.size,
                "policy": args.policy,
            }),
        },
        output,
    )
    .await
}

async fn memory_strings_and_print(
    pipe: String,
    args: MemoryStringsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_memory_strings".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "size": args.size,
                "policy": args.policy,
                "encoding": args.encoding,
                "min_len": args.min_len,
                "max_strings": args.max_strings,
            }),
        },
        output,
    )
    .await
}

async fn memory_dps_and_print(
    pipe: String,
    args: MemoryDpsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_memory_dps".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "size": args.size,
                "policy": args.policy,
                "pointer_size": args.pointer_size,
                "target_info": args.target_info,
            }),
        },
        output,
    )
    .await
}

async fn memory_chase_and_print(
    pipe: String,
    args: MemoryChaseArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    call_and_print(
        pipe,
        ToolCall {
            name: "ttd_memory_chase".into(),
            arguments: json!({
                "session_id": args.session,
                "cursor_id": args.cursor,
                "address": args.address,
                "offset": args.offset,
                "depth": args.depth,
                "pointer_size": args.pointer_size,
                "policy": args.policy,
                "target_info": args.target_info,
            }),
        },
        output,
    )
    .await
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
    use windbg_ttd::analysis::{audit_modules, normalize_dll_name};
    use windbg_ttd::analysis::{
        classify_memory, collect_timeline_events, disassemble_x64, hex_to_bytes, memory_dump,
        read_pointer_value, recover_stack_candidates, timeline_source_summary,
    };

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
        assert_eq!(
            subject,
            Some(DebugSubject::Ttd {
                session: 7,
                cursor: Some(9)
            })
        );

        let target_only = resolve_debug_subject(
            &DebugSubjectArgs {
                session: None,
                cursor: None,
                target: Some(3),
            },
            false,
        )?;
        assert_eq!(target_only, Some(DebugSubject::Target { target: 3 }));

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
