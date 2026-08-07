use clap::{error::ErrorKind, Parser};
use serde_json::json;

use super::daemon_mode;
use super::output::{invalid_argument, print_value, OutputOptions};
use super::platform;
use super::remote;
use super::*;

pub(super) async fn run_cli() -> anyhow::Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(());
        }
        Err(error) => return Err(invalid_argument(error.to_string()).into()),
    };
    let output = OutputOptions::new(cli.compact, cli.field, cli.raw, cli.envelope);
    let pipe = cli.pipe.unwrap_or_else(default_pipe_name);

    match cli.command {
        None | Some(Commands::Mcp) => run_mcp_stdio().await,
        Some(Commands::Discover) => print_value(discover_manifest(), &output),
        Some(Commands::Recipes(args)) => print_value(recipes_value(args)?, &output),
        Some(Commands::Schema(args)) => print_value(tool_schema(&args.tool)?, &output),
        Some(Commands::CliSchema(args)) => print_value(cli_schema(args)?, &output),
        Some(Commands::Trace { command }) => match command {
            TraceCommand::List(args) => call_and_print(pipe, trace_list_call(args), &output).await,
            TraceCommand::Record(args) => platform::run_trace_record(args, &output),
        },
        Some(Commands::TraceList(args)) => {
            call_and_print(pipe, trace_list_call(args), &output).await
        }
        Some(Commands::Daemon { command }) => {
            daemon_mode::run_daemon_command(command, pipe, &output).await
        }
        Some(Commands::DbgEng { command }) => match command {
            DbgEngCommand::Server(args) => platform::run_dbgeng_server(args, &output),
        },
        Some(Commands::Live { command }) => match command {
            LiveCommand::Launch(args) => platform::run_live_launch(args, &output),
            LiveCommand::StartupBreak(args) => platform::run_live_startup_break(args, &output),
            LiveCommand::StartupProfile(args) => platform::run_live_startup_profile(args, &output),
            LiveCommand::StartupCompare(args) => platform::run_live_startup_compare(args, &output),
            LiveCommand::StartupReport(args) => platform::run_live_startup_report(args, &output),
            LiveCommand::ManagedBreak(args) => platform::run_live_managed_break(args, &output),
            LiveCommand::Start(args) => live_start_and_print(pipe, args, &output).await,
            LiveCommand::Attach(args) => live_attach_and_print(pipe, args, &output).await,
            LiveCommand::Capabilities => print_value(platform::live_capabilities(), &output),
        },
        Some(Commands::Dump { command }) => match command {
            DumpCommand::Open(args) => dump_open_and_print(pipe, args, &output).await,
            DumpCommand::Inspect(args) => platform::run_dump_inspect(args, &output),
            DumpCommand::Triage(args) => platform::run_dump_inspect(args, &output),
            DumpCommand::PoolTriage(args) => platform::run_dump_inspect(args, &output),
            DumpCommand::Create(args) => platform::run_dump_create(args, &output),
        },
        Some(Commands::DbgSrv(args)) => platform::run_dbgeng_server(args, &output),
        Some(Commands::Remote { command }) => {
            print_value(remote::remote_command_value(command)?, &output)
        }
        Some(Commands::Debug { command }) => match command {
            DebugCommand::Capabilities(args) => {
                debug_capabilities_and_print(pipe, args, &output).await
            }
            DebugCommand::Snapshot(args) => debug_snapshot_and_print(pipe, args, &output).await,
            DebugCommand::Log { command } => match command {
                DebugLogCommand::Summarize(args) => debug_log_summarize_and_print(args, &output),
            },
        },
        Some(Commands::Triage { command }) => match command {
            TriageCommand::Crash(args) => triage_and_print(pipe, "crash", args, &output).await,
            TriageCommand::Hang(args) => triage_and_print(pipe, "hang", args, &output).await,
            TriageCommand::AccessViolation(args) => {
                triage_and_print(pipe, "access_violation", args, &output).await
            }
            TriageCommand::MemoryCorruption(args) => {
                triage_and_print(pipe, "memory_corruption", args, &output).await
            }
            TriageCommand::Loader(args) => triage_and_print(pipe, "loader", args, &output).await,
            TriageCommand::SymbolHealth(args) => {
                triage_and_print(pipe, "symbol_health", args, &output).await
            }
            TriageCommand::Deadlock(args) => {
                triage_and_print(pipe, "deadlock", args, &output).await
            }
        },
        Some(Commands::Windbg { command }) => platform::run_windbg_command(command, &output),
        Some(Commands::Open(args)) => open_and_print(pipe, args, &output).await,
        Some(Commands::Load(args)) => call_and_print(pipe, load_call(args), &output).await,
        Some(Commands::Sessions) => {
            let client = DaemonClient::new(pipe);
            print_value(client.sessions().await?, &output)
        }
        Some(Commands::Context { command }) => match command {
            ContextCommand::Snapshot(args) => context_snapshot_and_print(pipe, args, &output).await,
        },
        Some(Commands::Close(args)) => {
            call_and_print(pipe, session_call("ttd_close_trace", args), &output).await
        }
        Some(Commands::Info(args)) => {
            call_and_print(pipe, session_call("ttd_trace_info", args), &output).await
        }
        Some(Commands::Symbols { command }) => match command {
            SymbolsCommand::Diagnose(args) => symbols_diagnose_and_print(pipe, args, &output).await,
            SymbolsCommand::Inspect(args) => print_value(diagnose_pe(&args.path)?, &output),
            SymbolsCommand::Exports(args) => symbols_exports_and_print(args, &output),
            SymbolsCommand::Nearest(args) => symbols_nearest_and_print(pipe, args, &output).await,
            SymbolsCommand::Doctor(args) => symbols_doctor_and_print(pipe, args, &output).await,
        },
        Some(Commands::Source { command }) => match command {
            SourceCommand::Resolve(args) => print_value(source_resolve(args)?, &output),
        },
        Some(Commands::Architecture { command }) => match command {
            ArchitectureCommand::State(args) => {
                architecture_state_and_print(pipe, args, &output).await
            }
        },
        Some(Commands::Capabilities(args)) => {
            call_and_print(pipe, session_call("ttd_capabilities", args), &output).await
        }
        Some(Commands::Index { command }) => match command {
            IndexCommand::Status(args) => {
                call_and_print(pipe, session_call("ttd_index_status", args), &output).await
            }
            IndexCommand::Stats(args) => {
                call_and_print(pipe, session_call("ttd_index_stats", args), &output).await
            }
            IndexCommand::Build(args) => {
                call_and_print(pipe, index_build_call(args), &output).await
            }
        },
        Some(Commands::Tools) => print_value(json!({ "tools": tools::definitions() }), &output),
        Some(Commands::Tool(args)) => {
            let name = args.name.clone();
            let arguments = tool_arguments(args)?;
            call_and_print(pipe, ToolCall { name, arguments }, &output).await
        }
        Some(Commands::Threads(args)) => {
            call_and_print(pipe, session_call("ttd_list_threads", args), &output).await
        }
        Some(Commands::Modules(args)) => {
            call_and_print(pipe, session_call("ttd_list_modules", args), &output).await
        }
        Some(Commands::Keyframes(args)) => {
            call_and_print(pipe, session_call("ttd_list_keyframes", args), &output).await
        }
        Some(Commands::Exceptions(args)) => {
            call_and_print(pipe, session_call("ttd_list_exceptions", args), &output).await
        }
        Some(Commands::Exception { command }) => match command {
            ExceptionCommand::Focus(args) => exception_focus_and_print(pipe, args, &output).await,
        },
        Some(Commands::Events { command }) => match command {
            EventsCommand::Modules(args) => {
                call_and_print(pipe, session_call("ttd_module_events", args), &output).await
            }
            EventsCommand::Threads(args) => {
                call_and_print(pipe, session_call("ttd_thread_events", args), &output).await
            }
        },
        Some(Commands::Timeline { command }) => match command {
            TimelineCommand::Events(args) => timeline_events_and_print(pipe, args, &output).await,
        },
        Some(Commands::Module { command }) => match command {
            ModuleCommand::Info(args) => {
                call_and_print(pipe, module_info_call(args)?, &output).await
            }
            ModuleCommand::Audit(args) => module_audit_and_print(pipe, args, &output).await,
            ModuleCommand::SearchOrder(args) => module_search_order_and_print(args, &output),
        },
        Some(Commands::Address(args)) => {
            call_and_print(pipe, address_info_call(args), &output).await
        }
        Some(Commands::Cursor { command }) => match command {
            CursorCommand::Create(args) => {
                call_and_print(pipe, session_call("ttd_cursor_create", args), &output).await
            }
            CursorCommand::Modules(args) => {
                call_and_print(pipe, cursor_call("ttd_cursor_modules", args), &output).await
            }
        },
        Some(Commands::ActiveThreads(args)) => {
            call_and_print(pipe, cursor_call("ttd_active_threads", args), &output).await
        }
        Some(Commands::Position { command }) => match command {
            PositionCommand::Get(args) => {
                call_and_print(pipe, cursor_call("ttd_position_get", args), &output).await
            }
            PositionCommand::Set(args) => {
                call_and_print(pipe, position_set_call(args)?, &output).await
            }
        },
        Some(Commands::Step(args)) => call_and_print(pipe, step_call(args), &output).await,
        Some(Commands::Replay { command }) => match command {
            ReplayCommand::Capabilities(args) => {
                replay_capabilities_and_print(pipe, args, &output).await
            }
            ReplayCommand::To(args) => replay_to_and_print(pipe, args, &output).await,
            ReplayCommand::WatchMemory(args) => {
                call_and_print(pipe, watchpoint_call(args)?, &output).await
            }
        },
        Some(Commands::Sweep { command }) => match command {
            SweepCommand::WatchMemory(args) => {
                if args.background {
                    start_watch_memory_job_and_print(pipe, args, &output).await
                } else {
                    sweep_watch_memory_and_print(pipe, args, &output).await
                }
            }
        },
        Some(Commands::Job { command }) => match command {
            JobCommand::List => {
                call_and_print(
                    pipe,
                    ToolCall {
                        name: "job_list".to_string(),
                        arguments: json!({}),
                    },
                    &output,
                )
                .await
            }
            JobCommand::Status(args) => {
                call_and_print(pipe, job_call("job_status", args.job), &output).await
            }
            JobCommand::Result(args) => {
                call_and_print(pipe, job_call("job_result", args.job), &output).await
            }
            JobCommand::Cancel(args) => {
                call_and_print(pipe, job_call("job_cancel", args.job), &output).await
            }
        },
        Some(Commands::Breakpoint { command }) => match command {
            BreakpointCommand::Capabilities => {
                print_value(platform::breakpoint_capabilities(), &output)
            }
            BreakpointCommand::List(args) => {
                call_and_print(
                    pipe,
                    target_call("target_list_breakpoints", args.target),
                    &output,
                )
                .await
            }
            BreakpointCommand::Set(args) => {
                call_and_print(pipe, breakpoint_set_call(args)?, &output).await
            }
            BreakpointCommand::Enable(args) => {
                call_and_print(pipe, breakpoint_enable_call(args, true), &output).await
            }
            BreakpointCommand::Disable(args) => {
                call_and_print(pipe, breakpoint_enable_call(args, false), &output).await
            }
            BreakpointCommand::Remove(args) => {
                call_and_print(pipe, breakpoint_remove_call(args), &output).await
            }
            BreakpointCommand::Plan(args) => breakpoint_plan_and_print(pipe, args, &output).await,
        },
        Some(Commands::Datamodel { command }) => match command {
            DataModelCommand::Capabilities => {
                print_value(platform::datamodel_capabilities(), &output)
            }
            DataModelCommand::Eval(args) => {
                call_and_print(pipe, target_eval_call(args), &output).await
            }
        },
        Some(Commands::Target { command }) => match command {
            TargetCommand::Capabilities(args) => {
                target_capabilities_and_print(pipe, args, &output).await
            }
            TargetCommand::List => target_list_and_print(pipe, &output).await,
            TargetCommand::Status(args) => {
                call_and_print(pipe, target_call("target_status", args.target), &output).await
            }
            TargetCommand::Close(args) => {
                call_and_print(pipe, target_call("target_close", args.target), &output).await
            }
            TargetCommand::Terminate(args) => {
                call_and_print(pipe, target_call("target_terminate", args.target), &output).await
            }
            TargetCommand::Wait(args) => {
                call_and_print(pipe, target_wait_call(args), &output).await
            }
            TargetCommand::Continue(args) => {
                call_and_print(pipe, target_call("target_continue", args.target), &output).await
            }
            TargetCommand::ContinueWait(args) => {
                call_and_print(pipe, target_continue_wait_call(args), &output).await
            }
            TargetCommand::Step(args) => {
                call_and_print(pipe, target_call("target_step_into", args.target), &output).await
            }
            TargetCommand::StepOver(args) => {
                call_and_print(pipe, target_call("target_step_over", args.target), &output).await
            }
            TargetCommand::Threads(args) => {
                call_and_print(
                    pipe,
                    target_call("target_list_threads", args.target),
                    &output,
                )
                .await
            }
            TargetCommand::Modules(args) => {
                call_and_print(
                    pipe,
                    target_call("target_list_modules", args.target),
                    &output,
                )
                .await
            }
            TargetCommand::Registers(args) => {
                call_and_print(
                    pipe,
                    target_call("target_core_registers", args.target),
                    &output,
                )
                .await
            }
            TargetCommand::Event(args) => {
                call_and_print(pipe, target_call("target_last_event", args.target), &output).await
            }
            TargetCommand::Memory(args) => {
                call_and_print(pipe, target_memory_call(args)?, &output).await
            }
            TargetCommand::MemoryMap(args) => {
                call_and_print(pipe, target_memory_map_call(args), &output).await
            }
            TargetCommand::Address(args) => {
                call_and_print(pipe, target_address_inspect_call(args)?, &output).await
            }
            TargetCommand::ThreadAccounting(args) => {
                call_and_print(pipe, target_thread_accounting_call(args), &output).await
            }
            TargetCommand::ModuleParameters(args) => {
                call_and_print(pipe, target_module_parameters_call(args)?, &output).await
            }
            TargetCommand::Stack(args) => {
                call_and_print(pipe, target_stack_call(args), &output).await
            }
            TargetCommand::Thread(args) => {
                call_and_print(pipe, target_thread_context_call(args), &output).await
            }
            TargetCommand::Disasm(args) => {
                call_and_print(pipe, target_disasm_call(args)?, &output).await
            }
            TargetCommand::Symbol(args) => {
                call_and_print(
                    pipe,
                    target_address_call("target_symbol_by_offset", args)?,
                    &output,
                )
                .await
            }
            TargetCommand::SymbolEntryRange(args) => {
                call_and_print(
                    pipe,
                    target_address_call("target_symbol_entry_range", args)?,
                    &output,
                )
                .await
            }
            TargetCommand::Source(args) => {
                call_and_print(
                    pipe,
                    target_address_call("target_source_by_offset", args)?,
                    &output,
                )
                .await
            }
            TargetCommand::Dump(args) => {
                call_and_print(pipe, target_dump_call(args), &output).await
            }
        },
        Some(Commands::Disasm(args)) => disasm_and_print(pipe, args, &output).await,
        Some(Commands::Registers(args)) => {
            call_and_print(pipe, cursor_call("ttd_registers", args), &output).await
        }
        Some(Commands::RegisterContext(args)) => {
            call_and_print(pipe, register_context_call(args), &output).await
        }
        Some(Commands::Stack { command }) => match command {
            StackCommand::Info(args) => {
                call_and_print(pipe, cursor_call("ttd_stack_info", args), &output).await
            }
            StackCommand::Read(args) => call_and_print(pipe, stack_read_call(args), &output).await,
            StackCommand::Recover(args) => stack_recover_and_print(pipe, args, &output).await,
            StackCommand::Backtrace(args) => stack_backtrace_and_print(pipe, args, &output).await,
        },
        Some(Commands::CommandLine(args)) => {
            call_and_print(pipe, cursor_call("ttd_command_line", args), &output).await
        }
        Some(Commands::Memory { command }) => match command {
            MemoryCommand::Read(args) => {
                call_and_print(pipe, memory_read_call(args)?, &output).await
            }
            MemoryCommand::Range(args) => {
                call_and_print(pipe, memory_range_call(args)?, &output).await
            }
            MemoryCommand::Buffer(args) => {
                call_and_print(pipe, memory_buffer_call(args)?, &output).await
            }
            MemoryCommand::Dump(args) => memory_dump_and_print(pipe, args, &output).await,
            MemoryCommand::Classify(args) => memory_classify_and_print(pipe, args, &output).await,
            MemoryCommand::Strings(args) => memory_strings_and_print(pipe, args, &output).await,
            MemoryCommand::Dps(args) => memory_dps_and_print(pipe, args, &output).await,
            MemoryCommand::Chase(args) => memory_chase_and_print(pipe, args, &output).await,
            MemoryCommand::Watchpoint(args) => {
                call_and_print(pipe, watchpoint_call(args)?, &output).await
            }
        },
        Some(Commands::Object { command }) => match command {
            ObjectCommand::Vtable(args) => object_vtable_and_print(pipe, args, &output).await,
        },
        Some(Commands::Watchpoint(args)) => {
            call_and_print(pipe, watchpoint_call(args)?, &output).await
        }
    }
}
