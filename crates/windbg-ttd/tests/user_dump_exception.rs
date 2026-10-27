//! End-to-end check that `dump triage` decodes a captured user-mode exception.
//!
//! The test re-launches its own binary under DbgEng to run `crash_helper`, which faults on a
//! null-pointer read (`mov rax, [rcx]` with RCX = 0). It writes a full dump while stopped on the
//! first-chance access violation, then triages the dump. It is skipped when DbgEng cannot launch
//! the child, unless `WINDBG_TOOL_EXPECT_DBGENG` is set.

#![cfg(all(windows, target_arch = "x86_64"))]

use std::env;
use std::path::PathBuf;
use windbg_dbgeng::{launch_live_session, LiveInitialStop, LiveLaunchSessionOptions};
use windbg_ttd::analysis::{dump_triage, DumpTriageRequest};

const EXPECT_DBGENG_ENV: &str = "WINDBG_TOOL_EXPECT_DBGENG";
const ACCESS_VIOLATION: u32 = 0xC000_0005;

#[test]
#[ignore = "helper process for user_dump_exception_triage; faults deliberately"]
fn crash_helper() {
    // SAFETY: none; this deliberately dereferences null to produce a real access violation.
    unsafe {
        std::arch::asm!("mov rax, [rcx]", in("rcx") 0usize, out("rax") _);
    }
}

#[test]
fn user_dump_exception_triage() {
    // Live DbgEng sessions reject `srv*` symbol paths from `_NT_SYMBOL_PATH`; this test needs no
    // symbols, so drop a developer's symbol-server path. It is the only non-ignored test here.
    if env::var(windbg_dbgeng::NT_SYMBOL_PATH_ENV)
        .is_ok_and(|path| path.to_ascii_lowercase().contains("srv*"))
    {
        env::remove_var(windbg_dbgeng::NT_SYMBOL_PATH_ENV);
    }
    let exe = env::current_exe().expect("current test executable");
    let command_line = format!(
        "\"{}\" crash_helper --exact --ignored --test-threads=1 --nocapture",
        exe.display()
    );
    let session = match launch_live_session(LiveLaunchSessionOptions {
        command_line,
        initial_break_timeout_ms: 30_000,
        initial_stop: LiveInitialStop::SoftwareBreakpoint,
    }) {
        Ok(session) => session,
        Err(error) if env::var_os(EXPECT_DBGENG_ENV).is_none() => {
            eprintln!("skipping: DbgEng live launch is unavailable: {error:#}");
            return;
        }
        Err(error) => panic!("DbgEng live launch failed: {error:#}"),
    };

    let mut fault = None;
    for _ in 0..64 {
        let run = session
            .continue_and_wait(30_000, None)
            .expect("continue debuggee");
        let event = run.event.expect("debug event before timeout");
        if let Some(exception) = event
            .exception
            .as_ref()
            .filter(|e| e.code == ACCESS_VIOLATION)
        {
            let thread_id = session
                .core_registers()
                .expect("fault-time registers")
                .thread_system_id
                .expect("fault thread id");
            fault = Some((thread_id, exception.clone()));
            break;
        }
        assert!(
            event.exit_code.is_none(),
            "helper exited before faulting: {event:?}"
        );
    }
    let (thread_id, exception) = fault.expect("helper raised an access violation");
    assert!(exception.first_chance);

    let dump_dir = env::temp_dir().join(format!("windbg-tool-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dump_dir).unwrap();
    let dump_path = dump_dir.join("crash_helper.dmp");
    session
        .execute_command(&format!(".dump /ma /o \"{}\"", dump_path.display()))
        .expect("write dump with exception stream");
    let _ = session.terminate();
    drop(session);

    let result = dump_triage(DumpTriageRequest {
        path: dump_path.clone(),
        max_frames: 16,
        refresh_symbols: false,
        symbol_cache: dump_dir.join("symbols"),
        image_path: vec![exe.parent().map(PathBuf::from).unwrap()],
        offline: true,
        inspect_address: None,
        tracker_table_base: None,
        profile: None,
    })
    .expect("triage dump");
    let _ = std::fs::remove_dir_all(&dump_dir);

    let triage = &result["triage"];
    assert_eq!(result["triage_profile"], "user_exception_context");
    let record = &triage["exception_record"];
    assert_eq!(record["status"], "captured", "{record:#}");
    assert_eq!(record["thread_system_id"], thread_id);
    let selection = &record["selection"];
    assert_eq!(selection["exception_code"], ACCESS_VIOLATION);
    assert_eq!(selection["code_name"], "STATUS_ACCESS_VIOLATION");
    assert_eq!(selection["exception_address"], exception.address);
    assert_eq!(selection["access"]["operation"], "read");
    assert_eq!(selection["access"]["address"], 0);

    let context = &triage["exception_context"]["context"];
    assert_eq!(context["architecture"], "amd64", "{context:#}");
    assert_eq!(context["registers"]["rcx"], 0);
    assert_eq!(context["registers"]["rip"], exception.address);
    assert_eq!(context["instruction_pointer"], exception.address);
    let frames = context["stack"]["frames"]
        .as_array()
        .unwrap_or_else(|| panic!("exception-context stack: {context:#}"));
    assert_eq!(frames[0]["instruction_offset"], exception.address);

    let operand = &triage["fault_operand"];
    assert_eq!(operand["status"], "decoded", "{operand:#}");
    assert_eq!(operand["instruction"]["text"], "mov rax,[rcx]");
    assert_eq!(operand["matched_operand"], 0);
    assert!(operand["hints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|hint| hint["kind"] == "null_base_register" && hint["register"] == "rcx"));
}
