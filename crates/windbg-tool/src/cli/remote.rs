use anyhow::{bail, Context};
use serde_json::{json, Value};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::{
    diagnostic_item, fix_item, RemoteCommand, RemoteConnectCommandArgs, RemoteDoctorArgs,
    RemoteKind, RemotePlanArgs, RemoteServerCommandArgs, RemoteStatusArgs,
};

pub(super) fn remote_command_value(command: RemoteCommand) -> anyhow::Result<Value> {
    match command {
        RemoteCommand::Explain(args) => {
            let workflows = remote_workflows();
            let Some(kind) = args.kind else {
                return Ok(json!({
                    "workflows": workflows,
                    "default": "dbgsrv",
                    "recipes": ["windbg-tool recipes remote-debugging"],
                }));
            };
            Ok(json!({
                "workflow": remote_workflow(kind),
                "recipes": ["windbg-tool recipes remote-debugging"],
            }))
        }
        RemoteCommand::ServerCommand(args) => {
            if matches!(args.kind, RemoteKind::Ntsd)
                && args.pid.is_some()
                && args.executable.is_some()
            {
                bail!(
                    "remote server-command --kind ntsd accepts either --pid or --executable, not both"
                )
            }
            Ok(json!({
                "side": "target",
                "workflow": remote_workflow(args.kind),
                "command": remote_server_command(&args),
                "notes": remote_server_notes(&args),
            }))
        }
        RemoteCommand::ConnectCommand(args) => Ok(json!({
            "side": "host",
            "workflow": remote_workflow(args.kind),
            "command": remote_connect_command(&args),
            "notes": remote_connect_notes(&args),
        })),
        RemoteCommand::Doctor(args) => doctor(args),
        RemoteCommand::Status(args) => status(RemoteStatusArgs {
            kind: args.kind,
            server: args.server,
            transport: args.transport,
            probe_connect: args.probe_connect,
            timeout_ms: args.timeout_ms,
        }),
        RemoteCommand::Plan(args) => plan(args),
    }
}

pub(super) fn doctor(args: RemoteDoctorArgs) -> anyhow::Result<Value> {
    if matches!(args.kind, RemoteKind::Ntsd) && args.pid.is_some() && args.executable.is_some() {
        bail!("remote doctor --kind ntsd accepts either --pid or --executable, not both");
    }
    let status = status(RemoteStatusArgs {
        kind: args.kind,
        server: args.server.clone(),
        transport: args.transport.clone(),
        probe_connect: args.probe_connect,
        timeout_ms: args.timeout_ms,
    })?;
    let plan = plan(RemotePlanArgs {
        kind: args.kind,
        server: args.server,
        transport: args.transport,
        pid: args.pid,
        executable: args.executable,
    })?;
    Ok(json!({
        "schema_version": 1,
        "kind": remote_kind_name(args.kind),
        "status": status,
        "plan": plan,
        "diagnostics": status["diagnostics"],
        "next_safe_commands": [
            "windbg-tool remote plan",
            "windbg-tool remote status --probe-connect"
        ]
    }))
}

pub(super) fn status(args: RemoteStatusArgs) -> anyhow::Result<Value> {
    let mut diagnostics = Vec::new();
    let parsed_transport = parse_tcp_transport(&args.transport);
    if parsed_transport.is_none() {
        diagnostics.push(diagnostic_item(
            "remote.transport.unsupported",
            "blocker",
            "Only tcp:port=<port> transports can be locally diagnosed today.",
            format!("Transport '{}' can still be emitted in generated commands, but port checks and connect probes are unavailable.", args.transport),
            "high",
            Some(fix_item(
                "Use a TCP transport for agent-diagnosable remote workflows.",
                Some("windbg-tool remote doctor --transport tcp:port=5005"),
            )),
        ));
    }

    if let Some(port) = parsed_transport {
        diagnostics.push(match TcpListener::bind(("127.0.0.1", port)) {
            Ok(_) => diagnostic_item(
                "remote.local_port.available",
                "info",
                format!("Local TCP port {port} is available."),
                "This only checks the current machine; remote target availability still depends on firewall, account, and server state.",
                "medium",
                None,
            ),
            Err(error) => diagnostic_item(
                "remote.local_port.unavailable",
                "warning",
                format!("Local TCP port {port} is not available."),
                error.to_string(),
                "medium",
                Some(fix_item(
                    "Choose a different transport port or stop the process currently using it.",
                    Some("windbg-tool remote doctor --transport tcp:port=5006"),
                )),
            ),
        });
    }

    let probe = if args.probe_connect {
        if let (Some(server), Some(port)) = (args.server.as_deref(), parsed_transport) {
            Some(connect_probe(server, port, args.timeout_ms)?)
        } else {
            diagnostics.push(diagnostic_item(
                "remote.probe.skipped",
                "warning",
                "Connect probe skipped.",
                "A TCP probe requires both --server and a tcp:port=<port> transport.",
                "high",
                None,
            ));
            None
        }
    } else {
        diagnostics.push(diagnostic_item(
            "remote.probe.opt_in",
            "info",
            "Remote reachability was not probed.",
            "Use --probe-connect for a bounded TCP connect check; this may be visible to remote network monitoring.",
            "high",
            None,
        ));
        None
    };

    diagnostics.push(diagnostic_item(
        "remote.long_running.server",
        "info",
        "Target-side remote server commands are long-running.",
        "Run them in a terminal or supervised process; this command only generates and diagnoses command lines.",
        "high",
        None,
    ));

    Ok(json!({
        "schema_version": 1,
        "kind": remote_kind_name(args.kind),
        "transport": args.transport,
        "server": args.server,
        "parsed_tcp_port": parsed_transport,
        "probe": probe,
        "diagnostics": diagnostics
    }))
}

pub(super) fn plan(args: RemotePlanArgs) -> anyhow::Result<Value> {
    if matches!(args.kind, RemoteKind::Ntsd) && args.pid.is_some() && args.executable.is_some() {
        bail!("remote plan --kind ntsd accepts either --pid or --executable, not both");
    }
    let server_args = RemoteServerCommandArgs {
        kind: args.kind,
        transport: args.transport.clone(),
        pid: args.pid,
        executable: args.executable.clone(),
    };
    let connect = args.server.as_ref().map(|server| {
        remote_connect_command(&RemoteConnectCommandArgs {
            kind: args.kind,
            server: server.clone(),
            transport: args.transport.clone(),
        })
    });
    Ok(json!({
        "schema_version": 1,
        "kind": remote_kind_name(args.kind),
        "workflow": remote_workflow(args.kind),
        "steps": [
            {
                "id": "target_start_server",
                "side": "target",
                "long_running": true,
                "command": remote_server_command(&server_args),
                "notes": remote_server_notes(&server_args)
            },
            {
                "id": "host_connect",
                "side": "host",
                "requires": ["target_start_server"],
                "command": connect,
                "notes": if args.server.is_some() {
                    remote_connect_notes(&RemoteConnectCommandArgs {
                        kind: args.kind,
                        server: args.server.clone().unwrap_or_default(),
                        transport: args.transport.clone(),
                    })
                } else {
                    json!(["Pass --server <target> to emit the exact host-side command."])
                }
            },
            {
                "id": "verify",
                "side": "host",
                "command": ["windbg-tool", "remote", "status", "--probe-connect"],
                "notes": ["Run after the target-side server is listening."]
            }
        ],
        "cleanup": [
            "Close the host debugger connection.",
            "Stop the target-side server process or terminal."
        ]
    }))
}

fn remote_workflows() -> Value {
    json!([
        remote_workflow(RemoteKind::Dbgsrv),
        remote_workflow(RemoteKind::Ntsd)
    ])
}

fn remote_workflow(kind: RemoteKind) -> Value {
    match kind {
        RemoteKind::Dbgsrv => json!({
            "kind": "dbgsrv",
            "summary": "DbgEng process server: debugger brains, symbols, and extensions stay on the host.",
            "use_when": [
                "target should stay lightweight",
                "host owns symbol/source paths and extensions",
                "host should launch or attach through -premote"
            ],
            "target_side": "windbg-tool dbgeng server --transport tcp:port=5005",
            "host_side": "windbg-tool windbg run -- -premote tcp:port=5005,server=<target>"
        }),
        RemoteKind::Ntsd => json!({
            "kind": "ntsd",
            "summary": "NTSD/CDB remote session: debugger brains, symbols, and extensions run on the target.",
            "use_when": [
                "latency is high and command execution should be target-local",
                "target has the necessary symbols/extensions",
                "a preexisting debugger session should be exposed remotely"
            ],
            "target_side": "ntsd -server tcp:port=5005 -p <pid>",
            "host_side": "windbg-tool windbg run -- -remote tcp:port=5005,server=<target>"
        }),
    }
}

fn remote_kind_name(kind: RemoteKind) -> &'static str {
    match kind {
        RemoteKind::Dbgsrv => "dbgsrv",
        RemoteKind::Ntsd => "ntsd",
    }
}

fn parse_tcp_transport(transport: &str) -> Option<u16> {
    let rest = transport.strip_prefix("tcp:")?;
    rest.split(',')
        .find_map(|part| part.strip_prefix("port="))
        .and_then(|port| port.parse::<u16>().ok())
}

fn connect_probe(server: &str, port: u16, timeout_ms: u64) -> anyhow::Result<Value> {
    let timeout = Duration::from_millis(timeout_ms);
    let mut addrs = (server, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {server}:{port}"))?;
    let Some(addr) = addrs.next() else {
        return Ok(json!({
            "status": "error",
            "summary": "No socket addresses resolved.",
            "server": server,
            "port": port,
            "timeout_ms": timeout_ms
        }));
    };
    let result = TcpStream::connect_timeout(&addr, timeout);
    Ok(match result {
        Ok(_) => json!({
            "status": "ok",
            "summary": "TCP connect probe succeeded.",
            "server": server,
            "port": port,
            "address": addr.to_string(),
            "timeout_ms": timeout_ms
        }),
        Err(error) => json!({
            "status": "error",
            "summary": "TCP connect probe failed.",
            "server": server,
            "port": port,
            "address": addr.to_string(),
            "timeout_ms": timeout_ms,
            "error": error.to_string()
        }),
    })
}

fn remote_server_command(args: &RemoteServerCommandArgs) -> Vec<String> {
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".to_string(),
            "dbgeng".to_string(),
            "server".to_string(),
            "--transport".to_string(),
            args.transport.clone(),
        ],
        RemoteKind::Ntsd => {
            let mut command = vec![
                "ntsd".to_string(),
                "-server".to_string(),
                args.transport.clone(),
            ];
            if let Some(pid) = args.pid {
                command.push("-p".to_string());
                command.push(pid.to_string());
            } else if let Some(executable) = &args.executable {
                command.push(executable.clone());
            } else {
                command.push("-p".to_string());
                command.push("<pid>".to_string());
            }
            command
        }
    }
}

fn remote_server_notes(args: &RemoteServerCommandArgs) -> Value {
    match args.kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the target machine.",
            "The command blocks until the DbgEng process server exits.",
            "Use remote connect-command --kind dbgsrv on the host to generate the WinDbg -premote command."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the target machine with NTSD or CDB available.",
            "Symbols and extensions are resolved by the target-side debugger process.",
            "Use remote connect-command --kind ntsd on the host to generate the WinDbg -remote command."
        ]),
    }
}

fn remote_connect_command(args: &RemoteConnectCommandArgs) -> Vec<String> {
    let remote = format!("{},server={}", args.transport, args.server);
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".to_string(),
            "windbg".to_string(),
            "run".to_string(),
            "--".to_string(),
            "-premote".to_string(),
            remote,
        ],
        RemoteKind::Ntsd => vec![
            "windbg-tool".to_string(),
            "windbg".to_string(),
            "run".to_string(),
            "--".to_string(),
            "-remote".to_string(),
            remote,
        ],
    }
}

fn remote_connect_notes(args: &RemoteConnectCommandArgs) -> Value {
    match args.kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the host machine.",
            "This connects WinDbg to a DbgSrv process server; launch/attach decisions happen from the host.",
            "Append additional WinDbg launch/attach arguments after the generated -premote transport if needed."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the host machine.",
            "This connects WinDbg to an existing target-side NTSD/CDB -server session.",
            "Do not use -premote for NTSD/CDB -server sessions."
        ]),
    }
}
