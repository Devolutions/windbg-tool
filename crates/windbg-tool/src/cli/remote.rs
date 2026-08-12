use serde_json::Value;
use windbg_ttd::analysis::{
    remote_connect_command as shared_remote_connect_command, remote_doctor as shared_remote_doctor,
    remote_explain as shared_remote_explain, remote_plan as shared_remote_plan,
    remote_server_command as shared_remote_server_command, remote_status as shared_remote_status,
    RemoteConnectCommandRequest, RemoteDoctorRequest, RemoteExplainRequest,
    RemoteKind as SharedRemoteKind, RemotePlanRequest, RemoteServerCommandRequest,
    RemoteStatusRequest,
};

use super::{RemoteCommand, RemoteDoctorArgs, RemoteKind, RemotePlanArgs, RemoteStatusArgs};

pub(super) fn remote_command_value(command: RemoteCommand) -> anyhow::Result<Value> {
    match command {
        RemoteCommand::Explain(args) => shared_remote_explain(RemoteExplainRequest {
            kind: args.kind.map(map_kind),
        }),
        RemoteCommand::ServerCommand(args) => {
            shared_remote_server_command(RemoteServerCommandRequest {
                kind: map_kind(args.kind),
                transport: args.transport,
                pid: args.pid,
                executable: args.executable,
            })
        }
        RemoteCommand::ConnectCommand(args) => {
            shared_remote_connect_command(RemoteConnectCommandRequest {
                kind: map_kind(args.kind),
                server: args.server,
                transport: args.transport,
            })
        }
        RemoteCommand::Doctor(args) => doctor(args),
        RemoteCommand::Status(args) => status(args),
        RemoteCommand::Plan(args) => plan(args),
    }
}

pub(super) fn doctor(args: RemoteDoctorArgs) -> anyhow::Result<Value> {
    shared_remote_doctor(RemoteDoctorRequest {
        kind: map_kind(args.kind),
        server: args.server,
        transport: args.transport,
        pid: args.pid,
        executable: args.executable,
        probe_connect: args.probe_connect,
        timeout_ms: args.timeout_ms,
    })
}

pub(super) fn status(args: RemoteStatusArgs) -> anyhow::Result<Value> {
    shared_remote_status(RemoteStatusRequest {
        kind: map_kind(args.kind),
        server: args.server,
        transport: args.transport,
        probe_connect: args.probe_connect,
        timeout_ms: args.timeout_ms,
    })
}

pub(super) fn plan(args: RemotePlanArgs) -> anyhow::Result<Value> {
    shared_remote_plan(RemotePlanRequest {
        kind: map_kind(args.kind),
        server: args.server,
        transport: args.transport,
        pid: args.pid,
        executable: args.executable,
    })
}

fn map_kind(kind: RemoteKind) -> SharedRemoteKind {
    match kind {
        RemoteKind::Dbgsrv => SharedRemoteKind::Dbgsrv,
        RemoteKind::Ntsd => SharedRemoteKind::Ntsd,
    }
}
