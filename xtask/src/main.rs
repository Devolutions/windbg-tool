use anyhow::{bail, ensure, Context};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const DEBUGGING_PLATFORM_VERSION: &str = "20260319.1511.0";
const DEFAULT_SYMBOL_CACHE: &str = ".ttd-symbol-cache";
const NATIVE_BRIDGE_DLL: &str = "ttd_replay_bridge.dll";
const TTD_RUNTIME_FILES: &[&str] = &["TTDReplay.dll", "TTDReplayCPU.dll"];
const DBGENG_RUNTIME_FILES: &[&str] = &[
    "dbgeng.dll",
    "dbgcore.dll",
    "dbghelp.dll",
    "dbgmodel.dll",
    "msdia140.dll",
];

struct SymbolRuntimeFile {
    package: &'static str,
    dll: &'static str,
}

const SYMBOL_RUNTIME_FILES: &[SymbolRuntimeFile] = &[
    SymbolRuntimeFile {
        package: "Microsoft.Debugging.Platform.DbgEng",
        dll: "dbghelp.dll",
    },
    SymbolRuntimeFile {
        package: "Microsoft.Debugging.Platform.SrcSrv",
        dll: "srcsrv.dll",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageArch {
    Amd64,
    Arm64,
}

impl PackageArch {
    fn from_value(value: &str) -> anyhow::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "amd64" | "x64" | "x86_64" => Ok(Self::Amd64),
            "arm64" | "aarch64" => Ok(Self::Arm64),
            _ => bail!("unsupported package architecture: {value}"),
        }
    }

    fn from_rust_target(target: &str) -> anyhow::Result<Self> {
        if target.starts_with("x86_64-") {
            Ok(Self::Amd64)
        } else if target.starts_with("aarch64-") {
            Ok(Self::Arm64)
        } else {
            bail!("unsupported Windows Rust target: {target}")
        }
    }

    fn host() -> Self {
        if env::var("PROCESSOR_ARCHITECTURE")
            .map(|arch| arch.eq_ignore_ascii_case("ARM64"))
            .unwrap_or(false)
        {
            Self::Arm64
        } else {
            Self::Amd64
        }
    }

    fn nuget_arch(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    fn ttd_arch(self) -> &'static str {
        match self {
            Self::Amd64 => "x64",
            Self::Arm64 => "arm64",
        }
    }

    fn msvc_platform(self) -> &'static str {
        match self {
            Self::Amd64 => "x64",
            Self::Arm64 => "ARM64",
        }
    }

    fn rust_target(self) -> &'static str {
        match self {
            Self::Amd64 => "x86_64-pc-windows-msvc",
            Self::Arm64 => "aarch64-pc-windows-msvc",
        }
    }

    fn package_label(self) -> &'static str {
        match self {
            Self::Amd64 => "windows-x64",
            Self::Arm64 => "windows-arm64",
        }
    }
}

#[derive(Clone, Debug)]
struct XtaskOptions {
    arch: PackageArch,
    explicit_target_layout: bool,
    rust_target: Option<String>,
    profile: String,
    package_dir: Option<PathBuf>,
    static_crt: bool,
}

impl XtaskOptions {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut arch = None;
        let mut rust_target = None;
        let mut profile = String::from("debug");
        let mut package_dir = None;
        let mut static_crt = false;
        let mut explicit_target_layout = false;

        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--arch" => {
                    index += 1;
                    let value = args.get(index).context("--arch requires a value")?;
                    arch = Some(PackageArch::from_value(value)?);
                    explicit_target_layout = true;
                }
                "--target" => {
                    index += 1;
                    let value = args.get(index).context("--target requires a value")?;
                    rust_target = Some(value.clone());
                    explicit_target_layout = true;
                }
                "--profile" => {
                    index += 1;
                    let value = args.get(index).context("--profile requires a value")?;
                    ensure!(
                        value == "debug" || value == "release",
                        "--profile must be 'debug' or 'release'"
                    );
                    profile = value.clone();
                }
                "--out" | "--package-dir" => {
                    index += 1;
                    let value = args.get(index).context("--out requires a value")?;
                    package_dir = Some(PathBuf::from(value));
                }
                "--static-crt" => {
                    static_crt = true;
                }
                option => bail!("unknown xtask option: {option}"),
            }
            index += 1;
        }

        let inferred_arch = match (&arch, &rust_target) {
            (Some(arch), Some(target)) => {
                let target_arch = PackageArch::from_rust_target(target)?;
                ensure!(
                    *arch == target_arch,
                    "--arch {} does not match --target {}",
                    arch.nuget_arch(),
                    target
                );
                *arch
            }
            (Some(arch), None) => *arch,
            (None, Some(target)) => PackageArch::from_rust_target(target)?,
            (None, None) => PackageArch::host(),
        };

        let rust_target = if explicit_target_layout {
            Some(rust_target.unwrap_or_else(|| inferred_arch.rust_target().to_string()))
        } else {
            None
        };

        Ok(Self {
            arch: inferred_arch,
            explicit_target_layout,
            rust_target,
            profile,
            package_dir,
            static_crt,
        })
    }

    fn default_host() -> Self {
        Self {
            arch: PackageArch::host(),
            explicit_target_layout: false,
            rust_target: None,
            profile: String::from("debug"),
            package_dir: None,
            static_crt: false,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next();
    let rest = args.collect::<Vec<_>>();
    match command.as_deref() {
        Some("doctor") => doctor(),
        Some("deps") => deps(&XtaskOptions::parse(&rest)?),
        Some("native-build") => native_build(&XtaskOptions::parse(&rest)?),
        Some("package") => package(&XtaskOptions::parse(&rest)?),
        Some("mcp-smoke") => mcp_smoke(),
        Some(command) => bail!("unknown xtask command: {command}"),
        None => {
            eprintln!(
                "Usage: cargo xtask <doctor|deps|native-build|package|mcp-smoke> [--arch amd64|arm64] [--target <triple>] [--profile debug|release] [--out <dir>] [--static-crt]"
            );
            Ok(())
        }
    }
}

fn doctor() -> anyhow::Result<()> {
    let root = workspace_root()?;

    println!("windbg-tool doctor");
    println!("  OS: {}", env::consts::OS);
    check_command("cargo");
    check_command("nuget");
    check_command("cmake");
    check_command("msbuild");
    check_command("powershell");

    let runtime_dir = env::var_os("TTD_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/ttd-runtime"));
    println!("  info: checking TTD runtime dir {}", runtime_dir.display());
    check_file(&runtime_dir.join("TTDReplay.dll"));
    check_file(&runtime_dir.join("TTDReplayCPU.dll"));

    let symbol_runtime_dir = env::var_os("TTD_SYMBOL_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/symbol-runtime"));
    println!(
        "  info: checking symbol runtime dir {}",
        symbol_runtime_dir.display()
    );
    for file in SYMBOL_RUNTIME_FILES {
        check_file(&symbol_runtime_dir.join(file.dll));
    }
    let dbgeng_runtime_dir = env::var_os("WINDBG_DBGENG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/dbgeng-runtime"));
    println!(
        "  info: checking DbgEng runtime dir {}",
        dbgeng_runtime_dir.display()
    );
    for file in DBGENG_RUNTIME_FILES {
        check_file(&dbgeng_runtime_dir.join(file));
    }
    println!("  info: native Rust symbol cache {}", DEFAULT_SYMBOL_CACHE);

    let test_trace = env::var_os("TTD_TEST_TRACE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("traces/ping/ping01.run"));
    check_file(&test_trace);
    check_file(&root.join("traces/ping/ping.exe"));

    if let Some(path) = native_bridge_candidates(&root, &XtaskOptions::default_host())
        .into_iter()
        .find(|path| path.is_file())
    {
        println!("  ok: {}", path.display());
    } else {
        println!("  warn: missing native bridge DLL; run cargo xtask native-build after entering an MSVC developer environment");
    }

    Ok(())
}

fn deps(options: &XtaskOptions) -> anyhow::Result<()> {
    let root = workspace_root()?;
    let packages_config = root.join("native/ttd-replay-bridge/packages.config");
    let packages_dir = root.join("target/nuget");
    std::fs::create_dir_all(&packages_dir).context("creating target/nuget")?;

    run(Command::new("nuget")
        .arg("restore")
        .arg(&packages_config)
        .arg("-PackagesDirectory")
        .arg(&packages_dir))
    .context("restoring native NuGet packages")?;

    stage_symbol_runtime(
        &packages_dir,
        &symbol_runtime_dir(&root, options),
        options.arch,
    )
    .context("staging symbol runtime DLLs")?;
    stage_dbgeng_runtime(
        &packages_dir,
        &dbgeng_runtime_dir(&root, options),
        options.arch,
    )
    .context("staging DbgEng runtime DLLs")?;

    run(Command::new("powershell")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(root.join("scripts/Get-TtdReplayRuntime.ps1"))
        .arg("-OutDir")
        .arg(ttd_runtime_dir(&root, options))
        .arg("-Arch")
        .arg(options.arch.ttd_arch()))
    .context("downloading TTD replay runtime")?;

    Ok(())
}

fn native_build(options: &XtaskOptions) -> anyhow::Result<()> {
    let root = workspace_root()?;
    let packages_dir = root.join("target/nuget");
    let ttd_apis_package = package_dir(&packages_dir, "Microsoft.TimeTravelDebugging.Apis")?;
    let source_dir = root.join("native/ttd-replay-bridge");
    let build_dir = native_build_dir(&root, options);
    fs::create_dir_all(&build_dir).context("creating native bridge build directory")?;

    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(&source_dir)
        .arg("-B")
        .arg(&build_dir)
        .arg(format!(
            "-DTTD_APIS_PACKAGE_DIR={}",
            ttd_apis_package.display()
        ))
        .env("Platform", options.arch.msvc_platform());

    if options.static_crt {
        configure.arg("-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>");
    }

    if cfg!(windows) && cmake_generator_accepts_platform() {
        configure.arg("-A").arg(options.arch.msvc_platform());
    }

    run(&mut configure).context("configuring native TTD replay bridge")?;

    run(Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .arg("--config")
        .arg("Release"))
    .context("building native TTD replay bridge")?;

    Ok(())
}

fn package(options: &XtaskOptions) -> anyhow::Result<()> {
    let root = workspace_root()?;
    let package_dir = options
        .package_dir
        .clone()
        .unwrap_or_else(|| default_package_dir(&root, options));
    if package_dir.exists() {
        fs::remove_dir_all(&package_dir)
            .with_context(|| format!("clearing package directory {}", package_dir.display()))?;
    }
    fs::create_dir_all(&package_dir).context("creating package directory")?;
    copy_if_exists(
        &windbg_tool_exe(&root, options),
        &package_dir.join("windbg-tool.exe"),
    )?;
    copy_first_existing(
        native_bridge_candidates(&root, options),
        &package_dir.join(NATIVE_BRIDGE_DLL),
    )?;
    copy_runtime_files(
        &ttd_runtime_dir(&root, options),
        &package_dir,
        TTD_RUNTIME_FILES,
    )?;
    for file in SYMBOL_RUNTIME_FILES {
        copy_if_exists(
            &symbol_runtime_dir(&root, options).join(file.dll),
            &package_dir.join(file.dll),
        )?;
    }
    copy_runtime_files(
        &dbgeng_runtime_dir(&root, options),
        &package_dir,
        DBGENG_RUNTIME_FILES,
    )?;
    println!("Package directory prepared at {}", package_dir.display());
    Ok(())
}

fn mcp_smoke() -> anyhow::Result<()> {
    let root = workspace_root()?;
    run(Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("windbg-tool"))
    .context("building windbg-tool before packaged MCP smoke test")?;
    package(&XtaskOptions::default_host()).context("preparing MCP package directory")?;

    let package_dir = root.join("target/package");
    let server_path = package_dir.join("windbg-tool.exe");
    ensure!(
        server_path.is_file(),
        "packaged server was not found at {}",
        server_path.display()
    );

    let mut client = SmokeClient::start(&server_path, &package_dir)?;
    client.initialize()?;
    let tools = client.request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }))?;
    assert_response_id(&tools, 2)?;
    let tool_names = tools["result"]["tools"]
        .as_array()
        .context("tools/list result should include tools")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    ensure!(
        tool_names.contains(&"ttd_load_trace")
            && tool_names.contains(&"ttd_capabilities")
            && tool_names.contains(&"ttd_list_keyframes")
            && tool_names.contains(&"ttd_cursor_modules")
            && tool_names.contains(&"ttd_module_events")
            && tool_names.contains(&"ttd_thread_events")
            && tool_names.contains(&"ttd_module_info")
            && tool_names.contains(&"ttd_address_info")
            && tool_names.contains(&"ttd_active_threads")
            && tool_names.contains(&"ttd_register_context")
            && tool_names.contains(&"ttd_stack_info")
            && tool_names.contains(&"ttd_stack_read")
            && tool_names.contains(&"ttd_memory_range")
            && tool_names.contains(&"ttd_memory_buffer")
            && tool_names.contains(&"ttd_read_memory"),
        "packaged MCP server did not advertise expected tools: {tools}"
    );

    let trace_path = root.join("traces/ping/ping01.run");
    if trace_path.is_file() {
        let loaded = client.call_tool_json(
            3,
            "ttd_load_trace",
            serde_json::json!({
                "trace_path": path_string(&trace_path),
                "symbols": {
                    "binary_paths": ping_binary_paths(&trace_path),
                }
            }),
        )?;
        let session_id = loaded["session_id"]
            .as_u64()
            .context("ttd_load_trace should return a session id")?;
        let capabilities = client.call_tool_json(
            4,
            "ttd_capabilities",
            serde_json::json!({ "session_id": session_id }),
        )?;
        ensure!(
            capabilities["features"]["trace_info"] == true,
            "ttd_capabilities should report trace_info support: {capabilities}"
        );
        client.call_tool_json(
            5,
            "ttd_close_trace",
            serde_json::json!({ "session_id": session_id }),
        )?;
    } else {
        println!(
            "  info: skipping packaged trace load smoke; {} is not present",
            trace_path.display()
        );
    }

    println!("Packaged MCP smoke test passed");
    Ok(())
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    env::current_dir().context("reading current directory")
}

fn check_command(command: &str) {
    let found = Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if found {
        println!("  ok: {command} found");
    } else {
        println!("  warn: {command} not found on PATH");
    }
}

fn check_file(path: &Path) {
    if path.is_file() {
        println!("  ok: {}", path.display());
    } else {
        println!("  warn: missing {}", path.display());
    }
}

fn stage_symbol_runtime(
    packages_dir: &Path,
    symbol_runtime_dir: &Path,
    arch: PackageArch,
) -> anyhow::Result<()> {
    fs::create_dir_all(symbol_runtime_dir)
        .with_context(|| format!("creating {}", symbol_runtime_dir.display()))?;
    for file in SYMBOL_RUNTIME_FILES {
        let source = package_content_file(packages_dir, file.package, file.dll, arch.nuget_arch())?;
        let destination = symbol_runtime_dir.join(file.dll);
        fs::copy(&source, &destination).with_context(|| {
            format!("copying {} to {}", source.display(), destination.display())
        })?;
        println!("Staged {}", destination.display());
    }

    Ok(())
}

fn stage_dbgeng_runtime(
    packages_dir: &Path,
    dbgeng_runtime_dir: &Path,
    arch: PackageArch,
) -> anyhow::Result<()> {
    fs::create_dir_all(dbgeng_runtime_dir)
        .with_context(|| format!("creating {}", dbgeng_runtime_dir.display()))?;
    for dll in DBGENG_RUNTIME_FILES {
        let source = package_content_file(
            packages_dir,
            "Microsoft.Debugging.Platform.DbgEng",
            dll,
            arch.nuget_arch(),
        )?;
        let destination = dbgeng_runtime_dir.join(dll);
        fs::copy(&source, &destination).with_context(|| {
            format!("copying {} to {}", source.display(), destination.display())
        })?;
        println!("Staged {}", destination.display());
    }
    Ok(())
}

fn package_content_file(
    packages_dir: &Path,
    package: &str,
    dll: &str,
    arch: &str,
) -> anyhow::Result<PathBuf> {
    let package_dir = package_dir(packages_dir, package)?;
    let file = package_dir.join("content").join(arch).join(dll);
    ensure!(
        file.is_file(),
        "{} did not contain expected symbol runtime file {}",
        package,
        file.display()
    );
    Ok(file)
}

fn package_dir(packages_dir: &Path, package: &str) -> anyhow::Result<PathBuf> {
    let exact = packages_dir.join(format!("{package}.{DEBUGGING_PLATFORM_VERSION}"));
    if exact.is_dir() {
        return Ok(exact);
    }

    let package_prefix = format!("{}.", package.to_ascii_lowercase());
    for entry in
        fs::read_dir(packages_dir).with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name.starts_with(&package_prefix) && entry.path().is_dir() {
            return Ok(entry.path());
        }
    }

    bail!(
        "restored package directory for {} was not found under {}",
        package,
        packages_dir.display()
    )
}

fn cmake_generator_accepts_platform() -> bool {
    env::var("CMAKE_GENERATOR")
        .map(|generator| !generator.to_ascii_lowercase().contains("ninja"))
        .unwrap_or(true)
}

fn runtime_root(root: &Path, options: &XtaskOptions) -> PathBuf {
    root.join("target/runtime").join(options.arch.nuget_arch())
}

fn symbol_runtime_dir(root: &Path, options: &XtaskOptions) -> PathBuf {
    if options.explicit_target_layout {
        runtime_root(root, options).join("symbol-runtime")
    } else {
        root.join("target/symbol-runtime")
    }
}

fn dbgeng_runtime_dir(root: &Path, options: &XtaskOptions) -> PathBuf {
    if options.explicit_target_layout {
        runtime_root(root, options).join("dbgeng-runtime")
    } else {
        root.join("target/dbgeng-runtime")
    }
}

fn ttd_runtime_dir(root: &Path, options: &XtaskOptions) -> PathBuf {
    if options.explicit_target_layout {
        runtime_root(root, options).join("ttd-runtime")
    } else {
        root.join("target/ttd-runtime")
    }
}

fn native_build_dir(root: &Path, options: &XtaskOptions) -> PathBuf {
    if options.explicit_target_layout {
        root.join("target/native")
            .join(format!("ttd-replay-bridge-{}", options.arch.nuget_arch()))
    } else {
        root.join("target/native/ttd-replay-bridge")
    }
}

fn default_package_dir(root: &Path, options: &XtaskOptions) -> PathBuf {
    if options.explicit_target_layout {
        root.join("target/package")
            .join(options.arch.package_label())
    } else {
        root.join("target/package")
    }
}

fn windbg_tool_exe(root: &Path, options: &XtaskOptions) -> PathBuf {
    if let Some(rust_target) = &options.rust_target {
        root.join("target")
            .join(rust_target)
            .join(&options.profile)
            .join("windbg-tool.exe")
    } else {
        root.join("target")
            .join(&options.profile)
            .join("windbg-tool.exe")
    }
}

fn native_bridge_candidates(root: &Path, options: &XtaskOptions) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os("TTD_NATIVE_BRIDGE_DLL").map(PathBuf::from) {
        candidates.push(path);
    }

    let build_dir = native_build_dir(root, options);
    candidates.push(build_dir.join("bin/Release").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("bin/Debug").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("Release").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("Debug").join(NATIVE_BRIDGE_DLL));
    candidates
}

fn copy_runtime_files(
    source_dir: &Path,
    package_dir: &Path,
    file_names: &[&str],
) -> anyhow::Result<()> {
    for file_name in file_names {
        copy_if_exists(&source_dir.join(file_name), &package_dir.join(file_name))?;
    }
    Ok(())
}

fn copy_if_exists(source: &Path, destination: &Path) -> anyhow::Result<()> {
    if source.is_file() {
        fs::copy(source, destination).with_context(|| {
            format!("copying {} to {}", source.display(), destination.display())
        })?;
        println!("  copied: {}", destination.display());
    } else {
        println!("  warn: missing {}", source.display());
    }
    Ok(())
}

fn copy_first_existing(sources: Vec<PathBuf>, destination: &Path) -> anyhow::Result<()> {
    for source in &sources {
        if source.is_file() {
            return copy_if_exists(source, destination);
        }
    }

    println!(
        "  warn: missing {} (run cargo xtask native-build)",
        sources
            .first()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| NATIVE_BRIDGE_DLL.to_string())
    );
    Ok(())
}

struct SmokeClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl SmokeClient {
    fn start(server_path: &Path, current_dir: &Path) -> anyhow::Result<Self> {
        let mut child = Command::new(server_path)
            .current_dir(current_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning packaged MCP server {}", server_path.display()))?;
        let stdin = child.stdin.take().context("child stdin was not piped")?;
        let stdout = child.stdout.take().context("child stdout was not piped")?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn initialize(&mut self) -> anyhow::Result<()> {
        let response = self.request(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "windbg-tool-package-smoke",
                    "version": "0.0.0"
                }
            }
        }))?;
        assert_response_id(&response, 1)?;
        self.notify(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }))
    }

    fn notify(&mut self, value: serde_json::Value) -> anyhow::Result<()> {
        writeln!(self.stdin, "{}", serde_json::to_string(&value)?)?;
        self.stdin.flush()?;
        Ok(())
    }

    fn request(&mut self, value: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        writeln!(self.stdin, "{}", serde_json::to_string(&value)?)?;
        self.stdin.flush()?;

        let mut response = String::new();
        let bytes = self.stdout.read_line(&mut response)?;
        ensure!(bytes > 0, "server closed stdout before writing a response");
        serde_json::from_str(response.trim_end()).context("parsing MCP response")
    }

    fn call_tool_json(
        &mut self,
        id: u64,
        name: &str,
        arguments: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let response = self.request(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            }
        }))?;
        assert_response_id(&response, id)?;
        ensure!(
            response["result"]["isError"].as_bool() != Some(true),
            "{name} returned an MCP tool error: {response}"
        );
        parse_tool_json(&response)
    }
}

impl Drop for SmokeClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_response_id(response: &serde_json::Value, expected_id: u64) -> anyhow::Result<()> {
    ensure!(
        response["jsonrpc"] == "2.0",
        "missing JSON-RPC version: {response}"
    );
    ensure!(
        response["id"] == expected_id,
        "unexpected response id: {response}"
    );
    ensure!(
        response.get("error").is_none(),
        "response should not be an error: {response}"
    );
    Ok(())
}

fn parse_tool_json(response: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .context("tool result should include text content")?;
    serde_json::from_str(text).context("parsing tool result JSON")
}

fn ping_binary_paths(trace_path: &Path) -> Vec<String> {
    trace_path
        .parent()
        .map(|trace_dir| trace_dir.join("ping.exe"))
        .filter(|binary_path| binary_path.is_file())
        .map(|binary_path| vec![path_string(&binary_path)])
        .unwrap_or_default()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn run(command: &mut Command) -> anyhow::Result<()> {
    let status = command.status().context("starting command")?;
    if !status.success() {
        bail!("command failed with status {status}");
    }
    Ok(())
}
