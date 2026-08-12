fn main() {
    println!("cargo:rerun-if-env-changed=WINDBG_TOOL_VERSION");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "WinDbg Tool");
    res.set("FileDescription", "WinDbg automation CLI and MCP server");
    res.set("CompanyName", "Devolutions");
    res.set("LegalCopyright", "Copyright (c) Devolutions");
    res.set("OriginalFilename", "windbg-tool.exe");
    res.set("InternalName", "windbg-tool");

    // Prefer release CI stamp; otherwise use the Cargo package version.
    // PE FileVersion is always four numeric components (major.minor.patch.build).
    let product_version = std::env::var("WINDBG_TOOL_VERSION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "0.0.0".to_string());
    let file_version = pe_file_version(&product_version);
    res.set("FileVersion", &file_version);
    res.set("ProductVersion", &product_version);

    res.compile()
        .expect("failed to compile Windows version resources for windbg-tool");
}

fn pe_file_version(version: &str) -> String {
    let numeric = version.split(['-', '+']).next().unwrap_or(version);
    let mut parts = numeric
        .split('.')
        .filter_map(|part| part.parse::<u16>().ok())
        .collect::<Vec<_>>();
    while parts.len() < 4 {
        parts.push(0);
    }
    parts.truncate(4);
    format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3])
}
