use anyhow::ensure;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn audit_modules(modules: &[Value], max_suspicious: usize) -> Value {
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

fn module_path(module: &Value) -> Option<&str> {
    module["path"].as_str().filter(|path| !path.is_empty())
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

pub fn normalize_dll_name(name: &str) -> anyhow::Result<String> {
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

pub fn search_candidate(order: usize, kind: &str, directory: &Path, dll: &str) -> Value {
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

pub fn directory_risk(directory: &Path) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
