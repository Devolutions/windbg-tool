use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use windbg_dbgeng::StandardSymbolEnvironment;

const DEFAULT_SYMBOL_CACHE: &str = ".ttd-symbol-cache";
const DEFAULT_SYMBOL_RUNTIME_DIR: &str = "target/symbol-runtime";

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SymbolSettings {
    #[serde(default)]
    pub binary_paths: Vec<PathBuf>,
    #[serde(default)]
    pub symbol_paths: Vec<String>,
    pub symcache_dir: Option<PathBuf>,
}

impl SymbolSettings {
    pub fn effective_symbol_path(&self) -> String {
        self.resolve(None).symbol_path
    }

    pub fn resolve_for_process(&self) -> ResolvedSymbolConfig {
        self.resolve(Some(default_symbol_runtime_dir()))
    }

    pub fn resolve(&self, symbol_runtime_dir: Option<PathBuf>) -> ResolvedSymbolConfig {
        self.resolve_with_standard_symbol_environment(
            symbol_runtime_dir,
            StandardSymbolEnvironment::from_process(),
        )
    }

    fn resolve_with_standard_symbol_environment(
        &self,
        symbol_runtime_dir: Option<PathBuf>,
        environment: StandardSymbolEnvironment,
    ) -> ResolvedSymbolConfig {
        let paths = if self.symbol_paths.is_empty() {
            environment
                .symbol_path
                .map(|path| vec![path])
                .unwrap_or_default()
        } else {
            self.symbol_paths.clone()
        };
        let symbol_cache_dir = self
            .symcache_dir
            .clone()
            .or(environment.symcache_dir)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SYMBOL_CACHE));

        ResolvedSymbolConfig {
            symbol_path: paths.join(";"),
            image_path: self
                .binary_paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(";"),
            symbol_cache_dir,
            symbol_runtime_dir,
            binary_path_count: self.binary_paths.len(),
            microsoft_public_symbols: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSymbolConfig {
    pub symbol_path: String,
    pub image_path: String,
    pub symbol_cache_dir: PathBuf,
    pub symbol_runtime_dir: Option<PathBuf>,
    pub binary_path_count: usize,
    pub microsoft_public_symbols: bool,
}

pub fn default_symbol_runtime_dir() -> PathBuf {
    std::env::var_os("TTD_SYMBOL_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SYMBOL_RUNTIME_DIR))
}

impl ResolvedSymbolConfig {
    pub fn has_image_path(&self) -> bool {
        !self.image_path.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_symbol_path_does_not_add_a_symbol_server() {
        let settings = SymbolSettings::default();
        assert!(settings
            .resolve_with_standard_symbol_environment(
                None,
                StandardSymbolEnvironment::from_values(None, None, None),
            )
            .symbol_path
            .is_empty());
    }

    #[test]
    fn keeps_custom_symbol_cache_dir() {
        let settings = SymbolSettings {
            symcache_dir: Some(PathBuf::from("target/test-symbol-cache")),
            ..SymbolSettings::default()
        };

        let resolved = settings.resolve_with_standard_symbol_environment(
            None,
            StandardSymbolEnvironment::from_values(
                None,
                None,
                Some(PathBuf::from("target/environment-symbol-cache")),
            ),
        );
        assert_eq!(
            resolved.symbol_cache_dir,
            PathBuf::from("target/test-symbol-cache")
        );
        assert!(resolved.symbol_path.is_empty());
    }

    #[test]
    fn preserves_caller_symbol_paths_without_adding_a_default_server() {
        let settings = SymbolSettings {
            symbol_paths: vec!["C:/symbols".to_string()],
            ..SymbolSettings::default()
        };

        let resolved = settings.resolve_with_standard_symbol_environment(
            None,
            StandardSymbolEnvironment::from_values(None, None, None),
        );
        assert_eq!(resolved.symbol_path, "C:/symbols");
    }

    #[test]
    fn uses_standard_symbol_environment_when_symbol_paths_are_empty() {
        let resolved = SymbolSettings::default().resolve_with_standard_symbol_environment(
            None,
            StandardSymbolEnvironment::from_values(
                Some("C:/env-symbols".to_string()),
                Some("C:/alternate-symbols".to_string()),
                Some(PathBuf::from("C:/symbol-cache")),
            ),
        );
        assert!(resolved.symbol_path.contains("C:/env-symbols"));
        assert!(resolved.symbol_path.contains("C:/alternate-symbols"));
        assert_eq!(resolved.symbol_cache_dir, PathBuf::from("C:/symbol-cache"));
    }

    #[test]
    fn explicit_symbol_paths_override_nt_symbol_path() {
        let settings = SymbolSettings {
            symbol_paths: vec!["C:/explicit-symbols".to_string()],
            ..SymbolSettings::default()
        };

        let resolved = settings.resolve_with_standard_symbol_environment(
            None,
            StandardSymbolEnvironment::from_values(
                Some("C:/env-symbols".to_string()),
                Some("C:/alternate-symbols".to_string()),
                Some(PathBuf::from("C:/symbol-cache")),
            ),
        );

        assert!(resolved.symbol_path.contains("C:/explicit-symbols"));
        assert!(!resolved.symbol_path.contains("C:/env-symbols"));
    }

    #[test]
    fn builds_image_path_from_binary_paths() {
        let settings = SymbolSettings {
            binary_paths: vec![
                PathBuf::from("traces/ping/ping.exe"),
                PathBuf::from("C:/Windows/System32"),
            ],
            ..SymbolSettings::default()
        };

        let resolved = settings.resolve_with_standard_symbol_environment(
            Some(PathBuf::from("target/symbol-runtime")),
            StandardSymbolEnvironment::from_values(None, None, None),
        );
        assert_eq!(resolved.binary_path_count, 2);
        assert_eq!(
            resolved.symbol_runtime_dir,
            Some(PathBuf::from("target/symbol-runtime"))
        );
        assert!(resolved.has_image_path());
        assert!(resolved.image_path.contains("traces/ping/ping.exe"));
        assert!(resolved.image_path.contains(';'));
    }

    #[test]
    fn resolves_process_symbol_runtime_dir() {
        let resolved = SymbolSettings::default().resolve_for_process();
        assert_eq!(
            resolved.symbol_runtime_dir,
            Some(default_symbol_runtime_dir())
        );
    }
}
