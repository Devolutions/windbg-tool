//! PE helpers live in `windbg_ttd::analysis` so MCP tools and the CLI share one path.
#[allow(unused_imports)]
pub use windbg_ttd::analysis::{
    bounded_pe_file_metadata, diagnose_pe, export_symbol_value, read_export_symbols, ExportSymbol,
};

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn parses_current_exe_pe_identity_with_bounded_file_metadata() -> anyhow::Result<()> {
        use windbg_ttd::analysis::{bounded_pe_file_metadata, diagnose_pe};

        let executable = std::env::current_exe()?;
        let info = diagnose_pe(&executable)?;
        assert!(info["timestamp"].is_u64(), "{info}");
        assert!(info["size_of_image"].is_u64(), "{info}");
        assert!(info["image_symbol_store_key"].is_string(), "{info}");
        let metadata = bounded_pe_file_metadata(&executable, 64 * 1024 * 1024)?;
        assert_eq!(metadata["source"], "host_file_metadata");
        assert!(metadata["pe"]["machine"].is_string(), "{metadata}");
        Ok(())
    }
}
