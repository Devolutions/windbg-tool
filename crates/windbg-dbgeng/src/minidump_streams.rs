//! Bounded decoding of auxiliary user-mode MINIDUMP streams (modules, unloaded modules, thread
//! names, memory regions and handles). Layouts follow `minidumpapiset.h`; every list is capped and
//! truncation is reported instead of silently scanning the whole dump.

use super::{minidump_stream_range_status, minidump_u32, minidump_u64, MinidumpDirectoryInventory};
use anyhow::{ensure, Context};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const MODULE_LIST_STREAM: u32 = 4;
const HANDLE_DATA_STREAM: u32 = 12;
const UNLOADED_MODULE_LIST_STREAM: u32 = 14;
const MEMORY_INFO_LIST_STREAM: u32 = 16;
const THREAD_NAMES_STREAM: u32 = 24;

const MODULE_ENTRY_SIZE: usize = 108;
const UNLOADED_MODULE_ENTRY_SIZE: usize = 24;
const THREAD_NAME_ENTRY_SIZE: usize = 12;
const MEMORY_INFO_ENTRY_SIZE: usize = 48;
const HANDLE_DESCRIPTOR_SIZE: usize = 32;
const VS_FIXEDFILEINFO_SIGNATURE: u32 = 0xFEEF_04BD;
const CODEVIEW_RSDS_SIGNATURE: u32 = 0x5344_5352;

pub const MAX_STREAM_MODULES: u32 = 4096;
pub const MAX_STREAM_UNLOADED_MODULES: u32 = 1024;
pub const MAX_REPORTED_UNLOADED_MODULES: usize = 64;
pub const MAX_STREAM_THREAD_NAMES: u32 = 4096;
pub const MAX_REPORTED_THREAD_NAMES: usize = 64;
pub const MAX_STREAM_MEMORY_REGIONS: u64 = 262_144;
pub const MAX_STREAM_HANDLES: u32 = 65_536;
pub const MAX_REPORTED_HANDLE_TYPES: usize = 64;
pub const MAX_STREAM_STRING_BYTES: u32 = 1024;

#[derive(Debug, Clone, Serialize)]
pub struct UserDumpStreams {
    pub source: &'static str,
    pub fault_module: FaultModule,
    pub unloaded_modules: UnloadedModules,
    pub thread_names: ThreadNames,
    pub memory_info: MemoryInfoSummary,
    pub handles: HandleSummary,
    pub detail: &'static str,
    #[serde(skip)]
    regions: Vec<MemoryRegion>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FaultModule {
    pub status: String,
    pub address: Option<u64>,
    pub module: Option<ModuleIdentity>,
    pub unloaded_match: Option<UnloadedModule>,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModuleIdentity {
    pub name: Option<String>,
    pub base: u64,
    pub size: u32,
    pub offset: u64,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub time_date_stamp_utc: String,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub pdb: Option<CodeViewIdentity>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeViewIdentity {
    pub file_name: String,
    pub guid: String,
    pub age: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnloadedModule {
    pub name: Option<String>,
    pub base: u64,
    pub size: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub time_date_stamp_utc: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UnloadedModules {
    pub status: String,
    pub count: Option<u32>,
    pub modules: Vec<UnloadedModule>,
    pub truncated: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadName {
    pub thread_system_id: u32,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ThreadNames {
    pub status: String,
    pub count: Option<u32>,
    pub exception_thread_name: Option<String>,
    pub names: Vec<ThreadName>,
    pub truncated: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub region_size: u64,
    pub state: u32,
    pub state_name: &'static str,
    pub protect: u32,
    pub protect_name: String,
    pub region_type: u32,
    pub type_name: &'static str,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MemoryInfoSummary {
    pub status: String,
    pub count: Option<u64>,
    pub loaded: u64,
    pub truncated: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandleTypeCount {
    pub type_name: String,
    pub count: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HandleSummary {
    pub status: String,
    pub count: Option<u32>,
    pub by_type: Vec<HandleTypeCount>,
    pub types_truncated: bool,
    pub descriptors_truncated: bool,
    pub detail: String,
}

impl UserDumpStreams {
    /// Returns the captured MINIDUMP_MEMORY_INFO region containing `address`, if any.
    pub fn region_for(&self, address: u64) -> Option<&MemoryRegion> {
        let index = self
            .regions
            .partition_point(|region| region.base_address <= address);
        let region = self.regions.get(index.checked_sub(1)?)?;
        (address - region.base_address < region.region_size).then_some(region)
    }
}

/// Decodes the auxiliary user-mode streams. `fault_address` selects the fault module and
/// `exception_thread_id` selects the exception thread's name.
pub fn inspect_user_dump_streams(
    path: &Path,
    directory: &MinidumpDirectoryInventory,
    fault_address: Option<u64>,
    exception_thread_id: Option<u32>,
) -> UserDumpStreams {
    let mut reader = StreamReader::open(path, directory);
    let unloaded_modules = reader.unloaded_modules();
    let fault_module = reader.fault_module(fault_address, &unloaded_modules);
    let thread_names = reader.thread_names(exception_thread_id);
    let (memory_info, regions) = reader.memory_info();
    let handles = reader.handles();
    UserDumpStreams {
        source: "minidump_auxiliary_streams",
        fault_module,
        unloaded_modules: unloaded_modules.summary,
        thread_names,
        memory_info,
        handles,
        detail: "Decoded documented ModuleList, UnloadedModuleList, ThreadNames, MemoryInfoList and HandleData streams with fixed entry limits. Missing streams are reported as not_present; nothing is inferred from debugger state.",
        regions,
    }
}

struct StreamReader<'a> {
    file: anyhow::Result<(File, u64)>,
    directory: &'a MinidumpDirectoryInventory,
}

struct UnloadedScan {
    summary: UnloadedModules,
    all: Vec<UnloadedModule>,
}

impl<'a> StreamReader<'a> {
    fn open(path: &Path, directory: &'a MinidumpDirectoryInventory) -> Self {
        let file = (|| {
            ensure!(
                matches!(
                    directory.status.as_str(),
                    "captured" | "captured_with_invalid_stream_ranges"
                ),
                "The MINIDUMP directory is unavailable: {}",
                directory.detail
            );
            let file = File::open(path).context("opening dump for bounded stream inspection")?;
            let size = file.metadata()?.len();
            Ok((file, size))
        })();
        Self { file, directory }
    }

    /// Returns the unique stream's (rva, size), `Ok(None)` when absent.
    fn stream(&self, stream_type: u32) -> anyhow::Result<Option<(u32, u32)>> {
        let (_, file_bytes) = self
            .file
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
        let mut entries = self
            .directory
            .entries
            .iter()
            .filter(|entry| entry.stream_type == stream_type);
        let Some(entry) = entries.next() else {
            return Ok(None);
        };
        ensure!(
            entries.next().is_none(),
            "Ambiguous stream type {stream_type}: multiple directory entries"
        );
        ensure!(
            minidump_stream_range_status(*file_bytes, entry.data_rva, entry.data_size)
                == "within_file",
            "Stream {stream_type} range is outside the file"
        );
        Ok(Some((entry.data_rva, entry.data_size)))
    }

    fn read(&mut self, offset: u64, size: usize) -> anyhow::Result<Vec<u8>> {
        let (file, file_bytes) = self
            .file
            .as_mut()
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
        let end = offset
            .checked_add(size as u64)
            .context("file range overflow")?;
        ensure!(
            end <= *file_bytes,
            "File range {offset:#x}..{end:#x} is outside the dump"
        );
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; size];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// Reads a MINIDUMP_STRING (UTF-16, byte length prefix) bounded to MAX_STREAM_STRING_BYTES.
    fn string(&mut self, rva: u64) -> Option<String> {
        if rva == 0 {
            return None;
        }
        let length = minidump_u32(&self.read(rva, 4).ok()?, 0).min(MAX_STREAM_STRING_BYTES) & !1;
        let bytes = self.read(rva + 4, length as usize).ok()?;
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        Some(
            String::from_utf16_lossy(&units)
                .trim_end_matches('\0')
                .to_string(),
        )
    }

    fn fault_module(&mut self, address: Option<u64>, unloaded: &UnloadedScan) -> FaultModule {
        let mut result = FaultModule {
            status: "not_applicable".into(),
            address,
            detail: "No exception address was captured.".into(),
            ..Default::default()
        };
        let Some(address) = address else {
            return result;
        };
        let scan = (|| -> anyhow::Result<Option<ModuleIdentity>> {
            let Some((rva, size)) = self.stream(MODULE_LIST_STREAM)? else {
                return Ok(None);
            };
            ensure!(size >= 4, "Partial MINIDUMP_MODULE_LIST");
            let count = minidump_u32(&self.read(u64::from(rva), 4)?, 0);
            ensure!(
                count <= MAX_STREAM_MODULES,
                "Module count {count} exceeds the {MAX_STREAM_MODULES}-entry limit"
            );
            let needed = 4 + count as usize * MODULE_ENTRY_SIZE;
            ensure!(size as usize >= needed, "Partial MINIDUMP_MODULE_LIST");
            let table = self.read(u64::from(rva) + 4, needed - 4)?;
            for entry in table.chunks_exact(MODULE_ENTRY_SIZE) {
                let base = minidump_u64(entry, 0);
                let image_size = minidump_u32(entry, 8);
                if address < base || address - base >= u64::from(image_size) {
                    continue;
                }
                let time_date_stamp = minidump_u32(entry, 16);
                let fixed = &entry[24..76];
                let (file_version, product_version) =
                    if minidump_u32(fixed, 0) == VS_FIXEDFILEINFO_SIGNATURE {
                        (
                            Some(version_string(
                                minidump_u32(fixed, 8),
                                minidump_u32(fixed, 12),
                            )),
                            Some(version_string(
                                minidump_u32(fixed, 16),
                                minidump_u32(fixed, 20),
                            )),
                        )
                    } else {
                        (None, None)
                    };
                let name = self.string(u64::from(minidump_u32(entry, 20)));
                let pdb = self.codeview(minidump_u32(entry, 76), minidump_u32(entry, 80));
                return Ok(Some(ModuleIdentity {
                    name,
                    base,
                    size: image_size,
                    offset: address - base,
                    checksum: minidump_u32(entry, 12),
                    time_date_stamp,
                    time_date_stamp_utc: utc_timestamp(time_date_stamp),
                    file_version,
                    product_version,
                    pdb,
                }));
            }
            Ok(None)
        })();
        match scan {
            Ok(Some(module)) => {
                result.status = "captured".into();
                result.detail = "The exception address lies in this ModuleList entry; versions come from its VS_FIXEDFILEINFO and the PDB identity from its CodeView record.".into();
                result.module = Some(module);
            }
            Ok(None) => {
                result.unloaded_match = unloaded
                    .all
                    .iter()
                    .find(|module| {
                        address >= module.base && address - module.base < u64::from(module.size)
                    })
                    .cloned();
                if result.unloaded_match.is_some() {
                    result.status = "unloaded_module".into();
                    result.detail = "The exception address is not in a loaded module but lies in an UnloadedModuleList range: code may have run after its DLL was unloaded (the range may also have been reused).".into();
                } else {
                    result.status = "not_in_module".into();
                    result.detail = "The exception address is not inside any captured loaded or unloaded module (dynamic code, a corrupt instruction pointer, or a missing ModuleList).".into();
                }
            }
            Err(error) => {
                result.status = "invalid".into();
                result.detail = format!("Could not decode the ModuleList: {error:#}");
            }
        }
        result
    }

    fn codeview(&mut self, size: u32, rva: u32) -> Option<CodeViewIdentity> {
        if size < 25 || rva == 0 {
            return None;
        }
        let bytes = self
            .read(
                u64::from(rva),
                size.min(24 + MAX_STREAM_STRING_BYTES) as usize,
            )
            .ok()?;
        if minidump_u32(&bytes, 0) != CODEVIEW_RSDS_SIGNATURE {
            return None;
        }
        let guid = format!(
            "{:08X}-{:04X}-{:04X}-{}",
            minidump_u32(&bytes, 4),
            u16::from_le_bytes([bytes[8], bytes[9]]),
            u16::from_le_bytes([bytes[10], bytes[11]]),
            bytes[12..20]
                .iter()
                .enumerate()
                .map(|(index, byte)| if index == 2 {
                    format!("-{byte:02X}")
                } else {
                    format!("{byte:02X}")
                })
                .collect::<String>()
        );
        let name = &bytes[24..];
        let name = &name[..name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len())];
        Some(CodeViewIdentity {
            file_name: String::from_utf8_lossy(name).into_owned(),
            guid,
            age: minidump_u32(&bytes, 20),
        })
    }

    fn unloaded_modules(&mut self) -> UnloadedScan {
        let mut summary = UnloadedModules {
            status: "not_present".into(),
            detail: "The dump has no UnloadedModuleListStream.".into(),
            ..Default::default()
        };
        let mut all = Vec::new();
        let scan = (|| -> anyhow::Result<bool> {
            let Some((rva, size)) = self.stream(UNLOADED_MODULE_LIST_STREAM)? else {
                return Ok(false);
            };
            ensure!(size >= 12, "Partial MINIDUMP_UNLOADED_MODULE_LIST header");
            let header = self.read(u64::from(rva), 12)?;
            let header_size = minidump_u32(&header, 0);
            let entry_size = minidump_u32(&header, 4) as usize;
            let count = minidump_u32(&header, 8);
            ensure!(
                header_size >= 12 && entry_size >= UNLOADED_MODULE_ENTRY_SIZE,
                "Unsupported unloaded-module header/entry size"
            );
            summary.count = Some(count);
            let loaded = count.min(MAX_STREAM_UNLOADED_MODULES);
            summary.truncated = loaded < count;
            let table_bytes = loaded as usize * entry_size;
            ensure!(
                u64::from(header_size) + table_bytes as u64 <= u64::from(size),
                "Partial MINIDUMP_UNLOADED_MODULE_LIST"
            );
            let table = self.read(u64::from(rva) + u64::from(header_size), table_bytes)?;
            for entry in table.chunks_exact(entry_size) {
                let time_date_stamp = minidump_u32(entry, 16);
                all.push(UnloadedModule {
                    name: self.string(u64::from(minidump_u32(entry, 20))),
                    base: minidump_u64(entry, 0),
                    size: minidump_u32(entry, 8),
                    checksum: minidump_u32(entry, 12),
                    time_date_stamp,
                    time_date_stamp_utc: utc_timestamp(time_date_stamp),
                });
            }
            Ok(true)
        })();
        match scan {
            Ok(false) => {}
            Ok(true) => {
                summary.status = "captured".into();
                summary.truncated |= all.len() > MAX_REPORTED_UNLOADED_MODULES;
                summary.modules = all
                    .iter()
                    .take(MAX_REPORTED_UNLOADED_MODULES)
                    .cloned()
                    .collect();
                summary.detail = format!(
                    "Up to {MAX_REPORTED_UNLOADED_MODULES} entries are listed and {MAX_STREAM_UNLOADED_MODULES} are checked against the fault address. Unloaded ranges may since have been reused."
                );
            }
            Err(error) => {
                summary.status = "invalid".into();
                summary.detail = format!("Could not decode the UnloadedModuleList: {error:#}");
            }
        }
        UnloadedScan { summary, all }
    }

    fn thread_names(&mut self, exception_thread_id: Option<u32>) -> ThreadNames {
        let mut result = ThreadNames {
            status: "not_present".into(),
            detail: "The dump has no ThreadNamesStream (written only when threads were named with SetThreadDescription and the dump writer supports it).".into(),
            ..Default::default()
        };
        let scan = (|| -> anyhow::Result<bool> {
            let Some((rva, size)) = self.stream(THREAD_NAMES_STREAM)? else {
                return Ok(false);
            };
            ensure!(size >= 4, "Partial MINIDUMP_THREAD_NAME_LIST");
            let count = minidump_u32(&self.read(u64::from(rva), 4)?, 0);
            result.count = Some(count);
            let loaded = count.min(MAX_STREAM_THREAD_NAMES);
            let table_bytes = loaded as usize * THREAD_NAME_ENTRY_SIZE;
            ensure!(
                4 + table_bytes as u64 <= u64::from(size),
                "Partial MINIDUMP_THREAD_NAME_LIST"
            );
            let table = self.read(u64::from(rva) + 4, table_bytes)?;
            let mut names = Vec::new();
            for entry in table.chunks_exact(THREAD_NAME_ENTRY_SIZE) {
                let thread_system_id = minidump_u32(entry, 0);
                let Some(name) = self.string(minidump_u64(entry, 4)) else {
                    continue;
                };
                if Some(thread_system_id) == exception_thread_id {
                    result.exception_thread_name = Some(name.clone());
                }
                names.push(ThreadName {
                    thread_system_id,
                    name,
                });
            }
            result.truncated = loaded < count || names.len() > MAX_REPORTED_THREAD_NAMES;
            names.truncate(MAX_REPORTED_THREAD_NAMES);
            result.names = names;
            Ok(true)
        })();
        match scan {
            Ok(false) => {}
            Ok(true) => {
                result.status = "captured".into();
                result.detail = format!(
                    "Thread descriptions captured by the dump writer; up to {MAX_REPORTED_THREAD_NAMES} are listed."
                );
            }
            Err(error) => {
                result.status = "invalid".into();
                result.detail = format!("Could not decode the ThreadNamesStream: {error:#}");
            }
        }
        result
    }

    fn memory_info(&mut self) -> (MemoryInfoSummary, Vec<MemoryRegion>) {
        let mut summary = MemoryInfoSummary {
            status: "not_present".into(),
            detail:
                "The dump has no MemoryInfoListStream, so region state/protection is unavailable."
                    .into(),
            ..Default::default()
        };
        let mut regions = Vec::new();
        let scan = (|| -> anyhow::Result<bool> {
            let Some((rva, size)) = self.stream(MEMORY_INFO_LIST_STREAM)? else {
                return Ok(false);
            };
            ensure!(size >= 16, "Partial MINIDUMP_MEMORY_INFO_LIST header");
            let header = self.read(u64::from(rva), 16)?;
            let header_size = minidump_u32(&header, 0);
            let entry_size = minidump_u32(&header, 4) as usize;
            let count = minidump_u64(&header, 8);
            ensure!(
                header_size >= 16 && entry_size >= MEMORY_INFO_ENTRY_SIZE,
                "Unsupported memory-info header/entry size"
            );
            summary.count = Some(count);
            let loaded = count.min(MAX_STREAM_MEMORY_REGIONS);
            summary.truncated = loaded < count;
            let table_bytes = loaded as usize * entry_size;
            ensure!(
                u64::from(header_size) + table_bytes as u64 <= u64::from(size),
                "Partial MINIDUMP_MEMORY_INFO_LIST"
            );
            let table = self.read(u64::from(rva) + u64::from(header_size), table_bytes)?;
            regions.extend(table.chunks_exact(entry_size).map(memory_region));
            regions.sort_by_key(|region| region.base_address);
            summary.loaded = regions.len() as u64;
            Ok(true)
        })();
        match scan {
            Ok(false) => {}
            Ok(true) => {
                summary.status = "captured".into();
                summary.detail = format!(
                    "Region state/protection/type is reported only for addresses triage inspects; at most {MAX_STREAM_MEMORY_REGIONS} regions are loaded."
                );
            }
            Err(error) => {
                regions.clear();
                summary.status = "invalid".into();
                summary.detail = format!("Could not decode the MemoryInfoList: {error:#}");
            }
        }
        (summary, regions)
    }

    fn handles(&mut self) -> HandleSummary {
        let mut result = HandleSummary {
            status: "not_present".into(),
            detail: "The dump has no HandleDataStream (written only with MiniDumpWithHandleData)."
                .into(),
            ..Default::default()
        };
        let scan = (|| -> anyhow::Result<bool> {
            let Some((rva, size)) = self.stream(HANDLE_DATA_STREAM)? else {
                return Ok(false);
            };
            ensure!(size >= 16, "Partial MINIDUMP_HANDLE_DATA_STREAM header");
            let header = self.read(u64::from(rva), 16)?;
            let header_size = minidump_u32(&header, 0);
            let descriptor_size = minidump_u32(&header, 4) as usize;
            let count = minidump_u32(&header, 8);
            ensure!(
                header_size >= 16 && descriptor_size >= HANDLE_DESCRIPTOR_SIZE,
                "Unsupported handle header/descriptor size"
            );
            result.count = Some(count);
            let loaded = count.min(MAX_STREAM_HANDLES);
            result.descriptors_truncated = loaded < count;
            let table_bytes = loaded as usize * descriptor_size;
            ensure!(
                u64::from(header_size) + table_bytes as u64 <= u64::from(size),
                "Partial MINIDUMP_HANDLE_DATA_STREAM"
            );
            let table = self.read(u64::from(rva) + u64::from(header_size), table_bytes)?;
            let mut names: HashMap<u32, String> = HashMap::new();
            let mut counts: Vec<HandleTypeCount> = Vec::new();
            for descriptor in table.chunks_exact(descriptor_size) {
                let type_rva = minidump_u32(descriptor, 8);
                let type_name: &String = names.entry(type_rva).or_insert_with(|| {
                    self.string(u64::from(type_rva))
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| "<unknown>".into())
                });
                if let Some(entry) = counts
                    .iter_mut()
                    .find(|entry| &entry.type_name == type_name)
                {
                    entry.count += 1;
                } else if counts.len() < MAX_REPORTED_HANDLE_TYPES {
                    counts.push(HandleTypeCount {
                        type_name: type_name.clone(),
                        count: 1,
                    });
                } else {
                    result.types_truncated = true;
                }
            }
            counts.sort_by(|a, b| b.count.cmp(&a.count).then(a.type_name.cmp(&b.type_name)));
            result.by_type = counts;
            Ok(true)
        })();
        match scan {
            Ok(false) => {}
            Ok(true) => {
                result.status = "captured".into();
                result.detail = format!(
                    "Handle counts by object type from at most {MAX_STREAM_HANDLES} descriptors; object names are not reported."
                );
            }
            Err(error) => {
                result.status = "invalid".into();
                result.detail = format!("Could not decode the HandleDataStream: {error:#}");
            }
        }
        result
    }
}

fn memory_region(entry: &[u8]) -> MemoryRegion {
    let state = minidump_u32(entry, 32);
    let protect = minidump_u32(entry, 36);
    let region_type = minidump_u32(entry, 40);
    MemoryRegion {
        base_address: minidump_u64(entry, 0),
        allocation_base: minidump_u64(entry, 8),
        allocation_protect: minidump_u32(entry, 16),
        region_size: minidump_u64(entry, 24),
        state,
        state_name: match state {
            0x1000 => "MEM_COMMIT",
            0x2000 => "MEM_RESERVE",
            0x10000 => "MEM_FREE",
            _ => "unknown",
        },
        protect,
        protect_name: protect_name(protect),
        region_type,
        type_name: match region_type {
            0 => "none",
            0x20000 => "MEM_PRIVATE",
            0x40000 => "MEM_MAPPED",
            0x1000000 => "MEM_IMAGE",
            _ => "unknown",
        },
    }
}

pub fn protect_name(protect: u32) -> String {
    let base = match protect & 0xFF {
        0 => "none",
        0x01 => "PAGE_NOACCESS",
        0x02 => "PAGE_READONLY",
        0x04 => "PAGE_READWRITE",
        0x08 => "PAGE_WRITECOPY",
        0x10 => "PAGE_EXECUTE",
        0x20 => "PAGE_EXECUTE_READ",
        0x40 => "PAGE_EXECUTE_READWRITE",
        0x80 => "PAGE_EXECUTE_WRITECOPY",
        _ => "unknown",
    };
    let mut name = base.to_string();
    for (flag, modifier) in [
        (0x100, "PAGE_GUARD"),
        (0x200, "PAGE_NOCACHE"),
        (0x400, "PAGE_WRITECOMBINE"),
    ] {
        if protect & flag != 0 {
            name.push('|');
            name.push_str(modifier);
        }
    }
    name
}

fn version_string(most: u32, least: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        most >> 16,
        most & 0xFFFF,
        least >> 16,
        least & 0xFFFF
    )
}

/// Formats a PE/minidump `time_t` as an RFC 3339 UTC timestamp. Note that reproducible builds
/// store a content hash rather than a time in TimeDateStamp.
pub fn utc_timestamp(seconds: u32) -> String {
    let days = i64::from(seconds / 86_400);
    let remainder = seconds % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3600,
        remainder / 60 % 60,
        remainder % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inspect_minidump_directory, tests::temporary_runtime_directory};

    fn utf16_string(text: &str) -> Vec<u8> {
        let units = text.encode_utf16().collect::<Vec<_>>();
        let mut bytes = ((units.len() * 2) as u32).to_le_bytes().to_vec();
        bytes.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
        bytes.extend([0, 0]);
        bytes
    }

    /// Builds a minidump with the given (stream type, payload) pairs. Payloads may contain the
    /// placeholder RVA `0xFFFF_0000 + n` that is patched to point at `extra[n]`.
    fn build_dump(streams: &[(u32, Vec<u8>)], extra: &[Vec<u8>]) -> Vec<u8> {
        let directory_rva = 32u32;
        let mut offset = directory_rva + 12 * streams.len() as u32;
        let mut stream_rvas = Vec::new();
        for (_, payload) in streams {
            stream_rvas.push(offset);
            offset += payload.len() as u32;
        }
        let mut extra_rvas = Vec::new();
        for blob in extra {
            extra_rvas.push(offset);
            offset += blob.len() as u32;
        }
        let mut file = Vec::new();
        file.extend(0x504D_444Du32.to_le_bytes());
        file.extend(0xA793u32.to_le_bytes());
        file.extend((streams.len() as u32).to_le_bytes());
        file.extend(directory_rva.to_le_bytes());
        file.extend([0u8; 16]);
        for ((stream_type, payload), rva) in streams.iter().zip(&stream_rvas) {
            file.extend(stream_type.to_le_bytes());
            file.extend((payload.len() as u32).to_le_bytes());
            file.extend(rva.to_le_bytes());
        }
        for (_, payload) in streams {
            let mut payload = payload.clone();
            for window in 0..payload.len().saturating_sub(3) {
                let value = minidump_u32(&payload, window);
                if value & 0xFFFF_0000 == 0xFFFF_0000 {
                    let index = (value & 0xFFFF) as usize;
                    if let Some(rva) = extra_rvas.get(index) {
                        payload[window..window + 4].copy_from_slice(&rva.to_le_bytes());
                    }
                }
            }
            file.extend(payload);
        }
        for blob in extra {
            file.extend(blob);
        }
        file
    }

    fn module_entry(base: u64, size: u32, name_rva: u32, cv_rva: u32, cv_size: u32) -> Vec<u8> {
        let mut entry = vec![0u8; MODULE_ENTRY_SIZE];
        entry[0..8].copy_from_slice(&base.to_le_bytes());
        entry[8..12].copy_from_slice(&size.to_le_bytes());
        entry[12..16].copy_from_slice(&0x1234u32.to_le_bytes());
        entry[16..20].copy_from_slice(&0x6500_0000u32.to_le_bytes());
        entry[20..24].copy_from_slice(&name_rva.to_le_bytes());
        entry[24..28].copy_from_slice(&VS_FIXEDFILEINFO_SIGNATURE.to_le_bytes());
        entry[32..36].copy_from_slice(&(10u32 << 16).to_le_bytes());
        entry[36..40].copy_from_slice(&((26100u32 << 16) | 33438).to_le_bytes());
        entry[40..44].copy_from_slice(&(10u32 << 16).to_le_bytes());
        entry[44..48].copy_from_slice(&((26100u32 << 16) | 1).to_le_bytes());
        entry[76..80].copy_from_slice(&cv_size.to_le_bytes());
        entry[80..84].copy_from_slice(&cv_rva.to_le_bytes());
        entry
    }

    fn write_dump(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let directory = temporary_runtime_directory(name);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("streams.dmp");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn decodes_fault_module_unloaded_thread_names_memory_and_handles() {
        let mut modules = 2u32.to_le_bytes().to_vec();
        modules.extend(module_entry(0x1000_0000, 0x1000, 0xFFFF_0000, 0, 0));
        modules.extend(module_entry(
            0x7ff6_c8dd_0000,
            0x10_0000,
            0xFFFF_0001,
            0xFFFF_0002,
            0,
        ));
        let mut codeview = CODEVIEW_RSDS_SIGNATURE.to_le_bytes().to_vec();
        codeview.extend([
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        codeview.extend(3u32.to_le_bytes());
        codeview.extend(b"rdpshell.pdb\0");
        let cv_size = codeview.len() as u32;
        let cv_offset = 4 + MODULE_ENTRY_SIZE + 76;
        modules[cv_offset..cv_offset + 4].copy_from_slice(&cv_size.to_le_bytes());

        let mut unloaded = 12u32.to_le_bytes().to_vec();
        unloaded.extend((UNLOADED_MODULE_ENTRY_SIZE as u32).to_le_bytes());
        unloaded.extend(1u32.to_le_bytes());
        unloaded.extend(0x2000_0000u64.to_le_bytes());
        unloaded.extend(0x1000u32.to_le_bytes());
        unloaded.extend(0u32.to_le_bytes());
        unloaded.extend(0u32.to_le_bytes());
        unloaded.extend(0xFFFF_0003u32.to_le_bytes());

        let mut names = 2u32.to_le_bytes().to_vec();
        names.extend(10292u32.to_le_bytes());
        names.extend(0xFFFF_0004u64.to_le_bytes());
        names.extend(7u32.to_le_bytes());
        names.extend(0xFFFF_0005u64.to_le_bytes());

        let mut memory = 16u32.to_le_bytes().to_vec();
        memory.extend((MEMORY_INFO_ENTRY_SIZE as u32).to_le_bytes());
        memory.extend(2u64.to_le_bytes());
        for (base, size, state, protect, kind) in [
            (0x5000u64, 0x2000u64, 0x1000u32, 0x04u32, 0x20000u32),
            (0x0u64, 0x1_0000u64, 0x10000, 0x01, 0),
        ] {
            let mut entry = vec![0u8; MEMORY_INFO_ENTRY_SIZE];
            entry[0..8].copy_from_slice(&base.to_le_bytes());
            entry[8..16].copy_from_slice(&base.to_le_bytes());
            entry[24..32].copy_from_slice(&size.to_le_bytes());
            entry[32..36].copy_from_slice(&state.to_le_bytes());
            entry[36..40].copy_from_slice(&protect.to_le_bytes());
            entry[40..44].copy_from_slice(&kind.to_le_bytes());
            memory.extend(entry);
        }

        let mut handles = 16u32.to_le_bytes().to_vec();
        handles.extend((HANDLE_DESCRIPTOR_SIZE as u32).to_le_bytes());
        handles.extend(3u32.to_le_bytes());
        handles.extend(0u32.to_le_bytes());
        for type_rva in [0xFFFF_0006u32, 0xFFFF_0007, 0xFFFF_0006] {
            let mut descriptor = vec![0u8; HANDLE_DESCRIPTOR_SIZE];
            descriptor[8..12].copy_from_slice(&type_rva.to_le_bytes());
            handles.extend(descriptor);
        }

        let bytes = build_dump(
            &[
                (MODULE_LIST_STREAM, modules),
                (UNLOADED_MODULE_LIST_STREAM, unloaded),
                (THREAD_NAMES_STREAM, names),
                (MEMORY_INFO_LIST_STREAM, memory),
                (HANDLE_DATA_STREAM, handles),
            ],
            &[
                utf16_string("C:\\x\\other.dll"),
                utf16_string("C:\\Windows\\System32\\rdpshell.exe"),
                codeview,
                utf16_string("gone.dll"),
                utf16_string("RAIL worker"),
                utf16_string("main"),
                utf16_string("Event"),
                utf16_string("File"),
            ],
        );
        let path = write_dump("minidump-streams", &bytes);
        let directory = inspect_minidump_directory(&path);
        let streams =
            inspect_user_dump_streams(&path, &directory, Some(0x7ff6_c8e3_f853), Some(10292));

        let module = streams.fault_module.module.as_ref().expect("fault module");
        assert_eq!(streams.fault_module.status, "captured");
        assert_eq!(
            module.name.as_deref(),
            Some("C:\\Windows\\System32\\rdpshell.exe")
        );
        assert_eq!(module.offset, 0x6f853);
        assert_eq!(module.file_version.as_deref(), Some("10.0.26100.33438"));
        assert_eq!(module.product_version.as_deref(), Some("10.0.26100.1"));
        assert_eq!(module.time_date_stamp_utc, "2023-09-12T06:06:56Z");
        let pdb = module.pdb.as_ref().expect("codeview identity");
        assert_eq!(pdb.file_name, "rdpshell.pdb");
        assert_eq!(pdb.guid, "12345678-1234-5678-0102-030405060708");
        assert_eq!(pdb.age, 3);

        assert_eq!(streams.unloaded_modules.status, "captured");
        assert_eq!(
            streams.unloaded_modules.modules[0].name.as_deref(),
            Some("gone.dll")
        );
        assert_eq!(
            streams.thread_names.exception_thread_name.as_deref(),
            Some("RAIL worker")
        );
        assert_eq!(streams.thread_names.names.len(), 2);
        assert_eq!(streams.memory_info.loaded, 2);
        let region = streams.region_for(0x6000).expect("region");
        assert_eq!(region.state_name, "MEM_COMMIT");
        assert_eq!(region.protect_name, "PAGE_READWRITE");
        assert_eq!(region.type_name, "MEM_PRIVATE");
        assert_eq!(streams.region_for(0x10).unwrap().state_name, "MEM_FREE");
        assert!(streams.region_for(0x7000).is_none());
        assert_eq!(streams.handles.count, Some(3));
        assert_eq!(streams.handles.by_type[0].type_name, "Event");
        assert_eq!(streams.handles.by_type[0].count, 2);

        let unloaded = inspect_user_dump_streams(&path, &directory, Some(0x2000_0010), None);
        assert_eq!(unloaded.fault_module.status, "unloaded_module");
        assert_eq!(
            unloaded
                .fault_module
                .unloaded_match
                .as_ref()
                .and_then(|module| module.name.as_deref()),
            Some("gone.dll")
        );
        let nowhere = inspect_user_dump_streams(&path, &directory, Some(0x3000_0000), None);
        assert_eq!(nowhere.fault_module.status, "not_in_module");
    }

    #[test]
    fn reports_missing_and_oversized_streams_without_reading_payloads() {
        let path = write_dump("minidump-streams-empty", &build_dump(&[], &[]));
        let directory = inspect_minidump_directory(&path);
        let streams = inspect_user_dump_streams(&path, &directory, Some(0x1000), None);
        assert_eq!(streams.fault_module.status, "not_in_module");
        assert_eq!(streams.unloaded_modules.status, "not_present");
        assert_eq!(streams.thread_names.status, "not_present");
        assert_eq!(streams.memory_info.status, "not_present");
        assert_eq!(streams.handles.status, "not_present");

        let mut modules = (MAX_STREAM_MODULES + 1).to_le_bytes().to_vec();
        modules.extend([0u8; 8]);
        let path = write_dump(
            "minidump-streams-oversized",
            &build_dump(&[(MODULE_LIST_STREAM, modules)], &[]),
        );
        let directory = inspect_minidump_directory(&path);
        let streams = inspect_user_dump_streams(&path, &directory, Some(0x1000), None);
        assert_eq!(streams.fault_module.status, "invalid");
        assert!(streams.fault_module.detail.contains("limit"));
    }

    #[test]
    fn formats_timestamps_and_protection() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(protect_name(0x104), "PAGE_READWRITE|PAGE_GUARD");
    }
}
