//! Target-side (live/dump) analysis helpers that reuse pure memory/stack classifiers.

use super::disasm::disassemble_x64;
use super::memory::{
    ascii_strings, classify_memory, memory_dump, plausible_x64_pointer, read_pointer_value,
    utf16le_strings,
};
use super::stack::recover_stack_candidates;
use super::util::{hex_to_bytes, parse_u64_argument};
use crate::state::ServiceState;
use crate::targets::{TargetId, TargetMemoryReadRequest, TargetRequest};
use anyhow::{ensure, Context};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

fn default_disasm_count() -> u32 {
    16
}
fn default_disasm_bytes() -> u32 {
    128
}
fn default_memory_size() -> u32 {
    256
}
fn default_dump_format() -> String {
    "db".to_string()
}
fn default_encoding() -> String {
    "both".to_string()
}
fn default_min_len() -> usize {
    4
}
fn default_max_strings() -> usize {
    256
}
fn default_pointer_size() -> u32 {
    8
}
fn default_chase_depth() -> u32 {
    8
}
fn default_max_candidates() -> usize {
    64
}
fn default_min_confidence() -> f64 {
    0.45
}
fn default_stack_size() -> u32 {
    4096
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetDisassembleAnalysisRequest {
    pub target_id: TargetId,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default = "default_disasm_count")]
    pub count: u32,
    #[serde(default = "default_disasm_bytes")]
    pub bytes: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetMemoryAnalysisRequest {
    pub target_id: TargetId,
    pub address: String,
    #[serde(default = "default_memory_size")]
    pub size: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetMemoryDumpRequest {
    #[serde(flatten)]
    pub base: TargetMemoryAnalysisRequest,
    #[serde(default = "default_dump_format")]
    pub format: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetMemoryStringsRequest {
    #[serde(flatten)]
    pub base: TargetMemoryAnalysisRequest,
    #[serde(default = "default_encoding")]
    pub encoding: String,
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    #[serde(default = "default_max_strings")]
    pub max_strings: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetMemoryDpsRequest {
    #[serde(flatten)]
    pub base: TargetMemoryAnalysisRequest,
    #[serde(default = "default_pointer_size")]
    pub pointer_size: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetMemoryChaseRequest {
    pub target_id: TargetId,
    pub address: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_chase_depth")]
    pub depth: u32,
    #[serde(default = "default_pointer_size")]
    pub pointer_size: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetStackRecoverRequest {
    pub target_id: TargetId,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default = "default_stack_size")]
    pub size: u32,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
}

fn read_target_bytes(
    state: &ServiceState,
    target_id: TargetId,
    address: u64,
    size: u32,
) -> anyhow::Result<(u64, Vec<u8>)> {
    ensure!(size > 0, "size must be greater than zero");
    ensure!(size <= 65536, "size must be 65536 bytes or less");
    let response = state.targets.read_memory(TargetMemoryReadRequest {
        target_id,
        address,
        size,
    })?;
    let bytes = hex_to_bytes(&response.memory.data)?;
    Ok((response.memory.address, bytes))
}

fn resolve_target_pc(state: &ServiceState, target_id: TargetId) -> anyhow::Result<u64> {
    let regs = state.targets.core_registers(TargetRequest { target_id })?;
    regs.registers
        .instruction_offset
        .context("target core registers did not include instruction_offset; pass address")
}

fn resolve_target_sp(state: &ServiceState, target_id: TargetId) -> anyhow::Result<u64> {
    let regs = state.targets.core_registers(TargetRequest { target_id })?;
    regs.registers
        .stack_offset
        .context("target core registers did not include stack_offset; pass address")
}

fn stack_read_from_bytes(address: u64, bytes: &[u8]) -> Value {
    let mut pointers = Vec::new();
    let mut offset = 0usize;
    while offset + 8 <= bytes.len() {
        let slot = address + offset as u64;
        let value = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        pointers.push(json!({
            "address": slot,
            "offset": offset,
            "value": value,
            "module": Value::Null,
        }));
        offset += 8;
    }
    json!({
        "address": address,
        "size": bytes.len(),
        "pointers": pointers,
    })
}

pub fn target_disassemble(
    state: &ServiceState,
    request: TargetDisassembleAnalysisRequest,
) -> anyhow::Result<Value> {
    ensure!(
        request.count > 0 && request.count <= 256,
        "count must be 1..=256"
    );
    ensure!(
        request.bytes > 0 && request.bytes <= 4096,
        "bytes must be 1..=4096"
    );
    let address = match request.address.as_deref() {
        Some(value) => parse_u64_argument(value)?,
        None => resolve_target_pc(state, request.target_id)?,
    };
    let (address, bytes) = read_target_bytes(state, request.target_id, address, request.bytes)?;
    Ok(json!({
        "target_id": request.target_id,
        "architecture": "x64",
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "bytes_read": bytes.len(),
        "instructions": disassemble_x64(address, &bytes, request.count as usize),
    }))
}

pub fn target_memory_dump(
    state: &ServiceState,
    request: TargetMemoryDumpRequest,
) -> anyhow::Result<Value> {
    let address = parse_u64_argument(&request.base.address)?;
    let (address, bytes) =
        read_target_bytes(state, request.base.target_id, address, request.base.size)?;
    let mut dump = memory_dump(address, &bytes, &request.format)?;
    if let Some(object) = dump.as_object_mut() {
        object.insert("target_id".into(), json!(request.base.target_id));
        object.insert("address".into(), json!(address));
        object.insert("address_hex".into(), json!(format!("0x{address:X}")));
        object.insert("size".into(), json!(bytes.len()));
    }
    Ok(dump)
}

pub fn target_memory_classify(
    state: &ServiceState,
    request: TargetMemoryAnalysisRequest,
) -> anyhow::Result<Value> {
    let address = parse_u64_argument(&request.address)?;
    let (address, bytes) = read_target_bytes(state, request.target_id, address, request.size)?;
    let mut value = classify_memory(address, &bytes);
    if let Some(object) = value.as_object_mut() {
        object.insert("target_id".into(), json!(request.target_id));
    }
    Ok(value)
}

pub fn target_memory_strings(
    state: &ServiceState,
    request: TargetMemoryStringsRequest,
) -> anyhow::Result<Value> {
    let address = parse_u64_argument(&request.base.address)?;
    let (address, bytes) =
        read_target_bytes(state, request.base.target_id, address, request.base.size)?;
    let encoding = request.encoding.to_ascii_lowercase();
    let mut strings = Vec::new();
    if encoding == "ascii" || encoding == "both" {
        strings.extend(ascii_strings(address, &bytes));
    }
    if matches!(encoding.as_str(), "utf16" | "utf-16" | "both") {
        strings.extend(utf16le_strings(address, &bytes));
    }
    strings.retain(|entry| {
        entry["length"]
            .as_u64()
            .map(|len| len as usize >= request.min_len)
            .unwrap_or(false)
    });
    strings.truncate(request.max_strings);
    Ok(json!({
        "target_id": request.base.target_id,
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "size": bytes.len(),
        "encoding": request.encoding,
        "min_len": request.min_len,
        "count": strings.len(),
        "strings": strings,
    }))
}

pub fn target_memory_dps(
    state: &ServiceState,
    request: TargetMemoryDpsRequest,
) -> anyhow::Result<Value> {
    ensure!(
        request.pointer_size == 4 || request.pointer_size == 8,
        "pointer_size must be 4 or 8"
    );
    let address = parse_u64_argument(&request.base.address)?;
    let (address, bytes) =
        read_target_bytes(state, request.base.target_id, address, request.base.size)?;
    let mut rows = Vec::new();
    let step = request.pointer_size as usize;
    let mut offset = 0usize;
    while offset + step <= bytes.len() {
        let slot = address + offset as u64;
        let value = read_pointer_value(&bytes[offset..], request.pointer_size)?;
        rows.push(json!({
            "address": slot,
            "address_hex": format!("0x{slot:X}"),
            "value": value,
            "value_hex": format!("0x{value:X}"),
            "plausible_pointer": plausible_x64_pointer(value),
        }));
        offset += step;
    }
    Ok(json!({
        "target_id": request.base.target_id,
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "pointer_size": request.pointer_size,
        "count": rows.len(),
        "rows": rows,
    }))
}

pub fn target_memory_chase(
    state: &ServiceState,
    request: TargetMemoryChaseRequest,
) -> anyhow::Result<Value> {
    ensure!(
        request.depth > 0 && request.depth <= 32,
        "depth must be 1..=32"
    );
    ensure!(
        request.pointer_size == 4 || request.pointer_size == 8,
        "pointer_size must be 4 or 8"
    );
    let mut current = parse_u64_argument(&request.address)?;
    let mut chain = Vec::new();
    for index in 0..request.depth {
        let read_at = current.saturating_add(request.offset);
        match state.targets.read_memory(TargetMemoryReadRequest {
            target_id: request.target_id,
            address: read_at,
            size: request.pointer_size,
        }) {
            Ok(response) => {
                let bytes = hex_to_bytes(&response.memory.data)?;
                if bytes.len() < request.pointer_size as usize {
                    chain.push(json!({
                        "index": index,
                        "address": read_at,
                        "error": "short_read",
                    }));
                    break;
                }
                let value = read_pointer_value(&bytes, request.pointer_size)?;
                chain.push(json!({
                    "index": index,
                    "address": read_at,
                    "address_hex": format!("0x{read_at:X}"),
                    "value": value,
                    "value_hex": format!("0x{value:X}"),
                    "plausible_pointer": plausible_x64_pointer(value),
                }));
                if value == 0 || !plausible_x64_pointer(value) {
                    break;
                }
                current = value;
            }
            Err(error) => {
                chain.push(json!({
                    "index": index,
                    "address": read_at,
                    "error": error.to_string(),
                }));
                break;
            }
        }
    }
    Ok(json!({
        "target_id": request.target_id,
        "start": request.address,
        "offset": request.offset,
        "depth": request.depth,
        "pointer_size": request.pointer_size,
        "steps": chain.len(),
        "chain": chain,
    }))
}

pub fn target_stack_recover(
    state: &ServiceState,
    request: TargetStackRecoverRequest,
) -> anyhow::Result<Value> {
    ensure!(
        (0.0..=1.0).contains(&request.min_confidence),
        "min_confidence must be between 0.0 and 1.0"
    );
    ensure!(request.max_candidates > 0, "max_candidates must be > 0");
    ensure!(
        request.max_candidates <= 512,
        "max_candidates must be <= 512"
    );
    let address = match request.address.as_deref() {
        Some(value) => parse_u64_argument(value)?,
        None => resolve_target_sp(state, request.target_id)?,
    };
    let (address, bytes) = read_target_bytes(state, request.target_id, address, request.size)?;
    let stack_value = stack_read_from_bytes(address, &bytes);
    let candidates =
        recover_stack_candidates(&stack_value, request.max_candidates, request.min_confidence);
    Ok(json!({
        "target_id": request.target_id,
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "size": bytes.len(),
        "stack": stack_value,
        "candidates": candidates,
        "heuristics": [
            "Pointer-sized stack values that look like canonical x64 code pointers are return-address candidates.",
            "Without module maps this is lower fidelity than TTD stack recover with decode_pointers."
        ],
    }))
}
