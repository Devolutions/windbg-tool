use serde_json::{json, Value};

pub fn recover_stack_candidates(
    stack_read: &Value,
    max_candidates: usize,
    min_confidence: f64,
) -> Vec<Value> {
    let mut candidates = stack_read["pointers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pointer| {
            let value = pointer["value"].as_u64()?;
            let slot_address = pointer["address"].as_u64()?;
            let module = pointer["module"].as_str();
            let confidence = stack_candidate_confidence(value, slot_address, module.is_some());
            (confidence >= min_confidence).then(|| {
                json!({
                    "slot_address": slot_address,
                    "slot_address_hex": format!("0x{slot_address:X}"),
                    "offset": pointer["offset"].as_u64().unwrap_or_default(),
                    "target": value,
                    "target_hex": format!("0x{value:X}"),
                    "module": module,
                    "confidence": confidence,
                    "reasons": stack_candidate_reasons(value, slot_address, module.is_some()),
                })
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right["confidence"]
            .as_f64()
            .partial_cmp(&left["confidence"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                left["slot_address"]
                    .as_u64()
                    .cmp(&right["slot_address"].as_u64())
            })
    });
    candidates.truncate(max_candidates);
    candidates
}

/// Return addresses point just past a `call` instruction and therefore have no particular
/// alignment, so the target is only required to be a canonical, non-null-page address. Rewarding
/// 8/16-byte-aligned targets would rank in-module data and function-start pointers above genuine
/// return addresses.
fn canonical_code_address(value: u64) -> bool {
    value >= 0x10000 && !(0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&value)
}

pub fn stack_candidate_confidence(value: u64, slot_address: u64, in_module: bool) -> f64 {
    let mut score = 15u32;
    if in_module {
        score += 55;
    }
    if slot_address.is_multiple_of(8) {
        score += 10;
    }
    if canonical_code_address(value) {
        score += 15;
    }
    f64::from(score.min(100)) / 100.0
}

pub fn stack_candidate_reasons(
    value: u64,
    slot_address: u64,
    in_module: bool,
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if in_module {
        reasons.push("target_in_loaded_module");
    }
    if slot_address.is_multiple_of(8) {
        reasons.push("aligned_stack_slot");
    }
    if canonical_code_address(value) {
        reasons.push("canonical_x64_address");
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_stack_candidates_from_module_pointers() {
        let stack = json!({
            "pointers": [
                {
                    "offset": 0,
                    "address": 0x1000u64,
                    "value": 0x7ff612341000u64,
                    "module": "app.exe"
                },
                {
                    "offset": 8,
                    "address": 0x1008u64,
                    "value": 0x1234u64,
                    "module": null
                }
            ]
        });
        let candidates = recover_stack_candidates(&stack, 8, 0.5);
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0]["module"], "app.exe");
        assert!(
            candidates[0]["reasons"]
                .as_array()
                .is_some_and(|reasons| reasons
                    .iter()
                    .any(|reason| reason == "target_in_loaded_module")),
            "{candidates:?}"
        );
    }

    #[test]
    fn unaligned_return_addresses_are_not_outranked_by_aligned_module_pointers() {
        // A return address follows a call instruction and is rarely 8- or 16-byte aligned.
        let return_address = stack_candidate_confidence(0x7ff6_1234_1a3b, 0x1000, true);
        let function_pointer = stack_candidate_confidence(0x7ff6_1234_1a40, 0x1008, true);
        assert!(
            return_address >= function_pointer,
            "{return_address} < {function_pointer}"
        );
        assert!(stack_candidate_reasons(0x7ff6_1234_1a3b, 0x1000, true)
            .contains(&"canonical_x64_address"));
        assert!(!stack_candidate_reasons(0x1234, 0x1000, false).contains(&"canonical_x64_address"));
        assert!(!stack_candidate_reasons(0x8000_0000_0000, 0x1000, true)
            .contains(&"canonical_x64_address"));
    }
}
