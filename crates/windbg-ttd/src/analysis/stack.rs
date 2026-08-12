use super::memory::plausible_x64_pointer;
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

pub fn stack_candidate_confidence(value: u64, slot_address: u64, in_module: bool) -> f64 {
    let mut confidence = 0.15;
    if in_module {
        confidence += 0.55;
    }
    if slot_address.is_multiple_of(8) {
        confidence += 0.10;
    }
    if plausible_x64_pointer(value) {
        confidence += 0.15;
    }
    if value.is_multiple_of(16) {
        confidence += 0.05;
    }
    f64::min(confidence, 1.0)
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
    if plausible_x64_pointer(value) {
        reasons.push("canonical_aligned_x64_pointer");
    }
    if value.is_multiple_of(16) {
        reasons.push("target_16_byte_aligned");
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
}
