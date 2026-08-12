use serde_json::{json, Value};

pub fn collect_timeline_events(
    events: &mut Vec<Value>,
    kind: &str,
    source: &Value,
    array_key: &str,
) {
    let Some(items) = timeline_source_items(source, array_key) else {
        return;
    };
    for item in items {
        let position = item
            .get("position")
            .cloned()
            .or_else(|| {
                item.get("module")
                    .and_then(|module| module.get("load_position"))
                    .cloned()
            })
            .unwrap_or(Value::Null);
        events.push(json!({
            "kind": kind,
            "event_kind": item.get("kind").cloned().unwrap_or(Value::Null),
            "position": position,
            "sequence": position.get("sequence").cloned().unwrap_or(Value::Null),
            "payload": item,
        }));
    }
}

pub fn collect_keyframe_events(events: &mut Vec<Value>, source: &Value) {
    let Some(items) = timeline_source_items(source, "keyframes") else {
        return;
    };
    for position in items {
        events.push(json!({
            "kind": "keyframe",
            "event_kind": "keyframe",
            "position": position,
            "sequence": position.get("sequence").cloned().unwrap_or(Value::Null),
            "payload": position,
        }));
    }
}

pub fn timeline_source_items<'a>(source: &'a Value, array_key: &str) -> Option<&'a Vec<Value>> {
    let value = source.get("value")?;
    value
        .get(array_key)
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
}

pub fn timeline_source_summary(source: &Value, array_key: &str) -> Value {
    if source["ok"].as_bool() != Some(true) {
        return source.clone();
    }

    let item_count = timeline_source_items(source, array_key).map_or(0, Vec::len);
    json!({
        "ok": true,
        "item_count": item_count,
        "items_omitted": true
    })
}

pub fn timeline_sequence(event: &Value) -> u64 {
    event["sequence"].as_u64().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_source_summary_omits_unbounded_items() {
        let source = json!({
            "ok": true,
            "value": [{ "sequence": 1 }, { "sequence": 2 }]
        });
        let summary = timeline_source_summary(&source, "keyframes");

        assert_eq!(summary["ok"], true);
        assert_eq!(summary["item_count"], 2);
        assert_eq!(summary["items_omitted"], true);
        assert!(summary.get("value").is_none());
    }

    #[test]
    fn timeline_collects_top_level_exception_arrays() {
        let source = json!({
            "ok": true,
            "value": [{
                "position": { "sequence": 479966, "steps": 0 },
                "code": 0xE06D7363u64
            }]
        });
        let mut events = Vec::new();

        collect_timeline_events(&mut events, "exception", &source, "exceptions");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "exception");
        assert_eq!(events[0]["sequence"], 479966);
    }
}
