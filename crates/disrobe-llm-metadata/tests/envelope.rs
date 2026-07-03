#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_llm_metadata::PerPassEnvelope;
use serde_json::{Value as Json, json};

#[test]
fn applicable_roundtrip() {
    let env: PerPassEnvelope =
        PerPassEnvelope::applicable("disrobe-pass-py-disasm", "0.1.0", json!({"k": 1}));
    let s: String = serde_json::to_string(&env).unwrap();
    let parsed: PerPassEnvelope = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed, env);
}

#[test]
fn not_applicable_carries_reason_and_null_value() {
    let env: PerPassEnvelope =
        PerPassEnvelope::not_applicable("disrobe-pass-shell", "0.1.0", "no disasm in shell");
    assert!(!env.applicable);
    assert_eq!(env.reason.as_deref(), Some("no disasm in shell"));
    assert!(env.value.is_none());
}

#[test]
fn json_shape_matches_schema_keys() {
    let env: PerPassEnvelope = PerPassEnvelope::applicable("p", "v", json!("payload"));
    let v: Json = serde_json::to_value(&env).unwrap();
    let obj: &serde_json::Map<String, Json> = v.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["applicable", "pass", "pass_version", "reason", "value"]
    );
}
