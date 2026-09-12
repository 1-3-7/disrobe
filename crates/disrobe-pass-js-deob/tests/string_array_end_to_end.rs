#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{StringArrayRecovery, recover_string_array};

#[test]
fn recovers_basic_string_array_fixture() {
    let source: &str = include_str!("../../../corpus/src/javascript/string-array-basic.js");
    let recovery: StringArrayRecovery = recover_string_array(source)
        .expect("recovery should not error")
        .expect("recovery should find string array");

    assert_eq!(recovery.array_id, "_0xabcd");
    assert_eq!(recovery.original_strings, vec!["log", "Hello", "world"]);
    assert!(recovery.rotator_removed, "rotator IIFE must be removed");
    assert!(
        !recovery
            .rewritten_source
            .contains("push(_0x1234[\"shift\"])"),
        "rewritten source should not contain rotator artifacts"
    );
}

#[test]
fn returns_none_on_clean_js() {
    let source: &str = "const x = 1; console.log(x);";
    assert!(recover_string_array(source).expect("ok").is_none());
}
