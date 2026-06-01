#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::uninlined_format_args
)]

use disrobe_pass_js_deob::{PresetEnvUndoResult, undo_preset_env};

#[test]
fn restores_spread_from_to_consumable_array() {
    let src: &str = "var combined = [].concat(_toConsumableArray(list), [42]);";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert!(r.spreads_restored >= 1);
    assert!(r.rewritten.contains("...list"));
}

#[test]
fn drops_class_call_check() {
    let src: &str = "function Cat() { _classCallCheck(this, Cat); this.name = 'mu'; }";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert!(!r.rewritten.contains("_classCallCheck"));
    assert!(r.classes_restored >= 1);
}

#[test]
fn rewrites_async_to_generator() {
    let src: &str = "var fetch = _asyncToGenerator(function* () { yield 1; });";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert!(r.async_restored >= 1);
    assert!(r.rewritten.contains("async function()"));
}

#[test]
fn rewrites_optional_chain_polyfill() {
    let src: &str = "var v = (obj === null || obj === void 0) ? void 0 : obj.field;";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert!(r.optional_chains_restored >= 1, "{:?}", r);
    assert!(r.rewritten.contains("obj?.field"));
}

#[test]
fn rewrites_nullish_coalescing_polyfill() {
    let src: &str = "var x = (val !== null && val !== void 0 ? val : fallback);";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert!(r.nullish_coalesce_restored >= 1);
    assert!(r.rewritten.contains("val ?? fallback"));
}

#[test]
fn strips_helper_function_definitions() {
    let src: &str = "function _classCallCheck(a, b) { if (!(a instanceof b)) throw 1; } var z = 0;";
    let r: PresetEnvUndoResult = undo_preset_env(src);
    assert_eq!(r.helpers_removed.get("_classCallCheck"), Some(&1));
    assert!(!r.rewritten.contains("function _classCallCheck"));
}
