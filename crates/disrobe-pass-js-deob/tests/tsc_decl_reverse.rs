#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{DtsReverseResult, reverse_declarations};

#[test]
fn maps_dts_function_to_js_impl() {
    let dts: &str = "declare function add(a: number, b: number): number;";
    let js: &str = "function add(a, b) { return a + b; }";
    let res: DtsReverseResult = reverse_declarations(dts, js);
    assert_eq!(res.stats.symbols_matched_via_corpus, 1);
    assert!(res.mapped_symbols.contains_key("add"));
    assert!(res.emitted_ts.contains("FUNCTION add"));
}

#[test]
fn maps_dts_const_to_js_const() {
    let dts: &str = "declare const VERSION: string;";
    let js: &str = "const VERSION = '1.0.0';";
    let res: DtsReverseResult = reverse_declarations(dts, js);
    assert!(res.mapped_symbols.contains_key("VERSION"));
}

#[test]
fn missing_in_js_marked_unknown() {
    let dts: &str = "declare function noImpl(): void;\ndeclare function hasImpl(): void;";
    let js: &str = "function hasImpl() {}";
    let res: DtsReverseResult = reverse_declarations(dts, js);
    assert_eq!(res.stats.unknown_symbols, 1);
    assert_eq!(res.stats.symbols_matched_via_corpus, 1);
}

#[test]
fn handles_class_declarations() {
    let dts: &str = "declare class Service { run(): void; }";
    let js: &str = "class Service { run() { return 1; } }";
    let res: DtsReverseResult = reverse_declarations(dts, js);
    assert!(res.declared_symbols.contains_key("Service"));
    assert!(res.mapped_symbols.contains_key("Service"));
}
