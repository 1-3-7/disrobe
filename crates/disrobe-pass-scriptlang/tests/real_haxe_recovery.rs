#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::haxe::{HaxeFingerprint, HaxeTarget, detect};

const HAXE_JS: &[u8] = include_bytes!("fixtures/haxe_calc.js");
const HAXE_HL: &[u8] = include_bytes!("fixtures/haxe_calc.hl");
const HAXE_NEKO: &[u8] = include_bytes!("fixtures/haxe_calc.n");
const HAXE_SRC: &str = include_str!("fixtures/HaxeCalc.hx");

fn fp(bytes: &[u8]) -> HaxeFingerprint {
    detect(bytes).expect("real haxe target must be detected")
}

#[test]
fn source_fixture_sanity() {
    assert!(HAXE_SRC.contains("class Calculator"));
    assert!(HAXE_SRC.contains("class Main"));
    assert!(HAXE_SRC.contains("function add"));
    assert!(HAXE_SRC.contains("function describe"));
}

#[test]
fn js_target_lifts_classes_and_methods() {
    let f: HaxeFingerprint = fp(HAXE_JS);
    assert_eq!(f.target, HaxeTarget::JavaScript);
    assert_eq!(f.compiler_version.as_deref(), Some("4.3.7"));
    for class in ["Calculator", "Main"] {
        assert!(HAXE_SRC.contains(&format!("class {class}")));
        assert!(
            f.recovered.classes.iter().any(|c: &String| c == class),
            "JS lift must recover class '{class}': {:?}",
            f.recovered.classes
        );
    }
    for method in ["add", "describe", "main"] {
        assert!(
            f.recovered.methods.iter().any(|m: &String| m == method),
            "JS lift must recover method '{method}': {:?}",
            f.recovered.methods
        );
    }
}

#[test]
fn js_target_recovers_source_position_markers() {
    let f: HaxeFingerprint = fp(HAXE_JS);
    assert!(
        f.recovered
            .source_files
            .iter()
            .any(|s: &String| s == "Main.hx"),
        "trace() compiles to console.log with Main.hx:line markers: {:?}",
        f.recovered.source_files
    );
}

#[test]
fn js_target_recovers_string_literals() {
    let f: HaxeFingerprint = fp(HAXE_JS);
    assert!(HAXE_SRC.contains("\"disrobe-demo\""));
    assert!(
        f.recovered
            .string_literals
            .iter()
            .any(|s: &String| s == "disrobe-demo"),
        "string literal from source must be recovered: {:?}",
        f.recovered.string_literals
    );
}

#[test]
fn hashlink_target_lifts_names_from_string_table() {
    let f: HaxeFingerprint = fp(HAXE_HL);
    assert_eq!(f.target, HaxeTarget::HashLink);
    assert!(f.hl_version.is_some());
    assert!(
        f.recovered
            .classes
            .iter()
            .any(|c: &String| c == "Calculator"),
        "HL string table retains the Calculator class name: {:?}",
        f.recovered.classes
    );
    assert!(
        f.recovered.methods.iter().any(|m: &String| m == "describe"),
        "HL retains the describe method name: {:?}",
        f.recovered.methods
    );
    assert!(
        f.recovered
            .source_files
            .iter()
            .any(|s: &String| s == "Main.hx"),
        "HL embeds the Main.hx source filename: {:?}",
        f.recovered.source_files
    );
    assert!(
        f.recovered
            .std_modules
            .iter()
            .any(|m: &String| m.contains("Std") || m.contains("String")),
        "HL retains std module .hx paths: {:?}",
        f.recovered.std_modules
    );
}

#[test]
fn neko_target_is_detected_and_lifted() {
    let f: HaxeFingerprint = fp(HAXE_NEKO);
    assert_eq!(
        f.target,
        HaxeTarget::Neko,
        "NEKO-magic Haxe output must be recognized as the neko target"
    );
    assert_eq!(f.route_pass_id, "scriptlang.classify");
    assert!(
        f.recovered
            .classes
            .iter()
            .any(|c: &String| c == "Calculator"),
        "neko bytecode retains the Calculator name: {:?}",
        f.recovered.classes
    );
    assert!(
        f.recovered.methods.iter().any(|m: &String| m == "describe"),
        "neko retains method names: {:?}",
        f.recovered.methods
    );
    assert!(f.haxe_confirmed, "Main.hx marker confirms haxe origin");
}

#[test]
fn recovery_symbol_count_is_nonzero_for_real_targets() {
    for bytes in [HAXE_JS, HAXE_HL, HAXE_NEKO] {
        let f: HaxeFingerprint = fp(bytes);
        assert!(
            f.recovered.symbol_count() >= 3,
            "every real haxe target retains at least the user classes+methods: {} for {:?}",
            f.recovered.symbol_count(),
            f.target
        );
    }
}
