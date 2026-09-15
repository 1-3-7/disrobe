use std::time::Duration;

use disrobe_pass_mobile::{
    render_dart_with_header, render_hermes_disasm_with_header, render_hermes_lifted_with_header,
    render_rn_bundle_with_header,
};

#[test]
fn hermes_disasm_emits_two_line_hermes_header() {
    let out: String = render_hermes_disasm_with_header(".hbc\n", Duration::from_millis(50), "0.12");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Disassembled in 50ms with Disrobe"));
    assert_eq!(lines[1], "// Hermes 0.12");
}

#[test]
fn hermes_lifted_emits_two_line_js_header() {
    let out: String =
        render_hermes_lifted_with_header("function f(){}\n", Duration::from_millis(200), "ES2024");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Lifted in 200ms with Disrobe"));
    assert_eq!(lines[1], "// JavaScript ES2024");
}

#[test]
fn dart_emits_two_line_dart_header() {
    let out: String = render_dart_with_header("void main(){}\n", Duration::from_millis(120), "3.4");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Decompiled in 120ms with Disrobe"));
    assert_eq!(lines[1], "// Dart 3.4");
}

#[test]
fn rn_bundle_emits_two_line_js_header() {
    let out: String =
        render_rn_bundle_with_header("var x = 1;\n", Duration::from_millis(15), "0.74");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Extracted in 15ms with Disrobe"));
    assert_eq!(lines[1], "// JavaScript 0.74");
}
