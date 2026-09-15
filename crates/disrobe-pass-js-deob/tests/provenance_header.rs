use std::time::Duration;

use disrobe_pass_js_deob::{render_js_deobfuscated_with_header, render_v8_disasm_with_header};

#[test]
fn js_deob_emits_two_line_js_header() {
    let out: String =
        render_js_deobfuscated_with_header("x = 1;\n", Duration::from_millis(340), "ES2024");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Deobfuscated in 340ms with Disrobe"));
    assert_eq!(lines[1], "// JavaScript ES2024");
}

#[test]
fn v8_disasm_emits_two_line_v8_header() {
    let out: String = render_v8_disasm_with_header("Ldar\n", Duration::from_millis(8), "12.0");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Disassembled in 8ms with Disrobe"));
    assert_eq!(lines[1], "// V8 Bytecode 12.0");
}
