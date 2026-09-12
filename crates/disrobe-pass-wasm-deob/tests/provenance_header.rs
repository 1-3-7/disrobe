use std::time::Duration;

use disrobe_pass_wasm_deob::{
    render_c_lifted_with_header, render_rust_lifted_with_header, render_ts_lifted_with_header,
    render_wat_decompiled_with_header,
};

#[test]
fn wat_decompiled_emits_two_line_wat_header() {
    let out: String =
        render_wat_decompiled_with_header("(module)\n", Duration::from_millis(5100), "1.0");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with(";; Decompiled in 5.1s with Disrobe"));
    assert_eq!(lines[1], ";; WebAssembly 1.0");
}

#[test]
fn rust_lifted_emits_two_line_rust_header() {
    let out: String =
        render_rust_lifted_with_header("fn x(){}\n", Duration::from_millis(120), "edition 2024");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Lifted in 120ms with Disrobe"));
    assert_eq!(lines[1], "// Rust edition 2024");
}

#[test]
fn ts_lifted_emits_two_line_ts_header() {
    let out: String =
        render_ts_lifted_with_header("function f(){}\n", Duration::from_millis(30), "5.5");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Lifted in 30ms with Disrobe"));
    assert_eq!(lines[1], "// TypeScript 5.5");
}

#[test]
fn c_lifted_emits_two_line_c_header() {
    let out: String =
        render_c_lifted_with_header("int main(){}\n", Duration::from_millis(2), "C11");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Lifted in 2ms with Disrobe"));
    assert_eq!(lines[1], "// C C11");
}
