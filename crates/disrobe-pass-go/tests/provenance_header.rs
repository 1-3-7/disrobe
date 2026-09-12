use std::time::Duration;

use disrobe_pass_go::render_go_decompiled_with_header;

#[test]
fn go_decompiled_emits_two_line_go_header() {
    let out: String =
        render_go_decompiled_with_header("package main\n", Duration::from_millis(330), "1.22");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Decompiled in 330ms with Disrobe"));
    assert_eq!(lines[1], "// Go 1.22");
}
