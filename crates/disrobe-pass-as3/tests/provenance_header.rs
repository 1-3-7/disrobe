use std::time::Duration;

use disrobe_pass_as3::render_as3_with_header;

#[test]
fn as3_emits_two_line_as3_header() {
    let out: String = render_as3_with_header("package x{}\n", Duration::from_millis(70), "3.0");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Decompiled in 70ms with Disrobe"));
    assert_eq!(lines[1], "// ActionScript 3.0");
}
