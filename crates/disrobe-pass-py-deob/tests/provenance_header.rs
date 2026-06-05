use std::time::Duration;

use disrobe_pass_py_deob::render_deobfuscated_with_header;

#[test]
fn py_deob_emits_two_line_python_header() {
    let out: String = render_deobfuscated_with_header("x = 1\n", Duration::from_millis(75), "3.13");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Deobfuscated in 75ms with Disrobe"));
    assert_eq!(lines[1], "# Python 3.13");
}
