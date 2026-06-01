use std::time::Duration;

use disrobe_pass_pyarmor::render_disasm_with_header;

#[test]
fn pyarmor_disasm_emits_two_line_python_header() {
    let body: &str = "LOAD_CONST 0\n";
    let out: String = render_disasm_with_header(body, Duration::from_millis(1200), "3.13");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Disassembled in 1.2s with Disrobe"));
    assert_eq!(lines[1], "# Python 3.13");
    assert!(out.ends_with(body));
}
