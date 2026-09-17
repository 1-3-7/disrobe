use std::time::Duration;

use disrobe_pass_py_disasm::render_disasm_with_header;

#[test]
fn py_disasm_emits_two_line_python_header() {
    let out: String =
        render_disasm_with_header("LOAD_CONST 0\n", Duration::from_millis(11), "3.13");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Disassembled in 11ms with Disrobe"));
    assert_eq!(lines[1], "# Python 3.13");
}
