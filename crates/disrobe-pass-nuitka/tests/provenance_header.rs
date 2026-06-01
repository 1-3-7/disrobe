use std::time::Duration;

use disrobe_pass_nuitka::render_c_disasm_with_header;

#[test]
fn nuitka_c_disasm_emits_two_line_c_header() {
    let out: String =
        render_c_disasm_with_header("// asm\n", Duration::from_millis(900), "Nuitka 2.4");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Disassembled in 900ms with Disrobe"));
    assert_eq!(lines[1], "// C Nuitka 2.4");
}
