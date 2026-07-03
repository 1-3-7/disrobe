use std::time::Duration;

use disrobe_pass_dotnet::{render_cil_with_header, render_csharp_with_header};

#[test]
fn cil_emits_two_line_cil_header() {
    let out: String = render_cil_with_header(".method\n", Duration::from_millis(20), "ECMA-335");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Disassembled in 20ms with Disrobe"));
    assert_eq!(lines[1], "// CIL ECMA-335");
}

#[test]
fn csharp_emits_two_line_csharp_header() {
    let out: String = render_csharp_with_header("class C{}\n", Duration::from_millis(45), "12");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Decompiled in 45ms with Disrobe"));
    assert_eq!(lines[1], "// C# 12");
}
