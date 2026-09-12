use std::time::Duration;

use disrobe_pass_jvm::{render_java_with_header, render_smali_with_header};

#[test]
fn smali_emits_two_line_smali_header() {
    let out: String = render_smali_with_header(".class\n", Duration::from_millis(70), "JVM 21");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Disassembled in 70ms with Disrobe"));
    assert_eq!(lines[1], "// Smali JVM 21");
}

#[test]
fn java_emits_two_line_java_header() {
    let out: String = render_java_with_header("class C{}\n", Duration::from_millis(900), "21");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Decompiled in 900ms with Disrobe"));
    assert_eq!(lines[1], "// Java 21");
}
