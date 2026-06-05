use std::time::Duration;

use disrobe_pass_native::{render_c_with_header, render_cpp_with_header, render_rust_with_header};

#[test]
fn rust_recovery_emits_two_line_rust_header() {
    let out: String =
        render_rust_with_header("fn x(){}\n", Duration::from_millis(10), "edition 2024");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Lifted in 10ms with Disrobe"));
    assert_eq!(lines[1], "// Rust edition 2024");
}

#[test]
fn c_recovery_emits_two_line_c_header() {
    let out: String = render_c_with_header("int main(){}\n", Duration::from_millis(5), "C11");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Lifted in 5ms with Disrobe"));
    assert_eq!(lines[1], "// C C11");
}

#[test]
fn cpp_recovery_emits_two_line_cpp_header() {
    let out: String = render_cpp_with_header("int main(){}\n", Duration::from_millis(7), "C++20");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Lifted in 7ms with Disrobe"));
    assert_eq!(lines[1], "// C++ C++20");
}
