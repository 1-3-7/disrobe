use std::time::Duration;

use disrobe_pass_ruby::{render_ruby_with_header, render_yarv_with_header};

#[test]
fn yarv_emits_two_line_ruby_header() {
    let out: String = render_yarv_with_header("trace\n", Duration::from_millis(15), "3.3");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Disassembled in 15ms with Disrobe"));
    assert_eq!(lines[1], "# Ruby 3.3");
}

#[test]
fn ruby_decompile_emits_two_line_ruby_header() {
    let out: String = render_ruby_with_header("def x; end\n", Duration::from_millis(80), "3.3");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Decompiled in 80ms with Disrobe"));
    assert_eq!(lines[1], "# Ruby 3.3");
}
