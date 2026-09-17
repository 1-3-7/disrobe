use std::time::Duration;

use disrobe_pass_beam::{
    render_core_erlang_with_header, render_elixir_with_header, render_erlang_with_header,
};

#[test]
fn core_erlang_emits_two_line_percent_header() {
    let out: String = render_core_erlang_with_header("module x\n", Duration::from_millis(15), "27");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("% Lifted in 15ms with Disrobe"));
    assert_eq!(lines[1], "% Core Erlang 27");
}

#[test]
fn erlang_emits_two_line_percent_header() {
    let out: String = render_erlang_with_header("-module(x).\n", Duration::from_millis(11), "26");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("% Decompiled in 11ms with Disrobe"));
    assert_eq!(lines[1], "% Erlang 26");
}

#[test]
fn elixir_emits_two_line_hash_header() {
    let out: String =
        render_elixir_with_header("defmodule X do\nend\n", Duration::from_millis(20), "1.17");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Decompiled in 20ms with Disrobe"));
    assert_eq!(lines[1], "# Elixir 1.17");
}
