use std::time::Duration;

use disrobe_pass_lua::{render_lua_decompiled_with_header, render_lua_deobfuscated_with_header};

#[test]
fn lua_decompiled_emits_two_line_lua_header() {
    let out: String =
        render_lua_decompiled_with_header("print(1)\n", Duration::from_millis(30), "5.4");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("-- Decompiled in 30ms with Disrobe"));
    assert_eq!(lines[1], "-- Lua 5.4");
}

#[test]
fn lua_deobfuscated_emits_two_line_lua_header() {
    let out: String =
        render_lua_deobfuscated_with_header("print(1)\n", Duration::from_millis(40), "5.1");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("-- Deobfuscated in 40ms with Disrobe"));
    assert_eq!(lines[1], "-- Lua 5.1");
}
