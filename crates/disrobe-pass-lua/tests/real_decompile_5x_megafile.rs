#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::decompile::{self, DecompiledChunk};
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{lua52, lua53, lua54};

fn corpus_path(rel: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn load(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(rel);
    fs::read(&path).unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", path.display()))
}

fn assert_no_failure_markers(src: &str) {
    assert!(
        !src.contains("unknown opcode"),
        "lifter emitted unknown-opcode marker:\n{src}"
    );
    assert!(
        !src.contains("insn=0x"),
        "lifter fell back to raw hex dump:\n{src}"
    );
    assert!(
        !src.contains("nesting limit reached"),
        "lifter blew the depth limit:\n{src}"
    );
    assert!(
        !src.contains("UNKNOWN"),
        "lifter emitted UNKNOWN mnemonic:\n{src}"
    );
}

#[test]
fn lua52_hello_round_trips_to_print_call() {
    let bytes: Vec<u8> = load("luac/hello.5_2.luac");
    let chunk: LuaChunk = lua52::read(&bytes).expect("parse 5.2 hello");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.2 hello");
    assert!(
        out.source.contains("print(\"hello world\")"),
        "expected print call recovery, got:\n{}",
        out.source
    );
    assert!(out.source.contains("function _main"));
    assert!(out.source.contains("(lua 5.2"));
    assert_no_failure_markers(&out.source);
}

#[test]
fn lua53_hello_round_trips_to_print_call() {
    let bytes: Vec<u8> = load("luac/hello.5_3.luac");
    let chunk: LuaChunk = lua53::read(&bytes).expect("parse 5.3 hello");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.3 hello");
    assert!(
        out.source.contains("print(\"hello world\")"),
        "expected print call recovery, got:\n{}",
        out.source
    );
    assert!(out.source.contains("(lua 5.3"));
    assert_no_failure_markers(&out.source);
}

#[test]
fn lua54_hello_round_trips_to_print_call() {
    let bytes: Vec<u8> = load("luac/hello.5_4.luac");
    let chunk: LuaChunk = lua54::read(&bytes).expect("parse 5.4 hello");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.4 hello");
    assert!(
        out.source.contains("print(\"hello world\")"),
        "expected print call recovery, got:\n{}",
        out.source
    );
    assert!(out.source.contains("(lua 5.4"));
    assert_no_failure_markers(&out.source);
}

#[test]
fn lua52_megafile_lifts_arithmetic_and_field_assignments() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_2.luac");
    let chunk: LuaChunk = lua52::read(&bytes).expect("parse 5.2 megafile");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.2 megafile");
    assert_no_failure_markers(&out.source);
    assert!(
        out.source.contains("tbl_") && out.source.contains("integer = 42"),
        "expected literal-table recovery"
    );
    assert!(
        out.source.contains("(a + b)"),
        "expected real arithmetic recovery with debug-named params"
    );
    assert!(
        out.source.contains("(a .. b)"),
        "expected real concat recovery with debug-named params"
    );
    assert!(
        out.source
            .lines()
            .any(|l: &str| l.contains("for ") && l.contains(" = ") && l.contains(" do")),
        "expected numeric for-loop recovery, got:\n{}",
        out.source
    );
    let fn_count: usize = out.source.matches("function").count();
    assert!(
        fn_count >= 30,
        "expected many nested functions in megafile, got {fn_count}"
    );
}

#[test]
fn lua53_megafile_lifts_bitwise_and_integer_constants() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_3.luac");
    let chunk: LuaChunk = lua53::read(&bytes).expect("parse 5.3 megafile");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.3 megafile");
    assert_no_failure_markers(&out.source);
    assert!(
        out.source.contains("integer = 42"),
        "expected real integer constant recovery in 5.3"
    );
    assert!(
        out.source.contains("(a / b)") && out.source.contains("(a % b)"),
        "expected real arithmetic in 5.3 megafile with debug-named params"
    );
    assert!(
        out.source.contains("(a .. b)"),
        "expected real concat in 5.3 megafile with debug-named params"
    );
    assert!(out.source.contains("string.format"));
}

#[test]
fn lua54_megafile_lifts_5_4_constructs_with_real_constants() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_4.luac");
    let chunk: LuaChunk = lua54::read(&bytes).expect("parse 5.4 megafile");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.4 megafile");
    assert_no_failure_markers(&out.source);
    assert!(
        out.source.contains("integer = 42"),
        "expected real integer 42 in 5.4 (reader bug fix)"
    );
    assert!(
        out.source.contains("float = 3.14"),
        "expected real float 3.14 in 5.4 (reader bug fix)"
    );
    assert!(
        out.source.contains("negative = -7"),
        "expected real negative integer in 5.4"
    );
    assert!(
        out.source
            .lines()
            .any(|l: &str| l.contains("for ") && l.contains(" = ") && l.contains(" do")),
        "expected 5.4 numeric for-loop recovery, got:\n{}",
        out.source
    );
    assert!(
        out.source.contains("fizzbuzz"),
        "expected 5.4 string-constant recovery (fizzbuzz)"
    );
    let any_huge_label: bool = out
        .source
        .lines()
        .filter(|l: &&str| l.contains("lbl_"))
        .any(|l: &str| {
            l.split("lbl_")
                .nth(1)
                .and_then(|rest: &str| {
                    rest.split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|n: &str| n.parse::<u32>().ok())
                })
                .is_some_and(|n: u32| n >= 1_000_000)
        });
    assert!(
        !any_huge_label,
        "5.4 sJ bias must decode to small in-function offsets, found a malformed huge label:\n{}",
        out.source
    );
    let structured: bool =
        out.source.contains("while ") || out.source.contains("for ") || out.source.contains("if ");
    assert!(
        structured,
        "expected structured control flow reconstruction in 5.4 megafile, got:\n{}",
        out.source
    );
}

#[test]
fn lua52_53_54_constants_are_faithful() {
    for rel in [
        "luac/edge_cases.5_2.luac",
        "luac/edge_cases.5_3.luac",
        "luac/edge_cases.5_4.luac",
    ] {
        let bytes: Vec<u8> = load(rel);
        let chunk: LuaChunk = match rel {
            r if r.ends_with("5_2.luac") => lua52::read(&bytes).expect("parse 52"),
            r if r.ends_with("5_3.luac") => lua53::read(&bytes).expect("parse 53"),
            _ => lua54::read(&bytes).expect("parse 54"),
        };
        let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile megafile");
        assert!(
            out.source.contains("\"alpha\"") && out.source.contains("\"omega\""),
            "{rel} must preserve real string constants"
        );
        assert!(
            out.source.contains("setmetatable"),
            "{rel} must recover setmetatable global call"
        );
    }
}
