#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::decompile::{self, DecompiledChunk, Fidelity};
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::lua51;

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

#[test]
fn lua51_hello_decompile_produces_function_skeleton() {
    let bytes: Vec<u8> = load("luac/hello.5_1.luac");
    let chunk: LuaChunk = lua51::read(&bytes).expect("parse 5.1 hello");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.1 hello");
    assert!(matches!(
        out.fidelity,
        Fidelity::Lossless | Fidelity::Lossy | Fidelity::BestEffort
    ));
    assert!(out.source.contains("function _main"));
    assert!(out.source.contains("end"));
}

#[test]
fn lua51_megafile_decompile_produces_many_functions() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_1.luac");
    let chunk: LuaChunk = lua51::read(&bytes).expect("parse 5.1 megafile");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.1 megafile");
    let fn_count: usize = out.source.matches("function").count();
    assert!(
        fn_count >= 2,
        "expected nested functions in lifted source, got {fn_count}"
    );
    assert!(out.source.contains("end"));
}

#[test]
fn lua51_megafile_decompile_lifts_real_calls() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_1.luac");
    let chunk: LuaChunk = lua51::read(&bytes).expect("parse 5.1 megafile");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile 5.1 megafile");
    let has_call: bool = out.source.contains('(') && out.source.contains(')');
    assert!(has_call, "lifted source should contain call/expr syntax");
    assert!(
        !out.source.contains("insn=0x"),
        "lifter must not fall back to raw hex dump"
    );
}
