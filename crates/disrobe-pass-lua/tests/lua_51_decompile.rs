#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_lua::decompile::{self, DecompiledChunk, Fidelity};
use disrobe_pass_lua::reader::{common::LuaChunk, lua51};

fn corpus_path(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("lua");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

#[test]
fn lua51_decompile_real_hello_lifts_print_call() {
    let path: PathBuf = corpus_path("luac/hello.5_1.luac");
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("hello.5_1.luac fixture must be tracked: {e}"));
    let chunk: LuaChunk = lua51::read(&bytes).expect("parse real luac");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile");
    assert_eq!(out.fidelity, Fidelity::Lossless);
    assert!(out.source.contains("function _main"));
    assert!(
        out.source.contains("print(\"hello world\")"),
        "expected real lifted call print(\"hello world\") from hello.5_1.luac, got:\n{}",
        out.source
    );
}
