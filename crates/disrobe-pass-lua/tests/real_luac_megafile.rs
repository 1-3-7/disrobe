#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant};
use disrobe_pass_lua::reader::{lua51, lua52, lua53, lua54};

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
    fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("failed to read corpus fixture {}: {e}", path.display())
    })
}

fn count_protos(p: &disrobe_pass_lua::reader::common::LuaProto) -> usize {
    let mut n: usize = 1;
    for child in &p.protos {
        n += count_protos(child);
    }
    n
}

fn collect_constants(p: &disrobe_pass_lua::reader::common::LuaProto, out: &mut Vec<LuaConstant>) {
    for c in &p.constants {
        out.push(c.clone());
    }
    for child in &p.protos {
        collect_constants(child, out);
    }
}

#[test]
fn megafile_5_1_proto_tree_is_deep() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_1.luac");
    let chunk: LuaChunk = lua51::read(&bytes).expect("parse 5.1 megafile");
    let total: usize = count_protos(&chunk.main);
    assert!(total > 50, "expected >50 proto nodes, got {total}");
}

#[test]
fn megafile_5_2_proto_tree_is_deep() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_2.luac");
    let chunk: LuaChunk = lua52::read(&bytes).expect("parse 5.2 megafile");
    let total: usize = count_protos(&chunk.main);
    assert!(total > 50, "expected >50 proto nodes, got {total}");
}

#[test]
fn megafile_5_3_proto_tree_is_deep() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_3.luac");
    let chunk: LuaChunk = lua53::read(&bytes).expect("parse 5.3 megafile");
    let total: usize = count_protos(&chunk.main);
    assert!(total > 50, "expected >50 proto nodes, got {total}");
}

#[test]
fn megafile_5_4_proto_tree_is_deep() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_4.luac");
    let chunk: LuaChunk = lua54::read(&bytes).expect("parse 5.4 megafile");
    let total: usize = count_protos(&chunk.main);
    assert!(total > 50, "expected >50 proto nodes, got {total}");
}

#[test]
fn megafile_5_4_contains_expected_string_literals() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_4.luac");
    let chunk: LuaChunk = lua54::read(&bytes).expect("parse 5.4 megafile");
    let mut consts: Vec<LuaConstant> = Vec::new();
    collect_constants(&chunk.main, &mut consts);
    let has_loaded: bool = consts.iter().any(|c: &LuaConstant| match c {
        LuaConstant::Str(s) => s == "edge_cases loaded",
        _ => false,
    });
    assert!(
        has_loaded,
        "expected 'edge_cases loaded' literal in 5.4 megafile"
    );
}

#[test]
fn megafile_5_1_contains_expected_string_literals() {
    let bytes: Vec<u8> = load("luac/edge_cases.5_1.luac");
    let chunk: LuaChunk = lua51::read(&bytes).expect("parse 5.1 megafile");
    let mut consts: Vec<LuaConstant> = Vec::new();
    collect_constants(&chunk.main, &mut consts);
    let has_loaded: bool = consts.iter().any(|c: &LuaConstant| match c {
        LuaConstant::Str(s) => s == "edge_cases loaded",
        _ => false,
    });
    assert!(
        has_loaded,
        "expected 'edge_cases loaded' literal in 5.1 megafile"
    );
}
