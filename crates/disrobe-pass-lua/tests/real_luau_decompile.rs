#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::DecompiledChunk;
use disrobe_pass_lua::decompile::decompile_chunk;
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::luau;

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

fn count_children(p: &disrobe_pass_lua::reader::common::LuaProto) -> usize {
    let mut total: usize = p.protos.len();
    for child in &p.protos {
        total += count_children(child);
    }
    total
}

#[test]
fn real_luau_megafile_child_protos_are_linked() {
    let bytes: Vec<u8> = load("luau/edge_cases.luau.bin");
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau megafile");
    let nested: usize = count_children(&chunk.main);
    assert!(
        nested > 0,
        "expected linked child protos in megafile, found {nested}"
    );
}

#[test]
fn real_luau_megafile_decompiles_with_low_unknown_rate() {
    let bytes: Vec<u8> = load("luau/edge_cases.luau.bin");
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau megafile");
    let dc: DecompiledChunk = decompile_chunk(&chunk).expect("decompile luau megafile");
    let mut distinct_unknown: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for l in dc.source.lines() {
        if let Some(idx) = l.find("unknown luau op ") {
            let num: String = l[idx + 16..]
                .chars()
                .take_while(|c: &char| c.is_ascii_digit())
                .collect();
            distinct_unknown.insert(num);
        }
    }
    let placeholders: usize = dc.source.matches("placeholder").count();
    assert!(
        distinct_unknown.len() <= 1 && distinct_unknown.iter().all(|n: &String| n == "87"),
        "luau decompile emitted unexpected unknown ops {distinct_unknown:?}; \
         only the non-standard edge-case op 0x57 (87) is tolerated, any other \
         unknown indicates aux-word misalignment regression"
    );
    assert_eq!(
        placeholders, 0,
        "luau decompile emitted {placeholders} child-proto placeholders"
    );
}

#[test]
fn real_luau_hello_decompiles_with_print() {
    let bytes: Vec<u8> = load("luau/hello.luau");
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau hello");
    let dc: DecompiledChunk = decompile_chunk(&chunk).expect("decompile luau hello");
    assert!(
        dc.source.contains("print"),
        "expected print call in decompiled hello.luau:\n{}",
        dc.source
    );
}

fn op_histogram(
    p: &disrobe_pass_lua::reader::common::LuaProto,
    h: &mut std::collections::BTreeMap<u8, usize>,
) {
    let code: &[u32] = &p.code;
    let mut pc: usize = 0;
    while pc < code.len() {
        let op: u8 = (code[pc] & 0xFF) as u8;
        *h.entry(op).or_default() += 1;
        pc += disrobe_pass_lua::decompile::luau_lift::test_op_length(op);
    }
    for c in &p.protos {
        op_histogram(c, h);
    }
}

#[test]
fn real_luau_megafile_instruction_stream_stays_aligned() {
    let bytes: Vec<u8> = load("luau/edge_cases.luau.bin");
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau megafile");
    let mut hist: std::collections::BTreeMap<u8, usize> = std::collections::BTreeMap::new();
    op_histogram(&chunk.main, &mut hist);
    let nonstandard: Vec<u8> = hist
        .keys()
        .copied()
        .filter(|op: &u8| *op > 82 && *op != 87)
        .collect();
    assert!(
        nonstandard.is_empty(),
        "aux-aware pc walk desynced: saw out-of-range ops {nonstandard:?} \
         (standard luau ops are 0..=82, edge-case 0x57 is the sole tolerated extra)"
    );
}
