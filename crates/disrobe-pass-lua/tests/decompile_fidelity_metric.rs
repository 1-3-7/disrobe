#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::decompile::{self, DecompiledChunk};
use disrobe_pass_lua::reader::common::{LuaChunk, LuaProto};
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
    fs::read(&path).unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", path.display()))
}

fn collect_debug_local_names(p: &LuaProto, out: &mut BTreeSet<String>) {
    for loc in &p.locals {
        let n: &str = loc.name.as_str();
        if !n.is_empty() && n != "(for index)" && !n.starts_with('(') {
            out.insert(n.to_owned());
        }
    }
    for child in &p.protos {
        collect_debug_local_names(child, out);
    }
}

fn placeholder_register_count(src: &str) -> usize {
    let mut n: usize = 0;
    let bytes: &[u8] = src.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'R' {
            let prev_ok: bool =
                i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
            let mut j: usize = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if prev_ok && j > i + 1 {
                n += 1;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    n
}

fn measure(rel: &str, chunk: LuaChunk) {
    let mut declared: BTreeSet<String> = BTreeSet::new();
    collect_debug_local_names(&chunk.main, &mut declared);
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile");
    let recovered: usize = declared
        .iter()
        .filter(|name: &&String| {
            let pat: String = format!(" {name} ");
            out.source.contains(name.as_str())
                && (out.source.contains(&pat)
                    || out.source.contains(&format!("local {name}"))
                    || out.source.contains(&format!("{name} =")))
        })
        .count();
    let total: usize = declared.len();
    let pct: f64 = if total == 0 {
        0.0
    } else {
        100.0 * recovered as f64 / total as f64
    };
    let placeholders: usize = placeholder_register_count(&out.source);
    eprintln!(
        "[fidelity] {rel}: debug-locals {recovered}/{total} ({pct:.1}%) named; residual R<n> placeholders={placeholders}; out_bytes={}",
        out.source.len()
    );
}

fn strip_debug(p: &mut LuaProto) {
    p.locals.clear();
    p.source_lines.clear();
    for u in &mut p.upvalues {
        u.name.clear();
    }
    for child in &mut p.protos {
        strip_debug(child);
    }
}

fn measure_stripped(rel: &str, mut chunk: LuaChunk) {
    strip_debug(&mut chunk.main);
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile");
    let placeholders: usize = placeholder_register_count(&out.source);
    let synthetic_locals: usize = out.source.matches("loc_").count();
    eprintln!(
        "[fidelity-nodebug] {rel}: residual R<n> placeholders={placeholders}; synthetic loc_ names={synthetic_locals}; out_bytes={}",
        out.source.len()
    );
}

#[test]
fn report_local_name_recovery() {
    let b: Vec<u8> = load("luac/edge_cases.5_1.luac");
    measure("5.1", lua51::read(&b).expect("5.1"));
    measure_stripped("5.1", lua51::read(&b).expect("5.1"));
    let b: Vec<u8> = load("luac/edge_cases.5_2.luac");
    measure("5.2", lua52::read(&b).expect("5.2"));
    let b: Vec<u8> = load("luac/edge_cases.5_3.luac");
    measure("5.3", lua53::read(&b).expect("5.3"));
    let b: Vec<u8> = load("luac/edge_cases.5_4.luac");
    measure("5.4", lua54::read(&b).expect("5.4"));
}
