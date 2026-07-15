#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::decompile::decompile_auto;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant, LuaProto};
use disrobe_pass_lua::reader::read_auto;

static SEQ: AtomicU64 = AtomicU64::new(0);

const TRICKY_SOURCE: &str = r#"local t = {
  "\0005", "\0012", "\0275",
  "x\0y", "\27done", "tab\ttab",
  "cr\rlf\nend", "q\"q", "b\\s",
  "plain hello", "\1\2\3",
}
return t
"#;

fn luac_51_candidates() -> Vec<String> {
    let mut v: Vec<String> = vec![
        "C:/Program Files (x86)/Lua/5.1/luac.exe".to_owned(),
        "C:/Program Files/Lua/5.1/luac.exe".to_owned(),
        "luac5.1".to_owned(),
    ];
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        v.push(format!("{home}/Programs/Lua/5.1/luac.exe"));
    }
    v
}

fn luac_54_candidates() -> Vec<String> {
    let mut v: Vec<String> = vec![
        "C:/Program Files/Lua/5.4/luac.exe".to_owned(),
        "luac5.4".to_owned(),
        "luac".to_owned(),
    ];
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        v.push(format!("{home}/Programs/Lua/bin/luac.exe"));
    }
    v
}

fn find_luac(candidates: &[String]) -> Option<String> {
    for c in candidates {
        if c.contains('/') || c.contains('\\') {
            if Path::new(c).exists() {
                return Some(c.clone());
            }
        } else if Command::new(c).arg("-v").output().is_ok() {
            return Some(c.clone());
        }
    }
    None
}

fn scratch_dir(tag: &str) -> PathBuf {
    let seq: u64 = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_lua_string_escape-{tag}-{}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn compile(luac: &str, src: &Path, out: &Path) -> bool {
    Command::new(luac)
        .arg("-o")
        .arg(out)
        .arg(src)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success())
}

fn collect_strings(p: &LuaProto, acc: &mut Vec<Vec<u8>>) {
    for c in &p.constants {
        if let LuaConstant::Str(s) = c {
            acc.push(s.clone().into_bytes());
        }
    }
    for child in &p.protos {
        collect_strings(child, acc);
    }
}

fn strings_of(bytes: &[u8]) -> Vec<Vec<u8>> {
    let chunk: LuaChunk = read_auto(bytes).expect("parse chunk");
    let mut acc: Vec<Vec<u8>> = Vec::new();
    collect_strings(&chunk.main, &mut acc);
    acc.sort();
    acc
}

fn strip_main_wrapper(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start: usize = lines
        .iter()
        .position(|l: &&str| l.trim_start().starts_with("function _main"))
        .map_or(0, |i: usize| i + 1);
    let end: usize = lines
        .iter()
        .rposition(|l: &&str| l.trim() == "end")
        .unwrap_or(lines.len());
    if start >= end {
        return source.to_owned();
    }
    lines[start..end].join("\n")
}

fn assert_string_constants_survive(luac: &str, tag: &str) {
    let dir: PathBuf = scratch_dir(tag);
    let src: PathBuf = dir.join("orig.lua");
    std::fs::write(&src, TRICKY_SOURCE).expect("write source");
    let original: PathBuf = dir.join("orig.luac");
    assert!(
        compile(luac, &src, &original),
        "luac ({tag}) compiles fixture"
    );
    let orig_bytes: Vec<u8> = std::fs::read(&original).expect("read original");

    let orig_strings: Vec<Vec<u8>> = strings_of(&orig_bytes);
    let nul_then_digit: Vec<u8> = vec![0x00, 0x35];
    let ctrl_then_digit: Vec<u8> = vec![0x1B, 0x35];
    assert!(
        orig_strings.contains(&nul_then_digit),
        "fixture must produce a NUL-then-digit constant ({tag}); got {orig_strings:?}"
    );
    assert!(
        orig_strings.contains(&ctrl_then_digit),
        "fixture must produce a control-then-digit constant ({tag}); got {orig_strings:?}"
    );

    let decompiled = decompile_auto(&orig_bytes).expect("decompile");
    let body: String = strip_main_wrapper(&decompiled.source);
    let body_src: PathBuf = dir.join("recovered.lua");
    std::fs::write(&body_src, &body).expect("write recovered source");
    let recompiled: PathBuf = dir.join("recovered.luac");
    assert!(
        compile(luac, &body_src, &recompiled),
        "disrobe output ({tag}) must recompile; source was:\n{body}"
    );
    let re_bytes: Vec<u8> = std::fs::read(&recompiled).expect("read recompiled");
    let re_strings: Vec<Vec<u8>> = strings_of(&re_bytes);

    assert_eq!(
        orig_strings, re_strings,
        "string constant table must round-trip byte-identical ({tag})\nsource:\n{body}"
    );
}

#[test]
fn string_constants_round_trip_lua_5_1() {
    let Some(luac): Option<String> = find_luac(&luac_51_candidates()) else {
        eprintln!("skip: luac 5.1 not found on box");
        return;
    };
    assert_string_constants_survive(&luac, "5_1");
}

#[test]
fn string_constants_round_trip_lua_5_4() {
    let Some(luac): Option<String> = find_luac(&luac_54_candidates()) else {
        eprintln!("skip: luac 5.4 not found on box");
        return;
    };
    assert_string_constants_survive(&luac, "5_4");
}
