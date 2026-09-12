#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::decompile::decompile_auto;
use disrobe_pass_lua::decompile::opcode::{Decoded, Op, decode};
use disrobe_pass_lua::reader::common::{LuaChunk, LuaProto};
use disrobe_pass_lua::reader::read_auto;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

const FIXTURE: &str = "local function f()\n  local a = 2.0\n  local b = 1000000.0\n  local c = 3.5\n  local d = 7\n  return a, b, c, d\nend\nreturn f\n";

fn lua_bin(name: &str) -> Option<String> {
    let home: String = std::env::var("LOCALAPPDATA").ok()?;
    let p: String = format!("{home}/Programs/Lua/bin/{name}.exe");
    let alt: String = "C:/Program Files/Lua/5.4/luac.exe".to_owned();
    if Path::new(&p).exists() {
        Some(p)
    } else if Path::new(&alt).exists() && name == "luac" {
        Some(alt)
    } else if Command::new(name).arg("-v").output().is_ok() {
        Some(name.to_owned())
    } else {
        None
    }
}

fn scratch_dir() -> disrobe_core::scratch::ScratchDir {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_lua_float_type-{}-{seq}", std::process::id());
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

fn compile(luac: &str, src: &Path, out: &Path) -> bool {
    Command::new(luac)
        .arg("-o")
        .arg(out)
        .arg(src)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success())
}

fn opcode_multiset(p: &LuaProto, dialect: LuaDialect, acc: &mut Vec<String>) {
    for raw in &p.code {
        let d: Decoded = decode(*raw, dialect);
        if !matches!(
            d.op,
            Op::MmBin | Op::MmBinI | Op::MmBinK | Op::ExtraArg | Op::VarargPrep
        ) {
            acc.push(format!("{:?}", d.op));
        }
    }
    for c in &p.protos {
        opcode_multiset(c, dialect, acc);
    }
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

fn run_math_type(interp: &str, dir: &Path, chunk: &str) -> Option<String> {
    let runner: PathBuf = dir.join("mtype.lua");
    let full: String = format!(
        "local g = assert(load([==[\n{chunk}\n]==]))()\nlocal a, b, c, d = g()\nprint(math.type(a), math.type(b), math.type(c), math.type(d))\n"
    );
    std::fs::write(&runner, full).ok()?;
    let out = Command::new(interp).arg(&runner).output().ok()?;
    if !out.status.success() {
        eprintln!("lua run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .replace("\r\n", "\n")
            .trim()
            .to_owned(),
    )
}

#[test]
fn lua54_float_literals_keep_float_type_after_recovery() {
    let Some(luac): Option<String> = lua_bin("luac") else {
        eprintln!("skip: luac 5.4 not found on box");
        return;
    };
    let Some(interp): Option<String> = lua_bin("lua") else {
        eprintln!("skip: lua 5.4 interpreter not found on box");
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src: PathBuf = dir.join("f.lua");
    std::fs::write(&src, FIXTURE).expect("write fixture");
    let original: PathBuf = dir.join("f.luac");
    assert!(compile(&luac, &src, &original), "luac must compile fixture");
    let bytes: Vec<u8> = std::fs::read(&original).expect("read original luac");

    let decompiled = decompile_auto(&bytes).expect("decompile must succeed");
    let body: String = strip_main_wrapper(&decompiled.source);

    let body_src: PathBuf = dir.join("f.re.lua");
    std::fs::write(&body_src, &body).expect("write recompile source");
    let recompiled: PathBuf = dir.join("f.re.luac");
    assert!(
        compile(&luac, &body_src, &recompiled),
        "disrobe output must recompile, source was:\n{body}"
    );
    let rebytes: Vec<u8> = std::fs::read(&recompiled).expect("read recompiled luac");

    let oc: LuaChunk = read_auto(&bytes).expect("parse original");
    let rc: LuaChunk = read_auto(&rebytes).expect("parse recompiled");
    let mut a: Vec<String> = Vec::new();
    let mut b: Vec<String> = Vec::new();
    opcode_multiset(&oc.main, oc.dialect, &mut a);
    opcode_multiset(&rc.main, rc.dialect, &mut b);
    a.sort();
    b.sort();
    assert_eq!(
        a, b,
        "recompiled opcode multiset must match original (LOADF must not degrade to LOADI)\noriginal={a:?}\nrecompiled={b:?}\nsource:\n{body}"
    );

    let expected: String =
        run_math_type(&interp, &dir, FIXTURE).expect("original fixture runs under lua");
    let actual: String =
        run_math_type(&interp, &dir, &body).expect("recovered source runs under lua");
    assert_eq!(
        actual, expected,
        "recovered floats must keep math.type == 'float' (integral floats must not become integers)\nsource:\n{body}"
    );
    assert_eq!(
        actual, "float\tfloat\tfloat\tinteger",
        "fixture types must be float/float/float/integer, got: {actual:?}\nsource:\n{body}"
    );
}
