#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::decompile::decompile_auto;
use disrobe_pass_lua::decompile::opcode::{Decoded, Op, decode};
use disrobe_pass_lua::reader::common::{LuaChunk, LuaProto};
use disrobe_pass_lua::reader::read_auto;

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

fn src_path(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("oracle_src");
    p.push(format!("{name}.lua"));
    p
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

fn assert_recompile_equivalent(luac: &str, name: &str, dialect_tag: &str) {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_lua_recompile_oracle-{}-{seq}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let original: PathBuf = dir.join(format!("{name}.{dialect_tag}.luac"));
    let src: PathBuf = src_path(name);
    assert!(
        compile(luac, &src, &original),
        "luac must compile fixture {name}"
    );
    let bytes: Vec<u8> = std::fs::read(&original).expect("read original luac");

    let decompiled = decompile_auto(&bytes).expect("decompile must succeed");
    let body: String = strip_main_wrapper(&decompiled.source);
    let recompiled_path: PathBuf = dir.join(format!("{name}.{dialect_tag}.re.luac"));
    let body_src: PathBuf = dir.join(format!("{name}.{dialect_tag}.re.lua"));
    std::fs::write(&body_src, &body).expect("write recompile source");
    assert!(
        compile(luac, &body_src, &recompiled_path),
        "disrobe output for {name} ({dialect_tag}) must recompile, source was:\n{body}"
    );
    let rebytes: Vec<u8> = std::fs::read(&recompiled_path).expect("read recompiled luac");

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
        "recompiled bytecode opcode multiset must match original for {name} ({dialect_tag})\noriginal={a:?}\nrecompiled={b:?}\nsource:\n{body}"
    );
}

const FIXTURES: [&str; 6] = ["ifelse", "loops", "tables", "nested", "logic", "ctor"];

#[test]
fn recompile_equivalence_lua_5_1() {
    let Some(luac): Option<String> = find_luac(&luac_51_candidates()) else {
        eprintln!("skip: luac 5.1 not found on box");
        return;
    };
    for name in FIXTURES {
        assert_recompile_equivalent(&luac, name, "5_1");
    }
}

#[test]
fn recompile_equivalence_lua_5_4() {
    let Some(luac): Option<String> = find_luac(&luac_54_candidates()) else {
        eprintln!("skip: luac 5.4 not found on box");
        return;
    };
    for name in FIXTURES {
        assert_recompile_equivalent(&luac, name, "5_4");
    }
}

fn find_lua_interp() -> Option<String> {
    let mut candidates: Vec<String> =
        vec!["lua".to_owned(), "lua5.4".to_owned(), "lua5.1".to_owned()];
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        candidates.push(format!("{home}/Programs/Lua/bin/lua.exe"));
    }
    for c in &candidates {
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

const SERIALIZE_HARNESS: &str = r#"
local function ser(v, depth)
  depth = depth or 0
  local t = type(v)
  if t == "table" and depth < 12 then
    local keys = {}
    for k in pairs(v) do keys[#keys + 1] = k end
    table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
    local parts = {}
    for _, k in ipairs(keys) do
      parts[#parts + 1] = tostring(k) .. "=" .. ser(v[k], depth + 1)
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  if t == "function" then return "fn" end
  return tostring(v)
end
"#;

fn run_lua_capture(interp: &str, source: &str) -> Option<String> {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_lua_runtime-{}-{seq}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).ok()?;
    let dir: PathBuf = scratch.path().to_path_buf();
    let script: PathBuf = dir.join("run.lua");
    let full: String = format!(
        "{SERIALIZE_HARNESS}\nlocal make = (function()\n{source}\nend)()\nlocal a, b, c = make(\"probe\", 3)\nprint(ser(a))\nprint(ser(b))\nprint(ser(c))\n"
    );
    std::fs::write(&script, full).ok()?;
    let out = Command::new(interp).arg(&script).output().ok()?;
    if !out.status.success() {
        eprintln!("lua run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

#[test]
fn constructor_recovery_is_runtime_equivalent() {
    let mut candidates: Vec<String> = luac_51_candidates();
    candidates.extend(luac_54_candidates());
    let Some(luac): Option<String> = find_luac(&candidates) else {
        eprintln!("skip: no luac on box");
        return;
    };
    let Some(interp): Option<String> = find_lua_interp() else {
        eprintln!("skip: no lua interpreter on box");
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_lua_ctor_runtime")
            .expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let out: PathBuf = dir.join("ctor.luac");
    assert!(
        compile(&luac, &src_path("ctor"), &out),
        "compile ctor fixture"
    );
    let bytes: Vec<u8> = std::fs::read(&out).expect("read luac");
    let decompiled = decompile_auto(&bytes).expect("decompile ctor");
    let body: String = strip_main_wrapper(&decompiled.source);

    let original: String = std::fs::read_to_string(src_path("ctor")).expect("read source");

    let expected: String =
        run_lua_capture(&interp, &original).expect("original ctor runs under lua");
    let actual: String = run_lua_capture(&interp, &body).expect("recovered ctor runs under lua");
    assert_eq!(
        actual, expected,
        "recovered constructor must produce identical runtime tables\n--- recovered ---\n{body}"
    );
    assert!(
        body.contains("{kind = \"record\"") || body.contains("kind = \"record\""),
        "literal table must fold to a constructor, got:\n{body}"
    );
    assert!(
        body.contains("{1, 2, 3"),
        "mixed table positional part must fold to a constructor, got:\n{body}"
    );
}

#[test]
fn decompiled_output_is_structured_not_goto_soup() {
    let mut candidates: Vec<String> = luac_51_candidates();
    candidates.extend(luac_54_candidates());
    let Some(luac): Option<String> = find_luac(&candidates) else {
        eprintln!("skip: no luac on box");
        return;
    };
    for name in FIXTURES {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_lua_struct_check")
                .expect("create scratch dir");
        let dir: PathBuf = scratch.path().to_path_buf();
        let out: PathBuf = dir.join(format!("{name}.luac"));
        if !compile(&luac, &src_path(name), &out) {
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(&out).expect("read luac");
        let decompiled = decompile_auto(&bytes).expect("decompile");
        assert!(
            !decompiled.source.contains("goto lbl_"),
            "structured decompiler must not emit goto/label soup for {name}, got:\n{}",
            decompiled.source
        );
    }
}
