#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use disrobe_pass_lua::decompile::lift::{LiftedProto, lift_proto_dialect};
use disrobe_pass_lua::{DecompiledChunk, Fidelity, LuaChunk, decompile_auto, read_auto};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct Toolchain {
    luac: String,
    lua: String,
}

fn first_existing(candidates: &[String]) -> Option<String> {
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

fn toolchain_51() -> Option<Toolchain> {
    let luac: String = first_existing(&[
        "C:/Program Files (x86)/Lua/5.1/luac.exe".to_owned(),
        "C:/Program Files/Lua/5.1/luac.exe".to_owned(),
        "luac5.1".to_owned(),
    ])?;
    let lua: String = first_existing(&[
        "C:/Program Files (x86)/Lua/5.1/lua.exe".to_owned(),
        "C:/Program Files/Lua/5.1/lua.exe".to_owned(),
        "lua5.1".to_owned(),
    ])?;
    Some(Toolchain { luac, lua })
}

fn toolchain_54() -> Option<Toolchain> {
    let mut luac_cands: Vec<String> = vec![
        "C:/Program Files/Lua/5.4/luac.exe".to_owned(),
        "luac5.4".to_owned(),
    ];
    let mut lua_cands: Vec<String> = vec![
        "C:/Program Files/Lua/5.4/lua.exe".to_owned(),
        "lua5.4".to_owned(),
    ];
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        luac_cands.insert(0, format!("{home}/Programs/Lua/bin/luac.exe"));
        lua_cands.insert(0, format!("{home}/Programs/Lua/bin/lua.exe"));
    }
    let luac: String = first_existing(&luac_cands)?;
    let lua: String = first_existing(&lua_cands)?;
    Some(Toolchain { luac, lua })
}

fn scratch_dir() -> PathBuf {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_lua_structuring_floor-{}-{seq}",
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

const RUN_TIMEOUT: Duration = Duration::from_secs(8);

fn run_source(lua: &str, dir: &Path, name: &str, source: &str) -> Option<String> {
    let script: PathBuf = dir.join(format!("{name}.run.lua"));
    std::fs::write(&script, source).ok()?;
    let out_path: PathBuf = dir.join(format!("{name}.stdout.txt"));
    let err_path: PathBuf = dir.join(format!("{name}.stderr.txt"));
    let out_file: File = File::create(&out_path).ok()?;
    let err_file: File = File::create(&err_path).ok()?;
    let mut child = Command::new(lua)
        .arg(&script)
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .ok()?;
    let deadline: Instant = Instant::now() + RUN_TIMEOUT;
    let success: bool = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => return None,
        }
    };
    if !success {
        return None;
    }
    let mut combined: String = std::fs::read_to_string(&out_path).ok()?;
    combined.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());
    Some(combined.replace("\r\n", "\n"))
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

struct Outcome {
    fully_structured: bool,
    equivalent: bool,
    ran: bool,
    detail: String,
}

fn compile_failed(name: &str) -> Outcome {
    Outcome {
        fully_structured: false,
        equivalent: false,
        ran: false,
        detail: format!("{name}: luac-failed"),
    }
}

fn measure_production(
    tc: &Toolchain,
    run_lua: &str,
    dir: &Path,
    name: &str,
    source: &str,
) -> Outcome {
    let src_path: PathBuf = dir.join(format!("{name}.p.lua"));
    if std::fs::write(&src_path, source).is_err() {
        return compile_failed(name);
    }
    let bc_path: PathBuf = dir.join(format!("{name}.p.luac"));
    if !compile(&tc.luac, &src_path, &bc_path) {
        return compile_failed(name);
    }
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&bc_path) else {
        return compile_failed(name);
    };
    let Ok(decompiled): Result<DecompiledChunk, _> = decompile_auto(&bytes) else {
        return compile_failed(name);
    };
    let body: String = strip_main_wrapper(&decompiled.source);
    let expected: Option<String> = run_source(run_lua, dir, &format!("{name}.p.orig"), source);
    let actual: Option<String> = run_source(run_lua, dir, &format!("{name}.p.dec"), &body);
    let equivalent: bool = matches!((&expected, &actual), (Some(e), Some(a)) if e == a);
    Outcome {
        fully_structured: !matches!(decompiled.fidelity, Fidelity::BestEffort),
        equivalent,
        ran: actual.is_some(),
        detail: format!(
            "{name}: fidelity={:?} expected={:?} actual={:?}",
            decompiled.fidelity,
            expected.as_deref(),
            actual.as_deref()
        ),
    }
}

fn measure_fallback(
    tc: &Toolchain,
    run_lua: &str,
    dir: &Path,
    name: &str,
    source: &str,
) -> Outcome {
    let src_path: PathBuf = dir.join(format!("{name}.f.lua"));
    if std::fs::write(&src_path, source).is_err() {
        return compile_failed(name);
    }
    let bc_path: PathBuf = dir.join(format!("{name}.f.luac"));
    if !compile(&tc.luac, &src_path, &bc_path) {
        return compile_failed(name);
    }
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&bc_path) else {
        return compile_failed(name);
    };
    let Ok(chunk): Result<LuaChunk, _> = read_auto(&bytes) else {
        return compile_failed(name);
    };
    let lifted: LiftedProto = lift_proto_dialect(&chunk.main, chunk.dialect, 0);
    let expected: Option<String> = run_source(run_lua, dir, &format!("{name}.f.orig"), source);
    let actual: Option<String> = run_source(run_lua, dir, &format!("{name}.f.dec"), &lifted.source);
    let equivalent: bool = matches!((&expected, &actual), (Some(e), Some(a)) if e == a);
    Outcome {
        fully_structured: lifted.fully_structured,
        equivalent,
        ran: actual.is_some(),
        detail: format!(
            "{name}: fully_structured={} expected={:?} actual={:?} recovered={}",
            lifted.fully_structured,
            expected.as_deref(),
            actual.as_deref(),
            lifted.source
        ),
    }
}

struct LaneReport {
    total: usize,
    ran: usize,
    equivalent: usize,
    structured: usize,
    false_green: Vec<String>,
    misses: Vec<String>,
}

fn run_lane(
    tc: &Toolchain,
    run_lua: &str,
    lane_tag: &str,
    measure: fn(&Toolchain, &str, &Path, &str, &str) -> Outcome,
) -> LaneReport {
    let dir: PathBuf = scratch_dir();
    let mut report: LaneReport = LaneReport {
        total: 0,
        ran: 0,
        equivalent: 0,
        structured: 0,
        false_green: Vec::new(),
        misses: Vec::new(),
    };
    for (name, source) in CORPUS {
        report.total += 1;
        let outcome: Outcome = measure(tc, run_lua, &dir, name, source);
        if outcome.ran {
            report.ran += 1;
        }
        if outcome.equivalent {
            report.equivalent += 1;
        } else {
            report.misses.push(format!("{lane_tag}/{}", outcome.detail));
        }
        if outcome.fully_structured {
            report.structured += 1;
        }
        if outcome.fully_structured && !outcome.equivalent {
            report
                .false_green
                .push(format!("{lane_tag}/{}", outcome.detail));
        }
    }
    report
}

fn assert_lane(
    lane_tag: &str,
    dialect_tag: &str,
    force_goto_capable_runtime: bool,
    measure: fn(&Toolchain, &str, &Path, &str, &str) -> Outcome,
    equivalence_floor_num: usize,
    structuring_floor_num: usize,
) {
    let tc: Option<Toolchain> = match dialect_tag {
        "5.1" => toolchain_51(),
        "5.4" => toolchain_54(),
        _ => None,
    };
    let Some(tc): Option<Toolchain> = tc else {
        eprintln!("skip: lua {dialect_tag} toolchain (luac+lua) not found on box");
        return;
    };
    let goto_capable_runtime: Option<Toolchain> = toolchain_54();
    let run_lua: &str = if force_goto_capable_runtime {
        let Some(rt): Option<&Toolchain> = goto_capable_runtime.as_ref() else {
            eprintln!("skip: no goto-capable (5.2+) lua runtime found on box");
            return;
        };
        &rt.lua
    } else {
        &tc.lua
    };
    let report: LaneReport = run_lane(&tc, run_lua, lane_tag, measure);
    eprintln!(
        "[{lane_tag} {dialect_tag}] ran {}/{}, exec-equivalent {}/{}, fully_structured {}/{}",
        report.ran, report.total, report.equivalent, report.total, report.structured, report.total
    );
    for miss in &report.misses {
        eprintln!("[{lane_tag} {dialect_tag}] MISS {miss}");
    }

    assert!(
        report.false_green.is_empty(),
        "FALSE-GREEN in {lane_tag} {dialect_tag}: fully_structured=true was reported but \
         re-execution diverged from the original for {} fixture(s); fully_structured MUST \
         imply behavioral equivalence.\n{}",
        report.false_green.len(),
        report.false_green.join("\n----\n")
    );

    assert!(
        report.equivalent * CORPUS.len() >= equivalence_floor_num * report.total,
        "{lane_tag} {dialect_tag} behavioral-equivalence regressed below floor \
         {equivalence_floor_num}/{}: got {}/{}",
        CORPUS.len(),
        report.equivalent,
        report.total
    );
    assert!(
        report.structured * CORPUS.len() >= structuring_floor_num * report.total,
        "{lane_tag} {dialect_tag} structuring rate regressed below floor \
         {structuring_floor_num}/{}: got {}/{}",
        CORPUS.len(),
        report.structured,
        report.total
    );
}

const CORPUS: &[(&str, &str)] = &[
    (
        "bare_if_else",
        "local flag = true\nlocal other = false\nif flag then\n  print(\"A\", 1)\nelse\n  print(\"B\", 2)\nend\nif other then\n  print(\"C\", 3)\nelse\n  print(\"D\", 4)\nend\n",
    ),
    (
        "bare_if_only_no_else",
        "local n = 0\nlocal flag = true\nif flag then\n  n = n + 10\nend\nif not flag then\n  n = n + 100\nend\nprint(n)\n",
    ),
    (
        "bool_materialized_from_compare",
        "local a, b, c = 3, 3, 4\nlocal eq = (a == b)\nlocal neq = (a == c)\nprint(eq, neq, not eq, not neq)\n",
    ),
    (
        "array_literal_ctor",
        "local t = {10, 20, 30, 40}\nlocal sum = 0\nfor i = 1, #t do sum = sum + t[i] end\nprint(t[1], t[2], t[3], t[4], #t, sum)\n",
    ),
    (
        "mixed_positional_and_hash_ctor",
        "local rec = {1, 2, 3, name = \"x\", flag = true}\nprint(rec[1], rec[2], rec[3], rec.name, rec.flag)\n",
    ),
    (
        "logical_and_or_ternary",
        "local function pick(a, b, c)\n  return a and b or c\nend\nprint(pick(true, \"yes\", \"no\"), pick(false, \"yes\", \"no\"), pick(nil, 0, 9))\n",
    ),
    (
        "nested_if_elseif_chain",
        "local function grade(n)\n  if n >= 90 then return \"A\"\n  elseif n >= 80 then return \"B\"\n  elseif n >= 70 then return \"C\"\n  else return \"F\" end\nend\nprint(grade(95), grade(85), grade(72), grade(40))\n",
    ),
    (
        "while_and_numeric_for",
        "local acc = 0\nlocal i = 1\nwhile i <= 5 do\n  acc = acc + i\n  i = i + 1\nend\nfor j = 1, 5 do\n  acc = acc + j\nend\nprint(acc)\n",
    ),
];

const PRODUCTION_EQUIVALENCE_FLOOR: usize = 7;
const PRODUCTION_STRUCTURING_FLOOR: usize = 7;
const FALLBACK_EQUIVALENCE_FLOOR: usize = 5;
const FALLBACK_STRUCTURING_FLOOR: usize = 2;

#[test]
fn production_lane_lua_5_1() {
    assert_lane(
        "production",
        "5.1",
        false,
        measure_production,
        PRODUCTION_EQUIVALENCE_FLOOR,
        PRODUCTION_STRUCTURING_FLOOR,
    );
}

#[test]
fn production_lane_lua_5_4() {
    assert_lane(
        "production",
        "5.4",
        false,
        measure_production,
        PRODUCTION_EQUIVALENCE_FLOOR,
        PRODUCTION_STRUCTURING_FLOOR,
    );
}

#[test]
fn fallback_lifter_lua_5_1() {
    assert_lane(
        "fallback",
        "5.1",
        true,
        measure_fallback,
        FALLBACK_EQUIVALENCE_FLOOR,
        FALLBACK_STRUCTURING_FLOOR,
    );
}

#[test]
fn fallback_lifter_lua_5_4() {
    assert_lane(
        "fallback",
        "5.4",
        true,
        measure_fallback,
        FALLBACK_EQUIVALENCE_FLOOR,
        FALLBACK_STRUCTURING_FLOOR,
    );
}
