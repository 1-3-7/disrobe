#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use disrobe_pass_lua::decompile::{DecompiledChunk, Fidelity, decompile_auto};

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
    let mut luac_cands: Vec<String> = vec![
        "C:/Program Files (x86)/Lua/5.1/luac.exe".to_owned(),
        "C:/Program Files/Lua/5.1/luac.exe".to_owned(),
        "luac5.1".to_owned(),
    ];
    let mut lua_cands: Vec<String> = vec![
        "C:/Program Files (x86)/Lua/5.1/lua.exe".to_owned(),
        "C:/Program Files/Lua/5.1/lua.exe".to_owned(),
        "lua5.1".to_owned(),
    ];
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        luac_cands.insert(0, format!("{home}/Programs/Lua51/luac5.1.exe"));
        lua_cands.insert(0, format!("{home}/Programs/Lua51/lua5.1.exe"));
    }
    let luac: String = first_existing(&luac_cands)?;
    let lua: String = first_existing(&lua_cands)?;
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

fn scratch_dir() -> disrobe_core::scratch::ScratchDir {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_lua_reexec-{}-{seq}", std::process::id());
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

struct LaneResult {
    total: usize,
    compiled: usize,
    equivalent: usize,
    lossless_lie: Vec<String>,
    non_equivalent: Vec<String>,
}

fn run_lane(tc: &Toolchain) -> LaneResult {
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut res: LaneResult = LaneResult {
        total: 0,
        compiled: 0,
        equivalent: 0,
        lossless_lie: Vec::new(),
        non_equivalent: Vec::new(),
    };
    for (name, source) in CORPUS {
        res.total += 1;
        let src_path: PathBuf = dir.join(format!("{name}.lua"));
        if std::fs::write(&src_path, source).is_err() {
            res.non_equivalent.push(format!("{name}: write-src-failed"));
            continue;
        }
        let bc_path: PathBuf = dir.join(format!("{name}.luac"));
        if !compile(&tc.luac, &src_path, &bc_path) {
            res.non_equivalent.push(format!("{name}: luac-failed"));
            continue;
        }
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&bc_path) else {
            res.non_equivalent.push(format!("{name}: read-bc-failed"));
            continue;
        };
        let Ok(decompiled): Result<DecompiledChunk, _> = decompile_auto(&bytes) else {
            res.non_equivalent.push(format!("{name}: decompile-err"));
            continue;
        };
        res.compiled += 1;
        let body: String = strip_main_wrapper(&decompiled.source);
        let expected: Option<String> = run_source(&tc.lua, &dir, &format!("{name}.orig"), source);
        let actual: Option<String> = run_source(&tc.lua, &dir, &format!("{name}.dec"), &body);
        let equivalent: bool = match (&expected, &actual) {
            (Some(e), Some(a)) => e == a,
            _ => false,
        };
        if equivalent {
            res.equivalent += 1;
        } else {
            res.non_equivalent.push(format!(
                "{name}: fidelity={:?} expected={:?} actual={:?}",
                decompiled.fidelity,
                expected.as_deref().map(short),
                actual.as_deref().map(short)
            ));
        }
        if matches!(decompiled.fidelity, Fidelity::Lossless) && !equivalent {
            res.lossless_lie.push(format!(
                "{name}: reported Lossless but re-exec differs\n--- expected ---\n{}\n--- actual ---\n{}\n--- recovered ---\n{body}",
                expected.as_deref().unwrap_or("<orig-failed>"),
                actual.as_deref().unwrap_or("<dec-failed-to-run>")
            ));
        }
    }
    res
}

fn short(s: &str) -> String {
    let one: String = s.replace('\n', " | ");
    if one.len() > 120 {
        format!("{}...", &one[..120])
    } else {
        one
    }
}

fn assert_lane(tag: &str) {
    let tc: Option<Toolchain> = match tag {
        "5.1" => toolchain_51(),
        "5.4" => toolchain_54(),
        _ => None,
    };
    let Some(tc): Option<Toolchain> = tc else {
        eprintln!("skip: lua {tag} toolchain (luac+lua) not found on box");
        return;
    };
    let res: LaneResult = run_lane(&tc);
    let pct: f64 = if res.total == 0 {
        0.0
    } else {
        100.0 * res.equivalent as f64 / res.total as f64
    };
    eprintln!(
        "[reexec {tag}] behavioral-equivalent {}/{} ({pct:.1}%), decompiled-ok {}, lossless-lies {}",
        res.equivalent,
        res.total,
        res.compiled,
        res.lossless_lie.len()
    );
    for line in &res.non_equivalent {
        eprintln!("[reexec {tag}] MISS {line}");
    }

    assert!(
        res.lossless_lie.is_empty(),
        "LOSSLESS LIE in lua {tag} lane: {} fixture(s) reported Fidelity::Lossless but re-execution diverged. A Lossless claim MUST imply behavioral equivalence.\n{}",
        res.lossless_lie.len(),
        res.lossless_lie.join("\n----\n")
    );

    let floor_num: usize = REEXEC_FLOOR_NUM;
    assert!(
        res.equivalent * CORPUS.len() >= floor_num * res.total,
        "lua {tag} behavioral-equivalence regressed below floor {floor_num}/{}: got {}/{}",
        CORPUS.len(),
        res.equivalent,
        res.total
    );
}

const REEXEC_FLOOR_NUM: usize = 29;
const VARARG_TABLE_PROGRAM: &str = "local function sumall(...)\n  local s = 0\n  for _, v in ipairs({...}) do s = s + v end\n  return s\nend\nprint(sumall(1, 2, 3, 4, 5))\n";

#[test]
fn reexec_equivalence_lua_5_1() {
    assert_lane("5.1");
}

#[test]
fn reexec_equivalence_lua_5_4() {
    assert_lane("5.4");
}

#[test]
fn vararg_table_constructor_reexecutes_lua_5_1() {
    let Some(tc): Option<Toolchain> = toolchain_51() else {
        eprintln!("skip: lua 5.1 toolchain not found");
        return;
    };
    assert_vararg_table_constructor_reexecutes(&tc);
}

#[test]
fn vararg_table_constructor_reexecutes_lua_5_4() {
    let Some(tc): Option<Toolchain> = toolchain_54() else {
        eprintln!("skip: lua 5.4 toolchain not found");
        return;
    };
    assert_vararg_table_constructor_reexecutes(&tc);
}

fn assert_vararg_table_constructor_reexecutes(tc: &Toolchain) {
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src: PathBuf = dir.join("vararg_table.lua");
    std::fs::write(&src, VARARG_TABLE_PROGRAM).expect("write source");
    let bc: PathBuf = dir.join("vararg_table.luac");
    assert!(compile(&tc.luac, &src, &bc), "luac compiles source");
    let bytes: Vec<u8> = std::fs::read(&bc).expect("read bytecode");
    let decompiled: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
    let body: String = strip_main_wrapper(&decompiled.source);
    let expected: String =
        run_source(&tc.lua, &dir, "vararg_orig", VARARG_TABLE_PROGRAM).expect("original runs");
    let actual: String =
        run_source(&tc.lua, &dir, "vararg_dec", &body).expect("recovered source runs");
    assert_eq!(
        actual, expected,
        "vararg table constructor must preserve every argument\n--- recovered ---\n{body}"
    );
}

const GOTO_PROGRAM: &str = "local acc = 0\nlocal i = 1\n::top::\nif i > 5 then goto done end\nacc = acc + i\ni = i + 1\ngoto top\n::done::\nprint(acc)\n";

#[test]
fn goto_edges_preserved_not_dropped_lua_5_4() {
    let Some(tc): Option<Toolchain> = toolchain_54() else {
        eprintln!("skip: lua 5.4 toolchain not found");
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src: PathBuf = dir.join("goto_prog.lua");
    std::fs::write(&src, GOTO_PROGRAM).expect("write goto src");
    let bc: PathBuf = dir.join("goto_prog.luac");
    assert!(
        compile(&tc.luac, &src, &bc),
        "luac 5.4 compiles goto program"
    );
    let bytes: Vec<u8> = std::fs::read(&bc).expect("read bc");
    let decompiled: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
    let body: String = strip_main_wrapper(&decompiled.source);

    assert!(
        body.contains("goto lbl_") && body.contains("::lbl_"),
        "unstructured edge must be recovered as goto/label, not dropped; got:\n{body}"
    );
    assert!(
        !matches!(decompiled.fidelity, Fidelity::Lossless),
        "output containing a recovered goto must not claim Lossless; fidelity was {:?}",
        decompiled.fidelity
    );

    let expected: String = run_source(&tc.lua, &dir, "goto_orig", GOTO_PROGRAM).expect("orig runs");
    let actual: String = run_source(&tc.lua, &dir, "goto_dec", &body).expect("recovered runs");
    assert_eq!(
        expected, actual,
        "goto-preserved recovery must re-execute identically; recovered:\n{body}"
    );
}

const LOOP_HEAD_PROGRAMS_54: &[(&str, &str)] = &[
    (
        "goto_head_runs_a_statement_before_the_test",
        "local i = 0\nlocal acc = 0\n::top::\nacc = acc + 1\nif i < 5 then\n  i = i + 1\n  goto top\nend\nprint(i, acc)\n",
    ),
    (
        "goto_head_before_a_compound_test",
        "local i = 0\nlocal seen = 0\n::top::\nseen = seen + i\nif i < 4 and seen < 100 then\n  i = i + 1\n  goto top\nend\nprint(i, seen)\n",
    ),
    (
        "goto_head_inside_a_nested_closure",
        "local function tally()\n  local i = 0\n  local acc = 0\n  ::top::\n  acc = acc + 1\n  if i < 5 then\n    i = i + 1\n    goto top\n  end\n  return i, acc\nend\nprint(tally())\n",
    ),
    (
        "goto_head_before_a_repeat_style_test",
        "local n = 0\nlocal hits = 0\n::again::\nhits = hits + 1\nn = n + 2\nif n < 9 then goto again end\nprint(n, hits)\n",
    ),
];

const LOOP_HEAD_PROGRAMS_51: &[(&str, &str)] = &[
    (
        "while_test_after_a_call_in_the_condition",
        "local i = 0\nlocal calls = 0\nlocal function still_going()\n  calls = calls + 1\n  return i < 5\nend\nwhile still_going() do\n  i = i + 1\nend\nprint(i, calls)\n",
    ),
    (
        "repeat_until_with_a_compound_test",
        "local i = 0\nlocal s = 0\nrepeat\n  i = i + 1\n  s = s + i\nuntil i >= 4 or s > 100\nprint(i, s)\n",
    ),
    (
        "while_over_a_table_lookup_condition",
        "local t = {true, true, true}\nlocal i = 1\nlocal steps = 0\nwhile t[i] do\n  steps = steps + 1\n  i = i + 1\nend\nprint(i, steps)\n",
    ),
];

fn require_toolchain(tag: &str) -> Toolchain {
    let found: Option<Toolchain> = match tag {
        "5.1" => toolchain_51(),
        "5.4" => toolchain_54(),
        _ => None,
    };
    let Some(tc): Option<Toolchain> = found else {
        panic!(
            "no lua {tag} toolchain (luac + lua) is usable here, so the structuring claim would be \
             compared against nothing and this run would go green having graded nothing. Install \
             lua{tag} and luac{tag} and put them on PATH."
        )
    };
    tc
}

struct LaneClaims {
    graded: usize,
    claimed_structure: usize,
    unclaimed_with_labelled_jump: usize,
}

fn assert_structure_claim_matches_reexecution(
    compile_tag: &str,
    programs: &[(&str, &str)],
) -> LaneClaims {
    let tc: Toolchain = require_toolchain(compile_tag);
    let runtime: Toolchain = require_toolchain("5.4");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut lies: Vec<String> = Vec::new();
    let mut diverged: Vec<String> = Vec::new();
    let mut claims: LaneClaims = LaneClaims {
        graded: 0,
        claimed_structure: 0,
        unclaimed_with_labelled_jump: 0,
    };

    for (name, source) in programs {
        let src: PathBuf = dir.join(format!("{name}.lua"));
        std::fs::write(&src, source).expect("stage the source");
        let bc: PathBuf = dir.join(format!("{name}.luac"));
        assert!(
            compile(&tc.luac, &src, &bc),
            "luac {compile_tag} must compile {name}, otherwise nothing downstream is measured"
        );
        let bytes: Vec<u8> = std::fs::read(&bc).expect("read the bytecode");
        let decompiled: DecompiledChunk = decompile_auto(&bytes).expect("decompile the bytecode");
        let body: String = strip_main_wrapper(&decompiled.source);
        let expected: String = run_source(&runtime.lua, &dir, &format!("{name}.orig"), source)
            .expect("the original program must run under the reference interpreter");
        let actual: Option<String> = run_source(&runtime.lua, &dir, &format!("{name}.dec"), &body);
        claims.graded += 1;
        let equivalent: bool = actual.as_deref() == Some(expected.as_str());
        let claims_structure: bool = !matches!(decompiled.fidelity, Fidelity::BestEffort);
        if claims_structure {
            claims.claimed_structure += 1;
        } else if body.contains("goto lbl_") && body.contains("::lbl_") {
            claims.unclaimed_with_labelled_jump += 1;
        }
        if claims_structure && !equivalent {
            lies.push(format!(
                "{name}: fidelity={:?} warnings={:?}\n--- expected ---\n{expected}\n--- actual \
                 ---\n{}\n--- recovered ---\n{body}",
                decompiled.fidelity,
                decompiled.warnings,
                actual
                    .as_deref()
                    .unwrap_or("<recovered source did not run>")
            ));
        }
        if !equivalent {
            diverged.push(format!(
                "{name}: expected={expected:?} actual={:?}\n--- recovered ---\n{body}",
                actual.as_deref()
            ));
        }
    }

    assert_eq!(
        claims.graded,
        programs.len(),
        "every program in this lane has to reach the interpreter"
    );
    assert!(
        lies.is_empty(),
        "lua {compile_tag}: {} program(s) claimed a recovered structure while re-execution \
         diverged. A dropped edge must lower the claim, never sit behind a clean one.\n{}",
        lies.len(),
        lies.join("\n----\n")
    );
    assert!(
        diverged.is_empty(),
        "lua {compile_tag}: {} program(s) re-executed differently from the original. An edge the \
         structure cannot carry has to survive as a labelled jump, not be deleted.\n{}",
        diverged.len(),
        diverged.join("\n----\n")
    );
    claims
}

#[test]
fn a_loop_head_before_the_test_keeps_its_edge_lua_5_4() {
    let claims: LaneClaims =
        assert_structure_claim_matches_reexecution("5.4", LOOP_HEAD_PROGRAMS_54);

    assert!(
        claims.claimed_structure < claims.graded,
        "every program here runs a statement at a loop head that the recovered while cannot \
         re-enter, so at least one must report less than a complete structure; a lane where all \
         {} claim one is measuring nothing",
        claims.graded
    );
    assert_eq!(
        claims.unclaimed_with_labelled_jump,
        claims.graded - claims.claimed_structure,
        "a program that reports an incomplete structure must show the edge it could not place, as \
         a label and a jump to it; without them the edge was deleted rather than reported"
    );
}

#[test]
fn a_loop_head_before_the_test_keeps_its_edge_lua_5_1() {
    assert_structure_claim_matches_reexecution("5.1", LOOP_HEAD_PROGRAMS_51);
}

const CORPUS: &[(&str, &str)] = &[
    (
        "arith",
        "local a = 7\nlocal b = 3\nprint(a + b, a - b, a * b, a % b)\nprint((a + b) * (a - b))\nprint(-a, #\"hello\")\n",
    ),
    (
        "string_ops",
        "local s = \"disrobe\"\nprint(string.upper(s))\nprint(string.sub(s, 1, 3))\nprint(#s, s .. \"!\")\nprint(string.format(\"%d-%s\", 42, s))\n",
    ),
    (
        "array_table",
        "local t = {10, 20, 30, 40}\nlocal sum = 0\nfor i = 1, #t do sum = sum + t[i] end\nprint(sum, #t, t[1], t[4])\n",
    ),
    (
        "hash_table",
        "local m = {a = 1, b = 2, c = 3}\nlocal keys = {\"a\", \"b\", \"c\"}\nfor _, k in ipairs(keys) do print(k, m[k]) end\n",
    ),
    (
        "mixed_table",
        "local t = {1, 2, 3, name = \"x\", flag = true}\nprint(t[1], t[2], t[3], t.name, t.flag)\n",
    ),
    (
        "numeric_for",
        "local acc = 0\nfor i = 1, 10 do acc = acc + i end\nfor i = 10, 1, -2 do acc = acc - i end\nprint(acc)\n",
    ),
    (
        "generic_for_ipairs",
        "local xs = {5, 15, 25}\nlocal total = 0\nfor idx, v in ipairs(xs) do total = total + idx * v end\nprint(total)\n",
    ),
    (
        "while_loop",
        "local n = 100\nlocal steps = 0\nwhile n > 1 do\n  if n % 2 == 0 then n = n / 2 else n = n * 3 + 1 end\n  steps = steps + 1\nend\nprint(steps)\n",
    ),
    (
        "repeat_loop",
        "local i = 0\nlocal s = \"\"\nrepeat\n  i = i + 1\n  s = s .. tostring(i)\nuntil i >= 5\nprint(s)\n",
    ),
    (
        "if_elseif_else",
        "local function grade(n)\n  if n >= 90 then return \"A\"\n  elseif n >= 80 then return \"B\"\n  elseif n >= 70 then return \"C\"\n  else return \"F\" end\nend\nprint(grade(95), grade(85), grade(72), grade(40))\n",
    ),
    (
        "and_or",
        "local function pick(a, b, c)\n  local x = a and b or c\n  local y = a or b\n  return x, y\nend\nprint(pick(true, \"yes\", \"no\"))\nprint(pick(false, \"yes\", \"no\"))\nprint(pick(nil, 0, 9))\n",
    ),
    (
        "nested_if",
        "local function classify(x, y)\n  if x > 0 then\n    if y > 0 then return \"q1\" else return \"q4\" end\n  else\n    if y > 0 then return \"q2\" else return \"q3\" end\n  end\nend\nprint(classify(1, 1), classify(1, -1), classify(-1, 1), classify(-1, -1))\n",
    ),
    (
        "closure_upvalue",
        "local function counter()\n  local n = 0\n  return function()\n    n = n + 1\n    return n\n  end\nend\nlocal c = counter()\nprint(c(), c(), c())\n",
    ),
    (
        "recursion",
        "local function fib(n)\n  if n < 2 then return n end\n  return fib(n - 1) + fib(n - 2)\nend\nprint(fib(10), fib(15))\n",
    ),
    (
        "multi_return",
        "local function minmax(t)\n  local lo, hi = t[1], t[1]\n  for i = 2, #t do\n    if t[i] < lo then lo = t[i] end\n    if t[i] > hi then hi = t[i] end\n  end\n  return lo, hi\nend\nprint(minmax({4, 1, 7, 3, 9, 2}))\n",
    ),
    ("varargs", VARARG_TABLE_PROGRAM),
    (
        "method_self",
        "local obj = {value = 10}\nfunction obj:add(x) self.value = self.value + x return self.value end\nprint(obj:add(5), obj:add(3))\n",
    ),
    (
        "break_loop",
        "local first = nil\nfor i = 1, 100 do\n  if i * i > 50 then first = i break end\nend\nprint(first)\n",
    ),
    (
        "concat_chain",
        "local parts = {\"a\", \"b\", \"c\", \"d\"}\nlocal out = \"\"\nfor _, p in ipairs(parts) do out = out .. p .. \"-\" end\nprint(out)\n",
    ),
    (
        "comparison_chain",
        "local function between(x, lo, hi)\n  return x >= lo and x <= hi\nend\nprint(between(5, 1, 10), between(0, 1, 10), between(10, 1, 10))\n",
    ),
    (
        "not_unm",
        "local a = true\nlocal b = false\nprint(not a, not b, not nil)\nlocal n = 5\nprint(-n, -(-n))\n",
    ),
    (
        "table_sort",
        "local t = {3, 1, 4, 1, 5, 9, 2, 6}\ntable.sort(t)\nlocal out = \"\"\nfor _, v in ipairs(t) do out = out .. v end\nprint(out)\ntable.sort(t, function(x, y) return x > y end)\nlocal rev = \"\"\nfor _, v in ipairs(t) do rev = rev .. v end\nprint(rev)\n",
    ),
    (
        "nested_functions",
        "local function outer(base)\n  local function inner(x) return x * base end\n  return inner(3) + inner(4)\nend\nprint(outer(10), outer(2))\n",
    ),
    (
        "string_find_gsub",
        "local s = \"the quick brown fox\"\nprint(string.gsub(s, \"o\", \"0\"))\nprint(string.find(s, \"quick\"))\n",
    ),
    (
        "loop_accumulate_table",
        "local acc = {}\nfor i = 1, 5 do acc[i] = i * i end\nlocal s = 0\nfor i = 1, #acc do s = s + acc[i] end\nprint(s, acc[3])\n",
    ),
    (
        "conditional_assign",
        "local function abs(x)\n  local r\n  if x < 0 then r = -x else r = x end\n  return r\nend\nprint(abs(-7), abs(4), abs(0))\n",
    ),
    (
        "early_return_guard",
        "local function safe_div(a, b)\n  if b == 0 then return nil, \"div by zero\" end\n  return a / b\nend\nprint(safe_div(10, 2))\nprint(safe_div(1, 0))\n",
    ),
    (
        "chained_calls",
        "local function double(x) return x * 2 end\nlocal function inc(x) return x + 1 end\nprint(double(inc(double(3))))\n",
    ),
    (
        "while_with_break_continue",
        "local i = 0\nlocal collected = {}\nwhile i < 20 do\n  i = i + 1\n  if i % 3 == 0 then\n    collected[#collected + 1] = i\n  end\n  if i >= 15 then break end\nend\nlocal out = \"\"\nfor _, v in ipairs(collected) do out = out .. v .. \",\" end\nprint(out)\n",
    ),
    (
        "elseif_no_else",
        "local function sign(x)\n  if x > 0 then return 1\n  elseif x < 0 then return -1 end\n  return 0\nend\nprint(sign(5), sign(-5), sign(0))\n",
    ),
];

const PROMETHEUS_VMIFY_CLEAN: &str = include_str!("../../../corpus/lua/prometheus/vmify/clean.lua");
const PROMETHEUS_VMIFY_OBFUSCATED: &str =
    include_str!("../../../corpus/lua/prometheus/vmify/obfuscated.lua");
const PROMETHEUS_WEAK_CLEAN: &str = include_str!("../../../corpus/lua/prometheus/weak/clean.lua");
const PROMETHEUS_WEAK_OBFUSCATED: &str =
    include_str!("../../../corpus/lua/prometheus/weak/obfuscated.lua");

#[test]
fn prometheus_weak_preset_recovers_and_reexecutes_identically() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    let peeled: PeelResult = prometheus::peel(
        PROMETHEUS_WEAK_OBFUSCATED.as_bytes(),
        &DeobfOptions::default(),
    )
    .expect("prometheus peel must run on the tracked Weak preset fixture");
    assert!(
        peeled
            .passes_run
            .iter()
            .any(|pass: &String| pass == "prometheus-vmify-container-devirt"),
        "the pinned Weak-equivalent order must reach Vmify recovery after ConstantArray and WrapInFunction; passes={:?}, residual={:?}",
        peeled.passes_run,
        peeled.residual_markers
    );

    let recovered_src: String =
        String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "prometheus_weak_clean",
        PROMETHEUS_WEAK_CLEAN,
    )
    .expect("the tracked clean Weak-preset input must run under real Lua 5.1");
    let actual: String = run_source(&tc.lua, &dir, "prometheus_weak_recovered", &recovered_src)
        .expect("the recovered Weak-preset source must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "Weak-preset recovery must preserve runtime output under real Lua 5.1"
    );
}

#[test]
fn prometheus_vmify_recovers_and_reexecutes_identically_to_the_original() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    let opts: DeobfOptions = DeobfOptions::default();
    let peeled: PeelResult = prometheus::peel(PROMETHEUS_VMIFY_OBFUSCATED.as_bytes(), &opts)
        .expect("prometheus peel must run");

    assert!(
        peeled
            .passes_run
            .iter()
            .any(|p: &String| p == "prometheus-vmify-container-devirt"),
        "the Vmify container-devirt pass must have actually run; passes_run={:?}",
        peeled.passes_run
    );
    assert!(
        peeled
            .residual_markers
            .iter()
            .any(|m: &String| m.contains("handlers")),
        "the devirt pass must report real handler coverage, not a vacuous pass; residual_markers={:?}",
        peeled.residual_markers
    );

    let recovered_src: String =
        String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");

    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let orig_path: PathBuf = dir.join("prometheus_vmify_orig.lua");
    let recovered_path: PathBuf = dir.join("prometheus_vmify_recovered.lua");
    std::fs::write(&orig_path, PROMETHEUS_VMIFY_CLEAN).expect("write original fixture");
    std::fs::write(&recovered_path, &recovered_src).expect("write recovered source");

    let expected: String = run_source(
        &tc.lua,
        &dir,
        "prometheus_vmify_orig_run",
        PROMETHEUS_VMIFY_CLEAN,
    )
    .expect("the original Vmify-obfuscated sample's clean source must run under real Lua 5.1");
    let actual: String = run_source(&tc.lua, &dir, "prometheus_vmify_recovered_run", &recovered_src).expect(
        "the recovered source must run under real Lua 5.1; a parse/runtime error means the devirtualizer emitted broken Lua",
    );

    assert_eq!(
        expected, actual,
        "recovered Vmify source must re-execute identically to the real original under real Lua 5.1\n--- recovered ---\n{recovered_src}"
    );
}

const PROMETHEUS_VMIFY_SIMPLE_CLEAN: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_simple/clean.lua");
const PROMETHEUS_VMIFY_SIMPLE_OBFUSCATED: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_simple/obfuscated.lua");

#[test]
fn prometheus_vmify_loop_free_sample_recovers_fully_structured() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    let opts: DeobfOptions = DeobfOptions::default();
    let peeled: PeelResult = prometheus::peel(PROMETHEUS_VMIFY_SIMPLE_OBFUSCATED.as_bytes(), &opts)
        .expect("prometheus peel must run");

    assert!(
        peeled.fully_recovered,
        "a loop-free Vmify sample with only if/elseif/else control flow must reach full clean structuring; residual_markers={:?}",
        peeled.residual_markers
    );

    let recovered_src: String =
        String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_simple_orig",
        PROMETHEUS_VMIFY_SIMPLE_CLEAN,
    )
    .expect("original must run");
    let actual: String = run_source(&tc.lua, &dir, "vmify_simple_recovered", &recovered_src)
        .expect("recovered source must run");
    assert_eq!(
        expected, actual,
        "fully structured recovered source must re-execute identically to the original\n--- recovered ---\n{recovered_src}"
    );
}

const PROMETHEUS_VMIFY_NESTED_CLEAN: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_nested/clean.lua");
const PROMETHEUS_VMIFY_NESTED_OBFUSCATED: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_nested/obfuscated.lua");

#[test]
fn prometheus_vmify_nested_double_layer_fixtures_already_agree() {
    let tc: Toolchain = require_toolchain("5.1");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_nested_fixture_clean",
        PROMETHEUS_VMIFY_NESTED_CLEAN,
    )
    .expect("clean fixture must run under real Lua 5.1");
    let actual: String = run_source(
        &tc.lua,
        &dir,
        "vmify_nested_fixture_obfuscated",
        PROMETHEUS_VMIFY_NESTED_OBFUSCATED,
    )
    .expect("real Prometheus Vmify-applied-twice output must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "the committed nested obfuscated fixture must be a faithful Vmify-applied-twice transform of the committed clean fixture"
    );
}

#[test]
fn prometheus_vmify_nested_double_layer_sample_recovers_and_reexecutes_identically() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    let opts: DeobfOptions = DeobfOptions::default();
    let peeled: PeelResult = prometheus::peel(PROMETHEUS_VMIFY_NESTED_OBFUSCATED.as_bytes(), &opts)
        .expect("prometheus peel must run on a real Vmify-applied-twice sample");
    let emitted: String =
        String::from_utf8(peeled.deobfuscated).expect("emitted artifact must be UTF-8");
    assert!(
        !emitted.contains("prometheus-vmify:"),
        "the emitted artifact must not carry one of this pass's own not-recovered stubs\n--- emitted ---\n{emitted}"
    );
    assert!(
        !emitted.contains("__pc"),
        "both Vmify layers must recover to real Lua control flow\n--- emitted ---\n{emitted}"
    );

    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_nested_orig",
        PROMETHEUS_VMIFY_NESTED_CLEAN,
    )
    .expect("the clean double-Vmify source must run under real Lua 5.1");
    let actual: String = run_source(&tc.lua, &dir, "vmify_nested_recovered", &emitted)
        .expect("the recovered double-Vmify source must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "a sample put through Vmify twice must recover to source that re-executes identically to \
         the real original\n--- recovered ---\n{emitted}"
    );
}

#[test]
fn prometheus_vmify_dispatch_leaf_with_nested_local_function_recovers_and_reexecutes() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    let obfuscated: String = PROMETHEUS_VMIFY_NESTED_OBFUSCATED.replace(
        "N=\"F\"y=N g={y}",
        "N=(function() local q=\"F\" local get=function() return q end return get() end)() y=N g={y}",
    );
    assert_ne!(
        obfuscated, PROMETHEUS_VMIFY_NESTED_OBFUSCATED,
        "the tracked real nested fixture must retain the selected reachable handler expression"
    );

    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_nested_local_function_orig",
        PROMETHEUS_VMIFY_NESTED_CLEAN,
    )
    .expect("the clean nested source must run under real Lua 5.1");
    let obfuscated_output: String = run_source(
        &tc.lua,
        &dir,
        "vmify_nested_local_function_obfuscated",
        &obfuscated,
    )
    .expect("the nested-closure variant must run under real Lua 5.1");
    assert_eq!(
        expected, obfuscated_output,
        "the nested local function must preserve the real fixture's behavior"
    );

    let peeled: PeelResult = prometheus::peel(obfuscated.as_bytes(), &DeobfOptions::default())
        .expect(
            "prometheus peel must run on a dispatch leaf that constructs a nested local function",
        );
    assert!(
        peeled.fully_recovered,
        "a local declaration owned by a nested function must not make the enclosing dispatcher leaf refuse; residual_markers={:?}",
        peeled.residual_markers
    );
    let recovered: String =
        String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");
    let actual: String = run_source(
        &tc.lua,
        &dir,
        "vmify_nested_local_function_recovered",
        &recovered,
    )
    .expect("the recovered nested-closure variant must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "the recovered nested-closure variant must re-execute identically to the real original\n--- recovered ---\n{recovered}"
    );
}

const PROMETHEUS_VMIFY_UPVALUE_CLEAN: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_upvalue/clean.lua");
const PROMETHEUS_VMIFY_UPVALUE_OBFUSCATED: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_upvalue/obfuscated.lua");

#[test]
fn prometheus_vmify_upvalue_fixtures_already_agree() {
    let tc: Toolchain = require_toolchain("5.1");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_upvalue_fixture_clean",
        PROMETHEUS_VMIFY_UPVALUE_CLEAN,
    )
    .expect("clean fixture must run under real Lua 5.1");
    let actual: String = run_source(
        &tc.lua,
        &dir,
        "vmify_upvalue_fixture_obfuscated",
        PROMETHEUS_VMIFY_UPVALUE_OBFUSCATED,
    )
    .expect("real Prometheus Vmify output must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "the committed upvalue-closure obfuscated fixture must be a faithful Prometheus Vmify transform of the committed clean fixture"
    );
}

#[test]
fn prometheus_vmify_upvalue_closure_recovers_and_reexecutes_identically() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    let peeled: PeelResult = prometheus::peel(
        PROMETHEUS_VMIFY_UPVALUE_OBFUSCATED.as_bytes(),
        &DeobfOptions::default(),
    )
    .expect("prometheus peel must run on a real Vmify sample whose source captures an upvalue");
    assert!(
        peeled
            .passes_run
            .iter()
            .any(|p: &String| p == "prometheus-vmify-container-devirt"),
        "the Vmify container-devirt pass must run on the upvalue-closure sample; passes_run={:?}",
        peeled.passes_run
    );

    let recovered_src: String =
        String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_upvalue_orig",
        PROMETHEUS_VMIFY_UPVALUE_CLEAN,
    )
    .expect("the clean upvalue-closure source must run under real Lua 5.1");
    let actual: String = run_source(&tc.lua, &dir, "vmify_upvalue_recovered", &recovered_src)
        .expect("the recovered upvalue-closure source must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "a Vmify'd closure that captures a local must recover to source that re-executes identically under real Lua 5.1\n--- recovered ---\n{recovered_src}"
    );
}

#[test]
fn prometheus_vmify_refusal_reaches_a_consumer_surface_naming_its_cause() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let stripped: String = PROMETHEUS_VMIFY_UPVALUE_OBFUSCATED
        .replace("X[K]=X[K]-1 if X[K]==0 then X[K],x[K]=nil,nil end", "");
    assert_ne!(
        stripped, PROMETHEUS_VMIFY_UPVALUE_OBFUSCATED,
        "the reference-counted release helper must be present in the tracked fixture, otherwise \
         this case removes nothing and proves nothing"
    );

    let peeled: PeelResult = prometheus::peel(stripped.as_bytes(), &DeobfOptions::default())
        .expect("a sample whose capture helpers cannot be fingerprinted must still peel");
    assert!(
        !peeled.fully_recovered,
        "a chunk that captures a variable this pass cannot resolve must never report full \
         recovery; residual_markers={:?}",
        peeled.residual_markers
    );
    assert!(
        peeled.residual_markers.iter().any(|m: &String| m
            .contains("refused rather than emitted partly wrong")
            && m.contains("capture helpers could not be fingerprinted")),
        "the refusal reason must reach a consumer-visible surface naming the real cause rather \
         than being silently discarded; residual_markers={:?}",
        peeled.residual_markers
    );
    let emitted: String =
        String::from_utf8(peeled.deobfuscated).expect("emitted artifact must be UTF-8");
    assert!(
        !emitted.contains("prometheus-vmify:"),
        "a refused sample must not leave one of this pass's own stubs in the emitted artifact"
    );
    assert!(
        !emitted.contains("__vu"),
        "a refused sample must not emit a partly resolved captured variable\n--- emitted ---\n{emitted}"
    );
}

#[test]
fn prometheus_vmify_never_reports_full_recovery_while_emitting_an_unrecovered_closure() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let peeled: PeelResult = prometheus::peel(
        PROMETHEUS_VMIFY_UPVALUE_OBFUSCATED.as_bytes(),
        &DeobfOptions::default(),
    )
    .expect("prometheus peel must run on a real Vmify sample whose source captures an upvalue");
    let recovered_src: String =
        String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");
    let carries_stub: bool = recovered_src.contains("prometheus-vmify:");
    assert!(
        !(peeled.fully_recovered && carries_stub),
        "the pass reported full recovery while the emitted source still carries one of its own \
         not-recovered stubs, which is a false success: a consumer would run source that silently \
         differs from the original. residual_markers={:?}\n--- recovered ---\n{recovered_src}",
        peeled.residual_markers
    );
}

const PROMETHEUS_VMIFY_LOOP_CAPTURE_CLEAN: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_loop_capture/clean.lua");
const PROMETHEUS_VMIFY_LOOP_CAPTURE_OBFUSCATED: &str =
    include_str!("../../../corpus/lua/prometheus/vmify_loop_capture/obfuscated.lua");

#[test]
fn prometheus_vmify_loop_capture_fixtures_already_agree() {
    let tc: Toolchain = require_toolchain("5.1");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_loop_capture_fixture_clean",
        PROMETHEUS_VMIFY_LOOP_CAPTURE_CLEAN,
    )
    .expect("clean fixture must run under real Lua 5.1");
    let actual: String = run_source(
        &tc.lua,
        &dir,
        "vmify_loop_capture_fixture_obfuscated",
        PROMETHEUS_VMIFY_LOOP_CAPTURE_OBFUSCATED,
    )
    .expect("real Prometheus Vmify output must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "the committed loop-capture obfuscated fixture must be a faithful Prometheus Vmify transform of the committed clean fixture"
    );
    assert_eq!(
        expected.replace('\r', ""),
        "10\n20\n30\n",
        "the fixture must actually distinguish per-iteration capture from a shared variable; three identical lines would make the refusal it drives untestable"
    );
}

#[test]
fn prometheus_vmify_per_iteration_capture_recovers_and_reexecutes_identically() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    let peeled: PeelResult = prometheus::peel(
        PROMETHEUS_VMIFY_LOOP_CAPTURE_OBFUSCATED.as_bytes(),
        &DeobfOptions::default(),
    )
    .expect("prometheus peel must run on a real loop-capture sample");
    assert!(
        peeled
            .passes_run
            .iter()
            .any(|p: &String| p == "prometheus-vmify-container-devirt"),
        "the Vmify container-devirt pass must run on the loop-capture sample; passes_run={:?}, residual={:?}",
        peeled.passes_run,
        peeled.residual_markers
    );

    let recovered_src: String =
        String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(
        &tc.lua,
        &dir,
        "vmify_loop_capture_orig",
        PROMETHEUS_VMIFY_LOOP_CAPTURE_CLEAN,
    )
    .expect("the clean per-iteration-capture source must run under real Lua 5.1");
    let actual: String = run_source(
        &tc.lua,
        &dir,
        "vmify_loop_capture_recovered",
        &recovered_src,
    )
    .expect("the recovered per-iteration-capture source must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "each loop iteration captures a fresh variable, so a recovery that hoists one declaration \
         out of the loop prints the last value three times\n--- recovered ---\n{recovered_src}"
    );
}

#[test]
fn prometheus_vmify_loop_recovers_real_lua_control_flow_not_a_dispatch_state_machine() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult, prometheus};

    let tc: Toolchain = require_toolchain("5.1");
    for (name, obfuscated, clean) in [
        ("vmify", PROMETHEUS_VMIFY_OBFUSCATED, PROMETHEUS_VMIFY_CLEAN),
        (
            "vmify_loop_capture",
            PROMETHEUS_VMIFY_LOOP_CAPTURE_OBFUSCATED,
            PROMETHEUS_VMIFY_LOOP_CAPTURE_CLEAN,
        ),
    ] {
        let peeled: PeelResult = prometheus::peel(obfuscated.as_bytes(), &DeobfOptions::default())
            .unwrap_or_else(|e: disrobe_pass_lua::Error| panic!("{name}: peel must run: {e:?}"));
        let recovered_src: String =
            String::from_utf8(peeled.deobfuscated).expect("recovered source must be UTF-8");
        assert!(
            !recovered_src.contains("__pc"),
            "{name}: a guest loop must recover as real Lua control flow, not as an instruction-pointer state machine\n--- recovered ---\n{recovered_src}"
        );
        assert!(
            recovered_src.contains("while "),
            "{name}: the guest loop must appear as a Lua loop in the recovered source\n--- recovered ---\n{recovered_src}"
        );
        assert!(
            peeled.fully_recovered,
            "{name}: every dispatch leaf is structured, so recovery must report itself complete; residual_markers={:?}\n--- recovered ---\n{recovered_src}",
            peeled.residual_markers
        );

        let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
        let dir: PathBuf = scratch.path().to_path_buf();
        let expected: String = run_source(&tc.lua, &dir, &format!("{name}_orig"), clean)
            .unwrap_or_else(|| panic!("{name}: the clean source must run under real Lua 5.1"));
        let actual: String = run_source(&tc.lua, &dir, &format!("{name}_rec"), &recovered_src)
            .unwrap_or_else(|| {
                panic!(
                    "{name}: the recovered source must run under real Lua 5.1\n--- recovered ---\n{recovered_src}"
                )
            });
        assert_eq!(
            expected, actual,
            "{name}: structured loop recovery must re-execute identically to the real original\n--- recovered ---\n{recovered_src}"
        );
    }
}

#[test]
fn prometheus_vmify_obfuscated_and_clean_fixtures_already_agree() {
    let tc: Toolchain = require_toolchain("5.1");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let expected: String = run_source(&tc.lua, &dir, "vmify_fixture_clean", PROMETHEUS_VMIFY_CLEAN)
        .expect("clean fixture must run under real Lua 5.1");
    let actual: String = run_source(
        &tc.lua,
        &dir,
        "vmify_fixture_obfuscated",
        PROMETHEUS_VMIFY_OBFUSCATED,
    )
    .expect("real Prometheus Vmify output must run under real Lua 5.1");
    assert_eq!(
        expected, actual,
        "the committed obfuscated fixture must be a faithful Prometheus Vmify transform of the committed clean fixture"
    );
}
