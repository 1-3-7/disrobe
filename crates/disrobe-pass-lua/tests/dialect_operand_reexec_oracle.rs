#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::lua_toolchain::{Dialect, interpreter, toolchain};
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_lua::decompile::{DecompiledChunk, decompile_auto, decompile_chunk};
use disrobe_pass_lua::reader::common::{
    LuaChunk, LuaConstant, LuaDialect, LuaProto, LuaUpvalueName,
};
use disrobe_pass_lua::reader::read_auto;

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

const RUN_TIMEOUT: Duration = Duration::from_secs(20);

const UPVALUE_CAPTURE: &str = "upvalue_capture";
const LOADNIL_ABOVE_R0: &str = "loadnil_above_r0";
const CONSTRUCTOR_75: &str = "constructor_75";
const CONSTRUCTOR_25600: &str = "constructor_25600";
const SHAPES: [&str; 4] = [
    UPVALUE_CAPTURE,
    LOADNIL_ABOVE_R0,
    CONSTRUCTOR_75,
    CONSTRUCTOR_25600,
];

fn fixture_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    p.push("dialect_operands");
    p
}

fn fixture_source(name: &str) -> String {
    let path: PathBuf = fixture_dir().join(format!("{name}.lua"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture must be tracked: {}: {e}", path.display()))
}

fn fixture_bytes(file: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join(file);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture must be tracked: {}: {e}", path.display()))
}

fn scratch() -> ScratchDir {
    let seq: u64 = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_lua_dialect_operands-{}-{seq}", std::process::id());
    ScratchDir::create(&purpose).expect("create scratch dir")
}

fn compile(luac: &str, dir: &Path, name: &str, source: &str, strip: bool) -> Vec<u8> {
    let src_path: PathBuf = dir.join(format!("{name}.lua"));
    std::fs::write(&src_path, source).expect("write source");
    let out_path: PathBuf = dir.join(format!("{name}.luac"));
    let mut cmd: Command = Command::new(luac);
    if strip {
        cmd.arg("-s");
    }
    let status: ExitStatus = cmd
        .arg("-o")
        .arg(&out_path)
        .arg(&src_path)
        .status()
        .unwrap_or_else(|e| panic!("{luac} starts: {e}"));
    assert!(status.success(), "{luac} compiles {name}");
    std::fs::read(&out_path).expect("read bytecode")
}

fn run(lua: &str, dir: &Path, name: &str, source: &str) -> String {
    let script: PathBuf = dir.join(format!("{name}.run.lua"));
    std::fs::write(&script, source).expect("write script");
    let out_path: PathBuf = dir.join(format!("{name}.stdout.txt"));
    let err_path: PathBuf = dir.join(format!("{name}.stderr.txt"));
    let out_file: File = File::create(&out_path).expect("create stdout file");
    let err_file: File = File::create(&err_path).expect("create stderr file");
    let mut child = Command::new(lua)
        .arg(&script)
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .unwrap_or_else(|e| panic!("{lua} starts: {e}"));
    let deadline: Instant = Instant::now() + RUN_TIMEOUT;
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait().expect("poll lua") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{name}: {lua} did not finish within {RUN_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(15));
    };
    let stdout: String = std::fs::read_to_string(&out_path).expect("read stdout");
    let stderr: String = std::fs::read_to_string(&err_path).unwrap_or_default();
    assert!(
        status.success(),
        "{name}: {lua} failed with {status}\n--- stderr ---\n{stderr}\n--- script ---\n{source}"
    );
    stdout.replace("\r\n", "\n")
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
    assert!(start < end, "decompiled source has a _main body:\n{source}");
    lines[start..end].join("\n")
}

fn assert_same_output(lua: &str, name: &str, source: &str, recovered: &DecompiledChunk) {
    let dir_guard: ScratchDir = scratch();
    let dir: &Path = dir_guard.path();
    let body: String = strip_main_wrapper(&recovered.source);
    let expected: String = run(lua, dir, &format!("{name}.orig"), source);
    let actual: String = run(lua, dir, &format!("{name}.dec"), &body);
    assert_eq!(
        expected, actual,
        "{name}: the recovered program diverged from its source.\n--- recovered ---\n{body}"
    );
}

fn reexec_compiled(dialect: Dialect, name: &str, source: &str, strip: bool) {
    let Some((luac, lua)): Option<(String, String)> = toolchain(dialect) else {
        return;
    };
    let dir_guard: ScratchDir = scratch();
    let bytes: Vec<u8> = compile(&luac, dir_guard.path(), name, source, strip);
    let recovered: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
    assert_same_output(&lua, name, source, &recovered);
}

fn reexec_committed_chunk(suffix: &str, lifter: &str, name: &str) {
    let Some(lua): Option<String> = interpreter(Dialect::Lua54) else {
        return;
    };
    let source: String = fixture_source(name);
    let bytes: Vec<u8> = fixture_bytes(&format!("{name}.{suffix}.luac"));
    let recovered: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
    assert!(
        recovered.source.contains(lifter),
        "{name}.{suffix}.luac is read by the {lifter}:\n{}",
        recovered.source.lines().next().unwrap_or_default()
    );
    assert_same_output(&lua, &format!("{name}_{suffix}"), &source, &recovered);
}

fn generated_constructor(items: u32) -> String {
    let values: Vec<String> = (1..=items)
        .map(|i: u32| (i * 7 % 1000).to_string())
        .collect();
    format!(
        "local t = {{{}}}\n\
         local sum = 0\n\
         for i = 1, #t do sum = sum + t[i] end\n\
         print(#t, t[1], t[50], t[51], t[{items}], t[{}], sum)\n\
         print(t[256], t[257], t[300], t[301], t[25550], t[25551])\n",
        values.join(", "),
        items + 1,
    )
}

#[test]
fn lua51_closure_upvalue_pseudo_instructions_are_consumed() {
    let source: String = fixture_source(UPVALUE_CAPTURE);
    reexec_compiled(Dialect::Lua51, "upvalue_51", &source, false);
}

#[test]
fn stripped_lua51_closure_names_upvalues_from_pseudo_instructions() {
    let source: String = fixture_source(UPVALUE_CAPTURE);
    reexec_compiled(Dialect::Lua51, "upvalue_51_stripped", &source, true);
}

#[test]
fn glua_closure_upvalue_pseudo_instructions_are_consumed() {
    let Some((luac, lua)): Option<(String, String)> = toolchain(Dialect::Lua51) else {
        return;
    };
    let source: String = fixture_source(UPVALUE_CAPTURE);
    for strip in [false, true] {
        let dir_guard: ScratchDir = scratch();
        let bytes: Vec<u8> = compile(&luac, dir_guard.path(), "upvalue_glua", &source, strip);
        let mut chunk: LuaChunk = read_auto(&bytes).expect("read 5.1 chunk");
        chunk.dialect = LuaDialect::GLua;
        let recovered: DecompiledChunk = decompile_chunk(&chunk).expect("decompile");
        assert_same_output(&lua, "upvalue_glua", &source, &recovered);
    }
}

#[test]
fn lua54_closure_upvalues_reexecute() {
    let source: String = fixture_source(UPVALUE_CAPTURE);
    reexec_compiled(Dialect::Lua54, "upvalue_54", &source, false);
    reexec_compiled(Dialect::Lua54, "upvalue_54_stripped", &source, true);
}

#[test]
fn lua52_builds_of_every_shape_reexecute() {
    for name in SHAPES {
        reexec_committed_chunk("5_2", "lua 5.2 register lifter", name);
    }
}

#[test]
fn lua53_constructor_past_25550_items_reads_the_extraarg_block() {
    reexec_committed_chunk("5_3", "lua 5.3 register lifter", CONSTRUCTOR_25600);
}

#[test]
fn lua54_constructor_past_25550_items_reexecutes() {
    reexec_compiled(
        Dialect::Lua54,
        "ctor25600_54",
        &fixture_source(CONSTRUCTOR_25600),
        false,
    );
}

#[test]
fn lua51_and_lua54_loadnil_spans_reexecute() {
    let source: String = fixture_source(LOADNIL_ABOVE_R0);
    reexec_compiled(Dialect::Lua51, "loadnil_51", &source, false);
    reexec_compiled(Dialect::Lua51, "loadnil_51_stripped", &source, true);
    reexec_compiled(Dialect::Lua54, "loadnil_54", &source, false);
}

#[test]
fn lua53_loadnil_above_r0_reexecutes() {
    let Some(lua): Option<String> = interpreter(Dialect::Lua54) else {
        return;
    };
    let source: String = fixture_source(LOADNIL_ABOVE_R0);
    let bytes: Vec<u8> = fixture_bytes(&format!("{LOADNIL_ABOVE_R0}.5_3.luac"));
    let recovered: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
    assert!(
        recovered.source.contains("lua 5.3 register lifter"),
        "the committed chunk is read as Lua 5.3:\n{}",
        recovered.source
    );
    assert_same_output(&lua, "loadnil_53", &source, &recovered);
}

#[test]
fn lua53_upvalue_and_constructor_chunks_reexecute() {
    let Some(lua): Option<String> = interpreter(Dialect::Lua54) else {
        return;
    };
    for name in [UPVALUE_CAPTURE, CONSTRUCTOR_75] {
        let source: String = fixture_source(name);
        let bytes: Vec<u8> = fixture_bytes(&format!("{name}.5_3.luac"));
        let recovered: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
        assert_same_output(&lua, &format!("{name}_53"), &source, &recovered);
    }
}

#[test]
fn lua54_second_constructor_flush_keeps_its_item_offset() {
    let source: String = fixture_source(CONSTRUCTOR_75);
    reexec_compiled(Dialect::Lua54, "ctor75_54", &source, false);
}

#[test]
fn lua54_constructor_past_255_items_reads_the_extraarg_offset() {
    reexec_compiled(
        Dialect::Lua54,
        "ctor400_54",
        &generated_constructor(400),
        false,
    );
}

#[test]
fn lua51_constructor_past_511_blocks_reads_the_block_word() {
    reexec_compiled(
        Dialect::Lua51,
        "ctor25600_51",
        &fixture_source(CONSTRUCTOR_25600),
        false,
    );
    reexec_compiled(
        Dialect::Lua51,
        "ctor75_51",
        &fixture_source(CONSTRUCTOR_75),
        false,
    );
}

const fn abc(op: u32, a: u32, b: u32, c: u32) -> u32 {
    op | (a << 6) | (c << 14) | (b << 23)
}

const fn abx(op: u32, a: u32, bx: u32) -> u32 {
    op | (a << 6) | (bx << 14)
}

const fn ax(op: u32, value: u32) -> u32 {
    op | (value << 6)
}

const RK_CONSTANT: u32 = 256;

struct Ops52 {
    move_: u32,
    loadk: u32,
    loadnil: u32,
    gettabup: u32,
    gettable: u32,
    newtable: u32,
    call: u32,
    ret: u32,
    setlist: u32,
    extraarg: u32,
}

const OPS_52: Ops52 = Ops52 {
    move_: 0,
    loadk: 1,
    loadnil: 4,
    gettabup: 6,
    gettable: 7,
    newtable: 11,
    call: 29,
    ret: 31,
    setlist: 36,
    extraarg: 39,
};

const OPS_53: Ops52 = Ops52 {
    move_: 0,
    loadk: 1,
    loadnil: 4,
    gettabup: 6,
    gettable: 7,
    newtable: 11,
    call: 36,
    ret: 38,
    setlist: 43,
    extraarg: 46,
};

fn hand_chunk(dialect: LuaDialect, code: Vec<u32>, constants: Vec<LuaConstant>) -> LuaChunk {
    let version_byte: u8 = dialect.version_byte().expect("standard dialect");
    LuaChunk {
        dialect,
        version_byte,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 8,
        size_of_instruction: 4,
        size_of_lua_integer: 8,
        size_of_lua_number: 8,
        integral_number: false,
        main: LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 1,
            max_stack_size: 8,
            code,
            constants,
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: vec![LuaUpvalueName {
                name: "_ENV".to_owned(),
                descriptor: None,
            }],
        },
    }
}

const fn number(dialect: LuaDialect, value: i64) -> LuaConstant {
    if matches!(dialect, LuaDialect::Lua52) {
        LuaConstant::Number(value as f64)
    } else {
        LuaConstant::Integer(value)
    }
}

fn loadnil_chunk(dialect: LuaDialect, ops: &Ops52) -> LuaChunk {
    let code: Vec<u32> = vec![
        abx(ops.loadk, 0, 0),
        abx(ops.loadk, 1, 1),
        abx(ops.loadk, 2, 2),
        abc(ops.loadnil, 1, 1, 0),
        abc(ops.gettabup, 3, 0, RK_CONSTANT + 3),
        abc(ops.move_, 4, 0, 0),
        abc(ops.move_, 5, 1, 0),
        abc(ops.move_, 6, 2, 0),
        abc(ops.call, 3, 4, 1),
        abc(ops.ret, 0, 1, 0),
    ];
    let constants: Vec<LuaConstant> = vec![
        number(dialect, 1),
        number(dialect, 2),
        number(dialect, 3),
        LuaConstant::Str("print".to_owned()),
    ];
    hand_chunk(dialect, code, constants)
}

fn setlist_extraarg_chunk(dialect: LuaDialect, ops: &Ops52) -> LuaChunk {
    let code: Vec<u32> = vec![
        abc(ops.newtable, 0, 1, 0),
        abx(ops.loadk, 1, 0),
        abc(ops.setlist, 0, 1, 0),
        ax(ops.extraarg, 600),
        abc(ops.gettabup, 1, 0, RK_CONSTANT + 1),
        abc(ops.gettable, 2, 0, RK_CONSTANT + 2),
        abc(ops.gettable, 3, 0, RK_CONSTANT + 3),
        abc(ops.call, 1, 3, 1),
        abc(ops.ret, 0, 1, 0),
    ];
    let constants: Vec<LuaConstant> = vec![
        number(dialect, 42),
        LuaConstant::Str("print".to_owned()),
        number(dialect, 29_951),
        number(dialect, 1),
    ];
    hand_chunk(dialect, code, constants)
}

fn reexec_hand_chunk(name: &str, chunk: &LuaChunk, expected: &str) {
    let recovered: DecompiledChunk = decompile_chunk(chunk).expect("decompile");
    let body: String = strip_main_wrapper(&recovered.source);
    let Some(lua): Option<String> = interpreter(Dialect::Lua54) else {
        return;
    };
    let dir_guard: ScratchDir = scratch();
    let actual: String = run(&lua, dir_guard.path(), name, &body);
    assert_eq!(
        actual, expected,
        "{name}: the recovered program diverged from the encoded one.\n--- recovered ---\n{body}"
    );
}

#[test]
fn lua52_and_lua53_loadnil_spans_a_plus_b() {
    reexec_hand_chunk(
        "loadnil_52",
        &loadnil_chunk(LuaDialect::Lua52, &OPS_52),
        "1\tnil\tnil\n",
    );
    reexec_hand_chunk(
        "loadnil_53",
        &loadnil_chunk(LuaDialect::Lua53, &OPS_53),
        "1\tnil\tnil\n",
    );
}

#[test]
fn lua52_and_lua53_setlist_reads_the_extraarg_block() {
    reexec_hand_chunk(
        "setlist_52",
        &setlist_extraarg_chunk(LuaDialect::Lua52, &OPS_52),
        "42\tnil\n",
    );
    reexec_hand_chunk(
        "setlist_53",
        &setlist_extraarg_chunk(LuaDialect::Lua53, &OPS_53),
        "42\tnil\n",
    );
}
