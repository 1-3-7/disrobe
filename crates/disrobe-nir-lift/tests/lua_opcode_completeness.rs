#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::{lift_lua_chunk, lua_function_address};
use disrobe_pass_lua::read_auto;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaDialect, LuaProto};

const COMMITTED_FIXTURES: [&str; 8] = [
    "hello.5_1.luac",
    "hello.5_2.luac",
    "hello.5_3.luac",
    "hello.5_4.luac",
    "edge_cases.5_1.luac",
    "edge_cases.5_2.luac",
    "edge_cases.5_3.luac",
    "edge_cases.5_4.luac",
];

const BROAD_FIXTURES: [&str; 4] = [
    "edge_cases.5_1.luac",
    "edge_cases.5_2.luac",
    "edge_cases.5_3.luac",
    "edge_cases.5_4.luac",
];

fn fixture_path(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("lua");
    path.push("luac");
    path.push(name);
    path
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name))
        .unwrap_or_else(|e| panic!("committed luac fixture {name} present: {e}"))
}

fn opcode_byte(raw: u32, dialect: LuaDialect) -> u8 {
    let mask: u32 = if dialect == LuaDialect::Lua54 {
        0x7F
    } else {
        0x3F
    };
    (raw & mask) as u8
}

fn proto_by_address(chunk: &LuaChunk) -> BTreeMap<u64, &LuaProto> {
    fn walk<'a>(proto: &'a LuaProto, next: &mut u32, out: &mut BTreeMap<u64, &'a LuaProto>) {
        let index: u32 = *next;
        *next = next.saturating_add(1);
        out.insert(lua_function_address(index), proto);
        for sub in &proto.protos {
            walk(sub, next, out);
        }
    }
    let mut out: BTreeMap<u64, &LuaProto> = BTreeMap::new();
    let mut next: u32 = 0;
    walk(&chunk.main, &mut next, &mut out);
    out
}

#[derive(Debug, Default)]
struct NirStats {
    total: usize,
    unmodeled: usize,
    nop: usize,
    opcodes: BTreeSet<u8>,
    mnemonics: BTreeSet<String>,
}

fn analyze(name: &str) -> NirStats {
    let bytes: Vec<u8> = fixture_bytes(name);
    let module: NirModule = lift_lua_chunk(&bytes).expect("lift lua chunk to NIR");
    let chunk: LuaChunk = read_auto(&bytes).expect("decode lua chunk");
    let dialect: LuaDialect = chunk.dialect;
    let protos: BTreeMap<u64, &LuaProto> = proto_by_address(&chunk);

    let mut stats: NirStats = NirStats::default();
    for function in &module.functions {
        let function: &NirFunction = function;
        let proto: &LuaProto = protos
            .get(&function.address)
            .copied()
            .expect("a decoded proto for every lifted function base");
        assert_eq!(
            function.instructions.len(),
            proto.code.len(),
            "one lifted instruction per bytecode word for {}",
            function.name
        );
        for (pc, instr) in function.instructions.iter().enumerate() {
            let instr: &NirInstr = instr;
            let raw: u32 = proto.code.get(pc).copied().unwrap_or_default();
            let opcode: u8 = opcode_byte(raw, dialect);
            let offset: u32 = u32::try_from(pc).unwrap_or(u32::MAX);
            assert_eq!(
                instr.address,
                function.address.saturating_add(u64::from(offset)),
                "lifted address must track the bytecode index for {}",
                function.name
            );
            stats.total += 1;
            stats.opcodes.insert(opcode);
            stats.mnemonics.insert(instr.mnemonic.clone());
            match &instr.op {
                NirOp::Nop => stats.nop += 1,
                NirOp::Unmodeled {
                    opcode: carried,
                    offset: carried_offset,
                } => {
                    assert_eq!(
                        *carried, opcode,
                        "Unmodeled must carry the real opcode for {} at pc {pc}",
                        function.name
                    );
                    assert_eq!(
                        *carried_offset, offset,
                        "Unmodeled must carry the real offset for {} at pc {pc}",
                        function.name
                    );
                    stats.unmodeled += 1;
                }
                _ => {}
            }
        }
    }
    stats
}

#[test]
fn committed_luac_fixtures_surface_unmodeled_without_silent_nop() {
    for name in COMMITTED_FIXTURES {
        let stats: NirStats = analyze(name);
        assert!(stats.total > 0, "{name} must lift to instructions");
        assert_eq!(
            stats.nop, 0,
            "no real lua opcode may silently lift to Nop in {name}: {stats:?}"
        );
    }
    for name in BROAD_FIXTURES {
        let stats: NirStats = analyze(name);
        assert!(
            stats.unmodeled >= 1,
            "{name} exercises opcodes disrobe surfaces as Unmodeled: {stats:?}"
        );
        assert!(
            stats.opcodes.len() >= 15,
            "{name} opcode range must be non-vacuous: {} distinct",
            stats.opcodes.len()
        );
    }
}

#[test]
fn move_opcode_surfaces_as_unmodeled_not_nop() {
    let bytes: Vec<u8> = fixture_bytes("edge_cases.5_1.luac");
    let module: NirModule = lift_lua_chunk(&bytes).expect("lift lua chunk to NIR");
    let mut saw_move: bool = false;
    for function in &module.functions {
        for instr in &function.instructions {
            let instr: &NirInstr = instr;
            if instr.mnemonic == "MOVE" {
                saw_move = true;
                assert!(
                    instr.op.is_unmodeled(),
                    "a real MOVE must never collapse to a silent Nop"
                );
                assert_eq!(
                    instr.op.unmodeled_opcode(),
                    Some(0),
                    "MOVE (opcode 0) must surface as Unmodeled carrying its real opcode"
                );
            }
        }
    }
    assert!(saw_move, "edge_cases exercises MOVE");
}

fn tool_version() -> Option<(u32, u32, &'static str)> {
    let output: Output = Command::new("luac").arg("-v").output().ok()?;
    let mut text: String = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    for (needle, major, minor, suffix) in [
        ("Lua 5.1", 5u32, 1u32, "5_1"),
        ("Lua 5.2", 5u32, 2u32, "5_2"),
        ("Lua 5.3", 5u32, 3u32, "5_3"),
        ("Lua 5.4", 5u32, 4u32, "5_4"),
    ] {
        if text.contains(needle) {
            return Some((major, minor, suffix));
        }
    }
    None
}

fn parse_listing_line(trimmed: &str) -> Option<(u32, String)> {
    let mut tokens: std::str::SplitWhitespace<'_> = trimmed.split_whitespace();
    let number: u32 = tokens.next()?.parse().ok()?;
    let line_token: &str = tokens.next()?;
    if !line_token.starts_with('[') {
        return None;
    }
    let mnemonic: &str = tokens.next()?;
    if mnemonic.is_empty()
        || !mnemonic
            .bytes()
            .all(|b: u8| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return None;
    }
    Some((number.saturating_sub(1), mnemonic.to_owned()))
}

fn luac_offset_mnemonics(listing: &str) -> Vec<Vec<(u32, String)>> {
    let mut functions: Vec<Vec<(u32, String)>> = Vec::new();
    let mut current: Option<Vec<(u32, String)>> = None;
    for line in listing.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with("main <") || trimmed.starts_with("function <") {
            if let Some(done) = current.replace(Vec::new()) {
                functions.push(done);
            }
            continue;
        }
        let Some(pair): Option<(u32, String)> = parse_listing_line(trimmed) else {
            continue;
        };
        if let Some(stream) = current.as_mut() {
            stream.push(pair);
        }
    }
    if let Some(done) = current.take() {
        functions.push(done);
    }
    functions.sort();
    functions
}

fn disrobe_offset_mnemonics(module: &NirModule) -> Vec<Vec<(u32, String)>> {
    let mut streams: Vec<Vec<(u32, String)>> = module
        .functions
        .iter()
        .map(|function: &NirFunction| {
            function
                .instructions
                .iter()
                .map(|instr: &NirInstr| {
                    let offset: u32 = u32::try_from(instr.address.saturating_sub(function.address))
                        .unwrap_or(u32::MAX);
                    (offset, instr.mnemonic.clone())
                })
                .collect::<Vec<(u32, String)>>()
        })
        .collect();
    streams.sort();
    streams
}

fn expected_mnemonics(suffix: &str) -> &'static [&'static str] {
    const CORE: [&str; 12] = [
        "MOVE", "LOADK", "NEWTABLE", "GETTABLE", "SETTABLE", "CONCAT", "JMP", "CALL", "RETURN",
        "FORLOOP", "FORPREP", "CLOSURE",
    ];
    match suffix {
        "5_1" => &[
            "MOVE",
            "LOADK",
            "GETGLOBAL",
            "GETUPVAL",
            "GETTABLE",
            "SETTABLE",
            "NEWTABLE",
            "SELF",
            "ADD",
            "SUB",
            "MUL",
            "CONCAT",
            "JMP",
            "CALL",
            "TAILCALL",
            "RETURN",
            "FORLOOP",
            "FORPREP",
            "CLOSURE",
            "VARARG",
        ],
        "5_2" | "5_3" => &[
            "MOVE", "LOADK", "GETTABUP", "GETUPVAL", "GETTABLE", "SETTABLE", "NEWTABLE", "SELF",
            "ADD", "CONCAT", "JMP", "CALL", "RETURN", "FORLOOP", "FORPREP", "CLOSURE", "VARARG",
        ],
        "5_4" => &[
            "MOVE",
            "LOADK",
            "GETTABUP",
            "NEWTABLE",
            "SELF",
            "ADD",
            "CONCAT",
            "JMP",
            "CALL",
            "RETURN",
            "FORLOOP",
            "FORPREP",
            "CLOSURE",
            "VARARG",
            "VARARGPREP",
        ],
        _ => &CORE,
    }
}

#[test]
fn lua_lift_agrees_with_luac_and_surfaces_unmodeled_opcodes() {
    let Some((major, minor, suffix)): Option<(u32, u32, &'static str)> = tool_version() else {
        eprintln!("skipping luac agreement: no supported luac (5.1-5.4) on PATH");
        return;
    };

    let scratch: PathBuf =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("lua_opcode_completeness");
    std::fs::create_dir_all(&scratch).expect("create scratch dir");

    for stem in ["hello", "edge_cases"] {
        let name: String = format!("{stem}.{suffix}.luac");
        let path: PathBuf = fixture_path(&name);
        let listing: Output = Command::new("luac")
            .arg("-l")
            .arg(&path)
            .current_dir(&scratch)
            .output()
            .expect("run luac -l");
        assert!(
            listing.status.success(),
            "luac -l failed for {name}: {}",
            String::from_utf8_lossy(&listing.stderr)
        );
        let listing_text: String = String::from_utf8_lossy(&listing.stdout).into_owned();
        let expected: Vec<Vec<(u32, String)>> = luac_offset_mnemonics(&listing_text);
        assert!(
            !expected.is_empty(),
            "luac -l must decode instructions for {name}"
        );

        let module: NirModule = lift_lua_chunk(&fixture_bytes(&name)).expect("lift lua chunk");
        let lifted: Vec<Vec<(u32, String)>> = disrobe_offset_mnemonics(&module);
        assert_eq!(
            lifted, expected,
            "disrobe lifted (offset, mnemonic) stream must equal luac -l for {name} (Lua {major}.{minor})"
        );
    }

    let stats: NirStats = analyze(&format!("edge_cases.{suffix}.luac"));
    assert!(
        stats.unmodeled >= 1,
        "the graded chunk must surface unmodeled opcodes: {stats:?}"
    );
    assert!(
        stats.opcodes.len() >= 15,
        "the graded opcode range must be non-vacuous: {} distinct",
        stats.opcodes.len()
    );
    for mnemonic in expected_mnemonics(suffix) {
        assert!(
            stats.mnemonics.contains(*mnemonic),
            "the graded opcode range must include {mnemonic}: {:?}",
            stats.mnemonics
        );
    }
}
