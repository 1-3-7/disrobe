#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_nir::{NirModule, NirOp, SourceLang};
use disrobe_nir_lift::lift_lua_chunk;
use disrobe_pass_lua::decompile::opcode::{Decoded, Op, decode};
use disrobe_pass_lua::read_auto;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant, LuaDialect, LuaProto};

fn fixture_bytes(name: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("lua");
    p.push("luac");
    p.push(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("committed luac fixture {name} present: {e}"))
}

fn lifted(name: &str) -> NirModule {
    lift_lua_chunk(&fixture_bytes(name)).expect("lift lua chunk to NIR")
}

struct DecodedFacts {
    callees: BTreeSet<String>,
    string_constants: BTreeSet<String>,
    accesses: BTreeSet<String>,
    branch_count: usize,
}

fn const_string(proto: &LuaProto, index: u32) -> Option<String> {
    match proto.constants.get(index as usize)? {
        LuaConstant::Str(s) => Some(s.clone()),
        _ => None,
    }
}

const fn is_compare_skip(op: Op) -> bool {
    matches!(
        op,
        Op::Eq
            | Op::Lt
            | Op::Le
            | Op::EqK
            | Op::EqI
            | Op::LtI
            | Op::LeI
            | Op::GtI
            | Op::GeI
            | Op::Test
            | Op::TestSet
    )
}

fn access_name(proto: &LuaProto, op: Op, d: &Decoded) -> Option<String> {
    match op {
        Op::GetGlobal | Op::SetGlobal => const_string(proto, d.bx),
        Op::GetField | Op::SetField | Op::Self_ | Op::GetTabUp => const_string(proto, d.c),
        Op::SetTabUp => const_string(proto, d.b),
        _ => None,
    }
}

fn set_name(slots: &mut [Option<String>], reg: u32, name: Option<String>) {
    if let Some(slot) = slots.get_mut(reg as usize) {
        *slot = name;
    }
}

fn get_name(slots: &[Option<String>], reg: u32) -> Option<String> {
    slots.get(reg as usize).and_then(Clone::clone)
}

fn scan_proto(proto: &LuaProto, dialect: LuaDialect, facts: &mut DecodedFacts) {
    let decoded: Vec<Decoded> = proto.code.iter().map(|raw| decode(*raw, dialect)).collect();
    let mut names: Vec<Option<String>> = vec![None; 256];

    for d in &decoded {
        match d.op {
            Op::Jmp | Op::ForPrep | Op::ForLoop | Op::TForLoop | Op::TForCall => {
                facts.branch_count += 1;
            }
            _ if is_compare_skip(d.op) => facts.branch_count += 1,
            _ => {}
        }
        match d.op {
            Op::GetGlobal | Op::GetField | Op::Self_ | Op::GetTabUp => {
                if let Some(n) = access_name(proto, d.op, d) {
                    facts.accesses.insert(n.clone());
                    set_name(&mut names, d.a, Some(n));
                } else {
                    set_name(&mut names, d.a, None);
                }
            }
            Op::SetGlobal | Op::SetField | Op::SetTabUp => {
                if let Some(n) = access_name(proto, d.op, d) {
                    facts.accesses.insert(n);
                }
            }
            Op::LoadK | Op::LoadKx => {
                if let Some(LuaConstant::Str(s)) = proto.constants.get(d.bx as usize) {
                    facts.string_constants.insert(s.clone());
                    set_name(&mut names, d.a, Some(s.clone()));
                } else {
                    set_name(&mut names, d.a, None);
                }
            }
            Op::Move => {
                let src: Option<String> = get_name(&names, d.b);
                set_name(&mut names, d.a, src);
            }
            Op::Call | Op::TailCall => {
                if let Some(n) = get_name(&names, d.a) {
                    facts.callees.insert(n);
                }
                set_name(&mut names, d.a, None);
            }
            _ => set_name(&mut names, d.a, None),
        }
    }

    for sub in &proto.protos {
        scan_proto(sub, dialect, facts);
    }
}

fn same_decoder_facts(name: &str) -> DecodedFacts {
    let chunk: LuaChunk = read_auto(&fixture_bytes(name)).expect("decode lua chunk");
    let mut facts: DecodedFacts = DecodedFacts {
        callees: BTreeSet::new(),
        string_constants: BTreeSet::new(),
        accesses: BTreeSet::new(),
        branch_count: 0,
    };
    scan_proto(&chunk.main, chunk.dialect, &mut facts);
    facts
}

fn lifted_callees(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Call { .. })
                && let Some(name) = ins.operands.first()
            {
                out.insert(name.clone());
            }
        }
    }
    out
}

fn lifted_string_constants(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if ins.op == NirOp::Const
                && matches!(ins.mnemonic.as_str(), "LOADK" | "LOADKX")
                && let Some(v) = ins.operands.first()
            {
                out.insert(v.clone());
            }
        }
    }
    out
}

fn lifted_accesses(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Load | NirOp::Store)
                && matches!(
                    ins.mnemonic.as_str(),
                    "GETGLOBAL"
                        | "SETGLOBAL"
                        | "GETFIELD"
                        | "SETFIELD"
                        | "SELF"
                        | "GETTABUP"
                        | "SETTABUP"
                )
                && let Some(v) = ins.operands.first()
            {
                out.insert(v.clone());
            }
        }
    }
    out
}

fn lifted_branch_count(nir: &NirModule) -> usize {
    nir.functions
        .iter()
        .flat_map(|f| f.instructions.iter())
        .filter(|ins| matches!(ins.op, NirOp::Branch { .. } | NirOp::CondBranch { .. }))
        .count()
}

#[test]
fn input_is_a_real_compiled_lua_image() {
    let bytes: Vec<u8> = fixture_bytes("hello.5_4.luac");
    assert_eq!(
        &bytes[..4],
        &[0x1B, b'L', b'u', b'a'],
        "real luac signature"
    );
    let chunk: LuaChunk = read_auto(&bytes).expect("decode");
    assert_eq!(chunk.dialect, LuaDialect::Lua54);
    assert!(
        !chunk.main.code.is_empty(),
        "the compiled chunk has real instructions"
    );
}

#[test]
fn lifted_callees_equal_a_direct_walk_of_the_same_lua_decode() {
    let decoded: DecodedFacts = same_decoder_facts("hello.5_4.luac");
    let lifted: BTreeSet<String> = lifted_callees(&lifted("hello.5_4.luac"));
    assert!(
        !decoded.callees.is_empty(),
        "hello.lua issues a real global call"
    );
    assert_eq!(
        lifted, decoded.callees,
        "lifted Mir call targets must equal the directly re-walked callee-name set exactly"
    );
    assert!(
        decoded.callees.iter().any(|c: &String| c == "print"),
        "hello.lua calls print: {:?}",
        decoded.callees
    );
}

#[test]
fn lifted_string_constants_equal_a_direct_walk_of_the_same_lua_decode() {
    let decoded: DecodedFacts = same_decoder_facts("hello.5_4.luac");
    let lifted: BTreeSet<String> = lifted_string_constants(&lifted("hello.5_4.luac"));
    assert!(
        !decoded.string_constants.is_empty(),
        "hello.lua has at least one string literal"
    );
    assert_eq!(
        lifted, decoded.string_constants,
        "lifted Mir LOADK string operands must equal the directly re-walked string-constant set exactly"
    );
    assert!(
        decoded
            .string_constants
            .iter()
            .any(|s: &String| s == "hello world"),
        "hello.lua loads the literal \"hello world\": {:?}",
        decoded.string_constants
    );
}

#[test]
fn lifted_accesses_equal_a_direct_walk_of_the_same_lua_decode() {
    let decoded: DecodedFacts = same_decoder_facts("edge_cases.5_4.luac");
    let lifted: BTreeSet<String> = lifted_accesses(&lifted("edge_cases.5_4.luac"));
    assert!(
        !decoded.accesses.is_empty(),
        "edge_cases touches many global/field names"
    );
    assert_eq!(
        lifted, decoded.accesses,
        "lifted Mir global/field accesses must equal the directly re-walked access-name set exactly"
    );
    for expected in ["math", "table", "string"] {
        assert!(
            decoded.accesses.iter().any(|s: &String| s == expected),
            "edge_cases references the {expected} library: {:?}",
            decoded.accesses
        );
    }
}

#[test]
fn lifted_branch_count_equals_a_direct_walk_of_the_same_lua_decode() {
    let decoded: DecodedFacts = same_decoder_facts("edge_cases.5_4.luac");
    assert!(
        decoded.branch_count >= 50,
        "edge_cases compiles to many branch and loop-control instructions: {}",
        decoded.branch_count
    );
    assert_eq!(
        lifted_branch_count(&lifted("edge_cases.5_4.luac")),
        decoded.branch_count,
        "lifted Mir branch/cond-branch count must equal the directly re-walked branch-instruction count exactly"
    );
}

#[test]
fn lua51_dialect_also_lifts_and_resolves_print() {
    let decoded: DecodedFacts = same_decoder_facts("hello.5_1.luac");
    let nir: NirModule = lifted("hello.5_1.luac");
    assert_eq!(nir.lang, SourceLang::Lua);
    assert_eq!(
        lifted_callees(&nir),
        decoded.callees,
        "the 5.1 GETGLOBAL path resolves the same callee set as a direct walk of the same decode"
    );
    assert!(decoded.callees.iter().any(|c: &String| c == "print"));
    assert_eq!(
        lifted_string_constants(&nir),
        decoded.string_constants,
        "5.1 string constants match a direct walk of the same decode"
    );
}

#[test]
fn branch_targets_resolve_to_real_lifted_instructions() {
    let nir: NirModule = lifted("edge_cases.5_4.luac");
    let mut checked: usize = 0;
    for f in &nir.functions {
        for ins in &f.instructions {
            if let NirOp::CondBranch {
                target: Some(target),
            }
            | NirOp::Branch {
                target: Some(target),
            } = ins.op
            {
                assert!(
                    f.instructions.iter().any(|other| other.address == target),
                    "branch at {:#x} must target a real lifted instruction in the same proto, got {target:#x}",
                    ins.address
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 10,
        "edge_cases has many resolvable jump and conditional-branch targets, got {checked}"
    );
}

#[test]
fn main_proto_lifts_as_an_exported_function_ending_in_return() {
    let nir: NirModule = lifted("hello.5_4.luac");
    let main: &disrobe_nir::NirFunction = nir
        .functions
        .iter()
        .find(|f| f.name == "<main>")
        .expect("main proto present");
    assert!(main.is_export, "the main chunk is the module entry");
    assert!(main.instructions.iter().any(|i| i.op == NirOp::Return));
}

#[test]
fn lift_is_deterministic() {
    assert_eq!(
        lifted("edge_cases.5_4.luac"),
        lifted("edge_cases.5_4.luac"),
        "the lua lift must be byte-stable"
    );
}
