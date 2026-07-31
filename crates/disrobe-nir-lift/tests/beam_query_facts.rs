#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_nir::{NirModule, NirOp};
use disrobe_nir_lift::lift_beam_module;
use disrobe_pass_beam::chunks::{Chunks, ImportEntry};
use disrobe_pass_beam::{
    BeamFile, CodeChunk, Disassembly, Instruction, Operand, Term, disassemble,
};

fn fixture_bytes() -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("beam");
    p.push("disasm_oracle");
    p.push("probe.beam");
    std::fs::read(&p).expect("committed probe BEAM fixture present")
}

fn lifted() -> NirModule {
    lift_beam_module(&fixture_bytes()).expect("lift BEAM module to NIR")
}

struct DecodedFacts {
    callees: BTreeSet<String>,
    constants: BTreeSet<String>,
    branch_count: usize,
}

const TEST_OPS: &[&str] = &[
    "is_lt",
    "is_ge",
    "is_eq",
    "is_ne",
    "is_eq_exact",
    "is_ne_exact",
    "is_integer",
    "is_float",
    "is_number",
    "is_atom",
    "is_pid",
    "is_reference",
    "is_port",
    "is_nil",
    "is_binary",
    "is_list",
    "is_nonempty_list",
    "is_tuple",
    "test_arity",
    "is_function",
    "is_boolean",
    "is_function2",
    "is_bitstr",
    "is_map",
    "is_tagged_tuple",
    "has_map_fields",
];

fn label_value(op: Option<&Operand>) -> Option<u32> {
    match op {
        Some(Operand::Label(l)) => Some(*l),
        Some(Operand::Literal(v)) => u32::try_from(*v).ok(),
        _ => None,
    }
}

fn value_u32(op: Option<&Operand>) -> u32 {
    match op {
        Some(Operand::Literal(v)) => u32::try_from(*v).map_or(0, |converted: u32| converted),
        Some(Operand::SignedInteger(v)) => u32::try_from(*v).map_or(0, |converted: u32| converted),
        Some(
            Operand::Atom(v)
            | Operand::XReg(v)
            | Operand::YReg(v)
            | Operand::Label(v)
            | Operand::Character(v)
            | Operand::LiteralIndex(v)
            | Operand::FpReg(v),
        ) => *v,
        _ => 0,
    }
}

fn label_to_mfa(
    instrs: &[Instruction],
    chunks: &Chunks,
) -> std::collections::BTreeMap<u32, String> {
    let mut map: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    let module: &str = chunks.atoms.module_name().map_or("?", |value: &str| value);
    let mut current: Option<String> = None;
    for instr in instrs {
        match instr.name {
            "func_info" => {
                let fun_atom: u32 = match instr.operands.get(1) {
                    Some(Operand::Atom(a)) => *a,
                    _ => 0,
                };
                let arity: u32 = match instr.operands.get(2) {
                    Some(Operand::Literal(v)) => {
                        u32::try_from(*v).map_or(0, |converted: u32| converted)
                    }
                    _ => 0,
                };
                let name: &str = chunks.atoms.get(fun_atom).map_or("?", |value: &str| value);
                current = Some(format!("{module}:{name}/{arity}"));
            }
            "label" => {
                if let (Some(mfa), Some(label)) = (&current, label_value(instr.operands.first())) {
                    map.insert(label, mfa.clone());
                }
            }
            _ => {}
        }
    }
    map
}

fn import_mfa(chunks: &Chunks, index: u32) -> Option<String> {
    let entry: &ImportEntry = chunks.imports.get(index as usize)?;
    let module: &str = chunks.atoms.get(entry.module_atom_index)?;
    let function: &str = chunks.atoms.get(entry.function_atom_index)?;
    Some(format!("{module}:{function}/{}", entry.arity))
}

fn bif_name(chunks: &Chunks, index: u32) -> Option<String> {
    let entry: &ImportEntry = chunks.imports.get(index as usize)?;
    chunks
        .atoms
        .get(entry.function_atom_index)
        .map(str::to_owned)
}

fn is_arithmetic_bif(name: &str) -> bool {
    matches!(
        name,
        "+" | "-" | "*" | "/" | "div" | "rem" | "band" | "bor" | "bxor" | "bsl" | "bsr" | "bnot"
    )
}

fn render_term(term: &Term) -> String {
    match term {
        Term::SmallInt(v) => v.to_string(),
        Term::Int(v) => v.to_string(),
        Term::Atom(a) => a.clone(),
        Term::Nil => "[]".to_owned(),
        Term::String(bytes) | Term::Binary(bytes) => core::str::from_utf8(bytes).map_or_else(
            |_| {
                bytes
                    .iter()
                    .map(|b: &u8| b.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            },
            str::to_owned,
        ),
        Term::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(render_term).collect();
            format!("{{{}}}", inner.join(","))
        }
        Term::List { elements, tail } => {
            let mut inner: Vec<String> = elements.iter().map(render_term).collect();
            if !matches!(**tail, Term::Nil) {
                inner.push(format!("|{}", render_term(tail)));
            }
            format!("[{}]", inner.join(","))
        }
        Term::Float(f) => f.to_string(),
        _ => "<term>".to_owned(),
    }
}

fn move_constant(chunks: &Chunks, op: Option<&Operand>) -> Option<String> {
    match op {
        Some(Operand::Atom(0)) => Some("nil".to_owned()),
        Some(Operand::Atom(index)) => chunks.atoms.get(*index).map(str::to_owned),
        Some(Operand::SignedInteger(v)) => Some(v.to_string()),
        Some(Operand::Literal(v)) => Some(v.to_string()),
        Some(Operand::Character(c)) => Some(c.to_string()),
        Some(Operand::LiteralIndex(index)) => chunks
            .literals
            .as_ref()
            .and_then(|c| c.literals.get(*index as usize))
            .map(render_term),
        _ => None,
    }
}

fn same_decoder_facts() -> DecodedFacts {
    let bytes: Vec<u8> = fixture_bytes();
    let beam: BeamFile = BeamFile::parse(&bytes).expect("parse probe beam");
    let chunks: &Chunks = &beam.chunks;
    let code: &CodeChunk = chunks.code.as_ref().expect("Code chunk");
    let disasm: Disassembly = disassemble(code).expect("disasm probe beam");
    let instrs: &[Instruction] = &disasm.instructions;
    let labels: std::collections::BTreeMap<u32, String> = label_to_mfa(instrs, chunks);

    let mut callees: BTreeSet<String> = BTreeSet::new();
    let mut constants: BTreeSet<String> = BTreeSet::new();
    let mut branch_count: usize = 0;

    for instr in instrs {
        let ops: &[Operand] = &instr.operands;
        match instr.name {
            "call" | "call_only" | "call_last" => {
                if let Some(label) = label_value(ops.get(1))
                    && let Some(mfa) = labels.get(&label)
                {
                    callees.insert(mfa.clone());
                }
            }
            "call_ext" | "call_ext_only" | "call_ext_last" => {
                if let Some(mfa) = import_mfa(chunks, value_u32(ops.get(1))) {
                    callees.insert(mfa);
                }
            }
            "gc_bif1" | "gc_bif2" | "gc_bif3" => {
                if let Some(name) = bif_name(chunks, value_u32(ops.get(2)))
                    && !is_arithmetic_bif(&name)
                {
                    callees.insert(name);
                }
            }
            "bif0" => {
                if let Some(name) = bif_name(chunks, value_u32(ops.first()))
                    && !is_arithmetic_bif(&name)
                {
                    callees.insert(name);
                }
            }
            "bif1" | "bif2" | "bif3" => {
                if let Some(name) = bif_name(chunks, value_u32(ops.get(1)))
                    && !is_arithmetic_bif(&name)
                {
                    callees.insert(name);
                }
            }
            "move" => {
                if let Some(value) = move_constant(chunks, ops.first()) {
                    constants.insert(value);
                }
            }
            "jump" | "select_val" | "select_tuple_arity" => branch_count += 1,
            name if TEST_OPS.contains(&name) => branch_count += 1,
            _ => {}
        }
    }

    DecodedFacts {
        callees,
        constants,
        branch_count,
    }
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

fn lifted_constants(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if ins.op == NirOp::Const
                && ins.mnemonic == "move"
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
fn input_is_a_real_compiled_beam_module() {
    let bytes: Vec<u8> = fixture_bytes();
    assert_eq!(&bytes[..4], b"FOR1", "real IFF container magic");
    assert_eq!(&bytes[8..12], b"BEAM", "real BEAM form type");
    let beam: BeamFile = BeamFile::parse(&bytes).expect("parse");
    assert_eq!(beam.module_name(), Some("probe"));
    let code: &CodeChunk = beam.chunks.code.as_ref().expect("Code chunk");
    assert!(code.num_functions >= 7, "probe exports several functions");
    assert!(
        !beam.chunks.imports.is_empty(),
        "probe imports external functions"
    );
}

#[test]
fn lifted_callees_equal_a_direct_walk_of_the_same_beam_decode() {
    let decoded: DecodedFacts = same_decoder_facts();
    let lifted: BTreeSet<String> = lifted_callees(&lifted());
    assert!(
        !decoded.callees.is_empty(),
        "the source issues real local and external calls"
    );
    assert_eq!(
        lifted, decoded.callees,
        "lifted Mir call targets must equal the BEAM resolved MFA set exactly"
    );
    for expected in ["probe:fac/1", "erlang:++/2", "lists:foldl/3"] {
        assert!(
            decoded.callees.iter().any(|c: &String| c == expected),
            "the source calls {expected}: {:?}",
            decoded.callees
        );
    }
}

#[test]
fn lifted_constants_equal_a_direct_walk_of_the_same_beam_decode() {
    let decoded: DecodedFacts = same_decoder_facts();
    let lifted: BTreeSet<String> = lifted_constants(&lifted());
    assert!(
        !decoded.constants.is_empty(),
        "the source moves atom and literal constants into registers"
    );
    assert_eq!(
        lifted, decoded.constants,
        "lifted Mir move constants must equal the BEAM move-operand literal set exactly"
    );
    for expected in ["integer", "atom", "other", "default"] {
        assert!(
            decoded.constants.iter().any(|c: &String| c == expected),
            "the source moves atom {expected}: {:?}",
            decoded.constants
        );
    }
    assert!(
        decoded.constants.iter().any(|c: &String| c == "hello "),
        "greet/1 moves the literal string \"hello \": {:?}",
        decoded.constants
    );
}

#[test]
fn lifted_branch_count_equals_a_direct_walk_of_the_same_beam_decode() {
    let decoded: DecodedFacts = same_decoder_facts();
    assert!(
        decoded.branch_count >= 4,
        "fac/classify/mapkv compile to several type tests"
    );
    assert_eq!(
        lifted_branch_count(&lifted()),
        decoded.branch_count,
        "lifted Mir branch/cond-branch count must equal the BEAM test/jump/select count exactly"
    );
}

#[test]
fn conditional_branch_targets_resolve_to_real_lifted_instructions() {
    let nir: NirModule = lifted();
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
                    nir.functions
                        .iter()
                        .flat_map(|g| g.instructions.iter())
                        .any(|other| other.address == target),
                    "branch at {:#x} must target a real lifted instruction, got {target:#x}",
                    ins.address
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 3,
        "the fixture has resolvable type-test branch targets"
    );
}

#[test]
fn module_lifts_with_the_beam_lang_tag_and_returns() {
    let nir: NirModule = lifted();
    assert_eq!(nir.lang, disrobe_nir::SourceLang::Beam);
    let fac: &disrobe_nir::NirFunction = nir
        .functions
        .iter()
        .find(|f| f.name == "fac/1")
        .expect("fac/1 lifted");
    assert!(fac.instructions.iter().any(|i| i.op == NirOp::Return));
    assert!(
        nir.functions.iter().any(|f| f.name == "add/2"),
        "add/2 lifted"
    );
}

#[test]
fn lift_is_deterministic() {
    assert_eq!(lifted(), lifted(), "the BEAM lift must be byte-stable");
}
