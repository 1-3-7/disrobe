#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_nir::{NirModule, NirOp};
use disrobe_nir_lift::lift_dotnet_pe;
use disrobe_pass_dotnet::{
    ClrHeader, FlowControl, Instruction, MetadataRoot, MethodBody, OperandValue, PeImage, Resolver,
    parse as parse_pe, parse_clr_header, parse_metadata_root, parse_method_body,
};
use disrobe_query::{
    CallSiteMatch, Function, FunctionMatch, Module, Query, QueryResult, XrefMatch, run,
};

const CIL_PROBE: &[u8] = include_bytes!("../../../corpus/dotnet/cil/CilProbe.dll");

fn lifted_nir() -> NirModule {
    lift_dotnet_pe(CIL_PROBE).expect("lift .NET PE to NIR")
}

fn lifted_module() -> Module {
    Module::from_nir(&lifted_nir())
}

fn function_names(module: &Module) -> Vec<String> {
    match run(module, &Query::Functions) {
        QueryResult::Functions { matches } => {
            matches.into_iter().map(|m: FunctionMatch| m.name).collect()
        }
        other => panic!("expected Functions, got {other:?}"),
    }
}

fn calls_to(module: &Module, target: &str) -> Vec<CallSiteMatch> {
    match run(
        module,
        &Query::CallsTo {
            target: target.to_owned(),
        },
    ) {
        QueryResult::CallsTo { matches, .. } => matches,
        other => panic!("expected CallsTo, got {other:?}"),
    }
}

fn xrefs_to(module: &Module, symbol: &str) -> Vec<XrefMatch> {
    match run(
        module,
        &Query::XrefsTo {
            symbol: symbol.to_owned(),
        },
    ) {
        QueryResult::XrefsTo { matches, .. } => matches,
        other => panic!("expected XrefsTo, got {other:?}"),
    }
}

struct OracleFacts {
    callees: BTreeSet<String>,
    ldstr_values: BTreeSet<String>,
    field_accesses: BTreeSet<String>,
    branch_edges: usize,
}

fn independent_oracle() -> OracleFacts {
    let pe: PeImage = parse_pe(CIL_PROBE).expect("pe");
    let clr: ClrHeader = parse_clr_header(CIL_PROBE, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(CIL_PROBE, &pe, &clr).expect("root");
    let resolver: Resolver = Resolver::build(CIL_PROBE, &pe, &clr, &root).expect("resolver");

    let mut callees: BTreeSet<String> = BTreeSet::new();
    let mut ldstr_values: BTreeSet<String> = BTreeSet::new();
    let mut field_accesses: BTreeSet<String> = BTreeSet::new();
    let mut branch_edges: usize = 0;

    for (_, _, rva) in resolver.methods_with_bodies() {
        let slice: &[u8] = pe.slice_at_rva_to_end(CIL_PROBE, rva).expect("body");
        let body: MethodBody = match parse_method_body(slice) {
            Ok(body) => body,
            Err(_) => continue,
        };
        for insn in &body.instructions {
            let i: &Instruction = insn;
            match i.flow {
                FlowControl::Call => {
                    if let OperandValue::Token(token) = i.operand {
                        callees.insert(resolver.resolve_token(token));
                    }
                }
                FlowControl::Branch | FlowControl::CondBranch => {
                    branch_edges += 1;
                }
                _ => {}
            }
            if i.name == "ldstr"
                && let OperandValue::Token(token) = i.operand
            {
                ldstr_values.insert(resolver.resolve_token(token));
            }
            if matches!(i.name.as_str(), "ldfld" | "ldsfld" | "stfld" | "stsfld")
                && let OperandValue::Token(token) = i.operand
            {
                field_accesses.insert(resolver.resolve_token(token));
            }
        }
    }

    OracleFacts {
        callees,
        ldstr_values,
        field_accesses,
        branch_edges,
    }
}

fn lifted_callees(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Call { .. } | NirOp::IndirectCall)
                && let Some(name) = ins.operands.first()
            {
                out.insert(name.clone());
            }
        }
    }
    out
}

fn lifted_consts(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if ins.op == NirOp::Const
                && ins.mnemonic == "ldstr"
                && let Some(v) = ins.operands.first()
            {
                out.insert(v.clone());
            }
        }
    }
    out
}

fn lifted_field_accesses(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Load | NirOp::Store)
                && matches!(
                    ins.mnemonic.as_str(),
                    "ldfld" | "ldsfld" | "stfld" | "stsfld"
                )
                && let Some(name) = ins.operands.first()
            {
                out.insert(name.clone());
            }
        }
    }
    out
}

fn lifted_branch_edges(nir: &NirModule) -> usize {
    nir.functions
        .iter()
        .flat_map(|f| f.instructions.iter())
        .filter(|ins| matches!(ins.op, NirOp::Branch { .. } | NirOp::CondBranch { .. }))
        .count()
}

#[test]
fn methods_are_recovered_as_functions_with_visibility() {
    let module: Module = lifted_module();
    let names: Vec<String> = function_names(&module);
    for expected in ["Transform", "Describe", "Emit", "IsProbe", ".ctor"] {
        assert!(
            names.iter().any(|n: &String| n == expected),
            "method {expected} must be lifted: {names:?}"
        );
    }
    let transform: &Function = module.function_by_name("Transform").expect("Transform");
    assert!(transform.is_export, "public Transform is exported");
    let emit: &Function = module.function_by_name("Emit").expect("Emit");
    assert!(!emit.is_export, "private Emit is not exported");
}

#[test]
fn lifted_callees_match_the_independent_il_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    let lifted: BTreeSet<String> = lifted_callees(&nir);
    assert!(
        !oracle.callees.is_empty(),
        "the source method bodies do contain calls"
    );
    assert_eq!(
        lifted, oracle.callees,
        "lifted Mir call targets must equal the IL's actual call set (no dropped or invented calls)"
    );
    assert!(
        oracle
            .callees
            .iter()
            .any(|c: &String| c.contains("WriteLine")),
        "Emit calls Console.WriteLine in the source: {:?}",
        oracle.callees
    );
}

#[test]
fn lifted_string_constants_match_the_independent_il_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    let lifted: BTreeSet<String> = lifted_consts(&nir);
    assert_eq!(
        lifted, oracle.ldstr_values,
        "lifted ldstr literals must equal the IL's actual user-string set"
    );
    for literal in ["large value seen", "small value seen"] {
        assert!(
            oracle.ldstr_values.iter().any(|s: &String| s == literal),
            "source declares the literal {literal:?}: {:?}",
            oracle.ldstr_values
        );
    }
}

#[test]
fn lifted_field_accesses_match_the_independent_il_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    let lifted: BTreeSet<String> = lifted_field_accesses(&nir);
    assert_eq!(
        lifted, oracle.field_accesses,
        "lifted field-access targets must equal the IL's actual field set"
    );
    assert!(
        oracle
            .field_accesses
            .iter()
            .any(|f: &String| f.contains("_accumulator")),
        "Transform writes _accumulator: {:?}",
        oracle.field_accesses
    );
    assert!(
        oracle
            .field_accesses
            .iter()
            .any(|f: &String| f.contains("_counter")),
        "Transform reads and writes the static _counter: {:?}",
        oracle.field_accesses
    );
}

#[test]
fn lifted_branch_edge_count_matches_the_independent_il_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    assert!(
        oracle.branch_edges > 0,
        "Transform's for-loop and Describe's if both emit branches"
    );
    assert_eq!(
        lifted_branch_edges(&nir),
        oracle.branch_edges,
        "lifted Mir branch/cond-branch count must equal the IL's actual branch instruction count"
    );
}

#[test]
fn internal_emit_is_called_by_describe_through_a_resolved_edge() {
    let module: Module = lifted_module();
    let call_sites: Vec<CallSiteMatch> = calls_to(&module, "Emit");
    assert!(
        call_sites.len() >= 2,
        "Describe calls Emit on both branches: {call_sites:?}"
    );
    let xrefs: Vec<XrefMatch> = xrefs_to(&module, "Emit");
    let callers: Vec<&str> = xrefs
        .iter()
        .filter_map(|x: &XrefMatch| x.from_function.as_deref())
        .collect();
    assert!(
        callers.contains(&"Describe"),
        "Describe must reference the internal Emit: callers={callers:?}"
    );
}

#[test]
fn transform_loop_is_detected_as_a_byte_decoder() {
    let nir: NirModule = lifted_nir();
    let transform: &disrobe_nir::NirFunction = nir
        .functions
        .iter()
        .find(|f| f.name == "Transform")
        .expect("Transform");
    let byte_arith: usize = transform
        .instructions
        .iter()
        .filter(|ins| ins.byte_width && matches!(ins.op, NirOp::BinOp { .. }))
        .count();
    assert!(
        byte_arith >= 1,
        "the xor/shr over a loaded byte element must count as byte-arith"
    );
    let memory_ops: usize = transform
        .instructions
        .iter()
        .filter(|ins| ins.reads_memory || ins.writes_memory)
        .count();
    assert!(
        memory_ops >= 1,
        "the ldelem.u1/stelem.i1 must count as memory ops"
    );
}

#[test]
fn lift_is_deterministic() {
    let first: NirModule = lifted_nir();
    let second: NirModule = lifted_nir();
    assert_eq!(first, second, "the .NET lift must be byte-stable");
}
