#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_dotnet::cil::{
    Instruction, MethodBody, OperandValue, disassemble, parse_method_body,
};
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::peel::deflatten::decrypt::{
    DecryptInlineReport, InlinedLiteral, inline_decryptors,
};
use disrobe_pass_dotnet::peel::deflatten::grade::{
    PayloadEdge, PayloadGraph, StructuralScore, clean_payload_graph, grade, recovered_payload_graph,
};
use disrobe_pass_dotnet::peel::deflatten::rebuild::{
    RecoveredInstructionBlock, recover_payload_instructions,
};
use disrobe_pass_dotnet::peel::deflatten::{
    DeflattenSummary, MethodRecovery, analyze, is_flattened, recover_method,
};
use disrobe_pass_dotnet::signature::{MethodSig, SIG_KIND_MASK, SIG_VARARG};
use disrobe_pass_dotnet::tables::TableId;

const CLEAN: &str = "../../corpus/dotnet/cff/CffSample.clean.exe";
const FLAT: &str = "../../corpus/dotnet/cff/CffSample.ctrlflow.exe";
const DECRYPT: &str = "../../corpus/dotnet/cff/DecryptSample.exe";

const PRED_CLEAN: &str = "../../corpus/dotnet/cff/CffPred.clean.exe";
const PRED_X86: &str = "../../corpus/dotnet/cff/CffPred.x86pred.exe";
const PRED_EXPR: &str = "../../corpus/dotnet/cff/CffPred.exprpred.exe";

const PRED_METHODS: [&str; 8] = [
    "Fnv1a",
    "Adler",
    "Gcd",
    "Collatz",
    "Clamp",
    "Classify",
    "CountWords",
    "Decode",
];

fn pred_clean_body_named(name: &str) -> MethodBody {
    let bytes: Vec<u8> = load(PRED_CLEAN);
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr = parse_clr_header(&bytes, &pe).expect("clr");
    let root = parse_metadata_root(&bytes, &pe, &clr).expect("md");
    let resolver: Resolver = Resolver::build(&bytes, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();
    for ty in &model.types {
        for m in &ty.methods {
            if m.name == name && m.rva != 0 {
                let off: usize = pe.rva_to_offset(m.rva).expect("off");
                return parse_method_body(&bytes[off..]).expect("body");
            }
        }
    }
    panic!("clean predicate method {name} not found");
}

fn pred_recover_named(flat: &str, name: &str) -> MethodRecovery {
    let bytes: Vec<u8> = load(flat);
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr = parse_clr_header(&bytes, &pe).expect("clr");
    let root = parse_metadata_root(&bytes, &pe, &clr).expect("md");
    let resolver: Resolver = Resolver::build(&bytes, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();
    for ty in &model.types {
        for m in &ty.methods {
            if m.name == name
                && let Some(rec) = recover_method(&bytes, &pe, ty, m)
            {
                return rec;
            }
        }
    }
    panic!("predicate method {name} not recovered as flattened in {flat}");
}

fn assert_predicate_set_recovers_clean_cfg(flat: &str, label: &str) {
    let summary: DeflattenSummary =
        analyze(&load(flat)).unwrap_or_else(|| panic!("{label}: methods must be flattened"));
    assert!(
        summary.flattened_methods >= 8,
        "{label}: the predicate-protected sample flattened the benign methods; found {}",
        summary.flattened_methods
    );
    assert_eq!(
        summary.flattened_methods, summary.deflattened_methods,
        "{label}: every flattened method must fully resolve through the predicate decoder; \
         {}/{} resolved",
        summary.deflattened_methods, summary.flattened_methods
    );

    let mut matched: usize = 0;
    let mut expected: usize = 0;
    for name in PRED_METHODS {
        let rec: MethodRecovery = pred_recover_named(flat, name);
        assert!(
            rec.recovered.unresolved.is_empty(),
            "{label} {name}: left {} unresolved blocks",
            rec.recovered.unresolved.len()
        );
        let clean: MethodBody = pred_clean_body_named(name);
        let score: StructuralScore = grade(&clean, &rec.recovered);
        assert!(
            score.is_full(),
            "{label} {name}: recovered CFG must equal the known-original clean CFG; \
             signatures {}/{}, branch_ok={}, ret_ok={}, edge_ok={}",
            score.matched_signatures,
            score.expected_signatures,
            score.branch_blocks_match,
            score.return_blocks_match,
            score.edge_count_match
        );
        matched += score.matched_signatures;
        expected += score.expected_signatures;
    }
    let pct: f64 = matched as f64 / expected as f64 * 100.0;
    println!("{label} structural recovery: {matched}/{expected} block-signatures = {pct:.1}%");
    assert!((pct - 100.0).abs() < f64::EPSILON);
}

#[test]
fn x86_predicate_sample_actually_carries_native_predicate_stubs() {
    use disrobe_pass_dotnet::peel::deflatten::predicate::PredicateOracle;
    let image: Vec<u8> = load(PRED_X86);
    let pe: PeImage = parse(&image).expect("pe");
    let clr = parse_clr_header(&image, &pe).expect("clr");
    let root = parse_metadata_root(&image, &pe, &clr).expect("md");
    let resolver: Resolver = Resolver::build(&image, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();
    let oracle: PredicateOracle = PredicateOracle::build(&image, &pe, &model);
    assert!(
        oracle.predicate_method_count() >= 1,
        "the x86Predicate sample must ship at least one int->int predicate method for the \
         stub emulator to resolve; found {}",
        oracle.predicate_method_count()
    );
}

#[test]
fn x86_predicate_switch_keys_resolve_via_native_stub_emulation() {
    assert_predicate_set_recovers_clean_cfg(PRED_X86, "x86Predicate");
}

#[test]
fn expression_predicate_switch_keys_resolve_via_inverse_folding() {
    assert_predicate_set_recovers_clean_cfg(PRED_EXPR, "ExpressionPredicate");
}

#[test]
fn predicate_clean_baselines_carry_no_dispatcher() {
    assert!(
        analyze(&load(PRED_CLEAN)).is_none(),
        "the unobfuscated predicate baseline must contain no control-flow dispatcher"
    );
}

#[test]
fn predicate_protected_exes_run_byte_identically_to_clean() {
    let Some(clean_out): Option<String> = dotnet_run(PRED_CLEAN) else {
        eprintln!("SKIP: no .NET runtime on PATH to execute the predicate behavioral oracle");
        return;
    };
    for (label, flat) in [
        ("x86Predicate", PRED_X86),
        ("ExpressionPredicate", PRED_EXPR),
    ] {
        let flat_out: String = dotnet_run(flat)
            .unwrap_or_else(|| panic!("{label} exe must run under the same runtime as clean"));
        assert_eq!(
            clean_out, flat_out,
            "{label}: the predicate-flattened exe must print byte-identical output to the clean exe"
        );
    }
    assert!(clean_out.lines().count() >= 8);
}

const CFF_METHODS: [&str; 6] = ["Crc32", "Classify", "CountWords", "Gcd", "Collatz", "Clamp"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum GroundTruthOperand {
    Raw(OperandValue),
    ResolvedMethod(String),
}

type GroundTruthPayloadOp = (u16, GroundTruthOperand);

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroundTruthBlock {
    instructions: Vec<GroundTruthPayloadOp>,
    edge: PayloadEdge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroundTruthGraph {
    entry: usize,
    blocks: Vec<GroundTruthBlock>,
}

fn resolved_method_identity(resolver: &Resolver, token: u32) -> Option<String> {
    let name: String = resolver.resolve_token(token);
    let signature: MethodSig = resolver.callee_signature(token)?;
    if signature.calling_convention & SIG_KIND_MASK > SIG_VARARG {
        return None;
    }
    let return_type: String = resolver.resolve_type_tokens(&signature.return_type.render());
    let params: String = signature
        .params
        .iter()
        .map(|param| resolver.resolve_type_tokens(&param.render()))
        .collect::<Vec<String>>()
        .join(",");
    Some(format!(
        "{name}|cc={}|this={}|explicit={}|generic={}|({params})->{return_type}",
        signature.calling_convention,
        signature.has_this,
        signature.explicit_this,
        signature.generic_param_count,
    ))
}

fn is_method_operand(name: &str) -> bool {
    matches!(
        name,
        "jmp" | "call" | "callvirt" | "newobj" | "ldftn" | "ldvirtftn"
    )
}

fn token_table(token: u32) -> Option<TableId> {
    TableId::from_index(u8::try_from(token >> 24).ok()?)
}

fn ground_truth_operand(
    instruction: &Instruction,
    resolver: &Resolver,
) -> Option<GroundTruthOperand> {
    if !is_method_operand(&instruction.name) {
        return Some(GroundTruthOperand::Raw(instruction.operand.clone()));
    }
    let OperandValue::Token(token) = instruction.operand else {
        return None;
    };
    let table: TableId = token_table(token)?;
    if !matches!(table, TableId::MethodDef | TableId::MemberRef) {
        return None;
    }
    Some(GroundTruthOperand::ResolvedMethod(
        resolved_method_identity(resolver, token)?,
    ))
}

fn ground_truth_payload_graph(
    graph: PayloadGraph,
    resolver: &Resolver,
) -> Option<GroundTruthGraph> {
    let blocks: Vec<GroundTruthBlock> = graph
        .blocks
        .into_iter()
        .map(|block| {
            let instructions: Option<Vec<GroundTruthPayloadOp>> = block
                .instructions
                .iter()
                .map(|instruction: &Instruction| {
                    Some((
                        instruction.opcode,
                        ground_truth_operand(instruction, resolver)?,
                    ))
                })
                .collect();
            Some(GroundTruthBlock {
                instructions: instructions?,
                edge: block.edge,
            })
        })
        .collect::<Option<Vec<GroundTruthBlock>>>()?;
    Some(GroundTruthGraph {
        entry: graph.entry,
        blocks,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PredicateFamily {
    NonZero,
    Equal,
    Greater,
    GreaterOrEqual,
}

fn predicate_form(name: &str) -> Option<(PredicateFamily, bool)> {
    let base: &str = name.strip_suffix(".s").unwrap_or(name);
    match base {
        "brtrue" => Some((PredicateFamily::NonZero, false)),
        "brfalse" => Some((PredicateFamily::NonZero, true)),
        "beq" => Some((PredicateFamily::Equal, false)),
        "bne.un" => Some((PredicateFamily::Equal, true)),
        "bgt" => Some((PredicateFamily::Greater, false)),
        "ble" => Some((PredicateFamily::Greater, true)),
        "bge" => Some((PredicateFamily::GreaterOrEqual, false)),
        "blt" => Some((PredicateFamily::GreaterOrEqual, true)),
        _ => None,
    }
}

const fn edge_kind(edge: &PayloadEdge) -> u8 {
    match edge {
        PayloadEdge::Goto(_) => 1,
        PayloadEdge::Branch { .. } => 2,
        PayloadEdge::Return => 0,
    }
}

fn edge_targets(edge: &PayloadEdge) -> Vec<usize> {
    match edge {
        PayloadEdge::Goto(target) => vec![*target],
        PayloadEdge::Branch {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        PayloadEdge::Return => Vec::new(),
    }
}

fn predecessor_counts(graph: &GroundTruthGraph) -> Option<Vec<usize>> {
    let mut counts: Vec<usize> = vec![0; graph.blocks.len()];
    for block in &graph.blocks {
        for target in edge_targets(&block.edge) {
            let count: &mut usize = counts.get_mut(target)?;
            *count = count.checked_add(1)?;
        }
    }
    Some(counts)
}

fn partial_mapping_matches(
    expected: &GroundTruthGraph,
    recovered: &GroundTruthGraph,
    mapping: &[Option<usize>],
) -> bool {
    for (expected_source, recovered_source) in mapping.iter().enumerate() {
        let Some(recovered_source): Option<usize> = *recovered_source else {
            continue;
        };
        let Some(expected_block): Option<&GroundTruthBlock> = expected.blocks.get(expected_source)
        else {
            return false;
        };
        let Some(recovered_block): Option<&GroundTruthBlock> =
            recovered.blocks.get(recovered_source)
        else {
            return false;
        };
        let targets_match = |expected_target: usize, recovered_target: usize| -> bool {
            mapping
                .get(expected_target)
                .is_some_and(|mapped: &Option<usize>| {
                    mapped.is_none_or(|value| value == recovered_target)
                })
        };
        match (&expected_block.edge, &recovered_block.edge) {
            (PayloadEdge::Goto(expected), PayloadEdge::Goto(recovered)) => {
                if !targets_match(*expected, *recovered) {
                    return false;
                }
            }
            (
                PayloadEdge::Branch {
                    taken: expected_taken,
                    fallthrough: expected_fallthrough,
                    predicate: expected_predicate,
                },
                PayloadEdge::Branch {
                    taken: recovered_taken,
                    fallthrough: recovered_fallthrough,
                    predicate: recovered_predicate,
                },
            ) => {
                let expected_form: Option<(PredicateFamily, bool)> =
                    predicate_form(expected_predicate);
                let recovered_form: Option<(PredicateFamily, bool)> =
                    predicate_form(recovered_predicate);
                let (expected_true, expected_false, recovered_true, recovered_false): (
                    usize,
                    usize,
                    usize,
                    usize,
                ) = match (expected_form, recovered_form) {
                    (
                        Some((expected_family, expected_inverted)),
                        Some((recovered_family, recovered_inverted)),
                    ) if expected_family == recovered_family => (
                        if expected_inverted {
                            *expected_fallthrough
                        } else {
                            *expected_taken
                        },
                        if expected_inverted {
                            *expected_taken
                        } else {
                            *expected_fallthrough
                        },
                        if recovered_inverted {
                            *recovered_fallthrough
                        } else {
                            *recovered_taken
                        },
                        if recovered_inverted {
                            *recovered_taken
                        } else {
                            *recovered_fallthrough
                        },
                    ),
                    _ if expected_predicate == recovered_predicate => (
                        *expected_taken,
                        *expected_fallthrough,
                        *recovered_taken,
                        *recovered_fallthrough,
                    ),
                    _ => return false,
                };
                if !targets_match(expected_true, recovered_true)
                    || !targets_match(expected_false, recovered_false)
                {
                    return false;
                }
            }
            (PayloadEdge::Return, PayloadEdge::Return) => {}
            _ => return false,
        }
    }
    true
}

fn search_graph_mapping(
    expected: &GroundTruthGraph,
    recovered: &GroundTruthGraph,
    expected_predecessors: &[usize],
    recovered_predecessors: &[usize],
    mapping: &mut [Option<usize>],
    claimed: &mut [bool],
    budget: &mut usize,
) -> bool {
    if mapping.iter().all(Option::is_some) {
        return partial_mapping_matches(expected, recovered, mapping);
    }
    let mut selected: Option<(usize, Vec<usize>)> = None;
    for expected_index in 0..expected.blocks.len() {
        if mapping[expected_index].is_some() {
            continue;
        }
        let expected_block: &GroundTruthBlock = &expected.blocks[expected_index];
        let candidates: Vec<usize> = recovered
            .blocks
            .iter()
            .enumerate()
            .filter(|(recovered_index, recovered_block)| {
                let predecessor_count_matches: bool = expected_predecessors[expected_index]
                    == recovered_predecessors[*recovered_index];
                !claimed[*recovered_index]
                    && expected_block.instructions == recovered_block.instructions
                    && edge_kind(&expected_block.edge) == edge_kind(&recovered_block.edge)
                    && predecessor_count_matches
            })
            .map(|(index, _)| index)
            .collect();
        if candidates.is_empty() {
            return false;
        }
        if selected
            .as_ref()
            .is_none_or(|(_, current): &(usize, Vec<usize>)| candidates.len() < current.len())
        {
            selected = Some((expected_index, candidates));
        }
    }
    let Some((expected_index, candidates)): Option<(usize, Vec<usize>)> = selected else {
        return false;
    };
    for recovered_index in candidates {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        mapping[expected_index] = Some(recovered_index);
        claimed[recovered_index] = true;
        if partial_mapping_matches(expected, recovered, mapping)
            && search_graph_mapping(
                expected,
                recovered,
                expected_predecessors,
                recovered_predecessors,
                mapping,
                claimed,
                budget,
            )
        {
            return true;
        }
        claimed[recovered_index] = false;
        mapping[expected_index] = None;
    }
    false
}

fn exact_payload_graph_match(expected: &GroundTruthGraph, recovered: &GroundTruthGraph) -> bool {
    const MAX_BLOCKS: usize = 256;
    const SEARCH_BUDGET: usize = 1_000_000;
    if expected.blocks.len() != recovered.blocks.len()
        || expected.blocks.is_empty()
        || expected.blocks.len() > MAX_BLOCKS
        || expected.entry >= expected.blocks.len()
        || recovered.entry >= recovered.blocks.len()
    {
        return false;
    }
    let Some(expected_predecessors): Option<Vec<usize>> = predecessor_counts(expected) else {
        return false;
    };
    let Some(recovered_predecessors): Option<Vec<usize>> = predecessor_counts(recovered) else {
        return false;
    };
    let expected_entry: &GroundTruthBlock = &expected.blocks[expected.entry];
    let recovered_entry: &GroundTruthBlock = &recovered.blocks[recovered.entry];
    if expected_entry.instructions != recovered_entry.instructions
        || edge_kind(&expected_entry.edge) != edge_kind(&recovered_entry.edge)
        || expected_predecessors[expected.entry] != recovered_predecessors[recovered.entry]
    {
        return false;
    }
    let mut mapping: Vec<Option<usize>> = vec![None; expected.blocks.len()];
    let mut claimed: Vec<bool> = vec![false; recovered.blocks.len()];
    mapping[expected.entry] = Some(recovered.entry);
    claimed[recovered.entry] = true;
    let mut budget: usize = SEARCH_BUDGET;
    partial_mapping_matches(expected, recovered, &mapping)
        && search_graph_mapping(
            expected,
            recovered,
            &expected_predecessors,
            &recovered_predecessors,
            &mut mapping,
            &mut claimed,
            &mut budget,
        )
}

#[test]
fn payload_graph_match_rejects_operands_moved_between_cfg_positions() {
    let op = |value: i32| -> Vec<GroundTruthPayloadOp> {
        vec![(0x20, GroundTruthOperand::Raw(OperandValue::I32(value)))]
    };
    let expected: GroundTruthGraph = GroundTruthGraph {
        entry: 0,
        blocks: vec![
            GroundTruthBlock {
                instructions: Vec::new(),
                edge: PayloadEdge::Branch {
                    taken: 1,
                    fallthrough: 2,
                    predicate: "brtrue".to_owned(),
                },
            },
            GroundTruthBlock {
                instructions: op(1),
                edge: PayloadEdge::Return,
            },
            GroundTruthBlock {
                instructions: op(2),
                edge: PayloadEdge::Return,
            },
        ],
    };
    let mut moved: GroundTruthGraph = expected.clone();
    moved.blocks.swap(1, 2);
    moved.blocks[0].edge = PayloadEdge::Branch {
        taken: 1,
        fallthrough: 2,
        predicate: "brtrue".to_owned(),
    };
    assert!(!exact_payload_graph_match(&expected, &moved));
    let mut inverted: GroundTruthGraph = expected.clone();
    inverted.blocks[0].edge = PayloadEdge::Branch {
        taken: 2,
        fallthrough: 1,
        predicate: "brfalse".to_owned(),
    };
    assert!(exact_payload_graph_match(&expected, &inverted));
}

const GAUNTLET_CLEAN: &str = "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.clean.exe";
const GAUNTLET_PROTECTED: &str =
    "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.confuserex2.exe";
const GAUNTLET_PROCESS_TOKEN: u32 = 0x0600_000A;
const GAUNTLET_PROTECTED_PROCESS_TOKEN: u32 = 0x0600_0042;

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "real CFF corpus fixture missing at {} ({e}); a missing fixture must hard-fail",
            path.display()
        )
    })
}

fn load_model(rel: &str) -> (Vec<u8>, PeImage, AssemblyModel) {
    let bytes: Vec<u8> = load(rel);
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata");
    let resolver: Resolver = Resolver::build(&bytes, &pe, &clr, &root).expect("resolver");
    (bytes, pe, resolver.model())
}

fn load_resolver(rel: &str) -> Resolver {
    let bytes: Vec<u8> = load(rel);
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata");
    Resolver::build(&bytes, &pe, &clr, &root).expect("resolver")
}

fn body_named(rel: &str, name: &str) -> MethodBody {
    let bytes: Vec<u8> = load(rel);
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr = parse_clr_header(&bytes, &pe).expect("clr");
    let root = parse_metadata_root(&bytes, &pe, &clr).expect("md");
    let resolver: Resolver = Resolver::build(&bytes, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();
    for ty in &model.types {
        let _: &TypeModel = ty;
        for m in &ty.methods {
            let mm: &MethodModel = m;
            if mm.name == name && mm.rva != 0 {
                let off: usize = pe.rva_to_offset(mm.rva).expect("off");
                return parse_method_body(&bytes[off..]).expect("body");
            }
        }
    }
    panic!("method {name} not found in {rel}");
}

fn clean_body_named(name: &str) -> MethodBody {
    body_named(CLEAN, name)
}

fn protected_body_named(name: &str) -> MethodBody {
    body_named(FLAT, name)
}

fn recover_named(name: &str) -> MethodRecovery {
    let bytes: Vec<u8> = load(FLAT);
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr = parse_clr_header(&bytes, &pe).expect("clr");
    let root = parse_metadata_root(&bytes, &pe, &clr).expect("md");
    let resolver: Resolver = Resolver::build(&bytes, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();
    for ty in &model.types {
        for m in &ty.methods {
            if m.name == name
                && let Some(rec) = recover_method(&bytes, &pe, ty, m)
            {
                return rec;
            }
        }
    }
    panic!("method {name} not recovered as flattened");
}

#[test]
fn clean_baseline_carries_no_dispatcher() {
    let image: Vec<u8> = load(CLEAN);
    assert!(
        analyze(&image).is_none(),
        "the unobfuscated baseline must contain no control-flow dispatcher"
    );
}

#[test]
fn pass_run_path_surfaces_deflattening_and_inlined_literals() {
    let flat: Vec<u8> = load(FLAT);
    let summary: disrobe_pass_dotnet::PassSummary =
        disrobe_pass_dotnet::analyze(&flat).expect("pass analyze");
    let cff: &DeflattenSummary = summary
        .control_flow_flattening
        .as_ref()
        .expect("the dotnet pass must surface control-flow flattening on the real path");
    assert!(cff.deflattened_methods >= 6);
    assert_eq!(cff.flattened_methods, cff.deflattened_methods);

    let decrypt: Vec<u8> = load(DECRYPT);
    let dsummary: disrobe_pass_dotnet::PassSummary =
        disrobe_pass_dotnet::analyze(&decrypt).expect("pass analyze decrypt");
    assert!(
        dsummary
            .inlined_literals
            .iter()
            .any(|s: &String| s == "genuine"),
        "the run path must inline the recovered decryptor literal; got {:?}",
        dsummary.inlined_literals
    );
}

#[test]
fn real_confuserex_control_flow_is_detected() {
    let image: Vec<u8> = load(FLAT);
    let summary: DeflattenSummary = analyze(&image).expect("flattened methods detected");
    assert!(
        summary.flattened_methods >= 6,
        "ConfuserEx control-flow protection flattened the benign methods; found {}",
        summary.flattened_methods
    );
}

#[test]
fn every_flattened_method_recovers_the_original_cfg() {
    for name in CFF_METHODS {
        let rec: MethodRecovery = recover_named(name);
        assert!(
            rec.recovered.unresolved.is_empty(),
            "method {name} left {} unresolved blocks",
            rec.recovered.unresolved.len()
        );
        let clean: MethodBody = clean_body_named(name);
        let score: StructuralScore = grade(&clean, &rec.recovered);
        assert!(
            score.is_full(),
            "method {name}: recovered CFG must match the known-original clean CFG exactly; \
             signatures {}/{}, branch_ok={}, ret_ok={}, edge_ok={}",
            score.matched_signatures,
            score.expected_signatures,
            score.branch_blocks_match,
            score.return_blocks_match,
            score.edge_count_match
        );
    }
}

#[test]
fn aggregate_structural_recovery_is_total_against_known_originals() {
    let mut matched: usize = 0;
    let mut expected: usize = 0;
    let mut full: usize = 0;
    for name in CFF_METHODS {
        let rec: MethodRecovery = recover_named(name);
        let clean: MethodBody = clean_body_named(name);
        let score: StructuralScore = grade(&clean, &rec.recovered);
        matched += score.matched_signatures;
        expected += score.expected_signatures;
        if score.is_full() {
            full += 1;
        }
    }
    let pct: f64 = matched as f64 / expected as f64 * 100.0;
    println!(
        "CFF structural recovery: {matched}/{expected} block-signatures = {pct:.1}%, {full}/{} methods fully recovered",
        CFF_METHODS.len()
    );
    assert_eq!(
        full,
        CFF_METHODS.len(),
        "all benign methods must fully recover vs the known-original clean CFG"
    );
    assert!((pct - 100.0).abs() < f64::EPSILON);
}

#[test]
fn every_real_confuserex_payload_preserves_exact_opcodes_and_operands() {
    let clean_resolver: Resolver = load_resolver(CLEAN);
    let protected_resolver: Resolver = load_resolver(FLAT);
    let mut matched: usize = 0;
    let mut expected: usize = 0;
    let mut raw_representations: usize = 0;
    for name in CFF_METHODS {
        let recovery: MethodRecovery = recover_named(name);
        let clean: MethodBody = clean_body_named(name);
        let protected: MethodBody = protected_body_named(name);
        let structural: StructuralScore = grade(&clean, &recovery.recovered);
        assert!(
            structural.is_full(),
            "{name}: structural ground truth changed"
        );
        let recovered_payloads: Vec<RecoveredInstructionBlock> =
            recover_payload_instructions(&recovery.graph, &protected, &recovery.recovered)
                .expect("recovery graph and protected method body must agree");
        for payload_block in &recovered_payloads {
            let block: &disrobe_pass_dotnet::peel::deflatten::rebuild::RecoveredBlock = recovery
                .recovered
                .blocks
                .iter()
                .find(|block| block.id == payload_block.id)
                .expect("payload block has a recovered edge block");
            let projected: Vec<String> = payload_block
                .instructions
                .iter()
                .map(|instruction: &Instruction| instruction.name.clone())
                .collect();
            assert_eq!(
                block.payload, projected,
                "{name}: legacy opcode-name payload diverged from parsed instruction payload"
            );
        }
        let clean_graph: GroundTruthGraph = ground_truth_payload_graph(
            clean_payload_graph(&clean).expect("clean payload graph"),
            &clean_resolver,
        )
        .expect("clean metadata operands must resolve");
        let recovered_graph: GroundTruthGraph = ground_truth_payload_graph(
            recovered_payload_graph(&recovery.graph, &protected, &recovery.recovered)
                .expect("recovered payload graph"),
            &protected_resolver,
        )
        .expect("protected metadata operands must resolve");
        let clean_count: usize = clean_graph
            .blocks
            .iter()
            .map(|block: &GroundTruthBlock| block.instructions.len())
            .sum();
        let recovered_count: usize = recovered_graph
            .blocks
            .iter()
            .map(|block: &GroundTruthBlock| block.instructions.len())
            .sum();
        assert_eq!(
            recovered_count, clean_count,
            "{name}: payload count differs from the clean assembly; clean={clean_graph:?} \
             recovered={recovered_graph:?}"
        );
        assert!(
            exact_payload_graph_match(&clean_graph, &recovered_graph),
            "{name}: the rooted opcode-operand control-flow graph differs from the clean \
             assembly; clean={clean_graph:?} recovered={recovered_graph:?}"
        );
        matched += clean_count;
        expected += clean_count;
        raw_representations += clean_graph
            .blocks
            .iter()
            .flat_map(|block: &GroundTruthBlock| &block.instructions)
            .filter(|(_, operand): &&GroundTruthPayloadOp| {
                matches!(operand, GroundTruthOperand::Raw(_))
            })
            .count();
    }
    println!(
        "CFF exact payload recovery: {matched}/{expected} opcode-operand pairs, \
         {raw_representations}/{expected} raw operand representations"
    );
    assert_eq!(matched, expected);
}

#[test]
fn real_confuserex2_preserves_call_result_pops_before_dispatcher_key_tails() {
    let (clean_bytes, clean_pe, clean_model): (Vec<u8>, PeImage, AssemblyModel) =
        load_model(GAUNTLET_CLEAN);
    let clean_method: &MethodModel = clean_model
        .types
        .iter()
        .flat_map(|ty: &TypeModel| &ty.methods)
        .find(|method: &&MethodModel| method.token == GAUNTLET_PROCESS_TOKEN)
        .expect("clean Process method");
    assert_eq!(clean_method.name, "Process");
    let clean_offset: usize = clean_pe
        .rva_to_offset(clean_method.rva)
        .expect("clean Process RVA");
    let clean_body: MethodBody =
        parse_method_body(&clean_bytes[clean_offset..]).expect("clean Process body");

    let (protected_bytes, protected_pe, protected_model): (Vec<u8>, PeImage, AssemblyModel) =
        load_model(GAUNTLET_PROTECTED);
    let (protected_type, protected_method): (&TypeModel, &MethodModel) = protected_model
        .types
        .iter()
        .find_map(|ty: &TypeModel| {
            ty.methods
                .iter()
                .find(|method: &&MethodModel| method.token == GAUNTLET_PROTECTED_PROCESS_TOKEN)
                .map(|method: &MethodModel| (ty, method))
        })
        .expect("protected Process method");
    let recovery: MethodRecovery = recover_method(
        &protected_bytes,
        &protected_pe,
        protected_type,
        protected_method,
    )
    .expect("protected Process deflattened");
    assert!(recovery.recovered.unresolved.is_empty());

    let clean_pops: usize = clean_body
        .instructions
        .iter()
        .filter(|instruction| instruction.name == "pop")
        .count();
    let recovered_pops: usize = recovery
        .recovered
        .blocks
        .iter()
        .flat_map(|block| &block.payload)
        .filter(|name| name.as_str() == "pop")
        .count();
    let clean_callvirt_pops: usize = clean_body
        .instructions
        .windows(2)
        .filter(|pair: &&[Instruction]| pair[0].name == "callvirt" && pair[1].name == "pop")
        .count();
    let recovered_callvirt_pops: usize = recovery
        .recovered
        .blocks
        .iter()
        .map(|block| {
            block
                .payload
                .windows(2)
                .filter(|pair: &&[String]| pair[0] == "callvirt" && pair[1] == "pop")
                .count()
        })
        .sum();
    assert_eq!(clean_pops, 6, "clean Process ground truth changed");
    assert_eq!(
        clean_callvirt_pops, clean_pops,
        "every clean Process pop must discard a callvirt result"
    );
    assert_eq!(
        recovered_pops, clean_pops,
        "every original call-result pop must survive dispatcher key-tail removal"
    );
    assert_eq!(
        recovered_callvirt_pops, clean_callvirt_pops,
        "every original callvirt-pop pair must survive dispatcher key-tail removal"
    );

    let score: StructuralScore = grade(&clean_body, &recovery.recovered);
    assert_eq!(score.matched_signatures, 11);
    assert_eq!(score.expected_signatures, 12);
    assert!(score.branch_blocks_match);
    assert!(score.return_blocks_match);
    assert!(score.edge_count_match);
}

const CE2: &str = "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll";

#[test]
fn real_confuserex2_flattened_methods_fully_deflatten_with_sound_edges() {
    use disrobe_pass_dotnet::peel::deflatten::rebuild::{Edge, RecoveredBlock, edge_targets};

    let bytes: Vec<u8> = load(CE2);
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr = parse_clr_header(&bytes, &pe).expect("clr");
    let root = parse_metadata_root(&bytes, &pe, &clr).expect("md");
    let resolver: Resolver = Resolver::build(&bytes, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();

    let mut flattened: usize = 0;
    let mut conditional_edges: usize = 0;
    for ty in &model.types {
        for m in &ty.methods {
            let Some(rec): Option<MethodRecovery> = recover_method(&bytes, &pe, ty, m) else {
                continue;
            };
            flattened += 1;
            assert!(
                rec.recovered.unresolved.is_empty(),
                "real ConfuserEx2 method {} left {} unresolved block(s); its injected decoder \
                 carries in-block if/else predicates that must deflatten, not stall",
                rec.name,
                rec.recovered.unresolved.len()
            );
            let ids: std::collections::BTreeSet<usize> = rec
                .recovered
                .blocks
                .iter()
                .map(|b: &RecoveredBlock| b.id)
                .collect();
            for b in &rec.recovered.blocks {
                for t in edge_targets(&b.edge) {
                    assert!(
                        ids.contains(&t),
                        "method {}: recovered block {} has an edge to {} which is not a \
                         recovered block (silently-wrong control flow)",
                        rec.name,
                        b.id,
                        t
                    );
                }
                if matches!(b.edge, Edge::Cond { .. }) {
                    conditional_edges += 1;
                }
            }
        }
    }
    assert!(
        flattened >= 2,
        "the real ConfuserEx2 fixture flattens the cctor and its injected decoder; found {flattened}"
    );
    assert!(
        conditional_edges >= 9,
        "the injected decoder's real in-block ternary/loop predicates must survive deflattening \
         as recovered conditional edges rather than being linearized; found {conditional_edges}"
    );
}

#[test]
fn recovered_predicates_cover_the_original_comparisons() {
    let rec: MethodRecovery = recover_named("Collatz");
    let preds: Vec<String> =
        disrobe_pass_dotnet::peel::deflatten::grade::predicate_kinds(&rec.recovered);
    assert!(
        preds.iter().any(|p: &String| p.starts_with("ble")),
        "Collatz loop guard (n > 1 -> ble) must survive deflattening; got {preds:?}"
    );
}

#[test]
fn pathological_dispatcher_is_bounded_not_hung() {
    let mut code: Vec<u8> = vec![0x16, 0x25, 0x0A, 0x17, 0x5E, 0x45];
    code.extend_from_slice(&1u32.to_le_bytes());
    code.extend_from_slice(&(-11i32).to_le_bytes());
    code.push(0x2A);
    let body: MethodBody = MethodBody {
        max_stack: 8,
        code_size: code.len() as u32,
        local_var_sig_tok: 0,
        init_locals: true,
        instructions: disassemble(&code).expect("disasm"),
        exception_clauses: Vec::new(),
    };
    if is_flattened(&body) {
        let _ = disrobe_pass_dotnet::peel::deflatten::deflatten_body(&body);
    }
}

#[test]
fn decryptor_inliner_recovers_known_literals_by_real_execution() {
    let image: Vec<u8> = load(DECRYPT);
    let report: DecryptInlineReport = inline_decryptors(&image).expect("inliner runs");
    assert!(
        report.decryptor_methods >= 1,
        "pure Decrypt(int) recognized"
    );
    let texts: Vec<&str> = report
        .call_sites
        .iter()
        .filter_map(|c| match &c.literal {
            InlinedLiteral::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        texts.contains(&"genuine") && texts.contains(&"payload"),
        "Decrypt(100)/Decrypt(200) must virtually execute to known literals; got {texts:?}"
    );
}

#[test]
fn expression_predicate_string_loader_recovers_known_originals() {
    let image: Vec<u8> = load(PRED_EXPR);
    let report: DecryptInlineReport =
        inline_decryptors(&image).expect("inliner runs on protected fixture");
    let mut recovered: Vec<(i64, &str)> = report
        .call_sites
        .iter()
        .filter_map(
            |site: &disrobe_pass_dotnet::peel::deflatten::decrypt::CallSite| match &site.literal {
                InlinedLiteral::Text(text) => Some((site.argument, text.as_str())),
                _ => None,
            },
        )
        .collect();
    recovered.sort_unstable();
    assert_eq!(
        recovered,
        [(11, "PMFMI"), (22, "DDBBCEFG")],
        "the real ConfuserEx ExpressionPredicate fixture must statically recover both outputs of \
         Secrets.Decode(int) against its committed source"
    );
}

fn dotnet_run(exe: &str) -> Option<String> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(exe);
    let direct: std::io::Result<std::process::Output> = Command::new(&path).output();
    if let Ok(out) = direct
        && out.status.success()
    {
        return Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"));
    }
    let via: std::io::Result<std::process::Output> = Command::new("dotnet").arg(&path).output();
    match via {
        Ok(out) if out.status.success() => {
            Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
        }
        _ => None,
    }
}

#[test]
fn behavioral_oracle_clean_and_flattened_print_identically() {
    let Some(clean_out): Option<String> = dotnet_run(CLEAN) else {
        eprintln!("SKIP: no .NET runtime on PATH to execute the behavioral oracle");
        return;
    };
    let flat_out: String =
        dotnet_run(FLAT).expect("flattened exe must run under the same runtime as the clean exe");
    assert_eq!(
        clean_out, flat_out,
        "the deflattener's ground-truth oracle is the original program's behavior: the \
         ConfuserEx control-flow-flattened exe must print byte-identical output to the clean exe"
    );
    assert!(
        clean_out.lines().count() >= 8,
        "the sample exercises every benign method; got {} lines",
        clean_out.lines().count()
    );
}
