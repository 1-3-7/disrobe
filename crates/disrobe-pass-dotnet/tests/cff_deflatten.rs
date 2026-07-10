#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_dotnet::cil::{MethodBody, disassemble, parse_method_body};
use disrobe_pass_dotnet::metadata::parse_metadata_root;
use disrobe_pass_dotnet::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::peel::deflatten::decrypt::{
    DecryptInlineReport, InlinedLiteral, inline_decryptors,
};
use disrobe_pass_dotnet::peel::deflatten::grade::{StructuralScore, grade};
use disrobe_pass_dotnet::peel::deflatten::{
    DeflattenSummary, MethodRecovery, analyze, is_flattened, recover_method,
};

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

fn clean_body_named(name: &str) -> MethodBody {
    let bytes: Vec<u8> = load(CLEAN);
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
    panic!("clean method {name} not found");
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
