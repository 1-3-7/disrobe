#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::pass::{KoiVmSummary, PassSummary, analyze};
use disrobe_pass_dotnet::peel::koivm::grade::{GroundOp, RecoveryScore, grade, project};
use disrobe_pass_dotnet::peel::koivm::lift::{CmpOp, LiftedOp};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy, RecoveredMethod, peel_by};
use disrobe_pass_dotnet::protectors::{
    ExecuteOptions, ExecutionOutcome, Protector, plan_execution,
};
use disrobe_pass_dotnet::{KoiVmRecovery, detect_koivm, devirtualize_koivm};

const KOIVM_REL: &str = "../../corpus/dotnet/koivm/KoiSample.koivm.exe";
const CLEAN_REL: &str = "../../corpus/dotnet/koivm/KoiSample.clean.exe";
const EAZVM_REL: &str = "../../corpus/dotnet/eazvm/EazSample.eazvm.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn real_koivm_sample_is_detected_and_devirtualized() {
    let image: Vec<u8> = load(KOIVM_REL);
    let detection = detect_koivm(&image);
    assert!(
        detection.koi_stream_present,
        "real KoiVM #Koi stream present"
    );
    assert_eq!(detection.virtualized_method_count, 6);

    let recovery: KoiVmRecovery = devirtualize_koivm(&image).expect("devirtualize real KoiVM");
    assert_eq!(recovery.methods.len(), 6, "all six methods recovered");
    assert!(recovery.undecoded_ids.is_empty(), "no undecoded methods");
}

#[test]
fn pass_summary_reports_koivm_recovery() {
    let image: Vec<u8> = load(KOIVM_REL);
    let summary: PassSummary = analyze(&image).expect("analyze KoiVM sample");
    let koivm: &KoiVmSummary = summary
        .koivm
        .as_ref()
        .expect("KoiVM summary present on virtualized sample");
    assert!(koivm.koi_stream_present);
    assert_eq!(koivm.virtualized_methods, 6);
    assert_eq!(koivm.devirtualized_methods, 6);
    assert!(
        summary.protectors_detected.contains(&Protector::KoiVm),
        "KoiVM must appear in detected protectors; got {:?}",
        summary.protectors_detected
    );
    for expected in ["Add", "Square", "SumTo", "Classify", "Factorial", "Max3"] {
        assert!(
            koivm
                .recovered_method_names
                .iter()
                .any(|n: &String| n == expected),
            "expected {expected} among recovered names {:?}",
            koivm.recovered_method_names
        );
    }
}

#[test]
fn clean_baseline_has_no_koivm_summary() {
    let image: Vec<u8> = load(CLEAN_REL);
    let summary: PassSummary = analyze(&image).expect("analyze clean baseline");
    assert!(
        summary.koivm.is_none(),
        "clean exe must not yield a KoiVM summary"
    );
    assert!(!summary.protectors_detected.contains(&Protector::KoiVm));
}

#[test]
fn koivm_protector_plans_devirtualization() {
    let outcome: ExecutionOutcome = plan_execution(Protector::KoiVm, ExecuteOptions::default());
    assert!(matches!(outcome, ExecutionOutcome::Devirtualized));
}

fn cil_op_kind(line: &str) -> Option<GroundOp> {
    let mnemonic: &str = line.split_whitespace().nth(1)?;
    Some(match mnemonic {
        "ldarg" => GroundOp::LoadArg,
        "ldloc" => GroundOp::LoadLocal,
        "stloc" => GroundOp::StoreLocal,
        "add" => GroundOp::Add,
        "mul" => GroundOp::Mul,
        m if m.starts_with("cmp.") => GroundOp::CompareAndBranch,
        "ret" => GroundOp::Return,
        _ => return None,
    })
}

fn count_kind(ops: &[GroundOp], kind: GroundOp) -> usize {
    ops.iter().filter(|o: &&GroundOp| **o == kind).count()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchKind {
    True,
    False,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchDestination {
    LoadArg(u32),
    LoadLocal(u32),
    Return,
    Other,
    Invalid,
}

type EdgeSignature = (
    usize,
    BranchKind,
    Option<CmpOp>,
    usize,
    BranchDestination,
    Option<usize>,
);

fn edge_signatures(ops: &[LiftedOp]) -> Vec<EdgeSignature> {
    let mut signatures: Vec<EdgeSignature> = Vec::new();
    for (index, op) in ops.iter().enumerate() {
        let (kind, target): (BranchKind, u32) = match op {
            LiftedOp::BranchTrue(target) => (BranchKind::True, *target),
            LiftedOp::BranchFalse(target) => (BranchKind::False, *target),
            LiftedOp::Branch(target) => (BranchKind::Always, *target),
            _ => continue,
        };
        let target_index: Option<usize> = usize::try_from(target).ok();
        let destination: BranchDestination = target_index
            .and_then(|target: usize| ops.get(target))
            .map_or(
                BranchDestination::Invalid,
                |target: &LiftedOp| match target {
                    LiftedOp::LoadArg(argument) => BranchDestination::LoadArg(*argument),
                    LiftedOp::LoadLocal(local) => BranchDestination::LoadLocal(*local),
                    LiftedOp::Return => BranchDestination::Return,
                    _ => BranchDestination::Other,
                },
            );
        let comparison: Option<CmpOp> = if matches!(kind, BranchKind::Always) {
            None
        } else {
            index
                .checked_sub(1)
                .and_then(|previous: usize| ops.get(previous))
                .and_then(|previous: &LiftedOp| match previous {
                    LiftedOp::Compare(comparison) => Some(*comparison),
                    _ => None,
                })
        };
        signatures.push((
            index,
            kind,
            comparison,
            target_index.unwrap_or(usize::MAX),
            destination,
            if matches!(kind, BranchKind::Always) {
                None
            } else {
                index.checked_add(1)
            },
        ));
    }
    signatures
}

fn expected_edge_signatures(method: &str) -> Vec<EdgeSignature> {
    use BranchDestination::{LoadArg, LoadLocal, Return};
    use BranchKind::{Always, False, True};

    let ge: Option<CmpOp> = Some(CmpOp::GreaterOrEqual);
    match method {
        "Add" | "Square" => Vec::new(),
        "SumTo" => vec![
            (5, True, ge, 8, LoadLocal(1), Some(6)),
            (15, Always, None, 2, LoadLocal(0), None),
        ],
        "Classify" => vec![
            (2, True, ge, 4, LoadArg(0), Some(3)),
            (6, False, ge, 8, Return, Some(7)),
        ],
        "Factorial" => vec![
            (4, False, ge, 7, LoadLocal(1), Some(5)),
            (16, Always, None, 2, LoadArg(0), None),
        ],
        "Max3" => vec![
            (5, True, ge, 8, LoadArg(2), Some(6)),
            (11, True, ge, 14, LoadLocal(0), Some(12)),
        ],
        _ => panic!("no clean-IL edge ground truth for {method}"),
    }
}

#[test]
fn peel_path_devirtualizes_koivm_and_delivers_recovered_cil() {
    let image: Vec<u8> = load(KOIVM_REL);
    let report: PeelReport = peel_by(Protector::KoiVm, &image)
        .expect("KoiVM is registered in peel_by")
        .expect("peel of real KoiVM sample must not error");
    assert_eq!(report.protector, Protector::KoiVm);
    assert_eq!(
        report.strategy,
        PeelStrategy::EncryptedResourceExtracted,
        "devirtualizing a real KoiVM image must flip strategy off the DR-CLI-0454 wall"
    );
    assert_eq!(
        report.recovered_methods.len(),
        6,
        "all six virtualized bodies must be delivered as CIL; got {:?}",
        report
            .recovered_methods
            .iter()
            .map(|m: &RecoveredMethod| m.method_name.as_str())
            .collect::<Vec<&str>>()
    );
    assert!(
        report.recovered_decoders >= 6,
        "peel must count the six recovered bodies; got {}",
        report.recovered_decoders
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("KoiVM VM-tier") && n.contains("devirtualized")),
        "peel notes must describe the KoiVM devirtualization; got {:?}",
        report.notes
    );

    let recovery: KoiVmRecovery = devirtualize_koivm(&image).expect("devirtualize");
    for m in &report.recovered_methods {
        assert!(
            !m.cil.is_empty(),
            "delivered method {} carried no CIL lines",
            m.method_name
        );
        let live: &disrobe_pass_dotnet::KoiVmMethod = recovery
            .methods
            .iter()
            .find(|k: &&disrobe_pass_dotnet::KoiVmMethod| k.method_name == m.method_name)
            .expect("delivered method must exist in the live recovery");
        assert_eq!(
            m.cil.len(),
            live.lifted.ops.len(),
            "the delivered CIL for {} must render exactly the lifted ops",
            m.method_name
        );
        let delivered: Vec<GroundOp> = m
            .cil
            .iter()
            .filter_map(|l: &String| cil_op_kind(l))
            .collect();
        let live_proj: Vec<GroundOp> = project(&live.lifted.ops);
        for kind in [
            GroundOp::LoadArg,
            GroundOp::LoadLocal,
            GroundOp::StoreLocal,
            GroundOp::Add,
            GroundOp::Mul,
            GroundOp::Return,
        ] {
            assert_eq!(
                count_kind(&delivered, kind),
                count_kind(&live_proj, kind),
                "{}: delivered CIL must carry the same {kind:?} count as the lifted body; \
                 delivered={:?}",
                m.method_name,
                m.cil
            );
        }
    }
}

#[test]
fn peel_delivered_bodies_recover_known_originals() {
    let image: Vec<u8> = load(KOIVM_REL);
    let recovery: KoiVmRecovery = devirtualize_koivm(&image).expect("devirtualize");

    for name in ["Add", "Square"] {
        let m: &disrobe_pass_dotnet::KoiVmMethod = recovery
            .methods
            .iter()
            .find(|k: &&disrobe_pass_dotnet::KoiVmMethod| k.method_name == name)
            .unwrap_or_else(|| panic!("{name} recovered"));
        let score: RecoveryScore =
            grade(name, &m.lifted).unwrap_or_else(|| panic!("graded {name}"));
        assert!(
            score.is_full(),
            "{name} must recover fully vs the known original; matched {}/{}",
            score.matched,
            score.expected
        );
    }

    let mut total_matched: u32 = 0;
    let mut total_expected: u32 = 0;
    for m in &recovery.methods {
        if let Some(score) = grade(&m.method_name, &m.lifted) {
            total_matched += score.matched;
            total_expected += score.expected;
        }
    }
    let pct: f64 = f64::from(total_matched) / f64::from(total_expected) * 100.0;
    assert!(
        pct >= 75.0,
        "aggregate structural recovery of the delivered KoiVM bodies vs known originals must be \
         >= 75%; got {pct:.1}% ({total_matched}/{total_expected})"
    );
}

#[test]
fn real_koivm_control_flow_matches_clean_il_and_targets_lifted_ops() {
    let image: Vec<u8> = load(KOIVM_REL);
    let recovery: KoiVmRecovery = devirtualize_koivm(&image).expect("devirtualize");
    for name in ["Add", "Square", "SumTo", "Classify", "Factorial", "Max3"] {
        let method: &disrobe_pass_dotnet::KoiVmMethod = recovery
            .methods
            .iter()
            .find(|method: &&disrobe_pass_dotnet::KoiVmMethod| method.method_name == name)
            .unwrap_or_else(|| panic!("{name} recovered"));
        assert_eq!(
            edge_signatures(&method.lifted.ops),
            expected_edge_signatures(name),
            "{name} edge polarity, predicate, direction, and destination must match KoiSample.clean.il; got {:?}",
            method.lifted.ops
        );
        assert!(
            method
                .lifted
                .ops
                .iter()
                .all(|op: &LiftedOp| !matches!(op, LiftedOp::Unknown("branch-target"))),
            "{name} real fixture must recover every branch target; got {:?}",
            method.lifted.ops
        );
    }
}

#[test]
fn analyze_surfaces_both_koivm_and_eazvm_vm_tiers() {
    let koi: PassSummary = analyze(&load(KOIVM_REL)).expect("analyze KoiVM");
    assert!(
        koi.koivm.is_some(),
        "analyze must surface the KoiVM VM-tier on a KoiVM image"
    );
    assert_eq!(
        koi.koivm
            .as_ref()
            .map(|s: &KoiVmSummary| s.devirtualized_methods),
        Some(6)
    );

    let eaz: PassSummary = analyze(&load(EAZVM_REL)).expect("analyze EazVM");
    let eazvm = eaz
        .eazvm
        .as_ref()
        .expect("analyze must surface the EazVM VM-tier on an EazVM image");
    assert!(eazvm.dispatch_table_present);
    assert_eq!(
        eazvm.devirtualized_methods, 6,
        "EazVM analyze must report all six devirtualized methods; got {}",
        eazvm.devirtualized_methods
    );
    assert!(
        eaz.protectors_detected.contains(&Protector::EazfuscatorNet),
        "EazVM devirt must add EazfuscatorNet to detected protectors; got {:?}",
        eaz.protectors_detected
    );
    for expected in ["Add", "Classify", "Max3", "Poly", "SumTo"] {
        assert!(
            eazvm
                .recovered_method_names
                .iter()
                .any(|n: &String| n == expected),
            "expected EazVM method {expected} among {:?}",
            eazvm.recovered_method_names
        );
    }
}
