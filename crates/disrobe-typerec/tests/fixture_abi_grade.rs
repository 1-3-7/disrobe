#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_typerec::abi::{Convention, RecoveredProto, ReturnKind};
use disrobe_typerec::dwarf_gt::{self, DebugImage};
use disrobe_typerec::grade::{self, SigGradeReport};

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn stripped_input() -> DebugImage {
    let unstripped: DebugImage =
        dwarf_gt::load(&fixture("abi_corpus.unstripped.exe")).expect("load unstripped");
    let (base, text): (u64, Vec<u8>) =
        dwarf_gt::load_text(&fixture("abi_corpus.stripped.exe")).expect("load stripped");
    assert_eq!(base, unstripped.text_base, "text bases must match");
    assert_eq!(text, unstripped.text, "strip must not alter .text bytes");
    DebugImage {
        text_base: base,
        text,
        functions: unstripped.functions,
    }
}

#[test]
fn measured_signatures_against_dwarf() {
    let image: DebugImage = stripped_input();
    let report: SigGradeReport = grade::grade_signature_image(&image, Convention::Win64);

    eprintln!(
        "abi Win64 O0: functions total={} graded={} return_graded={}",
        report.functions_total, report.functions_graded, report.return_graded
    );
    eprintln!(
        "arg_count correct={}/{} precision={:.4}",
        report.arg_count.correct,
        report.arg_count.total,
        report.arg_count.precision()
    );
    eprintln!(
        "arg_regs correct={}/{} precision={:.4}",
        report.arg_regs.correct,
        report.arg_regs.total,
        report.arg_regs.precision()
    );
    eprintln!(
        "return_kind correct={}/{} predicted={} precision={:.4} recall={:.4}",
        report.return_kind.correct,
        report.return_kind.total,
        report.return_kind.predicted,
        report.return_kind.precision(),
        report.return_kind.recall()
    );
    eprintln!("sret correct={}/{}", report.sret_correct, report.sret_total);
    for mismatch in &report.mismatches {
        eprintln!("MISMATCH {mismatch:?}");
    }

    assert_eq!(
        report.functions_total, 10,
        "committed prototyped function count"
    );
    assert_eq!(
        report.functions_graded, 10,
        "every function recovers a prototype"
    );
    assert!(report.mismatches.is_empty(), "no axis may be wrong");

    assert_eq!(report.arg_count.correct, 10);
    assert_eq!(report.arg_count.total, 10);
    assert!((report.arg_count.precision() - 1.0).abs() < f64::EPSILON);

    assert_eq!(report.arg_regs.correct, 10);
    assert_eq!(report.arg_regs.total, 10);
    assert!((report.arg_regs.precision() - 1.0).abs() < f64::EPSILON);

    assert_eq!(
        report.return_graded, 9,
        "the entry _start has no caller to observe its return"
    );
    assert_eq!(report.return_kind.correct, 9);
    assert_eq!(report.return_kind.predicted, 9);
    assert_eq!(report.return_kind.total, 9);
    assert!((report.return_kind.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.return_kind.recall() - 1.0).abs() < f64::EPSILON);

    assert_eq!(
        report.sret_correct, 1,
        "make_big returns a 24-byte struct via a hidden pointer"
    );
    assert_eq!(report.sret_total, 1);
}

#[test]
fn grader_rejects_a_wrong_argument_count() {
    let image: DebugImage = stripped_input();
    let called: BTreeSet<u64> = grade::called_functions(&image);
    let protos: Vec<Option<RecoveredProto>> =
        grade::recover_protos_image(&image, Convention::Win64);
    let baseline: SigGradeReport =
        grade::grade_signatures(&image.functions, &protos, Convention::Win64, &called);
    assert_eq!(baseline.arg_count.correct, baseline.arg_count.total);

    let mut mutated: Vec<Option<RecoveredProto>> = protos;
    let mut touched: bool = false;
    for slot in &mut mutated {
        if let Some(proto) = slot.as_mut()
            && !proto.args.is_empty()
        {
            proto.args.pop();
            touched = true;
            break;
        }
    }
    assert!(
        touched,
        "at least one recovered prototype has arguments to drop"
    );

    let report: SigGradeReport =
        grade::grade_signatures(&image.functions, &mutated, Convention::Win64, &called);
    assert!(
        report.arg_count.correct < baseline.arg_count.correct,
        "dropping an argument must be caught as a wrong count",
    );
    assert!(report.mismatches.iter().any(|m| m.variable == "arg_count"));
}

#[test]
fn grader_rejects_a_wrong_return_kind() {
    let image: DebugImage = stripped_input();
    let called: BTreeSet<u64> = grade::called_functions(&image);
    let protos: Vec<Option<RecoveredProto>> =
        grade::recover_protos_image(&image, Convention::Win64);
    let baseline: SigGradeReport =
        grade::grade_signatures(&image.functions, &protos, Convention::Win64, &called);
    assert_eq!(baseline.return_kind.correct, baseline.return_kind.predicted);

    let mut mutated: Vec<Option<RecoveredProto>> = protos;
    let mut touched: bool = false;
    for slot in &mut mutated {
        if let Some(proto) = slot.as_mut()
            && proto.ret == ReturnKind::IntRax
        {
            proto.ret = ReturnKind::Void;
            touched = true;
            break;
        }
    }
    assert!(
        touched,
        "at least one recovered prototype returns an integer to corrupt"
    );

    let report: SigGradeReport =
        grade::grade_signatures(&image.functions, &mutated, Convention::Win64, &called);
    assert!(
        report.return_kind.correct < baseline.return_kind.correct,
        "flipping a return kind must be caught",
    );
    assert!(
        report
            .mismatches
            .iter()
            .any(|m| m.variable == "return_kind")
    );
}
