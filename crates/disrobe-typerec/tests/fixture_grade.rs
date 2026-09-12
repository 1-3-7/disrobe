#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_typerec::dwarf_gt::{self, DebugImage};
use disrobe_typerec::grade::{self, GradeReport};
use disrobe_typerec::region::RegionModel;

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn stripped_input() -> DebugImage {
    let unstripped: DebugImage =
        dwarf_gt::load(&fixture("types_corpus.unstripped.exe")).expect("load unstripped");
    let stripped: Vec<u8> = fixture("types_corpus.stripped.exe");
    let (stripped_base, stripped_text): (u64, Vec<u8>) =
        dwarf_gt::load_text(&stripped).expect("load stripped");
    assert_eq!(
        stripped_base, unstripped.text_base,
        "stripped and unstripped text bases must match",
    );
    assert_eq!(
        stripped_text, unstripped.text,
        "strip must not alter .text bytes",
    );
    DebugImage {
        text_base: stripped_base,
        text: stripped_text,
        functions: unstripped.functions,
        locations: unstripped.locations,
        regions: RegionModel::from_image(&stripped),
    }
}

#[test]
fn measured_width_and_sign_against_dwarf() {
    let report: GradeReport = grade::grade_image(&stripped_input());

    eprintln!(
        "O0 width+sign vs DWARF: total={} mapped={}",
        report.total_vars, report.mapped_vars
    );
    eprintln!(
        "width predicted={} correct={} precision={:.4} recall={:.4}",
        report.width.predicted,
        report.width.correct,
        report.width.precision(),
        report.width.recall()
    );
    eprintln!(
        "sign predicted={} correct={} abstentions={} precision={:.4} recall={:.4}",
        report.sign.predicted,
        report.sign.correct,
        report.sign_abstentions,
        report.sign.precision(),
        report.sign.recall()
    );

    assert_eq!(report.total_vars, 24, "committed corpus variable count");
    assert_eq!(
        report.mapped_vars, report.total_vars,
        "every DWARF variable must map to a recovered slot",
    );

    assert!(report.width_mismatches.is_empty(), "no width may be wrong");
    assert_eq!(report.width.correct, 24);
    assert_eq!(report.width.predicted, 24);
    assert!((report.width.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.width.recall() - 1.0).abs() < f64::EPSILON);

    assert!(
        report.sign_mismatches.is_empty(),
        "signedness must never be predicted wrong: {:?}",
        report.sign_mismatches,
    );
    assert_eq!(report.sign.predicted, 11);
    assert_eq!(report.sign.correct, 11);
    assert!((report.sign.precision() - 1.0).abs() < f64::EPSILON);
    assert_eq!(report.sign_abstentions, 13);
    assert!(report.sign.recall() > 0.45 && report.sign.recall() < 0.46);
}
