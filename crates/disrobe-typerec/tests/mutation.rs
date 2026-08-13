#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_typerec::dwarf_gt::{self, DebugImage};
use disrobe_typerec::grade::{self, GradeReport};
use disrobe_typerec::lattice::{Sign, Width};
use disrobe_typerec::recover::{RecoveredScalar, TypedFunction};
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
    let (base, text): (u64, Vec<u8>) = dwarf_gt::load_text(&stripped).expect("load stripped");
    DebugImage {
        text_base: base,
        text,
        functions: unstripped.functions,
        locations: unstripped.locations,
        regions: RegionModel::from_image(&stripped),
    }
}

const fn flip_sign(sign: Sign) -> Sign {
    match sign {
        Sign::Signed => Sign::Unsigned,
        Sign::Unsigned => Sign::Signed,
        other => other,
    }
}

fn other_width(width: Width) -> Width {
    if width == Width::Dword {
        Width::Byte
    } else {
        Width::Dword
    }
}

fn mutate(
    recovered: &[TypedFunction],
    mutator: impl Fn(RecoveredScalar) -> RecoveredScalar,
) -> Vec<TypedFunction> {
    recovered
        .iter()
        .map(|function: &TypedFunction| TypedFunction {
            has_frame_pointer: function.has_frame_pointer,
            objects: function.objects.clone(),
            structs: function.structs.clone(),
            proto: function.proto.clone(),
            rbp_slots: function
                .rbp_slots
                .iter()
                .map(|(disp, scalar): (&i64, &RecoveredScalar)| (*disp, mutator(*scalar)))
                .collect(),
        })
        .collect()
}

#[test]
fn grader_rejects_flipped_signedness() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let baseline: GradeReport = grade::grade_functions(&image.functions, &recovered);
    assert!((baseline.sign.precision() - 1.0).abs() < f64::EPSILON);
    assert!(baseline.sign_mismatches.is_empty());
    assert!(
        baseline.sign.correct > 0,
        "baseline must predict some signs"
    );

    let flipped: Vec<TypedFunction> =
        mutate(&recovered, |scalar: RecoveredScalar| RecoveredScalar {
            sign: flip_sign(scalar.sign),
            ..scalar
        });
    let report: GradeReport = grade::grade_functions(&image.functions, &flipped);
    assert!(
        report.sign.precision() < 1.0,
        "grader must fail on flipped signedness",
    );
    assert!(!report.sign_mismatches.is_empty());
    assert_eq!(
        report.sign.correct, 0,
        "every flipped determined sign must now be wrong",
    );
}

#[test]
fn grader_rejects_halved_width() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let baseline: GradeReport = grade::grade_functions(&image.functions, &recovered);
    assert!((baseline.width.precision() - 1.0).abs() < f64::EPSILON);
    assert!(baseline.width_mismatches.is_empty());

    let widened: Vec<TypedFunction> =
        mutate(&recovered, |scalar: RecoveredScalar| RecoveredScalar {
            width: other_width(scalar.width),
            ..scalar
        });
    let report: GradeReport = grade::grade_functions(&image.functions, &widened);
    assert!(
        report.width.precision() < 1.0,
        "grader must fail on corrupted widths",
    );
    assert!(!report.width_mismatches.is_empty());
}

#[test]
fn grader_rejects_demoted_sign_to_unknown_only_on_recall() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let demoted: Vec<TypedFunction> =
        mutate(&recovered, |scalar: RecoveredScalar| RecoveredScalar {
            sign: Sign::Unknown,
            ..scalar
        });
    let report: GradeReport = grade::grade_functions(&image.functions, &demoted);
    assert_eq!(
        report.sign.predicted, 0,
        "abstaining removes all predictions"
    );
    assert!((report.sign.precision() - 1.0).abs() < f64::EPSILON);
    assert_eq!(report.sign.correct, 0);
}
