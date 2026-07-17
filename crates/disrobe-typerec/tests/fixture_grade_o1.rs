#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_typerec::dwarf_gt::{self, DebugImage};
use disrobe_typerec::grade::{self, GradeReport, IdentityReport};
use disrobe_typerec::recover::{RecoveredObject, TypedFunction};

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn stripped_input() -> DebugImage {
    let unstripped: DebugImage =
        dwarf_gt::load(&fixture("types_o1_corpus.unstripped.exe")).expect("load unstripped");
    let (base, text): (u64, Vec<u8>) =
        dwarf_gt::load_text(&fixture("types_o1_corpus.stripped.exe")).expect("load stripped");
    assert_eq!(base, unstripped.text_base, "text bases must match");
    assert_eq!(text, unstripped.text, "strip must not alter .text bytes");
    DebugImage {
        text_base: base,
        text,
        functions: unstripped.functions,
    }
}

#[test]
fn o1_slot_reuse_split_is_sound_and_lifts_sign_recall() {
    let image: DebugImage = stripped_input();
    assert_eq!(image.functions.len(), 4, "committed O1 function count");

    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let identity: IdentityReport = grade::grade_identity(&image.functions, &recovered);
    eprintln!(
        "O1 identity: variables={} mapped={} reused={} false_merges={} false_splits={}",
        identity.variables,
        identity.mapped,
        identity.reused,
        identity.false_merges,
        identity.false_splits
    );
    assert_eq!(identity.variables, 8, "committed O1 stack-variable count");
    assert_eq!(
        identity.mapped, 8,
        "every real slot maps to a recovered object"
    );
    assert_eq!(
        identity.reused, 6,
        "three offsets each host two reused variables"
    );
    assert_eq!(
        identity.false_merges, 0,
        "splitting must not merge distinct slots"
    );
    assert_eq!(
        identity.false_splits, 0,
        "splitting must not fragment one slot"
    );
    assert!((identity.false_merge_rate()).abs() < f64::EPSILON);
    assert!((identity.false_split_rate()).abs() < f64::EPSILON);

    let merged: GradeReport = grade::grade_functions(&image.functions, &recovered);
    let split: GradeReport = grade::grade_functions_split(&image.functions, &recovered);
    eprintln!(
        "MERGED sign predicted={} correct={} abstentions={} recall={:.4}",
        merged.sign.predicted,
        merged.sign.correct,
        merged.sign_abstentions,
        merged.sign.recall()
    );
    eprintln!(
        "SPLIT  sign predicted={} correct={} abstentions={} recall={:.4}",
        split.sign.predicted,
        split.sign.correct,
        split.sign_abstentions,
        split.sign.recall()
    );

    assert!(
        merged.sign_mismatches.is_empty(),
        "merged view never guesses wrong"
    );
    assert!(
        split.sign_mismatches.is_empty(),
        "split view never guesses wrong"
    );
    assert!(split.width_mismatches.is_empty() && merged.width_mismatches.is_empty());

    assert_eq!(merged.sign.predicted, 2);
    assert_eq!(merged.sign.correct, 2);
    assert_eq!(merged.sign_abstentions, 6);
    assert!((merged.sign.recall() - 0.25).abs() < 1e-9);

    assert_eq!(split.sign.predicted, 8);
    assert_eq!(split.sign.correct, 8);
    assert_eq!(split.sign_abstentions, 0);
    assert!((split.sign.recall() - 1.0).abs() < 1e-9);

    assert!(
        split.sign.recall() > merged.sign.recall(),
        "live-range splitting must raise signedness recall",
    );

    assert!((merged.width.recall() - 1.0).abs() < 1e-9);
    assert!((split.width.recall() - 1.0).abs() < 1e-9);
}

#[test]
fn grader_detects_a_seeded_merge() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);
    let clean: IdentityReport = grade::grade_identity(&image.functions, &recovered);
    assert_eq!(clean.false_merges, 0);

    let merged: Vec<TypedFunction> = recovered.iter().map(collapse_offset_zero).collect();
    let report: IdentityReport = grade::grade_identity(&image.functions, &merged);
    assert!(
        report.false_merges > 0,
        "collapsing reused slots into one object must be caught as a false merge",
    );
}

#[test]
fn grader_detects_a_seeded_split() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);
    let clean: IdentityReport = grade::grade_identity(&image.functions, &recovered);
    assert_eq!(clean.false_splits, 0);

    let fragmented: Vec<TypedFunction> = recovered.iter().map(fragment_objects).collect();
    let report: IdentityReport = grade::grade_identity(&image.functions, &fragmented);
    assert!(
        report.false_splits > 0,
        "fragmenting one slot across the whole function must be caught as a false split",
    );
}

fn collapse_offset_zero(function: &TypedFunction) -> TypedFunction {
    let mut lo: u64 = u64::MAX;
    let mut hi: u64 = 0;
    for object in &function.objects {
        if object.offset == 0 {
            lo = lo.min(object.live_lo);
            hi = hi.max(object.live_hi);
        }
    }
    let mut objects: Vec<RecoveredObject> = function
        .objects
        .iter()
        .filter(|object: &&RecoveredObject| object.offset != 0)
        .copied()
        .collect();
    if hi >= lo {
        objects.push(RecoveredObject {
            offset: 0,
            width: disrobe_typerec::lattice::Width::Qword,
            sign: disrobe_typerec::lattice::Sign::Unknown,
            sign_conflict: true,
            live_lo: lo,
            live_hi: hi,
            escaped: false,
        });
    }
    TypedFunction {
        rbp_slots: function.rbp_slots.clone(),
        objects,
        structs: function.structs.clone(),
        has_frame_pointer: function.has_frame_pointer,
        proto: function.proto.clone(),
    }
}

fn fragment_objects(function: &TypedFunction) -> TypedFunction {
    let mut objects: Vec<RecoveredObject> = Vec::new();
    for object in &function.objects {
        objects.push(*object);
        objects.push(RecoveredObject {
            live_lo: object.live_lo,
            live_hi: object.live_hi.saturating_add(1),
            ..*object
        });
    }
    TypedFunction {
        rbp_slots: function.rbp_slots.clone(),
        objects,
        structs: function.structs.clone(),
        has_frame_pointer: function.has_frame_pointer,
        proto: function.proto.clone(),
    }
}
