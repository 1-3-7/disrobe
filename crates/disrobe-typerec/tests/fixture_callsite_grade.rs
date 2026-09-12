#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_typerec::callsite::{self, ApiType, CallsiteTyping, TypedSlot};
use disrobe_typerec::dwarf_gt::{self, DebugImage, GroundTruthFunction};
use disrobe_typerec::grade::{self, ApiTypeGradeReport};
use disrobe_typerec::import_map::ImportMap;
use disrobe_typerec::lattice::{Sign, Width};
use disrobe_typerec::region::RegionModel;
use disrobe_typerec::sigdb::{Abi, SigDb};

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn stripped_input() -> (DebugImage, ImportMap) {
    let unstripped: DebugImage =
        dwarf_gt::load(&fixture("callsite_corpus.unstripped.so")).expect("load unstripped dwarf");
    let stripped_bytes: Vec<u8> = fixture("callsite_corpus.stripped.so");
    let (base, text): (u64, Vec<u8>) =
        dwarf_gt::load_text(&stripped_bytes).expect("load stripped text");
    assert_eq!(base, unstripped.text_base, "text bases must match");
    assert_eq!(text, unstripped.text, "strip must not alter .text bytes");
    let imports: ImportMap = ImportMap::from_image(&stripped_bytes);
    (
        DebugImage {
            text_base: base,
            text,
            functions: unstripped.functions,
            locations: unstripped.locations,
            regions: RegionModel::from_image(&stripped_bytes),
        },
        imports,
    )
}

fn function<'a>(image: &'a DebugImage, name: &str) -> &'a GroundTruthFunction {
    image
        .functions
        .iter()
        .find(|f: &&GroundTruthFunction| f.name == name)
        .unwrap_or_else(|| panic!("ground truth must carry {name}"))
}

fn typing_of(image: &DebugImage, imports: &ImportMap, name: &str) -> CallsiteTyping {
    let f: &GroundTruthFunction = function(image, name);
    callsite::type_function(
        &image.text,
        image.text_base,
        f.low_pc,
        f.high_pc,
        imports,
        &SigDb::builtin(),
        Abi::SysV,
    )
}

fn slot(typing: &CallsiteTyping, f: &GroundTruthFunction, rbp_disp: i64) -> TypedSlot {
    typing
        .slot_covering(rbp_disp, f.low_pc, f.high_pc)
        .unwrap_or_else(|| panic!("expected a recovered type at slot {rbp_disp:#x}"))
}

#[test]
fn callsite_propagation_matches_dwarf_ground_truth() {
    let (image, imports): (DebugImage, ImportMap) = stripped_input();
    let report: ApiTypeGradeReport =
        grade::grade_api_types(&image, &imports, &SigDb::builtin(), Abi::SysV);

    eprintln!(
        "api-type grade: graded_slots={} pointer={}/{} integer_width={}/{} integer_sign={}/{}",
        report.graded_slots,
        report.pointer.correct,
        report.pointer.predicted,
        report.integer_width.correct,
        report.integer_width.predicted,
        report.integer_sign.correct,
        report.integer_sign.predicted,
    );
    for mismatch in &report.mismatches {
        eprintln!("MISMATCH {mismatch:?}");
    }

    assert!(
        report.mismatches.is_empty(),
        "a caller-local type may never be recovered wrong: {:?}",
        report.mismatches
    );
    assert_eq!(
        report.pointer.correct, 5,
        "five pointer arguments recovered"
    );
    assert_eq!(report.pointer.predicted, 5);
    assert_eq!(
        report.integer_width.correct, 4,
        "four integer-width arguments recovered"
    );
    assert_eq!(report.integer_width.predicted, 4);
    assert_eq!(report.integer_sign.correct, 4);
}

#[test]
fn dup_prefix_locals_are_typed_from_the_api_calls() {
    let (image, imports): (DebugImage, ImportMap) = stripped_input();
    let f: &GroundTruthFunction = function(&image, "dup_prefix");
    let typing: CallsiteTyping = typing_of(&image, &imports, "dup_prefix");

    assert_eq!(
        slot(&typing, f, -0x8).ty,
        ApiType::Pointer,
        "s flows into strlen and memcpy as a pointer"
    );
    assert_eq!(
        slot(&typing, f, -0x10).ty,
        ApiType::Integer {
            width: Width::Qword,
            sign: Sign::Unsigned
        },
        "len is the size_t returned by strlen"
    );
    assert_eq!(
        slot(&typing, f, -0x18).ty,
        ApiType::Pointer,
        "buf is the pointer returned by malloc"
    );
}

#[test]
fn fill_and_read_locals_are_typed_from_the_api_calls() {
    let (image, imports): (DebugImage, ImportMap) = stripped_input();
    let f: &GroundTruthFunction = function(&image, "fill_and_read");
    let typing: CallsiteTyping = typing_of(&image, &imports, "fill_and_read");

    assert_eq!(
        slot(&typing, f, -0x4).ty,
        ApiType::Integer {
            width: Width::Dword,
            sign: Sign::Signed
        },
        "fd is the int passed to read"
    );
    assert_eq!(
        slot(&typing, f, -0x10).ty,
        ApiType::Pointer,
        "dst flows into memset and read as a pointer"
    );
    assert_eq!(
        slot(&typing, f, -0x18).ty,
        ApiType::Integer {
            width: Width::Qword,
            sign: Sign::Unsigned
        },
        "n is the size_t count"
    );
}

#[test]
fn wrong_import_map_makes_the_pass_abstain() {
    let (image, _imports): (DebugImage, ImportMap) = stripped_input();
    let empty: ImportMap = ImportMap::default();
    let report: ApiTypeGradeReport =
        grade::grade_api_types(&image, &empty, &SigDb::builtin(), Abi::SysV);
    assert_eq!(
        report.graded_slots, 0,
        "with no resolvable imports the pass emits nothing, never a guess"
    );
}
