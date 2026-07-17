#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_typerec::dwarf_gt::{self, DebugImage};
use disrobe_typerec::grade::{self, StructGradeReport};
use disrobe_typerec::lattice::Width;
use disrobe_typerec::recover::TypedFunction;
use disrobe_typerec::structrec::{AccessFlags, FieldNameTier, RecoveredField, RecoveredStruct};

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn stripped_input() -> DebugImage {
    let unstripped: DebugImage =
        dwarf_gt::load(&fixture("struct_corpus.unstripped.exe")).expect("load unstripped");
    let (base, text): (u64, Vec<u8>) =
        dwarf_gt::load_text(&fixture("struct_corpus.stripped.exe")).expect("load stripped");
    assert_eq!(base, unstripped.text_base, "text bases must match");
    assert_eq!(text, unstripped.text, "strip must not alter .text bytes");
    DebugImage {
        text_base: base,
        text,
        functions: unstripped.functions,
    }
}

#[test]
fn measured_struct_offsets_and_widths_against_dwarf() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);
    let report: StructGradeReport = grade::grade_structs(&image.functions, &recovered);

    eprintln!(
        "struct offsets predicted={} correct={} total={} precision={:.4} recall={:.4}",
        report.offset.predicted,
        report.offset.correct,
        report.offset.total,
        report.offset.precision(),
        report.offset.recall()
    );
    eprintln!(
        "struct widths predicted={} correct={} total={} precision={:.4} recall={:.4}",
        report.width.predicted,
        report.width.correct,
        report.width.total,
        report.width.precision(),
        report.width.recall()
    );

    assert_eq!(
        report.aggregates_total, 7,
        "committed pointer-aggregate count"
    );
    assert_eq!(
        report.aggregates_mapped, 7,
        "every aggregate maps to a struct"
    );

    assert!(report.missing_leaves.is_empty(), "no field may be missing");
    assert!(report.spurious_leaves.is_empty(), "no invented field");
    assert_eq!(report.offset.total, 15);
    assert_eq!(report.offset.predicted, 15);
    assert_eq!(report.offset.correct, 15);
    assert!((report.offset.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.offset.recall() - 1.0).abs() < f64::EPSILON);

    assert_eq!(report.width.total, 16);
    assert_eq!(report.width.predicted, 16);
    assert_eq!(report.width.correct, 16);
    assert!((report.width.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.width.recall() - 1.0).abs() < f64::EPSILON);

    assert_eq!(report.union_total, 1, "one union in the corpus");
    assert_eq!(report.union_correct, 1, "the union is recovered as a union");
}

#[test]
fn union_array_and_field_shape_are_recovered() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let mut point: Option<RecoveredStruct> = None;
    let mut union: Option<RecoveredStruct> = None;
    let mut array: Option<RecoveredStruct> = None;
    for (function, recovery) in image.functions.iter().zip(recovered.iter()) {
        match function.name.as_str() {
            "sum_point" => point = recovery.struct_at(0x10).cloned(),
            "union_read" => union = recovery.struct_at(0x10).cloned(),
            "arr_sum" => array = recovery.struct_at(0x10).cloned(),
            _ => {}
        }
    }

    let point: RecoveredStruct = point.expect("sum_point struct");
    let point_slots: std::collections::BTreeSet<(i64, Width)> = point.field_slots();
    assert!(point_slots.contains(&(0, Width::Dword)));
    assert!(point_slots.contains(&(4, Width::Dword)));
    assert_eq!(point_slots.len(), 2);

    let union: RecoveredStruct = union.expect("union_read struct");
    assert!(
        union.is_union,
        "overlapping widths at one offset is a union"
    );
    let union_slots: std::collections::BTreeSet<(i64, Width)> = union.field_slots();
    assert!(union_slots.contains(&(0, Width::Dword)));
    assert!(union_slots.contains(&(0, Width::Qword)));

    let array: RecoveredStruct = array.expect("arr_sum struct");
    let element: &RecoveredField = array
        .fields
        .iter()
        .find(|field: &&RecoveredField| field.offset == 0)
        .expect("array element field");
    assert_eq!(element.stride, Some(4), "int array stride is 4");
    assert_eq!(element.width, Width::Dword);
    assert_eq!(element.name_tier, FieldNameTier::Typed);
}

fn mutate(
    recovered: &[TypedFunction],
    mutator: impl Fn(&RecoveredStruct) -> RecoveredStruct,
) -> Vec<TypedFunction> {
    recovered
        .iter()
        .map(|function: &TypedFunction| TypedFunction {
            rbp_slots: function.rbp_slots.clone(),
            objects: function.objects.clone(),
            structs: function.structs.iter().map(&mutator).collect(),
            has_frame_pointer: function.has_frame_pointer,
        })
        .collect()
}

#[test]
fn grader_rejects_a_shifted_field_offset() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);
    let baseline: StructGradeReport = grade::grade_structs(&image.functions, &recovered);
    assert!((baseline.offset.precision() - 1.0).abs() < f64::EPSILON);

    let shifted: Vec<TypedFunction> = mutate(&recovered, |item: &RecoveredStruct| {
        let fields: Vec<RecoveredField> = item
            .fields
            .iter()
            .map(|field: &RecoveredField| RecoveredField {
                offset: field.offset.saturating_add(1),
                ..field.clone()
            })
            .collect();
        RecoveredStruct {
            fields,
            ..item.clone()
        }
    });
    let report: StructGradeReport = grade::grade_structs(&image.functions, &shifted);
    assert!(
        report.offset.precision() < 1.0,
        "a shifted offset must break offset precision",
    );
    assert!(
        report.offset.recall() < 1.0,
        "a shifted offset breaks recall"
    );
    assert!(!report.spurious_leaves.is_empty());
}

#[test]
fn grader_rejects_merged_fields() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let merged: Vec<TypedFunction> = mutate(&recovered, |item: &RecoveredStruct| {
        let first: Vec<RecoveredField> = item.fields.iter().take(1).cloned().collect();
        RecoveredStruct {
            fields: first,
            ..item.clone()
        }
    });
    let report: StructGradeReport = grade::grade_structs(&image.functions, &merged);
    assert!(
        report.width.recall() < 1.0,
        "collapsing fields into one must drop recall",
    );
    assert!(
        !report.missing_leaves.is_empty(),
        "dropped fields are missing"
    );
}

#[test]
fn grader_rejects_an_invented_padding_field() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let padded: Vec<TypedFunction> = mutate(&recovered, |item: &RecoveredStruct| {
        let mut fields: Vec<RecoveredField> = item.fields.clone();
        fields.push(RecoveredField {
            offset: 0x40,
            width: Width::Dword,
            access: AccessFlags {
                read: true,
                written: false,
            },
            stride: None,
            is_pointer: false,
            name: "field_0x40".to_owned(),
            name_tier: FieldNameTier::Offset,
        });
        RecoveredStruct {
            fields,
            ..item.clone()
        }
    });
    let report: StructGradeReport = grade::grade_structs(&image.functions, &padded);
    assert!(
        report.offset.precision() < 1.0,
        "an invented field in padding must break precision",
    );
    assert!(!report.spurious_leaves.is_empty());
}

#[test]
fn grader_rejects_a_corrupted_width() {
    let image: DebugImage = stripped_input();
    let recovered: Vec<TypedFunction> = grade::recover_image(&image);

    let widened: Vec<TypedFunction> = mutate(&recovered, |item: &RecoveredStruct| {
        let fields: Vec<RecoveredField> = item
            .fields
            .iter()
            .map(|field: &RecoveredField| RecoveredField {
                width: other_width(field.width),
                ..field.clone()
            })
            .collect();
        RecoveredStruct {
            fields,
            ..item.clone()
        }
    });
    let report: StructGradeReport = grade::grade_structs(&image.functions, &widened);
    assert!(
        report.width.precision() < 1.0,
        "a corrupted width must break width precision",
    );
    assert!(report.offset.precision() > report.width.precision());
}

fn other_width(width: Width) -> Width {
    if width == Width::Qword {
        Width::Dword
    } else {
        Width::Qword
    }
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|out: std::process::Output| out.status.success())
}

fn run(command: &mut Command) -> bool {
    command
        .status()
        .is_ok_and(|status: std::process::ExitStatus| status.success())
}

fn source_path() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("struct_corpus.c");
    path
}

#[test]
fn recompiled_struct_corpus_reproduces_perfect_layout() {
    if !tool_available("gcc") || !tool_available("objcopy") {
        eprintln!("skipping: gcc and objcopy are required for the recompile path");
        return;
    }
    let work: PathBuf =
        std::env::temp_dir().join(format!("disrobe_typerec_struct_{}", std::process::id()));
    if std::fs::create_dir_all(&work).is_err() {
        eprintln!("skipping: could not create a working directory");
        return;
    }
    let unstripped: PathBuf = work.join("struct.unstripped.exe");
    let stripped: PathBuf = work.join("struct.stripped.exe");

    let built: bool = run(Command::new("gcc")
        .args([
            "-g",
            "-O0",
            "-gdwarf-4",
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&unstripped)
        .arg(source_path()));
    if !built {
        cleanup(&work);
        eprintln!("skipping: gcc could not build the struct corpus on this host");
        return;
    }
    if !run(Command::new("objcopy")
        .arg("--strip-debug")
        .arg(&unstripped)
        .arg(&stripped))
    {
        cleanup(&work);
        eprintln!("skipping: objcopy could not strip on this host");
        return;
    }

    let Some(ground_truth): Option<DebugImage> = std::fs::read(&unstripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load(&bytes).ok())
    else {
        cleanup(&work);
        panic!("freshly built unstripped binary must carry DWARF");
    };
    let Some((base, text)): Option<(u64, Vec<u8>)> = std::fs::read(&stripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load_text(&bytes).ok())
    else {
        cleanup(&work);
        panic!("freshly stripped binary must expose .text");
    };

    let image: DebugImage = DebugImage {
        text_base: base,
        text,
        functions: ground_truth.functions,
    };
    let report: StructGradeReport = grade::grade_struct_image(&image);
    cleanup(&work);

    assert!(report.aggregates_total >= 6, "corpus exposes aggregates");
    assert!(report.missing_leaves.is_empty(), "no field may be missing");
    assert!(report.spurious_leaves.is_empty(), "no invented field");
    assert!((report.offset.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.offset.recall() - 1.0).abs() < f64::EPSILON);
    assert!((report.width.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.width.recall() - 1.0).abs() < f64::EPSILON);
}

fn cleanup(work: &Path) {
    let _ = std::fs::remove_dir_all(work);
}
