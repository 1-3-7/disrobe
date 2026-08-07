#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_typerec::CellStore;
use disrobe_typerec::cfg;
use disrobe_typerec::decode::decode_all;
use disrobe_typerec::dwarf_gt::{self, DebugImage};
use disrobe_typerec::grade::{self, StructGradeReport};
use disrobe_typerec::lattice::{TypeVar, Width};
use disrobe_typerec::memssa;
use disrobe_typerec::recover::TypedFunction;
use disrobe_typerec::structrec::{AccessFlags, FieldNameTier, RecoveredField, RecoveredStruct};
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

#[path = "support/cc_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod cc_toolchain;

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
        locations: unstripped.locations,
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
            proto: function.proto.clone(),
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

fn indexed_source_path() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("strided_indexed.c");
    path
}

fn has_indexed_rbp_memory(text: &[u8], base: u64) -> bool {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, text, base, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction: Instruction = decoder.decode();
        if instruction.is_invalid() {
            return false;
        }
        let operand_count: u32 = instruction.op_count();
        for operand in 0..operand_count {
            if instruction.op_kind(operand) == OpKind::Memory
                && instruction.memory_base() == Register::RBP
                && instruction.memory_index() != Register::None
                && instruction.memory_index_scale() == 8
            {
                return true;
            }
        }
    }
    false
}

#[test]
fn o2_indexed_stack_fixture_matches_dwarf_offsets_and_widths() {
    if !tool_available("clang") || !tool_available("objcopy") {
        eprintln!("skipping: clang and objcopy are required for the indexed ELF fixture");
        return;
    }
    let scratch: ScratchDir = if let Ok(scratch) = ScratchDir::create("disrobe_typerec_indexed") {
        scratch
    } else {
        eprintln!("skipping: could not create a working directory");
        return;
    };
    let work: PathBuf = scratch.path().to_path_buf();
    let unstripped: PathBuf = work.join("indexed.unstripped.elf");
    let stripped: PathBuf = work.join("indexed.stripped.elf");
    let built: bool = run(Command::new("clang")
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-g",
            "-O2",
            "-gdwarf-4",
            "-fno-omit-frame-pointer",
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-fuse-ld=lld",
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&unstripped)
        .arg(indexed_source_path()));
    if !built {
        eprintln!("skipping: clang could not build the indexed ELF fixture on this host");
        return;
    }
    if !run(Command::new("objcopy")
        .arg("--strip-debug")
        .arg(&unstripped)
        .arg(&stripped))
    {
        eprintln!("skipping: objcopy could not strip the indexed ELF fixture on this host");
        return;
    }
    let Some(ground_truth): Option<DebugImage> = std::fs::read(&unstripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load(&bytes).ok())
    else {
        panic!("freshly built indexed fixture must carry DWARF");
    };
    let Some((base, text)): Option<(u64, Vec<u8>)> = std::fs::read(&stripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load_text(&bytes).ok())
    else {
        panic!("freshly stripped indexed fixture must expose .text");
    };
    let locations: disrobe_typerec::dwarf_location::LocationSurvey = ground_truth.locations.clone();
    let functions: Vec<dwarf_gt::GroundTruthFunction> = ground_truth
        .functions
        .into_iter()
        .filter(|function: &dwarf_gt::GroundTruthFunction| function.name == "indexed_pair")
        .collect();
    let image: DebugImage = DebugImage {
        text_base: base,
        text,
        functions,
        locations,
    };
    let Some(function): Option<dwarf_gt::GroundTruthFunction> = image
        .functions
        .iter()
        .find(|function: &&dwarf_gt::GroundTruthFunction| function.name == "indexed_pair")
        .cloned()
    else {
        eprintln!("skipping: this build did not keep indexed_pair as a standalone function");
        return;
    };
    let bytes: &[u8] = image
        .function_bytes(&function)
        .expect("indexed function bytes");
    let instructions: Vec<Instruction> = decode_all(bytes, function.low_pc);
    let control_flow: cfg::Cfg = cfg::build(&instructions);
    let mut store: CellStore = CellStore::new();
    let ssa: memssa::MemSsa = memssa::build(&instructions, &control_flow, &mut store);
    let mut fields: BTreeSet<(i64, TypeVar)> = BTreeSet::new();
    for instruction in &instructions {
        if instruction.memory_base() != Register::RBP
            || instruction.memory_index() == Register::None
            || instruction.memory_index_scale() != 8
        {
            continue;
        }
        let displacement: i64 =
            i64::from_ne_bytes(instruction.memory_displacement64().to_ne_bytes());
        let Some(cell): Option<TypeVar> = ssa.version_cell(instruction.ip(), displacement) else {
            continue;
        };
        fields.insert((displacement, cell));
    }
    if !has_indexed_rbp_memory(&image.text, image.text_base) || fields.len() != 2 {
        eprintln!("skipping: this build did not emit the expected two scale-8 indexed rbp fields");
        return;
    }
    let report: StructGradeReport = grade::grade_struct_image(&image);
    let cells: BTreeSet<TypeVar> = fields
        .iter()
        .map(|(_, cell): &(i64, TypeVar)| *cell)
        .collect();
    assert_eq!(cells.len(), 2);
    assert_eq!(report.aggregates_total, 1);
    assert_eq!(report.aggregates_mapped, 1);
    assert_eq!(report.offset.total, 2);
    assert_eq!(report.offset.correct, 2);
    assert_eq!(report.width.total, 2);
    assert_eq!(report.width.correct, 2);
    assert!((report.offset.recall() - 1.0).abs() < f64::EPSILON);
    assert!((report.width.recall() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn recompiled_struct_corpus_reproduces_perfect_layout() {
    let graded: &str = "the fresh-build DWARF aggregate reference";
    let Some(toolchain): Option<cc_toolchain::CcToolchain> = cc_toolchain::require(graded) else {
        return;
    };
    let scratch: ScratchDir = ScratchDir::create("disrobe_typerec_struct")
        .unwrap_or_else(|error| panic!("{graded} needs a working directory: {error}"));
    let work: PathBuf = scratch.path().to_path_buf();
    let source: OsString = cc_toolchain::stage_source(&work, &source_path())
        .unwrap_or_else(|defect| panic!("stage the struct corpus: {defect}"));
    let unstripped: OsString = OsString::from("struct.unstripped.bin");
    let stripped: OsString = OsString::from("struct.stripped.bin");
    let protection: &str = if cc_toolchain::accepts_flag(&toolchain, &work, "-fcf-protection=full")
    {
        "-fcf-protection=full"
    } else {
        "-fno-common"
    };

    if let Err(defect) = cc_toolchain::compile(
        &toolchain,
        &work,
        &source,
        &unstripped,
        &[
            "-g",
            "-O0",
            "-gdwarf-4",
            protection,
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-Wl,-e,_start",
        ],
    ) {
        panic!("{graded} cannot be measured because the compiler refused the corpus: {defect}");
    }
    if let Err(defect) = cc_toolchain::strip_debug(&toolchain, &work, &unstripped, &stripped) {
        panic!("{graded} cannot be measured because the strip failed: {defect}");
    }

    let unstripped_bytes: Vec<u8> = std::fs::read(work.join("struct.unstripped.bin"))
        .unwrap_or_else(|error| panic!("read the fresh unstripped struct build: {error}"));
    let stripped_bytes: Vec<u8> = std::fs::read(work.join("struct.stripped.bin"))
        .unwrap_or_else(|error| panic!("read the fresh stripped struct build: {error}"));
    let ground_truth: DebugImage = dwarf_gt::load(&unstripped_bytes)
        .unwrap_or_else(|error| panic!("read the DWARF of the fresh struct build: {error}"));
    let (base, text): (u64, Vec<u8>) = dwarf_gt::load_text(&stripped_bytes)
        .unwrap_or_else(|error| panic!("read the .text of the stripped struct build: {error}"));

    let image: DebugImage = DebugImage {
        text_base: base,
        text,
        functions: ground_truth.functions,
        locations: ground_truth.locations,
    };
    eprintln!("fresh struct reference: {}", image.locations);
    assert!(
        image.locations.balances(),
        "the fresh struct survey lost declared variables without naming a reason: {}",
        image.locations,
    );
    let report: StructGradeReport = grade::grade_struct_image(&image);
    assert!(
        report.aggregates_total > 0,
        "the fresh struct build exposed no gradeable aggregate, so this case measured nothing: {}",
        image.locations,
    );
    assert!(report.aggregates_total >= 6, "corpus exposes aggregates");
    assert!(report.missing_leaves.is_empty(), "no field may be missing");
    assert!(report.spurious_leaves.is_empty(), "no invented field");
    assert!((report.offset.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.offset.recall() - 1.0).abs() < f64::EPSILON);
    assert!((report.width.precision() - 1.0).abs() < f64::EPSILON);
    assert!((report.width.recall() - 1.0).abs() < f64::EPSILON);
}
