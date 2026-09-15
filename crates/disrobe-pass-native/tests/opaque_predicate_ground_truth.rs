#![cfg(feature = "smt-solver")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::deobf::{
    Bits, OpaqueResult, defeat_bogus_control_flow, defeat_bogus_control_flow_deep,
    locate_containing_block,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use object::{Object, ObjectSection, ObjectSymbol};

const FIXTURE_SRC: &str = include_str!("fixtures/opaque_predicate_ground_truth.c");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroundTruth {
    OpaqueAlwaysTrue,
    OpaqueAlwaysFalse,
    DataDependent,
}

impl GroundTruth {
    const fn is_opaque(self) -> bool {
        !matches!(self, Self::DataDependent)
    }
}

const GROUND_TRUTH: &[(&str, GroundTruth)] = &[
    ("check_even_add", GroundTruth::OpaqueAlwaysTrue),
    ("check_even_sub", GroundTruth::OpaqueAlwaysTrue),
    ("check_bit_tautology", GroundTruth::OpaqueAlwaysTrue),
    ("check_square_never_equal", GroundTruth::OpaqueAlwaysTrue),
    ("check_even_mul", GroundTruth::OpaqueAlwaysTrue),
    ("check_odd_add_never", GroundTruth::OpaqueAlwaysFalse),
    ("check_self_and_complement", GroundTruth::OpaqueAlwaysFalse),
    ("check_square_equal_never", GroundTruth::OpaqueAlwaysFalse),
    ("check_odd_mul_never", GroundTruth::OpaqueAlwaysFalse),
    ("check_data_gt", GroundTruth::DataDependent),
    ("check_data_eq", GroundTruth::DataDependent),
    ("check_data_mod", GroundTruth::DataDependent),
    ("check_data_and", GroundTruth::DataDependent),
    ("check_data_mul_cmp", GroundTruth::DataDependent),
    ("check_data_xor_eq", GroundTruth::DataDependent),
];

fn clang() -> Option<&'static str> {
    Command::new("clang")
        .arg("--version")
        .output()
        .ok()
        .filter(|out: &std::process::Output| out.status.success())
        .map(|_| "clang")
}

fn scratch_dir() -> ScratchDir {
    ScratchDir::create("disrobe-opaque-ground-truth").expect("create scratch directory")
}

fn compile_object(clang_bin: &str, opt_level: &str) -> Option<Vec<u8>> {
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join(format!("fixture_{opt_level}.c"));
    std::fs::write(&src_path, FIXTURE_SRC).expect("write fixture source");
    let obj_path: PathBuf = dir.join(format!("fixture_{opt_level}.o"));
    let compile: std::process::Output = Command::new(clang_bin)
        .args([
            "--target=x86_64-unknown-linux-gnu",
            opt_level,
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-c",
            "-o",
        ])
        .arg(&obj_path)
        .arg(&src_path)
        .output()
        .expect("invoke clang for the ground-truth object");
    if !compile.status.success() {
        eprintln!(
            "skipping {opt_level}: clang cannot emit a linux/x86-64 object on this host: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        return None;
    }
    Some(std::fs::read(&obj_path).expect("read compiled ground-truth object"))
}

fn function_code(object_bytes: &[u8], name: &str) -> Option<(Vec<u8>, u64)> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let sym: object::Symbol<'_, '_> = file
        .symbols()
        .find(|s: &object::Symbol<'_, '_>| s.name().is_ok_and(|n: &str| n == name))?;
    let section_index: object::SectionIndex = match sym.section() {
        object::SymbolSection::Section(idx) => idx,
        _ => return None,
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let size: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if size == 0 {
        let next_off: usize = file
            .symbols()
            .filter(|s: &object::Symbol<'_, '_>| {
                matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                    && s.address() > sym_addr
                    && s.kind() == object::SymbolKind::Text
            })
            .filter_map(|s: object::Symbol<'_, '_>| {
                usize::try_from(s.address().saturating_sub(section.address())).ok()
            })
            .min()
            .unwrap_or(data.len());
        next_off.min(data.len())
    } else {
        start.saturating_add(size).min(data.len())
    };
    let slice: &[u8] = data.get(start..end)?;
    Some((slice.to_vec(), sym_addr))
}

fn conditional_branch_addresses(code: &[u8], base: u64) -> Vec<u64> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, code, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut out: Vec<u64> = Vec::new();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        if insn.flow_control() == FlowControl::ConditionalBranch {
            out.push(insn.ip());
        }
    }
    out
}

#[derive(Debug, Default, Clone, Copy)]
struct Confusion {
    true_positive: u32,
    false_positive: u32,
    false_negative: u32,
    true_negative: u32,
    resolved_by_compiler: u32,
}

impl Confusion {
    fn precision(self) -> f64 {
        let denom: u32 = self.true_positive + self.false_positive;
        if denom == 0 {
            1.0
        } else {
            f64::from(self.true_positive) / f64::from(denom)
        }
    }

    fn recall(self) -> f64 {
        let denom: u32 = self.true_positive + self.false_negative;
        if denom == 0 {
            1.0
        } else {
            f64::from(self.true_positive) / f64::from(denom)
        }
    }
}

fn grade_pass<F>(object_bytes: &[u8], opt_level: &str, pass_name: &str, resolve: F) -> Confusion
where
    F: Fn(u64, &[u8], u64) -> Option<OpaqueResult>,
{
    let mut confusion: Confusion = Confusion::default();
    for &(name, truth) in GROUND_TRUTH {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
            eprintln!("[{opt_level}/{pass_name}] {name}: symbol not located, skipping");
            continue;
        };
        let branches: Vec<u64> = conditional_branch_addresses(&code, base);
        let Some(&branch_address): Option<&u64> = branches.first() else {
            confusion.resolved_by_compiler += 1;
            eprintln!(
                "[{opt_level}/{pass_name}] {name}: no conditional branch survived compilation (compiler already folded it)"
            );
            continue;
        };
        let outcome: Option<OpaqueResult> = resolve(base, &code, branch_address);
        let predicted_opaque: bool = matches!(
            outcome,
            Some(OpaqueResult::AlwaysTaken | OpaqueResult::AlwaysNotTaken)
        );
        match (truth.is_opaque(), predicted_opaque) {
            (true, true) => confusion.true_positive += 1,
            (true, false) => confusion.false_negative += 1,
            (false, true) => confusion.false_positive += 1,
            (false, false) => confusion.true_negative += 1,
        }
        eprintln!("[{opt_level}/{pass_name}] {name}: ground_truth={truth:?} verdict={outcome:?}");
    }
    confusion
}

#[test]
fn measures_precision_and_recall_against_real_clang_compiled_ground_truth() {
    let Some(clang_bin): Option<&str> = clang() else {
        eprintln!("skipping: clang not on PATH, no real non-circular oracle available");
        return;
    };

    for opt_level in ["-O0", "-O1"] {
        let Some(object_bytes): Option<Vec<u8>> = compile_object(clang_bin, opt_level) else {
            continue;
        };

        let fast: Confusion = grade_pass(
            &object_bytes,
            opt_level,
            "fast-pattern-match",
            |base, code, branch_address| {
                let (block_addr, range): (u64, std::ops::Range<usize>) =
                    locate_containing_block(64, base, code, branch_address)?;
                defeat_bogus_control_flow(Bits::Bits64, block_addr, &code[range])
                    .map(|found| found.result)
            },
        );
        let deep: Confusion = grade_pass(
            &object_bytes,
            opt_level,
            "backward-dse-smt",
            |base, code, branch_address| {
                defeat_bogus_control_flow_deep(Bits::Bits64, base, code, branch_address)
                    .map(|found| found.result)
            },
        );

        println!(
            "{opt_level} fast pattern-match: TP={} FP={} FN={} TN={} compiler-resolved={} precision={:.3} recall={:.3}",
            fast.true_positive,
            fast.false_positive,
            fast.false_negative,
            fast.true_negative,
            fast.resolved_by_compiler,
            fast.precision(),
            fast.recall(),
        );
        println!(
            "{opt_level} composed backward DSE+SMT: TP={} FP={} FN={} TN={} compiler-resolved={} precision={:.3} recall={:.3}",
            deep.true_positive,
            deep.false_positive,
            deep.false_negative,
            deep.true_negative,
            deep.resolved_by_compiler,
            deep.precision(),
            deep.recall(),
        );

        assert_eq!(
            fast.false_positive, 0,
            "{opt_level}: the fast pattern-match pass must never claim a genuinely data-dependent branch is opaque"
        );
        assert_eq!(
            deep.false_positive, 0,
            "{opt_level}: the composed backward DSE+SMT pass must never claim a genuinely data-dependent branch is opaque"
        );
        assert!(
            deep.true_positive >= fast.true_positive,
            "{opt_level}: composing the deep pass must never regress recall below the fast pass alone"
        );
    }
}
