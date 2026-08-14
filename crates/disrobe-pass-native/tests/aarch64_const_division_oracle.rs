#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{Arch, DisasmInsn, LeafRecovery, disassemble, recover_aarch64_function};

use common::{clang, compile_object_opt, function_code, scratch_dir};

const OPT_LEVELS: [&str; 3] = ["-O1", "-O2", "-Os"];

const CROSS_FLAGS: [&str; 3] = ["-c", "--target=aarch64-linux-gnu", "-ffreestanding"];

const MULTIPLY_MNEMONICS: [&str; 8] = [
    "mul", "madd", "msub", "mneg", "umulh", "smulh", "umull", "smull",
];

const SAMPLED_DIVISORS: [u64; 18] = [
    3,
    5,
    6,
    7,
    9,
    10,
    100,
    641,
    1000,
    1023,
    12345,
    65535,
    65537,
    1_000_003,
    100_000_007,
    2_147_483_647,
    1_000_000_007,
    999_999_937,
];

fn cross_compiler() -> Option<String> {
    let bin: String = clang()?;
    let scratch: ScratchDir = scratch_dir("disrobe-aarch64-div-probe");
    let out: PathBuf = scratch.path().join("probe.o");
    compile_object_opt(
        &bin,
        "-O2",
        &CROSS_FLAGS,
        "unsigned probe(unsigned a){ return a + 1u; }\n",
        &out,
    )
    .map(|_: Vec<u8>| bin)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lowering {
    Multiply,
    ShiftOrCopy,
}

fn lowering_of(code: &[u8], base: u64) -> Option<Lowering> {
    let insns: Vec<DisasmInsn> = disassemble(Arch::Aarch64, base, code).ok()?;
    let multiplies: bool = insns
        .iter()
        .take_while(|insn: &&DisasmInsn| insn.mnemonic != "ret")
        .any(|insn: &DisasmInsn| MULTIPLY_MNEMONICS.contains(&insn.mnemonic.as_str()));
    Some(if multiplies {
        Lowering::Multiply
    } else {
        Lowering::ShiftOrCopy
    })
}

fn recovered_constant_operator(source: &str) -> Option<(char, u64)> {
    for line in source.lines() {
        for operator in ['/', '%'] {
            let Some(position): Option<usize> = line.find(&format!(" {operator} ")) else {
                continue;
            };
            let tail: &str = &line[position..];
            let mut digits: String = String::new();
            let mut best: Option<u64> = None;
            for byte in tail.bytes() {
                if byte.is_ascii_digit() {
                    digits.push(char::from(byte));
                    continue;
                }
                if byte == b'L' && !digits.is_empty() {
                    best = digits.parse::<u64>().ok();
                    break;
                }
                digits.clear();
            }
            if let Some(value) = best {
                return Some((operator, value));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Expectation {
    operator: char,
    divisor: u64,
}

fn battery_source(divisors: &[u64], bits: u32) -> (String, BTreeMap<String, Expectation>) {
    let mut source: String = String::new();
    let mut expected: BTreeMap<String, Expectation> = BTreeMap::new();
    let (unsigned_type, signed_type, unsigned_suffix, signed_suffix): (&str, &str, &str, &str) =
        if bits == 64 {
            ("unsigned long long", "long long", "ull", "ll")
        } else {
            ("unsigned", "int", "u", "")
        };
    for divisor in divisors {
        for (prefix, operator) in [("ud", '/'), ("um", '%')] {
            let name: String = format!("{prefix}{divisor}_{bits}");
            let _ = writeln!(
                source,
                "{unsigned_type} {name}({unsigned_type} a){{ return a {operator} \
                 {divisor}{unsigned_suffix}; }}"
            );
            expected.insert(
                name,
                Expectation {
                    operator,
                    divisor: *divisor,
                },
            );
        }
        if *divisor >= (1u64 << (bits - 1)) {
            continue;
        }
        for (prefix, operator) in [("sd", '/'), ("sm", '%')] {
            let name: String = format!("{prefix}{divisor}_{bits}");
            let _ = writeln!(
                source,
                "{signed_type} {name}({signed_type} a){{ return a {operator} \
                 {divisor}{signed_suffix}; }}"
            );
            expected.insert(
                name,
                Expectation {
                    operator,
                    divisor: *divisor,
                },
            );
        }
    }
    (source, expected)
}

const REQUIRED_CASES: [&str; 16] = [
    "ud3_32",
    "sd3_32",
    "ud7_32",
    "sd7_32",
    "um7_32",
    "sm7_32",
    "ud641_32",
    "ud65537_32",
    "um65537_32",
    "ud1000000007_32",
    "ud7_64",
    "sd7_64",
    "um7_64",
    "sm7_64",
    "ud1000003_64",
    "sd1000003_64",
];

#[derive(Debug, Default)]
struct Tally {
    multiply_lowered: usize,
    recovered: usize,
    unrecovered: Vec<String>,
    wrong: Vec<String>,
    proven: BTreeSet<String>,
}

fn grade_battery(
    compiler: &str,
    opt: &str,
    divisors: &[u64],
    bits: u32,
    scratch: &ScratchDir,
    tally: &mut Tally,
) {
    let (source, expected): (String, BTreeMap<String, Expectation>) =
        battery_source(divisors, bits);
    let object_path: PathBuf = scratch.path().join(format!("aarch64_div_{opt}_{bits}.o"));
    let Some(object): Option<Vec<u8>> =
        compile_object_opt(compiler, opt, &CROSS_FLAGS, &source, &object_path)
    else {
        return;
    };
    for (name, want) in &expected {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, name) else {
            continue;
        };
        let Some(lowering): Option<Lowering> = lowering_of(&code, base) else {
            continue;
        };
        let label: String = format!("clang {opt} {bits}-bit {name}");
        let found: Option<(char, u64)> = match recover_aarch64_function(&code, base) {
            Ok(recovery) => recovered_constant_operator(&recovery.source),
            Err(error) => {
                if lowering == Lowering::Multiply {
                    tally.multiply_lowered += 1;
                    tally
                        .unrecovered
                        .push(format!("{label}: lift failed ({error})"));
                }
                continue;
            }
        };
        match lowering {
            Lowering::Multiply => {
                tally.multiply_lowered += 1;
                match found {
                    Some((operator, value))
                        if operator == want.operator && value == want.divisor =>
                    {
                        tally.recovered += 1;
                        tally.proven.insert(name.clone());
                    }
                    Some((operator, value)) => tally.wrong.push(format!(
                        "{label}: wanted `{} {}` but recovered `{operator} {value}`",
                        want.operator, want.divisor
                    )),
                    None => tally
                        .unrecovered
                        .push(format!("{label}: no division emitted")),
                }
            }
            Lowering::ShiftOrCopy => {
                if let Some((operator, value)) = found {
                    assert!(
                        operator == want.operator && value == want.divisor,
                        "{label}: a shift or copy lowering must never name a different operation, \
                         but the recovery emitted `{operator} {value}` where the source wrote `{} \
                         {}`",
                        want.operator,
                        want.divisor
                    );
                }
            }
        }
    }
}

#[test]
fn aarch64_magic_lowered_division_recovers_the_compiler_divisor() {
    let Some(compiler): Option<String> = cross_compiler() else {
        eprintln!("skipping aarch64 constant-division battery: no clang that targets aarch64");
        return;
    };
    let divisors: Vec<u64> = (1u64..=192)
        .chain(SAMPLED_DIVISORS)
        .collect::<BTreeSet<u64>>()
        .into_iter()
        .collect();
    let scratch: ScratchDir = scratch_dir("disrobe-aarch64-const-division");
    let mut tally: Tally = Tally::default();
    for opt in OPT_LEVELS {
        for bits in [32u32, 64u32] {
            grade_battery(&compiler, opt, &divisors, bits, &scratch, &mut tally);
        }
    }
    assert!(
        tally.multiply_lowered > 0,
        "the aarch64 battery measured nothing: clang emitted no multiply-based division"
    );
    assert!(
        tally.wrong.is_empty(),
        "a recovered aarch64 division named the wrong operation, which silently changes the \
         program:\n{}",
        tally
            .wrong
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<String>>()
            .join("\n")
    );
    let rate: f64 = tally.recovered as f64 / tally.multiply_lowered as f64;
    println!(
        "aarch64 constant-division recovery: {}/{} magic-lowered operations ({:.1}%)",
        tally.recovered,
        tally.multiply_lowered,
        rate * 100.0
    );
    for line in tally.unrecovered.iter().take(12) {
        println!("  still unrecovered: {line}");
    }
    for required in REQUIRED_CASES {
        assert!(
            tally.proven.contains(required),
            "`{required}` never recovered, so the battery proved nothing about the form it \
             covers; the rate alone can hide a whole family"
        );
    }
    assert!(
        rate >= 0.98,
        "aarch64 constant-division recovery fell to {}/{} magic-lowered operations; unrecovered \
         cases:\n{}",
        tally.recovered,
        tally.multiply_lowered,
        tally
            .unrecovered
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<String>>()
            .join("\n")
    );
}

#[test]
fn aarch64_fixed_point_scale_is_never_rewritten_as_a_division() {
    let Some(compiler): Option<String> = cross_compiler() else {
        eprintln!("skipping aarch64 fixed-point near-miss: no clang that targets aarch64");
        return;
    };
    let program: &str = "unsigned near_a(unsigned a){ return (unsigned)(((unsigned long long)a * \
                         3435973837ull) >> 33); }\n\
                         unsigned near_b(unsigned a){ return (unsigned)(((unsigned long long)a * \
                         2454267027ull) >> 35); }\n\
                         unsigned near_c(unsigned a){ return (unsigned)(((unsigned long long)a * \
                         613566757ull) >> 30); }\n";
    let scratch: ScratchDir = scratch_dir("disrobe-aarch64-const-division-nearmiss");
    let mut measured: usize = 0;
    for opt in OPT_LEVELS {
        let object_path: PathBuf = scratch.path().join(format!("aarch64_nearmiss_{opt}.o"));
        let Some(object): Option<Vec<u8>> =
            compile_object_opt(&compiler, opt, &CROSS_FLAGS, program, &object_path)
        else {
            continue;
        };
        for name in ["near_a", "near_b", "near_c"] {
            let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, name) else {
                continue;
            };
            if lowering_of(&code, base) != Some(Lowering::Multiply) {
                continue;
            }
            let Ok(recovery): Result<LeafRecovery, _> = recover_aarch64_function(&code, base)
            else {
                continue;
            };
            measured += 1;
            assert!(
                recovered_constant_operator(&recovery.source).is_none(),
                "clang {opt} {name}: an aarch64 fixed-point scale was rewritten as a \
                 division:\n{}",
                recovery.source
            );
        }
    }
    assert!(
        measured > 0,
        "the aarch64 fixed-point near-miss check measured nothing, so nothing proved the \
         back-check rejects a near miss"
    );
    println!("aarch64 fixed-point near-miss: {measured} multiply-shift scales left as multiplies");
}
