#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::fmt::Write as _;
use std::path::PathBuf;

use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, ProgramFunction, RecoveredProgram, disassemble,
    recover_leaf_function_abi, recover_program,
};

use common::{
    CompilerId, available_compilers, compile_object_opt, function_code, link_and_run, scratch_dir,
    strip_includes,
};
use disrobe_core::scratch::ScratchDir;

const OPT_LEVELS: [&str; 3] = ["-O1", "-O2", "-Os"];

const SAMPLED_DIVISORS: [u64; 24] = [
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
    1024,
    12345,
    65535,
    65537,
    1_000_003,
    16_777_216,
    100_000_007,
    2_147_483_647,
    2_147_483_648,
    3_000_000_019,
    4_294_967_291,
    4_294_967_295,
    1_000_000_007,
    999_999_937,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lowering {
    Multiply,
    ShiftOrCopy,
}

fn lowering_of(code: &[u8], base: u64) -> Option<Lowering> {
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, code).ok()?;
    let mut saw_multiply: bool = false;
    for insn in &insns {
        if insn.mnemonic == "ret" {
            break;
        }
        if matches!(insn.mnemonic.as_str(), "imul" | "mul" | "mulx") {
            saw_multiply = true;
        }
    }
    Some(if saw_multiply {
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

fn battery_source(divisors: &[u64], bits: u32) -> String {
    let mut source: String = String::new();
    let (unsigned_type, signed_type, suffix): (&str, &str, &str) = if bits == 64 {
        ("unsigned long long", "long long", "ull")
    } else {
        ("unsigned", "int", "u")
    };
    for divisor in divisors {
        let _ = writeln!(
            source,
            "{unsigned_type} ud{divisor}({unsigned_type} a){{ return a / {divisor}{suffix}; }}"
        );
        if *divisor < (1u64 << (bits - 1)) {
            let signed_suffix: &str = if bits == 64 { "ll" } else { "" };
            let _ = writeln!(
                source,
                "{signed_type} sd{divisor}({signed_type} a){{ return a / {divisor}{signed_suffix}; }}"
            );
        }
    }
    source
}

struct BatteryTally {
    multiply_lowered: usize,
    recovered: usize,
    unrecovered: Vec<String>,
    wrong: Vec<String>,
}

fn grade_battery(
    compiler: &CompilerId,
    opt: &str,
    divisors: &[u64],
    bits: u32,
    scratch: &ScratchDir,
    tally: &mut BatteryTally,
) {
    let source: String = battery_source(divisors, bits);
    let object_path: PathBuf = scratch
        .path()
        .join(format!("division_{}_{opt}_{bits}.o", compiler.bin));
    let Some(object): Option<Vec<u8>> =
        compile_object_opt(compiler.bin, opt, &["-c"], &source, &object_path)
    else {
        return;
    };
    for divisor in divisors {
        for prefix in ["ud", "sd"] {
            if prefix == "sd" && *divisor >= (1u64 << (bits - 1)) {
                continue;
            }
            let name: String = format!("{prefix}{divisor}");
            let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, &name) else {
                continue;
            };
            let Some(lowering): Option<Lowering> = lowering_of(&code, base) else {
                continue;
            };
            let label: String = format!("{} {opt} {bits}-bit {name}", compiler.bin);
            let recovery: LeafRecovery =
                match recover_leaf_function_abi(&code, base, common::HOST_ABI) {
                    Ok(value) => value,
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
            let found: Option<(char, u64)> = recovered_constant_operator(&recovery.source);
            match lowering {
                Lowering::Multiply => {
                    tally.multiply_lowered += 1;
                    match found {
                        Some(('/', value)) if value == *divisor => tally.recovered += 1,
                        Some((operator, value)) => tally
                            .wrong
                            .push(format!("{label}: recovered `{operator} {value}`")),
                        None => tally
                            .unrecovered
                            .push(format!("{label}: no division emitted")),
                    }
                }
                Lowering::ShiftOrCopy => {
                    if let Some((operator, value)) = found {
                        assert!(
                            value == *divisor,
                            "{label}: a shift or copy lowering must never produce a different \
                             divisor, but the recovery emitted `{operator} {value}`"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn magic_lowered_division_recovers_the_compiler_divisor() {
    let compilers: Vec<CompilerId> = available_compilers();
    if compilers.is_empty() {
        eprintln!("skipping constant-division battery: no C compiler on PATH");
        return;
    }
    let divisors: Vec<u64> = (1u64..=1024)
        .chain(SAMPLED_DIVISORS)
        .collect::<std::collections::BTreeSet<u64>>()
        .into_iter()
        .collect();
    let scratch: ScratchDir = scratch_dir("disrobe-const-division");
    let mut tally: BatteryTally = BatteryTally {
        multiply_lowered: 0,
        recovered: 0,
        unrecovered: Vec::new(),
        wrong: Vec::new(),
    };
    for compiler in &compilers {
        for opt in OPT_LEVELS {
            for bits in [32u32, 64u32] {
                grade_battery(compiler, opt, &divisors, bits, &scratch, &mut tally);
            }
        }
    }
    assert!(
        tally.multiply_lowered > 0,
        "the battery measured nothing: no compiler emitted a multiply-based division"
    );
    assert!(
        tally.wrong.is_empty(),
        "a recovered division named the wrong divisor, which silently changes the program:\n{}",
        tally.wrong.join("\n")
    );
    let rate: f64 = tally.recovered as f64 / tally.multiply_lowered as f64;
    println!(
        "constant-division recovery: {}/{} magic-lowered divisions ({:.1}%)",
        tally.recovered,
        tally.multiply_lowered,
        rate * 100.0
    );
    for line in tally.unrecovered.iter().take(12) {
        println!("  still unrecovered: {line}");
    }
    assert!(
        rate >= 0.98,
        "constant-division recovery fell to {}/{} magic-lowered divisions; unrecovered cases:\n{}",
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

struct DifferentialCase {
    name: &'static str,
    arity: usize,
    c_source: String,
}

fn differential_cases() -> Vec<DifferentialCase> {
    let mut cases: Vec<DifferentialCase> = Vec::new();
    for (name, text) in [
        ("cd_u7", "unsigned cd_u7(unsigned a){ return a / 7u; }"),
        ("cd_s7", "int cd_s7(int a){ return a / 7; }"),
        ("cd_u3", "unsigned cd_u3(unsigned a){ return a / 3u; }"),
        ("cd_s3", "int cd_s3(int a){ return a / 3; }"),
        ("cd_u6", "unsigned cd_u6(unsigned a){ return a / 6u; }"),
        ("cd_s5", "int cd_s5(int a){ return a / 5; }"),
        (
            "cd_u641",
            "unsigned cd_u641(unsigned a){ return a / 641u; }",
        ),
        (
            "cd_ubig",
            "unsigned cd_ubig(unsigned a){ return a / 4294967291u; }",
        ),
        ("cm_u7", "unsigned cm_u7(unsigned a){ return a % 7u; }"),
        ("cm_s7", "int cm_s7(int a){ return a % 7; }"),
        ("cm_s11", "int cm_s11(int a){ return a % 11; }"),
        (
            "cd_mix",
            "unsigned cd_mix(unsigned a){ return a / 7u + a; }",
        ),
        (
            "cd_mix2",
            "unsigned cd_mix2(unsigned a){ return (a / 7u) * 3u + (a % 7u); }",
        ),
        (
            "cd_u64",
            "unsigned long long cd_u64(unsigned long long a){ return a / 7ull; }",
        ),
        (
            "cd_u64b",
            "unsigned long long cd_u64b(unsigned long long a){ return a / 1000003ull; }",
        ),
        ("cd_s64", "long long cd_s64(long long a){ return a / 7ll; }"),
        (
            "cd_s64b",
            "long long cd_s64b(long long a){ return a / 3ll; }",
        ),
        (
            "cd_s64c",
            "long long cd_s64c(long long a){ return a / 1000003ll; }",
        ),
        ("cm_s64", "long long cm_s64(long long a){ return a % 7ll; }"),
        ("cd_u14", "unsigned cd_u14(unsigned a){ return a / 14u; }"),
        ("cd_u28", "unsigned cd_u28(unsigned a){ return a / 28u; }"),
        ("cd_s5b", "int cd_s5b(int a){ return a / 9; }"),
        (
            "cd_scale",
            "unsigned cd_scale(unsigned a){ return (unsigned)(((unsigned long long)a * 3435973837ull) >> 33); }",
        ),
        (
            "cd_scale2",
            "unsigned cd_scale2(unsigned a){ return (unsigned)(((unsigned long long)a * 2454267027ull) >> 35); }",
        ),
    ] {
        cases.push(DifferentialCase {
            name,
            arity: 1,
            c_source: text.to_owned(),
        });
    }
    cases
}

const DIFFERENTIAL_INPUTS: &str = "0, 1, 2, 3, 6, 7, 8, 13, 14, 41, 100, 1000, 65535, 65536, \
     2147483647, 2147483648ULL, 4294967294ULL, 4294967295ULL, \
     18446744073709551615ULL, 9223372036854775807ULL, 9223372036854775808ULL, \
     0xdeadbeefULL, 0xcafef00dULL, 123456789ULL, 999999937ULL";

#[test]
fn recovered_constant_division_matches_the_compiled_function() {
    let compilers: Vec<CompilerId> = available_compilers();
    if compilers.is_empty() {
        eprintln!("skipping constant-division differential: no C compiler on PATH");
        return;
    }
    let cases: Vec<DifferentialCase> = differential_cases();
    let mut program: String = String::new();
    for case in &cases {
        program.push_str(&case.c_source);
        program.push('\n');
    }
    let scratch: ScratchDir = scratch_dir("disrobe-const-division-diff");
    let mut measured: usize = 0;
    for compiler in &compilers {
        for opt in OPT_LEVELS {
            let object_path: PathBuf = scratch
                .path()
                .join(format!("differential_{}_{opt}.o", compiler.bin));
            let Some(object): Option<Vec<u8>> =
                compile_object_opt(compiler.bin, opt, &["-c"], &program, &object_path)
            else {
                continue;
            };
            let mut declarations: String = String::new();
            let mut body: String = String::new();
            let mut lifted: usize = 0;
            for case in &cases {
                let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, case.name)
                else {
                    continue;
                };
                let Ok(recovery): Result<LeafRecovery, _> =
                    recover_leaf_function_abi(&code, base, common::HOST_ABI)
                else {
                    continue;
                };
                let recovered_name: String = format!("rec_{}", case.name);
                let renamed: String = strip_includes(&recovery.source.replacen(
                    "uint64_t recovered(",
                    &format!("uint64_t {recovered_name}("),
                    1,
                ));
                declarations.push_str(&renamed);
                declarations.push('\n');
                let _ = writeln!(
                    declarations,
                    "extern unsigned long long {}(unsigned long long);",
                    case.name
                );
                let mask: String = if recovery.return_width_bits == 64 {
                    "0xFFFFFFFFFFFFFFFFULL".to_owned()
                } else {
                    format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
                };
                let arguments: String = (0..case.arity.max(recovery.signature.callable_arity()))
                    .map(|_| "in".to_owned())
                    .collect::<Vec<String>>()
                    .join(", ");
                let _ = write!(
                    body,
                    "    for (size_t k = 0; k < n_inputs; k++) {{\n\
                     \x20       unsigned long long in = inputs[k];\n\
                     \x20       unsigned long long want = (unsigned long long){}(in) & {mask};\n\
                     \x20       unsigned long long got = {recovered_name}({arguments}) & {mask};\n\
                     \x20       if (want != got) {{ printf(\"MISMATCH {} in=%llu want=%llu got=%llu\\n\", in, want, got); return 1; }}\n\
                     \x20   }}\n",
                    case.name, case.name,
                );
                lifted += 1;
            }
            if lifted == 0 {
                continue;
            }
            let driver: String = format!(
                "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{declarations}\n\
                 int main(void) {{\n\
                 \x20   unsigned long long inputs[] = {{ {DIFFERENTIAL_INPUTS} }};\n\
                 \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
                 {body}\
                 \x20   printf(\"OK\\n\");\n\
                 \x20   return 0;\n\
                 }}\n"
            );
            let tag: String = format!("constdiv_{}_{}", compiler.bin, opt.trim_start_matches('-'));
            let stdout: String = link_and_run(compiler.bin, &driver, &object, &tag, 60);
            assert!(
                stdout.contains("OK"),
                "{} {opt}: a recovered constant division disagreed with the compiled function:\n{stdout}",
                compiler.bin
            );
            measured += lifted;
        }
    }
    assert!(
        measured > 0,
        "the constant-division differential measured nothing"
    );
    println!("constant-division differential: {measured} recovered functions executed");
}

#[test]
fn a_fixed_point_scale_is_never_rewritten_as_a_division() {
    let compilers: Vec<CompilerId> = available_compilers();
    if compilers.is_empty() {
        eprintln!("skipping fixed-point near-miss: no C compiler on PATH");
        return;
    }
    let program: &str = "unsigned near_a(unsigned a){ return (unsigned)(((unsigned long long)a * 3435973837ull) >> 33); }\n\
         unsigned near_b(unsigned a){ return (unsigned)(((unsigned long long)a * 2454267027ull) >> 35); }\n\
         unsigned near_c(unsigned a){ return (unsigned)(((unsigned long long)a * 613566757ull) >> 30); }\n";
    let scratch: ScratchDir = scratch_dir("disrobe-const-division-nearmiss");
    let mut measured: usize = 0;
    for compiler in &compilers {
        for opt in OPT_LEVELS {
            let object_path: PathBuf = scratch
                .path()
                .join(format!("nearmiss_{}_{opt}.o", compiler.bin));
            let Some(object): Option<Vec<u8>> =
                compile_object_opt(compiler.bin, opt, &["-c"], program, &object_path)
            else {
                continue;
            };
            for name in ["near_a", "near_b", "near_c"] {
                let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, name)
                else {
                    continue;
                };
                if lowering_of(&code, base) != Some(Lowering::Multiply) {
                    continue;
                }
                let Ok(recovery): Result<LeafRecovery, _> =
                    recover_leaf_function_abi(&code, base, common::HOST_ABI)
                else {
                    continue;
                };
                measured += 1;
                assert!(
                    recovered_constant_operator(&recovery.source).is_none(),
                    "{} {opt} {name}: a fixed-point scale was rewritten as a division:\n{}",
                    compiler.bin,
                    recovery.source
                );
            }
        }
    }
    assert!(
        measured > 0,
        "the fixed-point near-miss check measured nothing: no multiply-shift scale survived \
         optimization, so nothing proved the back-check rejects a near miss"
    );
    println!("fixed-point near-miss: {measured} multiply-shift scales left as multiplies");
}

#[test]
fn whole_program_recovery_reaches_constant_division() {
    let compilers: Vec<CompilerId> = available_compilers();
    if compilers.is_empty() {
        eprintln!("skipping whole-program constant division: no C compiler on PATH");
        return;
    }
    let program: &str = "unsigned wp_div(unsigned a){ return a / 7u; }\n\
         unsigned wp_entry(unsigned a){ return wp_div(a) + wp_div(a + 1u); }\n";
    let scratch: ScratchDir = scratch_dir("disrobe-const-division-wholeprog");
    let mut measured: usize = 0;
    for compiler in &compilers {
        let object_path: PathBuf = scratch.path().join(format!("wholeprog_{}.o", compiler.bin));
        let Some(object): Option<Vec<u8>> =
            compile_object_opt(compiler.bin, "-O2", &["-c"], program, &object_path)
        else {
            continue;
        };
        let mut functions: Vec<ProgramFunction> = Vec::new();
        for name in ["wp_div", "wp_entry"] {
            let Some((code, address)): Option<(Vec<u8>, u64)> = function_code(&object, name) else {
                continue;
            };
            functions.push(ProgramFunction {
                name: name.to_owned(),
                address,
                code,
            });
        }
        if functions.is_empty() {
            continue;
        }
        let recovered: RecoveredProgram = recover_program(&object, &functions, common::HOST_ABI);
        let Some(divider) = recovered
            .recovered
            .iter()
            .find(|function| function.name == "wp_div")
        else {
            continue;
        };
        measured += 1;
        assert_eq!(
            recovered_constant_operator(&divider.source),
            Some(('/', 7)),
            "{}: whole-program recovery must reach the constant-division idiom:\n{}",
            compiler.bin,
            divider.source
        );
    }
    assert!(
        measured > 0,
        "the whole-program constant-division check measured nothing"
    );
}
