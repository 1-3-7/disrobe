#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{
    LeafRecovery, PseudoAbi, PseudoScalarType as ScalarType, recover_leaf_function_abi,
};

#[path = "support/compiler_toolchain.rs"]
#[allow(clippy::redundant_pub_crate)]
mod compiler_toolchain;
#[path = "support/object_symbol.rs"]
#[allow(clippy::redundant_pub_crate)]
mod object_symbol;

use object_symbol::function_code;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    Int,
    Float,
    Double,
    AnyFp,
    Aggregate,
    NotScalarFp,
    NeverScalarFp,
}

struct Case {
    name: &'static str,
    group: &'static str,
    channel: Channel,
    source: &'static str,
}

const PRELUDE: &str = "typedef double v2df __attribute__((vector_size(16)));\n\
     typedef struct { long long a; long long b; long long c; } triple;\n\
     typedef struct { long long i; double d; } mixed;\n";

const CASES: &[Case] = &[
    Case {
        name: "rc_feq_ll",
        group: "compare-only reload",
        channel: Channel::Int,
        source: "long long rc_feq_ll(double a, double b){ return a == b; }",
    },
    Case {
        name: "rc_fne_ll",
        group: "compare-only reload",
        channel: Channel::Int,
        source: "long long rc_fne_ll(double a, double b){ return a != b; }",
    },
    Case {
        name: "rc_flt_f",
        group: "compare-only reload",
        channel: Channel::Int,
        source: "long long rc_flt_f(float a, float b){ return a < b; }",
    },
    Case {
        name: "rc_fle_d",
        group: "compare-only reload",
        channel: Channel::Int,
        source: "int rc_fle_d(double a, double b){ return a <= b; }",
    },
    Case {
        name: "rc_fgt_f",
        group: "compare-only reload",
        channel: Channel::Int,
        source: "int rc_fgt_f(float a, float b){ return a > b; }",
    },
    Case {
        name: "rc_fge_d",
        group: "compare-only reload",
        channel: Channel::Int,
        source: "int rc_fge_d(double a, double b){ return a >= b; }",
    },
    Case {
        name: "rc_uno_d",
        group: "compare-only reload",
        channel: Channel::Int,
        source: "int rc_uno_d(double a, double b){ return a != a || b != b; }",
    },
    Case {
        name: "rc_bool_d",
        group: "boolean materialization",
        channel: Channel::Int,
        source: "_Bool rc_bool_d(double a, double b){ return a < b; }",
    },
    Case {
        name: "rc_sel_int",
        group: "boolean materialization",
        channel: Channel::Int,
        source: "long long rc_sel_int(double a, double b, long long x, long long y){ return a < b ? x : y; }",
    },
    Case {
        name: "rc_count",
        group: "boolean materialization",
        channel: Channel::Int,
        source: "int rc_count(double a, double b, double c){ return (a < b) + (b < c); }",
    },
    Case {
        name: "rc_add_d",
        group: "floating-point result",
        channel: Channel::Double,
        source: "double rc_add_d(double a, double b){ return a + b; }",
    },
    Case {
        name: "rc_mul_f",
        group: "floating-point result",
        channel: Channel::Float,
        source: "float rc_mul_f(float a, float b){ return a * b; }",
    },
    Case {
        name: "rc_div_d",
        group: "floating-point result",
        channel: Channel::Double,
        source: "double rc_div_d(double a, double b){ return a / b; }",
    },
    Case {
        name: "rc_sqrt_d",
        group: "floating-point result",
        channel: Channel::Double,
        source: "double rc_sqrt_d(double a){ return __builtin_sqrt(a) * 2.0; }",
    },
    Case {
        name: "rc_i2d",
        group: "floating-point result",
        channel: Channel::Double,
        source: "double rc_i2d(long long a){ return (double)a; }",
    },
    Case {
        name: "rc_f2d",
        group: "floating-point result",
        channel: Channel::Double,
        source: "double rc_f2d(float a){ return (double)a; }",
    },
    Case {
        name: "rc_pick_d",
        group: "floating-point result moved from another xmm register, whose scalar width the move instruction does not carry",
        channel: Channel::AnyFp,
        source: "double rc_pick_d(double a, double b){ (void)a; return b; }",
    },
    Case {
        name: "rc_cmp_then_fp",
        group: "floating-point result",
        channel: Channel::Double,
        source: "double rc_cmp_then_fp(double a, double b){ return a < b ? a + b : a - b; }",
    },
    Case {
        name: "rc_zero_d",
        group: "floating-point result",
        channel: Channel::Double,
        source: "double rc_zero_d(void){ return 0.0; }",
    },
    Case {
        name: "rc_discard_fp",
        group: "integer result touching xmm0",
        channel: Channel::Int,
        source: "long long rc_discard_fp(double a, long long b){ (void)a; return b; }",
    },
    Case {
        name: "rc_cmp_pick_int",
        group: "integer result touching xmm0",
        channel: Channel::Int,
        source: "long long rc_cmp_pick_int(double a, double b, long long c){ if (a > b) return c; return -c; }",
    },
    Case {
        name: "rc_zero_then_int",
        group: "integer result touching xmm0",
        channel: Channel::Int,
        source: "long long rc_zero_then_int(double *p){ *p = 0.0; return 1; }",
    },
    Case {
        name: "rc_store_reload",
        group: "integer result touching xmm0",
        channel: Channel::Int,
        source: "long long rc_store_reload(double a, double *p){ *p = a; return 7; }",
    },
    Case {
        name: "rc_triple",
        group: "aggregate return",
        channel: Channel::Aggregate,
        source: "triple rc_triple(long long x){ triple t; t.a = x; t.b = x + 1; t.c = x + 2; return t; }",
    },
    Case {
        name: "rc_vec_add",
        group: "vector return",
        channel: Channel::NeverScalarFp,
        source: "v2df rc_vec_add(v2df a, v2df b){ return a + b; }",
    },
    Case {
        name: "rc_void_store",
        group: "void return",
        channel: Channel::NotScalarFp,
        source: "void rc_void_store(double a, double *p){ *p = a * 2.0; }",
    },
    Case {
        name: "rc_loop_sum",
        group: "multi-site return",
        channel: Channel::Double,
        source: "double rc_loop_sum(const double *p, int n){ double s = 0.0; int i; for (i = 0; i < n; i++) { s += p[i]; } return s; }",
    },
    Case {
        name: "rc_branch_fp",
        group: "multi-site return",
        channel: Channel::Double,
        source: "double rc_branch_fp(double a, double b){ if (a > b) { return a; } return b; }",
    },
];

const LEVELS: [&str; 5] = ["-O0", "-O1", "-O2", "-O3", "-Os"];

const HOST_ABI: PseudoAbi = if cfg!(windows) {
    PseudoAbi::MsX64
} else {
    PseudoAbi::SysV
};

fn cc() -> Option<String> {
    compiler_toolchain::probe_any(&["gcc", "clang", "cc"])
}

fn battery_source() -> String {
    let mut source: String = PRELUDE.to_owned();
    for case in CASES {
        source.push_str(case.source);
        source.push('\n');
    }
    source
}

fn compile(
    dir: &Path,
    source: &str,
    compiler: &str,
    extra: &[&str],
    tag: &str,
    level: &str,
) -> Option<Vec<u8>> {
    let battery_c: PathBuf = dir.join("return_channel_battery.c");
    std::fs::write(&battery_c, source.as_bytes()).expect("write battery source");
    let object_path: PathBuf = dir.join(format!("{tag}{level}.o"));
    let mut command: Command = Command::new(compiler);
    command
        .args(extra)
        .args([level, "-fno-stack-protector", "-c", "-o"])
        .arg(&object_path)
        .arg(&battery_c);
    let output: std::process::Output = command.output().expect("invoke the c compiler");
    if !output.status.success() {
        eprintln!(
            "{tag} {level} compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    Some(std::fs::read(&object_path).expect("read the compiled object"))
}

fn channel_mismatch(case: &Case, recovery: &LeafRecovery) -> Option<String> {
    let returns_fp: Option<ScalarType> = recovery.returns_fp;
    let aggregate: bool = recovery.sret.is_some();
    let matched: bool = match case.channel {
        Channel::Int => returns_fp.is_none() && !aggregate,
        Channel::Float => returns_fp == Some(ScalarType::Float),
        Channel::Double => returns_fp == Some(ScalarType::Double),
        Channel::AnyFp => returns_fp.is_some(),
        Channel::Aggregate | Channel::NotScalarFp | Channel::NeverScalarFp => returns_fp.is_none(),
    };
    if matched {
        return None;
    }
    Some(format!(
        "declared {:?} but recovered returns_fp={returns_fp:?} aggregate={aggregate} width={}",
        case.channel, recovery.return_width_bits
    ))
}

struct Target {
    tag: &'static str,
    compiler: String,
    extra: Vec<&'static str>,
    abi: PseudoAbi,
}

fn targets() -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    let Some(compiler): Option<String> = cc() else {
        return out;
    };
    out.push(Target {
        tag: "host",
        compiler,
        extra: Vec::new(),
        abi: HOST_ABI,
    });
    if compiler_toolchain::probe_one("clang").is_some() {
        out.push(Target {
            tag: "sysv",
            compiler: "clang".to_owned(),
            extra: vec!["--target=x86_64-unknown-linux-gnu", "-fcf-protection=none"],
            abi: PseudoAbi::SysV,
        });
    }
    out
}

#[test]
fn declared_return_channel_survives_every_optimization_level() {
    let targets: Vec<Target> = targets();
    assert!(
        !targets.is_empty(),
        "no C compiler on PATH; this corpus is graded against a real compiler and cannot run without one"
    );
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-return-channel").expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery: String = battery_source();

    let mut recovered_per_case: Vec<usize> = vec![0; CASES.len()];
    let mut aggregate_per_case: Vec<usize> = vec![0; CASES.len()];
    let mut attempted: usize = 0;
    let mut mismatches: Vec<String> = Vec::new();

    for target in &targets {
        for level in LEVELS {
            let Some(object): Option<Vec<u8>> = compile(
                &dir,
                &battery,
                &target.compiler,
                &target.extra,
                target.tag,
                level,
            ) else {
                continue;
            };
            for (index, case) in CASES.iter().enumerate() {
                let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, case.name)
                else {
                    eprintln!("{} {level} {}: symbol not located", target.tag, case.name);
                    continue;
                };
                attempted += 1;
                let recovery: LeafRecovery =
                    match recover_leaf_function_abi(&code, base, target.abi) {
                        Ok(recovery) => recovery,
                        Err(error) => {
                            eprintln!(
                                "{} {level} {}: outside the leaf class ({error})",
                                target.tag, case.name
                            );
                            continue;
                        }
                    };
                recovered_per_case[index] += 1;
                if recovery.sret.is_some() {
                    aggregate_per_case[index] += 1;
                }
                if let Some(reason) = channel_mismatch(case, &recovery) {
                    mismatches.push(format!(
                        "{} {level} {} [{}]: {reason}",
                        target.tag, case.name, case.group
                    ));
                }
            }
        }
    }

    for (case, count) in CASES.iter().zip(&recovered_per_case) {
        println!("{:<20} {:>2} recovered  [{}]", case.name, count, case.group);
    }
    assert!(
        mismatches.is_empty(),
        "the recovered return channel disagrees with the declared C return type:\n{}",
        mismatches.join("\n")
    );
    let never_recovered: Vec<&str> = CASES
        .iter()
        .zip(&recovered_per_case)
        .filter(|(case, count): &(&Case, &usize)| {
            **count == 0 && case.channel != Channel::NeverScalarFp
        })
        .map(|(case, _): (&Case, &usize)| case.name)
        .collect();
    assert!(
        never_recovered.is_empty(),
        "these rows recovered at no optimization level, so they grade nothing: {never_recovered:?}"
    );
    let aggregate_never_detected: Vec<&str> = CASES
        .iter()
        .zip(&aggregate_per_case)
        .filter(|(case, count): &(&Case, &usize)| {
            case.channel == Channel::Aggregate && **count == 0
        })
        .map(|(case, _): (&Case, &usize)| case.name)
        .collect();
    assert!(
        aggregate_never_detected.is_empty(),
        "an aggregate row never produced a hidden-pointer return plan at any optimization level, so nothing proves the aggregate path is reached: {aggregate_never_detected:?}"
    );
    let graded: usize = recovered_per_case.iter().sum();
    println!(
        "return channel graded on {graded} of {attempted} recovered functions across {} rows and {} targets",
        CASES.len(),
        targets.len()
    );
}

const LIMIT_PRELUDE: &str = "typedef struct { long long i; double d; } limit_mixed;\n";

const LIMIT_CASES: &[(&str, &str, Option<ScalarType>, &str)] = &[
    (
        "rc_limit_two_register_aggregate",
        "limit_mixed rc_limit_two_register_aggregate(long long i, double d){ limit_mixed m; m.i = i; m.d = d; return m; }",
        Some(ScalarType::Double),
        "a System V aggregate returned in rax and xmm0 together is claimed as a scalar double, because at register level it is identical to a floating-point return whose dead integer load happens to sit in rax; deciding it needs the aggregate plan, not the return channel",
    ),
    (
        "rc_limit_fp_tail_call",
        "double rc_limit_fp_tail_call(double a){ return __builtin_sqrt(a); }",
        None,
        "a tail call whose callee returns in xmm0 is claimed as an integer return, because a call is modelled as defining the integer result register and the callee's return type is not known from a relocated call site",
    ),
];

fn limit_battery_source() -> String {
    let mut source: String = LIMIT_PRELUDE.to_owned();
    for (_, case_source, _, _) in LIMIT_CASES {
        source.push_str(case_source);
        source.push('\n');
    }
    source
}

#[test]
fn recorded_limits_of_a_register_only_return_channel() {
    let targets: Vec<Target> = targets();
    assert!(!targets.is_empty(), "no C compiler on PATH");
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-return-channel-limits").expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery: String = limit_battery_source();

    let mut observed: Vec<usize> = vec![0; LIMIT_CASES.len()];
    for target in &targets {
        for level in LEVELS {
            let Some(object): Option<Vec<u8>> = compile(
                &dir,
                &battery,
                &target.compiler,
                &target.extra,
                target.tag,
                level,
            ) else {
                continue;
            };
            for (index, (name, _, limit_channel, _)) in LIMIT_CASES.iter().enumerate() {
                let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, name)
                else {
                    continue;
                };
                let Ok(recovery): Result<LeafRecovery, _> =
                    recover_leaf_function_abi(&code, base, target.abi)
                else {
                    continue;
                };
                if recovery.returns_fp == *limit_channel && recovery.sret.is_none() {
                    observed[index] += 1;
                }
            }
        }
    }

    for ((name, _, _, explanation), count) in LIMIT_CASES.iter().zip(&observed) {
        assert!(
            *count > 0,
            "{name} no longer reproduces its recorded limit at any optimization level. The limit \
             was: {explanation}. Re-measure it and rewrite this record rather than deleting it."
        );
        println!("recorded limit {name} still reproduces at {count} of the compiled variants");
    }
}

const HAND_ASSEMBLED_ABSTENTIONS: &[(&str, &[u8])] = &[(
    "return sites disagree on the channel",
    &[
        0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x10, 0x45, 0x10, 0x66, 0x0f, 0x2f, 0x45, 0x18, 0x76,
        0x07, 0xf2, 0x0f, 0x10, 0x45, 0x10, 0xeb, 0x05, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x5d, 0xc3,
    ],
)];

#[test]
fn an_undecidable_channel_abstains_with_a_named_reason() {
    for (index, (description, code)) in HAND_ASSEMBLED_ABSTENTIONS.iter().enumerate() {
        let base: u64 = 0x1_4000_1000 + (index as u64) * 0x100;
        let error: String = match recover_leaf_function_abi(code, base, PseudoAbi::MsX64) {
            Ok(recovery) => panic!(
                "{description}: expected an abstention, got returns_fp={:?} width={}",
                recovery.returns_fp, recovery.return_width_bits
            ),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("return channel reject"),
            "{description}: abstained without naming the return channel as the reason: {error}"
        );
    }
}
