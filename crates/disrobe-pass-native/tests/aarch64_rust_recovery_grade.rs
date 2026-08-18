#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

#[path = "support/oracle_demand.rs"]
mod oracle_demand;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, PseudoScalarType as ScalarType, disassemble,
    recover_aarch64_function,
};

#[path = "aarch64_grade/battery.rs"]
mod battery;

use battery::{
    CASES, EXTERNS, FP_DRIVER_HELPERS, FpExpectation, HOST_FP_PRECHECK, ORACLE_FLAGS,
    build_ground_truth_object, cc, compare_block, expected_arity, fp_expectation,
    run_with_watchdog,
};

const RUST_EDITION: &str = "2021";
const HARNESS_WATCHDOG: Duration = Duration::from_mins(4);
const MAX_COMPILE_ROUNDS: usize = 16;
const MAX_RUN_ROUNDS: usize = 96;

fn rustc() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "rustc".to_owned())
}

const fn shared_object_name() -> &'static str {
    if cfg!(windows) {
        "a64_recovered_rust.dll"
    } else if cfg!(target_os = "macos") {
        "liba64_recovered_rust.dylib"
    } else {
        "liba64_recovered_rust.so"
    }
}

fn c_type_for_rust(token: &str) -> Option<&'static str> {
    Some(match token {
        "u8" => "uint8_t",
        "u16" => "uint16_t",
        "u32" => "uint32_t",
        "u64" => "uint64_t",
        "f32" => "float",
        "f64" => "double",
        "()" => "void",
        _ => return None,
    })
}

struct Signature {
    params: Vec<String>,
    ret: String,
}

fn matching_paren(line: &str, open: usize) -> Option<usize> {
    let mut depth: usize = 0;
    for (index, ch) in line.char_indices() {
        if index < open {
            continue;
        }
        match ch {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_rust_signature(source: &str) -> Option<Signature> {
    let line: &str = source
        .lines()
        .find(|line: &&str| line.trim_start().starts_with("pub fn recovered("))?;
    let open: usize = line.find('(')?;
    let close: usize = matching_paren(line, open)?;
    let inside: &str = line.get(open.checked_add(1)?..close)?;
    let params: Vec<String> = if inside.trim().is_empty() {
        Vec::new()
    } else {
        inside
            .split(',')
            .map(|param: &str| param.split(':').nth(1).unwrap_or("").trim().to_owned())
            .collect()
    };
    if params.iter().any(String::is_empty) {
        return None;
    }
    let ret: String = line
        .get(close.checked_add(1)?..)?
        .trim()
        .trim_start_matches("->")
        .trim()
        .trim_end_matches('{')
        .trim()
        .to_owned();
    if ret.is_empty() {
        return None;
    }
    Some(Signature { params, ret })
}

fn parse_c_signature(source: &str) -> Option<Signature> {
    let marker: &str = " recovered(";
    let line: &str = source.lines().find(|line: &&str| line.contains(marker))?;
    let open: usize = line.find(marker)?;
    let ret: String = line.get(..open)?.trim().to_owned();
    let rest: &str = line.get(open.checked_add(marker.len())?..)?;
    let close: usize = rest.rfind(')')?;
    let inside: &str = rest.get(..close)?;
    let params: Vec<String> = if inside.trim().is_empty() || inside.trim() == "void" {
        Vec::new()
    } else {
        inside
            .split(',')
            .map(|param: &str| {
                let tokens: Vec<&str> = param.split_whitespace().collect();
                tokens
                    .get(..tokens.len().saturating_sub(1))
                    .unwrap_or(&[])
                    .join(" ")
            })
            .collect()
    };
    if ret.is_empty() || params.iter().any(String::is_empty) {
        return None;
    }
    Some(Signature { params, ret })
}

struct Driven {
    opt: &'static str,
    name: &'static str,
    bytes: &'static [u8],
    symbol: String,
    rust_source: String,
    rust_params: Vec<String>,
    rust_ret: String,
    c_params: Vec<String>,
    c_ret: String,
    block: String,
}

impl Driven {
    fn c_declaration(&self) -> String {
        let params: String = if self.c_params.is_empty() {
            "void".to_owned()
        } else {
            self.c_params.join(", ")
        };
        format!("extern {} {}({params});", self.c_ret, self.symbol)
    }

    fn rust_definition(&self, index: usize) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("mod impl_{index} {{"));
        for line in self.rust_source.lines() {
            lines.push(line.to_owned());
        }
        lines.push("}".to_owned());
        let params: String = self
            .rust_params
            .iter()
            .enumerate()
            .map(|(position, ty): (usize, &String)| format!("a{position}: {ty}"))
            .collect::<Vec<String>>()
            .join(", ");
        let args: String = (0..self.rust_params.len())
            .map(|position: usize| format!("a{position}"))
            .collect::<Vec<String>>()
            .join(", ");
        lines.push("#[no_mangle]".to_owned());
        lines.push(format!(
            "pub extern \"C\" fn {}({params}) -> {} {{",
            self.symbol, self.rust_ret
        ));
        lines.push(format!("    impl_{index}::recovered({args})"));
        lines.push("}".to_owned());
        lines
    }
}

fn rust_unit(cases: &[Driven]) -> (String, Vec<(usize, usize)>) {
    let mut lines: Vec<String> = vec![
        "#![allow(unused, dead_code, non_snake_case, non_camel_case_types, unused_mut, unused_parens, unused_assignments, unused_variables)]".to_owned(),
    ];
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let start: usize = lines.len().saturating_add(1);
        lines.extend(case.rust_definition(index));
        spans.push((start, lines.len()));
    }
    (format!("{}\n", lines.join("\n")), spans)
}

fn error_lines(stderr: &str, unit_path: &str) -> Vec<usize> {
    let needle: String = format!("{unit_path}:");
    stderr
        .lines()
        .filter_map(|line: &str| {
            let arrow: usize = line.find("--> ")?;
            let location: &str = line.get(arrow.checked_add(4)?..)?.trim();
            if !location.starts_with(&needle) {
                return None;
            }
            let mut parts = location.rsplitn(3, ':');
            let _column: &str = parts.next()?;
            parts.next()?.parse::<usize>().ok()
        })
        .collect()
}

fn disassembly(bytes: &[u8]) -> String {
    match disassemble(Arch::Aarch64, 0, bytes) {
        Ok(insns) => insns
            .iter()
            .map(|insn: &DisasmInsn| {
                format!(
                    "      {:#06x}  {} {}",
                    insn.address, insn.mnemonic, insn.operands
                )
                .trim_end()
                .to_owned()
            })
            .collect::<Vec<String>>()
            .join("\n"),
        Err(error) => format!("      <disassembly unavailable: {error}>"),
    }
}

const HOST_REFERENCE_PROBES: &str = "    {\n\
     \x20       volatile uint32_t pa = 0x7f7fffffu, pb = 0x40000000u, pc = 0xff7fffffu;\n\
     \x20       printf(\"PROBE ground truth fma_madd_f(FLT_MAX,2,-FLT_MAX) = %08x   fused answer 7f7fffff, unfused answer 7f800000\\n\",\n\
     \x20           fp_f_to_bits(fma_madd_f(fp_f_from_bits(pa), fp_f_from_bits(pb), fp_f_from_bits(pc))));\n\
     \x20       volatile uint64_t qa = 0x7fefffffffffffffULL, qb = 0x4000000000000000ULL, qc = 0xffefffffffffffffULL;\n\
     \x20       printf(\"PROBE ground truth fma_madd_d(DBL_MAX,2,-DBL_MAX) = %016llx   fused answer 7fefffffffffffff, unfused answer 7ff0000000000000\\n\",\n\
     \x20           (unsigned long long)fp_d_to_bits(fma_madd_d(fp_d_from_bits(qa), fp_d_from_bits(qb), fp_d_from_bits(qc))));\n\
     \x20       volatile float pinf = fp_f_from_bits(0x7f800000u);\n\
     \x20       printf(\"PROBE ground truth fp_to_int_s(+inf) = %08x   aarch64 fcvtzs saturates to 7fffffff\\n\",\n\
     \x20           (uint32_t)fp_to_int_s(pinf));\n\
     \x20       volatile float psnan = fp_f_from_bits(0x7f800001u);\n\
     \x20       printf(\"PROBE ground truth fp_ceil_f(snan 7f800001) = %08x   aarch64 frintp quiets to 7fc00001\\n\",\n\
     \x20           fp_f_to_bits(fp_ceil_f(psnan)));\n\
     \x20       volatile float pneg = -0.0f;\n\
     \x20       printf(\"PROBE ground truth fz_relu_f(-0.0) = %08x\\n\", fp_f_to_bits(fz_relu_f(pneg)));\n\
     \x20       fflush(stdout);\n\
     \x20   }\n";

fn rust_reference_probes() -> Vec<String> {
    let flt_max: f32 = f32::from_bits(0x7f7f_ffff);
    let neg_flt_max: f32 = f32::from_bits(0xff7f_ffff);
    let dbl_max: f64 = f64::from_bits(0x7fef_ffff_ffff_ffff);
    let neg_dbl_max: f64 = f64::from_bits(0xffef_ffff_ffff_ffff);
    let snan: f32 = f32::from_bits(0x7f80_0001);
    vec![
        format!(
            "PROBE rust f32::mul_add(FLT_MAX,2,-FLT_MAX) = {:08x}",
            std::hint::black_box(flt_max)
                .mul_add(
                    std::hint::black_box(2.0f32),
                    std::hint::black_box(neg_flt_max)
                )
                .to_bits()
        ),
        format!(
            "PROBE rust f64::mul_add(DBL_MAX,2,-DBL_MAX) = {:016x}",
            std::hint::black_box(dbl_max)
                .mul_add(
                    std::hint::black_box(2.0f64),
                    std::hint::black_box(neg_dbl_max)
                )
                .to_bits()
        ),
        format!(
            "PROBE rust f32::INFINITY as i32 = {:08x}",
            std::hint::black_box(f32::INFINITY) as i32 as u32
        ),
        format!(
            "PROBE rust f32::ceil(snan 7f800001) = {:08x}",
            std::hint::black_box(snan).ceil().to_bits()
        ),
        format!(
            "PROBE rust f32::max(-0.0,+0.0) = {:08x}",
            std::hint::black_box(-0.0f32)
                .max(std::hint::black_box(0.0f32))
                .to_bits()
        ),
    ]
}

fn build_driver(cases: &[Driven]) -> String {
    let mut decls: String = String::new();
    let mut blocks: String = String::new();
    for case in cases {
        decls.push_str(&case.c_declaration());
        decls.push('\n');
        let _ = writeln!(
            blocks,
            "    printf(\"CASE {} {}\\n\"); fflush(stdout);",
            case.opt, case.name
        );
        blocks.push_str(&case.block);
    }
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <stddef.h>\n\
         #define BUFN 16\n#define ITER 400\n\
         {EXTERNS}\n\
         static uint64_t xs(uint64_t *st) {{ uint64_t x = *st; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *st = x; return x; }}\n\
         {FP_DRIVER_HELPERS}\n\
         static long long passed = 0;\n\
         static long long fails = 0;\n\
         {decls}\n\
         int main(void) {{\n\
         {HOST_FP_PRECHECK}\
         {HOST_REFERENCE_PROBES}\
         {blocks}\
         \x20   printf(\"GRADEDONE passed=%lld fails=%lld\\n\", passed, fails);\n\
         \x20   fflush(stdout);\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
#[ignore = "toolchain: needs a host c compiler and rustc to recompile and run the corpus; the ubuntu leg provisions clang-18 and runs it by name with DISROBE_REQUIRE_AARCH64_ORACLES set"]
fn corpus_rust_grade_report() {
    let Some(compiler): Option<String> = cc() else {
        oracle_demand::unmeasured(
            "the aarch64 rust recompile differential",
            "no host C compiler (gcc, clang or cc) is on PATH",
        );
        return;
    };
    let Some(rust_compiler): Option<String> = rustc() else {
        oracle_demand::unmeasured(
            "the aarch64 rust recompile differential",
            "rustc is not on PATH, so the rust rendering cannot be compiled",
        );
        return;
    };

    let dir: tempfile::TempDir = tempfile::tempdir().expect("scratch dir");
    let Ok(battery_o): Result<PathBuf, String> = build_ground_truth_object(&compiler, dir.path())
    else {
        oracle_demand::unmeasured(
            "the aarch64 rust recompile differential",
            "the host compiler could not build the ground-truth battery",
        );
        return;
    };

    let attempted: usize = CASES.len();
    let mut skips: Vec<(String, String, String)> = Vec::new();
    let mut wrong: Vec<(String, String, String)> = Vec::new();
    let mut driven: Vec<Driven> = Vec::new();

    for (index, (opt, name, bytes)) in CASES.iter().enumerate() {
        let recovery: LeafRecovery = match recover_aarch64_function(bytes, 0) {
            Ok(value) => value,
            Err(error) => {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    format!("aarch64 recovery rejected: {error}"),
                ));
                continue;
            }
        };

        let expected_fp: Option<FpExpectation> = fp_expectation(name);
        if let Some(expectation) = expected_fp {
            if recovery.signature.parameter_types().as_slice() != expectation.params
                || recovery.returns_fp != expectation.returns
                || recovery.return_width_bits != expectation.return_width_bits
            {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    "fp signature mismatch".to_owned(),
                ));
                continue;
            }
        } else {
            let Some(expected): Option<usize> = expected_arity(name) else {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    "no driver descriptor".to_owned(),
                ));
                continue;
            };
            let has_fp_parameter: bool = recovery
                .signature
                .parameter_types()
                .iter()
                .any(|parameter: &ScalarType| *parameter != ScalarType::Int);
            if recovery.returns_fp.is_some() || has_fp_parameter {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    "unexpected floating-point signature".to_owned(),
                ));
                continue;
            }
            if recovery.signature.observed_integer_registers().len() != expected {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    "arity mismatch".to_owned(),
                ));
                continue;
            }
        }

        let Some(rust_source): Option<String> = recovery.rust_source.clone() else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "no rust rendering emitted".to_owned(),
            ));
            continue;
        };
        let Some(rust_signature): Option<Signature> = parse_rust_signature(&rust_source) else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "rust rendering has no parseable signature".to_owned(),
            ));
            continue;
        };
        let Some(c_signature): Option<Signature> = parse_c_signature(&recovery.source) else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "c rendering has no parseable signature".to_owned(),
            ));
            continue;
        };
        let mapped_ret: Option<&'static str> = c_type_for_rust(&rust_signature.ret);
        let mapped_params: Option<Vec<&'static str>> = rust_signature
            .params
            .iter()
            .map(|ty: &String| c_type_for_rust(ty))
            .collect();
        let (Some(mapped_ret), Some(mapped_params)): (
            Option<&'static str>,
            Option<Vec<&'static str>>,
        ) = (mapped_ret, mapped_params) else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "rust rendering uses a type with no c abi equivalent".to_owned(),
            ));
            continue;
        };
        if mapped_ret != c_signature.ret || mapped_params != c_signature.params {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                format!(
                    "c and rust renderings disagree on the signature (c {} ({}), rust {} ({}))",
                    c_signature.ret,
                    c_signature.params.join(", "),
                    mapped_ret,
                    mapped_params.join(", ")
                ),
            ));
            continue;
        }

        let symbol: String = format!("rec_{opt}_{name}");
        let seed: u64 = 0x9E37_79B9_7F4A_7C15u64
            ^ (index as u64)
                .wrapping_add(1)
                .wrapping_mul(0x0000_0100_0000_01B3);
        let seed: u64 = if seed == 0 {
            0xDEAD_BEEF_CAFE_F00D
        } else {
            seed
        };
        let Some(block): Option<String> = compare_block(opt, name, &symbol, seed) else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "no driver descriptor".to_owned(),
            ));
            continue;
        };

        driven.push(Driven {
            opt,
            name,
            bytes,
            symbol,
            rust_source,
            rust_params: rust_signature.params,
            rust_ret: rust_signature.ret,
            c_params: c_signature.params,
            c_ret: c_signature.ret,
            block,
        });
    }

    assert!(
        !driven.is_empty(),
        "aarch64 rust grade produced no case with both a rust rendering and a runnable driver descriptor"
    );

    let unit_path: PathBuf = dir.path().join("a64_recovered.rs");
    let unit_display: String = unit_path.to_string_lossy().into_owned();
    let shared_object: PathBuf = dir.path().join(shared_object_name());
    let mut compile_round: usize = 0;
    loop {
        compile_round = compile_round.saturating_add(1);
        assert!(
            compile_round <= MAX_COMPILE_ROUNDS,
            "rustc kept rejecting the emitted rust after {MAX_COMPILE_ROUNDS} attribution rounds"
        );
        let (unit, spans): (String, Vec<(usize, usize)>) = rust_unit(&driven);
        std::fs::write(&unit_path, unit.as_bytes()).expect("write recovered rust unit");
        let built: std::process::Output = Command::new(&rust_compiler)
            .args([
                "--edition",
                RUST_EDITION,
                "--crate-type=cdylib",
                "-C",
                "overflow-checks=on",
                "-o",
            ])
            .arg(&shared_object)
            .arg(&unit_path)
            .output()
            .expect("invoke rustc for the recovered rust unit");
        if built.status.success() {
            break;
        }
        let stderr: String = String::from_utf8_lossy(&built.stderr).into_owned();
        let mut rejected: Vec<usize> = Vec::new();
        for line in error_lines(&stderr, &unit_display) {
            if let Some(position) = spans
                .iter()
                .position(|(start, end): &(usize, usize)| *start <= line && line <= *end)
            {
                rejected.push(position);
            }
        }
        rejected.sort_unstable();
        rejected.dedup();
        assert!(
            !rejected.is_empty(),
            "rustc rejected the recovered rust unit and no diagnostic could be attributed to a case:\n{stderr}"
        );
        for position in rejected.iter().rev() {
            let case: Driven = driven.remove(*position);
            skips.push((
                case.opt.to_owned(),
                case.name.to_owned(),
                "rustc rejected the emitted rust rendering".to_owned(),
            ));
            eprintln!(
                "---- rustc rejected {} {} ----\n{}",
                case.opt, case.name, case.rust_source
            );
        }
        assert!(
            !driven.is_empty(),
            "rustc rejected every emitted rust rendering"
        );
    }

    let driver_c: PathBuf = dir.path().join("a64_rust_grade_driver.c");
    let harness_exe: PathBuf = dir
        .path()
        .join(if cfg!(windows) { "grade.exe" } else { "grade" });
    let rpath: String = format!("-Wl,-rpath,{}", dir.path().to_string_lossy());
    let mut run_round: usize = 0;
    let mut probes: Vec<String> = Vec::new();
    let (passed, driver_fails): (i64, i64) = loop {
        run_round = run_round.saturating_add(1);
        assert!(
            run_round <= MAX_RUN_ROUNDS,
            "the rust grade harness kept terminating abnormally after {MAX_RUN_ROUNDS} rounds"
        );
        let driver: String = build_driver(&driven);
        std::fs::write(&driver_c, driver.as_bytes()).expect("write rust grade driver");
        let mut link: Command = Command::new(&compiler);
        link.args(ORACLE_FLAGS).arg("-o").arg(&harness_exe);
        if !cfg!(windows) {
            link.arg(&rpath);
        }
        let linked: std::process::Output = link
            .arg(&driver_c)
            .arg(&battery_o)
            .arg(&shared_object)
            .output()
            .expect("invoke cc to link the rust grade harness");
        assert!(
            linked.status.success(),
            "rust grade harness failed to compile/link ({} driven cases): {}",
            driven.len(),
            String::from_utf8_lossy(&linked.stderr)
        );

        let output: Option<std::process::Output> =
            run_with_watchdog(&harness_exe, HARNESS_WATCHDOG);
        let timed_out: bool = output.is_none();
        let stdout: String = output.as_ref().map_or_else(String::new, |out| {
            String::from_utf8_lossy(&out.stdout).into_owned()
        });
        let stderr: String = output.as_ref().map_or_else(String::new, |out| {
            String::from_utf8_lossy(&out.stderr).into_owned()
        });

        assert!(
            !stdout
                .lines()
                .any(|line: &str| line.starts_with("HOSTFP flush-to-zero detected")),
            "rust grade requires host gradual underflow for f32 and f64:\n{stdout}"
        );

        let mut last_case: Option<(String, String)> = None;
        let mut round_fails: Vec<(String, String, String)> = Vec::new();
        let mut graded_done: Option<(i64, i64)> = None;
        probes.clear();
        for line in stdout.lines() {
            if line.starts_with("PROBE ") {
                probes.push(line.to_owned());
            } else if let Some(rest) = line.strip_prefix("CASE ") {
                let mut parts = rest.splitn(2, ' ');
                let opt: &str = parts.next().unwrap_or("?");
                let name: &str = parts.next().unwrap_or("?");
                last_case = Some((opt.to_owned(), name.to_owned()));
            } else if let Some(rest) = line.strip_prefix("FAIL ") {
                let mut parts = rest.splitn(3, ' ');
                let opt: &str = parts.next().unwrap_or("?");
                let name: &str = parts.next().unwrap_or("?");
                let detail: &str = parts.next().unwrap_or("");
                round_fails.push((opt.to_owned(), name.to_owned(), detail.to_owned()));
            } else if let Some(rest) = line.strip_prefix("GRADEDONE ") {
                let mut done_passed: i64 = 0;
                let mut done_fails: i64 = 0;
                for token in rest.split_whitespace() {
                    if let Some(value) = token.strip_prefix("passed=") {
                        done_passed = value.parse().unwrap_or(0);
                    } else if let Some(value) = token.strip_prefix("fails=") {
                        done_fails = value.parse().unwrap_or(0);
                    }
                }
                graded_done = Some((done_passed, done_fails));
            }
        }

        if let Some((done_passed, done_fails)) = graded_done {
            wrong.extend(round_fails);
            break (done_passed, done_fails);
        }

        let Some((opt, name)): Option<(String, String)> = last_case else {
            panic!(
                "the rust grade harness produced no case marker and no summary; run did not start:\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        };
        drop(round_fails);
        let reason: String = if timed_out {
            "recovered rust did not terminate within the watchdog window".to_owned()
        } else {
            format!(
                "recovered rust aborted the harness (overflow check, invalid memory access, or trap); harness stderr: {}",
                stderr.lines().take(3).collect::<Vec<&str>>().join(" | ")
            )
        };
        let Some(position): Option<usize> = driven
            .iter()
            .position(|case: &Driven| case.opt == opt && case.name == name)
        else {
            panic!("the rust grade harness reported an unknown case marker `{opt} {name}`");
        };
        let case: Driven = driven.remove(position);
        eprintln!("---- recovered rust aborted on {opt} {name} ----");
        eprintln!("{}", disassembly(case.bytes));
        eprintln!("{}", case.rust_source);
        wrong.push((opt, name, reason));
    };

    let graded_equivalent: i64 = passed;
    let recovered_but_wrong: usize = wrong.len();
    let skipped: usize = skips.len();

    eprintln!("============ AARCH64 RUST RENDERING GRADE ============");
    eprintln!("attempted            {attempted}");
    eprintln!("driven (graded)      {}", driven.len());
    eprintln!(
        "graded-equivalent    {graded_equivalent}   (rustc-compiled + behaviorally matched against the c ground truth on directed and random inputs)"
    );
    eprintln!(
        "recovered-but-wrong  {recovered_but_wrong}   (rust rendering diverged, trapped, or hung)"
    );
    eprintln!("skipped-from-grading {skipped}");
    if !wrong.is_empty() {
        eprintln!("---- recovered-but-wrong (CORRECTNESS BUGS) ----");
        for (opt, name, detail) in &wrong {
            eprintln!("  WRONG {opt} {name}  {detail}");
            if let Some((_, _, bytes)) =
                CASES
                    .iter()
                    .find(|(case_opt, case_name, _): &&(&str, &str, &[u8])| {
                        case_opt == opt && case_name == name
                    })
            {
                eprintln!("{}", disassembly(bytes));
            }
        }
        let mut per_function: BTreeMap<String, usize> = BTreeMap::new();
        for (_, name, _) in &wrong {
            *per_function.entry(name.clone()).or_default() += 1;
        }
        eprintln!("  divergent function tally:");
        for (name, count) in &per_function {
            eprintln!("    {count}x  {name}");
        }
    }
    eprintln!("---- host reference vs rust reference on the ieee corners the corpus probes ----");
    for probe in probes.iter().chain(rust_reference_probes().iter()) {
        eprintln!("  {probe}");
    }
    if !skips.is_empty() {
        eprintln!("---- skipped-from-grading (with reason) ----");
        let mut reason_counts: BTreeMap<String, usize> = BTreeMap::new();
        for (optimization, name, reason) in &skips {
            eprintln!("  SKIP {optimization} {name}: {reason}");
            *reason_counts.entry(reason.clone()).or_default() += 1;
        }
        eprintln!("  reason tally:");
        for (reason, count) in &reason_counts {
            eprintln!("    {count}x  {reason}");
        }
    }
    eprintln!("=====================================================");

    assert_eq!(
        i64::try_from(driven.len()).unwrap_or(-1),
        passed.saturating_add(driver_fails),
        "every driven case must be accounted for as pass or fail"
    );
    assert_eq!(
        graded_equivalent
            .saturating_add(i64::try_from(recovered_but_wrong).unwrap_or(-1))
            .saturating_add(i64::try_from(skipped).unwrap_or(-1)),
        i64::try_from(attempted).unwrap_or(-1),
        "graded, wrong and skipped counts must partition the corpus"
    );
    assert!(
        wrong.is_empty(),
        "every driven aarch64 rust rendering must agree with the reference after NaN canonicalization: {wrong:?}"
    );
    let descriptor_skips: Vec<&(String, String, String)> = skips
        .iter()
        .filter(|(_, _, reason): &&(String, String, String)| {
            matches!(
                reason.as_str(),
                "fp signature mismatch"
                    | "unexpected floating-point signature"
                    | "no driver descriptor"
                    | "arity mismatch"
            )
        })
        .collect();
    assert!(
        descriptor_skips.is_empty(),
        "every recovered corpus case must have a total, matching driver descriptor: {descriptor_skips:?}"
    );
}
