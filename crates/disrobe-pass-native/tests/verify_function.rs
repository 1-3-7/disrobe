#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use crate::verify_function::{
    CaseClassification, VerifyFunctionError, VerifyFunctionOptions, VerifyFunctionReport,
    verify_function,
};

const CASES: u32 = 2_000;
const SEED: u64 = 0xA11C_E5E5_1234_5678;

#[derive(Clone, Copy)]
enum Target {
    ElfX86_64,
    PeX86_64,
    PeI386,
}

impl Target {
    const fn clang_target(self) -> &'static str {
        match self {
            Self::ElfX86_64 => "x86_64-unknown-linux-gnu",
            Self::PeX86_64 => "x86_64-pc-windows-msvc",
            Self::PeI386 => "i686-pc-windows-msvc",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::ElfX86_64 => "elf",
            Self::PeX86_64 | Self::PeI386 => "exe",
        }
    }

    const fn linker_arguments(self) -> &'static [&'static str] {
        match self {
            Self::ElfX86_64 => &["-fuse-ld=lld", "-no-pie", "-Wl,-e,verify_overflow"],
            Self::PeX86_64 => &[
                "-fuse-ld=lld",
                "-Wl,/entry:verify_overflow",
                "-Wl,/subsystem:console",
            ],
            Self::PeI386 => &[
                "-fuse-ld=lld",
                "-Wl,/entry:verify_overflow",
                "-Wl,/subsystem:console",
            ],
        }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("native crate must remain two directories beneath the repository root")
        .to_path_buf()
}

fn source(name: &str) -> PathBuf {
    repo_root().join("corpus/native/verify").join(name)
}

fn clang() -> String {
    let output: disrobe_testkit::ToolOutput = disrobe_testkit::tool_output(
        disrobe_testkit::CommandSpec::new("clang", Duration::from_secs(30)).arg("--version"),
    )
    .expect("invoke clang --version through the bounded test process");
    assert!(
        output.success,
        "clang --version must succeed: {}",
        output.stderr_text()
    );
    let banner: String = output.stdout_text();
    let first_line: &str = banner.lines().next().unwrap_or_default();
    let major: Option<u32> = first_line
        .split("clang version ")
        .nth(1)
        .and_then(|rest: &str| rest.split('.').next())
        .and_then(|digits: &str| digits.parse::<u32>().ok());
    assert!(
        major.is_some_and(|value: u32| (18..=21).contains(&value)),
        "verify-function requires clang 18 through 21, found `{first_line}`"
    );
    "clang".to_owned()
}

fn run_clang(arguments: &[OsString]) {
    let output: disrobe_testkit::ToolOutput = disrobe_testkit::tool_output(
        disrobe_testkit::CommandSpec::new(clang(), Duration::from_mins(2)).args(arguments),
    )
    .expect("invoke clang through the bounded test process");
    assert!(output.success, "clang failed: {}", output.stderr_text());
}

fn compile_original(directory: &TempDir, target: Target) -> Vec<u8> {
    let output: PathBuf = directory
        .path()
        .join(format!("original.{}", target.extension()));
    let mut arguments: Vec<OsString> = vec![
        OsString::from(format!("--target={}", target.clang_target())),
        OsString::from("-O2"),
        OsString::from("-ffreestanding"),
        OsString::from("-fno-stack-protector"),
        OsString::from("-fno-pic"),
        OsString::from("-nostdlib"),
        source("verify_original.c").into_os_string(),
    ];
    arguments.extend(target.linker_arguments().iter().map(OsString::from));
    arguments.push(OsString::from("-o"));
    arguments.push(output.clone().into_os_string());
    run_clang(&arguments);
    std::fs::read(output).expect("read linked authored original")
}

fn compile_candidate(directory: &TempDir, target: Target, name: &str) -> Vec<u8> {
    compile_candidate_with_optimization(directory, target, name, "-O0")
}

fn compile_candidate_with_optimization(
    directory: &TempDir,
    target: Target,
    name: &str,
    optimization: &str,
) -> Vec<u8> {
    let output: PathBuf = directory
        .path()
        .join(format!("{name}-{}.o", optimization.trim_start_matches('-')));
    let arguments: Vec<OsString> = vec![
        OsString::from(format!("--target={}", target.clang_target())),
        OsString::from(optimization),
        OsString::from("-ffreestanding"),
        OsString::from("-fno-stack-protector"),
        OsString::from("-fno-pic"),
        OsString::from("-c"),
        source(name).into_os_string(),
        OsString::from("-o"),
        output.clone().into_os_string(),
    ];
    run_clang(&arguments);
    std::fs::read(output).expect("read candidate object")
}

fn options(function: &str, signature: &str) -> VerifyFunctionOptions {
    let mut result: VerifyFunctionOptions = VerifyFunctionOptions::new(function);
    result.signature = Some(signature.to_owned());
    result.cases = CASES;
    result.seed = SEED;
    result.step_cap = 100_000;
    result
}

fn verify(
    directory: &TempDir,
    target: Target,
    function: &str,
    signature: &str,
    candidate: &str,
) -> VerifyFunctionReport {
    let original: Vec<u8> = compile_original(directory, target);
    let candidate: Vec<u8> = compile_candidate(directory, target, candidate);
    verify_function(&original, &candidate, &options(function, signature))
        .expect("authored verifier target must load and execute")
}

fn assert_equivalent(report: &VerifyFunctionReport) {
    assert_eq!(report.cases, CASES);
    assert_eq!(report.verdict, "equivalent-on-cases", "{report:#?}");
    assert_eq!(report.totals.get("match"), Some(&CASES));
    assert!(report.divergences.is_empty());
}

#[test]
fn authored_reconstructions_are_equivalent_on_the_full_target_matrix() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let functions: [(&str, &str); 5] = [
        ("verify_overflow", "u32(u32,u32)"),
        ("verify_table", "u32(u32)"),
        ("verify_until_zero", "u32(ptr,u32)"),
        ("verify_order", "u32(i32,u32)"),
        ("verify_store", "u32(ptr,u32,u32)"),
    ];
    for target in [Target::ElfX86_64, Target::PeX86_64, Target::PeI386] {
        let original: Vec<u8> = compile_original(&directory, target);
        let candidate: Vec<u8> = compile_candidate(&directory, target, "candidate_good.c");
        for (function, signature) in functions {
            let report: VerifyFunctionReport =
                verify_function(&original, &candidate, &options(function, signature))
                    .expect("authored verifier matrix entry must load and execute");
            assert_equivalent(&report);
        }
    }
}

#[test]
fn authored_overflow_reconstruction_is_equivalent_on_x86_64_elf_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::ElfX86_64,
        "verify_overflow",
        "u32(u32,u32)",
        "candidate_good.c",
    );
    assert_equivalent(&report);
}

#[test]
fn optimized_candidate_is_equivalent_on_x86_64_elf_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let original: Vec<u8> = compile_original(&directory, Target::ElfX86_64);
    let candidate: Vec<u8> = compile_candidate_with_optimization(
        &directory,
        Target::ElfX86_64,
        "candidate_good.c",
        "-O2",
    );
    let report: VerifyFunctionReport = verify_function(
        &original,
        &candidate,
        &options("verify_overflow", "u32(u32,u32)"),
    )
    .expect("optimized candidate must load and execute");
    assert_equivalent(&report);
}

#[test]
fn authored_overflow_reconstruction_is_equivalent_on_x86_64_pe_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::PeX86_64,
        "verify_overflow",
        "u32(u32,u32)",
        "candidate_good.c",
    );
    assert_equivalent(&report);
}

#[test]
fn authored_overflow_reconstruction_is_equivalent_on_i386_pe_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::PeI386,
        "verify_overflow",
        "u32(u32,u32)",
        "candidate_good.c",
    );
    assert_equivalent(&report);
}

#[test]
fn recovered_signatures_drive_x86_64_and_i386_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    for target in [Target::ElfX86_64, Target::PeI386] {
        let original: Vec<u8> = compile_original(&directory, target);
        let candidate: Vec<u8> = compile_candidate(&directory, target, "candidate_good.c");
        let mut recovered: VerifyFunctionOptions = VerifyFunctionOptions::new("verify_overflow");
        recovered.cases = CASES;
        recovered.seed = SEED;
        let report: VerifyFunctionReport = verify_function(&original, &candidate, &recovered)
            .expect("recover the authored function signature");
        assert_equivalent(&report);
    }
}

#[test]
fn authored_table_reconstruction_is_equivalent_on_x86_64_elf_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::ElfX86_64,
        "verify_table",
        "u32(u32)",
        "candidate_good.c",
    );
    assert_equivalent(&report);
}

#[test]
fn authored_early_exit_loop_is_equivalent_on_x86_64_elf_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::ElfX86_64,
        "verify_until_zero",
        "u32(ptr,u32)",
        "candidate_good.c",
    );
    assert_equivalent(&report);
}

#[test]
fn authored_signed_order_reconstruction_is_equivalent_on_x86_64_pe_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::PeX86_64,
        "verify_order",
        "u32(i32,u32)",
        "candidate_good.c",
    );
    assert_equivalent(&report);
}

#[test]
fn authored_pointer_store_reconstruction_is_equivalent_on_i386_pe_cases() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::PeI386,
        "verify_store",
        "u32(ptr,u32,u32)",
        "candidate_good.c",
    );
    assert_equivalent(&report);
}

fn first_mismatch(report: &VerifyFunctionReport) -> &crate::verify_function::CaseDivergence {
    assert_eq!(report.verdict, "diverged-on-cases");
    let divergence = report.divergences.first().expect("mutation must diverge");
    assert_eq!(divergence.classification, CaseClassification::Mismatch);
    divergence
}

#[test]
fn off_by_one_mutation_reports_its_first_generated_input() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::ElfX86_64,
        "verify_overflow",
        "u32(u32,u32)",
        "candidate_off_by_one.c",
    );
    let divergence = first_mismatch(&report);
    assert_eq!(divergence.case_index, 0);
    assert_eq!(
        divergence.inputs,
        vec![
            "0x0".to_owned(),
            "0x7".to_owned(),
            "scratch=d49574c469774963ad3a024880d10e56...".to_owned(),
        ]
    );
    assert_eq!(
        divergence.detail,
        "return differs: original 0x7, candidate 0x8"
    );
}

#[test]
fn wrong_signedness_mutation_reports_a_stable_first_generated_input() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::ElfX86_64,
        "verify_order",
        "u32(i32,u32)",
        "candidate_wrong_signedness.c",
    );
    let divergence = first_mismatch(&report);
    assert_eq!(divergence.case_index, 0);
    assert_eq!(
        divergence.inputs,
        vec![
            "0x0".to_owned(),
            "0x7".to_owned(),
            "scratch=d49574c469774963ad3a024880d10e56...".to_owned(),
        ]
    );
    assert_eq!(
        divergence.detail,
        "return differs: original 0x9, candidate 0xb"
    );
    let replay: VerifyFunctionReport = verify(
        &directory,
        Target::ElfX86_64,
        "verify_order",
        "u32(i32,u32)",
        "candidate_wrong_signedness.c",
    );
    let replay_divergence = first_mismatch(&replay);
    assert_eq!(
        (divergence.case_index, &divergence.inputs),
        (replay_divergence.case_index, &replay_divergence.inputs),
        "the first signedness counterexample must be reproducible from the seed"
    );
}

#[test]
fn missed_side_effect_mutation_reports_the_first_changed_scratch_case() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let report: VerifyFunctionReport = verify(
        &directory,
        Target::ElfX86_64,
        "verify_store",
        "u32(ptr,u32,u32)",
        "candidate_missed_side_effect.c",
    );
    let divergence = first_mismatch(&report);
    assert_eq!(divergence.case_index, 0);
    assert_eq!(
        divergence.inputs,
        vec![
            "ptr+0x0".to_owned(),
            "0x7".to_owned(),
            "0x20".to_owned(),
            "scratch=d49574c469774963ad3a024880d10e56...".to_owned(),
        ]
    );
    assert_eq!(
        divergence.detail,
        "scratch[0x7] differs: original 0x27, candidate 0x63"
    );
}

#[test]
fn unresolved_candidate_import_is_refused_by_name() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let original: Vec<u8> = compile_original(&directory, Target::ElfX86_64);
    let candidate: Vec<u8> = compile_candidate(&directory, Target::ElfX86_64, "candidate_import.c");
    let error = verify_function(
        &original,
        &candidate,
        &options("verify_overflow", "u32(u32)"),
    )
    .expect_err("candidate imports must not execute in the emulator");
    assert!(
        matches!(error, VerifyFunctionError::ExternalSymbol(ref name) if name == "imported_target"),
        "expected named import refusal, got {error}"
    );
}

#[test]
fn candidate_without_requested_function_is_refused_by_name() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let original: Vec<u8> = compile_original(&directory, Target::ElfX86_64);
    let candidate: Vec<u8> = compile_candidate(
        &directory,
        Target::ElfX86_64,
        "candidate_wrong_signedness.c",
    );
    let error: VerifyFunctionError = verify_function(
        &original,
        &candidate,
        &options("verify_overflow", "u32(u32,u32)"),
    )
    .expect_err("a different candidate symbol must not be selected as a fallback");
    assert!(
        matches!(error, VerifyFunctionError::CandidateFunctionNotFound(ref name) if name == "verify_overflow"),
        "expected named candidate function refusal, got {error}"
    );
}

#[test]
#[cfg(all(windows, target_arch = "x86_64"))]
fn authored_native_execution_matches_emulation_for_the_first_case() {
    let directory: TempDir = tempfile::tempdir().expect("create verifier scratch directory");
    let driver: PathBuf = directory.path().join("native_driver.c");
    std::fs::write(
        &driver,
        b"unsigned int verify_overflow(unsigned int, unsigned int); int main(void) { return (int)(verify_overflow(0u, 7u) & 255u); }\n",
    )
    .expect("write authored native driver");
    let native: PathBuf = directory.path().join("native_reference.exe");
    run_clang(&[
        OsString::from("-O2"),
        source("verify_original.c").into_os_string(),
        driver.into_os_string(),
        OsString::from("-o"),
        native.clone().into_os_string(),
    ]);
    let native_output: disrobe_testkit::ToolOutput = disrobe_testkit::tool_output(
        disrobe_testkit::CommandSpec::new(&native, Duration::from_secs(30)),
    )
    .expect("run repository-authored native reference");
    assert_eq!(native_output.exit_code, Some(7), "{native_output:?}");

    let constant_source: PathBuf = directory.path().join("candidate_constant.c");
    std::fs::write(
        &constant_source,
        b"unsigned int verify_overflow(unsigned int left, unsigned int right) { (void)left; (void)right; return 7u; }\n",
    )
    .expect("write authored constant candidate");
    let constant_object: PathBuf = directory.path().join("candidate_constant.o");
    run_clang(&[
        OsString::from("--target=x86_64-pc-windows-msvc"),
        OsString::from("-O0"),
        OsString::from("-ffreestanding"),
        OsString::from("-fno-stack-protector"),
        OsString::from("-fno-pic"),
        OsString::from("-c"),
        constant_source.into_os_string(),
        OsString::from("-o"),
        constant_object.clone().into_os_string(),
    ]);
    let original: Vec<u8> = compile_original(&directory, Target::PeX86_64);
    let candidate: Vec<u8> = std::fs::read(constant_object).expect("read constant candidate");
    let mut verify_options: VerifyFunctionOptions = options("verify_overflow", "u32(u32,u32)");
    verify_options.cases = 1;
    let report: VerifyFunctionReport = verify_function(&original, &candidate, &verify_options)
        .expect("emulate the native-reference case");
    assert_eq!(report.verdict, "equivalent-on-cases", "{report:#?}");
}
