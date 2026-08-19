#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{CRYSTAL_PE, D_PE, NIM_ELF, ZIG_ELF, fixture_or_fail, tool_or_unmeasured};
use disrobe_pass_nativelang::{
    BodyRecovery, BodyStatus, BoundaryConfidence, FunctionBody, NativeLangAnalysis, RustBody,
    analyze,
};

const MAX_GRADED_C_BODIES: usize = 512;
const MAX_GRADED_RUST_BODIES: usize = 512;

struct Fixture {
    tag: &'static str,
    relative_path: &'static str,
    language: &'static str,
    recovered_floor: u32,
    rust_floor: u32,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        tag: "nim-elf",
        relative_path: NIM_ELF,
        language: "nim",
        recovered_floor: 75,
        rust_floor: 75,
    },
    Fixture {
        tag: "zig-elf",
        relative_path: ZIG_ELF,
        language: "zig",
        recovered_floor: 312,
        rust_floor: 309,
    },
    Fixture {
        tag: "crystal-pe",
        relative_path: CRYSTAL_PE,
        language: "crystal",
        recovered_floor: 19,
        rust_floor: 19,
    },
    Fixture {
        tag: "d-pe",
        relative_path: D_PE,
        language: "d",
        recovered_floor: 86,
        rust_floor: 84,
    },
];

fn analyze_fixture(fixture: &Fixture) -> NativeLangAnalysis {
    let bytes: Vec<u8> = fixture_or_fail(fixture.relative_path);
    let analysis: NativeLangAnalysis = analyze(&bytes)
        .unwrap_or_else(|error| panic!("{} must analyze, got {error}", fixture.relative_path));
    assert_eq!(
        analysis.fingerprint.lang.label(),
        fixture.language,
        "{} must fingerprint as {}",
        fixture.relative_path,
        fixture.language
    );
    analysis
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-nativelang-body-{tag}-{}",
        std::process::id()
    ));
    drop(std::fs::remove_dir_all(&dir));
    std::fs::create_dir_all(&dir).expect("create the scratch directory for the recompile grade");
    dir
}

fn recovered_c_bodies(recovery: &BodyRecovery) -> Vec<(&FunctionBody, &str)> {
    recovery
        .bodies
        .iter()
        .filter_map(|body: &FunctionBody| match &body.status {
            BodyStatus::Recovered { pseudo_c, .. } => Some((body, pseudo_c.as_str())),
            BodyStatus::RecoveredElided { .. }
            | BodyStatus::Rejected { .. }
            | BodyStatus::NotAttempted { .. } => None,
        })
        .collect()
}

fn recovered_rust_bodies(recovery: &BodyRecovery) -> Vec<(&FunctionBody, &str)> {
    recovery
        .bodies
        .iter()
        .filter_map(|body: &FunctionBody| match &body.status {
            BodyStatus::Recovered {
                pseudo_rust: RustBody::Emitted(rust),
                ..
            } => Some((body, rust.as_str())),
            BodyStatus::Recovered { .. }
            | BodyStatus::RecoveredElided { .. }
            | BodyStatus::Rejected { .. }
            | BodyStatus::NotAttempted { .. } => None,
        })
        .collect()
}

#[test]
fn every_recovered_pseudo_c_body_compiles_under_a_real_c_compiler() {
    let Some(compiler): Option<String> = tool_or_unmeasured(
        &["gcc", "clang", "cc"],
        "the nativelang pseudo-C body recompile grade",
    ) else {
        return;
    };
    let mut graded_total: usize = 0;
    for fixture in FIXTURES {
        let analysis: NativeLangAnalysis = analyze_fixture(fixture);
        let bodies: Vec<(&FunctionBody, &str)> = recovered_c_bodies(&analysis.bodies);
        assert_eq!(
            u32::try_from(bodies.len()).unwrap(),
            analysis.bodies.recovered,
            "{}: the recovered counter must match the recovered body list",
            fixture.tag
        );
        assert!(
            analysis.bodies.recovered >= fixture.recovered_floor,
            "{}: recovered {} pseudo-C bodies, below the recorded floor of {}",
            fixture.tag,
            analysis.bodies.recovered,
            fixture.recovered_floor
        );
        let dir: PathBuf = scratch_dir(&format!("{}-c", fixture.tag));
        let mut inputs: Vec<PathBuf> = Vec::new();
        for (body, source) in bodies.iter().take(MAX_GRADED_C_BODIES) {
            let file: PathBuf = dir.join(format!("{:016x}.c", body.start));
            std::fs::write(&file, source).expect("write a graded body");
            inputs.push(file);
        }
        let graded: usize = inputs.len();
        let output: Output = Command::new(&compiler)
            .arg("-fsyntax-only")
            .arg("-std=c11")
            .arg("-Werror=implicit-function-declaration")
            .arg("-w")
            .args(&inputs)
            .output()
            .expect("run the C compiler over the recovered bodies");
        println!(
            "{}: {graded}/{} recovered pseudo-C bodies compiled by {compiler}",
            fixture.tag, analysis.bodies.recovered
        );
        assert!(
            output.status.success(),
            "{}: {compiler} rejected a body the pass reported as recovered; a body that cannot \
             stand alone must be rejected, not published:\n{}",
            fixture.tag,
            String::from_utf8_lossy(&output.stderr)
        );
        graded_total = graded_total.saturating_add(graded);
        drop(std::fs::remove_dir_all(&dir));
    }
    assert!(
        graded_total >= 492,
        "the pseudo-C grade must cover at least 492 real bodies, covered {graded_total}"
    );
}

#[test]
fn every_recovered_pseudo_rust_body_compiles_under_rustc() {
    let Some(compiler): Option<String> = tool_or_unmeasured(
        &["rustc"],
        "the nativelang pseudo-Rust body recompile grade",
    ) else {
        return;
    };
    let mut graded_total: usize = 0;
    for fixture in FIXTURES {
        let analysis: NativeLangAnalysis = analyze_fixture(fixture);
        let bodies: Vec<(&FunctionBody, &str)> = recovered_rust_bodies(&analysis.bodies);
        assert_eq!(
            u32::try_from(bodies.len()).unwrap(),
            analysis.bodies.rust_bodies,
            "{}: the pseudo-Rust counter must match the emitted pseudo-Rust list",
            fixture.tag
        );
        assert!(
            analysis.bodies.rust_bodies >= fixture.rust_floor,
            "{}: emitted {} pseudo-Rust bodies, below the recorded floor of {}",
            fixture.tag,
            analysis.bodies.rust_bodies,
            fixture.rust_floor
        );
        let dir: PathBuf = scratch_dir(&format!("{}-rust", fixture.tag));
        let mut crate_source: String = String::new();
        let mut graded: usize = 0;
        for (body, source) in bodies.iter().take(MAX_GRADED_RUST_BODIES) {
            writeln!(
                crate_source,
                "#[allow(dead_code, non_snake_case, unused_imports)]\nmod body_{:016x} \
                 {{\n{source}\n}}",
                body.start
            )
            .expect("append a graded body to the crate under test");
            graded = graded.saturating_add(1);
        }
        let file: PathBuf = dir.join("graded_bodies.rs");
        std::fs::write(&file, &crate_source).expect("write the graded pseudo-Rust crate");
        let output: Output = Command::new(&compiler)
            .arg("--edition")
            .arg("2021")
            .arg("--crate-type")
            .arg("lib")
            .arg("--emit=metadata")
            .arg("-A")
            .arg("warnings")
            .arg("-o")
            .arg(dir.join("graded_bodies.rmeta"))
            .arg(&file)
            .output()
            .expect("run rustc over the recovered bodies");
        assert!(
            output.status.success(),
            "{}: rustc rejected a pseudo-Rust body the pass reported as emitted:\n{}",
            fixture.tag,
            String::from_utf8_lossy(&output.stderr)
        );
        println!(
            "{}: {graded}/{} emitted pseudo-Rust bodies compiled by {compiler}",
            fixture.tag, analysis.bodies.rust_bodies
        );
        graded_total = graded_total.saturating_add(graded);
        drop(std::fs::remove_dir_all(&dir));
    }
    assert!(
        graded_total >= 487,
        "the pseudo-Rust grade must cover at least 487 real bodies, covered {graded_total}"
    );
}

#[test]
fn body_outcomes_partition_every_recovered_function() {
    for fixture in FIXTURES {
        let analysis: NativeLangAnalysis = analyze_fixture(fixture);
        let recovery: &BodyRecovery = &analysis.bodies;
        let total: u32 = recovery.recovered
            + recovery.recovered_elided
            + recovery.rejected
            + recovery.not_attempted;
        assert_eq!(
            total, recovery.function_count,
            "{}: outcome counts must sum to the recovered function count",
            fixture.tag
        );
        assert_eq!(
            u32::try_from(recovery.bodies.len()).unwrap(),
            recovery.function_count,
            "{}: every carved function must carry exactly one body outcome",
            fixture.tag
        );
        assert_eq!(
            recovery.function_count,
            u32::try_from(analysis.function_recovery.functions.len()).unwrap(),
            "{}: the body pass must see every carved function",
            fixture.tag
        );
        for body in &recovery.bodies {
            match &body.status {
                BodyStatus::Recovered { pseudo_c, .. } => assert!(
                    !pseudo_c.trim().is_empty(),
                    "{}: {} was reported recovered with an empty body",
                    fixture.tag,
                    body.name
                ),
                BodyStatus::Rejected { reason } => assert!(
                    !format!("{reason:?}").is_empty(),
                    "{}: {} was rejected without a reason",
                    fixture.tag,
                    body.name
                ),
                BodyStatus::RecoveredElided { .. } | BodyStatus::NotAttempted { .. } => {}
            }
        }
    }
}

#[test]
fn low_confidence_carves_never_receive_a_body() {
    for fixture in FIXTURES {
        let analysis: NativeLangAnalysis = analyze_fixture(fixture);
        for body in &analysis.bodies.bodies {
            if body.boundary_confidence == BoundaryConfidence::Low {
                assert!(
                    matches!(body.status, BodyStatus::NotAttempted { .. }),
                    "{}: {} at {:#x} has a low-confidence boundary and must not be lifted, got \
                     {:?}",
                    fixture.tag,
                    body.name,
                    body.start,
                    body.status
                );
            }
        }
    }
}

#[test]
fn emitted_names_are_unique_valid_c_identifiers() {
    for fixture in FIXTURES {
        let analysis: NativeLangAnalysis = analyze_fixture(fixture);
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for body in &analysis.bodies.bodies {
            let name: &str = body.emitted_name.as_str();
            let mut chars: std::str::Chars<'_> = name.chars();
            let head: char = chars.next().unwrap_or(' ');
            assert!(
                head.is_ascii_alphabetic() || head == '_',
                "{}: emitted name {name} does not start a C identifier",
                fixture.tag
            );
            assert!(
                chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_'),
                "{}: emitted name {name} is not a C identifier",
                fixture.tag
            );
            assert!(
                seen.insert(name),
                "{}: emitted name {name} is used by two functions",
                fixture.tag
            );
        }
    }
}

#[test]
fn body_recovery_is_byte_identical_across_runs() {
    for fixture in FIXTURES {
        let bytes: Vec<u8> = fixture_or_fail(fixture.relative_path);
        let first: NativeLangAnalysis = analyze(&bytes).expect("first analysis");
        let second: NativeLangAnalysis = analyze(&bytes).expect("second analysis");
        assert_eq!(
            first.bodies, second.bodies,
            "{}: body recovery must be deterministic",
            fixture.tag
        );
        let rendered_first: String =
            serde_json::to_string(&first.bodies).expect("serialize the first run");
        let rendered_second: String =
            serde_json::to_string(&second.bodies).expect("serialize the second run");
        assert_eq!(rendered_first, rendered_second);
    }
}

#[test]
fn user_functions_and_language_runtime_are_labelled_apart() {
    let nim: NativeLangAnalysis = analyze_fixture(&FIXTURES[0]);
    let nim_user: &FunctionBody = nim
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| body.name == "hello.fib")
        .expect("corpus/native/nim/hello.nim declares fib, so hello.fib must be carved");
    assert_eq!(
        nim_user.role,
        disrobe_pass_nativelang::RuntimeRole::UserCode,
        "hello.fib comes from the committed hello.nim source and is user code"
    );
    assert!(
        nim.bodies.bodies.iter().any(|body: &FunctionBody| {
            body.name.starts_with("system.")
                && body.role == disrobe_pass_nativelang::RuntimeRole::LanguageRuntime
        }),
        "the nim system module is runtime code and must be labelled as such"
    );
    assert!(
        nim.bodies.bodies.iter().any(|body: &FunctionBody| {
            body.name.starts_with("nim")
                && body.role == disrobe_pass_nativelang::RuntimeRole::CompilerGenerated
        }),
        "nim compiler-generated helpers must be labelled apart from user code"
    );

    let zig: NativeLangAnalysis = analyze_fixture(&FIXTURES[1]);
    let zig_user: &FunctionBody = zig
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| body.name == "hello.fib")
        .expect("corpus/native/zig/hello.zig declares fib, so hello.fib must be carved");
    assert_eq!(
        zig_user.role,
        disrobe_pass_nativelang::RuntimeRole::UserCode,
        "hello.fib comes from the committed hello.zig source and is user code"
    );
    assert!(
        zig.bodies.bodies.iter().any(|body: &FunctionBody| {
            body.name.starts_with("io.")
                && body.role == disrobe_pass_nativelang::RuntimeRole::LanguageRuntime
        }),
        "the zig io module is standard library code and must be labelled as such"
    );
}

#[test]
fn a_truncated_image_yields_a_typed_refusal_rather_than_a_body() {
    let bytes: Vec<u8> = fixture_or_fail(NIM_ELF);
    for cut in [1_usize, 64, 4096, bytes.len() / 3, bytes.len() / 2] {
        let truncated: &[u8] = bytes.get(..cut).unwrap_or(&bytes);
        match analyze(truncated) {
            Ok(analysis) => {
                let recovery: &BodyRecovery = &analysis.bodies;
                assert_eq!(
                    recovery.recovered
                        + recovery.recovered_elided
                        + recovery.rejected
                        + recovery.not_attempted,
                    recovery.function_count,
                    "a truncated image must still partition its outcomes"
                );
                for body in &recovery.bodies {
                    if let BodyStatus::Recovered { pseudo_c, .. } = &body.status {
                        assert!(!pseudo_c.trim().is_empty());
                    }
                }
            }
            Err(error) => {
                let message: String = error.to_string();
                assert!(
                    !message.is_empty(),
                    "a refusal must name its reason at cut {cut}"
                );
            }
        }
    }
}

#[test]
fn a_declared_body_larger_than_the_cap_is_not_attempted() {
    let bytes: Vec<u8> = fixture_or_fail(ZIG_ELF);
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze");
    let oversized: usize = analysis
        .bodies
        .bodies
        .iter()
        .filter(|body: &&FunctionBody| body.byte_len > 64 * 1024)
        .count();
    for body in &analysis.bodies.bodies {
        if body.byte_len > 64 * 1024 {
            assert!(
                matches!(body.status, BodyStatus::NotAttempted { .. }),
                "{} at {:#x} spans {} bytes and must not be lifted",
                body.name,
                body.start,
                body.byte_len
            );
        }
    }
    println!("zig-elf: {oversized} carved functions exceed the 64 KiB body cap");
}

fn assert_no_directory(path: &Path) {
    assert!(
        !path.exists(),
        "the recompile grade must clean its scratch directory {}",
        path.display()
    );
}

#[test]
fn scratch_directories_do_not_survive_a_graded_run() {
    let dir: PathBuf = scratch_dir("cleanup-probe");
    std::fs::write(dir.join("probe.c"), "int probe(void) { return 0; }\n").expect("write");
    std::fs::remove_dir_all(&dir).expect("remove");
    assert_no_directory(&dir);
}
