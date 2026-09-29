#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_ruby::analyze_bytes;
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};
use ruby_toolchain::{ToolchainBanner, require_exact_mri_recompile};

const GRADED: &str = "the Ruby 4.0 YARV behaviour check over corpus/ruby/mri/yarv40";

const PROGRAMS: [&str; 16] = [
    "programs",
    "control",
    "objects",
    "text",
    "patterns",
    "loops",
    "guards",
    "introspection",
    "features",
    "operators",
    "functional",
    "flow",
    "values",
    "cases",
    "case_join",
    "nested_cases",
];

fn corpus_ruby() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("corpus")
        .join("ruby")
}

fn run(ruby: &Path, program: &Path) -> ToolOutput {
    tool_output(CommandSpec::new(ruby, Duration::from_mins(1)).arg(program))
        .unwrap_or_else(|error: disrobe_testkit::ToolError| panic!("running ruby failed: {error}"))
}

struct Graded {
    original: ToolOutput,
    recovered_source: String,
    recovered: ToolOutput,
}

fn grade(name: &str, transform: fn(&str) -> String) -> Graded {
    let toolchain: ToolchainBanner = require_exact_mri_recompile(GRADED);
    let ruby: PathBuf = PathBuf::from(&toolchain.executable);
    let fixture: PathBuf = corpus_ruby()
        .join("mri")
        .join("yarv40")
        .join(format!("{name}.yarvc"));
    let ibf: Vec<u8> = std::fs::read(&fixture).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the tracked Ruby 4.0 fixture {} is missing ({error}); restore it with git checkout",
            fixture.display()
        )
    });
    assert_eq!(
        ibf.get(..12),
        Some(&b"YARB\x04\x00\x00\x00\x00\x00\x00\x00"[..]),
        "{} must be a Ruby 4.0 instruction sequence",
        fixture.display()
    );
    let analysis = analyze_bytes(&ibf, &format!("{name}.yarvc"))
        .unwrap_or_else(|error| panic!("analyze {}: {error}", fixture.display()));
    let yarv = analysis
        .yarv
        .unwrap_or_else(|| panic!("a YARV analysis for {}", fixture.display()));
    let recovered_source: String = transform(&yarv.decompiled.source);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_ruby40_behaviour").expect("create scratch directory");
    let recovered_path: PathBuf = scratch.path().join("recovered.rb");
    std::fs::write(&recovered_path, &recovered_source).expect("write the recovered program");
    let source: PathBuf = corpus_ruby().join("behaviour").join(format!("{name}.rb"));
    let original: ToolOutput = run(&ruby, &source);
    assert!(
        original.success && !original.stdout.is_empty(),
        "the original program must run and print: {}",
        original.stderr_text()
    );
    let recovered: ToolOutput = run(&ruby, &recovered_path);
    Graded {
        original,
        recovered_source,
        recovered,
    }
}

#[test]
fn programs_compiled_by_ruby_4_0_recover_to_source_that_prints_what_the_original_prints() {
    let mut diverged: Vec<String> = Vec::new();
    for name in PROGRAMS {
        let graded: Graded = grade(name, str::to_owned);
        if !graded.recovered.success || graded.recovered.stdout != graded.original.stdout {
            diverged.push(format!(
                "{name}: exit {:?}\n--- stderr:\n{}\n--- recovered:\n{}",
                graded.recovered.exit_code,
                graded.recovered.stderr_text(),
                graded.recovered_source
            ));
        }
    }
    assert!(
        diverged.is_empty(),
        "{} of {} Ruby 4.0 programs diverged:\n{}",
        diverged.len(),
        PROGRAMS.len(),
        diverged.join("\n\n")
    );
}

#[test]
fn a_changed_constant_in_the_recovered_ruby_4_0_program_turns_the_grade_red() {
    let graded: Graded = grade("programs", |source: &str| {
        source.replacen("3.14159", "3.0", 1)
    });
    assert!(
        graded.recovered_source.contains("3.0"),
        "the mutation must reach the recovered source:\n{}",
        graded.recovered_source
    );
    assert_ne!(
        graded.recovered.stdout, graded.original.stdout,
        "{GRADED} cannot see a changed constant"
    );
}
