#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_ruby::analyze_bytes;
use ruby_toolchain::{ToolchainBanner, require_exact_mri_recompile};

const GRADED: &str = "the recovered-ruby behaviour check over corpus/ruby/behaviour";

fn program_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("corpus")
        .join("ruby")
        .join("behaviour")
        .join(name)
}

fn run(ruby: &OsString, args: &[&Path]) -> Output {
    Command::new(ruby)
        .args(args)
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("running ruby failed: {error}"))
}

fn compile_to_ibf(ruby: &OsString, source: &Path, ibf: &Path) -> Vec<u8> {
    let output: Output = Command::new(ruby)
        .arg("-e")
        .arg("File.binwrite(ARGV[1], RubyVM::InstructionSequence.compile_file(ARGV[0]).to_binary)")
        .arg(source)
        .arg(ibf)
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("running ruby failed: {error}"));
    assert!(
        output.status.success(),
        "ruby could not compile {} to YARV: {}",
        source.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(ibf).expect("read the compiled instruction sequence")
}

struct Graded {
    original: Output,
    recovered_source: String,
    recovered: Output,
}

fn grade(name: &str, transform: fn(&str) -> String) -> Graded {
    let toolchain: ToolchainBanner = require_exact_mri_recompile(GRADED);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_ruby_behaviour").expect("create scratch directory");
    let source: PathBuf = program_path(name);
    let ibf_path: PathBuf = scratch.path().join("programs.yarvc");
    let ibf: Vec<u8> = compile_to_ibf(&toolchain.executable, &source, &ibf_path);
    let analysis = analyze_bytes(&ibf, "programs.yarvc").expect("analyze the compiled program");
    let yarv = analysis
        .yarv
        .expect("a YARV analysis for the compiled program");
    let recovered_source: String = transform(&yarv.decompiled.source);
    let recovered_path: PathBuf = scratch.path().join("recovered.rb");
    std::fs::write(&recovered_path, &recovered_source).expect("write the recovered program");
    let original: Output = run(&toolchain.executable, &[source.as_path()]);
    assert!(
        original.status.success() && !original.stdout.is_empty(),
        "the original program must run and print: {}",
        String::from_utf8_lossy(&original.stderr)
    );
    let recovered: Output = run(&toolchain.executable, &[recovered_path.as_path()]);
    Graded {
        original,
        recovered_source,
        recovered,
    }
}

fn assert_same_output(name: &str) {
    let graded: Graded = grade(name, str::to_owned);
    assert!(
        graded.recovered.status.success(),
        "the recovered program failed: {}\nsource:\n{}",
        String::from_utf8_lossy(&graded.recovered.stderr),
        graded.recovered_source
    );
    assert_eq!(
        String::from_utf8_lossy(&graded.recovered.stdout),
        String::from_utf8_lossy(&graded.original.stdout),
        "recovered source:\n{}",
        graded.recovered_source
    );
}

#[test]
fn the_recovered_program_prints_what_the_original_prints() {
    assert_same_output("programs.rb");
}

#[test]
fn recovered_control_flow_prints_what_the_original_prints() {
    assert_same_output("control.rb");
}

#[test]
fn a_recovered_object_model_prints_what_the_original_prints() {
    assert_same_output("objects.rb");
}

#[test]
fn recovered_text_processing_prints_what_the_original_prints() {
    assert_same_output("text.rb");
}

#[test]
fn a_changed_constant_in_the_recovered_program_turns_the_grade_red() {
    let graded: Graded = grade("programs.rb", |source: &str| {
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
