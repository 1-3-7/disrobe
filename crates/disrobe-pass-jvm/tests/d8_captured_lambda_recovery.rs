#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

pub mod common;

const DEX: &[u8] =
    include_bytes!("../../../corpus/jvm/desugar-lambda/CapturedLambdaProbe-min21.dex");
const SOURCE: &str = include_str!("../../../corpus/jvm/desugar-lambda/CapturedLambdaProbe.java");
const PROVENANCE: &str = include_str!("../../../corpus/jvm/desugar-lambda/provenance.toml");
const DEX_SHA256: &str = "537346bf56ac0ef033de0a9999f929d30f32fc30cf1fe7056ceff2136d6ff1ac";
const SOURCE_SHA256: &str = "85bb5423ec833faeefbe95fbab09f6e01ca3e0b0f29782d6f83ed3a0012fc0b1";
const SERIALIZABLE_LOOKALIKE: &str = "import java.io.Serializable; public final class CapturedLambdaProbe { Serializable make(int captured) { return new CapturedLambdaProbe$_0(this, captured); } int lambda$make$0(int captured, int value) { return captured; } } final class CapturedLambdaProbe$_0 implements Serializable { private final CapturedLambdaProbe receiver; private final int captured; CapturedLambdaProbe$_0(CapturedLambdaProbe receiver, int captured) { this.receiver = receiver; this.captured = captured; } int applyAsInt(int value) { return receiver.lambda$make$0(captured, value); } }";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn program_source(recovered: &DecompiledDex) -> &String {
    recovered
        .sources
        .values()
        .find(|source: &&String| source.contains("class CapturedLambdaProbe {"))
        .expect("recover the authored compilation unit")
}

fn execute_java(label: &str, source: &str) -> Vec<u8> {
    let javac: PathBuf = common::find_on_path("javac").expect("javac is required");
    let java: PathBuf = common::find_on_path("java").expect("java is required");
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let source_path: PathBuf = scratch.path().join("CapturedLambdaProbe.java");
    let harness_path: PathBuf = scratch.path().join("Harness.java");
    let harness: &str = "public final class Harness { public static void main(String[] args) { System.out.println(CapturedLambdaProbe.run(11, 13)); System.out.println(CapturedLambdaProbe.run(-5, 23)); } }";
    std::fs::write(&source_path, source).expect("write Java program");
    std::fs::write(&harness_path, harness).expect("write Java harness");
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .arg(&harness_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("Harness")
        .output()
        .expect("run Java harness");
    assert!(
        executed.status.success(),
        "Java rejected {label}:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    executed.stdout
}

fn assert_java_sources_compile(label: &str, sources: &[(&str, &str)]) {
    let javac: PathBuf = common::find_on_path("javac").expect("javac is required");
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let paths: Vec<PathBuf> = sources
        .iter()
        .map(|(name, source): &(&str, &str)| {
            let path: PathBuf = scratch.path().join(name);
            std::fs::write(&path, source).expect("write Java source");
            path
        })
        .collect();
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .args(&paths)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
}

fn synthetic_descriptor(dex: &DexFile) -> &String {
    dex.class_descriptors
        .iter()
        .find(|name: &&String| {
            name.contains("SyntheticLambda") || name.starts_with("LCapturedLambdaProbe$")
        })
        .unwrap_or_else(|| {
            panic!(
                "real D8 artifact carries a synthetic lambda class: {:?}",
                dex.class_descriptors
            )
        })
}

fn retains_synthetic(recovered: &DecompiledDex) -> bool {
    recovered
        .sources
        .values()
        .any(|source: &String| source.contains("class CapturedLambdaProbe$_"))
}

#[test]
fn real_d8_captured_lambda_recompiles_and_preserves_runtime_behavior() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(SOURCE.as_bytes()), SOURCE_SHA256);
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert!(PROVENANCE.contains(DEX_SHA256));
    assert!(PROVENANCE.contains(SOURCE_SHA256));
    assert_eq!(DEX.get(..8), Some(b"dex\n035\0".as_slice()));

    let dex: DexFile = parse_dex(DEX).expect("parse real D8 artifact");
    let synthetic: &String = synthetic_descriptor(&dex);
    assert!(
        dex.strings
            .iter()
            .any(|value: &String| value.starts_with("lambda$make$0")),
        "real D8 artifact must carry the synthetic lambda helper"
    );
    let recovered: DecompiledDex = decompile_dex(&dex, DEX);
    let source: &String = program_source(&recovered);
    assert!(source.contains("return p0 ->"), "{source}");
    assert!(source.contains("(arg0, p0)"), "{source}");
    assert!(!source.contains("new CapturedLambdaProbe$_"), "{source}");
    assert!(
        !retains_synthetic(&recovered),
        "the exclusively constructed D8 lambda class {synthetic} must be elided"
    );

    let original_stdout: Vec<u8> = execute_java("d8-captured-lambda-original", SOURCE);
    let recovered_stdout: Vec<u8> = execute_java("d8-captured-lambda-recovered", source);
    let original_text: String = String::from_utf8_lossy(&original_stdout).into_owned();
    let original_lines: Vec<&str> = original_text.lines().collect();
    assert_eq!(original_lines, ["11", "-5"]);
    assert_eq!(recovered_stdout, original_stdout);

    let mutated: String = source.replacen("(arg0, p0)", "(p0, arg0)", 1);
    assert_ne!(mutated, *source, "the argument-order mutation must apply");
    let mutated_stdout: Vec<u8> = execute_java("d8-captured-lambda-mutated", &mutated);
    assert_ne!(mutated_stdout, original_stdout);
}

#[test]
fn ambiguous_or_modern_invocation_metadata_keeps_the_d8_lambda_visible() {
    let dex: DexFile = parse_dex(DEX).expect("parse real D8 artifact");
    let descriptor: String = synthetic_descriptor(&dex).clone();
    let binary_name: String = descriptor
        .trim_start_matches('L')
        .trim_end_matches(';')
        .replace('/', ".");

    let mut reflected: DexFile = dex.clone();
    reflected.strings.push(binary_name);
    let reflected_output: DecompiledDex = decompile_dex(&reflected, DEX);
    assert!(retains_synthetic(&reflected_output));
    assert!(program_source(&reflected_output).contains("new CapturedLambdaProbe$_"));

    let mut modern: DexFile = dex;
    modern.call_site_ids_size = 1;
    let modern_output: DecompiledDex = decompile_dex(&modern, DEX);
    assert!(retains_synthetic(&modern_output));
    assert!(program_source(&modern_output).contains("new CapturedLambdaProbe$_"));
}

#[test]
fn serializable_lookalike_and_non_int_capture_keep_the_synthetic_class() {
    let dex: DexFile = parse_dex(DEX).expect("parse real D8 artifact");
    assert_java_sources_compile(
        "d8-captured-lambda-serializable-lookalike",
        &[("CapturedLambdaProbe.java", SERIALIZABLE_LOOKALIKE)],
    );

    let mut lookalike: DexFile = dex.clone();
    let functional_interface: &mut String = lookalike
        .type_names
        .iter_mut()
        .find(|name: &&mut String| name.as_str() == "Ljava/util/function/IntUnaryOperator;")
        .expect("IntUnaryOperator type");
    *functional_interface = "Ljava/io/Serializable;".to_owned();
    let lookalike_output: DecompiledDex = decompile_dex(&lookalike, DEX);
    assert!(retains_synthetic(&lookalike_output));
    assert!(program_source(&lookalike_output).contains("new CapturedLambdaProbe$_"));

    let mut wide_capture: DexFile = dex;
    let captured_field: &mut disrobe_pass_jvm::dex::FieldId = wide_capture
        .field_ids
        .iter_mut()
        .find(|field: &&mut disrobe_pass_jvm::dex::FieldId| {
            field.class.starts_with("LCapturedLambdaProbe$") && field.type_name == "I"
        })
        .expect("captured int field");
    captured_field.type_name = "J".to_owned();
    let wide_capture_output: DecompiledDex = decompile_dex(&wide_capture, DEX);
    assert!(retains_synthetic(&wide_capture_output));
    assert!(program_source(&wide_capture_output).contains("new CapturedLambdaProbe$_"));
}
