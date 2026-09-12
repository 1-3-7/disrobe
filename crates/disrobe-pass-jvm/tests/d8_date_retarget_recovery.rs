#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, wait_with_output_timeout};
use disrobe_pass_jvm::dalvik_decompile::{DecompiledDex, decompile_dex};
use disrobe_pass_jvm::dex::{DexFile, MethodId, parse as parse_dex};

const FIXTURE: &[u8] = include_bytes!("fixtures/d8_date_retarget/DateRetargetProbe-min21.dex");
const IDENTIFIER: &str = "com.tools.android:desugar_jdk_libs_configuration:2.1.5";
const AUTHORED: &str = include_str!("fixtures/d8_date_retarget/DateRetargetProbe.java");
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CAPTURE_BYTES: usize = 1 << 20;
const HARNESS: &str = r"package fixtures.desugar;

import java.time.Instant;
import java.util.Date;

public final class DateRetargetHarness {
    public static void main(String[] args) {
        System.out.println(DateRetargetProbe.fromInstant(Instant.ofEpochMilli(123456789L)).getTime());
        System.out.println(DateRetargetProbe.toInstant(new Date(987654321L)).toEpochMilli());
    }
}
";

fn source_from(dex: &DexFile) -> String {
    let recovered: DecompiledDex = decompile_dex(dex, FIXTURE);
    recovered
        .sources
        .get("fixtures/desugar/DateRetargetProbe.java")
        .expect("recover the authored class")
        .clone()
}

fn recovered_source() -> String {
    let dex: DexFile = parse_dex(FIXTURE).expect("parse trusted D8 fixture");
    source_from(&dex)
}

fn compile_and_run(label: &str, source: &str) -> CapturedOutput {
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let source_root: PathBuf = scratch.path().join("src/fixtures/desugar");
    let classes: PathBuf = scratch.path().join("classes");
    std::fs::create_dir_all(&source_root).expect("create Java source directory");
    std::fs::create_dir_all(&classes).expect("create Java class directory");
    let probe_path: PathBuf = source_root.join("DateRetargetProbe.java");
    let harness_path: PathBuf = source_root.join("DateRetargetHarness.java");
    std::fs::write(&probe_path, source).expect("write Java probe");
    std::fs::write(&harness_path, HARNESS).expect("write Java harness");
    let paths: [&Path; 2] = [probe_path.as_path(), harness_path.as_path()];
    let compile_child: Child = Command::new("javac")
        .arg("--release")
        .arg("11")
        .arg("-d")
        .arg(&classes)
        .args(paths)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start javac");
    let compile: CapturedOutput =
        wait_with_output_timeout(compile_child, PROCESS_TIMEOUT, MAX_CAPTURE_BYTES)
            .expect("javac completes within the timeout");
    assert!(
        compile.exit_code == Some(0),
        "javac rejected {label}: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let java_child: Child = Command::new("java")
        .arg("-cp")
        .arg(classes)
        .arg("fixtures.desugar.DateRetargetHarness")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Java harness");
    wait_with_output_timeout(java_child, PROCESS_TIMEOUT, MAX_CAPTURE_BYTES)
        .expect("Java harness completes within the timeout")
}

#[test]
fn real_d8_date_retargets_return_to_java_util_date_calls() {
    let dex: DexFile = parse_dex(FIXTURE).expect("parse trusted D8 fixture");
    assert!(dex.strings.iter().any(|value: &String| {
        value.starts_with("~~D8") && value.contains(IDENTIFIER) && value.contains("9.1.31")
    }));
    for owner in ["Lj$/util/DesugarDate;", "Lj$/util/DateRetargetClass;"] {
        assert!(
            dex.method_ids
                .iter()
                .any(|method: &MethodId| method.class == owner),
            "the real D8 artifact must carry {owner}"
        );
    }

    let source: String = recovered_source();
    assert!(source.contains("java.util.Date.from("), "{source}");
    assert!(source.contains(".toInstant()"), "{source}");
    assert!(!source.contains("DesugarDate"), "{source}");
    assert!(!source.contains("DateRetargetClass"), "{source}");
    assert!(!source.contains("DR-JVM-CORE-"), "{source}");
}

#[test]
fn date_retarget_recovery_is_deterministic() {
    assert_eq!(recovered_source(), recovered_source());
}

#[test]
fn an_unknown_date_retarget_signature_remains_visible_with_a_diagnostic() {
    let mut dex: DexFile = parse_dex(FIXTURE).expect("parse trusted D8 fixture");
    let helper: &mut MethodId = dex
        .method_ids
        .iter_mut()
        .find(|method: &&mut MethodId| method.class == "Lj$/util/DateRetargetClass;")
        .expect("find the receiver-first date retarget");
    helper.proto.return_type = "J".to_string();
    let recovered: DecompiledDex = decompile_dex(&dex, FIXTURE);
    assert!(recovered.source.contains("DateRetargetClass"));
    assert!(recovered.source.contains("DR-JVM-CORE-0004"));
    assert!(!recovered.source.contains(".toInstant()"));
}

#[test]
fn exact_date_helpers_require_exact_ownership_but_not_broad_relocation() {
    let parsed: DexFile = parse_dex(FIXTURE).expect("parse trusted D8 fixture");
    let mut missing_marker: DexFile = parsed.clone();
    missing_marker
        .strings
        .retain(|value: &String| !value.starts_with("~~D8"));
    let missing_source: String = source_from(&missing_marker);
    assert!(missing_source.contains("java.util.Date.from("));
    assert!(missing_source.contains(".toInstant()"));

    let mut conflicting_marker: DexFile = parsed.clone();
    for value in &mut conflicting_marker.strings {
        if value.starts_with("~~D8") {
            *value = value.replace(IDENTIFIER, "unknown:configuration:9.9.9");
        }
    }
    let conflicting_source: String = source_from(&conflicting_marker);
    assert!(conflicting_source.contains("java.util.Date.from("));
    assert!(conflicting_source.contains(".toInstant()"));

    let mut unrelated_owned_prefix: DexFile = parsed.clone();
    unrelated_owned_prefix
        .class_descriptors
        .push("Lj$/application/Owned;".to_string());
    let unrelated_source: String = source_from(&unrelated_owned_prefix);
    assert!(unrelated_source.contains("java.util.Date.from("));
    assert!(unrelated_source.contains(".toInstant()"));

    let mut exact_owner_collision: DexFile = parsed;
    exact_owner_collision
        .class_descriptors
        .push("Lj$/util/DesugarDate;".to_string());
    let collision_source: String = source_from(&exact_owner_collision);
    assert!(collision_source.contains("DesugarDate"));
    assert!(collision_source.contains("DR-JVM-CORE-0003"));
}

#[test]
fn recovered_date_retargets_recompile_and_match_the_authored_behavior() {
    let authored: CapturedOutput = compile_and_run("d8-date-retarget-authored", AUTHORED);
    let recovered: CapturedOutput =
        compile_and_run("d8-date-retarget-recovered", &recovered_source());
    assert_eq!(authored.exit_code, Some(0));
    assert_eq!(recovered.exit_code, Some(0));
    assert_eq!(recovered.stdout, authored.stdout);
    assert_eq!(
        String::from_utf8_lossy(&authored.stdout)
            .lines()
            .collect::<Vec<&str>>(),
        ["123456789", "987654321"]
    );
}
