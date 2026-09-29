#![allow(clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, decompile_dex_from_bytes};
use sha2::{Digest, Sha256};

use crate::common;

const AUTHORED: &str = include_str!("../fixtures/dalvik_debug_names/DebugNames.java");
const RELEASE_DEX: &[u8] =
    include_bytes!("../fixtures/dalvik_debug_names/DebugNames-release-min21.dex");
const DEBUG_DEX: &[u8] =
    include_bytes!("../fixtures/dalvik_debug_names/DebugNames-debug-min21.dex");
const PROVENANCE: &str = include_str!("../fixtures/dalvik_debug_names/provenance.toml");
const AUTHORED_SHA256: &str = "ee2364ac2b72b0f6f0ffb0f1fad7bc86032f3587d39b7d4e7ea6a142780001ac";
const RELEASE_SHA256: &str = "2c7cbc5eeca08a09d4948aec4e08afebd8697ddf66dee7b1780da01e90b4e6fc";
const DEBUG_SHA256: &str = "6315ab550a3e6ef6db7ccc4314d1f52b6e625d04216050ac422ce18eba73eaf1";
const UNIT: &str = "DebugNames.java";
const CLASS: &str = "DebugNames";
const SCALE_INPUTS: [(i32, i32); 7] = [
    (0, 3),
    (1, 3),
    (4, 3),
    (7, -2),
    (-3, 5),
    (10, 10),
    (46_341, 46_341),
];

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered_unit(dex: &[u8], expected_sha256: &str) -> String {
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert_eq!(sha256_hex(dex), expected_sha256);
    assert!(PROVENANCE.contains(AUTHORED_SHA256) && PROVENANCE.contains(expected_sha256));
    let decompiled: DecompiledDex = decompile_dex_from_bytes(dex).expect("decompile DebugNames");
    decompiled.sources.get(UNIT).cloned().unwrap_or_else(|| {
        panic!(
            "recovered unit {UNIT} in {:?}",
            decompiled.sources.keys().collect::<Vec<&String>>()
        )
    })
}

fn method_text(source: &str, name: &str) -> String {
    let signature: String = format!(" {name}(");
    let mut lines = source.lines();
    let mut text: String = String::new();
    for line in lines.by_ref() {
        let trimmed: &str = line.trim_start();
        if line.starts_with("    ")
            && !line.starts_with("     ")
            && (trimmed.starts_with("public ") || trimmed.starts_with("static "))
            && line.contains(&signature)
            && line.ends_with('{')
        {
            text.push_str(line);
            text.push('\n');
            break;
        }
    }
    assert!(!text.is_empty(), "no method {name} in:\n{source}");
    for line in lines {
        text.push_str(line);
        text.push('\n');
        if line == "    }" {
            return text;
        }
    }
    panic!("method {name} never closes in:\n{source}");
}

fn javac() -> PathBuf {
    common::find_on_path("javac").expect("javac is required to recompile the recovered DebugNames")
}

fn compile(out: &Path, sources: &[PathBuf]) -> Result<(), String> {
    let output: Output = Command::new(javac())
        .arg("-Xlint:-options")
        .arg("--release")
        .arg("8")
        .arg("-d")
        .arg(out)
        .args(sources)
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run javac");
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn run_java(classes: &Path, main_class: &str) -> String {
    let java: PathBuf =
        common::find_on_path("java").expect("java is required to run the recovered DebugNames");
    let output: Output = Command::new(java)
        .arg("-cp")
        .arg(classes)
        .arg(main_class)
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run java");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn execute(scratch: &Path, tag: &str, file: &str, main_class: &str, source: &str) -> String {
    let root: PathBuf = scratch.join(tag);
    std::fs::create_dir_all(&root).expect("create source directory");
    let path: PathBuf = root.join(file);
    std::fs::write(&path, source).expect("write source");
    let classes: PathBuf = root.join("classes");
    if let Err(diagnostics) = compile(&classes, &[path]) {
        panic!("{tag} does not recompile:\n{diagnostics}\n{source}");
    }
    run_java(&classes, main_class)
}

fn scale_probe(method: &str) -> String {
    let mut source: String = String::from("public class ScaleProbe {\n");
    source.push_str(method);
    source.push_str("    public static void main(String[] args) {\n");
    for (count, factor) in SCALE_INPUTS {
        let _: std::fmt::Result = writeln!(
            source,
            "        System.out.println(\"{count} {factor} \" + scale({count}, {factor}));"
        );
    }
    source.push_str("    }\n}\n");
    source
}

fn authored_table(scratch: &Path) -> String {
    let reference: String = execute(scratch, "authored", UNIT, CLASS, AUTHORED);
    assert_eq!(reference.lines().count(), 6, "{reference}");
    reference
}

#[test]
fn the_recovered_class_recompiles_and_prints_the_authored_table() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_debug_names_table").expect("scratch");
    let reference: String = authored_table(scratch.path());
    for (tag, dex, digest) in [
        ("release", RELEASE_DEX, RELEASE_SHA256),
        ("debug", DEBUG_DEX, DEBUG_SHA256),
    ] {
        let recovered: String = recovered_unit(dex, digest);
        let printed: String = execute(scratch.path(), tag, UNIT, CLASS, &recovered);
        assert_eq!(
            printed, reference,
            "the recovered {tag} class must print what the authored class prints:\n{recovered}"
        );
    }
}

#[test]
fn a_seeded_change_in_the_recovered_class_changes_the_printed_table() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_debug_names_control").expect("scratch");
    let reference: String = authored_table(scratch.path());
    let recovered: String = recovered_unit(RELEASE_DEX, RELEASE_SHA256);
    assert_eq!(recovered.matches("\"small\"").count(), 1, "{recovered}");
    let mutated: String = recovered.replace("\"small\"", "\"tiny\"");
    let printed: String = execute(scratch.path(), "mutated", UNIT, CLASS, &mutated);
    assert_ne!(
        printed, reference,
        "grader control: a changed literal in the recovered class must change the table"
    );
}

#[test]
fn scale_adds_the_product_before_the_counter_advances() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_debug_names_scale").expect("scratch");
    let authored: String = method_text(AUTHORED, "scale");
    let reference: String = execute(
        scratch.path(),
        "authored",
        "ScaleProbe.java",
        "ScaleProbe",
        &scale_probe(&authored),
    );
    assert_eq!(reference.lines().count(), SCALE_INPUTS.len(), "{reference}");
    let recovered: String = method_text(&recovered_unit(RELEASE_DEX, RELEASE_SHA256), "scale");
    let printed: String = execute(
        scratch.path(),
        "recovered",
        "ScaleProbe.java",
        "ScaleProbe",
        &scale_probe(&recovered),
    );
    assert_eq!(printed, reference, "{recovered}");
}

#[test]
fn describe_divides_by_the_double_constant_not_its_bit_pattern() {
    let describe: String = method_text(&recovered_unit(RELEASE_DEX, RELEASE_SHA256), "describe");
    assert!(
        !describe.contains("4611686018427387904"),
        "the const-wide/high16 double 2.0 leaked as its raw long bits:\n{describe}"
    );
    assert!(describe.contains(" / 2.0)"), "{describe}");
}

#[test]
fn main_calls_scale_and_describe_once_per_iteration() {
    let main: String = method_text(&recovered_unit(RELEASE_DEX, RELEASE_SHA256), "main");
    assert_eq!(main.matches("scale(").count(), 1, "{main}");
    assert_eq!(main.matches("describe(").count(), 1, "{main}");
    assert_eq!(main.matches("println(").count(), 1, "{main}");
}

#[test]
fn debug_parameter_names_are_the_names_the_body_reads() {
    let recovered: String = recovered_unit(DEBUG_DEX, DEBUG_SHA256);
    for (name, parameters) in [
        ("scale", ["count", "factor"]),
        ("describe", ["value", "verbose"]),
    ] {
        let method: String = method_text(&recovered, name);
        let (signature, body): (&str, &str) = method.split_once('\n').expect("method has a body");
        for parameter in parameters {
            assert!(signature.contains(&format!(" {parameter}")), "{method}");
            assert!(body.contains(parameter), "{method}");
        }
        assert!(
            !body.contains("arg0") && !body.contains("arg1"),
            "the body reads positional names the signature does not declare:\n{method}"
        );
    }
}
