#![allow(clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, decompile_dex_from_bytes};
use sha2::{Digest, Sha256};

pub mod common;

const AUTHORED: &str = include_str!("fixtures/dexguard_cff/FlatteningProbe.java");
const DEX: &[u8] = include_bytes!("fixtures/dexguard_cff/FlatteningProbe-min21.dex");
const PROVENANCE: &str = include_str!("fixtures/dexguard_cff/provenance.toml");
const AUTHORED_SHA256: &str = "e6c168b22906d1fd64103e15f7e626db6be1472fe735f93475a851b46ceb4a3d";
const DEX_SHA256: &str = "710906957eb0f3e806b22a5af50a2bf8da6a109b04d45215e5d6132028205bb5";
const UNIT: &str = "FlatteningProbe.java";
const INPUTS: [i32; 8] = [-3, 0, 1, 2, 3, 7, 12, 25];

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered_unit() -> String {
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert!(PROVENANCE.contains(AUTHORED_SHA256) && PROVENANCE.contains(DEX_SHA256));
    let decompiled: DecompiledDex =
        decompile_dex_from_bytes(DEX).expect("decompile the flattening probe");
    decompiled.sources.get(UNIT).cloned().unwrap_or_else(|| {
        panic!(
            "recovered unit {UNIT} in {:?}",
            decompiled.sources.keys().collect::<Vec<&String>>()
        )
    })
}

fn method_body<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    let signature: String = format!(" {name}(");
    let mut lines = source.lines();
    for line in lines.by_ref() {
        if line.starts_with("    public ") && line.contains(&signature) && line.ends_with('{') {
            break;
        }
    }
    lines.take_while(|line: &&str| *line != "    }").collect()
}

fn control_skeleton(body: &[&str]) -> Vec<String> {
    body.iter()
        .filter_map(|line: &&str| {
            let trimmed: &str = line.trim();
            let depth: usize = (line.len() - line.trim_start().len()) / 4;
            let kind: &str = if trimmed.starts_with("while (") {
                "while"
            } else if trimmed == "do {" {
                "do"
            } else if trimmed.starts_with("} while") {
                "do-end"
            } else if trimmed.starts_with("if (") {
                "if"
            } else if trimmed == "} else {" {
                "else"
            } else if trimmed.starts_with("switch (") {
                "switch"
            } else if trimmed.starts_with("case ") || trimmed == "default:" {
                "case"
            } else if trimmed.starts_with("return") {
                "return"
            } else if trimmed.starts_with("break") {
                "break"
            } else if trimmed.starts_with("continue") {
                "continue"
            } else if trimmed.starts_with("throw ") {
                "throw"
            } else if trimmed == "}" {
                "end"
            } else {
                return None;
            };
            Some(format!("{depth}:{kind}"))
        })
        .collect()
}

fn run_java(classes: &Path, driver: &str) -> String {
    let java: PathBuf =
        common::find_on_path("java").expect("java is required for the flattening probe oracle");
    let output: Output = Command::new(java)
        .arg("-cp")
        .arg(classes)
        .arg(driver)
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

fn compile(javac: &Path, out: &Path, sources: &[PathBuf], unit: &str) {
    let output: Output = Command::new(javac)
        .arg("-Xlint:-options")
        .arg("--release")
        .arg("8")
        .arg("-d")
        .arg(out)
        .args(sources)
        .output()
        .expect("run javac");
    assert!(
        output.status.success(),
        "{}\n{}\n{unit}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn driver_source(method: &str) -> String {
    let mut source: String = "public class Driver {
    public static void main(String[] args) {
"
    .to_owned();
    for input in INPUTS {
        let _: std::fmt::Result = writeln!(
            source,
            "        System.out.println(\"{input} \" + FlatteningProbe.{method}({input}));"
        );
    }
    source.push_str(
        "    }
}
",
    );
    source
}

fn execute(scratch: &Path, tag: &str, unit: &str, method: &str) -> String {
    let javac: PathBuf =
        common::find_on_path("javac").expect("javac is required for the flattening probe oracle");
    let root: PathBuf = scratch.join(tag);
    std::fs::create_dir_all(&root).expect("create source directory");
    let probe: PathBuf = root.join(UNIT);
    let driver: PathBuf = root.join("Driver.java");
    std::fs::write(&probe, unit).expect("write probe");
    std::fs::write(&driver, driver_source(method)).expect("write driver");
    let classes: PathBuf = root.join("classes");
    compile(&javac, &classes, &[probe, driver], unit);
    run_java(&classes, "Driver")
}

#[test]
fn a_flattened_method_lifts_from_the_rewired_graph() {
    let recovered: String = recovered_unit();
    let flattened: Vec<&str> = method_body(&recovered, "flattened");
    let original: Vec<&str> = method_body(&recovered, "original");
    assert!(!flattened.is_empty() && !original.is_empty(), "{recovered}");

    let authored_flattened: Vec<&str> = method_body(AUTHORED, "flattened");
    assert_ne!(
        control_skeleton(&authored_flattened),
        control_skeleton(&original),
        "grader control: a dispatcher-shaped body must not match the unflattened skeleton"
    );

    assert!(
        flattened
            .iter()
            .any(|line: &&str| line.contains("lifted from the rewired graph")),
        "{recovered}"
    );
    assert!(
        !flattened
            .iter()
            .any(|line: &&str| line.contains("switch (")),
        "the dispatcher switch survived the rewiring:\n{recovered}"
    );
    assert_eq!(
        control_skeleton(&flattened),
        control_skeleton(&original),
        "the rewired body must structure like the unflattened method:\n{recovered}"
    );
    assert!(
        !original
            .iter()
            .any(|line: &&str| line.contains("control-flow flattening")),
        "{recovered}"
    );

    let scratch: ScratchDir = ScratchDir::create("dexguard_cff_rewired_lift").expect("scratch");
    let reference: String = execute(scratch.path(), "authored", AUTHORED, "original");
    let lifted: String = execute(scratch.path(), "recovered", &recovered, "flattened");
    assert_eq!(reference.lines().count(), INPUTS.len(), "{reference}");
    assert_eq!(
        lifted, reference,
        "the recovered flattened method must compute what the authored original computes"
    );
}
