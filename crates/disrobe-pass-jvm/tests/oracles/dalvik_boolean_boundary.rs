#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, decompile_dex_from_bytes};

use crate::common;

const BOOLEAN_BOUNDARY_DEX: &[u8] =
    include_bytes!("../fixtures/dalvik_boolean_boundary/BooleanBoundary-min21.dex");
const RECOVERED_PATH: &str = "fixture/bool/BooleanBoundary.java";
const BOOLEAN_SITES: [&str; 13] = [
    "        fixture.bool.BooleanBoundary.shared = arg0;",
    "        arg1[arg2] = arg0[arg2];",
    "        return arg0;",
    "        this.flags[arg0] = arg1;",
    "        this.flag = arg0;",
    "        return (arg0 & arg1);",
    "        return (arg0 | arg1);",
    "        return (arg0 ^ arg1);",
    "        return (!arg0);",
    "        this.flag = (arg0 & arg1);",
    "        this.flag = (!arg0);",
    "        fixture.bool.BooleanBoundary.shared = (arg0 | arg1);",
    "        this.flags[arg0] = (arg1 ^ arg2);",
];

fn recovered_boolean_boundary() -> String {
    let recovered: DecompiledDex = decompile_dex_from_bytes(BOOLEAN_BOUNDARY_DEX)
        .expect("decompile the boolean boundary DEX through the direct Dalvik route");
    recovered
        .sources
        .get(RECOVERED_PATH)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "direct route source {RECOVERED_PATH} in {:?}",
                recovered.sources.keys()
            )
        })
}

#[test]
fn direct_dalvik_boolean_boundaries_recompile_under_javac() {
    let source: String = recovered_boolean_boundary();
    for site in BOOLEAN_SITES {
        assert_eq!(
            source.lines().filter(|line: &&str| *line == site).count(),
            1,
            "boolean boundary statement {site:?}:\n{source}"
        );
    }
    assert!(!source.contains("!= 0"), "{source}");

    let javac: PathBuf =
        common::find_on_path("javac").expect("javac is required for the boolean boundary oracle");
    let scratch: ScratchDir =
        ScratchDir::create("dalvik_boolean_boundary_oracle").expect("create javac scratch");
    let source_path: PathBuf = scratch.path().join(RECOVERED_PATH);
    std::fs::create_dir_all(source_path.parent().expect("recovered source parent"))
        .expect("create recovered source directory");
    std::fs::write(&source_path, &source).expect("write recovered source");
    let output: std::process::Output = std::process::Command::new(javac)
        .arg("-XDrawDiagnostics")
        .arg("-d")
        .arg(scratch.path().join("classes"))
        .arg(&source_path)
        .output()
        .expect("run javac");
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}\n{source}");
    assert!(
        !stderr
            .lines()
            .any(|line: &str| line.contains(": compiler.")),
        "{stderr}\n{source}"
    );
    assert!(source.contains("this.flags = new boolean[4];"), "{source}");
}
