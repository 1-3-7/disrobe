#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, decompile_dex_from_bytes};
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};
use sha2::{Digest, Sha256};

use crate::common;

const PROBE_CLASS: &str = "Divisions";
const DRIVER_CLASS: &str = "DivisionsDriver";
const PROBE: &str = include_str!("../fixtures/dalvik_division_effects/Divisions.java");
const PROBE_SHA256: &str = "0568d9eff744805de50854ca09b35c722f791155053b138b267d2fd7b419b020";
const RELEASE_DEX: &[u8] =
    include_bytes!("../fixtures/dalvik_division_effects/Divisions-release-min21.dex");
const RELEASE_DEX_SHA256: &str = "6c4343c262151e1129c239aaa189f4e877540e6cd497e9bb40dd16c3d853f6be";
const PROVENANCE: &str = include_str!("../fixtures/dalvik_division_effects/provenance.toml");
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

const DRIVER: &str = r#"public class DivisionsDriver {
    public static void main(String[] args) {
        System.out.println("orderedBeforeAppend=" + Divisions.orderedBeforeAppend(8, 2, 5));
        System.out.println("orderedBeforeAppend=" + Divisions.orderedBeforeAppend(8, 0, 5));
        System.out.println("unusedQuotientInTry=" + Divisions.unusedQuotientInTry(7, 5));
        System.out.println("unusedQuotientInTry=" + Divisions.unusedQuotientInTry(7, 6));
        System.out.println("unusedRemainderInTry=" + Divisions.unusedRemainderInTry(7, 3));
        System.out.println("unusedRemainderInTry=" + Divisions.unusedRemainderInTry(7, 4));
        System.out.println("unusedLongQuotientInTry=" + Divisions.unusedLongQuotientInTry(7L, 2L));
        System.out.println("unusedLongQuotientInTry=" + Divisions.unusedLongQuotientInTry(7L, 3L));
        System.out.println("nestedUnusedQuotient=" + Divisions.nestedUnusedQuotient(8, 2, 5));
        System.out.println("nestedUnusedQuotient=" + Divisions.nestedUnusedQuotient(8, 0, 5));
        System.out.println("nestedUnusedQuotient=" + Divisions.nestedUnusedQuotient(8, 2, 4));
    }
}
"#;

const EXPECTED: &str = "orderedBeforeAppend=[-4]:4
orderedBeforeAppend=[99]:8
unusedQuotientInTry=zero
unusedQuotientInTry=ok
unusedRemainderInTry=zero
unusedRemainderInTry=ok
unusedLongQuotientInTry=zero
unusedLongQuotientInTry=ok
nestedUnusedQuotient=[-4, -1, 4]
nestedUnusedQuotient=[-2]
nestedUnusedQuotient=[-3, 4]";

fn compile_and_run(tag: &str, probe_source: &str) -> String {
    let scratch: ScratchDir =
        ScratchDir::create(&format!("jvm_dalvik_division_{tag}")).expect("scratch dir");
    let dir: &Path = scratch.path();
    let mut javac: CommandSpec = CommandSpec::new(common::grader_jdk_tool("javac"), TOOL_TIMEOUT)
        .args(["-nowarn", "-proc:none", "-d"])
        .arg(dir.to_path_buf());
    for (name, source) in [(PROBE_CLASS, probe_source), (DRIVER_CLASS, DRIVER)] {
        let path: PathBuf = dir.join(format!("{name}.java"));
        std::fs::write(&path, source).expect("write source");
        javac = javac.arg(path);
    }
    let compiled: ToolOutput =
        tool_output(javac).unwrap_or_else(|error: ToolError| panic!("javac: {error}"));
    assert!(
        compiled.success,
        "{tag}: javac rejects the probe:\n{}{}\n{probe_source}",
        compiled.stdout_text(),
        compiled.stderr_text()
    );
    let ran: ToolOutput = tool_output(
        CommandSpec::new(common::grader_jdk_tool("java"), TOOL_TIMEOUT)
            .arg("-cp")
            .arg(dir.to_path_buf())
            .arg(DRIVER_CLASS),
    )
    .unwrap_or_else(|error: ToolError| panic!("java: {error}"));
    assert!(
        ran.success,
        "{tag}: the driver fails:\n{}\n{probe_source}",
        ran.stderr_text()
    );
    ran.stdout_text()
        .replace("\r\n", "\n")
        .trim_end()
        .to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn the_authored_division_probe_prints_the_pinned_output() {
    assert_eq!(compile_and_run("authored", PROBE), EXPECTED);
}

#[test]
fn dalvik_divisions_keep_their_order_and_their_exceptions() {
    assert_eq!(sha256_hex(PROBE.as_bytes()), PROBE_SHA256);
    assert_eq!(sha256_hex(RELEASE_DEX), RELEASE_DEX_SHA256);
    assert!(PROVENANCE.contains(PROBE_SHA256) && PROVENANCE.contains(RELEASE_DEX_SHA256));
    let decompiled: DecompiledDex =
        decompile_dex_from_bytes(RELEASE_DEX).expect("decompile the division probe DEX");
    let unit: String = format!("{PROBE_CLASS}.java");
    let source: String = decompiled.sources.get(&unit).cloned().unwrap_or_else(|| {
        panic!(
            "recovered unit {unit} in {:?}",
            decompiled.sources.keys().collect::<Vec<&String>>()
        )
    });
    assert_eq!(
        decompiled.fully_lifted_methods, decompiled.method_count,
        "every probe method is fully lifted; recovered source:\n{source}"
    );
    assert_eq!(compile_and_run("dalvik", &source), EXPECTED, "{source}");
}
