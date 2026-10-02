#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, decompile_dex_from_bytes};
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};
use sha2::{Digest, Sha256};

use crate::common;

const PROBE_CLASS: &str = "GeneratedShapes";
const DRIVER_CLASS: &str = "GeneratedShapesDriver";
const PROBE: &str = include_str!("../fixtures/dalvik_generated_shapes/GeneratedShapes.java");
const PROBE_SHA256: &str = "6a8a3abccc2690148cc4b586dc70e55b4b6e0aae8861b7ef8824e65bd9a4525b";
const SINK: &str = include_str!("../fixtures/dalvik_generated_shapes/Sink.java");
const SINK_SHA256: &str = "8d2cfc59185e2e24b4494af332345ae3eea24c11654ecb6e6a81261c29333387";
const RELEASE_DEX: &[u8] =
    include_bytes!("../fixtures/dalvik_generated_shapes/GeneratedShapes-release-min26.dex");
const RELEASE_DEX_SHA256: &str = "0a5c018d169c7c691deea7f30abafdee75f26c08cb0da2cc9010db360ab3b820";
const PROVENANCE: &str = include_str!("../fixtures/dalvik_generated_shapes/provenance.toml");
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

const DRIVER: &str = r#"public class GeneratedShapesDriver {
    public static void main(String[] args) {
        String[] names = {"loopWithElseIfChain", "doWhileAroundGuardedWhile", "tryFinallyAroundDoWhile", "tryInsideCountedLoop", "valueAssignedInsideTry", "splitHandlersBesideFinally", "liveAcrossCoveredFixupBlock", "tryAroundOnlyLiteralRemainders"};
        Runnable[] shapes = {GeneratedShapes::loopWithElseIfChain, GeneratedShapes::doWhileAroundGuardedWhile, GeneratedShapes::tryFinallyAroundDoWhile, GeneratedShapes::tryInsideCountedLoop, GeneratedShapes::valueAssignedInsideTry, GeneratedShapes::splitHandlersBesideFinally, GeneratedShapes::liveAcrossCoveredFixupBlock, GeneratedShapes::tryAroundOnlyLiteralRemainders};
        for (int index = 0; index < shapes.length; index++) {
            Sink.reset();
            shapes[index].run();
            System.out.println(names[index] + "=" + Sink.take().trim());
        }
    }
}
"#;

const EXPECTED: &str = "loopWithElseIfChain=0 0 0 12 6 2 4 68 [2, 0, 2, 0]
doWhileAroundGuardedWhile=9 45 9 45 0 -10 9 -2 5 0 [-4, 9, -2, -4, 9, -2]
tryFinallyAroundDoWhile=8 8 4 56 1 -2 8 [3, -30, -30]
tryInsideCountedLoop=0 0 0 22 23 0 -1 zero 22 23 0 -1 zero -5 6 7 0 0 7 -208 -6 [19, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 13, 16, 7]
valueAssignedInsideTry=3 0 0 0 0 0 0 0 0 0 0 960 -13 -45 -4 4 [0, 24, 24, 24, 24, 24]
splitHandlersBesideFinally=6 4 9 1 zero 4 8 2 2 4 2 [12]
liveAcrossCoveredFixupBlock=26 26 26 0 0 9 7 13 5 [26, 9, 0, 2, 12, 0, 5, 0, 2, 13, 0, 5, 0, 2, 14, 0, 5]
tryAroundOnlyLiteralRemainders=32 6 6 0 6 0 5 [0]";

fn compile_and_run(tag: &str, probe_source: &str) -> String {
    let scratch: ScratchDir =
        ScratchDir::create(&format!("jvm_dalvik_generated_shapes_{tag}")).expect("scratch dir");
    let dir: &Path = scratch.path();
    let mut javac: CommandSpec = CommandSpec::new(common::grader_jdk_tool("javac"), TOOL_TIMEOUT)
        .args(["-nowarn", "-proc:none", "-d"])
        .arg(dir.to_path_buf());
    for (name, source) in [
        (PROBE_CLASS, probe_source),
        ("Sink", SINK),
        (DRIVER_CLASS, DRIVER),
    ] {
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
        ran.success && !ran.timed_out,
        "{tag}: the driver fails or does not finish:\n{}\n{probe_source}",
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
fn the_authored_generated_shapes_print_the_pinned_output() {
    assert_eq!(compile_and_run("authored", PROBE), EXPECTED);
}

#[test]
fn d8_generated_shapes_recompile_and_run_as_authored() {
    assert_eq!(sha256_hex(PROBE.as_bytes()), PROBE_SHA256);
    assert_eq!(sha256_hex(SINK.as_bytes()), SINK_SHA256);
    assert_eq!(sha256_hex(RELEASE_DEX), RELEASE_DEX_SHA256);
    assert!(
        [PROBE_SHA256, SINK_SHA256, RELEASE_DEX_SHA256]
            .iter()
            .all(|digest: &&str| PROVENANCE.contains(digest))
    );
    let decompiled: DecompiledDex =
        decompile_dex_from_bytes(RELEASE_DEX).expect("decompile the generated shapes DEX");
    let unit: String = format!("{PROBE_CLASS}.java");
    let source: String = decompiled.sources.get(&unit).cloned().unwrap_or_else(|| {
        panic!(
            "recovered unit {unit} in {:?}",
            decompiled.sources.keys().collect::<Vec<&String>>()
        )
    });
    assert!(
        !source.contains("<decompile:"),
        "no shape is refused; recovered source:\n{source}"
    );
    assert_eq!(
        decompiled.fully_lifted_methods, decompiled.method_count,
        "every shape is fully lifted; recovered source:\n{source}"
    );
    assert_eq!(compile_and_run("dalvik", &source), EXPECTED, "{source}");
}
