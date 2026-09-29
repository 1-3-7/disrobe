#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{
    DecompiledClass, DecompiledDex, decompile_classfile_bytes, decompile_dex_from_bytes,
};
use sha2::{Digest, Sha256};

use crate::common;

const PROBE_CLASS: &str = "CompoundLoops";
const DRIVER_CLASS: &str = "CompoundLoopsDriver";
const REFUSED: &str = "refused";

const PROBE: &str = include_str!("../fixtures/compound_loop_condition/CompoundLoops.java");
const PROBE_SHA256: &str = "9724d31478cad8f9308380e45e5a15c4fbe330ebc6eff790b5696e709c5cadf6";
const RELEASE_DEX: &[u8] =
    include_bytes!("../fixtures/compound_loop_condition/CompoundLoops-release-min21.dex");
const RELEASE_DEX_SHA256: &str = "cfe7c8207627b0bcedcc8c0649c58b59f85a10911e433208c13866f434f335ea";
const PROVENANCE: &str = include_str!("../fixtures/compound_loop_condition/provenance.toml");
const PROBE_METHODS: [&str; 9] = [
    "andChainWithAssignment",
    "orChain",
    "mixedChain",
    "forWithCall",
    "doWhileCompound",
    "fieldCondition",
    "headerAssignsBeforeTest",
    "assignInCondition",
    "postIncrementIndex",
];

const DRIVER: &str = r#"import java.util.function.IntSupplier;

public class CompoundLoopsDriver {
    static void show(String label, IntSupplier call) {
        String value;
        try {
            value = Integer.toString(call.getAsInt());
        } catch (UnsupportedOperationException refused) {
            value = "refused";
        }
        System.out.println(label + "=" + value);
    }

    static CompoundLoops tagged(String tag) {
        CompoundLoops probe = new CompoundLoops();
        probe.tag = tag;
        return probe;
    }

    public static void main(String[] args) {
        show("andChainWithAssignment", () -> CompoundLoops.andChainWithAssignment(true, 3, true));
        show("andChainWithAssignment", () -> CompoundLoops.andChainWithAssignment(true, 5, false));
        show("andChainWithAssignment", () -> CompoundLoops.andChainWithAssignment(false, 3, true));
        show("andChainWithAssignment", () -> CompoundLoops.andChainWithAssignment(true, 25, true));
        show("orChain", () -> CompoundLoops.orChain(0, "ab"));
        show("orChain", () -> CompoundLoops.orChain(5, "a"));
        show("orChain", () -> CompoundLoops.orChain(5, "abcdef"));
        show("mixedChain", () -> CompoundLoops.mixedChain(0, 5, false));
        show("mixedChain", () -> CompoundLoops.mixedChain(0, 3, true));
        show("mixedChain", () -> CompoundLoops.mixedChain(20, 3, true));
        show("forWithCall", () -> CompoundLoops.forWithCall(3));
        show("forWithCall", () -> CompoundLoops.forWithCall(20));
        show("forWithCall", () -> CompoundLoops.forWithCall(0));
        show("doWhileCompound", () -> CompoundLoops.doWhileCompound(0, 5));
        show("doWhileCompound", () -> CompoundLoops.doWhileCompound(1, 9));
        show("doWhileCompound", () -> CompoundLoops.doWhileCompound(10, 2));
        show("fieldCondition", () -> tagged("t").fieldCondition(null));
        show("fieldCondition", () -> tagged("t").fieldCondition("u"));
        show("fieldCondition", () -> tagged(null).fieldCondition("u"));
        show("headerAssignsBeforeTest", () -> CompoundLoops.headerAssignsBeforeTest(new int[] {4, 5, 6, 0}, 100));
        show("headerAssignsBeforeTest", () -> CompoundLoops.headerAssignsBeforeTest(new int[] {4, 5, 6, 0}, 12));
        show("headerAssignsBeforeTest", () -> CompoundLoops.headerAssignsBeforeTest(new int[] {0, 5}, 100));
        show("assignInCondition", () -> CompoundLoops.assignInCondition(3, 4));
        show("assignInCondition", () -> CompoundLoops.assignInCondition(15, 10));
        show("postIncrementIndex", () -> CompoundLoops.postIncrementIndex(new int[] {7, 8, 9}, 1));
        show("postIncrementIndex", () -> CompoundLoops.postIncrementIndex(new int[] {7, 8, 9}, 0));
    }
}
"#;

const EXPECTED: &str = "andChainWithAssignment=162921
andChainWithAssignment=5
andChainWithAssignment=0
andChainWithAssignment=25
orChain=3035
orChain=4095
orChain=56
mixedChain=606
mixedChain=3012
mixedChain=20
forWithCall=903
forWithCall=6307
forWithCall=0
doWhileCompound=301
doWhileCompound=4504
doWhileCompound=1311
fieldCondition=306
fieldCondition=408
fieldCondition=0
headerAssignsBeforeTest=1504
headerAssignsBeforeTest=903
headerAssignsBeforeTest=1
assignInCondition=14
assignInCondition=25
postIncrementIndex=82
postIncrementIndex=71";

fn tool(name: &str) -> PathBuf {
    common::find_on_path(name)
        .unwrap_or_else(|| panic!("{name} is required to compile and run the compound loop probe"))
}

fn compile(dir: &Path, sources: &[(&str, &str)]) {
    let mut command: Command = Command::new(tool("javac"));
    command
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(dir)
        .env_remove("FORCE_COLOR");
    for (name, source) in sources {
        let path: PathBuf = dir.join(format!("{name}.java"));
        std::fs::write(&path, source).expect("write source");
        command.arg(&path);
    }
    let compiled: Output = command.output().expect("run javac");
    assert!(
        compiled.status.success(),
        "javac failed:\n{}{}\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr),
        sources
            .iter()
            .map(|(name, source)| format!("--- {name}.java\n{source}"))
            .collect::<Vec<String>>()
            .join("\n")
    );
}

fn run(dir: &Path) -> String {
    let ran: Output = Command::new(tool("java"))
        .arg("-cp")
        .arg(dir)
        .arg(DRIVER_CLASS)
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run java");
    assert!(
        ran.status.success(),
        "{DRIVER_CLASS} fails at run time:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    String::from_utf8(ran.stdout)
        .expect("utf8 stdout")
        .replace("\r\n", "\n")
        .trim_end()
        .to_owned()
}

fn run_with_probe(tag: &str, probe_source: &str) -> String {
    let scratch: ScratchDir =
        ScratchDir::create(&format!("jvm_compound_loop_{tag}")).expect("scratch dir");
    compile(
        scratch.path(),
        &[(PROBE_CLASS, probe_source), (DRIVER_CLASS, DRIVER)],
    );
    run(scratch.path())
}

fn decompiled_probe() -> DecompiledClass {
    let scratch: ScratchDir =
        ScratchDir::create("jvm_compound_loop_classfile").expect("scratch dir");
    compile(scratch.path(), &[(PROBE_CLASS, PROBE)]);
    let bytes: Vec<u8> = std::fs::read(scratch.path().join(format!("{PROBE_CLASS}.class")))
        .expect("read the compiled probe class");
    decompile_classfile_bytes(&bytes).expect("decompile the probe class")
}

fn method_body<'a>(source: &'a str, name: &str) -> &'a str {
    let signature: String = format!(" {name}(");
    let header: &str = source
        .lines()
        .find(|line: &&str| {
            line.starts_with("    ")
                && !line.starts_with("     ")
                && line.contains(&signature)
                && line.ends_with('{')
        })
        .unwrap_or_else(|| panic!("no method {name} in the recovered source:\n{source}"));
    let start: usize = source
        .find(header)
        .expect("the header line is part of the source");
    let rest: &str = &source[start..];
    let end: usize = rest.find("\n    }").map_or(rest.len(), |end: usize| end);
    &rest[..end]
}

fn named_refusal(body: &str) -> Option<&str> {
    [
        "// <decompile: not recovered: ",
        "// <decompile: incomplete: ",
    ]
    .iter()
    .find_map(|marker: &&str| {
        let start: usize = body.find(marker)? + marker.len();
        let reason: &str = &body[start..];
        reason.find('>').map(|end: usize| reason[..end].trim())
    })
    .filter(|reason: &&str| !reason.is_empty())
}

fn has_empty_infinite_loop(body: &str) -> bool {
    let lines: Vec<&str> = body.lines().map(str::trim).collect();
    lines.windows(2).any(|pair: &[&str]| {
        matches!(
            pair,
            ["while (true) {" | "for (;;) {", "}"] | ["do {", "} while (true);"]
        )
    })
}

#[test]
fn the_authored_probe_prints_the_pinned_output() {
    assert_eq!(run_with_probe("authored", PROBE), EXPECTED);
}

fn assert_behaviour_or_named_refusal(route: &str, source: &str, fully_lifted: usize, total: usize) {
    let printed: String = run_with_probe(route, source);
    let expected_lines: Vec<&str> = EXPECTED.lines().collect();
    let printed_lines: Vec<&str> = printed.lines().collect();
    assert_eq!(
        printed_lines.len(),
        expected_lines.len(),
        "{route}: the recovered probe prints one line per call:\n{printed}\nrecovered source:\n{source}"
    );
    let mut refused_methods: Vec<&str> = Vec::new();
    for (expected, printed) in expected_lines.iter().zip(&printed_lines) {
        if expected == printed {
            continue;
        }
        let (label, _): (&str, &str) = expected.split_once('=').expect("label=value line");
        assert!(
            named_refusal(method_body(source, label)).is_some(),
            "{route}: {label} prints {printed} instead of {expected} without a named refusal; \
             recovered source:\n{source}"
        );
        if !refused_methods.contains(&label) {
            refused_methods.push(label);
        }
    }
    for line in &printed_lines {
        let (label, value): (&str, &str) = line.split_once('=').expect("label=value line");
        if value == REFUSED {
            assert!(
                named_refusal(method_body(source, label)).is_some(),
                "{route}: {label} throws without naming its reason; recovered source:\n{source}"
            );
        }
    }
    assert!(
        fully_lifted + refused_methods.len() <= total,
        "{route}: a method counted as fully lifted still printed a wrong value; \
         recovered source:\n{source}"
    );
    for method in PROBE_METHODS {
        let body: &str = method_body(source, method);
        if named_refusal(body).is_none() {
            assert!(
                !has_empty_infinite_loop(body),
                "{route}: {method} keeps an empty infinite loop; recovered source:\n{source}"
            );
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decompiled_release_dex() -> (String, DecompiledDex) {
    assert_eq!(sha256_hex(PROBE.as_bytes()), PROBE_SHA256);
    assert_eq!(sha256_hex(RELEASE_DEX), RELEASE_DEX_SHA256);
    assert!(PROVENANCE.contains(PROBE_SHA256) && PROVENANCE.contains(RELEASE_DEX_SHA256));
    let decompiled: DecompiledDex =
        decompile_dex_from_bytes(RELEASE_DEX).expect("decompile the probe DEX");
    let unit: String = format!("{PROBE_CLASS}.java");
    let source: String = decompiled.sources.get(&unit).cloned().unwrap_or_else(|| {
        panic!(
            "recovered unit {unit} in {:?}",
            decompiled.sources.keys().collect::<Vec<&String>>()
        )
    });
    (source, decompiled)
}

#[test]
fn compound_loop_conditions_recompile_to_the_authored_behaviour_or_a_named_refusal() {
    let decompiled: DecompiledClass = decompiled_probe();
    assert_behaviour_or_named_refusal(
        "classfile",
        &decompiled.source,
        decompiled.fully_lifted_methods,
        decompiled.method_count,
    );
}

#[test]
fn dalvik_compound_loop_conditions_recompile_to_the_authored_behaviour_or_a_named_refusal() {
    let (source, decompiled): (String, DecompiledDex) = decompiled_release_dex();
    assert_behaviour_or_named_refusal(
        "dalvik",
        &source,
        decompiled.fully_lifted_methods,
        decompiled.method_count,
    );
}

#[test]
fn every_compound_loop_shape_is_recovered_without_refusal() {
    let decompiled: DecompiledClass = decompiled_probe();
    let source: &str = &decompiled.source;
    assert_eq!(
        decompiled.fully_lifted_methods, decompiled.method_count,
        "every probe method is fully lifted; recovered source:\n{source}"
    );
    assert_eq!(
        run_with_probe("recovered_exact", source),
        EXPECTED,
        "recovered source:\n{source}"
    );
}

#[test]
fn every_dalvik_compound_loop_shape_is_recovered_without_refusal() {
    let (source, decompiled): (String, DecompiledDex) = decompiled_release_dex();
    assert_eq!(
        decompiled.fully_lifted_methods, decompiled.method_count,
        "every probe method is fully lifted; recovered source:\n{source}"
    );
    assert_eq!(
        run_with_probe("dalvik_exact", &source),
        EXPECTED,
        "recovered source:\n{source}"
    );
}

#[test]
fn a_seeded_change_in_the_recovered_condition_changes_the_output() {
    let decompiled: DecompiledClass = decompiled_probe();
    let source: &str = &decompiled.source;
    let body: &str = method_body(source, "andChainWithAssignment");
    assert_eq!(
        body.matches("20").count(),
        1,
        "the recovered andChainWithAssignment tests its bound once:\n{source}"
    );
    let mutated_body: String = body.replace("20", "13");
    let mutated: String = source.replace(body, &mutated_body);
    assert_ne!(
        run_with_probe("mutated", &mutated),
        EXPECTED,
        "grader control: a changed loop bound in the recovered class must change the output"
    );
}
