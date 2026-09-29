#![allow(clippy::expect_used, clippy::panic)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output};
use std::time::{Duration, Instant};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, decompile_dex_from_bytes};
use sha2::{Digest, Sha256};

pub mod common;

const AUTHORED: &str = include_str!("fixtures/dalvik_lift_probes/LiftProbes.java");
const RELEASE_DEX: &[u8] =
    include_bytes!("fixtures/dalvik_lift_probes/LiftProbes-release-min21.dex");
const DEBUG_DEX: &[u8] = include_bytes!("fixtures/dalvik_lift_probes/LiftProbes-debug-min21.dex");
const PROVENANCE: &str = include_str!("fixtures/dalvik_lift_probes/provenance.toml");
const AUTHORED_SHA256: &str = "c66c8dc7b82571a30baa90f82f58304ff51e0a445ca2661c3cd4ecd35d2809bc";
const RELEASE_SHA256: &str = "2ea3ef6930b6a02acd7565a34a9680523f9a492f7e2fb2c29cdc5cb5a267aff4";
const DEBUG_SHA256: &str = "255a598c648e15013cbdb3171780ddfd6d4d5c8e29c46a3aea7df376cd53942a";
const UNIT: &str = "LiftProbes.java";
const CLASS: &str = "LiftProbes";
const RUN_TIMEOUT: Duration = Duration::from_mins(1);
const RUN_POLL: Duration = Duration::from_millis(20);

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered_unit() -> String {
    recovered_unit_from(RELEASE_DEX, RELEASE_SHA256)
}

fn recovered_unit_from(dex: &[u8], sha256: &str) -> String {
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert_eq!(sha256_hex(dex), sha256);
    assert!(PROVENANCE.contains(AUTHORED_SHA256) && PROVENANCE.contains(sha256));
    let decompiled: DecompiledDex = decompile_dex_from_bytes(dex).expect("decompile LiftProbes");
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

fn tool(name: &str) -> PathBuf {
    common::find_on_path(name)
        .unwrap_or_else(|| panic!("{name} is required to recompile the recovered LiftProbes"))
}

fn execute(scratch: &Path, tag: &str, source: &str) -> String {
    let root: PathBuf = scratch.join(tag);
    let classes: PathBuf = root.join("classes");
    std::fs::create_dir_all(&classes).expect("create source directory");
    let path: PathBuf = root.join(UNIT);
    std::fs::write(&path, source).expect("write source");
    let compiled: Output = Command::new(tool("javac"))
        .arg("-Xlint:-options")
        .arg("-nowarn")
        .arg("--release")
        .arg("8")
        .arg("-d")
        .arg(&classes)
        .arg(&path)
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "{tag} does not recompile:\n{}{}\n{source}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let stdout_path: PathBuf = root.join("stdout.txt");
    let stderr_path: PathBuf = root.join("stderr.txt");
    let mut child: Child = Command::new(tool("java"))
        .arg("-cp")
        .arg(&classes)
        .arg(CLASS)
        .env_remove("FORCE_COLOR")
        .stdout(File::create(&stdout_path).expect("create stdout capture"))
        .stderr(File::create(&stderr_path).expect("create stderr capture"))
        .spawn()
        .expect("run java");
    let started: Instant = Instant::now();
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait().expect("poll java") {
            break status;
        }
        if started.elapsed() > RUN_TIMEOUT {
            child.kill().expect("stop the runaway program");
            child.wait().expect("reap the runaway program");
            panic!("{tag} did not finish within {RUN_TIMEOUT:?}:\n{source}");
        }
        std::thread::sleep(RUN_POLL);
    };
    assert!(
        status.success(),
        "{tag} fails at run time:\n{}\n{source}",
        std::fs::read_to_string(&stderr_path).unwrap_or_default()
    );
    std::fs::read_to_string(&stdout_path).expect("utf8 stdout")
}

fn probe(method: &str, calls: &[&str]) -> String {
    let mut source: String =
        String::from("import java.util.Arrays;\n\npublic class LiftProbes {\n");
    source.push_str("    static int counter;\n    static String trace = \"\";\n");
    source.push_str("    static final Object LOCK = new Object();\n");
    source.push_str(&method_text(AUTHORED, "tick"));
    source.push_str(&method_text(AUTHORED, "combine"));
    source.push_str(method);
    source.push_str("    public static void main(String[] args) {\n");
    for call in calls {
        source.push_str("        System.out.println(");
        source.push_str(call);
        source.push_str(");\n");
    }
    source.push_str("    }\n}\n");
    source
}

fn assert_method_matches(name: &str, calls: &[&str]) -> String {
    assert_method_matches_in(RELEASE_DEX, RELEASE_SHA256, name, calls)
}

fn assert_method_matches_in(dex: &[u8], sha256: &str, name: &str, calls: &[&str]) -> String {
    let scratch: ScratchDir = ScratchDir::create("dalvik_lift_probes_method").expect("scratch");
    let reference: String = execute(
        scratch.path(),
        "authored",
        &probe(&method_text(AUTHORED, name), calls),
    );
    assert_eq!(reference.lines().count(), calls.len(), "{reference}");
    let recovered: String = method_text(&recovered_unit_from(dex, sha256), name);
    let printed: String = execute(scratch.path(), "recovered", &probe(&recovered, calls));
    assert_eq!(
        printed, reference,
        "the recovered {name} must print what the authored {name} prints:\n{recovered}"
    );
    recovered
}

#[test]
fn the_recovered_class_recompiles_and_prints_the_authored_output() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_lift_probes_unit").expect("scratch");
    let reference: String = execute(scratch.path(), "authored", AUTHORED);
    assert_eq!(reference.lines().count(), 41, "{reference}");
    let recovered: String = recovered_unit();
    let printed: String = execute(scratch.path(), "recovered", &recovered);
    assert_eq!(
        printed, reference,
        "the recovered class must print what the authored class prints:\n{recovered}"
    );
}

#[test]
fn the_debug_build_with_local_names_recompiles_and_prints_the_authored_output() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_lift_probes_debug").expect("scratch");
    let reference: String = execute(scratch.path(), "authored", AUTHORED);
    let recovered: String = recovered_unit_from(DEBUG_DEX, DEBUG_SHA256);
    let printed: String = execute(scratch.path(), "recovered", &recovered);
    assert_eq!(
        printed, reference,
        "the recovered debug class must print what the authored class prints:
{recovered}"
    );
    let temporaries: String = method_text(&recovered, "temporaries");
    assert!(temporaries.contains("(int count)"), "{temporaries}");
    assert!(!temporaries.contains("arg0"), "{temporaries}");
}

#[test]
fn a_seeded_change_in_the_recovered_class_changes_the_output() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_lift_probes_control").expect("scratch");
    let reference: String = execute(scratch.path(), "authored", AUTHORED);
    let recovered: String = recovered_unit();
    assert_eq!(recovered.matches("-2.25f").count(), 1, "{recovered}");
    let mutated: String = recovered.replace("-2.25f", "-2.5f");
    let printed: String = execute(scratch.path(), "mutated", &mutated);
    assert_ne!(
        printed, reference,
        "grader control: a changed array element in the recovered class must change the output"
    );
}

#[test]
fn filled_and_payload_arrays_keep_every_element() {
    let recovered: String = assert_method_matches(
        "arrays",
        &["arrays(-1)", "arrays(0)", "arrays(1)", "arrays(2)"],
    );
    assert!(
        recovered.contains("new int[]{3, 1, 4, 1, 5, 9, 2, 6, -5, 65536}"),
        "{recovered}"
    );
}

#[test]
fn while_header_statements_run_on_every_iteration() {
    assert_method_matches(
        "halvings",
        &[
            "halvings(0)",
            "halvings(4)",
            "halvings(13)",
            "halvings(39)",
            "halvings(1000)",
        ],
    );
    assert_method_matches("reads", &["reads(1000)", "reads(1000)", "reads(1000)"]);
    let polls: String = assert_method_matches("polls", &["polls()", "polls()"]);
    assert!(
        polls.contains("while ((LiftProbes.tick(\"w\") % 5) != 0) {"),
        "a header whose only statement folds into the test keeps the plain loop:\n{polls}"
    );
}

#[test]
fn string_constants_are_java_literals() {
    let recovered: String = assert_method_matches("strings", &["strings()"]);
    assert!(!recovered.contains("\\u{"), "{recovered}");
}

#[test]
fn calls_keep_their_source_order() {
    let recovered: String = assert_method_matches("order", &["order()", "order()"]);
    let first: usize = recovered.find("tick(\"a\")").expect("tick a");
    let second: usize = recovered.find("tick(\"b\")").expect("tick b");
    let third: usize = recovered.find("tick(\"c\")").expect("tick c");
    assert!(first < second && second < third, "{recovered}");
}

#[test]
fn registers_reused_across_types_recompile_and_run_as_authored() {
    assert_method_matches(
        "temporaries",
        &["temporaries(0)", "temporaries(2)", "temporaries(5)"],
    );
}

#[test]
fn an_else_if_chain_meets_at_its_shared_join_in_both_builds() {
    let calls: [&str; 4] = [
        "chain(\"a\", 1)",
        "chain(\"bb\", 2)",
        "chain(\"k\", 3)",
        "chain(\"\", 4)",
    ];
    assert_method_matches_in(RELEASE_DEX, RELEASE_SHA256, "chain", &calls);
    let debug: String = assert_method_matches_in(DEBUG_DEX, DEBUG_SHA256, "chain", &calls);
    assert!(debug.contains("(String key, int mode)"), "{debug}");
    assert!(!debug.contains("arg0"), "{debug}");
}

#[test]
fn a_try_inside_a_catch_handler_keeps_both_exceptions_apart() {
    let calls: [&str; 4] = [
        "fallback(\"4\", \"x\")",
        "fallback(\"y\", \"5\")",
        "fallback(\"zz\", \"wwww\")",
        "fallback(\"\", \"-\")",
    ];
    assert_method_matches_in(RELEASE_DEX, RELEASE_SHA256, "fallback", &calls);
    let debug: String = assert_method_matches_in(DEBUG_DEX, DEBUG_SHA256, "fallback", &calls);
    assert!(debug.contains("(String first, String second)"), "{debug}");
    assert!(debug.contains("Integer.parseInt(second)"), "{debug}");
}

#[test]
fn nested_classes_declare_their_supertypes_without_the_clashing_bridge() {
    let recovered: String = recovered_unit();
    assert!(
        recovered.contains(
            "public static abstract class Worker implements java.util.concurrent.Callable, Runnable {"
        ),
        "{recovered}"
    );
    assert!(
        recovered.contains("public static class Counting extends LiftProbes.Worker {"),
        "{recovered}"
    );
    assert!(!recovered.contains("public Object call()"), "{recovered}");
    assert_eq!(recovered.matches(" call() {").count(), 1, "{recovered}");
}

fn assert_in_both_builds(name: &str, calls: &[&str]) -> (String, String) {
    let release: String = assert_method_matches_in(RELEASE_DEX, RELEASE_SHA256, name, calls);
    let debug: String = assert_method_matches_in(DEBUG_DEX, DEBUG_SHA256, name, calls);
    (release, debug)
}

#[test]
fn a_finally_split_across_branches_keeps_every_catch_path_in_both_builds() {
    let (release, debug): (String, String) = assert_in_both_builds(
        "settle",
        &["settle(0)", "settle(1)", "settle(2)", "settle(1)", "trace"],
    );
    for recovered in [&release, &debug] {
        assert!(
            recovered.contains("catch (NumberFormatException "),
            "{recovered}"
        );
        assert!(!recovered.contains("Throwable var"), "{recovered}");
    }
}

#[test]
fn a_try_inside_a_catch_keeps_the_continuation_after_its_handler() {
    let (release, debug): (String, String) = assert_in_both_builds(
        "rescue",
        &[
            "rescue(\"4\", \"x\")",
            "rescue(\"y\", \"5\")",
            "rescue(\"zz\", \"w\")",
        ],
    );
    for recovered in [&release, &debug] {
        let doubled: usize = recovered.find("* 2)").expect("the doubled parse");
        let fallback: usize = recovered.find("= -1;").expect("the nested handler");
        assert!(
            doubled < fallback,
            "the doubling stays in the inner try body:\n{recovered}"
        );
    }
}

#[test]
fn string_switches_recompile_as_string_switches_in_both_builds() {
    let (release, debug): (String, String) = assert_in_both_builds(
        "keyed",
        &[
            "keyed(\"alpha\")",
            "keyed(\"beta\")",
            "keyed(\"Aa\")",
            "keyed(\"BB\")",
            "keyed(\"one\")",
            "keyed(\"\")",
        ],
    );
    for recovered in [&release, &debug] {
        assert!(recovered.contains("case \"Aa\":"), "{recovered}");
        assert!(!recovered.contains("equals("), "{recovered}");
        assert!(!recovered.contains("flattening"), "{recovered}");
    }
    let (release, debug): (String, String) = assert_in_both_builds(
        "spelled",
        &[
            "spelled(\"two\")",
            "spelled(\"three\")",
            "spelled(\"one\")",
            "spelled(\"\")",
            "spelled(\"four\")",
        ],
    );
    for recovered in [&release, &debug] {
        assert!(recovered.contains("case \"two\":"), "{recovered}");
    }
}

#[test]
fn synchronized_blocks_hold_their_monitor_in_both_builds() {
    let (release, debug): (String, String) =
        assert_in_both_builds("guarded", &["guarded(0)", "guarded(5)"]);
    for recovered in [&release, &debug] {
        assert!(
            recovered.contains("synchronized (LiftProbes.LOCK) {"),
            "{recovered}"
        );
        assert!(!recovered.contains("try {"), "{recovered}");
    }
    let (release, debug): (String, String) = assert_in_both_builds(
        "guardedReturn",
        &[
            "guardedReturn(new int[] {4, 5}, 1)",
            "guardedReturn(new int[] {4, 5}, -1)",
        ],
    );
    for recovered in [&release, &debug] {
        assert!(recovered.contains("synchronized ("), "{recovered}");
    }
    let (release, debug): (String, String) =
        assert_in_both_builds("looped", &["looped(3)", "looped(10)", "trace"]);
    for recovered in [&release, &debug] {
        assert!(recovered.contains("synchronized ("), "{recovered}");
    }
}

#[test]
fn a_loop_break_after_a_call_leaves_the_loop_in_both_builds() {
    let (release, debug): (String, String) =
        assert_in_both_builds("drained", &["drained(3)", "drained(10)", "trace"]);
    assert!(debug.contains("break;"), "{debug}\n{release}");
}
