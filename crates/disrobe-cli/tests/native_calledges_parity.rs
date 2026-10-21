#![cfg(feature = "native")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn native_dir() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit/native");
    path
}

fn objdump_edges(text: &str) -> BTreeSet<(String, String)> {
    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
    let mut caller: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_suffix(">:")
            && let Some((address, name)) = rest.split_once(" <")
            && u64::from_str_radix(address.trim(), 16).is_ok()
        {
            caller = Some(name.to_owned());
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(_address) = parts.next() else {
            continue;
        };
        let Some(mnemonic) = parts.next() else {
            continue;
        };
        if !matches!(mnemonic, "bl" | "call" | "callq") {
            continue;
        }
        let Some(target) = line
            .split('<')
            .nth(1)
            .and_then(|t: &str| t.split('>').next())
        else {
            continue;
        };
        let Some(current) = caller.as_ref() else {
            panic!("call before the first function header: {line}");
        };
        let callee: &str = target.strip_suffix("@plt").unwrap_or(target);
        edges.insert((current.clone(), callee.to_owned()));
    }
    edges
}

fn disrobe_edges(library: &PathBuf) -> BTreeSet<(String, String)> {
    let scratch = temp_dir("calledges");
    let out: PathBuf = scratch.path().join("callgraph.json");
    let run = run_disrobe(&[
        "native",
        "callgraph",
        library.to_str().expect("utf-8 path"),
        "--emit",
        "json",
        "-o",
        out.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(run.code, 0, "native callgraph failed: {}", run.stderr);
    let text: String = std::fs::read_to_string(&out).expect("call graph json");
    let graph: serde_json::Value = serde_json::from_str(&text).expect("call graph parses");
    graph["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .map(|edge: &serde_json::Value| {
            (
                edge["caller"].as_str().expect("caller").to_owned(),
                edge["callee"].as_str().expect("callee").to_owned(),
            )
        })
        .collect()
}

fn assert_edges_match(abi: &str, name: &str, minimum: usize) {
    let library: PathBuf = native_dir().join(format!("lib/{abi}/lib{name}.so"));
    let reference_path: PathBuf =
        native_dir().join(format!("reference/{abi}/lib{name}.objdump.txt"));
    let reference_text: String =
        std::fs::read_to_string(&reference_path).expect("llvm-objdump reference");
    let reference: BTreeSet<(String, String)> = objdump_edges(&reference_text);
    assert!(
        reference.len() >= minimum,
        "{abi}/{name}: the reference carries at least {minimum} call edges, got {}",
        reference.len()
    );
    let recovered: BTreeSet<(String, String)> = disrobe_edges(&library);
    assert_eq!(
        recovered, reference,
        "{abi}/{name}: every call edge equals llvm-objdump's bl/call sites with PLT callees named"
    );
}

#[test]
fn arm64_anti_debug_library_call_edges_equal_objdump() {
    assert_edges_match("arm64-v8a", "antidebug", 20);
}

#[test]
fn x86_64_anti_debug_library_call_edges_equal_objdump() {
    assert_edges_match("x86_64", "antidebug", 20);
}

#[test]
fn control_library_call_edges_equal_objdump_on_both_abis() {
    assert_edges_match("arm64-v8a", "clean", 1);
    assert_edges_match("x86_64", "clean", 1);
}

#[test]
fn one_dropped_reference_edge_turns_the_comparison_red() {
    let reference_path: PathBuf = native_dir().join("reference/arm64-v8a/libantidebug.objdump.txt");
    let text: String = std::fs::read_to_string(&reference_path).expect("reference");
    let full: BTreeSet<(String, String)> = objdump_edges(&text);
    let mutated: String = text.replacen("<ptrace@plt>", "<ptrace_removed@plt>", 1);
    assert_ne!(text, mutated);
    assert_ne!(objdump_edges(&mutated), full);
}
