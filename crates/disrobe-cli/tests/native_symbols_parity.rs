#![cfg(feature = "native")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn fixture(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("disrobe-pass-jvm/tests/fixtures/jni_register");
    path.push(name);
    path
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NmRow {
    name: String,
    address: u64,
    size: u64,
    kind: &'static str,
}

fn nm_reference(name: &str) -> Vec<NmRow> {
    let text: String = std::fs::read_to_string(fixture(name)).expect("read llvm-nm reference");
    let mut rows: Vec<NmRow> = text
        .lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(parts.len(), 4, "llvm-nm -D -S row: {line}");
            NmRow {
                name: parts[3].to_owned(),
                address: u64::from_str_radix(parts[0], 16).expect("address"),
                size: u64::from_str_radix(parts[1], 16).expect("size"),
                kind: match parts[2] {
                    "T" | "t" => "text",
                    "B" | "b" | "D" | "d" | "R" | "r" => "data",
                    other => panic!("unexpected nm type {other} in {line}"),
                },
            }
        })
        .collect();
    rows.sort();
    rows
}

fn disrobe_rows(library: &str, scratch: &std::path::Path) -> Vec<serde_json::Value> {
    let out: PathBuf = scratch.path_join(library);
    let run = run_disrobe(&[
        "native",
        "symbols",
        fixture(library).to_str().expect("utf-8 path"),
        "--out",
        out.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let dump: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).expect("symbols json")).expect("json");
    dump["exports"].as_array().expect("exports").clone()
}

trait PathJoin {
    fn path_join(&self, name: &str) -> PathBuf;
}

impl PathJoin for std::path::Path {
    fn path_join(&self, name: &str) -> PathBuf {
        self.join(format!("{name}.symbols.json"))
    }
}

fn assert_parity(library: &str, reference: &str) {
    let scratch = temp_dir("native-symbols-parity");
    let rows: Vec<serde_json::Value> = disrobe_rows(library, scratch.path());
    let nm: Vec<NmRow> = nm_reference(reference);
    assert!(
        nm.len() >= 5,
        "the reference lists the exported functions and data"
    );
    let ours: BTreeSet<NmRow> = rows
        .iter()
        .map(|row: &serde_json::Value| NmRow {
            name: row["name"].as_str().expect("name").to_owned(),
            address: row["address"].as_u64().expect("address"),
            size: row["size"].as_u64().expect("size"),
            kind: match row["kind"].as_str().expect("kind") {
                "text" => "text",
                "data" => "data",
                _ => "other",
            },
        })
        .collect();
    for expected in &nm {
        assert!(
            ours.contains(expected),
            "{library}: llvm-nm row {expected:?} must appear with the same address, size and kind; have {ours:#?}"
        );
    }
    let names: Vec<&str> = rows
        .iter()
        .map(|row: &serde_json::Value| row["name"].as_str().expect("name"))
        .collect();
    assert!(
        names.iter().all(|n: &&str| !n.starts_with('$')),
        "{library}: ARM mapping symbols are not symbol rows: {names:?}"
    );
    let distinct: BTreeSet<(&str, u64, &str)> = rows
        .iter()
        .map(|row: &serde_json::Value| {
            (
                row["name"].as_str().expect("name"),
                row["address"].as_u64().expect("address"),
                row["kind"].as_str().expect("kind"),
            )
        })
        .collect();
    assert_eq!(
        distinct.len(),
        rows.len(),
        "{library}: a symbol present in both .symtab and .dynsym is listed once"
    );
    assert!(
        rows.iter().all(|row: &serde_json::Value| !matches!(
            row["kind"].as_str(),
            Some("section" | "file")
        )),
        "{library}: section and file symbols are not symbol rows"
    );
}

#[test]
fn aarch64_jni_library_symbols_match_llvm_nm() {
    assert_parity("libjnireg_a64.so", "libjnireg_a64.nm-dynsyms.txt");
}

#[test]
fn x86_64_jni_library_symbols_match_llvm_nm() {
    assert_parity("libjnireg_x64.so", "libjnireg_x64.nm-dynsyms.txt");
}

#[test]
fn the_parity_check_turns_red_on_a_changed_reference_size() {
    let text: String =
        std::fs::read_to_string(fixture("libjnireg_a64.nm-dynsyms.txt")).expect("reference");
    let mutated: String = text.replacen(
        "0000000000000020 T JNI_OnLoad",
        "0000000000000024 T JNI_OnLoad",
        1,
    );
    assert_ne!(text, mutated);
    let scratch = temp_dir("native-symbols-parity-control");
    let rows: Vec<serde_json::Value> = disrobe_rows("libjnireg_a64.so", scratch.path());
    let onload: &serde_json::Value = rows
        .iter()
        .find(|row: &&serde_json::Value| row["name"] == "JNI_OnLoad")
        .expect("JNI_OnLoad row");
    assert_eq!(onload["size"].as_u64(), Some(0x20));
    assert!(
        mutated.contains("0000000000000024"),
        "the control changed the size"
    );
}
