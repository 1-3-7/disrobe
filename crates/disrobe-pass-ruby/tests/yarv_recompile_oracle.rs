#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::analyze_bytes;

const HELLO_FLOOR_PCT: u32 = 100;
const GREETER_FLOOR_PCT: u32 = 100;
const MEGAFILE_FLOOR_PCT: u32 = 98;
const MEGAFILE_MATCHED_FLOOR: u32 = 23580;

const PUBLISHED_HEADING: &str = "Ruby YARV";
const PUBLISHED_GREETER_BAR: &str = "greeter";
const PUBLISHED_MEGAFILE_BAR: &str = "megafile";

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    p
}

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("xtask");
    path.push("data");
    path.push("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

fn published_value(label: &str) -> f64 {
    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, label);
    bar["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("the {label} bar must carry a numeric value"))
}

#[test]
fn published_yarv_bars_match_the_floors_this_crate_enforces() {
    let greeter: f64 = published_value(PUBLISHED_GREETER_BAR);
    let megafile: f64 = published_value(PUBLISHED_MEGAFILE_BAR);
    assert!(
        (greeter - f64::from(GREETER_FLOOR_PCT)).abs() < f64::EPSILON,
        "xtask/data/recovery.json publishes greeter at {greeter}% and every document renders that \
         number, but this gate enforces {GREETER_FLOOR_PCT}%"
    );
    assert!(
        (megafile - f64::from(MEGAFILE_FLOOR_PCT)).abs() < f64::EPSILON,
        "xtask/data/recovery.json publishes megafile at {megafile}% and every document renders \
         that number, but this gate enforces {MEGAFILE_FLOOR_PCT}%"
    );
}

fn corpus_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = corpus_dir();
    for seg in rel.split('/') {
        path.push(seg);
    }
    path
}

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn recover_source(yarvc_rel: &str) -> Option<String> {
    let bytes: Vec<u8> = std::fs::read(corpus_path(yarvc_rel)).ok()?;
    let analysis = analyze_bytes(&bytes, yarvc_rel).ok()?;
    let yarv = analysis.yarv?;
    Some(yarv.decompiled.source)
}

fn oracle_line(original_rel: &str, yarvc_rel: &str) -> Option<String> {
    let recovered: String = recover_source(yarvc_rel)?;
    let purpose: String = format!(
        "disrobe_yarv_recovered_{}",
        yarvc_rel.replace(['/', '.'], "_")
    );
    let (scratch, file): (ScratchFile, std::fs::File) = ScratchFile::create(&purpose, "rb").ok()?;
    drop(file);
    let rec_path: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&rec_path, recovered).ok()?;

    let oracle: PathBuf = corpus_path("mri/yarv/recompile_oracle.rb");
    let original: PathBuf = corpus_path(original_rel);
    let output = Command::new("ruby")
        .arg(&oracle)
        .arg(&original)
        .arg(&rec_path)
        .output()
        .ok()?;
    let line: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    println!("[{yarvc_rel}] {line}");
    Some(line)
}

fn measure(original_rel: &str, yarvc_rel: &str) -> Option<u32> {
    oracle_line(original_rel, yarvc_rel)?
        .rsplit_once("pct=")
        .and_then(|(_, p)| p.split_whitespace().next())
        .and_then(|p| p.parse::<u32>().ok())
}

fn measure_matched(original_rel: &str, yarvc_rel: &str) -> Option<u32> {
    let line: String = oracle_line(original_rel, yarvc_rel)?;
    let field: &str = line
        .split_whitespace()
        .find_map(|t| t.strip_prefix("matched="))?;
    field
        .split_once('/')
        .and_then(|(n, _)| n.parse::<u32>().ok())
}

#[test]
fn yarv_recompile_equivalence_is_reproducible() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the non-circular YARV oracle");
        return;
    }
    assert!(
        std::fs::read(corpus_path("mri/yarv/greeter.rb.yarvc")).is_ok(),
        "missing committed fixture corpus/ruby/mri/yarv/greeter.rb.yarvc"
    );

    let hello: u32 = measure("hello.rb", "mri/yarv/hello.rb.yarvc")
        .expect("hello recompile oracle produced a rate");
    let greeter: u32 = measure("greeter.rb", "mri/yarv/greeter.rb.yarvc")
        .expect("greeter recompile oracle produced a rate");
    let megafile: u32 = measure("megafile/edge_cases.rb", "mri/yarv/edge_cases.rb.yarvc")
        .expect("megafile recompile oracle produced a rate");

    assert!(
        hello >= HELLO_FLOOR_PCT,
        "hello opcode-equivalence regressed below {HELLO_FLOOR_PCT}%, got {hello}%"
    );
    assert!(
        greeter >= GREETER_FLOOR_PCT,
        "greeter opcode-equivalence regressed below {GREETER_FLOOR_PCT}%, got {greeter}%"
    );
    assert!(
        megafile >= MEGAFILE_FLOOR_PCT,
        "megafile opcode-equivalence regressed below {MEGAFILE_FLOOR_PCT}%, got {megafile}%"
    );

    let megafile_matched: u32 =
        measure_matched("megafile/edge_cases.rb", "mri/yarv/edge_cases.rb.yarvc")
            .expect("megafile recompile oracle produced a matched count");
    assert!(
        megafile_matched >= MEGAFILE_MATCHED_FLOOR,
        "megafile matched-opcode count regressed below the locked floor \
         {MEGAFILE_MATCHED_FLOOR}, got {megafile_matched}"
    );

    assert!(
        f64::from(greeter) >= published_value(PUBLISHED_GREETER_BAR),
        "recovery.json publishes greeter at {}%; this run measured {greeter}%",
        published_value(PUBLISHED_GREETER_BAR)
    );
    assert!(
        f64::from(megafile) >= published_value(PUBLISHED_MEGAFILE_BAR),
        "recovery.json publishes megafile at {}%; this run measured {megafile}%",
        published_value(PUBLISHED_MEGAFILE_BAR)
    );
}
