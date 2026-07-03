#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_ruby::analyze_bytes;

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = corpus_dir();
    for seg in rel.split('/') {
        path.push(seg);
    }
    path
}

fn recovered_source(rel: &str) -> Option<String> {
    let bytes: Vec<u8> = std::fs::read(corpus_path(rel)).ok()?;
    let analysis = analyze_bytes(&bytes, rel).ok()?;
    Some(analysis.yarv?.decompiled.source)
}

#[test]
fn literals_iseq_recovers_immediates_collections_and_ranges() {
    let Some(source): Option<String> = recovered_source("mri/yarv/literals.rb.yarvc") else {
        eprintln!("skip: mri/yarv/literals.rb.yarvc fixture absent");
        return;
    };

    assert!(
        !source.contains("obj["),
        "literal recovery must resolve every IBF object reference, but a raw obj[N] placeholder leaked:\n{source}"
    );

    let must_contain: &[&str] = &[
        "PRIMES = [2, 3, 5, 7].freeze",
        "EMPTY = [].freeze",
        "FLAGS = [true, false, nil]",
        "SPAN = (1..10)",
        "OPEN = (1...10)",
        "BEGINLESS = (..5)",
        "ENDLESS = (1..)",
        "[4, 8, 15, 16, 23, 42].max",
        "# frozen_string_literal: true",
        "# shareable_constant_value: literal",
    ];
    for needle in must_contain {
        assert!(
            source.contains(needle),
            "recovered literals source missing `{needle}`:\n{source}"
        );
    }
    assert!(
        source.contains("timeout: 30") && source.contains("debug: false"),
        "recovered CONFIG hash literal must carry its symbol keys and false value:\n{source}"
    );
}

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn literals_iseq_recompiles_to_identical_opcode_multiset() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x for the non-circular oracle");
        return;
    }
    let Some(source): Option<String> = recovered_source("mri/yarv/literals.rb.yarvc") else {
        eprintln!("skip: mri/yarv/literals.rb.yarvc fixture absent");
        return;
    };

    let mut rec_path: PathBuf = std::env::temp_dir();
    rec_path.push("disrobe_yarv_literals_recovered.rb");
    std::fs::write(&rec_path, source).expect("write recovered literals source");

    let oracle: PathBuf = corpus_path("mri/yarv/recompile_oracle.rb");
    let original: PathBuf = corpus_path("mri/yarv/literals.rb");
    let output = Command::new("ruby")
        .arg(&oracle)
        .arg(&original)
        .arg(&rec_path)
        .output()
        .expect("run recompile oracle");
    let _ = std::fs::remove_file(&rec_path);

    let line: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let pct: u32 = line
        .rsplit_once("pct=")
        .and_then(|(_, p)| p.split_whitespace().next())
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or_else(|| panic!("oracle produced no rate: {line}"));

    assert!(
        pct >= 100,
        "recovered literals must recompile to a byte-equivalent opcode multiset against real Ruby, got {pct}% ({line})"
    );
}
