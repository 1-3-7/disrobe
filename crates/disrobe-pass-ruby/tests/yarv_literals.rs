#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::analyze_bytes;
use ruby_toolchain::require_mri;

const LITERALS_YARVC: &str = "mri/yarv/literals.rb.yarvc";
const GRADED: &str = "the literals recompile comparison against real ruby";

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

fn recovered_source(rel: &str) -> String {
    let path: PathBuf = corpus_path(rel);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "corpus/ruby/{rel} is tracked in this repository but could not be read here ({e}); an \
             absent or unreadable fixture is never a skip, because that is how a check stops \
             comparing anything without saying so"
        )
    });
    let analysis =
        analyze_bytes(&bytes, rel).unwrap_or_else(|e| panic!("analyze corpus/ruby/{rel}: {e}"));
    analysis
        .yarv
        .unwrap_or_else(|| panic!("corpus/ruby/{rel} produced no YARV analysis"))
        .decompiled
        .source
}

#[test]
fn literals_iseq_recovers_immediates_collections_and_ranges() {
    let source: String = recovered_source(LITERALS_YARVC);

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

#[test]
fn literals_iseq_recompiles_to_identical_opcode_multiset() {
    if require_mri(GRADED).is_none() {
        return;
    }
    let source: String = recovered_source(LITERALS_YARVC);

    let (scratch, file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_yarv_literals_recovered", "rb")
            .expect("create recovered source scratch file");
    drop(file);
    let rec_path: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&rec_path, source).expect("write recovered literals source");

    let oracle: PathBuf = corpus_path("mri/yarv/recompile_oracle.rb");
    let original: PathBuf = corpus_path("mri/yarv/literals.rb");
    let output = Command::new("ruby")
        .arg(&oracle)
        .arg(&original)
        .arg(&rec_path)
        .output()
        .expect("run recompile oracle");

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
