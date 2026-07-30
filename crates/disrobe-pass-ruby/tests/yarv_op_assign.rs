#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::analyze_bytes;
use ruby_toolchain::require_mri;

const OPASSIGN_YARVC: &str = "mri/yarv/opassign.rb.yarvc";
const GRADED: &str = "the compound-assignment recompile comparison against real ruby";

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

fn recover_source(yarvc_rel: &str) -> String {
    let path: PathBuf = corpus_path(yarvc_rel);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "corpus/ruby/{yarvc_rel} is tracked in this repository but could not be read here \
             ({e}); an absent or unreadable fixture is never a skip, because that is how a check \
             stops comparing anything without saying so"
        )
    });
    let analysis = analyze_bytes(&bytes, yarvc_rel)
        .unwrap_or_else(|e| panic!("analyze corpus/ruby/{yarvc_rel}: {e}"));
    analysis
        .yarv
        .unwrap_or_else(|| panic!("corpus/ruby/{yarvc_rel} produced no YARV analysis"))
        .decompiled
        .source
}

#[test]
fn op_assign_forms_reconstruct_idiomatic_compound_assignment() {
    let source: String = recover_source(OPASSIGN_YARVC);
    for expected in [
        "cfg[:cache] ||= {}",
        "cfg[:nested] &&= cfg[:nested].dup",
        "total ||= 5",
        "total &&= 20",
        "hits[:n] += 4",
        "scores[0] += 7",
        "node.value ||= 99",
        "node.value += 1",
        "@store ||= []",
        "$global ||= \"x\"",
        "matrix[0][0] += 5",
    ] {
        assert!(
            source.lines().any(|l| l.trim() == expected),
            "recovered source must reconstruct `{expected}`, got:\n{source}"
        );
    }
}

#[test]
fn op_assign_recompiles_to_matching_opcode_multiset() {
    if require_mri(GRADED).is_none() {
        return;
    }
    let recovered: String = recover_source(OPASSIGN_YARVC);

    let (scratch, file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_yarv_opassign_recovered", "rb")
            .expect("create recovered source scratch file");
    drop(file);
    let rec_path: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&rec_path, recovered).expect("write recovered source");

    let oracle: PathBuf = corpus_path("mri/yarv/recompile_oracle.rb");
    let original: PathBuf = corpus_path("mri/yarv/opassign.rb");
    let output = Command::new("ruby")
        .arg(&oracle)
        .arg(&original)
        .arg(&rec_path)
        .output()
        .expect("run recompile oracle");
    let line: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    println!("[opassign] {line}");
    let pct: u32 = line
        .rsplit_once("pct=")
        .and_then(|(_, p)| p.split_whitespace().next())
        .and_then(|p| p.parse::<u32>().ok())
        .expect("oracle emitted a pct");
    assert!(
        pct >= 95,
        "op-assign opcode-equivalence regressed below 95%, got {pct}%"
    );
}
