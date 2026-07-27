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
        hello >= 100,
        "hello opcode-equivalence regressed below 100%, got {hello}%"
    );
    assert!(
        greeter >= 100,
        "greeter opcode-equivalence regressed below 100%, got {greeter}%"
    );
    assert!(
        megafile >= 98,
        "megafile opcode-equivalence regressed below 98%, got {megafile}%"
    );

    let megafile_matched: u32 =
        measure_matched("megafile/edge_cases.rb", "mri/yarv/edge_cases.rb.yarvc")
            .expect("megafile recompile oracle produced a matched count");
    assert!(
        megafile_matched >= 23580,
        "megafile matched-opcode count regressed below the locked floor 23580, got {megafile_matched}"
    );
}
