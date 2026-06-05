//! Non-circular YARV recompile-equivalence harness, committed and reproducible.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
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

/// Decompile `yarvc_rel`, write the recovered source to a temp file, run the committed oracle
/// against `original_rel`, and return the measured opcode-multiset recovery percentage.
fn measure(original_rel: &str, yarvc_rel: &str) -> Option<u32> {
    let recovered: String = recover_source(yarvc_rel)?;
    let mut rec_path: PathBuf = std::env::temp_dir();
    rec_path.push(format!(
        "disrobe_yarv_recovered_{}.rb",
        yarvc_rel.replace(['/', '.'], "_")
    ));
    std::fs::write(&rec_path, recovered).ok()?;

    let oracle: PathBuf = corpus_path("mri/yarv/recompile_oracle.rb");
    let original: PathBuf = corpus_path(original_rel);
    let output = Command::new("ruby")
        .arg(&oracle)
        .arg(&original)
        .arg(&rec_path)
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&rec_path);
    let line: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    println!("[{yarvc_rel}] {line}");
    line.rsplit_once("pct=")
        .and_then(|(_, p)| p.split_whitespace().next())
        .and_then(|p| p.parse::<u32>().ok())
}

#[test]
fn yarv_recompile_equivalence_is_reproducible() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the non-circular YARV oracle");
        return;
    }
    if std::fs::read(corpus_path("mri/yarv/greeter.rb.yarvc")).is_err() {
        eprintln!("skip: yarv corpus fixtures absent");
        return;
    }

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
        greeter >= 90,
        "greeter opcode-equivalence regressed below 90%, got {greeter}%"
    );
    assert!(
        megafile >= 80,
        "megafile opcode-equivalence regressed below 80%, got {megafile}%"
    );
}
