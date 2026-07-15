#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_ruby::analyze_bytes;

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn compile_to_ibf(src: &str, tag: &str) -> Option<Vec<u8>> {
    let dir: PathBuf = std::env::temp_dir();
    let src_path: PathBuf = dir.join(format!("disrobe_ruby_rt_src_{tag}.rb"));
    let ibf_path: PathBuf = dir.join(format!("disrobe_ruby_rt_{tag}.yarvc"));
    std::fs::write(&src_path, src).ok()?;
    let status = Command::new("ruby")
        .arg("-e")
        .arg("File.binwrite(ARGV[1], RubyVM::InstructionSequence.compile(File.read(ARGV[0])).to_binary)")
        .arg(&src_path)
        .arg(&ibf_path)
        .status()
        .ok()?;
    let bytes: Option<Vec<u8>> = status
        .success()
        .then(|| std::fs::read(&ibf_path).ok())
        .flatten();
    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&ibf_path);
    bytes
}

fn run_ruby_stdout(src: &str, tag: &str) -> Option<Vec<u8>> {
    let path: PathBuf = std::env::temp_dir().join(format!("disrobe_ruby_rt_run_{tag}.rb"));
    std::fs::write(&path, src).ok()?;
    let out = Command::new("ruby").arg(&path).output().ok()?;
    let _ = std::fs::remove_file(&path);
    out.status.success().then_some(out.stdout)
}

#[test]
fn recovered_string_literals_reproduce_original_bytes() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.x to run the string round-trip check");
        return;
    }
    let source: &str = concat!(
        "puts '#{1 + 1}'\n",
        "puts 'ivar #@a global #$b cvar #@@c'\n",
        "p \"\\x007\\x018tail\".bytes\n",
        "p \"quote \\\" back \\\\ hash #x end\".bytes\n",
        "p \"tab\\tnl\\rnul\\x00del\\x7F\".bytes\n",
    );
    let ibf: Vec<u8> = compile_to_ibf(source, "strings").expect("ruby compiled the fixture to ibf");
    let analysis = analyze_bytes(&ibf, "roundtrip.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv analysis present");
    let recovered: String = yarv.decompiled.source;

    let want: Vec<u8> = run_ruby_stdout(source, "orig").expect("original source ran under ruby");
    let got: Vec<u8> =
        run_ruby_stdout(&recovered, "recovered").expect("recovered source ran under ruby");

    assert_eq!(
        want, got,
        "recovered string literals must reproduce the original runtime bytes.\nrecovered source:\n{recovered}\nwant={want:?}\n got={got:?}"
    );
}
