#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use disrobe_pass_ruby::{RubyAnalysis, YarvAnalysis, analyze_bytes};

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn compile_to_ibf(src: &str) -> Option<Vec<u8>> {
    let mut child = Command::new("ruby")
        .arg("-e")
        .arg("STDOUT.binmode; STDOUT.write(RubyVM::InstructionSequence.compile(STDIN.read).to_binary)")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(src.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    Some(out.stdout)
}

fn opcode_multiset(bytes: &[u8]) -> BTreeMap<String, usize> {
    let analysis: RubyAnalysis = analyze_bytes(bytes, "runtime.yarvc").expect("analyze");
    let yarv: &YarvAnalysis = analysis.yarv.as_ref().expect("yarv analysis present");
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for body in &yarv.ibf.iseqs {
        for insn in &body.instructions {
            *counts.entry(insn.mnemonic.clone()).or_default() += 1;
        }
    }
    counts
}

#[test]
fn class_variable_reads_and_writes_survive_a_recompile() {
    if !ruby_available() {
        eprintln!(
            "skip: ruby not on PATH; install ruby 3.4.x to run the class-variable recompile check"
        );
        return;
    }
    let src: &str = "class Registry\n  @@items = []\n  def self.push(x)\n    @@items = @@items + [x]\n    @@items\n  end\nend\n";
    let original: Vec<u8> =
        compile_to_ibf(src).expect("compile the original class-variable source");
    let analysis: RubyAnalysis =
        analyze_bytes(&original, "cvar.yarvc").expect("analyze the original image");
    let yarv: &YarvAnalysis = analysis.yarv.as_ref().expect("yarv analysis present");
    let recovered: &str = yarv.decompiled.source.as_str();

    assert!(
        recovered.contains("@@items = @@items"),
        "the class-variable assignment must be recovered, not dropped: {recovered}"
    );

    let original_ms: BTreeMap<String, usize> = opcode_multiset(&original);
    let recompiled: Vec<u8> =
        compile_to_ibf(recovered).expect("the recovered source must recompile under MRI");
    let recompiled_ms: BTreeMap<String, usize> = opcode_multiset(&recompiled);

    for op in ["getclassvariable", "setclassvariable"] {
        let want: usize = original_ms.get(op).copied().unwrap_or(0);
        let got: usize = recompiled_ms.get(op).copied().unwrap_or(0);
        assert!(want > 0, "the fixture must exercise {op}");
        assert_eq!(
            got, want,
            "{op} count must match after recompiling the recovered source; original={original_ms:?} recompiled={recompiled_ms:?}"
        );
    }
}
