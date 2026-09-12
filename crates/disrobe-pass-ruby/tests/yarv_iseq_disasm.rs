#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes, render_image_disasm};

fn corpus(rel: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    for seg in rel.split('/') {
        p.push(seg);
    }
    std::fs::read(&p).unwrap_or_else(|_| panic!("missing committed fixture corpus/ruby/{rel}"))
}

#[test]
fn emits_ibf_image_summary_for_real_iseq() {
    let bytes: Vec<u8> = corpus("mri/yarv/hello.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "hello.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv present");
    assert!(yarv.disasm_text.contains("== disasm: <top> (ruby 3.4) =="));
    assert!(yarv.disasm_text.contains("IBF image:"));
    assert!(
        yarv.disasm_text.contains("\"hello world\""),
        "summary should list recovered string literal"
    );
    assert!(
        yarv.ibf.iseq_offsets.len() == 1,
        "hello.rb has a single top-level iseq, got {}",
        yarv.ibf.iseq_offsets.len()
    );
}

#[test]
fn disassembles_real_hello_iseq_to_concrete_opcodes() {
    let bytes: Vec<u8> = corpus("mri/yarv/hello.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "hello.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv present");
    let disasm: String = render_image_disasm(&yarv.ibf, yarv.version);
    for mnemonic in [
        "putself",
        "putchilledstring",
        "opt_send_without_block",
        "leave",
    ] {
        assert!(
            disasm.contains(mnemonic),
            "expected `{mnemonic}` in real hello disasm, got:\n{disasm}"
        );
    }
    assert!(
        disasm.contains("\"hello world\"") && disasm.contains(":puts"),
        "expected resolved string + method id in disasm, got:\n{disasm}"
    );
    let top = yarv
        .ibf
        .iseqs
        .first()
        .expect("at least one decoded iseq body");
    assert_eq!(
        top.instructions.len(),
        4,
        "hello top iseq has 4 instructions"
    );
}
