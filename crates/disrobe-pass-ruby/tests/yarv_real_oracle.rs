#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_ruby::{RubyAnalysis, YarvAnalysis, analyze_bytes};

fn corpus_path(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn read_corpus(rel: &str) -> Vec<u8> {
    let p: PathBuf = corpus_path(rel);
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", p.display()))
}

fn recovered_mnemonics(rel: &str) -> Vec<Vec<String>> {
    let bytes: Vec<u8> = read_corpus(rel);
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, rel).unwrap_or_else(|e| panic!("analyze {rel}: {e}"));
    let yarv: &YarvAnalysis = analysis
        .yarv
        .as_ref()
        .unwrap_or_else(|| panic!("{rel} produced no YARV analysis"));
    yarv.ibf
        .iseqs
        .iter()
        .map(|body| {
            body.instructions
                .iter()
                .map(|insn| insn.mnemonic.clone())
                .collect::<Vec<String>>()
        })
        .collect()
}

fn expected_oracle() -> serde_json::Value {
    let raw: Vec<u8> = read_corpus("mri/yarv/expected_iseq_mnemonics.json");
    serde_json::from_slice(&raw).expect("expected mnemonics oracle is valid JSON")
}

fn expected_for(oracle: &serde_json::Value, name: &str) -> Vec<Vec<String>> {
    oracle[name]
        .as_array()
        .unwrap_or_else(|| panic!("oracle missing entry {name}"))
        .iter()
        .map(|iseq| {
            iseq.as_array()
                .expect("iseq is array")
                .iter()
                .map(|m| m.as_str().expect("mnemonic is string").to_owned())
                .collect::<Vec<String>>()
        })
        .collect()
}

#[test]
fn hello_ibf_decodes_to_real_yarv_mnemonics() {
    let oracle: serde_json::Value = expected_oracle();
    let expected: Vec<Vec<String>> = expected_for(&oracle, "hello");
    let recovered: Vec<Vec<String>> = recovered_mnemonics("mri/yarv/hello.rb.yarvc");
    assert_eq!(
        recovered, expected,
        "disrobe's IBF opcode decode of the real `puts \"hello world\"` iseq must equal the real Ruby disasm mnemonic sequence, instruction-for-instruction"
    );
}

#[test]
fn greeter_ibf_decodes_to_real_yarv_mnemonics() {
    let oracle: serde_json::Value = expected_oracle();
    let expected: Vec<Vec<String>> = expected_for(&oracle, "greeter");
    let recovered: Vec<Vec<String>> = recovered_mnemonics("mri/yarv/greeter.rb.yarvc");
    assert_eq!(
        recovered.len(),
        expected.len(),
        "iseq count must match the real Ruby disasm: {} recovered vs {} real",
        recovered.len(),
        expected.len()
    );
    for (idx, (got, want)) in recovered.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            got, want,
            "iseq[{idx}] opcode decode must equal the real Ruby disasm mnemonic sequence"
        );
    }
}

#[test]
fn recovered_string_literals_match_the_real_source() {
    let bytes: Vec<u8> = read_corpus("mri/yarv/hello.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "hello.rb.yarvc").expect("analyze");
    let yarv: &YarvAnalysis = analysis.yarv.as_ref().expect("yarv");
    assert!(
        yarv.decompiled
            .recovered_strings
            .iter()
            .any(|s| s == "hello world"),
        "the real string literal `hello world` from the source must be recovered from the genuine IBF; got {:?}",
        yarv.decompiled.recovered_strings
    );
}
