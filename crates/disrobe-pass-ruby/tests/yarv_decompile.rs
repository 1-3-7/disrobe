#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;

use disrobe_pass_ruby::{Fidelity, RubyAnalysis, analyze_bytes};

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    for seg in rel.split('/') {
        p.push(seg);
    }
    std::fs::read(&p).ok()
}

#[test]
fn decompiles_real_hello_iseq_to_method_call() {
    let Some(bytes): Option<Vec<u8>> = corpus("mri/yarv/hello.rb.yarvc") else {
        eprintln!("skip: mri/yarv/hello.rb.yarvc fixture absent");
        return;
    };
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "hello.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    assert_eq!(
        yarv.decompiled.fidelity,
        Fidelity::StructuralOnly,
        "hello iseq body should decode to structural source, not pool-only"
    );
    assert!(
        yarv.decompiled.source.contains("puts(\"hello world\")"),
        "expected recovered `puts(\"hello world\")`, got:\n{}",
        yarv.decompiled.source
    );
    assert!(
        yarv.decompiled
            .recovered_strings
            .iter()
            .any(|s| s == "hello world")
    );
    assert!(
        yarv.decompiled
            .recovered_symbols
            .iter()
            .any(|s| s == "puts")
    );
}

#[test]
fn decompiles_real_greeter_iseq_with_class_and_methods() {
    let Some(bytes): Option<Vec<u8>> = corpus("mri/yarv/greeter.rb.yarvc") else {
        eprintln!("skip: mri/yarv/greeter.rb.yarvc fixture absent");
        return;
    };
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greeter.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    let src: &str = &yarv.decompiled.source;
    assert!(
        src.contains("module Tiny"),
        "expected `module Tiny`, got:\n{src}"
    );
    assert!(
        src.contains("def initialize") && src.contains("def greet"),
        "expected def initialize/greet, got:\n{src}"
    );
    assert!(
        src.contains(".new(\"world\")") || src.contains("new(\"world\")"),
        "expected `new(\"world\")` call, got:\n{src}"
    );
    assert!(
        yarv.ibf.iseqs.len() >= 5,
        "greeter has 5 iseq bodies, got {}",
        yarv.ibf.iseqs.len()
    );
}

#[test]
fn recovers_thousands_of_instructions_from_real_megafile_iseq() {
    let Some(bytes): Option<Vec<u8>> = corpus("mri/yarv/edge_cases.rb.yarvc") else {
        eprintln!("skip: mri/yarv/edge_cases.rb.yarvc fixture absent");
        return;
    };
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "edge_cases.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    assert!(
        yarv.ibf.recovered_literal_count > 500,
        "megafile should recover hundreds of literals, got {}",
        yarv.ibf.recovered_literal_count
    );
    assert!(
        yarv.ibf.recovered_instruction_count > 2000,
        "megafile should recover thousands of instructions, got {}",
        yarv.ibf.recovered_instruction_count
    );
    assert!(
        yarv.ibf.iseqs.len() > 100,
        "megafile should have many iseq bodies, got {}",
        yarv.ibf.iseqs.len()
    );
}
