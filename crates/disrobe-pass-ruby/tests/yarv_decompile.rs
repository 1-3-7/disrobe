#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_ruby::{Fidelity, RubyAnalysis, analyze_bytes};

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
fn decompiles_real_hello_iseq_to_method_call() {
    let bytes: Vec<u8> = corpus("mri/yarv/hello.rb.yarvc");
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
    let bytes: Vec<u8> = corpus("mri/yarv/greeter.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greeter.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    let src: &str = &yarv.decompiled.source;
    assert!(
        src.contains("module Tiny"),
        "expected `module Tiny`, got:\n{src}"
    );
    assert!(
        src.contains("def initialize(who)") && src.contains("def greet"),
        "expected def initialize(who)/greet with recovered method params, got:\n{src}"
    );
    assert!(
        src.contains(".new(\"world\")") || src.contains("new(\"world\")"),
        "expected `new(\"world\")` call, got:\n{src}"
    );
    assert!(
        src.contains("Tiny::Greeter.new(\"world\")"),
        "expected the constant path `Tiny::Greeter` resolved from the iseq cache, got:\n{src}"
    );
    assert!(
        src.contains("\"hello, #{@who}!\""),
        "expected recovered string interpolation `\"hello, #{{@who}}!\"`, got:\n{src}"
    );
    assert!(
        yarv.ibf.iseqs.len() >= 5,
        "greeter has 5 iseq bodies, got {}",
        yarv.ibf.iseqs.len()
    );
}

#[test]
fn greeter_recovers_well_formed_nested_recompilable_source() {
    let bytes: Vec<u8> = corpus("mri/yarv/greeter.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greeter.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    let code: String = yarv
        .decompiled
        .source
        .lines()
        .take_while(|l| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !code.contains("...; end") && !code.contains("{ ... }") && !code.contains("# iseq"),
        "recovered body should be real nested source, not placeholders:\n{code}"
    );
    let opens: usize = code
        .lines()
        .filter(|l| {
            let t: &str = l.trim_start();
            t.starts_with("def ")
                || t.starts_with("class ")
                || t.starts_with("module ")
                || t == "class << self"
        })
        .count();
    let ends: usize = code.lines().filter(|l| l.trim() == "end").count();
    assert_eq!(
        opens, ends,
        "block openers and `end` must balance for recompilable source; got {opens} vs {ends}\n{code}"
    );
    assert!(
        code.contains("  class Greeter") && code.contains("    def initialize(who)"),
        "expected indented nesting module > class > def:\n{code}"
    );
}

#[test]
fn recovers_real_local_variable_name_from_iseq_local_table() {
    let bytes: Vec<u8> = corpus("mri/yarv/greeter.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greeter.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    let initialize_body = yarv
        .ibf
        .iseqs
        .iter()
        .find(|b| b.local_table.iter().any(|n| n.as_deref() == Some("who")))
        .expect("an iseq body whose local_table preserves the `who` parameter");
    assert_eq!(
        initialize_body.local_table,
        vec![Some("who".to_owned())],
        "initialize(who) should recover exactly its single named local from the local_table"
    );
    let src: &str = &yarv.decompiled.source;
    assert!(
        src.contains("@who = who"),
        "decompiled body should bind `@who = who` via the recovered local name, got:\n{src}"
    );
    assert!(
        !src.contains("@who = local3") && !src.contains("= local"),
        "no synthetic local{{N}} placeholder should survive where the local_table named the slot, got:\n{src}"
    );
}

#[test]
fn recovers_block_parameter_names_from_megafile_block_iseqs() {
    let bytes: Vec<u8> = corpus("mri/yarv/edge_cases.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "edge_cases.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    let src: &str = &yarv.decompiled.source;
    assert!(
        src.contains(".each do |n|") || src.contains(".each { |n|"),
        "expected a recovered each block with a single named block parameter from the megafile"
    );
    assert!(
        src.contains("|i|") || src.contains("|x|"),
        "expected a recovered block with a single named block parameter from the megafile"
    );
    let multi_param_block: bool = src.lines().any(|l| {
        l.contains('|')
            && l.split_once('|')
                .is_some_and(|(_, rest)| rest.split_once('|').is_some_and(|(p, _)| p.contains(',')))
    });
    assert!(
        multi_param_block,
        "expected at least one multi-parameter block in the megafile"
    );
}

#[test]
fn recovers_method_signatures_and_metaprogramming_surface_from_megafile() {
    let bytes: Vec<u8> = corpus("mri/yarv/edge_cases.rb.yarvc");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "edge_cases.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    let src: &str = &yarv.decompiled.source;
    let methods_with_params: usize = src
        .lines()
        .filter(|l| l.trim_start().starts_with("def ") && l.contains('('))
        .count();
    assert!(
        methods_with_params >= 50,
        "expected many recovered method signatures with params, got {methods_with_params}"
    );
    assert!(
        src.contains("def method_missing(name, *args, **kwargs, &blk)"),
        "expected `def method_missing(name, *args, **kwargs, &blk)` with its full recovered signature"
    );
    assert!(
        src.contains("define_method") && src.contains("class_eval"),
        "expected define_method and class_eval metaprogramming surface"
    );
}

#[test]
fn recovers_thousands_of_instructions_from_real_megafile_iseq() {
    let bytes: Vec<u8> = corpus("mri/yarv/edge_cases.rb.yarvc");
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
