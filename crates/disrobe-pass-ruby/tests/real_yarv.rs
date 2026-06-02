#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;

use disrobe_pass_ruby::{Flavor, RubyAnalysis, YarvBinaryHeader, analyze_bytes};

fn corpus_dir() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
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

fn load_corpus(rel: &str) -> Option<Vec<u8>> {
    std::fs::read(corpus_path(rel)).ok()
}

#[test]
fn real_yarv_hello_iseq_parses_with_3_4_header() {
    let Some(bytes): Option<Vec<u8>> = load_corpus("mri/yarv/hello.rb.yarvc") else {
        eprintln!("skip: mri/yarv/hello.rb.yarvc fixture absent");
        return;
    };
    assert!(
        bytes.len() > 36,
        "real iseq should exceed header size, got {}",
        bytes.len()
    );
    assert_eq!(&bytes[..4], b"YARB", "real YARB magic");
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, "hello.rb.yarvc").expect("analyze real yarv");
    assert_eq!(analysis.flavor, Flavor::YarvBinary);
    let yarv = analysis.yarv.expect("yarv analysis present");
    let header: YarvBinaryHeader = yarv.header;
    assert_eq!(header.magic, *b"YARB");
    assert_eq!(header.major, 3);
    assert_eq!(header.minor, 4);
    assert!(
        header.size as usize == bytes.len(),
        "header size {} should equal file size {}",
        header.size,
        bytes.len()
    );
    assert!(header.iseq_list_size >= 1);
    assert!(yarv.disasm_text.contains("== disasm: <top> (ruby 3.4) =="));
}

#[test]
fn real_yarv_greeter_iseq_parses_with_3_4_header() {
    let Some(bytes): Option<Vec<u8>> = load_corpus("mri/yarv/greeter.rb.yarvc") else {
        eprintln!("skip: mri/yarv/greeter.rb.yarvc fixture absent");
        return;
    };
    assert!(
        bytes.len() > 200,
        "greeter iseq should be substantial, got {}",
        bytes.len()
    );
    assert_eq!(&bytes[..4], b"YARB");
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, "greeter.rb.yarvc").expect("analyze real yarv");
    assert_eq!(analysis.flavor, Flavor::YarvBinary);
    let yarv = analysis.yarv.expect("yarv analysis present");
    assert_eq!(yarv.header.major, 3);
    assert_eq!(yarv.header.minor, 4);
    assert!(yarv.header.iseq_list_size >= 1);
    assert!(yarv.header.global_object_list_size >= 1);
    assert!(yarv.disasm_text.contains("ruby 3.4"));
}

#[test]
fn real_yarv_hello_source_is_real_ruby() {
    let Some(bytes): Option<Vec<u8>> = load_corpus("hello.rb") else {
        eprintln!("skip: hello.rb fixture absent");
        return;
    };
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "hello.rb").expect("analyze real source");
    assert_eq!(analysis.flavor, Flavor::MriSource);
    let mri = analysis.mri.expect("mri analysis present");
    assert!(mri.tokens.iter().any(|t| t.value == "puts"));
}

#[test]
fn real_yarv_greeter_source_has_module_class_def() {
    let Some(bytes): Option<Vec<u8>> = load_corpus("greeter.rb") else {
        eprintln!("skip: greeter.rb fixture absent");
        return;
    };
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greeter.rb").expect("analyze real source");
    assert_eq!(analysis.flavor, Flavor::MriSource);
    let mri = analysis.mri.expect("mri analysis present");
    let values: Vec<&str> = mri.tokens.iter().map(|t| t.value.as_str()).collect();
    assert!(values.contains(&"module"));
    assert!(values.contains(&"class"));
    assert!(values.contains(&"def"));
}

#[test]
fn real_yarv_megafile_iseq_parses() {
    let Some(bytes): Option<Vec<u8>> = load_corpus("mri/yarv/edge_cases.rb.yarvc") else {
        eprintln!("skip: mri/yarv/edge_cases.rb.yarvc fixture absent");
        return;
    };
    assert!(
        bytes.len() > 100_000,
        "megafile iseq should be large, got {}",
        bytes.len()
    );
    assert_eq!(&bytes[..4], b"YARB");
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, "edge_cases.rb.yarvc").expect("analyze megafile yarv");
    assert_eq!(analysis.flavor, Flavor::YarvBinary);
    let yarv = analysis.yarv.expect("yarv analysis present");
    assert_eq!(yarv.header.major, 3);
    assert_eq!(yarv.header.minor, 4);
    assert!(yarv.header.iseq_list_size >= 1);
    assert!(
        yarv.header.global_object_list_size >= 10,
        "megafile should have many global objects, got {}",
        yarv.header.global_object_list_size
    );
}

#[test]
fn real_yarv_megafile_source_has_broad_feature_surface() {
    let Some(bytes): Option<Vec<u8>> = load_corpus("megafile/edge_cases.rb") else {
        eprintln!("skip: megafile/edge_cases.rb fixture absent");
        return;
    };
    assert!(
        bytes.len() > 30_000,
        "megafile source should be substantial"
    );
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, "megafile/edge_cases.rb").expect("analyze megafile source");
    assert_eq!(analysis.flavor, Flavor::MriSource);
    let mri = analysis.mri.expect("mri analysis present");
    let values: Vec<&str> = mri.tokens.iter().map(|t| t.value.as_str()).collect();
    for kw in [
        "BEGIN", "END", "module", "class", "def", "case", "in", "rescue", "ensure", "retry",
    ] {
        assert!(values.contains(&kw), "megafile should contain keyword {kw}");
    }
    assert!(
        mri.line_count >= 1500,
        "megafile should be >=1500 lines, got {}",
        mri.line_count
    );
    assert!(
        mri.token_count > 5_000,
        "megafile token count should be substantial, got {}",
        mri.token_count
    );
    assert!(mri.definitions.iter().any(|d| d.kind == "class"));
    assert!(mri.definitions.iter().any(|d| d.kind == "module"));
}
