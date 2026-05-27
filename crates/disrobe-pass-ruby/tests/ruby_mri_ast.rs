#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_ruby::{Flavor, MriAst, RubyAnalysis, analyze_bytes};

mod common;

#[test]
fn parses_tiny_rb_fixture_into_full_ast() {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("tiny.rb");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, path.to_str().expect("path")).expect("analyze");
    assert_eq!(analysis.flavor, Flavor::MriSource);
    let mri: MriAst = analysis.mri.expect("mri present");
    let names: Vec<&str> = mri.definitions.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"Tiny"));
    assert!(names.contains(&"Greeter"));
    assert!(names.contains(&"initialize"));
    assert!(names.contains(&"greet"));
    assert!(mri.requires.contains(&"json".to_owned()));
    assert!(mri.token_count > 30);
}

#[test]
fn rejects_invalid_utf8() {
    let bytes: Vec<u8> = vec![b'#', b'!', b'/', b'r', 0xFFu8];
    let err: disrobe_pass_ruby::RubyError =
        analyze_bytes(&bytes, "bad.rb").expect_err("must reject");
    assert!(matches!(
        err,
        disrobe_pass_ruby::RubyError::MriBadUtf8 { .. }
    ));
}
