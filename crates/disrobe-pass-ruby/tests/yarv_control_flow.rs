#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes};

fn recover(bytes: &[u8], name: &str) -> String {
    let analysis: RubyAnalysis = analyze_bytes(bytes, name).expect("analyze real yarv fixture");
    analysis.yarv.expect("yarv analysis").decompiled.source
}

fn code_only(source: &str) -> String {
    source
        .lines()
        .take_while(|l: &&str| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn recovers_single_arm_case_when_with_else() {
    const BYTES: &[u8] = include_bytes!("fixtures/case_one_arm.yarvc");
    let src: String = recover(BYTES, "case_one_arm.yarvc");
    let code: String = code_only(&src);
    assert!(
        code.contains("case x"),
        "single-arm case subject must be recovered as `case x`, not an inverted unless:\n{code}"
    );
    assert!(
        code.contains("when Integer"),
        "the sole `when Integer` arm must survive, not be dropped:\n{code}"
    );
    assert!(
        code.contains("\"int\"") && code.contains("\"other\""),
        "both the when body and the else body must be emitted:\n{code}"
    );
    assert!(
        !code.contains("unless") && !code.contains("===("),
        "must not degrade to `unless Integer.===(x)`:\n{code}"
    );
}

#[test]
fn recovers_block_captured_compound_or_assign_as_parenthesized_long_form() {
    const BYTES: &[u8] = include_bytes!("fixtures/compound_or_block.yarvc");
    let src: String = recover(BYTES, "compound_or_block.yarvc");
    let code: String = code_only(&src);
    assert!(
        code.contains("memo || (memo = it)") || code.contains("memo ||= it"),
        "block-captured `memo ||= it` must survive as the parenthesized long form \
         `memo || (memo = it)` (recompilable) or the folded `memo ||= it`, never the \
         unparenthesized `memo || memo = it` which Ruby rejects:\n{code}"
    );
    assert!(
        !code.contains("memo || memo = it"),
        "the unparenthesized `memo || memo = it` is a syntax error and must not be emitted:\n{code}"
    );
}
