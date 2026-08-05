#![allow(clippy::expect_used, clippy::panic)]

use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");

fn is_identifier_start(c: char) -> bool {
    c.is_alphabetic() || c == '$' || c == '_'
}

fn is_identifier_part(c: char) -> bool {
    c.is_alphanumeric() || c == '$' || c == '_'
}

fn unwritable_identifiers(source: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in source.lines() {
        let code: &str = line.split('"').next().unwrap_or(line);
        let mut current: String = String::new();
        for c in code.chars() {
            if is_identifier_part(c) || c == '-' {
                current.push(c);
                continue;
            }
            if !current.is_empty() {
                found.extend(unwritable_token(&current));
                current.clear();
            }
        }
        found.extend(unwritable_token(&current));
    }
    found.sort_unstable();
    found.dedup();
    found
}

fn unwritable_token(token: &str) -> Option<String> {
    if token.is_empty() || token.chars().all(|c: char| c == '-') {
        return None;
    }
    let numeric_literal: bool = token
        .trim_start_matches('-')
        .chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_digit());
    if numeric_literal {
        return None;
    }
    let mut chars: core::str::Chars<'_> = token.chars();
    let start_ok: bool = chars.next().is_some_and(is_identifier_start);
    if start_ok && chars.all(is_identifier_part) {
        return None;
    }
    Some(token.to_owned())
}

#[test]
fn every_identifier_the_dalvik_recovery_emits_can_be_written_in_java() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse EdgeCases.dex");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let offenders: Vec<String> = unwritable_identifiers(&recovered.source);
    assert!(
        offenders.is_empty(),
        "the recovered source carries {} identifier(s) that no Java compiler can parse, so the \
         whole file stops at the parser and no method in it can be graded: {offenders:?}. D8 and \
         R8 emit nest-access bridges and interface companions whose names contain characters that \
         are legal in a dex and illegal in Java source; every one of them has to be rewritten at \
         the declaration and at every reference alike",
        offenders.len()
    );
}

#[test]
fn distinct_unwritable_names_never_collapse_onto_one_legal_name() {
    let originals: [&str; 8] = [
        "-$$Nest$sfgetCTR",
        "+$$Nest$sfgetCTR",
        "-$$Nest$sfgetOTHER",
        "a-b",
        "a+b",
        "a b",
        "0leading",
        "class",
    ];
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    for original in originals {
        let rewritten: String = disrobe_pass_jvm::java_writable_identifier(original);
        assert!(
            unwritable_token(&rewritten).is_none(),
            "`{original}` rewrote to `{rewritten}`, which java still cannot parse"
        );
        if let Some(previous) = seen.insert(rewritten.clone(), original) {
            panic!(
                "`{previous}` and `{original}` both rewrote to `{rewritten}`. Two distinct names \
                 in a dex collapsing onto one java name silently merges two members, which is a \
                 worse defect than the syntax error the rewrite exists to remove"
            );
        }
    }
}

#[test]
fn a_rewritten_name_is_stable_between_its_declaration_and_its_uses() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse EdgeCases.dex");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let joined: String = recovered.source;
    let expected: String = disrobe_pass_jvm::java_writable_identifier("-$$Nest$sfgetCTR");
    assert_ne!(
        expected, "-$$Nest$sfgetCTR",
        "the name under test has to be one the rewrite actually changes"
    );
    assert!(
        joined.contains(&format!("{expected}(")),
        "the nest-access bridge has to survive the rewrite under the one name the rewriter chose, \
         `{expected}`, not disappear and not appear under a second spelling"
    );
    assert!(
        !joined.contains("-$$Nest"),
        "no reference may keep the original unwritable spelling once the declaration was rewritten"
    );
}
