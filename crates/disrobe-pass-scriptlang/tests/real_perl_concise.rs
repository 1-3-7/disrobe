#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_scriptlang::lang::perl::{PerlOpTree, PerlSub, is_concise, read_concise};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

const HELLO_CONCISE: &[u8] = include_bytes!("fixtures/hello.concise.txt");

fn sub_named<'a>(tree: &'a PerlOpTree, name: &str) -> &'a PerlSub {
    tree.subs
        .iter()
        .find(|s: &&PerlSub| s.name == name)
        .unwrap_or_else(|| panic!("sub '{name}' must be present; got {:?}", names(tree)))
}

fn names(tree: &PerlOpTree) -> Vec<String> {
    tree.subs.iter().map(|s: &PerlSub| s.name.clone()).collect()
}

#[test]
fn real_concise_is_detected() {
    assert!(is_concise(HELLO_CONCISE));
    assert_eq!(classify(HELLO_CONCISE), Some(ScriptLang::Perl));
}

#[test]
fn real_concise_recovers_sub_names_oracle() {
    let tree: PerlOpTree = read_concise(HELLO_CONCISE).expect("parse");
    assert!(
        tree.subs.iter().any(|s: &PerlSub| s.name == "main::greet"),
        "sub greet defined in hello.pl must be recovered: {:?}",
        names(&tree)
    );
    assert!(
        tree.subs.iter().any(|s: &PerlSub| s.name == "main::add"),
        "sub add defined in hello.pl must be recovered: {:?}",
        names(&tree)
    );
    assert!(
        tree.subs.iter().any(|s: &PerlSub| s.is_main_program),
        "main program block must be present"
    );
}

#[test]
fn real_concise_recovers_lexicals_oracle() {
    let tree: PerlOpTree = read_concise(HELLO_CONCISE).expect("parse");
    let greet: &PerlSub = sub_named(&tree, "main::greet");
    assert!(
        greet.pad_vars.iter().any(|v: &String| v == "$name"),
        "lexical $name from greet() must be recovered: {:?}",
        greet.pad_vars
    );
    let add: &PerlSub = sub_named(&tree, "main::add");
    assert!(
        add.pad_vars.iter().any(|v: &String| v == "$a"),
        "lexical $a from add() must be recovered: {:?}",
        add.pad_vars
    );
    assert!(
        add.pad_vars.iter().any(|v: &String| v == "$b"),
        "lexical $b from add() must be recovered: {:?}",
        add.pad_vars
    );
}

#[test]
fn real_concise_recovers_constants_and_calls_oracle() {
    let tree: PerlOpTree = read_concise(HELLO_CONCISE).expect("parse");
    let all_consts: Vec<String> = tree
        .subs
        .iter()
        .flat_map(|s: &PerlSub| s.constants.iter().cloned())
        .collect();
    assert!(
        all_consts.iter().any(|c: &String| c.contains("disrobe")),
        "string constant \"disrobe\" from source must be recovered: {all_consts:?}"
    );
    let all_calls: Vec<String> = tree
        .subs
        .iter()
        .flat_map(|s: &PerlSub| s.called_subs.iter().cloned())
        .collect();
    assert!(
        all_calls.iter().any(|c: &String| c == "greet"),
        "call to greet() from main must be recovered: {all_calls:?}"
    );
    assert!(
        all_calls.iter().any(|c: &String| c == "add"),
        "call to add() from main must be recovered: {all_calls:?}"
    );
}

#[test]
fn real_concise_analyze_returns_perl_artifact() {
    let art: ScriptArtifact = analyze(HELLO_CONCISE).expect("analyze");
    match art {
        ScriptArtifact::Perl(tree) => assert!(tree.op_count > 10),
        other => panic!("expected Perl artifact, got {other:?}"),
    }
}
