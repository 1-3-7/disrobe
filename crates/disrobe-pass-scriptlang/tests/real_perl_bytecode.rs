#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::PerlOpTree;
use disrobe_pass_scriptlang::lang::perl::PerlSub;
use disrobe_pass_scriptlang::lang::perl_bytecode::{is_bytecode, read_bytecode};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

const HELLO_PLC: &[u8] = include_bytes!("../../../corpus/scriptlang/perl/hello.plc");
const HELLO_DISASM: &str = include_str!("../../../corpus/scriptlang/perl/hello.disasm.txt");

fn ground_truth_opcodes() -> Vec<&'static str> {
    HELLO_DISASM
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty())
        .collect()
}

#[test]
fn real_bytecode_is_detected_and_classified() {
    assert!(is_bytecode(HELLO_PLC));
    assert_eq!(classify(HELLO_PLC), Some(ScriptLang::Perl));
}

#[test]
fn real_bytecode_analyzes_as_perl() {
    let art: ScriptArtifact = analyze(HELLO_PLC).expect("analyze real plc");
    match art {
        ScriptArtifact::Perl(tree) => assert!(tree.op_count > 100),
        other => panic!("expected Perl artifact from real bytecode, got {other:?}"),
    }
}

#[test]
fn real_bytecode_header_matches_producer() {
    let tree: PerlOpTree = read_bytecode(HELLO_PLC).expect("parse real plc");
    assert_eq!(
        tree.source_hint.as_deref(),
        Some("MSWin32-x86-multi-thread"),
        "archname from the perl 5.8.9 header must be recovered as the source hint"
    );
}

#[test]
fn real_bytecode_opcode_stream_matches_disassembler() {
    let tree: PerlOpTree = read_bytecode(HELLO_PLC).expect("parse real plc");
    let main: &PerlSub = tree
        .subs
        .first()
        .expect("real bytecode must produce the main program op tree");

    let expected: Vec<&str> = ground_truth_opcodes();
    let actual: Vec<&str> = main.ops.iter().map(|o| o.name.as_str()).collect();

    assert_eq!(
        actual.len(),
        expected.len(),
        "decoder walked {} ops, B::Disassembler emitted {}",
        actual.len(),
        expected.len()
    );

    for (i, (got, want)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            got,
            want,
            "opcode {i} mismatch: decoder={got} ground-truth={want} (preceding: {:?})",
            &actual[i.saturating_sub(4)..i]
        );
    }

    assert_eq!(
        actual.last().copied(),
        Some("ret"),
        "the real stream terminates in ret"
    );
}

#[test]
fn real_bytecode_recovers_embedded_names_and_constants() {
    let tree: PerlOpTree = read_bytecode(HELLO_PLC).expect("parse real plc");
    let main: &PerlSub = tree.subs.first().expect("main op tree");

    for sub_name in ["main::add", "main::greet"] {
        assert!(
            main.called_subs.iter().any(|s: &String| s == sub_name),
            "glob name '{sub_name}' from the real bytecode must be harvested: {:?}",
            main.called_subs
        );
    }

    for literal in ["$a", "$b", "main"] {
        assert!(
            main.constants.iter().any(|c: &String| c == literal),
            "PV '{literal}' from the real bytecode must be recovered: {:?}",
            main.constants
        );
    }
}
