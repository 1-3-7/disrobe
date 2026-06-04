#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_scriptlang::lang::perl::{PerlOpTree, read_concise};
use disrobe_pass_scriptlang::lang::perl_decompile::{DecompileWalker, PerlSource, PerlSubSource};

const HELLO_CONCISE: &[u8] = include_bytes!("fixtures/hello.concise.txt");
const HELLO_PL: &str = include_str!("fixtures/hello.pl");

fn decompiled() -> PerlSource {
    let tree: PerlOpTree = read_concise(HELLO_CONCISE).expect("parse concise");
    DecompileWalker::new(&tree).decompile()
}

fn sub<'a>(src: &'a PerlSource, name: &str) -> &'a PerlSubSource {
    src.subs
        .iter()
        .find(|s: &&PerlSubSource| s.name == name)
        .unwrap_or_else(|| panic!("sub '{name}' must be reconstructed"))
}

#[test]
fn rendered_source_tokens_match_original_hello_pl() {
    let src: PerlSource = decompiled();
    let rendered: &str = &src.rendered;
    for token in [
        "sub greet",
        "sub add",
        "my ($name) = @_;",
        "my ($a, $b) = @_;",
        "return",
        "$name",
        "$a",
        "$b",
        "greet(",
        "\"disrobe\"",
        "print",
    ] {
        assert!(
            rendered.contains(token),
            "token '{token}' present in original hello.pl must appear in the recovered source:\n{rendered}"
        );
    }
}

#[test]
fn original_lexical_names_round_trip_against_source() {
    let src: PerlSource = decompiled();
    for lexical in ["$name", "$a", "$b", "$msg"] {
        assert!(
            HELLO_PL.contains(lexical),
            "fixture sanity: '{lexical}' is in hello.pl"
        );
        assert!(
            src.rendered.contains(lexical),
            "lexical '{lexical}' from hello.pl must survive in the pad and be recovered:\n{}",
            src.rendered
        );
    }
}

#[test]
fn greet_body_matches_original_return_against_source() {
    assert!(HELLO_PL.contains(r#"return "Hello, $name!";"#));
    let src: PerlSource = decompiled();
    let greet: &PerlSubSource = sub(&src, "main::greet");
    assert!(
        greet
            .statements
            .iter()
            .any(|s| s.text == r#"return "Hello, $name!";"#),
        "greet body must reconstruct the original return verbatim: {:?}",
        greet.statements
    );
}

#[test]
fn add_body_matches_original_arithmetic_against_source() {
    assert!(HELLO_PL.contains("return $a + $b;"));
    let src: PerlSource = decompiled();
    let add: &PerlSubSource = sub(&src, "main::add");
    assert!(
        add.statements.iter().any(|s| s.text == "return $a + $b;"),
        "add body must reconstruct '$a + $b' from the binary-op + pad names: {:?}",
        add.statements
    );
}

#[test]
fn main_program_reconstructs_call_and_assignment() {
    assert!(HELLO_PL.contains(r#"my $msg = greet("disrobe");"#));
    let src: PerlSource = decompiled();
    let main: &PerlSubSource = sub(&src, "main program");
    assert!(
        main.statements
            .iter()
            .any(|s| s.text == r#"my $msg = greet("disrobe");"#),
        "main must reconstruct the greet call assigned to $msg: {:?}",
        main.statements
    );
}

#[test]
fn recovery_is_measured_and_honest() {
    let src: PerlSource = decompiled();
    assert!(
        src.statements_total >= 4,
        "expected at least the greet/add returns plus two main statements; got {}",
        src.statements_total
    );
    assert!(src.statements_recovered <= src.statements_total);
    let ratio: f64 = src.recovery_ratio();
    assert!(
        ratio >= 0.75,
        "names-erased Perl op-tree ceiling is ~0.75; measured recovery was {ratio}"
    );
}
