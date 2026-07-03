#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::perl::{PerlOpTree, read_concise};
use disrobe_pass_scriptlang::lang::perl_decompile::{DecompileWalker, PerlSource, PerlSubSource};

const SAMPLE1_CONCISE: &[u8] = include_bytes!("fixtures/sample1.concise.txt");
const SAMPLE1_PL: &str = include_str!("fixtures/sample1.pl");

fn decompiled() -> PerlSource {
    let tree: PerlOpTree = read_concise(SAMPLE1_CONCISE).expect("parse real perl 5.42 concise");
    DecompileWalker::new(&tree).decompile()
}

fn sub<'a>(src: &'a PerlSource, name: &str) -> &'a PerlSubSource {
    src.subs
        .iter()
        .find(|s: &&PerlSubSource| s.name == name)
        .unwrap_or_else(|| panic!("sub '{name}' must be reconstructed from the real op-tree"))
}

#[test]
fn real_542_dump_parses_all_three_subs() {
    let tree: PerlOpTree = read_concise(SAMPLE1_CONCISE).expect("parse");
    for name in ["main::greet", "main::add", "main::area"] {
        assert!(
            tree.subs.iter().any(|s| s.name == name),
            "named sub '{name}' from the real -MO=Concise dump must be present: {:?}",
            tree.subs.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }
    assert!(tree.subs.iter().any(|s| s.is_main_program));
}

#[test]
fn real_542_signatures_match_source() {
    let src: PerlSource = decompiled();
    assert!(SAMPLE1_PL.contains("my ($name) = @_;"));
    assert!(SAMPLE1_PL.contains("my ($a, $b) = @_;"));
    assert!(SAMPLE1_PL.contains("my ($w, $h) = @_;"));
    assert_eq!(
        sub(&src, "main::greet").signature.as_deref(),
        Some("my ($name) = @_;")
    );
    assert_eq!(
        sub(&src, "main::add").signature.as_deref(),
        Some("my ($a, $b) = @_;")
    );
    assert_eq!(
        sub(&src, "main::area").signature.as_deref(),
        Some("my ($w, $h) = @_;")
    );
}

#[test]
fn real_542_bodies_reconstruct_against_source() {
    let src: PerlSource = decompiled();
    assert!(SAMPLE1_PL.contains(r#"return "Hello, $name!";"#));
    assert!(
        sub(&src, "main::greet")
            .statements
            .iter()
            .any(|s| s.text == r#"return "Hello, $name!";"#),
        "greet body: {:?}",
        sub(&src, "main::greet").statements
    );
    assert!(SAMPLE1_PL.contains("return $a + $b;"));
    assert!(
        sub(&src, "main::add")
            .statements
            .iter()
            .any(|s| s.text == "return $a + $b;"),
        "add body: {:?}",
        sub(&src, "main::add").statements
    );
    assert!(SAMPLE1_PL.contains("return $w * $h;"));
    assert!(
        sub(&src, "main::area")
            .statements
            .iter()
            .any(|s| s.text == "return $w * $h;"),
        "area body: {:?}",
        sub(&src, "main::area").statements
    );
}

#[test]
fn real_542_main_reconstructs_calls() {
    let src: PerlSource = decompiled();
    assert!(SAMPLE1_PL.contains(r#"my $msg = greet("disrobe");"#));
    let main: &PerlSubSource = sub(&src, "main program");
    assert!(
        main.statements
            .iter()
            .any(|s| s.text == r#"my $msg = greet("disrobe");"#),
        "main greet call: {:?}",
        main.statements
    );
    assert!(SAMPLE1_PL.contains("my $sum = add(2, 3);"));
    assert!(
        main.statements
            .iter()
            .any(|s| s.text == "my $sum = add(2, 3);"),
        "main add call: {:?}",
        main.statements
    );
}

#[test]
fn real_542_recovery_is_honest() {
    let src: PerlSource = decompiled();
    assert!(src.statements_total >= 6);
    assert!(src.statements_recovered <= src.statements_total);
    let ratio: f64 = src.recovery_ratio();
    assert!(
        ratio >= 0.75,
        "names-erased Perl op-tree ceiling ~0.75; real 5.42 measured {ratio}"
    );
}
