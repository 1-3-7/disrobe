#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::perl::{PerlOpTree, read_concise};
use disrobe_pass_scriptlang::lang::perl_decompile::{
    DecompileWalker, PerlSource, PerlStatement, PerlSubSource,
};

const RICH_CONCISE: &[u8] = include_bytes!("fixtures/rich.concise.txt");
const RICH_PL: &str = include_str!("fixtures/rich.pl");
const OPS_CONCISE: &[u8] = include_bytes!("fixtures/ops.concise.txt");
const OPS_PL: &str = include_str!("fixtures/ops.pl");
const CTL_CONCISE: &[u8] = include_bytes!("fixtures/ctl.concise.txt");
const CTL_PL: &str = include_str!("fixtures/ctl.pl");

fn decompile(bytes: &[u8]) -> PerlSource {
    let tree: PerlOpTree = read_concise(bytes).expect("parse real perl 5.42 concise");
    DecompileWalker::new(&tree).decompile()
}

fn sub<'a>(src: &'a PerlSource, name: &str) -> &'a PerlSubSource {
    src.subs
        .iter()
        .find(|s: &&PerlSubSource| s.name == name)
        .unwrap_or_else(|| panic!("sub '{name}' must be reconstructed from the real op-tree"))
}

fn has_stmt(sub: &PerlSubSource, text: &str) -> bool {
    sub.statements
        .iter()
        .any(|s: &PerlStatement| s.text == text)
}

#[test]
fn rich_recovers_if_with_return_branch_against_source() {
    assert!(RICH_PL.contains("if ($n > 10) {"));
    assert!(RICH_PL.contains(r#"return "big";"#));
    let src: PerlSource = decompile(RICH_CONCISE);
    let classify: &PerlSubSource = sub(&src, "main::classify");
    assert!(
        has_stmt(classify, r#"if ($n > 10) { return "big"; }"#),
        "if/return branch must reconstruct from and+gt+return: {:?}",
        classify.statements
    );
    assert!(
        has_stmt(classify, r#"return "small";"#),
        "trailing return after the conditional must survive: {:?}",
        classify.statements
    );
}

#[test]
fn rich_recovers_my_scalar_and_in_place_arithmetic_against_source() {
    assert!(RICH_PL.contains("my $sum = $a + $b;"));
    assert!(RICH_PL.contains("$sum = $sum + $c;"));
    let src: PerlSource = decompile(RICH_CONCISE);
    let total: &PerlSubSource = sub(&src, "main::total");
    assert!(
        has_stmt(total, "my $sum = $a + $b;"),
        "lexical-scalar add assignment must reconstruct: {:?}",
        total.statements
    );
    assert!(
        has_stmt(total, "$sum = $sum + $c;"),
        "in-place TARGMY reassignment must reconstruct: {:?}",
        total.statements
    );
    assert!(has_stmt(total, "return $sum;"));
}

#[test]
fn rich_recovers_while_loop_against_source() {
    assert!(RICH_PL.contains("my $acc = 0;"));
    assert!(RICH_PL.contains("while ($acc < $limit) {"));
    assert!(RICH_PL.contains("$acc = $acc + 1;"));
    let src: PerlSource = decompile(RICH_CONCISE);
    let loop_sum: &PerlSubSource = sub(&src, "main::loop_sum");
    assert!(
        has_stmt(loop_sum, "my $acc = 0;"),
        "scalar-zero initialiser must reconstruct: {:?}",
        loop_sum.statements
    );
    assert!(
        has_stmt(loop_sum, "while ($acc < $limit) { $acc = $acc + 1; }"),
        "while loop with comparison guard and in-place body must reconstruct: {:?}",
        loop_sum.statements
    );
    assert!(has_stmt(loop_sum, "return $acc;"));
}

#[test]
fn rich_recovers_interpolated_print_in_source_order() {
    assert!(RICH_PL.contains(r#"print "$x\n";"#));
    let src: PerlSource = decompile(RICH_CONCISE);
    let main: &PerlSubSource = sub(&src, "main program");
    assert!(
        has_stmt(main, r#"print "$x\n";"#),
        "multiconcat interpolation must place the lexical before the trailing newline: {:?}",
        main.statements
    );
    assert!(
        has_stmt(main, r#"print "$t\n";"#),
        "second interpolated print must reconstruct in source order: {:?}",
        main.statements
    );
    assert!(
        has_stmt(main, "my $count = 4;"),
        "bare integer-constant lexical assignment must reconstruct: {:?}",
        main.statements
    );
}

#[test]
fn rich_recovery_is_total_on_this_corpus() {
    let src: PerlSource = decompile(RICH_CONCISE);
    assert_eq!(
        src.statements_recovered, src.statements_total,
        "every statement in rich.pl is structurally recoverable from its op-tree; rendered:\n{}",
        src.rendered
    );
    assert!(src.statements_total >= 12);
    assert!((src.recovery_ratio() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn ops_recovers_comparison_operators_against_source() {
    for token in ["$a == $b", "$a < $b", "$a >= $b", "$a % $b"] {
        assert!(OPS_PL.contains(token), "fixture sanity: {token}");
    }
    let src: PerlSource = decompile(OPS_CONCISE);
    let cmps: &PerlSubSource = sub(&src, "main::cmps");
    assert!(has_stmt(cmps, "my $p = $a == $b;"), "{:?}", cmps.statements);
    assert!(has_stmt(cmps, "my $q = $a < $b;"), "{:?}", cmps.statements);
    assert!(has_stmt(cmps, "my $r = $a >= $b;"), "{:?}", cmps.statements);
    assert!(has_stmt(cmps, "my $u = $a % $b;"), "{:?}", cmps.statements);
}

#[test]
fn ops_recovers_binary_with_constant_operand_against_source() {
    assert!(OPS_PL.contains("my $y = $x * 2;"));
    assert!(OPS_PL.contains("$y = $y - 1;"));
    let src: PerlSource = decompile(OPS_CONCISE);
    let assigns: &PerlSubSource = sub(&src, "main::assigns");
    assert!(
        has_stmt(assigns, "my $y = $x * 2;"),
        "pad * const must keep the constant operand in order: {:?}",
        assigns.statements
    );
    assert!(
        has_stmt(assigns, "$y = $y - 1;"),
        "in-place subtract of a constant must reconstruct: {:?}",
        assigns.statements
    );
    assert!(has_stmt(assigns, "my $z = $x;"));
}

#[test]
fn ops_concat_multiconcat_keeps_my_intro() {
    assert!(OPS_PL.contains("my $s = $a . $b;"));
    let src: PerlSource = decompile(OPS_CONCISE);
    let cmps: &PerlSubSource = sub(&src, "main::cmps");
    assert!(
        has_stmt(cmps, "my $s = $a . $b;"),
        "an LVINTRO multiconcat without the STRINGIFY private flag came from the concat operator, not from interpolation, and must render as `$a . $b`: {:?}",
        cmps.statements
    );
}

#[test]
fn ctl_recovers_bare_if_and_unless_against_source() {
    assert!(CTL_PL.contains("if ($flag) {"));
    assert!(CTL_PL.contains("unless ($n == 0) {"));
    let src: PerlSource = decompile(CTL_CONCISE);
    let bare_if: &PerlSubSource = sub(&src, "main::bare_if");
    assert!(
        has_stmt(bare_if, "if ($flag) { return 1; }"),
        "bare-boolean if (no comparison op) must reconstruct: {:?}",
        bare_if.statements
    );
    assert!(has_stmt(bare_if, "return 0;"));
    let use_unless: &PerlSubSource = sub(&src, "main::use_unless");
    assert!(
        has_stmt(use_unless, "unless ($n == 0) { return $n; }"),
        "or-guarded statement-modifier compiles to unless and must reconstruct: {:?}",
        use_unless.statements
    );
    assert!(has_stmt(use_unless, "return 99;"));
}

#[test]
fn ctl_recovery_is_total_on_this_corpus() {
    let src: PerlSource = decompile(CTL_CONCISE);
    assert_eq!(src.statements_recovered, src.statements_total);
}

#[test]
fn statement_recovery_is_measured_and_bounded() {
    for bytes in [RICH_CONCISE, OPS_CONCISE, CTL_CONCISE] {
        let src: PerlSource = decompile(bytes);
        assert!(src.statements_total > 0);
        assert!(src.statements_recovered <= src.statements_total);
        let ratio: f64 = src.recovery_ratio();
        assert!((0.0..=1.0).contains(&ratio), "ratio {ratio}");
    }
}
