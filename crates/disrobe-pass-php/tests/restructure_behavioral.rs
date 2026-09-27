#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery
)]

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use disrobe_pass_php::restructure::{RestructureReport, restructure};
use php_toolchain::{PhpRuntime, goto_count, require_php, required_corpus};

const OBFUSCATED: &str = "yakpro/controlflow_yakpro_3.0.0.php";
const ORIGINAL: &str = "yakpro/controlflow_original.php";

fn assert_structure_recovered(obfuscated: &[u8], report: &RestructureReport) {
    assert!(
        report.whiles_recovered >= 1,
        "the for/while loop must be recovered to a native while; source:\n{}",
        String::from_utf8_lossy(&report.source)
    );
    assert!(
        report.ifs_recovered >= 1,
        "the if/else must be recovered to native if/else; source:\n{}",
        String::from_utf8_lossy(&report.source)
    );
    let before: usize = goto_count(obfuscated);
    let after: usize = goto_count(&report.source);
    assert!(
        after < before,
        "restructure must reduce goto count before its output runs: before={before} after={after}"
    );
}

#[test]
#[should_panic(expected = "restructure must reduce goto count before its output runs")]
fn a_restructure_that_hands_back_its_input_is_refused_before_php_runs() {
    let obfuscated: Vec<u8> = required_corpus(OBFUSCATED);
    let passthrough: RestructureReport = RestructureReport {
        source: obfuscated.clone(),
        whiles_recovered: 1,
        ifs_recovered: 1,
        gotos_remaining: goto_count(&obfuscated),
    };
    assert_structure_recovered(&obfuscated, &passthrough);
}

#[test]
fn oracle_controlflow_restructures_and_runs_identically() {
    let obfuscated: Vec<u8> = required_corpus(OBFUSCATED);
    let original: Vec<u8> = required_corpus(ORIGINAL);

    let report: RestructureReport = restructure(&obfuscated).expect("restructure");
    assert_structure_recovered(&obfuscated, &report);

    let Some(php): Option<PhpRuntime> = require_php(
        "the yakpro-po restructure of corpus/php/yakpro/controlflow_yakpro_3.0.0.php, \
         re-executed under the real php interpreter",
    ) else {
        return;
    };
    let original_stdout: Vec<u8> = php.stdout_of(ORIGINAL, &original);
    assert!(
        !original_stdout.is_empty(),
        "{ORIGINAL}: the reference program prints nothing, so comparing stdout against it would \
         accept a recovery that also prints nothing"
    );
    let recovered_stdout: Vec<u8> = php.stdout_of("restructured controlflow", &report.source);
    assert_eq!(
        String::from_utf8_lossy(&recovered_stdout),
        String::from_utf8_lossy(&original_stdout),
        "restructured output must equal original output\nsource:\n{}",
        String::from_utf8_lossy(&report.source)
    );
}
