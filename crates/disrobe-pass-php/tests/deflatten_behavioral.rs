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

use disrobe_pass_php::deflatten::{DeflattenReport, deflatten};
use php_toolchain::{PhpRuntime, require_php, required_corpus};

fn graded_for(sample: &str) -> String {
    format!(
        "the yakpro-po deflatten of corpus/php/yakpro/{sample}, re-executed under the real php interpreter"
    )
}

fn contains_goto(src: &[u8]) -> bool {
    let lower: Vec<u8> = src.to_ascii_lowercase();
    lower.windows(5).any(|w: &[u8]| w == b"goto ")
}

fn assert_recovered_matches_original(obf_name: &str, orig_name: &str, require_goto_gone: bool) {
    let graded: String = graded_for(obf_name);
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let obfuscated: Vec<u8> = required_corpus(&format!("yakpro/{obf_name}"));
    let original: Vec<u8> = required_corpus(&format!("yakpro/{orig_name}"));

    assert!(
        contains_goto(&obfuscated),
        "{obf_name}: the committed sample is supposed to be goto-flattened, and it carries no \
         `goto ` at all; a deflatten graded over a sample that was never flattened proves nothing"
    );
    assert!(
        !contains_goto(&original),
        "{orig_name}: the reference source must be the unflattened original"
    );

    let original_stdout: Vec<u8> = php.stdout_of(orig_name, &original);
    assert!(
        !original_stdout.is_empty(),
        "{orig_name}: the reference program prints nothing under {}, so comparing stdout against \
         it would accept a recovery that also prints nothing",
        php.banner
    );
    let obfuscated_stdout: Vec<u8> = php.stdout_of(obf_name, &obfuscated);
    assert_eq!(
        obfuscated_stdout, original_stdout,
        "{obf_name}: the flattened sample does not behave like {orig_name}, so the pair is not a \
         valid before-and-after and nothing graded against it means anything"
    );

    let report: DeflattenReport =
        deflatten(&obfuscated).unwrap_or_else(|e| panic!("{obf_name}: deflatten failed: {e}"));
    let recovered: Vec<u8> = report.source;

    if require_goto_gone {
        assert!(
            !contains_goto(&recovered),
            "{obf_name}: deflattened output must drop the linear goto chain; got:\n{}",
            String::from_utf8_lossy(&recovered)
        );
    }

    let recovered_stdout: Vec<u8> = php.stdout_of(&format!("{obf_name} recovered"), &recovered);
    assert_eq!(
        String::from_utf8_lossy(&recovered_stdout),
        String::from_utf8_lossy(&original_stdout),
        "{obf_name}: the deflattened source does not print what {orig_name} prints\n--- recovered \
         ---\n{}",
        String::from_utf8_lossy(&recovered)
    );
}

#[test]
fn oracle_linear_goto_chain_deflattens_to_original_output() {
    assert_recovered_matches_original("calc_yakpro_3.0.0.php", "calc_original.php", true);
}

#[test]
fn oracle_control_flow_sample_runs_identically_after_deflatten() {
    assert_recovered_matches_original(
        "controlflow_yakpro_3.0.0.php",
        "controlflow_original.php",
        false,
    );
}
