#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
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
use php_toolchain::{PhpRuntime, goto_count, require_php, required_corpus};

fn graded_for(sample: &str) -> String {
    format!(
        "the yakpro-po deflatten of corpus/php/yakpro/{sample}, re-executed under the real php interpreter"
    )
}

fn assert_goto_layer_undone(
    obf_name: &str,
    flattened_gotos: usize,
    report: &DeflattenReport,
    require_goto_gone: bool,
) {
    let remaining_gotos: usize = goto_count(&report.source);
    assert!(
        report.gotos_followed > 0 && remaining_gotos < flattened_gotos,
        "{obf_name}: deflatten followed {} gotos and left {remaining_gotos} of {flattened_gotos}, \
         so the yakpro-po goto layer was not undone and its output must not run; got:\n{}",
        report.gotos_followed,
        String::from_utf8_lossy(&report.source)
    );
    if require_goto_gone {
        assert_eq!(
            remaining_gotos,
            0,
            "{obf_name}: deflattened output must drop the linear goto chain; got:\n{}",
            String::from_utf8_lossy(&report.source)
        );
    }
}

#[test]
#[should_panic(expected = "so the yakpro-po goto layer was not undone and its output must not run")]
fn a_deflatten_that_hands_back_its_input_is_refused_before_php_runs() {
    let obfuscated: Vec<u8> = required_corpus("yakpro/controlflow_yakpro_3.0.0.php");
    let passthrough: DeflattenReport = DeflattenReport {
        source: obfuscated.clone(),
        labels_dropped: 0,
        gotos_followed: 1,
        strings_decoded: 0,
    };
    assert_goto_layer_undone(
        "controlflow_yakpro_3.0.0.php",
        goto_count(&obfuscated),
        &passthrough,
        false,
    );
}

fn assert_recovered_matches_original(obf_name: &str, orig_name: &str, require_goto_gone: bool) {
    let obfuscated: Vec<u8> = required_corpus(&format!("yakpro/{obf_name}"));
    let original: Vec<u8> = required_corpus(&format!("yakpro/{orig_name}"));
    let flattened_gotos: usize = goto_count(&obfuscated);

    assert!(
        flattened_gotos > 0,
        "{obf_name}: the committed sample is supposed to be goto-flattened, and it carries no \
         `goto ` at all; a deflatten graded over a sample that was never flattened proves nothing"
    );
    assert_eq!(
        goto_count(&original),
        0,
        "{orig_name}: the reference source must be the unflattened original"
    );

    let report: DeflattenReport =
        deflatten(&obfuscated).unwrap_or_else(|e| panic!("{obf_name}: deflatten failed: {e}"));
    assert_goto_layer_undone(obf_name, flattened_gotos, &report, require_goto_gone);
    let recovered: Vec<u8> = report.source;

    let graded: String = graded_for(obf_name);
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let original_stdout: Vec<u8> = php.stdout_of(orig_name, &original);
    assert!(
        !original_stdout.is_empty(),
        "{orig_name}: the reference program prints nothing under {}, so comparing stdout against \
         it would accept a recovery that also prints nothing",
        php.banner
    );

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
