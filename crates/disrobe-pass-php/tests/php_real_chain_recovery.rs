#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use disrobe_pass_php::{RecoveryStage, recover_php};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/php_real_chains"
);

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn recover(name: &str) -> String {
    let bytes: Vec<u8> = load(name);
    recover_php(&bytes, None)
        .unwrap_or_else(|e| panic!("recover {name}: {e}"))
        .output
}

fn assert_recovers_original(name: &str) {
    let out: String = recover(name);
    assert!(
        out.contains("function greet") && out.contains("echo greet('world')"),
        "{name}: recovered output is missing the original source body; got:\n{out}"
    );
    assert!(
        !out.contains("base64_decode")
            && !out.contains("gzinflate")
            && !out.contains("gzuncompress")
            && !out.contains("gzdecode")
            && !out.contains("str_rot13")
            && !out.contains("strrev")
            && !out.contains("eval(")
            && !out.contains("pack("),
        "{name}: a decode primitive survived in the recovered output; got:\n{out}"
    );
}

#[test]
fn concatenation_hex_named_variable_function_chain_recovers() {
    assert_recovers_original("h_hexname.php");
}

#[test]
fn eval_chain_embedded_in_surrounding_inline_html_recovers() {
    assert_recovers_original("h_htmlwrap.php");
}

#[test]
fn eval_chain_decoding_to_goto_flattened_code_is_fully_unrolled() {
    let out: String = recover("r_gotochain.php");
    assert!(
        out.contains("function greet") && out.contains("echo greet('world')"),
        "r_gotochain.php: original body missing; got:\n{out}"
    );
    assert!(
        !out.to_ascii_lowercase().contains("goto "),
        "r_gotochain.php: goto scrambling survived after peel + deflatten; got:\n{out}"
    );
}

#[test]
fn preg_replace_e_modifier_loader_recovers_replacement_body() {
    assert_recovers_original("p_preg.php");
    assert_recovers_original("p_preg2.php");
}

#[test]
fn decoy_padded_and_globals_indirection_chains_recover() {
    assert_recovers_original("p_decoy.php");
    assert_recovers_original("p_globals.php");
}

#[test]
fn five_layer_and_double_base64_chains_recover() {
    assert_recovers_original("p_deep5.php");
    assert_recovers_original("s_doubleb64.php");
}

#[test]
fn pack_hex_eval_recovers() {
    assert_recovers_original("h_packhex.php");
}

#[test]
fn clean_control_yields_no_obfuscation_recovery() {
    let bytes: Vec<u8> = load("clean_control.php");
    let report = recover_php(&bytes, None).expect("recover clean");
    assert_eq!(
        report.stage,
        RecoveryStage::PlainSource,
        "a clean file must not be reported as obfuscated; notes: {:?}",
        report.notes
    );
    assert!(
        report.output.contains("function greet"),
        "clean control passthrough lost the source; got:\n{}",
        report.output
    );
}

#[test]
fn runtime_sourced_key_walls_instead_of_fabricating_plaintext() {
    let bytes: Vec<u8> = load("runtime_key.php");
    let report = recover_php(&bytes, None).expect("recover runtime-key");
    assert!(
        !report.output.contains("function greet"),
        "a $_GET-sourced eval key is not present in the file; recovery must not fabricate a body; got:\n{}",
        report.output
    );
}
