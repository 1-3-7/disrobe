#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
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

use disrobe_pass_php::{PeelOptions, PeelReport, peel_eval_chain};
use php_toolchain::{PhpRun, PhpRuntime, require_php, residual_decode_primitives, with_open_tag};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoaderRuns {
    OnThisInterpreter,
    NeverBecauseEvalIsNotCallableIndirectly,
}

fn graded_for(label: &str) -> String {
    format!("the {label} peel, re-executed under the real php interpreter")
}

fn generate_loader(php: &PhpRuntime, label: &str, builder_php: &str) -> Vec<u8> {
    let loader: Vec<u8> = php.stdout_of(&format!("{label} generator"), builder_php.as_bytes());
    assert!(
        !loader.is_empty(),
        "{label}: the generator script printed no loader, so nothing was peeled"
    );
    loader
}

fn peel_to_source(label: &str, loader: &[u8]) -> String {
    let report: PeelReport = peel_eval_chain(loader, PeelOptions::default()).unwrap_or_else(|e| {
        panic!(
            "{label}: peel failed: {e}\nloader was:\n{}",
            String::from_utf8_lossy(loader)
        )
    });
    String::from_utf8_lossy(&report.final_source).into_owned()
}

fn assert_loader_runnability(
    php: &PhpRuntime,
    label: &str,
    loader: &[u8],
    original_stdout: &[u8],
    runs: LoaderRuns,
) {
    match runs {
        LoaderRuns::OnThisInterpreter => {
            let loader_stdout: Vec<u8> = php.stdout_of(&format!("{label} loader"), loader);
            assert_eq!(
                loader_stdout, original_stdout,
                "{label}: the generated loader does not reproduce the payload it wraps, so the \
                 fixture itself is wrong and nothing downstream of it grades the peel"
            );
        }
        LoaderRuns::NeverBecauseEvalIsNotCallableIndirectly => {
            let run: PhpRun = php.run_reporting_errors(&format!("{label} loader"), loader);
            assert!(
                !run.exited_clean,
                "{label}: this loader reaches eval through a variable function, which php rejects, \
                 so it is pinned as a static-recovery-only fixture. It now runs under {}, which \
                 means the pin is stale and the case can be graded by executing the loader too.",
                php.banner
            );
            assert!(
                run.stderr.contains("undefined function eval"),
                "{label}: this loader is pinned to fail for one specific reason, that php cannot \
                 call eval through a variable; it failed for another reason instead, so what the \
                 peel is graded against is no longer understood: {}",
                run.stderr
            );
        }
    }
}

fn behavioral_roundtrip(label: &str, payload: &str, builder_php: &str, runs: LoaderRuns) {
    let graded: String = graded_for(label);
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };

    let original_full: String = format!("<?php {payload}");
    let original_stdout: Vec<u8> =
        php.stdout_of(&format!("{label} original"), original_full.as_bytes());
    assert!(
        !original_stdout.is_empty(),
        "{label}: the original payload prints nothing, so comparing stdout against it would accept \
         any recovery that also prints nothing"
    );

    let loader: Vec<u8> = generate_loader(&php, label, builder_php);
    assert_loader_runnability(&php, label, &loader, &original_stdout, runs);

    let recovered: String = peel_to_source(label, &loader);
    let recovered_full: String = with_open_tag(&recovered);
    let recovered_stdout: Vec<u8> =
        php.stdout_of(&format!("{label} recovered"), recovered_full.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&recovered_stdout),
        String::from_utf8_lossy(&original_stdout),
        "{label}: the recovered source produced different output than the original \
         payload\n--- recovered ---\n{recovered_full}"
    );

    let residual: Vec<&'static str> = residual_decode_primitives(&recovered);
    assert!(
        residual.is_empty(),
        "{label}: the recovered source prints the right thing but still calls {residual:?}, so a \
         layer was left on; a loader missing one peel executes identically to the recovered \
         program\n--- recovered ---\n{recovered_full}"
    );
}

const PAYLOAD: &str = "echo 'recovered-and-re-executed:' . (7 * 6);";

#[test]
fn oracle_multi_statement_b64_gzinflate_loader() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode(gzdeflate($payload));
echo "<?php\n";
echo "\$a = '$blob';\n";
echo "\$b = base64_decode(\$a);\n";
echo "\$c = gzinflate(\$b);\n";
echo "eval(\$c);\n";
"#;
    behavioral_roundtrip(
        "multi-statement base64+gzinflate",
        PAYLOAD,
        builder,
        LoaderRuns::OnThisInterpreter,
    );
}

#[test]
fn oracle_multi_statement_gzuncompress_loader() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode(gzcompress($payload));
echo "<?php\n";
echo "\$data = '$blob';\n";
echo "\$step1 = base64_decode(\$data);\n";
echo "\$step2 = gzuncompress(\$step1);\n";
echo "eval(\$step2);\n";
"#;
    behavioral_roundtrip(
        "multi-statement gzuncompress",
        PAYLOAD,
        builder,
        LoaderRuns::OnThisInterpreter,
    );
}

#[test]
fn oracle_str_rot13_over_base64_loader() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = str_rot13(base64_encode($payload));
echo "<?php\n";
echo "\$e = '$blob';\n";
echo "\$d = base64_decode(str_rot13(\$e));\n";
echo "eval(\$d);\n";
"#;
    behavioral_roundtrip(
        "str_rot13 over base64",
        PAYLOAD,
        builder,
        LoaderRuns::OnThisInterpreter,
    );
}

#[test]
fn oracle_concat_function_name_loader() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$decoder = 'bas' . 'e64_' . 'decode';\n";
echo "\$runner = 'ev' . 'al';\n";
echo "\$runner(\$decoder('$blob'));\n";
"#;
    behavioral_roundtrip(
        "concatenated function name",
        PAYLOAD,
        builder,
        LoaderRuns::NeverBecauseEvalIsNotCallableIndirectly,
    );
}

#[test]
fn oracle_chr_concat_function_name_loader() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$a = chr(101) . chr(118) . chr(97) . chr(108);\n";
echo "\$d = chr(98).chr(97).chr(115).chr(101).chr(54).chr(52).chr(95).chr(100).chr(101).chr(99).chr(111).chr(100).chr(101);\n";
echo "\$a(\$d('$blob'));\n";
"#;
    behavioral_roundtrip(
        "chr-concatenated function name",
        PAYLOAD,
        builder,
        LoaderRuns::NeverBecauseEvalIsNotCallableIndirectly,
    );
}

#[test]
fn oracle_hex_chr_concat_function_name_loader() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$a = chr(0x65) . chr(0x76) . chr(0x61) . chr(0x6c);\n";
echo "\$d = chr(0x62).chr(0x61).chr(0x73).chr(0x65).chr(0x36).chr(0x34).chr(0x5f).chr(0x64).chr(0x65).chr(0x63).chr(0x6f).chr(0x64).chr(0x65);\n";
echo "\$a(\$d('$blob'));\n";
"#;
    behavioral_roundtrip(
        "hex chr-concatenated function name",
        PAYLOAD,
        builder,
        LoaderRuns::NeverBecauseEvalIsNotCallableIndirectly,
    );
}

#[test]
fn oracle_globals_indirection_function_call_loader() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "\$GLOBALS['r'] = 'ev' . 'al';\n";
echo "\$GLOBALS['d'] = 'base64_' . 'decode';\n";
echo "\$GLOBALS['r'](\$GLOBALS['d']('$blob'));\n";
"#;
    behavioral_roundtrip(
        "GLOBALS indirection",
        PAYLOAD,
        builder,
        LoaderRuns::NeverBecauseEvalIsNotCallableIndirectly,
    );
}

#[test]
fn oracle_preg_replace_e_modifier_loader() {
    let label: &str = "preg_replace /e modifier";
    let graded: String = graded_for(label);
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let payload: &str = "echo 'preg-e-recovered:' . (3 + 4);";
    let builder: &str = r#"<?php
$payload = "echo 'preg-e-recovered:' . (3 + 4);";
$blob = base64_encode($payload);
echo "<?php\n";
echo "preg_replace('/(.*)/e', base64_decode('$blob'), '');\n";
"#;
    let original_full: String = format!("<?php {payload}");
    let original_stdout: Vec<u8> =
        php.stdout_of(&format!("{label} original"), original_full.as_bytes());
    assert!(
        !original_stdout.is_empty(),
        "{label}: the original payload prints nothing, so stdout comparison would grade nothing"
    );

    let loader: Vec<u8> = generate_loader(&php, label, builder);
    let recovered: String = peel_to_source(label, &loader);
    let recovered_full: String = with_open_tag(&recovered);
    let recovered_stdout: Vec<u8> =
        php.stdout_of(&format!("{label} recovered"), recovered_full.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&recovered_stdout),
        String::from_utf8_lossy(&original_stdout),
        "{label}: the recovered replacement body did not re-execute to the same \
         output\n--- recovered ---\n{recovered_full}"
    );
    let residual: Vec<&'static str> = residual_decode_primitives(&recovered);
    assert!(
        residual.is_empty(),
        "{label}: the recovered body still calls {residual:?}\n--- recovered ---\n{recovered_full}"
    );
}

#[test]
fn oracle_deep_chain_strrev_b64_gzinflate_multi_statement() {
    let builder: &str = r#"<?php
$payload = "echo 'recovered-and-re-executed:' . (7 * 6);";
$blob = strrev(base64_encode(gzdeflate($payload)));
echo "<?php\n";
echo "\$p = '$blob';\n";
echo "\$q = strrev(\$p);\n";
echo "\$r = base64_decode(\$q);\n";
echo "\$s = gzinflate(\$r);\n";
echo "eval(\$s);\n";
"#;
    behavioral_roundtrip(
        "deep strrev+base64+gzinflate chain",
        PAYLOAD,
        builder,
        LoaderRuns::OnThisInterpreter,
    );
}

#[test]
fn oracle_plain_source_passes_through_unchanged() {
    let label: &str = "plain source passthrough";
    let graded: String = graded_for(label);
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let plain: &[u8] = b"<?php echo 'no obfuscation here:' . (1 + 1);";
    let plain_stdout: Vec<u8> = php.stdout_of(label, plain);
    assert_eq!(
        String::from_utf8_lossy(&plain_stdout),
        "no obfuscation here:2",
        "{label}: the reference program does not print what this case is written around"
    );
    let outcome: disrobe_pass_php::Result<PeelReport> =
        peel_eval_chain(plain, PeelOptions::default());
    let Ok(report): disrobe_pass_php::Result<PeelReport> = outcome else {
        return;
    };
    let recovered: String = String::from_utf8_lossy(&report.final_source).into_owned();
    let recovered_stdout: Vec<u8> = php.stdout_of(
        &format!("{label} recovered"),
        with_open_tag(&recovered).as_bytes(),
    );
    assert_eq!(
        recovered_stdout, plain_stdout,
        "{label}: a file with nothing to peel must be handed back running identically; \
         got:\n{recovered}"
    );
}
