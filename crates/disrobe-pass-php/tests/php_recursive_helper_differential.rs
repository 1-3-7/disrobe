#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::print_stdout,
    clippy::print_stderr,
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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use disrobe_pass_php::{RecoveryReport, RecoveryStage, recover_php};
use php_toolchain::{PhpRuntime, require_php, residual_decode_primitives, with_open_tag};

const MARKER: &str = "DISROBE-PHP-HELPER-8B2E";
const XOR_BYTE: u8 = 42;

fn payload() -> String {
    format!("echo '{MARKER}';")
}

fn b64(bytes: &[u8]) -> String {
    B64_STD.encode(bytes)
}

fn xored_payload_b64() -> String {
    b64(&payload()
        .bytes()
        .map(|b: u8| b ^ XOR_BYTE)
        .collect::<Vec<u8>>())
}

fn recover_and_grade(label: &str, obfuscated: &[u8]) -> String {
    let graded: String = format!("the {label} recursive helper against the real php interpreter");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return String::new();
    };

    let obf_stdout: Vec<u8> = php.stdout_of(label, obfuscated);
    let obf_text: String = String::from_utf8_lossy(&obf_stdout).into_owned();
    assert!(
        obf_text.contains(MARKER),
        "{label}: the loader itself does not print {MARKER:?} under {}; got {obf_text:?}. Grading \
         a recovery against an input that never produced the marker would grade nothing.",
        php.banner
    );

    let report: RecoveryReport = recover_php(obfuscated, None)
        .unwrap_or_else(|e: disrobe_pass_php::Error| panic!("{label}: recover failed: {e}"));
    assert_ne!(
        report.stage,
        RecoveryStage::PlainSource,
        "{label}: an obfuscated helper loader must not be reported as plain source"
    );
    assert!(
        !report.output.is_empty(),
        "{label}: recovery produced no source to grade"
    );

    let recovered_source: String = with_open_tag(&report.output);
    let recovered_stdout: Vec<u8> = php.stdout_of(label, recovered_source.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&recovered_stdout),
        String::from_utf8_lossy(&obf_stdout),
        "{label}: the recovered source is not behaviorally equivalent to the loader under \
         {}\n--- recovered ---\n{recovered_source}",
        php.banner
    );

    let residual: Vec<&'static str> = residual_decode_primitives(&report.output);
    assert!(
        residual.is_empty(),
        "{label}: the recovered source runs to the same output but still calls {residual:?}, so \
         the helper was never actually evaluated.\n--- recovered ---\n{recovered_source}"
    );
    report.output
}

#[test]
fn tail_recursive_helper_over_a_string_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function dd($s){{ return $s === '' ? '' : chr(ord($s[0]) ^ {XOR_BYTE}) . dd(substr($s, 1)); }} $c = base64_decode('{}'); $o = dd($c); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("tail-recursive-over-string", &blob);
}

#[test]
fn index_recursive_helper_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function dd($s, $i){{ return $i >= strlen($s) ? '' : chr(ord($s[$i]) ^ {XOR_BYTE}) . dd($s, $i + 1); }} $c = base64_decode('{}'); $o = dd($c, 0); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("index-recursive", &blob);
}

#[test]
fn helper_with_a_default_argument_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function dd($s, $i = 0){{ return $i >= strlen($s) ? '' : chr(ord($s[$i]) ^ {XOR_BYTE}) . dd($s, $i + 1); }} $c = base64_decode('{}'); $o = dd($c); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("default-argument", &blob);
}

#[test]
fn mutually_recursive_helpers_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function odd($s, $i){{ return $i >= strlen($s) ? '' : chr(ord($s[$i]) ^ {XOR_BYTE}) . evn($s, $i + 1); }} function evn($s, $i){{ return $i >= strlen($s) ? '' : chr(ord($s[$i]) ^ {XOR_BYTE}) . odd($s, $i + 1); }} $c = base64_decode('{}'); $o = odd($c, 0); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("mutual-recursion", &blob);
}

#[test]
fn helper_wrapping_a_loop_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function dd($s){{ $o = ''; for ($i = 0; $i < strlen($s); $i++) {{ $o .= chr(ord($s[$i]) ^ {XOR_BYTE}); }} return $o; }} $c = base64_decode('{}'); $o = dd($c); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("helper-wrapping-a-loop", &blob);
}

#[test]
fn helper_called_before_it_is_declared_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php $c = base64_decode('{}'); $o = dd($c); function dd($s){{ $o = ''; for ($i = 0; $i < strlen($s); $i++) {{ $o .= chr(ord($s[$i]) ^ {XOR_BYTE}); }} return $o; }} ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("called-before-declared", &blob);
}

#[test]
fn helper_name_built_by_concatenation_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function dd($s){{ $o = ''; for ($i = 0; $i < strlen($s); $i++) {{ $o .= chr(ord($s[$i]) ^ {XOR_BYTE}); }} return $o; }} $c = base64_decode('{}'); $f = 'd' . 'd'; $o = $f($c); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("concatenated-helper-name", &blob);
}

#[test]
fn helper_taking_an_array_argument_runtime_equivalent() {
    let table: String = (0u16..256)
        .map(|c: u16| ((c as u8) ^ XOR_BYTE).to_string())
        .collect::<Vec<String>>()
        .join(",");
    let blob: Vec<u8> = format!(
        "<?php function dd($s, $t){{ $o = ''; foreach (str_split($s) as $ch) {{ $o .= chr($t[ord($ch)]); }} return $o; }} $c = base64_decode('{}'); $tbl = array({table}); $o = dd($c, $tbl); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("array-argument", &blob);
}

#[test]
fn helper_reassigning_its_own_parameter_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function dd($s){{ $o = ''; while ($s !== '') {{ $o .= chr(ord($s[0]) ^ {XOR_BYTE}); $s = substr($s, 1); }} return $o; }} $c = base64_decode('{}'); $o = dd($c); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("parameter-reassigned", &blob);
}

#[test]
fn helper_result_passed_straight_into_the_sink_runtime_equivalent() {
    let blob: Vec<u8> = format!(
        "<?php function dd($s){{ $o = ''; for ($i = 0; $i < strlen($s); $i++) {{ $o .= chr(ord($s[$i]) ^ {XOR_BYTE}); }} return $o; }} $c = base64_decode('{}'); ev\x61l(dd($c));",
        xored_payload_b64()
    )
    .into_bytes();
    recover_and_grade("helper-result-into-sink", &blob);
}

#[test]
fn a_non_terminating_helper_cannot_hang_the_pass() {
    let blob: &[u8] =
        b"<?php function dd($s){ return dd($s . 'x'); } $c = 'seed'; $o = dd($c); ev\x61l($o);";
    let started: std::time::Instant = std::time::Instant::now();
    let _: Result<RecoveryReport, disrobe_pass_php::Error> = recover_php(blob, None);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "a helper that never terminates must hit a budget and abstain, not run forever"
    );
}

#[test]
fn a_helper_calling_an_impure_function_is_never_evaluated() {
    let blob: &[u8] =
        b"<?php function dd($s){ return file_get_contents('/etc/passwd'); } $c = 'x'; $o = dd($c); ev\x61l($o);";
    if let Ok(report) = recover_php(blob, None) {
        assert!(
            !report.output.contains("root:"),
            "a helper body calling file_get_contents must be refused by the allowlist, never \
             evaluated; got:\n{}",
            report.output
        );
    }
}

#[test]
fn a_helper_reading_a_runtime_key_still_walls() {
    let graded: String = String::from("the runtime-keyed recursive helper wall");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let blob: Vec<u8> = format!(
        "<?php function dd($s, $k){{ $o = ''; for ($i = 0; $i < strlen($s); $i++) {{ $o .= chr(ord($s[$i]) ^ ord($k[$i % strlen($k)])); }} return $o; }} $c = base64_decode('{}'); $k = $_GET['k']; $o = dd($c, $k); ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    let report: RecoveryReport = recover_php(&blob, None).expect("recover runtime-keyed helper");
    assert!(
        !report.output.contains(MARKER),
        "the key is absent from the file, so the plaintext is not statically derivable and must \
         never be produced; got:\n{}",
        report.output
    );
    let sanity: Vec<u8> = php.stdout_of("wall sanity", b"<?php echo 'helper-wall-ok';");
    assert_eq!(
        String::from_utf8_lossy(&sanity),
        "helper-wall-ok",
        "the php reference this wall is graded beside does not run, so the absence of a \
         fabricated body proves nothing"
    );
}

#[test]
fn a_declaration_beside_a_loop_does_not_break_the_loops_own_recovery() {
    let graded: String = String::from("a helper declared beside a decode loop");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let blob: Vec<u8> = format!(
        "<?php function strrev2($s){{ return strrev($s); }} $c = base64_decode('{}'); $o = ''; for ($i = 0; $i < strlen($c); $i++) {{ $o .= chr(ord($c[$i]) ^ {XOR_BYTE}); }} ev\x61l($o);",
        xored_payload_b64()
    )
    .into_bytes();
    let report: RecoveryReport = recover_php(&blob, None).expect("recover");
    let recovered: String = with_open_tag(&report.output);
    let out: Vec<u8> = php.stdout_of("builtin-shadow", recovered.as_bytes());
    assert!(
        String::from_utf8_lossy(&out).contains(MARKER),
        "a helper declared beside a loop must not disturb the loop's own recovery; got \
         {:?}\n--- recovered ---\n{recovered}",
        String::from_utf8_lossy(&out)
    );
}
