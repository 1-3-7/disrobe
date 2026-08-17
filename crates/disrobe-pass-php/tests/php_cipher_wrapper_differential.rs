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
use php_toolchain::{
    PhpRuntime, require_php, require_php_extensions, residual_decode_primitives, with_open_tag,
};

const MARKER: &str = "DISROBE-PHP-CIPHER-5B3D";
const OPENSSL: &[(&str, &str)] = &[("openssl", "openssl_decrypt")];
const BZIP2: &[(&str, &str)] = &[("bz2", "bzdecompress")];

fn payload() -> String {
    format!("echo '{MARKER}';")
}

fn b64(bytes: &[u8]) -> String {
    B64_STD.encode(bytes)
}

fn php_with(extensions: &[(&str, &str)], graded: &str) -> Option<PhpRuntime> {
    let base: PhpRuntime = require_php(graded)?;
    require_php_extensions(&base, extensions, graded)
}

fn grade(php: &PhpRuntime, label: &str, obfuscated: &[u8]) -> String {
    let obf_stdout: Vec<u8> = php.stdout_of(label, obfuscated);
    let obf_text: String = String::from_utf8_lossy(&obf_stdout).into_owned();
    assert!(
        obf_text.contains(MARKER),
        "{label}: the obfuscated loader itself does not print {MARKER:?} under {}; got \
         {obf_text:?}. Grading a recovery against an input that never produced the marker would \
         grade nothing.",
        php.banner
    );

    let report: RecoveryReport = recover_php(obfuscated, None)
        .unwrap_or_else(|e: disrobe_pass_php::Error| panic!("{label}: recover failed: {e}"));
    assert_ne!(
        report.stage,
        RecoveryStage::PlainSource,
        "{label}: an obfuscated payload must not be reported as plain source"
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
         the decode layer was never actually evaluated.\n--- recovered ---\n{recovered_source}"
    );
    report.output
}

fn php_expression(php: &PhpRuntime, label: &str, expression: &str) -> String {
    let source: String = format!("<?php echo {expression};");
    let produced: Vec<u8> = php.stdout_of(label, source.as_bytes());
    let text: String = String::from_utf8_lossy(&produced).into_owned();
    assert!(
        !text.is_empty(),
        "{label}: `{expression}` produced nothing under {}, so there is no ciphertext to recover",
        php.banner
    );
    text
}

fn encrypted_payload(
    php: &PhpRuntime,
    label: &str,
    algorithm: &str,
    key: &str,
    options: &str,
    iv: &str,
    plain: &str,
) -> String {
    let seed: String = b64(plain.as_bytes());
    let call: String = format!(
        "openssl_encrypt(base64_decode('{seed}'), '{algorithm}', '{key}', {options}, '{iv}')"
    );
    let wrapped: String = if options.contains("OPENSSL_RAW_DATA") {
        format!("base64_encode({call})")
    } else {
        call
    };
    php_expression(php, label, &wrapped)
}

#[test]
fn aes_128_cbc_raw_static_key_runtime_equivalent() {
    let graded: String = String::from("the aes-128-cbc static-key sink against real php");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-128-cbc-raw";
    let key: &str = "disrobe-key-0001";
    let iv: &str = "disrobe-ivec-001";
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-cbc",
        key,
        "OPENSSL_RAW_DATA",
        iv,
        &payload(),
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; $k = '{key}'; $v = '{iv}'; ev\x61l(openssl_decrypt(base64_decode($c), 'aes-128-cbc', $k, OPENSSL_RAW_DATA, $v));"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn aes_256_cbc_base64_option_runtime_equivalent() {
    let graded: String = String::from("the aes-256-cbc base64-input sink against real php");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-256-cbc-b64";
    let key: &str = "disrobe-256-bit-key-material-32b";
    let iv: &str = "0123456789abcdef";
    let cipher: String = encrypted_payload(&php, label, "aes-256-cbc", key, "0", iv, &payload());
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; $k = '{key}'; $v = '{iv}'; ev\x61l(openssl_decrypt($c, 'aes-256-cbc', $k, 0, $v));"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn aes_128_ecb_runtime_equivalent() {
    let graded: String = String::from("the aes-128-ecb static-key sink against real php");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-128-ecb";
    let key: &str = "ecb-mode-key-016";
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-ecb",
        key,
        "OPENSSL_RAW_DATA",
        "",
        &payload(),
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; $k = '{key}'; ev\x61l(openssl_decrypt(base64_decode($c), 'AES-128-ECB', $k, OPENSSL_RAW_DATA));"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn aes_256_ecb_zero_padding_runtime_equivalent() {
    let graded: String = String::from("the aes-256-ecb zero-padding sink against real php");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-256-ecb-zeropad";
    let key: &str = "another-256-bit-key-material-32b";
    let mut plain: String = payload();
    while !plain.len().is_multiple_of(16) {
        plain.push(' ');
    }
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-256-ecb",
        key,
        "OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING",
        "",
        &plain,
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; $k = '{key}'; ev\x61l(openssl_decrypt(base64_decode($c), 'aes-256-ecb', $k, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING));"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn aes_key_held_in_a_defined_constant_runtime_equivalent() {
    let graded: String = String::from("an aes key held in a define() constant against real php");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-define-key";
    let key: &str = "constant-keyed1";
    let iv: &str = "constant-ivec-01";
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-cbc",
        key,
        "OPENSSL_RAW_DATA",
        iv,
        &payload(),
    );
    let blob: Vec<u8> = format!(
        "<?php define('DKEY', '{key}'); define('DVEC', '{iv}'); $c = '{cipher}'; ev\x61l(openssl_decrypt(base64_decode($c), 'aes-128-cbc', DKEY, OPENSSL_RAW_DATA, constant('DVEC')));"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn aes_short_passphrase_is_zero_extended_like_php() {
    let graded: String = String::from("a short aes passphrase against real php key derivation");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-short-key";
    let key: &str = "tiny";
    let iv: &str = "shortkey-ivec-01";
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-cbc",
        key,
        "OPENSSL_RAW_DATA",
        iv,
        &payload(),
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; ev\x61l(openssl_decrypt(base64_decode($c), 'aes-128-cbc', '{key}', OPENSSL_RAW_DATA, '{iv}'));"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn an_empty_aes_passphrase_matches_php_zero_extension() {
    let graded: String = String::from("an empty aes passphrase against real php key derivation");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-empty-key";
    let iv: &str = "emptykey-ivec-01";
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-cbc",
        "",
        "OPENSSL_RAW_DATA",
        iv,
        &payload(),
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; $k = ''; ev\x61l(openssl_decrypt(base64_decode($c), 'aes-128-cbc', $k, OPENSSL_RAW_DATA, '{iv}'));"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn aes_plaintext_feeding_a_decode_loop_runtime_equivalent() {
    let graded: String = String::from("an aes layer wrapping a xor decode loop against real php");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-then-xor-loop";
    let key: &str = "layered-key-0016";
    let iv: &str = "layered-ivec-001";
    let inner: Vec<u8> = payload().bytes().map(|b: u8| b ^ 0x3d).collect();
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-cbc",
        key,
        "OPENSSL_RAW_DATA",
        iv,
        &b64(&inner),
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; $d = base64_decode(openssl_decrypt(base64_decode($c), 'aes-128-cbc', '{key}', OPENSSL_RAW_DATA, '{iv}')); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ 61); }} ev\x61l($o);"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn a_runtime_sourced_aes_key_still_walls() {
    let graded: String = String::from("the runtime-keyed aes wall");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-runtime-key-wall";
    let key: &str = "not-in-the-file";
    let iv: &str = "runtime-ivec-001";
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-cbc",
        key,
        "OPENSSL_RAW_DATA",
        iv,
        &payload(),
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; $k = $_GET['k']; ev\x61l(openssl_decrypt(base64_decode($c), 'aes-128-cbc', $k, OPENSSL_RAW_DATA, '{iv}'));"
    )
    .into_bytes();
    let report: RecoveryReport = recover_php(&blob, None).expect("recover runtime-keyed loader");
    assert!(
        !report.output.contains(MARKER),
        "{label}: the aes key is absent from the file, so the plaintext is not statically \
         derivable and must never be produced; got:\n{}",
        report.output
    );
    assert!(
        report.output.contains("openssl_decrypt"),
        "{label}: the undecidable decrypt call must be left in place rather than dropped; \
         got:\n{}",
        report.output
    );
    let sanity: Vec<u8> = php.stdout_of(label, b"<?php echo 'aes-wall-ok';");
    assert_eq!(
        String::from_utf8_lossy(&sanity),
        "aes-wall-ok",
        "{label}: the php reference this wall is graded beside does not run, so the absence of a \
         fabricated body proves nothing"
    );
}

#[test]
fn an_unsupported_cipher_algorithm_is_refused_rather_than_guessed() {
    let graded: String = String::from("the refusal of an aes mode the evaluator does not model");
    let Some(php): Option<PhpRuntime> = php_with(OPENSSL, &graded) else {
        return;
    };
    let label: &str = "aes-ctr-refused";
    let key: &str = "ctr-mode-key-016";
    let iv: &str = "ctr-mode-ivec-01";
    let cipher: String = encrypted_payload(
        &php,
        label,
        "aes-128-ctr",
        key,
        "OPENSSL_RAW_DATA",
        iv,
        &payload(),
    );
    let blob: Vec<u8> = format!(
        "<?php $c = '{cipher}'; ev\x61l(openssl_decrypt(base64_decode($c), 'aes-128-ctr', '{key}', OPENSSL_RAW_DATA, '{iv}'));"
    )
    .into_bytes();
    let loader_stdout: Vec<u8> = php.stdout_of(label, &blob);
    assert!(
        String::from_utf8_lossy(&loader_stdout).contains(MARKER),
        "{label}: the ctr loader itself must run, otherwise the refusal proves nothing"
    );
    let report: RecoveryReport = recover_php(&blob, None).expect("recover ctr loader");
    assert!(
        !report.output.contains(MARKER),
        "{label}: aes-ctr is not modelled by the evaluator, so producing the plaintext would mean \
         a mode was decrypted by the wrong primitive; got:\n{}",
        report.output
    );
    assert!(
        report.output.contains("openssl_decrypt"),
        "{label}: an unmodelled mode must leave its call in the source rather than replace it with \
         whatever another primitive produced; got:\n{}",
        report.output
    );
}

#[test]
fn defined_constant_key_drives_a_decode_loop_runtime_equivalent() {
    let graded: String = String::from("a define() constant used as the loop key against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "define-constant-key";
    let key: &[u8] = b"c0nstKey";
    let cipher: Vec<u8> = payload()
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
        .collect();
    let blob: Vec<u8> = format!(
        "<?php define('XK', '{}'); $d = base64_decode('{}'); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ ord(XK[$i % strlen(XK)])); }} ev\x61l($o);",
        String::from_utf8_lossy(key),
        b64(&cipher)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn file_scope_const_key_drives_a_decode_loop_runtime_equivalent() {
    let graded: String =
        String::from("a file-scope const expression used as the loop key against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "file-scope-const-key";
    let key: &[u8] = b"staticKey";
    let cipher: Vec<u8> = payload()
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
        .collect();
    let blob: Vec<u8> = format!(
        "<?php const XK = 'static' . 'Key'; $d = base64_decode('{}'); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ ord(XK[$i % strlen(XK)])); }} ev\x61l($o);",
        b64(&cipher)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn file_scope_const_refuses_unsupported_scope_and_order_cases() {
    let key: &[u8] = b"staticKey";
    let cipher: Vec<u8> = payload()
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
        .collect();
    let cipher_b64: String = b64(&cipher);
    let cases: [(&str, &str, &str, &str); 4] = [
        (
            "namespace-const",
            "namespace Foo; const XK = 'staticKey';",
            "XK",
            "",
        ),
        (
            "class-const",
            "class Holder { public const XK = 'staticKey'; }",
            "Holder::XK",
            "",
        ),
        (
            "multiple-const",
            "const UNUSED = 'unused', XK = 'staticKey';",
            "XK",
            "",
        ),
        ("const-after-sink", "", "XK", "const XK = 'staticKey';"),
    ];
    for case in cases {
        let (label, setup, key_expr, trailing): (&str, &str, &str, &str) = case;
        let blob: Vec<u8> = format!(
            "<?php {setup} $d = base64_decode('{cipher_b64}'); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ ord({key_expr}[$i % strlen({key_expr})])); }} ev\x61l($o); {trailing}"
        )
        .into_bytes();
        let report: RecoveryReport = recover_php(&blob, None)
            .unwrap_or_else(|error: disrobe_pass_php::Error| panic!("{label}: {error}"));
        assert!(
            !report.output.contains(MARKER),
            "{label}: a constant outside the supported single global declaration boundary must not drive recovery; got:\n{}",
            report.output
        );
    }
}

#[test]
fn an_undefined_constant_leaves_the_loop_in_place() {
    let label: &str = "undefined-constant";
    let key: &[u8] = b"absentKey";
    let cipher: Vec<u8> = payload()
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
        .collect();
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode('{}'); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ ord(MISSING_KEY[$i % strlen(MISSING_KEY)])); }} ev\x61l($o);",
        b64(&cipher)
    )
    .into_bytes();
    let report: RecoveryReport =
        recover_php(&blob, None).expect("recover undefined-constant loader");
    assert!(
        !report.output.contains(MARKER),
        "{label}: the constant is never defined in the file, so php would fatal and no plaintext \
         is derivable; got:\n{}",
        report.output
    );
}

#[test]
fn base64_url_alphabet_runtime_equivalent() {
    let graded: String = String::from("a url-alphabet base64 wrapper against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "base64-url-alphabet";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(23)).collect();
    let url_safe: String = b64(&cipher).replace('+', "-").replace('/', "_");
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode(strtr('{url_safe}', '-_', '+/')); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr((ord($d[$i]) - 23 + 256) % 256); }} ev\x61l($o);"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn custom_base64_alphabet_runtime_equivalent() {
    let graded: String = String::from("a custom base64 alphabet wrapper against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "base64-custom-alphabet";
    const STANDARD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const CUSTOM: &str = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210_-";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b ^ 0x71).collect();
    let standard_text: String = b64(&cipher);
    let translated: String = standard_text
        .chars()
        .map(|c: char| match STANDARD.find(c) {
            Some(index) => CUSTOM.chars().nth(index).unwrap_or(c),
            None => c,
        })
        .collect();
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode(strtr('{translated}', '{CUSTOM}', '{STANDARD}')); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ 113); }} ev\x61l($o);"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn gzuncompress_wrapper_runtime_equivalent() {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;

    let graded: String = String::from("a gzuncompress wrapper against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "gzuncompress-wrapper";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_sub(41)).collect();
    let mut encoder: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&cipher).expect("zlib");
    let compressed: Vec<u8> = encoder.finish().expect("zlib finish");
    let blob: Vec<u8> = format!(
        "<?php $d = gzuncompress(base64_decode('{}')); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr((ord($d[$i]) + 41) % 256); }} ev\x61l($o);",
        b64(&compressed)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn gzdecode_wrapper_runtime_equivalent() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;

    let graded: String = String::from("a gzdecode wrapper against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "gzdecode-wrapper";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.rotate_left(5)).collect();
    let mut encoder: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&cipher).expect("gzip");
    let compressed: Vec<u8> = encoder.finish().expect("gzip finish");
    let blob: Vec<u8> = format!(
        "<?php $d = gzdecode(base64_decode('{}')); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(((ord($d[$i]) >> 5) | (ord($d[$i]) << 3)) & 255); }} ev\x61l($o);",
        b64(&compressed)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn bzdecompress_wrapper_runtime_equivalent() {
    let graded: String = String::from("a bzdecompress wrapper against real php");
    let Some(php): Option<PhpRuntime> = php_with(BZIP2, &graded) else {
        return;
    };
    let label: &str = "bzdecompress-wrapper";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b ^ 0x4c).collect();
    let compressed: String = php_expression(
        &php,
        label,
        &format!(
            "base64_encode(bzcompress(base64_decode('{}')))",
            b64(&cipher)
        ),
    );
    let blob: Vec<u8> = format!(
        "<?php $d = bzdecompress(base64_decode('{compressed}')); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ 76); }} ev\x61l($o);"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn convert_uudecode_wrapper_runtime_equivalent() {
    let graded: String = String::from("a convert_uudecode wrapper against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "uudecode-wrapper";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(9)).collect();
    let encoded: String = php_expression(
        &php,
        label,
        &format!(
            "base64_encode(convert_uuencode(base64_decode('{}')))",
            b64(&cipher)
        ),
    );
    let blob: Vec<u8> = format!(
        "<?php $d = convert_uudecode(base64_decode('{encoded}')); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr((ord($d[$i]) - 9 + 256) % 256); }} ev\x61l($o);"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn unpack_c_star_runtime_equivalent() {
    let graded: String = String::from("an unpack('C*') byte walk against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "unpack-C-star";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b ^ 0x2a).collect();
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode('{}'); $o = ''; foreach (unpack('C*', $d) as $x) {{ $o .= chr($x ^ 42); }} ev\x61l($o);",
        b64(&cipher)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn unpack_c_star_indexed_from_one_runtime_equivalent() {
    let graded: String = String::from("an unpack('C*') result indexed by key against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "unpack-C-star-indexed";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(63)).collect();
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode('{}'); $p = unpack('C*', $d); $o = ''; for ($i = 1; $i <= count($p); $i++) {{ $o .= chr(($p[$i] - 63 + 256) % 256); }} ev\x61l($o);",
        b64(&cipher)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn unpack_v_star_runtime_equivalent() {
    let graded: String = String::from("an unpack('V*') word walk against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "unpack-V-star";
    let mut plain: Vec<u8> = payload().into_bytes();
    while !plain.len().is_multiple_of(4) {
        plain.push(b' ');
    }
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode('{}'); $o = ''; foreach (unpack('V*', $d) as $w) {{ $o .= chr($w & 255) . chr(($w >> 8) & 255) . chr(($w >> 16) & 255) . chr(($w >> 24) & 255); }} ev\x61l($o);",
        b64(&plain)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn unpack_h_star_yields_a_php_shaped_array_runtime_equivalent() {
    let graded: String = String::from("an unpack('H*') array shape against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "unpack-H-star";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(88)).collect();
    let blob: Vec<u8> = format!(
        "<?php $raw = base64_decode('{}'); $h = unpack('H*', $raw); $d = pack('H*', $h[1]); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr((ord($d[$i]) - 88 + 256) % 256); }} ev\x61l($o);",
        b64(&cipher)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn pack_c_star_runtime_equivalent() {
    let graded: String = String::from("a pack('C*') accumulator against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "pack-C-star";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_sub(17)).collect();
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode('{}'); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= pack('C*', (ord($d[$i]) + 17) % 256); }} ev\x61l($o);",
        b64(&cipher)
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn pack_low_nibble_hex_runtime_equivalent() {
    let graded: String = String::from("a pack('h*') low-nibble hex wrapper against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "pack-h-star";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b ^ 0x5e).collect();
    let swapped: String = cipher
        .iter()
        .map(|b: &u8| format!("{:x}{:x}", b & 0x0f, b >> 4))
        .collect();
    let blob: Vec<u8> = format!(
        "<?php $d = pack('h*', '{swapped}'); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr(ord($d[$i]) ^ 94); }} ev\x61l($o);"
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn nested_wrapper_chain_runtime_equivalent() {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;

    let graded: String =
        String::from("a nested strtr/rot13/base64/gzuncompress chain against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "nested-wrapper-chain";
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(3)).collect();
    let mut encoder: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&cipher).expect("zlib");
    let compressed: Vec<u8> = encoder.finish().expect("zlib finish");
    let url_safe: String = b64(&compressed).replace('+', "-").replace('/', "_");
    let rotated: String = url_safe
        .bytes()
        .map(|b: u8| match b {
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            other => other,
        })
        .map(char::from)
        .collect();
    let blob: Vec<u8> = format!(
        "<?php $d = gzuncompress(base64_decode(strtr(str_rot13(strrev('{}')), '-_', '+/'))); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $o .= chr((ord($d[$i]) - 3 + 256) % 256); }} ev\x61l($o);",
        rotated.chars().rev().collect::<String>()
    )
    .into_bytes();
    grade(&php, label, &blob);
}

const XXTEA_WORDS: &str = "\
function w($s) { $v = array(); $n = strlen($s) / 4; for ($i = 0; $i < $n; $i++) { \
$v[$i] = ord($s[$i * 4]) | (ord($s[$i * 4 + 1]) << 8) | (ord($s[$i * 4 + 2]) << 16) | \
(ord($s[$i * 4 + 3]) << 24); } return $v; } \
function b($v, $n) { $o = ''; for ($i = 0; $i < $n; $i++) { $o .= chr($v[$i] & 255) . \
chr(($v[$i] >> 8) & 255) . chr(($v[$i] >> 16) & 255) . chr(($v[$i] >> 24) & 255); } return $o; } ";

const XXTEA_MIX: &str = "\
$mx = ((($z >> 5) & 134217727) ^ (($y << 2) & 4294967295)) + ((($y >> 3) & 536870911) ^ \
(($z << 4) & 4294967295)); ";

fn xxtea_decoder() -> String {
    format!(
        "{XXTEA_WORDS}function xd($d, $kb) {{ $v = w($d); $k = w($kb); $n = strlen($d) / 4; \
         $q = 6 + 52 / $n; $sum = ($q * 2654435769) & 4294967295; $y = $v[0]; \
         while ($sum != 0) {{ $e = ($sum >> 2) & 3; \
         for ($p = $n - 1; $p > 0; $p--) {{ $z = $v[$p - 1]; {XXTEA_MIX} \
         $mx = ($mx ^ ((($sum ^ $y) + ($k[($p & 3) ^ $e] ^ $z)) & 4294967295)) & 4294967295; \
         $v[$p] = ($v[$p] - $mx) & 4294967295; $y = $v[$p]; }} \
         $z = $v[$n - 1]; {XXTEA_MIX} \
         $mx = ($mx ^ ((($sum ^ $y) + ($k[0 ^ $e] ^ $z)) & 4294967295)) & 4294967295; \
         $v[0] = ($v[0] - $mx) & 4294967295; $y = $v[0]; \
         $sum = ($sum - 2654435769) & 4294967295; }} return b($v, $n); }} "
    )
}

fn xxtea_encoder() -> String {
    format!(
        "{XXTEA_WORDS}function xe($d, $kb) {{ $v = w($d); $k = w($kb); $n = strlen($d) / 4; \
         $q = 6 + 52 / $n; $sum = 0; $z = $v[$n - 1]; \
         while ($q > 0) {{ $sum = ($sum + 2654435769) & 4294967295; $e = ($sum >> 2) & 3; \
         for ($p = 0; $p < $n - 1; $p++) {{ $y = $v[$p + 1]; {XXTEA_MIX} \
         $mx = ($mx ^ ((($sum ^ $y) + ($k[($p & 3) ^ $e] ^ $z)) & 4294967295)) & 4294967295; \
         $v[$p] = ($v[$p] + $mx) & 4294967295; $z = $v[$p]; }} \
         $y = $v[0]; {XXTEA_MIX} \
         $mx = ($mx ^ ((($sum ^ $y) + ($k[(($n - 1) & 3) ^ $e] ^ $z)) & 4294967295)) & 4294967295; \
         $v[$n - 1] = ($v[$n - 1] + $mx) & 4294967295; $z = $v[$n - 1]; $q = $q - 1; }} \
         return b($v, $n); }} "
    )
}

#[test]
fn userland_xxtea_helper_runtime_equivalent() {
    let graded: String = String::from("a file-declared xxtea helper against real php");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let label: &str = "userland-xxtea";
    let key: &str = "sixteen-byte-key";
    let mut plain: String = payload();
    while plain.len() < 52 {
        plain.push(' ');
    }
    assert_eq!(
        plain.len(),
        52,
        "{label}: the payload must fill exactly thirteen words so 52/n divides exactly"
    );
    let generator: String = format!(
        "<?php {}echo base64_encode(xe(base64_decode('{}'), '{key}'));",
        xxtea_encoder(),
        b64(plain.as_bytes())
    );
    let cipher: Vec<u8> = php.stdout_of(label, generator.as_bytes());
    let encoded: String = String::from_utf8_lossy(&cipher).into_owned();
    assert!(
        !encoded.is_empty(),
        "{label}: the php xxtea encoder produced nothing to recover"
    );
    let blob: Vec<u8> = format!(
        "<?php {}$c = '{encoded}'; $k = '{key}'; ev\x61l(xd(base64_decode($c), $k));",
        xxtea_decoder()
    )
    .into_bytes();
    grade(&php, label, &blob);
}

#[test]
fn no_cipher_implementation_lives_in_this_crate() {
    let root: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources: Vec<(String, String)> = Vec::new();
    collect_sources(&root, &mut sources);
    assert!(
        sources.len() > 10,
        "the crate source walk found only {} files, so this assertion is measuring nothing",
        sources.len()
    );

    const TRANSFORM_MARKERS: [&str; 8] = [
        "0x9e3779b9",
        "0x61c88647",
        "fn aes_encrypt",
        "fn aes_decrypt",
        "fn aes_round",
        "fn rijndael",
        "fn expand_key",
        "fn rc4_apply",
    ];
    for (name, body) in &sources {
        let lowered: String = body.to_ascii_lowercase();
        for marker in TRANSFORM_MARKERS {
            assert!(
                !lowered.contains(marker),
                "{name} contains `{marker}`, which means a cipher is being implemented inside this \
                 crate instead of reused from disrobe-core"
            );
        }
    }

    let table_owners: Vec<&str> = sources
        .iter()
        .filter(|(_, body): &&(String, String)| body.contains("[u8; 256]"))
        .map(|(name, _): &(String, String)| name.as_str())
        .collect();
    assert_eq!(
        table_owners,
        vec!["key_extractor.rs"],
        "a 256-entry byte table outside the SourceGuardian detector is a cipher lookup table being \
         built in this crate"
    );
    let detector: &(String, String) = sources
        .iter()
        .find(|(name, _): &&(String, String)| name == "key_extractor.rs")
        .expect("key_extractor.rs is part of this crate");
    assert!(
        !detector.1.contains("AES_SBOX[") && !detector.1.contains("AES_RCON["),
        "key_extractor.rs indexes its AES tables, so they have stopped being detection constants \
         and become a cipher implementation"
    );

    let loader: &(String, String) = sources
        .iter()
        .find(|(name, _): &&(String, String)| name == "loader.rs")
        .expect("loader.rs is part of this crate");
    assert!(
        loader.1.contains("disrobe_core::codec::cipher::rc4_apply"),
        "the rc4 loop recovery must run the disrobe-core stream cipher, not a second one written \
         here"
    );
    let interpreter: &(String, String) = sources
        .iter()
        .find(|(name, _): &&(String, String)| name == "decode_loop.rs")
        .expect("decode_loop.rs is part of this crate");
    assert!(
        interpreter
            .1
            .contains("use disrobe_core::codec::{CbcPadding, aes_cbc_decrypt};"),
        "the openssl_decrypt evaluator must reach aes through disrobe-core, not through a block \
         cipher assembled here"
    );
}

fn collect_sources(directory: &std::path::Path, out: &mut Vec<(String, String)>) {
    let Ok(entries): Result<std::fs::ReadDir, std::io::Error> = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path: std::path::PathBuf = entry.path();
        if path.is_dir() {
            collect_sources(&path, out);
        } else if path
            .extension()
            .is_some_and(|e: &std::ffi::OsStr| e == "rs")
        {
            let name: String = path
                .file_name()
                .map(|n: &std::ffi::OsStr| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let body: String = std::fs::read_to_string(&path).unwrap_or_default();
            out.push((name, body));
        }
    }
}
