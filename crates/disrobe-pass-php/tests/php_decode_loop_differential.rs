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

const MARKER: &str = "DISROBE-PHP-LOOP-4C71";

fn payload() -> String {
    format!("echo '{MARKER}';")
}

fn b64(bytes: &[u8]) -> String {
    B64_STD.encode(bytes)
}

fn xor_repeating(plain: &[u8], key: &[u8]) -> Vec<u8> {
    plain
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect()
}

fn recover_and_grade(label: &str, obfuscated: &[u8]) -> String {
    let graded: String = format!("the {label} decode loop against the real php interpreter");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return String::new();
    };

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
        "{label}: an obfuscated decode loop must not be reported as plain source"
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
         the decode layer was never actually evaluated.\n--- recovered \
         ---\n{recovered_source}"
    );
    report.output
}

fn loader_with_body(cipher: &[u8], setup: &str, body: &str) -> Vec<u8> {
    format!(
        "<?php $d = base64_decode('{}'); {setup} $o = ''; {body} ev\x61l($o);",
        b64(cipher)
    )
    .into_bytes()
}

#[test]
fn canonical_xor_modulo_shape_still_recovers() {
    let key: &[u8] = b"Reg3xSh4pe";
    let cipher: Vec<u8> = xor_repeating(payload().as_bytes(), key);
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        &format!("$k = '{}';", String::from_utf8_lossy(key)),
        "for ($i = 0; $i < strlen($d); $i++) { $o .= chr(ord($d[$i]) ^ ord($k[$i % strlen($k)])); }",
    );
    recover_and_grade("canonical-xor-modulo", &blob);
}

#[test]
fn while_loop_manual_index_runtime_equivalent() {
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(61)).collect();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "$i = 0;",
        "while ($i < strlen($d)) { $o .= chr((ord($d[$i]) - 61 + 256) % 256); $i++; }",
    );
    recover_and_grade("while-manual-index", &blob);
}

#[test]
fn foreach_over_str_split_runtime_equivalent() {
    let cipher: Vec<u8> = payload()
        .bytes()
        .map(|b: u8| b.wrapping_add(7))
        .collect::<Vec<u8>>();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "foreach (str_split($d) as $c) { $o .= chr((ord($c) - 7 + 256) % 256); }",
    );
    recover_and_grade("foreach-str-split", &blob);
}

#[test]
fn do_while_loop_runtime_equivalent() {
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| !b).collect();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "$i = 0;",
        "do { $o .= chr(~ord($d[$i]) & 255); $i++; } while ($i < strlen($d));",
    );
    recover_and_grade("do-while", &blob);
}

#[test]
fn reversed_index_runtime_equivalent() {
    let cipher: Vec<u8> = payload().bytes().rev().collect();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d); $i++) { $o .= $d[strlen($d) - 1 - $i]; }",
    );
    recover_and_grade("reversed-index", &blob);
}

#[test]
fn stride_index_runtime_equivalent() {
    let mut cipher: Vec<u8> = Vec::new();
    for b in payload().bytes() {
        cipher.push(b);
        cipher.push(b'#');
    }
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d); $i += 2) { $o .= $d[$i]; }",
    );
    recover_and_grade("stride-index", &blob);
}

#[test]
fn rotating_index_runtime_equivalent() {
    let key: &[u8] = b"r0tat3";
    let cipher: Vec<u8> = xor_repeating(payload().as_bytes(), key);
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "$k = 'r0tat3'; $j = 0;",
        "for ($i = 0; $i < strlen($d); $i++) { $o .= chr(ord($d[$i]) ^ ord($k[$j])); $j = ($j + 1) % strlen($k); }",
    );
    recover_and_grade("rotating-index", &blob);
}

#[test]
fn nested_inner_loop_runtime_equivalent() {
    let plain: String = payload();
    let mut cipher: Vec<u8> = plain.clone().into_bytes();
    while !cipher.len().is_multiple_of(4) {
        cipher.push(b' ');
    }
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d) / 4; $i++) { for ($j = 0; $j < 4; $j++) { $o .= $d[$i * 4 + $j]; } }",
    );
    let recovered: String = recover_and_grade("nested-inner-loop", &blob);
    if !recovered.is_empty() {
        assert!(
            recovered.contains(MARKER),
            "nested-inner-loop: recovered source lost the payload: {recovered}"
        );
    }
}

#[test]
fn addition_with_wraparound_runtime_equivalent() {
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(200)).collect();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d); $i++) { $o .= chr((ord($d[$i]) - 200 + 256) % 256); }",
    );
    recover_and_grade("add-wraparound", &blob);
}

#[test]
fn subtraction_with_wraparound_runtime_equivalent() {
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_sub(200)).collect();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d); $i++) { $o .= chr((ord($d[$i]) + 200) % 256); }",
    );
    recover_and_grade("sub-wraparound", &blob);
}

#[test]
fn byte_rotation_runtime_equivalent() {
    let cipher: Vec<u8> = payload()
        .bytes()
        .map(|b: u8| b.rotate_right(3))
        .collect::<Vec<u8>>();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d); $i++) { $o .= chr(((ord($d[$i]) << 3) | (ord($d[$i]) >> 5)) & 255); }",
    );
    recover_and_grade("byte-rotation", &blob);
}

#[test]
fn negation_runtime_equivalent() {
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| !b).collect();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d); $i++) { $o .= chr(~ord($d[$i]) & 255); }",
    );
    recover_and_grade("negation", &blob);
}

#[test]
fn table_substitution_runtime_equivalent() {
    let shift: u8 = 0x5b;
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b ^ shift).collect();
    let table: String = (0u16..256)
        .map(|c: u16| ((c as u8) ^ shift).to_string())
        .collect::<Vec<String>>()
        .join(",");
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        &format!("$t = array({table});"),
        "for ($i = 0; $i < strlen($d); $i++) { $o .= chr($t[ord($d[$i])]); }",
    );
    recover_and_grade("table-substitution", &blob);
}

#[test]
fn parity_selected_operation_runtime_equivalent() {
    let cipher: Vec<u8> = payload()
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| {
            if i.is_multiple_of(2) {
                b.wrapping_add(1)
            } else {
                b.wrapping_sub(1)
            }
        })
        .collect();
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "",
        "for ($i = 0; $i < strlen($d); $i++) { if ($i % 2 == 0) { $o .= chr((ord($d[$i]) - 1 + 256) % 256); } else { $o .= chr((ord($d[$i]) + 1) % 256); } }",
    );
    recover_and_grade("parity-selected-op", &blob);
}

#[test]
fn hex_wrapped_ciphertext_runtime_equivalent() {
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.rotate_right(3)).collect();
    let hex: String = cipher
        .iter()
        .map(|b: &u8| format!("{b:02x}"))
        .collect::<String>();
    let blob: Vec<u8> = format!(
        "<?php $d = pack('H*', '{hex}'); $i = 0; $o = ''; while ($i < strlen($d)) {{ $o .= chr(((ord($d[$i]) << 3) | (ord($d[$i]) >> 5)) & 255); $i++; }} ev\x61l($o);"
    )
    .into_bytes();
    recover_and_grade("pack-H*-wrapped", &blob);
}

#[test]
fn nested_base64_rot13_gzinflate_wrapper_runtime_equivalent() {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write as _;

    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_sub(19)).collect();
    let mut encoder: DeflateEncoder<Vec<u8>> =
        DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&cipher).expect("deflate");
    let deflated: Vec<u8> = encoder.finish().expect("deflate finish");
    let rot: String = b64(&deflated)
        .bytes()
        .map(|b: u8| match b {
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            other => other,
        })
        .map(char::from)
        .collect();
    let blob: Vec<u8> = format!(
        "<?php $d = gzinflate(base64_decode(str_rot13('{rot}'))); $i = 0; $o = ''; while ($i < strlen($d)) {{ $o .= chr((ord($d[$i]) + 19) % 256); $i++; }} ev\x61l($o);"
    )
    .into_bytes();
    recover_and_grade("gzinflate(base64(rot13))-wrapped", &blob);
}

#[test]
fn rc4_in_a_while_loop_matches_the_canonical_recognizer_shape() {
    let graded: String = String::from("the rc4 interpreter and recognizer cross-check");
    let Some(_php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let key: &[u8] = b"cross_check_rc4";
    let cipher: Vec<u8> = disrobe_core::codec::cipher::rc4_apply(key, payload().as_bytes());
    let encoded: String = b64(&cipher);
    let key_text: String = String::from_utf8_lossy(key).into_owned();

    let canonical: Vec<u8> = format!(
        "<?php $d = base64_decode('{encoded}'); $k = '{key_text}'; $s = array(); for($i=0;$i<256;$i++){{ $s[$i]=$i; }} $j=0; for($i=0;$i<256;$i++){{ $j=($j+$s[$i]+ord($k[$i%strlen($k)]))%256; $t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t; }} $i=0;$j=0;$o=''; for($y=0;$y<strlen($d);$y++){{ $i=($i+1)%256; $j=($j+$s[$i])%256; $t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t; $o .= $d[$y] ^ chr($s[($s[$i]+$s[$j])%256]); }} ev\x61l($o);"
    )
    .into_bytes();

    let while_form: Vec<u8> = format!(
        "<?php $d = base64_decode('{encoded}'); $k = '{key_text}'; $s = array(); $i = 0; while($i<256){{ $s[$i]=$i; $i++; }} $i=0; $j=0; while($i<256){{ $kb = ord($k[$i % strlen($k)]); $j = ($j + $s[$i] + $kb) % 256; $t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t; $i++; }} $i=0;$j=0;$y=0;$o=''; while($y<strlen($d)){{ $i=($i+1)%256; $j=($j+$s[$i])%256; $t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t; $ks = $s[($s[$i]+$s[$j]) % 256]; $b = ord($d[$y]); $o .= chr($b ^ $ks); $y++; }} ev\x61l($o);"
    )
    .into_bytes();

    let from_recognizer: String = recover_and_grade("rc4-canonical", &canonical);
    let from_interpreter: String = recover_and_grade("rc4-while-form", &while_form);
    assert_eq!(
        from_recognizer, from_interpreter,
        "the rc4 shape recognizer and the bounded interpreter disagree on the same key and \
         ciphertext, so one of the two decode paths is wrong"
    );
    assert!(
        from_recognizer.contains(MARKER),
        "both rc4 paths agreed but neither recovered the payload: {from_recognizer}"
    );
}

#[test]
fn rc4_helper_with_chained_state_initialization_runtime_equivalent() {
    let key: &[u8] = b"chained_rc4_state";
    let cipher: Vec<u8> = disrobe_core::codec::cipher::rc4_apply(key, payload().as_bytes());
    let encoded: String = b64(&cipher);
    let key_text: String = String::from_utf8_lossy(key).into_owned();
    let blob: Vec<u8> = format!(
        "<?php function rc4($key, $data) {{ $state = range(0, 255); $j = 0; for ($i = 0; $i < 256; $i++) {{ $j = ($j + $state[$i] + ord($key[$i % strlen($key)])) % 256; $swap = $state[$i]; $state[$i] = $state[$j]; $state[$j] = $swap; }} $i = 37; $j = 73; $i = $j = 0; $out = ''; for ($n = 0; $n < strlen($data); $n++) {{ $i = ($i + 1) % 256; $j = ($j + $state[$i]) % 256; $swap = $state[$i]; $state[$i] = $state[$j]; $state[$j] = $swap; $out .= $data[$n] ^ chr($state[($state[$i] + $state[$j]) % 256]); }} return $out; }} ev\x61l(rc4('{key_text}', base64_decode('{encoded}')));"
    )
    .into_bytes();

    recover_and_grade("rc4-helper-chained-state", &blob);
}

#[test]
fn a_loop_that_clobbers_an_outer_variable_matches_php_scoping() {
    let cipher: Vec<u8> = payload().bytes().map(|b: u8| b.wrapping_add(5)).collect();
    let blob: Vec<u8> = format!(
        "<?php $s = \"ech\x6f 'STALE-OUTER-VALUE';\"; $d = base64_decode('{}'); $o = ''; for ($i = 0; $i < strlen($d); $i++) {{ $s = chr((ord($d[$i]) - 5 + 256) % 256); $o .= $s; }} ev\x61l($o);",
        b64(&cipher)
    )
    .into_bytes();
    let recovered: String = recover_and_grade("outer-variable-clobbered-by-loop", &blob);
    if !recovered.is_empty() {
        assert!(
            !recovered.contains("STALE-OUTER-VALUE"),
            "php has no block scope, so the loop body's write to $s replaces the outer value; a \
             recovery that resurrects the pre-loop value is modelling a scope php does not \
             have.\n{recovered}"
        );
    }
}

#[test]
fn a_loop_counter_never_displaces_the_key_the_sink_still_reads() {
    let key: &[u8] = b"sh4dow";
    let cipher: Vec<u8> = xor_repeating(payload().as_bytes(), key);
    let blob: Vec<u8> = format!(
        "<?php $d = base64_decode('{}'); $k = '{}'; $o = ''; $n = strlen($d); for ($i = 0; $i < $n; $i++) {{ $c = $d[$i]; $o .= chr(ord($c) ^ ord($k[$i % strlen($k)])); }} ev\x61l($o);",
        b64(&cipher),
        String::from_utf8_lossy(key)
    )
    .into_bytes();
    recover_and_grade("loop-locals-beside-a-live-key", &blob);
}

#[test]
fn a_runtime_sourced_key_still_walls_instead_of_inventing_a_body() {
    let graded: String = String::from("the runtime-keyed decode loop wall");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let key: &[u8] = b"n0tInTheFile";
    let cipher: Vec<u8> = xor_repeating(payload().as_bytes(), key);
    let blob: Vec<u8> = loader_with_body(
        &cipher,
        "$k = $_GET['k']; $i = 0;",
        "while ($i < strlen($d)) { $o .= chr(ord($d[$i]) ^ ord($k[$i % strlen($k)])); $i++; }",
    );
    let report: RecoveryReport = recover_php(&blob, None).expect("recover runtime-keyed loader");
    assert!(
        !report.output.contains(MARKER),
        "the key is absent from the file, so the plaintext is not statically derivable and must \
         never be produced; got:\n{}",
        report.output
    );
    let sanity: Vec<u8> = php.stdout_of("wall sanity", b"<?php echo 'loop-wall-ok';");
    assert_eq!(
        String::from_utf8_lossy(&sanity),
        "loop-wall-ok",
        "the php reference this wall is graded beside does not run, so the absence of a \
         fabricated body proves nothing"
    );
}

#[test]
fn an_impure_call_inside_a_loop_is_never_evaluated() {
    let blob: Vec<u8> =
        b"<?php $d = 'x'; $o = ''; for ($i = 0; $i < 1; $i++) { $o .= file_get_contents('/etc/passwd'); } ev\x61l($o);"
            .to_vec();
    let report: Result<RecoveryReport, disrobe_pass_php::Error> = recover_php(&blob, None);
    if let Ok(recovered) = report {
        assert!(
            !recovered.output.contains("root:"),
            "a loop body calling file_get_contents must be refused by the allowlist, never \
             evaluated; got:\n{}",
            recovered.output
        );
    }
}

#[test]
fn a_huge_trip_count_cannot_hang_the_pass() {
    let blob: Vec<u8> =
        b"<?php $d = 'x'; $o = ''; for ($i = 0; $i < 9000000000; $i++) { $o .= 'a'; } ev\x61l($o);"
            .to_vec();
    let started: std::time::Instant = std::time::Instant::now();
    let _: Result<RecoveryReport, disrobe_pass_php::Error> = recover_php(&blob, None);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "a hostile trip count must hit a budget and abstain, not run to completion"
    );
}
