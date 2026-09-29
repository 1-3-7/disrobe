#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
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

use disrobe_pass_php::{
    PhpDetection, PhpKind, RecoveryReport, RecoveryStage, ScanReport, TokKind, Token, detect_php,
    recover_php, signature_scan, tokenize,
};
use php_toolchain::required_corpus;

#[derive(Debug, Clone, Copy)]
struct PinnedTokenStream {
    sample: &'static str,
    tokens: usize,
    variables: usize,
}

const PINNED_TOKEN_STREAMS: [PinnedTokenStream; 5] = [
    PinnedTokenStream {
        sample: "baseline/hello.php",
        tokens: 7,
        variables: 0,
    },
    PinnedTokenStream {
        sample: "better-php-obfuscator/hello.obf.php",
        tokens: 6,
        variables: 0,
    },
    PinnedTokenStream {
        sample: "better-php-obfuscator/edge_cases.obf.php",
        tokens: 2_890,
        variables: 333,
    },
    PinnedTokenStream {
        sample: "megafile/edge_cases.php",
        tokens: 6_467,
        variables: 499,
    },
    PinnedTokenStream {
        sample: "megafile/pre80_edge_cases.php",
        tokens: 2_894,
        variables: 333,
    },
];

const NANEAU_RENAMED_VARIABLE_OCCURRENCES: usize = 264;

fn token_stream(sample: &str) -> Vec<u8> {
    required_corpus(sample)
}

#[test]
fn detects_baseline_hello_as_source_php() {
    let bytes: Vec<u8> = token_stream("baseline/hello.php");
    let det: PhpDetection = detect_php(&bytes);
    assert!(matches!(det.kind, PhpKind::Source | PhpKind::Unknown));
}

#[test]
fn tokenizes_baseline_hello_yields_open_tag() {
    let bytes: Vec<u8> = token_stream("baseline/hello.php");
    let toks: Vec<Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(!toks.is_empty());
    assert!(
        toks.iter()
            .any(|t: &Token<'_>| matches!(t.kind, TokKind::OpenTag))
    );
}

#[test]
fn every_committed_sample_tokenizes_to_its_pinned_stream_length() {
    let mut defects: Vec<String> = Vec::new();
    for pinned in &PINNED_TOKEN_STREAMS {
        let bytes: Vec<u8> = token_stream(pinned.sample);
        let toks: Vec<Token<'_>> = tokenize(&bytes)
            .unwrap_or_else(|e| panic!("tokenize corpus/php/{}: {e}", pinned.sample));
        let variables: usize = toks
            .iter()
            .filter(|t: &&Token<'_>| matches!(t.kind, TokKind::Variable))
            .count();
        if toks.len() != pinned.tokens {
            defects.push(format!(
                "corpus/php/{} tokenizes to {} tokens, pinned at {}. The count is pinned rather \
                 than bounded below so a tokenizer that silently stops early, or a sample that was \
                 edited, fails here instead of clearing a threshold with room to spare",
                pinned.sample,
                toks.len(),
                pinned.tokens
            ));
        }
        if variables != pinned.variables {
            defects.push(format!(
                "corpus/php/{} yields {variables} variable tokens, pinned at {}",
                pinned.sample, pinned.variables
            ));
        }
    }
    assert!(
        defects.is_empty(),
        "{} pinned token streams changed:\n{}",
        defects.len(),
        defects.join("\n")
    );
}

#[test]
fn naneau_obfuscator_renames_variables_consistently() {
    let bytes: Vec<u8> = token_stream("better-php-obfuscator/edge_cases.obf.php");
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    let occurrences: usize = text.matches("$sp").count();
    assert_eq!(
        occurrences, NANEAU_RENAMED_VARIABLE_OCCURRENCES,
        "the committed naneau output renames every variable to `$sp<hex>`, and this sample carries \
         {NANEAU_RENAMED_VARIABLE_OCCURRENCES} of them; it now carries {occurrences}, so either the \
         sample was replaced or it is no longer real obfuscator output"
    );
    let plain: String =
        String::from_utf8_lossy(&token_stream("megafile/pre80_edge_cases.php")).into_owned();
    assert_eq!(
        plain.matches("$sp").count(),
        0,
        "the unobfuscated original must carry none of the renamed variables, otherwise counting \
         them says nothing about the obfuscator"
    );
}

#[test]
fn scans_baseline_hello_no_signature_hits() {
    let bytes: Vec<u8> = token_stream("baseline/hello.php");
    let report: ScanReport = signature_scan(&bytes);
    assert!(report.hits.is_empty(), "unexpected hits: {:?}", report.hits);
}

fn assert_renamed_sample_passes_through_as_plain_source(obfuscated: &str) {
    let obfuscated_bytes: Vec<u8> = token_stream(obfuscated);
    let report: RecoveryReport = recover_php(&obfuscated_bytes, None)
        .unwrap_or_else(|e| panic!("recover corpus/php/{obfuscated}: {e}"));
    assert_eq!(
        report.stage,
        RecoveryStage::PlainSource,
        "corpus/php/{obfuscated} is naneau identifier renaming with no decode layer, so recovery \
         must hand it back as plain source; notes {:?}",
        report.notes
    );
    assert_eq!(
        report.output.as_bytes(),
        obfuscated_bytes.as_slice(),
        "a plain-source pass-through must return corpus/php/{obfuscated} byte for byte"
    );
}

#[test]
fn real_naneau_hello_passes_through_as_plain_source() {
    assert_renamed_sample_passes_through_as_plain_source("better-php-obfuscator/hello.obf.php");
}

#[test]
fn real_naneau_megafile_passes_through_as_plain_source() {
    assert_renamed_sample_passes_through_as_plain_source(
        "better-php-obfuscator/edge_cases.obf.php",
    );
}

fn has_pinned_readonly_parent_mismatch(source: &str) -> bool {
    source.contains("abstract class AbstractEntity")
        && !source.contains("readonly abstract class AbstractEntity")
        && source.contains("readonly class User extends AbstractEntity")
}

#[test]
fn the_php8_megafile_has_the_pinned_readonly_parent_mismatch_and_is_graded_statically_only() {
    let source: String = String::from_utf8(token_stream("megafile/edge_cases.php"))
        .expect("the committed PHP source must be valid UTF-8");
    assert!(
        has_pinned_readonly_parent_mismatch(&source),
        "corpus/php/megafile/edge_cases.php must retain the readonly User subclass of the \
         non-readonly AbstractEntity parent that PHP rejects; without that exact incompatibility \
         its static-only grade is no longer justified"
    );

    let mutant: String = source.replacen(
        "readonly class User extends AbstractEntity",
        "final class User extends AbstractEntity",
        1,
    );
    assert!(
        !has_pinned_readonly_parent_mismatch(&mutant),
        "the mutation control must remove the exact readonly-parent mismatch"
    );
}
