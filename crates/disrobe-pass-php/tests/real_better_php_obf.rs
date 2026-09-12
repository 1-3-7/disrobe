#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
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
    PhpDetection, PhpKind, RecoveryReport, ScanReport, TokKind, Token, detect_php, recover_php,
    signature_scan, tokenize,
};
use php_toolchain::{PhpRun, PhpRuntime, require_php, required_corpus};

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

fn assert_obfuscated_pair_is_behaviorally_identical(obfuscated: &str, original: &str) {
    let graded: String = format!(
        "the real naneau sample corpus/php/{obfuscated} against its original corpus/php/{original}"
    );
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let original_bytes: Vec<u8> = token_stream(original);
    let obfuscated_bytes: Vec<u8> = token_stream(obfuscated);

    let original_run: PhpRun = php.run_reporting_errors(original, &original_bytes);
    assert!(
        original_run.exited_clean,
        "corpus/php/{original} does not run under {}, so nothing can be graded against its output: \
         {}",
        php.banner, original_run.stderr
    );
    assert!(
        !original_run.stdout.is_empty(),
        "corpus/php/{original} prints nothing, so stdout comparison would accept any sample that \
         also prints nothing"
    );

    let obfuscated_stdout: Vec<u8> = php.stdout_of(obfuscated, &obfuscated_bytes);
    assert_eq!(
        String::from_utf8_lossy(&obfuscated_stdout),
        String::from_utf8_lossy(&original_run.stdout),
        "corpus/php/{obfuscated} does not behave like corpus/php/{original} under {}, so the pair \
         is not a real before-and-after and any recovery graded over it proves nothing",
        php.banner
    );

    let report: RecoveryReport = recover_php(&obfuscated_bytes, None)
        .unwrap_or_else(|e| panic!("recover corpus/php/{obfuscated}: {e}"));
    let recovered_stdout: Vec<u8> =
        php.stdout_of(&format!("{obfuscated} recovered"), report.output.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&recovered_stdout),
        String::from_utf8_lossy(&original_run.stdout),
        "what this crate hands back for corpus/php/{obfuscated} at stage {:?} no longer prints what \
         corpus/php/{original} prints",
        report.stage
    );
    println!(
        "corpus/php/{obfuscated} graded against corpus/php/{original} under {}",
        php.banner
    );
}

#[test]
fn real_naneau_hello_matches_its_original_under_php() {
    assert_obfuscated_pair_is_behaviorally_identical(
        "better-php-obfuscator/hello.obf.php",
        "baseline/hello.php",
    );
}

#[test]
fn real_naneau_megafile_matches_its_original_under_php() {
    assert_obfuscated_pair_is_behaviorally_identical(
        "better-php-obfuscator/edge_cases.obf.php",
        "megafile/pre80_edge_cases.php",
    );
}

#[test]
fn the_php8_megafile_does_not_run_on_this_interpreter_and_is_graded_statically_only() {
    let graded: String =
        "the runnability of corpus/php/megafile/edge_cases.php on the host interpreter".to_owned();
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let bytes: Vec<u8> = token_stream("megafile/edge_cases.php");
    let run: PhpRun = php.run_reporting_errors("megafile/edge_cases.php", &bytes);
    assert!(
        !run.exited_clean,
        "corpus/php/megafile/edge_cases.php now runs under {}, so the execution differentials in \
         this crate can be extended to cover it; this case exists so that fact cannot go unnoticed",
        php.banner
    );
    assert!(
        run.stderr.contains("Readonly class"),
        "corpus/php/megafile/edge_cases.php is pinned as unrunnable for one specific reason, a \
         readonly class extending a non-readonly parent, which php 8.2 rejects. It now fails for a \
         different reason, so what this sample can and cannot be graded on is no longer understood: \
         {}",
        run.stderr
    );
    println!(
        "corpus/php/megafile/edge_cases.php is parsed and tokenized but cannot be executed here: {}",
        run.stderr.lines().next().unwrap_or_default()
    );
}
