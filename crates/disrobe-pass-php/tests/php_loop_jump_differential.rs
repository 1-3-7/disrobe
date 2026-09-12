#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
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

use disrobe_pass_php::{Decompilation, OpArray, decompile_oparray, parse_oparray};
use php_toolchain::{
    PHP_OPCACHE, PhpRun, PhpRuntime, fixture_path, require_php, required_fixture, unmeasured,
    write_opcache_source,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SAMPLES: [&str; 4] = [
    "while_jumps",
    "for_jumps",
    "nested_levels",
    "switch_in_loop",
];

struct Recovery {
    source: String,
    unrecovered: Vec<String>,
}

fn recover(sample: &str, wire: &[u8]) -> Recovery {
    let parsed: OpArray = parse_oparray(wire).unwrap_or_else(|error: disrobe_pass_php::Error| {
        panic!("the tracked {sample} op array must parse: {error}")
    });
    let first: Decompilation = decompile_oparray(&parsed);
    let second: Decompilation = decompile_oparray(&parsed);
    assert_eq!(
        first.php_skeleton, second.php_skeleton,
        "{sample} recovered two different sources from one op array, so the output is not \
         deterministic"
    );
    Recovery {
        unrecovered: first
            .unrecovered
            .iter()
            .map(|record: &disrobe_pass_php::UnrecoveredOp| {
                format!(
                    "{} at op {} ({})",
                    record.mnemonic, record.index, record.reason
                )
            })
            .collect(),
        source: first.php_skeleton,
    }
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn assert_statement_counts(sample: &str, source: &str, expected: &[(&str, usize)]) {
    for (statement, wanted) in expected {
        let seen: usize = source
            .lines()
            .filter(|line: &&str| line.trim() == *statement)
            .count();
        assert_eq!(
            seen, *wanted,
            "{sample} must recover exactly {wanted} `{statement}` statement(s), found \
             {seen}\n--- recovered ---\n{source}"
        );
    }
}

fn assert_no_generated_names(sample: &str, source: &str) {
    for prefix in ["$v", "~", "@"] {
        let bytes: &[u8] = source.as_bytes();
        let mut from: usize = 0;
        while let Some(hit) = source[from..].find(prefix) {
            let start: usize = from + hit;
            let mut end: usize = start + prefix.len();
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            let digits: usize = end - start - prefix.len();
            let boundary: bool = bytes
                .get(end)
                .is_none_or(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_');
            assert!(
                digits == 0 || !boundary,
                "{sample} kept the generated slot name {} instead of a data-flow name\n--- \
                 recovered ---\n{source}",
                &source[start..end]
            );
            from = start + prefix.len();
        }
    }
}

fn assert_recovered(sample: &str) -> String {
    let wire: Vec<u8> = required_fixture(&format!("oparray_loops/{sample}.dzoa"));
    let recovery: Recovery = recover(sample, &wire);
    assert!(
        recovery.unrecovered.is_empty(),
        "{sample} is graded as a fully recovered sample, so every opcode the php 8.4 compiler \
         emitted for it must be modelled; these were refused: {:?}\n--- recovered ---\n{}",
        recovery.unrecovered,
        recovery.source
    );
    assert!(
        !recovery.source.contains("disrobe: unrecovered"),
        "{sample} still carries a refusal marker\n--- recovered ---\n{}",
        recovery.source
    );
    assert!(
        !recovery.source.contains("goto "),
        "{sample} rendered a jump as goto soup instead of a structured statement\n--- recovered \
         ---\n{}",
        recovery.source
    );
    for forbidden in ["break 0;", "continue 0;", "break 1;", "continue 1;"] {
        assert!(
            !recovery.source.contains(forbidden),
            "{sample} emitted `{forbidden}`, which php rejects or which names a level php spells \
             without a number\n--- recovered ---\n{}",
            recovery.source
        );
    }
    assert_no_generated_names(sample, &recovery.source);
    recovery.source
}

fn php_stdout(php: &PhpRuntime, label: &str, source: &[u8]) -> Vec<u8> {
    let run: PhpRun = php.run_reporting_errors(label, source);
    assert!(
        run.exited_clean,
        "{label} did not run cleanly under {}: {}",
        php.banner, run.stderr
    );
    assert!(
        run.stderr.is_empty(),
        "{label} produced diagnostics under {}, so a behavioural comparison would hide them: {}",
        php.banner,
        run.stderr
    );
    assert!(
        !run.stdout.is_empty(),
        "{label} printed nothing, so comparing against it would accept a recovery that also \
         prints nothing"
    );
    run.stdout
}

fn assert_runtime_equivalent(php: &PhpRuntime, sample: &str, recovered: &str) {
    let original: Vec<u8> = std::fs::read(fixture_path(&format!("oparray_loops/{sample}.php")))
        .expect("read the tracked loop-jump source");
    let expected: Vec<u8> = php_stdout(php, &format!("{sample} original"), &original);
    let actual: Vec<u8> = php_stdout(php, &format!("{sample} recovered"), recovered.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&actual),
        String::from_utf8_lossy(&expected),
        "{sample} recovered to source that php 8.4 runs differently from the original\n--- \
         recovered ---\n{recovered}"
    );
}

fn opcache_dll(php: &PhpRuntime) -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("DZOA_OPCACHE_DLL") {
        let path: PathBuf = PathBuf::from(configured);
        return path.is_file().then_some(path);
    }
    let directory: &Path = php.binary.parent()?;
    ["ext/php_opcache.dll", "php_opcache.dll", "ext/opcache.so"]
        .into_iter()
        .map(|relative: &str| directory.join(relative))
        .find(|candidate: &PathBuf| candidate.is_file())
}

fn emitter() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("php")
        .join("oparray")
        .join("emit_dzoa.php")
}

#[test]
fn while_and_do_while_jumps_recover_as_break_and_continue() {
    let source: String = assert_recovered("while_jumps");
    assert_statement_counts(
        "while_jumps",
        &source,
        &[
            ("continue;", 4),
            ("break;", 3),
            ("} while ($step < 20);", 1),
        ],
    );
    assert_eq!(count(&source, "while ($index < 12) {"), 1, "{source}");
    assert_eq!(count(&source, "while (true) {"), 1, "{source}");
    assert_eq!(count(&source, "do {"), 1, "{source}");
}

#[test]
fn a_for_loop_step_is_reconstructed_when_a_continue_edge_names_it() {
    let source: String = assert_recovered("for_jumps");
    assert_eq!(count(&source, "for (; $i < 10; ++$i) {"), 1, "{source}");
    assert_eq!(count(&source, "for (; $k < 12; ++$k) {"), 1, "{source}");
    assert_eq!(
        count(&source, "for (; $a < $b; ++$a, --$b) {"),
        1,
        "{source}"
    );
    assert_eq!(count(&source, "while ($j < 10) {"), 1, "{source}");
    assert_statement_counts("for_jumps", &source, &[("continue;", 3), ("break;", 2)]);
}

#[test]
fn multi_level_jumps_carry_the_level_php_compiled() {
    let source: String = assert_recovered("nested_levels");
    assert_statement_counts(
        "nested_levels",
        &source,
        &[
            ("continue;", 1),
            ("break;", 1),
            ("continue 2;", 2),
            ("break 2;", 2),
            ("continue 3;", 1),
            ("break 3;", 1),
        ],
    );
    assert_eq!(
        count(&source, "foreach ($rows as $key => $row) {"),
        1,
        "{source}"
    );
    assert_eq!(count(&source, "foreach ($cols as $col) {"), 2, "{source}");
    assert_eq!(count(&source, "for (; $x < 3; ++$x) {"), 1, "{source}");
}

#[test]
fn a_switch_between_a_jump_and_its_loop_counts_as_one_level() {
    let source: String = assert_recovered("switch_in_loop");
    assert_statement_counts(
        "switch_in_loop",
        &source,
        &[("continue 2;", 2), ("break 2;", 2), ("break;", 2)],
    );
    assert_eq!(count(&source, "switch ($code) {"), 1, "{source}");
    assert_eq!(count(&source, "switch ($n) {"), 1, "{source}");
    for label in ["case 1:", "case 2:", "case 3:", "case 4:", "case 5:"] {
        assert!(source.contains(label), "{label} missing\n{source}");
    }
    assert_eq!(count(&source, "default:"), 2, "{source}");
}

#[test]
fn every_loop_jump_sample_runs_the_same_as_its_original_under_php() {
    let graded: &str = "the php 8.4 loop break and continue recovery differential";
    let Some(php): Option<PhpRuntime> = require_php(graded) else {
        return;
    };
    assert!(php.banner.starts_with("PHP 8."), "{}", php.banner);
    for sample in SAMPLES {
        let source: String = assert_recovered(sample);
        assert_runtime_equivalent(&php, sample, &source);
    }
}

#[test]
fn the_tracked_op_arrays_reproduce_from_their_tracked_sources() {
    let graded: &str =
        "the tracked loop-jump op arrays against the php 8.4 compiler that made them";
    let Some(php): Option<PhpRuntime> = require_php(graded) else {
        return;
    };
    let Some(dll): Option<PathBuf> = opcache_dll(&php) else {
        unmeasured(
            &PHP_OPCACHE,
            graded,
            "the opcache extension was not found beside the php binary",
        );
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_loop_jump_reemit")
            .expect("create the re-emission scratch directory");
    for sample in SAMPLES {
        let tracked: Vec<u8> = std::fs::read(fixture_path(&format!("oparray_loops/{sample}.php")))
            .expect("read the tracked loop-jump source");
        let source_path: PathBuf = scratch.path().join(format!("{sample}.php"));
        write_opcache_source(&source_path, &tracked).expect("stage the loop-jump source");
        let produced: PathBuf = scratch.path().join(format!("{sample}.dzoa"));
        let output: Output = Command::new(&php.binary)
            .env("DZOA_OPCACHE_DLL", &dll)
            .arg(emitter())
            .arg(&source_path)
            .arg(&produced)
            .output()
            .expect("run the php 8.4 op array emitter");
        if !output.status.success() {
            unmeasured(
                &PHP_OPCACHE,
                graded,
                &format!(
                    "the php 8.4 opcache extension emitted no op array dump for {sample}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            );
            return;
        }
        let fresh: Vec<u8> = std::fs::read(&produced).expect("read the re-emitted op array");
        assert_eq!(
            fresh,
            required_fixture(&format!("oparray_loops/{sample}.dzoa")),
            "the tracked {sample} op array no longer reproduces from its tracked source under {}, \
             so the recovery is being graded against a stale compiler artefact",
            php.banner
        );
    }
}
