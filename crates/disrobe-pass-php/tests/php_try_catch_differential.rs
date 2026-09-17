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
    PHP, PHP_OPCACHE, PhpRun, PhpRuntime, ToolchainRequirement, fixture_path,
    require_with_requirement, required_fixture, write_opcache_source,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SAMPLES: [&str; 2] = ["try_catch", "try_finally"];

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

fn graded_php(graded: &str) -> PhpRuntime {
    require_with_requirement(&PHP, graded, ToolchainRequirement::Mandatory).unwrap_or_else(|| {
        panic!(
            "{graded} is graded only by running php, so this case cannot report success without \
             it. Missing prerequisite: a php 8.4 interpreter on PATH or at DISROBE_PHP_BIN."
        )
    })
}

fn assert_recovered(sample: &str) -> String {
    let wire: Vec<u8> = required_fixture(&format!("oparray_try/{sample}.dzoa"));
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
    recovery.source
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

#[test]
fn catch_clauses_recover_with_their_declared_types_and_binding() {
    let source: String = assert_recovered("try_catch");
    assert_no_generated_names("try_catch", &source);
    assert_eq!(count(&source, "try {"), 7, "{source}");
    for (clause, wanted) in [
        ("} catch (\\InvalidArgumentException $error) {", 1),
        (
            "} catch (\\RuntimeException | \\LogicException $error) {",
            1,
        ),
        ("} catch (\\RuntimeException $error) {", 1),
        ("} catch (\\RuntimeException) {", 1),
        ("} catch (\\Throwable $other) {", 2),
        ("} catch (\\Throwable $error) {", 2),
    ] {
        assert_eq!(
            count(&source, clause),
            wanted,
            "try_catch must recover exactly {wanted} `{clause}` clause(s)\n--- recovered \
             ---\n{source}"
        );
    }
    assert!(
        !source.contains("finally"),
        "try_catch has no finally block, so none may be invented\n--- recovered ---\n{source}"
    );
}

#[test]
fn finally_blocks_recover_once_for_every_exit_that_calls_them() {
    let source: String = assert_recovered("try_finally");
    assert_no_generated_names("try_finally", &source);
    assert_eq!(count(&source, "try {"), 7, "{source}");
    assert_eq!(count(&source, "} finally {"), 7, "{source}");
    assert_eq!(
        count(&source, "} catch (\\RuntimeException $error) {"),
        1,
        "{source}"
    );
    for (statement, wanted) in [("continue;", 2), ("break;", 1)] {
        assert_eq!(
            source
                .lines()
                .filter(|line: &&str| line.trim() == statement)
                .count(),
            wanted,
            "try_finally must keep the `{statement}` that leaves a try region through its \
             finally\n--- recovered ---\n{source}"
        );
    }
    assert_eq!(
        count(&source, "for (; $i < $limit; $i = $i + 1) {"),
        1,
        "a for loop whose body holds a try region is lifted twice, so its step must still \
         rebuild\n--- recovered ---\n{source}"
    );
}

#[test]
fn a_try_region_whose_shape_is_not_php_8_is_refused_rather_than_emitted_as_goto_soup() {
    let wire: Vec<u8> = required_fixture("oparray_try/try_catch.dzoa");
    let mut parsed: OpArray = parse_oparray(&wire).expect("the tracked op array must parse");
    let target: &mut OpArray = parsed
        .children
        .iter_mut()
        .find(|child: &&mut OpArray| child.name.as_deref() == Some("classify"))
        .expect("the tracked sample declares classify");
    let row: &mut disrobe_pass_php::TryCatch = target
        .try_catch
        .first_mut()
        .expect("classify carries one try_catch row");
    row.catch_op = Some(row.try_op + 1);
    let recovered: Decompilation = decompile_oparray(&parsed);
    assert!(
        recovered
            .unrecovered
            .iter()
            .any(|entry: &disrobe_pass_php::UnrecoveredOp| entry.mnemonic == "ZEND_CATCH"),
        "a try_catch row that does not describe a php 8 region must be refused by name, got \
         {:?}\n--- recovered ---\n{}",
        recovered.unrecovered,
        recovered.php_skeleton
    );
    let classify_body: &str = recovered
        .php_skeleton
        .split("function classify(")
        .nth(1)
        .and_then(|rest: &str| rest.split("\nfunction ").next())
        .expect("the recovered source declares classify");
    assert!(
        !classify_body.contains("try {"),
        "a try_catch row that does not describe a php 8 region must not have a try header \
         invented for it; the jumps inside it may only be reproduced as the jumps they are\n--- \
         recovered classify ---\n{classify_body}"
    );
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
    let original: Vec<u8> = std::fs::read(fixture_path(&format!("oparray_try/{sample}.php")))
        .expect("read the tracked try-region source");
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
fn every_try_region_sample_runs_the_same_as_its_original_under_php() {
    let graded: &str = "the php 8.4 try, catch and finally recovery differential";
    let php: PhpRuntime = graded_php(graded);
    assert!(php.banner.starts_with("PHP 8."), "{}", php.banner);
    for sample in SAMPLES {
        let source: String = assert_recovered(sample);
        assert_runtime_equivalent(&php, sample, &source);
    }
}

#[test]
fn the_tracked_op_arrays_reproduce_from_their_tracked_sources() {
    let graded: &str =
        "the tracked try-region op arrays against the php 8.4 compiler that made them";
    let php: PhpRuntime = graded_php(graded);
    let dll: PathBuf = opcache_dll(&php).unwrap_or_else(|| {
        panic!(
            "{graded} is graded only by recompiling them, so this case cannot report success \
             without the compiler that made them. Missing prerequisite: the php 8.4 opcache \
             extension beside the php binary or at DZOA_OPCACHE_DLL. Toolchain: {}.",
            PHP_OPCACHE.program
        )
    });
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_try_reemit")
            .expect("create the re-emission scratch directory");
    for sample in SAMPLES {
        let tracked: Vec<u8> = std::fs::read(fixture_path(&format!("oparray_try/{sample}.php")))
            .expect("read the tracked try-region source");
        let source_path: PathBuf = scratch.path().join(format!("{sample}.php"));
        write_opcache_source(&source_path, &tracked).expect("stage the try-region source");
        let produced: PathBuf = scratch.path().join(format!("{sample}.dzoa"));
        let output: Output = Command::new(&php.binary)
            .env("DZOA_OPCACHE_DLL", &dll)
            .arg(emitter())
            .arg(&source_path)
            .arg(&produced)
            .output()
            .expect("run the php 8.4 op array emitter");
        assert!(
            output.status.success(),
            "{graded} could not be measured because the php 8.4 opcache extension emitted no op \
             array dump for {sample}, and a comparison that runs nothing must not report \
             success: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let fresh: Vec<u8> = std::fs::read(&produced).expect("read the re-emitted op array");
        assert_eq!(
            fresh,
            required_fixture(&format!("oparray_try/{sample}.dzoa")),
            "the tracked {sample} op array no longer reproduces from its tracked source under {}, \
             so the recovery is being graded against a stale compiler artefact",
            php.banner
        );
    }
}
