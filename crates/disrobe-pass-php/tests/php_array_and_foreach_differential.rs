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

const SAMPLE: &str = "by_reference";

const BY_REFERENCE_HEADERS: [(&str, &str); 5] = [
    ("double_each", "foreach ($rows as &$row) {"),
    ("tag_each", "foreach ($rows as $key => &$row) {"),
    ("scale_grid outer", "foreach ($grid as &$line) {"),
    ("scale_grid inner", "foreach ($line as &$cell) {"),
    ("clamp_each", "foreach ($rows as $key => &$row) {"),
];

const BY_VALUE_HEADERS: [(&str, &str); 4] = [
    ("sum_only", "foreach ($rows as $row) {"),
    ("pairs_only", "foreach ($rows as $key => $row) {"),
    ("join_flat", "foreach ($rows as $row) {"),
    ("join_grid", "foreach ($grid as $line) {"),
];

const KEYED_ARRAY_SITES: [(&str, &str); 4] = [
    ("build_list", "return [$seed, $seed + 1, $seed + 2];"),
    (
        "build_keyed",
        "return ['first' => $seed, 'second' => $seed * 2, 7 => $seed * 3];",
    ),
    (
        "build_dynamic",
        "return [$key => $value, 'fixed' => $value + 1];",
    ),
    (
        "build_grid",
        "return [build_list($seed), build_list($seed + 10)];",
    ),
];

struct Recovery {
    source: String,
    unrecovered: Vec<String>,
}

fn recover(wire: &[u8]) -> Recovery {
    let parsed: OpArray = parse_oparray(wire).unwrap_or_else(|error: disrobe_pass_php::Error| {
        panic!("the tracked {SAMPLE} op array must parse: {error}")
    });
    let first: Decompilation = decompile_oparray(&parsed);
    let second: Decompilation = decompile_oparray(&parsed);
    assert_eq!(
        first.php_skeleton, second.php_skeleton,
        "{SAMPLE} recovered two different sources from one op array, so the output is not \
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

fn assert_recovered() -> String {
    let wire: Vec<u8> = required_fixture(&format!("oparray_foreach/{SAMPLE}.dzoa"));
    let recovery: Recovery = recover(&wire);
    assert!(
        recovery.unrecovered.is_empty(),
        "{SAMPLE} is graded as a fully recovered sample, so every opcode the php 8.4 compiler \
         emitted for it must be modelled; these were refused: {:?}\n--- recovered ---\n{}",
        recovery.unrecovered,
        recovery.source
    );
    assert!(
        !recovery.source.contains("disrobe: unrecovered"),
        "{SAMPLE} still carries a refusal marker\n--- recovered ---\n{}",
        recovery.source
    );
    assert!(
        !recovery.source.contains("goto "),
        "{SAMPLE} rendered a jump as goto soup instead of a structured statement\n--- recovered \
         ---\n{}",
        recovery.source
    );
    recovery.source
}

#[test]
fn every_by_reference_foreach_recovers_its_binding_and_no_by_value_foreach_gains_one() {
    let source: String = assert_recovered();
    let headers: usize = count(&source, "foreach (");
    assert_eq!(
        headers,
        BY_REFERENCE_HEADERS.len() + BY_VALUE_HEADERS.len(),
        "{SAMPLE} declares {} foreach sites, so the recovery must produce exactly that many \
         headers\n--- recovered ---\n{source}",
        BY_REFERENCE_HEADERS.len() + BY_VALUE_HEADERS.len()
    );
    let mut restored: usize = 0;
    let mut lost: Vec<&str> = Vec::new();
    for (site, header) in BY_REFERENCE_HEADERS {
        let by_value: String = header.replace("&$", "$");
        if count(&source, header) == 0 {
            lost.push(site);
            assert_eq!(
                count(&source, &by_value),
                0,
                "{site} iterates by reference, so recovering it as `{by_value}` is source that \
                 php 8.4 runs differently from the original\n--- recovered ---\n{source}"
            );
        } else {
            restored += 1;
        }
    }
    assert!(
        lost.is_empty(),
        "{restored}/{} by-reference foreach sites recovered their binding; these lost it: \
         {lost:?}\n--- recovered ---\n{source}",
        BY_REFERENCE_HEADERS.len()
    );
    for (site, header) in BY_VALUE_HEADERS {
        assert!(
            count(&source, header) > 0,
            "{site} iterates by value, so its header must recover as `{header}`\n--- recovered \
             ---\n{source}"
        );
    }
    let by_reference: usize = count(&source, " as &$") + count(&source, "=> &$");
    assert_eq!(
        by_reference,
        BY_REFERENCE_HEADERS.len(),
        "{SAMPLE} declares exactly {} by-reference bindings, so the recovery must not invent one \
         on a by-value foreach\n--- recovered ---\n{source}",
        BY_REFERENCE_HEADERS.len()
    );
}

#[test]
fn every_runtime_array_keeps_the_key_it_was_built_with() {
    let source: String = assert_recovered();
    let mut lost: Vec<&str> = Vec::new();
    let mut restored: usize = 0;
    for (site, statement) in KEYED_ARRAY_SITES {
        if source.contains(statement) {
            restored += 1;
        } else {
            lost.push(site);
        }
    }
    assert!(
        lost.is_empty(),
        "{restored}/{} array construction sites rebuilt their elements and keys; these did not: \
         {lost:?}\n--- recovered ---\n{source}",
        KEYED_ARRAY_SITES.len()
    );
    for dropped in ["['first', 'second', 7]", "[$seed, $seed * 2, $seed * 3]"] {
        assert!(
            !source.contains(dropped),
            "a keyed array recovered as `{dropped}`, which php 8.4 builds with different keys \
             from the original\n--- recovered ---\n{source}"
        );
    }
    let array_keys: usize = source
        .lines()
        .filter(|line: &&str| !line.trim_start().starts_with("foreach ("))
        .map(|line: &str| count(line, " => "))
        .sum();
    assert_eq!(
        array_keys, 5,
        "the sample builds exactly five keyed array elements, so the recovery must not invent or \
         drop one\n--- recovered ---\n{source}"
    );
}

#[test]
fn the_recovered_source_runs_the_same_as_its_original_under_php() {
    let graded: &str = "the php 8.4 by-reference foreach recovery differential";
    let php: PhpRuntime = graded_php(graded);
    assert!(php.banner.starts_with("PHP 8."), "{}", php.banner);
    let recovered: String = assert_recovered();
    let original: Vec<u8> = std::fs::read(fixture_path(&format!("oparray_foreach/{SAMPLE}.php")))
        .expect("read the tracked foreach source");
    let expected: Vec<u8> = php_stdout(&php, "by_reference original", &original);
    let actual: Vec<u8> = php_stdout(&php, "by_reference recovered", recovered.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&actual),
        String::from_utf8_lossy(&expected),
        "{SAMPLE} recovered to source that php 8.4 runs differently from the original\n--- \
         recovered ---\n{recovered}"
    );
}

#[test]
fn a_reset_and_fetch_pair_that_disagree_on_binding_mode_is_refused_rather_than_guessed() {
    let wire: Vec<u8> = required_fixture(&format!("oparray_foreach/{SAMPLE}.dzoa"));
    let mut parsed: OpArray = parse_oparray(&wire).expect("the tracked op array must parse");
    let target: &mut OpArray = parsed
        .children
        .iter_mut()
        .find(|child: &&mut OpArray| child.name.as_deref() == Some("double_each"))
        .expect("the tracked sample declares double_each");
    let reset: &mut disrobe_pass_php::Op = target
        .ops
        .iter_mut()
        .find(|op: &&mut disrobe_pass_php::Op| op.opcode == 125)
        .expect("double_each resets its iterator by reference");
    reset.opcode = 77;
    let recovered: Decompilation = decompile_oparray(&parsed);
    assert!(
        recovered
            .unrecovered
            .iter()
            .any(|entry: &disrobe_pass_php::UnrecoveredOp| entry.mnemonic == "ZEND_FE_RESET_R"),
        "a foreach whose reset and fetch disagree on binding mode is not a php 8 iteration and \
         must be refused by name, got {:?}\n--- recovered ---\n{}",
        recovered.unrecovered,
        recovered.php_skeleton
    );
    assert!(
        !recovered.php_skeleton.contains("goto "),
        "a refused iteration must not render as goto soup\n--- recovered ---\n{}",
        recovered.php_skeleton
    );
}

#[test]
fn an_array_element_whose_value_operand_is_absent_is_refused_rather_than_built_without_it() {
    let wire: Vec<u8> = required_fixture(&format!("oparray_foreach/{SAMPLE}.dzoa"));
    for (mnemonic, opcode) in [
        ("ZEND_INIT_ARRAY", 71_u8),
        ("ZEND_ADD_ARRAY_ELEMENT", 72_u8),
    ] {
        let mut parsed: OpArray = parse_oparray(&wire).expect("the tracked op array must parse");
        let target: &mut OpArray = parsed
            .children
            .iter_mut()
            .find(|child: &&mut OpArray| child.name.as_deref() == Some("build_keyed"))
            .expect("the tracked sample declares build_keyed");
        let element: &mut disrobe_pass_php::Op = target
            .ops
            .iter_mut()
            .find(|op: &&mut disrobe_pass_php::Op| op.opcode == opcode)
            .unwrap_or_else(|| panic!("build_keyed builds a keyed array with {mnemonic}"));
        element.op1_type = disrobe_pass_php::OperandType::Unused;
        element.op1 = 0;
        let recovered: Decompilation = decompile_oparray(&parsed);
        assert!(
            recovered
                .unrecovered
                .iter()
                .any(|entry: &disrobe_pass_php::UnrecoveredOp| entry.mnemonic == mnemonic),
            "a keyed array element with no value operand is not a php 8 array construction and \
             must be refused by name, got {:?}\n--- recovered ---\n{}",
            recovered.unrecovered,
            recovered.php_skeleton
        );
        assert!(
            !recovered.php_skeleton.contains("=> $seed]"),
            "{mnemonic} was refused, so no array may still be rendered from its operands\n--- \
             recovered ---\n{}",
            recovered.php_skeleton
        );
    }
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
fn the_tracked_op_array_reproduces_from_its_tracked_source() {
    let graded: &str =
        "the tracked by-reference foreach op array against the php 8.4 compiler that made it";
    let php: PhpRuntime = graded_php(graded);
    let dll: PathBuf = opcache_dll(&php).unwrap_or_else(|| {
        panic!(
            "{graded} is graded only by recompiling it, so this case cannot report success \
             without the compiler that made it. Missing prerequisite: the php 8.4 opcache \
             extension beside the php binary or at DZOA_OPCACHE_DLL. Toolchain: {}.",
            PHP_OPCACHE.program
        )
    });
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_php_foreach_reemit")
            .expect("create the re-emission scratch directory");
    let tracked: Vec<u8> = std::fs::read(fixture_path(&format!("oparray_foreach/{SAMPLE}.php")))
        .expect("read the tracked foreach source");
    let source_path: PathBuf = scratch.path().join(format!("{SAMPLE}.php"));
    write_opcache_source(&source_path, &tracked).expect("stage the foreach source");
    let produced: PathBuf = scratch.path().join(format!("{SAMPLE}.dzoa"));
    let output: Output = Command::new(&php.binary)
        .env("DZOA_OPCACHE_DLL", &dll)
        .arg(emitter())
        .arg(&source_path)
        .arg(&produced)
        .output()
        .expect("run the php 8.4 op array emitter");
    assert!(
        output.status.success(),
        "{graded} could not be measured because the php 8.4 opcache extension emitted no op array \
         dump, and a comparison that runs nothing must not report success: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let fresh: Vec<u8> = std::fs::read(&produced).expect("read the re-emitted op array");
    assert_eq!(
        fresh,
        required_fixture(&format!("oparray_foreach/{SAMPLE}.dzoa")),
        "the tracked {SAMPLE} op array no longer reproduces from its tracked source under {}, so \
         the recovery is being graded against a stale compiler artefact",
        php.banner
    );
}
