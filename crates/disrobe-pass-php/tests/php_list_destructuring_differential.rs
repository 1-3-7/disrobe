#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
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

use disrobe_pass_php::{Decompilation, Op, OpArray, OperandType, decompile_oparray, parse_oparray};
use php_toolchain::{PHP, PhpRun, PhpRuntime, ToolchainRequirement, required_fixture};

const SAMPLE: &str = "oparray_list/destructuring";
const FETCH_LIST_R: u8 = 98;
const FREE: u8 = 70;
type OpMutation = fn(&mut Op);

fn graded_php(graded: &str) -> PhpRuntime {
    php_toolchain::require_with_requirement(&PHP, graded, ToolchainRequirement::Mandatory)
        .unwrap_or_else(|| {
            panic!(
                "{graded} requires a php 8.4 interpreter at DISROBE_PHP_BIN; a missing runtime \
                 cannot count as a passing differential"
            )
        })
}

fn parsed_fixture() -> OpArray {
    let wire: Vec<u8> = required_fixture(&format!("{SAMPLE}.dzoa"));
    parse_oparray(&wire).expect("parse the tracked php 8.4 list-destructuring op array")
}

fn recovered(parsed: &OpArray) -> Decompilation {
    let first: Decompilation = decompile_oparray(parsed);
    let second: Decompilation = decompile_oparray(parsed);
    assert_eq!(first.php_skeleton, second.php_skeleton);
    assert_eq!(first.unrecovered, second.unrecovered);
    first
}

fn fully_recovered() -> String {
    let result: Decompilation = recovered(&parsed_fixture());
    assert!(
        result.unrecovered.is_empty(),
        "the tracked php 8.4 list-destructuring sample must recover every opcode: {:?}\n{}",
        result.unrecovered,
        result.php_skeleton
    );
    assert!(
        result.limitations.is_empty(),
        "the tracked php 8.4 list-destructuring sample must emit no opacity limitations: {:?}\n{}",
        result.limitations,
        result.php_skeleton
    );
    result.php_skeleton
}

fn php_stdout(php: &PhpRuntime, label: &str, source: &[u8]) -> Vec<u8> {
    let run: PhpRun = php.run_reporting_errors(label, source);
    assert!(
        run.exited_clean,
        "{label} failed under {}: {}\n{}",
        php.banner,
        run.stderr,
        String::from_utf8_lossy(source)
    );
    assert!(run.stderr.is_empty(), "{label}: {}", run.stderr);
    assert!(
        !run.stdout.is_empty(),
        "{label} printed no gradeable output"
    );
    run.stdout
}

#[test]
fn php_84_list_fetches_recover_their_distinguishable_shape() {
    let source: String = fully_recovered();
    let expected: [&str; 5] = [
        "[$first, $second] = $values;",
        "[$first, , $third] = $values;",
        "['left' => $left, 7 => $seventh] = $values;",
        "[$head, ['value' => $inside]] = $values;",
        "[[$first, $second], $tail] = $values;",
    ];
    let missing: Vec<&str> = expected
        .into_iter()
        .filter(|statement: &&str| !source.contains(*statement))
        .collect();
    assert!(
        missing.is_empty(),
        "{}/{} list assignments recovered with their container-proven keys and nesting; missing \
         {missing:?}\n{source}",
        expected.len() - missing.len(),
        expected.len()
    );
    for statement in [
        "$_disrobe_list_2 = $values;",
        "[$values] = $_disrobe_list_2;",
        "$copy = $_disrobe_list_2;",
    ] {
        assert!(
            source.contains(statement),
            "the reused assignment container must be evaluated once before its target overwrites \
             it; missing `{statement}`\n{source}"
        );
    }
}

#[test]
fn recovered_list_destructuring_matches_php_84_behavior() {
    let graded: &str = "the php 8.4 list-destructuring recovery differential";
    let php: PhpRuntime = graded_php(graded);
    let original: Vec<u8> = required_fixture(&format!("{SAMPLE}.php"));
    let source: String = fully_recovered();
    let expected: Vec<u8> = php_stdout(&php, "list original", &original);
    let actual: Vec<u8> = php_stdout(&php, "list recovered", source.as_bytes());
    assert_eq!(
        actual, expected,
        "the recovered list assignments run differently from the php 8.4 source\n{source}"
    );
    let wrong: String = source.replace(
        "[$first, , $third] = $values;",
        "[$first, $third] = $values;",
    );
    let counterfactual: Vec<u8> = php_stdout(&php, "list wrong-position control", wrong.as_bytes());
    assert_ne!(
        counterfactual, expected,
        "the differential must reject a recovery that loses the skipped position"
    );
}

#[test]
fn every_php_84_fetch_list_site_is_recovered_once() {
    let parsed: OpArray = parsed_fixture();
    let population: Vec<String> = parsed
        .children
        .iter()
        .flat_map(|child: &OpArray| {
            child
                .ops
                .iter()
                .enumerate()
                .filter(|(_, op): &(usize, &Op)| op.opcode == FETCH_LIST_R)
                .map(|(index, _): (usize, &Op)| {
                    format!("{}#{index}", child.name.as_deref().unwrap_or("$_main"))
                })
        })
        .collect();
    assert_eq!(
        population,
        [
            "simple#2",
            "simple#4",
            "skipped#2",
            "skipped#4",
            "keyed#2",
            "keyed#4",
            "nested#2",
            "nested#4",
            "nested#5",
            "reused#2",
            "nested_multiple#2",
            "nested_multiple#3",
            "nested_multiple#5",
            "nested_multiple#8",
        ]
    );
    let source: String = fully_recovered();
    assert_eq!(source.matches(" = $values;").count(), 6);
}

#[test]
fn dynamic_or_out_of_range_list_operands_are_refused_by_name() {
    let cases: [(&str, OpMutation); 3] = [
        ("dynamic key", |op: &mut Op| {
            op.op2_type = OperandType::Cv;
            op.op2 = 0;
        }),
        ("out-of-range literal", |op: &mut Op| {
            op.op2_type = OperandType::Const;
            op.op2 = u32::MAX;
        }),
        ("undefined container", |op: &mut Op| {
            op.op1_type = OperandType::TmpVar;
            op.op1 = u32::MAX;
        }),
    ];
    for (label, mutate) in cases {
        let mut parsed: OpArray = parsed_fixture();
        let simple: &mut OpArray = parsed
            .children
            .iter_mut()
            .find(|child: &&mut OpArray| child.name.as_deref() == Some("simple"))
            .expect("simple function");
        let fetch: &mut Op = simple
            .ops
            .iter_mut()
            .find(|op: &&mut Op| op.opcode == FETCH_LIST_R)
            .expect("simple FETCH_LIST_R");
        mutate(fetch);
        let result: Decompilation = recovered(&parsed);
        assert!(
            result.unrecovered.iter().any(|entry| {
                entry.mnemonic == "ZEND_FETCH_LIST_R"
                    && entry.reason
                        == "list destructuring requires a literal key, a defined container, and \
                            one bounded assignment tree"
            }),
            "{label} must be refused as FETCH_LIST_R: {:?}\n{}",
            result.unrecovered,
            result.php_skeleton
        );
        assert!(
            !result.php_skeleton.contains("[$first, $second] = $values;"),
            "{label} cannot retain the recovered list statement\n{}",
            result.php_skeleton
        );
    }
}

#[test]
fn a_list_fetch_without_its_exact_assignment_is_refused() {
    let mut parsed: OpArray = parsed_fixture();
    let simple: &mut OpArray = parsed
        .children
        .iter_mut()
        .find(|child: &&mut OpArray| child.name.as_deref() == Some("simple"))
        .expect("simple function");
    let assignment: &mut Op = simple
        .ops
        .iter_mut()
        .find(|op: &&mut Op| op.opcode == 22)
        .expect("simple assignment");
    assignment.op2 = assignment.op2.saturating_add(1);
    let result: Decompilation = recovered(&parsed);
    assert!(
        result
            .unrecovered
            .iter()
            .any(|entry| entry.mnemonic == "ZEND_FETCH_LIST_R"),
        "a broken fetch-to-assignment edge must be refused: {:?}\n{}",
        result.unrecovered,
        result.php_skeleton
    );
    assert!(!result.php_skeleton.contains("[$first, $second] = $values;"));
}

#[test]
fn a_nested_list_free_with_switch_metadata_is_refused() {
    let mut parsed: OpArray = parsed_fixture();
    let nested: &mut OpArray = parsed
        .children
        .iter_mut()
        .find(|child: &&mut OpArray| child.name.as_deref() == Some("nested"))
        .expect("nested function");
    let free: &mut Op = nested
        .ops
        .iter_mut()
        .find(|op: &&mut Op| op.opcode == FREE)
        .expect("nested list FREE");
    free.extended_value = 1;

    let result: Decompilation = recovered(&parsed);
    assert!(
        result
            .unrecovered
            .iter()
            .any(|entry| entry.mnemonic == "ZEND_FETCH_LIST_R"),
        "a list FREE carrying switch metadata must refuse the FETCH_LIST_R tree: {:?}\n{}",
        result.unrecovered,
        result.php_skeleton
    );
    assert!(
        !result
            .php_skeleton
            .contains("[$head, ['value' => $inside]] = $values;"),
        "a malformed list terminator cannot retain the recovered assignment\n{}",
        result.php_skeleton
    );
}
