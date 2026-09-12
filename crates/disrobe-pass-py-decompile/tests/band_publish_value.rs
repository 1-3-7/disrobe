#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use common::stdlib_measure::{publish_pct, recovery_document};

const BAND_LABEL_PREFIX: &str = "CPython 3.";

struct RoundingCase {
    num: u64,
    den: u64,
    publish: f64,
    rounded: f64,
}

const CASES: &[RoundingCase] = &[
    RoundingCase {
        num: 5_717,
        den: 5_966,
        publish: 95.82,
        rounded: 95.83,
    },
    RoundingCase {
        num: 5_402,
        den: 5_659,
        publish: 95.45,
        rounded: 95.46,
    },
    RoundingCase {
        num: 6_072,
        den: 6_286,
        publish: 96.59,
        rounded: 96.60,
    },
];

#[test]
fn the_publish_value_truncates_where_rounding_would_disagree() {
    for case in CASES {
        let produced: f64 = publish_pct(case.num, case.den);
        let exact: f64 = (case.num as f64) * 100.0 / (case.den as f64);
        assert!(
            (produced - case.publish).abs() < 1e-9,
            "{} / {} = {exact:.6} publishes as {produced}, not the {} this band records; a \
             publish value is the fraction truncated to two digits",
            case.num,
            case.den,
            case.publish
        );
        assert!(
            (produced - case.rounded).abs() > 1e-9,
            "{} / {} = {exact:.6} is a case where truncation and rounding differ, and this one \
             produced the rounded {}; the whole point of the publish value is that it cannot be \
             the rounded one",
            case.num,
            case.den,
            case.rounded
        );
    }
}

#[test]
fn every_published_band_bar_is_the_truncation_of_its_own_counts() {
    let doc: serde_json::Value = recovery_document();
    let groups: &Vec<serde_json::Value> = doc
        .get("groups")
        .and_then(serde_json::Value::as_array)
        .expect("xtask/data/recovery.json carries no groups array");

    let mut checked: u64 = 0;
    let mut wrong: Vec<String> = Vec::new();
    for group in groups {
        let Some(bars): Option<&Vec<serde_json::Value>> =
            group.get("bars").and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for bar in bars {
            let Some(label): Option<&str> = bar.get("label").and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            if !label.starts_with(BAND_LABEL_PREFIX) {
                continue;
            }
            let Some(num): Option<u64> = bar.get("num").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let Some(den): Option<u64> = bar.get("den").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let Some(value): Option<f64> = bar.get("value").and_then(serde_json::Value::as_f64)
            else {
                continue;
            };
            checked += 1;
            let expected: f64 = publish_pct(num, den);
            let exact: f64 = (num as f64) * 100.0 / (den as f64);
            println!(
                "{label}: {num} / {den} = {exact:.4}, publishes {value}, truncation {expected:.2}"
            );
            if (value - expected).abs() > 1e-9 {
                wrong.push(format!(
                    "`{label}` publishes {value} but {num} / {den} = {exact:.6}, which truncates \
                     to {expected:.2}"
                ));
            }
        }
    }

    assert!(
        checked >= 6,
        "only {checked} CPython band bars were read from xtask/data/recovery.json, so this case \
         graded almost nothing; the bands are published under labels starting `{BAND_LABEL_PREFIX}`"
    );
    assert!(
        wrong.is_empty(),
        "a published band value has to be its own counts truncated to two digits, because the \
         gate that guards it compares the measured percentage against that exact number: {}",
        wrong.join("; ")
    );
}
