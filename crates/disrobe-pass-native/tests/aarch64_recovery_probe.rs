#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::recover_aarch64_function;
use std::collections::BTreeMap;

const CASES: &[(&str, &str, &[u8])] = &include!("aarch64_recovery_corpus.inc");

const RECOVERY_FLOOR: usize = 249;

#[test]
fn aarch64_recovery_corpus_meets_the_floor() {
    let mut recovered: usize = 0;
    let mut rejects: BTreeMap<String, usize> = BTreeMap::new();
    for (opt, name, bytes) in CASES {
        match recover_aarch64_function(bytes, 0) {
            Ok(_) => recovered += 1,
            Err(error) => {
                let message: String = format!("{error:?}");
                let tail: &str = message.split("aarch64 reject: ").nth(1).unwrap_or(&message);
                let bucket: String = tail
                    .split(" `")
                    .next()
                    .unwrap_or(tail)
                    .chars()
                    .take(64)
                    .collect();
                *rejects.entry(bucket).or_default() += 1;
                let reason: String = tail.chars().take(90).collect();
                eprintln!("REJECT {opt} {name}: {reason}");
            }
        }
    }
    eprintln!(
        "=== aarch64 recovery {recovered}/{} (non-rejection rate, NOT a correctness claim; see aarch64_recovery_grade) ===",
        CASES.len()
    );
    let mut ordered: Vec<(&String, &usize)> = rejects.iter().collect();
    ordered.sort_by(|left: &(&String, &usize), right: &(&String, &usize)| right.1.cmp(left.1));
    for (bucket, count) in ordered {
        eprintln!("  {count}x  {bucket}");
    }
    assert!(
        recovered >= RECOVERY_FLOOR,
        "aarch64 recovery {recovered}/{} regressed below the floor {RECOVERY_FLOOR}",
        CASES.len()
    );
}
