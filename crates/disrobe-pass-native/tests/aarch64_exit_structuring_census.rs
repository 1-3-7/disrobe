#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;

use disrobe_pass_native::{LeafRecovery, recover_aarch64_function};

const CASES: &[(&str, &str, &[u8])] = &include!("aarch64_recovery_corpus.inc");
const EARLY_EXIT_REJECT: &str = "multiple/early returns not in forward-skip class";
const EARLY_EXIT_REJECT_CEILING: usize = 2;
const RECOVERED_FLOOR: usize = 1247;

fn corpus_fingerprint(digests: &BTreeMap<String, String>) -> String {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    for (case, digest) in digests {
        hasher.update(case.as_bytes());
        hasher.update(b" ");
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

fn recovered_source_digests() -> BTreeMap<String, String> {
    CASES
        .iter()
        .filter_map(|(opt, name, bytes): &(&str, &str, &[u8])| {
            let recovery: LeafRecovery = recover_aarch64_function(bytes, 0).ok()?;
            Some((
                format!("{opt}/{name}"),
                blake3::hash(recovery.source.as_bytes())
                    .to_hex()
                    .to_string(),
            ))
        })
        .collect()
}

fn reason_bucket(message: &str) -> String {
    let trimmed: &str = message
        .split_once("llvm-ir text parse failed: ")
        .map_or(message, |(_, rest): (&str, &str)| rest);
    let head: &str = trimmed.split(" at 0x").next().unwrap_or(trimmed);
    head.to_owned()
}

#[test]
fn aarch64_corpus_exit_structuring_census() {
    let mut recovered: usize = 0;
    let mut rejected: usize = 0;
    let mut early_exit_rejected: Vec<String> = Vec::new();
    let mut buckets: BTreeMap<String, usize> = BTreeMap::new();

    let mut source_digest: BTreeMap<String, String> = BTreeMap::new();
    for (opt, name, bytes) in CASES {
        match recover_aarch64_function(bytes, 0) {
            Ok(recovery) => {
                recovered += 1;
                source_digest.insert(
                    format!("{opt}/{name}"),
                    blake3::hash(recovery.source.as_bytes())
                        .to_hex()
                        .to_string(),
                );
            }
            Err(error) => {
                rejected += 1;
                let message: String = error.to_string();
                if message.contains(EARLY_EXIT_REJECT) {
                    early_exit_rejected.push(format!("{opt}/{name}"));
                }
                *buckets.entry(reason_bucket(&message)).or_default() += 1;
            }
        }
    }

    for (bucket, count) in &buckets {
        println!("aarch64 abstention bucket {count:>4}  {bucket}");
    }
    if std::env::var_os("DISROBE_AARCH64_SOURCE_DIGEST").is_some() {
        for (case, digest) in &source_digest {
            println!("aarch64 source digest {case} {digest}");
        }
    }
    println!(
        "aarch64 recovered-source fingerprint {}",
        corpus_fingerprint(&source_digest)
    );
    println!(
        "aarch64 census: cases={} recovered={recovered} rejected={rejected} early_exit_rejected={}",
        CASES.len(),
        early_exit_rejected.len()
    );
    if !early_exit_rejected.is_empty() {
        println!("aarch64 early-exit rejects: {early_exit_rejected:?}");
    }

    assert!(
        recovered >= RECOVERED_FLOOR,
        "aarch64 corpus recovery fell below the recorded floor: {recovered} of {}, floor {RECOVERED_FLOOR}",
        CASES.len()
    );
    assert!(
        early_exit_rejected.len() <= EARLY_EXIT_REJECT_CEILING,
        "more aarch64 corpus functions hit the early-exit structuring abstention than the recorded ceiling {EARLY_EXIT_REJECT_CEILING}: {early_exit_rejected:?}"
    );
}

#[test]
fn aarch64_corpus_recovered_source_is_deterministic() {
    let first: BTreeMap<String, String> = recovered_source_digests();
    let second: BTreeMap<String, String> = recovered_source_digests();
    assert_eq!(
        first, second,
        "aarch64 recovered source must be byte-identical across repeated runs"
    );
    let recovered_now: usize = CASES
        .iter()
        .filter(|(_opt, _name, bytes): &&(&str, &str, &[u8])| {
            recover_aarch64_function(bytes, 0).is_ok()
        })
        .count();
    assert_eq!(
        first.len(),
        recovered_now,
        "the determinism sweep must cover every recovered corpus case, not a count pinned \
         separately: the sweep digested {} of the {recovered_now} cases that recover today",
        first.len()
    );
    assert!(
        recovered_now >= RECOVERED_FLOOR,
        "the determinism sweep covers {recovered_now} recovered case(s), below the floor \
         {RECOVERED_FLOOR} the census enforces"
    );
}
