#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/evidence_corpus.rs"]
#[allow(clippy::redundant_pub_crate)]
mod evidence_corpus;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use disrobe_mba::{BinOp, Expr, Simplification, Width, simplify};
use evidence_corpus::{
    CASE_KEYS, Case, Truth, corpus_dir, load_cases, load_truths, parse_prefix, read_lines,
    width_from_bits,
};

const PER_ENTRY_BUDGET: Duration = Duration::from_secs(2);
const GRADED_FLOOR: usize = 180;

#[derive(Debug, Clone)]
struct Recovered {
    expression: Expr,
    proven: bool,
    changed: bool,
}

#[derive(Debug, Clone)]
enum Attempt {
    Produced(Recovered),
    BudgetRefusal,
}

#[derive(Debug, Clone)]
struct Landed {
    id: String,
    width: Width,
    attempt: Attempt,
    elapsed: Duration,
    original: Expr,
    original_nodes: usize,
    checks: Vec<(Vec<u64>, u64)>,
}

#[derive(Debug, Clone, Default)]
struct Report {
    total: usize,
    graded: usize,
    failures: Vec<String>,
    matched_ground_truth: usize,
    at_or_below_source_size: usize,
    proven: usize,
}

fn bounded_simplify(obfuscated: &Expr, width: Width) -> (Attempt, Duration) {
    let (sender, receiver): (mpsc::Sender<Recovered>, mpsc::Receiver<Recovered>) = mpsc::channel();
    let payload: Expr = obfuscated.clone();
    let started: Instant = Instant::now();
    let handle: thread::JoinHandle<()> = thread::spawn(move || {
        let simplification: Simplification = simplify(&payload, width);
        let _ = sender.send(Recovered {
            proven: simplification.verification.is_proven(),
            changed: simplification.changed(),
            expression: simplification.simplified,
        });
    });
    receiver.recv_timeout(PER_ENTRY_BUDGET).map_or_else(
        |_| (Attempt::BudgetRefusal, started.elapsed()),
        |recovered: Recovered| {
            let elapsed: Duration = started.elapsed();
            let _ = handle.join();
            (Attempt::Produced(recovered), elapsed)
        },
    )
}

fn corpus() -> &'static (Vec<Case>, BTreeMap<String, Truth>) {
    static LOADED: OnceLock<(Vec<Case>, BTreeMap<String, Truth>)> = OnceLock::new();
    LOADED.get_or_init(|| {
        let directory: PathBuf = corpus_dir();
        let cases: Vec<Case> = load_cases(&directory);
        let truths: Vec<Truth> = load_truths(&directory);
        assert!(!cases.is_empty(), "the corpus is empty");
        assert_eq!(
            cases.len(),
            truths.len(),
            "every case needs exactly one held-out original"
        );
        let indexed: BTreeMap<String, Truth> = truths
            .into_iter()
            .map(|truth: Truth| (truth.id.clone(), truth))
            .collect();
        (cases, indexed)
    })
}

fn landings() -> &'static Vec<Landed> {
    static LANDED: OnceLock<Vec<Landed>> = OnceLock::new();
    LANDED.get_or_init(|| {
        let (cases, truths): &(Vec<Case>, BTreeMap<String, Truth>) = corpus();
        let mut landed: Vec<Landed> = Vec::with_capacity(cases.len());
        for case in cases {
            let truth: &Truth = truths
                .get(&case.id)
                .unwrap_or_else(|| panic!("{}: no held-out original for this case", case.id));
            let width: Width = width_from_bits(case.width);
            let obfuscated: Expr = parse_prefix(&case.obfuscated);
            let (attempt, elapsed): (Attempt, Duration) = bounded_simplify(&obfuscated, width);
            landed.push(Landed {
                id: case.id.clone(),
                width,
                attempt,
                elapsed,
                original: parse_prefix(&truth.original),
                original_nodes: truth.original_nodes,
                checks: truth
                    .checks
                    .iter()
                    .map(|check| (check.inputs.clone(), check.output))
                    .collect(),
            });
        }
        let mut slowest: Vec<&Landed> = landed.iter().collect();
        slowest.sort_by_key(|entry: &&Landed| std::cmp::Reverse(entry.elapsed));
        eprintln!("slowest corpus entries under simplify:");
        for entry in slowest.iter().take(5) {
            eprintln!("  {:>8?}  {}", entry.elapsed, entry.id);
        }
        landed
    })
}

fn swap_add_and_xor(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Binary(BinOp::Add, left, right) => {
            Some(Expr::xor(left.as_ref().clone(), right.as_ref().clone()))
        }
        Expr::Binary(BinOp::Xor, left, right) => {
            Some(Expr::add(left.as_ref().clone(), right.as_ref().clone()))
        }
        Expr::Binary(op, left, right) => swap_add_and_xor(left)
            .map(|rebuilt: Expr| {
                Expr::Binary(*op, Box::new(rebuilt), Box::new(right.as_ref().clone()))
            })
            .or_else(|| {
                swap_add_and_xor(right).map(|rebuilt: Expr| {
                    Expr::Binary(*op, Box::new(left.as_ref().clone()), Box::new(rebuilt))
                })
            }),
        Expr::Unary(op, inner) => {
            swap_add_and_xor(inner).map(|rebuilt: Expr| Expr::Unary(*op, Box::new(rebuilt)))
        }
        _ => None,
    }
}

fn unchanged(recovered: &Recovered) -> Recovered {
    recovered.clone()
}

fn offset_by_one(recovered: &Recovered) -> Recovered {
    Recovered {
        expression: Expr::add(recovered.expression.clone(), Expr::konst(1)),
        proven: true,
        changed: true,
    }
}

fn carry_confusion(recovered: &Recovered) -> Recovered {
    let mutated: Expr = swap_add_and_xor(&recovered.expression)
        .unwrap_or_else(|| Expr::add(recovered.expression.clone(), Expr::konst(1)));
    Recovered {
        expression: mutated,
        proven: true,
        changed: true,
    }
}

fn grade(label: &str, mutate: fn(&Recovered) -> Recovered) -> Report {
    let entries: &Vec<Landed> = landings();
    let mut report: Report = Report {
        total: entries.len(),
        ..Report::default()
    };
    for entry in entries {
        let Attempt::Produced(produced) = &entry.attempt else {
            continue;
        };
        report.graded += 1;
        let candidate: Recovered = mutate(produced);
        let mut divergence: Option<String> = None;
        for (inputs, expected) in &entry.checks {
            let value: u64 = candidate.expression.eval(inputs, entry.width);
            if value != *expected {
                divergence = Some(format!(
                    "{}: recovery returned {value} where the held-out original returns {expected} on inputs {inputs:?}",
                    entry.id
                ));
                break;
            }
        }
        if let Some(detail) = divergence {
            report.failures.push(detail);
            continue;
        }
        if candidate.changed && !candidate.proven {
            report.failures.push(format!(
                "{}: a rewrite was emitted with no established proof",
                entry.id
            ));
            continue;
        }
        if candidate.proven {
            report.proven += 1;
        }
        if candidate.expression == entry.original {
            report.matched_ground_truth += 1;
        }
        if candidate.expression.node_count() <= entry.original_nodes {
            report.at_or_below_source_size += 1;
        }
    }
    eprintln!(
        "{label}: {} graded of {} entries, {} rejected, {} at or below the source size, {} structurally equal to the original, {} carry a proof",
        report.graded,
        report.total,
        report.failures.len(),
        report.at_or_below_source_size,
        report.matched_ground_truth,
        report.proven
    );
    report
}

#[test]
fn published_corpus_size_matches_the_committed_corpus() {
    const GROUP: &str =
        "Ground-truth corpora whose originals the recovery path never reads (counts)";
    const BAR: &str = "Mixed boolean arithmetic";
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("recovery.json parses");
    let published: u64 = document
        .get("groups")
        .and_then(serde_json::Value::as_array)
        .and_then(|groups: &Vec<serde_json::Value>| {
            groups.iter().find(|group: &&serde_json::Value| {
                group.get("heading").and_then(serde_json::Value::as_str) == Some(GROUP)
            })
        })
        .and_then(|group: &serde_json::Value| group.get("bars"))
        .and_then(serde_json::Value::as_array)
        .and_then(|bars: &Vec<serde_json::Value>| {
            bars.iter().find(|bar: &&serde_json::Value| {
                bar.get("label").and_then(serde_json::Value::as_str) == Some(BAR)
            })
        })
        .and_then(|bar: &serde_json::Value| bar.get("value"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("recovery.json has no group {GROUP:?} with bar {BAR:?}"));
    let (cases, _): &(Vec<Case>, BTreeMap<String, Truth>) = corpus();
    assert_eq!(
        published as usize,
        cases.len(),
        "the published corpus count and the committed corpus disagree"
    );
}

#[test]
fn the_case_file_carries_no_ground_truth() {
    let directory: PathBuf = corpus_dir();
    for line in read_lines(&directory.join("cases.jsonl")) {
        let value: serde_json::Value = serde_json::from_str(&line).expect("case record parses");
        let object: &serde_json::Map<String, serde_json::Value> =
            value.as_object().expect("case record is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            CASE_KEYS.to_vec(),
            "the case record shape changed; a field carrying the original would leak ground truth into the recovery input"
        );
    }
}

#[test]
fn every_entry_is_a_real_transform_of_its_original() {
    let (cases, truths): &(Vec<Case>, BTreeMap<String, Truth>) = corpus();
    for case in cases {
        let truth: &Truth = truths.get(&case.id).expect("held-out original");
        assert_ne!(
            case.obfuscated, truth.original,
            "{}: the transform left the expression unchanged",
            case.id
        );
        assert!(
            !truth.checks.is_empty(),
            "{}: the held-out original carries no check vectors",
            case.id
        );
        let width: Width = width_from_bits(case.width);
        let obfuscated: Expr = parse_prefix(&case.obfuscated);
        let original: Expr = parse_prefix(&truth.original);
        assert_eq!(
            obfuscated.node_count(),
            case.obfuscated_nodes,
            "{}: the recorded node count does not match the recorded expression",
            case.id
        );
        assert_eq!(
            original.node_count(),
            truth.original_nodes,
            "{}: the recorded original node count does not match the recorded original",
            case.id
        );
        for check in &truth.checks {
            assert_eq!(
                original.eval(&check.inputs, width),
                check.output,
                "{}: this crate's evaluator disagrees with the corpus check vector on the original",
                case.id
            );
            assert_eq!(
                obfuscated.eval(&check.inputs, width),
                check.output,
                "{}: the obfuscated form is not an identity of the held-out original",
                case.id
            );
        }
    }
}

#[test]
fn recovery_agrees_with_the_held_out_originals() {
    let report: Report = grade("recovery", unchanged);
    for failure in report.failures.iter().take(20) {
        eprintln!("  {failure}");
    }
    assert!(
        report.failures.is_empty(),
        "{} of {} graded corpus entries were recovered wrongly or unproven",
        report.failures.len(),
        report.graded
    );
    let refusals: Vec<&str> = landings()
        .iter()
        .filter(|entry: &&Landed| matches!(entry.attempt, Attempt::BudgetRefusal))
        .map(|entry: &Landed| entry.id.as_str())
        .collect();
    eprintln!(
        "{} of {} entries refused the {PER_ENTRY_BUDGET:?} budget and are reported rather than counted as recovered: {refusals:?}",
        refusals.len(),
        landings().len()
    );
    assert!(
        report.graded >= GRADED_FLOOR,
        "only {} of {} entries were graded, the floor is {GRADED_FLOOR}; a run that refuses the budget on nearly everything would pass this gate without grading anything",
        report.graded,
        report.total
    );
}

#[test]
fn a_seeded_wrong_recovery_is_rejected_by_the_corpus() {
    let offset: Report = grade("seeded-wrong offset-by-one", offset_by_one);
    for failure in offset.failures.iter().take(3) {
        eprintln!("  rejected {failure}");
    }
    assert_eq!(
        offset.failures.len(),
        offset.graded,
        "a recovery one greater than the truth must fail every graded entry, otherwise the corpus grades nothing"
    );

    let confusion: Report = grade("seeded-wrong carry-confusion", carry_confusion);
    for failure in confusion.failures.iter().take(3) {
        eprintln!("  rejected {failure}");
    }
    let survivors: usize = confusion.graded - confusion.failures.len();
    eprintln!(
        "seeded-wrong carry-confusion: {} of {} rejected, {survivors} survived because the substitution happens to preserve the value",
        confusion.failures.len(),
        confusion.graded
    );
    assert!(
        confusion.failures.len() * 2 > confusion.graded,
        "swapping addition for exclusive-or must be caught on most entries, was caught on {} of {}",
        confusion.failures.len(),
        confusion.graded
    );

    let honest: Report = grade("recovery", unchanged);
    assert!(
        honest.failures.is_empty(),
        "the same grader must pass the real recovery it rejects the wrong one for"
    );
    assert!(
        honest.graded >= GRADED_FLOOR,
        "the seeded-wrong comparison is only meaningful over a real population, {} entries were graded",
        honest.graded
    );
}
