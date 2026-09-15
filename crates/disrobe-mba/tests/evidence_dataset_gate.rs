#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/evidence_corpus.rs"]
#[allow(clippy::redundant_pub_crate)]
mod evidence_corpus;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use disrobe_mba::{Expr, Simplification, Width, simplify};
use evidence_corpus::{Case, Truth, load_cases, load_truths, parse_prefix, width_from_bits};

const DATASET_CORPUS_VAR: &str = "DISROBE_MBA_DATASET_CORPUS";
const PER_ENTRY_BUDGET: Duration = Duration::from_secs(2);
const MINIMUM_DATASET_ENTRIES: usize = 100;

fn dataset_directory() -> Option<PathBuf> {
    let raw: OsString = std::env::var_os(DATASET_CORPUS_VAR)?;
    let text: String = raw.to_string_lossy().trim().to_owned();
    if text.is_empty() {
        return None;
    }
    Some(PathBuf::from(text))
}

fn bounded_simplify(obfuscated: &Expr, width: Width) -> Option<Expr> {
    let (sender, receiver): (mpsc::Sender<Expr>, mpsc::Receiver<Expr>) = mpsc::channel();
    let payload: Expr = obfuscated.clone();
    let handle: thread::JoinHandle<()> = thread::spawn(move || {
        let simplification: Simplification = simplify(&payload, width);
        let _ = sender.send(simplification.simplified);
    });
    let produced: Option<Expr> = receiver.recv_timeout(PER_ENTRY_BUDGET).ok();
    if produced.is_some() {
        let _ = handle.join();
    }
    produced
}

#[test]
fn published_dataset_originals_grade_the_recovery_when_the_cache_is_present() {
    let Some(directory) = dataset_directory() else {
        eprintln!(
            "{DATASET_CORPUS_VAR} is unset, so the published-dataset lane did not run. \
             Populate it with: python evidence/generators/mba/fetch_datasets.py, then \
             cargo run -p disrobe-evidence-mba --release -- datasets --input target/mba-datasets \
             --out target/mba-dataset-corpus, then set {DATASET_CORPUS_VAR} to that output directory. \
             This lane is published as a local figure and never as a continuous-integration one."
        );
        return;
    };
    let path: &Path = directory.as_path();
    assert!(
        path.join("cases.jsonl").is_file(),
        "{DATASET_CORPUS_VAR} points at {}, which holds no cases.jsonl; the lane was demanded and cannot run",
        path.display()
    );

    let cases: Vec<Case> = load_cases(path);
    let truths: BTreeMap<String, Truth> = load_truths(path)
        .into_iter()
        .map(|truth: Truth| (truth.id.clone(), truth))
        .collect();
    assert!(
        cases.len() >= MINIMUM_DATASET_ENTRIES,
        "the dataset lane holds only {} entries, fewer than the {MINIMUM_DATASET_ENTRIES} a meaningful run needs",
        cases.len()
    );

    let mut graded: usize = 0;
    let mut refusals: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut generators: BTreeMap<String, usize> = BTreeMap::new();
    for case in &cases {
        let truth: &Truth = truths
            .get(&case.id)
            .unwrap_or_else(|| panic!("{}: no held-out original", case.id));
        let width: Width = width_from_bits(case.width);
        let obfuscated: Expr = parse_prefix(&case.obfuscated);
        let original: Expr = parse_prefix(&truth.original);
        for check in &truth.checks {
            assert_eq!(
                original.eval(&check.inputs, width),
                check.output,
                "{}: this crate's evaluator disagrees with the dataset check vector",
                case.id
            );
        }
        let Some(recovered) = bounded_simplify(&obfuscated, width) else {
            refusals += 1;
            continue;
        };
        graded += 1;
        *generators.entry(case.generator.clone()).or_insert(0) += 1;
        for check in &truth.checks {
            let produced: u64 = recovered.eval(&check.inputs, width);
            if produced != check.output {
                failures.push(format!(
                    "{}: recovery returned {produced} where the published original returns {} on inputs {:?}",
                    case.id, check.output, check.inputs
                ));
                break;
            }
        }
    }

    eprintln!(
        "published-dataset lane: {graded} graded of {} entries, {refusals} refused the {PER_ENTRY_BUDGET:?} budget, {} rejected",
        cases.len(),
        failures.len()
    );
    for (generator, count) in &generators {
        eprintln!("  {count:>4} from {generator}");
    }
    for failure in failures.iter().take(20) {
        eprintln!("  {failure}");
    }
    assert!(
        failures.is_empty(),
        "{} published-dataset entries were recovered wrongly",
        failures.len()
    );
    assert!(
        graded > 0,
        "the dataset lane graded nothing; every entry refused the budget"
    );
}
