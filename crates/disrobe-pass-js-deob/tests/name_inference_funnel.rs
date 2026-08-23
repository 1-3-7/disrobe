#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    MangledCandidate, MangledRestoredName, RenamedBinding, SourceMap, TerserRestoreReport,
    parse_source_map_v3, renamed_bindings, restore_terser_mangled,
};

const FIXTURES: &[&str] = &[
    "crates/disrobe-pass-js-deob/corpus/unminify/symbolized/terser/widget.min.js",
    "crates/disrobe-pass-js-deob/corpus/unminify/symbolized/terser/loader.min.js",
    "crates/disrobe-pass-js-deob/corpus/unminify/symbolized/terser/collection.min.js",
    "crates/disrobe-pass-js-deob/corpus/unminify/symbolized/esbuild/widget.min.js",
    "crates/disrobe-pass-js-deob/corpus/unminify/symbolized/esbuild/loader.min.js",
    "crates/disrobe-pass-js-deob/corpus/unminify/symbolized/esbuild/collection.min.js",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js",
    "corpus/js/sourcemaps/terser/math.min.js",
];

const MINIMUM_GROUND_TRUTH: usize = 90;
const MINIMUM_KEPT_NAMES: usize = 20;

#[derive(Debug, Default, Clone, Copy)]
struct Funnel {
    ground_truth: usize,
    eligible: usize,
    suggested: usize,
    correct: usize,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_required(path: &Path, purpose: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the {purpose} at {} is required to measure the name-inference funnel \
             and could not be read ({error})",
            path.display()
        )
    })
}

struct Fixture {
    label: String,
    report: TerserRestoreReport,
    bindings: Vec<RenamedBinding>,
}

fn load(relative: &str) -> Fixture {
    let js_path: PathBuf = repository_root().join(relative);
    let map_path: PathBuf = repository_root().join(format!("{relative}.map"));
    let source: String = read_required(&js_path, "generated fixture");
    let raw_map: String = read_required(&map_path, "source map");
    let map: SourceMap = parse_source_map_v3(&raw_map)
        .unwrap_or_else(|error| panic!("the map at {} must parse: {error}", map_path.display()));
    let bindings: Vec<RenamedBinding> = renamed_bindings(&map, &source);
    Fixture {
        label: relative.to_owned(),
        report: restore_terser_mangled(&source),
        bindings,
    }
}

fn fixtures() -> Vec<Fixture> {
    FIXTURES.iter().map(|relative| load(relative)).collect()
}

fn measure(fixture: &Fixture) -> Funnel {
    let truth: BTreeMap<String, BTreeSet<String>> = fixture
        .bindings
        .iter()
        .filter(|binding: &&RenamedBinding| binding.was_renamed())
        .fold(BTreeMap::new(), |mut acc, binding: &RenamedBinding| {
            acc.entry(binding.generated.clone())
                .or_default()
                .insert(binding.original.clone());
            acc
        });
    let eligible: BTreeSet<String> = fixture
        .report
        .candidates
        .iter()
        .map(|candidate: &MangledCandidate| candidate.original.clone())
        .collect();
    let suggested: BTreeMap<String, BTreeSet<String>> = fixture.report.renames.iter().fold(
        BTreeMap::new(),
        |mut acc, rename: &MangledRestoredName| {
            acc.entry(rename.original.clone())
                .or_default()
                .insert(rename.restored.clone());
            acc
        },
    );

    let mut funnel: Funnel = Funnel {
        ground_truth: truth.len(),
        ..Funnel::default()
    };
    for (generated, originals) in &truth {
        if !eligible.contains(generated) {
            continue;
        }
        funnel.eligible = funnel.eligible.saturating_add(1);
        let Some(restored): Option<&BTreeSet<String>> = suggested.get(generated) else {
            continue;
        };
        funnel.suggested = funnel.suggested.saturating_add(1);
        if restored
            .iter()
            .any(|name: &String| originals.contains(name))
        {
            funnel.correct = funnel.correct.saturating_add(1);
        }
    }
    funnel
}

fn total(all: &[Fixture]) -> Funnel {
    all.iter()
        .map(measure)
        .fold(Funnel::default(), |mut acc: Funnel, one: Funnel| {
            acc.ground_truth = acc.ground_truth.saturating_add(one.ground_truth);
            acc.eligible = acc.eligible.saturating_add(one.eligible);
            acc.suggested = acc.suggested.saturating_add(one.suggested);
            acc.correct = acc.correct.saturating_add(one.correct);
            acc
        })
}

#[test]
fn the_funnel_is_measured_against_ground_truth_not_against_what_the_pass_attempted() {
    let all: Vec<Fixture> = fixtures();
    let funnel: Funnel = total(&all);
    assert!(
        funnel.ground_truth >= MINIMUM_GROUND_TRUTH,
        "the source maps yielded only {} renamed bindings, below the floor of {MINIMUM_GROUND_TRUTH}. \
         This denominator comes from the maps, not from the pass, so a pass that attempts nothing \
         cannot shrink it.",
        funnel.ground_truth
    );
    println!("name inference funnel, measured against source-map ground truth");
    println!("  ground truth renamed bindings: {}", funnel.ground_truth);
    println!(
        "  eligible  (passed is_likely_mangled): {}/{}",
        funnel.eligible, funnel.ground_truth
    );
    println!(
        "  suggested (a source fired):           {}/{}",
        funnel.suggested, funnel.eligible
    );
    println!(
        "  correct                               {}/{}",
        funnel.correct, funnel.suggested
    );
    for fixture in &all {
        let one: Funnel = measure(fixture);
        println!(
            "    {:<70} truth {:<4} eligible {:<4} suggested {:<4} correct {}",
            fixture.label, one.ground_truth, one.eligible, one.suggested, one.correct
        );
    }
    assert!(
        funnel.eligible <= funnel.ground_truth
            && funnel.suggested <= funnel.eligible
            && funnel.correct <= funnel.suggested,
        "the funnel must narrow at every stage: {funnel:?}"
    );
}

#[test]
fn the_threshold_does_not_exclude_a_binding_the_minifier_actually_renamed() {
    let all: Vec<Fixture> = fixtures();
    let mut excluded: Vec<String> = Vec::new();
    for fixture in &all {
        let eligible: BTreeSet<String> = fixture
            .report
            .candidates
            .iter()
            .map(|candidate: &MangledCandidate| candidate.original.clone())
            .collect();
        for binding in &fixture.bindings {
            if binding.was_renamed() && !eligible.contains(&binding.generated) {
                excluded.push(format!(
                    "{}|{}|{}",
                    fixture.label, binding.generated, binding.original
                ));
            }
        }
    }
    excluded.sort();
    excluded.dedup();
    assert!(
        excluded.is_empty(),
        "the candidate filter skipped {} bindings the minifier really did rename, so raising the \
         threshold would recover them:\n{}",
        excluded.len(),
        excluded.join("\n")
    );
}

#[test]
fn a_name_the_minifier_kept_is_never_renamed() {
    let all: Vec<Fixture> = fixtures();
    let mut kept_total: usize = 0;
    let mut false_positives: Vec<String> = Vec::new();
    for fixture in &all {
        let kept: BTreeSet<String> = fixture
            .bindings
            .iter()
            .filter(|binding: &&RenamedBinding| !binding.was_renamed())
            .map(|binding: &RenamedBinding| binding.generated.clone())
            .collect();
        kept_total = kept_total.saturating_add(kept.len());
        for rename in &fixture.report.renames {
            if kept.contains(&rename.original) {
                false_positives.push(format!(
                    "{}|{}|{}",
                    fixture.label, rename.original, rename.restored
                ));
            }
        }
    }
    false_positives.sort();
    false_positives.dedup();
    assert!(
        kept_total >= MINIMUM_KEPT_NAMES,
        "only {kept_total} kept names were found, below the floor of {MINIMUM_KEPT_NAMES}; \
         without them this test cannot detect a false positive"
    );
    println!("kept names examined: {kept_total}");
    assert!(
        false_positives.is_empty(),
        "{} names the minifier deliberately KEPT were renamed anyway, which destroys a name the \
         author chose:\n{}",
        false_positives.len(),
        false_positives.join("\n")
    );
}
