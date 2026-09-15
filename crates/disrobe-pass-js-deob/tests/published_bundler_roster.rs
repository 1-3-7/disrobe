#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    BundlerDetection, BundlerKind, detect_amd, detect_browserify, detect_bun, detect_esbuild,
    detect_parcel, detect_rolldown, detect_rollup, detect_systemjs, detect_turbopack, detect_vite,
    detect_webpack4, detect_webpack5,
};

const DECLARED: usize = 12;
const PUBLISHED_FAMILIES: usize = 11;

const PUBLISHED_BAR: &str = "JS bundlers";
const RECOVERY_JSON: &str = "xtask/data/recovery.json";

const NOT_A_BUNDLE: &str = "export function add(a, b) {\n  return a + b;\n}\n\
                            const total = add(2, 3);\n\
                            console.log('sum is', total);\n";

#[derive(Debug, Clone, Copy)]
struct RosterEntry {
    kind: BundlerKind,
    family: &'static str,
    sample: &'static str,
}

const ROSTER: [RosterEntry; DECLARED] = [
    RosterEntry {
        kind: BundlerKind::Webpack4,
        family: "webpack",
        sample: "corpus/src/javascript/webpack4-sample.js",
    },
    RosterEntry {
        kind: BundlerKind::Webpack5,
        family: "webpack",
        sample: "corpus/js/webpack5/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::Vite,
        family: "vite",
        sample: "corpus/js/vite/assets/index-DQvCGGXF.js",
    },
    RosterEntry {
        kind: BundlerKind::Rollup,
        family: "rollup",
        sample: "corpus/js/rollup/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::Rolldown,
        family: "rolldown",
        sample: "crates/disrobe-pass-js-deob/corpus/bundlers/rolldown/simple/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::Esbuild,
        family: "esbuild",
        sample: "corpus/js/esbuild/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::Turbopack,
        family: "turbopack",
        sample: "corpus/js/turbopack/runtime.js",
    },
    RosterEntry {
        kind: BundlerKind::Bun,
        family: "bun",
        sample: "corpus/js/bun/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::Browserify,
        family: "browserify",
        sample: "corpus/js/browserify/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::Parcel,
        family: "parcel",
        sample: "corpus/js/parcel/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::SystemJs,
        family: "systemjs",
        sample: "corpus/js/systemjs/bundle.js",
    },
    RosterEntry {
        kind: BundlerKind::Amd,
        family: "amd",
        sample: "corpus/js/requirejs/bundle.js",
    },
];

const fn published_family(kind: BundlerKind) -> &'static str {
    match kind {
        BundlerKind::Webpack4 | BundlerKind::Webpack5 => "webpack",
        BundlerKind::Vite => "vite",
        BundlerKind::Rollup => "rollup",
        BundlerKind::Rolldown => "rolldown",
        BundlerKind::Esbuild => "esbuild",
        BundlerKind::Turbopack => "turbopack",
        BundlerKind::Bun => "bun",
        BundlerKind::Browserify => "browserify",
        BundlerKind::Parcel => "parcel",
        BundlerKind::SystemJs => "systemjs",
        BundlerKind::Amd => "amd",
    }
}

fn detect(kind: BundlerKind, source: &str) -> BundlerDetection {
    match kind {
        BundlerKind::Webpack4 => detect_webpack4(source),
        BundlerKind::Webpack5 => detect_webpack5(source),
        BundlerKind::Vite => detect_vite(source),
        BundlerKind::Rollup => detect_rollup(source),
        BundlerKind::Rolldown => detect_rolldown(source),
        BundlerKind::Esbuild => detect_esbuild(source),
        BundlerKind::Turbopack => detect_turbopack(source),
        BundlerKind::Bun => detect_bun(source),
        BundlerKind::Browserify => detect_browserify(source),
        BundlerKind::Parcel => detect_parcel(source),
        BundlerKind::SystemJs => detect_systemjs(source),
        BundlerKind::Amd => detect_amd(source),
    }
}

fn repo_root() -> PathBuf {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "every bundler sample is named relative to the repository root, two directories above \
             {}, so a manifest path with no grandparent leaves the roster exercised against nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn sample_source(entry: RosterEntry) -> String {
    let path: PathBuf = repo_root().join(entry.sample);
    let text: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{:?} is on the roster the published `{PUBLISHED_BAR}` count is cut from, and the \
             bundle it is exercised on is tracked in this repository, so its absence is never a \
             skip: {error} at {}",
            entry.kind,
            path.display()
        )
    });
    assert!(
        !text.trim().is_empty(),
        "{:?} names {} as the bundle that exercises it, and that file is empty, so a detector \
         that matched nothing would still be counted",
        entry.kind,
        entry.sample
    );
    text
}

fn published_bar_value() -> f64 {
    let path: PathBuf = repo_root().join(RECOVERY_JSON);
    let raw: String = fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("reading {}: {error}", path.display()));
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parsing {}: {error}", path.display()));
    let mut found: Vec<f64> = Vec::new();
    for group in parsed["groups"].as_array().expect("groups array") {
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(PUBLISHED_BAR) {
                found.push(bar["value"].as_f64().unwrap_or_else(|| {
                    panic!("the `{PUBLISHED_BAR}` bar carries no numeric value")
                }));
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "{RECOVERY_JSON} must carry exactly one `{PUBLISHED_BAR}` bar; found {}",
        found.len()
    );
    found[0]
}

fn exercised_kinds() -> Vec<BundlerKind> {
    ROSTER
        .into_iter()
        .filter(|entry: &RosterEntry| {
            let source: String = sample_source(*entry);
            let detection: BundlerDetection = detect(entry.kind, &source);
            detection.matched && detection.kind == entry.kind
        })
        .map(|entry: RosterEntry| entry.kind)
        .collect()
}

fn same_members(left: &[BundlerKind], right: &[BundlerKind]) -> bool {
    left.len() == right.len()
        && left.iter().all(|kind: &BundlerKind| right.contains(kind))
        && right.iter().all(|kind: &BundlerKind| left.contains(kind))
}

#[test]
fn the_roster_this_check_walks_is_every_bundler_the_crate_declares() {
    assert_eq!(
        ROSTER.len(),
        DECLARED,
        "the roster is the population the published count is cut from, so it is pinned by equality \
         rather than counted from whatever this table happens to hold"
    );
    assert_eq!(
        BundlerKind::ALL.len(),
        DECLARED,
        "`BundlerKind::ALL` carries {} variants against the {DECLARED} this check walks, so a \
         bundler was added or removed without an entry naming the bundle that exercises it",
        BundlerKind::ALL.len()
    );

    let declared: Vec<BundlerKind> = BundlerKind::ALL.to_vec();
    let walked: Vec<BundlerKind> = ROSTER
        .into_iter()
        .map(|entry: RosterEntry| entry.kind)
        .collect();
    assert!(
        same_members(&declared, &walked),
        "the bundlers this check exercises and the bundlers the crate declares are different sets: \
         {walked:?} against {declared:?}"
    );

    for entry in ROSTER {
        assert_eq!(
            published_family(entry.kind),
            entry.family,
            "the exhaustive mapping and the roster disagree on which published family {:?} belongs \
             to",
            entry.kind
        );
    }
}

#[test]
fn the_published_count_is_the_declared_roster_minus_its_one_alias() {
    let families: BTreeSet<&'static str> = ROSTER
        .into_iter()
        .map(|entry: RosterEntry| entry.family)
        .collect();
    assert_eq!(
        families.len(),
        PUBLISHED_FAMILIES,
        "the roster resolves to {} published families against the {PUBLISHED_FAMILIES} the README \
         and the catalog state: {families:?}",
        families.len()
    );
    assert_eq!(
        DECLARED - BundlerKind::PUBLISHED_FAMILY_ALIASES,
        PUBLISHED_FAMILIES,
        "`PUBLISHED_FAMILY_ALIASES` is {}, which does not reconcile {DECLARED} declared variants \
         with {PUBLISHED_FAMILIES} published families",
        BundlerKind::PUBLISHED_FAMILY_ALIASES
    );

    let webpack: Vec<BundlerKind> = ROSTER
        .into_iter()
        .filter(|entry: &RosterEntry| entry.family == "webpack")
        .map(|entry: RosterEntry| entry.kind)
        .collect();
    assert!(
        same_members(&webpack, &[BundlerKind::Webpack4, BundlerKind::Webpack5]),
        "the single alias the published count folds away is webpack 4 and 5 sharing one family; \
         this roster folds {webpack:?} instead, so the number and the names would disagree"
    );

    let published: f64 = published_bar_value();
    assert!(
        (published - PUBLISHED_FAMILIES as f64).abs() < f64::EPSILON,
        "{RECOVERY_JSON} publishes {published} on the `{PUBLISHED_BAR}` bar and README.md and \
         docs/src/catalog.md render that number, but this roster resolves to {PUBLISHED_FAMILIES} \
         families"
    );
}

#[test]
fn every_declared_bundler_detects_the_committed_bundle_it_names() {
    let exercised: Vec<BundlerKind> = exercised_kinds();
    let declared: Vec<BundlerKind> = BundlerKind::ALL.to_vec();

    assert!(
        same_members(&exercised, &declared),
        "the published count says this crate handles {PUBLISHED_FAMILIES} bundler families, but \
         only {exercised:?} detect the real bundle their roster entry names; a family that stops \
         detecting drops out here rather than leaving a count green"
    );
    assert_eq!(
        exercised.len(),
        DECLARED,
        "the exercised set is pinned by equality against the declared roster so that a bundler \
         which stops detecting cannot be replaced by one that starts"
    );

    for entry in ROSTER {
        let source: String = sample_source(entry);
        let detection: BundlerDetection = detect(entry.kind, &source);
        assert!(
            detection.confidence > 0.0,
            "{:?} matched {} at zero confidence, which a caller ranking detections would discard",
            entry.kind,
            entry.sample
        );
        assert!(
            !detection.markers.is_empty(),
            "{:?} matched {} without naming a marker, so nothing records why it decided",
            entry.kind,
            entry.sample
        );
    }
}

#[test]
fn no_bundler_claims_a_script_that_was_never_bundled() {
    let claimants: Vec<BundlerKind> = BundlerKind::ALL
        .iter()
        .copied()
        .filter(|kind: &BundlerKind| detect(*kind, NOT_A_BUNDLE).matched)
        .collect();
    assert!(
        claimants.is_empty(),
        "a plain module that no bundler produced was claimed by {claimants:?}; a detector that \
         fires on anything would satisfy the membership assertion above while recovering nothing"
    );
}

#[test]
fn the_strongest_detection_on_each_bundle_names_the_family_that_produced_it() {
    let mut misattributed: Vec<String> = Vec::new();
    for entry in ROSTER {
        let source: String = sample_source(entry);
        let mut ranked: Vec<(BundlerKind, f32)> = BundlerKind::ALL
            .iter()
            .copied()
            .map(|kind: BundlerKind| (kind, detect(kind, &source)))
            .filter(|pair: &(BundlerKind, BundlerDetection)| pair.1.matched)
            .map(|pair: (BundlerKind, BundlerDetection)| (pair.0, pair.1.confidence))
            .collect();
        ranked.sort_by(|left: &(BundlerKind, f32), right: &(BundlerKind, f32)| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(core::cmp::Ordering::Equal)
        });
        let Some(top): Option<&(BundlerKind, f32)> = ranked.first() else {
            misattributed.push(format!(
                "{:?} matched nothing on {}",
                entry.kind, entry.sample
            ));
            continue;
        };
        if published_family(top.0) != entry.family {
            misattributed.push(format!(
                "{} is {:?} output but {:?} outranks it at {:.2}",
                entry.sample, entry.kind, top.0, top.1
            ));
            continue;
        }
        let tied: Vec<BundlerKind> = ranked
            .iter()
            .filter(|pair: &&(BundlerKind, f32)| {
                (pair.1 - top.1).abs() < f32::EPSILON && published_family(pair.0) != entry.family
            })
            .map(|pair: &(BundlerKind, f32)| pair.0)
            .collect();
        if !tied.is_empty() {
            misattributed.push(format!(
                "{} is {:?} output and {tied:?} tie it at {:.2}, so the winner is arbitrary",
                entry.sample, entry.kind, top.1
            ));
        }
    }
    assert!(
        misattributed.is_empty(),
        "the published count treats these as {PUBLISHED_FAMILIES} separable families, so the \
         strongest detection on a real bundle must name the tool that produced it; a detector that \
         became unspecific enough to outrank the true family would otherwise keep every count \
         green while routing the bundle to the wrong unbundler: {}",
        misattributed.join("; ")
    );
}

#[test]
fn the_attribution_check_rejects_a_bundle_no_family_produced() {
    let ranked: Vec<BundlerKind> = BundlerKind::ALL
        .iter()
        .copied()
        .filter(|kind: &BundlerKind| detect(*kind, NOT_A_BUNDLE).matched)
        .collect();
    assert!(
        ranked.is_empty(),
        "the attribution check leans on a strongest match existing; a plain module claimed by \
         {ranked:?} would give it one for free"
    );
}

#[test]
fn the_membership_check_rejects_a_roster_whose_samples_stopped_detecting() {
    let none: Vec<BundlerKind> = BundlerKind::ALL
        .iter()
        .copied()
        .filter(|kind: &BundlerKind| detect(*kind, NOT_A_BUNDLE).matched)
        .collect();
    assert!(
        !same_members(&none, BundlerKind::ALL),
        "the membership assertion must reject a run in which nothing detected, otherwise it proves \
         nothing"
    );
    assert!(
        !same_members(&[BundlerKind::Webpack5], BundlerKind::ALL),
        "the membership assertion must reject a roster missing every family but one"
    );
}
