#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    MangledRestoredName, OriginalPosition, PositionResolver, TerserRestoreReport,
    restore_terser_mangled,
};

const FIXTURES: &[(&str, &str)] = &[
    ("terser", "widget"),
    ("terser", "loader"),
    ("terser", "collection"),
    ("esbuild", "widget"),
    ("esbuild", "loader"),
    ("esbuild", "collection"),
];

const CORPUS_ROOT: &str = "corpus/unminify/symbolized";

const MINIMUM_GRADED_SLOTS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GradedSlot {
    fixture: String,
    original: String,
    restored: String,
    truth: String,
    tier: String,
}

impl GradedSlot {
    fn pin(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.fixture, self.original, self.restored, self.truth, self.tier
        )
    }

    fn matched(&self) -> bool {
        self.restored == self.truth
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT)
}

fn read_required(path: &Path, purpose: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the {purpose} at {} is required to grade name inference and could not be read ({error}). \
             Regenerate it with `sh generate.sh` in {}.",
            path.display(),
            fixture_dir().display()
        )
    })
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts: Vec<usize> = vec![0];
    for (offset, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(offset.saturating_add(1));
        }
    }
    starts
}

fn position_of(starts: &[usize], offset: usize) -> (u32, u32) {
    let line: usize = match starts.binary_search(&offset) {
        Ok(exact) => exact,
        Err(next) => next.saturating_sub(1),
    };
    let column: usize = offset.saturating_sub(starts.get(line).copied().unwrap_or(0));
    (
        u32::try_from(line).unwrap_or(u32::MAX),
        u32::try_from(column).unwrap_or(u32::MAX),
    )
}

fn grade_fixture(tool: &str, module: &str) -> Vec<GradedSlot> {
    let dir: PathBuf = fixture_dir().join(tool);
    let js_path: PathBuf = dir.join(format!("{module}.min.js"));
    let map_path: PathBuf = dir.join(format!("{module}.min.js.map"));
    let source: String = read_required(&js_path, "minified fixture");
    let raw_map: String = read_required(&map_path, "source map");

    assert!(
        source.is_ascii(),
        "{}: the fixture must be ASCII so a byte offset equals a source-map UTF-16 column",
        js_path.display()
    );

    let resolver: PositionResolver =
        PositionResolver::from_json(&raw_map).unwrap_or_else(|error| {
            panic!(
                "the source map at {} must parse to grade name inference: {error}",
                map_path.display()
            )
        });

    let report: TerserRestoreReport = restore_terser_mangled(&source);
    let starts: Vec<usize> = line_starts(&source);
    let label: String = format!("{tool}/{module}");

    let mut slots: Vec<GradedSlot> = Vec::new();
    for rename in &report.renames {
        let (line, column): (u32, u32) = position_of(&starts, rename.declaration_offset);
        let Some(position): Option<OriginalPosition> = resolver.resolve(line, column) else {
            continue;
        };
        let Some(truth): Option<String> = position.name else {
            continue;
        };
        if truth == rename.original {
            continue;
        }
        slots.push(GradedSlot {
            fixture: label.clone(),
            original: rename.original.clone(),
            restored: rename.restored.clone(),
            truth,
            tier: rename.tier.label().to_owned(),
        });
    }
    slots.sort();
    slots.dedup();
    slots
}

fn grade_all() -> Vec<GradedSlot> {
    let mut slots: Vec<GradedSlot> = Vec::new();
    for (tool, module) in FIXTURES {
        slots.extend(grade_fixture(tool, module));
    }
    slots.sort();
    slots
}

#[test]
fn the_graded_population_is_restoration_and_never_presence() {
    let slots: Vec<GradedSlot> = grade_all();
    assert!(
        slots.len() >= MINIMUM_GRADED_SLOTS,
        "only {} graded slots were produced, below the floor of {MINIMUM_GRADED_SLOTS}. \
         A grader that reads almost nothing cannot back a precision figure. \
         Every slot must be a binding whose minified spelling differs from the source-map name.",
        slots.len()
    );
    for slot in &slots {
        assert_ne!(
            slot.original, slot.truth,
            "{}: `{}` already carried its original spelling, so it is presence rather than restoration",
            slot.fixture, slot.original
        );
    }
}

#[test]
fn the_graded_membership_matches_its_pin() {
    let slots: Vec<GradedSlot> = grade_all();
    let observed: Vec<String> = slots.iter().map(GradedSlot::pin).collect();
    let pinned: Vec<String> = PINNED_MEMBERSHIP
        .iter()
        .map(|s: &&str| (*s).to_owned())
        .collect();
    let missing: Vec<&String> = pinned.iter().filter(|p| !observed.contains(p)).collect();
    let added: Vec<&String> = observed.iter().filter(|o| !pinned.contains(o)).collect();
    assert!(
        missing.is_empty() && added.is_empty(),
        "the graded population changed.\n--no longer graded--\n{}\n--newly graded--\n{}",
        missing
            .iter()
            .map(|s: &&String| s.as_str())
            .collect::<Vec<&str>>()
            .join("\n"),
        added
            .iter()
            .map(|s: &&String| s.as_str())
            .collect::<Vec<&str>>()
            .join("\n")
    );
}

#[test]
fn the_measured_precision_is_reported_per_confidence_tier() {
    let slots: Vec<GradedSlot> = grade_all();
    assert!(
        slots.len() >= MINIMUM_GRADED_SLOTS,
        "a precision figure over {} slots is not a measurement; the floor is {MINIMUM_GRADED_SLOTS}",
        slots.len()
    );
    let mut per_tier: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for slot in &slots {
        let entry: &mut (usize, usize) = per_tier.entry(slot.tier.clone()).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
        if slot.matched() {
            entry.0 = entry.0.saturating_add(1);
        }
    }
    let matched: usize = slots.iter().filter(|s: &&GradedSlot| s.matched()).count();
    println!("name inference restoration precision");
    println!("  overall: {matched}/{}", slots.len());
    for (tier, (hit, total)) in &per_tier {
        println!("  {tier}: {hit}/{total}");
    }
    assert_eq!(
        per_tier
            .values()
            .map(|v: &(usize, usize)| v.1)
            .sum::<usize>(),
        slots.len(),
        "every graded slot must land in exactly one confidence tier"
    );
}

#[test]
fn two_runs_over_the_same_input_grade_identically() {
    let first: Vec<GradedSlot> = grade_all();
    let second: Vec<GradedSlot> = grade_all();
    assert_eq!(
        first, second,
        "the inference must be deterministic across runs"
    );
}

const FREE_REFERENCE_CAPTURE: &str =
    "function g(a){ a.addEventListener('x', function(){ return target; }); }";

#[test]
fn an_inferred_name_never_captures_a_free_reference() {
    let report: TerserRestoreReport = restore_terser_mangled(FREE_REFERENCE_CAPTURE);
    let renamed: Option<&str> = report
        .renames
        .iter()
        .find(|rename: &&MangledRestoredName| rename.original == "a")
        .map(|rename: &MangledRestoredName| rename.restored.as_str());
    assert_eq!(
        renamed,
        Some("target_2"),
        "`target` is a free reference here, so the parameter that the heuristic wants to call \
         `target` must be given a distinct name instead of capturing it; got {renamed:?}"
    );
    assert!(
        report.rewritten.contains("return target;"),
        "the free reference must still resolve to the outer binding:\n{}",
        report.rewritten
    );
}

const PINNED_MEMBERSHIP: &[&str] = &[
    "esbuild/collection|a|args|groupBy|medium",
    "esbuild/collection|e|event|index|medium",
    "esbuild/collection|e|event|keys|medium",
    "esbuild/collection|e|event|offset|medium",
    "esbuild/collection|e|event|rejected|medium",
    "esbuild/collection|f|fn|right|medium",
    "esbuild/collection|i|index|chunk|medium",
    "esbuild/collection|n|node|cursor|medium",
    "esbuild/collection|n|node|record|medium",
    "esbuild/collection|n|node|value|medium",
    "esbuild/collection|o|options|patch|medium",
    "esbuild/collection|o|options|predicate|medium",
    "esbuild/collection|o|options|selector|medium",
    "esbuild/collection|o|options|size|medium",
    "esbuild/collection|p|props|bucket|medium",
    "esbuild/collection|p|props|name|medium",
    "esbuild/collection|p|props|position|medium",
    "esbuild/collection|r|result|groups|medium",
    "esbuild/collection|r|result|matched|medium",
    "esbuild/collection|r|result|output|medium",
    "esbuild/collection|r|result|result|medium",
    "esbuild/collection|s|state|partition|medium",
    "esbuild/collection|t|target|records|medium",
    "esbuild/collection|t|target|source|medium",
    "esbuild/collection|t|target|target|medium",
    "esbuild/collection|t|target|values|medium",
    "esbuild/collection|u|utils|left|medium",
    "esbuild/collection|v|value|mergeDeep|medium",
    "esbuild/loader|a|args|baseUrl|medium",
    "esbuild/loader|c|context|load|medium",
    "esbuild/loader|d|data|invalidate|medium",
    "esbuild/loader|e|event|params|medium",
    "esbuild/loader|e|event|prefix|medium",
    "esbuild/loader|f|fn|transport|medium",
    "esbuild/loader|i|index|error|medium",
    "esbuild/loader|i|index|response|medium",
    "esbuild/loader|l|list|createLoader|medium",
    "esbuild/loader|n|node|query|medium",
    "esbuild/loader|n|node|removed|medium",
    "esbuild/loader|n|node|url|medium",
    "esbuild/loader|o|options|resource|medium",
    "esbuild/loader|r|result|key|medium",
    "esbuild/loader|r|result|promise|medium",
    "esbuild/loader|r|result|url|medium",
    "esbuild/loader|t|target|cache|medium",
    "esbuild/loader|u|utils|buildUrl|medium",
    "esbuild/widget|c|context|increment|medium",
    "esbuild/widget|e|event|callback|medium",
    "esbuild/widget|e|event|event|medium",
    "esbuild/widget|e|event|label|medium",
    "esbuild/widget|f|fn|position|medium",
    "esbuild/widget|i|index|options|medium",
    "esbuild/widget|l|list|subscribe|medium",
    "esbuild/widget|n|node|counter|medium",
    "esbuild/widget|o|options|render|medium",
    "esbuild/widget|r|result|index|medium",
    "esbuild/widget|s|target|button|high",
    "esbuild/widget|t|list_2|listeners|high",
    "esbuild/widget|u|root|root|high",
    "esbuild/widget|v|value|mountWidget|medium",
    "terser/collection|c|context|right|medium",
    "terser/collection|e|event|records|medium",
    "terser/collection|e|event|source|medium",
    "terser/collection|e|event|target|medium",
    "terser/collection|e|event|value|medium",
    "terser/collection|e|event|values|medium",
    "terser/collection|n|node|cursor|medium",
    "terser/collection|n|node|position|medium",
    "terser/collection|n|node|record|medium",
    "terser/collection|o|options|index|medium",
    "terser/collection|o|options|keys|medium",
    "terser/collection|o|options|offset|medium",
    "terser/collection|o|options|rejected|medium",
    "terser/collection|p|props|left|medium",
    "terser/collection|r|result|patch|medium",
    "terser/collection|r|result|predicate|medium",
    "terser/collection|r|result|selector|medium",
    "terser/collection|r|result|size|medium",
    "terser/collection|t|target|groups|medium",
    "terser/collection|t|target|matched|medium",
    "terser/collection|t|target|output|medium",
    "terser/collection|t|target|result|medium",
    "terser/collection|u|utils|bucket|medium",
    "terser/collection|u|utils|name|medium",
    "terser/loader|a|args|url|medium",
    "terser/loader|e|event|cache|medium",
    "terser/loader|e|event|params|medium",
    "terser/loader|i|index|promise|medium",
    "terser/loader|n|node|baseUrl|medium",
    "terser/loader|n|node|error|medium",
    "terser/loader|n|node|response|medium",
    "terser/loader|o|options|key|medium",
    "terser/loader|o|options|params|medium",
    "terser/loader|o|options|removed|medium",
    "terser/loader|r|result|resource|medium",
    "terser/loader|r|result|transport|medium",
    "terser/loader|t|target|prefix|medium",
    "terser/loader|t|target|query|medium",
    "terser/loader|t|target|resource|medium",
    "terser/widget|e|list|listeners|high",
    "terser/widget|i|index|counter|medium",
    "terser/widget|n|node|index|medium",
    "terser/widget|n|node|options|medium",
    "terser/widget|n|node|position|medium",
    "terser/widget|o|options|render|medium",
    "terser/widget|r|result|increment|medium",
    "terser/widget|t|target|callback|medium",
    "terser/widget|t|target|event|medium",
    "terser/widget|t|target|root|medium",
    "terser/widget|u|target_2|button|high",
];
