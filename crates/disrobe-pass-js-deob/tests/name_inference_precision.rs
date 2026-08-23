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

const HOLDOUT_FIXTURES: &[&str] = &[
    "corpus/js/parcel/bundle.js",
    "corpus/js/parcel/lazy.js",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js",
    "corpus/js/sourcemaps/terser/math.min.js",
    "corpus/js/sourcemaps/jsobf-separate/math.obf.js",
    "corpus/js/vite/assets/index-DQvCGGXF.js",
];

const CORPUS_ROOT: &str = "corpus/unminify/symbolized";

const MINIMUM_GRADED_SLOTS: usize = 40;
const MINIMUM_HOLDOUT_SLOTS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GradedSlot {
    fixture: String,
    original: String,
    restored: String,
    truth: String,
    tier: String,
    source: String,
}

impl GradedSlot {
    fn pin(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.fixture, self.original, self.restored, self.truth, self.tier, self.source
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

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn grade_fixture(tool: &str, module: &str) -> Vec<GradedSlot> {
    let dir: PathBuf = fixture_dir().join(tool);
    let js_path: PathBuf = dir.join(format!("{module}.min.js"));
    let map_path: PathBuf = dir.join(format!("{module}.min.js.map"));
    grade_paths(&format!("{tool}/{module}"), &js_path, &map_path)
}

fn grade_holdout_fixture(relative: &str) -> Vec<GradedSlot> {
    let js_path: PathBuf = repository_root().join(relative);
    let map_path: PathBuf = repository_root().join(format!("{relative}.map"));
    grade_paths(relative, &js_path, &map_path)
}

fn grade_paths(label_text: &str, js_path: &Path, map_path: &Path) -> Vec<GradedSlot> {
    let source: String = read_required(js_path, "minified fixture");
    let raw_map: String = read_required(map_path, "source map");

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
    let label: String = label_text.to_owned();

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
            source: rename.source_label.to_owned(),
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

fn grade_holdout() -> Vec<GradedSlot> {
    let mut slots: Vec<GradedSlot> = Vec::new();
    for relative in HOLDOUT_FIXTURES {
        slots.extend(grade_holdout_fixture(relative));
    }
    slots.sort();
    slots
}

fn report_rates(title: &str, slots: &[GradedSlot]) {
    let mut per_source: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for slot in slots {
        let key: String = format!("{}/{}", slot.source, slot.tier);
        let entry: &mut (usize, usize) = per_source.entry(key).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
        if slot.matched() {
            entry.0 = entry.0.saturating_add(1);
        }
    }
    let matched: usize = slots.iter().filter(|s: &&GradedSlot| s.matched()).count();
    println!("{title}");
    println!("  overall: {matched}/{}", slots.len());
    for (source, (hit, total)) in &per_source {
        println!("  source {source}: {hit}/{total}");
    }
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
    let mut per_source: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for slot in &slots {
        let key: String = format!("{}/{}", slot.source, slot.tier);
        let entry: &mut (usize, usize) = per_source.entry(key).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
        if slot.matched() {
            entry.0 = entry.0.saturating_add(1);
        }
    }
    let matched: usize = slots.iter().filter(|s: &&GradedSlot| s.matched()).count();
    println!("name inference restoration precision");
    println!("  overall: {matched}/{}", slots.len());
    for (tier, (hit, total)) in &per_tier {
        println!("  tier {tier}: {hit}/{total}");
    }
    for (source, (hit, total)) in &per_source {
        println!("  source {source}: {hit}/{total}");
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

const OUTER_BINDING_COLLISION: &str =
    "var list = [1, 2]; function g(a){ a.push(3); return list.length; }";

#[test]
fn an_inferred_name_never_shadows_an_outer_binding() {
    let report: TerserRestoreReport = restore_terser_mangled(OUTER_BINDING_COLLISION);
    let renamed: Option<&str> = report
        .renames
        .iter()
        .find(|rename: &&MangledRestoredName| rename.original == "a")
        .map(|rename: &MangledRestoredName| rename.restored.as_str());
    assert_eq!(
        renamed,
        Some("list_2"),
        "`list` is bound in an enclosing scope, so the parameter must not take that name; got {renamed:?}"
    );
    assert!(
        report.rewritten.contains("var list = [1, 2]"),
        "the outer binding must be left alone:\n{}",
        report.rewritten
    );
    assert!(
        report.rewritten.contains("return list.length"),
        "the reference to the outer binding must still resolve to it:\n{}",
        report.rewritten
    );
}

const DESCENDANT_BINDING_COLLISION: &str = "function outer(a){ a.push(1); function inner(){ var list = 5; return list; } return inner(); }";

#[test]
fn an_inferred_name_never_collides_with_a_descendant_binding() {
    let report: TerserRestoreReport = restore_terser_mangled(DESCENDANT_BINDING_COLLISION);
    let renamed: Option<&str> = report
        .renames
        .iter()
        .find(|rename: &&MangledRestoredName| rename.original == "a")
        .map(|rename: &MangledRestoredName| rename.restored.as_str());
    assert_eq!(
        renamed,
        Some("list_2"),
        "a nested scope binds `list`, so taking that name would put the parameter behind a shadow; got {renamed:?}"
    );
    assert!(
        report.rewritten.contains("var list = 5"),
        "the nested binding must be left alone:\n{}",
        report.rewritten
    );
}

const SIBLING_SCOPES_MAY_REUSE: &str =
    "function first(a){ a.push(1); } function second(b){ b.push(2); }";

#[test]
fn two_bindings_in_sibling_scopes_may_receive_the_same_name() {
    let report: TerserRestoreReport = restore_terser_mangled(SIBLING_SCOPES_MAY_REUSE);
    let names: Vec<&str> = report
        .renames
        .iter()
        .map(|rename: &MangledRestoredName| rename.restored.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["list", "list"],
        "sibling scopes cannot capture each other, so suffixing them apart would be needless churn; got {names:?}"
    );
}

const MANGLED_CALLEE: &str = "function o(){ return 1; } var p = o(); print(p);";

#[test]
fn a_name_is_never_inferred_from_a_callee_that_is_itself_mangled() {
    let report: TerserRestoreReport = restore_terser_mangled(MANGLED_CALLEE);
    let renamed: Option<&str> = report
        .renames
        .iter()
        .find(|rename: &&MangledRestoredName| rename.original == "p")
        .map(|rename: &MangledRestoredName| rename.restored.as_str());
    assert!(
        !matches!(renamed, Some("o" | "o_2")),
        "`o` is itself mangled, so it carries nothing to restore `p` from; got {renamed:?}"
    );
}

const RESERVED_WORD_CALLEE: &str = "var r = q.catch(h); print(r);";

#[test]
fn a_name_is_never_inferred_from_a_reserved_word_callee() {
    let report: TerserRestoreReport = restore_terser_mangled(RESERVED_WORD_CALLEE);
    let renamed: Option<&str> = report
        .renames
        .iter()
        .find(|rename: &&MangledRestoredName| rename.original == "r")
        .map(|rename: &MangledRestoredName| rename.restored.as_str());
    assert!(
        !matches!(renamed, Some("catch" | "catch_2")),
        "`catch` cannot be a binding name, and suffixing it into `catch_2` names nothing; got {renamed:?}"
    );
}

#[test]
fn the_holdout_population_is_graded_and_reported_separately() {
    let slots: Vec<GradedSlot> = grade_holdout();
    assert!(
        slots.len() >= MINIMUM_HOLDOUT_SLOTS,
        "the holdout produced {} graded slots, below the floor of {MINIMUM_HOLDOUT_SLOTS}. \
         These fixtures were authored for other purposes and are never calibrated against, \
         so they are the only uncontaminated measurement available.",
        slots.len()
    );
    for slot in &slots {
        assert_ne!(
            slot.original, slot.truth,
            "{}: `{}` already carried its original spelling, so it is presence rather than restoration",
            slot.fixture, slot.original
        );
    }
    report_rates("holdout precision", &slots);
}

#[test]
fn the_holdout_membership_matches_its_pin() {
    let slots: Vec<GradedSlot> = grade_holdout();
    let observed: Vec<String> = slots.iter().map(GradedSlot::pin).collect();
    let pinned: Vec<String> = PINNED_HOLDOUT
        .iter()
        .map(|s: &&str| (*s).to_owned())
        .collect();
    let missing: Vec<&String> = pinned.iter().filter(|p| !observed.contains(p)).collect();
    let added: Vec<&String> = observed.iter().filter(|o| !pinned.contains(o)).collect();
    assert!(
        missing.is_empty() && added.is_empty(),
        "the holdout population changed.\n--no longer graded--\n{}\n--newly graded--\n{}",
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

const PINNED_HOLDOUT: &[&str] = &[
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|a|args|require_index|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|c|context|sub|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|d|data|init_greet|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|f|fn|init_math|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|l|list|greet|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|o|options|b|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|s|state|total|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|t|target|a|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|t|target|who|low|corpus",
    "corpus/js/sourcemaps/esbuild-external/bundle.ext.js|u|utils|add|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|a|args|require_index|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|c|context|sub|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|d|data|init_greet|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|f|fn|init_math|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|l|list|greet|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|o|options|b|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|s|state|total|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|t|target|a|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|t|target|who|low|corpus",
    "corpus/js/sourcemaps/esbuild-min/bundle.min.js|u|utils|add|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|a|args|require_index|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|c|context|sub|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|d|data|init_greet|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|f|fn|init_math|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|l|list|greet|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|o|options|b|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|s|state|total|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|t|target|a|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|t|target|who|low|corpus",
    "corpus/js/sourcemaps/esbuild-sourceroot/bundle.sr.js|u|utils|add|low|corpus",
    "corpus/js/sourcemaps/terser/math.min.js|n|node|b|low|corpus",
    "corpus/js/sourcemaps/terser/math.min.js|t|target|a|low|corpus",
];

const PINNED_MEMBERSHIP: &[&str] = &[
    "esbuild/collection|a|args|groupBy|low|corpus",
    "esbuild/collection|e|concat|keys|low|context",
    "esbuild/collection|e|event|index|low|corpus",
    "esbuild/collection|e|event|offset|low|corpus",
    "esbuild/collection|e|list_2|rejected|medium|heuristic",
    "esbuild/collection|f|fn|right|low|corpus",
    "esbuild/collection|i|index|chunk|low|corpus",
    "esbuild/collection|n|node|cursor|low|corpus",
    "esbuild/collection|n|node|record|low|corpus",
    "esbuild/collection|n|node|value|low|corpus",
    "esbuild/collection|o|options|patch|low|corpus",
    "esbuild/collection|o|options|predicate|low|corpus",
    "esbuild/collection|o|options|selector|low|corpus",
    "esbuild/collection|o|options|size|low|corpus",
    "esbuild/collection|p|props|bucket|low|corpus",
    "esbuild/collection|p|props|name|low|corpus",
    "esbuild/collection|p|props|position|low|corpus",
    "esbuild/collection|r|list_2|result|medium|heuristic",
    "esbuild/collection|r|list|matched|medium|heuristic",
    "esbuild/collection|r|result|groups|low|corpus",
    "esbuild/collection|r|result|output|low|corpus",
    "esbuild/collection|s|state|partition|low|corpus",
    "esbuild/collection|t|list|records|low|heuristic",
    "esbuild/collection|t|list|source|low|heuristic",
    "esbuild/collection|t|target|target|low|corpus",
    "esbuild/collection|t|target|values|low|corpus",
    "esbuild/collection|u|utils|left|low|corpus",
    "esbuild/collection|v|value|mergeDeep|low|corpus",
    "esbuild/loader|a|args|baseUrl|low|corpus",
    "esbuild/loader|c|context|load|low|corpus",
    "esbuild/loader|d|data|invalidate|low|corpus",
    "esbuild/loader|e|event|params|low|corpus",
    "esbuild/loader|e|event|prefix|low|corpus",
    "esbuild/loader|f|fn|transport|low|corpus",
    "esbuild/loader|i|index|error|low|corpus",
    "esbuild/loader|i|index|response|low|corpus",
    "esbuild/loader|l|list|createLoader|low|corpus",
    "esbuild/loader|n|list_2|query|medium|heuristic",
    "esbuild/loader|n|node|removed|low|corpus",
    "esbuild/loader|n|node|url|low|corpus",
    "esbuild/loader|o|options|resource|low|corpus",
    "esbuild/loader|r|result|key|low|corpus",
    "esbuild/loader|r|result|promise|low|corpus",
    "esbuild/loader|r|result|url|low|corpus",
    "esbuild/loader|t|target|cache|low|corpus",
    "esbuild/loader|u|utils|buildUrl|low|corpus",
    "esbuild/widget|c|context|increment|low|corpus",
    "esbuild/widget|e|event|callback|low|corpus",
    "esbuild/widget|e|event|event|low|corpus",
    "esbuild/widget|e|querySelector|label|low|context",
    "esbuild/widget|f|indexOf|position|low|context",
    "esbuild/widget|i|index|options|low|corpus",
    "esbuild/widget|l|list_2|subscribe|low|corpus",
    "esbuild/widget|n|node|counter|low|corpus",
    "esbuild/widget|o|options|render|low|corpus",
    "esbuild/widget|r|result|index|low|corpus",
    "esbuild/widget|s|button|button|high|context",
    "esbuild/widget|t|list|listeners|medium|heuristic",
    "esbuild/widget|u|root|root|high|heuristic",
    "esbuild/widget|v|value|mountWidget|low|corpus",
    "terser/collection|c|context|right|low|corpus",
    "terser/collection|e|event_2|value|low|corpus",
    "terser/collection|e|event|target|low|corpus",
    "terser/collection|e|event|values|low|corpus",
    "terser/collection|e|list|records|low|heuristic",
    "terser/collection|e|list|source|low|heuristic",
    "terser/collection|n|node|cursor|low|corpus",
    "terser/collection|n|node|position|low|corpus",
    "terser/collection|n|node|record|low|corpus",
    "terser/collection|o|concat|keys|low|context",
    "terser/collection|o|list_2|rejected|medium|heuristic",
    "terser/collection|o|options|index|low|corpus",
    "terser/collection|o|options|offset|low|corpus",
    "terser/collection|p|props|left|low|corpus",
    "terser/collection|r|result|patch|low|corpus",
    "terser/collection|r|result|predicate|low|corpus",
    "terser/collection|r|result|selector|low|corpus",
    "terser/collection|r|result|size|low|corpus",
    "terser/collection|t|list_2|result|medium|heuristic",
    "terser/collection|t|list|matched|medium|heuristic",
    "terser/collection|t|target|groups|low|corpus",
    "terser/collection|t|target|output|low|corpus",
    "terser/collection|u|utils|bucket|low|corpus",
    "terser/collection|u|utils|name|low|corpus",
    "terser/loader|a|args|url|low|corpus",
    "terser/loader|e|event_2|params|low|corpus",
    "terser/loader|e|event|cache|low|corpus",
    "terser/loader|i|index|promise|low|corpus",
    "terser/loader|n|node_2|error|low|corpus",
    "terser/loader|n|node_2|response|low|corpus",
    "terser/loader|n|node|baseUrl|low|corpus",
    "terser/loader|o|options_2|key|low|corpus",
    "terser/loader|o|options|params|low|corpus",
    "terser/loader|o|options|removed|low|corpus",
    "terser/loader|r|result_2|resource|low|corpus",
    "terser/loader|r|result|transport|low|corpus",
    "terser/loader|t|list|query|medium|heuristic",
    "terser/loader|t|target|prefix|low|corpus",
    "terser/loader|t|target|resource|low|corpus",
    "terser/widget|e|list|listeners|medium|heuristic",
    "terser/widget|i|index|counter|low|corpus",
    "terser/widget|n|indexOf|position|low|context",
    "terser/widget|n|node_2|index|low|corpus",
    "terser/widget|n|node|options|low|corpus",
    "terser/widget|o|options|render|low|corpus",
    "terser/widget|r|result|increment|low|corpus",
    "terser/widget|t|root|root|high|heuristic",
    "terser/widget|t|target|callback|low|corpus",
    "terser/widget|t|target|event|low|corpus",
    "terser/widget|u|button|button|high|context",
];
