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

const PINNED_MEMBERSHIP: &[&str] = &[
    "esbuild/collection|a|args|groupBy|low",
    "esbuild/collection|e|concat|keys|medium",
    "esbuild/collection|e|event|index|low",
    "esbuild/collection|e|event|offset|low",
    "esbuild/collection|e|list_2|rejected|high",
    "esbuild/collection|f|fn|right|low",
    "esbuild/collection|i|index|chunk|low",
    "esbuild/collection|n|node|cursor|low",
    "esbuild/collection|n|node|record|low",
    "esbuild/collection|n|node|value|low",
    "esbuild/collection|o|options|patch|low",
    "esbuild/collection|o|options|predicate|low",
    "esbuild/collection|o|options|selector|low",
    "esbuild/collection|o|options|size|low",
    "esbuild/collection|p|props|bucket|low",
    "esbuild/collection|p|props|name|low",
    "esbuild/collection|p|props|position|low",
    "esbuild/collection|r|list_2|result|high",
    "esbuild/collection|r|list|matched|high",
    "esbuild/collection|r|result|groups|low",
    "esbuild/collection|r|result|output|low",
    "esbuild/collection|s|state|partition|low",
    "esbuild/collection|t|list|records|low",
    "esbuild/collection|t|list|source|low",
    "esbuild/collection|t|target|target|low",
    "esbuild/collection|t|target|values|low",
    "esbuild/collection|u|utils|left|low",
    "esbuild/collection|v|value|mergeDeep|low",
    "esbuild/loader|a|args|baseUrl|low",
    "esbuild/loader|c|context|load|low",
    "esbuild/loader|d|data|invalidate|low",
    "esbuild/loader|e|event|params|low",
    "esbuild/loader|e|event|prefix|low",
    "esbuild/loader|f|fn|transport|low",
    "esbuild/loader|i|index|error|low",
    "esbuild/loader|i|index|response|low",
    "esbuild/loader|l|list|createLoader|low",
    "esbuild/loader|n|list_2|query|high",
    "esbuild/loader|n|node|removed|low",
    "esbuild/loader|n|node|url|low",
    "esbuild/loader|o|options|resource|low",
    "esbuild/loader|r|result|key|low",
    "esbuild/loader|r|result|promise|low",
    "esbuild/loader|r|result|url|low",
    "esbuild/loader|t|target|cache|low",
    "esbuild/loader|u|utils|buildUrl|low",
    "esbuild/widget|c|context|increment|low",
    "esbuild/widget|e|event|callback|low",
    "esbuild/widget|e|event|event|low",
    "esbuild/widget|e|querySelector|label|medium",
    "esbuild/widget|f|indexOf|position|medium",
    "esbuild/widget|i|index|options|low",
    "esbuild/widget|l|list_2|subscribe|low",
    "esbuild/widget|n|node|counter|low",
    "esbuild/widget|o|options|render|low",
    "esbuild/widget|r|result|index|low",
    "esbuild/widget|s|button|button|high",
    "esbuild/widget|t|list|listeners|high",
    "esbuild/widget|u|root|root|high",
    "esbuild/widget|v|value|mountWidget|low",
    "terser/collection|c|context|right|low",
    "terser/collection|e|event_2|value|low",
    "terser/collection|e|event|target|low",
    "terser/collection|e|event|values|low",
    "terser/collection|e|list|records|low",
    "terser/collection|e|list|source|low",
    "terser/collection|n|node|cursor|low",
    "terser/collection|n|node|position|low",
    "terser/collection|n|node|record|low",
    "terser/collection|o|concat|keys|medium",
    "terser/collection|o|list_2|rejected|high",
    "terser/collection|o|options|index|low",
    "terser/collection|o|options|offset|low",
    "terser/collection|p|props|left|low",
    "terser/collection|r|result|patch|low",
    "terser/collection|r|result|predicate|low",
    "terser/collection|r|result|selector|low",
    "terser/collection|r|result|size|low",
    "terser/collection|t|list_2|result|high",
    "terser/collection|t|list|matched|high",
    "terser/collection|t|target|groups|low",
    "terser/collection|t|target|output|low",
    "terser/collection|u|utils|bucket|low",
    "terser/collection|u|utils|name|low",
    "terser/loader|a|args|url|low",
    "terser/loader|e|event_2|params|low",
    "terser/loader|e|event|cache|low",
    "terser/loader|i|index|promise|low",
    "terser/loader|n|node_2|error|low",
    "terser/loader|n|node_2|response|low",
    "terser/loader|n|node|baseUrl|low",
    "terser/loader|o|options_2|key|low",
    "terser/loader|o|options|params|low",
    "terser/loader|o|options|removed|low",
    "terser/loader|r|result_2|resource|low",
    "terser/loader|r|result|transport|low",
    "terser/loader|t|list|query|high",
    "terser/loader|t|target|prefix|low",
    "terser/loader|t|target|resource|low",
    "terser/widget|e|list|listeners|high",
    "terser/widget|i|index|counter|low",
    "terser/widget|n|indexOf|position|medium",
    "terser/widget|n|node_2|index|low",
    "terser/widget|n|node|options|low",
    "terser/widget|o|options|render|low",
    "terser/widget|r|result|increment|low",
    "terser/widget|t|root|root|high",
    "terser/widget|t|target|callback|low",
    "terser/widget|t|target|event|low",
    "terser/widget|u|button|button|high",
];
