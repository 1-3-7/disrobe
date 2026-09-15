#![cfg(feature = "nir-lift")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::PathBuf;

use serde_json::Value;

const MIXED: &str = "tests/fixtures/native_aarch64_mixed_coverage.elf";
const MANY_LOW: &str = "tests/fixtures/native_aarch64_many_low_coverage.elf";

fn decompile(fixture: &str) -> (common::Run, Value) {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(fixture);
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create output directory");
    let output: PathBuf = scratch.path().join("out");
    let run: common::Run = common::run_disrobe(&[
        "native",
        "decompile",
        &path.display().to_string(),
        "--backend",
        "native",
        "--format",
        "c",
        "--out",
        &output.display().to_string(),
    ]);
    assert_eq!(
        run.code, 0,
        "native decompile must succeed on {fixture}; stderr={}",
        run.stderr
    );
    let manifest: PathBuf = output.join("manifest.json");
    let parsed: Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest)
            .unwrap_or_else(|error| panic!("read {}: {error}", manifest.display())),
    )
    .expect("manifest must be JSON");
    (run, parsed)
}

fn recovered<'a>(manifest: &'a Value, name: &str) -> &'a Value {
    manifest["recovered"]
        .as_array()
        .expect("recovered must be an array")
        .iter()
        .find(|entry: &&Value| entry["name"] == name)
        .unwrap_or_else(|| panic!("{name} must be recovered: {manifest}"))
}

fn whole(manifest: &Value) -> &Value {
    manifest
        .get("decode_coverage")
        .expect("the manifest must carry a whole-binary decode_coverage block")
}

fn supported(block: &Value) -> u64 {
    block["by_status"]
        .as_array()
        .expect("by_status must be an array")
        .iter()
        .find(|share: &&Value| share["status"] == "supported")
        .and_then(|share: &Value| share["instructions"].as_u64())
        .expect("the supported share must be present")
}

#[test]
fn every_recovered_function_carries_its_own_decode_coverage() {
    let (_run, manifest): (common::Run, Value) = decompile(MIXED);
    let clean: &Value = &recovered(&manifest, "clean_arith")["decode"];
    let probe: &Value = &recovered(&manifest, "system_probe")["decode"];
    assert_eq!(
        clean["decoded_instructions"], 11,
        "clean_arith is ten arithmetic instructions and a return"
    );
    assert_eq!(
        supported(clean),
        11,
        "every instruction in clean_arith is semantically lifted"
    );
    assert_eq!(clean["semantic_percent"], "100.00");
    assert_eq!(
        probe["decoded_instructions"], 3,
        "system_probe is mrs, svc and a return"
    );
    assert_eq!(
        supported(probe),
        1,
        "only the return of system_probe is semantically lifted"
    );
    assert_eq!(probe["semantic_percent"], "33.33");
}

#[test]
fn a_high_whole_binary_figure_does_not_hide_a_poorly_covered_function() {
    let (run, manifest): (common::Run, Value) = decompile(MIXED);
    let block: &Value = whole(&manifest);
    assert_eq!(
        block["decoded_instructions"], 14,
        "the two functions decode fourteen instructions between them"
    );
    assert_eq!(supported(block), 12, "twelve of them are lifted");
    assert_eq!(
        block["semantic_percent"], "85.71",
        "the whole-binary figure is high enough to read as broad success"
    );
    let lowest: &Vec<Value> = block["lowest_covered_functions"]
        .as_array()
        .expect("lowest_covered_functions must be an array");
    assert_eq!(
        lowest.len(),
        1,
        "exactly one function sits below the whole-binary figure: {lowest:?}"
    );
    assert_eq!(lowest[0]["function"], "system_probe");
    assert_eq!(lowest[0]["decoded_instructions"], 3);
    assert_eq!(lowest[0]["semantically_lifted_instructions"], 1);
    assert_eq!(
        lowest[0]["semantic_percent"], "33.33",
        "the poorly covered function must be reported at its own figure, not the whole-binary one"
    );
    assert_eq!(
        block["lowest_covered_functions_omitted"], 0,
        "nothing was dropped from the list, and the count must say so rather than be absent"
    );
    let line: &str = run
        .stdout
        .lines()
        .find(|line: &&str| line.contains("system_probe"))
        .unwrap_or_else(|| {
            panic!(
                "the human output must name the poorly covered function: {}",
                run.stdout
            )
        });
    assert!(
        line.contains("1/3") && line.contains("(33.33%)"),
        "the human line must print the same counts and figure as the manifest; line={line}"
    );
    assert!(
        run.stdout.contains("lowest covered functions:"),
        "the human output must introduce the list: {}",
        run.stdout
    );
}

#[test]
fn a_function_at_or_above_the_whole_binary_figure_is_not_listed_as_poorly_covered() {
    let (run, manifest): (common::Run, Value) = decompile(MIXED);
    let listed: Vec<&str> = whole(&manifest)["lowest_covered_functions"]
        .as_array()
        .expect("lowest_covered_functions must be an array")
        .iter()
        .filter_map(|share: &Value| share["function"].as_str())
        .collect();
    assert!(
        !listed.contains(&"clean_arith"),
        "a fully lifted function must not appear in a list of functions below the whole-binary \
         figure: {listed:?}"
    );
    let section: &str = run
        .stdout
        .split("lowest covered functions:")
        .nth(1)
        .expect("the human output must carry the section");
    assert!(
        !section.contains("clean_arith"),
        "the human list must match the manifest list rather than printing every function; \
         section={section}"
    );
}

#[test]
fn a_uniformly_covered_binary_says_so_rather_than_printing_an_empty_list() {
    let (run, manifest): (common::Run, Value) =
        decompile("tests/fixtures/native_aarch64_scalar_post_index.elf");
    let lowest: &Vec<Value> = whole(&manifest)["lowest_covered_functions"]
        .as_array()
        .expect("lowest_covered_functions must be an array");
    assert!(
        lowest.is_empty(),
        "both functions of the scalar fixture carry the same coverage, so neither is below the \
         whole-binary figure: {lowest:?}"
    );
    assert!(
        run.stdout
            .contains("lowest covered functions: none below the whole-binary figure"),
        "an empty list must be stated rather than left out, so a reader can tell it from missing \
         output: {}",
        run.stdout
    );
}

#[test]
fn a_capped_list_names_how_many_functions_it_left_out() {
    let (run, manifest): (common::Run, Value) = decompile(MANY_LOW);
    let block: &Value = whole(&manifest);
    assert_eq!(
        block["decoded_instructions"], 54,
        "eleven arithmetic instructions, a ten-instruction mixed function, and eleven probes of \
         three"
    );
    assert_eq!(
        block["semantic_percent"], "48.15",
        "twenty-six of fifty-four instructions are semantically lifted"
    );
    let lowest: &Vec<Value> = block["lowest_covered_functions"]
        .as_array()
        .expect("lowest_covered_functions must be an array");
    assert_eq!(
        lowest.len(),
        10,
        "twelve functions sit below the whole-binary figure and the list is capped at ten"
    );
    assert_eq!(
        block["lowest_covered_functions_omitted"], 2,
        "the two functions the cap dropped must be counted, so a truncated list is never read as \
         the whole set"
    );
    let named: Vec<&str> = lowest
        .iter()
        .filter_map(|share: &Value| share["function"].as_str())
        .collect();
    assert_eq!(
        named,
        [
            "system_probe_00",
            "system_probe_01",
            "system_probe_02",
            "system_probe_03",
            "system_probe_04",
            "system_probe_05",
            "system_probe_06",
            "system_probe_07",
            "system_probe_08",
            "system_probe_09",
        ],
        "functions tied on coverage must be ordered by name so the capped list is deterministic \
         rather than dependent on discovery order"
    );
    assert!(
        !named.contains(&"clean_arith"),
        "the fully lifted function is above the whole-binary figure and must not be listed"
    );
    assert!(
        !named.contains(&"mid_probe"),
        "mid_probe is below the whole-binary figure at 40.00 per cent but better covered than \
         every probe, so a worst-first list capped at ten must drop it rather than lead with it; \
         a best-first list would put it first: {named:?}"
    );
    assert_eq!(
        recovered(&manifest, "mid_probe")["decode"]["semantic_percent"],
        "40.00",
        "mid_probe must still carry its own figure in its per-function block even though the \
         capped summary list leaves it out"
    );
    assert!(
        run.stdout
            .contains("2 further function(s) below the whole-binary figure are not listed"),
        "the human output must say what the cap dropped rather than truncating silently: {}",
        run.stdout
    );
}
