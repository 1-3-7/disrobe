#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const GATE_FILE: &str = "roundtrip.rs";
const README: &str = "README.md";

const FIXTURES_CONST: &str = "PINNED_FIXTURES";
const REEXECUTED_CONST: &str = "PINNED_REEXECUTED";
const FLOOR_CONST: &str = "FLOOR_PERCENT";

fn repo_root() -> PathBuf {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "the pickle roundtrip figure is published in {README}, two directories above {}, so a \
             manifest path with no grandparent leaves the published figure checked against nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn gate_source() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(GATE_FILE);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{GATE_FILE} declares the counts {README} publishes, so a run that cannot read it must \
             fail rather than report a green that compared nothing: {error} at {}",
            path.display()
        )
    })
}

fn readme() -> String {
    let path: PathBuf = repo_root().join(README);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{README} is the surface that publishes the pickle roundtrip figure, so a run that \
             cannot read it must fail rather than report a green that checked no document: {error} \
             at {}",
            path.display()
        )
    })
}

fn rendered_readme() -> String {
    readme()
        .replace("<!-- m:pickle_roundtrip_frac -->", "")
        .replace("<!-- /m -->", "")
}

fn declared(source: &str, name: &str) -> usize {
    let needle: String = format!("const {name}: usize = ");
    let Some(at): Option<usize> = source.find(&needle) else {
        panic!(
            "{GATE_FILE} no longer declares `{name}`, so the number {README} publishes is bound to \
             nothing this check can read"
        )
    };
    let Some(tail): Option<&str> = source.get(at.saturating_add(needle.len())..) else {
        panic!("`{name}` in {GATE_FILE} starts mid-character, so its value cannot be read")
    };
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    let Ok(value): Result<usize, core::num::ParseIntError> = digits.parse::<usize>() else {
        panic!("`{name}` in {GATE_FILE} is not declared as a plain integer literal")
    };
    value
}

#[test]
fn the_readme_states_the_roundtrip_figure_this_gate_enforces() {
    let source: String = gate_source();
    let fixtures: usize = declared(&source, FIXTURES_CONST);
    let reexecuted: usize = declared(&source, REEXECUTED_CONST);
    let floor: usize = declared(&source, FLOOR_CONST);

    assert!(
        fixtures > 0 && reexecuted > 0,
        "{GATE_FILE} declares a zero population, so every containment check below would compare \
         against a figure that grades nothing"
    );
    assert_eq!(
        reexecuted, fixtures,
        "{README} publishes this row as a complete recovery, so the gate's re-executed count and \
         its population are pinned equal; {GATE_FILE} now declares {reexecuted} of {fixtures} and \
         the published sentence would overstate it"
    );

    let doc: String = rendered_readme();
    let coverage_figure: String = format!(
        "{reexecuted} / {fixtures} reconstructed fixtures pass re-execution equality checks"
    );
    assert!(
        doc.contains(&coverage_figure),
        "{README} does not state `{coverage_figure}`; {GATE_FILE} pins {FIXTURES_CONST} at {fixtures} and \
         {REEXECUTED_CONST} at {reexecuted}, so the page publishes a figure the gate does not \
         measure"
    );

    let result_path: &str = "evidence/results/pickle-roundtrip.md";
    assert!(doc.contains(&format!("[Result]({result_path})")));
    let result: String = fs::read_to_string(repo_root().join(result_path))
        .expect("the linked pickle result is readable");
    let graded_row: String = format!("- floor: {floor}.00 (holds)");
    assert!(
        result.contains(&graded_row),
        "{result_path} must state `{graded_row}` to match {FLOOR_CONST} in {GATE_FILE}"
    );

    assert_eq!(
        doc.matches(&coverage_figure).count(),
        1,
        "{README} states `{coverage_figure}` {} times; the coverage table must carry it exactly \
         once",
        doc.matches(&coverage_figure).count()
    );
    assert_eq!(
        result.matches(&graded_row).count(),
        1,
        "{result_path} must state `{graded_row}` exactly once"
    );
}

#[test]
fn the_readme_check_rejects_a_figure_the_gate_does_not_measure() {
    let source: String = gate_source();
    let fixtures: usize = declared(&source, FIXTURES_CONST);
    let reexecuted: usize = declared(&source, REEXECUTED_CONST);
    let doc: String = rendered_readme();

    let understated: String = format!(
        "{} / {} reconstructed fixtures pass re-execution equality checks",
        reexecuted.saturating_sub(1),
        fixtures.saturating_sub(1)
    );
    assert!(
        !doc.contains(&understated),
        "{README} still states `{understated}`, a population the gate does not grade, so the \
         containment assertion above would pass on a stale figure"
    );

    let overstated: String = format!(
        "{} / {} reconstructed fixtures pass re-execution equality checks",
        reexecuted.saturating_add(1),
        fixtures.saturating_add(1)
    );
    assert!(
        !doc.contains(&overstated),
        "{README} states `{overstated}`, which claims more than {GATE_FILE} measures"
    );
}
