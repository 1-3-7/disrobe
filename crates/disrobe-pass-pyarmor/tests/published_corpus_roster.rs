#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST: &str = "corpus/python/pyarmor/MANIFEST.toml";
const GATE_FILE: &str = "static_unpack_corpus.rs";
const FLOOR_CONST: &str = "RECOVERY_FLOOR";

const FIXTURE_HEADER: &str = "[[fixture]]";
const VERSION_KEY: &str = "pyarmor_version";
const OUTPUT_KEY: &str = "output_path";
const TOTAL_KEY: &str = "total_fixtures";
const V8_KEY: &str = "v8_fixtures";
const V9_KEY: &str = "v9_fixtures";

#[derive(Debug, Clone)]
struct DeclaredFixture {
    version: String,
    output_path: String,
}

fn repo_root() -> PathBuf {
    let manifest_dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest_dir.parent().and_then(Path::parent) else {
        panic!(
            "the PyArmor corpus roster lives at {MANIFEST}, two directories above {}, so a \
             manifest path with no grandparent leaves the declared roster checked against nothing",
            manifest_dir.display()
        )
    };
    root.to_path_buf()
}

fn read(relative: &str) -> String {
    let path: PathBuf = repo_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{relative} is committed evidence behind the published PyArmor figures, so a run that \
             cannot read it must fail rather than report a green that checked nothing: {error} at \
             {}",
            path.display()
        )
    })
}

fn quoted_value(line: &str, key: &str) -> Option<String> {
    let trimmed: &str = line.trim();
    let rest: &str = trimmed.strip_prefix(key)?;
    let after: &str = rest.trim_start().strip_prefix('=')?;
    let opened: &str = after.trim_start().strip_prefix('"')?;
    let (value, _): (&str, &str) = opened.split_once('"')?;
    Some(value.to_owned())
}

fn integer_value(text: &str, key: &str) -> usize {
    for line in text.lines() {
        let trimmed: &str = line.trim();
        let Some(rest): Option<&str> = trimmed.strip_prefix(key) else {
            continue;
        };
        let Some(after): Option<&str> = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let digits: String = after
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let Ok(value): Result<usize, core::num::ParseIntError> = digits.parse::<usize>() else {
            panic!("`{key}` in {MANIFEST} is not declared as a plain integer")
        };
        return value;
    }
    panic!(
        "{MANIFEST} no longer declares `{key}`, so the published corpus size is bound to nothing"
    )
}

fn declared_fixtures(text: &str) -> Vec<DeclaredFixture> {
    let mut fixtures: Vec<DeclaredFixture> = Vec::new();
    for block in text.split(FIXTURE_HEADER).skip(1) {
        let mut version: Option<String> = None;
        let mut output_path: Option<String> = None;
        for line in block.lines() {
            if line.trim_start().starts_with('[') {
                break;
            }
            if version.is_none() {
                version = quoted_value(line, VERSION_KEY);
            }
            if output_path.is_none() {
                output_path = quoted_value(line, OUTPUT_KEY);
            }
        }
        let (Some(version), Some(output_path)): (Option<String>, Option<String>) =
            (version, output_path)
        else {
            panic!(
                "a `{FIXTURE_HEADER}` block in {MANIFEST} declares no `{VERSION_KEY}` or no \
                 `{OUTPUT_KEY}`, so one member of the roster the published figures are cut from \
                 names no file"
            )
        };
        fixtures.push(DeclaredFixture {
            version,
            output_path,
        });
    }
    fixtures
}

fn absent_or_empty(root: &Path, fixtures: &[DeclaredFixture]) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    for fixture in fixtures {
        let path: PathBuf = root.join(&fixture.output_path);
        match fs::metadata(&path) {
            Ok(meta) if meta.is_file() && meta.len() > 0 => {}
            Ok(meta) if meta.is_file() => defects.push(format!("{} is empty", fixture.output_path)),
            Ok(_) => defects.push(format!("{} is not a file", fixture.output_path)),
            Err(error) => defects.push(format!("{} is absent: {error}", fixture.output_path)),
        }
    }
    defects
}

fn declared_floor() -> usize {
    let source: String = {
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(GATE_FILE);
        fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{GATE_FILE} is the gate that recovers every fixture the roster declares, so a run \
                 that cannot read it cannot compare the two: {error} at {}",
                path.display()
            )
        })
    };
    let needle: String = format!("const {FLOOR_CONST}: usize = ");
    let Some(at): Option<usize> = source.find(&needle) else {
        panic!(
            "{GATE_FILE} no longer declares `{FLOOR_CONST}`, so nothing holds the recovery gate to \
             the size of the roster {MANIFEST} declares"
        )
    };
    let Some(tail): Option<&str> = source.get(at.saturating_add(needle.len())..) else {
        panic!("`{FLOOR_CONST}` in {GATE_FILE} starts mid-character")
    };
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    let Ok(value): Result<usize, core::num::ParseIntError> = digits.parse::<usize>() else {
        panic!("`{FLOOR_CONST}` in {GATE_FILE} is not a plain integer literal")
    };
    value
}

#[test]
fn the_declared_roster_is_the_population_the_published_figures_are_cut_from() {
    let text: String = read(MANIFEST);
    let fixtures: Vec<DeclaredFixture> = declared_fixtures(&text);
    let total: usize = integer_value(&text, TOTAL_KEY);
    let v8: usize = integer_value(&text, V8_KEY);
    let v9: usize = integer_value(&text, V9_KEY);

    assert_eq!(
        fixtures.len(),
        total,
        "{MANIFEST} states `{TOTAL_KEY} = {total}` but carries {} `{FIXTURE_HEADER}` blocks; the \
         declared total is the denominator the published PyArmor figure divides by, so it is \
         pinned by equality and cannot renormalise onto whatever the file happens to list",
        fixtures.len()
    );
    assert_eq!(
        v8.saturating_add(v9),
        total,
        "{MANIFEST} splits the roster {v8} v8 and {v9} v9, which does not account for the declared \
         {total}"
    );

    let mut by_version: BTreeMap<String, usize> = BTreeMap::new();
    for fixture in &fixtures {
        *by_version.entry(fixture.version.clone()).or_default() += 1;
    }
    assert_eq!(
        by_version.get("v8").copied().unwrap_or_default(),
        v8,
        "the v8 half of the roster is declared as {v8} but {} blocks carry `{VERSION_KEY} = \"v8\"`; \
         a fixture that moved between versions would keep the total green while the split changed",
        by_version.get("v8").copied().unwrap_or_default()
    );
    assert_eq!(
        by_version.get("v9").copied().unwrap_or_default(),
        v9,
        "the v9 half of the roster is declared as {v9} but {} blocks carry `{VERSION_KEY} = \"v9\"`",
        by_version.get("v9").copied().unwrap_or_default()
    );
    assert_eq!(
        by_version.len(),
        2,
        "the roster declares versions {:?}; the published split names two, so a third would be \
         counted in the total and described nowhere",
        by_version.keys().collect::<Vec<&String>>()
    );
}

#[test]
fn every_declared_fixture_is_a_file_this_checkout_carries() {
    let root: PathBuf = repo_root();
    let text: String = read(MANIFEST);
    let fixtures: Vec<DeclaredFixture> = declared_fixtures(&text);

    let mut paths: Vec<&str> = fixtures
        .iter()
        .map(|fixture: &DeclaredFixture| fixture.output_path.as_str())
        .collect();
    let declared: usize = paths.len();
    paths.sort_unstable();
    paths.dedup();
    assert_eq!(
        paths.len(),
        declared,
        "{MANIFEST} names the same output path in more than one block, so the declared total counts \
         one file twice"
    );

    let defects: Vec<String> = absent_or_empty(&root, &fixtures);
    assert!(
        defects.is_empty(),
        "{} of the {declared} fixtures {MANIFEST} declares are not in this checkout, so the \
         published PyArmor figure is divided by a population that is not all here: {}",
        defects.len(),
        defects.join("; ")
    );
}

#[test]
fn the_recovery_gate_floors_at_the_size_of_the_declared_roster() {
    let text: String = read(MANIFEST);
    let total: usize = integer_value(&text, TOTAL_KEY);
    let floor: usize = declared_floor();

    assert_eq!(
        floor, total,
        "`{FLOOR_CONST}` in {GATE_FILE} is {floor} while {MANIFEST} declares {total} fixtures; a \
         floor below the roster lets a fixture stop recovering without the published figure moving, \
         and a floor above it cannot be met"
    );
}

#[test]
fn the_presence_check_rejects_a_fixture_the_tree_does_not_carry() {
    let root: PathBuf = repo_root();
    let fabricated: Vec<DeclaredFixture> = vec![DeclaredFixture {
        version: "v9".to_owned(),
        output_path: "corpus/python/pyarmor/v9/this-fixture-was-never-committed.py".to_owned(),
    }];
    let defects: Vec<String> = absent_or_empty(&root, &fabricated);
    assert_eq!(
        defects.len(),
        1,
        "the presence check must report a declared fixture the tree does not carry, otherwise the \
         assertion above passes no matter which file is deleted"
    );
    assert!(
        defects[0].contains("this-fixture-was-never-committed.py"),
        "the presence check must name the missing fixture: {defects:?}"
    );
}
