#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const GATE_FILE: &str = "arbitrary_recompile_gate.rs";
const MODULES_CONST: &str = "MODULES_EXACT_FLOOR";
const RECOVERY_DOC: &str = "xtask/data/recovery.json";
const PINNED_BAR_LABEL: &str = "200-module pinned corpus";

const SITES: [&str; 4] = [
    "README.md",
    "docs/src/introduction.md",
    "docs/src/architecture/whitepaper.md",
    "docs/src/languages/python.md",
];

const STALE_LOOKBACK: u64 = 16;

fn repo_root() -> PathBuf {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "the whole-module figure is published two directories above {}, so a manifest path \
             with no grandparent leaves the published figure checked against nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn read(path: &Path, what: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{what} carries the whole-module figure this check compares, so a run that cannot read \
             it must fail rather than report a green that compared nothing: {error} at {}",
            path.display()
        )
    })
}

fn without_markers(doc: &str) -> String {
    let mut out: String = String::with_capacity(doc.len());
    let mut rest: &str = doc;
    while let Some(open) = rest.find("<!--") {
        let Some(head): Option<&str> = rest.get(..open) else {
            break;
        };
        out.push_str(head);
        let Some(tail): Option<&str> = rest.get(open..) else {
            break;
        };
        let Some(close): Option<usize> = tail.find("-->") else {
            rest = "";
            break;
        };
        let Some(after): Option<&str> = tail.get(close.saturating_add(3)..) else {
            rest = "";
            break;
        };
        rest = after;
    }
    out.push_str(rest);
    out
}

fn page(root: &Path, site: &str) -> String {
    without_markers(&read(&root.join(site), site))
}

fn fraction_forms(numerator: u64, denominator: u64) -> [String; 2] {
    [
        format!("{numerator} of {denominator}"),
        format!("{numerator} of the {denominator}"),
    ]
}

fn states_fraction(doc: &str, numerator: u64, denominator: u64) -> bool {
    fraction_forms(numerator, denominator)
        .iter()
        .any(|form: &String| doc.contains(form.as_str()))
}

fn gate_floor() -> u64 {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(GATE_FILE);
    let source: String = read(&path, GATE_FILE);
    let needle: String = format!("const {MODULES_CONST}: u64 = ");
    let Some(at): Option<usize> = source.find(&needle) else {
        panic!(
            "{GATE_FILE} no longer declares `{MODULES_CONST}`, so the whole-module number the \
             documents publish is bound to nothing this check can read"
        )
    };
    let Some(tail): Option<&str> = source.get(at.saturating_add(needle.len())..) else {
        panic!("`{MODULES_CONST}` in {GATE_FILE} starts mid-character, so its value cannot be read")
    };
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    let Ok(value): Result<u64, core::num::ParseIntError> = digits.parse::<u64>() else {
        panic!("`{MODULES_CONST}` in {GATE_FILE} is not declared as a plain integer literal")
    };
    value
}

fn pinned_modules(root: &Path) -> u64 {
    let raw: String = read(&root.join(RECOVERY_DOC), RECOVERY_DOC);
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {RECOVERY_DOC}: {error}"));
    let groups: &Vec<serde_json::Value> = doc["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("{RECOVERY_DOC} carries no groups array"));
    let mut found: Vec<u64> = Vec::new();
    for group in groups {
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() != Some(PINNED_BAR_LABEL) {
                continue;
            }
            let Some(modules): Option<u64> = bar["modules"].as_u64() else {
                panic!(
                    "the `{PINNED_BAR_LABEL}` bar in {RECOVERY_DOC} states no module count, so the \
                     denominator of the published whole-module fraction is checked against nothing"
                )
            };
            found.push(modules);
        }
    }
    assert_eq!(
        found.len(),
        1,
        "{RECOVERY_DOC} must carry exactly one `{PINNED_BAR_LABEL}` bar, found {}",
        found.len()
    );
    found.remove(0)
}

fn one_decimal_percent(numerator: u64, denominator: u64) -> String {
    let pct: f64 = 100.0 * numerator as f64 / denominator as f64;
    format!("{pct:.1}%")
}

#[test]
fn every_page_states_the_whole_module_fraction_this_gate_floors() {
    let root: PathBuf = repo_root();
    let modules_exact: u64 = gate_floor();
    let modules: u64 = pinned_modules(&root);

    assert!(
        modules_exact > 0 && modules > 0,
        "a zero population would let every containment check below pass against a figure that \
         grades nothing"
    );
    assert!(
        modules_exact <= modules,
        "{GATE_FILE} floors {modules_exact} whole modules out of a published population of \
         {modules}, which claims more modules recovered than the corpus holds"
    );

    let mut checked: usize = 0;
    for site in SITES {
        let doc: String = page(&root, site);
        let lowered: String = doc.to_ascii_lowercase();
        if !lowered.contains("whole module") && !lowered.contains("whole-module") {
            continue;
        }
        assert!(
            states_fraction(&doc, modules_exact, modules),
            "{site} discusses the whole-module figure but never states {:?}, the count \
             `{MODULES_CONST}` in {GATE_FILE} floors, so the page publishes a number the gate does \
             not measure",
            fraction_forms(modules_exact, modules)
        );
        checked = checked.saturating_add(1);
    }
    assert!(
        checked >= 3,
        "only {checked} page(s) were checked against the whole-module fraction; README, the \
         introduction and the whitepaper each carry it, so a lower count means this check stopped \
         reading the surfaces that publish it"
    );
}

#[test]
fn no_page_states_a_count_or_a_rate_the_gate_does_not_floor() {
    let root: PathBuf = repo_root();
    let modules_exact: u64 = gate_floor();
    let modules: u64 = pinned_modules(&root);
    let current: String = one_decimal_percent(modules_exact, modules);

    for site in SITES {
        let doc: String = page(&root, site);

        for other in [
            modules_exact.saturating_sub(1),
            modules_exact.saturating_add(1),
        ] {
            assert!(
                !states_fraction(&doc, other, modules),
                "{site} states a whole-module count of {other} of {modules}, which is not the \
                 {modules_exact} of {modules} `{MODULES_CONST}` floors"
            );
        }

        for behind in 1u64..=STALE_LOOKBACK {
            let Some(fewer): Option<u64> = modules_exact.checked_sub(behind) else {
                break;
            };
            let stale: String = one_decimal_percent(fewer, modules);
            if stale == current {
                continue;
            }
            assert!(
                !doc.contains(&stale),
                "{site} still states `{stale}`, which is what {fewer} of {modules} modules would \
                 measure rather than the {modules_exact} of {modules} the gate now floors"
            );
        }
    }
}
