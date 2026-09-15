#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pyfreeze::common::manifest::EntryRecord;
use disrobe_pass_pyfreeze::pass::{self, PyfreezeOutput};
use disrobe_pass_pyfreeze::{FreezerKind, RecoveredModule};

const PUBLISHED_DOC: &str = "docs/src/languages/python.md";
const PUBLISHED_COMMAND: &str = "disrobe pyfreeze extract app.exe";
const PUBLISHED_FREEZER_ROW: &str = "| Freezers |";

const DECLARED_FAMILIES: usize = 6;
const EXERCISED_FAMILIES: usize = 5;

#[derive(Debug, Clone, Copy)]
struct PublishedFreezer {
    doc_token: &'static str,
    kind: FreezerKind,
    artifact: Option<&'static str>,
    expected_module: &'static str,
    unexercised_because: &'static str,
}

const ROSTER: [PublishedFreezer; DECLARED_FAMILIES] = [
    PublishedFreezer {
        doc_token: "cx_Freeze",
        kind: FreezerKind::CxFreeze,
        artifact: Some("cxfreeze/extracted/hello.exe"),
        expected_module: "edge_cases_3_12",
        unexercised_because: "",
    },
    PublishedFreezer {
        doc_token: "py2exe",
        kind: FreezerKind::Py2exe,
        artifact: Some("py2exe/hello.exe"),
        expected_module: "__pythonscript__",
        unexercised_because: "",
    },
    PublishedFreezer {
        doc_token: "shiv",
        kind: FreezerKind::Shiv,
        artifact: Some("shiv/hello.pyz"),
        expected_module: "edge_cases_3_12",
        unexercised_because: "",
    },
    PublishedFreezer {
        doc_token: "pex",
        kind: FreezerKind::Pex,
        artifact: Some("pex/hello.pex"),
        expected_module: "edge_cases_3_12",
        unexercised_because: "",
    },
    PublishedFreezer {
        doc_token: "PyOxidizer (experimental, unvalidated)",
        kind: FreezerKind::PyOxidizer,
        artifact: None,
        expected_module: "",
        unexercised_because: "no PyOxidizer artifact is committed; pyoxidizer_real_binary.rs builds one with the \
             real tool into target/test-fixtures and grades it there, so a clean checkout carries \
             no input for this family",
    },
    PublishedFreezer {
        doc_token: "Briefcase",
        kind: FreezerKind::Briefcase,
        artifact: Some("briefcase/extracted/hello.exe"),
        expected_module: "edge_cases_3_12",
        unexercised_because: "",
    },
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

fn corpus_path(relative: &str) -> PathBuf {
    let mut path: PathBuf = repo_root().join("corpus").join("python").join("freezers");
    for part in relative.split('/') {
        path.push(part);
    }
    path
}

fn published_doc() -> String {
    let path: PathBuf = repo_root().join(PUBLISHED_DOC);
    std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is the page this gate holds; a run that cannot read it compared nothing and must \
             fail rather than report a pass: {error}",
            path.display()
        )
    })
}

fn published_command_families(doc: &str) -> BTreeSet<String> {
    let line: &str = doc
        .lines()
        .find(|line: &&str| line.contains(PUBLISHED_COMMAND))
        .unwrap_or_else(|| {
            panic!("{PUBLISHED_DOC} no longer carries the {PUBLISHED_COMMAND} row this gate holds")
        });
    let (_, comment): (&str, &str) = line
        .split_once('#')
        .unwrap_or_else(|| panic!("the {PUBLISHED_COMMAND} row states no family list: {line}"));
    comment
        .split('/')
        .map(|family: &str| family.trim().to_owned())
        .filter(|family: &String| !family.is_empty())
        .collect()
}

fn extract_family(family: PublishedFreezer) -> PyfreezeOutput {
    let relative: &str = family
        .artifact
        .unwrap_or_else(|| panic!("{} carries no committed artifact", family.doc_token));
    let input: PathBuf = corpus_path(relative);
    assert!(
        input.is_file(),
        "{} is committed in this repository as the input behind the published {} family, so its \
         absence at {} is never a skip",
        relative,
        family.doc_token,
        input.display()
    );
    let scratch: ScratchDir = ScratchDir::create(&format!(
        "disrobe-published-freezer-{}-{}",
        family.kind.label(),
        std::process::id()
    ))
    .expect("create scratch dir");
    pass::extract(&input, scratch.path()).unwrap_or_else(|error| {
        panic!(
            "the published {} family must extract from {}: {error}",
            family.doc_token,
            input.display()
        )
    })
}

#[test]
fn the_published_command_names_this_roster_and_no_other_family() {
    let doc: String = published_doc();
    let published: BTreeSet<String> = published_command_families(&doc);
    let held: BTreeSet<String> = ROSTER
        .iter()
        .map(|family: &PublishedFreezer| family.doc_token.to_owned())
        .collect();
    assert_eq!(
        published, held,
        "the {PUBLISHED_COMMAND} row and the roster this gate exercises must name the same \
         families in both directions"
    );
    assert_eq!(
        published.len(),
        DECLARED_FAMILIES,
        "the declared family count moved without this gate moving with it"
    );
    let row: &str = doc
        .lines()
        .find(|line: &&str| line.starts_with(PUBLISHED_FREEZER_ROW))
        .unwrap_or_else(|| panic!("{PUBLISHED_DOC} no longer carries a Freezers table row"));
    for family in ROSTER {
        assert!(
            row.contains(family.doc_token),
            "the Freezers table row drops {}, which the command row still promises",
            family.doc_token
        );
    }
}

#[test]
fn every_published_family_with_a_committed_input_recovers_its_payload() {
    let mut exercised: BTreeSet<&'static str> = BTreeSet::new();
    for family in ROSTER {
        let Some(_): Option<&'static str> = family.artifact else {
            continue;
        };
        let output: PyfreezeOutput = extract_family(family);
        assert_eq!(
            output.detection.kind, family.kind,
            "{} must be dispatched to its own extractor, not to {:?}",
            family.doc_token, output.detection.kind
        );
        assert!(
            output.extracted_count > 0,
            "{} extracted nothing, so the published family recovers no payload",
            family.doc_token
        );
        let mut recovered: BTreeSet<&str> = output
            .recovery
            .modules
            .iter()
            .map(|module: &RecoveredModule| module.name.as_str())
            .collect();
        recovered.extend(
            output
                .manifest
                .entries
                .iter()
                .map(|entry: &EntryRecord| entry.name.as_str()),
        );
        assert!(
            recovered
                .iter()
                .any(|name: &&str| name.contains(family.expected_module)),
            "{} surfaced {} entries and none of them is the {} the committed application carries",
            family.doc_token,
            recovered.len(),
            family.expected_module
        );
        exercised.insert(family.doc_token);
    }
    let expected: BTreeSet<&'static str> = ROSTER
        .iter()
        .filter(|family: &&PublishedFreezer| family.artifact.is_some())
        .map(|family: &PublishedFreezer| family.doc_token)
        .collect();
    assert_eq!(
        exercised, expected,
        "every family this gate claims to exercise must have been exercised in this run"
    );
    assert_eq!(
        exercised.len(),
        EXERCISED_FAMILIES,
        "the exercised count moved; a published family gaining or losing a committed input changes \
         what this repository can prove from a clean checkout"
    );
}

#[test]
fn the_declared_and_exercised_split_is_stated_rather_than_averaged_away() {
    let unexercised: BTreeSet<&'static str> = ROSTER
        .iter()
        .filter(|family: &&PublishedFreezer| family.artifact.is_none())
        .map(|family: &PublishedFreezer| family.doc_token)
        .collect();
    assert_eq!(
        unexercised,
        BTreeSet::from(["PyOxidizer (experimental, unvalidated)"]),
        "the set of published families with no committed input is part of what this gate publishes; \
         changing it means the declared-against-exercised split on the page changed too"
    );
    assert_eq!(
        DECLARED_FAMILIES - EXERCISED_FAMILIES,
        unexercised.len(),
        "the two counts and the unexercised roster must agree"
    );
    for family in ROSTER {
        if family.artifact.is_some() {
            assert!(
                family.unexercised_because.is_empty(),
                "{} carries a committed input, so it must not also carry a reason for having none",
                family.doc_token
            );
            continue;
        }
        assert!(
            !family.unexercised_because.is_empty(),
            "{} has no committed input and must state why",
            family.doc_token
        );
    }
}

#[test]
fn a_corrupted_payload_is_refused_rather_than_recovered() {
    let family: PublishedFreezer = ROSTER
        .into_iter()
        .find(|family: &PublishedFreezer| family.doc_token == "shiv")
        .expect("the shiv family is in the roster");
    let input: PathBuf = corpus_path(family.artifact.expect("shiv carries a committed artifact"));
    let mut bytes: Vec<u8> = std::fs::read(&input)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", input.display()));
    for byte in bytes.iter_mut().skip(64) {
        *byte ^= 0xff;
    }
    let scratch: ScratchDir = ScratchDir::create(&format!(
        "disrobe-published-freezer-mutant-{}",
        std::process::id()
    ))
    .expect("create scratch dir");
    let corrupted: PathBuf = scratch.path().join("hello.pyz");
    std::fs::write(&corrupted, &bytes)
        .unwrap_or_else(|error: std::io::Error| panic!("write {}: {error}", corrupted.display()));
    let out: PathBuf = scratch.path().join("out");
    let recovered: usize = match pass::extract(&corrupted, &out) {
        Ok(output) => output
            .recovery
            .modules
            .iter()
            .filter(|module: &&RecoveredModule| module.name.contains(family.expected_module))
            .count(),
        Err(_) => 0,
    };
    assert_eq!(
        recovered, 0,
        "a payload whose body was overwritten must not still yield the modules the intact archive \
         carries, or the check above proves nothing about the archive"
    );
}
