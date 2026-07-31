#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_binfmt::container::{ContainerKind, detect_container_with_hint};
use disrobe_binfmt::extract::{ExtractionResult, extract_to};

const EVIDENCE: &str = "tests/golden/container_breadth.txt";
const REGENERATE: &str = "DISROBE_REGENERATE_CONTAINER_BREADTH";

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MIN_INPUT_BYTES: u64 = 4;

const STATUS_EXTRACT: &str = "extract";
const STATUS_DETECT: &str = "detect-only";
const STATUS_MISDETECT: &str = "misdetect";

const KNOWN_MISDETECTIONS: usize = 0;

const MISDETECTED_SOURCE_SUFFIXES: [&str; 2] = [".rs", ".pyc"];

#[derive(Debug, Clone, Copy)]
struct ForeignFamily {
    suffix: &'static str,
    family: &'static str,
    header_matches: fn(&[u8]) -> bool,
}

fn cpython_bytecode_header(bytes: &[u8]) -> bool {
    bytes.get(2..4) == Some(b"\r\n".as_slice())
}

fn jvm_classfile_header(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

fn source_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok()
}

const FOREIGN_FAMILIES: [ForeignFamily; 5] = [
    ForeignFamily {
        suffix: ".pyc",
        family: "CPython bytecode",
        header_matches: cpython_bytecode_header,
    },
    ForeignFamily {
        suffix: ".pyo",
        family: "CPython bytecode",
        header_matches: cpython_bytecode_header,
    },
    ForeignFamily {
        suffix: ".class",
        family: "JVM classfile",
        header_matches: jvm_classfile_header,
    },
    ForeignFamily {
        suffix: ".rs",
        family: "Rust source",
        header_matches: source_text,
    },
    ForeignFamily {
        suffix: ".py",
        family: "Python source",
        header_matches: source_text,
    },
];

fn foreign_family(relative: &str, bytes: &[u8]) -> Option<&'static ForeignFamily> {
    FOREIGN_FAMILIES.iter().find(|family: &&ForeignFamily| {
        relative.ends_with(family.suffix) && (family.header_matches)(bytes)
    })
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    let manifest: PathBuf = crate_root();
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "the container breadth figure is measured over the repository two directories above \
             {}, so a manifest path with no grandparent leaves that figure measured against \
             nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn tracked_files(root: &Path) -> Vec<PathBuf> {
    let out: Output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-files")
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "this figure counts container formats reachable from committed inputs, so it is \
                 measured over `git ls-files` rather than a directory walk that would also count \
                 build output and untracked samples: {error}"
            )
        });
    assert!(
        out.status.success(),
        "`git ls-files` failed in {}, so the committed-input population cannot be established",
        root.display()
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim_end)
        .filter(|line: &&str| !line.is_empty())
        .map(|line: &str| root.join(line))
        .collect()
}

fn is_source_text(relative: &str) -> bool {
    MISDETECTED_SOURCE_SUFFIXES
        .iter()
        .any(|suffix: &&str| relative.ends_with(suffix))
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

#[derive(Debug, Clone)]
struct Reached {
    status: &'static str,
    input: String,
}

fn measure() -> BTreeMap<&'static str, Reached> {
    let root: PathBuf = repo_root();
    let temp: tempfile::TempDir = tempfile::tempdir().expect("temp dir for extraction output");
    let mut reached: BTreeMap<&'static str, Reached> = BTreeMap::new();
    let mut seen: usize = 0;

    for path in tracked_files(&root) {
        let Ok(meta): Result<std::fs::Metadata, std::io::Error> = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_INPUT_BYTES || meta.len() < MIN_INPUT_BYTES {
            continue;
        }
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(&path) else {
            continue;
        };
        let Some(kind): Option<ContainerKind> =
            detect_container_with_hint(&bytes, Some(path.as_path()))
        else {
            continue;
        };
        let label: &'static str = kind.label();
        let relative: String = relative_to(&root, &path);
        seen += 1;

        let out_dir: PathBuf = temp.path().join(format!("{label}-{seen}"));
        std::fs::create_dir_all(&out_dir).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "cannot create {}, so {label} would drop out of the exercised count without \
                 being measured: {error}",
                out_dir.display()
            )
        });
        let wrote_members: bool = extract_to(kind, &bytes, &out_dir)
            .is_ok_and(|result: ExtractionResult| wrote_member_bytes(&result));
        let status: &'static str = if is_source_text(&relative) {
            STATUS_MISDETECT
        } else if wrote_members {
            STATUS_EXTRACT
        } else {
            STATUS_DETECT
        };

        let entry: &mut Reached = reached.entry(label).or_insert_with(|| Reached {
            status,
            input: relative.clone(),
        });
        if rank(status) > rank(entry.status) {
            entry.status = status;
            entry.input = relative;
        }
    }
    reached
}

const fn rank(status: &str) -> u8 {
    match status.as_bytes() {
        b"extract" => 2,
        b"detect-only" => 1,
        _ => 0,
    }
}

fn wrote_member_bytes(result: &ExtractionResult) -> bool {
    result.entries.iter().any(|entry| {
        entry
            .disk_path
            .as_ref()
            .is_some_and(|path: &PathBuf| path.is_file())
    })
}

fn rendered(reached: &BTreeMap<&'static str, Reached>) -> String {
    let mut out: String = String::new();
    for kind in ContainerKind::ALL {
        let label: &'static str = kind.label();
        let Some(row): Option<&Reached> = reached.get(label) else {
            continue;
        };
        writeln!(out, "{label}\t{}\t{}", row.status, row.input)
            .expect("writing a row into an in-memory string cannot fail");
    }
    out
}

fn evidence_path() -> PathBuf {
    crate_root().join(EVIDENCE)
}

fn committed_evidence() -> String {
    let path: PathBuf = evidence_path();
    std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{EVIDENCE} records which container formats a committed input actually reaches, and \
             every published breadth figure for this roster is derived from it, so its absence \
             leaves that figure measured against nothing: {error} at {}",
            path.display()
        )
    })
}

fn parse(evidence: &str) -> Vec<(String, String, String)> {
    evidence
        .lines()
        .map(str::trim_end)
        .filter(|line: &&str| !line.is_empty())
        .map(|line: &str| {
            let mut parts: std::str::Split<'_, char> = line.split('\t');
            let kind: String = parts.next().unwrap_or_default().to_owned();
            let status: String = parts.next().unwrap_or_default().to_owned();
            let input: String = parts.next().unwrap_or_default().to_owned();
            assert!(
                !kind.is_empty() && !status.is_empty() && !input.is_empty(),
                "{EVIDENCE} row `{line}` is not a kind, status and input separated by tabs, so \
                 this check cannot tell what it claims"
            );
            (kind, status, input)
        })
        .collect()
}

#[test]
fn the_evidence_is_what_a_committed_input_actually_reaches() {
    let reached: BTreeMap<&'static str, Reached> = measure();
    let derived: String = rendered(&reached);

    if std::env::var_os(REGENERATE).is_some() {
        std::fs::create_dir_all(evidence_path().parent().expect("evidence has a parent"))
            .expect("create golden dir");
        std::fs::write(evidence_path(), &derived).expect("write evidence");
        return;
    }

    let committed: String = committed_evidence();
    if committed != derived {
        let committed_rows: Vec<(String, String, String)> = parse(&committed);
        let derived_rows: Vec<(String, String, String)> = parse(&derived);
        let stale: Vec<&(String, String, String)> = committed_rows
            .iter()
            .filter(|row: &&(String, String, String)| !derived_rows.contains(row))
            .collect();
        let fresh: Vec<&(String, String, String)> = derived_rows
            .iter()
            .filter(|row: &&(String, String, String)| !committed_rows.contains(row))
            .collect();
        panic!(
            "{EVIDENCE} and the formats a committed input reaches have diverged. Recorded but no \
             longer reproduced: {stale:?}. Reproduced but not recorded: {fresh:?}. Regenerate with \
             {REGENERATE}=1 and move the published breadth figure with it."
        );
    }
}

#[test]
fn the_evidence_names_only_formats_the_roster_declares() {
    let declared: Vec<&'static str> = ContainerKind::ALL
        .iter()
        .map(|kind: &ContainerKind| kind.label())
        .collect();
    for (kind, _, _) in parse(&committed_evidence()) {
        assert!(
            declared.contains(&kind.as_str()),
            "{EVIDENCE} credits `{kind}` with a committed input, but `ContainerKind::ALL` declares \
             no such format, so the exercised figure counts something the binary cannot produce"
        );
    }
}

#[test]
fn the_exercised_figure_is_smaller_than_the_declared_roster_and_neither_is_empty() {
    let rows: Vec<(String, String, String)> = parse(&committed_evidence());
    let exercised: usize = rows
        .iter()
        .filter(|(_, status, _)| status == STATUS_EXTRACT)
        .count();
    assert!(
        exercised > 0,
        "no committed input reaches any container format, so this check would compare an empty \
         set against an empty set and pass"
    );
    assert!(
        exercised <= ContainerKind::ALL.len(),
        "the evidence credits {exercised} exercised formats against {} declared, which means a \
         format is counted twice",
        ContainerKind::ALL.len()
    );
    assert!(
        rows.len() >= exercised,
        "every exercised format must also be a recorded row"
    );
}

#[test]
fn a_format_whose_input_stopped_extracting_is_not_still_counted() {
    let rows: Vec<(String, String, String)> = parse(&committed_evidence());
    let reached: BTreeMap<&'static str, Reached> = measure();
    for (kind, status, input) in rows {
        if status != STATUS_EXTRACT {
            continue;
        }
        let Some(row): Option<&Reached> = reached.get(kind.as_str()) else {
            panic!(
                "{EVIDENCE} credits `{kind}` with extracting member bytes from `{input}`, but no \
                 committed input reaches that format any more, so the exercised figure counts a \
                 format nothing exercises"
            )
        };
        assert_eq!(
            row.status, STATUS_EXTRACT,
            "{EVIDENCE} credits `{kind}` with extracting member bytes, but the best a committed \
             input now achieves is `{}`, so the published figure would keep crediting a recovery \
             that stopped happening",
            row.status
        );
    }
}

#[test]
fn the_recorded_misdetections_only_ever_shrink() {
    let rows: Vec<(String, String, String)> = parse(&committed_evidence());
    let misdetected: Vec<&(String, String, String)> = rows
        .iter()
        .filter(|(_, status, _): &&(String, String, String)| status == STATUS_MISDETECT)
        .collect();
    assert!(
        misdetected.len() <= KNOWN_MISDETECTIONS,
        "{EVIDENCE} records {} formats claiming a source file they cannot contain, against a \
         ceiling of {KNOWN_MISDETECTIONS}. A detector that started firing on unrelated bytes must \
         fail here rather than be absorbed into the golden as an expected row: {misdetected:?}",
        misdetected.len()
    );
}

#[test]
fn no_recorded_row_credits_a_format_with_a_file_of_another_family() {
    let root: PathBuf = repo_root();
    let mut wrong: Vec<String> = Vec::new();
    for (kind, status, input) in parse(&committed_evidence()) {
        let path: PathBuf = root.join(&input);
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(&path) else {
            panic!(
                "{EVIDENCE} names `{input}` as what reaches `{kind}`, but that path cannot be read \
                 from {}, so the row rests on a file this check cannot inspect",
                root.display()
            )
        };
        if let Some(family) = foreign_family(&input, &bytes) {
            wrong.push(format!(
                "`{kind}` ({status}) is credited to `{input}`, whose `{}` extension and header are \
                 a {} file",
                family.suffix, family.family
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{EVIDENCE} is written by the same measurement this suite re-runs, so a misclassification \
         lands in it as the expected value and every row-by-row comparison then passes over it. \
         This is the rule that measurement cannot write for itself: a format may not be credited \
         to a file whose extension and header both belong to another family. {} row(s) break it: \
         {}",
        wrong.len(),
        wrong.join("; ")
    );
}

#[test]
fn no_committed_source_or_bytecode_file_is_claimed_as_a_container() {
    let root: PathBuf = repo_root();
    let mut claimed: Vec<String> = Vec::new();
    let mut inspected: usize = 0;
    for path in tracked_files(&root) {
        let relative: String = relative_to(&root, &path);
        if !FOREIGN_FAMILIES
            .iter()
            .any(|family: &ForeignFamily| relative.ends_with(family.suffix))
        {
            continue;
        }
        let Ok(meta): Result<std::fs::Metadata, std::io::Error> = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_INPUT_BYTES || meta.len() < MIN_INPUT_BYTES {
            continue;
        }
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(&path) else {
            continue;
        };
        let Some(family): Option<&ForeignFamily> = foreign_family(&relative, &bytes) else {
            continue;
        };
        inspected += 1;
        if let Some(kind) = detect_container_with_hint(&bytes, Some(path.as_path())) {
            claimed.push(format!(
                "`{relative}` is a {} file and the roster claims it as `{}`",
                family.family,
                kind.label()
            ));
        }
    }
    assert!(
        inspected >= FOREIGN_FAMILIES.len(),
        "only {inspected} committed file(s) match a family this check knows, which is too few for \
         it to have exercised the detector at all; the suffix table or the committed tree moved"
    );
    assert!(
        claimed.is_empty(),
        "the container roster claims {} committed file(s) whose extension and header both belong \
         to another family, so a published breadth figure counts a coincidence as a format: {}. \
         Tighten the detector rather than excluding the file",
        claimed.len(),
        claimed.join("; ")
    );
}
