use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Result, WrapErr, bail};

use crate::evidence_tiers::{cited_test_names, row_metric};
use crate::fileio::read_text_bounded;

const MAX_DOC_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: u64 = 256 * 1024;
const MAX_TEST_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

const LOCAL_TAG: &str = "[local]";
const CI_TAG: &str = "[CI]";
const JOIN_CALL: &str = ".join(\"";
const MIN_FRAGMENT_COMPONENTS: usize = 2;
const FIXTURE_ROOTS: [&str; 2] = ["corpus/", "fuzz/"];
const FIXTURE_SEGMENT: &str = "/tests/";
const DESCRIPTOR_DIR: &str = "evidence/descriptors/";
const AUDITED_DOC_ROOTS: [&str; 2] = ["docs/src/", "evidence/"];
const README: &str = "README.md";

#[derive(Debug)]
struct Record {
    document: String,
    label: String,
    citation: String,
}

const UNTRACKED_DECLARATION: &str = "gitignored";

#[derive(Debug, PartialEq, Eq)]
enum TrackedFixture {
    File { path: String },
    Directory { witness: String, files: usize },
}

impl TrackedFixture {
    fn describe(&self) -> String {
        match self {
            Self::File { path } => format!("the git-tracked file `{path}`"),
            Self::Directory { witness, files } => {
                format!("{files} git-tracked file(s) under it, the first of them `{witness}`")
            }
        }
    }
}

#[derive(Debug)]
struct Finding {
    document: String,
    label: String,
    test: String,
    named: String,
    tracked: TrackedFixture,
}

fn tracked_paths(root: &Path) -> Result<BTreeSet<String>> {
    let output: std::process::Output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .wrap_err("running `git ls-files -z` to learn which fixtures this checkout tracks")?;
    if !output.status.success() {
        bail!(
            "`git ls-files -z` failed with {} in {}; without it this check cannot tell a tracked fixture from an absent one, and passing on that guess is how a stale `[local]` tag survives",
            output.status,
            root.display()
        );
    }
    let text: String = String::from_utf8(output.stdout)
        .wrap_err("`git ls-files -z` listed a path that is not UTF-8")?;
    let paths: BTreeSet<String> = text
        .split('\0')
        .filter(|path: &&str| !path.is_empty())
        .map(str::to_owned)
        .collect();
    if paths.is_empty() {
        bail!(
            "`git ls-files -z` listed no tracked file in {}, so every fixture would read as absent",
            root.display()
        );
    }
    Ok(paths)
}

fn has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|ext: &OsStr| ext.eq_ignore_ascii_case(extension))
}

fn test_index(tracked: &BTreeSet<String>) -> BTreeMap<String, Vec<String>> {
    let mut index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in tracked {
        let is_test_source: bool = path.starts_with("crates/")
            && path.contains(FIXTURE_SEGMENT)
            && has_extension(path, "rs");
        if !is_test_source {
            continue;
        }
        let Some(stem): Option<&str> = Path::new(path)
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
        else {
            continue;
        };
        index.entry(stem.to_owned()).or_default().push(path.clone());
    }
    index
}

fn cited_package(citation: &str) -> Option<String> {
    let tokens: Vec<&str> = citation.split_whitespace().collect();
    tokens
        .iter()
        .position(|token: &&str| *token == "-p" || *token == "--package")
        .and_then(|at: usize| tokens.get(at + 1))
        .map(|token: &&str| {
            token
                .trim_matches(|c: char| c == '`' || c == ',' || c == '|')
                .to_owned()
        })
}

fn cited_test_paths(citation: &str, index: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let scope: Option<String> = cited_package(citation).map(|pkg: String| format!("crates/{pkg}/"));
    let mut paths: Vec<String> = Vec::new();
    for name in cited_test_names(citation) {
        let Some(candidates): Option<&Vec<String>> = index.get(&name) else {
            continue;
        };
        let scoped: Vec<String> = scope.as_deref().map_or_else(Vec::new, |prefix: &str| {
            candidates
                .iter()
                .filter(|path: &&String| path.starts_with(prefix))
                .cloned()
                .collect()
        });
        let chosen: &Vec<String> = if scoped.is_empty() {
            candidates
        } else {
            &scoped
        };
        paths.extend(chosen.iter().cloned());
    }
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn string_literals(source: &str) -> Vec<String> {
    let bytes: &[u8] = source.as_bytes();
    let mut literals: Vec<String> = Vec::new();
    let mut index: usize = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let start: usize = index + 1;
        let mut probe: usize = start;
        while probe < bytes.len() && bytes[probe] != b'"' {
            probe += if bytes[probe] == b'\\' { 2 } else { 1 };
        }
        let end: usize = probe.min(bytes.len());
        if let Some(text) = source.get(start..end) {
            literals.push(text.to_owned());
        }
        index = end + 1;
    }
    literals
}

fn chain_continues(gap: &str) -> bool {
    gap.strip_prefix(')')
        .is_some_and(|rest: &str| rest.chars().all(char::is_whitespace))
}

fn join_chains(source: &str) -> Vec<String> {
    let mut chains: Vec<String> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut after_previous: usize = 0;
    let mut index: usize = 0;
    while let Some(relative) = source
        .get(index..)
        .and_then(|rest: &str| rest.find(JOIN_CALL))
    {
        let at: usize = index + relative;
        let start: usize = at + JOIN_CALL.len();
        let Some(rest): Option<&str> = source.get(start..) else {
            break;
        };
        let Some(width): Option<usize> = rest.find('"') else {
            break;
        };
        let Some(literal): Option<&str> = rest.get(..width) else {
            break;
        };
        let contiguous: bool = source.get(after_previous..at).is_some_and(chain_continues);
        if !contiguous && !current.is_empty() {
            chains.push(current.join("/"));
            current.clear();
        }
        current.push(literal.to_owned());
        after_previous = start + width + 1;
        index = after_previous;
    }
    if !current.is_empty() {
        chains.push(current.join("/"));
    }
    chains
}

fn normalize_fragment(raw: &str) -> Option<String> {
    let unusable: bool = raw
        .chars()
        .any(|c: char| c.is_whitespace() || c == '{' || c == '}');
    let components: Vec<&str> = raw
        .split(['/', '\\'])
        .filter(|part: &&str| !part.is_empty() && *part != "." && *part != "..")
        .collect();
    if unusable || components.len() < MIN_FRAGMENT_COMPONENTS {
        None
    } else {
        Some(components.join("/"))
    }
}

fn named_fragments(source: &str) -> BTreeSet<String> {
    join_chains(source)
        .into_iter()
        .chain(string_literals(source))
        .filter_map(|raw: String| normalize_fragment(&raw))
        .collect()
}

fn is_fixture_path(path: &str) -> bool {
    let under_fixture_root: bool = FIXTURE_ROOTS
        .iter()
        .any(|root: &&str| path.starts_with(root))
        || path.contains(FIXTURE_SEGMENT);
    under_fixture_root && !has_extension(path, "rs")
}

fn tracked_fixture(fragment: &str, tracked: &BTreeSet<String>) -> Option<TrackedFixture> {
    let as_suffix: String = format!("/{fragment}");
    let as_prefix: String = format!("{fragment}/");
    let as_interior: String = format!("/{fragment}/");
    let file: Option<&String> = tracked.iter().find(|path: &&String| {
        (path.as_str() == fragment || path.ends_with(&as_suffix)) && is_fixture_path(path)
    });
    if let Some(path) = file {
        return Some(TrackedFixture::File { path: path.clone() });
    }
    let inside: Vec<&String> = tracked
        .iter()
        .filter(|path: &&String| {
            (path.starts_with(&as_prefix) || path.contains(&as_interior)) && is_fixture_path(path)
        })
        .collect();
    inside
        .first()
        .map(|witness: &&String| TrackedFixture::Directory {
            witness: (*witness).clone(),
            files: inside.len(),
        })
}

fn markdown_records(document: &str, text: &str) -> Vec<Record> {
    text.lines()
        .map(str::trim)
        .filter(|line: &&str| {
            line.starts_with('|') && line.contains(LOCAL_TAG) && !line.contains(CI_TAG)
        })
        .map(|line: &str| Record {
            document: document.to_owned(),
            label: row_metric(line),
            citation: line.to_owned(),
        })
        .collect()
}

fn descriptor_record(document: &str, raw: &str) -> Result<Option<Record>> {
    let parsed: toml::Table = raw
        .parse::<toml::Table>()
        .wrap_err_with(|| format!("parsing {document}"))?;
    let ci: Option<bool> = parsed.get("ci").and_then(toml::Value::as_bool);
    if ci != Some(false) {
        return Ok(None);
    }
    let id: &str = parsed
        .get("id")
        .and_then(toml::Value::as_str)
        .unwrap_or(document);
    let reproduce: &str = parsed
        .get("oracle")
        .and_then(|oracle: &toml::Value| oracle.get("reproduce"))
        .and_then(toml::Value::as_str)
        .unwrap_or_default();
    Ok(Some(Record {
        document: document.to_owned(),
        label: id.to_owned(),
        citation: reproduce.to_owned(),
    }))
}

fn is_audited_markdown(path: &str) -> bool {
    let audited_root: bool = path == README
        || AUDITED_DOC_ROOTS
            .iter()
            .any(|root: &&str| path.starts_with(root));
    audited_root && has_extension(path, "md")
}

fn records(root: &Path, tracked: &BTreeSet<String>) -> Result<Vec<Record>> {
    let mut collected: Vec<Record> = Vec::new();
    for path in tracked {
        let absolute: PathBuf = root.join(path);
        if is_audited_markdown(path) {
            let text: String = read_text_bounded(&absolute, MAX_DOC_BYTES)
                .wrap_err_with(|| format!("reading {path}"))?;
            collected.extend(markdown_records(path, &text));
        } else if path.starts_with(DESCRIPTOR_DIR) && has_extension(path, "toml") {
            let raw: String = read_text_bounded(&absolute, MAX_DESCRIPTOR_BYTES)
                .wrap_err_with(|| format!("reading {path}"))?;
            collected.extend(descriptor_record(path, &raw)?);
        }
    }
    Ok(collected)
}

fn contradictions(
    records: &[Record],
    sources: &BTreeMap<String, String>,
    index: &BTreeMap<String, Vec<String>>,
    tracked: &BTreeSet<String>,
) -> (Vec<Finding>, usize) {
    let mut found: Vec<Finding> = Vec::new();
    let mut unresolved: usize = 0;
    for record in records {
        let cited: Vec<String> = cited_test_paths(&record.citation, index);
        if cited.is_empty() {
            unresolved += 1;
            continue;
        }
        if record.citation.contains(UNTRACKED_DECLARATION) {
            continue;
        }
        let mut named: Vec<(String, String)> = Vec::new();
        for test in &cited {
            let Some(source): Option<&String> = sources.get(test) else {
                continue;
            };
            for fragment in named_fragments(source) {
                if is_fixture_path(&fragment) {
                    named.push((test.clone(), fragment));
                }
            }
        }
        if named.is_empty() {
            continue;
        }
        let reads_untracked: bool = named
            .iter()
            .any(|(_, fragment): &(String, String)| tracked_fixture(fragment, tracked).is_none());
        if reads_untracked {
            continue;
        }
        for (test, fragment) in named {
            if let Some(fixture) = tracked_fixture(&fragment, tracked) {
                found.push(Finding {
                    document: record.document.clone(),
                    label: record.label.clone(),
                    test,
                    named: fragment,
                    tracked: fixture,
                });
            }
        }
    }
    (found, unresolved)
}

fn read_cited_sources(
    root: &Path,
    records: &[Record],
    index: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<String, String>> {
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for record in records {
        for test in cited_test_paths(&record.citation, index) {
            if sources.contains_key(&test) {
                continue;
            }
            let text: String = read_text_bounded(&root.join(&test), MAX_TEST_SOURCE_BYTES)
                .wrap_err_with(|| format!("reading the cited test {test}"))?;
            sources.insert(test, text);
        }
    }
    Ok(sources)
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let tracked: BTreeSet<String> = tracked_paths(root)?;
    let index: BTreeMap<String, Vec<String>> = test_index(&tracked);
    let rows: Vec<Record> = records(root, &tracked)?;
    let sources: BTreeMap<String, String> = read_cited_sources(root, &rows, &index)?;
    let (found, unresolved): (Vec<Finding>, usize) =
        contradictions(&rows, &sources, &index, &tracked);

    if found.is_empty() {
        println!(
            "xtask regen: local-tag reproducibility cross-check ok ({} row(s) tagged `[local]` with no `[CI]` leg beside them; {} cite a test whose named fixture paths are all untracked, and {} cite no test target this check can resolve)",
            rows.len(),
            rows.len().saturating_sub(unresolved),
            unresolved
        );
        Ok(())
    } else {
        let listed: Vec<String> = found
            .iter()
            .map(|finding: &Finding| {
                format!(
                    "{}: the row `{}` is tagged `[local]`, but its cited test {} reads `{}`, which carries {}. A tag that says a figure does not reproduce from a clean checkout understates the evidence when the input is committed: either drop the tag or stop tracking the fixture",
                    finding.document,
                    finding.label,
                    finding.test,
                    finding.named,
                    finding.tracked.describe()
                )
            })
            .collect();
        bail!(
            "{} published row(s) tagged `[local]` cite a test that reads a git-tracked fixture ({} row(s) inspected, {} cite no resolvable test target):\n  {}",
            found.len(),
            rows.len(),
            unresolved,
            listed.join("\n  ")
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tracked_set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p: &&str| (*p).to_owned()).collect()
    }

    #[test]
    fn join_chain_merges_only_whitespace_separated_calls() {
        let source: &str = "root\n    .join(\"corpus\")\n    .join(\"mobile\")\n    .join(\"macho-mac\")\nlet other = dir.join(\"tmp\");\n";
        assert_eq!(
            join_chains(source),
            vec!["corpus/mobile/macho-mac".to_owned(), "tmp".to_owned()]
        );
    }

    #[test]
    fn string_literals_reads_each_quoted_run() {
        let source: &str = "let a = \"corpus/python/pyarmor\";\nlet b = \"escaped \\\" quote\";\n";
        let literals: Vec<String> = string_literals(source);
        assert!(
            literals.contains(&"corpus/python/pyarmor".to_owned()),
            "a slashed literal must be seen, got {literals:?}"
        );
    }

    #[test]
    fn normalize_fragment_rejects_prose_and_single_components() {
        assert_eq!(
            normalize_fragment("skip: macho-mac/SwiftHello.original absent"),
            None
        );
        assert_eq!(normalize_fragment("recovered {n}/{d} fixtures"), None);
        assert_eq!(normalize_fragment("corpus"), None);
        assert_eq!(
            normalize_fragment("../../corpus/mobile/macho-mac"),
            Some("corpus/mobile/macho-mac".to_owned())
        );
        assert_eq!(
            normalize_fragment("corpus\\python\\pyarmor"),
            Some("corpus/python/pyarmor".to_owned())
        );
    }

    #[test]
    fn tracked_fixture_reports_a_file_a_directory_and_nothing_for_tooling() {
        let tracked: BTreeSet<String> = tracked_set(&[
            "corpus/mobile/macho-mac/SwiftHello.original",
            "corpus/python/pyarmor/v8/wrapper.py",
            "corpus/python/pyarmor/v9/wrapper.py",
            "xtask/data/recovery.json",
            "crates/pass/tests/fixture_helper.rs",
        ]);
        assert_eq!(
            tracked_fixture("corpus/mobile/macho-mac/SwiftHello.original", &tracked),
            Some(TrackedFixture::File {
                path: "corpus/mobile/macho-mac/SwiftHello.original".to_owned()
            })
        );
        assert_eq!(
            tracked_fixture("corpus/python/pyarmor", &tracked),
            Some(TrackedFixture::Directory {
                witness: "corpus/python/pyarmor/v8/wrapper.py".to_owned(),
                files: 2
            })
        );
        assert_eq!(
            tracked_fixture("xtask/data/recovery.json", &tracked),
            None,
            "the published data file this check reads is not a fixture the row measures"
        );
        assert_eq!(
            tracked_fixture("pass/tests/fixture_helper.rs", &tracked),
            None,
            "a Rust source file is never the fixture"
        );
    }

    #[test]
    fn markdown_records_skips_a_row_that_also_carries_a_ci_leg() {
        let text: &str = "| Swift demangle | 37 / 37 `[local]` | symtab | `crates/s/tests/real_swift_demangle.rs` |\n| Hermes | 8 of 8 `[CI]`; bundle `[local]` | op-coverage | `crates/m/tests/real_hermes_sample.rs` |\n| Plain | 5 of 5 | x | y |\n";
        let rows: Vec<Record> = markdown_records("README.md", text);
        assert_eq!(rows.len(), 1, "only the local-only row is a record");
        assert_eq!(rows[0].label, "Swift demangle");
    }

    #[test]
    fn descriptor_record_is_built_only_for_a_local_descriptor() -> core::result::Result<(), String>
    {
        let local: &str = "id = \"swift-demangle\"\nci = false\n\n[oracle]\nreproduce = \"cargo test -p disrobe-pass-swift-objc --test real_swift_demangle\"\n";
        let attested: &str = "id = \"go-typemeta\"\nci = true\n\n[oracle]\nreproduce = \"cargo test -p disrobe-pass-go --test go_typemeta\"\n";
        let record: Option<Record> =
            descriptor_record("evidence/descriptors/swift-demangle.toml", local)
                .map_err(|e: eyre::Error| e.to_string())?;
        let record: Record =
            record.ok_or_else(|| "a ci=false descriptor is a record".to_owned())?;
        assert_eq!(record.label, "swift-demangle");
        assert!(
            descriptor_record("evidence/descriptors/go-typemeta.toml", attested)
                .map_err(|e: eyre::Error| e.to_string())?
                .is_none(),
            "a CI-attested descriptor claims nothing about a local-only fixture"
        );
        Ok(())
    }

    #[test]
    fn cited_test_paths_prefers_the_package_the_citation_names() {
        let index: BTreeMap<String, Vec<String>> = BTreeMap::from([(
            "corpus".to_owned(),
            vec![
                "crates/disrobe-pass-go/tests/corpus.rs".to_owned(),
                "crates/disrobe-pass-jvm/tests/corpus.rs".to_owned(),
            ],
        )]);
        assert_eq!(
            cited_test_paths("cargo test -p disrobe-pass-jvm --test corpus", &index),
            vec!["crates/disrobe-pass-jvm/tests/corpus.rs".to_owned()]
        );
        assert_eq!(
            cited_test_paths("cargo test --test corpus", &index).len(),
            2,
            "with no package named, an ambiguous stem inspects every candidate rather than guessing"
        );
    }

    #[test]
    fn contradictions_name_the_tracked_fixture_and_count_unresolvable_rows() {
        let rows: Vec<Record> = vec![
            Record {
                document: README.to_owned(),
                label: "Swift symbol demangle".to_owned(),
                citation: "| Swift symbol demangle | 37 / 37 `[local]` | `crates/s/tests/real_swift_demangle.rs` |".to_owned(),
            },
            Record {
                document: README.to_owned(),
                label: "Android DEX, real APKs".to_owned(),
                citation: "| Android DEX, real APKs | 92.5% `[local]` | `crates/j/tests/real_apks.rs` |".to_owned(),
            },
            Record {
                document: README.to_owned(),
                label: "full stdlib".to_owned(),
                citation: "| full stdlib | 95.09% `[local]` | a python harness |".to_owned(),
            },
        ];
        let index: BTreeMap<String, Vec<String>> = BTreeMap::from([
            (
                "real_swift_demangle".to_owned(),
                vec!["crates/s/tests/real_swift_demangle.rs".to_owned()],
            ),
            (
                "real_apks".to_owned(),
                vec!["crates/j/tests/real_apks.rs".to_owned()],
            ),
        ]);
        let sources: BTreeMap<String, String> = BTreeMap::from([
            (
                "crates/s/tests/real_swift_demangle.rs".to_owned(),
                "root.join(\"corpus\").join(\"mobile\").join(\"macho-mac\")".to_owned(),
            ),
            (
                "crates/j/tests/real_apks.rs".to_owned(),
                "corpus(&[\"mobile\", \"apk\", \"inbox\", \"transmissionic.apk\"])".to_owned(),
            ),
        ]);
        let tracked: BTreeSet<String> =
            tracked_set(&["corpus/mobile/macho-mac/SwiftHello.original"]);

        let (found, unresolved): (Vec<Finding>, usize) =
            contradictions(&rows, &sources, &index, &tracked);
        assert_eq!(unresolved, 1, "the python-harness row resolves to no test");
        assert_eq!(found.len(), 1, "only the tracked-fixture row contradicts");
        assert_eq!(found[0].label, "Swift symbol demangle");
        assert_eq!(found[0].named, "corpus/mobile/macho-mac");
        assert_eq!(
            found[0].tracked,
            TrackedFixture::Directory {
                witness: "corpus/mobile/macho-mac/SwiftHello.original".to_owned(),
                files: 1
            }
        );
    }

    #[test]
    fn a_row_whose_fixture_stops_being_tracked_stops_contradicting() {
        let rows: Vec<Record> = vec![Record {
            document: README.to_owned(),
            label: "PyArmor".to_owned(),
            citation: "| PyArmor | 72 / 72 `[local]` | `crates/p/tests/static_unpack_corpus.rs` |"
                .to_owned(),
        }];
        let index: BTreeMap<String, Vec<String>> = BTreeMap::from([(
            "static_unpack_corpus".to_owned(),
            vec!["crates/p/tests/static_unpack_corpus.rs".to_owned()],
        )]);
        let sources: BTreeMap<String, String> = BTreeMap::from([(
            "crates/p/tests/static_unpack_corpus.rs".to_owned(),
            "root.join(\"corpus/python/pyarmor\")".to_owned(),
        )]);

        let with_corpus: BTreeSet<String> = tracked_set(&["corpus/python/pyarmor/v8/wrapper.py"]);
        let (flagged, _): (Vec<Finding>, usize) =
            contradictions(&rows, &sources, &index, &with_corpus);
        assert_eq!(flagged.len(), 1);

        let without_corpus: BTreeSet<String> = tracked_set(&["crates/p/tests/x.rs"]);
        let (clean, _): (Vec<Finding>, usize) =
            contradictions(&rows, &sources, &index, &without_corpus);
        assert!(
            clean.is_empty(),
            "an untracked corpus is what a `[local]` tag is for"
        );
    }
}
