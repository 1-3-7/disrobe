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
const SEGMENT_CALLS: [&str; 2] = [".join(\"", ".push(\""];
const MODULE_PATH_ATTRIBUTE: &str = "#[path = \"";
const MODULE_DECLARATION: &str = "mod ";
const MAX_MODULE_DEPTH: usize = 3;
const MIN_FRAGMENT_COMPONENTS: usize = 2;
const FIXTURE_ROOTS: [&str; 2] = ["corpus/", "fuzz/"];
const FIXTURE_SEGMENT: &str = "/tests/";
const DESCRIPTOR_DIR: &str = "evidence/descriptors/";
const AUDITED_DOC_ROOTS: [&str; 2] = ["docs/src/", "evidence/"];
const README: &str = "README.md";
const CITABLE_ROOTS: [&str; 2] = ["crates/", "benches/"];
const CITATION_PUNCTUATION: [char; 6] = ['`', '|', ',', '(', ')', ';'];

#[derive(Debug)]
struct Record {
    document: String,
    label: String,
    citation: String,
}

const UNTRACKED_DECLARATIONS: [&str; 2] = ["gitignored", "uncommitted"];
const PREREQUISITE_DECLARATIONS: [&str; 2] = ["CI does not provision", "CI does not run"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalReason {
    UntrackedInput,
    ExternalPrerequisite,
}

fn declared_reason(citation: &str) -> Option<LocalReason> {
    if UNTRACKED_DECLARATIONS
        .iter()
        .any(|word: &&str| citation.contains(word))
    {
        Some(LocalReason::UntrackedInput)
    } else if PREREQUISITE_DECLARATIONS
        .iter()
        .any(|phrase: &&str| citation.contains(phrase))
    {
        Some(LocalReason::ExternalPrerequisite)
    } else {
        None
    }
}

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

fn cited_workspace_files(citation: &str, tracked: &BTreeSet<String>) -> Vec<String> {
    citation
        .split_whitespace()
        .map(|token: &str| token.trim_matches(|c: char| CITATION_PUNCTUATION.contains(&c)))
        .filter(|token: &&str| {
            CITABLE_ROOTS
                .iter()
                .any(|root: &&str| token.starts_with(root))
        })
        .filter(|token: &&str| tracked.contains(*token))
        .map(str::to_owned)
        .collect()
}

fn cited_sources(
    citation: &str,
    index: &BTreeMap<String, Vec<String>>,
    tracked: &BTreeSet<String>,
) -> Vec<String> {
    let mut paths: Vec<String> = cited_test_paths(citation, index);
    paths.extend(cited_workspace_files(citation, tracked));
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
    let Some(rest): Option<&str> = gap.strip_prefix(')') else {
        return false;
    };
    let rest: &str = rest.strip_prefix(';').unwrap_or(rest);
    let receiver: &str = rest.trim();
    receiver.is_empty()
        || receiver
            .chars()
            .all(|c: char| c.is_alphanumeric() || c == '_')
}

fn next_segment_call(source: &str, from: usize) -> Option<(usize, usize)> {
    SEGMENT_CALLS
        .iter()
        .filter_map(|call: &&str| {
            source
                .get(from..)
                .and_then(|rest: &str| rest.find(call))
                .map(|relative: usize| (from + relative, call.len()))
        })
        .min_by_key(|(at, _): &(usize, usize)| *at)
}

fn segment_chains(source: &str) -> Vec<String> {
    let mut chains: Vec<String> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut after_previous: usize = 0;
    let mut index: usize = 0;
    while let Some((at, call_width)) = next_segment_call(source, index) {
        let start: usize = at + call_width;
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

fn parent_directory(rel: &str) -> String {
    rel.rsplit_once('/')
        .map_or_else(String::new, |(dir, _): (&str, &str)| format!("{dir}/"))
}

fn resolve_relative(directory: &str, fragment: &str) -> Option<String> {
    let mut components: Vec<&str> = directory
        .split('/')
        .filter(|part: &&str| !part.is_empty())
        .collect();
    for part in fragment.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            other => components.push(other),
        }
    }
    Some(components.join("/"))
}

fn declared_module_files(rel: &str, source: &str, tracked: &BTreeSet<String>) -> Vec<String> {
    let directory: String = parent_directory(rel);
    let mut candidates: Vec<String> = Vec::new();
    for literal in string_literals(source) {
        if source.contains(&format!("{MODULE_PATH_ATTRIBUTE}{literal}"))
            && has_extension(&literal, "rs")
        {
            candidates.extend(resolve_relative(&directory, &literal));
        }
    }
    for line in source.lines().map(str::trim) {
        let Some(after): Option<&str> = line.find(MODULE_DECLARATION).and_then(|at: usize| {
            line.get(at + MODULE_DECLARATION.len()..)
                .and_then(|rest: &str| rest.strip_suffix(';'))
        }) else {
            continue;
        };
        let name: &str = after.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        candidates.extend(resolve_relative(&directory, &format!("{name}.rs")));
        candidates.extend(resolve_relative(&directory, &format!("{name}/mod.rs")));
    }
    candidates.retain(|path: &String| tracked.contains(path));
    candidates.sort_unstable();
    candidates.dedup();
    candidates
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

fn citation_fragments(citation: &str) -> BTreeSet<String> {
    citation
        .split_whitespace()
        .map(|token: &str| token.trim_matches(|c: char| CITATION_PUNCTUATION.contains(&c)))
        .filter_map(normalize_fragment)
        .collect()
}

fn named_fragments(source: &str) -> BTreeSet<String> {
    segment_chains(source)
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

#[derive(Debug, Default)]
struct Audit {
    problems: Vec<String>,
    untracked_input: usize,
    external_prerequisite: usize,
}

fn named_fixtures(
    record: &Record,
    cited: &[String],
    families: &BTreeMap<String, Vec<String>>,
    sources: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut named: Vec<(String, String)> = Vec::new();
    for fragment in citation_fragments(&record.citation) {
        if is_fixture_path(&fragment) {
            named.push((record.document.clone(), fragment));
        }
    }
    for test in cited {
        let family: &[String] = families
            .get(test)
            .map_or_else(|| core::slice::from_ref(test), Vec::as_slice);
        for member in family {
            let Some(source): Option<&String> = sources.get(member) else {
                continue;
            };
            for fragment in named_fragments(source) {
                if is_fixture_path(&fragment) {
                    named.push((member.clone(), fragment));
                }
            }
        }
    }
    named
}

fn describe(finding: &Finding) -> String {
    format!(
        "{}: the row `{}` is tagged `[local]`, but its cited test {} reads `{}`, which carries {}. A tag that says a figure does not reproduce from a clean checkout understates the evidence when the input is committed: either drop the tag or stop tracking the fixture",
        finding.document,
        finding.label,
        finding.test,
        finding.named,
        finding.tracked.describe()
    )
}

fn audit(
    records: &[Record],
    sources: &BTreeMap<String, String>,
    families: &BTreeMap<String, Vec<String>>,
    index: &BTreeMap<String, Vec<String>>,
    tracked: &BTreeSet<String>,
) -> Audit {
    let mut audit: Audit = Audit::default();
    for record in records {
        let cited: Vec<String> = cited_sources(&record.citation, index, tracked);
        if cited.is_empty() {
            audit.problems.push(format!(
                "{}: the row `{}` is tagged `[local]` but names no test target and no git-tracked \
                 file under {CITABLE_ROOTS:?} that this check can open, so nothing grades the \
                 figure it publishes. A citation that resolves to nothing reads as verified while \
                 proving less than an uncited number: name the `--test` target, or the exact path \
                 of the test or harness that measures it",
                record.document, record.label
            ));
            continue;
        }
        let Some(reason): Option<LocalReason> = declared_reason(&record.citation) else {
            audit.problems.push(format!(
                "{}: the row `{}` is tagged `[local]` but states no reason it cannot run in CI. \
                 Say `gitignored` or `uncommitted` when the input is absent from the checkout, or \
                 one of {PREREQUISITE_DECLARATIONS:?} when the measurement needs something no \
                 workflow gives it; an undeclared reason cannot be checked against the repository",
                record.document, record.label
            ));
            continue;
        };
        if reason == LocalReason::ExternalPrerequisite {
            audit.external_prerequisite += 1;
            continue;
        }
        audit.untracked_input += 1;
        let named: Vec<(String, String)> = named_fixtures(record, &cited, families, sources);
        if named.is_empty() {
            audit.problems.push(format!(
                "{}: the row `{}` declares its input untracked, but neither the row nor {} names a \
                 fixture path this check can read, so nothing confirms the input is absent from \
                 the checkout. Name the absent input in the row itself",
                record.document,
                record.label,
                cited.join(", ")
            ));
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
                audit.problems.push(describe(&Finding {
                    document: record.document.clone(),
                    label: record.label.clone(),
                    test,
                    named: fragment,
                    tracked: fixture,
                }));
            }
        }
    }
    audit
}

fn read_source(root: &Path, rel: &str, sources: &mut BTreeMap<String, String>) -> Result<()> {
    if sources.contains_key(rel) {
        return Ok(());
    }
    let text: String = read_text_bounded(&root.join(rel), MAX_TEST_SOURCE_BYTES)
        .wrap_err_with(|| format!("reading the cited test {rel}"))?;
    sources.insert(rel.to_owned(), text);
    Ok(())
}

fn module_family(
    root: &Path,
    entry: &str,
    tracked: &BTreeSet<String>,
    sources: &mut BTreeMap<String, String>,
) -> Result<Vec<String>> {
    let mut family: Vec<String> = vec![entry.to_owned()];
    let mut frontier: Vec<String> = vec![entry.to_owned()];
    for _ in 0..MAX_MODULE_DEPTH {
        let mut next: Vec<String> = Vec::new();
        for rel in &frontier {
            read_source(root, rel, sources)?;
            let Some(source): Option<&String> = sources.get(rel) else {
                continue;
            };
            for member in declared_module_files(rel, source, tracked) {
                if !family.contains(&member) {
                    family.push(member.clone());
                    next.push(member);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    for rel in &family {
        read_source(root, rel, sources)?;
    }
    Ok(family)
}

#[derive(Debug, Default)]
struct CitedSources {
    text: BTreeMap<String, String>,
    families: BTreeMap<String, Vec<String>>,
}

fn read_cited_sources(
    root: &Path,
    records: &[Record],
    index: &BTreeMap<String, Vec<String>>,
    tracked: &BTreeSet<String>,
) -> Result<CitedSources> {
    let mut read: CitedSources = CitedSources::default();
    for record in records {
        for test in cited_sources(&record.citation, index, tracked) {
            if read.families.contains_key(&test) {
                continue;
            }
            let family: Vec<String> = module_family(root, &test, tracked, &mut read.text)?;
            read.families.insert(test, family);
        }
    }
    Ok(read)
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let tracked: BTreeSet<String> = tracked_paths(root)?;
    let index: BTreeMap<String, Vec<String>> = test_index(&tracked);
    let rows: Vec<Record> = records(root, &tracked)?;
    let read: CitedSources = read_cited_sources(root, &rows, &index, &tracked)?;
    let audit: Audit = audit(&rows, &read.text, &read.families, &index, &tracked);

    if audit.problems.is_empty() {
        println!(
            "xtask regen: local-tag reproducibility cross-check ok ({} row(s) tagged `[local]` with \
             no `[CI]` leg beside them, every one of them resolving to a test or harness this \
             checkout carries and stating why CI cannot run it: {} name an input absent from the \
             checkout, and this check confirmed each of those cited tests reads a fixture git does \
             not track; the other {} name something no workflow gives them)",
            rows.len(),
            audit.untracked_input,
            audit.external_prerequisite
        );
        Ok(())
    } else {
        bail!(
            "{} of the {} published row(s) tagged `[local]` do not stand up: a `[local]` row must \
             name a test or harness this checkout carries and say why CI cannot run it, and a row \
             that blames an absent input must cite a test that really reads one:\n  {}",
            audit.problems.len(),
            rows.len(),
            audit.problems.join("\n  ")
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
    fn segment_chain_merges_only_whitespace_separated_calls() {
        let source: &str = "root\n    .join(\"corpus\")\n    .join(\"mobile\")\n    .join(\"macho-mac\")\nlet other = dir.join(\"tmp\");\n";
        assert_eq!(
            segment_chains(source),
            vec!["corpus/mobile/macho-mac".to_owned(), "tmp".to_owned()]
        );
    }

    #[test]
    fn segment_chain_reads_a_statement_per_line_push_sequence() {
        let source: &str = "let mut path: PathBuf = manifest();\n    path.pop();\n    path.push(\"corpus\");\n    path.push(\"mobile\");\n    path.push(\"apk\");\n    path.push(\"inbox\");\n";
        assert_eq!(
            segment_chains(source),
            vec!["corpus/mobile/apk/inbox".to_owned()],
            "a fixture directory built one push statement at a time is the same path as a join chain"
        );
    }

    #[test]
    fn declared_module_files_follows_both_module_forms() {
        let tracked: BTreeSet<String> = tracked_set(&[
            "crates/p/tests/common/mod.rs",
            "crates/p/tests/support/fixture.rs",
            "crates/p/tests/other.rs",
        ]);
        let source: &str =
            "pub mod common;\n#[path = \"support/fixture.rs\"]\nmod fixture;\nuse std::fs;\n";
        assert_eq!(
            declared_module_files("crates/p/tests/real_apks.rs", source, &tracked),
            vec![
                "crates/p/tests/common/mod.rs".to_owned(),
                "crates/p/tests/support/fixture.rs".to_owned()
            ]
        );
    }

    #[test]
    fn citation_fragments_reads_a_backticked_path_out_of_a_markdown_row() {
        let row: &str = "| Native packers | samples uncommitted `[local]` | whole-image | `corpus/native/packers/petite/megafile_DirCmp.exe`, `crates/n/tests/petite_unpack.rs` |";
        let fragments: BTreeSet<String> = citation_fragments(row);
        assert!(
            fragments.contains("corpus/native/packers/petite/megafile_DirCmp.exe"),
            "a row must be able to name the absent input itself, got {fragments:?}"
        );
        assert!(
            !fragments
                .iter()
                .any(|f: &String| is_fixture_path(f) && has_extension(f, "rs")),
            "the cited test is never the fixture, got {fragments:?}"
        );
    }

    #[test]
    fn resolve_relative_walks_out_of_the_directory() {
        assert_eq!(
            resolve_relative("crates/p/tests/", "../fixtures/a.bin"),
            Some("crates/p/fixtures/a.bin".to_owned())
        );
        assert_eq!(resolve_relative("", "../escape.rs"), None);
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
    fn a_row_whose_cited_test_reads_only_tracked_fixtures_is_named() {
        let rows: Vec<Record> = vec![
            Record {
                document: README.to_owned(),
                label: "Swift symbol demangle".to_owned(),
                citation: "| Swift symbol demangle | 37 / 37 `[local]` | gitignored input | `crates/s/tests/real_swift_demangle.rs` |".to_owned(),
            },
            Record {
                document: README.to_owned(),
                label: "Android DEX, real APKs".to_owned(),
                citation: "| Android DEX, real APKs | 92.5% `[local]` | gitignored apks | `crates/j/tests/real_apks.rs` |".to_owned(),
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
                "path.push(\"corpus\");\n    path.push(\"mobile\");\n    path.push(\"apk\");\n    path.push(\"inbox\");"
                    .to_owned(),
            ),
        ]);
        let tracked: BTreeSet<String> = tracked_set(&[
            "corpus/mobile/macho-mac/SwiftHello.original",
            "crates/s/tests/real_swift_demangle.rs",
            "crates/j/tests/real_apks.rs",
        ]);

        let result: Audit = audit(&rows, &sources, &BTreeMap::new(), &index, &tracked);
        assert_eq!(
            result.untracked_input, 2,
            "declaring the input untracked no longer excuses a row from having its fixtures read"
        );
        assert_eq!(
            result.problems.len(),
            1,
            "only the row whose every named fixture is committed is reported, got {:?}",
            result.problems
        );
        assert!(result.problems[0].contains("Swift symbol demangle"));
        assert!(result.problems[0].contains("corpus/mobile/macho-mac"));
    }

    #[test]
    fn a_row_that_resolves_to_nothing_is_a_failure_rather_than_a_counted_pass() {
        let rows: Vec<Record> = vec![Record {
            document: README.to_owned(),
            label: "full stdlib".to_owned(),
            citation: "| full stdlib | 95.09% `[local]` | gitignored | a python harness |"
                .to_owned(),
        }];
        let result: Audit = audit(
            &rows,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &tracked_set(&["crates/p/tests/x.rs"]),
        );
        assert_eq!(result.problems.len(), 1);
        assert!(
            result.problems[0].contains("names no test target"),
            "an unresolvable citation must be reported as the failure it is, got {:?}",
            result.problems
        );
    }

    #[test]
    fn a_row_that_states_no_reason_it_skips_ci_is_a_failure() {
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
        let result: Audit = audit(
            &rows,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &index,
            &tracked_set(&["a/b.rs"]),
        );
        assert_eq!(result.problems.len(), 1);
        assert!(
            result.problems[0].contains("states no reason"),
            "got {:?}",
            result.problems
        );
    }

    #[test]
    fn a_row_blocked_on_an_uninstalled_tool_keeps_its_committed_fixture() {
        let rows: Vec<Record> = vec![Record {
            document: "evidence/results/EVIDENCE.md".to_owned(),
            label: "recon".to_owned(),
            citation: "| recon | 62.50% | [local] | `cargo test -p b published_x` in benches/head-to-head/src/frisk.rs (requires apkleaks 2.6.3 on PATH, which CI does not provision) |".to_owned(),
        }];
        let tracked: BTreeSet<String> = tracked_set(&[
            "benches/head-to-head/src/frisk.rs",
            "corpus/recon/apk/planted-secrets.apk",
        ]);
        let sources: BTreeMap<String, String> = BTreeMap::from([(
            "benches/head-to-head/src/frisk.rs".to_owned(),
            "root.join(\"corpus/recon/apk/planted-secrets.apk\")".to_owned(),
        )]);
        let result: Audit = audit(
            &rows,
            &sources,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &tracked,
        );
        assert!(
            result.problems.is_empty(),
            "a row held local by an absent tool may read a committed fixture, got {:?}",
            result.problems
        );
        assert_eq!(result.external_prerequisite, 1);
        assert_eq!(result.untracked_input, 0);
    }

    #[test]
    fn a_declared_untracked_row_whose_test_names_no_fixture_is_reported() {
        let rows: Vec<Record> = vec![Record {
            document: README.to_owned(),
            label: "Hermes".to_owned(),
            citation:
                "| Hermes | 122633 `[local]` | gitignored input | `crates/m/tests/real_hermes.rs` |"
                    .to_owned(),
        }];
        let index: BTreeMap<String, Vec<String>> = BTreeMap::from([(
            "real_hermes".to_owned(),
            vec!["crates/m/tests/real_hermes.rs".to_owned()],
        )]);
        let sources: BTreeMap<String, String> = BTreeMap::from([(
            "crates/m/tests/real_hermes.rs".to_owned(),
            "assert_eq!(functions, 122_633);".to_owned(),
        )]);
        let result: Audit = audit(
            &rows,
            &sources,
            &BTreeMap::new(),
            &index,
            &tracked_set(&["a/b.rs"]),
        );
        assert_eq!(result.problems.len(), 1);
        assert!(
            result.problems[0].contains("names a fixture path this check can read"),
            "got {:?}",
            result.problems
        );
    }

    #[test]
    fn cited_workspace_files_resolves_a_harness_that_is_not_a_cargo_test_target() {
        let tracked: BTreeSet<String> = tracked_set(&[
            "crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py",
            "benches/head-to-head/src/frisk.rs",
        ]);
        let citation: &str = "| x | y | `python crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py --lib DIR` |";
        assert_eq!(
            cited_workspace_files(citation, &tracked),
            vec![
                "crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py".to_owned()
            ]
        );
        assert!(
            cited_workspace_files("cargo test -p x crates/gone/tests/absent.rs", &tracked)
                .is_empty(),
            "a path this checkout does not track resolves to nothing"
        );
    }

    #[test]
    fn declared_reason_reads_both_vocabularies_and_prefers_the_checkable_one() {
        assert_eq!(
            declared_reason("the apks are gitignored"),
            Some(LocalReason::UntrackedInput)
        );
        assert_eq!(
            declared_reason("samples uncommitted"),
            Some(LocalReason::UntrackedInput)
        );
        assert_eq!(
            declared_reason("needs apkleaks, which CI does not provision"),
            Some(LocalReason::ExternalPrerequisite)
        );
        assert_eq!(
            declared_reason("gitignored input on a machine where CI does not provision the tool"),
            Some(LocalReason::UntrackedInput),
            "when a row states both, the reason this check can verify against git wins"
        );
        assert_eq!(declared_reason("measured locally"), None);
    }
}
