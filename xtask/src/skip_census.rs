use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const RETURN_WINDOW: usize = 5;
const MIN_SCANNED_FILES: usize = 400;
const MIN_SCANNED_CRATES: usize = 20;

const SKIP_CEILING: &[(&str, usize)] = &[
    ("disrobe-binfmt", 3),
    ("disrobe-cli", 57),
    ("disrobe-core", 7),
    ("disrobe-irsummary", 1),
    ("disrobe-lift-x86", 2),
    ("disrobe-mba", 3),
    ("disrobe-nir-lift", 9),
    ("disrobe-pass-dotnet", 4),
    ("disrobe-pass-go", 2),
    ("disrobe-pass-js-deob", 60),
    ("disrobe-pass-jvm", 69),
    ("disrobe-pass-lua", 22),
    ("disrobe-pass-mobile", 5),
    ("disrobe-pass-native", 295),
    ("disrobe-pass-nativelang", 2),
    ("disrobe-pass-nuitka", 32),
    ("disrobe-pass-php", 6),
    ("disrobe-pass-py-decompile", 7),
    ("disrobe-pass-py-deob", 12),
    ("disrobe-pass-py-disasm", 1),
    ("disrobe-pass-pyarmor", 37),
    ("disrobe-pass-pyfreeze", 16),
    ("disrobe-pass-ruby", 12),
    ("disrobe-pass-shell", 8),
    ("disrobe-pass-swift-objc", 1),
    ("disrobe-pass-wasm-deob", 11),
    ("disrobe-pyarmor-cextract", 5),
    ("disrobe-semdiff", 2),
    ("disrobe-typerec", 3),
];

const SILENT_CEILING: &[(&str, usize)] = &[
    ("disrobe-cli", 20),
    ("disrobe-core", 1),
    ("disrobe-lift-x86", 4),
    ("disrobe-mba", 1),
    ("disrobe-nir-lift", 3),
    ("disrobe-pass-as3", 16),
    ("disrobe-pass-beam", 11),
    ("disrobe-pass-go", 26),
    ("disrobe-pass-js-deob", 72),
    ("disrobe-pass-jvm", 3),
    ("disrobe-pass-mobile", 5),
    ("disrobe-pass-native", 61),
    ("disrobe-pass-nuitka", 1),
    ("disrobe-pass-php", 56),
    ("disrobe-pass-py-decompile", 14),
    ("disrobe-pass-py-deob", 2),
    ("disrobe-pass-pyarmor", 5),
    ("disrobe-pass-pyfreeze", 3),
    ("disrobe-pass-pyinstaller", 3),
    ("disrobe-pass-ruby", 3),
    ("disrobe-pass-scriptlang", 2),
    ("disrobe-pass-shell", 6),
    ("disrobe-pass-swift-objc", 35),
    ("disrobe-pass-wasm-deob", 8),
    ("disrobe-pass-webview", 1),
    ("disrobe-semdiff", 6),
    ("disrobe-sleigh", 35),
    ("disrobe-typerec", 3),
    ("disrobe-vulnmatch", 40),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkipSite {
    pub(crate) file: String,
    pub(crate) line: usize,
    pub(crate) in_test: bool,
}

fn string_literal_mentions_skip(line: &str) -> bool {
    let Some(open) = line.find('"') else {
        return false;
    };
    let rest: &str = &line[open + 1..];
    let end: usize = rest.find('"').unwrap_or(rest.len());
    rest[..end].to_ascii_lowercase().contains("skip")
}

fn opens_a_print(line: &str) -> bool {
    let trimmed: &str = line.trim_start();
    trimmed.starts_with("println!(")
        || trimmed.starts_with("eprintln!(")
        || trimmed.contains(" println!(")
        || trimmed.contains(" eprintln!(")
}

fn is_bare_return(line: &str) -> bool {
    matches!(line.trim(), "return;" | "return ;")
}

fn opens_a_let_else(line: &str) -> bool {
    let trimmed: &str = line.trim_start();
    trimmed.starts_with("let ") && trimmed.contains(" else {")
}

fn closes_a_block(line: &str) -> bool {
    matches!(line.trim(), "}" | "};")
}

fn else_body_is_a_bare_return(lines: &[&str], index: usize) -> bool {
    let Some(current) = lines.get(index) else {
        return false;
    };
    let Some((_, tail)) = current.trim_end().split_once(" else {") else {
        return false;
    };
    let tail: &str = tail.trim();
    if !tail.is_empty() {
        return matches!(tail, "return; }" | "return; };" | "return }" | "return };");
    }
    lines
        .get(index.saturating_add(1))
        .is_some_and(|entry: &&str| is_bare_return(entry))
        && lines
            .get(index.saturating_add(2))
            .is_some_and(|entry: &&str| closes_a_block(entry))
}

pub(crate) fn silent_sites_in_source(relative: &str, source: &str) -> Vec<SkipSite> {
    let lines: Vec<&str> = source.lines().collect();
    let inside: Vec<bool> = lines_inside_tests(&lines);
    let mut found: Vec<SkipSite> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !opens_a_let_else(line) || !else_body_is_a_bare_return(&lines, index) {
            continue;
        }
        found.push(SkipSite {
            file: relative.to_owned(),
            line: index.saturating_add(1),
            in_test: inside.get(index).copied().unwrap_or(false),
        });
    }
    found
}

fn test_attribute(line: &str) -> bool {
    let trimmed: &str = line.trim_start();
    trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test")
}

fn opens_a_function(line: &str) -> bool {
    let trimmed: &str = line.trim_start();
    trimmed.starts_with("fn ")
        || trimmed.starts_with("pub fn ")
        || trimmed.starts_with("async fn ")
        || trimmed.starts_with("pub async fn ")
}

fn lines_inside_tests(lines: &[&str]) -> Vec<bool> {
    let mut inside: Vec<bool> = vec![false; lines.len()];
    let mut index: usize = 0;
    while index < lines.len() {
        if !test_attribute(lines[index]) {
            index = index.saturating_add(1);
            continue;
        }
        let mut start: usize = index.saturating_add(1);
        while start < lines.len() && !opens_a_function(lines[start]) {
            start = start.saturating_add(1);
        }
        if start >= lines.len() {
            break;
        }
        let mut depth: isize = 0;
        let mut opened: bool = false;
        let mut cursor: usize = start;
        while cursor < lines.len() {
            let line: &str = lines[cursor];
            depth += isize::try_from(line.matches('{').count()).unwrap_or(0);
            depth -= isize::try_from(line.matches('}').count()).unwrap_or(0);
            if line.contains('{') {
                opened = true;
            }
            inside[cursor] = true;
            if opened && depth <= 0 {
                break;
            }
            cursor = cursor.saturating_add(1);
        }
        index = cursor.saturating_add(1);
    }
    inside
}

fn declares_a_skip_helper(lines: &[&str], index: usize) -> Option<String> {
    let trimmed: &str = lines[index].trim_start();
    if !opens_a_function(trimmed) {
        return None;
    }
    let open: usize = trimmed.find('(')?;
    let head: &str = trimmed[..open].trim_end();
    let name: &str = head.rsplit(' ').next()?;
    if name.is_empty() {
        return None;
    }
    let mut depth: isize = 0;
    let mut opened: bool = false;
    let mut prints_a_skip: bool = false;
    let mut cursor: usize = index;
    while cursor < lines.len() {
        let line: &str = lines[cursor];
        depth += isize::try_from(line.matches('{').count()).unwrap_or(0);
        depth -= isize::try_from(line.matches('}').count()).unwrap_or(0);
        if line.contains('{') {
            opened = true;
        }
        if opens_a_print(line) && string_literal_mentions_skip(line) {
            prints_a_skip = true;
        }
        if opened && depth <= 0 {
            break;
        }
        cursor = cursor.saturating_add(1);
    }
    prints_a_skip.then(|| name.to_owned())
}

pub(crate) fn skip_helper_names(source: &str) -> std::collections::BTreeSet<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for index in 0..lines.len() {
        if let Some(name) = declares_a_skip_helper(&lines, index) {
            names.insert(name);
        }
    }
    names
}

fn calls_a_skip_helper(line: &str, helpers: &std::collections::BTreeSet<String>) -> bool {
    helpers.iter().any(|name: &String| {
        line.match_indices(name.as_str())
            .any(|(at, _): (usize, &str)| {
                let after: bool = line[at.saturating_add(name.len())..].starts_with('(');
                let before: bool = at == 0
                    || !line[..at]
                        .chars()
                        .next_back()
                        .is_some_and(|c: char| c.is_alphanumeric() || c == '_');
                after && before
            })
    })
}

pub(crate) fn sites_in_source_with_helpers(
    relative: &str,
    source: &str,
    helpers: &std::collections::BTreeSet<String>,
) -> Vec<SkipSite> {
    let lines: Vec<&str> = source.lines().collect();
    let inside: Vec<bool> = lines_inside_tests(&lines);
    let mut found: Vec<SkipSite> = Vec::new();
    let mut last_site: Option<usize> = None;
    for (index, line) in lines.iter().enumerate() {
        let printed: bool = opens_a_print(line) && string_literal_mentions_skip(line);
        let delegated: bool = !helpers.is_empty()
            && inside.get(index).copied().unwrap_or(false)
            && calls_a_skip_helper(line, helpers);
        if !printed && !delegated {
            continue;
        }
        if last_site.is_some_and(|previous: usize| index.saturating_sub(previous) <= RETURN_WINDOW)
        {
            continue;
        }
        last_site = Some(index);
        let stop: usize = index
            .saturating_add(RETURN_WINDOW)
            .min(lines.len().saturating_sub(1));
        let returns: bool = lines
            .get(index..=stop)
            .is_some_and(|window: &[&str]| window.iter().any(|entry: &&str| is_bare_return(entry)));
        if !returns {
            continue;
        }
        found.push(SkipSite {
            file: relative.to_owned(),
            line: index.saturating_add(1),
            in_test: inside.get(index).copied().unwrap_or(false),
        });
    }
    found
}

#[cfg(test)]
pub(crate) fn sites_in_source(relative: &str, source: &str) -> Vec<SkipSite> {
    sites_in_source_with_helpers(relative, source, &std::collections::BTreeSet::new())
}

fn crate_of(relative: &str) -> Option<&str> {
    let mut parts: std::str::Split<'_, char> = relative.split('/');
    (parts.next()? == "crates").then(|| parts.next())?
}

struct Census {
    printed: BTreeMap<String, Vec<SkipSite>>,
    silent: BTreeMap<String, Vec<SkipSite>>,
    scanned: usize,
}

fn scan(root: &Path) -> Result<Census> {
    let crates_dir: PathBuf = root.join("crates");
    let mut per_crate: BTreeMap<String, Vec<SkipSite>> = BTreeMap::new();
    let mut silent: BTreeMap<String, Vec<SkipSite>> = BTreeMap::new();
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut scanned: usize = 0;
    for entry in walkdir::WalkDir::new(&crates_dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path: &Path = entry.path();
        if !path.is_file()
            || path
                .extension()
                .is_none_or(|ext: &std::ffi::OsStr| ext != "rs")
        {
            continue;
        }
        let relative: String = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if !relative.contains("/tests/") && !relative.ends_with("/tests.rs") {
            continue;
        }
        let length: u64 = entry
            .metadata()
            .map_or(0, |meta: std::fs::Metadata| meta.len());
        if length > MAX_SOURCE_BYTES {
            continue;
        }
        let source: String =
            std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
        scanned = scanned.saturating_add(1);
        if crate_of(&relative).is_some() {
            sources.push((relative, source));
        }
    }

    let mut helpers: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (_, source) in &sources {
        helpers.extend(skip_helper_names(source));
    }

    for (relative, source) in &sources {
        let Some(owner) = crate_of(relative) else {
            continue;
        };
        let sites: Vec<SkipSite> = sites_in_source_with_helpers(relative, source, &helpers);
        if !sites.is_empty() {
            per_crate.entry(owner.to_owned()).or_default().extend(sites);
        }
        let quiet: Vec<SkipSite> = silent_sites_in_source(relative, source);
        if !quiet.is_empty() {
            silent.entry(owner.to_owned()).or_default().extend(quiet);
        }
    }
    Ok(Census {
        printed: per_crate,
        silent,
        scanned,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Printed,
    Silent,
}

impl Shape {
    const fn ceiling(self) -> &'static [(&'static str, usize)] {
        match self {
            Self::Printed => SKIP_CEILING,
            Self::Silent => SILENT_CEILING,
        }
    }

    const fn table(self) -> &'static str {
        match self {
            Self::Printed => "SKIP_CEILING",
            Self::Silent => "SILENT_CEILING",
        }
    }

    const fn shape(self) -> &'static str {
        match self {
            Self::Printed => "print a skip line and return",
            Self::Silent => "abandon a fallible binding with a bare return",
        }
    }

    const fn consequence(self) -> &'static str {
        match self {
            Self::Printed => {
                "A test that returns before its assertions is counted as passed and proves \
                 nothing. Either give the missing reference a named hard failure, or declare the \
                 reference optional and stop citing that test as evidence."
            }
            Self::Silent => {
                "This ceiling counts a shape, not a proven defect: a site whose guard already \
                 panics or prints a named declaration upstream is correct as it stands. What the \
                 ceiling enforces is that no new one appears without a deliberate edit here, \
                 because `let ... else { return; }` inside a #[test] passes while emitting no line \
                 at all. Before raising it, show the site cannot be reached without either a \
                 failure or a counted declaration."
            }
        }
    }
}

fn enforce(
    shape: Shape,
    per_crate: &BTreeMap<String, Vec<SkipSite>>,
    issues: &mut Vec<String>,
) -> usize {
    let declared: BTreeMap<&str, usize> = shape.ceiling().iter().copied().collect();
    let mut total_in_test: usize = 0;
    for (owner, sites) in per_crate {
        let in_test: usize = sites.iter().filter(|site: &&SkipSite| site.in_test).count();
        total_in_test = total_in_test.saturating_add(in_test);
        let ceiling: usize = declared.get(owner.as_str()).copied().unwrap_or(0);
        if in_test > ceiling {
            let first: String = sites
                .iter()
                .filter(|site: &&SkipSite| site.in_test)
                .take(3)
                .map(|site: &SkipSite| format!("{}:{}", site.file, site.line))
                .collect::<Vec<String>>()
                .join(", ");
            issues.push(format!(
                "{owner} carries {in_test} test(s) that {}, above its declared ceiling of \
                 {ceiling}. {} First site(s): {first}",
                shape.shape(),
                shape.consequence(),
            ));
        }
        if in_test < ceiling {
            issues.push(format!(
                "{owner} carries {in_test} test(s) that {}, below its declared ceiling of \
                 {ceiling}. Lower the {} entry in xtask/src/skip_census.rs in the same commit, so \
                 the number can only ratchet down",
                shape.shape(),
                shape.table(),
            ));
        }
    }
    for (owner, ceiling) in shape.ceiling() {
        if !per_crate.contains_key(*owner) && *ceiling > 0 {
            issues.push(format!(
                "{} declares {ceiling} for {owner}, which now carries none. Remove the entry in \
                 the same commit",
                shape.table(),
            ));
        }
    }
    total_in_test
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let census: Census = scan(root)?;

    if census.scanned < MIN_SCANNED_FILES {
        bail!(
            "xtask skip-census scanned only {} test source file(s), below the floor of \
             {MIN_SCANNED_FILES}. The scan itself is broken or the tree moved; a census that reads \
             nothing would report a clean sheet it did not earn",
            census.scanned
        );
    }

    let mut issues: Vec<String> = Vec::new();
    let printed: usize = enforce(Shape::Printed, &census.printed, &mut issues);
    let silent: usize = enforce(Shape::Silent, &census.silent, &mut issues);

    if !issues.is_empty() {
        bail!(
            "xtask skip-census: {} finding(s); {printed} test(s) print a skip line and return, \
             {silent} carry a bare-return let-else:\n  {}",
            issues.len(),
            issues.join("\n  ")
        );
    }

    if census.printed.len() < MIN_SCANNED_CRATES && !SKIP_CEILING.is_empty() {
        bail!(
            "xtask skip-census matched only {} crate(s), below the floor of {MIN_SCANNED_CRATES}",
            census.printed.len()
        );
    }

    println!(
        "xtask skip-census: {} test source file(s) scanned, {printed} skip-and-return test(s) \
         across {} crate(s) and {silent} bare-return let-else site(s) across {} crate(s), each at \
         or below its declared ceiling in xtask/src/skip_census.rs; both ceilings ratchet down \
         only, and the second counts a shape whose sites still need a guard proven upstream",
        census.scanned,
        census.printed.len(),
        census.silent.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_skip_print_followed_by_a_bare_return_inside_a_test_is_a_site() {
        let source: &str = "#[test]\nfn probe() {\n    if absent() {\n        \
                            eprintln!(\"skip: corpus absent\");\n        return;\n    }\n    \
                            assert!(false);\n}\n";
        let sites: Vec<SkipSite> = sites_in_source("crates/x/tests/a.rs", source);
        assert_eq!(
            sites.len(),
            1,
            "the skip-and-return must be found: {sites:?}"
        );
        assert!(sites[0].in_test, "it sits inside a #[test]: {sites:?}");
    }

    #[test]
    fn a_skip_print_without_a_return_is_not_a_site() {
        let source: &str = "#[test]\nfn probe() {\n    eprintln!(\"skip: nothing\");\n    \
                            assert!(true);\n}\n";
        assert!(
            sites_in_source("crates/x/tests/a.rs", source).is_empty(),
            "a diagnostic print that still reaches its assertions is not a skip-and-pass"
        );
    }

    #[test]
    fn a_print_whose_literal_does_not_say_skip_is_not_a_site() {
        let source: &str = "#[test]\nfn probe() {\n    println!(\"reading corpus\");\n    \
                            return;\n}\n";
        assert!(
            sites_in_source("crates/x/tests/a.rs", source).is_empty(),
            "the word skip must come from the printed literal, not from anywhere on the line"
        );
    }

    #[test]
    fn a_skip_and_return_outside_a_test_is_recorded_but_not_counted_against_the_ceiling() {
        let source: &str = "fn helper() {\n    eprintln!(\"skip: corpus absent\");\n    \
                            return;\n}\n";
        let sites: Vec<SkipSite> = sites_in_source("crates/x/tests/a.rs", source);
        assert_eq!(sites.len(), 1, "the site is still recorded: {sites:?}");
        assert!(
            !sites[0].in_test,
            "a helper is not itself a passing test, so it must not inflate the ceiling: {sites:?}"
        );
    }

    #[test]
    fn a_return_beyond_the_window_does_not_pair_with_the_skip() {
        let filler: String = "    let value: usize = 1;\n".repeat(RETURN_WINDOW + 2);
        let source: String = format!(
            "#[test]\nfn probe() {{\n    eprintln!(\"skip: corpus absent\");\n{filler}    return;\n}}\n"
        );
        assert!(
            sites_in_source("crates/x/tests/a.rs", &source).is_empty(),
            "a return far below an unrelated print must not be paired with it"
        );
    }

    #[test]
    fn a_let_else_whose_body_is_only_a_bare_return_is_a_silent_site() {
        let source: &str = "#[test]\nfn probe() {\n    let Some(bytes): Option<Vec<u8>> = \
                            read_fixture(\"a\") else {\n        return;\n    };\n                                assert!(!bytes.is_empty());\n}\n";
        let found: Vec<SkipSite> = silent_sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(
            found.len(),
            1,
            "the let-else abandons the test with no message"
        );
        assert!(found[0].in_test);
    }

    #[test]
    fn a_single_line_let_else_return_is_a_silent_site() {
        let source: &str =
            "#[test]\nfn probe() {\n    let Some(v) = f() else { return; };\n    assert!(v);\n}\n";
        let found: Vec<SkipSite> = silent_sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(
            found.len(),
            1,
            "the one-line form abandons the test just as silently"
        );
    }

    #[test]
    fn a_let_else_that_fails_loudly_is_not_a_silent_site() {
        let source: &str = "#[test]\nfn probe() {\n    let Some(v) = f() else {\n                                    panic!(\"tracked fixture is unreadable\");\n    };\n                                assert!(v);\n}\n";
        let found: Vec<SkipSite> = silent_sites_in_source("crates/c/tests/t.rs", source);
        assert!(
            found.is_empty(),
            "a named hard failure is the fix, not the defect"
        );
    }

    #[test]
    fn a_printed_skip_inside_a_let_else_belongs_to_one_dimension_only() {
        let source: &str = "#[test]\nfn probe() {\n    let Some(v) = f() else {\n                                    eprintln!(\"skip: corpus absent\");\n        return;\n    };\n                                assert!(v);\n}\n";
        let silent: Vec<SkipSite> = silent_sites_in_source("crates/c/tests/t.rs", source);
        assert!(
            silent.is_empty(),
            "the printed census already owns this site; counting it twice inflates the total"
        );
        let printed: Vec<SkipSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(printed.len(), 1, "and the printed census must still see it");
    }

    #[test]
    fn a_silent_return_outside_a_test_is_recorded_but_not_counted_against_the_ceiling() {
        let source: &str = "fn helper() {\n    let Some(v) = f() else {\n        return;\n    };\n    drop(v);\n}\n";
        let found: Vec<SkipSite> = silent_sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(found.len(), 1);
        assert!(
            !found[0].in_test,
            "only sites inside a #[test] move a ceiling"
        );
    }

    #[test]
    fn the_crate_name_comes_from_the_second_path_segment() {
        assert_eq!(
            crate_of("crates/disrobe-pass-jvm/tests/a.rs"),
            Some("disrobe-pass-jvm")
        );
        assert_eq!(crate_of("xtask/src/main.rs"), None);
    }
}
