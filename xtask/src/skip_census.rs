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
    ("disrobe-pass-as3", 22),
    ("disrobe-pass-dotnet", 4),
    ("disrobe-pass-go", 2),
    ("disrobe-pass-js-deob", 60),
    ("disrobe-pass-jvm", 73),
    ("disrobe-pass-lua", 22),
    ("disrobe-pass-mobile", 5),
    ("disrobe-pass-native", 295),
    ("disrobe-pass-nativelang", 2),
    ("disrobe-pass-nuitka", 32),
    ("disrobe-pass-php", 6),
    ("disrobe-pass-py-decompile", 7),
    ("disrobe-pass-py-deob", 12),
    ("disrobe-pass-py-disasm", 1),
    ("disrobe-pass-pyarmor", 39),
    ("disrobe-pass-pyfreeze", 19),
    ("disrobe-pass-ruby", 12),
    ("disrobe-pass-shell", 8),
    ("disrobe-pass-sourcedefender", 3),
    ("disrobe-pass-swift-objc", 1),
    ("disrobe-pass-wasm-deob", 11),
    ("disrobe-pyarmor-cextract", 5),
    ("disrobe-semdiff", 2),
    ("disrobe-typerec", 3),
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

fn scan(root: &Path) -> Result<(BTreeMap<String, Vec<SkipSite>>, usize)> {
    let crates_dir: PathBuf = root.join("crates");
    let mut per_crate: BTreeMap<String, Vec<SkipSite>> = BTreeMap::new();
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
    }
    Ok((per_crate, scanned))
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let (per_crate, scanned): (BTreeMap<String, Vec<SkipSite>>, usize) = scan(root)?;

    if scanned < MIN_SCANNED_FILES {
        bail!(
            "xtask skip-census scanned only {scanned} test source file(s), below the floor of \
             {MIN_SCANNED_FILES}. The scan itself is broken or the tree moved; a census that reads \
             nothing would report a clean sheet it did not earn"
        );
    }

    let declared: BTreeMap<&str, usize> = SKIP_CEILING.iter().copied().collect();
    let mut issues: Vec<String> = Vec::new();
    let mut total_in_test: usize = 0;
    let mut total: usize = 0;

    for (owner, sites) in &per_crate {
        let in_test: usize = sites.iter().filter(|site: &&SkipSite| site.in_test).count();
        total = total.saturating_add(sites.len());
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
                "{owner} carries {in_test} test(s) that print a skip line and return, above its \
                 declared ceiling of {ceiling}. A test that returns before its assertions is \
                 counted as passed and proves nothing. Either give the missing reference a named \
                 hard failure, or declare the reference optional and stop citing that test as \
                 evidence. First site(s): {first}"
            ));
        }
        if in_test < ceiling {
            issues.push(format!(
                "{owner} carries {in_test} skip-and-return test(s), below its declared ceiling of \
                 {ceiling}. Lower the ceiling in xtask/src/skip_census.rs in the same commit, so \
                 the number can only ratchet down"
            ));
        }
    }

    for (owner, ceiling) in SKIP_CEILING {
        if !per_crate.contains_key(*owner) && *ceiling > 0 {
            issues.push(format!(
                "SKIP_CEILING declares {ceiling} for {owner}, which now carries none. Remove the \
                 entry in the same commit"
            ));
        }
    }

    if !issues.is_empty() {
        bail!(
            "xtask skip-census: {} finding(s) over {} crate(s), {} site(s) of which {} sit inside a \
             #[test]:\n  {}",
            issues.len(),
            per_crate.len(),
            total,
            total_in_test,
            issues.join("\n  ")
        );
    }

    if per_crate.len() < MIN_SCANNED_CRATES && !SKIP_CEILING.is_empty() {
        bail!(
            "xtask skip-census matched only {} crate(s), below the floor of {MIN_SCANNED_CRATES}",
            per_crate.len()
        );
    }

    println!(
        "xtask skip-census: {scanned} test source file(s) scanned, {total_in_test} skip-and-return \
         test(s) across {} crate(s), each at or below its declared ceiling in \
         xtask/src/skip_census.rs; the ceiling ratchets down only",
        per_crate.len()
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
    fn the_crate_name_comes_from_the_second_path_segment() {
        assert_eq!(
            crate_of("crates/disrobe-pass-jvm/tests/a.rs"),
            Some("disrobe-pass-jvm")
        );
        assert_eq!(crate_of("xtask/src/main.rs"), None);
    }
}
