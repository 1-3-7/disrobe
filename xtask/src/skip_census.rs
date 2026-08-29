use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const RETURN_WINDOW: usize = 5;
const MIN_SCANNED_FILES: usize = 3_400;
const MIN_SCANNED_CRATES: usize = 20;

const SKIP_CEILING: &[(&str, usize)] = &[
    ("disrobe-binfmt", 3),
    ("disrobe-cli", 59),
    ("disrobe-core", 9),
    ("disrobe-irsummary", 1),
    ("disrobe-lift-x86", 2),
    ("disrobe-mba", 3),
    ("disrobe-nir-lift", 6),
    ("disrobe-pass-dotnet", 9),
    ("disrobe-pass-go", 7),
    ("disrobe-pass-js-deob", 67),
    ("disrobe-pass-jvm", 67),
    ("disrobe-pass-lua", 31),
    ("disrobe-pass-mobile", 5),
    ("disrobe-pass-native", 291),
    ("disrobe-pass-nativelang", 2),
    ("disrobe-pass-nuitka", 45),
    ("disrobe-pass-php", 6),
    ("disrobe-pass-py-decompile", 7),
    ("disrobe-pass-py-deob", 14),
    ("disrobe-pass-py-disasm", 1),
    ("disrobe-pass-pyarmor", 38),
    ("disrobe-pass-pyfreeze", 18),
    ("disrobe-pass-pyinstaller", 2),
    ("disrobe-pass-ruby", 12),
    ("disrobe-pass-scriptlang", 2),
    ("disrobe-pass-shell", 14),
    ("disrobe-pass-swift-objc", 1),
    ("disrobe-pass-wasm-deob", 17),
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

struct Census {
    printed: BTreeMap<String, Vec<SkipSite>>,
    scanned: usize,
}

fn scan(root: &Path) -> Result<Census> {
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
        if !relative.contains("/src/")
            && !relative.contains("/tests/")
            && !relative.ends_with("/tests.rs")
        {
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
    Ok(Census {
        printed: per_crate,
        scanned,
    })
}

fn enforce_scan_floor(scanned: usize) -> Result<()> {
    if scanned >= MIN_SCANNED_FILES {
        return Ok(());
    }
    bail!(
        "xtask skip-census scanned only {scanned} test source file(s), below the floor of \
         {MIN_SCANNED_FILES}. The scan itself is broken or the tree moved; a census that reads a \
         fraction of the tree reports a clean sheet for everything it never opened, so this floor \
         sits just under the count the workspace carries rather than at a token value a badly \
         narrowed scan would still clear"
    )
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let census: Census = scan(root)?;

    enforce_scan_floor(census.scanned)?;

    let declared: BTreeMap<&str, usize> = SKIP_CEILING.iter().copied().collect();
    let mut issues: Vec<String> = Vec::new();
    let mut printed: usize = 0;

    for (owner, sites) in &census.printed {
        let in_test: usize = sites.iter().filter(|site: &&SkipSite| site.in_test).count();
        printed = printed.saturating_add(in_test);
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
        if !census.printed.contains_key(*owner) && *ceiling > 0 {
            issues.push(format!(
                "SKIP_CEILING declares {ceiling} for {owner}, which now carries none. Remove the \
                 entry in the same commit"
            ));
        }
    }

    if !issues.is_empty() {
        bail!(
            "xtask skip-census: {} finding(s); {printed} test(s) print a skip line and \
             return:\n  {}",
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
         across {} crate(s), each at or below its declared ceiling in xtask/src/skip_census.rs; \
         the ceiling ratchets down only",
        census.scanned,
        census.printed.len()
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
    fn a_skip_and_return_inside_a_cfg_test_module_in_src_is_a_site() {
        let source: &str = concat!(
            "pub fn identify() {}\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    #[test]\n",
            "    fn probe() {\n",
            "        if !git_available() {\n",
            "            eprintln!(\"skipping: git not available\");\n",
            "            return;\n",
            "        }\n",
            "        assert!(finds_the_secret());\n",
            "    }\n",
            "}\n"
        );
        let found: Vec<SkipSite> = sites_in_source("crates/c/src/recon/git_history.rs", source);
        assert_eq!(
            found.len(),
            1,
            "a test that skips is a test wherever it lives, and reading only crates/*/tests left \
             74 of these unmeasured"
        );
        assert!(found[0].in_test);
    }

    #[test]
    fn the_scan_floor_refuses_a_walk_that_read_a_fraction_of_the_tree() {
        assert!(
            enforce_scan_floor(MIN_SCANNED_FILES).is_ok(),
            "the floor must accept the count the workspace actually carries"
        );
        let narrowed: usize = MIN_SCANNED_FILES.saturating_sub(1);
        let text: String = match enforce_scan_floor(narrowed) {
            Ok(()) => unreachable!("a walk one file short of the floor must refuse"),
            Err(refusal) => refusal.to_string(),
        };
        assert!(
            text.contains(&narrowed.to_string()),
            "the refusal must name what it actually read: {text}"
        );
        assert!(
            enforce_scan_floor(0).is_err(),
            "a walk that read nothing is the case this floor exists for"
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
