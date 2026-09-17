use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MIN_SCANNED_FILES: usize = 3_400;
const FLOOR_GAP: usize = 4;

const DENOMINATOR_CEILING: &[(&str, usize)] = &[
    ("disrobe-binfmt", 1),
    ("disrobe-cli", 1),
    ("disrobe-pass-dotnet", 2),
    ("disrobe-pass-go", 1),
    ("disrobe-pass-js-deob", 1),
    ("disrobe-pass-jvm", 3),
    ("disrobe-pass-lua", 1),
    ("disrobe-pass-mobile", 4),
    ("disrobe-pass-native", 3),
    ("disrobe-pass-py-decompile", 2),
    ("disrobe-pass-shell", 2),
    ("disrobe-pass-wasm-deob", 1),
    ("disrobe-semdiff", 2),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RateSite {
    pub(crate) file: String,
    pub(crate) test: String,
    pub(crate) denominator: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok<'a> {
    Ident(&'a str),
    Number,
    Star,
    Slash,
    Compare,
    Other,
}

fn strip_literals(line: &str) -> String {
    let mut out: String = String::with_capacity(line.len());
    let mut chars: std::str::Chars<'_> = line.chars();
    let mut quote: Option<char> = None;
    while let Some(current) = chars.next() {
        match quote {
            Some(open) => {
                if current == '\\' {
                    chars.next();
                    continue;
                }
                if current == open {
                    quote = None;
                    out.push(' ');
                }
            }
            None => {
                if current == '"' || current == '\'' {
                    quote = Some(current);
                    out.push(' ');
                } else {
                    out.push(current);
                }
            }
        }
    }
    out
}

fn tokenize(line: &str) -> Vec<Tok<'_>> {
    let bytes: &[u8] = line.as_bytes();
    let mut out: Vec<Tok<'_>> = Vec::new();
    let mut index: usize = 0;
    while index < bytes.len() {
        let current: u8 = bytes[index];
        if current.is_ascii_whitespace() {
            index = index.saturating_add(1);
            continue;
        }
        if current.is_ascii_alphabetic() || current == b'_' {
            let start: usize = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index = index.saturating_add(1);
            }
            out.push(Tok::Ident(&line[start..index]));
            continue;
        }
        if current.is_ascii_digit() {
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'_') {
                index = index.saturating_add(1);
            }
            out.push(Tok::Number);
            continue;
        }
        let next: Option<u8> = bytes.get(index.saturating_add(1)).copied();
        match (current, next) {
            (b'*', _) => out.push(Tok::Star),
            (b'/', Some(b'/')) => return out,
            (b'/', _) => out.push(Tok::Slash),
            (b'>' | b'<' | b'=' | b'!', Some(b'=')) => {
                out.push(Tok::Compare);
                index = index.saturating_add(2);
                continue;
            }
            (b'>' | b'<', _) => out.push(Tok::Compare),
            _ => out.push(Tok::Other),
        }
        index = index.saturating_add(1);
    }
    out
}

fn is_float_cast(tokens: &[Tok<'_>], at: usize) -> bool {
    matches!(tokens.get(at), Some(Tok::Ident("as")))
        && matches!(
            tokens.get(at.saturating_add(1)),
            Some(Tok::Ident("f64" | "f32"))
        )
}

fn denominators(tokens: &[Tok<'_>]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for index in 0..tokens.len() {
        if !matches!(tokens.get(index), Some(Tok::Ident(_))) {
            continue;
        }
        if is_float_cast(tokens, index.saturating_add(1))
            && matches!(tokens.get(index.saturating_add(3)), Some(Tok::Slash))
            && let Some(Tok::Ident(name)) = tokens.get(index.saturating_add(4))
            && is_float_cast(tokens, index.saturating_add(5))
        {
            found.push((*name).to_owned());
        }
        if matches!(tokens.get(index.saturating_add(1)), Some(Tok::Star))
            && matches!(tokens.get(index.saturating_add(2)), Some(Tok::Number))
            && matches!(tokens.get(index.saturating_add(3)), Some(Tok::Compare))
            && let Some(Tok::Ident(name)) = tokens.get(index.saturating_add(4))
            && matches!(tokens.get(index.saturating_add(5)), Some(Tok::Star))
            && matches!(tokens.get(index.saturating_add(6)), Some(Tok::Number))
        {
            found.push((*name).to_owned());
        }
        if matches!(tokens.get(index.saturating_add(1)), Some(Tok::Star))
            && matches!(tokens.get(index.saturating_add(2)), Some(Tok::Number))
            && matches!(tokens.get(index.saturating_add(3)), Some(Tok::Slash))
            && let Some(Tok::Ident(name)) = tokens.get(index.saturating_add(4))
        {
            found.push((*name).to_owned());
        }
    }
    found.sort();
    found.dedup();
    found
}

fn is_constant_name(name: &str) -> bool {
    name.len() > 1
        && name
            .chars()
            .all(|character: char| character.is_ascii_uppercase() || character == '_')
}

fn bounds_the_population(tokens: &[Tok<'_>], at: usize) -> bool {
    match tokens.get(at) {
        Some(Tok::Number) => true,
        Some(Tok::Ident(name)) if is_constant_name(name) => true,
        Some(Tok::Ident(_)) => matches!(
            tokens.get(at.saturating_add(2)),
            Some(Tok::Ident("len" | "count"))
        ),
        _ => false,
    }
}

fn pins_the_population(tokens: &[Tok<'_>], name: &str) -> bool {
    let Some(head) = tokens
        .iter()
        .position(|tok: &Tok<'_>| matches!(tok, Tok::Ident("assert_eq")))
    else {
        return false;
    };
    let mut cursor: usize = head.saturating_add(1);
    while matches!(tokens.get(cursor), Some(Tok::Other)) {
        cursor = cursor.saturating_add(1);
    }
    if !matches!(tokens.get(cursor), Some(Tok::Ident(found)) if *found == name) {
        return false;
    }
    let mut after: usize = cursor.saturating_add(1);
    while matches!(tokens.get(after), Some(Tok::Other)) {
        after = after.saturating_add(1);
    }
    bounds_the_population(tokens, after)
}

fn line_floors(line: &str, name: &str) -> bool {
    if !line.contains("assert") {
        return false;
    }
    let tokens: Vec<Tok<'_>> = tokenize(line);
    for index in 0..tokens.len() {
        if !matches!(tokens.get(index), Some(Tok::Ident(found)) if *found == name) {
            continue;
        }
        if index != 0
            && matches!(
                tokens.get(index.saturating_sub(1)),
                Some(Tok::Slash | Tok::Star)
            )
        {
            continue;
        }
        if tokens
            .get(index.saturating_add(1)..)
            .is_some_and(|rest: &[Tok<'_>]| {
                rest.iter().take(2).any(|tok: &Tok<'_>| {
                    matches!(tok, Tok::Ident("is_empty" | "is_some" | "is_ok"))
                })
            })
        {
            return true;
        }
        let window: usize = index.saturating_add(1);
        for offset in window..window.saturating_add(FLOOR_GAP).min(tokens.len()) {
            if matches!(tokens.get(offset), Some(Tok::Compare))
                && bounds_the_population(&tokens, offset.saturating_add(1))
            {
                return true;
            }
        }
    }
    pins_the_population(&tokens, name)
}

fn test_bodies<'a>(lines: &'a [&'a str]) -> Vec<(String, usize, usize)> {
    let mut out: Vec<(String, usize, usize)> = Vec::new();
    let mut index: usize = 0;
    while index < lines.len() {
        let trimmed: &str = lines[index].trim_start();
        if !trimmed.starts_with("#[test]") && !trimmed.starts_with("#[tokio::test") {
            index = index.saturating_add(1);
            continue;
        }
        let mut cursor: usize = index.saturating_add(1);
        let mut name: String = String::new();
        while cursor < lines.len() {
            let candidate: &str = lines[cursor].trim_start();
            if let Some(rest) = candidate
                .strip_prefix("pub async fn ")
                .or_else(|| candidate.strip_prefix("async fn "))
                .or_else(|| candidate.strip_prefix("pub fn "))
                .or_else(|| candidate.strip_prefix("fn "))
            {
                rest.split(|character: char| !character.is_alphanumeric() && character != '_')
                    .next()
                    .unwrap_or("")
                    .clone_into(&mut name);
                break;
            }
            cursor = cursor.saturating_add(1);
        }
        if cursor >= lines.len() {
            break;
        }
        let mut depth: isize = 0;
        let mut opened: bool = false;
        let mut end: usize = cursor;
        while end < lines.len() {
            for character in lines[end].chars() {
                if character == '{' {
                    depth = depth.saturating_add(1);
                    opened = true;
                } else if character == '}' {
                    depth = depth.saturating_sub(1);
                }
            }
            if opened && depth <= 0 {
                break;
            }
            end = end.saturating_add(1);
        }
        out.push((name, cursor, end.min(lines.len().saturating_sub(1))));
        index = end.saturating_add(1);
    }
    out
}

fn logical_lines(body: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending: String = String::new();
    let mut depth: isize = 0;
    for line in body {
        if !pending.is_empty() {
            pending.push(' ');
        }
        pending.push_str(line.trim());
        for character in line.chars() {
            match character {
                '(' | '[' => depth = depth.saturating_add(1),
                ')' | ']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if depth <= 0 {
            out.push(std::mem::take(&mut pending));
            depth = 0;
        }
    }
    if !pending.is_empty() {
        out.push(pending);
    }
    out
}

pub(crate) fn sites_in_source(relative: &str, source: &str) -> Vec<RateSite> {
    let stripped: Vec<String> = source
        .lines()
        .map(|line: &str| strip_literals(line))
        .collect();
    let lines: Vec<&str> = stripped.iter().map(String::as_str).collect();
    let mut found: Vec<RateSite> = Vec::new();
    for (test, start, end) in test_bodies(&lines) {
        let body: &[&str] = lines.get(start..=end).unwrap_or(&[]);
        let statements: Vec<String> = logical_lines(body);
        let mut names: Vec<String> = Vec::new();
        for statement in &statements {
            names.extend(denominators(&tokenize(statement)));
        }
        names.sort();
        names.dedup();
        for name in names {
            if statements
                .iter()
                .any(|statement: &String| line_floors(statement, &name))
            {
                continue;
            }
            found.push(RateSite {
                file: relative.to_owned(),
                test: test.clone(),
                denominator: name,
            });
        }
    }
    found
}

fn crate_of(relative: &str) -> Option<&str> {
    let mut parts: std::str::Split<'_, char> = relative.split('/');
    (parts.next()? == "crates").then(|| parts.next())?
}

fn scan(root: &Path) -> Result<(BTreeMap<String, Vec<RateSite>>, usize)> {
    let mut per_crate: BTreeMap<String, Vec<RateSite>> = BTreeMap::new();
    let mut scanned: usize = 0;
    for entry in walkdir::WalkDir::new(root.join("crates"))
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
        if entry
            .metadata()
            .map_or(0, |meta: std::fs::Metadata| meta.len())
            > MAX_SOURCE_BYTES
        {
            continue;
        }
        let source: String =
            std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
        scanned = scanned.saturating_add(1);
        let Some(owner) = crate_of(&relative) else {
            continue;
        };
        let sites: Vec<RateSite> = sites_in_source(&relative, &source);
        if !sites.is_empty() {
            per_crate.entry(owner.to_owned()).or_default().extend(sites);
        }
    }
    let _: PathBuf = root.join("crates");
    Ok((per_crate, scanned))
}

fn enforce_scan_floor(scanned: usize) -> Result<()> {
    if scanned >= MIN_SCANNED_FILES {
        return Ok(());
    }
    bail!(
        "xtask denominator-floor scanned only {scanned} test source file(s), below the floor of \
         {MIN_SCANNED_FILES}. A check that reads a fraction of the tree reports a clean sheet for \
         every rate it never opened, so this floor sits just under the count the workspace carries \
         rather than at a token value a badly narrowed scan would still clear"
    )
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let (per_crate, scanned): (BTreeMap<String, Vec<RateSite>>, usize) = scan(root)?;

    enforce_scan_floor(scanned)?;

    let declared: BTreeMap<&str, usize> = DENOMINATOR_CEILING.iter().copied().collect();
    let mut issues: Vec<String> = Vec::new();
    let mut total: usize = 0;

    for (owner, sites) in &per_crate {
        total = total.saturating_add(sites.len());
        let ceiling: usize = declared.get(owner.as_str()).copied().unwrap_or(0);
        if sites.len() > ceiling {
            let first: String = sites
                .iter()
                .take(3)
                .map(|site: &RateSite| {
                    format!("{}::{} over `{}`", site.file, site.test, site.denominator)
                })
                .collect::<Vec<String>>()
                .join(", ");
            issues.push(format!(
                "{owner} asserts {} rate(s) against a threshold over a denominator nothing floors, \
                 above its declared ceiling of {ceiling}. A rate over a population that can shrink \
                 keeps reporting a healthy figure while measuring almost nothing, and a rate over \
                 an empty population passes every threshold including equality. Floor the \
                 denominator in the same test. Site(s): {first}",
                sites.len()
            ));
        }
        if sites.len() < ceiling {
            issues.push(format!(
                "{owner} asserts {} such rate(s), below its declared ceiling of {ceiling}. Lower \
                 the DENOMINATOR_CEILING entry in xtask/src/denominator_floor.rs in the same \
                 commit, so the number can only ratchet down",
                sites.len()
            ));
        }
    }

    for (owner, ceiling) in DENOMINATOR_CEILING {
        if !per_crate.contains_key(*owner) && *ceiling > 0 {
            issues.push(format!(
                "DENOMINATOR_CEILING declares {ceiling} for {owner}, which now carries none. \
                 Remove the entry in the same commit"
            ));
        }
    }

    if !issues.is_empty() {
        bail!(
            "xtask denominator-floor: {} finding(s) over {} crate(s):\n  {}",
            issues.len(),
            per_crate.len(),
            issues.join("\n  ")
        );
    }

    println!(
        "xtask denominator-floor: {scanned} test source file(s) scanned, {total} rate(s) compared \
         against a threshold over an unfloored denominator across {} crate(s), each at or below \
         its declared ceiling in xtask/src/denominator_floor.rs; the ceiling ratchets down only",
        per_crate.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cross_multiplied_rate_over_an_unfloored_population_is_a_site() {
        let source: &str = "#[test]\nfn probe() {\n    let full: usize = count();\n    \
                            let bodies: usize = all();\n    assert!(full * 1000 >= bodies * 805);\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(found.len(), 1, "nothing floors `bodies`");
        assert_eq!(found[0].denominator, "bodies");
        assert_eq!(found[0].test, "probe");
    }

    #[test]
    fn the_same_rate_with_the_population_floored_is_not_a_site() {
        let source: &str = "#[test]\nfn probe() {\n    let full: usize = count();\n    \
                            let bodies: usize = all();\n    assert!(bodies > 1000);\n    \
                            assert!(full * 1000 >= bodies * 805);\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert!(
            found.is_empty(),
            "the floor is exactly the fix this gate asks for"
        );
    }

    #[test]
    fn a_float_ratio_over_an_unfloored_population_is_a_site() {
        let source: &str = "#[test]\nfn probe() {\n    let rate: f64 = hits as f64 / total as f64;\n    \
                            assert!(rate >= 0.9);\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].denominator, "total");
    }

    #[test]
    fn a_path_separator_inside_a_string_literal_is_not_a_division() {
        let source: &str = "#[test]\nfn probe() {\n    let bytes: Vec<u8> = \
                            read(\"packers/hello.exe\");\n    assert!(!bytes.is_empty());\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert!(
            found.is_empty(),
            "a literal path once produced 2404 findings where the real count was 13"
        );
    }

    #[test]
    fn a_floor_the_formatter_split_across_lines_still_counts() {
        let source: &str = "#[test]\nfn probe() {\n    assert!(\n        compared > 0,\n        \
                            \"the section must be present\",\n    );\n    let pct: f64 = matched \
                            as f64 / compared as f64;\n    assert!(pct >= 0.85);\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert!(
            found.is_empty(),
            "rustfmt puts `assert!(` and `compared > 0,` on separate lines, and reading them \
             apart reported an explicitly floored population as unfloored"
        );
    }

    #[test]
    fn a_rate_published_from_a_cfg_test_module_inside_src_is_a_site() {
        let source: &str = concat!(
            "pub fn identify() {}\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    #[test]\n",
            "    fn probe() {\n",
            "        let recall: f64 = hit as f64 / present as f64;\n",
            "        assert!(recall >= 1.0);\n",
            "    }\n",
            "}\n"
        );
        let found: Vec<RateSite> = sites_in_source("crates/c/src/fileid.rs", source);
        assert_eq!(
            found.len(),
            1,
            "a test that publishes a rate is a test wherever it lives, and scanning only \
             crates/*/tests left this one unmeasured"
        );
        assert_eq!(found[0].denominator, "present");
    }

    #[test]
    fn production_code_beside_a_cfg_test_module_is_not_a_site() {
        let source: &str = "pub fn ratio(hit: usize, total: usize) -> f64 {\n    \
                            hit as f64 / total as f64\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/src/fileid.rs", source);
        assert!(
            found.is_empty(),
            "scanning src must not reach production code, where an early return against malformed \
             input is correct refusal rather than a skipped measurement"
        );
    }

    #[test]
    fn a_denominator_pinned_to_a_collection_length_is_floored() {
        let source: &str = concat!(
            "#[test]\n",
            "fn probe() {\n",
            "    let recall: f64 = hit as f64 / present as f64;\n",
            "    assert_eq!(present, cases.len());\n",
            "    assert!(recall >= 1.0);\n",
            "}\n"
        );
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert!(
            found.is_empty(),
            "pinning the population to the case list is the strongest form available, and reading \
             only NAME compared with a numeric literal made it invisible"
        );
    }

    #[test]
    fn a_denominator_floored_against_a_named_constant_is_floored() {
        let source: &str = concat!(
            "#[test]\n",
            "fn probe() {\n",
            "    assert!(possible >= CLEAN_TOKEN_COUNT);\n",
            "    assert!(hits * 100 / possible >= 92);\n",
            "}\n"
        );
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert!(found.is_empty(), "a constant is a bound like any other");
    }

    #[test]
    fn an_equality_between_two_counted_populations_is_not_a_floor() {
        let source: &str = concat!(
            "#[test]\n",
            "fn probe() {\n",
            "    let rate: f64 = hits as f64 / total as f64;\n",
            "    assert_eq!(hits, total);\n",
            "    assert!(rate >= 0.9);\n",
            "}\n"
        );
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(
            found.len(),
            1,
            "demanding equality between two counts bounds neither of them, and both are zero when \
             the population is empty"
        );
        assert_eq!(found[0].denominator, "total");
    }

    #[test]
    fn the_scan_floor_refuses_a_walk_that_read_a_fraction_of_the_tree() {
        assert!(enforce_scan_floor(MIN_SCANNED_FILES).is_ok());
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
    fn a_ratio_outside_a_test_body_is_not_a_site() {
        let source: &str = "fn helper() {\n    let rate: f64 = hits as f64 / total as f64;\n    \
                            assert!(rate >= 0.9);\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert!(found.is_empty(), "only a #[test] body publishes a rate");
    }

    #[test]
    fn a_percentage_rate_over_an_unfloored_population_is_a_site() {
        let source: &str = "#[test]\nfn probe() {\n    \
                            assert!(recovered * 100 / attempted >= 80);\n}\n";
        let found: Vec<RateSite> = sites_in_source("crates/c/tests/t.rs", source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].denominator, "attempted");
    }
}
