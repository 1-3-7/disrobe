use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

use crate::capability_reachability::{cfg_test_ranges, production_rs_files};
use crate::fileio::read_text_bounded;

pub(crate) const ALLOW_LIST: &str = "xtask/data/as_char_allow.toml";
const MAX_ALLOW_LIST_BYTES: u64 = 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const PASS_CRATE_PREFIX: &str = "disrobe-pass-";
const EXTRA_SOURCE_DIRS: [&str; 2] = ["crates/disrobe-py-marshal/src", "crates/disrobe-binfmt/src"];
const LATIN1_PREFIX: &str = "LATIN1-REINTERPRET:";
const MODULE_SCOPE: &str = "(module)";
const FN_QUALIFIERS: [&str; 8] = [
    "pub",
    "pub(crate)",
    "pub(super)",
    "const",
    "async",
    "unsafe",
    "extern",
    "\"C\"",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    site: Vec<Allowance>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowance {
    file: String,
    #[serde(rename = "fn")]
    function: String,
    line: String,
    reason: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Site {
    file: String,
    line_number: usize,
    function: String,
    text: String,
}

#[derive(Debug, Default)]
pub(crate) struct AsCharScan {
    pub(crate) sites: usize,
    pub(crate) latin1_allowances: usize,
    pub(crate) unlisted: Vec<String>,
    pub(crate) stale: Vec<String>,
    pub(crate) invalid: Vec<String>,
}

pub(crate) fn scan(root: &Path) -> Result<AsCharScan> {
    let allow_text: String = read_text_bounded(&root.join(ALLOW_LIST), MAX_ALLOW_LIST_BYTES)
        .wrap_err_with(|| format!("reading {ALLOW_LIST}"))?;
    let allow: AllowFile =
        toml::from_str(&allow_text).wrap_err_with(|| format!("parsing {ALLOW_LIST}"))?;
    let mut sites: Vec<Site> = Vec::new();
    for dir in source_dirs(root)? {
        for path in production_rs_files(&dir)? {
            let source: String = read_text_bounded(&path, MAX_SOURCE_BYTES)
                .wrap_err_with(|| format!("reading {}", path.display()))?;
            sites.extend(sites_in_source(&relative(root, &path), &source)?);
        }
    }
    Ok(judge(&sites, &allow.site))
}

fn source_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let crates: PathBuf = root.join("crates");
    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for entry in
        std::fs::read_dir(&crates).wrap_err_with(|| format!("listing {}", crates.display()))?
    {
        let entry: std::fs::DirEntry =
            entry.wrap_err_with(|| format!("listing {}", crates.display()))?;
        let name: String = entry.file_name().to_string_lossy().into_owned();
        let src: PathBuf = entry.path().join("src");
        if name.starts_with(PASS_CRATE_PREFIX) && src.is_dir() {
            dirs.insert(src);
        }
    }
    for extra in EXTRA_SOURCE_DIRS {
        let dir: PathBuf = root.join(extra);
        if !dir.is_dir() {
            bail!("{extra} is not a directory; update EXTRA_SOURCE_DIRS in xtask/src/as_char.rs");
        }
        dirs.insert(dir);
    }
    Ok(dirs.into_iter().collect())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.to_string_lossy().replace('\\', "/"),
        |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
    )
}

fn sites_in_source(file: &str, source: &str) -> Result<Vec<Site>> {
    let test_ranges: Vec<(usize, usize)> = cfg_test_ranges(source)
        .wrap_err_with(|| format!("locating cfg(test) modules in {file}"))?;
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(
            source
                .match_indices('\n')
                .map(|(index, _): (usize, &str)| index + 1),
        )
        .collect();
    let lines: Vec<&str> = source.split('\n').collect();
    let mut sites: Vec<Site> = Vec::new();
    let mut last_line: Option<usize> = None;
    for offset in cast_offsets(source) {
        if test_ranges
            .iter()
            .any(|(start, end): &(usize, usize)| offset >= *start && offset < *end)
        {
            continue;
        }
        let index: usize = line_starts.partition_point(|start: &usize| *start <= offset) - 1;
        let Some(line) = lines.get(index) else {
            continue;
        };
        let text: &str = line.trim();
        if text.starts_with("//") || last_line == Some(index) {
            continue;
        }
        last_line = Some(index);
        sites.push(Site {
            file: file.to_owned(),
            line_number: index + 1,
            function: enclosing_fn(&lines, index),
            text: text.to_owned(),
        });
    }
    Ok(sites)
}

const fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn cast_offsets(source: &str) -> Vec<usize> {
    let bytes: &[u8] = source.as_bytes();
    let mut offsets: Vec<usize> = Vec::new();
    let mut from: usize = 0;
    while let Some(relative) = source.get(from..).and_then(|rest: &str| rest.find("as")) {
        let at: usize = from + relative;
        from = at + 2;
        let starts_token: bool = at == 0 || !is_ident(bytes[at - 1]);
        if !starts_token || !bytes.get(at + 2).is_some_and(u8::is_ascii_whitespace) {
            continue;
        }
        let mut next: usize = at + 2;
        while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
            next += 1;
        }
        let names_char: bool = bytes.get(next..next + 4) == Some(b"char".as_slice())
            && !bytes.get(next + 4).is_some_and(|byte: &u8| is_ident(*byte));
        if names_char {
            offsets.push(at);
        }
    }
    offsets
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn fn_name(line: &str) -> Option<&str> {
    let mut words: std::str::SplitWhitespace<'_> = line.split_whitespace();
    loop {
        let word: &str = words.next()?;
        if word == "fn" {
            let name: &str = words.next()?;
            let end: usize = name
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(name.len());
            return (end > 0).then_some(&name[..end]);
        }
        if !FN_QUALIFIERS.contains(&word) {
            return None;
        }
    }
}

fn enclosing_fn(lines: &[&str], index: usize) -> String {
    let site_indent: usize = lines.get(index).map_or(0, |line: &&str| indent(line));
    for candidate in (0..=index).rev() {
        let Some(line) = lines.get(candidate) else {
            continue;
        };
        if candidate != index && indent(line) >= site_indent {
            continue;
        }
        if let Some(name) = fn_name(line) {
            return name.to_owned();
        }
    }
    MODULE_SCOPE.to_owned()
}

fn judge(sites: &[Site], allowances: &[Allowance]) -> AsCharScan {
    let mut scan: AsCharScan = AsCharScan {
        sites: sites.len(),
        ..AsCharScan::default()
    };
    let mut by_key: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
    for (position, allowance) in allowances.iter().enumerate() {
        let key: (&str, &str, &str) = (
            allowance.file.as_str(),
            allowance.function.as_str(),
            allowance.line.as_str(),
        );
        if by_key.insert(key, position).is_some() {
            scan.invalid.push(format!(
                "{} (fn {}): `{}` is listed twice",
                allowance.file, allowance.function, allowance.line
            ));
        }
        let reason: &str = allowance.reason.trim();
        if reason.is_empty() || reason == LATIN1_PREFIX {
            scan.invalid.push(format!(
                "{} (fn {}): `{}` has no reason",
                allowance.file, allowance.function, allowance.line
            ));
        }
        if reason.starts_with(LATIN1_PREFIX) {
            scan.latin1_allowances += 1;
        }
    }
    let mut used: BTreeSet<usize> = BTreeSet::new();
    for site in sites {
        match by_key.get(&(
            site.file.as_str(),
            site.function.as_str(),
            site.text.as_str(),
        )) {
            Some(position) => {
                used.insert(*position);
            }
            None => scan.unlisted.push(format!(
                "{}:{} (fn {}): `{}`",
                site.file, site.line_number, site.function, site.text
            )),
        }
    }
    for (position, allowance) in allowances.iter().enumerate() {
        if !used.contains(&position) {
            scan.stale.push(format!(
                "{} (fn {}): `{}`",
                allowance.file, allowance.function, allowance.line
            ));
        }
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "fn render(bytes: &[u8]) -> String {\n    let mut out: String = String::new();\n    let mut i: usize = 0;\n    while i < bytes.len() {\n        out.push(bytes[i] as char);\n        i += 1;\n    }\n    out\n}\n\nfn hex(v: u8) -> char {\n    (b'0' + v) as char\n}\n\n#[cfg(test)]\nmod tests {\n    fn probe(b: u8) -> char {\n        b as char\n    }\n}\n";

    fn allowance(function: &str, line: &str, reason: &str) -> Allowance {
        Allowance {
            file: "crates/disrobe-pass-probe/src/lib.rs".to_owned(),
            function: function.to_owned(),
            line: line.to_owned(),
            reason: reason.to_owned(),
        }
    }

    fn probe_sites() -> Result<Vec<Site>> {
        sites_in_source("crates/disrobe-pass-probe/src/lib.rs", SOURCE)
    }

    #[test]
    fn as_char_finds_production_casts_and_skips_cfg_test_modules() -> Result<()> {
        let sites: Vec<Site> = probe_sites()?;
        let found: Vec<(usize, &str, &str)> = sites
            .iter()
            .map(|site: &Site| (site.line_number, site.function.as_str(), site.text.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                (5, "render", "out.push(bytes[i] as char);"),
                (12, "hex", "(b'0' + v) as char"),
            ]
        );
        Ok(())
    }

    #[test]
    fn as_char_unlisted_byte_cast_is_a_finding() -> Result<()> {
        let sites: Vec<Site> = probe_sites()?;
        let allowances: Vec<Allowance> = vec![allowance(
            "hex",
            "(b'0' + v) as char",
            "ASCII-only: decimal digit",
        )];
        let scan: AsCharScan = judge(&sites, &allowances);
        assert_eq!(
            scan.unlisted,
            vec![
                "crates/disrobe-pass-probe/src/lib.rs:5 (fn render): `out.push(bytes[i] as char);`"
                    .to_owned()
            ]
        );
        assert!(scan.stale.is_empty());
        Ok(())
    }

    #[test]
    fn as_char_allow_listed_lines_pass() -> Result<()> {
        let sites: Vec<Site> = probe_sites()?;
        let allowances: Vec<Allowance> = vec![
            allowance("hex", "(b'0' + v) as char", "ASCII-only: decimal digit"),
            allowance(
                "render",
                "out.push(bytes[i] as char);",
                "LATIN1-REINTERPRET: raw bytes become U+0000..U+00FF",
            ),
        ];
        let scan: AsCharScan = judge(&sites, &allowances);
        assert!(scan.unlisted.is_empty(), "{:?}", scan.unlisted);
        assert!(scan.stale.is_empty(), "{:?}", scan.stale);
        assert!(scan.invalid.is_empty(), "{:?}", scan.invalid);
        assert_eq!(scan.latin1_allowances, 1);
        Ok(())
    }

    #[test]
    fn as_char_stale_or_reasonless_entry_fails() -> Result<()> {
        let sites: Vec<Site> = probe_sites()?;
        let allowances: Vec<Allowance> = vec![
            allowance("hex", "(b'0' + v) as char", "ASCII-only: decimal digit"),
            allowance("render", "out.push(bytes[i] as char);", " "),
            allowance(
                "render",
                "out.push(bytes[j] as char);",
                "ASCII-only: moved away",
            ),
        ];
        let scan: AsCharScan = judge(&sites, &allowances);
        assert!(scan.unlisted.is_empty());
        assert_eq!(
            scan.stale,
            vec![
                "crates/disrobe-pass-probe/src/lib.rs (fn render): `out.push(bytes[j] as char);`"
                    .to_owned()
            ]
        );
        assert_eq!(scan.invalid.len(), 1);
        Ok(())
    }

    #[test]
    fn as_char_ignores_identifiers_that_merely_contain_as_and_char() {
        let source: &str = "fn f(has: u8, as_chars: u8) -> u8 {\n    let alias: u8 = has as u8;\n    let _c: char = alias as charset;\n    as_chars\n}\n";
        assert!(cast_offsets(source).is_empty());
        assert_eq!(cast_offsets("x as\n    char").len(), 1);
    }
}
