use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::binary::GoImage;
use crate::symbols::{GoFunc, GoSymbols, package_path};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrippedReport {
    pub stripped: bool,
    pub recovered_funcs: usize,
    pub recovered_packages: Vec<String>,
    pub buildid: Option<String>,
    pub buildversion: Option<String>,
    pub stdlib_ratio: f64,
}

const STDLIB_PREFIXES: &[&str] = &[
    "runtime",
    "internal",
    "sync",
    "syscall",
    "reflect",
    "unicode",
    "encoding",
    "errors",
    "io",
    "os",
    "fmt",
    "strconv",
    "strings",
    "sort",
    "bytes",
    "bufio",
    "context",
    "time",
    "math",
    "crypto",
    "net",
    "path",
    "hash",
    "compress",
    "html",
    "regexp",
    "text",
    "container",
    "embed",
    "iter",
    "slices",
    "maps",
    "cmp",
];

#[must_use]
pub fn analyze_stripped(
    image: &GoImage<'_>,
    syms: &GoSymbols,
    buildversion: Option<String>,
) -> StrippedReport {
    let (stdlib_hits, user_pkgs): (usize, Vec<String>) = classify(syms);
    let stripped: bool = is_stripped(image);
    let total: usize = syms.funcs.len().max(1);
    #[allow(clippy::cast_precision_loss)]
    let stdlib_ratio: f64 = stdlib_hits as f64 / total as f64;
    let buildid: Option<String> = extract_buildid(image);
    StrippedReport {
        stripped,
        recovered_funcs: syms.funcs.len(),
        recovered_packages: user_pkgs,
        buildid,
        buildversion,
        stdlib_ratio,
    }
}

fn classify(syms: &GoSymbols) -> (usize, Vec<String>) {
    let mut stdlib_hits: usize = 0;
    let mut user_packages: BTreeMap<String, usize> = BTreeMap::new();
    for f in &syms.funcs {
        let Some(path): Option<&str> = package_path(&f.name) else {
            continue;
        };
        if is_stdlib_import(path) {
            stdlib_hits += 1;
        } else {
            *user_packages.entry(path.to_owned()).or_insert(0) += 1;
        }
    }
    let mut user_sorted: Vec<(String, usize)> = user_packages.into_iter().collect();
    user_sorted
        .sort_by(|a: &(String, usize), b: &(String, usize)| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let users: Vec<String> = user_sorted.into_iter().map(|(k, _)| k).collect();
    (stdlib_hits, users)
}

fn is_stdlib_import(path: &str) -> bool {
    let first_segment: &str = path.split('/').next().unwrap_or(path);
    STDLIB_PREFIXES.contains(&first_segment)
}

fn is_stripped(image: &GoImage<'_>) -> bool {
    let user_named: usize = image
        .symbol_addrs
        .iter()
        .filter(|(n, _, _)| n.starts_with("main.") || n.starts_with("runtime."))
        .count();
    user_named < 4
}

fn extract_buildid(image: &GoImage<'_>) -> Option<String> {
    let needle: &[u8] = b"Go build ID: \"";
    for sec in &image.sections {
        let mut i: usize = 0;
        while i + needle.len() <= sec.data.len() {
            if &sec.data[i..i + needle.len()] == needle {
                let start: usize = i + needle.len();
                let tail: &[u8] = &sec.data[start..];
                let end: usize = tail
                    .iter()
                    .position(|b: &u8| *b == b'"' || *b == 0)
                    .unwrap_or(0);
                if (4..=256).contains(&end)
                    && let Ok(s) = std::str::from_utf8(&tail[..end])
                {
                    return Some(s.to_owned());
                }
            }
            i += 1;
        }
    }
    None
}

#[must_use]
pub fn synth_main_candidates<'a>(syms: &'a GoSymbols) -> Vec<&'a GoFunc> {
    let mut out: Vec<&'a GoFunc> = syms
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.name.starts_with("main."))
        .collect();
    out.sort_by_key(|f: &&GoFunc| f.entry);
    out
}
