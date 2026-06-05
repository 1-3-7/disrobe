use core::ops::Range;
use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
use crate::jscrambler::scanner::find_brace_close;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let decls: Vec<FnDecl> = collect_function_declarations(source);
    if decls.len() < 2 {
        return 0;
    }
    let ordered: Vec<usize> = topological_order(&decls);
    let current: Vec<usize> = (0..decls.len()).collect();
    usize::from(ordered != current)
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let decls: Vec<FnDecl> = collect_function_declarations(source);
    let mut stats: TransformStats = TransformStats::default();
    if decls.len() < 2 {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let ordered: Vec<usize> = topological_order(&decls);
    let current: Vec<usize> = (0..decls.len()).collect();
    if ordered == current {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    stats.matched = 1;
    let first_start: usize = decls.first().map_or(0, |d: &FnDecl| d.range.start);
    let last_end: usize = decls.last().map_or(0, |d: &FnDecl| d.range.end);
    let mut rebuilt_block: String = String::new();
    for (idx, target) in ordered.iter().enumerate() {
        let decl: &FnDecl = &decls[*target];
        let snippet: &str = source.get(decl.range.clone()).unwrap_or("");
        rebuilt_block.push_str(snippet.trim());
        if idx + 1 != ordered.len() {
            rebuilt_block.push('\n');
        }
    }
    let mut out: String = String::with_capacity(source.len());
    out.push_str(&source[..first_start]);
    out.push_str(&rebuilt_block);
    out.push_str(&source[last_end..]);
    stats.reversed = 1;
    TransformOutput { source: out, stats }
}

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    opts: &TransformOpts,
) -> Result<TransformOutput> {
    let out: TransformOutput = reverse(source, opts);
    if out.stats.matched == 0 && source.contains("function ") && source.contains('{') {
        return Ok(out);
    }
    if out.stats.matched == 0 {
        return Err(Error::TransformNotYetImplemented {
            transform: "functionReordering",
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct FnDecl {
    name: String,
    range: Range<usize>,
    refers_to: BTreeSet<String>,
}

fn collect_function_declarations(source: &str) -> Vec<FnDecl> {
    let bytes: &[u8] = source.as_bytes();
    let Ok(re): core::result::Result<Regex, regex::Error> =
        Regex::new(r"(?m)^\s*function\s+([A-Za-z_$][\w$]*)\s*\(")
    else {
        return Vec::new();
    };
    let mut out: Vec<FnDecl> = Vec::new();
    let mut names: BTreeSet<String> = BTreeSet::new();
    for cap in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(name): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let brace_open_opt: Option<usize> =
            (whole.end()..bytes.len()).find(|i: &usize| bytes[*i] == b'{');
        let Some(brace_open): Option<usize> = brace_open_opt else {
            continue;
        };
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            continue;
        };
        let decl_start: usize = source[..whole.start()]
            .rfind(['\n', ';'])
            .map_or_else(|| whole.start(), |p: usize| p + 1);
        let decl_end: usize = brace_close + 1;
        names.insert(name.as_str().to_owned());
        out.push(FnDecl {
            name: name.as_str().to_owned(),
            range: decl_start..decl_end,
            refers_to: BTreeSet::new(),
        });
    }
    let Ok(ident_re): core::result::Result<Regex, regex::Error> =
        Regex::new(r"\b[A-Za-z_$][\w$]*\b")
    else {
        return out;
    };
    for decl in &mut out {
        let body: &str = source.get(decl.range.clone()).unwrap_or("");
        for m in ident_re.find_iter(body) {
            let name: &str = m.as_str();
            if name == decl.name {
                continue;
            }
            if names.contains(name) {
                decl.refers_to.insert(name.to_owned());
            }
        }
    }
    out
}

fn topological_order(decls: &[FnDecl]) -> Vec<usize> {
    let name_to_idx: BTreeMap<String, usize> = decls
        .iter()
        .enumerate()
        .map(|(i, d): (usize, &FnDecl)| (d.name.clone(), i))
        .collect();
    let mut indeg: Vec<usize> = vec![0; decls.len()];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); decls.len()];
    for (i, d) in decls.iter().enumerate() {
        for r in &d.refers_to {
            if let Some(&j) = name_to_idx.get(r)
                && j != i
            {
                adj[j].push(i);
                indeg[i] += 1;
            }
        }
    }
    let mut ready: Vec<usize> = (0..decls.len())
        .filter(|i: &usize| indeg[*i] == 0)
        .collect();
    ready.sort_by(|a: &usize, b: &usize| decls[*a].name.cmp(&decls[*b].name));
    let mut out: Vec<usize> = Vec::with_capacity(decls.len());
    while let Some(n) = ready.pop() {
        out.push(n);
        let mut new_ready: Vec<usize> = Vec::new();
        for &m in &adj[n] {
            indeg[m] -= 1;
            if indeg[m] == 0 {
                new_ready.push(m);
            }
        }
        new_ready.sort_by(|a: &usize, b: &usize| decls[*b].name.cmp(&decls[*a].name));
        ready.extend(new_ready);
    }
    if out.len() != decls.len() {
        return (0..decls.len()).collect();
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn no_op_on_single_function() {
        let src: &str = "function a(){}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }

    #[test]
    fn reorders_when_deps_inverted() {
        let src: &str = "function b(){a();}\nfunction a(){return 1;}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        let a_pos: usize = out.source.find("function a()").unwrap();
        let b_pos: usize = out.source.find("function b()").unwrap();
        assert!(a_pos < b_pos);
    }

    #[test]
    fn keeps_order_when_already_ordered() {
        let src: &str = "function a(){return 1;}\nfunction b(){a();}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }

    #[test]
    fn returns_typed_error_in_strict_mode_on_empty() {
        let res: Result<TransformOutput> = reverse_strict("", &TransformOpts::default());
        assert!(res.is_err());
    }

    #[test]
    fn detect_flags_misordered_pair() {
        let src: &str = "function b(){a();}\nfunction a(){return 1;}";
        assert_eq!(detect(src), 1);
    }
}
