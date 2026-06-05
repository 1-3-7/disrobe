use std::collections::BTreeSet;

use serde::Serialize;

use crate::error::{Error, Result};

const CONCISE_OK_SUFFIX: &str = "syntax OK";
const MAIN_PROGRAM_HEADER: &str = "main program:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlOp {
    pub seq: String,
    pub name: String,
    pub flags: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlSub {
    pub name: String,
    pub is_main_program: bool,
    pub ops: Vec<PerlOp>,
    pub pad_vars: Vec<String>,
    pub constants: Vec<String>,
    pub called_subs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlOpTree {
    pub source_hint: Option<String>,
    pub subs: Vec<PerlSub>,
    pub op_count: usize,
}

#[must_use]
pub fn is_concise(bytes: &[u8]) -> bool {
    let text: &str = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let has_ok: bool = text
        .lines()
        .next()
        .is_some_and(|l: &str| l.trim_end().ends_with(CONCISE_OK_SUFFIX));
    let has_leavesub: bool = text.contains("leavesub") || text.contains(MAIN_PROGRAM_HEADER);
    let has_nextstate: bool = text.contains("nextstate") || text.contains("<;>");
    has_ok && has_leavesub && has_nextstate
}

pub fn read_concise(bytes: &[u8]) -> Result<PerlOpTree> {
    let text: &str = std::str::from_utf8(bytes).map_err(|_| Error::NotPerlConcise)?;
    if !is_concise(bytes) {
        return Err(Error::NotPerlConcise);
    }
    let mut lines: std::iter::Peekable<std::str::Lines<'_>> = text.lines().peekable();
    let source_hint: Option<String> = lines.peek().and_then(|first: &&str| {
        first
            .trim_end()
            .strip_suffix(CONCISE_OK_SUFFIX)
            .map(|p: &str| p.trim().to_owned())
            .filter(|s: &String| !s.is_empty())
    });
    if source_hint.is_some() {
        lines.next();
    }

    let mut subs: Vec<PerlSub> = Vec::new();
    let mut current: Option<PerlSub> = None;
    let mut op_count: usize = 0usize;

    for raw in lines {
        let line: &str = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = sub_header(line) {
            if let Some(done) = current.take() {
                subs.push(done);
            }
            current = Some(PerlSub {
                name: header.0,
                is_main_program: header.1,
                ops: Vec::new(),
                pad_vars: Vec::new(),
                constants: Vec::new(),
                called_subs: Vec::new(),
            });
            continue;
        }
        let Some(sub): Option<&mut PerlSub> = current.as_mut() else {
            continue;
        };
        if let Some(op) = parse_op_line(line) {
            harvest(sub, &op);
            sub.ops.push(op);
            op_count += 1;
        }
    }
    if let Some(done) = current.take() {
        subs.push(done);
    }
    if subs.is_empty() {
        return Err(Error::PerlEmptyDump);
    }
    for sub in &mut subs {
        dedup_sorted(&mut sub.pad_vars);
        dedup_sorted(&mut sub.constants);
        dedup_sorted(&mut sub.called_subs);
    }
    Ok(PerlOpTree {
        source_hint,
        subs,
        op_count,
    })
}

fn sub_header(line: &str) -> Option<(String, bool)> {
    if line == MAIN_PROGRAM_HEADER {
        return Some(("main program".to_owned(), true));
    }
    let stripped: &str = line.strip_suffix(':')?;
    if stripped.is_empty()
        || stripped.starts_with(|c: char| c.is_ascii_whitespace())
        || stripped.contains(' ')
        || stripped.contains('<')
    {
        return None;
    }
    if stripped.contains("::") {
        return Some((stripped.to_owned(), false));
    }
    None
}

fn parse_op_line(line: &str) -> Option<PerlOp> {
    let trimmed: &str = line.trim_start();
    let mut chars: std::str::CharIndices<'_> = trimmed.char_indices();
    let (seq_end, seq): (usize, String) = {
        let mut end: usize = 0usize;
        let mut seq: String = String::new();
        loop {
            match chars.next() {
                Some((idx, c)) if c.is_ascii_alphanumeric() => {
                    seq.push(c);
                    end = idx + c.len_utf8();
                }
                Some((idx, c)) if c == '-' && seq.is_empty() => {
                    seq.push(c);
                    end = idx + c.len_utf8();
                    break;
                }
                _ => break,
            }
        }
        (end, seq)
    };
    if seq.is_empty() {
        return None;
    }
    let rest: &str = trimmed[seq_end..].trim_start();
    let class_end: usize = rest.find('>').map(|i: usize| i + 1)?;
    if !rest.starts_with('<') {
        return None;
    }
    let after_class: &str = rest[class_end..].trim_start();
    let token_end: usize = token_boundary(after_class);
    let name: &str = &after_class[..token_end];
    let detail_flags: &str = after_class[token_end..].trim_start();
    let (name_only, detail): (String, Option<String>) = split_name_detail(name);
    let flags: String = detail_flags
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    Some(PerlOp {
        seq,
        name: name_only,
        flags,
        detail,
    })
}

fn token_boundary(s: &str) -> usize {
    let mut depth: i32 = 0i32;
    for (idx, c) in s.char_indices() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ' ' if depth <= 0 => return idx,
            _ => {}
        }
    }
    s.len()
}

fn split_name_detail(token: &str) -> (String, Option<String>) {
    let bracket: Option<usize> = token.find('[');
    let paren: Option<usize> = token.find('(');
    let open: Option<usize> = match (bracket, paren) {
        (Some(b), Some(p)) => Some(b.min(p)),
        (Some(b), None) => Some(b),
        (None, Some(p)) => Some(p),
        (None, None) => None,
    };
    match open {
        Some(idx) => (token[..idx].to_owned(), Some(token[idx..].to_owned())),
        None => (token.to_owned(), None),
    }
}

fn harvest(sub: &mut PerlSub, op: &PerlOp) {
    match op.name.as_str() {
        "padsv" | "padav" | "padhv" | "padrange" | "padsv_store" => {
            if let Some(detail) = op.detail.as_deref() {
                for var in extract_pad_names(detail) {
                    sub.pad_vars.push(var);
                }
            }
        }
        "const" => {
            if let Some(detail) = op.detail.as_deref()
                && let Some(c) = extract_const(detail)
            {
                sub.constants.push(c);
            }
        }
        "gv" => {
            if let Some(detail) = op.detail.as_deref()
                && let Some(callee) = extract_called_sub(detail)
            {
                sub.called_subs.push(callee);
            }
        }
        "multiconcat" => {
            if let Some(detail) = op.detail.as_deref()
                && let Some(c) = extract_multiconcat_literal(detail)
            {
                sub.constants.push(c);
            }
        }
        _ => {}
    }
}

fn extract_pad_names(detail: &str) -> Vec<String> {
    let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
    inner
        .split(';')
        .filter_map(|seg: &str| {
            let token: &str = seg.trim();
            let name: &str = token.split(':').next().unwrap_or(token).trim();
            if name.starts_with('$') || name.starts_with('@') || name.starts_with('%') {
                Some(name.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn extract_const(detail: &str) -> Option<String> {
    let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
    Some(inner.trim().to_owned()).filter(|s: &String| !s.is_empty())
}

fn extract_multiconcat_literal(detail: &str) -> Option<String> {
    let start: usize = detail.find('"')?;
    let rest: &str = detail.get(start + 1..)?;
    let end: usize = rest.find('"')?;
    let lit: &str = &rest[..end];
    if lit.is_empty() {
        None
    } else {
        Some(format!("PV \"{lit}\""))
    }
}

fn extract_called_sub(detail: &str) -> Option<String> {
    let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
    let name: &str = inner.trim_start_matches('*');
    if name.is_empty() || name == "_" {
        return None;
    }
    Some(name.to_owned())
}

fn dedup_sorted(items: &mut Vec<String>) {
    let set: BTreeSet<String> = items.drain(..).collect();
    items.extend(set);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SAMPLE: &str = "hello.pl syntax OK\n\
main::greet:\n\
7  <1> leavesub[1 ref] K/REFC,1 ->(end)\n\
-     <@> lineseq KP ->7\n\
1        <;> nextstate(main 4 hello.pl:5) v ->2\n\
2        <0> padrange[$name:4,5] */LVINTRO,range=1 ->3\n\
6        <+> multiconcat(\"Hello, !\",7,1)[t7] sK/STRINGIFY ->7\n\
5        <0> padsv[$name:4,5] s ->6\n\
main program:\n\
11 <@> leave[1 ref] vKP/REFC ->(end)\n\
j  <$> const[PV \"disrobe\"] sM ->k\n\
k  <#> gv[*greet] s ->l\n";

    #[test]
    fn detects_concise_dump() {
        assert!(is_concise(SAMPLE.as_bytes()));
    }

    #[test]
    fn rejects_non_concise() {
        assert!(!is_concise(b"this is not perl output at all"));
    }

    #[test]
    fn parses_subs_and_names() {
        let tree: PerlOpTree = read_concise(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(tree.source_hint.as_deref(), Some("hello.pl"));
        assert_eq!(tree.subs.len(), 2);
        assert_eq!(tree.subs[0].name, "main::greet");
        assert!(!tree.subs[0].is_main_program);
        assert!(tree.subs[1].is_main_program);
    }

    #[test]
    fn recovers_pad_vars_and_constants() {
        let tree: PerlOpTree = read_concise(SAMPLE.as_bytes()).expect("parse");
        assert!(tree.subs[0].pad_vars.iter().any(|v: &String| v == "$name"));
        let main: &PerlSub = &tree.subs[1];
        assert!(
            main.constants
                .iter()
                .any(|c: &String| c.contains("disrobe"))
        );
        assert!(main.called_subs.iter().any(|c: &String| c == "greet"));
    }

    #[test]
    fn counts_ops() {
        let tree: PerlOpTree = read_concise(SAMPLE.as_bytes()).expect("parse");
        assert!(tree.op_count >= 8);
    }
}
