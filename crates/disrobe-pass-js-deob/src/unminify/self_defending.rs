use serde::Serialize;

use crate::scan_utils::{find_paren_close, find_statement_end, skip_ws};

const SELF_DEFENDING_REGEX: &str = "(((.+)+)+)+$";

fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    find_paren_close(bytes, open + 1)
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize)]
pub(super) struct SelfDefendingStats {
    pub(super) checker_blocks: usize,
    pub(super) once_wrappers: usize,
    pub(super) debug_ratchets: usize,
}

pub(super) fn strip_self_defending(source: &str) -> (String, SelfDefendingStats) {
    let mut stats: SelfDefendingStats = SelfDefendingStats::default();
    let (after_checker, checker_names): (String, Vec<String>) = remove_checker_blocks(source);
    stats.checker_blocks = checker_names.len();
    let (after_wrapper, wrapper_removed): (String, usize) =
        remove_once_wrappers(&after_checker, &checker_names);
    stats.once_wrappers = wrapper_removed;
    let (after_debug, debug_removed): (String, usize) = remove_debug_ratchets(&after_wrapper);
    stats.debug_ratchets = debug_removed;
    (after_debug, stats)
}

fn remove_checker_blocks(source: &str) -> (String, Vec<String>) {
    let bytes: &[u8] = source.as_bytes();
    let mut removals: Vec<CheckerRemoval> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("(this,") {
        let call_open: usize = from + rel;
        from = call_open + "(this,".len();
        let Some(removal): Option<CheckerRemoval> = locate_checker(source, call_open) else {
            continue;
        };
        removals.push(removal);
    }
    if removals.is_empty() {
        return (source.to_owned(), Vec::new());
    }
    removals.sort_by_key(|r: &CheckerRemoval| r.start);
    let mut out: String = String::with_capacity(source.len());
    let mut wrapper_names: Vec<String> = Vec::new();
    let mut cursor: usize = 0;
    for removal in &removals {
        if removal.start < cursor {
            continue;
        }
        out.push_str(&source[cursor..removal.start]);
        cursor = removal.end;
        if let Some(w) = &removal.wrapper_name {
            wrapper_names.push(w.clone());
        }
    }
    out.push_str(&source[cursor..]);
    let _ = bytes;
    (out, wrapper_names)
}

struct CheckerRemoval {
    start: usize,
    end: usize,
    wrapper_name: Option<String>,
}

fn locate_checker(source: &str, call_open: usize) -> Option<CheckerRemoval> {
    let bytes: &[u8] = source.as_bytes();
    let wrapper_name: Option<String> = read_identifier_before(source, call_open);
    let wrapper_len: usize = wrapper_name.as_deref().map_or(0, str::len);
    let mut eq_cursor: usize = call_open.saturating_sub(wrapper_len);
    while eq_cursor > 0 && matches!(bytes[eq_cursor - 1], b' ' | b'\t') {
        eq_cursor -= 1;
    }
    if eq_cursor == 0 || bytes[eq_cursor - 1] != b'=' {
        return None;
    }
    let checker_name: String = read_identifier_before(source, eq_cursor - 1)?;
    let stmt_start: usize = backtrack_to_decl_start(bytes, eq_cursor - 1);
    if !is_decl_statement(&source[stmt_start..(stmt_start + 6).min(source.len())]) {
        return None;
    }
    let stmt_semi: usize = find_statement_end(bytes, stmt_start)?;
    if !source[stmt_start..stmt_semi].contains(SELF_DEFENDING_REGEX) {
        return None;
    }
    let decl_terminator: usize = stmt_semi + 1;
    let end: usize =
        find_bare_invocation(bytes, stmt_semi, &checker_name).unwrap_or(decl_terminator);
    Some(CheckerRemoval {
        start: stmt_start,
        end,
        wrapper_name,
    })
}

fn backtrack_to_decl_start(bytes: &[u8], pos: usize) -> usize {
    let mut i: usize = pos;
    let mut depth: i32 = 0;
    while i > 0 {
        i -= 1;
        let b: u8 = bytes[i];
        if depth <= 0 {
            if b == b';' || b == b'}' || b == b'{' {
                return skip_ws(bytes, i + 1);
            }
            if is_decl_keyword_at(bytes, i) {
                return i;
            }
        }
        match b {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => depth -= 1,
            _ => {}
        }
    }
    skip_ws(bytes, 0)
}

fn is_decl_keyword_at(bytes: &[u8], i: usize) -> bool {
    if i != 0 && is_ident_byte(bytes[i - 1]) {
        return false;
    }
    [b"const ".as_slice(), b"let ".as_slice(), b"var ".as_slice()]
        .iter()
        .any(|kw: &&[u8]| bytes[i..].starts_with(kw))
}

struct TopLevelStatement {
    start: usize,
    end: usize,
}

struct TopLevelStatements<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> TopLevelStatements<'a> {
    const fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            cursor: 0,
        }
    }
}

impl Iterator for TopLevelStatements<'_> {
    type Item = TopLevelStatement;

    fn next(&mut self) -> Option<Self::Item> {
        let start: usize = skip_ws(self.bytes, self.cursor);
        if start >= self.bytes.len() {
            self.cursor = start;
            return None;
        }
        let end: usize = match find_statement_end(self.bytes, start) {
            Some(semi) => semi,
            None => self.bytes.len(),
        };
        self.cursor = (end + 1).min(self.bytes.len());
        Some(TopLevelStatement { start, end })
    }
}

fn is_decl_statement(statement: &str) -> bool {
    let trimmed: &str = statement.trim_start();
    ["const", "let", "var"].iter().any(|kw: &&str| {
        trimmed
            .strip_prefix(*kw)
            .and_then(|rest: &str| rest.bytes().next())
            .is_some_and(|b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    })
}

fn read_identifier_before(statement: &str, call_pos: usize) -> Option<String> {
    let bytes: &[u8] = statement.as_bytes();
    let mut end: usize = call_pos;
    while end > 0 && !is_ident_byte(bytes[end - 1]) {
        end -= 1;
    }
    let mut start: usize = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    Some(statement[start..end].to_owned())
}

fn find_bare_invocation(bytes: &[u8], decl_end: usize, name: &str) -> Option<usize> {
    let after_semi: usize = if bytes.get(decl_end) == Some(&b';') {
        decl_end + 1
    } else {
        decl_end
    };
    let start: usize = skip_ws(bytes, after_semi);
    let name_bytes: &[u8] = name.as_bytes();
    if !bytes[start..].starts_with(name_bytes) {
        return None;
    }
    let boundary: usize = start + name_bytes.len();
    if bytes.get(boundary).is_some_and(|b: &u8| is_ident_byte(*b)) {
        return None;
    }
    let after_name: usize = skip_ws(bytes, boundary);
    if bytes.get(after_name) != Some(&b'(') {
        return None;
    }
    let close: usize = find_matching_paren(bytes, after_name)?;
    let end: usize = skip_ws(bytes, close + 1);
    if bytes.get(end) == Some(&b';') {
        return Some(end + 1);
    }
    Some(close + 1)
}

fn remove_once_wrappers(source: &str, wrapper_names: &[String]) -> (String, usize) {
    if wrapper_names.is_empty() {
        return (source.to_owned(), 0);
    }
    let mut removals: Vec<(usize, usize)> = Vec::new();
    for name in wrapper_names {
        if let Some((start, end)) = locate_once_wrapper_decl(source, name) {
            removals.push((start, end));
        }
    }
    if removals.is_empty() {
        return (source.to_owned(), 0);
    }
    removals.sort_by_key(|entry: &(usize, usize)| entry.0);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut count: usize = 0;
    for (start, end) in &removals {
        if *start < cursor {
            continue;
        }
        out.push_str(&source[cursor..*start]);
        cursor = *end;
        count += 1;
    }
    out.push_str(&source[cursor..]);
    (out, count)
}

fn locate_once_wrapper_decl(source: &str, name: &str) -> Option<(usize, usize)> {
    for stmt in TopLevelStatements::new(source) {
        let body: &str = &source[stmt.start..stmt.end];
        if !is_decl_statement(body) {
            continue;
        }
        let Some(declared): Option<&str> = single_declarator_name(body) else {
            continue;
        };
        if declared != name {
            continue;
        }
        if !is_once_wrapper_shape(body) {
            continue;
        }
        let end: usize = if source.as_bytes().get(stmt.end) == Some(&b';') {
            stmt.end + 1
        } else {
            stmt.end
        };
        return Some((stmt.start, end));
    }
    None
}

fn single_declarator_name(statement: &str) -> Option<&str> {
    let trimmed: &str = statement.trim_start();
    let after_kw: &str = ["const", "let", "var"]
        .iter()
        .find_map(|kw: &&str| trimmed.strip_prefix(*kw))?
        .trim_start();
    let name_len: usize = after_kw
        .bytes()
        .take_while(|b: &u8| is_ident_byte(*b))
        .count();
    if name_len == 0 {
        return None;
    }
    let name: &str = &after_kw[..name_len];
    let rest: &str = after_kw[name_len..].trim_start();
    if !rest.starts_with('=') {
        return None;
    }
    Some(name)
}

fn is_once_wrapper_shape(region: &str) -> bool {
    let has_flag: bool = region.contains("!![]") || region.contains("true");
    let returns_fn: bool = region.contains("return function");
    let resets_flag: bool =
        region.contains("![]") || region.contains("=false") || region.contains("= false");
    let iife: bool =
        region.trim_end().ends_with("()") || region.contains("}())") || region.contains("})()");
    has_flag && returns_fn && resets_flag && iife
}

fn remove_debug_ratchets(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("setInterval") {
        let pos: usize = from + rel;
        from = pos + "setInterval".len();
        let open: usize = skip_ws(bytes, pos + "setInterval".len());
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let Some(arg): Option<usize> = find_matching_paren(bytes, open) else {
            continue;
        };
        let body: &str = &source[open + 1..arg];
        if !mentions_debugger(body) {
            continue;
        }
        let mut end: usize = skip_ws(bytes, arg + 1);
        if bytes.get(end) == Some(&b';') {
            end += 1;
        }
        removals.push((pos, end));
    }
    if removals.is_empty() {
        return (source.to_owned(), 0);
    }
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut count: usize = 0;
    for (start, end) in &removals {
        if *start < cursor {
            continue;
        }
        out.push_str(&source[cursor..*start]);
        cursor = *end;
        count += 1;
    }
    out.push_str(&source[cursor..]);
    (out, count)
}

fn mentions_debugger(region: &str) -> bool {
    region.contains("debugger") || region.contains("'debugger'") || region.contains("\"debugger\"")
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const CHECKER: &str = "const _0xwrap=(function(){let _0xf=!![];return function(_0xa,_0xb){const _0xc=_0xf?function(){if(_0xb){const _0xd=_0xb['apply'](_0xa,arguments);return _0xb=null,_0xd;}}:function(){};return _0xf=![],_0xc;};}()),_0xck=_0xwrap(this,function(){return _0xck['toString']()['search']('(((.+)+)+)+$')['toString']()['constructor'](_0xck)['search']('(((.+)+)+)+$');});_0xck();const keep=1;";

    #[test]
    fn removes_checker_invocation_and_decl() {
        let (out, names): (String, Vec<String>) = remove_checker_blocks(CHECKER);
        assert!(
            !out.contains("(((.+)+)+)+$"),
            "regex literal must be gone: {out}"
        );
        assert!(
            !out.contains("_0xck()"),
            "bare invocation must be gone: {out}"
        );
        assert!(
            out.contains("const keep=1;"),
            "trailing code preserved: {out}"
        );
        assert_eq!(names, vec!["_0xwrap".to_owned()]);
    }

    #[test]
    fn full_strip_removes_wrapper_too() {
        let src: &str = "const _0xwrap=(function(){let _0xf=!![];return function(_0xa,_0xb){return _0xf=![],_0xa;};}());const _0xck=_0xwrap(this,function(){return _0xck['toString']()['search']('(((.+)+)+)+$');});_0xck();work();";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(src);
        assert!(!out.contains("(((.+)+)+)+$"), "checker gone: {out}");
        assert!(!out.contains("_0xwrap"), "wrapper gone: {out}");
        assert!(out.contains("work();"), "real code kept: {out}");
        assert_eq!(stats.checker_blocks, 1);
        assert_eq!(stats.once_wrappers, 1);
    }

    #[test]
    fn leaves_unrelated_code_untouched() {
        let src: &str = "function add(a,b){return a+b;}const s='value';add(1,2);";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(src);
        assert_eq!(out, src);
        assert_eq!(stats.checker_blocks, 0);
        assert_eq!(stats.once_wrappers, 0);
    }

    #[test]
    fn strips_setinterval_debugger_ratchet() {
        let src: &str = "start();setInterval(function(){debugger;},4000);end();";
        let (out, n): (String, usize) = remove_debug_ratchets(src);
        assert_eq!(n, 1);
        assert!(!out.contains("setInterval"), "{out}");
        assert!(out.contains("start();"));
        assert!(out.contains("end();"));
    }

    #[test]
    fn does_not_remove_benign_setinterval() {
        let src: &str = "setInterval(function(){tick();},1000);";
        let (out, n): (String, usize) = remove_debug_ratchets(src);
        assert_eq!(n, 0);
        assert_eq!(out, src);
    }
}
