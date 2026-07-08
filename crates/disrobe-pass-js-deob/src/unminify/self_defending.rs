use serde::Serialize;

use crate::scan_utils::{
    find_brace_close, find_paren_close, find_statement_end, skip_string, skip_ws,
};

const SELF_DEFENDING_REGEX: &str = "(((.+)+)+)+$";
const CONSOLE_HIJACK_MARKER_CONSOLE: &str = ".console=";
const CONSOLE_HIJACK_MARKER_PROTO: &str = ".__proto__=";
const INTEGRITY_INVOCATION_MARKER_REGEXP: &str = "RegExp(";
const INTEGRITY_INVOCATION_MARKER_TEST: &str = ".test(";
const RATCHET_FUNCTION_MARKER_LOOP: &str = "while (true) {}";
const RATCHET_FUNCTION_MARKER_CTOR: &str = "constructor";

fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    find_paren_close(bytes, open + 1)
}

fn is_protection_payload(statement: &str) -> bool {
    statement.contains(SELF_DEFENDING_REGEX)
        || (statement.contains(CONSOLE_HIJACK_MARKER_CONSOLE)
            && statement.contains(CONSOLE_HIJACK_MARKER_PROTO))
        || (statement.contains(INTEGRITY_INVOCATION_MARKER_REGEXP)
            && statement.contains(INTEGRITY_INVOCATION_MARKER_TEST))
}

const RATCHET_RESIDUAL_MAX_LEN: usize = 220;

fn is_ratchet_dispatcher_shape(
    source: &str,
    bytes: &[u8],
    outer_brace_open: usize,
    outer_brace_close: usize,
) -> bool {
    let mut search_from: usize = outer_brace_open + 1;
    while search_from < outer_brace_close {
        let Some(rel): Option<usize> = source[search_from..outer_brace_close].find("function ")
        else {
            return false;
        };
        let inner_kw_start: usize = search_from + rel;
        search_from = inner_kw_start + "function ".len();
        if is_ident_byte(bytes[inner_kw_start - 1]) {
            continue;
        }
        let inner_name_start: usize = inner_kw_start + "function ".len();
        let mut inner_name_end: usize = inner_name_start;
        while inner_name_end < bytes.len() && is_ident_byte(bytes[inner_name_end]) {
            inner_name_end += 1;
        }
        if inner_name_end == inner_name_start {
            continue;
        }
        let inner_name: &str = &source[inner_name_start..inner_name_end];
        let inner_paren_open: usize = skip_ws(bytes, inner_name_end);
        if bytes.get(inner_paren_open) != Some(&b'(') {
            continue;
        }
        let Some(inner_paren_close): Option<usize> = find_paren_close(bytes, inner_paren_open + 1)
        else {
            continue;
        };
        let inner_brace_open: usize = skip_ws(bytes, inner_paren_close + 1);
        if bytes.get(inner_brace_open) != Some(&b'{') {
            continue;
        }
        let Some(inner_brace_close): Option<usize> = find_brace_close(bytes, inner_brace_open + 1)
        else {
            continue;
        };
        if inner_brace_close >= outer_brace_close {
            continue;
        }
        let inner_body: &str = &source[inner_brace_open..=inner_brace_close];
        if !inner_body.contains(RATCHET_FUNCTION_MARKER_LOOP)
            || !inner_body.contains(RATCHET_FUNCTION_MARKER_CTOR)
            || !inner_body.contains(inner_name)
        {
            continue;
        }
        let residual_start: usize = inner_brace_close + 1;
        if residual_start > outer_brace_close {
            continue;
        }
        let residual: &str = source[residual_start..outer_brace_close].trim();
        if residual.len() > RATCHET_RESIDUAL_MAX_LEN {
            continue;
        }
        if (residual.starts_with("try{") || residual.starts_with("try {"))
            && residual.contains("catch")
            && residual.contains(inner_name)
        {
            return true;
        }
    }
    false
}

const RETURN_LITERALS: &[&str] = &["![]", "!![]", "true", "false"];

fn remove_discarded_constructor_apply_statements(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("(function(){return") {
        let stmt_start: usize = from + rel;
        let after_kw: usize = stmt_start + "(function(){return".len();
        from = after_kw;
        let after_return: usize = skip_ws(bytes, after_kw);
        let Some(ret_lit_end): Option<usize> = RETURN_LITERALS.iter().find_map(|lit: &&str| {
            source[after_return..]
                .starts_with(*lit)
                .then(|| after_return + lit.len())
        }) else {
            continue;
        };
        let semi: usize = skip_ws(bytes, ret_lit_end);
        if bytes.get(semi) != Some(&b';') {
            continue;
        }
        let close_fn_body: usize = skip_ws(bytes, semi + 1);
        if bytes.get(close_fn_body) != Some(&b'}') {
            continue;
        }
        let after_body: usize = close_fn_body + 1;
        let ctor_start: usize = if source[after_body..].starts_with("['constructor']") {
            after_body + "['constructor']".len()
        } else if source[after_body..].starts_with(".constructor") {
            after_body + ".constructor".len()
        } else {
            continue;
        };
        if bytes.get(ctor_start) != Some(&b'(') {
            continue;
        }
        let Some(ctor_close): Option<usize> = find_paren_close(bytes, ctor_start + 1) else {
            continue;
        };
        let after_ctor: usize = ctor_close + 1;
        let invoke_start: usize = if source[after_ctor..].starts_with("['apply']") {
            after_ctor + "['apply']".len()
        } else if source[after_ctor..].starts_with(".apply") {
            after_ctor + ".apply".len()
        } else if source[after_ctor..].starts_with("['call']") {
            after_ctor + "['call']".len()
        } else if source[after_ctor..].starts_with(".call") {
            after_ctor + ".call".len()
        } else {
            continue;
        };
        if bytes.get(invoke_start) != Some(&b'(') {
            continue;
        }
        let Some(invoke_close): Option<usize> = find_paren_close(bytes, invoke_start + 1) else {
            continue;
        };
        let after_invoke: usize = skip_ws(bytes, invoke_close + 1);
        if bytes.get(after_invoke) != Some(&b')') {
            continue;
        }
        let mut end: usize = after_invoke + 1;
        if bytes.get(end) == Some(&b';') {
            end += 1;
        }
        removals.push((stmt_start, end));
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
        out.push(';');
        cursor = *end;
        count += 1;
    }
    out.push_str(&source[cursor..]);
    (out, count)
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize)]
pub(super) struct SelfDefendingStats {
    pub(super) checker_blocks: usize,
    pub(super) once_wrappers: usize,
    pub(super) debug_ratchets: usize,
    pub(super) ratchet_functions: usize,
    pub(super) discarded_constructor_calls: usize,
}

pub(super) fn strip_self_defending(source: &str) -> (String, SelfDefendingStats) {
    let mut stats: SelfDefendingStats = SelfDefendingStats::default();
    let (after_checker, checker_names): (String, Vec<String>) = remove_checker_blocks(source);
    stats.checker_blocks = checker_names.len();
    let (after_wrapper, wrapper_removed): (String, usize) =
        remove_once_wrappers(&after_checker, &checker_names);
    stats.once_wrappers = wrapper_removed;
    let (after_iife, iife_removed): (String, usize) =
        remove_integrity_invocation_iifes(&after_wrapper);
    stats.checker_blocks += iife_removed;
    let (after_ratchet_fn, ratchet_fn_removed): (String, usize) =
        remove_ratchet_functions(&after_iife);
    stats.ratchet_functions = ratchet_fn_removed;
    let (after_ctor_call, ctor_call_removed): (String, usize) =
        remove_discarded_constructor_apply_statements(&after_ratchet_fn);
    stats.discarded_constructor_calls = ctor_call_removed;
    let (after_debug, debug_removed): (String, usize) = remove_debug_ratchets(&after_ctor_call);
    stats.debug_ratchets = debug_removed;
    (after_debug, stats)
}

fn enclosing_bare_iife(source: &str, inner_pos: usize) -> Option<(usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let outer_open: usize = source[..inner_pos].rfind("(function(")?;
    let fn_paren: usize = outer_open + "(function".len();
    if bytes.get(fn_paren) != Some(&b'(') {
        return None;
    }
    let params_close: usize = find_paren_close(bytes, fn_paren + 1)?;
    let brace_open: usize = skip_ws(bytes, params_close + 1);
    if bytes.get(brace_open) != Some(&b'{') {
        return None;
    }
    let brace_close: usize = find_brace_close(bytes, brace_open + 1)?;
    if !(brace_open < inner_pos && inner_pos < brace_close) {
        return None;
    }
    let after_body: usize = skip_ws(bytes, brace_close + 1);
    let final_close: usize = if bytes.get(after_body) == Some(&b'(') {
        let call_close: usize = find_paren_close(bytes, after_body + 1)?;
        let wrap_close: usize = skip_ws(bytes, call_close + 1);
        if bytes.get(wrap_close) != Some(&b')') {
            return None;
        }
        wrap_close
    } else if bytes.get(after_body) == Some(&b')') {
        let call_open: usize = skip_ws(bytes, after_body + 1);
        if bytes.get(call_open) != Some(&b'(') {
            return None;
        }
        find_paren_close(bytes, call_open + 1)?
    } else {
        return None;
    };
    let mut end: usize = final_close + 1;
    if bytes.get(end) == Some(&b';') {
        end += 1;
    }
    Some((outer_open, end))
}

fn remove_integrity_invocation_iifes(source: &str) -> (String, usize) {
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("(this,") {
        let call_open: usize = from + rel;
        from = call_open + "(this,".len();
        let Some((iife_start, iife_end)): Option<(usize, usize)> =
            enclosing_bare_iife(source, call_open)
        else {
            continue;
        };
        let body: &str = &source[iife_start..iife_end];
        if !is_protection_payload(body) {
            continue;
        }
        removals.push((iife_start, iife_end));
    }
    if removals.is_empty() {
        return (source.to_owned(), 0);
    }
    removals.sort_by_key(|r: &(usize, usize)| r.0);
    removals.dedup();
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

fn remove_ratchet_functions(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("function ") {
        let kw_start: usize = from + rel;
        from = kw_start + "function ".len();
        if kw_start != 0 && is_ident_byte(bytes[kw_start - 1]) {
            continue;
        }
        let name_start: usize = kw_start + "function ".len();
        let mut name_end: usize = name_start;
        while name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            continue;
        }
        let paren_open: usize = skip_ws(bytes, name_end);
        if bytes.get(paren_open) != Some(&b'(') {
            continue;
        }
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            continue;
        };
        let brace_open: usize = skip_ws(bytes, paren_close + 1);
        if bytes.get(brace_open) != Some(&b'{') {
            continue;
        }
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            continue;
        };
        if !is_ratchet_dispatcher_shape(source, bytes, brace_open, brace_close) {
            continue;
        }
        let mut end: usize = brace_close + 1;
        if bytes.get(end) == Some(&b';') {
            end += 1;
        }
        let outer_name: &str = &source[name_start..name_end];
        if identifier_referenced_outside(source, outer_name, kw_start, end) {
            continue;
        }
        removals.push((kw_start, end));
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

fn identifier_referenced_outside(
    source: &str,
    name: &str,
    excl_start: usize,
    excl_end: usize,
) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes: &[u8] = source.as_bytes();
    let mut search_from: usize = 0;
    while let Some(rel) = source[search_from..].find(name) {
        let match_start: usize = search_from + rel;
        let match_end: usize = match_start + name.len();
        search_from = match_end;
        if match_start >= excl_start && match_end <= excl_end {
            continue;
        }
        let before_is_boundary: bool = match_start == 0 || !is_ident_byte(bytes[match_start - 1]);
        let after_is_boundary: bool = match_end >= bytes.len() || !is_ident_byte(bytes[match_end]);
        if before_is_boundary && after_is_boundary {
            return true;
        }
    }
    false
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
    if !is_protection_payload(&source[stmt_start..stmt_semi]) {
        return None;
    }
    let decl_terminator: usize = stmt_semi + 1;
    let end: usize =
        find_bare_invocation(bytes, stmt_semi, &checker_name).unwrap_or(decl_terminator);
    if any_declared_name_escapes(source, stmt_start, end) {
        return None;
    }
    Some(CheckerRemoval {
        start: stmt_start,
        end,
        wrapper_name,
    })
}

fn any_declared_name_escapes(source: &str, start: usize, end: usize) -> bool {
    declared_names_in_range(source, start, end)
        .iter()
        .any(|name: &String| identifier_referenced_outside(source, name, start, end))
}

fn declared_names_in_range(source: &str, start: usize, end: usize) -> Vec<String> {
    let bytes: &[u8] = source.as_bytes();
    let mut names: Vec<String> = Vec::new();
    let Some(kw_len): Option<usize> = ["const ", "let ", "var "]
        .iter()
        .find(|kw: &&&str| source[start..end.min(source.len())].starts_with(*kw))
        .map(|kw: &&str| kw.len())
    else {
        return names;
    };
    let mut cursor: usize = skip_ws(bytes, start + kw_len);
    loop {
        let name_start: usize = cursor;
        let mut name_end: usize = name_start;
        while name_end < end && name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            break;
        }
        names.push(source[name_start..name_end].to_owned());
        let after_name: usize = skip_ws(bytes, name_end);
        if bytes.get(after_name) != Some(&b'=') {
            break;
        }
        let Some(comma): Option<usize> = find_top_level_comma(bytes, after_name + 1, end) else {
            break;
        };
        cursor = skip_ws(bytes, comma + 1);
        if cursor >= end {
            break;
        }
    }
    names
}

fn find_top_level_comma(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut i: usize = start;
    let (mut paren, mut bracket, mut brace): (i32, i32, i32) = (0, 0, 0);
    while i < limit && i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
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

    const CHECKER_SHARING_CONST_WITH_A_DATA_TABLE_SIBLING: &str = "const bigTable={'a':1,'b':2},wrap=(function(){let f=!![];return function(a,b){const c=f?function(){if(b){const d=b.apply(a,arguments);return b=null,d;}}:function(){};return f=![],c;};}()),ck=wrap(this,function(){return ck.toString().search('(((.+)+)+)+$');});ck();console.log(bigTable.a);";

    #[test]
    fn checker_sharing_a_const_statement_with_a_live_sibling_table_is_kept() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(CHECKER_SHARING_CONST_WITH_A_DATA_TABLE_SIBLING);
        assert!(
            out.contains("bigTable={"),
            "the sibling data table sharing the const keyword must survive because it is used after the checker: {out}"
        );
        assert!(
            out.contains("console.log(bigTable.a)"),
            "the real usage site must remain resolvable, not dangling: {out}"
        );
        assert_eq!(
            stats.checker_blocks, 0,
            "removing the checker here would delete bigTable's own declaration and leave console.log(bigTable.a) dangling"
        );
    }

    const DEDUPED_SECOND_LITERAL_CHECKER: &str = "const var_60=(function(){let var_61=!![];return function(var_62,var_63){const var_64=var_61?function(){if(var_63){const var_65=var_63.apply(var_62,arguments);return var_63=null,var_65;}}:function(){};return var_61=![],var_64;};}()),var_66=var_60(this,function(){return var_66.toString().search('(((.+)+)+)+$').toString().constructor(var_66).search(var_33.EOhGV);});var_66();const keep=1;";

    #[test]
    fn checker_with_object_transform_deduped_second_literal_is_removed() {
        let (out, names): (String, Vec<String>) =
            remove_checker_blocks(DEDUPED_SECOND_LITERAL_CHECKER);
        assert!(
            !out.contains("(((.+)+)+)+$"),
            "regex literal must be gone: {out}"
        );
        assert!(
            out.contains("const keep=1;"),
            "trailing code preserved: {out}"
        );
        assert_eq!(names, vec!["var_60".to_owned()]);
    }

    const CONSOLE_HIJACK: &str = "const _0xwrap=(function(){let _0xf=!![];return function(_0xa,_0xb){const _0xc=_0xf?function(){if(_0xb){const _0xd=_0xb.apply(_0xa,arguments);return _0xb=null,_0xd;}}:function(){};return _0xf=![],_0xc;};}()),_0xck=_0xwrap(this,function(){let _0xg;try{const _0xh=Function('return (function() {}.constructor(\"return this\")( ));');_0xg=_0xh();}catch(_0xi){_0xg=window;}const _0xj=_0xg.console=_0xg.console||{},_0xk=['log','warn','info','error','exception','table','trace'];for(let _0xl=0;_0xl<_0xk.length;_0xl++){const _0xm=_0xwrap.constructor.prototype.bind(_0xwrap),_0xn=_0xk[_0xl],_0xo=_0xj[_0xn]||_0xm;_0xm.__proto__=_0xwrap.bind(_0xwrap),_0xm.toString=_0xo.toString.bind(_0xo),_0xj[_0xn]=_0xm;}});_0xck();console.log('real');";

    #[test]
    fn console_output_hijack_payload_is_removed() {
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(CONSOLE_HIJACK);
        assert!(
            !out.contains(".console="),
            "console reassignment must be gone: {out}"
        );
        assert!(
            !out.contains("__proto__"),
            "prototype hijack must be gone: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code must survive: {out}"
        );
        assert_eq!(
            stats.checker_blocks, 1,
            "the combined wrapper+hijack declarator statement is removed as one checker block"
        );
    }

    const DISCARDED_CONSTRUCTOR_APPLY_WITH_DANGLING_PROXY_ARGS: &str = "function divide(a,b){const proxy={};proxy.op=function(x,y){return x===y;};if(proxy.op(b,0)){if(proxy.op('same','other'))(function(){return![];}['constructor'](KmPGMW.build(KmPGMW.debu,KmPGMW.gger)).apply(KmPGMW.target));else throw new Error('divide by zero');}return a/b;}console.log('real');";

    #[test]
    fn discarded_constructor_apply_call_is_removed_even_with_dangling_proxy_args() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(DISCARDED_CONSTRUCTOR_APPLY_WITH_DANGLING_PROXY_ARGS);
        assert!(
            !out.contains("KmPGMW"),
            "the discarded constructor+apply statement and its dangling proxy args must be gone: {out}"
        );
        assert!(
            out.contains("function divide(a,b)"),
            "the real divide function must survive: {out}"
        );
        assert!(
            out.contains("throw new Error('divide by zero')"),
            "the real throw branch must survive: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code after the function must survive: {out}"
        );
        assert_eq!(stats.discarded_constructor_calls, 1);
    }

    #[test]
    fn discarded_constructor_apply_as_unbraced_if_branch_keeps_valid_syntax() {
        let src: &str = "function f(cond){if(cond)(function(){return!![];}['constructor'](proxy.a(proxy.b,proxy.c)).call(proxy.d));else{real();}}";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(src);
        assert!(
            !out.contains("proxy"),
            "the discarded statement must be gone: {out}"
        );
        assert!(
            out.contains("if(cond);else{real();}") || out.contains("if(cond) ;else{real();}"),
            "the if-branch slot must be replaced with an empty statement, not deleted outright, or the else becomes a syntax error: {out}"
        );
        assert_eq!(stats.discarded_constructor_calls, 1);
    }

    const NESTED_INTEGRITY_INVOCATION_AND_RATCHET_FUNCTION: &str = "function add(a,b){return a+b;}function greet(name){const wrap=(function(){let f=!![];return function(a,b){const c=f?function(){if(b){const d=b.apply(a,arguments);return b=null,d;}}:function(){};return f=![],c;};}());(function(){wrap(this,function(){const r1=new RegExp('function *\\\\( *\\\\)'),r2=new RegExp('\\\\+\\\\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)','i'),probe=ratchet('init');!r1.test(probe+'chain')||!r2.test(probe+'input')?probe('0'):ratchet();})();}());const banner='hi';return banner+' :: '+name;}function ratchet(seed){function tick(counter){if(typeof counter==='string')return function(){}['constructor']('while (true) {}').apply('counter');else(''+counter/counter).length!==1||counter%20===0?function(){return!![];}['constructor']('debugger').call('action'):function(){return![];}['constructor']('debugger').apply('stateObject');tick(++counter);}try{if(seed)return tick;else tick(0);}catch(e){}}console.log(greet('real'));";

    #[test]
    fn nested_integrity_invocation_and_ratchet_function_are_removed() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(NESTED_INTEGRITY_INVOCATION_AND_RATCHET_FUNCTION);
        assert!(
            !out.contains("while (true) {}"),
            "ratchet loop must be gone: {out}"
        );
        assert!(
            !out.contains("function ratchet"),
            "ratchet function must be gone: {out}"
        );
        assert!(
            !out.contains("RegExp("),
            "integrity invocation must be gone: {out}"
        );
        assert!(
            !out.contains("ratchet("),
            "no dangling call site to the removed ratchet function may remain: {out}"
        );
        assert!(
            out.contains("console.log(greet('real'))"),
            "real code must survive: {out}"
        );
        assert!(
            out.contains("function add(a,b){return a+b;}"),
            "unrelated code preserved: {out}"
        );
        assert_eq!(stats.ratchet_functions, 1);
    }

    const RATCHET_FUNCTION_PRECEDED_BY_PROXY_TABLE: &str = "function ratchet(seed){const table={'a':function(x,y){return x===y;},'b':'divide by zero','c':function(x,y){return x/y;}};function tick(counter){if(typeof counter==='string')return function(){}['constructor']('while (true) {}').apply('counter');else(''+counter/counter).length!==1||counter%20===0?function(){return!![]}['constructor']('debugger').call('action'):function(){return![];}['constructor']('debugger').apply('stateObject');tick(++counter);}try{if(seed)return tick;else tick(0);}catch(e){}}console.log('real');";

    #[test]
    fn ratchet_function_preceded_by_object_transform_proxy_table_is_removed() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(RATCHET_FUNCTION_PRECEDED_BY_PROXY_TABLE);
        assert!(
            !out.contains("while (true) {}"),
            "ratchet loop must be gone: {out}"
        );
        assert!(
            !out.contains("function ratchet"),
            "whole ratchet function must be gone: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code must survive: {out}"
        );
        assert_eq!(stats.ratchet_functions, 1);
    }

    const RATCHET_FUNCTION_REFERENCED_BY_EXTERNAL_SETINTERVAL_CALLBACK: &str = "(function(){const timer=makeTimer();timer.setInterval(watchdog,4000);}());function watchdog(seed){function tick(counter){if(typeof counter==='string')return function(){}['constructor']('while (true) {}').apply('counter');else(''+counter/counter).length!==1||counter%20===0?function(){return!![]}['constructor']('debugger').call('action'):function(){return![];}['constructor']('debugger').apply('stateObject');tick(++counter);}try{if(seed)return tick;else tick(0);}catch(e){}}console.log('real');";

    #[test]
    fn ratchet_function_referenced_by_external_setinterval_callback_is_kept() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(RATCHET_FUNCTION_REFERENCED_BY_EXTERNAL_SETINTERVAL_CALLBACK);
        assert!(
            out.contains("function watchdog"),
            "the outer ratchet-shaped function must survive because setInterval still holds a live reference to it by name: {out}"
        );
        assert!(
            out.contains("timer.setInterval(watchdog,4000)"),
            "the external callback reference must remain resolvable, not dangling: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code must survive: {out}"
        );
        assert_eq!(
            stats.ratchet_functions, 0,
            "deleting watchdog here would leave the setInterval callback argument dangling"
        );
    }

    const REAL_FUNCTION_WITH_ANONYMOUS_ONCE_WRAPPERS_IS_NOT_A_RATCHET: &str = "function greet(name){const table={'a':function(x,y){return x+y;},'b':' :: hi, '};const once=(function(){let f=!![];return function(a,b){const c=f?function(){if(b){const d=b.apply(a,arguments);return b=null,d;}}:function(){};return f=![],c;};}());const guard=table.a(once,this,function(){return guard.toString();});table.a(guard);const banner=table.a('calc',table.b);return table.a(banner,name);}";

    #[test]
    fn real_function_with_only_anonymous_once_wrappers_is_not_removed_as_a_ratchet() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(REAL_FUNCTION_WITH_ANONYMOUS_ONCE_WRAPPERS_IS_NOT_A_RATCHET);
        assert_eq!(
            stats.ratchet_functions, 0,
            "a function whose only nested closures are anonymous once-wrappers, not a named self-recursive dispatcher, must never be deleted whole: {out}"
        );
        assert!(
            out.contains("function greet(name)"),
            "the real function declaration must survive: {out}"
        );
    }

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
