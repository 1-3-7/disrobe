use std::collections::BTreeMap;
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use crate::scan_utils::{find_brace_close, find_paren_close, skip_string};

#[derive(Debug, Clone, Serialize)]
pub(super) struct ControlFlowObjectResult {
    pub objects_merged: usize,
    pub call_sites_inlined: usize,
    pub rewritten_source: String,
}

#[derive(Debug, Clone)]
enum PropValue {
    StringLiteral(String),
    BinaryOp {
        params: Vec<String>,
        left: String,
        op: String,
        right: String,
    },
    LogicalOp {
        params: Vec<String>,
        left: String,
        op: String,
        right: String,
    },
    CallForward {
        arity: usize,
    },
    RestForward,
}

#[derive(Debug, Clone)]
struct CfObject {
    var: String,
    aliases: Vec<String>,
    decl_range: Range<usize>,
    decl_replacement: String,
    props: BTreeMap<String, PropValue>,
}

#[must_use]
pub(super) fn merge_control_flow_objects(source: &str) -> ControlFlowObjectResult {
    let objects: Vec<CfObject> = collect_objects(source);
    if objects.is_empty() {
        return passthrough(source);
    }
    let guarded: Vec<Range<usize>> = self_defending_spans(source);

    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut objects_merged: usize = 0;
    let mut call_sites_inlined: usize = 0;

    for obj in &objects {
        if guarded
            .iter()
            .any(|g: &Range<usize>| g.start <= obj.decl_range.start && obj.decl_range.end <= g.end)
        {
            continue;
        }
        let refs: Vec<MemberRef> = collect_member_refs(source, obj);
        if refs.is_empty() {
            continue;
        }
        if refs.iter().any(|r: &MemberRef| {
            guarded.iter().any(|g: &Range<usize>| {
                g.start <= r.member_range.start && r.member_range.end <= g.end
            })
        }) {
            continue;
        }
        if reassigned_outside_decl(source, obj) {
            continue;
        }
        let mut obj_names: Vec<String> = Vec::with_capacity(1 + obj.aliases.len());
        obj_names.push(obj.var.clone());
        obj_names.extend(obj.aliases.iter().cloned());
        let mut local_inlined: usize = 0;
        let mut local_edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
        let mut unresolved: usize = 0;
        for r in &refs {
            let Some(value): Option<&PropValue> = obj.props.get(&r.key) else {
                unresolved += 1;
                continue;
            };
            match render_ref(value, r, &obj_names, &obj.props) {
                Some((range, text)) => {
                    local_edits.push((range, Some(text)));
                    local_inlined += 1;
                }
                None => unresolved += 1,
            }
        }
        if local_inlined == 0 {
            continue;
        }
        let keep_decl: bool = unresolved > 0;
        edits.append(&mut local_edits);
        if !keep_decl {
            edits.push((obj.decl_range.clone(), Some(obj.decl_replacement.clone())));
        }
        objects_merged += 1;
        call_sites_inlined += local_inlined;
    }

    if edits.is_empty() {
        return passthrough(source);
    }
    let (rewritten, _): (String, usize) = apply_edits(source, &mut edits);
    ControlFlowObjectResult {
        objects_merged,
        call_sites_inlined,
        rewritten_source: rewritten,
    }
}

fn self_defending_spans(source: &str) -> Vec<Range<usize>> {
    let bytes: &[u8] = source.as_bytes();
    let markers: &[&str] = &[
        "['apply'](",
        "[\"apply\"](",
        "['constructor'](",
        "['search'](",
        "while(!![])",
        "while (!![])",
    ];
    let mut spans: Vec<Range<usize>> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(close) = find_brace_close(bytes, i + 1)
        {
            let body: &str = &source[i + 1..close];
            if markers.iter().any(|m: &&str| body.contains(m)) {
                let start: usize = block_owner_start(bytes, i);
                spans.push(start..close + 1);
                i = close + 1;
                continue;
            }
        }
        i += 1;
    }
    merge_ranges(spans)
}

fn block_owner_start(bytes: &[u8], brace_open: usize) -> usize {
    let mut i: usize = brace_open;
    let mut paren: i32 = 0;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => paren += 1,
            b'(' => {
                if paren == 0 {
                    return i;
                }
                paren -= 1;
            }
            b';' | b'}' if paren == 0 => return i + 1,
            _ => {}
        }
    }
    0
}

fn merge_ranges(mut spans: Vec<Range<usize>>) -> Vec<Range<usize>> {
    spans.sort_by_key(|r: &Range<usize>| r.start);
    let mut out: Vec<Range<usize>> = Vec::with_capacity(spans.len());
    for r in spans {
        match out.last_mut() {
            Some(last) if r.start <= last.end => {
                if r.end > last.end {
                    last.end = r.end;
                }
            }
            _ => out.push(r),
        }
    }
    out
}

fn passthrough(source: &str) -> ControlFlowObjectResult {
    ControlFlowObjectResult {
        objects_merged: 0,
        call_sites_inlined: 0,
        rewritten_source: source.to_owned(),
    }
}

fn collect_objects(source: &str) -> Vec<CfObject> {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?:(?:var|let|const)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*\{")
    else {
        return Vec::new();
    };
    let bytes: &[u8] = source.as_bytes();
    let mut out: Vec<CfObject> = Vec::new();
    let mut consumed_until: usize = 0;
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        if whole.start() < consumed_until {
            continue;
        }
        let Some(var): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let is_comma_decl: bool = source[whole.start()..=whole.start()] == *","
            && comma_is_inside_declaration(bytes, whole.start());
        let brace_open: usize = whole.end() - 1;
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            continue;
        };
        let body: &str = &source[brace_open + 1..brace_close];
        let mut props: BTreeMap<String, PropValue> = if body.trim().is_empty() {
            BTreeMap::new()
        } else {
            match parse_props(body) {
                Some(p) => p,
                None => continue,
            }
        };
        let mut end: usize = brace_close + 1;
        if bytes.get(end) == Some(&b';') {
            end += 1;
        }
        let assigned_end: usize = collect_assigned_props(source, var, end, &mut props);
        if props.is_empty() {
            continue;
        }
        let (aliases, alias_end): (Vec<String>, usize) = collect_aliases(source, var, assigned_end);
        let keyword: &str = if is_comma_decl {
            ""
        } else {
            caps.get(0)
                .map(|m: regex::Match<'_>| m.as_str())
                .and_then(|s: &str| s.split_whitespace().next())
                .unwrap_or("var")
        };
        let next_nonws: usize = skip_ws(bytes, alias_end);
        let (range_start, range_end, decl_replacement): (usize, usize, String) = if is_comma_decl {
            (whole.start(), alias_end, String::new())
        } else if bytes.get(next_nonws) == Some(&b',') {
            (whole.start(), next_nonws + 1, format!("{keyword} "))
        } else {
            (whole.start(), alias_end, String::new())
        };
        consumed_until = range_end;
        out.push(CfObject {
            var: var.to_owned(),
            aliases,
            decl_range: range_start..range_end,
            decl_replacement,
            props,
        });
    }
    out
}

fn comma_is_inside_declaration(bytes: &[u8], comma_pos: usize) -> bool {
    let mut i: usize = comma_pos;
    let mut paren: i32 = 0;
    let mut brace: i32 = 0;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => paren += 1,
            b'(' => {
                if paren == 0 {
                    return false;
                }
                paren -= 1;
            }
            b'}' => {
                if brace == 0 {
                    return false;
                }
                brace -= 1;
            }
            b'{' => brace += 1,
            b';' if paren == 0 && brace == 0 => return false,
            _ if paren == 0 && brace == 0 => {
                let slice: &[u8] = &bytes[..=i];
                let trimmed: &[u8] = slice.trim_ascii_end();
                if trimmed.ends_with(b"var")
                    || trimmed.ends_with(b"let")
                    || trimmed.ends_with(b"const")
                {
                    return true;
                }
                if bytes[i] == b',' || bytes[i] == b'=' {
                    continue;
                }
                if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$' {
                    continue;
                }
                if matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b'\'' | b'"') {
                    continue;
                }
                return false;
            }
            _ => {}
        }
    }
    false
}

fn collect_assigned_props(
    source: &str,
    var: &str,
    start: usize,
    props: &mut BTreeMap<String, PropValue>,
) -> usize {
    let assign_re: Regex = match Regex::new(&format!(
        r#"^\s*{}(?:\.([A-Za-z]{{5}})|\[\s*['"]([A-Za-z]{{5}})['"]\s*\])\s*=\s*"#,
        regex::escape(var)
    )) {
        Ok(re) => re,
        Err(_) => return start,
    };
    let bytes: &[u8] = source.as_bytes();
    let mut cursor: usize = start;
    loop {
        let rest: &str = &source[cursor..];
        let Some(caps): Option<regex::Captures<'_>> = assign_re.captures(rest) else {
            break;
        };
        let key: String = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m: regex::Match<'_>| m.as_str().to_owned())
            .unwrap_or_default();
        if key.is_empty() {
            break;
        }
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            break;
        };
        let value_start: usize = cursor + whole.end();
        let Some(value_end): Option<usize> = scan_statement_value_end(bytes, value_start) else {
            break;
        };
        let value_raw: &str = source[value_start..value_end].trim();
        let Some(value): Option<PropValue> = parse_value(value_raw) else {
            break;
        };
        props.entry(key).or_insert(value);
        let mut next: usize = value_end;
        if matches!(bytes.get(next), Some(&(b';' | b','))) {
            next += 1;
        }
        cursor = skip_ws(bytes, next);
    }
    cursor
}

fn scan_statement_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let (mut paren, mut bracket, mut brace): (i32, i32, i32) = (0, 0, 0);
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, b)?;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => {
                if brace == 0 {
                    return Some(i);
                }
                brace -= 1;
            }
            b';' | b',' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    Some(bytes.len())
}

fn collect_aliases(source: &str, var: &str, start: usize) -> (Vec<String>, usize) {
    let alias_re: Regex = match Regex::new(&format!(
        r"^\s*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*{}\s*[;,]",
        regex::escape(var)
    )) {
        Ok(re) => re,
        Err(_) => return (Vec::new(), start),
    };
    let mut aliases: Vec<String> = Vec::new();
    let mut cursor: usize = start;
    let bytes: &[u8] = source.as_bytes();
    loop {
        let rest: &str = &source[cursor..];
        let Some(caps): Option<regex::Captures<'_>> = alias_re.captures(rest) else {
            break;
        };
        let Some(alias): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            break;
        };
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            break;
        };
        aliases.push(alias.to_owned());
        cursor = skip_ws(bytes, cursor + whole.end());
    }
    (aliases, cursor)
}

fn parse_props(body: &str) -> Option<BTreeMap<String, PropValue>> {
    let entries: Vec<(String, String)> = split_object_entries(body)?;
    let mut map: BTreeMap<String, PropValue> = BTreeMap::new();
    let mut parsed_any: bool = false;
    for (key_raw, value_raw) in entries {
        let key: String = unquote_key(&key_raw)?;
        if key.len() != 5 || !key.chars().all(|c: char| c.is_ascii_alphabetic()) {
            return None;
        }
        if let Some(value) = parse_value(value_raw.trim()) {
            map.insert(key, value);
            parsed_any = true;
        }
    }
    if !parsed_any {
        return None;
    }
    Some(map)
}

fn split_object_entries(body: &str) -> Option<Vec<(String, String)>> {
    let bytes: &[u8] = body.as_bytes();
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        i = skip_ws(bytes, i);
        if i >= bytes.len() {
            break;
        }
        let key_start: usize = i;
        let quote: u8 = bytes[i];
        let key_end: usize = if matches!(quote, b'\'' | b'"') {
            skip_string(bytes, i, quote)?
        } else {
            let mut j: usize = i;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            j
        };
        let key_raw: String = body[key_start..key_end].to_owned();
        i = skip_ws(bytes, key_end);
        if i >= bytes.len() || bytes[i] != b':' {
            return None;
        }
        i += 1;
        i = skip_ws(bytes, i);
        let value_start: usize = i;
        let value_end: usize = scan_value_end(bytes, i)?;
        let value_raw: String = body[value_start..value_end].to_owned();
        entries.push((key_raw, value_raw));
        i = skip_ws(bytes, value_end);
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
        }
    }
    Some(entries)
}

fn scan_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, b)?;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => {
                if brace == 0 {
                    return Some(i);
                }
                brace -= 1;
            }
            b',' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    Some(bytes.len())
}

fn unquote_key(raw: &str) -> Option<String> {
    let trimmed: &str = raw.trim();
    let bytes: &[u8] = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if matches!(bytes[0], b'\'' | b'"') && bytes.len() >= 2 {
        Some(trimmed[1..trimmed.len() - 1].to_owned())
    } else {
        Some(trimmed.to_owned())
    }
}

fn parse_value(value: &str) -> Option<PropValue> {
    if let Some(lit) = string_literal_value(value) {
        return Some(PropValue::StringLiteral(lit));
    }
    parse_function_value(value)
}

fn string_literal_value(value: &str) -> Option<String> {
    let bytes: &[u8] = value.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let quote: u8 = bytes[0];
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let end: usize = skip_string(bytes, 0, quote)?;
    if end != bytes.len() {
        return None;
    }
    Some(value.to_owned())
}

fn parse_function_value(value: &str) -> Option<PropValue> {
    let re: Regex =
        Regex::new(r"^function\s*\(([^)]*)\)\s*\{\s*return\s+([\s\S]+?);?\s*\}$").ok()?;
    let caps: regex::Captures<'_> = re.captures(value.trim())?;
    let params_raw: &str = caps.get(1)?.as_str();
    let ret: &str = caps.get(2)?.as_str().trim();
    let params: Vec<String> = split_params(params_raw);
    classify_return(&params, ret)
}

fn split_params(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s: &str| s.trim().to_owned())
        .filter(|s: &String| !s.is_empty())
        .collect()
}

fn classify_return(params: &[String], ret: &str) -> Option<PropValue> {
    if params.len() == 2 {
        if let Some(rest) = params[1].strip_prefix("...") {
            let pattern: String = format!(
                r"^([A-Za-z_$][\w$]*)\s*\(\s*\.\.\.\s*{}\s*\)$",
                regex::escape(rest)
            );
            if let Ok(re) = Regex::new(&pattern)
                && let Some(caps) = re.captures(&normalize_ws(ret))
                && let Some(callee) = caps.get(1)
                && callee.as_str() == params[0]
            {
                return Some(PropValue::RestForward);
            }
        }
        if let Some(v) = binary_or_logical(params, ret) {
            return Some(v);
        }
    }
    if let Some(v) = call_forward(params, ret) {
        return Some(v);
    }
    None
}

fn binary_or_logical(params: &[String], ret: &str) -> Option<PropValue> {
    let a: &str = &params[0];
    let b: &str = &params[1];
    let norm: String = normalize_ws(ret);
    for op in [
        "+", "-", "*", "/", "%", "&&", "||", "<=", ">=", "===", "!==", "==", "!=", "<", ">",
    ] {
        let direct: String = format!("{a}{op}{b}");
        let spaced: String = format!("{a} {op} {b}");
        let rev: String = format!("{b}{op}{a}");
        let rev_spaced: String = format!("{b} {op} {a}");
        if norm == direct || norm == spaced {
            return Some(make_op(op, "0", "1", params));
        }
        if (op == "+" || op == "*" || op == "&&" || op == "||" || op == "==" || op == "===")
            && (norm == rev || norm == rev_spaced)
        {
            return Some(make_op(op, "1", "0", params));
        }
    }
    None
}

fn make_op(op: &str, left: &str, right: &str, params: &[String]) -> PropValue {
    if op == "&&" || op == "||" {
        PropValue::LogicalOp {
            params: params.to_vec(),
            left: left.to_owned(),
            op: op.to_owned(),
            right: right.to_owned(),
        }
    } else {
        PropValue::BinaryOp {
            params: params.to_vec(),
            left: left.to_owned(),
            op: op.to_owned(),
            right: right.to_owned(),
        }
    }
}

fn call_forward(params: &[String], ret: &str) -> Option<PropValue> {
    if params.is_empty() {
        return None;
    }
    let callee: &str = &params[0];
    let prefix: String = format!("{callee}(");
    let norm: String = normalize_ws(ret);
    let body: &str = norm.strip_prefix(&prefix)?.strip_suffix(')')?;
    let call_args: Vec<String> = if body.trim().is_empty() {
        Vec::new()
    } else {
        body.split(',')
            .map(|s: &str| s.trim().to_owned())
            .collect::<Vec<String>>()
    };
    let expected: &[String] = &params[1..];
    if call_args.len() != expected.len() {
        return None;
    }
    for (got, want) in call_args.iter().zip(expected.iter()) {
        if got != want {
            return None;
        }
    }
    Some(PropValue::CallForward {
        arity: params.len(),
    })
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<&str>>().join(" ")
}

#[derive(Debug, Clone)]
struct MemberRef {
    key: String,
    member_range: Range<usize>,
    call_args: Option<(Vec<String>, usize)>,
}

fn collect_member_refs(source: &str, obj: &CfObject) -> Vec<MemberRef> {
    let bytes: &[u8] = source.as_bytes();
    let mut names: Vec<String> = Vec::with_capacity(1 + obj.aliases.len());
    names.push(obj.var.clone());
    names.extend(obj.aliases.iter().cloned());
    let alternation: String = names
        .iter()
        .map(|n: &String| regex::escape(n))
        .collect::<Vec<String>>()
        .join("|");
    let dot_pattern: String =
        format!(r#"\b(?:{alternation})(?:\.([A-Za-z]{{5}})|\[\s*['"]([A-Za-z]{{5}})['"]\s*\])"#);
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&dot_pattern) else {
        return Vec::new();
    };
    let mut refs: Vec<MemberRef> = Vec::new();
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        if overlaps(&obj.decl_range, whole.start()) {
            continue;
        }
        let key: String = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m: regex::Match<'_>| m.as_str().to_owned())
            .unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let after: usize = skip_ws(bytes, whole.end());
        let call_args: Option<(Vec<String>, usize)> = if bytes.get(after) == Some(&b'(') {
            find_paren_close(bytes, after + 1).map(|close: usize| {
                let inner: &str = &source[after + 1..close];
                (split_top_args(inner), close + 1)
            })
        } else {
            None
        };
        refs.push(MemberRef {
            key,
            member_range: whole.start()..whole.end(),
            call_args,
        });
    }
    refs
}

const fn overlaps(range: &Range<usize>, pos: usize) -> bool {
    pos >= range.start && pos < range.end
}

fn reassigned_outside_decl(source: &str, obj: &CfObject) -> bool {
    let mut names: Vec<&str> = Vec::with_capacity(1 + obj.aliases.len());
    names.push(obj.var.as_str());
    names.extend(obj.aliases.iter().map(String::as_str));
    let alternation: String = names
        .iter()
        .map(|n: &&str| regex::escape(n))
        .collect::<Vec<String>>()
        .join("|");
    let pattern: String = format!(r"\b(?:{alternation})\s*=[^=]");
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
        return true;
    };
    let bytes: &[u8] = source.as_bytes();
    re.find_iter(source).any(|m: regex::Match<'_>| {
        let pos: usize = m.start();
        if overlaps(&obj.decl_range, pos) {
            return false;
        }
        let prev: Option<u8> = pos.checked_sub(1).map(|i: usize| bytes[i]);
        !matches!(prev, Some(b'.'))
    })
}

fn render_ref(
    value: &PropValue,
    r: &MemberRef,
    names: &[String],
    props: &BTreeMap<String, PropValue>,
) -> Option<(Range<usize>, String)> {
    match value {
        PropValue::StringLiteral(lit) => {
            if r.call_args.is_some() {
                return None;
            }
            Some((r.member_range.clone(), lit.clone()))
        }
        PropValue::BinaryOp {
            params,
            left,
            op,
            right,
        }
        | PropValue::LogicalOp {
            params,
            left,
            op,
            right,
        } => {
            let (args, end): &(Vec<String>, usize) = r.call_args.as_ref()?;
            if args.len() != params.len() {
                return None;
            }
            let l_raw: &String = positional(left, args)?;
            let rg_raw: &String = positional(right, args)?;
            let l: String = resolve_arg(l_raw, names, props);
            let rg: String = resolve_arg(rg_raw, names, props);
            Some((r.member_range.start..*end, format!("({l}{op}{rg})")))
        }
        PropValue::CallForward { arity } => {
            let (call_args, end): &(Vec<String>, usize) = r.call_args.as_ref()?;
            if call_args.len() != *arity || call_args.is_empty() {
                return None;
            }
            let callee: String = resolve_arg(&call_args[0], names, props);
            let forwarded: Vec<String> = call_args[1..]
                .iter()
                .map(|a: &String| resolve_arg(a, names, props))
                .collect();
            Some((
                r.member_range.start..*end,
                format!("{}({})", callee, forwarded.join(",")),
            ))
        }
        PropValue::RestForward => {
            let (call_args, end): &(Vec<String>, usize) = r.call_args.as_ref()?;
            if call_args.is_empty() {
                return None;
            }
            let callee: String = resolve_arg(&call_args[0], names, props);
            let forwarded: Vec<String> = call_args[1..]
                .iter()
                .map(|a: &String| resolve_arg(a, names, props))
                .collect();
            Some((
                r.member_range.start..*end,
                format!("{}({})", callee, forwarded.join(",")),
            ))
        }
    }
}

fn resolve_arg(arg: &str, names: &[String], props: &BTreeMap<String, PropValue>) -> String {
    let trimmed: &str = arg.trim();
    let key: Option<&str> = names.iter().find_map(|name: &String| {
        let dot_prefix: String = format!("{name}.");
        let bracket_prefix: String = format!("{name}['");
        let bracket_prefix2: String = format!("{name}[\"");
        if let Some(rest) = trimmed.strip_prefix(&dot_prefix)
            && rest.len() == 5
            && rest.chars().all(|c: char| c.is_ascii_alphabetic())
        {
            return Some(rest);
        }
        if let Some(rest) = trimmed
            .strip_prefix(&bracket_prefix)
            .and_then(|r: &str| r.strip_suffix("']"))
            && rest.len() == 5
            && rest.chars().all(|c: char| c.is_ascii_alphabetic())
        {
            return Some(rest);
        }
        if let Some(rest) = trimmed
            .strip_prefix(&bracket_prefix2)
            .and_then(|r: &str| r.strip_suffix("\"]"))
            && rest.len() == 5
            && rest.chars().all(|c: char| c.is_ascii_alphabetic())
        {
            return Some(rest);
        }
        None
    });
    let Some(key): Option<&str> = key else {
        return arg.to_owned();
    };
    match props.get(key) {
        Some(PropValue::StringLiteral(lit)) => lit.clone(),
        _ => arg.to_owned(),
    }
}

fn positional<'a>(index: &str, args: &'a [String]) -> Option<&'a String> {
    let i: usize = index.parse::<usize>().ok()?;
    args.get(i)
}

fn split_top_args(text: &str) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let (mut paren, mut bracket, mut brace): (i32, i32, i32) = (0, 0, 0);
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                if let Some(after) = skip_string(bytes, i, b) {
                    i = after;
                    continue;
                }
                return vec![text.to_owned()];
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if paren == 0 && bracket == 0 && brace == 0 => {
                out.push(text[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(text[start..].trim().to_owned());
    out
}

fn skip_ws(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

fn apply_edits(source: &str, edits: &mut [(Range<usize>, Option<String>)]) -> (String, usize) {
    edits.sort_by_key(|e: &(Range<usize>, Option<String>)| e.0.start);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut applied: usize = 0;
    for (range, replacement) in edits.iter() {
        if range.start < cursor {
            continue;
        }
        out.push_str(&source[cursor..range.start]);
        if let Some(s) = replacement {
            out.push_str(s);
            applied += 1;
        }
        cursor = range.end;
    }
    out.push_str(&source[cursor..]);
    (out, applied)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn merges_binary_op_proxy() {
        let src: &str = "function add(a,b){var _0x1={'WOfoz':function(x,y){return x+y;}};return _0x1['WOfoz'](a,b);}";
        let r: ControlFlowObjectResult = merge_control_flow_objects(src);
        assert_eq!(r.objects_merged, 1);
        assert!(
            r.rewritten_source.contains("(a+b)"),
            "got: {}",
            r.rewritten_source
        );
        assert!(!r.rewritten_source.contains("WOfoz"));
    }

    #[test]
    fn merges_call_forward_proxy() {
        let src: &str = "function f(g,x){var _0x2={'NiLKX':function(a,b){return a(b);}};return _0x2['NiLKX'](g,x);}";
        let r: ControlFlowObjectResult = merge_control_flow_objects(src);
        assert_eq!(r.objects_merged, 1);
        assert!(
            r.rewritten_source.contains("g(x)"),
            "got: {}",
            r.rewritten_source
        );
    }

    #[test]
    fn merges_string_literal_proxy() {
        let src: &str = "function f(){var _0x3={'aBcDe':'hello world'};return _0x3['aBcDe'];}";
        let r: ControlFlowObjectResult = merge_control_flow_objects(src);
        assert_eq!(r.objects_merged, 1);
        assert!(r.rewritten_source.contains("'hello world'"));
    }

    #[test]
    fn leaves_unrelated_object_alone() {
        let src: &str = "var config={'name':'test','value':42};config.name;";
        let r: ControlFlowObjectResult = merge_control_flow_objects(src);
        assert_eq!(r.objects_merged, 0);
    }

    #[test]
    fn skips_reassigned_object() {
        let src: &str =
            "var _0x4={'WOfoz':function(x,y){return x+y;}};_0x4=other;_0x4['WOfoz'](1,2);";
        let r: ControlFlowObjectResult = merge_control_flow_objects(src);
        assert_eq!(r.objects_merged, 0);
    }

    #[test]
    fn merges_object_inside_class_method() {
        let src: &str = "class C{add(t){const _0x5={'EkcVb':function(a,b){return a===b;},'qtgzp':'IoYFb'};if(this.c[t]){if(_0x5['EkcVb'](_0x5['qtgzp'],_0x5['qtgzp']))this.c[t]+=1;else{this.c[t]=1;}}else{this.c[t]=1;}}}";
        let r: ControlFlowObjectResult = merge_control_flow_objects(src);
        assert!(
            r.objects_merged >= 1,
            "class method CF object must be merged; got merged={} src:\n{}",
            r.objects_merged,
            r.rewritten_source
        );
    }

    #[test]
    fn merges_object_with_mixed_string_and_function_props() {
        let src: &str = "class C{['add'](_0xABC){const _0x5094dc={'EkcVb':function(_0x5e1234,_0x16a130){return _0x5e1234===_0x16a130;},'qtgzp':'IoYFb','qggaI':function(_0xb153ed,_0x50a774){return _0xb153ed===_0x50a774;},'YbApq':'UiLnS'};var _0x348ed7=_0xABC['toLowerCase']();if(this['counts'][_0x348ed7]){if(_0x5094dc['EkcVb'](_0x5094dc['qtgzp'],_0x5094dc['qtgzp']))this['counts'][_0x348ed7]+=0x1;else{var _0x11=new X('histogram');}}else{if(_0x5094dc['qggaI'](_0x5094dc['YbApq'],'qfAhe')){var _0x15=_0xABC['toLowerCase']();this['counts'][_0x15]=0x1;}else this['counts'][_0x348ed7]=0x1;}}}";
        let r: ControlFlowObjectResult = merge_control_flow_objects(src);
        assert!(
            r.objects_merged >= 1,
            "mixed-prop CF object inside class computed method must merge; merged={} out:\n{}",
            r.objects_merged,
            r.rewritten_source
        );
        assert!(
            r.rewritten_source.contains("('IoYFb'==='IoYFb')")
                || r.rewritten_source.contains("(\"IoYFb\"===\"IoYFb\")"),
            "EkcVb(qtgzp, qtgzp) must inline to string===string; got:\n{}",
            r.rewritten_source
        );
    }
}
