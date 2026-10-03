use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::cil::{MethodBody, OperandValue};
use crate::structurize::{StructuredMethod, TokenNamer};

const DISPLAY_CLASS_PREFIX: &str = "<>c__DisplayClass";
const THIS_FIELD: &str = "<>4__this";
const OUTER_THIS: &str = "__disrobe_outer_this";
const MAX_NESTING: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClosureType {
    pub(crate) fields: BTreeMap<String, String>,
    pub(crate) is_struct: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Allocation {
    pub(crate) sites: usize,
    pub(crate) in_loop: bool,
}

#[must_use]
pub(crate) fn is_display_class_name(short: &str) -> bool {
    short.starts_with(DISPLAY_CLASS_PREFIX)
}

#[must_use]
pub(crate) fn closure_allocations<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
) -> BTreeMap<String, Allocation> {
    let mut back_edges: Vec<(u32, u32)> = Vec::new();
    for (index, ins) in body.instructions.iter().enumerate() {
        let next: i64 = body
            .instructions
            .get(index + 1)
            .map_or_else(|| i64::from(u32::MAX), |n| i64::from(n.offset));
        let relatives: Vec<i32> = match &ins.operand {
            OperandValue::BrTarget(rel) => vec![*rel],
            OperandValue::Switch(rels) => rels.clone(),
            _ => Vec::new(),
        };
        for rel in relatives {
            let target: i64 = next + i64::from(rel);
            if target <= i64::from(ins.offset) {
                back_edges.push((ins.offset, u32::try_from(target.max(0)).unwrap_or(0)));
            }
        }
    }
    let mut out: BTreeMap<String, Allocation> = BTreeMap::new();
    for ins in &body.instructions {
        if ins.name != "newobj" {
            continue;
        }
        let OperandValue::Token(token) = ins.operand else {
            continue;
        };
        let raw: String = namer.name(token);
        let Some(declared) = raw.strip_suffix("::.ctor") else {
            continue;
        };
        let short: &str = short_type_name(declared);
        if !is_display_class_name(short) {
            continue;
        }
        let in_loop: bool = back_edges
            .iter()
            .any(|&(from, to): &(u32, u32)| to <= ins.offset && ins.offset < from);
        let entry: &mut Allocation = out.entry(short.to_owned()).or_default();
        entry.sites = entry.sites.saturating_add(1);
        entry.in_loop |= in_loop;
    }
    out
}

fn short_type_name(name: &str) -> &str {
    name.rsplit(['.', '/', '+']).next().unwrap_or(name)
}

#[derive(Debug, Clone)]
struct Helper {
    owner: String,
    name: String,
    return_type: String,
    params: Vec<(String, String)>,
    is_static: bool,
    inner: Vec<String>,
}

pub(crate) fn lower_display_classes(
    methods: &mut [StructuredMethod],
    closure_types: &BTreeMap<String, BTreeMap<String, ClosureType>>,
    allocations: &BTreeMap<u32, BTreeMap<String, Allocation>>,
    scopes: &BTreeMap<u32, String>,
) -> u32 {
    let mut helpers: BTreeMap<&str, BTreeMap<String, Vec<Helper>>> = BTreeMap::new();
    for method in methods.iter() {
        let Some(scope) = scopes.get(&method.token) else {
            continue;
        };
        if let Some(helper) = parse_helper(&method.body) {
            helpers
                .entry(scope.as_str())
                .or_default()
                .entry(helper.name.clone())
                .or_default()
                .push(helper);
        }
    }
    let no_types: BTreeMap<String, ClosureType> = BTreeMap::new();
    let no_helpers: BTreeMap<String, Vec<Helper>> = BTreeMap::new();
    let no_sites: BTreeMap<String, Allocation> = BTreeMap::new();
    let mut lowered: u32 = 0;
    for method in methods.iter_mut() {
        if parse_helper(&method.body).is_some() {
            continue;
        }
        let Some(scope) = scopes.get(&method.token) else {
            continue;
        };
        let types: &BTreeMap<String, ClosureType> = closure_types.get(scope).unwrap_or(&no_types);
        let scoped: &BTreeMap<String, Vec<Helper>> =
            helpers.get(scope.as_str()).unwrap_or(&no_helpers);
        let sites: &BTreeMap<String, Allocation> =
            allocations.get(&method.token).unwrap_or(&no_sites);
        if let Some(body) = lower_method(&method.body, types, sites, scoped) {
            method.body = body;
            lowered = lowered.saturating_add(1);
        }
    }
    lowered
}

fn mangled_kind(name: &str) -> Option<char> {
    let rest: &str = name.strip_prefix('<')?;
    let close: usize = rest.find('>')?;
    let after: &str = &rest[close + 1..];
    if after.starts_with("b__") {
        Some('b')
    } else if after.starts_with("g__") {
        Some('g')
    } else {
        None
    }
}

fn local_function_name(name: &str) -> Option<&str> {
    let rest: &str = name.strip_prefix('<')?;
    let close: usize = rest.find('>')?;
    let after: &str = rest[close + 1..].strip_prefix("g__")?;
    let end: usize = after.find('|')?;
    let ident: &str = &after[..end];
    is_identifier(ident).then_some(ident)
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn split_body(body: &str) -> Option<(Vec<String>, Vec<String>)> {
    let lines: Vec<&str> = body.lines().collect();
    let open: usize = lines.iter().position(|l: &&str| l.trim() == "{")?;
    let close: usize = lines.iter().rposition(|l: &&str| l.trim() == "}")?;
    if close <= open {
        return None;
    }
    let header: Vec<String> = lines[..=open]
        .iter()
        .map(|l: &&str| (*l).to_owned())
        .collect();
    let inner: Vec<String> = lines[open + 1..close]
        .iter()
        .map(|l: &&str| (*l).to_owned())
        .collect();
    Some((header, inner))
}

fn parse_helper(body: &str) -> Option<Helper> {
    let (header, inner): (Vec<String>, Vec<String>) = split_body(body)?;
    let owner_line: &str = header.first()?.trim();
    let owner: &str = owner_line.strip_prefix("// ")?;
    let owner: &str = owner.split(" [").next()?.trim();
    let signature: &str = header.get(1)?.trim();
    let open: usize = signature.find('(')?;
    let close: usize = signature.rfind(')')?;
    if close != signature.len() - 1 || close < open {
        return None;
    }
    let head: Vec<&str> = signature[..open].split_whitespace().collect();
    let name: &str = head.last()?;
    mangled_kind(name)?;
    let is_static: bool = head.contains(&"static");
    let return_type: &str = head.get(head.len().checked_sub(2)?)?;
    if head
        .iter()
        .any(|w: &&str| matches!(*w, "async" | "unsafe" | "extern"))
        || name.contains('`')
    {
        return None;
    }
    let params: Vec<(String, String)> = split_top_level(&signature[open + 1..close])
        .into_iter()
        .filter(|p: &String| !p.trim().is_empty())
        .map(|p: String| {
            let p: &str = p.trim();
            let split: usize = p.rfind(' ')?;
            Some((p[..split].trim().to_owned(), p[split + 1..].to_owned()))
        })
        .collect::<Option<Vec<(String, String)>>>()?;
    Some(Helper {
        owner: owner.to_owned(),
        name: (*name).to_owned(),
        return_type: (*return_type).to_owned(),
        params,
        is_static,
        inner,
    })
}

fn split_top_level(text: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut depth: i32 = 0;
    let mut current: String = String::new();
    let mut in_string: bool = false;
    let mut in_char: bool = false;
    let mut escaped: bool = false;
    for c in text.chars() {
        if in_string || in_char {
            current.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if (in_string && c == '"') || (in_char && c == '\'') {
                in_string = false;
                in_char = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '\'' => in_char = true,
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    parts.push(current);
    parts
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn identifiers(text: &str) -> BTreeSet<String> {
    identifiers_in_code(&crate::iterator_reverse::code_outside_string_literals(text))
}

fn identifiers_in_code(text: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        if is_ident_char(chars[i]) {
            let start: usize = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let member: bool = start > 0 && chars[start - 1] == '.';
            if !member {
                out.insert(chars[start..i].iter().collect());
            }
        } else {
            i += 1;
        }
    }
    out
}

fn replace_bounded(text: &str, needle: &str, replacement: &str) -> String {
    crate::iterator_reverse::rewrite_code_outside_string_literals(text, |code: &str| {
        Some(replace_bounded_in_code(code, needle, replacement))
    })
    .unwrap_or_else(|| text.to_owned())
}

fn replace_bounded_in_code(text: &str, needle: &str, replacement: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    while let Some(at) = rest.find(needle) {
        let end: usize = at + needle.len();
        let before_ok: bool = needle.starts_with(|c: char| !is_ident_char(c))
            || !rest[..at]
                .chars()
                .next_back()
                .is_some_and(|c: char| is_ident_char(c) || c == '.');
        let after_ok: bool = needle.ends_with(|c: char| !is_ident_char(c))
            || !rest[end..].chars().next().is_some_and(is_ident_char);
        out.push_str(&rest[..at]);
        if before_ok && after_ok {
            out.push_str(replacement);
        } else {
            out.push_str(needle);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn contains_bounded(text: &str, needle: &str) -> bool {
    replace_bounded(text, needle, "\u{0}") != text
}

#[derive(Debug, Clone)]
struct Lowering<'a> {
    closure_types: &'a BTreeMap<String, ClosureType>,
    helpers: &'a BTreeMap<String, Vec<Helper>>,
    variables: BTreeMap<(String, String), String>,
    local_functions: BTreeMap<String, String>,
    declared_functions: BTreeMap<String, Vec<String>>,
    reserved: BTreeSet<String>,
    next_scope: usize,
}

impl Lowering<'_> {
    fn helper(&self, owner: Option<&str>, name: &str) -> Option<Helper> {
        let mut found = self
            .helpers
            .get(name)?
            .iter()
            .filter(|h: &&Helper| owner.is_none_or(|o: &str| h.owner == o));
        let first: &Helper = found.next()?;
        found.next().is_none().then(|| first.clone())
    }

    fn variable(&mut self, closure: &str, field: &str) -> Option<String> {
        if field == THIS_FIELD {
            return Some(OUTER_THIS.to_owned());
        }
        let key: (String, String) = (closure.to_owned(), field.to_owned());
        if let Some(name) = self.variables.get(&key) {
            return Some(name.clone());
        }
        let ty: &String = self.closure_types.get(closure)?.fields.get(field)?;
        if is_display_class_name(short_type_name(ty)) || !is_identifier(field) {
            return None;
        }
        let name: String = self.fresh(field);
        self.variables.insert(key, name.clone());
        Some(name)
    }

    fn fresh(&mut self, base: &str) -> String {
        let mut candidate: String = base.to_owned();
        let mut suffix: usize = 0;
        while self.reserved.contains(&candidate) {
            suffix += 1;
            candidate = format!("{base}_{suffix}");
        }
        self.reserved.insert(candidate.clone());
        candidate
    }

    fn rewrite_handle(
        &mut self,
        text: &str,
        handle: &str,
        closure: &str,
        depth: usize,
    ) -> Option<String> {
        crate::iterator_reverse::rewrite_code_outside_string_literals(text, |code: &str| {
            self.rewrite_handle_in_code(code, handle, closure, depth)
        })
    }

    fn rewrite_handle_in_code(
        &mut self,
        text: &str,
        handle: &str,
        closure: &str,
        depth: usize,
    ) -> Option<String> {
        let ty: &ClosureType = self.closure_types.get(closure)?;
        let fields: Vec<String> = ty.fields.keys().cloned().collect();
        let mut out: String = text.to_owned();
        for field in fields {
            let needle: String = format!("{handle}.{field}");
            if !contains_bounded(&out, &needle) {
                continue;
            }
            let name: String = self.variable(closure, &field)?;
            out = replace_bounded(&out, &needle, &name);
        }
        let members: Vec<String> = self
            .helpers
            .values()
            .flatten()
            .filter(|h: &&Helper| h.owner == closure && !h.is_static)
            .map(|h: &Helper| h.name.clone())
            .collect();
        for member in members {
            let needle: String = format!("{handle}.{member}");
            if !out.contains(&needle) {
                continue;
            }
            out = self.replace_member(&out, &needle, closure, &member, depth)?;
        }
        Some(out)
    }

    fn replace_member(
        &mut self,
        text: &str,
        needle: &str,
        owner: &str,
        member: &str,
        depth: usize,
    ) -> Option<String> {
        crate::iterator_reverse::rewrite_code_outside_string_literals(text, |code: &str| {
            self.replace_member_in_code(code, needle, owner, member, depth)
        })
    }

    fn replace_member_in_code(
        &mut self,
        text: &str,
        needle: &str,
        owner: &str,
        member: &str,
        depth: usize,
    ) -> Option<String> {
        let kind: char = mangled_kind(member)?;
        let mut out: String = String::with_capacity(text.len());
        let mut rest: &str = text;
        while let Some(at) = rest.find(needle) {
            let before_ok: bool = !rest[..at]
                .chars()
                .next_back()
                .is_some_and(|c: char| is_ident_char(c) || c == '.');
            let end: usize = at + needle.len();
            if !before_ok || rest[end..].starts_with(is_ident_char) {
                out.push_str(&rest[..end]);
                rest = &rest[end..];
                continue;
            }
            out.push_str(&rest[..at]);
            let tail: &str = &rest[end..];
            if kind == 'g' {
                if !tail.starts_with('(') {
                    return None;
                }
                let name: String = self.local_function(Some(owner), member, depth)?;
                out.push_str(&name);
            } else {
                let lambda: String = self.lambda(owner, member, depth)?;
                if tail.starts_with(".Invoke(") {
                    let delegate: String = self.delegate_type(owner, member)?;
                    write!(out, "new {delegate}({lambda})").ok()?;
                } else if tail.starts_with('.') || tail.starts_with('(') {
                    return None;
                } else {
                    write!(out, "({lambda})").ok()?;
                }
            }
            rest = tail;
        }
        out.push_str(rest);
        Some(out)
    }

    fn delegate_type(&self, owner: &str, member: &str) -> Option<String> {
        let helper: Helper = self.helper(Some(owner), member)?;
        let mut args: Vec<String> = helper
            .params
            .iter()
            .map(|(ty, _): &(String, String)| ty.clone())
            .collect();
        if args.iter().any(|ty: &String| {
            ty.starts_with("ref ") || ty.starts_with("out ") || ty.starts_with("in ")
        }) {
            return None;
        }
        if helper.return_type == "void" {
            if args.is_empty() {
                return Some("System.Action".to_owned());
            }
            return Some(format!("System.Action<{}>", args.join(", ")));
        }
        args.push(helper.return_type);
        Some(format!("System.Func<{}>", args.join(", ")))
    }

    fn helper_body(
        &mut self,
        helper: &Helper,
        handles: &[(String, String)],
        depth: usize,
    ) -> Option<Vec<String>> {
        if depth > MAX_NESTING {
            return None;
        }
        self.next_scope += 1;
        let scope: usize = self.next_scope;
        let mut lines: Vec<String> = Vec::new();
        for line in &helper.inner {
            let trimmed: &str = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("//") {
                return None;
            }
            lines.push(line.clone());
        }
        let mut text: String = lines.join("\n");
        for (handle, closure) in handles {
            text = self.rewrite_handle(&text, handle, closure, depth + 1)?;
        }
        let by_reference: BTreeMap<String, String> = handles
            .iter()
            .filter(|(handle, _): &&(String, String)| handle != "this")
            .cloned()
            .collect();
        text = self.rewrite_static_calls(&text, &by_reference, depth + 1)?;
        for ident in identifiers(&text) {
            if ident.starts_with("local")
                && ident[5..].bytes().all(|b: u8| b.is_ascii_digit())
                && ident.len() > 5
            {
                text = replace_bounded(&text, &ident, &format!("scope{scope}_{ident}"));
            }
        }
        if contains_bounded(&text, "this")
            || text.contains("<>")
            || text.contains(DISPLAY_CLASS_PREFIX)
        {
            return None;
        }
        Some(text.lines().map(str::to_owned).collect())
    }

    fn lambda(&mut self, owner: &str, member: &str, depth: usize) -> Option<String> {
        let helper: Helper = self.helper(Some(owner), member)?;
        if helper.is_static {
            return None;
        }
        let handles: Vec<(String, String)> = vec![("this".to_owned(), helper.owner.clone())];
        let params: String = helper
            .params
            .iter()
            .map(|(ty, name): &(String, String)| format!("{ty} {name}"))
            .collect::<Vec<String>>()
            .join(", ");
        let body: Vec<String> = self.helper_body(&helper, &handles, depth)?;
        let statements: Vec<String> = body.iter().map(|l: &String| l.trim().to_owned()).collect();
        if let [only] = statements.as_slice()
            && let Some(expr) = only
                .strip_prefix("return ")
                .and_then(|e: &str| e.strip_suffix(';'))
        {
            return Some(format!("({params}) => {expr}"));
        }
        let mut statements: Vec<String> = statements;
        if helper.return_type == "void"
            && statements.last().is_some_and(|l: &String| l == "return;")
        {
            statements.pop();
        }
        Some(format!("({params}) => {{ {} }}", statements.join(" ")))
    }

    fn local_function(
        &mut self,
        owner: Option<&str>,
        member: &str,
        depth: usize,
    ) -> Option<String> {
        if let Some(name) = self.local_functions.get(member) {
            return Some(name.clone());
        }
        let helper: Helper = self.helper(owner, member)?;
        let base: &str = local_function_name(member)?;
        let name: String = self.fresh(base);
        self.local_functions.insert(member.to_owned(), name.clone());
        let mut handles: Vec<(String, String)> = Vec::new();
        let mut kept: Vec<String> = Vec::new();
        for (ty, param) in &helper.params {
            let bare: &str = ty.strip_prefix("ref ").unwrap_or(ty);
            if is_display_class_name(short_type_name(bare)) {
                if !ty.starts_with("ref ")
                    || !self
                        .closure_types
                        .get(short_type_name(bare))
                        .is_some_and(|c: &ClosureType| c.is_struct)
                {
                    return None;
                }
                handles.push((param.clone(), short_type_name(bare).to_owned()));
            } else {
                kept.push(format!("{ty} {param}"));
            }
        }
        if !helper.is_static {
            handles.push(("this".to_owned(), helper.owner.clone()));
        }
        let body: Vec<String> = self.helper_body(&helper, &handles, depth)?;
        let mut declaration: Vec<String> = vec![
            format!("    {} {name}({})", helper.return_type, kept.join(", ")),
            "    {".to_owned(),
        ];
        declaration.extend(body.iter().map(|l: &String| format!("    {l}")));
        declaration.push("    }".to_owned());
        self.declared_functions.insert(name.clone(), declaration);
        Some(name)
    }

    fn rewrite_static_calls(
        &mut self,
        text: &str,
        handles: &BTreeMap<String, String>,
        depth: usize,
    ) -> Option<String> {
        crate::iterator_reverse::rewrite_code_outside_string_literals(text, |code: &str| {
            self.rewrite_static_calls_in_code(code, handles, depth)
        })
    }

    fn rewrite_static_calls_in_code(
        &mut self,
        text: &str,
        handles: &BTreeMap<String, String>,
        depth: usize,
    ) -> Option<String> {
        let members: Vec<String> = self
            .helpers
            .values()
            .flatten()
            .filter(|h: &&Helper| h.is_static && mangled_kind(&h.name) == Some('g'))
            .map(|h: &Helper| h.name.clone())
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        let mut out: String = text.to_owned();
        for member in members {
            while let Some(at) = out.find(&format!("{member}(")) {
                let open: usize = at + member.len();
                let close: usize = matching_paren(&out, open)?;
                let mut start: usize = at;
                while start > 0 {
                    let prev: char = out[..start].chars().next_back()?;
                    if is_ident_char(prev) || prev == '.' {
                        start -= prev.len_utf8();
                    } else {
                        break;
                    }
                }
                let args: Vec<String> = split_top_level(&out[open + 1..close]);
                let mut kept: Vec<String> = Vec::new();
                for arg in args {
                    let a: &str = arg.trim();
                    if a.is_empty() {
                        continue;
                    }
                    let bare: &str = a
                        .strip_prefix("ref ")
                        .or_else(|| a.strip_prefix("out "))
                        .unwrap_or(a);
                    let bare: &str = bare
                        .strip_prefix("(&")
                        .and_then(|b: &str| b.strip_suffix(')'))
                        .or_else(|| bare.strip_prefix('&'))
                        .unwrap_or(bare);
                    if handles.contains_key(bare) {
                        continue;
                    }
                    kept.push(a.to_owned());
                }
                let name: String = self.local_function(None, &member, depth)?;
                out = format!(
                    "{}{name}({}){}",
                    &out[..start],
                    kept.join(", "),
                    &out[close + 1..]
                );
            }
        }
        Some(out)
    }
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let bytes: &[u8] = text.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth: usize = 0;
    let mut in_string: bool = false;
    let mut escaped: bool = false;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn declared_handle(line: &str) -> Option<(String, String)> {
    let trimmed: &str = line.trim();
    let decl: &str = trimmed.strip_suffix(';')?;
    if let Some(slot) = decl.strip_prefix("var ")
        && let Some((name, value)) = slot.split_once(" = default(")
        && let Some(ty) = value.strip_suffix(')')
    {
        return (is_display_class_name(ty) && is_identifier(name))
            .then(|| (name.to_owned(), ty.to_owned()));
    }
    let (ty, name): (&str, &str) = decl.split_once(' ')?;
    if !is_display_class_name(ty) || !is_identifier(name) {
        return None;
    }
    Some((name.to_owned(), ty.to_owned()))
}

fn lower_method(
    body: &str,
    closure_types: &BTreeMap<String, ClosureType>,
    sites: &BTreeMap<String, Allocation>,
    helpers: &BTreeMap<String, Vec<Helper>>,
) -> Option<String> {
    if !body.contains(DISPLAY_CLASS_PREFIX)
        && !helpers.keys().any(|h: &String| body.contains(h.as_str()))
    {
        return None;
    }
    let (header, inner): (Vec<String>, Vec<String>) = split_body(body)?;
    if inner
        .iter()
        .any(|l: &String| l.trim_start().starts_with("// disrobe"))
    {
        return None;
    }
    let mut handles: BTreeMap<String, String> = BTreeMap::new();
    let mut statements: Vec<String> = Vec::new();
    let mut declarations_end: usize = 0;
    for line in &inner {
        if let Some((name, ty)) = declared_handle(line) {
            handles.insert(name, ty);
            continue;
        }
        statements.push(line.clone());
    }
    let mut aliases_dropped: Vec<String> = Vec::with_capacity(statements.len());
    for line in statements {
        let Some((target, source)) = line
            .trim()
            .strip_suffix(';')
            .and_then(|l: &str| l.split_once(" = "))
        else {
            aliases_dropped.push(line);
            continue;
        };
        let Some(ty) = handles.get(target) else {
            aliases_dropped.push(line);
            continue;
        };
        let same: bool = handles.get(source) == Some(ty) || source == format!("new {ty}()");
        if !same {
            aliases_dropped.push(line);
            continue;
        }
        if closure_types.get(ty)?.is_struct {
            return None;
        }
    }
    let statements: Vec<String> = aliases_dropped;
    for (i, line) in statements.iter().enumerate() {
        if line.trim().is_empty() {
            declarations_end = i;
            break;
        }
    }
    let mut stack_kept: BTreeSet<String> = BTreeSet::new();
    for line in &statements {
        let mut rest: &str = line;
        while let Some(at) = rest.find(&format!("new {DISPLAY_CLASS_PREFIX}")) {
            let after: &str = &rest[at + 4..];
            let end: usize = after.find("()")?;
            stack_kept.insert(after[..end].to_owned());
            rest = &after[end..];
        }
    }
    let mut used_types: BTreeSet<String> = handles.values().cloned().collect();
    used_types.extend(stack_kept.iter().cloned());
    for ty in &used_types {
        let closure: &ClosureType = closure_types.get(ty)?;
        let allocation: Allocation = sites.get(ty).copied().unwrap_or_default();
        if closure.is_struct {
            if allocation.sites != 0 {
                return None;
            }
        } else if allocation.sites != 1 || allocation.in_loop {
            return None;
        }
    }
    let mut reserved: BTreeSet<String> = identifiers(body);
    for helper in helpers.values().flatten() {
        for line in &helper.inner {
            reserved.extend(identifiers(line));
        }
        reserved.extend(
            helper
                .params
                .iter()
                .map(|(_, n): &(String, String)| n.clone()),
        );
    }
    let mut lowering: Lowering<'_> = Lowering {
        closure_types,
        helpers,
        variables: BTreeMap::new(),
        local_functions: BTreeMap::new(),
        declared_functions: BTreeMap::new(),
        reserved,
        next_scope: 0,
    };
    let mut text: String = statements.join("\n");
    for (handle, ty) in &handles {
        let addressed: String = format!("(&{handle})");
        text = lowering.rewrite_handle(&text, &addressed, ty, 0)?;
        text = lowering.rewrite_handle(&text, handle, ty, 0)?;
    }
    for ty in &stack_kept {
        let created: String = format!("new {ty}()");
        text = lowering.rewrite_handle(&text, &created, ty, 0)?;
        if text.contains(&created) {
            return None;
        }
    }
    let handle_names: BTreeMap<String, String> = handles.clone();
    text = lowering.rewrite_static_calls(&text, &handle_names, 0)?;
    for handle in handles.keys() {
        if contains_bounded(&text, handle) {
            return None;
        }
    }
    if text.contains(DISPLAY_CLASS_PREFIX) {
        return None;
    }
    if lowering.variables.is_empty()
        && lowering.declared_functions.is_empty()
        && text == statements.join("\n")
    {
        return None;
    }
    let captures_this: String = format!("{OUTER_THIS} = this;");
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l: &&str| l.trim() != captures_this)
        .map(|l: &str| replace_bounded(l, OUTER_THIS, "this"))
        .collect();
    let mut captured: Vec<String> = Vec::new();
    for ((closure, field), name) in &lowering.variables {
        let ty: &String = closure_types.get(closure)?.fields.get(field)?;
        captured.push(format!("    {ty} {name} = default;"));
    }
    let at: usize = declarations_end.min(lines.len());
    for (offset, line) in captured.into_iter().enumerate() {
        lines.insert(at + offset, line);
    }
    for declaration in lowering.declared_functions.values() {
        lines.push(String::new());
        lines.extend(
            declaration
                .iter()
                .map(|l: &String| replace_bounded(l, OUTER_THIS, "this")),
        );
    }
    let mut out: String = header.join("\n");
    out.push('\n');
    out.push_str(&lines.join("\n"));
    out.push_str("\n}\n");
    Some(out)
}
