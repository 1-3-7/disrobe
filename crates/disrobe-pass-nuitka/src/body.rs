use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::constants::ConstantsPool;
use crate::version_specific_patterns::{EraPatternPack, guess_era_from_csource, pack_for_era};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiftFidelity {
    FullBody,
    PartialBody,
    Skeleton,
}

impl From<LiftFidelity> for disrobe_core::RecoverySignal {
    #[inline]
    fn from(fidelity: LiftFidelity) -> Self {
        match fidelity {
            LiftFidelity::FullBody => Self::FullBodyLifted,
            LiftFidelity::PartialBody => Self::SomeBodiesLifted,
            LiftFidelity::Skeleton => Self::NoRecovery,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOpKind {
    Add,
    Sub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOpKind {
    Lt,
    Eq,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PythonExpr {
    Name(String),
    Const(String),
    FStringJoin {
        parts: Vec<Self>,
    },
    BinOp {
        op: BinOpKind,
        left: Box<Self>,
        right: Box<Self>,
    },
    Compare {
        op: CmpOpKind,
        left: Box<Self>,
        right: Box<Self>,
    },
    Call {
        func: Box<Self>,
        args: Vec<Self>,
    },
    Tuple(Vec<Self>),
    List(Vec<Self>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PythonStmt {
    Return(PythonExpr),
    If {
        test: PythonExpr,
        body: Vec<Self>,
        orelse: Vec<Self>,
    },
    Assign {
        targets: Vec<String>,
        value: PythonExpr,
    },
    TupleUnpackAssign {
        targets: Vec<String>,
        value: PythonExpr,
    },
    For {
        target: String,
        iter: PythonExpr,
        body: Vec<Self>,
    },
    Raise(PythonExpr),
    Expr(PythonExpr),
}

pub fn extract_impl_body_text<'a>(
    source: &'a str,
    module_name: &str,
    source_index: u32,
    fn_name: &str,
) -> Option<&'a str> {
    let needle: String =
        format!("static PyObject *impl_{module_name}$$$function__{source_index}_{fn_name}(");
    let start: usize = source.find(needle.as_str())?;
    let bytes: &[u8] = source.as_bytes();
    let mut depth: i32 = 0i32;
    let mut in_body: bool = false;
    let mut i: usize = start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                depth += 1;
                in_body = true;
            }
            b'}' => {
                depth -= 1;
                if in_body && depth <= 0 {
                    return Some(&source[start..=i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn strip_mod_consts(token: &str) -> &str {
    token.strip_prefix("mod_consts.").unwrap_or(token)
}

fn resolve_const_token(token: &str, pool: &ConstantsPool) -> PythonExpr {
    let t: &str = strip_mod_consts(token.trim().trim_end_matches(';'));
    if let Some(expr) = resolve_singleton_token(t) {
        return expr;
    }
    if let Some(expr) = resolve_numeric_token(t) {
        return expr;
    }
    if let Some(expr) = resolve_string_token(t, pool) {
        return expr;
    }
    if let Some(expr) = resolve_bytes_token(t, pool) {
        return expr;
    }
    if let Some(inner) = t
        .strip_prefix("const_tuple_")
        .and_then(|i: &str| i.strip_suffix("_tuple"))
    {
        return resolve_sequence_inner(inner, pool, false);
    }
    if let Some(inner) = t
        .strip_prefix("const_list_")
        .and_then(|i: &str| i.strip_suffix("_list"))
    {
        return resolve_sequence_inner(inner, pool, true);
    }
    if t == "const_tuple_empty" {
        return PythonExpr::Tuple(Vec::new());
    }
    if t == "const_list_empty" {
        return PythonExpr::List(Vec::new());
    }
    PythonExpr::Name(t.to_owned())
}

fn resolve_singleton_token(t: &str) -> Option<PythonExpr> {
    let lit: &str = match t {
        "const_true" => "True",
        "const_false" => "False",
        "const_none" => "None",
        "const_ellipsis" => "...",
        _ => return None,
    };
    Some(PythonExpr::Const(lit.to_owned()))
}

fn resolve_numeric_token(t: &str) -> Option<PythonExpr> {
    if t == "const_int_0" || t == "const_long_0" || t == "global_constants[2]" {
        return Some(PythonExpr::Const("0".to_owned()));
    }
    for prefix in ["const_int_pos_", "const_long_pos_"] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return Some(PythonExpr::Const(rest.to_owned()));
        }
    }
    for prefix in ["const_int_neg_", "const_long_neg_"] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return Some(PythonExpr::Const(format!("-{rest}")));
        }
    }
    if let Some(rest) = t
        .strip_prefix("const_int_hex_")
        .or_else(|| t.strip_prefix("const_long_hex_"))
    {
        return Some(PythonExpr::Const(format!("0x{rest}")));
    }
    if let Some(rest) = t.strip_prefix("const_float_") {
        return Some(resolve_float_fragment(rest));
    }
    None
}

fn resolve_float_fragment(fragment: &str) -> PythonExpr {
    if fragment == "plus_nan" || fragment == "minus_nan" {
        return PythonExpr::Const("float('nan')".to_owned());
    }
    let restored: String = fragment.replace("minus_", "-").replace('_', ".");
    PythonExpr::Const(restored)
}

fn resolve_string_token(t: &str, pool: &ConstantsPool) -> Option<PythonExpr> {
    let body: &str = t.strip_prefix("const_str_")?;
    Some(resolve_string_fragment(body, pool, false))
}

fn resolve_bytes_token(t: &str, pool: &ConstantsPool) -> Option<PythonExpr> {
    let body: &str = t.strip_prefix("const_bytes_")?;
    Some(resolve_string_fragment(body, pool, true))
}

fn resolve_string_fragment(body: &str, pool: &ConstantsPool, is_bytes: bool) -> PythonExpr {
    let prefix: &str = if is_bytes { "b" } else { "" };
    if let Some(rest) = body.strip_prefix("plain_") {
        return PythonExpr::Const(format!("{prefix}'{rest}'"));
    }
    if let Some(rest) = body.strip_prefix("chr_")
        && let Ok(code) = rest.parse::<u32>()
        && let Some(ch) = char::from_u32(code)
    {
        return PythonExpr::Const(format!("{prefix}'{}'", escape_char_literal(ch)));
    }
    if let Some(rest) = body.strip_prefix("angle_") {
        return PythonExpr::Const(format!("{prefix}'<{rest}>'"));
    }
    let named: Option<&str> = match body {
        "empty" => Some(""),
        "null" => Some("\\x00"),
        "space" => Some(" "),
        "dot" => Some("."),
        "newline" => Some("\\n"),
        "slash" => Some("/"),
        "backslash" => Some("\\\\"),
        "underscore" => Some("_"),
        _ => None,
    };
    if let Some(literal) = named {
        return PythonExpr::Const(format!("{prefix}'{literal}'"));
    }
    if let Some(hex) = body.strip_prefix("digest_") {
        if let Some(s) = pool.digest_to_string.get(hex) {
            return PythonExpr::Const(format!("{prefix}'{s}'"));
        }
        return PythonExpr::Const(format!("UNRESOLVED:{hex}"));
    }
    PythonExpr::Const(format!("UNRESOLVED:{body}"))
}

fn escape_char_literal(ch: char) -> String {
    match ch {
        '\n' => "\\n".to_owned(),
        '\t' => "\\t".to_owned(),
        '\r' => "\\r".to_owned(),
        '\'' => "\\'".to_owned(),
        '\\' => "\\\\".to_owned(),
        c if c.is_control() => format!("\\x{:02x}", c as u32),
        c => c.to_string(),
    }
}

fn resolve_sequence_inner(inner: &str, pool: &ConstantsPool, is_list: bool) -> PythonExpr {
    let items: Vec<PythonExpr> = split_tuple_tokens(inner)
        .into_iter()
        .map(|tok: String| resolve_const_token(&tok, pool))
        .collect();
    if is_list {
        PythonExpr::List(items)
    } else {
        PythonExpr::Tuple(items)
    }
}

const SINGLE_SEGMENT_PREFIXES: &[&str] = &[
    "str_plain_",
    "str_digest_",
    "str_chr_",
    "str_angle_",
    "bytes_plain_",
    "bytes_digest_",
    "bytes_chr_",
    "int_pos_",
    "int_neg_",
    "int_hex_",
    "long_pos_",
    "long_neg_",
    "long_hex_",
];

const ATOMIC_FRAGMENTS: &[&str] = &[
    "true",
    "false",
    "none",
    "ellipsis",
    "int_0",
    "long_0",
    "str_empty",
    "str_null",
    "str_space",
    "str_dot",
    "str_newline",
    "str_slash",
    "str_backslash",
    "str_underscore",
    "tuple_empty",
    "list_empty",
];

fn split_tuple_tokens(inner: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut remaining: &str = inner;
    while !remaining.is_empty() {
        let (fragment, rest): (&str, &str) = next_sequence_fragment(remaining);
        out.push(format!("const_{fragment}"));
        remaining = rest;
    }
    out
}

fn next_sequence_fragment(remaining: &str) -> (&str, &str) {
    for atom in ATOMIC_FRAGMENTS {
        if remaining == *atom {
            return (remaining, "");
        }
        if let Some(rest) = remaining.strip_prefix(atom)
            && rest.starts_with('_')
        {
            return (&remaining[..atom.len()], &rest[1..]);
        }
    }
    for prefix in SINGLE_SEGMENT_PREFIXES {
        if let Some(after) = remaining.strip_prefix(prefix) {
            let seg_end: usize = after.find('_').unwrap_or(after.len());
            let frag_end: usize = prefix.len() + seg_end;
            let next: &str = remaining.get(frag_end + 1..).unwrap_or("");
            return (&remaining[..frag_end], next);
        }
    }
    let end: usize = remaining.find('_').unwrap_or(remaining.len());
    let next: &str = remaining.get(end + 1..).unwrap_or("");
    (&remaining[..end], next)
}

fn contains_unresolved(expr: &PythonExpr) -> bool {
    match expr {
        PythonExpr::Const(s) => s.starts_with("UNRESOLVED:"),
        PythonExpr::Name(_) => false,
        PythonExpr::FStringJoin { parts } => parts.iter().any(contains_unresolved),
        PythonExpr::BinOp { left, right, .. } | PythonExpr::Compare { left, right, .. } => {
            contains_unresolved(left) || contains_unresolved(right)
        }
        PythonExpr::Call { func, args } => {
            contains_unresolved(func) || args.iter().any(contains_unresolved)
        }
        PythonExpr::Tuple(items) | PythonExpr::List(items) => items.iter().any(contains_unresolved),
    }
}

fn stmt_has_unresolved(stmt: &PythonStmt) -> bool {
    match stmt {
        PythonStmt::Return(e) | PythonStmt::Expr(e) | PythonStmt::Raise(e) => {
            contains_unresolved(e)
        }
        PythonStmt::If { test, body, orelse } => {
            contains_unresolved(test)
                || body.iter().any(stmt_has_unresolved)
                || orelse.iter().any(stmt_has_unresolved)
        }
        PythonStmt::Assign { value, .. } | PythonStmt::TupleUnpackAssign { value, .. } => {
            contains_unresolved(value)
        }
        PythonStmt::For { iter, body, .. } => {
            contains_unresolved(iter) || body.iter().any(stmt_has_unresolved)
        }
    }
}

fn build_tmp_map(lines: &[&str], pool: &ConstantsPool) -> BTreeMap<String, PythonExpr> {
    let mut map: BTreeMap<String, PythonExpr> = BTreeMap::new();
    for line in lines {
        let t: &str = line.trim();
        if let Some((lhs, rhs)) = parse_simple_assignment(t)
            && (lhs.starts_with("tmp_") || lhs.starts_with("par_"))
        {
            let expr: PythonExpr = resolve_rhs_token(rhs, &map, pool);
            map.insert(lhs.to_owned(), expr);
        }
    }
    map
}

fn resolve_rhs_token(
    rhs: &str,
    map: &BTreeMap<String, PythonExpr>,
    pool: &ConstantsPool,
) -> PythonExpr {
    let t: &str = rhs.trim().trim_end_matches(';');
    let clean: &str = strip_mod_consts(t);
    if let Some(existing) = map.get(clean) {
        return existing.clone();
    }
    if clean.starts_with("par_") {
        return PythonExpr::Name(clean.strip_prefix("par_").unwrap_or(clean).to_owned());
    }
    if clean.starts_with("var_") {
        return PythonExpr::Name(clean.strip_prefix("var_").unwrap_or(clean).to_owned());
    }
    resolve_const_token(clean, pool)
}

fn parse_simple_assignment(line: &str) -> Option<(&str, &str)> {
    let t: &str = line.trim();
    if !t.ends_with(';') {
        return None;
    }
    if t.starts_with("if ") || t.starts_with("assert") || t.starts_with("//") {
        return None;
    }
    let eq: usize = t.find(" = ")?;
    let lhs: &str = t[..eq].trim();
    let rhs: &str = t[eq + 3..].trim().trim_end_matches(';');
    if lhs.contains('(') || lhs.contains('*') || lhs.contains('[') {
        return None;
    }
    if rhs.contains('(') {
        return None;
    }
    Some((lhs, rhs))
}

fn resolve_through_map(
    token: &str,
    map: &BTreeMap<String, PythonExpr>,
    pool: &ConstantsPool,
) -> PythonExpr {
    let t: &str = strip_mod_consts(token.trim().trim_end_matches(';'));
    if let Some(e) = map.get(t) {
        return e.clone();
    }
    if t.starts_with("par_") {
        return PythonExpr::Name(t.strip_prefix("par_").unwrap_or(t).to_owned());
    }
    if t.starts_with("var_") {
        return PythonExpr::Name(t.strip_prefix("var_").unwrap_or(t).to_owned());
    }
    resolve_const_token(t, pool)
}

struct BodyCtx<'a> {
    lines: &'a [&'a str],
    pool: &'a ConstantsPool,
    pack: EraPatternPack,
    map: BTreeMap<String, PythonExpr>,
    stmts: Vec<PythonStmt>,
}

impl<'a> BodyCtx<'a> {
    fn new(lines: &'a [&'a str], pool: &'a ConstantsPool, pack: EraPatternPack) -> Self {
        let map: BTreeMap<String, PythonExpr> = build_tmp_map(lines, pool);
        Self {
            lines,
            pool,
            pack,
            map,
            stmts: Vec::new(),
        }
    }

    fn resolve_tok(&self, token: &str) -> PythonExpr {
        resolve_through_map(token, &self.map, self.pool)
    }

    fn lift(mut self) -> Vec<PythonStmt> {
        let mut i: usize = 0usize;
        while i < self.lines.len() {
            let line: &str = self.lines[i].trim();

            if should_skip(line) {
                i += 1;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_if_block(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_runtime_tuple_unpack(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_tuple_unpack_const(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_for_loop(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_print_call(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_fstring_join(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_raise(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            if let Some((stmt, consumed)) = self.try_return(i) {
                self.stmts.push(stmt);
                i += consumed;
                continue;
            }

            i += 1;
        }
        self.stmts
    }

    fn try_if_block(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        let needle: &str = self.pack.rich_compare_lt;
        if !line.contains(needle) {
            return None;
        }
        let args: (&str, &str) = extract_two_args(line, needle)?;
        let lhs: PythonExpr = self.resolve_tok(args.0);
        let rhs: PythonExpr = self.resolve_tok(args.1);
        let test: PythonExpr = PythonExpr::Compare {
            op: CmpOpKind::Lt,
            left: Box::new(lhs),
            right: Box::new(rhs),
        };

        let yes_tag: String = find_branch_tag(self.lines, start, "branch_yes_")?;
        let no_tag: String = find_branch_tag(self.lines, start, "branch_no_")?;

        let yes_start: usize = find_label(self.lines, &format!("{yes_tag}:;"))?;
        let no_start: usize = find_label(self.lines, &format!("{no_tag}:;"))?;

        let yes_body: Vec<PythonStmt> =
            self.lift_range(yes_start + 1, no_start.min(self.lines.len()));

        let yes_ends_with_return: bool = yes_body
            .last()
            .is_some_and(|s: &PythonStmt| matches!(s, PythonStmt::Return(_)));

        if yes_ends_with_return {
            let stmt: PythonStmt = PythonStmt::If {
                test,
                body: yes_body,
                orelse: Vec::new(),
            };
            let consumed: usize = no_start.saturating_sub(start) + 1;
            Some((stmt, consumed))
        } else {
            let no_body: Vec<PythonStmt> = self.lift_range(no_start + 1, self.lines.len());
            let no_end: usize = find_end_of_branch(self.lines, no_start + 1)
                .unwrap_or_else(|| self.lines.len().saturating_sub(1));
            let stmt: PythonStmt = PythonStmt::If {
                test,
                body: yes_body,
                orelse: no_body,
            };
            let consumed: usize = no_end.saturating_sub(start) + 1;
            Some((stmt, consumed))
        }
    }

    fn lift_range(&self, from: usize, to: usize) -> Vec<PythonStmt> {
        let end: usize = to.min(self.lines.len());
        if from >= end {
            return Vec::new();
        }
        let slice: &[&str] = &self.lines[from..end];
        let child: BodyCtx<'_> = BodyCtx::new(slice, self.pool, self.pack);
        child.lift()
    }

    fn try_runtime_tuple_unpack(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        if !line.contains(self.pack.make_tuple_empty) {
            return None;
        }

        let first_raw: String = find_set_item0_var(self.lines, start + 1, 6)?;
        let first_expr: PythonExpr = self.resolve_tok(&first_raw);
        let add_needle: &str = self.pack.binary_add_object;
        let add_line: &str = find_nearby_line(self.lines, start + 1, 40, add_needle)?;
        let add_args: (&str, &str) = extract_two_args(add_line, add_needle)?;
        let add_left: PythonExpr = self.resolve_tok(add_args.0);
        let add_right: PythonExpr = self.resolve_tok(add_args.1);
        let add_expr: PythonExpr = PythonExpr::BinOp {
            op: BinOpKind::Add,
            left: Box::new(add_left),
            right: Box::new(add_right),
        };

        let no_exc_idx: usize =
            find_label_from(self.lines, start + 1, "tuple_build_no_exception_")?;
        let (unpack_vars, _): (Vec<String>, usize) =
            collect_unpack_targets(self.lines, no_exc_idx + 1);

        if unpack_vars.len() < 2 {
            return None;
        }

        let first_var_expr: PythonExpr = first_expr;
        let value: PythonExpr = PythonExpr::Tuple(vec![first_var_expr, add_expr]);

        let stmt: PythonStmt = PythonStmt::TupleUnpackAssign {
            targets: unpack_vars,
            value,
        };

        let end_idx: usize =
            find_label_from(self.lines, no_exc_idx, "try_end_").unwrap_or(no_exc_idx + 25);
        let consumed: usize = end_idx.saturating_sub(start) + 1;
        Some((stmt, consumed))
    }

    fn try_tuple_unpack_const(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        let needle: &str = self.pack.make_iterator_infallible;
        if !line.contains(needle) {
            return None;
        }
        let inner: &str = extract_single_arg(line, needle)?;
        let source_tok: &str = inner.trim().trim_end_matches(';');

        let resolved_value: PythonExpr = self.resolve_tok(source_tok);
        if !matches!(&resolved_value, PythonExpr::Tuple(_) | PythonExpr::Const(_)) {
            return None;
        }

        let (var_targets, consumed): (Vec<String>, usize) =
            collect_unpack_targets(self.lines, start + 1);
        if var_targets.is_empty() {
            return None;
        }

        let stmt: PythonStmt = PythonStmt::TupleUnpackAssign {
            targets: var_targets,
            value: resolved_value,
        };
        Some((stmt, consumed + 1))
    }

    fn try_for_loop(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        let needle: &str = self.pack.binary_sub_long;
        if !line.contains(needle) {
            return None;
        }
        let args: (&str, &str) = extract_two_args(line, needle)?;
        let left: PythonExpr = self.resolve_tok(args.0);
        let right: PythonExpr = self.resolve_tok(args.1);
        let sub_expr: PythonExpr = PythonExpr::BinOp {
            op: BinOpKind::Sub,
            left: Box::new(left),
            right: Box::new(right),
        };

        let loop_start_idx: usize = find_label_from(self.lines, start + 1, "loop_start_")?;
        let loop_end_idx: usize = find_label_from(self.lines, loop_start_idx + 1, "loop_end_")?;

        let iter: PythonExpr = PythonExpr::Call {
            func: Box::new(PythonExpr::Name("range".to_owned())),
            args: vec![sub_expr],
        };

        let body_stmts: Vec<PythonStmt> = self.lift_range(loop_start_idx + 1, loop_end_idx);

        let stmt: PythonStmt = PythonStmt::For {
            target: "_".to_owned(),
            iter,
            body: body_stmts,
        };

        let consumed: usize = loop_end_idx.saturating_sub(start) + 1;
        Some((stmt, consumed))
    }

    fn try_print_call(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        if !line.contains(self.pack.lookup_builtin_print) {
            return None;
        }

        let accessor_line: &str =
            find_nearby_line(self.lines, start + 1, 5, "module_var_accessor_")?;
        let fn_name: String = extract_module_var_fn(accessor_line)?;

        let call_needle: &str = self.pack.call_pos_args1;
        let pos_args_line: &str = find_nearby_line(self.lines, start + 1, 25, call_needle)?;
        let tuple_tok: &str = extract_tuple_from_pos_args1(pos_args_line, call_needle)?;
        let arg: PythonExpr = resolve_const_token(tuple_tok, self.pool);
        let single_arg: PythonExpr = unwrap_single_tuple(arg);

        let call: PythonExpr = PythonExpr::Call {
            func: Box::new(PythonExpr::Name(fn_name)),
            args: vec![single_arg],
        };
        let print_call: PythonExpr = PythonExpr::Call {
            func: Box::new(PythonExpr::Name("print".to_owned())),
            args: vec![call],
        };

        let end_offset: usize =
            find_relative_offset(self.lines, start + 1, 18, "Py_DECREF(tmp_call_result_")
                .unwrap_or(14);

        Some((PythonStmt::Expr(print_call), end_offset + 1))
    }

    fn try_fstring_join(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        if !line.contains(self.pack.unicode_join) {
            return None;
        }

        let digest_line: &str = find_nearby_before(self.lines, start, 30, "const_str_digest_")?;
        let digest_tok: &str = extract_digest_token(digest_line)?;
        let prefix: PythonExpr = resolve_const_token(digest_tok, self.pool);

        let format_needle: &str = self.pack.builtin_format;
        let format_line: &str = find_nearby_before(self.lines, start, 30, format_needle)?;
        let param: &str = extract_format_param(format_line, format_needle)?;
        let param_expr: PythonExpr = if param.starts_with("par_") {
            PythonExpr::Name(param.strip_prefix("par_").unwrap_or(param).to_owned())
        } else if param.starts_with("var_") {
            PythonExpr::Name(param.strip_prefix("var_").unwrap_or(param).to_owned())
        } else {
            self.resolve_tok(param)
        };

        let fstring: PythonExpr = PythonExpr::FStringJoin {
            parts: vec![prefix, param_expr],
        };
        Some((PythonStmt::Return(fstring), 3))
    }

    fn try_raise(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        if !line.contains(self.pack.raise_exception_with_value) {
            return None;
        }

        let ctor_line: &str =
            find_nearby_before(self.lines, start, 30, "CALL_FUNCTION_WITH_SINGLE_ARG(")?;
        let (called, arg): (&str, &str) =
            extract_two_args(ctor_line, "CALL_FUNCTION_WITH_SINGLE_ARG(tstate,")?;
        let exc_name: String = builtin_exception_name(called.trim())?;
        let arg_expr: PythonExpr = self.resolve_tok(arg.trim());

        let raise_expr: PythonExpr = PythonExpr::Call {
            func: Box::new(PythonExpr::Name(exc_name)),
            args: vec![arg_expr],
        };
        Some((PythonStmt::Raise(raise_expr), 1))
    }

    fn try_return(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();

        if let Some(rhs) = try_parse_assignment(line, "tmp_return_value") {
            let rhs_tok: &str = rhs.trim().trim_end_matches(';');
            if rhs_tok.starts_with("PyUnicode_Join(") {
                return None;
            }
            if rhs_tok == "const_int_0" {
                return Some((PythonStmt::Return(PythonExpr::Const("0".to_owned())), 1));
            }
            if rhs_tok.starts_with("var_") {
                let name: String = rhs_tok.strip_prefix("var_").unwrap_or(rhs_tok).to_owned();
                return Some((PythonStmt::Return(PythonExpr::Name(name)), 1));
            }
            if rhs_tok.starts_with("par_") {
                let name: String = rhs_tok.strip_prefix("par_").unwrap_or(rhs_tok).to_owned();
                return Some((PythonStmt::Return(PythonExpr::Name(name)), 1));
            }
            let expr: PythonExpr = self.resolve_tok(rhs_tok);
            return Some((PythonStmt::Return(expr), 1));
        }

        None
    }
}

fn should_skip(line: &str) -> bool {
    let t: &str = line.trim();
    if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
        return true;
    }
    let skip_prefixes: &[&str] = &[
        "Py_INCREF",
        "Py_DECREF",
        "Py_XDECREF",
        "Py_XINCREF",
        "CONSIDER_THREADING",
        "FETCH_ERROR_OCCURRED_STATE",
        "pushFrameStack",
        "popFrameStack",
        "NUITKA_CANNOT_GET_HERE",
        "goto frame_exception_exit",
        "goto tuple_build_exception",
        "goto frame_return_exit",
        "goto function_return_exit",
        "goto function_exception_exit",
        "goto try_",
        "goto loop_start_",
        "goto loop_end_",
        "goto branch_",
        "assert(",
        "CHECK_OBJECT",
        "CHECK_EXCEPTION_STATE",
        "RESTORE_ERROR_OCCURRED_STATE",
        "NUITKA_MAY_BE_UNUSED",
        "static struct",
        "struct Nuitka_",
        "isFrameUnusable",
        "cache_frame_frame",
        "MAKE_FUNCTION_FRAME",
        "assertFrameObject",
        "Nuitka_Frame_AttachLocals",
        "if (isFrameUnusable",
        "count_active_frame",
        "count_released_frame",
        "count_allocated_frame",
        "count_hit_frame",
        "#if _DEBUG",
        "#endif",
        "#else",
        "} else {",
        "return NULL;",
        "PyObject *tmp_",
        "bool tmp_",
        "nuitka_bool tmp_",
        "NUITKA_MAY_BE_UNUSED bool",
        "NUITKA_MAY_BE_UNUSED nuitka_void",
        "NUITKA_MAY_BE_UNUSED int",
        "NUITKA_MAY_BE_UNUSED char",
        "exception_lineno",
        "exception_state",
        "exception_keeper",
        "type_description",
        "HAS_ERROR_OCCURRED",
        "HAS_EXCEPTION_STATE",
        "INIT_ERROR_OCCURRED_STATE",
        "GET_EXCEPTION_STATE",
        "SET_EXCEPTION_STATE",
        "ADD_TRACEBACK",
        "MAKE_TRACEBACK",
        "PyTracebackObject",
        "CHAIN_EXCEPTION",
        "FORMAT_UNBOUND_LOCAL_ERROR",
        "RAISE_CURRENT_EXCEPTION",
        "CHECK_AND_CLEAR_STOP_ITERATION",
        "if (tmp_condition_result_",
        "if (tmp_",
        "if (var_",
        "if (par_",
        "if (unlikely(",
        "PyObject *old",
        "old =",
        "Py_INCREF(var_",
        "Py_INCREF(par_",
        "Py_INCREF(tmp_",
        "frame_frame_",
        "f_lineno",
        "pushFrameStackCompiledFrame",
        "had_error",
        "try_except_handler_",
        "try_end_",
        "try_return_handler_",
        "MAKE_ITERATOR(",
        "MAKE_ITERATOR_INFALLIBLE(",
        "UNPACK_NEXT(",
        "UNPACK_ITERATOR_CHECK(",
        "BUILTIN_XRANGE1(",
        "PyTuple_SET_ITEM(",
        "ITERATOR_NEXT_ITERATOR(",
        "if (CHECK_AND_CLEAR_STOP_ITERATION",
    ];
    for prefix in skip_prefixes {
        if t.starts_with(prefix) {
            return true;
        }
    }
    if t.starts_with("PyObject *var_")
        || t.starts_with("PyObject *par_n")
        || t.starts_with("PyObject *par_name")
        || t.starts_with("PyObject *tmp_for_loop")
        || t.starts_with("PyObject *tmp_tuple_unpack")
        || t.starts_with("PyObject *tmp_string_concat")
    {
        return true;
    }
    if (t.starts_with("frame_") && t.ends_with(":;") && !t.starts_with("frame_no_exception"))
        || t == "{"
        || t == "}"
    {
        return true;
    }
    if t.starts_with("var__ =") {
        return true;
    }
    false
}

fn extract_two_args<'a>(line: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let after: &str = line.split(prefix).nth(1)?;
    let close: usize = after.find(')')?;
    let inner: &str = &after[..close];
    let mut depth: i32 = 0i32;
    let mut split_pos: Option<usize> = None;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                split_pos = Some(idx);
                break;
            }
            _ => {}
        }
    }
    let pos: usize = split_pos?;
    Some((inner[..pos].trim(), inner[pos + 1..].trim()))
}

fn extract_single_arg<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let after: &str = line.split(prefix).nth(1)?;
    let close: usize = after.find(')')?;
    Some(after[..close].trim())
}

fn find_label(lines: &[&str], label: &str) -> Option<usize> {
    lines.iter().position(|l: &&str| {
        let t: &str = l.trim();
        t == label || t.starts_with(label)
    })
}

fn find_label_from(lines: &[&str], from: usize, prefix: &str) -> Option<usize> {
    lines[from..]
        .iter()
        .position(|l: &&str| {
            let t: &str = l.trim();
            t.starts_with(prefix) && t.ends_with(":;")
        })
        .map(|rel: usize| rel + from)
}

fn find_branch_tag(lines: &[&str], from: usize, prefix: &str) -> Option<String> {
    lines[from..].iter().find_map(|l: &&str| {
        let t: &str = l.trim();
        if t.starts_with("goto ") {
            let tag: &str = t.trim_start_matches("goto ").trim_end_matches(';');
            if tag.starts_with(prefix) {
                return Some(tag.to_owned());
            }
        }
        None
    })
}

fn collect_unpack_targets(lines: &[&str], from: usize) -> (Vec<String>, usize) {
    let mut targets: Vec<String> = Vec::new();
    let mut i: usize = from;
    let mut found_any: bool = false;
    while i < lines.len() {
        let t: &str = lines[i].trim();
        if (found_any && targets.len() >= 2)
            || t.starts_with("loop_start_")
            || t.starts_with("loop_end_")
            || t.starts_with("CONSIDER_THREADING")
            || t.starts_with("if (CONSIDER_THREADING")
        {
            break;
        }
        if t.starts_with("PyObject *old = var_")
            && let Some(var) = extract_var_from_old_var(t)
            && !targets.contains(&var)
        {
            targets.push(var);
            found_any = true;
        }
        i += 1;
    }
    let consumed: usize = i - from;
    (targets, consumed)
}

fn extract_var_from_old_var(line: &str) -> Option<String> {
    let t: &str = line.trim();
    let after: &str = t.strip_prefix("PyObject *old = var_")?;
    let name: &str = after.split(';').next()?.trim();
    if name == "_" {
        return None;
    }
    Some(name.to_owned())
}

fn find_end_of_branch(lines: &[&str], from: usize) -> Option<usize> {
    for (i, l) in lines[from..].iter().enumerate() {
        let t: &str = l.trim();
        if t.starts_with("goto frame_return_exit_") || t == "}" {
            return Some(from + i);
        }
    }
    None
}

fn find_nearby_line<'a>(
    lines: &'a [&'a str],
    from: usize,
    window: usize,
    needle: &str,
) -> Option<&'a str> {
    let end: usize = (from + window).min(lines.len());
    lines[from..end]
        .iter()
        .find(|l: &&&str| l.contains(needle))
        .copied()
}

fn find_nearby_before<'a>(
    lines: &'a [&'a str],
    before: usize,
    window: usize,
    needle: &str,
) -> Option<&'a str> {
    let start: usize = before.saturating_sub(window);
    lines[start..before]
        .iter()
        .rev()
        .find(|l: &&&str| l.contains(needle))
        .copied()
}

fn find_relative_offset(lines: &[&str], from: usize, window: usize, needle: &str) -> Option<usize> {
    let end: usize = (from + window).min(lines.len());
    lines[from..end]
        .iter()
        .position(|l: &&str| l.contains(needle))
}

fn find_set_item0_var(lines: &[&str], from: usize, window: usize) -> Option<String> {
    let end: usize = (from + window).min(lines.len());
    for l in &lines[from..end] {
        let t: &str = l.trim();
        if let Some(after) = t.strip_prefix("PyTuple_SET_ITEM0(") {
            let close: usize = after.find(')')?;
            let inner: &str = &after[..close];
            if let Some(comma) = inner.rfind(',') {
                let var: &str = inner[comma + 1..].trim();
                if !var.is_empty() {
                    return Some(var.to_owned());
                }
            }
        }
    }
    None
}

fn extract_module_var_fn(line: &str) -> Option<String> {
    let t: &str = line.trim();
    let start: usize = t.find("module_var_accessor_")?;
    let after: &str = &t[start + "module_var_accessor_".len()..];
    let end: usize = after.find('(')?;
    let full: &str = &after[..end];
    full.split('$').next_back().map(str::to_owned)
}

fn extract_tuple_from_pos_args1<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let after: &str = line.split(prefix).nth(1)?;
    let close: usize = after.find(')')?;
    let inner: &str = &after[..close];
    let comma: usize = inner.rfind(',')?;
    let tok: &str = strip_mod_consts(inner[comma + 1..].trim().trim_end_matches(')'));
    Some(tok)
}

fn unwrap_single_tuple(expr: PythonExpr) -> PythonExpr {
    match expr {
        PythonExpr::Tuple(mut items) if items.len() == 1 => items.remove(0),
        other => other,
    }
}

fn try_parse_assignment<'a>(line: &'a str, lhs: &str) -> Option<&'a str> {
    let t: &str = line.trim();
    let prefix: String = format!("{lhs} = ");
    t.strip_prefix(prefix.as_str())
        .map(|s: &str| s.trim_end_matches(';'))
}

fn extract_digest_token(line: &str) -> Option<&str> {
    let start: usize = line.find("const_str_digest_")?;
    let rest: &str = &line[start..];
    let end: usize = rest.find([';', ',', ')', ' ']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn extract_format_param<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let after: &str = line.split(prefix).nth(1)?;
    let close: usize = after.find(')')?;
    let inner: &str = &after[..close];
    let comma: usize = inner.find(',')?;
    Some(inner[..comma].trim())
}

fn builtin_exception_name(called: &str) -> Option<String> {
    let name: &str = called.strip_prefix("PyExc_")?;
    if name.is_empty() || !name.chars().all(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name.to_owned())
}

pub fn lift_body(
    c_body: &str,
    _params: &[String],
    pool: &ConstantsPool,
) -> (Vec<PythonStmt>, LiftFidelity) {
    let pack: EraPatternPack = pack_for_era(guess_era_from_csource(c_body));
    let lines: Vec<&str> = c_body.lines().collect();
    let ctx: BodyCtx<'_> = BodyCtx::new(&lines, pool, pack);
    let stmts: Vec<PythonStmt> = ctx.lift();

    let fidelity: LiftFidelity = if stmts.is_empty() {
        LiftFidelity::Skeleton
    } else if stmts.iter().any(stmt_has_unresolved) {
        LiftFidelity::PartialBody
    } else {
        LiftFidelity::FullBody
    };

    (stmts, fidelity)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn lit(token: &str) -> String {
        let pool: ConstantsPool = ConstantsPool::default();
        match resolve_const_token(token, &pool) {
            PythonExpr::Const(s) => s,
            other => panic!("expected Const for `{token}`, got {other:?}"),
        }
    }

    #[test]
    fn singleton_tokens_invert_to_python_literals() {
        assert_eq!(lit("const_true"), "True");
        assert_eq!(lit("const_false"), "False");
        assert_eq!(lit("const_none"), "None");
        assert_eq!(lit("const_ellipsis"), "...");
    }

    #[test]
    fn integer_tokens_cover_zero_pos_neg_hex() {
        assert_eq!(lit("const_int_0"), "0");
        assert_eq!(lit("const_int_pos_42"), "42");
        assert_eq!(lit("const_int_neg_7"), "-7");
        assert_eq!(lit("const_int_hex_deadbeef"), "0xdeadbeef");
        assert_eq!(lit("const_long_pos_100"), "100");
        assert_eq!(lit("const_long_neg_3"), "-3");
    }

    #[test]
    fn float_tokens_restore_dot_and_sign() {
        assert_eq!(lit("const_float_3_14"), "3.14");
        assert_eq!(lit("const_float_minus_1_5"), "-1.5");
        assert_eq!(lit("const_float_plus_nan"), "float('nan')");
    }

    #[test]
    fn string_tokens_cover_plain_special_and_chr() {
        assert_eq!(lit("const_str_plain_hello"), "'hello'");
        assert_eq!(lit("const_str_empty"), "''");
        assert_eq!(lit("const_str_space"), "' '");
        assert_eq!(lit("const_str_dot"), "'.'");
        assert_eq!(lit("const_str_newline"), "'\\n'");
        assert_eq!(lit("const_str_underscore"), "'_'");
        assert_eq!(lit("const_str_chr_65"), "'A'");
        assert_eq!(lit("const_str_angle_module"), "'<module>'");
    }

    #[test]
    fn bytes_tokens_carry_b_prefix() {
        assert_eq!(lit("const_bytes_plain_data"), "b'data'");
        assert_eq!(lit("const_bytes_empty"), "b''");
    }

    #[test]
    fn empty_collection_tokens_invert() {
        let pool: ConstantsPool = ConstantsPool::default();
        assert_eq!(
            resolve_const_token("const_tuple_empty", &pool),
            PythonExpr::Tuple(Vec::new())
        );
        assert_eq!(
            resolve_const_token("const_list_empty", &pool),
            PythonExpr::List(Vec::new())
        );
    }

    #[test]
    fn nested_sequence_fragments_split_correctly() {
        let pool: ConstantsPool = ConstantsPool::default();
        let got: PythonExpr = resolve_const_token("const_tuple_int_0_int_pos_1_tuple", &pool);
        assert_eq!(
            got,
            PythonExpr::Tuple(vec![
                PythonExpr::Const("0".to_owned()),
                PythonExpr::Const("1".to_owned()),
            ])
        );

        let mixed: PythonExpr =
            resolve_const_token("const_tuple_str_plain_name_int_neg_2_true_tuple", &pool);
        assert_eq!(
            mixed,
            PythonExpr::Tuple(vec![
                PythonExpr::Const("'name'".to_owned()),
                PythonExpr::Const("-2".to_owned()),
                PythonExpr::Const("True".to_owned()),
            ])
        );
    }

    #[test]
    fn list_sequence_fragment_yields_list_expr() {
        let pool: ConstantsPool = ConstantsPool::default();
        let got: PythonExpr = resolve_const_token("const_list_int_pos_1_int_pos_2_list", &pool);
        assert_eq!(
            got,
            PythonExpr::List(vec![
                PythonExpr::Const("1".to_owned()),
                PythonExpr::Const("2".to_owned()),
            ])
        );
    }

    #[test]
    fn split_tuple_handles_atomic_and_segment_mix() {
        let frags: Vec<String> = split_tuple_tokens("none_str_plain_x_int_0_ellipsis");
        assert_eq!(
            frags,
            vec![
                "const_none".to_owned(),
                "const_str_plain_x".to_owned(),
                "const_int_0".to_owned(),
                "const_ellipsis".to_owned(),
            ]
        );
    }

    #[test]
    fn builtin_exception_name_strips_pyexc_prefix() {
        assert_eq!(
            builtin_exception_name("PyExc_SystemExit"),
            Some("SystemExit".to_owned())
        );
        assert_eq!(
            builtin_exception_name("PyExc_ValueError"),
            Some("ValueError".to_owned())
        );
        assert_eq!(builtin_exception_name("tmp_called_value_1"), None);
        assert_eq!(builtin_exception_name("PyExc_"), None);
    }

    #[test]
    fn raise_idiom_lifts_to_raise_statement() {
        let body: &str = r"{
tmp_raise_type_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, PyExc_ValueError, mod_consts.const_str_plain_boom);
exception_state.exception_value = tmp_raise_type_1;
exception_lineno = 3;
RAISE_EXCEPTION_WITH_VALUE(tstate, &exception_state);
goto frame_exception_exit_1;
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let (stmts, _): (Vec<PythonStmt>, LiftFidelity) = lift_body(body, &[], &pool);
        assert_eq!(
            stmts,
            vec![PythonStmt::Raise(PythonExpr::Call {
                func: Box::new(PythonExpr::Name("ValueError".to_owned())),
                args: vec![PythonExpr::Const("'boom'".to_owned())],
            })]
        );
    }
}
