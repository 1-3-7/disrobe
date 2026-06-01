use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::constants::ConstantsPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiftFidelity {
    FullBody,
    PartialBody,
    Skeleton,
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
    if t == "const_int_0" || t == "global_constants[2]" {
        return PythonExpr::Const("0".to_owned());
    }
    if let Some(rest) = t.strip_prefix("const_int_pos_") {
        return PythonExpr::Const(rest.to_owned());
    }
    if let Some(rest) = t.strip_prefix("const_int_neg_") {
        return PythonExpr::Const(format!("-{rest}"));
    }
    if let Some(rest) = t.strip_prefix("const_str_plain_") {
        return PythonExpr::Const(format!("'{rest}'"));
    }
    if t == "const_str_empty" {
        return PythonExpr::Const("''".to_owned());
    }
    if let Some(hex) = t.strip_prefix("const_str_digest_") {
        if let Some(s) = pool.digest_to_string.get(hex) {
            return PythonExpr::Const(format!("'{s}'"));
        }
        return PythonExpr::Const(format!("UNRESOLVED:{hex}"));
    }
    if let Some(inner) = t.strip_prefix("const_tuple_")
        && let Some(inner2) = inner.strip_suffix("_tuple")
    {
        return resolve_tuple_inner(inner2, pool);
    }
    PythonExpr::Name(t.to_owned())
}

fn resolve_tuple_inner(inner: &str, pool: &ConstantsPool) -> PythonExpr {
    let items: Vec<PythonExpr> = split_tuple_tokens(inner)
        .into_iter()
        .map(|tok: String| resolve_const_token(&tok, pool))
        .collect();
    PythonExpr::Tuple(items)
}

fn split_tuple_tokens(inner: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut remaining: &str = inner;
    loop {
        if remaining.is_empty() {
            break;
        }
        if let Some(r) = remaining.strip_prefix("str_plain_") {
            let end: usize = r.find('_').unwrap_or(r.len());
            let name: &str = &r[..end];
            out.push(format!("const_str_plain_{name}"));
            remaining = if end < r.len() { &r[end + 1..] } else { "" };
        } else if let Some(r) = remaining.strip_prefix("str_digest_") {
            let end: usize = r.find('_').unwrap_or(r.len());
            let hex: &str = &r[..end];
            out.push(format!("const_str_digest_{hex}"));
            remaining = if end < r.len() { &r[end + 1..] } else { "" };
        } else if let Some(r) = remaining.strip_prefix("int_pos_") {
            let end: usize = r.find('_').unwrap_or(r.len());
            let num: &str = &r[..end];
            out.push(format!("const_int_pos_{num}"));
            remaining = if end < r.len() { &r[end + 1..] } else { "" };
        } else if let Some(r) = remaining.strip_prefix("int_neg_") {
            let end: usize = r.find('_').unwrap_or(r.len());
            let num: &str = &r[..end];
            out.push(format!("const_int_neg_{num}"));
            remaining = if end < r.len() { &r[end + 1..] } else { "" };
        } else if remaining.starts_with("int_0") {
            out.push("const_int_0".to_owned());
            remaining = remaining.strip_prefix("int_0").unwrap_or(remaining);
            remaining = remaining.strip_prefix('_').unwrap_or(remaining);
        } else {
            let end: usize = remaining.find('_').unwrap_or(remaining.len());
            out.push(remaining[..end].to_owned());
            remaining = if end < remaining.len() {
                &remaining[end + 1..]
            } else {
                ""
            };
        }
    }
    out
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
        PythonExpr::Tuple(items) => items.iter().any(contains_unresolved),
    }
}

fn stmt_has_unresolved(stmt: &PythonStmt) -> bool {
    match stmt {
        PythonStmt::Return(e) | PythonStmt::Expr(e) => contains_unresolved(e),
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
    map: BTreeMap<String, PythonExpr>,
    stmts: Vec<PythonStmt>,
}

impl<'a> BodyCtx<'a> {
    fn new(lines: &'a [&'a str], pool: &'a ConstantsPool) -> Self {
        let map: BTreeMap<String, PythonExpr> = build_tmp_map(lines, pool);
        Self {
            lines,
            pool,
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
        if !line.contains("RICH_COMPARE_LT_NBOOL_OBJECT_LONG(") {
            return None;
        }
        let args: (&str, &str) = extract_two_args(line, "RICH_COMPARE_LT_NBOOL_OBJECT_LONG(")?;
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
        let child: BodyCtx<'_> = BodyCtx::new(slice, self.pool);
        child.lift()
    }

    fn try_runtime_tuple_unpack(&self, start: usize) -> Option<(PythonStmt, usize)> {
        let line: &str = self.lines[start].trim();
        if !line.contains("MAKE_TUPLE_EMPTY(") {
            return None;
        }

        let first_raw: String = find_set_item0_var(self.lines, start + 1, 6)?;
        let first_expr: PythonExpr = self.resolve_tok(&first_raw);
        let add_line: &str = find_nearby_line(
            self.lines,
            start + 1,
            40,
            "BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(",
        )?;
        let add_args: (&str, &str) =
            extract_two_args(add_line, "BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(")?;
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
        if !line.contains("MAKE_ITERATOR_INFALLIBLE(") {
            return None;
        }
        let inner: &str = extract_single_arg(line, "MAKE_ITERATOR_INFALLIBLE(")?;
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
        if !line.contains("BINARY_OPERATION_SUB_OBJECT_OBJECT_LONG(") {
            return None;
        }
        let args: (&str, &str) =
            extract_two_args(line, "BINARY_OPERATION_SUB_OBJECT_OBJECT_LONG(")?;
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
        if !line.contains("LOOKUP_BUILTIN(const_str_plain_print)") {
            return None;
        }

        let accessor_line: &str =
            find_nearby_line(self.lines, start + 1, 5, "module_var_accessor_")?;
        let fn_name: String = extract_module_var_fn(accessor_line)?;

        let pos_args_line: &str =
            find_nearby_line(self.lines, start + 1, 25, "CALL_FUNCTION_WITH_POS_ARGS1(")?;
        let tuple_tok: &str = extract_tuple_from_pos_args1(pos_args_line)?;
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
        if !line.contains("PyUnicode_Join(") {
            return None;
        }

        let digest_line: &str = find_nearby_before(self.lines, start, 30, "const_str_digest_")?;
        let digest_tok: &str = extract_digest_token(digest_line)?;
        let prefix: PythonExpr = resolve_const_token(digest_tok, self.pool);

        let format_line: &str =
            find_nearby_before(self.lines, start, 30, "BUILTIN_FORMAT(tstate,")?;
        let param: &str = extract_format_param(format_line)?;
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

fn extract_tuple_from_pos_args1(line: &str) -> Option<&str> {
    let after: &str = line.split("CALL_FUNCTION_WITH_POS_ARGS1(").nth(1)?;
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

fn extract_format_param(line: &str) -> Option<&str> {
    let after: &str = line.split("BUILTIN_FORMAT(tstate,").nth(1)?;
    let close: usize = after.find(')')?;
    let inner: &str = &after[..close];
    let comma: usize = inner.find(',')?;
    Some(inner[..comma].trim())
}

pub fn lift_body(
    c_body: &str,
    _params: &[String],
    pool: &ConstantsPool,
) -> (Vec<PythonStmt>, LiftFidelity) {
    let lines: Vec<&str> = c_body.lines().collect();
    let ctx: BodyCtx<'_> = BodyCtx::new(&lines, pool);
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
