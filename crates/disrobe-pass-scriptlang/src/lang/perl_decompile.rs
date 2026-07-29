use serde::Serialize;

use crate::lang::perl::{PerlOp, PerlOpTree, PerlSub};

const INDENT: &str = "    ";
const ERASED_MARKER: &str =
    "# <expression erased: package-global temporaries are not named in the op-tree>";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlStatement {
    pub text: String,
    pub recovered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlSubSource {
    pub name: String,
    pub is_main_program: bool,
    pub signature: Option<String>,
    pub statements: Vec<PerlStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlSource {
    pub source_hint: Option<String>,
    pub subs: Vec<PerlSubSource>,
    pub rendered: String,
    pub statements_total: usize,
    pub statements_recovered: usize,
}

impl PerlSource {
    #[must_use]
    pub fn recovery_ratio(&self) -> f64 {
        if self.statements_total == 0 {
            return 1.0;
        }
        self.statements_recovered as f64 / self.statements_total as f64
    }
}

#[derive(Debug)]
pub struct DecompileWalker<'a> {
    tree: &'a PerlOpTree,
}

impl<'a> DecompileWalker<'a> {
    #[must_use]
    pub const fn new(tree: &'a PerlOpTree) -> Self {
        Self { tree }
    }

    #[must_use]
    pub fn decompile(&self) -> PerlSource {
        let subs: Vec<PerlSubSource> = self
            .tree
            .subs
            .iter()
            .map(|sub: &PerlSub| Self::decompile_sub(sub))
            .collect();
        let rendered: String = Self::render(self.tree.source_hint.as_deref(), &subs);
        let statements_total: usize = subs
            .iter()
            .map(|s: &PerlSubSource| s.statements.len())
            .sum();
        let statements_recovered: usize = subs
            .iter()
            .flat_map(|s: &PerlSubSource| s.statements.iter())
            .filter(|st: &&PerlStatement| st.recovered)
            .count();
        PerlSource {
            source_hint: self.tree.source_hint.clone(),
            subs,
            rendered,
            statements_total,
            statements_recovered,
        }
    }

    fn decompile_sub(sub: &PerlSub) -> PerlSubSource {
        let raw: Vec<&[PerlOp]> = split_statements(&sub.ops);
        let segments: Vec<Vec<PerlOp>> = merge_block_segments(&raw);
        let signature: Option<String> = recover_signature_owned(&segments);
        let sig_index: usize = segments
            .iter()
            .position(|seg: &Vec<PerlOp>| is_my_args_assignment(seg))
            .map_or(usize::MAX, |value: usize| value);
        let mut statements: Vec<PerlStatement> = Vec::new();
        for (idx, seg) in segments.iter().enumerate() {
            if signature.is_some() && idx == sig_index {
                continue;
            }
            let stmt: PerlStatement = reconstruct_statement(seg).unwrap_or_else(|| PerlStatement {
                text: format!("# <unrecovered op sequence: {} ops>", seg.len()),
                recovered: false,
            });
            statements.push(stmt);
        }
        PerlSubSource {
            name: sub.name.clone(),
            is_main_program: sub.is_main_program,
            signature,
            statements,
        }
    }

    fn render(source_hint: Option<&str>, subs: &[PerlSubSource]) -> String {
        let mut out: String = String::new();
        out.push_str("use strict;\n");
        out.push_str("use warnings;\n");
        if let Some(hint) = source_hint {
            out.push_str("# recovered from op-tree of ");
            out.push_str(hint);
            out.push('\n');
        }
        out.push('\n');
        for sub in subs.iter().filter(|s: &&PerlSubSource| !s.is_main_program) {
            render_named_sub(&mut out, sub);
            out.push('\n');
        }
        for sub in subs.iter().filter(|s: &&PerlSubSource| s.is_main_program) {
            for stmt in &sub.statements {
                out.push_str(&stmt.text);
                out.push('\n');
            }
        }
        out
    }
}

fn render_named_sub(out: &mut String, sub: &PerlSubSource) {
    let short: &str = sub
        .name
        .strip_prefix("main::")
        .map_or(&sub.name, |value: &str| value);
    out.push_str("sub ");
    out.push_str(short);
    out.push_str(" {\n");
    if let Some(sig) = &sub.signature {
        out.push_str(INDENT);
        out.push_str(sig);
        out.push('\n');
    }
    for stmt in &sub.statements {
        out.push_str(INDENT);
        out.push_str(&stmt.text);
        out.push('\n');
    }
    out.push_str("}\n");
}

fn split_statements(ops: &[PerlOp]) -> Vec<&[PerlOp]> {
    let mut bounds: Vec<usize> = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        if matches!(op.name.as_str(), "nextstate" | "dbstate") {
            bounds.push(idx);
        }
    }
    if bounds.is_empty() {
        return if ops.is_empty() {
            Vec::new()
        } else {
            vec![ops]
        };
    }
    let mut segments: Vec<&[PerlOp]> = Vec::with_capacity(bounds.len());
    for window in 0..bounds.len() {
        let start: usize = bounds[window] + 1;
        let end: usize = bounds
            .get(window + 1)
            .copied()
            .map_or(ops.len(), |value: usize| value);
        if start < end {
            segments.push(&ops[start..end]);
        }
    }
    segments
}

fn merge_block_segments(raw: &[&[PerlOp]]) -> Vec<Vec<PerlOp>> {
    let mut merged: Vec<Vec<PerlOp>> = Vec::with_capacity(raw.len());
    let mut idx: usize = 0usize;
    while idx < raw.len() {
        let seg: &[PerlOp] = raw[idx];
        if seg.iter().any(|o: &PerlOp| o.name == "enterloop")
            && !seg.iter().any(|o: &PerlOp| o.name == "unstack")
        {
            let mut block: Vec<PerlOp> = seg.to_vec();
            idx += 1;
            while idx < raw.len() {
                let follow: &[PerlOp] = raw[idx];
                let closes: bool = follow.iter().any(|o: &PerlOp| o.name == "unstack");
                block.extend_from_slice(follow);
                idx += 1;
                if closes {
                    break;
                }
            }
            merged.push(block);
        } else {
            merged.push(seg.to_vec());
            idx += 1;
        }
    }
    merged
}

fn recover_signature_owned(segments: &[Vec<PerlOp>]) -> Option<String> {
    let seg: &Vec<PerlOp> = segments
        .iter()
        .find(|s: &&Vec<PerlOp>| is_my_args_assignment(s))?;
    let pads: Vec<String> = collect_pad_names(seg);
    if pads.is_empty() {
        return None;
    }
    Some(format!("my ({}) = @_;", pads.join(", ")))
}

fn is_my_args_assignment(seg: &[PerlOp]) -> bool {
    let has_assign: bool = seg.iter().any(|o: &PerlOp| o.name == "aassign");
    let has_args: bool = seg.iter().any(|o: &PerlOp| {
        o.name == "gv" && o.detail.as_deref().is_some_and(|d: &str| d.contains("*_"))
    });
    let has_pad_intro: bool = seg
        .iter()
        .any(|o: &PerlOp| matches!(o.name.as_str(), "padrange" | "padsv" | "padav" | "padhv"));
    has_assign && has_args && has_pad_intro
}

fn reconstruct_statement(seg: &[PerlOp]) -> Option<PerlStatement> {
    if let Some(stmt) = reconstruct_conditional(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_while_loop(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_return(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_print(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_my_call_assignment(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_in_place_assignment(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_my_scalar_assignment(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_bare_call(seg) {
        return Some(stmt);
    }
    None
}

fn reconstruct_conditional(seg: &[PerlOp]) -> Option<PerlStatement> {
    let guard_idx: usize = seg.iter().position(|o: &PerlOp| {
        matches!(o.name.as_str(), "and" | "or") && !o.name.starts_with("ex-")
    })?;
    if seg.iter().any(|o: &PerlOp| o.name == "enterloop") {
        return None;
    }
    let keyword: &str = if seg[guard_idx].name == "or" {
        "unless"
    } else {
        "if"
    };
    let cond: String = recover_condition(&seg[guard_idx..])?;
    let body: &[PerlOp] = &seg[guard_idx + 1..];
    let inner: String = recover_branch_body(body)?;
    Some(PerlStatement {
        text: format!("{keyword} ({cond}) {{ {inner} }}"),
        recovered: true,
    })
}

fn reconstruct_while_loop(seg: &[PerlOp]) -> Option<PerlStatement> {
    let enter_idx: usize = seg.iter().position(|o: &PerlOp| o.name == "enterloop")?;
    let is_foreach: bool = seg
        .iter()
        .any(|o: &PerlOp| matches!(o.name.as_str(), "enteriter" | "iter"));
    let guard_idx: Option<usize> = seg
        .iter()
        .position(|o: &PerlOp| matches!(o.name.as_str(), "and" | "or"));
    let body_start: usize = seg
        .iter()
        .skip(enter_idx)
        .position(|o: &PerlOp| o.name == "lineseq")
        .map(|rel: usize| enter_idx + rel + 1)
        .map_or(enter_idx + 1, |value: usize| value);
    let body: &[PerlOp] = match seg.iter().position(|o: &PerlOp| o.name == "unstack") {
        Some(end) if end > body_start => &seg[body_start..end],
        _ => &seg[body_start..],
    };
    let inner: String = recover_branch_body(body)?;
    match guard_idx {
        Some(gi) if !is_foreach => {
            let cond: String = recover_condition(&seg[gi..])?;
            Some(PerlStatement {
                text: format!("while ({cond}) {{ {inner} }}"),
                recovered: true,
            })
        }
        _ => Some(PerlStatement {
            text: format!("for (;;) {{ {inner} }}"),
            recovered: true,
        }),
    }
}

fn recover_condition(seg: &[PerlOp]) -> Option<String> {
    if let Some(cmp_idx) = seg.iter().position(|o: &PerlOp| is_comparison(&o.name)) {
        let sym: &str = comparison_symbol(&seg[cmp_idx].name);
        let operands: Vec<String> = scalar_operand_list(&seg[cmp_idx..]);
        if operands.len() >= 2 {
            return Some(format!("{} {sym} {}", operands[0], operands[1]));
        }
        return None;
    }
    let guard_end: usize = seg
        .iter()
        .position(|o: &PerlOp| matches!(o.name.as_str(), "lineseq" | "scope" | "nextstate"))
        .map_or(seg.len(), |value: usize| value);
    let operands: Vec<String> = scalar_operand_list(&seg[..guard_end]);
    match operands.as_slice() {
        [single] => Some(single.clone()),
        _ => None,
    }
}

fn scalar_operand_list(seg: &[PerlOp]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for op in seg {
        match op.name.as_str() {
            "padsv" | "padav" | "padhv" => {
                if let Some(detail) = op.detail.as_deref()
                    && let Some(name) = first_pad_name(detail)
                {
                    out.push(name);
                }
            }
            "const" => {
                if let Some(lit) = op.detail.as_deref().and_then(const_literal) {
                    out.push(lit);
                }
            }
            _ => {}
        }
        if out.len() >= 2 {
            break;
        }
    }
    out
}

fn recover_branch_body(body: &[PerlOp]) -> Option<String> {
    if let Some(ret_idx) = body.iter().position(|o: &PerlOp| o.name == "return") {
        let expr: String = recover_expression(&body[ret_idx..])?;
        return Some(format!("return {expr};"));
    }
    if let Some(target) = targmy_target(body) {
        let rhs: String = targmy_rhs(body)?;
        return Some(format!("{target} = {rhs};"));
    }
    if let Some(store_idx) = body.iter().position(|o: &PerlOp| o.name == "padsv_store") {
        let stmt: PerlStatement = reconstruct_my_scalar_assignment(&body[store_idx..])?;
        return Some(stmt.text);
    }
    None
}

fn reconstruct_in_place_assignment(seg: &[PerlOp]) -> Option<PerlStatement> {
    let target: String = targmy_target(seg)?;
    let rhs: String = targmy_rhs(seg)?;
    let prefix: &str = if targmy_is_intro(seg) { "my " } else { "" };
    Some(PerlStatement {
        text: format!("{prefix}{target} = {rhs};"),
        recovered: true,
    })
}

fn targmy_is_intro(seg: &[PerlOp]) -> bool {
    seg.iter().any(|o: &PerlOp| {
        (is_binary_op(&o.name) || o.name.starts_with("multiconcat"))
            && o.flags.contains("TARGMY")
            && o.flags.contains("LVINTRO")
    })
}

fn reconstruct_my_scalar_assignment(seg: &[PerlOp]) -> Option<PerlStatement> {
    let store: &PerlOp = seg.iter().find(|o: &&PerlOp| o.name == "padsv_store")?;
    if seg.iter().any(|o: &PerlOp| o.name == "entersub") {
        return None;
    }
    let lhs: String = store.detail.as_deref().and_then(first_pad_name)?;
    let rhs: String = recover_assignment_rhs(seg, &lhs)?;
    Some(PerlStatement {
        text: format!("my {lhs} = {rhs};"),
        recovered: true,
    })
}

fn recover_assignment_rhs(seg: &[PerlOp], lhs: &str) -> Option<String> {
    if let Some(op) = multiconcat_op_in(seg) {
        let pads: Vec<String> = operand_list(seg);
        return render_concat(op, &pads);
    }
    if let Some(op_idx) = seg.iter().position(|o: &PerlOp| is_binary_op(&o.name)) {
        let operands: Vec<String> = scalar_operand_list(&seg[op_idx..]);
        if operands.len() >= 2 {
            let sym: &str = binary_symbol(&seg[op_idx].name);
            return Some(format!("{} {sym} {}", operands[0], operands[1]));
        }
    }
    if let Some(op) = seg.iter().find(|o: &&PerlOp| o.name == "const")
        && let Some(lit) = op.detail.as_deref().and_then(const_literal)
    {
        return Some(lit);
    }
    let operands: Vec<String> = operand_list(seg);
    operands.into_iter().find(|name: &String| name != lhs)
}

fn targmy_target(seg: &[PerlOp]) -> Option<String> {
    seg.iter().find_map(|o: &PerlOp| {
        if !is_binary_op(&o.name) && !o.name.starts_with("multiconcat") {
            return None;
        }
        if !o.flags.contains("TARGMY") {
            return None;
        }
        o.detail.as_deref().and_then(first_pad_name)
    })
}

fn targmy_rhs(seg: &[PerlOp]) -> Option<String> {
    let op: &PerlOp = seg.iter().find(|o: &&PerlOp| {
        (is_binary_op(&o.name) || o.name.starts_with("multiconcat")) && o.flags.contains("TARGMY")
    })?;
    if op.name.starts_with("multiconcat") {
        let pads: Vec<String> = operand_list(seg);
        return render_concat(op, &pads);
    }
    let operands: Vec<String> = operand_list(seg);
    let literal: Option<String> = seg
        .iter()
        .find(|o: &&PerlOp| o.name == "const")
        .and_then(|o: &PerlOp| o.detail.as_deref().and_then(const_literal));
    let sym: &str = binary_symbol(&op.name);
    match (operands.first(), operands.get(1), literal) {
        (Some(a), Some(b), _) => Some(format!("{a} {sym} {b}")),
        (Some(a), None, Some(lit)) => Some(format!("{a} {sym} {lit}")),
        _ => None,
    }
}

fn reconstruct_return(seg: &[PerlOp]) -> Option<PerlStatement> {
    let is_return: bool = seg
        .iter()
        .any(|o: &PerlOp| matches!(o.name.as_str(), "return" | "leavesub"));
    if !is_return {
        return None;
    }
    match recover_expression(seg) {
        Some(expr) => Some(PerlStatement {
            text: format!("return {expr};"),
            recovered: true,
        }),
        None => Some(PerlStatement {
            text: format!("return; {ERASED_MARKER}"),
            recovered: false,
        }),
    }
}

fn reconstruct_print(seg: &[PerlOp]) -> Option<PerlStatement> {
    if !seg.iter().any(|o: &PerlOp| o.name == "print") {
        return None;
    }
    match recover_print_args(seg) {
        Some(args) => Some(PerlStatement {
            text: format!("print {args};"),
            recovered: true,
        }),
        None => Some(PerlStatement {
            text: format!("print ...; {ERASED_MARKER}"),
            recovered: false,
        }),
    }
}

fn reconstruct_my_call_assignment(seg: &[PerlOp]) -> Option<PerlStatement> {
    let store: &PerlOp = seg
        .iter()
        .find(|o: &&PerlOp| matches!(o.name.as_str(), "padsv_store" | "sassign"))?;
    let lhs: String = store
        .detail
        .as_deref()
        .and_then(first_pad_name)
        .unwrap_or_else(|| "$_".to_owned());
    let callee: String = called_name(seg)?;
    let args: String = call_arguments(seg);
    Some(PerlStatement {
        text: format!("my {lhs} = {callee}({args});"),
        recovered: true,
    })
}

fn reconstruct_bare_call(seg: &[PerlOp]) -> Option<PerlStatement> {
    if !seg.iter().any(|o: &PerlOp| o.name == "entersub") {
        return None;
    }
    let callee: String = called_name(seg)?;
    let args: String = call_arguments(seg);
    Some(PerlStatement {
        text: format!("{callee}({args});"),
        recovered: true,
    })
}

fn recover_expression(seg: &[PerlOp]) -> Option<String> {
    if let Some(op) = multiconcat_op_in(seg) {
        let pads: Vec<String> = operand_list(seg);
        return render_concat(op, &pads);
    }
    let operands: Vec<String> = operand_list(seg);
    if let Some(op) = seg.iter().find(|o: &&PerlOp| is_binary_op(&o.name))
        && operands.len() >= 2
    {
        let sym: &str = binary_symbol(&op.name);
        return Some(format!("{} {sym} {}", operands[0], operands[1]));
    }
    if let Some(op) = seg.iter().find(|o: &&PerlOp| o.name == "const")
        && let Some(lit) = op.detail.as_deref().and_then(const_literal)
    {
        return Some(lit);
    }
    if operands.len() == 1 {
        return Some(operands[0].clone());
    }
    None
}

fn recover_print_args(seg: &[PerlOp]) -> Option<String> {
    if let Some(op) = multiconcat_op_in(seg) {
        let pads: Vec<String> = operand_list(seg);
        return render_concat(op, &pads);
    }
    if let Some(idx) = callee_index(seg) {
        let name: String = gv_call_name(&seg[idx])?;
        let args: String = operand_tokens(&seg[..idx]).join(", ");
        let mut items: Vec<String> = vec![format!("{name}({args})")];
        items.extend(operand_tokens(&seg[idx + 1..]));
        return Some(items.join(", "));
    }
    let pads: Vec<String> = collect_pad_names(seg);
    if !pads.is_empty() {
        return Some(pads.join(", "));
    }
    None
}

fn operand_list(seg: &[PerlOp]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for op in seg {
        if matches!(op.name.as_str(), "padsv" | "padav" | "padhv")
            && let Some(detail) = op.detail.as_deref()
            && let Some(name) = first_pad_name(detail)
        {
            names.push(name);
        }
    }
    names
}

fn collect_pad_names(seg: &[PerlOp]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for op in seg {
        if matches!(
            op.name.as_str(),
            "padsv" | "padav" | "padhv" | "padrange" | "padsv_store"
        ) && let Some(detail) = op.detail.as_deref()
        {
            for name in pad_names_in(detail) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

fn pad_names_in(detail: &str) -> Vec<String> {
    let inner: &str = match (detail.rfind('['), detail.rfind(']')) {
        (Some(open), Some(close)) if close > open => &detail[open + 1..close],
        _ => detail.trim_start_matches('[').trim_end_matches(']'),
    };
    inner
        .split(';')
        .filter_map(|seg: &str| {
            let token: &str = seg.trim();
            let name: &str = token
                .split(':')
                .next()
                .map_or(token, |value: &str| value)
                .trim();
            if name.starts_with('$') || name.starts_with('@') || name.starts_with('%') {
                Some(name.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn first_pad_name(detail: &str) -> Option<String> {
    pad_names_in(detail).into_iter().next()
}

fn gv_call_name(op: &PerlOp) -> Option<String> {
    if op.name != "gv" {
        return None;
    }
    let detail: &str = op.detail.as_deref()?;
    let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
    let name: &str = inner.trim_start_matches('*');
    if name.is_empty() || name == "_" {
        None
    } else {
        Some(name.to_owned())
    }
}

fn callee_index(seg: &[PerlOp]) -> Option<usize> {
    seg.iter()
        .position(|op: &PerlOp| gv_call_name(op).is_some())
}

fn called_name(seg: &[PerlOp]) -> Option<String> {
    seg.iter().find_map(gv_call_name)
}

fn call_arguments(seg: &[PerlOp]) -> String {
    let end: usize = callee_index(seg).map_or(seg.len(), |idx: usize| idx);
    operand_tokens(&seg[..end]).join(", ")
}

fn operand_tokens(seg: &[PerlOp]) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    for op in seg {
        match op.name.as_str() {
            "const" => {
                if let Some(lit) = op.detail.as_deref().and_then(const_literal) {
                    args.push(lit);
                }
            }
            "padsv" | "padav" | "padhv" => {
                if let Some(name) = op.detail.as_deref().and_then(first_pad_name) {
                    args.push(name);
                }
            }
            _ => {}
        }
    }
    args
}

fn const_literal(detail: &str) -> Option<String> {
    let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
    let inner: &str = inner.trim();
    if let Some(rest) = inner.strip_prefix("PV ") {
        let lit: &str = rest.trim().trim_matches('"');
        return Some(format!("\"{lit}\""));
    }
    if let Some(rest) = inner
        .strip_prefix("IV ")
        .or_else(|| inner.strip_prefix("NV "))
    {
        return Some(rest.trim().to_owned());
    }
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_owned())
    }
}

const MAX_MULTICONCAT_SEGMENTS: usize = 256;
const STRINGIFY_PRIVATE_FLAG: &str = "STRINGIFY";
const CONCAT_JOINER: &str = " . ";
const ELIDED_OPERAND: &str = "${...}";

fn multiconcat_op_in(seg: &[PerlOp]) -> Option<&PerlOp> {
    seg.iter()
        .find(|op: &&PerlOp| op.name.starts_with("multiconcat"))
}

fn render_concat(op: &PerlOp, pads: &[String]) -> Option<String> {
    let detail: &str = op.detail.as_deref()?;
    Some(render_concat_detail(
        detail,
        op.flags.contains(STRINGIFY_PRIVATE_FLAG),
        pads,
    ))
}

struct MultiConcatLayout {
    template: String,
    lengths: Vec<i64>,
}

fn parse_multiconcat(detail: &str) -> Option<MultiConcatLayout> {
    let open: usize = detail.find('(')?;
    let inner: &str = &detail[open + 1..];
    let close: usize = inner.rfind(')')?;
    let head: &str = &inner[..close];
    let first_quote: usize = head.find('"')?;
    let after: &str = &head[first_quote + 1..];
    let end_quote: usize = after.rfind('"')?;
    let template: String = after[..end_quote].to_owned();
    let tail: &str = after[end_quote + 1..].trim_start_matches(',');
    let lengths: Vec<i64> = tail
        .split(',')
        .filter_map(|tok: &str| {
            let t: &str = tok.trim();
            if t.is_empty() {
                None
            } else {
                t.parse::<i64>().ok()
            }
        })
        .take(MAX_MULTICONCAT_SEGMENTS)
        .collect();
    Some(MultiConcatLayout { template, lengths })
}

fn template_units(template: &str) -> Vec<String> {
    let mut units: Vec<String> = Vec::new();
    let mut chars: std::str::Chars<'_> = template.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(next) => units.push(format!("\\{next}")),
                None => units.push("\\".to_owned()),
            }
        } else {
            units.push(ch.to_string());
        }
    }
    units
}

enum ConcatPiece {
    Literal(String),
    Operand(String),
}

fn render_concat_detail(detail: &str, stringify: bool, pads: &[String]) -> String {
    let Some(layout): Option<MultiConcatLayout> = parse_multiconcat(detail) else {
        return format!("\"{}\"", quote_inner(detail));
    };
    let pieces: Vec<ConcatPiece> = concat_pieces(&layout, pads);
    if stringify {
        join_interpolated(&pieces, layout.template.len() + pads.len() * 4 + 2)
    } else {
        join_with_operator(&pieces)
    }
}

fn concat_pieces(layout: &MultiConcatLayout, pads: &[String]) -> Vec<ConcatPiece> {
    let units: Vec<String> = template_units(&layout.template);
    let mut cursor: usize = 0usize;
    let mut pad_iter: std::slice::Iter<'_, String> = pads.iter();
    let total: usize = layout.lengths.len();
    let mut pieces: Vec<ConcatPiece> = Vec::with_capacity(total * 2);
    for (idx, raw_len) in layout.lengths.iter().enumerate() {
        if *raw_len > 0 {
            let take: usize = (*raw_len as usize).min(units.len().saturating_sub(cursor));
            let literal: String = units[cursor..cursor + take].concat();
            cursor += take;
            if !literal.is_empty() {
                pieces.push(ConcatPiece::Literal(literal));
            }
        }
        if idx + 1 < total {
            let name: String = pad_iter
                .next()
                .map_or_else(|| ELIDED_OPERAND.to_owned(), Clone::clone);
            pieces.push(ConcatPiece::Operand(name));
        }
    }
    pieces
}

fn join_interpolated(pieces: &[ConcatPiece], capacity: usize) -> String {
    let mut out: String = String::with_capacity(capacity);
    out.push('"');
    for piece in pieces {
        match piece {
            ConcatPiece::Literal(text) => out.push_str(text),
            ConcatPiece::Operand(name) => push_interp(&mut out, name),
        }
    }
    out.push('"');
    out
}

fn join_with_operator(pieces: &[ConcatPiece]) -> String {
    if pieces.is_empty() {
        return String::from("\"\"");
    }
    pieces
        .iter()
        .map(|piece: &ConcatPiece| match piece {
            ConcatPiece::Literal(text) => format!("\"{text}\""),
            ConcatPiece::Operand(name) => name.clone(),
        })
        .collect::<Vec<String>>()
        .join(CONCAT_JOINER)
}

fn push_interp(out: &mut String, name: &str) {
    if let Some(first) = name.chars().next()
        && matches!(first, '$' | '@')
    {
        out.push_str(name);
    } else {
        out.push_str("${");
        out.push_str(name);
        out.push('}');
    }
}

fn quote_inner(raw: &str) -> String {
    raw.trim_start_matches('[').trim_end_matches(']').to_owned()
}

fn is_binary_op(name: &str) -> bool {
    is_binary_arith(name) || is_comparison(name)
}

fn binary_symbol(name: &str) -> &'static str {
    if is_comparison(name) {
        comparison_symbol(name)
    } else {
        arith_symbol(name)
    }
}

fn is_binary_arith(name: &str) -> bool {
    matches!(
        name,
        "add"
            | "subtract"
            | "multiply"
            | "divide"
            | "modulo"
            | "concat"
            | "repeat"
            | "pow"
            | "i_add"
            | "i_subtract"
            | "i_multiply"
            | "i_divide"
            | "i_modulo"
            | "bit_and"
            | "bit_or"
            | "bit_xor"
            | "left_shift"
            | "right_shift"
    )
}

fn arith_symbol(name: &str) -> &'static str {
    match name {
        "add" | "i_add" => "+",
        "subtract" | "i_subtract" => "-",
        "multiply" | "i_multiply" => "*",
        "divide" | "i_divide" => "/",
        "modulo" | "i_modulo" => "%",
        "concat" => ".",
        "repeat" => "x",
        "pow" => "**",
        "bit_and" => "&",
        "bit_or" => "|",
        "bit_xor" => "^",
        "left_shift" => "<<",
        "right_shift" => ">>",
        _ => "?",
    }
}

fn is_comparison(name: &str) -> bool {
    matches!(
        name,
        "lt" | "gt"
            | "le"
            | "ge"
            | "eq"
            | "ne"
            | "slt"
            | "sgt"
            | "sle"
            | "sge"
            | "seq"
            | "sne"
            | "ncmp"
            | "scmp"
    )
}

fn comparison_symbol(name: &str) -> &'static str {
    match name {
        "lt" => "<",
        "gt" => ">",
        "le" => "<=",
        "ge" => ">=",
        "eq" => "==",
        "ne" => "!=",
        "slt" => "lt",
        "sgt" => "gt",
        "sle" => "le",
        "sge" => "ge",
        "seq" => "eq",
        "sne" => "ne",
        "ncmp" => "<=>",
        "scmp" => "cmp",
        _ => "?",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::lang::perl::read_concise;

    use super::*;

    const SAMPLE: &[u8] = include_bytes!("../../tests/fixtures/hello.concise.txt");

    fn decompiled() -> PerlSource {
        let tree: PerlOpTree = read_concise(SAMPLE).expect("parse concise");
        DecompileWalker::new(&tree).decompile()
    }

    #[test]
    fn renders_named_subs() {
        let src: PerlSource = decompiled();
        assert!(
            src.rendered.contains("sub greet {"),
            "rendered:\n{}",
            src.rendered
        );
        assert!(
            src.rendered.contains("sub add {"),
            "rendered:\n{}",
            src.rendered
        );
    }

    #[test]
    fn recovers_lexical_signature_from_pad() {
        let src: PerlSource = decompiled();
        let greet: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::greet")
            .expect("greet");
        assert_eq!(greet.signature.as_deref(), Some("my ($name) = @_;"));
        let add: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::add")
            .expect("add");
        assert_eq!(add.signature.as_deref(), Some("my ($a, $b) = @_;"));
    }

    #[test]
    fn recovers_add_return_expression_from_pads() {
        let src: PerlSource = decompiled();
        let add: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::add")
            .expect("add");
        assert!(
            add.statements
                .iter()
                .any(|s: &PerlStatement| s.text == "return $a + $b;"),
            "add() return must reconstruct from pad add op: {:?}",
            add.statements
        );
    }

    #[test]
    fn recovers_greet_concat_return() {
        let src: PerlSource = decompiled();
        let greet: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::greet")
            .expect("greet");
        assert!(
            greet.statements.iter().any(|s: &PerlStatement| {
                s.text.starts_with("return \"Hello, ") && s.text.contains("$name")
            }),
            "greet() return must interpolate the recovered $name lexical: {:?}",
            greet.statements
        );
    }

    #[test]
    fn recovers_main_call_with_string_constant() {
        let src: PerlSource = decompiled();
        let main: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.is_main_program)
            .expect("main");
        assert!(
            main.statements
                .iter()
                .any(|s: &PerlStatement| s.text == "my $msg = greet(\"disrobe\");"),
            "main must reconstruct the greet(\"disrobe\") call into $msg: {:?}",
            main.statements
        );
    }

    #[test]
    fn recovery_ratio_is_honest_and_bounded() {
        let src: PerlSource = decompiled();
        assert!(src.statements_total > 0);
        assert!(src.statements_recovered <= src.statements_total);
        let ratio: f64 = src.recovery_ratio();
        assert!((0.0..=1.0).contains(&ratio), "ratio {ratio}");
    }

    #[test]
    fn empty_tree_is_fully_recovered_vacuously() {
        let tree: PerlOpTree = PerlOpTree {
            source_hint: None,
            subs: Vec::new(),
            op_count: 0,
        };
        let src: PerlSource = DecompileWalker::new(&tree).decompile();
        assert_eq!(src.statements_total, 0);
        assert!((src.recovery_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn multiconcat_splices_args_between_literal_runs() {
        let pads: Vec<String> = vec!["$x".to_owned(), "$y".to_owned()];
        assert_eq!(
            render_concat_detail("(\" mid \",-1,5,-1)[t1]", true, &pads),
            "\"$x mid $y\""
        );
        assert_eq!(
            render_concat_detail("(\"lead  tail\",5,5)[t1]", true, &[String::from("$x")]),
            "\"lead $x tail\""
        );
        assert_eq!(
            render_concat_detail("(\"\",-1,-1,-1)[$e:1,2]", true, &pads),
            "\"$x$y\""
        );
    }

    #[test]
    fn multiconcat_counts_escapes_as_one_logical_char() {
        assert_eq!(
            render_concat_detail("(\"\\n\",-1,1)[t4]", true, &[String::from("$x")]),
            "\"$x\\n\""
        );
        assert_eq!(
            render_concat_detail("(\"only \\n\",5,1)[$g:1,2]", true, &[String::from("$x")]),
            "\"only $x\\n\""
        );
    }

    #[test]
    fn multiconcat_without_stringify_renders_the_concat_operator() {
        let pads: Vec<String> = vec!["$a".to_owned(), "$b".to_owned()];
        assert_eq!(
            render_concat_detail("(\"\",-1,-1,-1)[$s:8,10]", false, &pads),
            "$a . $b"
        );
        assert_eq!(
            render_concat_detail("(\"-\",-1,1,-1)[t3]", false, &pads),
            "$a . \"-\" . $b"
        );
        assert_eq!(
            render_concat_detail("(\"-\",-1,1,-1)[t3]", true, &pads),
            "\"$a-$b\""
        );
    }

    #[test]
    fn call_arguments_stop_at_the_callee_glob() {
        let seg: Vec<PerlOp> = vec![
            op("print", "vK", None),
            op("pushmark", "s", None),
            op("entersub", "lKS/STRICT", None),
            op("const", "sM", Some("[IV 2]")),
            op("const", "sM", Some("[IV 3]")),
            op("gv", "s", Some("[*add]")),
            op("const", "s", Some("[PV \"\\n\"]")),
        ];
        assert_eq!(call_arguments(&seg), "2, 3");
        assert_eq!(
            recover_print_args(&seg).as_deref(),
            Some("add(2, 3), \"\\n\"")
        );
    }

    fn op(name: &str, flags: &str, detail: Option<&str>) -> PerlOp {
        PerlOp {
            seq: String::from("-"),
            name: name.to_owned(),
            flags: flags.to_owned(),
            detail: detail.map(str::to_owned),
        }
    }

    #[test]
    fn comparison_symbol_maps_numeric_and_string_forms() {
        assert_eq!(comparison_symbol("gt"), ">");
        assert_eq!(comparison_symbol("ge"), ">=");
        assert_eq!(comparison_symbol("eq"), "==");
        assert_eq!(comparison_symbol("sgt"), "gt");
        assert_eq!(comparison_symbol("ncmp"), "<=>");
    }

    #[test]
    fn multiconcat_segment_count_is_bounded() {
        let detail: String = format!("(\"\",{})[t1]", "-1,".repeat(4096));
        let layout: MultiConcatLayout =
            parse_multiconcat(&detail).expect("parse bounded multiconcat");
        assert!(layout.lengths.len() <= MAX_MULTICONCAT_SEGMENTS);
    }
}
