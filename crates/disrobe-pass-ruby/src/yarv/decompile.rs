//! Recompile-oriented decompiler for the YARV stack machine, driven by the decoded IBF iseq stream.
//!
//! Runs an abstract stack over each iseq body and emits nested, recompilable Ruby source: pushes for
//! `putobject`/`putstring`/`putself`/`putnil`/literals, `recv.method(args)` for `send`/`opt_*`,
//! recursion into child iseqs for `definemethod`/`defineclass`/block-bearing sends (so method, class,
//! module, and block bodies are inlined rather than placeholdered), and structured control flow for
//! forward `branchunless`/`branchif` (`if`/`unless`/`else`), the `dup; branch; pop` short-circuit
//! idiom (`&&`/`||`/`&.`), and the backward-branch `while`/`until` shape. Constructs that YARV
//! genuinely erases (see `INFORMATION.md` gaps) are dropped or approximated, never fabricated.

use core::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::yarv::ibf::{
    CatchType, IbfImage, IbfObjectKind, YarvCatchEntry, YarvIbfInstruction, YarvIseqBody,
    YarvOperand,
};

const MAX_STACK: usize = 8192;
const MAX_EXPR_LEN: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvDecompiled {
    pub source: String,
    pub statement_count: u32,
    pub fidelity: Fidelity,
    pub recovered_strings: Vec<String>,
    pub recovered_symbols: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fidelity {
    Lossy,
    StructuralOnly,
    LiteralPoolOnly,
}

#[must_use]
pub fn decompile_from_ibf(image: &IbfImage) -> YarvDecompiled {
    let mut recovered_strings: Vec<String> = Vec::new();
    let mut recovered_symbols: Vec<String> = Vec::new();
    for obj in &image.objects {
        match (obj.kind, obj.literal.as_ref()) {
            (IbfObjectKind::String | IbfObjectKind::Regexp, Some(text)) => {
                recovered_strings.push(text.clone());
            }
            (IbfObjectKind::Symbol, Some(text)) => recovered_symbols.push(text.clone()),
            _ => {}
        }
    }

    let ctx: DecompileContext<'_> = DecompileContext::from_image(image);

    let has_bodies: bool = image.iseqs.iter().any(|b| !b.instructions.is_empty());
    let (mut out, statement_count, fidelity): (String, u32, Fidelity) = if has_bodies {
        let root: Option<&YarvIseqBody> = ctx
            .body(0)
            .or_else(|| image.iseqs.iter().min_by_key(|b| b.index));
        let mut body_src: String = String::with_capacity(1024);
        let mut count: u32 = 0;
        if let Some(root) = root {
            let stmts: Vec<String> = render_iseq_statements(root, &ctx, 0);
            for stmt in &stmts {
                body_src.push_str(stmt);
                body_src.push('\n');
                count = count.saturating_add(1);
            }
        }
        (body_src, count, Fidelity::StructuralOnly)
    } else {
        let mut s: String = String::with_capacity(128);
        s.push_str("# (no iseq bodies decoded; reporting literal pool)\n");
        (s, 0, Fidelity::LiteralPoolOnly)
    };

    push_section(&mut out, "string literals", &recovered_strings);
    push_section(&mut out, "symbols", &recovered_symbols);

    YarvDecompiled {
        source: out,
        statement_count,
        fidelity,
        recovered_strings,
        recovered_symbols,
    }
}

const MAX_NEST_DEPTH: u32 = 64;

/// Per-branch resolved target instruction index for `branchunless`/`branchif`/`branchnil`/`jump`,
/// computed from the runtime-pc model (`target_pc = next_instr_pc + signed_offset`, with offsets
/// reinterpreted as signed so backward loop edges resolve). `None` when the target is out of range.
fn resolve_branch_targets(body: &YarvIseqBody) -> Vec<Option<usize>> {
    let mut rt_pc: Vec<u32> = Vec::with_capacity(body.instructions.len());
    let mut pc: u32 = 0;
    for instr in &body.instructions {
        rt_pc.push(pc);
        pc = pc.saturating_add(1 + instr.operands.len() as u32);
    }
    let mut targets: Vec<Option<usize>> = vec![None; body.instructions.len()];
    for (idx, instr) in body.instructions.iter().enumerate() {
        if !matches!(
            instr.mnemonic.as_str(),
            "branchunless" | "branchif" | "branchnil" | "jump"
        ) {
            continue;
        }
        let Some(off): Option<i64> = branch_offset(instr) else {
            continue;
        };
        let next_pc: i64 = i64::from(rt_pc[idx]) + 1 + instr.operands.len() as i64;
        let target_pc: i64 = next_pc + off;
        if target_pc < 0 {
            continue;
        }
        targets[idx] = rt_pc.iter().position(|&p| i64::from(p) == target_pc);
    }
    targets
}

fn branch_offset(instr: &YarvIbfInstruction) -> Option<i64> {
    match instr.operands.first() {
        Some(YarvOperand::Offset(o)) => Some(i64::from(*o as i32)),
        Some(YarvOperand::Num(n)) => Some(i64::from(*n as i32)),
        _ => None,
    }
}

/// Runtime pc of each instruction (cumulative `1 + operand_count`), for mapping catch-table pcs and
/// branch targets onto instruction indices.
fn runtime_pcs(body: &YarvIseqBody) -> Vec<u32> {
    let mut rt_pc: Vec<u32> = Vec::with_capacity(body.instructions.len());
    let mut pc: u32 = 0;
    for instr in &body.instructions {
        rt_pc.push(pc);
        pc = pc.saturating_add(1 + instr.operands.len() as u32);
    }
    rt_pc
}

/// Smallest instruction index whose runtime pc is `>= pc`, used to clamp a catch-table pc range to
/// instruction boundaries.
fn index_at_pc(rt_pc: &[u32], pc: u32) -> usize {
    rt_pc.iter().position(|&p| p >= pc).unwrap_or(rt_pc.len())
}

/// Recursively render an iseq body's statements as Ruby source lines, indented by `depth` levels.
/// Structural opcodes (`definemethod`/`defineclass`/`defineclass`-as-module and block-bearing
/// sends) recurse into their child iseq so method/class/block bodies are emitted inline; forward
/// `branchunless`/`branchif` regions are structured into `if`/`unless`/`else`; `catch_table`
/// rescue/ensure regions are structured into `begin`/`rescue`/`ensure`/`end`.
fn render_iseq_statements(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
) -> Vec<String> {
    if depth > MAX_NEST_DEPTH {
        return Vec::new();
    }
    if let Some(lines) = try_render_exception_region(body, ctx, depth) {
        return lines;
    }
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    let mut stack: Vec<String> = Vec::with_capacity(32);
    let mut stmts: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        0,
        body.instructions.len(),
        &targets,
        &mut stack,
        &mut stmts,
    );
    stmts
}

/// When this body has a top-level `rescue`/`ensure` catch entry whose protected range spans the body
/// before its trailing return, wrap that range in `begin`/`rescue`/`ensure`/`end`, splicing in the
/// decompiled rescue and ensure handler iseqs. Returns `None` when there is no rescue/ensure entry
/// to structure (so the caller renders linearly).
fn try_render_exception_region(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
) -> Option<Vec<String>> {
    let rescue: Option<&YarvCatchEntry> = body
        .catch_entries
        .iter()
        .find(|e| e.catch_type == CatchType::Rescue && e.handler_iseq.is_some());
    let ensure: Option<&YarvCatchEntry> = body
        .catch_entries
        .iter()
        .find(|e| e.catch_type == CatchType::Ensure && e.handler_iseq.is_some());
    if rescue.is_none() && ensure.is_none() {
        return None;
    }

    let rt_pc: Vec<u32> = runtime_pcs(body);
    let entry: &YarvCatchEntry = rescue.or(ensure)?;
    let start: usize = index_at_pc(&rt_pc, entry.start_pc);
    let end: usize = index_at_pc(&rt_pc, entry.end_pc);
    if start >= end || end > body.instructions.len() {
        return None;
    }

    let pad: String = indent(depth);
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    let mut lines: Vec<String> = Vec::new();

    let prefix: Vec<String> = render_slice(body, ctx, depth, 0, start, &targets);
    lines.extend(prefix);

    lines.push(format!("{pad}begin"));
    let protected: Vec<String> = render_slice(body, ctx, depth + 1, start, end, &targets);
    lines.extend(protected);

    if let Some(handler_idx) = rescue.and_then(|e| e.handler_iseq)
        && let Some(handler) = ctx.body(handler_idx)
    {
        lines.extend(render_rescue_handler(handler, ctx, depth));
    }
    if let Some(handler_idx) = ensure.and_then(|e| e.handler_iseq)
        && let Some(handler) = ctx.body(handler_idx)
    {
        lines.push(format!("{pad}ensure"));
        lines.extend(render_iseq_statements(handler, ctx, depth + 1));
    }
    lines.push(format!("{pad}end"));

    let suffix: Vec<String> =
        render_slice(body, ctx, depth, end, body.instructions.len(), &targets);
    lines.extend(suffix);
    Some(lines)
}

/// Decompile a `rescue in ...` handler iseq into one or more `rescue [Class => var]` clauses with
/// their bodies, at `depth`. The handler's shape is a ladder of
/// `getlocal $!; opt_getconstant_path Class; checkmatch; branchunless NEXT; [getlocal $!; setlocal
/// var;] <body>; leave` clauses, ending in a `getlocal $!; throw` re-raise. Clauses whose class test
/// is absent render as a bare `rescue`.
fn render_rescue_handler(
    handler: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
) -> Vec<String> {
    let pad: String = indent(depth);
    let targets: Vec<Option<usize>> = resolve_branch_targets(handler);
    let mut lines: Vec<String> = Vec::new();
    let mut i: usize = 0;
    let n: usize = handler.instructions.len();
    let mut produced: bool = false;

    while i < n {
        let m: &str = handler.instructions[i].mnemonic.as_str();
        if m == "throw" {
            break;
        }
        let (classes, var, body_lo, body_hi): (Vec<String>, Option<String>, usize, usize) =
            match parse_rescue_clause(handler, ctx, i, &targets) {
                Some(clause) => clause,
                None => break,
            };
        let header: String = render_rescue_header(&classes, var.as_deref());
        lines.push(format!("{pad}{header}"));
        let body: Vec<String> = render_slice(handler, ctx, depth + 1, body_lo, body_hi, &targets);
        lines.extend(body);
        produced = true;
        i = next_clause_start(handler, body_hi);
    }

    if !produced {
        lines.push(format!("{pad}rescue"));
        lines.extend(render_slice(handler, ctx, depth + 1, 0, n, &targets));
    }
    lines
}

/// Parse one rescue clause starting at `i`: returns its matched class names, the `=> var` binding,
/// and the `[body_lo, body_hi)` instruction range of the clause body.
fn parse_rescue_clause(
    handler: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    i: usize,
    targets: &[Option<usize>],
) -> Option<(Vec<String>, Option<String>, usize, usize)> {
    let mut k: usize = i;
    let mut classes: Vec<String> = Vec::new();
    let mut branch_target: Option<usize> = None;

    while k + 3 < handler.instructions.len() {
        if handler.instructions[k].mnemonic != "getlocal_WC_0" {
            break;
        }
        let class_instr: &YarvIbfInstruction = &handler.instructions[k + 1];
        let class_name: Option<String> = match class_instr.mnemonic.as_str() {
            "opt_getconstant_path" => Some(constant_path_value(class_instr, ctx)),
            "getconstant" => Some(id_or_index(class_instr, 0)),
            _ => None,
        };
        if handler.instructions.get(k + 2).map(|x| x.mnemonic.as_str()) != Some("checkmatch") {
            break;
        }
        if handler.instructions.get(k + 3).map(|x| x.mnemonic.as_str()) != Some("branchunless") {
            break;
        }
        if let Some(name) = class_name {
            classes.push(name);
        }
        branch_target = targets.get(k + 3).copied().flatten();
        k += 4;
        if handler.instructions.get(k).map(|x| x.mnemonic.as_str()) == Some("getlocal_WC_0")
            && handler.instructions.get(k + 1).is_some_and(|x| {
                x.mnemonic == "opt_getconstant_path" || x.mnemonic == "getconstant"
            })
        {
            continue;
        }
        break;
    }

    let next_clause: usize = branch_target?;
    let binds_var: bool = handler
        .instructions
        .get(k)
        .is_some_and(|x| x.mnemonic == "getlocal_WC_0")
        && handler
            .instructions
            .get(k + 1)
            .is_some_and(|x| x.mnemonic.starts_with("setlocal"));
    let (var, body_lo): (Option<String>, usize) = if binds_var {
        let name: String = local_name(
            &handler.local_table,
            operand_num(&handler.instructions[k + 1], 0),
        );
        (Some(name), k + 2)
    } else {
        (None, k)
    };
    let body_hi: usize = (body_lo..next_clause)
        .find(|&j| handler.instructions[j].mnemonic == "leave")
        .map_or(next_clause, |leave| leave);
    Some((classes, var, body_lo, body_hi))
}

/// The instruction index where the next rescue clause begins after a clause body ending at
/// `body_hi`: skip the clause's `leave`.
fn next_clause_start(handler: &YarvIseqBody, body_hi: usize) -> usize {
    if handler
        .instructions
        .get(body_hi)
        .is_some_and(|x| x.mnemonic == "leave")
    {
        body_hi + 1
    } else {
        body_hi
    }
}

fn render_rescue_header(classes: &[String], var: Option<&str>) -> String {
    let class_part: String = if classes.is_empty() {
        String::new()
    } else {
        format!(" {}", classes.join(", "))
    };
    match var {
        Some(v) if is_valid_rescue_var(v) => format!("rescue{class_part} => {v}"),
        _ => format!("rescue{class_part}"),
    }
}

/// Whether a recovered rescue-binding name is a usable local identifier (not the implicit `$!`
/// error global, a synthetic `local{N}`, or a hidden slot).
fn is_valid_rescue_var(v: &str) -> bool {
    !v.is_empty()
        && !v.starts_with("local")
        && !v.starts_with('$')
        && v.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
}

/// Render an instruction sub-range `[lo, hi)` with a fresh stack, returning its statement lines.
fn render_slice(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> Vec<String> {
    let mut stack: Vec<String> = Vec::with_capacity(16);
    let mut stmts: Vec<String> = Vec::new();
    render_region(body, ctx, depth, lo, hi, targets, &mut stack, &mut stmts);
    flush_trailing(&mut stack, depth, &mut stmts);
    stmts
}

/// Render instructions `[lo, hi)` of `body`, structuring forward conditional branches into
/// `if`/`unless`/`else` blocks. Non-branch instructions are dispatched to [`step`]; a clean forward
/// `branchunless`/`branchif` whose target lies within `[lo, hi]` opens a structured region, with an
/// optional `else` arm when the then-block ends in a forward `jump` past the branch target.
#[allow(clippy::too_many_arguments)]
fn render_region(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
    targets: &[Option<usize>],
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) {
    let mut i: usize = lo;
    while i < hi {
        let instr: &YarvIbfInstruction = &body.instructions[i];
        let m: &str = instr.mnemonic.as_str();
        if let Some(next) = try_short_circuit(body, ctx, depth, i, hi, targets, stack) {
            i = next;
            continue;
        }
        if let Some(next) = try_case_when(body, ctx, depth, i, hi, targets, stack, stmts) {
            i = next;
            stack.clear();
            continue;
        }
        if let Some(next) = try_loop(body, ctx, depth, i, hi, targets, stmts) {
            i = next;
            stack.clear();
            continue;
        }
        if matches!(m, "branchunless" | "branchif")
            && let Some(target) = targets[i]
            && target <= hi
            && target > i
        {
            let keyword: &str = if m == "branchunless" { "if" } else { "unless" };
            let cond: String = pop(stack);
            render_conditional(
                body, ctx, depth, i, target, hi, keyword, &cond, targets, stmts,
            );
            i = region_end_after_conditional(body, target, hi, targets);
            stack.clear();
            continue;
        }
        step(instr, &body.local_table, ctx, depth, stack, stmts);
        i += 1;
    }
}

/// Recognize a `case`/`when` ladder at instruction `i`: `dup; opt_case_dispatch <hash>, ELSE`
/// followed by a chain of `<value>; topn 1; === ; branchif WHEN_BODY` comparisons, then the `else`
/// body and the per-`when` bodies (each `pop; <body>; leave`). Renders `case subject; when V; ...;
/// else; ...; end`, returning the resume index when matched, else `None`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn try_case_when(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stack: &[String],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let subject: String = stack.last().cloned()?;
    let has_dispatch: bool = body
        .instructions
        .get(i)
        .is_some_and(|x| x.mnemonic == "dup")
        && body
            .instructions
            .get(i + 1)
            .is_some_and(|x| x.mnemonic == "opt_case_dispatch");
    let ladder_start: usize = if has_dispatch {
        i + 2
    } else if begins_when_comparison(body, i, hi) {
        i
    } else {
        return None;
    };

    let mut clauses: Vec<(Vec<String>, usize)> = Vec::new();
    let mut k: usize = ladder_start;
    let mut first_body: Option<usize> = None;
    while k < hi {
        let mut value_stack: Vec<String> = Vec::new();
        let mut sink: Vec<String> = Vec::new();
        let mut j: usize = k;
        while j < hi && !matches!(body.instructions[j].mnemonic.as_str(), "topn" | "pop") {
            step(
                &body.instructions[j],
                &body.local_table,
                ctx,
                depth,
                &mut value_stack,
                &mut sink,
            );
            j += 1;
        }
        if body.instructions.get(j).map(|x| x.mnemonic.as_str()) != Some("topn") {
            break;
        }
        let cmp: usize = j + 1;
        if body
            .instructions
            .get(cmp)
            .is_none_or(|x| !is_send(x.mnemonic.as_str()))
            || body.instructions.get(cmp + 1).map(|x| x.mnemonic.as_str()) != Some("branchif")
        {
            break;
        }
        let when_body: usize = targets.get(cmp + 1).copied().flatten()?;
        if when_body > hi || when_body <= i {
            break;
        }
        first_body.get_or_insert(when_body);
        let value: String = value_stack.pop().unwrap_or_default();
        clauses.push((vec![value], when_body));
        k = cmp + 2;
    }
    if clauses.len() < 2 && !has_dispatch {
        return None;
    }
    if clauses.is_empty() {
        return None;
    }

    let else_lo: usize = k;
    let else_hi: usize = first_body.unwrap_or(hi).min(hi);
    if else_lo >= else_hi {
        return None;
    }

    let mut bodies: Vec<(usize, usize)> = Vec::with_capacity(clauses.len());
    let mut last_end: usize = else_hi;
    for (_, start) in &clauses {
        let body_lo: usize = skip_leading_pop(body, *start);
        let body_hi: usize = (body_lo..hi)
            .find(|&x| body.instructions[x].mnemonic == "leave")
            .map_or(hi, |leave| leave);
        last_end = last_end.max(body_hi + 1);
        bodies.push((body_lo, body_hi));
    }

    let pad: String = indent(depth);
    stmts.push(format!("{pad}case {subject}"));
    for (idx, (values, _)) in clauses.iter().enumerate() {
        stmts.push(format!("{pad}when {}", values.join(", ")));
        let (blo, bhi): (usize, usize) = bodies[idx];
        stmts.extend(render_slice(body, ctx, depth + 1, blo, bhi, targets));
    }
    let else_body_lo: usize = skip_leading_pop(body, else_lo);
    let else_body_hi: usize = (else_body_lo..else_hi)
        .find(|&x| body.instructions[x].mnemonic == "leave")
        .map_or(else_hi, |leave| leave);
    if else_body_lo < else_body_hi {
        stmts.push(format!("{pad}else"));
        stmts.extend(render_slice(
            body,
            ctx,
            depth + 1,
            else_body_lo,
            else_body_hi,
            targets,
        ));
    }
    stmts.push(format!("{pad}end"));
    Some(last_end.min(hi))
}

#[inline]
fn is_send(m: &str) -> bool {
    m.starts_with("opt_send") || m == "send"
}

/// Whether `[i, hi)` begins a no-dispatch `when` comparison group `<value>; topn N; ===; branchif`
/// (a `case` whose `when` values are non-literal so no `opt_case_dispatch` jump-table was emitted).
fn begins_when_comparison(body: &YarvIseqBody, i: usize, hi: usize) -> bool {
    let topn: Option<usize> = (i..hi)
        .take(8)
        .find(|&j| body.instructions[j].mnemonic == "topn");
    let Some(t) = topn else {
        return false;
    };
    body.instructions
        .get(t + 1)
        .is_some_and(|x| is_send(x.mnemonic.as_str()))
        && body
            .instructions
            .get(t + 2)
            .is_some_and(|x| x.mnemonic == "branchif")
        && matches!(
            body.instructions.get(t + 1).and_then(|x| x.operands.first()),
            Some(YarvOperand::Call { method, .. }) if method == "==="
        )
}

/// Skip a leading `pop` (the `case`/`when` body's discard of the dispatched subject copy).
fn skip_leading_pop(body: &YarvIseqBody, idx: usize) -> usize {
    if body
        .instructions
        .get(idx)
        .is_some_and(|x| x.mnemonic == "pop")
    {
        idx + 1
    } else {
        idx
    }
}

/// Recognize a `while`/`until` loop at instruction `i`: a forward `jump COND` to the loop condition,
/// whose region `[COND, branch]` ends in a backward `branchif`/`branchunless` to the loop body
/// (`body_start = i + 1`). Renders `while cond`/`until cond` with the body, returning the resume
/// index (just past the backward branch) when matched, else `None`. The body's leading redo/next
/// handler stubs (`putnil; pop; jump COND`) are skipped.
#[allow(clippy::too_many_arguments)]
fn try_loop(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    if body.instructions.get(i)?.mnemonic != "jump" {
        return None;
    }
    let cond_start: usize = targets.get(i).copied().flatten()?;
    if cond_start <= i || cond_start >= hi {
        return None;
    }
    let branch_idx: usize = (cond_start..hi).find(|&k| {
        matches!(
            body.instructions[k].mnemonic.as_str(),
            "branchif" | "branchunless"
        ) && targets[k].is_some_and(|t| t > i && t <= cond_start)
    })?;
    let back_target: usize = targets[branch_idx]?;
    let keyword: &str = if body.instructions[branch_idx].mnemonic == "branchif" {
        "while"
    } else {
        "until"
    };

    let mut cond_stack: Vec<String> = Vec::with_capacity(8);
    let mut cond_sink: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        cond_start,
        branch_idx,
        targets,
        &mut cond_stack,
        &mut cond_sink,
    );
    let cond: String = cond_stack.pop().unwrap_or_else(|| "true".to_owned());

    let pad: String = indent(depth);
    stmts.push(format!("{pad}{keyword} {cond}"));
    let mut body_stack: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth + 1,
        back_target,
        cond_start,
        targets,
        &mut body_stack,
        stmts,
    );
    flush_trailing(&mut body_stack, depth + 1, stmts);
    stmts.push(format!("{pad}end"));
    Some(branch_idx + 1)
}

/// Recognize a short-circuit `&&`/`||`/safe-navigation idiom at instruction `i`:
/// `dup; branch{unless,if,nil} T; [pop;] <rhs in [.., T)>` folds the duplicated lhs and the rhs into
/// a single expression (`lhs && rhs`, `lhs || rhs`, or `lhs&.method`). Returns the instruction index
/// to resume at when matched, else `None`.
#[allow(clippy::too_many_arguments)]
fn try_short_circuit(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stack: &mut Vec<String>,
) -> Option<usize> {
    if body.instructions.get(i)?.mnemonic != "dup" {
        return None;
    }
    let branch: &YarvIbfInstruction = body.instructions.get(i + 1)?;
    let op: &str = match branch.mnemonic.as_str() {
        "branchunless" => "&&",
        "branchif" => "||",
        "branchnil" => "&.",
        _ => return None,
    };
    let target: usize = targets.get(i + 1).copied().flatten()?;
    if target > hi || target <= i + 1 {
        return None;
    }
    let lhs: String = pop(stack);
    let mut rhs_lo: usize = i + 2;
    if body
        .instructions
        .get(rhs_lo)
        .is_some_and(|inst| inst.mnemonic == "pop")
    {
        rhs_lo += 1;
    }

    if op != "&."
        && let Some(folded) = try_compound_assign(body, op, &lhs, rhs_lo, target)
    {
        push(stack, folded);
        return Some(target);
    }

    let mut rhs_stack: Vec<String> = vec![lhs.clone()];
    let mut sink: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        rhs_lo,
        target,
        targets,
        &mut rhs_stack,
        &mut sink,
    );
    let rhs: String = rhs_stack.pop().unwrap_or_default();
    let folded: String = if op == "&." {
        let method: &str = rhs.strip_prefix(&format!("{lhs}.")).unwrap_or(&rhs);
        format!("{lhs}&.{method}")
    } else if rhs == lhs || rhs.is_empty() {
        lhs
    } else {
        format!("{lhs} {op} {rhs}")
    };
    push(stack, folded);
    Some(target)
}

/// Recognize a compound conditional assignment `target ||= value` / `target &&= value`: the rhs
/// region `[rhs_lo, target_pc)` ends in a `setinstancevariable`/`setlocal`/`setglobal` of the same
/// `lhs` target, preceded by the value expression. Returns the folded `lhs ||= value` source.
fn try_compound_assign(
    body: &YarvIseqBody,
    op: &str,
    lhs: &str,
    rhs_lo: usize,
    target: usize,
) -> Option<String> {
    let set_idx: usize = (rhs_lo..target).find(|&j| {
        matches!(
            body.instructions[j].mnemonic.as_str(),
            "setinstancevariable" | "setlocal" | "setlocal_WC_0" | "setlocal_WC_1" | "setglobal"
        )
    })?;
    let set_instr: &YarvIbfInstruction = &body.instructions[set_idx];
    let set_target: String = match set_instr.mnemonic.as_str() {
        "setinstancevariable" => ivar_name(set_instr, 0),
        "setglobal" => id_or_index(set_instr, 0),
        _ => local_name(&body.local_table, operand_num(set_instr, 0)),
    };
    if set_target != lhs {
        return None;
    }
    let value: String = compound_value(body, rhs_lo, set_idx)?;
    let assign_op: &str = if op == "||" { "||=" } else { "&&=" };
    Some(format!("{lhs} {assign_op} {value}"))
}

/// The single value expression pushed in `[lo, set_idx)` of a compound assignment, ignoring the
/// intervening `pop`/`dup` housekeeping. `None` when no clean single value is found.
fn compound_value(body: &YarvIseqBody, lo: usize, set_idx: usize) -> Option<String> {
    let mut value_stack: Vec<String> = Vec::new();
    let mut sink: Vec<String> = Vec::new();
    let ctx: DecompileContext<'static> = DecompileContext {
        bodies_by_index: Vec::new(),
        objects: &[],
    };
    for j in lo..set_idx {
        let m: &str = body.instructions[j].mnemonic.as_str();
        if matches!(m, "dup" | "pop") {
            continue;
        }
        step(
            &body.instructions[j],
            &body.local_table,
            &ctx,
            0,
            &mut value_stack,
            &mut sink,
        );
    }
    value_stack.pop().filter(|v| !v.is_empty())
}

/// Render a structured `if cond`/`unless cond` (with optional `else`) for a branch at `branch_idx`
/// whose false/true target is `target`. The then-block is `[branch_idx+1, then_end)`; when it ends
/// in a forward `jump` to `else_end`, the else-block is `[target, else_end)`.
#[allow(clippy::too_many_arguments)]
fn render_conditional(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    branch_idx: usize,
    target: usize,
    hi: usize,
    keyword: &str,
    cond: &str,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) {
    let pad: String = indent(depth);
    let then_last: usize = target.saturating_sub(1);
    let then_ends_in_jump: bool = then_last > branch_idx
        && body
            .instructions
            .get(then_last)
            .is_some_and(|i| i.mnemonic == "jump")
        && targets[then_last].is_some_and(|t| t > target && t <= hi);
    let then_ends_in_leave: bool = then_last >= branch_idx
        && body
            .instructions
            .get(then_last)
            .is_some_and(|i| matches!(i.mnemonic.as_str(), "leave" | "throw"));

    let (then_hi, else_arm): (usize, Option<(usize, usize)>) = if then_ends_in_jump {
        let end: usize = targets[then_last].unwrap_or(target);
        (then_last, Some((target, end)))
    } else if then_ends_in_leave && target < hi {
        (target, Some((target, hi)))
    } else {
        (target, None)
    };

    stmts.push(format!("{pad}{keyword} {cond}"));
    let mut then_stack: Vec<String> = Vec::with_capacity(16);
    render_region(
        body,
        ctx,
        depth + 1,
        branch_idx + 1,
        then_hi,
        targets,
        &mut then_stack,
        stmts,
    );
    flush_trailing(&mut then_stack, depth + 1, stmts);

    if let Some((else_lo, else_hi)) = else_arm {
        stmts.push(format!("{pad}else"));
        let mut else_stack: Vec<String> = Vec::with_capacity(16);
        render_region(
            body,
            ctx,
            depth + 1,
            else_lo,
            else_hi,
            targets,
            &mut else_stack,
            stmts,
        );
        flush_trailing(&mut else_stack, depth + 1, stmts);
    }
    stmts.push(format!("{pad}end"));
}

/// The first instruction index after a rendered conditional region, i.e. its merge point. When the
/// then-block ends in a forward `jump`, the merge is the jump target; when it ends in `leave`/`throw`
/// (both arms exit), the conditional consumed the rest of the enclosing region (`hi`).
fn region_end_after_conditional(
    body: &YarvIseqBody,
    target: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> usize {
    let then_last: usize = target.saturating_sub(1);
    if body
        .instructions
        .get(then_last)
        .is_some_and(|i| i.mnemonic == "jump")
        && let Some(end) = targets[then_last]
        && end > target
        && end <= hi
    {
        end
    } else if body
        .instructions
        .get(then_last)
        .is_some_and(|i| matches!(i.mnemonic.as_str(), "leave" | "throw"))
        && target < hi
    {
        hi
    } else {
        target
    }
}

/// Emit any value left on a sub-region's stack as a trailing bare expression (the region's implicit
/// result), so an `if`/`else` arm that yields a value reads as Ruby.
fn flush_trailing(stack: &mut Vec<String>, depth: u32, stmts: &mut Vec<String>) {
    if let Some(top) = stack.pop()
        && !top.is_empty()
        && top != "nil"
    {
        emit_stmt(stmts, depth, top);
    }
    stack.clear();
}

#[inline]
fn indent(depth: u32) -> String {
    "  ".repeat(depth as usize)
}

/// Render a nested body (method/class/module) bracketed by `header` and `end`, with the child
/// iseq's statements indented one level deeper. The body is the referenced iseq, or an empty body
/// (just `header ... end`) when the iseq is unavailable.
fn render_nested(
    header: String,
    child: Option<&YarvIseqBody>,
    ctx: &DecompileContext<'_>,
    depth: u32,
    drop_trailing_value: bool,
) -> Vec<String> {
    let pad: String = indent(depth);
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("{pad}{header}"));
    if let Some(child) = child {
        let mut inner: Vec<String> = render_iseq_statements(child, ctx, depth + 1);
        if drop_trailing_value {
            drop_trailing_bare_value(&mut inner, depth + 1);
        }
        lines.extend(inner);
    }
    lines.push(format!("{pad}end"));
    lines
}

/// Drop a class/module body's trailing bare-value line (the implicit `nil`/last-def-symbol that
/// `defineclass` leaves on the stack), which is not part of the source.
fn drop_trailing_bare_value(inner: &mut Vec<String>, inner_depth: u32) {
    let pad: String = indent(inner_depth);
    if let Some(last) = inner.last()
        && let Some(trimmed) = last.strip_prefix(pad.as_str())
        && is_bare_value_line(trimmed)
    {
        inner.pop();
    }
}

/// A line that is a single bare literal/identifier with no side effect (e.g. `nil`, `:greet`,
/// `42`), safe to drop as an implicit body result.
fn is_bare_value_line(line: &str) -> bool {
    let t: &str = line.trim();
    if t.is_empty() {
        return false;
    }
    t == "nil"
        || t.starts_with(':')
        || t.chars().all(|c| c.is_ascii_digit())
        || (string_literal_body(t).is_some())
}

/// `VM_ENV_DATA_SIZE` in `vm_core.h`: the fixed environment slots a `getlocal`/`setlocal` operand
/// is biased by before it indexes the local table.
const VM_ENV_DATA_SIZE: u64 = 3;

/// Cross-iseq decompile context: per-iseq block-parameter names (`param.lead_num` leading
/// `local_table` entries), the iseq bodies indexed by table position (for recursive nesting of
/// method/class/block bodies), and the object table, so a `send` block-iseq operand renders
/// `recv.method(args) { |params| ... }` and an `opt_getconstant_path` cache resolves to `A::B::C`.
struct DecompileContext<'a> {
    bodies_by_index: Vec<Option<&'a YarvIseqBody>>,
    objects: &'a [crate::yarv::ibf::IbfObject],
}

impl<'a> DecompileContext<'a> {
    fn from_image(image: &'a IbfImage) -> Self {
        let max_index: usize = image
            .iseqs
            .iter()
            .map(|b| b.index as usize)
            .max()
            .map_or(0, |m| m + 1);
        let mut bodies_by_index: Vec<Option<&'a YarvIseqBody>> = vec![None; max_index];
        for body in &image.iseqs {
            if let Some(slot) = bodies_by_index.get_mut(body.index as usize) {
                *slot = Some(body);
            }
        }
        Self {
            bodies_by_index,
            objects: &image.objects,
        }
    }

    fn body(&self, iseq_index: u32) -> Option<&'a YarvIseqBody> {
        self.bodies_by_index
            .get(iseq_index as usize)
            .copied()
            .flatten()
    }

    /// Resolve a constant-path cache array into `A::B::C`. The IBF array stores the path as a
    /// sequence of symbol object-indices (`[:Tiny, :Greeter]` for `Tiny::Greeter`). Returns `None`
    /// when the object is not an array of symbols (so the caller falls back to `obj[N]`).
    fn constant_path(&self, object_index: u32) -> Option<String> {
        let array: &crate::yarv::ibf::IbfObject = self.objects.get(object_index as usize)?;
        if array.kind != IbfObjectKind::Array || array.elements.is_empty() {
            return None;
        }
        let mut names: Vec<&str> = Vec::with_capacity(array.elements.len());
        for &elem in &array.elements {
            let obj: &crate::yarv::ibf::IbfObject = self.objects.get(elem as usize)?;
            if obj.kind != IbfObjectKind::Symbol {
                return None;
            }
            names.push(obj.literal.as_deref()?);
        }
        Some(names.join("::"))
    }
}

/// Resolve a `getlocal`/`setlocal` operand to its source name via the body's `local_table`. YARV
/// erases names to environment offsets; when the dump preserved the table (non-hidden locals) the
/// slot index is `local_table_size - (operand - VM_ENV_DATA_SIZE) - 1` (`local_var_name` in
/// `iseq.c`). Falls back to `local{N}` when the table is absent or the slot is hidden.
fn local_name(local_table: &[Option<String>], operand: u64) -> String {
    let size: u64 = local_table.len() as u64;
    let resolved: Option<&str> = operand
        .checked_sub(VM_ENV_DATA_SIZE)
        .and_then(|op| size.checked_sub(op))
        .and_then(|n| n.checked_sub(1))
        .and_then(|idx| usize::try_from(idx).ok())
        .and_then(|idx| local_table.get(idx))
        .and_then(Option::as_deref);
    resolved.map_or_else(|| format!("local{operand}"), str::to_owned)
}

/// Push a finished statement line at the current nesting `depth`.
#[inline]
fn emit_stmt(stmts: &mut Vec<String>, depth: u32, line: String) {
    stmts.push(format!("{}{line}", indent(depth)));
}

#[allow(clippy::match_same_arms, clippy::too_many_lines)]
fn step(
    instr: &YarvIbfInstruction,
    local_table: &[Option<String>],
    ctx: &DecompileContext<'_>,
    depth: u32,
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) {
    let m: &str = instr.mnemonic.as_str();
    match m {
        "putnil" => push(stack, "nil".to_owned()),
        "putself" => push(stack, "self".to_owned()),
        "opt_getconstant_path" => push(stack, constant_path_value(instr, ctx)),
        "putobject" | "putstring" | "putchilledstring" | "duparray" | "duphash" => {
            push(stack, operand_value(instr, 0));
        }
        "putobject_INT2FIX_0_" => push(stack, "0".to_owned()),
        "putobject_INT2FIX_1_" => push(stack, "1".to_owned()),
        "getlocal" | "getlocal_WC_0" | "getlocal_WC_1" => {
            push(stack, local_name(local_table, operand_num(instr, 0)));
        }
        "getinstancevariable" => push(stack, ivar_name(instr, 0)),
        "getglobal" => push(stack, id_or_index(instr, 0)),
        "getconstant" => push(stack, id_or_index(instr, 0)),
        "newarray" | "newarraykwsplat" => {
            let n: usize = operand_num(instr, 0) as usize;
            let elems: Vec<String> = pop_n(stack, n);
            push(stack, format!("[{}]", elems.join(", ")));
        }
        "newhash" => {
            let n: usize = operand_num(instr, 0) as usize;
            let flat: Vec<String> = pop_n(stack, n);
            push(stack, render_hash(&flat));
        }
        "concatstrings" => {
            let n: usize = operand_num(instr, 0) as usize;
            let parts: Vec<String> = pop_n(stack, n);
            push(stack, render_interpolation(&parts));
        }
        "concatarray" | "concattoarray" => {
            let rhs: String = pop(stack);
            let lhs: String = pop(stack);
            push(stack, format!("{lhs} + {rhs}"));
        }
        "splatarray" => {
            let v: String = pop(stack);
            push(stack, format!("*{v}"));
        }
        "opt_send_without_block" | "send" | "sendforward" => {
            emit_send(instr, ctx, depth, stack, stmts);
        }
        "invokesuper" => emit_super(instr, stack),
        "invokeblock" => emit_invokeblock(instr, stack),
        "opt_newarray_send" => emit_unary_call(instr, stack),
        "opt_str_freeze" | "opt_str_uminus" | "opt_nil_p" | "opt_size" | "opt_length"
        | "opt_empty_p" | "opt_succ" | "opt_not" | "opt_regexpmatch2" => {
            emit_unary_call(instr, stack);
        }
        "objtostring" => {}
        "anytostring" => collapse_interp_coercion(stack),
        "opt_plus" => emit_binop(instr, stack, "+"),
        "opt_minus" => emit_binop(instr, stack, "-"),
        "opt_mult" => emit_binop(instr, stack, "*"),
        "opt_div" => emit_binop(instr, stack, "/"),
        "opt_mod" => emit_binop(instr, stack, "%"),
        "opt_eq" => emit_binop(instr, stack, "=="),
        "opt_neq" => emit_binop(instr, stack, "!="),
        "opt_lt" => emit_binop(instr, stack, "<"),
        "opt_le" => emit_binop(instr, stack, "<="),
        "opt_gt" => emit_binop(instr, stack, ">"),
        "opt_ge" => emit_binop(instr, stack, ">="),
        "opt_ltlt" => emit_binop(instr, stack, "<<"),
        "opt_and" => emit_binop(instr, stack, "&"),
        "opt_or" => emit_binop(instr, stack, "|"),
        "opt_aref" => {
            let idx: String = pop(stack);
            let recv: String = pop(stack);
            push(stack, format!("{recv}[{idx}]"));
        }
        "opt_aset" => {
            let val: String = pop(stack);
            let idx: String = pop(stack);
            let recv: String = pop(stack);
            push(stack, format!("{recv}[{idx}] = {val}"));
        }
        "setlocal" | "setlocal_WC_0" | "setlocal_WC_1" => {
            let v: String = pop(stack);
            emit_stmt(
                stmts,
                depth,
                format!("{} = {v}", local_name(local_table, operand_num(instr, 0))),
            );
        }
        "setinstancevariable" => {
            let v: String = pop(stack);
            emit_stmt(stmts, depth, format!("{} = {v}", ivar_name(instr, 0)));
        }
        "setglobal" => {
            let v: String = pop(stack);
            emit_stmt(stmts, depth, format!("{} = {v}", id_or_index(instr, 0)));
        }
        "setconstant" => {
            let v: String = pop(stack);
            let name: String = id_or_index(instr, 0);
            let _ = pop(stack);
            emit_stmt(stmts, depth, format!("{name} = {v}"));
        }
        "definemethod" => {
            let name: String = id_or_index(instr, 0);
            let header: String = format!("def {name}{}", method_signature(instr, ctx));
            let child: Option<&YarvIseqBody> = method_iseq(instr, ctx);
            stmts.extend(render_nested(header, child, ctx, depth, false));
            push(stack, format!(":{name}"));
        }
        "definesmethod" => {
            let name: String = id_or_index(instr, 0);
            let header: String = format!("def self.{name}{}", method_signature(instr, ctx));
            let child: Option<&YarvIseqBody> = method_iseq(instr, ctx);
            let _ = pop(stack);
            stmts.extend(render_nested(header, child, ctx, depth, false));
            push(stack, format!(":{name}"));
        }
        "defineclass" => {
            let name: String = id_or_index(instr, 0);
            let flags: u64 = operand_num(instr, 2);
            let child: Option<&YarvIseqBody> = match instr.operands.get(1) {
                Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index),
                _ => None,
            };
            let _ = pop(stack);
            let _ = pop(stack);
            let header: String = match flags & 7 {
                1 => "class << self".to_owned(),
                2 => format!("module {name}"),
                _ => format!("class {name}"),
            };
            stmts.extend(render_nested(header, child, ctx, depth, true));
            push(stack, "nil".to_owned());
        }
        "leave" => {
            if let Some(top) = stack.pop()
                && top != "nil"
            {
                emit_stmt(stmts, depth, top);
            }
        }
        "pop" => {
            if let Some(top) = stack.pop()
                && is_effecting_call(&top)
            {
                emit_stmt(stmts, depth, top);
            }
        }
        "dup" => {
            if let Some(top) = stack.last().cloned() {
                push(stack, top);
            }
        }
        "dupn" => {
            let n: usize = operand_num(instr, 0) as usize;
            let len: usize = stack.len();
            if n <= len {
                let slice: Vec<String> = stack[len - n..].to_vec();
                for v in slice {
                    push(stack, v);
                }
            }
        }
        "topn" => {
            let n: usize = operand_num(instr, 0) as usize;
            let len: usize = stack.len();
            if n < len {
                let v: String = stack[len - 1 - n].clone();
                push(stack, v);
            }
        }
        "setn" => {
            let n: usize = operand_num(instr, 0) as usize;
            let len: usize = stack.len();
            if n < len
                && let Some(top) = stack.last().cloned()
            {
                stack[len - 1 - n] = top;
            }
        }
        "adjuststack" => {
            let n: usize = operand_num(instr, 0) as usize;
            let _ = pop_n(stack, n);
        }
        "opt_case_dispatch" => {
            let _ = pop(stack);
        }
        "swap" => {
            let len: usize = stack.len();
            if len >= 2 {
                stack.swap(len - 1, len - 2);
            }
        }
        "nop" | "putspecialobject" | "intern" | "tostring" | "putchilledstring_dummy" => {}
        _ => {}
    }
}

/// Render a `newhash` from its flattened `[k0, v0, k1, v1, ...]` stack slice. Symbol keys collapse
/// to the `name:` shorthand; other keys use the `=> ` rocket.
fn render_hash(flat: &[String]) -> String {
    if flat.is_empty() {
        return "{}".to_owned();
    }
    let mut pairs: Vec<String> = Vec::with_capacity(flat.len() / 2);
    for chunk in flat.chunks(2) {
        match chunk {
            [k, v] => {
                if let Some(sym) = k.strip_prefix(':')
                    && sym.chars().all(|c| c.is_alphanumeric() || c == '_')
                    && !sym.is_empty()
                {
                    pairs.push(format!("{sym}: {v}"));
                } else {
                    pairs.push(format!("{k} => {v}"));
                }
            }
            [k] => pairs.push(format!("{k} => nil")),
            _ => {}
        }
    }
    format!("{{ {} }}", pairs.join(", "))
}

/// Collapse the YARV string-interpolation coercion idiom `dup; objtostring; anytostring`: the `dup`
/// left two copies of the interpolated value and `objtostring` is treated as identity, so
/// `anytostring` discards the spare copy, leaving one expression to feed `concatstrings`.
fn collapse_interp_coercion(stack: &mut Vec<String>) {
    if stack.len() >= 2 {
        let top: String = pop(stack);
        let below: String = pop(stack);
        push(stack, if top == below { top } else { below });
    }
}

/// Reconstruct a `concatstrings` join. When the parts mix quoted string literals with expressions
/// the result is a Ruby interpolation `"text#{expr}text"`; a single part passes through unchanged;
/// an all-expression join (no literal anchor) falls back to a `+` concatenation so nothing is
/// fabricated.
fn render_interpolation(parts: &[String]) -> String {
    match parts {
        [] => "\"\"".to_owned(),
        [single] => single.clone(),
        _ => {
            let has_literal: bool = parts.iter().any(|p| is_string_literal(p));
            if !has_literal {
                return parts.join(" + ");
            }
            let mut out: String = String::with_capacity(MAX_EXPR_LEN.min(128));
            out.push('"');
            for part in parts {
                if let Some(body) = string_literal_body(part) {
                    out.push_str(body);
                } else {
                    out.push_str("#{");
                    out.push_str(part);
                    out.push('}');
                }
            }
            out.push('"');
            out
        }
    }
}

#[inline]
fn is_string_literal(s: &str) -> bool {
    string_literal_body(s).is_some()
}

/// The inner text of a Rust-`Debug`-rendered string literal (`"..."`), or `None` when `s` is not a
/// plain double-quoted literal (e.g. an expression, or a literal containing nested quotes/escapes
/// that would be unsafe to splice verbatim into an interpolation).
fn string_literal_body(s: &str) -> Option<&str> {
    let inner: &str = s.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"') || inner.contains('\\') || inner.contains("#{") {
        return None;
    }
    Some(inner)
}

/// The method body iseq referenced by a `definemethod`/`definesmethod` (operand #1).
fn method_iseq<'a>(
    instr: &YarvIbfInstruction,
    ctx: &DecompileContext<'a>,
) -> Option<&'a YarvIseqBody> {
    match instr.operands.get(1) {
        Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index),
        _ => None,
    }
}

/// Render a `definemethod`/`definesmethod` signature `(a, b)` from the parameter ABI of the method
/// body iseq. Empty when the method takes no parameters, so the surface reads `def name`.
fn method_signature(instr: &YarvIbfInstruction, ctx: &DecompileContext<'_>) -> String {
    method_iseq(instr, ctx).map_or_else(String::new, render_param_signature)
}

/// Render a parameter list `(a, b)` from the leading `param.lead_num` `local_table` entries,
/// preserving arity: an unnamed (hidden) positional slot reuses the same `local{N}` identifier the
/// body's `getlocal`/`setlocal` references produce (`N` = its environment operand), so the parameter
/// and its uses stay consistent and recompile-correct. Empty when there are no leading parameters.
fn render_param_signature(body: &YarvIseqBody) -> String {
    let lead: usize = body.param_lead_num as usize;
    if lead == 0 {
        return String::new();
    }
    let size: usize = body.local_table.len();
    let params: Vec<String> = (0..lead)
        .map(|idx| {
            body.local_table
                .get(idx)
                .and_then(Option::as_deref)
                .map_or_else(
                    || format!("local{}", size - idx - 1 + VM_ENV_DATA_SIZE as usize),
                    str::to_owned,
                )
        })
        .collect();
    format!("({})", params.join(", "))
}

/// Render an `opt_getconstant_path` operand: resolve the cache array into `A::B::C` when possible,
/// a bare `Id`/`Literal` operand into the constant name, else fall back to `obj[N]`.
fn constant_path_value(instr: &YarvIbfInstruction, ctx: &DecompileContext<'_>) -> String {
    match instr.operands.first() {
        Some(YarvOperand::ObjectRef(index)) => ctx
            .constant_path(*index)
            .unwrap_or_else(|| operand_value(instr, 0)),
        Some(YarvOperand::Id(name) | YarvOperand::Literal(name)) => name.clone(),
        _ => operand_value(instr, 0),
    }
}

fn emit_send(
    instr: &YarvIbfInstruction,
    ctx: &DecompileContext<'_>,
    depth: u32,
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) {
    let (method, argc): (String, usize) = match instr.operands.first() {
        Some(YarvOperand::Call { method, argc }) => (method.clone(), *argc as usize),
        Some(YarvOperand::Id(name)) => (name.clone(), 0),
        _ => ("call".to_owned(), 0),
    };
    let block_iseq: Option<&YarvIseqBody> = match instr.operands.get(1) {
        Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index),
        _ => None,
    };
    let args: Vec<String> = pop_n(stack, argc);
    let recv: String = pop(stack);
    let call: String = render_method_call(&recv, &method, &args);

    match block_iseq {
        Some(block) if depth <= MAX_NEST_DEPTH => {
            let block_lines: Vec<String> = render_block_lines(block, ctx, depth);
            if block_lines.len() <= 1 {
                let inline: String = block_lines.first().map_or_else(
                    || format!("{call} {{ }}"),
                    |single| format!("{call} {single}"),
                );
                push(stack, inline);
            } else {
                emit_block_call(stmts, &call, &block_lines, depth);
                push(stack, String::new());
            }
        }
        _ => push(stack, call),
    }
}

/// Render a block as one line when its body is a single statement (`{ |x| body }`), else as the
/// header line `recv... do |x|` followed by indented body lines and a closing `end`. Returns the
/// lines; a single-element result is the inline form, multi-element is the `do...end` form.
fn render_block_lines(block: &YarvIseqBody, ctx: &DecompileContext<'_>, depth: u32) -> Vec<String> {
    let params: String = block_param_list(block);
    let inner: Vec<String> = render_iseq_statements(block, ctx, 0);
    let body_only: Vec<&str> = inner
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if body_only.len() <= 1 {
        let body: &str = body_only.first().copied().unwrap_or("");
        let one: String = if body.is_empty() {
            format!("{{{params} }}")
        } else {
            format!("{{{params} {body} }}")
        };
        return vec![one];
    }
    let mut lines: Vec<String> = Vec::with_capacity(inner.len() + 2);
    lines.push(format!("do{params}"));
    for l in render_iseq_statements(block, ctx, depth + 1) {
        lines.push(l);
    }
    lines
}

/// Append a multi-line `recv.method(args) do |x|` ... `end` block-call to `stmts`.
fn emit_block_call(stmts: &mut Vec<String>, call: &str, block_lines: &[String], depth: u32) {
    let pad: String = indent(depth);
    if let Some(header) = block_lines.first() {
        stmts.push(format!("{pad}{call} {header}"));
    }
    for line in &block_lines[1..] {
        stmts.push(line.clone());
    }
    stmts.push(format!("{pad}end"));
}

/// `" |a, b|"` from a block iseq's lead parameters, or `""` when it takes no positional params.
fn block_param_list(block: &YarvIseqBody) -> String {
    let params: Vec<&str> = block
        .local_table
        .iter()
        .take(block.param_lead_num as usize)
        .filter_map(Option::as_deref)
        .collect();
    if params.is_empty() {
        String::new()
    } else {
        format!(" |{}|", params.join(", "))
    }
}

/// An anonymous argument-forwarding marker that appears as a synthetic local name (`...`, `*`,
/// `**`, `&`); these cannot be spliced as an ordinary receiver/argument and are handled specially.
fn is_forward_marker(s: &str) -> bool {
    matches!(s, "..." | "*" | "**" | "&") || s.starts_with("...")
}

/// `invokesuper` -> `super(args)`, or bare `super` (implicit forward) for zero args or when any
/// argument is an anonymous-forwarding marker that cannot be named. The instruction also consumes a
/// block operand which carries no source text here.
fn emit_super(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let argc: usize = match instr.operands.first() {
        Some(YarvOperand::Call { argc, .. }) => *argc as usize,
        _ => 0,
    };
    let args: Vec<String> = pop_n(stack, argc);
    let _ = pop(stack);
    if args.is_empty() || args.iter().any(|a| is_forward_marker(a) || a.is_empty()) {
        push(stack, "super".to_owned());
    } else {
        push(stack, format!("super({})", args.join(", ")));
    }
}

/// `invokeblock` -> `yield(args)` (or bare `yield`).
fn emit_invokeblock(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let argc: usize = match instr.operands.first() {
        Some(YarvOperand::Call { argc, .. }) => *argc as usize,
        _ => 0,
    };
    let args: Vec<String> = pop_n(stack, argc);
    if args.is_empty() {
        push(stack, "yield".to_owned());
    } else {
        push(stack, format!("yield({})", args.join(", ")));
    }
}

fn emit_unary_call(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let method: String = match instr.operands.first() {
        Some(YarvOperand::Call { method, .. }) => method.clone(),
        _ => return,
    };
    let recv: String = pop(stack);
    push(stack, render_method_call(&recv, &method, &[]));
}

/// Ruby keywords that, when recovered as a method name on `self`, must keep the explicit `self.`
/// receiver (`self.class`, not bare `class`) to stay valid source.
const SELF_QUALIFIED_KEYWORDS: &[&str] = &[
    "class", "begin", "end", "do", "then", "case", "while", "until", "if", "unless", "def",
    "module", "return", "yield", "next", "break", "redo", "retry", "super", "self", "nil", "true",
    "false", "and", "or", "not", "in", "for", "ensure", "rescue", "raise",
];

fn render_method_call(recv: &str, method: &str, args: &[String]) -> String {
    let method: &str = sanitize_method(method);
    let prefix: String = if (recv == "self" && !SELF_QUALIFIED_KEYWORDS.contains(&method))
        || recv.is_empty()
        || is_forward_marker(recv)
    {
        String::new()
    } else {
        format!("{recv}.")
    };
    let clean_args: Vec<&String> = args.iter().filter(|a| !a.is_empty()).collect();
    if clean_args.is_empty() {
        format!("{prefix}{method}")
    } else {
        let joined: String = clean_args
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>()
            .join(", ");
        format!("{prefix}{method}({joined})")
    }
}

/// Map an unresolved/sentinel calldata method name to a valid identifier so the surface stays
/// compilable; `(call)` (mid not recovered) becomes `__send__` of no further info, rendered as a
/// neutral `call`.
fn sanitize_method(method: &str) -> &str {
    match method {
        "(call)" | "" => "call",
        other => other,
    }
}

fn emit_binop(_instr: &YarvIbfInstruction, stack: &mut Vec<String>, op: &str) {
    let rhs: String = pop(stack);
    let lhs: String = pop(stack);
    push(stack, format!("{lhs} {op} {rhs}"));
}

/// Whether a popped stack expression carries a side effect worth surfacing as a statement: a method
/// call (`(`/`.`), an assignment (` = `, including `[]=`/attribute writers), or `yield`/`super`.
fn is_effecting_call(expr: &str) -> bool {
    expr.contains('(')
        || expr.contains('.')
        || expr.contains(" = ")
        || expr.starts_with("yield")
        || expr.starts_with("super")
}

#[inline]
fn push(stack: &mut Vec<String>, v: String) {
    if stack.len() < MAX_STACK {
        let bounded: String = if v.len() > MAX_EXPR_LEN {
            "(...)".to_owned()
        } else {
            v
        };
        stack.push(bounded);
    }
}

#[inline]
fn pop(stack: &mut Vec<String>) -> String {
    stack.pop().unwrap_or_else(|| "_".to_owned())
}

fn pop_n(stack: &mut Vec<String>, n: usize) -> Vec<String> {
    let take: usize = n.min(stack.len());
    let mut out: Vec<String> = stack.split_off(stack.len() - take);
    if out.len() < n {
        let mut pad: Vec<String> = vec!["_".to_owned(); n - out.len()];
        pad.append(&mut out);
        out = pad;
    }
    out
}

fn operand_value(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Literal(s)) => format!("{s:?}"),
        Some(YarvOperand::NumLiteral(s)) => s.clone(),
        Some(YarvOperand::Id(s)) => format!(":{s}"),
        Some(YarvOperand::ObjectRef(i)) => format!("obj[{i}]"),
        Some(YarvOperand::IseqRef(i)) => format!("iseq[{i}]"),
        Some(YarvOperand::Num(n)) => n.to_string(),
        Some(YarvOperand::Offset(o)) => format!("->{o}"),
        Some(YarvOperand::Builtin(b)) => format!("<builtin {b}>"),
        Some(YarvOperand::Call { method, .. }) => format!(":{method}"),
        None => "_".to_owned(),
    }
}

fn operand_num(instr: &YarvIbfInstruction, idx: usize) -> u64 {
    match instr.operands.get(idx) {
        Some(YarvOperand::Num(n)) => *n,
        Some(YarvOperand::Offset(o)) => u64::from(*o),
        Some(YarvOperand::ObjectRef(i) | YarvOperand::IseqRef(i)) => u64::from(*i),
        _ => 0,
    }
}

fn id_or_index(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => s.clone(),
        Some(YarvOperand::ObjectRef(i)) => format!("Const{i}"),
        _ => "_".to_owned(),
    }
}

/// Instance-variable name from an operand whose symbol already carries its `@` sigil; falls back
/// to prefixing when an `ObjectRef` index could not resolve.
fn ivar_name(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) if s.starts_with('@') => s.clone(),
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => format!("@{s}"),
        _ => "@ivar".to_owned(),
    }
}

fn push_section(out: &mut String, title: &str, items: &[String]) {
    let _: core::result::Result<(), core::fmt::Error> =
        writeln!(out, "# {} ({}):", title, items.len());
    for item in items {
        let _: core::result::Result<(), core::fmt::Error> = writeln!(out, "#   {item:?}");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::yarv::ibf::{
        CatchType, IbfObject, IbfObjectKind, YarvCatchEntry, YarvIbfInstruction, YarvIseqBody,
        YarvOperand,
    };

    fn obj(index: u32, kind: IbfObjectKind, literal: Option<&str>) -> IbfObject {
        IbfObject {
            index,
            offset: 0,
            kind,
            literal: literal.map(str::to_owned),
            element_count: None,
            elements: Vec::new(),
        }
    }

    fn decompile_body(body: &YarvIseqBody) -> Vec<String> {
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects: Vec::new(),
            iseqs: vec![body.clone()],
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        decompile_in_image(body, &image)
    }

    fn decompile_in_image(body: &YarvIseqBody, image: &IbfImage) -> Vec<String> {
        let ctx: DecompileContext<'_> = DecompileContext::from_image(image);
        super::render_iseq_statements(body, &ctx, 0)
            .into_iter()
            .map(|l| l.trim_start().to_owned())
            .collect()
    }

    fn instr(mnemonic: &str, operands: Vec<YarvOperand>) -> YarvIbfInstruction {
        YarvIbfInstruction {
            pc: 0,
            opcode: 0,
            mnemonic: mnemonic.to_owned(),
            operands,
        }
    }

    #[test]
    fn catch_table_rescue_wraps_protected_range_in_begin_rescue_end() {
        let parent: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("a".to_owned()), Some("b".to_owned())],
            param_lead_num: 2,
            catch_entries: vec![YarvCatchEntry {
                catch_type: CatchType::Rescue,
                start_pc: 0,
                end_pc: 5,
                cont_pc: 6,
                handler_iseq: Some(1),
            }],
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(4)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "opt_div",
                    vec![YarvOperand::Call {
                        method: "/".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("nop", vec![]),
                instr("leave", vec![]),
            ],
        };
        let handler: YarvIseqBody = YarvIseqBody {
            index: 1,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("$!".to_owned())],
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "opt_getconstant_path",
                    vec![YarvOperand::Id("ZeroDivisionError".to_owned())],
                ),
                instr("checkmatch", vec![YarvOperand::Num(3)]),
                instr("branchunless", vec![YarvOperand::Offset(6)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("setlocal_WC_1", vec![YarvOperand::Num(3)]),
                instr("putobject_INT2FIX_0_", vec![]),
                instr("leave", vec![]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("throw", vec![YarvOperand::Num(0)]),
            ],
        };
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects: Vec::new(),
            iseqs: vec![parent.clone(), handler],
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        let stmts: Vec<String> = decompile_in_image(&parent, &image);
        assert!(stmts.iter().any(|s| s == "begin"), "stmts: {stmts:?}");
        assert!(
            stmts.iter().any(|s| s == "rescue ZeroDivisionError"),
            "stmts: {stmts:?}"
        );
        assert!(stmts.iter().any(|s| s == "end"), "stmts: {stmts:?}");
        assert!(stmts.iter().any(|s| s == "a / b"), "stmts: {stmts:?}");
    }

    #[test]
    fn ivar_or_assign_folds_to_compound_assignment() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr(
                    "getinstancevariable",
                    vec![YarvOperand::Id("@count".to_owned())],
                ),
                instr("dup", vec![]),
                instr("branchif", vec![YarvOperand::Offset(5)]),
                instr("pop", vec![]),
                instr("putobject_INT2FIX_0_", vec![]),
                instr("dup", vec![]),
                instr(
                    "setinstancevariable",
                    vec![YarvOperand::Id("@count".to_owned())],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "@count ||= 0"),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn no_dispatch_case_when_folds_class_comparisons() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("x".to_owned())],
            param_lead_num: 1,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "opt_getconstant_path",
                    vec![YarvOperand::Id("Integer".to_owned())],
                ),
                instr("topn", vec![YarvOperand::Num(1)]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "===".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("branchif", vec![YarvOperand::Offset(12)]),
                instr(
                    "opt_getconstant_path",
                    vec![YarvOperand::Id("String".to_owned())],
                ),
                instr("topn", vec![YarvOperand::Num(1)]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "===".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("branchif", vec![YarvOperand::Offset(8)]),
                instr("pop", vec![]),
                instr("putobject", vec![YarvOperand::Id("other".to_owned())]),
                instr("leave", vec![]),
                instr("pop", vec![]),
                instr("putobject", vec![YarvOperand::Id("int".to_owned())]),
                instr("leave", vec![]),
                instr("pop", vec![]),
                instr("putobject", vec![YarvOperand::Id("str".to_owned())]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(stmts.iter().any(|s| s == "case x"), "stmts: {stmts:?}");
        assert!(
            stmts.iter().any(|s| s == "when Integer"),
            "stmts: {stmts:?}"
        );
        assert!(stmts.iter().any(|s| s == "when String"), "stmts: {stmts:?}");
    }

    #[test]
    fn case_dispatch_folds_to_case_when_else() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("x".to_owned())],
            param_lead_num: 1,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("dup", vec![]),
                instr(
                    "opt_case_dispatch",
                    vec![YarvOperand::Num(0), YarvOperand::Offset(15)],
                ),
                instr("putobject_INT2FIX_1_", vec![]),
                instr("topn", vec![YarvOperand::Num(1)]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "===".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("branchif", vec![YarvOperand::Offset(12)]),
                instr("putobject", vec![YarvOperand::NumLiteral("2".to_owned())]),
                instr("topn", vec![YarvOperand::Num(1)]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "===".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("branchif", vec![YarvOperand::Offset(8)]),
                instr("pop", vec![]),
                instr("putstring", vec![YarvOperand::Literal("many".to_owned())]),
                instr("leave", vec![]),
                instr("pop", vec![]),
                instr("putstring", vec![YarvOperand::Literal("one".to_owned())]),
                instr("leave", vec![]),
                instr("pop", vec![]),
                instr("putstring", vec![YarvOperand::Literal("two".to_owned())]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(stmts.iter().any(|s| s == "case x"), "stmts: {stmts:?}");
        assert!(stmts.iter().any(|s| s == "when 1"), "stmts: {stmts:?}");
        assert!(stmts.iter().any(|s| s == "when 2"), "stmts: {stmts:?}");
        assert!(stmts.iter().any(|s| s == "else"), "stmts: {stmts:?}");
        assert!(stmts.iter().any(|s| s == "\"one\""), "stmts: {stmts:?}");
        assert!(stmts.iter().any(|s| s == "\"many\""), "stmts: {stmts:?}");
    }

    #[test]
    fn short_circuit_and_folds_to_logical_and() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("a".to_owned()), Some("b".to_owned())],
            param_lead_num: 2,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(4)]),
                instr("dup", vec![]),
                instr("branchunless", vec![YarvOperand::Offset(3)]),
                instr("pop", vec![]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert_eq!(stmts, vec!["a && b".to_owned()], "stmts: {stmts:?}");
    }

    #[test]
    fn short_circuit_or_folds_to_logical_or() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("a".to_owned()), Some("b".to_owned())],
            param_lead_num: 2,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(4)]),
                instr("dup", vec![]),
                instr("branchif", vec![YarvOperand::Offset(3)]),
                instr("pop", vec![]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert_eq!(stmts, vec!["a || b".to_owned()], "stmts: {stmts:?}");
    }

    #[test]
    fn safe_navigation_folds_branchnil() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("x".to_owned())],
            param_lead_num: 1,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("dup", vec![]),
                instr("branchnil", vec![YarvOperand::Offset(2)]),
                instr(
                    "opt_size",
                    vec![YarvOperand::Call {
                        method: "size".to_owned(),
                        argc: 0,
                    }],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert_eq!(stmts, vec!["x&.size".to_owned()], "stmts: {stmts:?}");
    }

    #[test]
    fn backward_branch_structures_while_loop() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("n".to_owned()), Some("i".to_owned())],
            param_lead_num: 1,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("putobject_INT2FIX_0_", vec![]),
                instr("setlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("jump", vec![YarvOperand::Offset(7)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("putobject_INT2FIX_1_", vec![]),
                instr(
                    "opt_plus",
                    vec![YarvOperand::Call {
                        method: "+".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("setlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(4)]),
                instr(
                    "opt_lt",
                    vec![YarvOperand::Call {
                        method: "<".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("branchif", vec![YarvOperand::Offset((-15_i32) as u32)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "while i < n") && stmts.iter().any(|s| s == "i = i + 1"),
            "stmts: {stmts:?}"
        );
        assert!(stmts.iter().any(|s| s == "end"), "stmts: {stmts:?}");
    }

    #[test]
    fn forward_branch_structures_if_else() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("x".to_owned())],
            param_lead_num: 1,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("putobject_INT2FIX_0_", vec![]),
                instr(
                    "opt_gt",
                    vec![YarvOperand::Call {
                        method: ">".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("branchunless", vec![YarvOperand::Offset(3)]),
                instr(
                    "putstring",
                    vec![YarvOperand::Literal("positive".to_owned())],
                ),
                instr("leave", vec![]),
                instr(
                    "putstring",
                    vec![YarvOperand::Literal("negative".to_owned())],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert_eq!(
            stmts,
            vec![
                "if x > 0".to_owned(),
                "\"positive\"".to_owned(),
                "else".to_owned(),
                "\"negative\"".to_owned(),
                "end".to_owned(),
            ],
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn interpolation_reconstructs_from_mixed_parts() {
        let parts: Vec<String> = vec![
            "\"hello, \"".to_owned(),
            "@who".to_owned(),
            "\"!\"".to_owned(),
        ];
        assert_eq!(render_interpolation(&parts), "\"hello, #{@who}!\"");
    }

    #[test]
    fn interpolation_all_expression_parts_fall_back_to_concat() {
        let parts: Vec<String> = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(render_interpolation(&parts), "a + b");
    }

    #[test]
    fn interpolation_single_part_passes_through() {
        assert_eq!(render_interpolation(&["x".to_owned()]), "x");
    }

    #[test]
    fn interp_coercion_idiom_collapses_to_single_expr() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 7,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr(
                    "putobject",
                    vec![YarvOperand::Literal("hello, ".to_owned())],
                ),
                instr(
                    "getinstancevariable",
                    vec![YarvOperand::Id("@who".to_owned())],
                ),
                instr("dup", vec![]),
                instr(
                    "objtostring",
                    vec![YarvOperand::Call {
                        method: "to_s".to_owned(),
                        argc: 0,
                    }],
                ),
                instr("anytostring", vec![]),
                instr("putobject", vec![YarvOperand::Literal("!".to_owned())]),
                instr("concatstrings", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "\"hello, #{@who}!\""),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn recovers_strings_and_symbols_from_pool() {
        let img: IbfImage = IbfImage {
            iseq_offsets: vec![0],
            objects: vec![
                obj(0, IbfObjectKind::String, Some("hello world")),
                obj(1, IbfObjectKind::Symbol, Some("puts")),
            ],
            iseqs: vec![],
            recovered_literal_count: 2,
            recovered_instruction_count: 0,
        };
        let out: YarvDecompiled = decompile_from_ibf(&img);
        assert!(out.recovered_strings.contains(&"hello world".to_owned()));
        assert!(out.recovered_symbols.contains(&"puts".to_owned()));
        assert_eq!(out.fidelity, Fidelity::LiteralPoolOnly);
    }

    #[test]
    fn surfaces_putself_putstring_send_as_method_call() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 4,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "putstring",
                    vec![YarvOperand::Literal("hello world".to_owned())],
                ),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "puts".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s.contains("puts(\"hello world\")")),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn local_name_maps_env_offset_through_local_table() {
        let table: Vec<Option<String>> = vec![Some("a".to_owned()), Some("b".to_owned())];
        assert_eq!(local_name(&table, 4), "a");
        assert_eq!(local_name(&table, 3), "b");
        assert_eq!(local_name(&table, 99), "local99");
        assert_eq!(local_name(&[], 3), "local3");
    }

    #[test]
    fn getlocal_setlocal_use_recovered_names() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 4,
            local_table: vec![Some("total".to_owned())],
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("putobject", vec![YarvOperand::Num(0)]),
                instr("setlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(stmts.iter().any(|s| s == "total = 0"), "stmts: {stmts:?}");
        assert!(stmts.iter().any(|s| s == "total"), "stmts: {stmts:?}");
    }

    #[test]
    fn definemethod_renders_param_list_from_method_iseq() {
        let method_body: YarvIseqBody = YarvIseqBody {
            index: 1,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("who".to_owned())],
            param_lead_num: 1,
            catch_entries: Vec::new(),
            instructions: Vec::new(),
        };
        let main: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 2,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr(
                    "definemethod",
                    vec![
                        YarvOperand::Id("initialize".to_owned()),
                        YarvOperand::IseqRef(1),
                    ],
                ),
                instr("leave", vec![]),
            ],
        };
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects: Vec::new(),
            iseqs: vec![main.clone(), method_body],
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        let stmts: Vec<String> = decompile_in_image(&main, &image);
        assert!(
            stmts.iter().any(|s| s == "def initialize(who)") && stmts.iter().any(|s| s == "end"),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn constant_path_joins_symbol_elements() {
        let objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Array,
                literal: None,
                element_count: Some(2),
                elements: vec![1, 2],
            },
            obj(1, IbfObjectKind::Symbol, Some("Tiny")),
            obj(2, IbfObjectKind::Symbol, Some("Greeter")),
        ];
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects,
            iseqs: Vec::new(),
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        let ctx: DecompileContext<'_> = DecompileContext::from_image(&image);
        assert_eq!(ctx.constant_path(0).as_deref(), Some("Tiny::Greeter"));
    }

    #[test]
    fn constant_path_rejects_non_symbol_array() {
        let objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Array,
                literal: None,
                element_count: Some(1),
                elements: vec![1],
            },
            obj(1, IbfObjectKind::String, Some("not a const")),
        ];
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects,
            iseqs: Vec::new(),
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        let ctx: DecompileContext<'_> = DecompileContext::from_image(&image);
        assert_eq!(ctx.constant_path(0), None);
    }

    #[test]
    fn block_param_list_formats_named_params() {
        let with_params: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("x".to_owned()), Some("y".to_owned())],
            param_lead_num: 2,
            catch_entries: Vec::new(),
            instructions: Vec::new(),
        };
        assert_eq!(block_param_list(&with_params), " |x, y|");
        let no_params: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: Vec::new(),
        };
        assert_eq!(block_param_list(&no_params), "");
    }

    #[test]
    fn send_with_block_iseq_renders_block_params() {
        let block_body: YarvIseqBody = YarvIseqBody {
            index: 1,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("n".to_owned())],
            param_lead_num: 1,
            catch_entries: Vec::new(),
            instructions: Vec::new(),
        };
        let main: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 3,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "each".to_owned(),
                            argc: 0,
                        },
                        YarvOperand::IseqRef(1),
                    ],
                ),
                instr("leave", vec![]),
            ],
        };
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects: Vec::new(),
            iseqs: vec![main.clone(), block_body],
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        let stmts: Vec<String> = decompile_in_image(&main, &image);
        assert!(
            stmts.iter().any(|s| s.contains(".each { |n| }")),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn send_with_sentinel_block_iseq_has_no_block() {
        let main: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 3,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "map".to_owned(),
                            argc: 0,
                        },
                        YarvOperand::IseqRef(u32::MAX),
                    ],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&main);
        assert!(
            stmts.iter().any(|s| s == "map"),
            "no block should be rendered for sentinel iseq ref, stmts: {stmts:?}"
        );
        assert!(stmts.iter().all(|s| !s.contains('{')), "stmts: {stmts:?}");
    }

    #[test]
    fn surfaces_binary_op() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 4,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                instr("putobject", vec![YarvOperand::Num(1)]),
                instr("putobject", vec![YarvOperand::Num(2)]),
                instr("opt_plus", vec![YarvOperand::Num(0)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s.contains("1 + 2")),
            "stmts: {stmts:?}"
        );
    }
}
