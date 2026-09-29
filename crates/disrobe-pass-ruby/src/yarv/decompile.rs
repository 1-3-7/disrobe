use std::collections::BTreeMap;
use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::yarv::ibf::{
    CatchType, IbfImage, IbfObjectKind, YarvCatchEntry, YarvIbfInstruction, YarvIseqBody,
    YarvOperand, ruby_string_literal,
};

const MAX_STACK: usize = 8192;
const MAX_EXPR_LEN: usize = 8192;
const MAX_OPERAND_COUNT: usize = MAX_STACK;

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

    let frozen_string_literal: bool = detect_frozen_string_literal(image);

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

    let mut magic: Vec<&str> = Vec::with_capacity(2);
    if frozen_string_literal {
        magic.push(FROZEN_STRING_MAGIC);
    }
    if detect_shareable_constant_value(image) {
        magic.push(SHAREABLE_CONSTANT_MAGIC);
    }
    if !magic.is_empty() {
        let header: String = magic.iter().fold(String::new(), |mut acc, line| {
            acc.push_str(line);
            acc.push('\n');
            acc
        });
        let mut with_magic: String = String::with_capacity(out.len() + header.len());
        with_magic.push_str(&header);
        with_magic.push_str(&out);
        out = with_magic;
    }

    YarvDecompiled {
        source: out,
        statement_count,
        fidelity,
        recovered_strings,
        recovered_symbols,
    }
}

const MAX_NEST_DEPTH: u32 = 64;
const FROZEN_STRING_MAGIC: &str = "# frozen_string_literal: true";
const SHAREABLE_CONSTANT_MAGIC: &str = "# shareable_constant_value: literal";
const VM_CALL_ARGS_SPLAT: u32 = 1;
const VM_CALL_ARGS_BLOCKARG: u32 = 1 << 1;
const VM_CALL_KW_SPLAT: u32 = 1 << 6;
const VM_CALL_ZSUPER: u32 = 1 << 9;
const DEFINECLASS_FLAG_SCOPED: u64 = 0x08;
const DEFINECLASS_FLAG_HAS_SUPERCLASS: u64 = 0x10;

fn detect_frozen_string_literal(image: &IbfImage) -> bool {
    let mut saw_string_putobject: bool = false;
    for body in &image.iseqs {
        for instr in &body.instructions {
            match instr.mnemonic.as_str() {
                "putstring" | "putchilledstring" => return false,
                "putobject" => {
                    if matches!(instr.operands.first(), Some(YarvOperand::StrLiteral(_))) {
                        saw_string_putobject = true;
                    }
                }
                _ => {}
            }
        }
    }
    saw_string_putobject
}

fn detect_shareable_constant_value(image: &IbfImage) -> bool {
    image.iseqs.iter().any(|body| {
        body.instructions.iter().any(|instr| {
            instr.mnemonic == "opt_send_without_block"
                && matches!(
                    instr.operands.first(),
                    Some(YarvOperand::Call { method, .. }) if method == "ensure_shareable"
                )
        })
    })
}

fn resolve_branch_targets(body: &YarvIseqBody) -> Vec<Option<usize>> {
    let mut rt_pc: Vec<u32> = Vec::with_capacity(body.instructions.len());
    let mut pc_to_index: BTreeMap<u32, usize> = BTreeMap::new();
    let mut pc: u32 = 0;
    for (idx, instr) in body.instructions.iter().enumerate() {
        rt_pc.push(pc);
        pc_to_index.entry(pc).or_insert(idx);
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
        targets[idx] = u32::try_from(target_pc)
            .ok()
            .and_then(|p| pc_to_index.get(&p).copied());
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

fn runtime_pcs(body: &YarvIseqBody) -> Vec<u32> {
    let mut rt_pc: Vec<u32> = Vec::with_capacity(body.instructions.len());
    let mut pc: u32 = 0;
    for instr in &body.instructions {
        rt_pc.push(pc);
        pc = pc.saturating_add(1 + instr.operands.len() as u32);
    }
    rt_pc
}

fn index_at_pc(rt_pc: &[u32], pc: u32) -> usize {
    rt_pc.iter().position(|&p| p >= pc).unwrap_or(rt_pc.len())
}

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
    let opt_end: usize = optional_prologue(body).map_or(0, |(_, end)| end);
    let start: usize = if body.param_flags & PARAM_FLAG_HAS_KW != 0 {
        keyword_default_prologue(body, ctx, opt_end).1
    } else {
        opt_end
    };
    let mut stack: Vec<String> = Vec::with_capacity(32);
    let mut stmts: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        start,
        body.instructions.len(),
        &targets,
        &mut stack,
        &mut stmts,
    );
    stmts
}

fn try_guarded_defined(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stack: &mut Vec<String>,
) -> Option<usize> {
    if body.instructions.get(i + 1)?.mnemonic != "branchunless" {
        return None;
    }
    let join: usize = targets.get(i + 1).copied().flatten()?;
    if join < i + 4 || join > hi {
        return None;
    }
    let tail_at = |defined: usize| -> bool {
        body.instructions[defined].mnemonic == "defined"
            && body.instructions[defined + 1].mnemonic == "swap"
            && body.instructions[defined + 2].mnemonic == "pop"
    };
    let last_idx: usize = if join < hi && tail_at(join - 2) {
        join - 2
    } else if join >= i + 5 && tail_at(join - 3) {
        join - 3
    } else {
        return None;
    };
    let end: usize = last_idx + 3;
    if end > hi || stack.len() < 2 {
        return None;
    }
    let last: &YarvIbfInstruction = &body.instructions[last_idx];
    let is_link_check = |k: usize| -> bool {
        body.instructions[k].mnemonic == "defined"
            && body
                .instructions
                .get(k + 1)
                .is_some_and(|x| x.mnemonic == "branchunless")
            && targets.get(k + 1).copied().flatten() == Some(join)
    };
    let mut links: Vec<usize> = Vec::new();
    let mut k: usize = i + 2;
    while k < last_idx {
        if is_link_check(k) {
            links.push(k);
            k += 2;
            continue;
        }
        if matches!(
            body.instructions[k].mnemonic.as_str(),
            "branchif" | "branchunless" | "branchnil" | "jump" | "defined" | "leave" | "throw"
        ) {
            return None;
        }
        k += 1;
    }
    let mut work: Vec<String> = stack.clone();
    work.pop();
    let mut sink: Vec<String> = Vec::new();
    let mut seg_lo: usize = i + 2;
    for link in links {
        render_region(
            body, ctx, depth, seg_lo, link, targets, &mut work, &mut sink,
        );
        work.pop()?;
        seg_lo = link + 2;
    }
    render_region(
        body, ctx, depth, seg_lo, last_idx, targets, &mut work, &mut sink,
    );
    if !sink.is_empty() {
        return None;
    }
    let receiver: String = work.pop()?;
    let name: String = defined_operand(last);
    let target: String = match operand_num(last, 0) {
        DEFINED_METHOD => format!("{}.{name}", assignment_receiver(receiver)),
        DEFINED_CONST | DEFINED_CONST_FROM => format!("{receiver}::{name}"),
        _ => return None,
    };
    let slot: &mut String = work.last_mut()?;
    *slot = format!("defined?({target})");
    *stack = work;
    Some(end)
}

fn is_user_rescue(entry: &YarvCatchEntry, ctx: &DecompileContext<'_>) -> bool {
    if entry.catch_type != CatchType::Rescue {
        return false;
    }
    let Some(handler): Option<&YarvIseqBody> = entry.handler_iseq.and_then(|h| ctx.body(h)) else {
        return false;
    };
    let is_defined_guard: bool = matches!(
        handler.instructions.as_slice(),
        [nil, leave] if nil.mnemonic == "putnil" && leave.mnemonic == "leave"
    );
    !is_defined_guard
}

fn try_render_exception_region(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
) -> Option<Vec<String>> {
    let rescue: Option<&YarvCatchEntry> =
        body.catch_entries.iter().find(|e| is_user_rescue(e, ctx));
    let ensure: Option<&YarvCatchEntry> = body
        .catch_entries
        .iter()
        .find(|e| e.catch_type == CatchType::Ensure && e.handler_iseq.is_some());
    if rescue.is_none() && ensure.is_none() {
        return None;
    }
    if body
        .catch_entries
        .iter()
        .filter(|e| e.catch_type == CatchType::Ensure && e.handler_iseq.is_some())
        .count()
        > 1
    {
        return None;
    }

    let rt_pc: Vec<u32> = runtime_pcs(body);
    let entry: &YarvCatchEntry = rescue.or(ensure)?;
    let start: usize = index_at_pc(&rt_pc, entry.start_pc);
    let end: usize = index_at_pc(&rt_pc, entry.end_pc);
    if start >= end || end > body.instructions.len() {
        return None;
    }
    if region_is_inside_a_loop(body, start, end) {
        return None;
    }

    let pad: String = indent(depth);
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    let mut pending: Vec<String> = Vec::new();
    let mut discarded: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        0,
        start,
        &targets,
        &mut pending,
        &mut discarded,
    );
    if !pending.is_empty() {
        return None;
    }
    let mut lines: Vec<String> = Vec::new();

    let prefix: Vec<String> = render_slice(body, ctx, depth, 0, start, &targets);
    lines.extend(prefix);

    let begin_line: usize = lines.len();
    lines.push(format!("{pad}begin"));
    let protected: Vec<String> = render_slice(body, ctx, depth + 1, start, end, &targets);
    lines.extend(protected);

    if let Some(handler_idx) = rescue.and_then(|e| e.handler_iseq)
        && let Some(handler) = ctx.body(handler_idx)
    {
        lines.extend(render_rescue_handler(
            handler,
            &body.local_table,
            ctx,
            depth,
        ));
    }
    let rescue_else: Option<(usize, usize)> = rescue.and_then(|entry| {
        let cont: usize = index_at_pc(&rt_pc, entry.cont_pc).min(body.instructions.len());
        let mut else_hi: usize = cont;
        while else_hi > end + 1
            && body
                .instructions
                .get(else_hi - 1)
                .is_some_and(|x| x.mnemonic == "nop")
        {
            else_hi -= 1;
        }
        (body
            .instructions
            .get(end)
            .is_some_and(|x| x.mnemonic == "pop")
            && end + 1 < else_hi)
            .then_some((end + 1, else_hi))
    });
    if let Some((else_lo, else_hi)) = rescue_else {
        lines.push(format!("{pad}else"));
        lines.extend(render_slice(
            body,
            ctx,
            depth + 1,
            else_lo,
            else_hi,
            &targets,
        ));
    }
    if let Some(handler_idx) = ensure.and_then(|e| e.handler_iseq)
        && let Some(handler) = ctx.body(handler_idx)
    {
        lines.push(format!("{pad}ensure"));
        let nested: DecompileContext<'_> = ctx.nested_in(&body.local_table);
        lines.extend(render_iseq_statements(handler, &nested, depth + 1));
    }
    lines.push(format!("{pad}end"));

    let suffix_start: usize = ensure.map_or(end, |entry| {
        index_at_pc(&rt_pc, entry.cont_pc)
            .max(end)
            .min(body.instructions.len())
    });
    let suffix_start: usize =
        rescue_else.map_or(suffix_start, |(_, else_hi)| suffix_start.max(else_hi));
    let assigned_at: Option<usize> =
        (suffix_start..body.instructions.len()).find(|&k| body.instructions[k].mnemonic != "nop");
    let suffix_start: usize = match assigned_at.and_then(|k| {
        assignment_target(&body.instructions[k], &body.local_table, ctx).map(|target| (k, target))
    }) {
        Some((k, target)) => {
            lines[begin_line] = format!("{pad}{target} = begin");
            k + 1
        }
        None => suffix_start,
    };
    let suffix: Vec<String> = render_slice(
        body,
        ctx,
        depth,
        suffix_start,
        body.instructions.len(),
        &targets,
    );
    lines.extend(suffix);
    Some(lines)
}

fn is_unconditional_loop_head(body: &YarvIseqBody, head: usize, targets: &[Option<usize>]) -> bool {
    head >= 3
        && body.instructions[head - 3].mnemonic == "jump"
        && targets.get(head - 3).copied().flatten() == Some(head)
        && body.instructions[head - 2].mnemonic == "putnil"
        && body.instructions[head - 1].mnemonic == "pop"
        && targets
            .iter()
            .rposition(|target| *target == Some(head))
            .is_some_and(|k| k >= head && body.instructions[k].mnemonic == "jump")
}

fn jump_leaves_a_loop(body: &YarvIseqBody, jump: usize, targets: &[Option<usize>]) -> bool {
    let Some(exit): Option<usize> = targets.get(jump).copied().flatten() else {
        return false;
    };
    if exit < jump + 3
        || body
            .instructions
            .get(exit - 1)
            .is_none_or(|x| x.mnemonic != "putnil")
    {
        return false;
    }
    let back_edge: usize = exit - 2;
    matches!(
        body.instructions[back_edge].mnemonic.as_str(),
        "branchif" | "branchunless" | "jump"
    ) && targets
        .get(back_edge)
        .copied()
        .flatten()
        .is_some_and(|back| back <= jump)
}

fn leave_is_inside_a_loop(leave: usize, targets: &[Option<usize>]) -> bool {
    targets
        .iter()
        .enumerate()
        .skip(leave + 1)
        .any(|(k, target)| target.is_some_and(|t| t <= leave && t < k))
}

fn region_is_inside_a_loop(body: &YarvIseqBody, start: usize, end: usize) -> bool {
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    targets
        .iter()
        .enumerate()
        .any(|(from, target): (usize, &Option<usize>)| {
            from >= end && target.is_some_and(|to: usize| to <= start)
        })
}

fn try_inline_ensure(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let rt_pc: Vec<u32> = runtime_pcs(body);
    let here: u32 = *rt_pc.get(i)?;
    let (end, cont): (usize, usize) = body
        .catch_entries
        .iter()
        .filter(|e: &&YarvCatchEntry| {
            e.catch_type == CatchType::Ensure && e.handler_iseq.is_some() && e.start_pc == here
        })
        .map(|e: &YarvCatchEntry| {
            let end: usize = index_at_pc(&rt_pc, e.end_pc);
            (end, index_at_pc(&rt_pc, e.cont_pc).max(end))
        })
        .filter(|&(end, cont): &(usize, usize)| end > i && end < hi && cont <= hi)
        .max_by_key(|&(end, _): &(usize, usize)| end)?;
    let pad: String = indent(depth);
    let begin_line: usize = stmts.len();
    stmts.push(format!("{pad}begin"));
    stmts.extend(render_slice(body, ctx, depth + 1, i, end, targets));
    stmts.push(format!("{pad}ensure"));
    stmts.extend(render_slice(body, ctx, depth + 1, end, cont, targets));
    stmts.push(format!("{pad}end"));
    let after: Option<usize> = (cont..hi).find(|&k| body.instructions[k].mnemonic != "nop");
    if let Some(k) = after
        && let Some(target) = assignment_target(&body.instructions[k], &body.local_table, ctx)
    {
        stmts[begin_line] = format!("{pad}{target} = begin");
        return Some(k + 1);
    }
    Some(cont)
}

fn try_inline_rescue(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let rt_pc: Vec<u32> = runtime_pcs(body);
    let here: u32 = *rt_pc.get(i)?;
    let entry: &YarvCatchEntry = body
        .catch_entries
        .iter()
        .find(|e: &&YarvCatchEntry| is_user_rescue(e, ctx) && e.start_pc == here)?;
    let end: usize = index_at_pc(&rt_pc, entry.end_pc);
    let cont: usize = index_at_pc(&rt_pc, entry.cont_pc).max(end);
    if end <= i || end >= hi || cont > hi {
        return None;
    }
    let handler: &YarvIseqBody = ctx.body(entry.handler_iseq?)?;
    if let Some(protected) = single_value_region(body, ctx, depth, i, end, targets) {
        let handler_lines: Vec<String> = render_rescue_handler(handler, &body.local_table, ctx, 0);
        if let [header, value] = handler_lines.as_slice()
            && matches!(header.trim(), "rescue" | "rescue StandardError")
            && !value.trim().is_empty()
            && !value.contains('\n')
        {
            push(stack, format!("({protected} rescue {})", value.trim()));
            return Some(cont.min(hi));
        }
    }
    let pad: String = indent(depth);
    stmts.push(format!("{pad}begin"));
    stmts.extend(render_slice(body, ctx, depth + 1, i, end, targets));
    stmts.extend(render_rescue_handler(
        handler,
        &body.local_table,
        ctx,
        depth,
    ));
    stmts.push(format!("{pad}end"));
    let resume: usize = if body
        .instructions
        .get(cont)
        .is_some_and(|x| x.mnemonic == "pop")
    {
        cont + 1
    } else {
        cont
    };
    Some(resume.min(hi))
}

fn render_rescue_handler(
    handler: &YarvIseqBody,
    parent_locals: &[Option<String>],
    ctx: &DecompileContext<'_>,
    depth: u32,
) -> Vec<String> {
    let pad: String = indent(depth);
    let targets: Vec<Option<usize>> = resolve_branch_targets(handler);
    let nested: DecompileContext<'_> = ctx.nested_in(parent_locals);
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
            match parse_rescue_clause(handler, parent_locals, ctx, i, &targets) {
                Some(clause) => clause,
                None => break,
            };
        let header: String = render_rescue_header(&classes, var.as_deref());
        lines.push(format!("{pad}{header}"));
        let body: Vec<String> =
            render_slice(handler, &nested, depth + 1, body_lo, body_hi, &targets);
        lines.extend(body);
        produced = true;
        i = next_clause_start(handler, body_hi);
    }

    if !produced {
        lines.push(format!("{pad}rescue"));
        lines.extend(render_slice(handler, &nested, depth + 1, 0, n, &targets));
    }
    lines
}

fn parse_rescue_clause(
    handler: &YarvIseqBody,
    parent_locals: &[Option<String>],
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
        let branch: &str = match handler.instructions.get(k + 3).map(|x| x.mnemonic.as_str()) {
            Some(b @ ("branchif" | "branchunless")) => b,
            _ => break,
        };
        if let Some(name) = class_name {
            classes.push(name);
        }
        k += 4;
        if branch == "branchif" {
            continue;
        }
        branch_target = targets.get(k - 1).copied().flatten();
        break;
    }

    let next_clause: usize = branch_target?;
    let loads_exception: bool = handler
        .instructions
        .get(k)
        .is_some_and(|x| x.mnemonic == "getlocal_WC_0");
    let set_instr: Option<&YarvIbfInstruction> = handler
        .instructions
        .get(k + 1)
        .filter(|_| loads_exception)
        .filter(|x| x.mnemonic.starts_with("setlocal"));
    let (var, body_lo): (Option<String>, usize) = set_instr.map_or((None, k), |set| {
        let table: &[Option<String>] = if local_access_level(set) >= 1 {
            parent_locals
        } else {
            &handler.local_table
        };
        (Some(local_name(table, operand_num(set, 0))), k + 2)
    });
    let body_hi: usize = (body_lo..next_clause)
        .find(|&j| handler.instructions[j].mnemonic == "leave")
        .map_or(next_clause, |leave| leave);
    Some((classes, var, body_lo, body_hi))
}

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

fn is_valid_rescue_var(v: &str) -> bool {
    !v.is_empty()
        && !v.starts_with("local")
        && !v.starts_with('$')
        && v.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
}

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
        let depth_before: usize = stack.len();
        if !body.catch_entries.is_empty()
            && stack.is_empty()
            && let Some(next) = try_inline_ensure(body, ctx, depth, i, hi, targets, stmts)
        {
            i = next;
            continue;
        }
        if !body.catch_entries.is_empty()
            && let Some(next) = try_inline_rescue(body, ctx, depth, i, hi, targets, stack, stmts)
        {
            i = next;
            if stack.len() <= depth_before {
                stack.clear();
            }
            continue;
        }
        if ctx.body_has_pattern(body.index)
            && let Some(next) = try_pattern_match(body, ctx, depth, i, hi, targets, stmts)
        {
            i = next;
            stack.clear();
            continue;
        }
        if let Some(next) = try_short_circuit(body, ctx, depth, i, hi, targets, stack) {
            i = next;
            continue;
        }
        if m == "defined"
            && let Some(next) = try_guarded_defined(body, ctx, depth, i, hi, targets, stack)
        {
            i = next;
            continue;
        }
        if m == "leave"
            && i >= 2
            && body.instructions[i - 1].mnemonic == "putnil"
            && body.instructions[i - 2].mnemonic == "pop"
            && stack.last().is_some_and(|top| top == "nil")
            && !leave_is_inside_a_loop(i, targets)
        {
            stack.pop();
            emit_stmt(stmts, depth, "nil".to_owned());
            i += 1;
            continue;
        }
        if m == "leave"
            && let Some(keyword) = ctx.early_exit_keyword(body.index)
            && leave_is_inside_a_loop(i, targets)
        {
            let value: String = stack.pop().unwrap_or_default();
            emit_value_flow(stmts, depth, keyword, value);
            i += 1;
            continue;
        }
        if let Some(next) = try_aref_compound_assign(body, ctx, depth, i, hi, targets, stack, stmts)
        {
            i = next;
            continue;
        }
        if let Some(next) = try_attr_compound_assign(body, ctx, depth, i, hi, targets, stack, stmts)
        {
            i = next;
            continue;
        }
        if let Some(next) = try_global_cond_assign(body, ctx, depth, i, hi, targets, stmts) {
            i = next;
            stack.clear();
            continue;
        }
        if let Some(next) = try_scalar_cond_assign(body, ctx, depth, i, hi, targets, stmts) {
            i = next;
            stack.clear();
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
            let first: String = pop(stack);
            let merged: MergedCondition =
                merge_condition(body, ctx, depth, i, target, first, targets);
            if let Some(next) = try_guard_return(body, ctx, depth, &merged, hi, targets, stmts) {
                i = next;
                stack.clear();
                continue;
            }
            if let Some((value, next)) =
                try_value_conditional(body, ctx, depth, &merged, hi, targets)
            {
                push(stack, value);
                i = next;
                continue;
            }
            let keyword: &str = if merged.branch_if { "unless" } else { "if" };
            render_conditional(
                body,
                ctx,
                depth,
                merged.branch_idx,
                merged.target,
                hi,
                keyword,
                &merged.cond,
                targets,
                stmts,
            );
            i = region_end_after_conditional(body, merged.target, hi, targets);
            stack.clear();
            continue;
        }
        if m == "dup"
            && let Some(next) = body.instructions.get(i + 1)
            && let Some(target) = assignment_target(next, &body.local_table, ctx)
            && !stack.is_empty()
        {
            let rhs: String = pop(stack);
            push(stack, format!("{target} = {rhs}"));
            i += 2;
            continue;
        }
        if m == "setn"
            && let Some(next) = try_retained_assignment(body, i, hi, stack)
        {
            i = next;
            continue;
        }
        if matches!(m, "opt_reverse" | "swap")
            && let Some(next) = try_parallel_assign(body, ctx, depth, i, hi, stack, stmts)
        {
            i = next;
            continue;
        }
        if m == "expandarray"
            && let Some(next) = try_massign(body, ctx, depth, i, hi, stack, stmts)
        {
            i = next;
            continue;
        }
        if m == "pop"
            && i > lo
            && send_method_argc(&body.instructions[i - 1]).is_some_and(|(_, argc)| argc == 0)
            && let Some(call) = stack.pop()
        {
            if is_effecting_call(&call) {
                emit_stmt(stmts, depth, call);
            } else if !call.is_empty() {
                emit_stmt(stmts, depth, format!("{call}()"));
            }
            i += 1;
            continue;
        }
        if matches!(m, "branchif" | "branchunless" | "jump")
            && let Some(head) = targets[i]
            && head <= i
            && is_unconditional_loop_head(body, head, targets)
        {
            if m == "jump" {
                emit_stmt(stmts, depth, "next".to_owned());
            } else {
                let cond: String = pop(stack);
                let keyword: &str = if m == "branchif" { "if" } else { "unless" };
                emit_stmt(stmts, depth, format!("next {keyword} {cond}"));
            }
            i += 1;
            continue;
        }
        if m == "jump"
            && ctx.early_exit_keyword(body.index) == Some("next")
            && targets[i].is_some_and(|t| {
                t <= i
                    && t > 0
                    && t == body
                        .instructions
                        .iter()
                        .position(|x: &YarvIbfInstruction| x.mnemonic != "nop")
                        .unwrap_or(0)
            })
        {
            emit_stmt(stmts, depth, "redo".to_owned());
            i += 1;
            continue;
        }
        if m == "jump" && jump_leaves_a_loop(body, i, targets) {
            let value: String = stack.pop().unwrap_or_default();
            emit_value_flow(stmts, depth, "break", value);
            i += 1;
            continue;
        }
        step(instr, &body.local_table, ctx, depth, stack, stmts);
        i += 1;
    }
}

struct MergedCondition {
    cond: String,
    branch_idx: usize,
    target: usize,
    branch_if: bool,
}

fn try_guard_return(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    merged: &MergedCondition,
    hi: usize,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let leave: usize = merged.target.checked_sub(1)?;
    if merged.target >= hi
        || leave <= merged.branch_idx
        || body.instructions[leave].mnemonic != "leave"
        || (merged.branch_idx + 1..leave).any(|j| {
            matches!(
                body.instructions[j].mnemonic.as_str(),
                "branchif" | "branchunless" | "branchnil" | "jump" | "leave" | "throw"
            )
        })
    {
        return None;
    }
    let mut then_stack: Vec<String> = Vec::with_capacity(4);
    let mut then_stmts: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        merged.branch_idx + 1,
        leave,
        targets,
        &mut then_stack,
        &mut then_stmts,
    );
    if !then_stmts.is_empty() || then_stack.len() > 1 {
        return None;
    }
    let exit_keyword: &str = ctx.early_exit_keyword(body.index)?;
    let value: String = then_stack.pop().unwrap_or_default();
    let keyword: &str = if merged.branch_if { "unless" } else { "if" };
    let tail_returns_nil: bool = hi == merged.target + 2
        && body.instructions[merged.target].mnemonic == "putnil"
        && body.instructions[merged.target + 1].mnemonic == "leave";
    if tail_returns_nil && !value.is_empty() && value != "nil" {
        emit_stmt(stmts, depth, format!("{value} {keyword} {}", merged.cond));
        return Some(hi);
    }
    let exit: String = if value.is_empty() || value == "nil" {
        exit_keyword.to_owned()
    } else {
        format!("{exit_keyword} {value}")
    };
    emit_stmt(stmts, depth, format!("{exit} {keyword} {}", merged.cond));
    Some(merged.target)
}

fn condition_operand(value: &str) -> String {
    if value.contains("||")
        || value.contains(" ? ")
        || value.contains(" or ")
        || value.contains(" and ")
    {
        format!("({value})")
    } else {
        value.to_owned()
    }
}

fn single_value_region(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> Option<String> {
    if lo >= hi {
        return None;
    }
    let mut stack: Vec<String> = Vec::new();
    let mut sink: Vec<String> = Vec::new();
    render_region(body, ctx, depth, lo, hi, targets, &mut stack, &mut sink);
    match (sink.is_empty(), stack.as_slice()) {
        (true, [value]) if !value.is_empty() && !value.contains('\n') => Some(value.clone()),
        _ => None,
    }
}

fn next_branch(body: &YarvIseqBody, from: usize, hi: usize) -> Option<usize> {
    (from..hi).find(|&k| {
        matches!(
            body.instructions[k].mnemonic.as_str(),
            "branchunless" | "branchif" | "branchnil" | "jump" | "leave" | "throw"
        )
    })
}

fn merge_condition(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    target: usize,
    first: String,
    targets: &[Option<usize>],
) -> MergedCondition {
    let mut merged: MergedCondition = MergedCondition {
        cond: first,
        branch_idx: i,
        target,
        branch_if: body.instructions[i].mnemonic == "branchif",
    };
    while let Some(k) = next_branch(body, merged.branch_idx + 1, merged.target) {
        let Some(next_target): Option<usize> = targets.get(k).copied().flatten() else {
            break;
        };
        if body.instructions[k].mnemonic == "branchif" {
            let op: &str = if !merged.branch_if && merged.target == k + 1 {
                "&&"
            } else if merged.branch_if && merged.target == next_target {
                "||"
            } else {
                break;
            };
            let Some(value): Option<String> =
                single_value_region(body, ctx, depth, merged.branch_idx + 1, k, targets)
            else {
                break;
            };
            merged.cond = format!(
                "{} {op} {}",
                condition_operand(&merged.cond),
                condition_operand(&value)
            );
            merged.branch_idx = k;
            merged.target = next_target;
            merged.branch_if = true;
            continue;
        }
        if body.instructions[k].mnemonic != "branchunless" {
            break;
        }
        let joins: bool = if merged.branch_if {
            merged.target == k + 1
        } else {
            next_target == merged.target
        };
        if !joins {
            break;
        }
        let Some(value): Option<String> =
            single_value_region(body, ctx, depth, merged.branch_idx + 1, k, targets)
        else {
            break;
        };
        let op: &str = if merged.branch_if { "||" } else { "&&" };
        merged.cond = format!(
            "{} {op} {}",
            condition_operand(&merged.cond),
            condition_operand(&value)
        );
        merged.branch_idx = k;
        merged.target = next_target;
        merged.branch_if = false;
    }
    merged
}

fn try_value_conditional(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    merged: &MergedCondition,
    hi: usize,
    targets: &[Option<usize>],
) -> Option<(String, usize)> {
    let then_last: usize = merged.target.checked_sub(1)?;
    if then_last <= merged.branch_idx || body.instructions.get(then_last)?.mnemonic != "jump" {
        return None;
    }
    let jumped_to: usize = targets.get(then_last).copied().flatten()?;
    let threaded_through_hi: bool = jumped_to > hi
        && body
            .instructions
            .get(hi)
            .is_some_and(|x| x.mnemonic == "jump")
        && targets.get(hi).copied().flatten() == Some(jumped_to);
    let join: usize = if threaded_through_hi { hi } else { jumped_to };
    if join <= merged.target || join > hi {
        return None;
    }
    if body
        .instructions
        .get(join)
        .is_none_or(|x| matches!(x.mnemonic.as_str(), "pop" | "leave"))
    {
        return None;
    }
    let fall: String =
        single_value_region(body, ctx, depth, merged.branch_idx + 1, then_last, targets)?;
    let taken: String = single_value_region(body, ctx, depth, merged.target, join, targets)?;
    let (when_true, when_false): (String, String) = if merged.branch_if {
        (taken, fall)
    } else {
        (fall, taken)
    };
    Some((
        format!(
            "({} ? {when_true} : {when_false})",
            condition_operand(&merged.cond)
        ),
        join,
    ))
}

fn try_massign(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let (targets, j): (Vec<String>, usize) = massign_targets(body, ctx, i, hi, 0)?;
    let rhs_raw: String = pop(stack);
    let rhs: &str = rhs_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&rhs_raw);
    let assignment: String = format!("{} = {rhs}", targets.join(", "));
    let retained: bool = i > 0
        && body.instructions[i - 1].mnemonic == "dup"
        && stack.last().is_some_and(|top| *top == rhs_raw);
    match stack.last_mut() {
        Some(top) if retained => *top = format!("({assignment})"),
        _ => emit_stmt(stmts, depth, assignment),
    }
    Some(j)
}

fn assignment_receiver(recv: String) -> String {
    if needs_receiver_parens(&recv) {
        format!("({recv})")
    } else {
        recv
    }
}

fn try_retained_assignment(
    body: &YarvIseqBody,
    i: usize,
    hi: usize,
    stack: &mut Vec<String>,
) -> Option<usize> {
    let n: usize = operand_count(&body.instructions[i], 0);
    let assign: &YarvIbfInstruction = body.instructions.get(i + 1)?;
    if i + 2 >= hi || body.instructions.get(i + 2)?.mnemonic != "pop" {
        return None;
    }
    let consumed: usize = match assign.mnemonic.as_str() {
        "opt_aset" => 3,
        "opt_aset_with" => 2,
        "opt_send_without_block" | "send" => match assign.operands.first() {
            Some(YarvOperand::Call { method, argc, .. })
                if method.ends_with('=') && !method.ends_with("==") && *argc == 1 =>
            {
                2
            }
            _ => return None,
        },
        _ => return None,
    };
    if n != consumed || stack.len() <= consumed {
        return None;
    }
    let expr: String = match assign.mnemonic.as_str() {
        "opt_aset" => {
            let val: String = pop(stack);
            let idx: String = pop(stack);
            let recv: String = assignment_receiver(pop(stack));
            format!("{recv}[{idx}] = {val}")
        }
        "opt_aset_with" => {
            let val: String = pop(stack);
            let recv: String = assignment_receiver(pop(stack));
            format!("{recv}[{}] = {val}", operand_value(assign, 0))
        }
        _ => {
            let Some(YarvOperand::Call { method, .. }) = assign.operands.first() else {
                return None;
            };
            let val: String = pop(stack);
            let recv: String = pop(stack);
            let attribute: &str = method.strip_suffix('=')?;
            if recv == "self" {
                format!("self.{attribute} = {val}")
            } else {
                format!("{}.{attribute} = {val}", assignment_receiver(recv))
            }
        }
    };
    let slot: &mut String = stack.last_mut()?;
    *slot = format!("({expr})");
    Some(i + 3)
}

fn try_parallel_assign(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let n: usize = if body.instructions[i].mnemonic == "swap" {
        2
    } else {
        operand_count(&body.instructions[i], 0)
    };
    if n < 2 || n > stack.len() || i + n >= hi {
        return None;
    }
    let targets: Vec<String> = (1..=n)
        .map(|k: usize| assignment_target(&body.instructions[i + k], &body.local_table, ctx))
        .collect::<Option<Vec<String>>>()?;
    let values: Vec<String> = pop_n(stack, n);
    emit_stmt(
        stmts,
        depth,
        format!("{} = {}", targets.join(", "), values.join(", ")),
    );
    Some(i + n + 1)
}

fn massign_targets(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    i: usize,
    hi: usize,
    nesting: u32,
) -> Option<(Vec<String>, usize)> {
    if nesting > MAX_NEST_DEPTH {
        return None;
    }
    let flags: u64 = operand_num(&body.instructions[i], 1);
    if flags & !1 != 0 {
        return None;
    }
    let n: usize = operand_count(&body.instructions[i], 0);
    let has_splat: bool = flags & 1 == 1;
    let total: usize = n
        .saturating_add(usize::from(has_splat))
        .min(MAX_OPERAND_COUNT);
    if total == 0 {
        return None;
    }
    let mut targets: Vec<String> = Vec::with_capacity(total);
    let mut total: usize = total;
    let mut j: usize = i + 1;
    while targets.len() < total && j < hi {
        if has_splat
            && targets.len() == n
            && body.instructions[j].mnemonic == "expandarray"
            && operand_num(&body.instructions[j], 1) == 3
        {
            let post: usize = operand_count(&body.instructions[j], 0).min(MAX_OPERAND_COUNT);
            let splat: String =
                assignment_target(body.instructions.get(j + 1)?, &body.local_table, ctx)?;
            targets.push(format!("*{splat}"));
            j += 2;
            for _ in 0..post {
                targets.push(assignment_target(
                    body.instructions.get(j)?,
                    &body.local_table,
                    ctx,
                )?);
                j += 1;
            }
            total += post;
            continue;
        }
        let target: String = if body.instructions[j].mnemonic == "expandarray" {
            let (inner, next): (Vec<String>, usize) =
                massign_targets(body, ctx, j, hi, nesting + 1)?;
            j = next;
            format!("({})", inner.join(", "))
        } else {
            let single: String = assignment_target(&body.instructions[j], &body.local_table, ctx)?;
            j += 1;
            single
        };
        if has_splat && targets.len() == n {
            targets.push(format!("*{target}"));
        } else {
            targets.push(target);
        }
    }
    (targets.len() == total).then_some((targets, j))
}

fn assignment_target(
    set_instr: &YarvIbfInstruction,
    local_table: &[Option<String>],
    ctx: &DecompileContext<'_>,
) -> Option<String> {
    match set_instr.mnemonic.as_str() {
        "setlocal" | "setlocal_WC_0" | "setlocal_WC_1" => {
            let level: u32 = local_access_level(set_instr);
            Some(ctx.local_at_level(local_table, level, operand_num(set_instr, 0)))
        }
        "setinstancevariable" => Some(ivar_name(set_instr, 0)),
        "setclassvariable" => Some(cvar_name(set_instr, 0)),
        "setglobal" => Some(id_or_index(set_instr, 0)),
        _ => None,
    }
}

const T_ARRAY: u64 = 7;
const T_HASH: u64 = 8;

fn body_has_pattern_construct(body: &YarvIseqBody) -> bool {
    body.instructions.iter().any(|instr| {
        instr.mnemonic == "checkmatch"
            || (instr.mnemonic == "checktype" && matches!(operand_num(instr, 0), T_ARRAY | T_HASH))
    })
}

struct CaseInArm {
    pattern: String,
    guard: Option<String>,
    body_lo: usize,
    body_hi: usize,
}

#[derive(Clone, Copy)]
struct ArmBody {
    target: usize,
    body_lo: usize,
    body_hi: usize,
}

#[allow(clippy::too_many_arguments)]
fn try_pattern_match(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let region: CaseInRegion = find_case_in_region(body, i, hi, targets)?;
    let first_dup: usize = find_case_in_subject(body, i, region.terminal_lo)?;
    let subject_idx: usize = first_dup - 1;
    let subject: String = pattern_subject_text(body, ctx, i, first_dup);

    let bodies: Vec<ArmBody> =
        collect_arm_bodies(body, subject_idx, region.body_floor, hi, targets);
    if bodies.is_empty() {
        return None;
    }

    let else_body: Option<(usize, usize)> = region.else_body;

    let mut arms: Vec<CaseInArm> = Vec::with_capacity(bodies.len());
    let mut test_lo: usize = subject_idx + 1;
    for arm_body in &bodies {
        let success: usize = find_success_branch(body, test_lo, arm_body.target, targets)?;
        let (pattern, guard): (String, Option<String>) =
            parse_case_in_arm(body, ctx, depth, test_lo, success, targets);
        arms.push(CaseInArm {
            pattern,
            guard,
            body_lo: arm_body.body_lo,
            body_hi: arm_body.body_hi,
        });
        test_lo = skip_type_error_tail(body, success + 1, hi);
    }

    let region_end: usize = case_in_region_end(&bodies, else_body, hi);

    let pad: String = indent(depth);
    let mut lines: Vec<String> = Vec::with_capacity(arms.len() * 2 + 2);
    lines.push(format!("{pad}case {subject}"));
    for arm in &arms {
        if !is_valid_pattern(&arm.pattern) {
            return None;
        }
        let header: String = arm.guard.as_ref().map_or_else(
            || format!("{pad}in {}", arm.pattern),
            |guard| format!("{pad}in {} if {guard}", arm.pattern),
        );
        lines.push(header);
        lines.extend(render_slice(
            body,
            ctx,
            depth + 1,
            arm.body_lo,
            arm.body_hi,
            targets,
        ));
    }
    if let Some((lo, ehi)) = else_body {
        let else_lines: Vec<String> = render_slice(body, ctx, depth + 1, lo, ehi, targets);
        if else_lines.iter().any(|l| !l.trim().is_empty()) {
            lines.push(format!("{pad}else"));
            lines.extend(else_lines);
        }
    }
    lines.push(format!("{pad}end"));

    if lines.iter().any(|l| line_has_leak(l)) {
        return None;
    }
    stmts.extend(lines);
    Some(region_end)
}

fn is_valid_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && pattern != "_"
        && !line_has_leak(pattern)
        && !pattern.contains(">=")
        && !pattern.contains("<=")
        && !pattern.contains("&&")
        && !pattern.contains("{ |")
}

fn line_has_leak(line: &str) -> bool {
    line.contains("core#")
        || line.contains("obj[")
        || line.contains("iseq[")
        || line.contains("respond_to?(:deconstruct")
        || line.contains(".length >=")
        || line.contains("must return")
        || line.trim_start().starts_with("_.")
}

struct CaseInRegion {
    terminal_lo: usize,
    body_floor: usize,
    else_body: Option<(usize, usize)>,
}

fn find_case_in_region(
    body: &YarvIseqBody,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> Option<CaseInRegion> {
    let has_checkmatch: bool = (i..hi).any(|k| body.instructions[k].mnemonic == "checkmatch");
    let has_deconstruct: bool = (i..hi).any(|k| {
        body.instructions[k].mnemonic == "checktype"
            && matches!(operand_num(&body.instructions[k], 0), T_ARRAY | T_HASH)
    });
    if !has_checkmatch && !has_deconstruct {
        return None;
    }

    if let Some(start) = (i..hi).find(|&k| is_no_match_epilogue_head(body, k)) {
        let raise_idx: usize = (start..hi)
            .find(|&k| is_named_raise_call(&body.instructions[k]))
            .unwrap_or(start);
        let body_floor: usize = (raise_idx..hi)
            .find(|&k| body.instructions[k].mnemonic == "adjuststack")
            .map_or(raise_idx, |adj| adj + 1);
        return Some(CaseInRegion {
            terminal_lo: start,
            body_floor,
            else_body: None,
        });
    }

    let first_cluster: usize = first_arm_body_cluster(body, i, hi, targets)?;
    let else_hi: usize = first_cluster.checked_sub(1).filter(|&leave| {
        body.instructions
            .get(leave)
            .is_some_and(|x| x.mnemonic == "leave")
    })?;
    let else_open: usize = (i..else_hi)
        .rev()
        .find(|&k| {
            matches!(
                body.instructions[k].mnemonic.as_str(),
                "leave" | "jump" | "adjuststack"
            ) || is_named_raise_call(&body.instructions[k])
        })
        .map_or(i, |edge| edge + 1);
    let last_failure: Option<usize> = (i..else_hi)
        .filter(|&k| body.instructions[k].mnemonic == "jump")
        .filter_map(|k| targets.get(k).copied().flatten())
        .filter(|&t| t > i && t < else_hi)
        .max();
    let else_open: usize = last_failure.map_or(else_open, |t| t.max(else_open));
    let else_lo: usize = skip_pattern_body_prologue(body, else_open);
    if else_lo >= else_hi || else_lo <= i {
        return None;
    }
    if (else_lo..else_hi).any(|j| is_named_raise_call(&body.instructions[j])) {
        return None;
    }
    Some(CaseInRegion {
        terminal_lo: else_open,
        body_floor: first_cluster,
        else_body: Some((else_lo, else_hi)),
    })
}

fn first_arm_body_cluster(
    body: &YarvIseqBody,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> Option<usize> {
    (i + 1..hi)
        .filter(|&idx| {
            matches!(
                body.instructions[idx].mnemonic.as_str(),
                "jump" | "branchif" | "branchnil"
            )
        })
        .filter_map(|idx| targets.get(idx).copied().flatten())
        .filter(|&t| {
            t > i
                && t < hi
                && body.instructions[t].mnemonic == "adjuststack"
                && body
                    .instructions
                    .get(skip_pattern_body_prologue(body, t))
                    .is_some_and(|x| x.mnemonic != "jump")
        })
        .min()
}

fn is_no_match_epilogue_head(body: &YarvIseqBody, k: usize) -> bool {
    body.instructions[k].mnemonic == "putspecialobject"
        && body
            .instructions
            .get(k + 1)
            .is_some_and(|x| x.mnemonic == "topn")
        && body
            .instructions
            .get(k + 2)
            .is_some_and(|x| x.mnemonic == "branchif")
        && (k + 3..(k + 12).min(body.instructions.len())).any(|j| {
            matches!(
                body.instructions[j].operands.first(),
                Some(YarvOperand::StrLiteral(s)) if s == "%p: %s"
            )
        })
}

fn is_named_raise_call(instr: &YarvIbfInstruction) -> bool {
    matches!(
        instr.operands.first(),
        Some(YarvOperand::Call { method, .. }) if method == "core#raise"
    )
}

fn find_case_in_subject(body: &YarvIseqBody, i: usize, terminal_lo: usize) -> Option<usize> {
    let first_dup: usize = (i..terminal_lo).find(|&k| body.instructions[k].mnemonic == "dup")?;
    if first_dup == 0 {
        return None;
    }
    Some(first_dup)
}

fn collect_arm_bodies(
    body: &YarvIseqBody,
    subject_idx: usize,
    epilogue_end: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> Vec<ArmBody> {
    let mut found: Vec<usize> = Vec::new();
    for idx in subject_idx + 1..hi {
        if !matches!(
            body.instructions[idx].mnemonic.as_str(),
            "jump" | "branchif" | "branchnil"
        ) {
            continue;
        }
        let Some(t): Option<usize> = targets.get(idx).copied().flatten() else {
            continue;
        };
        if t >= epilogue_end && t < hi && body.instructions[t].mnemonic == "adjuststack" && t > idx
        {
            found.push(t);
        }
    }
    found.sort_unstable();
    found.dedup();

    found
        .into_iter()
        .filter_map(|target| {
            let body_lo: usize = skip_pattern_body_prologue(body, target);
            if body
                .instructions
                .get(body_lo)
                .is_some_and(|x| x.mnemonic == "jump")
            {
                return None;
            }
            let body_hi: usize = (body_lo..hi)
                .find(|&x| body.instructions[x].mnemonic == "leave")
                .unwrap_or(hi);
            Some(ArmBody {
                target,
                body_lo,
                body_hi,
            })
        })
        .collect()
}

fn find_success_branch(
    body: &YarvIseqBody,
    test_lo: usize,
    target: usize,
    targets: &[Option<usize>],
) -> Option<usize> {
    (test_lo..target).rev().find(|&j| {
        matches!(
            body.instructions[j].mnemonic.as_str(),
            "jump" | "branchif" | "branchnil"
        ) && targets.get(j).copied().flatten() == Some(target)
    })
}

fn skip_type_error_tail(body: &YarvIseqBody, lo: usize, hi: usize) -> usize {
    if body.instructions.get(lo).map(|x| x.mnemonic.as_str()) != Some("putspecialobject") {
        return lo;
    }
    let Some(raise): Option<usize> = (lo..hi)
        .take(5)
        .find(|&k| is_named_raise_call(&body.instructions[k]))
    else {
        return lo;
    };
    let mut end: usize = raise + 1;
    while end < hi && body.instructions[end].mnemonic == "pop" {
        end += 1;
    }
    end
}

fn case_in_region_end(bodies: &[ArmBody], else_body: Option<(usize, usize)>, hi: usize) -> usize {
    let mut end: usize = bodies.iter().map(|b| b.body_hi).max().unwrap_or(hi);
    if let Some((_, ehi)) = else_body {
        end = end.max(ehi);
    }
    (end + 1).min(hi)
}

fn parse_case_in_arm(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    test_lo: usize,
    success: usize,
    targets: &[Option<usize>],
) -> (String, Option<String>) {
    let (bind, capture_at): (Option<String>, Option<usize>) =
        top_level_capture(body, test_lo, success);
    let guard_lo: usize =
        capture_at.map_or_else(|| guard_region_anchor(body, test_lo, success), |c| c + 1);
    let guard: Option<String> = if body.instructions[success].mnemonic == "branchif"
        && guard_lo < success
        && (guard_lo..success).any(|j| is_guard_value_opcode(&body.instructions[j]))
    {
        parse_guard_expr(body, ctx, guard_lo, success)
    } else {
        None
    };
    let pattern_end: usize = capture_at.map_or_else(
        || {
            if guard.is_some() {
                guard_region_anchor(body, test_lo, success)
            } else {
                success
            }
        },
        |c| capture_value_start(body, c),
    );
    let arm_target: Option<usize> = targets.get(success).copied().flatten();
    let pattern: String =
        split_structural_alternatives(body, ctx, depth, test_lo, pattern_end, targets, arm_target)
            .or_else(|| parse_pattern(body, ctx, depth, test_lo, pattern_end))
            .unwrap_or_else(|| "_".to_owned());
    let pattern_bound: String = match bind {
        Some(b) if is_identifier(&b) => format!("{pattern} => {b}"),
        _ => pattern,
    };
    (pattern_bound, guard)
}

fn top_level_capture(
    body: &YarvIseqBody,
    test_lo: usize,
    success: usize,
) -> (Option<String>, Option<usize>) {
    for j in (test_lo..success).rev() {
        if body.instructions[j].mnemonic != "checkmatch" {
            continue;
        }
        if checkmatch_is_nested(body, test_lo, j) {
            return (None, None);
        }
        let mut cursor: usize = j + 1;
        if body
            .instructions
            .get(cursor)
            .is_some_and(|x| matches!(x.mnemonic.as_str(), "branchunless" | "branchif"))
        {
            cursor += 1;
        }
        if let Some(set) = body.instructions.get(cursor)
            && set.mnemonic.starts_with("setlocal")
            && cursor < success
        {
            return (
                Some(local_name(&body.local_table, operand_num(set, 0))),
                Some(cursor),
            );
        }
        return (None, None);
    }
    (None, None)
}

fn checkmatch_is_nested(body: &YarvIseqBody, test_lo: usize, checkmatch: usize) -> bool {
    let lo: usize = checkmatch.saturating_sub(4).max(test_lo);
    (lo..checkmatch).any(|j| {
        body.instructions[j].mnemonic == "opt_aref"
            || matches!(
                body.instructions[j].operands.first(),
                Some(YarvOperand::Call { method, .. }) if method == "[]"
            )
    })
}

fn capture_value_start(body: &YarvIseqBody, capture_at: usize) -> usize {
    (0..capture_at)
        .rev()
        .find(|&j| body.instructions[j].mnemonic == "checkmatch")
        .map_or(capture_at, |cm| cm + 1)
}

fn guard_region_anchor(body: &YarvIseqBody, test_lo: usize, success: usize) -> usize {
    (test_lo..success)
        .rev()
        .find(|&j| {
            matches!(
                body.instructions[j].mnemonic.as_str(),
                "checkmatch" | "setlocal" | "setlocal_WC_0" | "setlocal_WC_1"
            )
        })
        .map_or(success, |j| j + 1)
}

fn is_guard_value_opcode(instr: &YarvIbfInstruction) -> bool {
    !matches!(
        instr.mnemonic.as_str(),
        "jump"
            | "pop"
            | "dup"
            | "branchunless"
            | "branchif"
            | "branchnil"
            | "putnil"
            | "adjuststack"
            | "setn"
            | "topn"
            | "swap"
    )
}

fn parse_guard_expr(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    lo: usize,
    success: usize,
) -> Option<String> {
    let expr: String = pattern_value_region(body, ctx, lo, success);
    let trimmed: String = expr.trim().to_owned();
    if trimmed.is_empty() || trimmed == "nil" || trimmed == "_" {
        return None;
    }
    if !trimmed.contains(|c: char| !c.is_alphanumeric() && c != '_') {
        return None;
    }
    Some(trimmed)
}

fn parse_pattern(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
) -> Option<String> {
    if let Some(alt) = split_alternatives(body, ctx, depth, lo, hi) {
        return Some(alt);
    }
    single_pattern(body, ctx, depth, lo, hi)
}

fn split_alternatives(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
) -> Option<String> {
    let mut alts: Vec<String> = Vec::new();
    let mut seg_lo: usize = lo;
    let mut j: usize = lo;
    while j < hi {
        let is_alt_boundary: bool = body.instructions[j].mnemonic == "checkmatch"
            && body
                .instructions
                .get(j + 1)
                .is_some_and(|x| matches!(x.mnemonic.as_str(), "branchunless" | "branchif"))
            && !segment_is_structural(body, seg_lo, j);
        if is_alt_boundary {
            if let Some(p) = single_pattern(body, ctx, depth, seg_lo, j + 1) {
                alts.push(p);
            }
            seg_lo = skip_alt_separator(body, j + 2);
            j = seg_lo;
            continue;
        }
        j += 1;
    }
    if alts.len() < 2 {
        return None;
    }
    if seg_lo < hi
        && let Some(p) = single_pattern(body, ctx, depth, seg_lo, hi)
        && !alts.contains(&p)
    {
        alts.push(p);
    }
    Some(alts.join(" | "))
}

fn split_structural_alternatives(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
    targets: &[Option<usize>],
    arm_target: Option<usize>,
) -> Option<String> {
    let arm_target: usize = arm_target?;
    let ends: Vec<usize> = (lo + 1..hi)
        .filter(|&j| {
            body.instructions[j].mnemonic == "jump"
                && body.instructions[j - 1].mnemonic == "pop"
                && targets.get(j).copied().flatten() == Some(arm_target)
        })
        .collect();
    if ends.is_empty() || !(lo..hi).any(|j| body.instructions[j].mnemonic == "checktype") {
        return None;
    }
    let mut alts: Vec<String> = Vec::with_capacity(ends.len() + 1);
    let mut seg_lo: usize = lo;
    for end in ends {
        alts.push(parse_pattern(body, ctx, depth, seg_lo, end - 1)?);
        seg_lo = end + 1;
    }
    alts.push(parse_pattern(body, ctx, depth, seg_lo, hi)?);
    Some(alts.join(" | "))
}

fn segment_is_structural(body: &YarvIseqBody, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|j| body.instructions[j].mnemonic == "checktype")
}

fn skip_alt_separator(body: &YarvIseqBody, after_branch: usize) -> usize {
    let mut j: usize = after_branch;
    while body
        .instructions
        .get(j)
        .is_some_and(|x| matches!(x.mnemonic.as_str(), "pop" | "jump" | "dup"))
    {
        j += 1;
    }
    j
}

fn single_pattern(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
) -> Option<String> {
    if let Some(checktype_idx) = find_checktype(body, lo, hi, T_ARRAY) {
        return Some(parse_array_or_find(body, ctx, checktype_idx + 1, hi));
    }
    if let Some(checktype_idx) = find_checktype(body, lo, hi, T_HASH) {
        let const_prefix: Option<String> = deconstruct_const_prefix(body, ctx, lo, checktype_idx);
        return Some(parse_hash(
            body,
            ctx,
            checktype_idx + 1,
            hi,
            const_prefix.as_deref(),
        ));
    }
    if let Some(lambda) = parse_lambda_pattern(body, ctx, depth, lo, hi) {
        return Some(lambda);
    }
    parse_value_or_class(body, ctx, lo, hi)
}

fn parse_lambda_pattern(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
) -> Option<String> {
    let send: usize = (lo..hi).find(|&j| {
        matches!(
            body.instructions[j].mnemonic.as_str(),
            "send" | "opt_send_without_block"
        ) && call_method_is(&body.instructions[j], "lambda")
    })?;
    let block: &YarvIseqBody = match body.instructions[send].operands.get(1) {
        Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index)?,
        _ => return None,
    };
    let params: Vec<&str> = block
        .local_table
        .iter()
        .take(block.param_lead_num as usize)
        .filter_map(Option::as_deref)
        .collect();
    let inner: Vec<String> = render_iseq_statements(block, ctx, depth.saturating_add(1));
    let body_line: String = inner
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_owned();
    if body_line.is_empty() || line_has_leak(&body_line) {
        return None;
    }
    let param_list: String = if params.is_empty() {
        String::new()
    } else {
        format!("({})", params.join(", "))
    };
    Some(format!("->{param_list} {{ {body_line} }}"))
}

fn find_checktype(body: &YarvIseqBody, lo: usize, hi: usize, kind: u64) -> Option<usize> {
    (lo..hi).find(|&j| {
        body.instructions[j].mnemonic == "checktype"
            && operand_num(&body.instructions[j], 0) == kind
    })
}

fn deconstruct_const_prefix(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    lo: usize,
    checktype_idx: usize,
) -> Option<String> {
    let checkmatch: usize = (lo..checktype_idx).find(|&j| {
        body.instructions[j].mnemonic == "checkmatch"
            && body
                .instructions
                .get(j + 1)
                .is_some_and(|x| x.mnemonic == "branchunless")
    })?;
    let value: String = pattern_value_region(body, ctx, lo, checkmatch);
    let trimmed: &str = value.trim();
    if trimmed.is_empty() || trimmed == "_" {
        return None;
    }
    Some(trimmed.to_owned())
}

fn parse_value_or_class(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    lo: usize,
    hi: usize,
) -> Option<String> {
    let checkmatch: usize = (lo..hi)
        .find(|&j| body.instructions[j].mnemonic == "checkmatch")
        .unwrap_or(hi);
    if checkmatch > lo
        && body.instructions[checkmatch - 1].mnemonic == "putnil"
        && (lo..checkmatch - 1).all(|j| body.instructions[j].mnemonic == "dup")
    {
        return Some("nil".to_owned());
    }
    let value: String = pattern_value_region(body, ctx, lo, checkmatch);
    let trimmed: &str = value.trim();
    if trimmed.is_empty() || trimmed == "_" {
        return None;
    }
    let ops: Vec<&str> = (lo..checkmatch)
        .map(|j| body.instructions[j].mnemonic.as_str())
        .filter(|m: &&str| *m != "dup")
        .collect();
    let pinned: String = match ops.as_slice() {
        [single]
            if single.starts_with("getlocal")
                || matches!(
                    *single,
                    "getinstancevariable" | "getglobal" | "getclassvariable"
                ) =>
        {
            format!("^{trimmed}")
        }
        _ if ops.iter().all(|m: &&str| is_literal_pattern_op(m)) => trimmed.to_owned(),
        _ => format!("^({trimmed})"),
    };
    Some(pinned)
}

fn is_literal_pattern_op(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "putobject"
            | "putobject_INT2FIX_0_"
            | "putobject_INT2FIX_1_"
            | "putstring"
            | "putchilledstring"
            | "putnil"
            | "opt_getconstant_path"
            | "getconstant"
            | "newrange"
            | "toregexp"
            | "once"
    )
}

fn parse_array_or_find(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    from: usize,
    hi: usize,
) -> String {
    if is_find_pattern(body, from, hi) {
        return parse_find(body, from, hi);
    }
    let is_splat: bool = (from..hi)
        .take(6)
        .find(|&j| matches!(body.instructions[j].mnemonic.as_str(), "opt_eq" | "opt_ge"))
        .is_some_and(|j| body.instructions[j].mnemonic == "opt_ge");
    let mut pre: Vec<String> = Vec::new();
    let mut post: Vec<String> = Vec::new();
    let mut splat: Option<String> = None;
    let mut j: usize = from;
    while j < hi {
        if body.instructions[j].mnemonic == "jump" {
            break;
        }
        if let Some((bind, next)) = read_element_bind(body, j)
            .or_else(|| read_element_value(body, ctx, j, hi))
            .or_else(|| read_element_nested(body, ctx, j, hi))
        {
            if splat.is_some() {
                post.push(bind);
            } else {
                pre.push(bind);
            }
            j = next;
            continue;
        }
        if is_splat
            && splat.is_none()
            && let Some((name, next)) = read_splat_bind(body, j, hi)
        {
            splat = Some(name);
            j = next;
            continue;
        }
        j += 1;
    }
    if pre.is_empty() && post.is_empty() && splat.is_none() && !is_splat {
        return "[]".to_owned();
    }
    let mut elements: Vec<String> = pre;
    if let Some(rest) = splat {
        elements.push(format!("*{rest}"));
    } else if is_splat {
        elements.push("*".to_owned());
    }
    elements.extend(post);
    format!("[{}]", elements.join(", "))
}

fn read_element_nested(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    j: usize,
    hi: usize,
) -> Option<(String, usize)> {
    if !is_array_index_literal(&body.instructions[j])
        || body.instructions.get(j + 1).map(|x| x.mnemonic.as_str()) != Some("opt_aref")
    {
        return None;
    }
    read_nested_subpattern(body, ctx, j + 2, hi)
}

fn read_nested_subpattern(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    lo: usize,
    hi: usize,
) -> Option<(String, usize)> {
    if body.instructions.get(lo).map(|x| x.mnemonic.as_str()) != Some("dup") {
        return None;
    }
    let checktype: usize = (lo..hi)
        .take(16)
        .find(|&k| body.instructions[k].mnemonic == "checktype")?;
    if body.instructions.get(checktype + 1)?.mnemonic != "branchunless" {
        return None;
    }
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    let tail: usize = targets.get(checktype + 1).copied().flatten()?;
    if tail <= checktype + 2
        || tail > hi
        || body.instructions[tail].mnemonic != "putspecialobject"
        || body.instructions[tail - 1].mnemonic != "jump"
    {
        return None;
    }
    let next: usize = targets.get(tail - 1).copied().flatten()?;
    if next <= tail {
        return None;
    }
    let kind: u64 = operand_num(&body.instructions[checktype], 0);
    let pattern: String = if kind == T_ARRAY {
        parse_array_or_find(body, ctx, checktype + 1, tail - 1)
    } else if kind == T_HASH {
        let const_prefix: Option<String> = deconstruct_const_prefix(body, ctx, lo, checktype);
        parse_hash(body, ctx, checktype + 1, tail - 1, const_prefix.as_deref())
    } else {
        return None;
    };
    Some((pattern, next))
}

fn read_element_value(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    j: usize,
    hi: usize,
) -> Option<(String, usize)> {
    if !is_array_index_literal(&body.instructions[j])
        || body.instructions.get(j + 1).map(|x| x.mnemonic.as_str()) != Some("opt_aref")
    {
        return None;
    }
    let bound: bool = body.instructions.get(j + 2)?.mnemonic == "dup";
    let value_lo: usize = if bound { j + 3 } else { j + 2 };
    let checkmatch: usize = (value_lo..hi)
        .take(8)
        .find(|&k| body.instructions[k].mnemonic == "checkmatch")?;
    if (value_lo..checkmatch).any(|k| {
        matches!(
            body.instructions[k].mnemonic.as_str(),
            "dup" | "checktype" | "branchif" | "branchunless" | "branchnil" | "jump" | "topn"
        ) || body.instructions[k].mnemonic.starts_with("setlocal")
    }) || body.instructions.get(checkmatch + 1)?.mnemonic != "branchunless"
    {
        return None;
    }
    let value: String = parse_value_or_class(body, ctx, value_lo, checkmatch + 1)?;
    if !bound {
        return Some((value, checkmatch + 2));
    }
    let set: &YarvIbfInstruction = body.instructions.get(checkmatch + 2)?;
    let tail: [&str; 3] = ["jump", "pop", "jump"];
    if !set.mnemonic.starts_with("setlocal")
        || (0..3).any(|n| {
            body.instructions
                .get(checkmatch + 3 + n)
                .map(|x| x.mnemonic.as_str())
                != Some(tail[n])
        })
    {
        return None;
    }
    let name: String = local_name(&body.local_table, operand_num(set, 0));
    Some((format!("{value} => {name}"), checkmatch + 6))
}

fn read_element_bind(body: &YarvIseqBody, j: usize) -> Option<(String, usize)> {
    if !is_array_index_literal(&body.instructions[j]) {
        return None;
    }
    if body.instructions.get(j + 1).map(|x| x.mnemonic.as_str()) != Some("opt_aref") {
        return None;
    }
    let set: &YarvIbfInstruction = body.instructions.get(j + 2)?;
    if !set.mnemonic.starts_with("setlocal") {
        return None;
    }
    let name: String = local_name(&body.local_table, operand_num(set, 0));
    Some((name, j + 3))
}

fn read_splat_bind(body: &YarvIseqBody, j: usize, hi: usize) -> Option<(String, usize)> {
    if body.instructions[j].mnemonic != "dup" {
        return None;
    }
    if !is_array_index_literal(body.instructions.get(j + 1)?) {
        return None;
    }
    if body.instructions.get(j + 2).map(|x| x.mnemonic.as_str()) != Some("topn") {
        return None;
    }
    let slice_call: usize = (j + 3..hi).take(10).find(|&k| {
        matches!(
            body.instructions[k].operands.first(),
            Some(YarvOperand::Call { method, argc, .. }) if method == "[]" && *argc == 2
        )
    })?;
    let set: &YarvIbfInstruction = body.instructions.get(slice_call + 1)?;
    if !set.mnemonic.starts_with("setlocal") {
        return None;
    }
    let name: String = local_name(&body.local_table, operand_num(set, 0));
    Some((name, slice_call + 2))
}

fn is_array_index_literal(instr: &YarvIbfInstruction) -> bool {
    matches!(
        instr.mnemonic.as_str(),
        "putobject_INT2FIX_0_" | "putobject_INT2FIX_1_"
    ) || (instr.mnemonic == "putobject"
        && matches!(
            instr.operands.first(),
            Some(YarvOperand::NumLiteral(_) | YarvOperand::Num(_))
        ))
}

fn is_find_pattern(body: &YarvIseqBody, from: usize, hi: usize) -> bool {
    (from..hi)
        .take(48)
        .any(|j| body.instructions[j].mnemonic == "opt_le")
        && (from..hi)
            .take(48)
            .any(|k| body.instructions[k].mnemonic == "checkmatch")
}

fn parse_find(body: &YarvIseqBody, from: usize, hi: usize) -> String {
    let mut mids: Vec<String> = Vec::new();
    if let Some(cm) = (from..hi).find(|&j| body.instructions[j].mnemonic == "checkmatch") {
        let val_lo: usize = (from..cm)
            .rev()
            .find(|&j| body.instructions[j].mnemonic == "opt_aref")
            .map_or(from, |aref| aref + 1);
        if let Some(v) = literal_value_in(body, val_lo, cm) {
            mids.push(v);
        }
    }
    for j in from..hi {
        if let Some((bind, _)) = read_element_bind(body, j) {
            mids.push(bind);
        }
    }
    if mids.is_empty() {
        return "[*, *]".to_owned();
    }
    format!("[*, {}, *]", mids.join(", "))
}

fn literal_value_in(body: &YarvIseqBody, lo: usize, hi: usize) -> Option<String> {
    (lo..hi)
        .rev()
        .find(|&j| {
            matches!(
                body.instructions[j].mnemonic.as_str(),
                "putobject" | "putobject_INT2FIX_0_" | "putobject_INT2FIX_1_"
            )
        })
        .map(|j| match body.instructions[j].mnemonic.as_str() {
            "putobject_INT2FIX_0_" => "0".to_owned(),
            "putobject_INT2FIX_1_" => "1".to_owned(),
            _ => operand_value(&body.instructions[j], 0),
        })
}

fn parse_hash(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    from: usize,
    hi: usize,
    const_prefix: Option<&str>,
) -> String {
    let mut pairs: Vec<String> = Vec::new();
    let mut kwrest: Option<String> = None;
    let mut saw_empty_check: bool = false;
    let mut j: usize = from;
    while j < hi {
        if body.instructions[j].mnemonic == "opt_empty_p" {
            saw_empty_check = true;
        }
        if let Some(key) = hash_key_literal(&body.instructions[j]) {
            let next: &str = body
                .instructions
                .get(j + 1)
                .map_or("", |x| x.mnemonic.as_str());
            let is_keycheck: bool = next == "opt_send_without_block"
                && call_method_is(&body.instructions[j + 1], "key?");
            if is_keycheck {
                j += 2;
                continue;
            }
            let is_fetch: bool = next == "opt_aref"
                || (next == "opt_send_without_block"
                    && (call_method_is(&body.instructions[j + 1], "delete")
                        || call_method_is(&body.instructions[j + 1], "fetch")));
            if is_fetch {
                let (pair, consumed): (String, usize) =
                    read_hash_value_pattern(body, ctx, &key, j + 2, hi);
                pairs.push(pair);
                j = consumed;
                continue;
            }
        }
        if body.instructions[j].mnemonic == "dup"
            && body
                .instructions
                .get(j + 1)
                .is_some_and(|x| x.mnemonic.starts_with("setlocal"))
        {
            kwrest = Some(local_name(
                &body.local_table,
                operand_num(&body.instructions[j + 1], 0),
            ));
            j += 2;
            continue;
        }
        j += 1;
    }
    if let Some(rest) = kwrest {
        pairs.push(format!("**{rest}"));
    }
    if pairs.is_empty() && saw_empty_check {
        return const_prefix.map_or_else(|| "{}".to_owned(), |prefix| format!("{prefix}({{}})"));
    }
    let inner: String = pairs.join(", ");
    const_prefix.map_or_else(
        || format!("{{{inner}}}"),
        |prefix| format!("{prefix}({inner})"),
    )
}

fn read_hash_value_pattern(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    key: &str,
    after_aref: usize,
    hi: usize,
) -> (String, usize) {
    if let Some((pattern, next)) = read_nested_subpattern(body, ctx, after_aref, hi) {
        return (format!("{key}: {pattern}"), next);
    }
    if let Some(set) = body.instructions.get(after_aref)
        && set.mnemonic.starts_with("setlocal")
    {
        let var: String = local_name(&body.local_table, operand_num(set, 0));
        return (render_hash_pair(key, Some(&var)), after_aref + 1);
    }
    let val_lo: usize = if body
        .instructions
        .get(after_aref)
        .is_some_and(|x| x.mnemonic == "dup")
    {
        after_aref + 1
    } else {
        after_aref
    };
    if let Some(literal) = body.instructions.get(val_lo)
        && body
            .instructions
            .get(val_lo + 1)
            .is_some_and(|x| x.mnemonic == "checkmatch")
    {
        let value: String = match literal.mnemonic.as_str() {
            "putobject" | "putstring" | "putchilledstring" => operand_value(literal, 0),
            "putobject_INT2FIX_0_" => "0".to_owned(),
            "putobject_INT2FIX_1_" => "1".to_owned(),
            "putnil" => "nil".to_owned(),
            _ => String::new(),
        };
        if !value.is_empty() {
            return (format!("{key}: {value}"), val_lo + 2);
        }
    }
    if body
        .instructions
        .get(val_lo)
        .is_some_and(|x| x.mnemonic == "opt_getconstant_path")
        && body
            .instructions
            .get(val_lo + 1)
            .is_some_and(|x| x.mnemonic == "checkmatch")
    {
        let class: String = constant_path_value(&body.instructions[val_lo], ctx);
        let mut cursor: usize = val_lo + 2;
        if body
            .instructions
            .get(cursor)
            .is_some_and(|x| x.mnemonic == "branchunless")
        {
            cursor += 1;
        }
        if let Some(set) = body.instructions.get(cursor)
            && set.mnemonic.starts_with("setlocal")
        {
            let var: String = local_name(&body.local_table, operand_num(set, 0));
            return (format!("{key}: {class} => {var}"), cursor + 1);
        }
        return (format!("{key}: {class}"), cursor);
    }
    (render_hash_pair(key, None), after_aref + 1)
}

fn render_hash_pair(key: &str, bind: Option<&str>) -> String {
    match bind {
        Some(var) if var == key => format!("{key}:"),
        Some(var) => format!("{key}: {var}"),
        None => format!("{key}:"),
    }
}

fn hash_key_literal(instr: &YarvIbfInstruction) -> Option<String> {
    if instr.mnemonic != "putobject" {
        return None;
    }
    match instr.operands.first() {
        Some(YarvOperand::SymLiteral(s) | YarvOperand::Id(s) | YarvOperand::Literal(s))
            if is_identifier(s) =>
        {
            Some(s.clone())
        }
        _ => None,
    }
}

fn call_method_is(instr: &YarvIbfInstruction, name: &str) -> bool {
    matches!(
        instr.operands.first(),
        Some(YarvOperand::Call { method, .. }) if method == name
    )
}

fn pattern_subject_text(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    region_lo: usize,
    first_dup: usize,
) -> String {
    let subject_lo: usize = subject_expr_start(body, region_lo, first_dup);
    let text: String = pattern_value_region(body, ctx, subject_lo, first_dup);
    if text.is_empty() {
        "subject".to_owned()
    } else {
        text
    }
}

fn subject_expr_start(body: &YarvIseqBody, region_lo: usize, first_dup: usize) -> usize {
    (region_lo..first_dup)
        .rev()
        .take_while(|&j| {
            !matches!(
                body.instructions[j].mnemonic.as_str(),
                "putnil" | "setlocal" | "setlocal_WC_0" | "setlocal_WC_1"
            )
        })
        .last()
        .unwrap_or_else(|| first_dup.saturating_sub(1))
}

fn pattern_value_region(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    lo: usize,
    hi: usize,
) -> String {
    let mut stack: Vec<String> = Vec::new();
    let mut sink: Vec<String> = Vec::new();
    for j in lo..hi {
        let m: &str = body.instructions[j].mnemonic.as_str();
        if matches!(
            m,
            "dup" | "pop" | "topn" | "swap" | "checkmatch" | "setn" | "putnil"
        ) {
            continue;
        }
        if matches!(m, "branchunless" | "branchif" | "branchnil" | "jump") {
            continue;
        }
        step(
            &body.instructions[j],
            &body.local_table,
            ctx,
            0,
            &mut stack,
            &mut sink,
        );
    }
    stack.pop().unwrap_or_default()
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn skip_pattern_body_prologue(body: &YarvIseqBody, idx: usize) -> usize {
    let mut j: usize = idx;
    while body
        .instructions
        .get(j)
        .is_some_and(|x| matches!(x.mnemonic.as_str(), "adjuststack" | "pop"))
    {
        j += 1;
    }
    j
}

fn symbol_literal(s: &str) -> String {
    if is_bare_symbol(s) {
        s.to_owned()
    } else {
        ruby_string_literal(s)
    }
}

fn is_bare_symbol(s: &str) -> bool {
    const OPERATOR_SYMBOLS: &[&str] = &[
        "+", "-", "*", "/", "%", "**", "==", "===", "!=", "<", "<=", ">", ">=", "<=>", "<<", ">>",
        "&", "|", "^", "~", "!", "[]", "[]=", "=~", "+@", "-@", "call",
    ];
    if OPERATOR_SYMBOLS.contains(&s) {
        return true;
    }
    let core: &str = s
        .strip_suffix(['?', '!', '='])
        .filter(|rest| !rest.is_empty())
        .unwrap_or(s);
    !core.is_empty()
        && core
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && core.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[allow(clippy::too_many_arguments)]
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
    if clauses.is_empty() {
        return None;
    }

    let else_lo: usize = k;
    let else_hi: usize = first_body.unwrap_or(hi).min(hi);
    if else_lo >= else_hi {
        return None;
    }

    let region_end: usize = match else_hi
        .checked_sub(1)
        .and_then(|last: usize| body.instructions.get(last).map(|x| (last, x)))
    {
        Some((last, x)) if x.mnemonic == "jump" => targets
            .get(last)
            .copied()
            .flatten()
            .filter(|&end: &usize| end > else_hi && end <= hi)
            .unwrap_or(hi),
        _ => hi,
    };
    let mut starts: Vec<usize> = clauses.iter().map(|(_, start)| *start).collect();
    starts.sort_unstable();
    starts.dedup();
    let mut bodies: Vec<(usize, usize)> = Vec::with_capacity(clauses.len());
    for (_, start) in &clauses {
        let body_lo: usize = skip_leading_pop(body, *start);
        let body_hi: usize = starts
            .iter()
            .copied()
            .find(|&next: &usize| next > *start)
            .unwrap_or(region_end)
            .max(body_lo);
        bodies.push((body_lo, body_hi));
    }
    let last_end: usize = region_end;

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
        let else_lines: Vec<String> =
            render_slice(body, ctx, depth + 1, else_body_lo, else_body_hi, targets);
        if else_lines.iter().any(|l| !l.trim().is_empty()) {
            stmts.push(format!("{pad}else"));
            stmts.extend(else_lines);
        }
    }
    stmts.push(format!("{pad}end"));
    Some(last_end.min(hi))
}

#[inline]
fn is_send(m: &str) -> bool {
    m.starts_with("opt_send") || m == "send"
}

fn begins_when_comparison(body: &YarvIseqBody, i: usize, hi: usize) -> bool {
    let topn: Option<usize> = (i..hi)
        .take(8)
        .find(|&j| body.instructions[j].mnemonic == "topn");
    let Some(t): Option<usize> = topn else {
        return false;
    };
    let only_when_values: bool = body.instructions[i..t]
        .iter()
        .all(|x: &YarvIbfInstruction| {
            matches!(
                x.mnemonic.as_str(),
                "putobject"
                    | "putobject_INT2FIX_0_"
                    | "putobject_INT2FIX_1_"
                    | "putnil"
                    | "putstring"
                    | "putchilledstring"
                    | "duparray"
                    | "duphash"
                    | "opt_getconstant_path"
                    | "getconstant"
                    | "getlocal"
                    | "getlocal_WC_0"
                    | "getlocal_WC_1"
                    | "getinstancevariable"
                    | "newrange"
            )
        });
    only_when_values
        && body
            .instructions
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

fn aref_argc(instr: &YarvIbfInstruction) -> Option<usize> {
    match instr.mnemonic.as_str() {
        "opt_aref" => match instr.operands.first() {
            Some(YarvOperand::Call { argc, .. }) => Some(call_arg_count(*argc)),
            _ => Some(1),
        },
        _ => None,
    }
}

fn binop_operator(instr: &YarvIbfInstruction) -> Option<&'static str> {
    match instr.mnemonic.as_str() {
        "opt_plus" => Some("+"),
        "opt_minus" => Some("-"),
        "opt_mult" => Some("*"),
        "opt_div" => Some("/"),
        "opt_mod" => Some("%"),
        "opt_ltlt" => Some("<<"),
        "opt_and" => Some("&"),
        "opt_or" => Some("|"),
        "opt_send_without_block" | "send" => match instr.operands.first() {
            Some(YarvOperand::Call { method, argc, .. }) if *argc == 1 => match method.as_str() {
                "**" => Some("**"),
                ">>" => Some(">>"),
                "^" => Some("^"),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn send_method_argc(instr: &YarvIbfInstruction) -> Option<(String, usize)> {
    if !is_send(instr.mnemonic.as_str()) {
        return None;
    }
    match instr.operands.first() {
        Some(YarvOperand::Call { method, argc, .. }) => {
            Some((method.clone(), call_arg_count(*argc)))
        }
        Some(YarvOperand::Id(name)) => Some((name.clone(), 0)),
        _ => None,
    }
}

fn scalar_read_target(
    instr: &YarvIbfInstruction,
    local_table: &[Option<String>],
    ctx: &DecompileContext<'_>,
) -> Option<(String, ScalarKind)> {
    match instr.mnemonic.as_str() {
        "getlocal" | "getlocal_WC_0" | "getlocal_WC_1" => {
            let level: u32 = local_access_level(instr);
            Some((
                ctx.local_at_level(local_table, level, operand_num(instr, 0)),
                ScalarKind::Local,
            ))
        }
        "getinstancevariable" => Some((ivar_name(instr, 0), ScalarKind::Ivar)),
        "getclassvariable" => Some((cvar_name(instr, 0), ScalarKind::ClassVar)),
        "getglobal" => Some((id_or_index(instr, 0), ScalarKind::Global)),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarKind {
    Local,
    Ivar,
    ClassVar,
    Global,
}

fn scalar_write_matches(
    instr: &YarvIbfInstruction,
    kind: ScalarKind,
    name: &str,
    local_table: &[Option<String>],
    ctx: &DecompileContext<'_>,
) -> bool {
    match (kind, instr.mnemonic.as_str()) {
        (ScalarKind::Local, "setlocal" | "setlocal_WC_0" | "setlocal_WC_1") => {
            let level: u32 = local_access_level(instr);
            ctx.local_at_level(local_table, level, operand_num(instr, 0)) == name
        }
        (ScalarKind::Ivar, "setinstancevariable") => ivar_name(instr, 0) == name,
        (ScalarKind::ClassVar, "setclassvariable") => cvar_name(instr, 0) == name,
        (ScalarKind::Global, "setglobal") => id_or_index(instr, 0) == name,
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn try_scalar_cond_assign(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let read: &YarvIbfInstruction = body.instructions.get(i)?;
    let (name, kind): (String, ScalarKind) = scalar_read_target(read, &body.local_table, ctx)?;
    let branch_idx: usize = i + 1;
    let branch: &YarvIbfInstruction = body.instructions.get(branch_idx)?;
    let op: &str = match branch.mnemonic.as_str() {
        "branchif" => "||=",
        "branchunless" => "&&=",
        _ => return None,
    };
    let skip: usize = targets.get(branch_idx).copied().flatten()?;
    if skip <= branch_idx || skip > hi {
        return None;
    }
    let write_idx: usize = skip.checked_sub(1)?;
    if write_idx <= branch_idx
        || !scalar_write_matches(
            &body.instructions[write_idx],
            kind,
            &name,
            &body.local_table,
            ctx,
        )
    {
        return None;
    }
    let rhs: String = render_value_region(body, ctx, depth, branch_idx + 1, write_idx, targets)?;
    emit_stmt(stmts, depth, format!("{name} {op} {rhs}"));
    Some(skip)
}

#[allow(clippy::too_many_arguments)]
fn try_global_cond_assign(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    if body.instructions.get(i)?.mnemonic != "putnil" {
        return None;
    }
    let defined_idx: usize = i + 1;
    if body.instructions.get(defined_idx)?.mnemonic != "defined" {
        return None;
    }
    let guard_idx: usize = defined_idx + 1;
    if body.instructions.get(guard_idx)?.mnemonic != "branchunless" {
        return None;
    }
    let guard_skip: usize = targets.get(guard_idx).copied().flatten()?;
    if guard_skip <= guard_idx || guard_skip > hi {
        return None;
    }
    let read_idx: usize = guard_idx + 1;
    let read: &YarvIbfInstruction = body.instructions.get(read_idx)?;
    if read.mnemonic != "getglobal" {
        return None;
    }
    let name: String = id_or_index(read, 0);
    let mut branch_idx: usize = read_idx + 1;
    if body
        .instructions
        .get(branch_idx)
        .is_some_and(|x| x.mnemonic == "dup")
    {
        branch_idx += 1;
    }
    let branch: &YarvIbfInstruction = body.instructions.get(branch_idx)?;
    let op: &str = match branch.mnemonic.as_str() {
        "branchif" => "||=",
        "branchunless" => "&&=",
        _ => return None,
    };
    let skip: usize = targets.get(branch_idx).copied().flatten()?;
    if skip <= branch_idx || skip > hi {
        return None;
    }
    let write_idx: usize = (guard_skip..skip).find(|&j| {
        body.instructions[j].mnemonic == "setglobal"
            && id_or_index(&body.instructions[j], 0) == name
    })?;
    let rhs: String = render_value_region(body, ctx, depth, branch_idx + 1, write_idx, targets)?;
    emit_stmt(stmts, depth, format!("{name} {op} {rhs}"));
    Some(attr_assign_resume(body, write_idx + 1))
}

#[allow(clippy::too_many_arguments)]
fn try_attr_compound_assign(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) -> Option<usize> {
    if body.instructions.get(i)?.mnemonic != "dup" || stack.is_empty() {
        return None;
    }
    let getter_idx: usize = i + 1;
    let (getter, getter_argc): (String, usize) =
        send_method_argc(body.instructions.get(getter_idx)?)?;
    if getter_argc != 0 || getter.ends_with('=') {
        return None;
    }
    let after_getter: usize = getter_idx + 1;
    let recv: String = stack.last().cloned()?;
    let setter_name: String = format!("{getter}=");

    if let Some(branch) = body.instructions.get(after_getter)
        && matches!(branch.mnemonic.as_str(), "branchif" | "branchunless")
    {
        let op: &str = if branch.mnemonic == "branchif" {
            "||="
        } else {
            "&&="
        };
        let skip: usize = targets.get(after_getter).copied().flatten()?;
        if skip <= after_getter || skip > hi {
            return None;
        }
        let setter_idx: usize = (after_getter + 1..skip)
            .find(|&j| setter_call_matches(&body.instructions[j], &setter_name))?;
        let rhs: String =
            render_value_region(body, ctx, depth, after_getter + 1, setter_idx, targets)?;
        let _ = pop(stack);
        emit_stmt(stmts, depth, format!("{recv}.{getter} {op} {rhs}"));
        return Some(attr_assign_resume(body, skip));
    }

    let setter_idx: usize = (after_getter..hi).find(|&j| {
        setter_call_matches(&body.instructions[j], &setter_name)
            || body.instructions[j].mnemonic == "leave"
    })?;
    if !setter_call_matches(&body.instructions[setter_idx], &setter_name) {
        return None;
    }
    let op_idx: usize = setter_idx.checked_sub(1)?;
    let op: &str = binop_operator(body.instructions.get(op_idx)?)?;
    let rhs: String = render_value_region(body, ctx, depth, after_getter, op_idx, targets)?;
    let _ = pop(stack);
    emit_stmt(stmts, depth, format!("{recv}.{getter} {op}= {rhs}"));
    Some(attr_assign_resume(body, setter_idx + 1))
}

fn setter_call_matches(instr: &YarvIbfInstruction, setter_name: &str) -> bool {
    send_method_argc(instr).is_some_and(|(method, argc)| method == setter_name && argc == 1)
}

fn attr_assign_resume(body: &YarvIseqBody, from: usize) -> usize {
    let mut resume: usize = from;
    while body
        .instructions
        .get(resume)
        .is_some_and(|x| matches!(x.mnemonic.as_str(), "pop" | "adjuststack"))
    {
        resume += 1;
    }
    resume
}

fn render_value_region(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    lo: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> Option<String> {
    let lo: usize = skip_leading_pop(body, lo);
    if lo >= hi {
        return None;
    }
    let mut value_stack: Vec<String> = Vec::with_capacity(8);
    let mut sink: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        lo,
        hi,
        targets,
        &mut value_stack,
        &mut sink,
    );
    value_stack.pop().filter(|v| !v.is_empty())
}

#[allow(clippy::too_many_arguments)]
fn try_aref_compound_assign(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    hi: usize,
    targets: &[Option<usize>],
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) -> Option<usize> {
    if body.instructions.get(i)?.mnemonic != "dupn" {
        return None;
    }
    let dup_n: usize = operand_count(&body.instructions[i], 0);
    let aref_idx: usize = i + 1;
    let argc: usize = aref_argc(body.instructions.get(aref_idx)?)?;
    if dup_n != argc + 1 || dup_n > stack.len() {
        return None;
    }
    if body.instructions.get(aref_idx + 1)?.mnemonic != "dup" {
        return try_aref_op_assign(body, ctx, depth, hi, targets, stack, stmts, aref_idx, argc);
    }
    let branch_idx: usize = aref_idx + 2;
    let op: &str = match body.instructions.get(branch_idx)?.mnemonic.as_str() {
        "branchif" => "||=",
        "branchunless" => "&&=",
        _ => return None,
    };
    let skip: usize = targets.get(branch_idx).copied().flatten()?;
    if skip <= branch_idx || skip > hi {
        return None;
    }
    let rhs_lo: usize = skip_leading_pop(body, branch_idx + 1);
    let aset_idx: usize = (rhs_lo..skip).find(|&j| {
        matches!(
            body.instructions[j].mnemonic.as_str(),
            "opt_aset" | "opt_aset_with"
        )
    })?;
    let rhs_hi: usize = (rhs_lo..aset_idx)
        .rev()
        .find(|&j| body.instructions[j].mnemonic == "setn")
        .unwrap_or(aset_idx);
    if rhs_lo >= rhs_hi {
        return None;
    }

    let keys: Vec<String> = pop_n(stack, argc);
    let recv: String = pop(stack);
    let index: String = keys.join(", ");

    let mut rhs_stack: Vec<String> = Vec::with_capacity(8);
    let mut rhs_sink: Vec<String> = Vec::new();
    render_region(
        body,
        ctx,
        depth,
        rhs_lo,
        rhs_hi,
        targets,
        &mut rhs_stack,
        &mut rhs_sink,
    );
    let rhs: String = rhs_stack.pop()?;
    let mut resume: usize = skip;
    let mut value_retained: bool = false;
    while let Some(x) = body.instructions.get(resume) {
        match x.mnemonic.as_str() {
            "setn" => {
                value_retained = true;
                resume += 1;
            }
            "adjuststack" => resume += 1,
            _ => break,
        }
    }
    let expr: String = format!("{recv}[{index}] {op} {rhs}");
    if value_retained {
        push(stack, format!("({expr})"));
    } else {
        emit_stmt(stmts, depth, expr);
    }
    Some(resume)
}

#[allow(clippy::too_many_arguments)]
fn try_aref_op_assign(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    hi: usize,
    targets: &[Option<usize>],
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
    aref_idx: usize,
    argc: usize,
) -> Option<usize> {
    let aset_idx: usize = (aref_idx + 1..hi).find(|&j| {
        matches!(
            body.instructions[j].mnemonic.as_str(),
            "opt_aset" | "opt_aset_with"
        )
    })?;
    let op_idx: usize = (aref_idx + 1..aset_idx)
        .rev()
        .find(|&j| binop_operator(&body.instructions[j]).is_some())?;
    let op: &str = binop_operator(&body.instructions[op_idx])?;
    if op_idx <= aref_idx {
        return None;
    }

    let keys: Vec<String> = pop_n(stack, argc);
    let recv: String = pop(stack);
    let index: String = keys.join(", ");
    let rhs: String = render_value_region(body, ctx, depth, aref_idx + 1, op_idx, targets)?;

    let mut resume: usize = aset_idx + 1;
    let mut value_retained: bool = false;
    while let Some(x) = body.instructions.get(resume) {
        match x.mnemonic.as_str() {
            "setn" => {
                value_retained = true;
                resume += 1;
            }
            "pop" | "adjuststack" => resume += 1,
            _ => break,
        }
    }
    let expr: String = format!("{recv}[{index}] {op}= {rhs}");
    if value_retained {
        push(stack, format!("({expr})"));
    } else {
        emit_stmt(stmts, depth, expr);
    }
    Some(resume)
}

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
    let init_target: usize = targets.get(i).copied().flatten()?;
    if init_target <= i || init_target >= hi {
        return None;
    }
    if is_unconditional_loop_head(body, init_target, targets) {
        let back_edge: usize = (init_target..hi)
            .rev()
            .find(|&k| targets[k] == Some(init_target))?;
        if body.instructions[back_edge].mnemonic != "jump" {
            return None;
        }
        let pad: String = indent(depth);
        stmts.push(format!("{pad}while true"));
        let mut body_stack: Vec<String> = Vec::new();
        render_region(
            body,
            ctx,
            depth + 1,
            init_target,
            back_edge,
            targets,
            &mut body_stack,
            stmts,
        );
        flush_trailing(&mut body_stack, depth + 1, stmts);
        stmts.push(format!("{pad}end"));
        return Some(back_edge + 1);
    }
    let branch_idx: usize = (init_target..hi).find(|&k| {
        matches!(
            body.instructions[k].mnemonic.as_str(),
            "branchif" | "branchunless"
        ) && targets[k].is_some_and(|t| t > i && t <= init_target)
    })?;
    let back_target: usize = targets[branch_idx]?;
    let branch_idx: usize = last_loop_branch(body, branch_idx, back_target, hi, targets);
    let keyword: &str = if body.instructions[branch_idx].mnemonic == "branchif" {
        "while"
    } else {
        "until"
    };

    if init_target == back_target {
        return render_post_tested_loop(
            body,
            ctx,
            depth,
            i,
            branch_idx,
            back_target,
            keyword,
            targets,
            stmts,
        );
    }
    let cond_start: usize = init_target;
    let cond: String = render_loop_condition(
        body,
        ctx,
        depth,
        cond_start,
        branch_idx,
        back_target,
        keyword,
        targets,
    );

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

fn last_loop_branch(
    body: &YarvIseqBody,
    first: usize,
    back_target: usize,
    hi: usize,
    targets: &[Option<usize>],
) -> usize {
    let mut last: usize = first;
    for (k, instr) in body
        .instructions
        .iter()
        .enumerate()
        .take(hi)
        .skip(first + 1)
    {
        let m: &str = instr.mnemonic.as_str();
        let is_control: bool = matches!(
            m,
            "branchif" | "branchunless" | "branchnil" | "jump" | "leave" | "throw"
        ) || m == "opt_case_dispatch";
        if !is_control {
            continue;
        }
        if matches!(m, "branchif" | "branchunless")
            && targets.get(k).copied().flatten() == Some(back_target)
        {
            last = k;
            continue;
        }
        break;
    }
    last
}

#[allow(clippy::too_many_arguments)]
fn render_loop_condition(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    cond_start: usize,
    branch_idx: usize,
    back_target: usize,
    keyword: &str,
    targets: &[Option<usize>],
) -> String {
    let exit: usize = branch_idx + 1;
    let mut segments: Vec<(usize, usize, bool, bool)> = Vec::new();
    let mut seg_lo: usize = cond_start;
    for j in cond_start..branch_idx {
        let jumps_if_true: bool = match body.instructions[j].mnemonic.as_str() {
            "branchif" => true,
            "branchunless" => false,
            _ => continue,
        };
        let Some(target): Option<usize> = targets.get(j).copied().flatten() else {
            continue;
        };
        if target != exit && target != back_target {
            continue;
        }
        segments.push((seg_lo, j, jumps_if_true, target == back_target));
        seg_lo = j + 1;
    }
    let render_value = |lo: usize, hi: usize| -> String {
        let mut stack: Vec<String> = Vec::with_capacity(8);
        let mut sink: Vec<String> = Vec::new();
        render_region(body, ctx, depth, lo, hi, targets, &mut stack, &mut sink);
        stack.pop().unwrap_or_else(|| "true".to_owned())
    };
    let is_until: bool = keyword == "until";
    let mut cond: String = render_value(seg_lo, branch_idx);
    let mut cond_op: Option<&str> = None;
    for &(lo, hi, jumps_if_true, to_body) in segments.iter().rev() {
        let value: String = render_value(lo, hi);
        let enters_body_when_true: bool = jumps_if_true == to_body;
        let negate: bool = enters_body_when_true == is_until;
        let op: &str = if to_body == is_until { "&&" } else { "||" };
        let lhs: String = if negate {
            format!("!{}", wrap_operand(&value))
        } else {
            logical_operand(value)
        };
        let rhs: String = match cond_op {
            Some(inner) if inner != op => format!("({cond})"),
            _ => logical_operand(cond),
        };
        cond = format!("{lhs} {op} {rhs}");
        cond_op = Some(op);
    }
    cond
}

fn logical_operand(value: String) -> String {
    if [" || ", " && ", " and ", " or ", " ? ", " = ", "not "]
        .iter()
        .any(|marker| value.contains(marker))
    {
        format!("({value})")
    } else {
        value
    }
}

fn wrap_operand(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '?' | '!' | '@'))
    {
        value.to_owned()
    } else {
        format!("({value})")
    }
}

#[allow(clippy::too_many_arguments)]
fn render_post_tested_loop(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    depth: u32,
    i: usize,
    branch_idx: usize,
    back_target: usize,
    keyword: &str,
    targets: &[Option<usize>],
    stmts: &mut Vec<String>,
) -> Option<usize> {
    let cond_start: usize = post_loop_cond_start(body, i, branch_idx, targets)?;
    if cond_start <= back_target || cond_start > branch_idx {
        return None;
    }

    let pad: String = indent(depth);
    stmts.push(format!("{pad}begin"));
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

    let cond: String = render_loop_condition(
        body,
        ctx,
        depth,
        cond_start,
        branch_idx,
        back_target,
        keyword,
        targets,
    );
    stmts.push(format!("{pad}end {keyword} {cond}"));
    Some(branch_idx + 1)
}

fn post_loop_cond_start(
    body: &YarvIseqBody,
    i: usize,
    branch_idx: usize,
    targets: &[Option<usize>],
) -> Option<usize> {
    let prologue_jump: usize = (i + 1..branch_idx).find(|&j| {
        body.instructions[j].mnemonic == "jump"
            && targets.get(j).copied().flatten().is_some_and(|t| t > j)
    })?;
    targets.get(prologue_jump).copied().flatten()
}

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
    if op != "&."
        && let Some(assignment) = assignment_to_lvalue(&sink, &rhs, &lhs)
    {
        push(stack, format!("{lhs} {op} ({assignment})"));
        return Some(target);
    }
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

fn assignment_to_lvalue(sink: &[String], rhs: &str, lhs: &str) -> Option<String> {
    let matches_lvalue = |stmt: &str| -> bool {
        stmt.split_once(" = ")
            .is_some_and(|(target, _): (&str, &str)| target == lhs)
    };
    if matches_lvalue(rhs) {
        return Some(rhs.to_owned());
    }
    sink.iter()
        .rev()
        .find(|stmt: &&String| matches_lvalue(stmt.trim_start()))
        .map(|stmt: &String| stmt.trim_start().to_owned())
}

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
            "setinstancevariable"
                | "setclassvariable"
                | "setlocal"
                | "setlocal_WC_0"
                | "setlocal_WC_1"
                | "setglobal"
        )
    })?;
    let set_instr: &YarvIbfInstruction = &body.instructions[set_idx];
    let set_target: String = match set_instr.mnemonic.as_str() {
        "setinstancevariable" => ivar_name(set_instr, 0),
        "setclassvariable" => cvar_name(set_instr, 0),
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

fn compound_value(body: &YarvIseqBody, lo: usize, set_idx: usize) -> Option<String> {
    let mut value_stack: Vec<String> = Vec::new();
    let mut sink: Vec<String> = Vec::new();
    let ctx: DecompileContext<'static> = DecompileContext {
        bodies_by_index: Vec::new(),
        objects: &[],
        enclosing_scopes: Vec::new(),
        pattern_present: Rc::from(Vec::<bool>::new()),
        method_bodies: Rc::from(Vec::<bool>::new()),
        block_bodies: Rc::from(Vec::<bool>::new()),
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

fn drop_trailing_bare_value(inner: &mut Vec<String>, inner_depth: u32) {
    let pad: String = indent(inner_depth);
    if let Some(last) = inner.last()
        && let Some(trimmed) = last.strip_prefix(pad.as_str())
        && is_bare_value_line(trimmed)
    {
        inner.pop();
    }
}

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

const VM_ENV_DATA_SIZE: u64 = 3;

struct DecompileContext<'a> {
    bodies_by_index: Vec<Option<&'a YarvIseqBody>>,
    objects: &'a [crate::yarv::ibf::IbfObject],
    enclosing_scopes: Vec<Vec<Option<String>>>,
    pattern_present: Rc<[bool]>,
    method_bodies: Rc<[bool]>,
    block_bodies: Rc<[bool]>,
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
        let mut pattern_present: Vec<bool> = vec![false; max_index];
        let mut method_bodies: Vec<bool> = vec![false; max_index];
        let mut block_bodies: Vec<bool> = vec![false; max_index];
        for body in &image.iseqs {
            for instr in &body.instructions {
                let kind: Option<&mut Vec<bool>> = match instr.mnemonic.as_str() {
                    "definemethod" | "definesmethod" => Some(&mut method_bodies),
                    "send" | "sendforward" | "invokesuper" | "invokesuperforward" => {
                        Some(&mut block_bodies)
                    }
                    _ => None,
                };
                if let Some(flags) = kind
                    && let Some(YarvOperand::IseqRef(index)) = instr.operands.get(1)
                    && let Some(flag) = flags.get_mut(*index as usize)
                {
                    *flag = true;
                }
            }
            let slot_index: usize = body.index as usize;
            if let Some(slot) = bodies_by_index.get_mut(slot_index) {
                *slot = Some(body);
            }
            if let Some(flag) = pattern_present.get_mut(slot_index) {
                *flag = body_has_pattern_construct(body);
            }
        }
        Self {
            bodies_by_index,
            objects: &image.objects,
            enclosing_scopes: Vec::new(),
            pattern_present: Rc::from(pattern_present),
            method_bodies: Rc::from(method_bodies),
            block_bodies: Rc::from(block_bodies),
        }
    }

    fn nested_in(&self, parent: &[Option<String>]) -> Self {
        let mut enclosing_scopes: Vec<Vec<Option<String>>> =
            Vec::with_capacity(self.enclosing_scopes.len() + 1);
        enclosing_scopes.push(parent.to_vec());
        enclosing_scopes.extend_from_slice(&self.enclosing_scopes);
        Self {
            bodies_by_index: self.bodies_by_index.clone(),
            objects: self.objects,
            enclosing_scopes,
            pattern_present: Rc::clone(&self.pattern_present),
            method_bodies: Rc::clone(&self.method_bodies),
            block_bodies: Rc::clone(&self.block_bodies),
        }
    }

    fn early_exit_keyword(&self, iseq_index: u32) -> Option<&'static str> {
        let index: usize = iseq_index as usize;
        if self.method_bodies.get(index).copied().unwrap_or(false) {
            Some("return")
        } else if self.block_bodies.get(index).copied().unwrap_or(false) {
            Some("next")
        } else {
            None
        }
    }

    fn body_has_pattern(&self, iseq_index: u32) -> bool {
        self.pattern_present
            .get(iseq_index as usize)
            .copied()
            .unwrap_or(false)
    }

    fn local_at_level(&self, current: &[Option<String>], level: u32, operand: u64) -> String {
        if level == 0 {
            return local_name(current, operand);
        }
        self.enclosing_scopes.get(level as usize - 1).map_or_else(
            || local_name(current, operand),
            |scope| local_name(scope, operand),
        )
    }

    fn body(&self, iseq_index: u32) -> Option<&'a YarvIseqBody> {
        self.bodies_by_index
            .get(iseq_index as usize)
            .copied()
            .flatten()
    }

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
        if names.first().is_some_and(|s| s.is_empty()) {
            return Some(format!("::{}", names[1..].join("::")));
        }
        Some(names.join("::"))
    }
}

fn local_access_level(instr: &YarvIbfInstruction) -> u32 {
    match instr.mnemonic.as_str() {
        "getlocal_WC_0" | "setlocal_WC_0" => 0,
        "getlocal_WC_1" | "setlocal_WC_1" => 1,
        _ => u32::try_from(operand_num(instr, 1)).unwrap_or(0),
    }
}

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

#[inline]
fn emit_stmt(stmts: &mut Vec<String>, depth: u32, line: String) {
    let text: &str = unwrapped_assignment(&line).unwrap_or(&line);
    stmts.push(format!("{}{text}", indent(depth)));
}

fn unwrapped_assignment(line: &str) -> Option<&str> {
    let inner: &str = line.strip_prefix('(')?.strip_suffix(')')?;
    if inner.starts_with('{') {
        return None;
    }
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut escaped: bool = false;
    let mut assigns: bool = false;
    let chars: Vec<char> = inner.chars().collect();
    for (k, &c) in chars.iter().enumerate() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            '=' if depth == 0 && k > 0 && chars[k - 1] == ' ' && chars.get(k + 1) == Some(&' ') => {
                assigns = true;
            }
            _ => {}
        }
    }
    (depth == 0 && quote.is_none() && assigns).then_some(inner)
}

#[allow(clippy::match_same_arms)]
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
            let level: u32 = local_access_level(instr);
            push(
                stack,
                ctx.local_at_level(local_table, level, operand_num(instr, 0)),
            );
        }
        "getblockparam" | "getblockparamproxy" => {
            let level: u32 = operand_num(instr, 1) as u32;
            push(
                stack,
                ctx.local_at_level(local_table, level, operand_num(instr, 0)),
            );
        }
        "getinstancevariable" => push(stack, ivar_name(instr, 0)),
        "getclassvariable" => push(stack, cvar_name(instr, 0)),
        "getglobal" => push(stack, id_or_index(instr, 0)),
        "getconstant" => push(stack, id_or_index(instr, 0)),
        "newarray" | "newarraykwsplat" => {
            let n: usize = operand_count(instr, 0);
            let elems: Vec<String> = pop_n(stack, n);
            push(stack, format!("[{}]", elems.join(", ")));
        }
        "newhash" => {
            let n: usize = operand_count(instr, 0);
            let flat: Vec<String> = pop_n(stack, n);
            push(stack, render_hash(&flat));
        }
        "concatstrings" => {
            let n: usize = operand_count(instr, 0);
            let parts: Vec<String> = pop_n(stack, n);
            push(stack, render_interpolation(&parts));
        }
        "concattoarray" => {
            let rhs: String = pop(stack);
            let lhs: String = pop(stack);
            push(
                stack,
                append_array_element(&lhs, &format!("*{}", strip_splat(&rhs))),
            );
        }
        "concatarray" => {
            let rhs: String = pop(stack);
            let lhs: String = pop(stack);
            push(stack, format!("{lhs} + {rhs}"));
        }
        "splatarray" => {
            let v: String = pop(stack);
            let bare: &str = strip_splat(&v);
            if operand_value(instr, 0) == "true" {
                push(stack, format!("[*{bare}]"));
            } else {
                push(stack, format!("*{bare}"));
            }
        }
        "opt_send_without_block" | "send" | "sendforward" => {
            emit_send(instr, local_table, ctx, depth, stack, stmts);
        }
        "invokesuper" => emit_super(instr, stack),
        "invokeblock" => emit_invokeblock(instr, stack),
        "opt_newarray_send" => emit_newarray_send(instr, stack),
        "opt_ary_freeze" | "opt_hash_freeze" | "opt_str_freeze" => {
            push(stack, format!("{}.freeze", operand_value(instr, 0)));
        }
        "opt_str_uminus" | "opt_nil_p" | "opt_size" | "opt_length" | "opt_empty_p" | "opt_succ"
        | "opt_not" => {
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
        "opt_aref_with" => {
            let idx: String = operand_value(instr, 0);
            let recv: String = pop(stack);
            push(stack, format!("{recv}[{idx}]"));
        }
        "opt_aset" => {
            let val: String = pop(stack);
            let idx: String = pop(stack);
            let recv: String = pop(stack);
            let recv: String = if needs_receiver_parens(&recv) {
                format!("({recv})")
            } else {
                recv
            };
            push(stack, format!("{recv}[{idx}] = {val}"));
        }
        "opt_regexpmatch2" => {
            let arg: String = pop(stack);
            let recv: String = pop(stack);
            let recv: String = parenthesize_operand(recv, 4, false);
            let arg: String = parenthesize_operand(arg, 4, true);
            push(stack, format!("{recv} =~ {arg}"));
        }
        "opt_reverse" => {
            let n: usize = operand_count(instr, 0).min(stack.len());
            let from: usize = stack.len() - n;
            stack[from..].reverse();
        }
        "opt_aset_with" => {
            let val: String = pop(stack);
            let idx: String = operand_value(instr, 0);
            let recv: String = pop(stack);
            push(stack, format!("{recv}[{idx}] = {val}"));
        }
        "newrange" => {
            let high: String = pop(stack);
            let low: String = pop(stack);
            let dots: &str = if operand_num(instr, 0) == 0 {
                ".."
            } else {
                "..."
            };
            push(stack, format!("({low}{dots}{high})"));
        }
        "defined" => {
            let base: String = pop(stack);
            let name: String = defined_operand(instr);
            let target: String = match operand_num(instr, 0) {
                DEFINED_METHOD => format!("{base}.{name}"),
                DEFINED_CONST | DEFINED_CONST_FROM if base != "nil" => format!("{base}::{name}"),
                DEFINED_YIELD => "yield".to_owned(),
                DEFINED_ZSUPER => "super".to_owned(),
                _ => name,
            };
            push(stack, format!("defined?({target})"));
        }
        "once" => {
            let child: Option<&YarvIseqBody> = match instr.operands.first() {
                Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index),
                _ => None,
            };
            let nested: DecompileContext<'_> = ctx.nested_in(local_table);
            let lines: Vec<String> = child.map_or_else(Vec::new, |body: &YarvIseqBody| {
                render_iseq_statements(body, &nested, depth)
            });
            match lines.as_slice() {
                [single] if !single.trim_start().starts_with("END {") => {
                    let value: &str = single.trim();
                    if value.starts_with('/') {
                        push(stack, format!("{value}o"));
                    } else {
                        push(stack, value.to_owned());
                    }
                }
                _ => {
                    stmts.extend(lines);
                    push(stack, "nil".to_owned());
                }
            }
        }
        "toregexp" => {
            let options: u64 = operand_num(instr, 0);
            let count: usize = operand_count(instr, 1);
            let parts: Vec<String> = pop_n(stack, count);
            push(stack, render_dynamic_regexp(&parts, options));
        }
        "definedivar" => {
            let name: String = id_or_index(instr, 0);
            push(stack, format!("defined?({name})"));
        }
        "getspecial" => {
            push(stack, getspecial_name(instr));
        }
        "pushtoarray" => {
            let n: usize = operand_count(instr, 0);
            let elems: Vec<String> = pop_n(stack, n);
            if let Some(arr) = stack.last_mut() {
                let mut acc: String = arr.clone();
                for e in elems {
                    acc = append_array_element(&acc, &e);
                }
                *arr = acc;
            }
        }
        "setlocal" | "setlocal_WC_0" | "setlocal_WC_1" => {
            let v: String = pop(stack);
            let level: u32 = local_access_level(instr);
            let name: String = ctx.local_at_level(local_table, level, operand_num(instr, 0));
            emit_stmt(stmts, depth, format!("{name} = {v}"));
        }
        "setinstancevariable" => {
            let v: String = pop(stack);
            emit_stmt(stmts, depth, format!("{} = {v}", ivar_name(instr, 0)));
        }
        "setclassvariable" => {
            let v: String = pop(stack);
            emit_stmt(stmts, depth, format!("{} = {v}", cvar_name(instr, 0)));
        }
        "setglobal" => {
            let v: String = pop(stack);
            emit_stmt(stmts, depth, format!("{} = {v}", id_or_index(instr, 0)));
        }
        "setconstant" => {
            let cbase: String = pop(stack);
            let v: String = pop(stack);
            let name: String = id_or_index(instr, 0);
            if cbase == CBASE {
                emit_stmt(stmts, depth, format!("{name} = {v}"));
            } else {
                emit_stmt(stmts, depth, format!("{cbase}::{name} = {v}"));
            }
        }
        "definemethod" => {
            let name: String = id_or_index(instr, 0);
            let header: String = format!("def {name}{}", method_signature(instr, ctx));
            let child: Option<&YarvIseqBody> = method_iseq(instr, ctx);
            stmts.extend(render_nested(header, child, ctx, depth, false));
        }
        "definesmethod" => {
            let name: String = id_or_index(instr, 0);
            let owner: String = pop(stack);
            let owner: String = if owner.is_empty() || owner == "_" {
                "self".to_owned()
            } else {
                owner
            };
            let header: String = format!("def {owner}.{name}{}", method_signature(instr, ctx));
            let child: Option<&YarvIseqBody> = method_iseq(instr, ctx);
            stmts.extend(render_nested(header, child, ctx, depth, false));
        }
        "defineclass" => {
            let name: String = id_or_index(instr, 0);
            let flags: u64 = operand_num(instr, 2);
            let child: Option<&YarvIseqBody> = match instr.operands.get(1) {
                Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index),
                _ => None,
            };
            let superclass: String = pop(stack);
            let cbase: String = pop(stack);
            let scoped_name: String = if flags & DEFINECLASS_FLAG_SCOPED != 0 {
                format!("{cbase}::{name}")
            } else {
                name
            };
            let header: String = match flags & 7 {
                1 => format!("class << {cbase}"),
                2 => format!("module {scoped_name}"),
                _ if flags & DEFINECLASS_FLAG_HAS_SUPERCLASS != 0 => {
                    format!("class {scoped_name} < {superclass}")
                }
                _ => format!("class {scoped_name}"),
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
            let n: usize = operand_count(instr, 0);
            let len: usize = stack.len();
            if n <= len {
                let slice: Vec<String> = stack[len - n..].to_vec();
                for v in slice {
                    push(stack, v);
                }
            }
        }
        "topn" => {
            let n: usize = operand_count(instr, 0);
            let len: usize = stack.len();
            if n < len {
                let v: String = stack[len - 1 - n].clone();
                push(stack, v);
            }
        }
        "setn" => {
            let n: usize = operand_count(instr, 0);
            let len: usize = stack.len();
            if n < len
                && let Some(top) = stack.last().cloned()
            {
                stack[len - 1 - n] = top;
            }
        }
        "adjuststack" => {
            let n: usize = operand_count(instr, 0);
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
        "throw" => emit_throw(instr, depth, stack, stmts),
        "putspecialobject" => push(
            stack,
            match operand_num(instr, 0) {
                1 => VMCORE.to_owned(),
                _ => CBASE.to_owned(),
            },
        ),
        "nop" | "intern" | "tostring" | "putchilledstring_dummy" => {}
        _ => {}
    }
}

const THROW_TAG_RETURN: u64 = 1;
const THROW_TAG_BREAK: u64 = 2;
const THROW_TAG_NEXT: u64 = 3;
const THROW_TAG_RETRY: u64 = 4;

fn emit_value_flow(stmts: &mut Vec<String>, depth: u32, keyword: &str, value: String) {
    let line: String = if value.is_empty() || value == "nil" {
        keyword.to_owned()
    } else {
        format!("{keyword} {value}")
    };
    emit_stmt(stmts, depth, line);
}

fn emit_throw(
    instr: &YarvIbfInstruction,
    depth: u32,
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) {
    let raw_tag: u64 = operand_num(instr, 0);
    if raw_tag == THROW_TAG_BREAK {
        let value: String = stack.pop().unwrap_or_default();
        emit_value_flow(stmts, depth, "break", value);
        return;
    }
    let tag: u64 = raw_tag & 0xff;
    match tag {
        THROW_TAG_BREAK => {
            let value: String = stack.pop().unwrap_or_default();
            emit_value_flow(stmts, depth, "break", value);
        }
        THROW_TAG_NEXT => {
            let value: String = stack.pop().unwrap_or_default();
            emit_value_flow(stmts, depth, "next", value);
        }
        THROW_TAG_RETRY => emit_stmt(stmts, depth, "retry".to_owned()),
        THROW_TAG_RETURN => {
            let value: String = stack.pop().unwrap_or_default();
            emit_value_flow(stmts, depth, "return", value);
        }
        _ => {}
    }
}

fn strip_splat(v: &str) -> &str {
    v.strip_prefix('*').unwrap_or(v)
}

fn array_literal_inner(arr: &str) -> Option<&str> {
    arr.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
}

fn append_array_element(arr: &str, element: &str) -> String {
    match array_literal_inner(arr) {
        Some("") => format!("[{element}]"),
        Some(inner) => format!("[{inner}, {element}]"),
        None => format!("[{arr}, {element}]"),
    }
}

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

fn collapse_interp_coercion(stack: &mut Vec<String>) {
    if stack.len() >= 2 {
        let top: String = pop(stack);
        let below: String = pop(stack);
        push(stack, if top == below { top } else { below });
    }
}

fn render_interpolation(parts: &[String]) -> String {
    match parts {
        [] => "\"\"".to_owned(),
        [single] => single.clone(),
        _ => {
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

fn render_dynamic_regexp(parts: &[String], options: u64) -> String {
    let mut source: String = String::new();
    for part in parts {
        let Some(body): Option<&str> = string_literal_body(part) else {
            source.push_str("#{");
            source.push_str(part);
            source.push('}');
            continue;
        };
        let mut chars: core::str::Chars<'_> = body.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('"') => source.push('"'),
                    Some(other) if other != '\\' => {
                        source.push('\\');
                        source.push(other);
                    }
                    _ => source.push('\\'),
                },
                '/' => source.push_str("\\/"),
                other => source.push(other),
            }
        }
    }
    let mut flags: String = String::new();
    for (bit, letter) in [(1_u64, 'i'), (2, 'x'), (4, 'm')] {
        if options & bit != 0 {
            flags.push(letter);
        }
    }
    format!("/{source}/{flags}")
}

fn string_literal_body(s: &str) -> Option<&str> {
    let inner: &str = s.strip_prefix('"')?.strip_suffix('"')?;
    let mut escaped: bool = false;
    for c in inner.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return None,
            _ => {}
        }
    }
    (!escaped && !inner.contains("#{")).then_some(inner)
}

fn method_iseq<'a>(
    instr: &YarvIbfInstruction,
    ctx: &DecompileContext<'a>,
) -> Option<&'a YarvIseqBody> {
    match instr.operands.get(1) {
        Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index),
        _ => None,
    }
}

fn method_signature(instr: &YarvIbfInstruction, ctx: &DecompileContext<'_>) -> String {
    method_iseq(instr, ctx).map_or_else(String::new, |body| render_param_signature(body, ctx))
}

const PARAM_FLAG_HAS_OPT: u64 = 1 << 1;
const PARAM_FLAG_HAS_POST: u64 = 1 << 3;
const PARAM_FLAG_HAS_REST: u64 = 1 << 2;
const PARAM_FLAG_HAS_KW: u64 = 1 << 4;
const PARAM_FLAG_HAS_KWREST: u64 = 1 << 5;
const PARAM_FLAG_HAS_BLOCK: u64 = 1 << 6;

fn instruction_at_pc(body: &YarvIseqBody, target: u32) -> Option<usize> {
    let mut pc: u32 = 0;
    for (idx, instr) in body.instructions.iter().enumerate() {
        if pc == target {
            return Some(idx);
        }
        pc = pc.saturating_add(1 + u32::try_from(instr.operands.len()).unwrap_or(u32::MAX));
    }
    (pc == target).then_some(body.instructions.len())
}

fn optional_prologue(body: &YarvIseqBody) -> Option<(Vec<usize>, usize)> {
    if body.param_flags & PARAM_FLAG_HAS_OPT == 0 || body.param_opt_table.is_empty() {
        return None;
    }
    let entries: Vec<usize> = body
        .param_opt_table
        .iter()
        .map(|&pc: &u32| instruction_at_pc(body, pc))
        .collect::<Option<Vec<usize>>>()?;
    let end: usize = *entries.last()?;
    Some((entries, end))
}

fn optional_defaults(body: &YarvIseqBody, ctx: &DecompileContext<'_>) -> Vec<Option<String>> {
    let Some((entries, _)): Option<(Vec<usize>, usize)> = optional_prologue(body) else {
        return Vec::new();
    };
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    entries
        .windows(2)
        .map(|pair: &[usize]| {
            let (lo, hi): (usize, usize) = (pair[0], pair[1]);
            let store: usize = hi.checked_sub(1)?;
            let last: &YarvIbfInstruction = body.instructions.get(store)?;
            if !matches!(last.mnemonic.as_str(), "setlocal_WC_0" | "setlocal") || store < lo {
                return None;
            }
            render_value_region(body, ctx, 0, lo, store, &targets).filter(|v| !v.is_empty())
        })
        .collect()
}

fn keyword_default_prologue(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
    start: usize,
) -> (Vec<(String, String)>, usize) {
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    let mut defaults: Vec<(String, String)> = Vec::new();
    let mut i: usize = start;
    while let Some(check) = body.instructions.get(i) {
        if check.mnemonic != "checkkeyword" {
            break;
        }
        let Some(branch) = body.instructions.get(i + 1) else {
            break;
        };
        if branch.mnemonic != "branchif" {
            break;
        }
        let Some(skip): Option<usize> = targets.get(i + 1).copied().flatten() else {
            break;
        };
        if skip <= i + 2 || skip > body.instructions.len() {
            break;
        }
        let store_idx: usize = skip - 1;
        let Some(store) = body.instructions.get(store_idx) else {
            break;
        };
        if !matches!(store.mnemonic.as_str(), "setlocal_WC_0" | "setlocal") {
            break;
        }
        let name: String = ctx.local_at_level(
            &body.local_table,
            local_access_level(store),
            operand_num(store, 0),
        );
        let Some(value): Option<String> =
            render_value_region(body, ctx, 0, i + 2, store_idx, &targets)
        else {
            break;
        };
        if name.starts_with("local") || value.is_empty() {
            break;
        }
        defaults.push((name, value));
        i = skip;
    }
    (defaults, i)
}

fn render_param_signature(body: &YarvIseqBody, ctx: &DecompileContext<'_>) -> String {
    let count: usize =
        (body.param_size.max(body.param_lead_num) as usize).min(body.local_table.len());
    if count == 0 {
        return String::new();
    }
    let has_opt: bool = body.param_flags & PARAM_FLAG_HAS_OPT != 0;
    let has_rest: bool = body.param_flags & PARAM_FLAG_HAS_REST != 0;
    let has_kw: bool = body.param_flags & PARAM_FLAG_HAS_KW != 0;
    let has_kwrest: bool = body.param_flags & PARAM_FLAG_HAS_KWREST != 0;
    let has_block: bool = body.param_flags & PARAM_FLAG_HAS_BLOCK != 0;
    let opt_lo: usize = body.param_lead_num as usize;
    let opt_hi: usize = opt_lo + body.param_opt_num as usize;
    let rest_idx: Option<usize> = has_rest.then_some(body.param_rest_start as usize);
    let block_idx: Option<usize> = has_block.then_some(body.param_block_start as usize);
    let kwrest_idx: Option<usize> = has_kwrest
        .then(|| block_idx.map_or_else(|| count.saturating_sub(1), |b| b.saturating_sub(1)));
    let kw_defaults: Vec<(String, String)> = if has_kw {
        let opt_end: usize = optional_prologue(body).map_or(0, |(_, end)| end);
        let mut defaults: Vec<(String, String)> = keyword_default_prologue(body, ctx, opt_end).0;
        if let Some(keyword) = &body.param_keyword {
            let optional: &[Option<String>] = keyword
                .names
                .get(keyword.required_num as usize..)
                .unwrap_or(&[]);
            for (name, value) in optional.iter().zip(&keyword.defaults) {
                if let (Some(name), Some(value)) = (name, value)
                    && !defaults.iter().any(|(kw, _)| kw == name)
                {
                    defaults.push((name.clone(), render_operand(value)));
                }
            }
        }
        defaults
    } else {
        Vec::new()
    };

    let opt_defaults: Vec<Option<String>> = optional_defaults(body, ctx);
    let mut params: Vec<String> = Vec::with_capacity(count);
    for idx in 0..count {
        let anonymous: String = format!(
            "local{}",
            (body.local_table.len() - 1 - idx) as u64 + VM_ENV_DATA_SIZE
        );
        let name: &str = match body.local_table.get(idx).and_then(Option::as_deref) {
            Some(name) if !name.is_empty() => name,
            _ if has_kw
                && idx >= opt_hi
                && Some(idx) != rest_idx
                && Some(idx) != block_idx
                && Some(idx) != kwrest_idx =>
            {
                continue;
            }
            _ => &anonymous,
        };
        let name: &str = name.trim_start_matches(['*', '&']);
        let rendered: String = if Some(idx) == rest_idx {
            format!("*{name}")
        } else if Some(idx) == block_idx {
            format!("&{name}")
        } else if Some(idx) == kwrest_idx {
            format!("**{name}")
        } else if has_opt && (opt_lo..opt_hi).contains(&idx) {
            match opt_defaults.get(idx - opt_lo) {
                Some(Some(value)) => format!("{name} = {value}"),
                _ => format!("{name} = nil"),
            }
        } else if has_kw && idx >= opt_hi && Some(idx) != rest_idx {
            match kw_defaults.iter().find(|(kw, _)| kw == name) {
                Some((_, value)) => format!("{name}: {value}"),
                None => format!("{name}:"),
            }
        } else {
            name.to_owned()
        };
        params.push(rendered);
    }
    if params.is_empty() {
        return String::new();
    }
    format!("({})", params.join(", "))
}

fn constant_path_value(instr: &YarvIbfInstruction, ctx: &DecompileContext<'_>) -> String {
    match instr.operands.first() {
        Some(YarvOperand::ObjectRef(index)) => ctx
            .constant_path(*index)
            .unwrap_or_else(|| operand_value(instr, 0)),
        Some(YarvOperand::Id(name) | YarvOperand::Literal(name)) => name.clone(),
        Some(YarvOperand::NumLiteral(text)) => {
            symbol_array_to_path(text).unwrap_or_else(|| operand_value(instr, 0))
        }
        _ => operand_value(instr, 0),
    }
}

fn symbol_array_to_path(text: &str) -> Option<String> {
    let inner: &str = text.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty() {
        return None;
    }
    let parts: Vec<&str> = inner.split(", ").collect();
    let absolute: bool = matches!(parts.first(), Some(&(":\"\"" | "\"\"")));
    let mut segments: Vec<&str> = Vec::new();
    for part in parts.iter().skip(usize::from(absolute)) {
        let name: &str = part.strip_prefix(':')?;
        if name.is_empty() {
            return None;
        }
        segments.push(name);
    }
    if segments.is_empty() {
        return None;
    }
    if absolute {
        Some(format!("::{}", segments.join("::")))
    } else {
        Some(segments.join("::"))
    }
}

fn emit_send(
    instr: &YarvIbfInstruction,
    enclosing: &[Option<String>],
    ctx: &DecompileContext<'_>,
    depth: u32,
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) {
    let (method, argc, flags, kwargs): (String, usize, u32, &[String]) =
        match instr.operands.first() {
            Some(YarvOperand::Call {
                method,
                argc,
                flags,
                kwargs,
            }) => (
                method.clone(),
                call_arg_count(*argc),
                *flags,
                kwargs.as_slice(),
            ),
            Some(YarvOperand::Id(name)) => (name.clone(), 0, 0, &[]),
            _ => ("call".to_owned(), 0, 0, &[]),
        };
    if method == "ensure_shareable" && argc == 2 {
        let _name: String = pop(stack);
        let value: String = pop(stack);
        push(stack, value);
        return;
    }
    let block_iseq: Option<&YarvIseqBody> = match instr.operands.get(1) {
        Some(YarvOperand::IseqRef(index)) if *index != u32::MAX => ctx.body(*index),
        _ => None,
    };
    let block_arg: Option<String> = (flags & VM_CALL_ARGS_BLOCKARG != 0).then(|| pop(stack));
    let forwarding: bool = instr.mnemonic == "sendforward";
    if forwarding {
        let _ = pop(stack);
    }
    let mut args: Vec<String> = pop_n(stack, argc);
    name_keyword_arguments(&mut args, kwargs);
    mark_splatted_arguments(&mut args, flags, kwargs.len());
    if let Some(blk) = block_arg {
        let rendered: String = if blk.starts_with('&') {
            blk
        } else {
            format!("&{blk}")
        };
        args.push(rendered);
    }
    if forwarding {
        args.push("...".to_owned());
    }
    let recv: String = pop(stack);
    if recv == VMCORE
        && let Some(rendered) = render_vmcore_call(&method, &args, block_iseq.is_some())
    {
        match rendered {
            VmcoreCall::Value(value) => {
                if block_iseq.is_none() {
                    push(stack, value);
                    return;
                }
            }
            VmcoreCall::Statement(line) => {
                emit_stmt(stmts, depth, line);
                push(stack, "nil".to_owned());
                return;
            }
        }
    }
    if recv == VMCORE
        && method == "core#set_postexe"
        && let Some(block) = block_iseq
        && depth <= MAX_NEST_DEPTH
    {
        let block_ctx: DecompileContext<'_> = ctx.nested_in(enclosing);
        let pad: String = indent(depth);
        emit_stmt(stmts, depth, "END {".to_owned());
        stmts.extend(render_iseq_statements(block, &block_ctx, depth + 1));
        stmts.push(format!("{pad}}}"));
        push(stack, "nil".to_owned());
        return;
    }
    let stabby: bool = recv == VMCORE && method == "lambda" && args.is_empty();
    let recv: String = if recv == VMCORE {
        "self".to_owned()
    } else {
        recv
    };
    let call: String = render_method_call(&recv, &method, &args);

    match block_iseq {
        Some(block) if depth <= MAX_NEST_DEPTH => {
            let block_ctx: DecompileContext<'_> = ctx.nested_in(enclosing);
            let mut block_lines: Vec<String> = render_block_lines(block, &block_ctx, depth);
            if stabby && let Some(header) = block_lines.first_mut() {
                *header = stabby_header(header);
                let body: String = if block_lines.len() <= 1 {
                    block_lines.concat()
                } else {
                    block_call_expression("", &block_lines, depth)
                        .trim_start()
                        .to_owned()
                };
                push(stack, format!("->{body}"));
                return;
            }
            if block_lines.len() <= 1 {
                let inline: String = block_lines.first().map_or_else(
                    || format!("{call} {{ }}"),
                    |single| format!("{call} {single}"),
                );
                push(stack, inline);
            } else {
                push(stack, block_call_expression(&call, &block_lines, depth));
            }
        }
        _ => push(stack, call),
    }
}

fn stabby_header(header: &str) -> String {
    let (opener, rest): (&str, &str) = if let Some(rest) = header.strip_prefix("{ |") {
        ("{", rest)
    } else if let Some(rest) = header.strip_prefix("do |") {
        ("do", rest)
    } else {
        return format!(" {header}");
    };
    match rest.split_once('|') {
        Some((params, body)) => format!("({params}) {opener}{body}"),
        None => format!(" {header}"),
    }
}

fn destructured_block_params(block: &YarvIseqBody) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    let mut i: usize = 0;
    while let [get, expand, ..] = &block.instructions[i..] {
        if get.mnemonic != "getlocal_WC_0" || expand.mnemonic != "expandarray" {
            break;
        }
        let count: usize = operand_count(expand, 0);
        if count < 2 || operand_num(expand, 1) != 0 {
            break;
        }
        let slot: u64 = operand_num(get, 0);
        let anonymous: String = local_name(&block.local_table, slot);
        let sets: Option<&[YarvIbfInstruction]> = block.instructions.get(i + 2..i + 2 + count);
        let Some(sets) = sets.filter(|sets| sets.iter().all(|s| s.mnemonic == "setlocal_WC_0"))
        else {
            break;
        };
        let targets: Vec<String> = sets
            .iter()
            .map(|s| local_name(&block.local_table, operand_num(s, 0)))
            .collect();
        if targets
            .iter()
            .any(|name| !is_identifier(name) || name.starts_with("local"))
        {
            break;
        }
        found.push((anonymous, targets.join(", ")));
        i += 2 + count;
    }
    found
}

fn apply_destructured_params(
    params: String,
    inner: Vec<String>,
    destructured: &[(String, String)],
) -> (String, Vec<String>) {
    let mut params: String = params;
    let mut inner: Vec<String> = inner;
    for (anonymous, targets) in destructured {
        let assignment: String = format!("{targets} = {anonymous}");
        let Some(first) = inner.iter().position(|l| !l.trim().is_empty()) else {
            break;
        };
        if inner[first].trim() != assignment {
            break;
        }
        let pattern: String = format!("({targets})");
        let replaced: String = params
            .split(", ")
            .map(|piece| {
                let bare: &str = piece.trim_start_matches(" |").trim_end_matches('|');
                if bare == anonymous {
                    piece.replacen(anonymous.as_str(), &pattern, 1)
                } else {
                    piece.to_owned()
                }
            })
            .collect::<Vec<String>>()
            .join(", ");
        if replaced == params {
            break;
        }
        params = replaced;
        inner.remove(first);
    }
    (params, inner)
}

fn render_block_lines(block: &YarvIseqBody, ctx: &DecompileContext<'_>, depth: u32) -> Vec<String> {
    let destructured: Vec<(String, String)> = destructured_block_params(block);
    let (params, inner): (String, Vec<String>) = apply_destructured_params(
        block_param_list(block, ctx),
        render_iseq_statements(block, ctx, depth.saturating_add(1)),
        &destructured,
    );
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
    let (_, deeper): (String, Vec<String>) = apply_destructured_params(
        block_param_list(block, ctx),
        render_iseq_statements(block, ctx, depth + 1),
        &destructured,
    );
    let mut lines: Vec<String> = Vec::with_capacity(deeper.len() + 2);
    lines.push(format!("do{params}"));
    lines.extend(deeper);
    lines
}

fn block_call_expression(call: &str, block_lines: &[String], depth: u32) -> String {
    let pad: String = indent(depth);
    let mut out: String = String::new();
    if let Some(header) = block_lines.first() {
        out.push_str(call);
        out.push(' ');
        out.push_str(header);
    }
    for line in &block_lines[1..] {
        out.push('\n');
        out.push_str(line);
    }
    out.push('\n');
    out.push_str(&pad);
    out.push_str("end");
    out
}

fn name_keyword_arguments(args: &mut [String], kwargs: &[String]) {
    let Some(first): Option<usize> = args.len().checked_sub(kwargs.len()) else {
        return;
    };
    if kwargs.is_empty() || kwargs.iter().any(String::is_empty) {
        return;
    }
    for (slot, name) in args[first..].iter_mut().zip(kwargs) {
        *slot = format!("{}: {slot}", keyword_label(name));
    }
}

fn keyword_label(name: &str) -> String {
    let plain: bool = name
        .strip_suffix(['?', '!'])
        .unwrap_or(name)
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_');
    if plain {
        name.to_owned()
    } else {
        format!("\"{name}\"")
    }
}

fn block_param_list(block: &YarvIseqBody, ctx: &DecompileContext<'_>) -> String {
    let lead: &[Option<String>] = block
        .local_table
        .get(..block.param_lead_num as usize)
        .unwrap_or(&[]);
    let numbered: bool = !lead.is_empty()
        && block.param_flags
            & (PARAM_FLAG_HAS_OPT
                | PARAM_FLAG_HAS_REST
                | PARAM_FLAG_HAS_POST
                | PARAM_FLAG_HAS_KW
                | PARAM_FLAG_HAS_KWREST
                | PARAM_FLAG_HAS_BLOCK)
            == 0
        && lead
            .iter()
            .enumerate()
            .all(|(i, name)| name.as_deref() == Some(format!("_{}", i + 1).as_str()));
    if numbered {
        return String::new();
    }
    let signature: String = render_param_signature(block, ctx);
    let destructured: Vec<(String, String)> = destructured_block_params(block);
    let shadowed: Vec<&str> = block
        .local_table
        .iter()
        .skip(block.param_size as usize)
        .filter_map(Option::as_deref)
        .filter(|name: &&str| {
            is_identifier(name)
                && !destructured
                    .iter()
                    .any(|(_, targets)| targets.split(", ").any(|target: &str| target == *name))
                && ctx
                    .enclosing_scopes
                    .iter()
                    .any(|scope| scope.iter().any(|outer| outer.as_deref() == Some(*name)))
        })
        .collect();
    let inner: &str = signature
        .strip_prefix('(')
        .and_then(|s: &str| s.strip_suffix(')'))
        .unwrap_or("");
    match (inner.is_empty(), shadowed.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(" |{inner}|"),
        (_, false) => format!(" |{inner}; {}|", shadowed.join(", ")),
    }
}

fn is_forward_marker(s: &str) -> bool {
    matches!(s, "..." | "*" | "**" | "&") || s.starts_with("...")
}

fn mark_splatted_arguments(args: &mut [String], flags: u32, keyword_count: usize) {
    let kw_splat: bool = flags & VM_CALL_KW_SPLAT != 0;
    if kw_splat
        && let Some(slot) = args.last_mut()
        && !slot.starts_with("**")
    {
        *slot = format!("**{slot}");
    }
    let positional: usize = args
        .len()
        .saturating_sub(keyword_count + usize::from(kw_splat));
    if flags & VM_CALL_ARGS_SPLAT != 0
        && positional > 0
        && let Some(slot) = args.get_mut(positional - 1)
        && !slot.starts_with('*')
    {
        *slot = format!("*{slot}");
    }
}

fn emit_super(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let (argc, flags, kwargs): (usize, u32, &[String]) = match instr.operands.first() {
        Some(YarvOperand::Call {
            argc,
            flags,
            kwargs,
            ..
        }) => (call_arg_count(*argc), *flags, kwargs.as_slice()),
        _ => (0, 0, &[]),
    };
    let block_arg: Option<String> = (flags & VM_CALL_ARGS_BLOCKARG != 0).then(|| pop(stack));
    let mut args: Vec<String> = pop_n(stack, argc);
    if flags & VM_CALL_ZSUPER != 0 {
        let _receiver: String = pop(stack);
        push(
            stack,
            block_arg.map_or_else(|| "super".to_owned(), |blk| format!("super(&{blk})")),
        );
        return;
    }
    name_keyword_arguments(&mut args, kwargs);
    mark_splatted_arguments(&mut args, flags, kwargs.len());
    if let Some(blk) = block_arg {
        args.push(if blk.starts_with('&') {
            blk
        } else {
            format!("&{blk}")
        });
    }
    let _ = pop(stack);
    if args.is_empty() || args.iter().any(|a| is_forward_marker(a) || a.is_empty()) {
        push(stack, "super".to_owned());
    } else {
        push(stack, format!("super({})", args.join(", ")));
    }
}

fn emit_invokeblock(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let argc: usize = match instr.operands.first() {
        Some(YarvOperand::Call { argc, .. }) => call_arg_count(*argc),
        _ => 0,
    };
    let args: Vec<String> = pop_n(stack, argc);
    if args.is_empty() {
        push(stack, "yield".to_owned());
    } else {
        push(stack, format!("yield({})", args.join(", ")));
    }
}

fn emit_newarray_send(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let count: usize = operand_count(instr, 0);
    let kind: u64 = operand_num(instr, 1);
    let mut elems: Vec<String> = pop_n(stack, count);
    let resolved: Option<(&str, usize)> = match kind {
        1 => Some(("max", 0)),
        2 => Some(("min", 0)),
        3 => Some(("hash", 0)),
        4 => Some(("pack", 1)),
        6 => Some(("include?", 1)),
        _ => None,
    };
    let Some((method, trailing_args)): Option<(&str, usize)> = resolved else {
        push(stack, format!("[{}]", elems.join(", ")));
        return;
    };
    let call_args: Vec<String> = if trailing_args > 0 && elems.len() >= trailing_args {
        elems.split_off(elems.len() - trailing_args)
    } else {
        Vec::new()
    };
    let array: String = format!("[{}]", elems.join(", "));
    push(stack, render_method_call(&array, method, &call_args));
}

fn emit_unary_call(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let method: String = match instr.operands.first() {
        Some(YarvOperand::Call { method, .. }) => method.clone(),
        _ => return,
    };
    let recv: String = pop(stack);
    push(stack, render_method_call(&recv, &method, &[]));
}

const SELF_QUALIFIED_KEYWORDS: &[&str] = &[
    "class", "begin", "end", "do", "then", "case", "while", "until", "if", "unless", "def",
    "module", "return", "yield", "next", "break", "redo", "retry", "super", "self", "nil", "true",
    "false", "and", "or", "not", "in", "for", "ensure", "rescue", "raise",
];

const VMCORE: &str = "\u{0}vmcore";
const CBASE: &str = "\u{0}cbase";

enum VmcoreCall {
    Value(String),
    Statement(String),
}

fn symbol_name(rendered: &str) -> Option<&str> {
    rendered.strip_prefix(':').filter(|s: &&str| !s.is_empty())
}

fn render_vmcore_call(method: &str, args: &[String], has_block: bool) -> Option<VmcoreCall> {
    match (method, args) {
        ("lambda", []) if has_block => Some(VmcoreCall::Value("lambda".to_owned())),
        ("core#hash_merge_ptr", [hash, pairs @ ..]) if pairs.len() % 2 == 0 => {
            let rendered: Vec<String> = pairs
                .chunks(2)
                .map(|kv: &[String]| format!("{} => {}", kv[0], kv[1]))
                .collect();
            let merged: String = match hash.strip_suffix('}') {
                Some(open) if open.trim_end().ends_with('{') => {
                    format!("{{ {} }}", rendered.join(", "))
                }
                Some(open) if hash.starts_with('{') => {
                    format!("{}, {} }}", open.trim_end(), rendered.join(", "))
                }
                _ => format!("{{ **{hash}, {} }}", rendered.join(", ")),
            };
            Some(VmcoreCall::Value(merged))
        }
        ("core#hash_merge_kwd", [lhs, rhs]) => {
            Some(VmcoreCall::Value(format!("{{ **{lhs}, **{rhs} }}")))
        }
        ("core#set_method_alias", [_, new, old]) | ("core#set_variable_alias", [new, old]) => Some(
            VmcoreCall::Statement(format!("alias {} {}", symbol_name(new)?, symbol_name(old)?)),
        ),
        ("core#undef_method", [_, name]) => Some(VmcoreCall::Statement(format!(
            "undef {}",
            symbol_name(name)?
        ))),
        _ => None,
    }
}

fn needs_receiver_parens(recv: &str) -> bool {
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut escaped: bool = false;
    for c in recv.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ' ' | '\n' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

fn render_method_call(recv: &str, method: &str, args: &[String]) -> String {
    let method: &str = sanitize_method(method);
    if let [arg] = args
        && !arg.is_empty()
        && !recv.is_empty()
        && recv != "self"
        && !is_forward_marker(recv)
        && matches!(method, "<=>" | "**" | "===" | "=~" | "!~" | "^" | ">>")
        && let Some(parent) = ruby_binop_precedence(method)
    {
        let lhs: String = if recv.starts_with('-') {
            format!("({recv})")
        } else {
            parenthesize_operand(recv.to_owned(), parent, false)
        };
        let rhs: String = parenthesize_operand(arg.clone(), parent, true);
        return format!("{lhs} {method} {rhs}");
    }
    let prefix: String = if (recv == "self" && !SELF_QUALIFIED_KEYWORDS.contains(&method))
        || recv.is_empty()
        || is_forward_marker(recv)
    {
        String::new()
    } else if needs_receiver_parens(recv) {
        format!("({recv}).")
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

fn sanitize_method(method: &str) -> &str {
    match method {
        "(call)" | "" => "call",
        other => other,
    }
}

fn emit_binop(_instr: &YarvIbfInstruction, stack: &mut Vec<String>, op: &str) {
    let rhs: String = pop(stack);
    let lhs: String = pop(stack);
    let parent: u8 = ruby_binop_precedence(op).unwrap_or(0);
    let lhs: String = parenthesize_operand(lhs, parent, false);
    let rhs: String = parenthesize_operand(rhs, parent, true);
    push(stack, format!("{lhs} {op} {rhs}"));
}

fn parenthesize_operand(expr: String, parent_prec: u8, is_right: bool) -> String {
    let Some(child): Option<u8> = top_level_binop_precedence(&expr) else {
        return expr;
    };
    let non_associative: bool = parent_prec == ruby_binop_precedence("==").unwrap_or(0);
    let right_associative: bool = parent_prec == ruby_binop_precedence("**").unwrap_or(0);
    let wrap: bool = match child.cmp(&parent_prec) {
        core::cmp::Ordering::Less => true,
        core::cmp::Ordering::Greater => false,
        core::cmp::Ordering::Equal => non_associative || (is_right != right_associative),
    };
    if wrap { format!("({expr})") } else { expr }
}

fn ruby_binop_precedence(op: &str) -> Option<u8> {
    let prec: u8 = match op {
        "**" => 12,
        "*" | "/" | "%" => 10,
        "+" | "-" => 9,
        "<<" | ">>" => 8,
        "&" => 7,
        "|" | "^" => 6,
        "<" | "<=" | ">" | ">=" => 5,
        "<=>" | "==" | "===" | "!=" | "=~" | "!~" => 4,
        "&&" => 3,
        "||" => 2,
        ".." | "..." => 1,
        _ => return None,
    };
    Some(prec)
}

fn top_level_binop_precedence(expr: &str) -> Option<u8> {
    let bytes: &[u8] = expr.as_bytes();
    let len: usize = bytes.len();
    let mut depth: i32 = 0;
    let mut string_quote: Option<u8> = None;
    let mut min_prec: Option<u8> = None;
    let mut i: usize = 0;
    while i < len {
        let b: u8 = bytes[i];
        if let Some(quote) = string_quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == quote {
                string_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => string_quote = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b' ' if depth == 0 => {
                if let Some((prec, op_len)) = spaced_operator_at(bytes, i) {
                    min_prec = Some(min_prec.map_or(prec, |current: u8| current.min(prec)));
                    i += 1 + op_len;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    min_prec
}

fn spaced_operator_at(bytes: &[u8], space_idx: usize) -> Option<(u8, usize)> {
    const OPERATORS: &[(&str, u8)] = &[
        ("||=", 0),
        ("&&=", 0),
        ("<<=", 0),
        (">>=", 0),
        ("**=", 0),
        ("+=", 0),
        ("-=", 0),
        ("*=", 0),
        ("/=", 0),
        ("%=", 0),
        ("|=", 0),
        ("&=", 0),
        ("^=", 0),
        ("=", 0),
        ("?", 0),
        (":", 0),
        ("<=>", 4),
        ("===", 4),
        ("...", 1),
        ("**", 12),
        ("<<", 8),
        (">>", 8),
        ("<=", 5),
        (">=", 5),
        ("==", 4),
        ("!=", 4),
        ("=~", 4),
        ("&&", 3),
        ("||", 2),
        ("..", 1),
        ("+", 9),
        ("-", 9),
        ("*", 10),
        ("/", 10),
        ("%", 10),
        ("&", 7),
        ("|", 6),
        ("^", 6),
        ("<", 5),
        (">", 5),
    ];
    let start: usize = space_idx + 1;
    for (op, prec) in OPERATORS {
        let op_bytes: &[u8] = op.as_bytes();
        let end: usize = start + op_bytes.len();
        if end < bytes.len() && &bytes[start..end] == op_bytes && bytes[end] == b' ' {
            return Some((*prec, op_bytes.len()));
        }
    }
    None
}

fn is_effecting_call(expr: &str) -> bool {
    expr.contains('(')
        || expr.contains('.')
        || expr.contains('{')
        || expr.contains(" = ")
        || expr.contains(" << ")
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
    let bounded: usize = n.min(MAX_OPERAND_COUNT);
    let take: usize = bounded.min(stack.len());
    let mut out: Vec<String> = stack.split_off(stack.len() - take);
    if out.len() < bounded {
        let mut pad: Vec<String> = vec!["_".to_owned(); bounded - out.len()];
        pad.append(&mut out);
        out = pad;
    }
    out
}

const DEFINED_CONST: u64 = 6;
const DEFINED_METHOD: u64 = 7;
const DEFINED_YIELD: u64 = 8;
const DEFINED_ZSUPER: u64 = 9;
const DEFINED_CONST_FROM: u64 = 17;

fn defined_operand(instr: &YarvIbfInstruction) -> String {
    let raw: String = match instr.operands.get(1) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s) | YarvOperand::SymLiteral(s)) => {
            s.clone()
        }
        Some(YarvOperand::NumLiteral(s)) if s == "false" => "yield".to_owned(),
        _ => return "x".to_owned(),
    };
    raw.strip_prefix(':').unwrap_or(&raw).to_owned()
}

fn getspecial_name(instr: &YarvIbfInstruction) -> String {
    let key: u64 = operand_num(instr, 1);
    if key == 0 {
        return "$~".to_owned();
    }
    if key & 1 == 1 {
        let ch: u8 = u8::try_from(key >> 1).unwrap_or(0);
        return format!("${}", char::from(ch));
    }
    format!("${}", key >> 1)
}

fn operand_value(instr: &YarvIbfInstruction, idx: usize) -> String {
    instr
        .operands
        .get(idx)
        .map_or_else(|| "_".to_owned(), render_operand)
}

fn render_operand(operand: &YarvOperand) -> String {
    match operand {
        YarvOperand::Literal(s) | YarvOperand::StrLiteral(s) => ruby_string_literal(s),
        YarvOperand::SymLiteral(s) => format!(":{}", symbol_literal(s)),
        YarvOperand::NumLiteral(s) => s.clone(),
        YarvOperand::Id(s) => format!(":{s}"),
        YarvOperand::ObjectRef(i) => format!("obj[{i}]"),
        YarvOperand::IseqRef(i) => format!("iseq[{i}]"),
        YarvOperand::Num(n) => n.to_string(),
        YarvOperand::Offset(o) => format!("->{o}"),
        YarvOperand::Builtin(b) => format!("<builtin {b}>"),
        YarvOperand::Call { method, .. } => format!(":{method}"),
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

fn operand_count(instr: &YarvIbfInstruction, idx: usize) -> usize {
    bounded_count(operand_num(instr, idx))
}

const fn call_arg_count(argc: u32) -> usize {
    bounded_count(argc as u64)
}

const fn bounded_count(value: u64) -> usize {
    if value > MAX_OPERAND_COUNT as u64 {
        MAX_OPERAND_COUNT
    } else {
        value as usize
    }
}

fn id_or_index(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => s.clone(),
        Some(YarvOperand::ObjectRef(i)) => format!("Const{i}"),
        _ => "_".to_owned(),
    }
}

fn ivar_name(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) if s.starts_with('@') => s.clone(),
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => format!("@{s}"),
        _ => "@ivar".to_owned(),
    }
}

fn cvar_name(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) if s.starts_with("@@") => s.clone(),
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => {
            format!("@@{}", s.trim_start_matches('@'))
        }
        _ => "@@cvar".to_owned(),
    }
}

fn push_fmt_line(out: &mut String, args: core::fmt::Arguments<'_>) {
    match core::fmt::write(out, args) {
        Ok(()) => out.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

fn push_section(out: &mut String, title: &str, items: &[String]) {
    push_fmt_line(out, format_args!("# {} ({}):", title, items.len()));
    for item in items {
        push_fmt_line(out, format_args!("#   {item:?}"));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::literal_string_with_formatting_args)]
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

    fn empty_image() -> IbfImage {
        IbfImage {
            iseq_offsets: Vec::new(),
            objects: Vec::new(),
            iseqs: Vec::new(),
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        }
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

    fn synthetic_body(instructions: Vec<YarvIbfInstruction>) -> YarvIseqBody {
        YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: u32::try_from(instructions.len()).unwrap_or(u32::MAX),
            instructions,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
        }
    }

    #[test]
    fn huge_stack_count_does_not_allocate_placeholders() {
        let body: YarvIseqBody =
            synthetic_body(vec![instr("adjuststack", vec![YarvOperand::Num(u64::MAX)])]);
        let stmts: Vec<String> = decompile_body(&body);
        assert!(stmts.is_empty());
    }

    #[test]
    fn huge_expandarray_count_does_not_overflow_massign() {
        let body: YarvIseqBody = synthetic_body(vec![
            instr("putobject", vec![YarvOperand::StrLiteral("x".to_owned())]),
            instr(
                "expandarray",
                vec![YarvOperand::Num(u64::MAX), YarvOperand::Num(1)],
            ),
        ]);
        let stmts: Vec<String> = decompile_body(&body);
        assert!(stmts.is_empty());
    }

    #[test]
    fn catch_table_rescue_wraps_protected_range_in_begin_rescue_end() {
        let parent: YarvIseqBody = YarvIseqBody {
            param_opt_table: Vec::new(),
            param_keyword: None,
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("a".to_owned()), Some("b".to_owned())],
            param_lead_num: 2,
            param_size: 2,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
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
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "opt_getconstant_path",
                    vec![YarvOperand::Id("ZeroDivisionError".to_owned())],
                ),
                instr("checkmatch", vec![YarvOperand::Num(3)]),
                instr("branchunless", vec![YarvOperand::Offset(2)]),
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
    fn rescue_clause_recovers_class_and_bound_variable_to_parent_scope() {
        let parent: YarvIseqBody = YarvIseqBody {
            param_opt_table: Vec::new(),
            param_keyword: None,
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![
                Some("a".to_owned()),
                Some("b".to_owned()),
                Some("e".to_owned()),
            ],
            param_lead_num: 2,
            param_size: 2,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: vec![YarvCatchEntry {
                catch_type: CatchType::Rescue,
                start_pc: 0,
                end_pc: 5,
                cont_pc: 6,
                handler_iseq: Some(1),
            }],
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(5)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(4)]),
                instr(
                    "opt_div",
                    vec![YarvOperand::Call {
                        method: "/".to_owned(),
                        argc: 1,
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "opt_getconstant_path",
                    vec![YarvOperand::Id("ZeroDivisionError".to_owned())],
                ),
                instr("checkmatch", vec![YarvOperand::Num(3)]),
                instr("branchunless", vec![YarvOperand::Offset(9)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("setlocal_WC_1", vec![YarvOperand::Num(3)]),
                instr("getlocal_WC_1", vec![YarvOperand::Num(3)]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "message".to_owned(),
                        argc: 0,
                        flags: 0,
                        kwargs: Vec::new(),
                    }],
                ),
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
        assert!(
            stmts.iter().any(|s| s == "rescue ZeroDivisionError => e"),
            "stmts: {stmts:?}"
        );
        assert!(
            stmts.iter().any(|s| s.contains("e.message")),
            "stmts: {stmts:?}"
        );
        assert!(
            !stmts.iter().any(|s| s.contains("$!")),
            "no raw implicit exception global should leak: {stmts:?}"
        );
    }

    #[test]
    fn ivar_or_assign_folds_to_compound_assignment() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
    fn class_variable_read_and_write_recover() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr(
                    "getclassvariable",
                    vec![YarvOperand::Id("@@count".to_owned()), YarvOperand::Num(0)],
                ),
                instr("putobject_INT2FIX_1_", vec![]),
                instr(
                    "opt_plus",
                    vec![YarvOperand::Call {
                        method: "+".to_owned(),
                        argc: 1,
                        flags: 0,
                        kwargs: Vec::new(),
                    }],
                ),
                instr(
                    "setclassvariable",
                    vec![YarvOperand::Id("@@count".to_owned()), YarvOperand::Num(0)],
                ),
                instr(
                    "getclassvariable",
                    vec![YarvOperand::Id("@@count".to_owned()), YarvOperand::Num(0)],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "@@count = @@count + 1"),
            "stmts: {stmts:?}"
        );
        assert!(stmts.iter().any(|s| s == "@@count"), "stmts: {stmts:?}");
    }

    #[test]
    fn class_variable_assignment_from_literal_recovers() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("newarray", vec![YarvOperand::Num(0)]),
                instr(
                    "setclassvariable",
                    vec![YarvOperand::Id("@@items".to_owned()), YarvOperand::Num(0)],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert_eq!(stmts, vec!["@@items = []".to_owned()], "stmts: {stmts:?}");
    }

    #[test]
    fn scalar_and_assign_without_dup_folds_to_compound_assignment() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("total".to_owned())],
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("branchunless", vec![YarvOperand::Offset(4)]),
                instr("putobject", vec![YarvOperand::Num(20)]),
                instr("setlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "total &&= 20"),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn aref_plus_assign_folds_to_compound_index_assignment() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("hits".to_owned())],
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("putobject", vec![YarvOperand::Id("n".to_owned())]),
                instr("dupn", vec![YarvOperand::Num(2)]),
                instr(
                    "opt_aref",
                    vec![YarvOperand::Call {
                        method: "[]".to_owned(),
                        argc: 1,
                        flags: 0,
                        kwargs: Vec::new(),
                    }],
                ),
                instr("putobject", vec![YarvOperand::Num(4)]),
                instr(
                    "opt_plus",
                    vec![YarvOperand::Call {
                        method: "+".to_owned(),
                        argc: 1,
                        flags: 0,
                        kwargs: Vec::new(),
                    }],
                ),
                instr(
                    "opt_aset",
                    vec![YarvOperand::Call {
                        method: "[]=".to_owned(),
                        argc: 2,
                        flags: 0,
                        kwargs: Vec::new(),
                    }],
                ),
                instr("pop", vec![]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "hits[:n] += 4"),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn attr_or_assign_folds_to_compound_setter_assignment() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("node".to_owned())],
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("dup", vec![]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "value".to_owned(),
                        argc: 0,
                        flags: 0,
                        kwargs: Vec::new(),
                    }],
                ),
                instr("branchif", vec![YarvOperand::Offset(4)]),
                instr("putobject", vec![YarvOperand::Num(99)]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "value=".to_owned(),
                        argc: 1,
                        flags: 0,
                        kwargs: Vec::new(),
                    }],
                ),
                instr("pop", vec![]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "node.value ||= 99"),
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
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
                        flags: 0,
                        kwargs: Vec::new(),
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
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
                        flags: 0,
                        kwargs: Vec::new(),
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
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 2,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
            param_size: 2,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("dup", vec![]),
                instr("branchnil", vec![YarvOperand::Offset(2)]),
                instr(
                    "opt_size",
                    vec![YarvOperand::Call {
                        method: "size".to_owned(),
                        argc: 0,
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
                        flags: 0,
                        kwargs: Vec::new(),
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
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("putobject_INT2FIX_0_", vec![]),
                instr(
                    "opt_gt",
                    vec![YarvOperand::Call {
                        method: ">".to_owned(),
                        argc: 1,
                        flags: 0,
                        kwargs: Vec::new(),
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
    fn interpolation_of_expression_parts_stays_an_interpolation() {
        let parts: Vec<String> = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(render_interpolation(&parts), "\"#{a}#{b}\"");
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
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
                        flags: 0,
                        kwargs: Vec::new(),
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
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: Vec::new(),
        };
        let main: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 2,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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
            param_size: 2,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: Vec::new(),
        };
        assert_eq!(
            block_param_list(&with_params, &DecompileContext::from_image(&empty_image())),
            " |x, y|"
        );
        let no_params: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: Vec::new(),
        };
        assert_eq!(
            block_param_list(&no_params, &DecompileContext::from_image(&empty_image())),
            ""
        );
    }

    #[test]
    fn send_with_block_iseq_renders_block_params() {
        let block_body: YarvIseqBody = YarvIseqBody {
            index: 1,
            offset: 0,
            iseq_size: 0,
            local_table: vec![Some("n".to_owned())],
            param_lead_num: 1,
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: Vec::new(),
        };
        let main: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 3,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "each".to_owned(),
                            argc: 0,
                            flags: 0,
                            kwargs: Vec::new(),
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
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "map".to_owned(),
                            argc: 0,
                            flags: 0,
                            kwargs: Vec::new(),
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
    fn self_referential_block_iseq_terminates() {
        let main: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 3,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "each".to_owned(),
                            argc: 0,
                            flags: 0,
                            kwargs: Vec::new(),
                        },
                        YarvOperand::IseqRef(0),
                    ],
                ),
                instr("leave", vec![]),
            ],
        };
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects: Vec::new(),
            iseqs: vec![main.clone()],
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        let stmts: Vec<String> = decompile_in_image(&main, &image);
        assert!(stmts.len() < 4096, "stmts: {stmts:?}");
    }

    #[test]
    fn self_referential_lambda_block_iseq_terminates() {
        let main: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 3,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "lambda".to_owned(),
                            argc: 0,
                            flags: 0,
                            kwargs: Vec::new(),
                        },
                        YarvOperand::IseqRef(0),
                    ],
                ),
                instr("leave", vec![]),
            ],
        };
        let image: IbfImage = IbfImage {
            iseq_offsets: Vec::new(),
            objects: Vec::new(),
            iseqs: vec![main.clone()],
            recovered_literal_count: 0,
            recovered_instruction_count: 0,
        };
        let ctx: DecompileContext<'_> = DecompileContext::from_image(&image);
        let _: Option<String> =
            super::parse_lambda_pattern(&main, &ctx, 0, 0, main.instructions.len());
    }

    #[test]
    fn surfaces_binary_op() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 4,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
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

    #[test]
    fn resolve_branch_targets_hand_checked_chain() {
        let forward: YarvIseqBody = synthetic_body(vec![
            instr("jump", vec![YarvOperand::Offset(0)]),
            instr("jump", vec![YarvOperand::Offset(0)]),
            instr("jump", vec![YarvOperand::Offset(0)]),
        ]);
        let forward_targets: Vec<Option<usize>> = resolve_branch_targets(&forward);
        assert_eq!(forward_targets, vec![Some(1), Some(2), None]);

        let backward: YarvIseqBody = synthetic_body(vec![
            instr("jump", vec![YarvOperand::Offset(0)]),
            instr("jump", vec![YarvOperand::Offset((-4i32) as u32)]),
        ]);
        let backward_targets: Vec<Option<usize>> = resolve_branch_targets(&backward);
        assert_eq!(backward_targets, vec![Some(1), Some(0)]);
    }

    #[test]
    fn resolve_branch_targets_scales_over_many_branches() {
        let count: usize = 100_000;
        let instructions: Vec<YarvIbfInstruction> = (0..count)
            .map(|_| instr("jump", vec![YarvOperand::Offset(0)]))
            .collect();
        let body: YarvIseqBody = synthetic_body(instructions);
        let start: std::time::Instant = std::time::Instant::now();
        let targets: Vec<Option<usize>> = resolve_branch_targets(&body);
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "resolve_branch_targets took {elapsed:?} for {count} branches"
        );
        assert_eq!(targets.len(), count);
        assert_eq!(targets[0], Some(1));
        assert_eq!(targets[count - 1], None);
    }

    #[test]
    fn body_has_pattern_construct_flags_pattern_opcodes() {
        let plain: YarvIseqBody =
            synthetic_body(vec![instr("pop", vec![]), instr("putnil", vec![])]);
        assert!(!body_has_pattern_construct(&plain));

        let checkmatch_body: YarvIseqBody =
            synthetic_body(vec![instr("checkmatch", vec![YarvOperand::Num(2)])]);
        assert!(body_has_pattern_construct(&checkmatch_body));

        let deconstruct_body: YarvIseqBody =
            synthetic_body(vec![instr("checktype", vec![YarvOperand::Num(T_ARRAY)])]);
        assert!(body_has_pattern_construct(&deconstruct_body));

        let checktype_other: YarvIseqBody =
            synthetic_body(vec![instr("checktype", vec![YarvOperand::Num(1)])]);
        assert!(!body_has_pattern_construct(&checktype_other));
    }

    #[test]
    fn find_case_in_region_is_none_without_pattern_opcodes() {
        let body: YarvIseqBody = synthetic_body(vec![
            instr("putnil", vec![]),
            instr("pop", vec![]),
            instr("putself", vec![]),
            instr("leave", vec![]),
        ]);
        let targets: Vec<Option<usize>> = resolve_branch_targets(&body);
        let n: usize = body.instructions.len();
        for i in 0..n {
            assert!(find_case_in_region(&body, i, n, &targets).is_none());
        }
    }

    #[test]
    fn large_non_pattern_body_decompiles_fast() {
        let count: usize = 120_000;
        let instructions: Vec<YarvIbfInstruction> =
            (0..count).map(|_| instr("pop", vec![])).collect();
        let body: YarvIseqBody = synthetic_body(instructions);
        let start: std::time::Instant = std::time::Instant::now();
        let stmts: Vec<String> = decompile_body(&body);
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "decompile took {elapsed:?} for {count} instructions"
        );
        assert!(stmts.is_empty(), "stmts: {stmts:?}");
    }

    #[test]
    fn small_normal_body_still_decompiles_to_expected_source() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 0,
            local_table: Vec::new(),
            param_lead_num: 0,
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
            param_opt_table: Vec::new(),
            param_keyword: None,
            instructions: vec![
                instr("newarray", vec![YarvOperand::Num(0)]),
                instr(
                    "setclassvariable",
                    vec![YarvOperand::Id("@@items".to_owned()), YarvOperand::Num(0)],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert_eq!(stmts, vec!["@@items = []".to_owned()], "stmts: {stmts:?}");
    }
}
