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
const VM_CALL_ARGS_BLOCKARG: u32 = 1 << 1;
const VM_CALL_KW_SPLAT: u32 = 1 << 6;

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
    let start: usize = if body.param_flags & PARAM_FLAG_HAS_KW != 0 {
        keyword_default_prologue(body, ctx).1
    } else {
        0
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
        lines.extend(render_rescue_handler(
            handler,
            &body.local_table,
            ctx,
            depth,
        ));
    }
    if let Some(handler_idx) = ensure.and_then(|e| e.handler_iseq)
        && let Some(handler) = ctx.body(handler_idx)
    {
        lines.push(format!("{pad}ensure"));
        lines.extend(render_iseq_statements(handler, ctx, depth + 1));
    }
    lines.push(format!("{pad}end"));

    let suffix_start: usize = ensure.map_or(end, |entry| {
        index_at_pc(&rt_pc, entry.cont_pc)
            .max(end)
            .min(body.instructions.len())
    });
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
            let keyword: &str = if m == "branchunless" { "if" } else { "unless" };
            let cond: String = pop(stack);
            render_conditional(
                body, ctx, depth, i, target, hi, keyword, &cond, targets, stmts,
            );
            i = region_end_after_conditional(body, target, hi, targets);
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
        step(instr, &body.local_table, ctx, depth, stack, stmts);
        i += 1;
    }
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
    let n: usize = operand_count(&body.instructions[i], 0);
    let has_splat: bool = operand_num(&body.instructions[i], 1) & 1 == 1;
    let total: usize = n
        .saturating_add(usize::from(has_splat))
        .min(MAX_OPERAND_COUNT);
    if total == 0 {
        return None;
    }
    let mut targets: Vec<String> = Vec::with_capacity(total);
    let mut j: usize = i + 1;
    while targets.len() < total && j < hi {
        let target: String = assignment_target(&body.instructions[j], &body.local_table, ctx)?;
        if has_splat && targets.len() == n {
            targets.push(format!("*{target}"));
        } else {
            targets.push(target);
        }
        j += 1;
    }
    if targets.len() != total {
        return None;
    }
    let rhs_raw: String = pop(stack);
    let rhs: &str = rhs_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&rhs_raw);
    emit_stmt(stmts, depth, format!("{} = {rhs}", targets.join(", ")));
    Some(j)
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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
            parse_case_in_arm(body, ctx, depth, test_lo, success);
        arms.push(CaseInArm {
            pattern,
            guard,
            body_lo: arm_body.body_lo,
            body_hi: arm_body.body_hi,
        });
        test_lo = success + 1;
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
    let pattern: String =
        parse_pattern(body, ctx, depth, test_lo, pattern_end).unwrap_or_else(|| "_".to_owned());
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
        return Some(parse_array_or_find(body, checktype_idx + 1, hi));
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
    let value: String = pattern_value_region(body, ctx, lo, checkmatch);
    let trimmed: &str = value.trim();
    if trimmed.is_empty() || trimmed == "_" {
        return None;
    }
    Some(trimmed.to_owned())
}

fn parse_array_or_find(body: &YarvIseqBody, from: usize, hi: usize) -> String {
    if is_find_pattern(body, from, hi) {
        return parse_find(body, from, hi);
    }
    let is_splat: bool = (from..hi).any(|j| body.instructions[j].mnemonic == "opt_ge");
    let mut pre: Vec<String> = Vec::new();
    let mut post: Vec<String> = Vec::new();
    let mut splat: Option<String> = None;
    let mut j: usize = from;
    while j < hi {
        if body.instructions[j].mnemonic == "jump" {
            break;
        }
        if let Some((bind, next)) = read_element_bind(body, j) {
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
        elements.push(if rest == "_" {
            "*".to_owned()
        } else {
            format!("*{rest}")
        });
    } else if is_splat {
        elements.push("*".to_owned());
    }
    elements.extend(post);
    format!("[{}]", elements.join(", "))
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
                    read_hash_value_pattern(body, ctx, &key, j + 2);
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
) -> (String, usize) {
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
    if body
        .instructions
        .get(val_lo)
        .is_some_and(is_array_index_literal)
        && body
            .instructions
            .get(val_lo + 1)
            .is_some_and(|x| x.mnemonic == "checkmatch")
    {
        let value: String = literal_value_in(body, val_lo, val_lo + 1).unwrap_or_default();
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

fn begins_when_comparison(body: &YarvIseqBody, i: usize, hi: usize) -> bool {
    let topn: Option<usize> = (i..hi)
        .take(8)
        .find(|&j| body.instructions[j].mnemonic == "topn");
    let Some(t): Option<usize> = topn else {
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
    let branch_idx: usize = (init_target..hi).find(|&k| {
        matches!(
            body.instructions[k].mnemonic.as_str(),
            "branchif" | "branchunless"
        ) && targets[k].is_some_and(|t| t > i && t <= init_target)
    })?;
    let back_target: usize = targets[branch_idx]?;
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
        for body in &image.iseqs {
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
        | "opt_not" | "opt_regexpmatch2" => {
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
            push(stack, format!("{recv}[{idx}] = {val}"));
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
            let _ = pop(stack);
            let target: String = defined_operand(instr);
            push(stack, format!("defined?({target})"));
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
        "nop" | "putspecialobject" | "intern" | "tostring" | "putchilledstring_dummy" => {}
        _ => {}
    }
}

const THROW_TAG_RETURN: u64 = 1;
const THROW_TAG_BREAK: u64 = 2;
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

fn string_literal_body(s: &str) -> Option<&str> {
    let inner: &str = s.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"') || inner.contains('\\') || inner.contains("#{") {
        return None;
    }
    Some(inner)
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
const PARAM_FLAG_HAS_REST: u64 = 1 << 2;
const PARAM_FLAG_HAS_KW: u64 = 1 << 4;
const PARAM_FLAG_HAS_KWREST: u64 = 1 << 5;
const PARAM_FLAG_HAS_BLOCK: u64 = 1 << 6;

fn keyword_default_prologue(
    body: &YarvIseqBody,
    ctx: &DecompileContext<'_>,
) -> (Vec<(String, String)>, usize) {
    let targets: Vec<Option<usize>> = resolve_branch_targets(body);
    let mut defaults: Vec<(String, String)> = Vec::new();
    let mut i: usize = 0;
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
        keyword_default_prologue(body, ctx).0
    } else {
        Vec::new()
    };

    let mut params: Vec<String> = Vec::with_capacity(count);
    for idx in 0..count {
        let Some(name): Option<&str> = body.local_table.get(idx).and_then(Option::as_deref) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let rendered: String = if Some(idx) == rest_idx {
            format!("*{name}")
        } else if Some(idx) == block_idx {
            format!("&{name}")
        } else if Some(idx) == kwrest_idx {
            format!("**{name}")
        } else if has_opt && (opt_lo..opt_hi).contains(&idx) {
            format!("{name} = nil")
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
    let (method, argc, flags): (String, usize, u32) = match instr.operands.first() {
        Some(YarvOperand::Call {
            method,
            argc,
            flags,
        }) => (method.clone(), call_arg_count(*argc), *flags),
        Some(YarvOperand::Id(name)) => (name.clone(), 0, 0),
        _ => ("call".to_owned(), 0, 0),
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
    if flags & VM_CALL_KW_SPLAT != 0
        && let Some(slot) = args.last_mut()
        && !slot.starts_with("**")
        && !slot.starts_with('{')
    {
        *slot = format!("**{slot}");
    }
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
    let call: String = render_method_call(&recv, &method, &args);

    match block_iseq {
        Some(block) if depth <= MAX_NEST_DEPTH => {
            let block_ctx: DecompileContext<'_> = ctx.nested_in(enclosing);
            let block_lines: Vec<String> = render_block_lines(block, &block_ctx, depth);
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

fn render_block_lines(block: &YarvIseqBody, ctx: &DecompileContext<'_>, depth: u32) -> Vec<String> {
    let params: String = block_param_list(block);
    let inner: Vec<String> = render_iseq_statements(block, ctx, depth.saturating_add(1));
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

fn is_forward_marker(s: &str) -> bool {
    matches!(s, "..." | "*" | "**" | "&") || s.starts_with("...")
}

fn emit_super(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let (argc, flags): (usize, u32) = match instr.operands.first() {
        Some(YarvOperand::Call { argc, flags, .. }) => (call_arg_count(*argc), *flags),
        _ => (0, 0),
    };
    let block_arg: Option<String> = (flags & VM_CALL_ARGS_BLOCKARG != 0).then(|| pop(stack));
    let mut args: Vec<String> = pop_n(stack, argc);
    if flags & VM_CALL_KW_SPLAT != 0
        && let Some(slot) = args.last_mut()
        && !slot.starts_with("**")
        && !slot.starts_with('{')
    {
        *slot = format!("**{slot}");
    }
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
    match top_level_binop_precedence(&expr) {
        Some(child) if (is_right && child <= parent_prec) || (!is_right && child < parent_prec) => {
            format!("({expr})")
        }
        _ => expr,
    }
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

fn defined_operand(instr: &YarvIbfInstruction) -> String {
    let raw: String = match instr.operands.get(1) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => s.clone(),
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
    match instr.operands.get(idx) {
        Some(YarvOperand::Literal(s) | YarvOperand::StrLiteral(s)) => ruby_string_literal(s),
        Some(YarvOperand::SymLiteral(s)) => format!(":{}", symbol_literal(s)),
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
                    }],
                ),
                instr("putobject", vec![YarvOperand::Num(4)]),
                instr(
                    "opt_plus",
                    vec![YarvOperand::Call {
                        method: "+".to_owned(),
                        argc: 1,
                        flags: 0,
                    }],
                ),
                instr(
                    "opt_aset",
                    vec![YarvOperand::Call {
                        method: "[]=".to_owned(),
                        argc: 2,
                        flags: 0,
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
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("dup", vec![]),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "value".to_owned(),
                        argc: 0,
                        flags: 0,
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
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("putobject_INT2FIX_0_", vec![]),
                instr(
                    "opt_gt",
                    vec![YarvOperand::Call {
                        method: ">".to_owned(),
                        argc: 1,
                        flags: 0,
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
            param_size: 0,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
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
                        flags: 0,
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
            instructions: Vec::new(),
        };
        assert_eq!(block_param_list(&with_params), " |x, y|");
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
            param_size: 1,
            param_flags: 0,
            param_opt_num: 0,
            param_rest_start: 0,
            param_block_start: 0,
            catch_entries: Vec::new(),
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
            instructions: vec![
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "each".to_owned(),
                            argc: 0,
                            flags: 0,
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
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "map".to_owned(),
                            argc: 0,
                            flags: 0,
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
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "each".to_owned(),
                            argc: 0,
                            flags: 0,
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
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "send",
                    vec![
                        YarvOperand::Call {
                            method: "lambda".to_owned(),
                            argc: 0,
                            flags: 0,
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
        let lambda: Option<String> =
            super::parse_lambda_pattern(&main, &ctx, 0, 0, main.instructions.len());
        let _ = lambda;
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
