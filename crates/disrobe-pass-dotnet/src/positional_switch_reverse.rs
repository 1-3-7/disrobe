use std::collections::BTreeMap;

use crate::cfg::{BlockId, Cfg, Terminator};
use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, SlotOp, slot_index_of};
use crate::names::NameTable;
use crate::structurize::{TargetLang, TokenNamer, csharp_string_literal};

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subject {
    Arg(u32),
    Local(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Eq,
    Ne,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Constraint {
    literal: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ArmState {
    slots: BTreeMap<u32, Constraint>,
}

#[derive(Debug, Clone)]
struct Arm {
    offset: u32,
    state: ArmState,
    value: String,
}

struct Deconstruction {
    type_name: String,
    components: Vec<u32>,
}

struct WalkCtx<'a, N: TokenNamer> {
    cfg: &'a Cfg,
    body: &'a MethodBody,
    namer: &'a N,
    result_local: u32,
    epilogue: BlockId,
    components: Vec<u32>,
}

#[must_use]
pub(crate) fn reconstruct_positional_switch<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> Option<String> {
    if lang != TargetLang::CSharp {
        return None;
    }
    let cfg: Cfg = Cfg::build(body);
    if cfg.blocks.len() < 4 {
        return None;
    }
    let (result_local, epilogue): (u32, BlockId) = find_epilogue(&cfg, body)?;
    let (deconstruction, start): (Deconstruction, BlockId) =
        find_deconstruction(&cfg, body, namer)?;
    let subject: Subject = entry_subject(&cfg, body)?;

    let ctx: WalkCtx<'_, N> = WalkCtx {
        cfg: &cfg,
        body,
        namer,
        result_local,
        epilogue,
        components: deconstruction.components.clone(),
    };
    let leaf_states: BTreeMap<BlockId, ArmState> = propagate(&ctx, start)?;
    let mut arms: Vec<Arm> = Vec::new();
    for (&bid, state) in &leaf_states {
        let (value, offset): (String, u32) = leaf_value(&ctx, bid)?;
        arms.push(Arm {
            offset,
            state: state.clone(),
            value,
        });
    }
    if arms.len() < 2 {
        return None;
    }
    arms.sort_by_key(|a: &Arm| a.offset);
    let default_index: usize = default_arm_index(&arms)?;
    let default_value: String = arms.remove(default_index).value;
    Some(render_positional_switch(
        &deconstruction.type_name,
        subject,
        &deconstruction.components,
        &arms,
        &default_value,
        names,
    ))
}

fn default_arm_index(arms: &[Arm]) -> Option<usize> {
    let last: usize = arms.len().checked_sub(1)?;
    if arms[last].state.slots.is_empty() {
        return Some(last);
    }
    arms.iter().position(|a: &Arm| a.state.slots.is_empty())
}

fn propagate<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    start: BlockId,
) -> Option<BTreeMap<BlockId, ArmState>> {
    let count: usize = ctx.cfg.blocks.len();
    let region: Vec<bool> = region_from(ctx.cfg, start, ctx.epilogue);
    let mut incoming: Vec<Vec<ArmState>> = vec![Vec::new(); count];
    let mut leaves: BTreeMap<BlockId, ArmState> = BTreeMap::new();
    incoming[start].push(ArmState::default());

    for &bid in &ctx.cfg.rpo {
        if bid == ctx.epilogue || incoming[bid].is_empty() {
            continue;
        }
        let pred_count: usize = region_pred_count(ctx.cfg, bid, start, &region);
        if incoming[bid].len() < pred_count.max(1) {
            return None;
        }
        let state: ArmState = meet(&incoming[bid])?;

        if leaf_value(ctx, bid).is_some() {
            leaves.insert(bid, state);
            continue;
        }

        match ctx.cfg.terminators[bid] {
            Terminator::Cond { taken, fallthrough } => {
                let (slot, relation, literal): (u32, Relation, i64) = comparison(ctx, bid)?;
                let taken_state: ArmState = refine(&state, slot, relation, literal)?;
                let ft_state: ArmState = refine(&state, slot, invert(relation), literal)?;
                incoming[taken].push(taken_state);
                incoming[fallthrough].push(ft_state);
            }
            Terminator::Goto(next) | Terminator::FallThrough(next)
                if block_body_ops(ctx.cfg, ctx.body, bid).is_empty() =>
            {
                incoming[next].push(state);
            }
            _ => return None,
        }
    }
    (!leaves.is_empty()).then_some(leaves)
}

fn region_from(cfg: &Cfg, start: BlockId, epilogue: BlockId) -> Vec<bool> {
    let mut seen: Vec<bool> = vec![false; cfg.blocks.len()];
    let mut stack: Vec<BlockId> = vec![start];
    seen[start] = true;
    while let Some(bid) = stack.pop() {
        if bid == epilogue {
            continue;
        }
        for &succ in &cfg.blocks[bid].succs {
            if succ != epilogue && !seen[succ] {
                seen[succ] = true;
                stack.push(succ);
            }
        }
    }
    seen
}

fn region_pred_count(cfg: &Cfg, bid: BlockId, start: BlockId, region: &[bool]) -> usize {
    if bid == start {
        return 1;
    }
    cfg.blocks[bid]
        .preds
        .iter()
        .filter(|&&p: &&BlockId| region.get(p).copied().unwrap_or(false))
        .count()
}

fn meet(states: &[ArmState]) -> Option<ArmState> {
    let (first, rest): (&ArmState, &[ArmState]) = states.split_first()?;
    let mut acc: ArmState = first.clone();
    for state in rest {
        acc.slots = acc
            .slots
            .iter()
            .filter_map(|(k, va): (&u32, &Constraint)| {
                state
                    .slots
                    .get(k)
                    .filter(|vb: &&Constraint| *vb == va)
                    .map(|_| (*k, va.clone()))
            })
            .collect();
    }
    Some(acc)
}

fn refine(state: &ArmState, slot: u32, relation: Relation, literal: i64) -> Option<ArmState> {
    if relation == Relation::Ne {
        return Some(state.clone());
    }
    let mut out: ArmState = state.clone();
    match out.slots.insert(slot, Constraint { literal }) {
        Some(prev) if prev.literal != literal => None,
        _ => Some(out),
    }
}

const fn invert(relation: Relation) -> Relation {
    match relation {
        Relation::Eq => Relation::Ne,
        Relation::Ne => Relation::Eq,
    }
}

fn find_deconstruction<N: TokenNamer>(
    cfg: &Cfg,
    body: &MethodBody,
    namer: &N,
) -> Option<(Deconstruction, BlockId)> {
    for bid in 0..cfg.blocks.len() {
        let full: &[Instruction] = block_real_instrs(cfg, body, bid);
        let ops: Vec<&Instruction> = full
            .iter()
            .filter(|i: &&Instruction| !is_noise(&i.name))
            .collect();
        let Some(call_idx): Option<usize> = ops.iter().position(|i: &&Instruction| {
            matches!(i.name.as_str(), "call" | "callvirt")
                && matches!(i.operand, OperandValue::Token(t) if is_deconstruct(&namer.name(t)))
        }) else {
            continue;
        };
        let call: &Instruction = ops[call_idx];
        let prefix: &[&Instruction] = &ops[..call_idx];
        let [subject, addrs @ ..] = prefix else {
            continue;
        };
        if subject_of(subject).is_none() || addrs.len() < 2 {
            continue;
        }
        let components: Vec<u32> = addrs
            .iter()
            .map(|ins: &&Instruction| ldloca_slot(ins))
            .collect::<Option<Vec<u32>>>()?;
        let OperandValue::Token(tok): OperandValue = call.operand else {
            continue;
        };
        let type_name: String = deconstruct_type(&namer.name(tok))?;
        return Some((
            Deconstruction {
                type_name,
                components,
            },
            bid,
        ));
    }
    None
}

fn entry_subject(cfg: &Cfg, body: &MethodBody) -> Option<Subject> {
    let head: &[Instruction] = block_real_instrs(cfg, body, cfg.entry);
    subject_of(head.first()?)
}

fn is_deconstruct(callee: &str) -> bool {
    let short: &str = callee.rsplit("::").next().unwrap_or(callee);
    short.split('(').next().unwrap_or(short) == "Deconstruct"
}

fn deconstruct_type(callee: &str) -> Option<String> {
    let (decl, _method): (&str, &str) = callee.split_once("::")?;
    let bare: &str = decl.split('<').next().unwrap_or(decl);
    let short: &str = bare.rsplit('.').next().unwrap_or(bare);
    (!short.is_empty()).then(|| short.to_owned())
}

fn find_epilogue(cfg: &Cfg, body: &MethodBody) -> Option<(u32, BlockId)> {
    let mut found: Option<(u32, BlockId)> = None;
    for bid in 0..cfg.blocks.len() {
        if !matches!(cfg.terminators[bid], Terminator::Return) {
            continue;
        }
        let slice: &[Instruction] = block_real_instrs(cfg, body, bid);
        let [load, ret]: &[Instruction] = slice else {
            continue;
        };
        if ret.name != "ret" {
            continue;
        }
        let Some(local): Option<u32> = ldloc_slot(load) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some((local, bid));
    }
    found
}

fn leaf_value<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> Option<(String, u32)> {
    let exits_to_epilogue: bool = match ctx.cfg.terminators[bid] {
        Terminator::Goto(next) | Terminator::FallThrough(next) => next == ctx.epilogue,
        _ => false,
    };
    if !exits_to_epilogue {
        return None;
    }
    let slice: &[Instruction] = block_body_ops(ctx.cfg, ctx.body, bid);
    let [push, store]: &[Instruction] = slice else {
        return None;
    };
    if ldloc_slot(push).is_some() {
        return None;
    }
    if stloc_slot(store)? != ctx.result_local {
        return None;
    }
    let value: String = constant_value(push, ctx.namer)?;
    Some((value, push.offset))
}

fn constant_value<N: TokenNamer>(ins: &Instruction, namer: &N) -> Option<String> {
    match ins.name.as_str() {
        "ldstr" => match ins.operand {
            OperandValue::Token(t) => Some(csharp_string_literal(&namer.name(t))),
            _ => None,
        },
        "ldnull" => Some("null".to_owned()),
        "ldc.i4.m1" => Some("-1".to_owned()),
        name if name.starts_with("ldc.i4") => Some(int_const(ins, name).to_string()),
        "ldc.i8" => match ins.operand {
            OperandValue::I64(v) => Some(format!("{v}L")),
            _ => None,
        },
        _ => None,
    }
}

fn comparison<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> Option<(u32, Relation, i64)> {
    let full: &[Instruction] = block_real_instrs(ctx.cfg, ctx.body, bid);
    let branch: &Instruction = full.last()?;
    let denoised: Vec<&Instruction> = block_body_ops(ctx.cfg, ctx.body, bid)
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    let head: &[&Instruction] = strip_deconstruct(ctx, &denoised);
    match head {
        [load] => {
            let slot: u32 = component_slot(ctx, load)?;
            let relation: Relation = match branch.name.as_str() {
                "brtrue" | "brtrue.s" => Relation::Ne,
                "brfalse" | "brfalse.s" => Relation::Eq,
                _ => return None,
            };
            Some((slot, relation, 0))
        }
        [load, push] => {
            let slot: u32 = component_slot(ctx, load)?;
            let relation: Relation = match branch.name.as_str() {
                "beq" | "beq.s" => Relation::Eq,
                "bne.un" | "bne.un.s" => Relation::Ne,
                _ => return None,
            };
            let literal: i64 = int_constant(push)?;
            Some((slot, relation, literal))
        }
        _ => None,
    }
}

fn strip_deconstruct<'a, N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    head: &'a [&'a Instruction],
) -> &'a [&'a Instruction] {
    let Some(call_idx): Option<usize> = head.iter().position(|i: &&Instruction| {
        matches!(i.name.as_str(), "call" | "callvirt")
            && matches!(i.operand, OperandValue::Token(t) if is_deconstruct(&ctx.namer.name(t)))
    }) else {
        return head;
    };
    &head[call_idx + 1..]
}

fn component_slot<N: TokenNamer>(ctx: &WalkCtx<'_, N>, load: &Instruction) -> Option<u32> {
    let slot: u32 = ldloc_slot(load)?;
    ctx.components.contains(&slot).then_some(slot)
}

fn render_positional_switch(
    type_name: &str,
    subject: Subject,
    components: &[u32],
    arms: &[Arm],
    default_value: &str,
    names: &NameTable,
) -> String {
    let mut text: String = String::new();
    push_format(
        &mut text,
        format_args!("    return {} switch\n", render_subject(subject, names)),
    );
    text.push_str("    {\n");
    for arm in arms {
        let patterns: Vec<String> = components
            .iter()
            .map(|slot: &u32| {
                arm.state
                    .slots
                    .get(slot)
                    .map_or_else(|| "_".to_owned(), |c: &Constraint| c.literal.to_string())
            })
            .collect();
        push_format(
            &mut text,
            format_args!(
                "        {type_name}({}) => {},\n",
                patterns.join(", "),
                arm.value
            ),
        );
    }
    push_format(&mut text, format_args!("        _ => {default_value},\n"));
    text.push_str("    };\n");
    text
}

fn subject_of(ins: &Instruction) -> Option<Subject> {
    if let Some(slot) = ldarg_slot(ins) {
        return Some(Subject::Arg(slot));
    }
    ldloc_slot(ins).map(Subject::Local)
}

fn render_subject(subject: Subject, names: &NameTable) -> String {
    match subject {
        Subject::Arg(slot) => names.arg_name(slot),
        Subject::Local(slot) => NameTable::local_name(slot),
    }
}

fn block_real_instrs<'a>(cfg: &Cfg, body: &'a MethodBody, bid: BlockId) -> &'a [Instruction] {
    let first: usize = cfg.blocks[bid].first;
    let last: usize = cfg.blocks[bid].last;
    let slice: &[Instruction] = &body.instructions[first..=last];
    let start: usize = slice
        .iter()
        .position(|i: &Instruction| !is_noise(&i.name))
        .unwrap_or(slice.len());
    &slice[start..]
}

fn block_body_ops<'a>(cfg: &Cfg, body: &'a MethodBody, bid: BlockId) -> &'a [Instruction] {
    let slice: &[Instruction] = block_real_instrs(cfg, body, bid);
    match slice.last() {
        Some(last) if matches!(last.flow, FlowControl::Branch | FlowControl::CondBranch) => {
            &slice[..slice.len() - 1]
        }
        _ => slice,
    }
}

fn is_noise(name: &str) -> bool {
    matches!(name, "nop" | "break") || name.starts_with("conv.")
}

fn ldarg_slot(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::LoadArgument).map(u32::from)
}

fn ldloc_slot(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::LoadLocal).map(u32::from)
}

fn ldloca_slot(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::LocalAddress).map(u32::from)
}

fn stloc_slot(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::StoreLocal).map(u32::from)
}

fn int_constant(ins: &Instruction) -> Option<i64> {
    match ins.name.as_str() {
        "ldc.i4.m1" => Some(-1),
        name if name.starts_with("ldc.i4") => Some(int_const(ins, name)),
        "ldc.i8" => match ins.operand {
            OperandValue::I64(v) => Some(v),
            _ => None,
        },
        _ => None,
    }
}

fn int_const(ins: &Instruction, name: &str) -> i64 {
    if let Some(rest) = name.strip_prefix("ldc.i4.") {
        return match rest {
            "s" => match ins.operand {
                OperandValue::U8(b) => i64::from(b.cast_signed()),
                _ => 0,
            },
            d => d.parse::<i64>().unwrap_or(0),
        };
    }
    if name == "ldc.i4"
        && let OperandValue::I32(v) = ins.operand
    {
        return i64::from(v);
    }
    0
}
