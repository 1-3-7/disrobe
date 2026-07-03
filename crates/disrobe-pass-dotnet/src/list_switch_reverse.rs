use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{BlockId, Cfg, Terminator};
use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue};
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
enum LengthBound {
    Exact(i64),
    Min(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotPattern {
    Bind,
    Constant(i64),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ArmState {
    length: Option<LengthBound>,
    front: BTreeMap<i64, SlotPattern>,
    back: BTreeMap<i64, SlotPattern>,
    slice: bool,
}

#[derive(Debug, Clone)]
struct Arm {
    offset: u32,
    state: ArmState,
    value: String,
}

#[derive(Debug, Clone, Copy)]
enum ElementSlot {
    Front(i64),
    Back(i64),
}

enum BlockTest {
    Null,
    LengthEqual {
        value: i64,
        taken_equal: bool,
    },
    LengthMin {
        min: i64,
        taken_min: bool,
    },
    Element {
        slot: ElementSlot,
        constant: i64,
        taken_equal: bool,
    },
}

#[derive(Debug, Clone)]
struct Binding {
    slot: ElementSlot,
}

struct WalkCtx<'a, N: TokenNamer> {
    cfg: &'a Cfg,
    body: &'a MethodBody,
    namer: &'a N,
    subject: Subject,
    length_local: Option<u32>,
    result_local: u32,
    epilogue: BlockId,
}

#[must_use]
pub(crate) fn reconstruct_list_switch<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> Option<String> {
    if lang != TargetLang::CSharp || !has_list_shape(body) {
        return None;
    }
    let cfg: Cfg = Cfg::build(body);
    if cfg.blocks.len() < 3 {
        return None;
    }
    let (result_local, epilogue): (u32, BlockId) = find_epilogue(&cfg, body)?;
    let subject: Subject = entry_subject(&cfg, body)?;
    let length_local: Option<u32> = find_length_local(body, subject);

    let ctx: WalkCtx<'_, N> = WalkCtx {
        cfg: &cfg,
        body,
        namer,
        subject,
        length_local,
        result_local,
        epilogue,
    };

    let leaf_states: BTreeMap<BlockId, ArmState> = propagate(&ctx)?;
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
    if arms.iter().any(|a: &Arm| !state_is_pattern(&a.state)) {
        return None;
    }
    let subject_name: String = render_subject(subject, names);
    Some(render_list_switch(&subject_name, &arms, &default_value))
}

fn state_is_pattern(state: &ArmState) -> bool {
    state.length.is_some() || state.slice || !state.front.is_empty() || !state.back.is_empty()
}

fn default_arm_index(arms: &[Arm]) -> Option<usize> {
    let last: usize = arms.len().checked_sub(1)?;
    if state_is_pattern(&arms[last].state) {
        arms.iter().position(|a: &Arm| !state_is_pattern(&a.state))
    } else {
        Some(last)
    }
}

fn propagate<N: TokenNamer>(ctx: &WalkCtx<'_, N>) -> Option<BTreeMap<BlockId, ArmState>> {
    let count: usize = ctx.cfg.blocks.len();
    let mut incoming: Vec<Vec<ArmState>> = vec![Vec::new(); count];
    let mut leaves: BTreeMap<BlockId, ArmState> = BTreeMap::new();
    incoming[ctx.cfg.entry].push(ArmState::default());

    for &bid in &ctx.cfg.rpo {
        if bid == ctx.epilogue {
            continue;
        }
        let pred_count: usize = reachable_pred_count(ctx.cfg, bid);
        if incoming[bid].len() < pred_count.max(1) {
            return None;
        }
        let mut state: ArmState = meet(&incoming[bid])?;

        if leaf_value(ctx, bid).is_some() {
            apply_leaf_binds(ctx, bid, &mut state)?;
            leaves.insert(bid, state);
            continue;
        }

        match ctx.cfg.terminators[bid] {
            Terminator::Cond { taken, fallthrough } => {
                let test: BlockTest = classify_test(ctx, bid)?;
                let (taken_state, ft_state): (ArmState, ArmState) = test.split(state)?;
                incoming[taken].push(taken_state);
                incoming[fallthrough].push(ft_state);
            }
            Terminator::Goto(next) | Terminator::FallThrough(next) => {
                let mut next_state: ArmState = state;
                if let Some(binding) = classify_binding(ctx, bid) {
                    apply_binding(&binding, &mut next_state)?;
                } else if !is_length_store_block(ctx, bid) && !block_is_bare(ctx, bid) {
                    return None;
                }
                incoming[next].push(next_state);
            }
            _ => return None,
        }
    }
    (!leaves.is_empty()).then_some(leaves)
}

fn reachable_pred_count(cfg: &Cfg, bid: BlockId) -> usize {
    cfg.blocks[bid]
        .preds
        .iter()
        .filter(|&&p: &&BlockId| cfg.is_reachable(p))
        .count()
}

fn meet(states: &[ArmState]) -> Option<ArmState> {
    let (first, rest): (&ArmState, &[ArmState]) = states.split_first()?;
    let mut acc: ArmState = first.clone();
    for state in rest {
        acc = meet_pair(&acc, state);
    }
    Some(acc)
}

fn meet_pair(a: &ArmState, b: &ArmState) -> ArmState {
    let front: BTreeMap<i64, SlotPattern> = meet_slots(&a.front, &b.front);
    let back: BTreeMap<i64, SlotPattern> = meet_slots(&a.back, &b.back);
    let slice: bool = a.slice || b.slice || !back.is_empty();
    ArmState {
        length: meet_length(a.length, b.length),
        front,
        back,
        slice,
    }
}

fn meet_length(a: Option<LengthBound>, b: Option<LengthBound>) -> Option<LengthBound> {
    match (a, b) {
        (Some(x), Some(y)) if x == y => Some(x),
        _ => None,
    }
}

fn meet_slots(
    a: &BTreeMap<i64, SlotPattern>,
    b: &BTreeMap<i64, SlotPattern>,
) -> BTreeMap<i64, SlotPattern> {
    let keys: BTreeSet<i64> = a.keys().chain(b.keys()).copied().collect();
    keys.into_iter()
        .filter_map(|k: i64| meet_slot(a.get(&k), b.get(&k)).map(|p: SlotPattern| (k, p)))
        .collect()
}

fn meet_slot(a: Option<&SlotPattern>, b: Option<&SlotPattern>) -> Option<SlotPattern> {
    match (a, b) {
        (Some(SlotPattern::Bind), _) | (_, Some(SlotPattern::Bind)) => Some(SlotPattern::Bind),
        (Some(SlotPattern::Constant(x)), Some(SlotPattern::Constant(y))) if x == y => {
            Some(SlotPattern::Constant(*x))
        }
        _ => None,
    }
}

fn has_list_shape(body: &MethodBody) -> bool {
    let mut has_ldlen: bool = false;
    let mut has_null_check: bool = false;
    let denoised: Vec<&Instruction> = body
        .instructions
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    for window in denoised.windows(2) {
        if is_load(&window[0].name) && is_bool_branch(&window[1].name) {
            has_null_check = true;
        }
    }
    for ins in &denoised {
        if ins.name == "ldlen" {
            has_ldlen = true;
        }
    }
    has_ldlen && has_null_check
}

fn is_load(name: &str) -> bool {
    name.starts_with("ldarg") || name.starts_with("ldloc")
}

fn is_bool_branch(name: &str) -> bool {
    matches!(name, "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s")
}

fn entry_subject(cfg: &Cfg, body: &MethodBody) -> Option<Subject> {
    let head: &[Instruction] = block_real_instrs(cfg, body, cfg.entry);
    subject_of(head.first()?)
}

fn find_length_local(body: &MethodBody, subject: Subject) -> Option<u32> {
    let denoised: Vec<&Instruction> = body
        .instructions
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    for window in denoised.windows(3) {
        if subject_of(window[0]) == Some(subject)
            && window[1].name == "ldlen"
            && let Some(slot) = stloc_slot(window[2])
        {
            return Some(slot);
        }
    }
    None
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

impl BlockTest {
    fn split(&self, state: ArmState) -> Option<(ArmState, ArmState)> {
        match self {
            Self::Null => Some((state.clone(), state)),
            Self::LengthEqual { value, taken_equal } => {
                let mut with_len: ArmState = state.clone();
                with_len.set_length(LengthBound::Exact(*value))?;
                let without_len: ArmState = with_min_after_exact(&state, *value);
                Some(if *taken_equal {
                    (with_len, without_len)
                } else {
                    (without_len, with_len)
                })
            }
            Self::LengthMin { min, taken_min } => {
                let mut with_min: ArmState = state.clone();
                with_min.set_length(LengthBound::Min(*min))?;
                Some(if *taken_min {
                    (with_min, state)
                } else {
                    (state, with_min)
                })
            }
            Self::Element {
                slot,
                constant,
                taken_equal,
            } => {
                let mut matched: ArmState = state.clone();
                set_slot(&mut matched, *slot, SlotPattern::Constant(*constant))?;
                Some(if *taken_equal {
                    (matched, state)
                } else {
                    (state, matched)
                })
            }
        }
    }
}

fn with_min_after_exact(state: &ArmState, value: i64) -> ArmState {
    let mut out: ArmState = state.clone();
    if value == 0 {
        let _ = out.set_length(LengthBound::Min(1));
    }
    out
}

impl ArmState {
    fn set_length(&mut self, bound: LengthBound) -> Option<()> {
        match self.length {
            None => {
                self.length = Some(bound);
                Some(())
            }
            Some(existing) => tighten(existing, bound).map(|merged: LengthBound| {
                self.length = Some(merged);
            }),
        }
    }
}

const fn tighten(existing: LengthBound, incoming: LengthBound) -> Option<LengthBound> {
    match (existing, incoming) {
        (LengthBound::Min(a), LengthBound::Min(b)) => {
            Some(LengthBound::Min(if a > b { a } else { b }))
        }
        (LengthBound::Min(a), LengthBound::Exact(b))
        | (LengthBound::Exact(b), LengthBound::Min(a)) => {
            if b >= a {
                Some(LengthBound::Exact(b))
            } else {
                None
            }
        }
        (LengthBound::Exact(a), LengthBound::Exact(b)) => {
            if a == b {
                Some(LengthBound::Exact(a))
            } else {
                None
            }
        }
    }
}

fn set_slot(state: &mut ArmState, slot: ElementSlot, pattern: SlotPattern) -> Option<()> {
    match slot {
        ElementSlot::Front(idx) => match state.front.insert(idx, pattern) {
            Some(prev) if prev != pattern => None,
            _ => Some(()),
        },
        ElementSlot::Back(idx) => {
            state.slice = true;
            match state.back.insert(idx, pattern) {
                Some(prev) if prev != pattern => None,
                _ => Some(()),
            }
        }
    }
}

fn apply_binding(binding: &Binding, state: &mut ArmState) -> Option<()> {
    set_slot(state, binding.slot, SlotPattern::Bind)
}

fn classify_test<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> Option<BlockTest> {
    let full: &[Instruction] = block_real_instrs(ctx.cfg, ctx.body, bid);
    let branch: &Instruction = full.last()?;
    let denoised: Vec<&Instruction> = block_body_ops(ctx.cfg, ctx.body, bid)
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    let head: &[&Instruction] = strip_length_cache(ctx, &denoised);
    if let [load] = head
        && subject_of(load) == Some(ctx.subject)
        && is_bool_branch(&branch.name)
    {
        return Some(BlockTest::Null);
    }
    if let Some(test) = length_test(ctx, head, branch) {
        return Some(test);
    }
    element_test(ctx, head, branch)
}

fn strip_length_cache<'a, N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    head: &'a [&'a Instruction],
) -> &'a [&'a Instruction] {
    let [subject, ldlen, store, rest @ ..] = head else {
        return head;
    };
    if subject_of(subject) == Some(ctx.subject)
        && ldlen.name == "ldlen"
        && ctx.length_local == stloc_slot(store)
        && ctx.length_local.is_some()
    {
        rest
    } else {
        head
    }
}

fn length_test<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    head: &[&Instruction],
    branch: &Instruction,
) -> Option<BlockTest> {
    if is_length_expr(ctx, head) == Some(()) {
        return match branch.name.as_str() {
            "brfalse" | "brfalse.s" => Some(BlockTest::LengthEqual {
                value: 0,
                taken_equal: true,
            }),
            "brtrue" | "brtrue.s" => Some(BlockTest::LengthEqual {
                value: 0,
                taken_equal: false,
            }),
            _ => None,
        };
    }
    let (konst, length_head): (&&Instruction, &[&Instruction]) = head.split_last()?;
    is_length_expr(ctx, length_head)?;
    let literal: i64 = int_constant(konst)?;
    match branch.name.as_str() {
        "beq" | "beq.s" => Some(BlockTest::LengthEqual {
            value: literal,
            taken_equal: true,
        }),
        "bne.un" | "bne.un.s" => Some(BlockTest::LengthEqual {
            value: literal,
            taken_equal: false,
        }),
        "bge" | "bge.s" | "bge.un" | "bge.un.s" => Some(BlockTest::LengthMin {
            min: literal,
            taken_min: true,
        }),
        "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => Some(BlockTest::LengthMin {
            min: literal.checked_add(1)?,
            taken_min: true,
        }),
        "blt" | "blt.s" | "blt.un" | "blt.un.s" => Some(BlockTest::LengthMin {
            min: literal,
            taken_min: false,
        }),
        "ble" | "ble.s" | "ble.un" | "ble.un.s" => Some(BlockTest::LengthMin {
            min: literal.checked_add(1)?,
            taken_min: false,
        }),
        _ => None,
    }
}

fn is_length_expr<N: TokenNamer>(ctx: &WalkCtx<'_, N>, head: &[&Instruction]) -> Option<()> {
    match head {
        [only] => is_length_source(ctx, only).then_some(()),
        [subject, ldlen] => {
            (subject_of(subject) == Some(ctx.subject) && ldlen.name == "ldlen").then_some(())
        }
        _ => None,
    }
}

fn is_length_source<N: TokenNamer>(ctx: &WalkCtx<'_, N>, ins: &Instruction) -> bool {
    ctx.length_local
        .is_some_and(|slot: u32| ldloc_slot(ins) == Some(slot))
        || ins.name == "ldlen"
}

fn element_test<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    head: &[&Instruction],
    branch: &Instruction,
) -> Option<BlockTest> {
    let (slot, konst): (ElementSlot, &Instruction) = element_access(ctx, head)?;
    let constant: i64 = int_constant(konst)?;
    match branch.name.as_str() {
        "beq" | "beq.s" => Some(BlockTest::Element {
            slot,
            constant,
            taken_equal: true,
        }),
        "bne.un" | "bne.un.s" => Some(BlockTest::Element {
            slot,
            constant,
            taken_equal: false,
        }),
        _ => None,
    }
}

fn is_length_store_block<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> bool {
    let head: Vec<&Instruction> = block_body_ops(ctx.cfg, ctx.body, bid)
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    let [subject, ldlen, store] = head.as_slice() else {
        return false;
    };
    subject_of(subject) == Some(ctx.subject)
        && ldlen.name == "ldlen"
        && ctx.length_local == stloc_slot(store)
        && ctx.length_local.is_some()
}

fn block_is_bare<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> bool {
    block_body_ops(ctx.cfg, ctx.body, bid)
        .iter()
        .all(|i: &Instruction| is_noise(&i.name))
}

fn classify_binding<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> Option<Binding> {
    let head: Vec<&Instruction> = block_body_ops(ctx.cfg, ctx.body, bid)
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    let (pop, before_pop): (&&Instruction, &[&Instruction]) = head.split_last()?;
    if pop.name != "pop" {
        return None;
    }
    let (slot, _last): (ElementSlot, &&Instruction) = element_access_slot(ctx, before_pop)?;
    Some(Binding { slot })
}

fn element_access<'a, N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    head: &'a [&'a Instruction],
) -> Option<(ElementSlot, &'a Instruction)> {
    let (slot, konst): (ElementSlot, &&Instruction) = element_access_konst(ctx, head)?;
    Some((slot, konst))
}

fn element_access_konst<'a, N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    head: &'a [&'a Instruction],
) -> Option<(ElementSlot, &'a &'a Instruction)> {
    let (konst, rest): (&&Instruction, &[&Instruction]) = head.split_last()?;
    let (slot, ldelem): (ElementSlot, &&Instruction) = element_access_slot(ctx, rest)?;
    let _ = ldelem;
    Some((slot, konst))
}

fn element_access_slot<'a, N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    head: &'a [&'a Instruction],
) -> Option<(ElementSlot, &'a &'a Instruction)> {
    let (ldelem, rest): (&&Instruction, &[&Instruction]) = head.split_last()?;
    if !is_ldelem(&ldelem.name) {
        return None;
    }
    match rest {
        [subject, index] => {
            if subject_of(subject) != Some(ctx.subject) {
                return None;
            }
            let idx: i64 = int_constant(index)?;
            Some((ElementSlot::Front(idx), ldelem))
        }
        [subject, len, konst, sub] => {
            if subject_of(subject) != Some(ctx.subject) || sub.name != "sub" {
                return None;
            }
            if !is_length_source(ctx, len) {
                return None;
            }
            let offset: i64 = int_constant(konst)?;
            let back_index: i64 = offset.checked_sub(1)?;
            (back_index >= 0).then_some((ElementSlot::Back(back_index), ldelem))
        }
        _ => None,
    }
}

fn is_ldelem(name: &str) -> bool {
    name.starts_with("ldelem")
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
    let (store, prefix): (&Instruction, &[Instruction]) = slice.split_last()?;
    let (push, _binds): (&Instruction, &[Instruction]) = prefix.split_last()?;
    if ldloc_slot(push).is_some() {
        return None;
    }
    if stloc_slot(store)? != ctx.result_local {
        return None;
    }
    let value: String = constant_value(push, ctx.namer)?;
    Some((value, push.offset))
}

fn apply_leaf_binds<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
    state: &mut ArmState,
) -> Option<()> {
    let slice: &[Instruction] = block_body_ops(ctx.cfg, ctx.body, bid);
    let (_store, prefix): (&Instruction, &[Instruction]) = slice.split_last()?;
    let (_push, binds): (&Instruction, &[Instruction]) = prefix.split_last()?;
    if binds.is_empty() {
        return Some(());
    }
    let denoised: Vec<&Instruction> = binds
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    fold_bind_groups(ctx, &denoised, state)
}

fn fold_bind_groups<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    ops: &[&Instruction],
    state: &mut ArmState,
) -> Option<()> {
    let mut rest: &[&Instruction] = ops;
    while !rest.is_empty() {
        let pop_at: usize = rest.iter().position(|i: &&Instruction| i.name == "pop")?;
        let group: &[&Instruction] = &rest[..pop_at];
        let (slot, _last): (ElementSlot, &&Instruction) = element_access_slot(ctx, group)?;
        set_slot(state, slot, SlotPattern::Bind)?;
        rest = &rest[pop_at + 1..];
    }
    Some(())
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

fn render_subject(subject: Subject, names: &NameTable) -> String {
    match subject {
        Subject::Arg(slot) => names.arg_name(slot),
        Subject::Local(slot) => NameTable::local_name(slot),
    }
}

fn render_list_switch(subject: &str, arms: &[Arm], default_value: &str) -> String {
    let mut text: String = String::new();
    let mut names: BindNames = BindNames::default();
    push_format(&mut text, format_args!("    return {subject} switch\n"));
    text.push_str("    {\n");
    for arm in arms {
        push_format(
            &mut text,
            format_args!(
                "        {} => {},\n",
                render_list_pattern(&arm.state, &mut names),
                arm.value
            ),
        );
    }
    push_format(&mut text, format_args!("        _ => {default_value},\n"));
    text.push_str("    };\n");
    text
}

#[derive(Debug, Default)]
struct BindNames {
    counter: u32,
    used: BTreeSet<String>,
}

impl BindNames {
    fn next(&mut self) -> String {
        loop {
            let name: String = format!("v{}", self.counter);
            self.counter = self.counter.saturating_add(1);
            if self.used.insert(name.clone()) {
                return name;
            }
        }
    }
}

fn render_list_pattern(state: &ArmState, names: &mut BindNames) -> String {
    let (front_count, back_count, slice): (i64, i64, bool) = pattern_shape(state);
    let mut parts: Vec<String> = Vec::new();
    for i in 0..front_count {
        parts.push(render_slot(state.front.get(&i), names));
    }
    if slice {
        parts.push("..".to_owned());
    }
    for k in (0..back_count).rev() {
        parts.push(render_slot(state.back.get(&k), names));
    }
    format!("[{}]", parts.join(", "))
}

fn pattern_shape(state: &ArmState) -> (i64, i64, bool) {
    let front_explicit: i64 = state.front.keys().copied().max().map_or(0, |k: i64| k + 1);
    let back_count: i64 = state.back.keys().copied().max().map_or(0, |k: i64| k + 1);
    let has_back: bool = back_count > 0;
    match state.length {
        Some(LengthBound::Exact(n)) if !state.slice && !has_back => (n, 0, false),
        Some(LengthBound::Min(m)) if !has_back => (front_explicit.max(m), 0, true),
        _ => (front_explicit, back_count, true),
    }
}

fn render_slot(pattern: Option<&SlotPattern>, names: &mut BindNames) -> String {
    match pattern {
        None => "_".to_owned(),
        Some(SlotPattern::Bind) => format!("var {}", names.next()),
        Some(SlotPattern::Constant(v)) => v.to_string(),
    }
}

fn subject_of(ins: &Instruction) -> Option<Subject> {
    if let Some(slot) = ldarg_slot(ins) {
        return Some(Subject::Arg(slot));
    }
    ldloc_slot(ins).map(Subject::Local)
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
    match ins.name.as_str() {
        "ldarg.0" => Some(0),
        "ldarg.1" => Some(1),
        "ldarg.2" => Some(2),
        "ldarg.3" => Some(3),
        "ldarg" | "ldarg.s" => operand_index(ins),
        _ => None,
    }
}

fn ldloc_slot(ins: &Instruction) -> Option<u32> {
    match ins.name.as_str() {
        "ldloc.0" => Some(0),
        "ldloc.1" => Some(1),
        "ldloc.2" => Some(2),
        "ldloc.3" => Some(3),
        "ldloc" | "ldloc.s" => operand_index(ins),
        _ => None,
    }
}

fn stloc_slot(ins: &Instruction) -> Option<u32> {
    match ins.name.as_str() {
        "stloc.0" => Some(0),
        "stloc.1" => Some(1),
        "stloc.2" => Some(2),
        "stloc.3" => Some(3),
        "stloc" | "stloc.s" => operand_index(ins),
        _ => None,
    }
}

fn operand_index(ins: &Instruction) -> Option<u32> {
    match ins.operand {
        OperandValue::U8(v) => Some(u32::from(v)),
        OperandValue::U16(v) => Some(u32::from(v)),
        OperandValue::I32(v) => u32::try_from(v).ok(),
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
