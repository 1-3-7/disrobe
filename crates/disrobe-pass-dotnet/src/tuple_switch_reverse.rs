use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::cfg::{BlockId, Cfg, Terminator};
use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, SlotOp, slot_index_of};
use crate::names::NameTable;
use crate::structurize::{TargetLang, TokenNamer, csharp_string_literal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Component {
    Arg(u32),
    Local(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Default)]
struct Constraint {
    tests: Vec<(Relation, i64)>,
}

impl Constraint {
    const fn is_unconstrained(&self) -> bool {
        self.tests.is_empty()
    }
}

#[derive(Debug, Clone)]
struct Arm {
    offset: u32,
    constraints: BTreeMap<Component, Constraint>,
    value: String,
}

struct WalkCtx<'a, N: TokenNamer> {
    cfg: &'a Cfg,
    body: &'a MethodBody,
    namer: &'a N,
    result_local: u32,
    epilogue: BlockId,
    default_block: BlockId,
}

#[must_use]
pub(crate) fn reconstruct_tuple_switch<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> Option<String> {
    if lang != TargetLang::CSharp || !has_tuple_shape(body) {
        return None;
    }
    let cfg: Cfg = Cfg::build(body);
    if cfg.blocks.len() < 4 {
        return None;
    }
    let (result_local, epilogue): (u32, BlockId) = find_epilogue(&cfg, body)?;
    let default_block: BlockId = find_default_block(&cfg, body, result_local, epilogue)?;

    let ctx: WalkCtx<'_, N> = WalkCtx {
        cfg: &cfg,
        body,
        namer,
        result_local,
        epilogue,
        default_block,
    };
    let mut arms: Vec<Arm> = Vec::new();
    let mut default_value: Option<String> = None;
    let mut budget: u32 = 0;
    walk(
        &ctx,
        cfg.entry,
        BTreeMap::new(),
        &mut arms,
        &mut default_value,
        &mut budget,
    )?;

    if arms.len() < 2 {
        return None;
    }
    let components: Vec<Component> = ordered_components(&arms)?;
    if components.len() < 2 {
        return None;
    }
    if arms
        .iter()
        .any(|a: &Arm| a.constraints.len() != components.len())
    {
        return None;
    }
    arms.sort_by_key(|a: &Arm| a.offset);
    let discriminants: Vec<String> = components
        .iter()
        .map(|c: &Component| render_component(*c, names))
        .collect();
    Some(render_tuple_switch(
        &discriminants,
        &components,
        &arms,
        &default_value?,
    ))
}

fn has_tuple_shape(body: &MethodBody) -> bool {
    let mut compares: u32 = 0;
    let mut has_store: bool = false;
    for ins in &body.instructions {
        if branch_relation(&ins.name).is_some()
            || matches!(ins.name.as_str(), "brtrue" | "brtrue.s")
        {
            compares = compares.saturating_add(1);
        }
        if matches!(ins.name.as_str(), "brfalse" | "brfalse.s") {
            compares = compares.saturating_add(1);
        }
        if stloc_slot(ins).is_some() {
            has_store = true;
        }
    }
    compares >= 3 && has_store
}

fn ordered_components(arms: &[Arm]) -> Option<Vec<Component>> {
    let mut ordered: Vec<Component> = Vec::new();
    for arm in arms {
        for c in arm.constraints.keys() {
            if !ordered.contains(c) {
                ordered.push(*c);
            }
        }
    }
    ordered.sort();
    (!ordered.is_empty()).then_some(ordered)
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

fn is_store_leaf(
    cfg: &Cfg,
    body: &MethodBody,
    bid: BlockId,
    result_local: u32,
    epilogue: BlockId,
) -> bool {
    let exits: bool = match cfg.terminators[bid] {
        Terminator::Goto(next) | Terminator::FallThrough(next) => next == epilogue,
        _ => false,
    };
    if !exits {
        return false;
    }
    let slice: &[Instruction] = block_body_ops(cfg, body, bid);
    let [push, store]: &[Instruction] = slice else {
        return false;
    };
    ldloc_slot(push).is_none() && stloc_slot(store) == Some(result_local)
}

fn find_default_block(
    cfg: &Cfg,
    body: &MethodBody,
    result_local: u32,
    epilogue: BlockId,
) -> Option<BlockId> {
    let mut found: Option<BlockId> = None;
    for bid in 0..cfg.blocks.len() {
        if !is_store_leaf(cfg, body, bid, result_local, epilogue) {
            continue;
        }
        if cfg.blocks[bid].preds.len() < 2 {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(bid);
    }
    found
}

fn walk<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
    constraints: BTreeMap<Component, Constraint>,
    arms: &mut Vec<Arm>,
    default_value: &mut Option<String>,
    budget: &mut u32,
) -> Option<()> {
    *budget = budget.checked_add(1)?;
    if *budget > 512 {
        return None;
    }
    if bid == ctx.epilogue {
        return Some(());
    }
    if bid == ctx.default_block {
        let (value, _offset): (String, u32) = leaf_value(ctx, bid)?;
        return match default_value {
            Some(existing) if *existing != value => None,
            _ => {
                *default_value = Some(value);
                Some(())
            }
        };
    }
    if let Some((value, offset)) = leaf_value(ctx, bid) {
        return record_leaf(constraints, value, offset, arms, default_value);
    }

    match ctx.cfg.terminators[bid] {
        Terminator::Cond { taken, fallthrough } => {
            let (component, relation, literal): (Component, Relation, i64) = comparison(ctx, bid)?;
            let taken_c: BTreeMap<Component, Constraint> =
                refine(&constraints, component, relation, literal)?;
            let ft_c: BTreeMap<Component, Constraint> =
                refine(&constraints, component, invert(relation), literal)?;
            walk(ctx, taken, taken_c, arms, default_value, budget)?;
            walk(ctx, fallthrough, ft_c, arms, default_value, budget)
        }
        Terminator::Goto(next) | Terminator::FallThrough(next)
            if block_body_ops(ctx.cfg, ctx.body, bid).is_empty() =>
        {
            walk(ctx, next, constraints, arms, default_value, budget)
        }
        _ => None,
    }
}

fn record_leaf(
    constraints: BTreeMap<Component, Constraint>,
    value: String,
    offset: u32,
    arms: &mut Vec<Arm>,
    _default_value: &mut Option<String>,
) -> Option<()> {
    if constraints.values().all(Constraint::is_unconstrained) {
        return None;
    }
    arms.push(Arm {
        offset,
        constraints,
        value,
    });
    Some(())
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

fn comparison<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
) -> Option<(Component, Relation, i64)> {
    let full: &[Instruction] = block_real_instrs(ctx.cfg, ctx.body, bid);
    let branch: &Instruction = full.last()?;
    let head: &[Instruction] = block_body_ops(ctx.cfg, ctx.body, bid);
    match head {
        [load] => {
            let component: Component = load_component(load)?;
            let relation: Relation = match branch.name.as_str() {
                "brtrue" | "brtrue.s" => Relation::Ne,
                "brfalse" | "brfalse.s" => Relation::Eq,
                _ => return None,
            };
            Some((component, relation, 0))
        }
        [load, push] => {
            let component: Component = load_component(load)?;
            let relation: Relation = branch_relation(&branch.name)?;
            let literal: i64 = match push.name.as_str() {
                "ldc.i4.m1" => -1,
                name if name.starts_with("ldc.i4") => int_const(push, name),
                _ => return None,
            };
            Some((component, relation, literal))
        }
        _ => None,
    }
}

fn branch_relation(name: &str) -> Option<Relation> {
    Some(match name {
        "blt" | "blt.s" | "blt.un" | "blt.un.s" => Relation::Lt,
        "ble" | "ble.s" | "ble.un" | "ble.un.s" => Relation::Le,
        "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => Relation::Gt,
        "bge" | "bge.s" | "bge.un" | "bge.un.s" => Relation::Ge,
        "beq" | "beq.s" => Relation::Eq,
        "bne.un" | "bne.un.s" => Relation::Ne,
        _ => return None,
    })
}

fn refine(
    constraints: &BTreeMap<Component, Constraint>,
    component: Component,
    relation: Relation,
    literal: i64,
) -> Option<BTreeMap<Component, Constraint>> {
    if relation == Relation::Ne {
        return None;
    }
    let mut out: BTreeMap<Component, Constraint> = constraints.clone();
    let slot: &mut Constraint = out.entry(component).or_default();
    slot.tests.push((relation, literal));
    Some(out)
}

const fn invert(relation: Relation) -> Relation {
    match relation {
        Relation::Lt => Relation::Ge,
        Relation::Le => Relation::Gt,
        Relation::Gt => Relation::Le,
        Relation::Ge => Relation::Lt,
        Relation::Eq => Relation::Ne,
        Relation::Ne => Relation::Eq,
    }
}

fn render_component(component: Component, names: &NameTable) -> String {
    match component {
        Component::Arg(slot) => names.arg_name(slot),
        Component::Local(slot) => NameTable::local_name(slot),
    }
}

const fn lower_bound(relation: Relation, literal: i64) -> Option<i64> {
    match relation {
        Relation::Ge => Some(literal),
        Relation::Gt => literal.checked_add(1),
        _ => None,
    }
}

const fn upper_bound(relation: Relation, literal: i64) -> Option<i64> {
    match relation {
        Relation::Lt => Some(literal),
        Relation::Le => literal.checked_add(1),
        _ => None,
    }
}

const fn relation_token(relation: Relation) -> &'static str {
    match relation {
        Relation::Lt => "<",
        Relation::Le => "<=",
        Relation::Gt => ">",
        Relation::Ge => ">=",
        Relation::Eq => "==",
        Relation::Ne => "!=",
    }
}

fn render_pattern(constraint: &Constraint) -> Option<String> {
    if constraint.tests.is_empty() {
        return Some("_".to_owned());
    }
    if let Some((_, literal)) = constraint
        .tests
        .iter()
        .find(|(r, _): &&(Relation, i64)| *r == Relation::Eq)
    {
        return Some(literal.to_string());
    }
    let lower: Option<(Relation, i64)> = constraint
        .tests
        .iter()
        .copied()
        .filter(|(r, l): &(Relation, i64)| lower_bound(*r, *l).is_some())
        .max_by_key(|(r, l): &(Relation, i64)| lower_bound(*r, *l).unwrap_or(i64::MIN));
    let upper: Option<(Relation, i64)> = constraint
        .tests
        .iter()
        .copied()
        .filter(|(r, l): &(Relation, i64)| upper_bound(*r, *l).is_some())
        .min_by_key(|(r, l): &(Relation, i64)| upper_bound(*r, *l).unwrap_or(i64::MAX));
    match (lower, upper) {
        (Some((rl, ll)), None) => Some(format!("{} {ll}", relation_token(rl))),
        (None, Some((ru, lu))) => Some(format!("{} {lu}", relation_token(ru))),
        (Some((rl, ll)), Some((ru, lu))) => {
            let lo: i64 = lower_bound(rl, ll)?;
            let hi: i64 = upper_bound(ru, lu)?;
            (lo < hi).then(|| {
                format!(
                    "{} {ll} and {} {lu}",
                    relation_token(rl),
                    relation_token(ru)
                )
            })
        }
        (None, None) => None,
    }
}

fn render_tuple_switch(
    discriminants: &[String],
    components: &[Component],
    arms: &[Arm],
    default_value: &str,
) -> String {
    let mut text: String = String::new();
    let _ = writeln!(text, "    return ({}) switch", discriminants.join(", "));
    let _ = writeln!(text, "    {{");
    for arm in arms {
        let patterns: Vec<String> = components
            .iter()
            .map(|c: &Component| {
                arm.constraints.get(c).map_or_else(
                    || "_".to_owned(),
                    |k: &Constraint| render_pattern(k).unwrap_or_else(|| "_".to_owned()),
                )
            })
            .collect();
        let _ = writeln!(text, "        ({}) => {},", patterns.join(", "), arm.value);
    }
    let _ = writeln!(text, "        _ => {default_value},");
    let _ = writeln!(text, "    }};");
    text
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

fn load_component(ins: &Instruction) -> Option<Component> {
    if let Some(slot) = ldarg_slot(ins) {
        return Some(Component::Arg(slot));
    }
    ldloc_slot(ins).map(Component::Local)
}

fn ldarg_slot(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::LoadArgument).map(u32::from)
}

fn ldloc_slot(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::LoadLocal).map(u32::from)
}

fn stloc_slot(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::StoreLocal).map(u32::from)
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn refine_records_exact_equality() {
        let base: BTreeMap<Component, Constraint> = BTreeMap::new();
        let refined: BTreeMap<Component, Constraint> =
            refine(&base, Component::Arg(1), Relation::Eq, 0).expect("refine");
        assert_eq!(refined[&Component::Arg(1)].tests, vec![(Relation::Eq, 0)]);
    }

    #[test]
    fn refine_rejects_not_equal() {
        let base: BTreeMap<Component, Constraint> = BTreeMap::new();
        assert!(refine(&base, Component::Arg(1), Relation::Ne, 0).is_none());
    }

    #[test]
    fn render_pattern_keeps_source_relation() {
        let gt0: Constraint = Constraint {
            tests: vec![(Relation::Gt, 0)],
        };
        assert_eq!(render_pattern(&gt0).as_deref(), Some("> 0"));
        let lt0: Constraint = Constraint {
            tests: vec![(Relation::Le, 0), (Relation::Lt, 0)],
        };
        assert_eq!(render_pattern(&lt0).as_deref(), Some("< 0"));
        let exact: Constraint = Constraint {
            tests: vec![(Relation::Eq, 0)],
        };
        assert_eq!(render_pattern(&exact).as_deref(), Some("0"));
        let any: Constraint = Constraint::default();
        assert_eq!(render_pattern(&any).as_deref(), Some("_"));
    }

    #[test]
    fn invert_round_trips() {
        for relation in [
            Relation::Lt,
            Relation::Le,
            Relation::Gt,
            Relation::Ge,
            Relation::Eq,
            Relation::Ne,
        ] {
            assert_eq!(invert(invert(relation)), relation);
        }
    }
}
