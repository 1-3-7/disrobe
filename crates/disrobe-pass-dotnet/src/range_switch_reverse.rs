use std::fmt::Write as _;

use crate::cfg::{BlockId, Cfg, Terminator};
use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, SlotOp, slot_index_of};
use crate::names::NameTable;
use crate::structurize::{TargetLang, TokenNamer, csharp_string_literal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Arg(u32),
    Local(u32),
}

#[derive(Debug, Clone, Copy)]
struct Bounds {
    lower: Option<i64>,
    upper: Option<i64>,
}

impl Bounds {
    const fn unbounded() -> Self {
        Self {
            lower: None,
            upper: None,
        }
    }

    const fn is_finite_range(&self) -> bool {
        self.lower.is_some() && self.upper.is_some()
    }
}

#[derive(Debug, Clone)]
struct RangeArm {
    lower: i64,
    upper: i64,
    value: String,
}

#[must_use]
pub(crate) fn reconstruct_range_switch<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> Option<String> {
    if lang != TargetLang::CSharp || !has_range_shape(body) {
        return None;
    }
    let cfg: Cfg = Cfg::build(body);
    if cfg.blocks.len() < 4 {
        return None;
    }
    let (result_local, epilogue): (u32, BlockId) = find_epilogue(&cfg, body)?;
    let discriminant: Discriminant = entry_discriminant(&cfg, body)?;

    let ctx: WalkCtx<'_, N> = WalkCtx {
        cfg: &cfg,
        body,
        namer,
        discriminant,
        result_local,
        epilogue,
    };
    let mut arms: Vec<RangeArm> = Vec::new();
    let mut default_value: Option<String> = None;
    let mut visited_guard: u32 = 0;
    walk(
        &ctx,
        cfg.entry,
        Bounds::unbounded(),
        &mut arms,
        &mut default_value,
        &mut visited_guard,
    )?;

    if arms.len() < 2 {
        return None;
    }
    arms.sort_by_key(|a: &RangeArm| a.lower);
    if arms
        .windows(2)
        .any(|w: &[RangeArm]| w[0].upper > w[1].lower)
    {
        return None;
    }
    let discriminant_name: String = render_discriminant(discriminant, names);
    Some(render_range_switch(
        &discriminant_name,
        &arms,
        &default_value?,
    ))
}

fn has_range_shape(body: &MethodBody) -> bool {
    let mut int_compares: u32 = 0;
    let mut has_store: bool = false;
    for ins in &body.instructions {
        if branch_relation(&ins.name).is_some() {
            int_compares = int_compares.saturating_add(1);
        }
        if stloc_slot(ins).is_some() {
            has_store = true;
        }
    }
    int_compares >= 3 && has_store
}

struct WalkCtx<'a, N: TokenNamer> {
    cfg: &'a Cfg,
    body: &'a MethodBody,
    namer: &'a N,
    discriminant: Discriminant,
    result_local: u32,
    epilogue: BlockId,
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

fn entry_discriminant(cfg: &Cfg, body: &MethodBody) -> Option<Discriminant> {
    let slice: &[Instruction] = block_real_instrs(cfg, body, cfg.entry);
    load_discriminant(slice.first()?)
}

fn walk<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
    bounds: Bounds,
    arms: &mut Vec<RangeArm>,
    default_value: &mut Option<String>,
    visited_guard: &mut u32,
) -> Option<()> {
    *visited_guard = visited_guard.checked_add(1)?;
    if *visited_guard > 256 {
        return None;
    }
    if bid == ctx.epilogue {
        return Some(());
    }
    if let Some(value) = leaf_value(ctx, bid) {
        return record_leaf(bounds, value, arms, default_value);
    }

    match ctx.cfg.terminators[bid] {
        Terminator::Cond { taken, fallthrough } => {
            let (relation, literal): (Relation, i64) = comparison(ctx, bid)?;
            let (taken_bounds, ft_bounds): (Bounds, Bounds) =
                split_bounds(bounds, relation, literal)?;
            walk(ctx, taken, taken_bounds, arms, default_value, visited_guard)?;
            walk(
                ctx,
                fallthrough,
                ft_bounds,
                arms,
                default_value,
                visited_guard,
            )
        }
        Terminator::Goto(next) | Terminator::FallThrough(next)
            if block_body_ops(ctx.cfg, ctx.body, bid).is_empty() =>
        {
            walk(ctx, next, bounds, arms, default_value, visited_guard)
        }
        _ => None,
    }
}

fn record_leaf(
    bounds: Bounds,
    value: String,
    arms: &mut Vec<RangeArm>,
    default_value: &mut Option<String>,
) -> Option<()> {
    if bounds.is_finite_range() {
        let lower: i64 = bounds.lower?;
        let upper: i64 = bounds.upper?;
        if lower >= upper {
            return None;
        }
        arms.push(RangeArm {
            lower,
            upper,
            value,
        });
        return Some(());
    }
    match default_value {
        Some(existing) if *existing != value => None,
        _ => {
            *default_value = Some(value);
            Some(())
        }
    }
}

fn leaf_value<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> Option<String> {
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
    constant_value(push, ctx.namer)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

fn comparison<N: TokenNamer>(ctx: &WalkCtx<'_, N>, bid: BlockId) -> Option<(Relation, i64)> {
    let full: &[Instruction] = block_real_instrs(ctx.cfg, ctx.body, bid);
    let branch: &Instruction = full.last()?;
    let relation: Relation = branch_relation(&branch.name)?;
    let head: &[Instruction] = block_body_ops(ctx.cfg, ctx.body, bid);
    let [load, push]: &[Instruction] = head else {
        return None;
    };
    if load_discriminant(load)? != ctx.discriminant {
        return None;
    }
    let literal: i64 = match push.name.as_str() {
        "ldc.i4.m1" => -1,
        name if name.starts_with("ldc.i4") => int_const(push, name),
        _ => return None,
    };
    Some((relation, literal))
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

fn split_bounds(bounds: Bounds, relation: Relation, literal: i64) -> Option<(Bounds, Bounds)> {
    let taken: Bounds = apply_relation(bounds, relation, literal)?;
    let ft: Bounds = apply_relation(bounds, invert(relation), literal)?;
    Some((taken, ft))
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

fn apply_relation(bounds: Bounds, relation: Relation, literal: i64) -> Option<Bounds> {
    let mut out: Bounds = bounds;
    match relation {
        Relation::Ge => out.lower = Some(max_opt(out.lower, literal)),
        Relation::Gt => out.lower = Some(max_opt(out.lower, literal.checked_add(1)?)),
        Relation::Lt => out.upper = Some(min_opt(out.upper, literal)),
        Relation::Le => out.upper = Some(min_opt(out.upper, literal.checked_add(1)?)),
        Relation::Eq | Relation::Ne => return None,
    }
    Some(out)
}

fn max_opt(current: Option<i64>, incoming: i64) -> i64 {
    current.map_or(incoming, |c: i64| c.max(incoming))
}

fn min_opt(current: Option<i64>, incoming: i64) -> i64 {
    current.map_or(incoming, |c: i64| c.min(incoming))
}

fn render_discriminant(discriminant: Discriminant, names: &NameTable) -> String {
    match discriminant {
        Discriminant::Arg(slot) => names.arg_name(slot),
        Discriminant::Local(slot) => NameTable::local_name(slot),
    }
}

fn render_range_switch(discriminant: &str, arms: &[RangeArm], default_value: &str) -> String {
    let mut text: String = String::new();
    let _ = writeln!(text, "    return {discriminant} switch");
    let _ = writeln!(text, "    {{");
    for arm in arms {
        let _ = writeln!(
            text,
            "        >= {} and < {} => {},",
            arm.lower, arm.upper, arm.value
        );
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

fn load_discriminant(ins: &Instruction) -> Option<Discriminant> {
    if let Some(slot) = ldarg_slot(ins) {
        return Some(Discriminant::Arg(slot));
    }
    ldloc_slot(ins).map(Discriminant::Local)
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
    fn record_leaf_rejects_conflicting_defaults() {
        let mut arms: Vec<RangeArm> = Vec::new();
        let mut default_value: Option<String> = None;
        let first: Option<()> = record_leaf(
            Bounds::unbounded(),
            "\"a\"".to_owned(),
            &mut arms,
            &mut default_value,
        );
        assert_eq!(first, Some(()));
        let second: Option<()> = record_leaf(
            Bounds::unbounded(),
            "\"b\"".to_owned(),
            &mut arms,
            &mut default_value,
        );
        assert_eq!(second, None);
    }

    #[test]
    fn record_leaf_pushes_finite_range_arm() {
        let mut arms: Vec<RangeArm> = Vec::new();
        let mut default_value: Option<String> = None;
        let bounds: Bounds = Bounds {
            lower: Some(10),
            upper: Some(100),
        };
        let pushed: Option<()> =
            record_leaf(bounds, "\"mid\"".to_owned(), &mut arms, &mut default_value);
        assert_eq!(pushed, Some(()));
        assert_eq!(arms.len(), 1);
        assert_eq!(arms[0].lower, 10);
        assert_eq!(arms[0].upper, 100);
        assert!(default_value.is_none());
    }

    #[test]
    fn split_bounds_refines_both_directions() {
        let (taken, ft): (Bounds, Bounds) =
            split_bounds(Bounds::unbounded(), Relation::Ge, 100).expect("split");
        assert_eq!(taken.lower, Some(100));
        assert_eq!(taken.upper, None);
        assert_eq!(ft.lower, None);
        assert_eq!(ft.upper, Some(100));
    }

    #[test]
    fn split_bounds_handles_strict_less_than() {
        let bounds: Bounds = Bounds {
            lower: Some(0),
            upper: None,
        };
        let (taken, ft): (Bounds, Bounds) = split_bounds(bounds, Relation::Lt, 10).expect("split");
        assert_eq!(taken.lower, Some(0));
        assert_eq!(taken.upper, Some(10));
        assert_eq!(ft.lower, Some(10));
        assert_eq!(ft.upper, None);
    }

    #[test]
    fn rejects_equality_branches() {
        assert!(apply_relation(Bounds::unbounded(), Relation::Eq, 3).is_none());
        assert!(apply_relation(Bounds::unbounded(), Relation::Ne, 3).is_none());
    }

    #[test]
    fn renders_ascending_arms_with_default() {
        let arms: Vec<RangeArm> = vec![
            RangeArm {
                lower: 0,
                upper: 10,
                value: "\"low\"".to_owned(),
            },
            RangeArm {
                lower: 10,
                upper: 100,
                value: "\"mid\"".to_owned(),
            },
        ];
        let out: String = render_range_switch("n", &arms, "\"extreme\"");
        assert!(out.contains("return n switch"), "{out}");
        assert!(out.contains(">= 0 and < 10 => \"low\","), "{out}");
        assert!(out.contains(">= 10 and < 100 => \"mid\","), "{out}");
        assert!(out.contains("_ => \"extreme\","), "{out}");
    }
}
