use std::fmt::Write as _;

use crate::cfg::{BlockId, Cfg, Terminator};
use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, SlotOp, slot_index_of};
use crate::names::NameTable;
use crate::structurize::{TargetLang, TokenNamer, csharp_string_literal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subject {
    Arg(u32),
    Local(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropBounds {
    Eq(i64),
    Lower { relation: Relation, literal: i64 },
    Upper { relation: Relation, literal: i64 },
    Range { lower: RelClause, upper: RelClause },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelClause {
    relation: Relation,
    literal: i64,
}

#[derive(Debug, Clone)]
struct PropConstraint {
    name: String,
    bounds: PropBounds,
}

#[derive(Debug, Clone)]
struct PathState {
    type_pattern: Option<String>,
    bound_local: Option<u32>,
    props: Vec<PropConstraint>,
    cached: Option<(u32, String)>,
}

impl PathState {
    const fn root() -> Self {
        Self {
            type_pattern: None,
            bound_local: None,
            props: Vec::new(),
            cached: None,
        }
    }

    fn add_equal(&mut self, name: String, value: i64) {
        self.props.push(PropConstraint {
            name,
            bounds: PropBounds::Eq(value),
        });
    }

    fn add_relation(&mut self, name: &str, relation: Relation, literal: i64) -> Option<()> {
        let clause: RelClause = RelClause { relation, literal };
        let is_lower: bool = matches!(relation, Relation::Ge | Relation::Gt);
        if let Some(existing) = self
            .props
            .iter_mut()
            .find(|p: &&mut PropConstraint| p.name == name)
        {
            let merged: PropBounds = merge_bound(existing.bounds, clause, is_lower)?;
            existing.bounds = merged;
            return Some(());
        }
        let bounds: PropBounds = if is_lower {
            PropBounds::Lower { relation, literal }
        } else {
            PropBounds::Upper { relation, literal }
        };
        self.props.push(PropConstraint {
            name: name.to_owned(),
            bounds,
        });
        Some(())
    }
}

const fn merge_bound(
    existing: PropBounds,
    clause: RelClause,
    is_lower: bool,
) -> Option<PropBounds> {
    match existing {
        PropBounds::Lower { relation, literal } if is_lower => {
            let s: RelClause = stricter_lower(RelClause { relation, literal }, clause);
            Some(PropBounds::Lower {
                relation: s.relation,
                literal: s.literal,
            })
        }
        PropBounds::Upper { relation, literal } if !is_lower => {
            let s: RelClause = stricter_upper(RelClause { relation, literal }, clause);
            Some(PropBounds::Upper {
                relation: s.relation,
                literal: s.literal,
            })
        }
        PropBounds::Lower { relation, literal } => Some(PropBounds::Range {
            lower: RelClause { relation, literal },
            upper: clause,
        }),
        PropBounds::Upper { relation, literal } => Some(PropBounds::Range {
            lower: clause,
            upper: RelClause { relation, literal },
        }),
        PropBounds::Range { lower, upper } if is_lower => Some(PropBounds::Range {
            lower: stricter_lower(lower, clause),
            upper,
        }),
        PropBounds::Range { lower, upper } => Some(PropBounds::Range {
            lower,
            upper: stricter_upper(upper, clause),
        }),
        PropBounds::Eq(_) => None,
    }
}

const fn lower_floor(clause: RelClause) -> i64 {
    match clause.relation {
        Relation::Gt => clause.literal.saturating_add(1),
        Relation::Ge | Relation::Lt | Relation::Le => clause.literal,
    }
}

const fn upper_ceiling(clause: RelClause) -> i64 {
    match clause.relation {
        Relation::Le => clause.literal.saturating_add(1),
        Relation::Lt | Relation::Gt | Relation::Ge => clause.literal,
    }
}

const fn stricter_lower(a: RelClause, b: RelClause) -> RelClause {
    if lower_floor(a) >= lower_floor(b) {
        a
    } else {
        b
    }
}

const fn stricter_upper(a: RelClause, b: RelClause) -> RelClause {
    if upper_ceiling(a) <= upper_ceiling(b) {
        a
    } else {
        b
    }
}

#[derive(Debug, Clone)]
struct Arm {
    offset: u32,
    type_pattern: Option<String>,
    props: Vec<PropConstraint>,
    value: String,
}

struct WalkCtx<'a, N: TokenNamer> {
    cfg: &'a Cfg,
    body: &'a MethodBody,
    namer: &'a N,
    subject: Subject,
    result_local: u32,
    epilogue: BlockId,
    default_block: BlockId,
}

#[must_use]
pub(crate) fn reconstruct_property_switch<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> Option<String> {
    if lang != TargetLang::CSharp || !has_property_shape(body) {
        return None;
    }
    let cfg: Cfg = Cfg::build(body);
    if cfg.blocks.len() < 4 {
        return None;
    }
    let (result_local, epilogue): (u32, BlockId) = find_epilogue(&cfg, body)?;
    let default_block: BlockId = find_default_block(&cfg, body, result_local, epilogue)?;
    let subject: Subject = entry_subject(&cfg, body)?;

    let ctx: WalkCtx<'_, N> = WalkCtx {
        cfg: &cfg,
        body,
        namer,
        subject,
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
        PathState::root(),
        &mut arms,
        &mut default_value,
        &mut budget,
    )?;

    if arms.len() < 2 {
        return None;
    }
    if arms.iter().any(|a: &Arm| a.props.is_empty()) {
        return None;
    }
    arms.sort_by_key(|a: &Arm| a.offset);
    let subject_name: String = render_subject(subject, names);
    Some(render_property_switch(
        &subject_name,
        &arms,
        &default_value?,
    ))
}

fn has_property_shape(body: &MethodBody) -> bool {
    let denoised: Vec<&Instruction> = body
        .instructions
        .iter()
        .filter(|ins: &&Instruction| !is_noise(&ins.name))
        .collect();
    let mut field_tests: u32 = 0;
    let mut has_store: bool = false;
    let mut has_property_cache: bool = false;
    for window in denoised.windows(2) {
        if is_member_load(&window[0].name) && is_bool_branch(&window[1].name) {
            field_tests = field_tests.saturating_add(1);
        }
        if stloc_slot(window[1]).is_some() {
            has_store = true;
        }
        if is_member_load(&window[0].name) && stloc_slot(window[1]).is_some() {
            has_property_cache = true;
        }
    }
    for window in denoised.windows(3) {
        if is_member_load(&window[0].name)
            && is_int_const(window[1])
            && (is_equality_branch(&window[2].name) || branch_relation(&window[2].name).is_some())
        {
            field_tests = field_tests.saturating_add(1);
        }
    }
    let has_switch: bool = denoised
        .iter()
        .any(|ins: &&Instruction| ins.name == "switch");
    let has_relational: bool = denoised
        .iter()
        .any(|ins: &&Instruction| branch_relation(&ins.name).is_some());
    (field_tests >= 2 || (has_property_cache && (has_switch || has_relational))) && has_store
}

fn is_member_load(name: &str) -> bool {
    matches!(name, "ldfld" | "call" | "callvirt" | "ldlen")
}

fn is_bool_branch(name: &str) -> bool {
    matches!(name, "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s")
}

fn is_equality_branch(name: &str) -> bool {
    matches!(name, "beq" | "beq.s" | "bne.un" | "bne.un.s")
}

fn is_int_const(ins: &Instruction) -> bool {
    int_constant(ins).is_some()
}

fn member_property_name<N: TokenNamer>(member: &Instruction, namer: &N) -> Option<String> {
    if member.name == "ldlen" {
        return Some("Length".to_owned());
    }
    let OperandValue::Token(tok): OperandValue = member.operand else {
        return None;
    };
    match member.name.as_str() {
        "ldfld" => Some(short_field_name(&namer.name(tok))),
        "call" | "callvirt" => property_from_getter(&namer.name(tok)),
        _ => None,
    }
}

fn property_from_getter(callee: &str) -> Option<String> {
    let short: &str = callee.rsplit("::").next().unwrap_or(callee);
    let name: &str = short.split('(').next().unwrap_or(short);
    let prop: &str = name.strip_prefix("get_")?;
    (!prop.is_empty()
        && prop
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_'))
    .then(|| prop.to_owned())
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

fn entry_subject(cfg: &Cfg, body: &MethodBody) -> Option<Subject> {
    let head: &[Instruction] = block_body_ops(cfg, body, cfg.entry);
    let first: &Instruction = head.first()?;
    subject_of(first)
}

fn subject_of(ins: &Instruction) -> Option<Subject> {
    if let Some(slot) = ldarg_slot(ins) {
        return Some(Subject::Arg(slot));
    }
    ldloc_slot(ins).map(Subject::Local)
}

fn walk<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
    state: PathState,
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
        arms.push(Arm {
            offset,
            type_pattern: state.type_pattern,
            props: state.props,
            value,
        });
        return Some(());
    }

    match &ctx.cfg.terminators[bid] {
        Terminator::Cond { taken, fallthrough } => {
            let (taken, fallthrough): (BlockId, BlockId) = (*taken, *fallthrough);
            let test: BlockTest = classify_test(ctx, bid, &state)?;
            let (taken_state, ft_state): (PathState, PathState) = test.split(state)?;
            walk(ctx, taken, taken_state, arms, default_value, budget)?;
            walk(ctx, fallthrough, ft_state, arms, default_value, budget)
        }
        Terminator::Switch { cases, fallthrough } => {
            let cases: Vec<BlockId> = cases.clone();
            let fallthrough: BlockId = *fallthrough;
            walk_jump_table(
                ctx,
                bid,
                &cases,
                fallthrough,
                &state,
                arms,
                default_value,
                budget,
            )
        }
        Terminator::Goto(next) | Terminator::FallThrough(next)
            if block_body_ops(ctx.cfg, ctx.body, bid).is_empty() =>
        {
            let next: BlockId = *next;
            walk(ctx, next, state, arms, default_value, budget)
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_jump_table<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
    cases: &[BlockId],
    fallthrough: BlockId,
    state: &PathState,
    arms: &mut Vec<Arm>,
    default_value: &mut Option<String>,
    budget: &mut u32,
) -> Option<()> {
    let table: JumpTable = classify_jump_table(ctx, bid, state)?;
    for (index, &case) in cases.iter().enumerate() {
        if resolves_to_default(ctx, case) {
            continue;
        }
        let constant: i64 = table.base.checked_add(i64::try_from(index).ok()?)?;
        let mut branch_state: PathState = state.clone();
        branch_state.add_equal(table.name.clone(), constant);
        walk(ctx, case, branch_state, arms, default_value, budget)?;
    }
    walk(ctx, fallthrough, state.clone(), arms, default_value, budget)
}

fn resolves_to_default<N: TokenNamer>(ctx: &WalkCtx<'_, N>, mut bid: BlockId) -> bool {
    let mut hops: u32 = 0;
    while bid != ctx.default_block {
        hops = hops.saturating_add(1);
        if hops > 8 || !block_body_ops(ctx.cfg, ctx.body, bid).is_empty() {
            return false;
        }
        match ctx.cfg.terminators[bid] {
            Terminator::Goto(next) | Terminator::FallThrough(next) => bid = next,
            _ => return false,
        }
    }
    true
}

struct JumpTable {
    name: String,
    base: i64,
}

fn classify_jump_table<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
    state: &PathState,
) -> Option<JumpTable> {
    let ops: Vec<&Instruction> = block_body_ops(ctx.cfg, ctx.body, bid)
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    let [load, member, cache, reload, tail @ ..] = ops.as_slice() else {
        return None;
    };
    if !field_load_matches_subject(load, state, ctx.subject) {
        return None;
    }
    let name: String = member_property_name(member, ctx.namer)?;
    let cached: u32 = stloc_slot(cache)?;
    if ldloc_slot(reload) != Some(cached) {
        return None;
    }
    let base: i64 = match tail {
        [konst, sub] if sub.name == "sub" => int_constant(konst)?,
        [] => 0,
        _ => return None,
    };
    Some(JumpTable { name, base })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Lt,
    Le,
    Gt,
    Ge,
}

enum BlockTest {
    Null,
    Type {
        pattern: String,
        bound_local: u32,
    },
    Field {
        name: String,
        constant: i64,
        taken_equal: bool,
    },
    Relational {
        name: String,
        relation: Relation,
        literal: i64,
    },
    CacheRelational {
        name: String,
        cache_local: u32,
        relation: Relation,
        literal: i64,
    },
    CachedRelational {
        name: String,
        relation: Relation,
        literal: i64,
    },
}

impl BlockTest {
    fn split(&self, state: PathState) -> Option<(PathState, PathState)> {
        match self {
            Self::Null => Some((state.clone(), state)),
            Self::Type {
                pattern,
                bound_local,
            } => {
                let ft: PathState = PathState {
                    type_pattern: Some(pattern.clone()),
                    bound_local: Some(*bound_local),
                    props: state.props,
                    cached: None,
                };
                let taken: PathState = PathState::root();
                Some((taken, ft))
            }
            Self::Field {
                name,
                constant,
                taken_equal,
            } => {
                let mut with_prop: PathState = state.clone();
                with_prop.add_equal(name.clone(), *constant);
                Some(if *taken_equal {
                    (with_prop, state)
                } else {
                    (state, with_prop)
                })
            }
            Self::Relational {
                name,
                relation,
                literal,
            } => {
                let mut taken: PathState = state.clone();
                taken.add_relation(name, *relation, *literal)?;
                Some((taken, state))
            }
            Self::CachedRelational {
                name,
                relation,
                literal,
            } => split_cached_relational(state, name, *relation, *literal),
            Self::CacheRelational {
                name,
                cache_local,
                relation,
                literal,
            } => {
                let mut base: PathState = state;
                base.cached = Some((*cache_local, name.clone()));
                split_cached_relational(base, name, *relation, *literal)
            }
        }
    }
}

fn split_cached_relational(
    state: PathState,
    name: &str,
    relation: Relation,
    literal: i64,
) -> Option<(PathState, PathState)> {
    let mut taken: PathState = state.clone();
    taken.add_relation(name, relation, literal)?;
    let mut ft: PathState = state;
    ft.add_relation(name, invert_relation(relation), literal)?;
    Some((taken, ft))
}

fn classify_test<N: TokenNamer>(
    ctx: &WalkCtx<'_, N>,
    bid: BlockId,
    state: &PathState,
) -> Option<BlockTest> {
    let full: &[Instruction] = block_real_instrs(ctx.cfg, ctx.body, bid);
    let branch: &Instruction = full.last()?;
    let head: Vec<&Instruction> = block_body_ops(ctx.cfg, ctx.body, bid)
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    match head.as_slice() {
        [load] => {
            if subject_of(load) != Some(ctx.subject) {
                return None;
            }
            matches!(
                branch.name.as_str(),
                "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s"
            )
            .then_some(BlockTest::Null)
        }
        [load, isinst, store, reload] => {
            if subject_of(load) != Some(ctx.subject) || isinst.name != "isinst" {
                return None;
            }
            let bound_local: u32 = stloc_slot(store)?;
            if ldloc_slot(reload) != Some(bound_local) {
                return None;
            }
            if !matches!(branch.name.as_str(), "brfalse" | "brfalse.s") {
                return None;
            }
            let OperandValue::Token(tok): OperandValue = isinst.operand else {
                return None;
            };
            Some(BlockTest::Type {
                pattern: keyword_type(&ctx.namer.name(tok)),
                bound_local,
            })
        }
        [first, second] => {
            if let Some((cache_local, name)) = state.cached.as_ref()
                && ldloc_slot(first) == Some(*cache_local)
                && let Some(literal) = int_constant(second)
                && let Some(relation) = branch_relation(&branch.name)
            {
                return Some(BlockTest::CachedRelational {
                    name: name.clone(),
                    relation,
                    literal,
                });
            }
            if !field_load_matches_subject(first, state, ctx.subject) {
                return None;
            }
            let name: String = member_property_name(second, ctx.namer)?;
            let taken_equal: bool = match branch.name.as_str() {
                "brfalse" | "brfalse.s" => true,
                "brtrue" | "brtrue.s" => false,
                _ => return None,
            };
            Some(BlockTest::Field {
                name,
                constant: 0,
                taken_equal,
            })
        }
        [load, member, konst] => {
            if !field_load_matches_subject(load, state, ctx.subject) {
                return None;
            }
            let name: String = member_property_name(member, ctx.namer)?;
            let constant: i64 = int_constant(konst)?;
            if let Some(relation) = branch_relation(&branch.name) {
                return Some(BlockTest::Relational {
                    name,
                    relation,
                    literal: constant,
                });
            }
            let taken_equal: bool = match branch.name.as_str() {
                "beq" | "beq.s" => true,
                "bne.un" | "bne.un.s" => false,
                _ => return None,
            };
            Some(BlockTest::Field {
                name,
                constant,
                taken_equal,
            })
        }
        [load, member, cache, reload, konst] => {
            if !field_load_matches_subject(load, state, ctx.subject) {
                return None;
            }
            let name: String = member_property_name(member, ctx.namer)?;
            let cache_local: u32 = stloc_slot(cache)?;
            if ldloc_slot(reload) != Some(cache_local) {
                return None;
            }
            let literal: i64 = int_constant(konst)?;
            let relation: Relation = branch_relation(&branch.name)?;
            Some(BlockTest::CacheRelational {
                name,
                cache_local,
                relation,
                literal,
            })
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
        _ => return None,
    })
}

const fn invert_relation(relation: Relation) -> Relation {
    match relation {
        Relation::Lt => Relation::Ge,
        Relation::Le => Relation::Gt,
        Relation::Gt => Relation::Le,
        Relation::Ge => Relation::Lt,
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

fn field_load_matches_subject(load: &Instruction, state: &PathState, subject: Subject) -> bool {
    state.bound_local.map_or_else(
        || subject_of(load) == Some(subject),
        |local: u32| ldloc_slot(load) == Some(local),
    )
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

fn render_subject(subject: Subject, names: &NameTable) -> String {
    match subject {
        Subject::Arg(slot) => names.arg_name(slot),
        Subject::Local(slot) => NameTable::local_name(slot),
    }
}

fn render_arm_pattern(arm: &Arm) -> String {
    let props: String = arm
        .props
        .iter()
        .map(render_constraint)
        .collect::<Vec<String>>()
        .join(", ");
    arm.type_pattern.as_ref().map_or_else(
        || format!("{{ {props} }}"),
        |ty: &String| format!("{ty} {{ {props} }}"),
    )
}

fn render_constraint(constraint: &PropConstraint) -> String {
    let name: &str = &constraint.name;
    match constraint.bounds {
        PropBounds::Eq(value) => format!("{name}: {value}"),
        PropBounds::Lower { relation, literal } | PropBounds::Upper { relation, literal } => {
            format!("{name}: {} {literal}", relation_token(relation))
        }
        PropBounds::Range { lower, upper } => format!(
            "{name}: {} {} and {} {}",
            relation_token(lower.relation),
            lower.literal,
            relation_token(upper.relation),
            upper.literal
        ),
    }
}

const fn relation_token(relation: Relation) -> &'static str {
    match relation {
        Relation::Lt => "<",
        Relation::Le => "<=",
        Relation::Gt => ">",
        Relation::Ge => ">=",
    }
}

fn render_property_switch(subject: &str, arms: &[Arm], default_value: &str) -> String {
    let mut text: String = String::new();
    let _ = writeln!(text, "    return {subject} switch");
    let _ = writeln!(text, "    {{");
    for arm in arms {
        let _ = writeln!(
            text,
            "        {} => {},",
            render_arm_pattern(arm),
            arm.value
        );
    }
    let _ = writeln!(text, "        _ => {default_value},");
    let _ = writeln!(text, "    }};");
    text
}

fn short_field_name(name: &str) -> String {
    name.rsplit("::").next().unwrap_or(name).to_owned()
}

fn keyword_type(ty: &str) -> String {
    let bare: &str = ty.split('<').next().unwrap_or(ty);
    let short: &str = bare.rsplit('.').next().unwrap_or(bare);
    let mapped: &str = match short {
        "Boolean" => "bool",
        "Byte" => "byte",
        "SByte" => "sbyte",
        "Char" => "char",
        "Int16" => "short",
        "UInt16" => "ushort",
        "Int32" => "int",
        "UInt32" => "uint",
        "Int64" => "long",
        "UInt64" => "ulong",
        "Single" => "float",
        "Double" => "double",
        "Decimal" => "decimal",
        "String" => "string",
        "Object" => "object",
        _ => short,
    };
    mapped.to_owned()
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

    fn eq(name: &str, value: i64) -> PropConstraint {
        PropConstraint {
            name: name.to_owned(),
            bounds: PropBounds::Eq(value),
        }
    }

    fn eq_names(props: &[PropConstraint]) -> Vec<(String, i64)> {
        props
            .iter()
            .map(|p: &PropConstraint| match p.bounds {
                PropBounds::Eq(v) => (p.name.clone(), v),
                _ => panic!("expected Eq constraint"),
            })
            .collect()
    }

    #[test]
    fn keyword_type_maps_primitives_and_keeps_user_types() {
        assert_eq!(keyword_type("Sample.Box"), "Box");
        assert_eq!(keyword_type("System.Int32"), "int");
        assert_eq!(keyword_type("String"), "string");
    }

    #[test]
    fn short_field_name_strips_declaring_type() {
        assert_eq!(short_field_name("Sample.Box::X"), "X");
        assert_eq!(short_field_name("Length"), "Length");
    }

    #[test]
    fn property_from_getter_extracts_name() {
        assert_eq!(
            property_from_getter("System.String::get_Length()").as_deref(),
            Some("Length")
        );
        assert_eq!(property_from_getter("Foo::set_X()"), None);
        assert_eq!(property_from_getter("Foo::Method()"), None);
    }

    #[test]
    fn field_split_puts_equal_on_taken_for_brfalse() {
        let state: PathState = PathState::root();
        let test: BlockTest = BlockTest::Field {
            name: "X".to_owned(),
            constant: 0,
            taken_equal: true,
        };
        let (taken, ft): (PathState, PathState) = test.split(state).expect("split");
        assert_eq!(eq_names(&taken.props), vec![("X".to_owned(), 0)]);
        assert!(ft.props.is_empty());
    }

    #[test]
    fn type_split_resets_taken_and_binds_fallthrough() {
        let state: PathState = PathState::root();
        let test: BlockTest = BlockTest::Type {
            pattern: "Box".to_owned(),
            bound_local: 1,
        };
        let (taken, ft): (PathState, PathState) = test.split(state).expect("split");
        assert!(taken.type_pattern.is_none());
        assert_eq!(ft.type_pattern.as_deref(), Some("Box"));
        assert_eq!(ft.bound_local, Some(1));
    }

    #[test]
    fn relational_split_leaves_fallthrough_unconstrained() {
        let state: PathState = PathState::root();
        let test: BlockTest = BlockTest::Relational {
            name: "Major".to_owned(),
            relation: Relation::Gt,
            literal: 0,
        };
        let (taken, ft): (PathState, PathState) = test.split(state).expect("split");
        assert_eq!(
            taken.props[0].bounds,
            PropBounds::Lower {
                relation: Relation::Gt,
                literal: 0,
            }
        );
        assert!(ft.props.is_empty());
    }

    #[test]
    fn cached_relational_split_records_inverted_bound_on_fallthrough() {
        let mut state: PathState = PathState::root();
        state.cached = Some((1, "Major".to_owned()));
        let test: BlockTest = BlockTest::CachedRelational {
            name: "Major".to_owned(),
            relation: Relation::Ge,
            literal: 5,
        };
        let (taken, ft): (PathState, PathState) = test.split(state).expect("split");
        assert_eq!(
            taken.props[0].bounds,
            PropBounds::Lower {
                relation: Relation::Ge,
                literal: 5,
            }
        );
        assert_eq!(
            ft.props[0].bounds,
            PropBounds::Upper {
                relation: Relation::Lt,
                literal: 5,
            }
        );
    }

    #[test]
    fn add_relation_forms_range_from_lower_then_upper() {
        let mut state: PathState = PathState::root();
        state.add_relation("Major", Relation::Ge, 1).expect("lower");
        state.add_relation("Major", Relation::Lt, 5).expect("upper");
        assert_eq!(state.props.len(), 1);
        assert_eq!(
            state.props[0].bounds,
            PropBounds::Range {
                lower: RelClause {
                    relation: Relation::Ge,
                    literal: 1,
                },
                upper: RelClause {
                    relation: Relation::Lt,
                    literal: 5,
                },
            }
        );
    }

    #[test]
    fn add_relation_tightens_two_lower_bounds() {
        let mut state: PathState = PathState::root();
        state.add_relation("Major", Relation::Ge, 5).expect("first");
        state
            .add_relation("Major", Relation::Ge, 10)
            .expect("second");
        assert_eq!(state.props.len(), 1);
        assert_eq!(
            state.props[0].bounds,
            PropBounds::Lower {
                relation: Relation::Ge,
                literal: 10,
            }
        );
    }

    #[test]
    fn render_arm_property_only() {
        let arm: Arm = Arm {
            offset: 0,
            type_pattern: None,
            props: vec![eq("X", 0), eq("Y", 0)],
            value: "\"origin\"".to_owned(),
        };
        assert_eq!(render_arm_pattern(&arm), "{ X: 0, Y: 0 }");
    }

    #[test]
    fn render_arm_single_relational_bound() {
        let arm: Arm = Arm {
            offset: 0,
            type_pattern: None,
            props: vec![PropConstraint {
                name: "Major".to_owned(),
                bounds: PropBounds::Lower {
                    relation: Relation::Gt,
                    literal: 0,
                },
            }],
            value: "\"pos\"".to_owned(),
        };
        assert_eq!(render_arm_pattern(&arm), "{ Major: > 0 }");
    }

    #[test]
    fn render_arm_range_bound() {
        let arm: Arm = Arm {
            offset: 0,
            type_pattern: None,
            props: vec![PropConstraint {
                name: "Major".to_owned(),
                bounds: PropBounds::Range {
                    lower: RelClause {
                        relation: Relation::Ge,
                        literal: 1,
                    },
                    upper: RelClause {
                        relation: Relation::Lt,
                        literal: 5,
                    },
                },
            }],
            value: "\"early\"".to_owned(),
        };
        assert_eq!(render_arm_pattern(&arm), "{ Major: >= 1 and < 5 }");
    }

    #[test]
    fn render_arm_type_and_property() {
        let arm: Arm = Arm {
            offset: 0,
            type_pattern: Some("Box".to_owned()),
            props: vec![eq("X", 0)],
            value: "\"bx\"".to_owned(),
        };
        assert_eq!(render_arm_pattern(&arm), "Box { X: 0 }");
    }

    fn ldc(name: &str, operand: OperandValue) -> Instruction {
        Instruction {
            offset: 0,
            opcode: 0,
            name: name.to_owned(),
            operand,
            flow: FlowControl::Next,
        }
    }

    #[test]
    fn int_constant_reads_short_and_wide_forms() {
        assert_eq!(int_constant(&ldc("ldc.i4.2", OperandValue::None)), Some(2));
        assert_eq!(
            int_constant(&ldc("ldc.i4.m1", OperandValue::None)),
            Some(-1)
        );
        assert_eq!(
            int_constant(&ldc("ldc.i4.s", OperandValue::U8(0xFB))),
            Some(-5)
        );
        assert_eq!(
            int_constant(&ldc("ldc.i4", OperandValue::I32(300))),
            Some(300)
        );
        assert_eq!(int_constant(&ldc("ldc.i8", OperandValue::I64(9))), Some(9));
        assert_eq!(int_constant(&ldc("ldstr", OperandValue::Token(1))), None);
    }

    #[test]
    fn field_split_records_nonzero_constant_on_taken_for_beq() {
        let state: PathState = PathState::root();
        let test: BlockTest = BlockTest::Field {
            name: "Major".to_owned(),
            constant: 2,
            taken_equal: true,
        };
        let (taken, ft): (PathState, PathState) = test.split(state).expect("split");
        assert_eq!(eq_names(&taken.props), vec![("Major".to_owned(), 2)]);
        assert!(ft.props.is_empty());
    }

    #[test]
    fn render_arm_nonzero_property() {
        let arm: Arm = Arm {
            offset: 0,
            type_pattern: None,
            props: vec![eq("Major", 2)],
            value: "\"maj\"".to_owned(),
        };
        assert_eq!(render_arm_pattern(&arm), "{ Major: 2 }");
    }

    struct StubNamer;

    impl crate::structurize::TokenNamer for StubNamer {
        fn name(&self, token: u32) -> String {
            match token {
                100 => "System.Version::get_Major()".to_owned(),
                200 => "one".to_owned(),
                201 => "two".to_owned(),
                202 => "three".to_owned(),
                203 => "other".to_owned(),
                210 => "early".to_owned(),
                211 => "mid".to_owned(),
                212 => "late".to_owned(),
                _ => format!("tok_{token}"),
            }
        }
    }

    fn ins(offset: u32, name: &str, operand: OperandValue, flow: FlowControl) -> Instruction {
        Instruction {
            offset,
            opcode: 0,
            name: name.to_owned(),
            operand,
            flow,
        }
    }

    fn jump_table_body() -> MethodBody {
        let instructions: Vec<Instruction> = vec![
            ins(0, "ldarg.1", OperandValue::None, FlowControl::Next),
            ins(
                1,
                "brfalse.s",
                OperandValue::BrTarget(20 - 1),
                FlowControl::CondBranch,
            ),
            ins(2, "ldarg.1", OperandValue::None, FlowControl::Next),
            ins(3, "callvirt", OperandValue::Token(100), FlowControl::Call),
            ins(4, "stloc.1", OperandValue::None, FlowControl::Next),
            ins(5, "ldloc.1", OperandValue::None, FlowControl::Next),
            ins(6, "ldc.i4.1", OperandValue::None, FlowControl::Next),
            ins(7, "sub", OperandValue::None, FlowControl::Next),
            ins(
                8,
                "switch",
                OperandValue::Switch(vec![10 - 8, 13 - 8, 16 - 8]),
                FlowControl::CondBranch,
            ),
            ins(
                9,
                "br.s",
                OperandValue::BrTarget(20 - 9),
                FlowControl::Branch,
            ),
            ins(10, "ldstr", OperandValue::Token(200), FlowControl::Next),
            ins(11, "stloc.0", OperandValue::None, FlowControl::Next),
            ins(
                12,
                "br.s",
                OperandValue::BrTarget(23 - 12),
                FlowControl::Branch,
            ),
            ins(13, "ldstr", OperandValue::Token(201), FlowControl::Next),
            ins(14, "stloc.0", OperandValue::None, FlowControl::Next),
            ins(
                15,
                "br.s",
                OperandValue::BrTarget(23 - 15),
                FlowControl::Branch,
            ),
            ins(16, "ldstr", OperandValue::Token(202), FlowControl::Next),
            ins(17, "stloc.0", OperandValue::None, FlowControl::Next),
            ins(
                18,
                "br.s",
                OperandValue::BrTarget(23 - 18),
                FlowControl::Branch,
            ),
            ins(20, "ldstr", OperandValue::Token(203), FlowControl::Next),
            ins(21, "stloc.0", OperandValue::None, FlowControl::Next),
            ins(23, "ldloc.0", OperandValue::None, FlowControl::Next),
            ins(24, "ret", OperandValue::None, FlowControl::Return),
        ];
        MethodBody {
            max_stack: 2,
            code_size: 25,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions,
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn reconstructs_shared_property_jump_table() {
        let body: MethodBody = jump_table_body();
        let names: NameTable = NameTable::default();
        let out: String =
            reconstruct_property_switch(&body, &StubNamer, &names, TargetLang::CSharp)
                .expect("shared-property jump table should reconstruct");
        assert!(out.contains("switch"), "{out}");
        assert!(out.contains("{ Major: 1 } => \"one\","), "{out}");
        assert!(out.contains("{ Major: 2 } => \"two\","), "{out}");
        assert!(out.contains("{ Major: 3 } => \"three\","), "{out}");
        assert!(out.contains("_ => \"other\","), "{out}");
    }

    fn range_relational_body() -> MethodBody {
        let instructions: Vec<Instruction> = vec![
            ins(0, "ldarg.1", OperandValue::None, FlowControl::Next),
            ins(
                1,
                "brfalse.s",
                OperandValue::BrTarget(21),
                FlowControl::CondBranch,
            ),
            ins(2, "ldarg.1", OperandValue::None, FlowControl::Next),
            ins(3, "callvirt", OperandValue::Token(100), FlowControl::Call),
            ins(4, "stloc.1", OperandValue::None, FlowControl::Next),
            ins(5, "ldloc.1", OperandValue::None, FlowControl::Next),
            ins(6, "ldc.i4.5", OperandValue::None, FlowControl::Next),
            ins(
                7,
                "bge.s",
                OperandValue::BrTarget(5),
                FlowControl::CondBranch,
            ),
            ins(8, "ldloc.1", OperandValue::None, FlowControl::Next),
            ins(9, "ldc.i4.1", OperandValue::None, FlowControl::Next),
            ins(
                10,
                "bge.s",
                OperandValue::BrTarget(6),
                FlowControl::CondBranch,
            ),
            ins(11, "br.s", OperandValue::BrTarget(11), FlowControl::Branch),
            ins(12, "ldloc.1", OperandValue::None, FlowControl::Next),
            ins(13, "ldc.i4.s", OperandValue::U8(10), FlowControl::Next),
            ins(
                14,
                "blt.s",
                OperandValue::BrTarget(5),
                FlowControl::CondBranch,
            ),
            ins(15, "br.s", OperandValue::BrTarget(7), FlowControl::Branch),
            ins(16, "ldstr", OperandValue::Token(210), FlowControl::Next),
            ins(17, "stloc.0", OperandValue::None, FlowControl::Next),
            ins(18, "br.s", OperandValue::BrTarget(6), FlowControl::Branch),
            ins(19, "ldstr", OperandValue::Token(211), FlowControl::Next),
            ins(20, "stloc.0", OperandValue::None, FlowControl::Next),
            ins(21, "br.s", OperandValue::BrTarget(3), FlowControl::Branch),
            ins(22, "ldstr", OperandValue::Token(212), FlowControl::Next),
            ins(23, "stloc.0", OperandValue::None, FlowControl::Next),
            ins(24, "ldloc.0", OperandValue::None, FlowControl::Next),
            ins(25, "ret", OperandValue::None, FlowControl::Return),
        ];
        MethodBody {
            max_stack: 2,
            code_size: 26,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions,
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn reconstructs_cached_local_range_relational_tree() {
        let body: MethodBody = range_relational_body();
        let names: NameTable = NameTable::default();
        let out: String =
            reconstruct_property_switch(&body, &StubNamer, &names, TargetLang::CSharp)
                .expect("cached-local relational range tree should reconstruct");
        assert!(out.contains("switch"), "{out}");
        assert!(
            out.contains("{ Major: >= 1 and < 5 } => \"early\","),
            "{out}"
        );
        assert!(
            out.contains("{ Major: >= 5 and < 10 } => \"mid\","),
            "{out}"
        );
        assert!(out.contains("_ => \"late\","), "{out}");
    }

    #[test]
    fn has_property_shape_counts_relational_across_conv_noise() {
        let instructions: Vec<Instruction> = vec![
            ins(0, "ldloc.1", OperandValue::None, FlowControl::Next),
            ins(1, "ldlen", OperandValue::None, FlowControl::Next),
            ins(2, "conv.i4", OperandValue::None, FlowControl::Next),
            ins(3, "ldc.i4.3", OperandValue::None, FlowControl::Next),
            ins(
                4,
                "blt.s",
                OperandValue::BrTarget(4),
                FlowControl::CondBranch,
            ),
            ins(5, "ldloc.2", OperandValue::None, FlowControl::Next),
            ins(6, "callvirt", OperandValue::Token(100), FlowControl::Call),
            ins(7, "ldc.i4.2", OperandValue::None, FlowControl::Next),
            ins(
                8,
                "bge.s",
                OperandValue::BrTarget(2),
                FlowControl::CondBranch,
            ),
            ins(9, "ldstr", OperandValue::Token(200), FlowControl::Next),
            ins(10, "stloc.0", OperandValue::None, FlowControl::Next),
        ];
        let body: MethodBody = MethodBody {
            max_stack: 2,
            code_size: 11,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions,
            exception_clauses: Vec::new(),
        };
        assert!(has_property_shape(&body));
    }
}
