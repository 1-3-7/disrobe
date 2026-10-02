use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{BlockId, Cfg};
use crate::cil::{ExceptionClause, ExceptionClauseKind, MethodBody};
use crate::names::NameTable;
use crate::structurize::{
    BlockCode, CarriedStack, Expr, LinearStmt, TargetLang, TokenNamer, lift_block_with_entry,
    rendered_expression, stack_slot, stack_slot_type,
};

const SLOT_PREFIX: &str = "__disrobe_stack";
const MAX_TYPE_ROUNDS: usize = 4;

#[derive(Debug, Clone, Default)]
pub(super) struct StackSlots {
    pub(super) exit_targets: Vec<Vec<SlotTarget>>,
    pub(super) declarations: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub(super) struct SlotTarget {
    slot: Expr,
    ty: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SlotKey {
    Entry(BlockId, usize),
    Def(BlockId, usize),
}

struct Depths {
    entry: Vec<Option<usize>>,
    kept: Vec<usize>,
    exit: Vec<usize>,
}

struct Components {
    parent: Vec<usize>,
    index: BTreeMap<SlotKey, usize>,
}

impl Components {
    fn id(&mut self, key: SlotKey) -> usize {
        if let Some(&id) = self.index.get(&key) {
            return id;
        }
        let id: usize = self.parent.len();
        self.parent.push(id);
        self.index.insert(key, id);
        id
    }

    fn root(&mut self, mut id: usize) -> usize {
        while self.parent[id] != id {
            self.parent[id] = self.parent[self.parent[id]];
            id = self.parent[id];
        }
        id
    }

    fn union(&mut self, a: SlotKey, b: SlotKey) {
        let a: usize = self.id(a);
        let b: usize = self.id(b);
        let (ra, rb): (usize, usize) = (self.root(a), self.root(b));
        if ra != rb {
            self.parent[ra.max(rb)] = ra.min(rb);
        }
    }
}

pub(super) struct SlotInputs<'a, N: TokenNamer> {
    pub(super) cfg: &'a Cfg,
    pub(super) body: &'a MethodBody,
    pub(super) namer: &'a N,
    pub(super) names: &'a NameTable,
    pub(super) lang: TargetLang,
    pub(super) exception_entries: &'a BTreeSet<BlockId>,
}

pub(super) fn plan_stack_slots<N: TokenNamer>(
    inputs: &SlotInputs<'_, N>,
    codes: &mut [BlockCode],
) -> Option<StackSlots> {
    if inputs.lang != TargetLang::CSharp {
        return None;
    }
    let depths: Depths = stack_depths(inputs, codes)?;
    let carried: Vec<BlockId> = (0..codes.len())
        .filter(|&b: &BlockId| {
            !inputs.exception_entries.contains(&b) && depths.entry[b].is_some_and(|d| d > 0)
        })
        .collect();
    if carried.is_empty() {
        return None;
    }
    let mut components: Components = Components {
        parent: Vec::new(),
        index: BTreeMap::new(),
    };
    let flows: Vec<BlockId> = (0..codes.len())
        .filter(|&b: &BlockId| depths.exit[b] > 0 && !leaves_protected_region(inputs, b))
        .collect();
    for &b in &flows {
        for &s in &inputs.cfg.blocks[b].succs {
            for i in 0..depths.exit[b] {
                components.union(exit_key(&depths, b, i), SlotKey::Entry(s, i));
            }
        }
    }
    let keys: Vec<SlotKey> = components.index.keys().copied().collect();
    let mut variables: BTreeMap<usize, usize> = BTreeMap::new();
    for key in &keys {
        if let SlotKey::Entry(..) = key {
            let id: usize = components.id(*key);
            let root: usize = components.root(id);
            let next: usize = variables.len();
            variables.entry(root).or_insert(next);
        }
    }
    let mut var_of = |key: SlotKey| -> Option<usize> {
        let id: usize = *components.index.get(&key)?;
        let root: usize = components.root(id);
        variables.get(&root).copied()
    };
    let entry_vars: BTreeMap<BlockId, Vec<usize>> = carried
        .iter()
        .map(|&b: &BlockId| {
            let vars: Option<Vec<usize>> = (0..depths.entry[b].unwrap_or(0))
                .map(|i: usize| var_of(SlotKey::Entry(b, i)))
                .collect();
            vars.map(|v: Vec<usize>| (b, v))
        })
        .collect::<Option<_>>()?;
    let exit_vars: BTreeMap<BlockId, Vec<usize>> = flows
        .iter()
        .filter(|&&b: &&BlockId| !inputs.cfg.blocks[b].succs.is_empty())
        .map(|&b: &BlockId| {
            let vars: Option<Vec<usize>> = (0..depths.exit[b])
                .map(|i: usize| var_of(exit_key(&depths, b, i)))
                .collect();
            vars.map(|v: Vec<usize>| (b, v))
        })
        .collect::<Option<_>>()?;
    let names: Vec<String> = (0..variables.len())
        .map(|v: usize| format!("{SLOT_PREFIX}{v}"))
        .collect();

    let mut types: Vec<Option<String>> = vec![None; names.len()];
    let mut relifted: BTreeMap<BlockId, BlockCode> = BTreeMap::new();
    let mut converged: bool = false;
    for _ in 0..MAX_TYPE_ROUNDS {
        relifted.clear();
        for (&b, vars) in &entry_vars {
            let entry: Vec<Expr> = vars
                .iter()
                .map(|&v: &usize| stack_slot(names[v].clone(), types[v].as_deref()))
                .collect();
            let block = &inputs.cfg.blocks[b];
            let code: BlockCode = lift_block_with_entry(
                inputs.namer,
                inputs.names,
                inputs.lang,
                &inputs.body.instructions,
                block.first,
                block.last,
                entry,
                CarriedStack::Settled,
            );
            if code.entry_deficit != 0 {
                return None;
            }
            relifted.insert(b, code);
        }
        let mut found: Vec<Option<String>> = vec![None; names.len()];
        for (&b, vars) in &exit_vars {
            let code: &BlockCode = relifted.get(&b).unwrap_or(&codes[b]);
            if code.exit_stack.len() != vars.len() {
                return None;
            }
            for (i, &v) in vars.iter().enumerate() {
                let ty: Option<String> = match &code.exit_stack[i] {
                    Expr::Temp { name, .. } if name.starts_with(SLOT_PREFIX) => {
                        let source: usize = names.iter().position(|n: &String| n == name)?;
                        if source == v {
                            continue;
                        }
                        types[source].clone()
                    }
                    _ => stack_slot_type(code, i, inputs.names),
                };
                if let Some(ty) = ty {
                    found[v] = Some(match found[v].take() {
                        None => ty,
                        Some(known) => merged_slot_type(&known, &ty)?,
                    });
                }
            }
        }
        if found == types {
            converged = true;
            break;
        }
        types = found;
    }
    if !converged || types.iter().any(Option::is_none) {
        return None;
    }
    let types: Vec<String> = types.into_iter().flatten().collect();
    for (b, code) in relifted {
        codes[b] = code;
    }
    let mut exit_targets: Vec<Vec<SlotTarget>> = vec![Vec::new(); codes.len()];
    for (&b, vars) in &exit_vars {
        let targets: Vec<SlotTarget> = vars
            .iter()
            .map(|&v: &usize| SlotTarget {
                slot: stack_slot(names[v].clone(), Some(&types[v])),
                ty: types[v].clone(),
            })
            .collect();
        assign_exit_slots(&mut codes[b], &targets, b, inputs.lang, inputs.names);
        exit_targets[b] = targets;
    }
    Some(StackSlots {
        exit_targets,
        declarations: names.into_iter().zip(types).collect(),
    })
}

fn merged_slot_type(known: &str, found: &str) -> Option<String> {
    match (known, found) {
        _ if known == found => Some(known.to_owned()),
        ("int" | "uint", "int" | "uint") => Some("int".to_owned()),
        ("long" | "ulong", "long" | "ulong") => Some("long".to_owned()),
        _ => None,
    }
}

fn exit_key(depths: &Depths, b: BlockId, i: usize) -> SlotKey {
    if i < depths.kept[b] {
        SlotKey::Entry(b, i)
    } else {
        SlotKey::Def(b, i)
    }
}

fn leaves_protected_region<N: TokenNamer>(inputs: &SlotInputs<'_, N>, b: BlockId) -> bool {
    inputs
        .body
        .instructions
        .get(inputs.cfg.blocks[b].last)
        .is_some_and(|ins| matches!(ins.name.as_str(), "leave" | "leave.s"))
}

fn seed(b: BlockId, d: usize, depths: &mut Depths, pending: &mut Vec<BlockId>) -> bool {
    match depths.entry[b] {
        None => {
            depths.entry[b] = Some(d);
            pending.push(b);
            true
        }
        Some(known) => known == d,
    }
}

fn stack_depths<N: TokenNamer>(inputs: &SlotInputs<'_, N>, codes: &[BlockCode]) -> Option<Depths> {
    let count: usize = codes.len();
    let mut depths: Depths = Depths {
        entry: vec![None; count],
        kept: vec![0; count],
        exit: vec![0; count],
    };
    let mut pending: Vec<BlockId> = Vec::new();
    if !seed(inputs.cfg.entry, 0, &mut depths, &mut pending) {
        return None;
    }
    let handler_starts: Vec<BlockId> = inputs
        .body
        .exception_clauses
        .iter()
        .filter(|c: &&ExceptionClause| {
            matches!(
                c.kind,
                ExceptionClauseKind::Finally | ExceptionClauseKind::Fault
            )
        })
        .filter_map(|c: &ExceptionClause| inputs.cfg.start_to_block.get(&c.handler_offset))
        .copied()
        .chain(inputs.exception_entries.iter().copied())
        .collect();
    for b in handler_starts {
        if !seed(b, 0, &mut depths, &mut pending) {
            return None;
        }
    }
    while let Some(b) = pending.pop() {
        let entry: usize = depths.entry[b]?;
        let code: &BlockCode = &codes[b];
        let kept: usize = entry.checked_sub(code.entry_deficit)?;
        depths.kept[b] = kept;
        let exit: usize = if leaves_protected_region(inputs, b) {
            0
        } else {
            kept.checked_add(code.exit_stack.len())?
        };
        depths.exit[b] = exit;
        for &s in &inputs.cfg.blocks[b].succs {
            if inputs.exception_entries.contains(&s) || !seed(s, exit, &mut depths, &mut pending) {
                return None;
            }
        }
    }
    Some(depths)
}

pub(super) fn assign_exit_slots(
    code: &mut BlockCode,
    targets: &[SlotTarget],
    block: BlockId,
    lang: TargetLang,
    names: &NameTable,
) {
    let mut assignments: Vec<(String, String)> = Vec::new();
    for (i, target) in targets.iter().enumerate() {
        let Expr::Temp { name, .. } = &target.slot else {
            continue;
        };
        let Some(value): Option<&Expr> = code.exit_stack.get(i) else {
            continue;
        };
        if matches!(value, Expr::Temp { name: current, .. } if current == name) {
            continue;
        }
        let rendered: String = rendered_expression(value, lang, names);
        let converted: String = if needs_conversion(value, code, i, &target.ty, names) {
            format!("unchecked(({})({rendered}))", target.ty)
        } else {
            rendered
        };
        assignments.push((name.clone(), converted));
    }
    let overlapping: bool = assignments.len() > 1
        && assignments.iter().any(|(_, value): &(String, String)| {
            assignments
                .iter()
                .any(|(name, _): &(String, String)| mentions(value, name))
        });
    if overlapping {
        for (name, value) in &assignments {
            code.stmts.push(LinearStmt::Declare {
                name: format!("{name}_{block}"),
                value: value.clone(),
            });
        }
        for (name, _) in assignments {
            let staged: String = format!("{name}_{block}");
            code.stmts.push(LinearStmt::Assign {
                target: name,
                value: staged,
            });
        }
    } else {
        for (name, value) in assignments {
            code.stmts.push(LinearStmt::Assign {
                target: name,
                value,
            });
        }
    }
    for (slot, target) in code.exit_stack.iter_mut().zip(targets) {
        *slot = target.slot.clone();
    }
}

fn needs_conversion(
    value: &Expr,
    code: &BlockCode,
    index: usize,
    slot_type: &str,
    names: &NameTable,
) -> bool {
    match value {
        Expr::Temp { .. } => false,
        Expr::Unary(..) | Expr::Binary(..) | Expr::Cond { .. } => {
            matches!(slot_type, "int" | "uint" | "long" | "ulong")
        }
        _ => stack_slot_type(code, index, names).is_some_and(|ty: String| ty != slot_type),
    }
}

pub(super) fn mentions(text: &str, name: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(name).any(|(at, _): (usize, &str)| {
        let before: bool = text[..at].chars().next_back().is_none_or(|c| !is_ident(c));
        let after: bool = text[at + name.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_ident(c));
        before && after
    })
}
