use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::dex::{DexFile, FieldId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SplitSlot {
    Int,
    Long,
    Float,
    Double,
    Ref,
}

impl SplitSlot {
    const fn is_wide(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    const fn from_descriptor_byte(b: Option<&u8>) -> Self {
        match b {
            Some(b'J') => Self::Long,
            Some(b'F') => Self::Float,
            Some(b'D') => Self::Double,
            Some(b'L' | b'[') => Self::Ref,
            _ => Self::Int,
        }
    }

    const fn from_field(desc: &str) -> Self {
        Self::from_descriptor_byte(desc.as_bytes().first())
    }

    const fn from_java(ty: &JavaType) -> Self {
        match ty {
            JavaType::Long => Self::Long,
            JavaType::Float => Self::Float,
            JavaType::Double => Self::Double,
            JavaType::Object(_) | JavaType::Array(_) => Self::Ref,
            _ => Self::Int,
        }
    }
}

const PARAM_DEF_BASE: usize = usize::MAX / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Def {
    site: usize,
    reg: u16,
    slot: SplitSlot,
}

#[derive(Debug)]
struct DefUse {
    def: Option<(u16, SplitSlot)>,
    uses: Vec<u16>,
    use_positions: Vec<usize>,
    def_position: Option<usize>,
    wide_def_high: bool,
}

#[derive(Debug)]
pub(crate) struct SplitPlan {
    pub(crate) insns: Vec<DalvikInsn>,
    pub(crate) virtual_local: BTreeMap<u16, u16>,
    pub(crate) max_locals: u16,
}

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb): (usize, usize) = (self.find(a), self.find(b));
        if ra == rb {
            return;
        }
        match self.rank[ra].cmp(&self.rank[rb]) {
            std::cmp::Ordering::Less => self.parent[ra] = rb,
            std::cmp::Ordering::Greater => self.parent[rb] = ra,
            std::cmp::Ordering::Equal => {
                self.parent[rb] = ra;
                self.rank[ra] += 1;
            }
        }
    }
}

pub(crate) struct SplitShape<'a> {
    pub(crate) registers_size: u16,
    pub(crate) ins_size: u16,
    pub(crate) is_static: bool,
    pub(crate) first_param_reg: u16,
    pub(crate) base_max_locals: u16,
    pub(crate) parsed: &'a MethodDescriptor,
}

pub(crate) fn plan_split(
    dex: &DexFile,
    insns: &[DalvikInsn],
    shape: &SplitShape<'_>,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
) -> Option<SplitPlan> {
    let pc_to_idx: BTreeMap<u32, usize> =
        insns.iter().enumerate().map(|(i, x)| (x.pc, i)).collect();

    let param_defs: BTreeMap<u16, Def> = seed_param_defs(shape);
    let du: Vec<DefUse> = insns
        .iter()
        .map(|insn: &DalvikInsn| def_use(dex, insn))
        .collect();

    let reach_in: Vec<BTreeMap<u16, BTreeSet<usize>>> = reaching_defs(
        insns,
        &du,
        &pc_to_idx,
        &param_defs,
        switch_targets,
        handler_edges,
    )?;

    let mut def_index: BTreeMap<usize, usize> = BTreeMap::new();
    let mut defs: Vec<Def> = Vec::new();
    for (reg, d) in &param_defs {
        def_index.insert(PARAM_DEF_BASE + usize::from(*reg), defs.len());
        defs.push(*d);
    }
    for (i, d) in du.iter().enumerate() {
        if let Some((reg, slot)) = d.def {
            def_index.insert(i, defs.len());
            defs.push(Def { site: i, reg, slot });
        }
    }
    if defs.is_empty() {
        return None;
    }

    let mut uf: UnionFind = UnionFind::new(defs.len());
    for (i, d) in du.iter().enumerate() {
        for &reg in &d.uses {
            let Some(reaching): Option<&BTreeSet<usize>> = reach_in[i].get(&reg) else {
                continue;
            };
            let nodes: Vec<usize> = reaching
                .iter()
                .filter_map(|site: &usize| def_index.get(site).copied())
                .collect();
            let Some((&first, rest)): Option<(&usize, &[usize])> = nodes.split_first() else {
                continue;
            };
            for &other in rest {
                uf.union(first, other);
            }
        }
    }

    let mut web_slot: BTreeMap<usize, SplitSlot> = BTreeMap::new();
    for (i, d) in defs.iter().enumerate() {
        let root: usize = uf.find(i);
        match web_slot.get(&root) {
            Some(existing) if *existing != d.slot => {
                let ref_mismatch: bool =
                    (*existing == SplitSlot::Ref) != (d.slot == SplitSlot::Ref);
                if existing.is_wide() != d.slot.is_wide() || ref_mismatch {
                    return None;
                }
            }
            _ => {
                web_slot.entry(root).or_insert(d.slot);
            }
        }
    }

    let mut reg_webs: BTreeMap<u16, BTreeSet<usize>> = BTreeMap::new();
    for (i, d) in defs.iter().enumerate() {
        reg_webs.entry(d.reg).or_default().insert(uf.find(i));
    }

    let conflicted: BTreeSet<u16> = reg_webs
        .iter()
        .filter(|(_, roots): &(&u16, &BTreeSet<usize>)| {
            let mut has_ref: bool = false;
            let mut has_nonref: bool = false;
            for root in *roots {
                match web_slot.get(root) {
                    Some(SplitSlot::Ref) => has_ref = true,
                    Some(_) => has_nonref = true,
                    None => {}
                }
            }
            has_ref && has_nonref
        })
        .map(|(&reg, _): (&u16, &BTreeSet<usize>)| reg)
        .collect();

    if conflicted.is_empty() {
        return None;
    }

    let mut next_reg: u16 = shape.registers_size;
    let mut web_reg: BTreeMap<usize, u16> = BTreeMap::new();
    let mut virtual_local: BTreeMap<u16, u16> = BTreeMap::new();
    let mut next_local: u16 = shape.base_max_locals;
    for (&reg, roots) in &reg_webs {
        if !conflicted.contains(&reg) {
            for &root in roots {
                web_reg.insert(root, reg);
            }
            continue;
        }
        let natural_slot: SplitSlot = natural_reg_slot(shape, reg);
        let mut primary_assigned: bool = false;
        let mut ordered: Vec<usize> = roots.iter().copied().collect();
        ordered.sort_by_key(|root: &usize| {
            let is_primary: bool = web_slot.get(root).copied() == Some(natural_slot);
            (!is_primary, *root)
        });
        for root in ordered {
            web_slot.get(&root)?;
            if !primary_assigned {
                web_reg.insert(root, reg);
                primary_assigned = true;
                continue;
            }
            web_reg.insert(root, next_reg);
            virtual_local.insert(next_reg, next_local);
            next_reg = next_reg.checked_add(2)?;
            next_local = next_local.checked_add(2)?;
        }
    }

    let reg_at = |reach: &BTreeMap<u16, BTreeSet<usize>>, uf: &mut UnionFind, reg: u16| -> u16 {
        let Some(reaching): Option<&BTreeSet<usize>> = reach.get(&reg) else {
            return reg;
        };
        let mut chosen: u16 = reg;
        for site in reaching {
            if let Some(&di) = def_index.get(site) {
                let root: usize = uf.find(di);
                if let Some(&assigned) = web_reg.get(&root) {
                    chosen = assigned;
                }
            }
        }
        chosen
    };

    let mut out_insns: Vec<DalvikInsn> = insns.to_vec();
    let mut rewrote: bool = false;
    for (i, insn) in out_insns.iter_mut().enumerate() {
        let d: &DefUse = &du[i];
        let def_root: Option<u16> = match (d.def_position, def_index.get(&i)) {
            (Some(_), Some(&di)) => web_reg.get(&uf.find(di)).copied(),
            _ => None,
        };
        for &pos in &d.use_positions {
            let Some(slot): Option<&mut u16> = insn.regs.get_mut(pos) else {
                continue;
            };
            let reg: u16 = *slot;
            if !conflicted.contains(&reg) {
                continue;
            }
            let mapped: u16 = reg_at(&reach_in[i], &mut uf, reg);
            if mapped != reg {
                *slot = mapped;
                rewrote = true;
            }
        }
        if let (Some(pos), Some(assigned)) = (d.def_position, def_root)
            && let Some(slot) = insn.regs.get_mut(pos)
            && conflicted.contains(slot)
            && *slot != assigned
        {
            *slot = assigned;
            rewrote = true;
        }
    }

    if !rewrote || virtual_local.is_empty() {
        return None;
    }

    if !renamed_is_sound(
        dex,
        &out_insns,
        &pc_to_idx,
        shape,
        switch_targets,
        handler_edges,
    ) {
        return None;
    }

    let _ = next_reg;
    Some(SplitPlan {
        insns: out_insns,
        virtual_local,
        max_locals: next_local.max(shape.base_max_locals),
    })
}

fn renamed_is_sound(
    dex: &DexFile,
    insns: &[DalvikInsn],
    pc_to_idx: &BTreeMap<u32, usize>,
    shape: &SplitShape<'_>,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
) -> bool {
    let param_defs: BTreeMap<u16, Def> = seed_param_defs(shape);
    let du: Vec<DefUse> = insns
        .iter()
        .map(|insn: &DalvikInsn| def_use(dex, insn))
        .collect();
    let Some(reach): Option<Vec<BTreeMap<u16, BTreeSet<usize>>>> = reaching_defs(
        insns,
        &du,
        pc_to_idx,
        &param_defs,
        switch_targets,
        handler_edges,
    ) else {
        return false;
    };
    let mut def_slot: BTreeMap<usize, SplitSlot> = BTreeMap::new();
    for (reg, d) in &param_defs {
        let _ = reg;
        def_slot.insert(d.site, d.slot);
    }
    for (i, d) in du.iter().enumerate() {
        if let Some((_reg, slot)) = d.def {
            def_slot.insert(i, slot);
        }
    }
    for (i, d) in du.iter().enumerate() {
        for &reg in &d.uses {
            let Some(reaching): Option<&BTreeSet<usize>> = reach[i].get(&reg) else {
                return false;
            };
            let mut slot: Option<SplitSlot> = None;
            for site in reaching {
                let Some(s): Option<&SplitSlot> = def_slot.get(site) else {
                    return false;
                };
                match slot {
                    Some(prev) if (prev == SplitSlot::Ref) != (*s == SplitSlot::Ref) => {
                        return false;
                    }
                    Some(prev) if prev.is_wide() != s.is_wide() => return false,
                    _ => slot = Some(*s),
                }
            }
        }
    }
    true
}

fn natural_reg_slot(shape: &SplitShape<'_>, reg: u16) -> SplitSlot {
    let mut cursor: u16 = shape.first_param_reg;
    if !shape.is_static {
        if reg == cursor {
            return SplitSlot::Ref;
        }
        cursor = cursor.saturating_add(1);
    }
    for ty in &shape.parsed.params {
        let slot: SplitSlot = SplitSlot::from_java(ty);
        if reg == cursor {
            return slot;
        }
        cursor = cursor.saturating_add(if slot.is_wide() { 2 } else { 1 });
    }
    SplitSlot::Int
}

fn seed_param_defs(shape: &SplitShape<'_>) -> BTreeMap<u16, Def> {
    let mut out: BTreeMap<u16, Def> = BTreeMap::new();
    let mut cursor: u16 = shape.first_param_reg;
    if !shape.is_static {
        out.insert(
            cursor,
            Def {
                site: PARAM_DEF_BASE,
                reg: cursor,
                slot: SplitSlot::Ref,
            },
        );
        cursor = cursor.saturating_add(1);
    }
    for ty in &shape.parsed.params {
        let slot: SplitSlot = SplitSlot::from_java(ty);
        out.insert(
            cursor,
            Def {
                site: PARAM_DEF_BASE + usize::from(cursor),
                reg: cursor,
                slot,
            },
        );
        cursor = cursor.saturating_add(if slot.is_wide() { 2 } else { 1 });
    }
    let _ = shape.registers_size;
    let _ = shape.ins_size;
    out
}

fn reaching_defs(
    insns: &[DalvikInsn],
    du: &[DefUse],
    pc_to_idx: &BTreeMap<u32, usize>,
    param_defs: &BTreeMap<u16, Def>,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
) -> Option<Vec<BTreeMap<u16, BTreeSet<usize>>>> {
    let n: usize = insns.len();
    let mut in_sets: Vec<BTreeMap<u16, BTreeSet<usize>>> = vec![BTreeMap::new(); n];
    let mut out_sets: Vec<BTreeMap<u16, BTreeSet<usize>>> = vec![BTreeMap::new(); n];

    let mut entry: BTreeMap<u16, BTreeSet<usize>> = BTreeMap::new();
    for (&reg, d) in param_defs {
        entry.insert(reg, BTreeSet::from([d.site]));
    }

    let succs: Vec<Vec<usize>> = (0..n)
        .map(|i: usize| successors(insns, i, pc_to_idx, switch_targets, handler_edges))
        .collect();

    let mut worklist: Vec<usize> = (0..n).collect();
    let mut in_worklist: Vec<bool> = vec![true; n];
    let mut iters: usize = 0;
    let cap: usize = n.saturating_mul(64).max(4096);

    while let Some(i) = worklist.pop() {
        in_worklist[i] = false;
        iters += 1;
        if iters > cap {
            return None;
        }
        let mut new_in: BTreeMap<u16, BTreeSet<usize>> = if i == 0 {
            entry.clone()
        } else {
            BTreeMap::new()
        };
        for (p, ss) in succs.iter().enumerate() {
            if !ss.contains(&i) {
                continue;
            }
            for (reg, sites) in &out_sets[p] {
                new_in
                    .entry(*reg)
                    .or_default()
                    .extend(sites.iter().copied());
            }
        }
        let mut new_out: BTreeMap<u16, BTreeSet<usize>> = new_in.clone();
        if let Some((reg, _slot)) = du[i].def {
            new_out.insert(reg, BTreeSet::from([i]));
            if du[i].wide_def_high {
                new_out.insert(reg.saturating_add(1), BTreeSet::from([usize::MAX]));
            }
        }
        let changed: bool = new_in != in_sets[i] || new_out != out_sets[i];
        in_sets[i] = new_in;
        if changed {
            out_sets[i] = new_out;
            for &s in &succs[i] {
                if !in_worklist[s] {
                    in_worklist[s] = true;
                    worklist.push(s);
                }
            }
        }
    }
    Some(in_sets)
}

fn successors(
    insns: &[DalvikInsn],
    idx: usize,
    pc_to_idx: &BTreeMap<u32, usize>,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
) -> Vec<usize> {
    let insn: &DalvikInsn = &insns[idx];
    let mut out: Vec<usize> = Vec::new();
    if let Some(t) = insn.branch_target_pc()
        && let Some(&j) = pc_to_idx.get(&t)
    {
        out.push(j);
    }
    if insn.is_switch()
        && let Some(targets) = switch_targets.get(&insn.pc)
    {
        for &t in targets {
            if let Some(&j) = pc_to_idx.get(&t) {
                out.push(j);
            }
        }
    }
    if !insn.is_unconditional_goto()
        && !insn.is_return()
        && !insn.is_throw()
        && insns.get(idx + 1).is_some()
    {
        out.push(idx + 1);
    }
    if let Some(edges) = handler_edges.get(&insn.pc) {
        for &t in edges {
            if let Some(&j) = pc_to_idx.get(&t) {
                out.push(j);
            }
        }
    }
    out
}

fn def_use(dex: &DexFile, insn: &DalvikInsn) -> DefUse {
    let op: u8 = insn.op;
    let n: usize = insn.regs.len();
    let (def_slot, use_positions): (Option<SplitSlot>, Vec<usize>) = match op {
        0x00 | 0x0E | 0x1D | 0x1E | 0x28..=0x2A => (None, Vec::new()),
        0x01..=0x03 => (Some(SplitSlot::Int), vec![1]),
        0x04..=0x06 => (Some(SplitSlot::Long), vec![1]),
        0x07..=0x09 => (Some(SplitSlot::Ref), vec![1]),
        0x0A => (Some(SplitSlot::Int), Vec::new()),
        0x0B => (Some(SplitSlot::Long), Vec::new()),
        0x0C | 0x0D => (Some(SplitSlot::Ref), Vec::new()),
        0x0F | 0x10 | 0x11 | 0x27 => (None, vec![0]),
        0x12..=0x15 => (Some(SplitSlot::Int), Vec::new()),
        0x16..=0x19 => (Some(SplitSlot::Long), Vec::new()),
        0x1A..=0x1C => (Some(SplitSlot::Ref), Vec::new()),
        0x1F => (Some(SplitSlot::Ref), vec![0]),
        0x20 | 0x21 => (Some(SplitSlot::Int), vec![1]),
        0x22 => (Some(SplitSlot::Ref), Vec::new()),
        0x23 => (Some(SplitSlot::Ref), vec![1]),
        0x24 | 0x25 => (None, (0..n).collect()),
        0x26 => (None, vec![0]),
        0x2D..=0x31 => (Some(SplitSlot::Int), (1..n).collect()),
        0x32..=0x37 => (None, vec![0, 1]),
        0x38..=0x3D => (None, vec![0]),
        0x44 => (Some(SplitSlot::Int), (1..n).collect()),
        0x45 => (Some(SplitSlot::Long), (1..n).collect()),
        0x46 => (Some(SplitSlot::Ref), (1..n).collect()),
        0x47..=0x4A => (Some(SplitSlot::Int), (1..n).collect()),
        0x4B..=0x51 => (None, (0..n.min(3)).collect()),
        0x52..=0x58 => (Some(field_slot(dex, insn.index)), vec![1]),
        0x59..=0x5F => (None, (0..n.min(2)).collect()),
        0x60..=0x66 => (Some(field_slot(dex, insn.index)), Vec::new()),
        0x67..=0x6D => (None, vec![0]),
        0x6E..=0x72 | 0x74..=0x78 => (None, (0..n).collect()),
        0x7B | 0x7C => (Some(SplitSlot::Int), vec![1]),
        0x7D | 0x7E => (Some(SplitSlot::Long), vec![1]),
        0x7F => (Some(SplitSlot::Float), vec![1]),
        0x80 => (Some(SplitSlot::Double), vec![1]),
        0x81..=0x8F => (Some(cast_to_slot(op)), vec![1]),
        0x90..=0xAF => (Some(arith_slot(op)), (1..n).collect()),
        0xB0..=0xCF => (Some(arith_slot(op - 0x20)), (0..n.min(2)).collect()),
        0xD0..=0xE2 => (Some(SplitSlot::Int), vec![1]),
        _ => (None, Vec::new()),
    };
    let def_position: Option<usize> = def_slot.and(if n > 0 { Some(0) } else { None });
    let def: Option<(u16, SplitSlot)> = match (def_position, def_slot) {
        (Some(p), Some(slot)) => insn.regs.get(p).map(|&r: &u16| (r, slot)),
        _ => None,
    };
    let uses: Vec<u16> = use_positions
        .iter()
        .filter_map(|&p: &usize| insn.regs.get(p).copied())
        .collect();
    let wide_def_high: bool = def.is_some_and(|(_, slot): (u16, SplitSlot)| slot.is_wide());
    DefUse {
        def,
        uses,
        use_positions,
        def_position,
        wide_def_high,
    }
}

fn field_slot(dex: &DexFile, index: Option<u32>) -> SplitSlot {
    index
        .and_then(|i: u32| dex.field_ids.get(i as usize))
        .map(|f: &FieldId| SplitSlot::from_field(&f.type_name))
        .unwrap_or(SplitSlot::Int)
}

const fn cast_to_slot(op: u8) -> SplitSlot {
    match op {
        0x81 | 0x86 => SplitSlot::Long,
        0x82 | 0x89 | 0x8C => SplitSlot::Float,
        0x83 | 0x8A | 0x8D => SplitSlot::Double,
        _ => SplitSlot::Int,
    }
}

const fn arith_slot(op: u8) -> SplitSlot {
    match op {
        0x9B..=0xA5 => SplitSlot::Long,
        0xA6..=0xAA => SplitSlot::Float,
        0xAB..=0xAF => SplitSlot::Double,
        _ => SplitSlot::Int,
    }
}
