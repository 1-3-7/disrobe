use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::dex::DexFile;

const MAX_FIXPOINT_ITERS: usize = 50_000;

const MAX_SUPERCLASS_DEPTH: usize = 256;

const MAX_ARRAY_JOIN_DEPTH: usize = 16;

pub(crate) const OBJECT_INTERNAL: &str = "java/lang/Object";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegType {
    Top,
    Int,
    Float,
    Long,
    Double,
    ZeroOrNull,
    NullRef,
    Ref(String),

    UninitializedThis,
    Uninitialized(u32),
}

impl RegType {
    pub(crate) const fn is_wide(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    fn from_descriptor(desc: &str) -> Self {
        match desc.as_bytes().first() {
            Some(b'J') => Self::Long,
            Some(b'F') => Self::Float,
            Some(b'D') => Self::Double,
            Some(b'L') => Self::Ref(strip_object(desc)),
            Some(b'[') => Self::Ref(desc.to_string()),
            _ => Self::Int,
        }
    }

    fn from_java(ty: &JavaType) -> Self {
        match ty {
            JavaType::Long => Self::Long,
            JavaType::Float => Self::Float,
            JavaType::Double => Self::Double,
            JavaType::Object(name) => Self::Ref(strip_object(name)),
            JavaType::Array(_) => Self::Ref(array_descriptor(ty)),
            _ => Self::Int,
        }
    }
}

fn strip_object(desc: &str) -> String {
    if desc.starts_with('L') && desc.ends_with(';') {
        desc[1..desc.len() - 1].to_string()
    } else {
        desc.to_string()
    }
}

fn array_descriptor(ty: &JavaType) -> String {
    match ty {
        JavaType::Array(inner) => format!("[{}", array_descriptor(inner)),
        JavaType::Object(name) => {
            if name.starts_with('L') {
                name.clone()
            } else {
                format!("L{name};")
            }
        }
        JavaType::Byte => "B".to_string(),
        JavaType::Char => "C".to_string(),
        JavaType::Double => "D".to_string(),
        JavaType::Float => "F".to_string(),
        JavaType::Int => "I".to_string(),
        JavaType::Long => "J".to_string(),
        JavaType::Short => "S".to_string(),
        JavaType::Boolean => "Z".to_string(),
        JavaType::Void => "V".to_string(),
    }
}

fn component_name(desc: &str) -> Option<String> {
    match desc.as_bytes().first() {
        Some(b'[') => Some(desc.to_string()),
        Some(b'L') if desc.ends_with(';') => Some(strip_object(desc)),
        _ => None,
    }
}

fn element_descriptor(name: &str) -> String {
    if name.starts_with('[') {
        name.to_string()
    } else {
        format!("L{name};")
    }
}

#[derive(Debug)]
pub(crate) struct TypeLattice<'a> {
    dex: &'a DexFile,
    superclass_chains: RefCell<BTreeMap<String, Vec<String>>>,
}

impl<'a> TypeLattice<'a> {
    pub(crate) const fn new(dex: &'a DexFile) -> Self {
        Self {
            dex,
            superclass_chains: RefCell::new(BTreeMap::new()),
        }
    }

    fn root_first_chain(&self, internal: &str) -> Vec<String> {
        if let Some(cached) = self.superclass_chains.borrow().get(internal) {
            return cached.clone();
        }
        let mut chain: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut cursor: String = internal.to_string();
        while chain.len() < MAX_SUPERCLASS_DEPTH && seen.insert(cursor.clone()) {
            chain.push(cursor.clone());
            if cursor == OBJECT_INTERNAL {
                break;
            }
            let Some(parent): Option<&String> =
                self.dex.class_super_descriptors.get(&format!("L{cursor};"))
            else {
                break;
            };
            cursor = strip_object(parent);
        }
        if chain.last().map(String::as_str) != Some(OBJECT_INTERNAL) {
            chain.push(OBJECT_INTERNAL.to_string());
        }
        chain.reverse();
        self.superclass_chains
            .borrow_mut()
            .insert(internal.to_string(), chain.clone());
        chain
    }

    fn join_class(&self, a: &str, b: &str) -> String {
        let left: Vec<String> = self.root_first_chain(a);
        let right: Vec<String> = self.root_first_chain(b);
        let mut common: &str = OBJECT_INTERNAL;
        for (x, y) in left.iter().zip(right.iter()) {
            if x != y {
                break;
            }
            common = x.as_str();
        }
        common.to_string()
    }

    fn join_ref(&self, a: &str, b: &str, depth: usize) -> String {
        if a == b {
            return a.to_string();
        }
        if depth >= MAX_ARRAY_JOIN_DEPTH {
            return OBJECT_INTERNAL.to_string();
        }
        match (a.starts_with('['), b.starts_with('[')) {
            (true, true) => {
                let (Some(left), Some(right)): (Option<String>, Option<String>) = (
                    a.get(1..).and_then(component_name),
                    b.get(1..).and_then(component_name),
                ) else {
                    return OBJECT_INTERNAL.to_string();
                };
                let element: String = self.join_ref(&left, &right, depth + 1);
                format!("[{}", element_descriptor(&element))
            }
            (false, false) => self.join_class(a, b),
            _ => OBJECT_INTERNAL.to_string(),
        }
    }

    pub(crate) fn join(&self, a: &RegType, b: &RegType) -> RegType {
        if a == b {
            return a.clone();
        }
        match (a, b) {
            (RegType::ZeroOrNull, RegType::Int) | (RegType::Int, RegType::ZeroOrNull) => {
                RegType::Int
            }
            (RegType::ZeroOrNull | RegType::NullRef, RegType::Ref(r))
            | (RegType::Ref(r), RegType::ZeroOrNull | RegType::NullRef) => RegType::Ref(r.clone()),
            (RegType::ZeroOrNull, RegType::NullRef) | (RegType::NullRef, RegType::ZeroOrNull) => {
                RegType::NullRef
            }
            (RegType::Ref(x), RegType::Ref(y)) => RegType::Ref(self.join_ref(x, y, 0)),
            _ => RegType::Top,
        }
    }

    fn join_state(&self, into: &mut RegState, from: &RegState) -> bool {
        let mut changed: bool = false;
        let keys: BTreeSet<u16> = into.keys().chain(from.keys()).copied().collect();
        for k in keys {
            let merged: RegType = match (into.get(&k), from.get(&k)) {
                (Some(x), Some(y)) => self.join(x, y),
                (Some(_), None) | (None, Some(_)) => RegType::Top,
                (None, None) => continue,
            };
            if into.get(&k) != Some(&merged) {
                into.insert(k, merged);
                changed = true;
            }
        }
        changed
    }
}

pub(crate) type RegState = BTreeMap<u16, RegType>;

fn define(regs: &mut RegState, d: u16, ty: RegType) {
    let wide: bool = ty.is_wide();
    if let Some(prev) = d.checked_sub(1)
        && regs.get(&prev).is_some_and(RegType::is_wide)
    {
        regs.insert(prev, RegType::Top);
    }
    regs.insert(d, ty);
    if wide {
        regs.insert(d.saturating_add(1), RegType::Top);
    }
}

fn reinitialize_aliases(regs: &mut RegState, marker: &RegType, initialized: &RegType) {
    let aliases: Vec<u16> = regs
        .iter()
        .filter_map(|(&reg, ty): (&u16, &RegType)| (ty == marker).then_some(reg))
        .collect();
    for reg in aliases {
        regs.insert(reg, initialized.clone());
    }
}

#[derive(Debug)]
pub(crate) struct TypeStates {
    pub(crate) entry_state: Vec<RegState>,
    pub(crate) reached: Vec<bool>,
}

fn invoke_result_type(dex: &DexFile, insn: &DalvikInsn) -> Option<RegType> {
    let m: &MethodId = method_id(dex, insn.index)?;
    if m.proto.return_type == "V" {
        return None;
    }
    Some(RegType::from_descriptor(&m.proto.return_type))
}

use crate::dex::MethodId;

fn method_id(dex: &DexFile, index: Option<u32>) -> Option<&MethodId> {
    index.and_then(|i| dex.method_ids.get(i as usize))
}

fn field_type(dex: &DexFile, index: Option<u32>) -> Option<RegType> {
    index
        .and_then(|i| dex.field_ids.get(i as usize))
        .map(|f| RegType::from_descriptor(&f.type_name))
}

fn type_name_at(dex: &DexFile, index: Option<u32>) -> Option<String> {
    index.and_then(|i| dex.type_names.get(i as usize).cloned())
}

fn precompute_move_results(dex: &DexFile, insns: &[DalvikInsn]) -> BTreeMap<u32, RegType> {
    let mut out: BTreeMap<u32, RegType> = BTreeMap::new();
    for win in insns.windows(2) {
        let prev: &DalvikInsn = &win[0];
        let cur: &DalvikInsn = &win[1];
        if !matches!(cur.op, 0x0A..=0x0C) {
            continue;
        }
        if matches!(prev.op, 0x6E..=0x72 | 0x74..=0x78)
            && let Some(t) = invoke_result_type(dex, prev)
        {
            out.insert(cur.pc, t);
        } else if matches!(prev.op, 0x24 | 0x25)
            && let Some(ty) = type_name_at(dex, prev.index)
        {
            out.insert(cur.pc, RegType::Ref(strip_object(&ty)));
        }
    }
    out
}

pub(crate) struct CfgEdges<'a> {
    pub(crate) switch_targets: &'a BTreeMap<u32, Vec<u32>>,
    pub(crate) handler_edges: &'a BTreeMap<u32, Vec<u32>>,
    pub(crate) move_exception_type: &'a BTreeMap<u32, String>,
}

pub(crate) struct MethodShape<'a> {
    pub(crate) registers_size: u16,
    pub(crate) ins_size: u16,
    pub(crate) is_static: bool,
    pub(crate) is_init_ctor: bool,
    pub(crate) class_internal: &'a str,
    pub(crate) materialize_new_pcs: &'a BTreeSet<u32>,
}

pub(crate) fn analyze(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
    shape: &MethodShape<'_>,
    edges: &CfgEdges<'_>,
) -> Option<TypeStates> {
    let class_internal: &str = shape.class_internal;
    let switch_targets: &BTreeMap<u32, Vec<u32>> = edges.switch_targets;
    let handler_edges: &BTreeMap<u32, Vec<u32>> = edges.handler_edges;
    let move_exception_type: &BTreeMap<u32, String> = edges.move_exception_type;
    let n: usize = insns.len();
    let pc_to_idx: BTreeMap<u32, usize> =
        insns.iter().enumerate().map(|(i, n)| (n.pc, i)).collect();
    let (_wide_doubles, narrow_floats): (BTreeSet<u16>, BTreeSet<u16>) =
        crate::dalvik_to_jvm::const_wide_double_and_float_regs(dex, insns, parsed);
    let wide_double_pcs: BTreeSet<u32> =
        crate::dalvik_to_jvm::wide_const_double_pcs(dex, insns, parsed);

    let mut entry: RegState = RegState::new();
    let this_reg: u16 = shape.registers_size.saturating_sub(shape.ins_size);
    let mut cursor: u16 = this_reg;
    if !shape.is_static {
        let this_ty: RegType = if shape.is_init_ctor {
            RegType::UninitializedThis
        } else {
            RegType::Ref(strip_object(class_internal))
        };
        entry.insert(cursor, this_ty);
        cursor = cursor.saturating_add(1);
    }
    for ty in &parsed.params {
        let rt: RegType = RegType::from_java(ty);
        let wide: bool = rt.is_wide();
        entry.insert(cursor, rt);
        cursor = cursor.saturating_add(if wide { 2 } else { 1 });
    }

    let move_result_type: BTreeMap<u32, RegType> = precompute_move_results(dex, insns);
    let tctx: TransferCtx<'_> = TransferCtx {
        move_result_type: &move_result_type,
        wide_double_pcs: &wide_double_pcs,
        narrow_floats: &narrow_floats,
        move_exception_type,
        class_internal,
        materialize_new_pcs: shape.materialize_new_pcs,
    };

    let lattice: TypeLattice<'_> = TypeLattice::new(dex);
    let mut state_in: Vec<Option<RegState>> = vec![None; n];
    let mut reached: Vec<bool> = vec![false; n];
    state_in[0] = Some(entry);

    let mut worklist: Vec<usize> = vec![0];
    let mut iters: usize = 0;

    while let Some(idx) = worklist.pop() {
        iters += 1;
        if iters > MAX_FIXPOINT_ITERS {
            crate::debug::dbg_kv("dalvik-typestate", || {
                format!(
                    "{class_internal} fixpoint aborted after {iters} iterations (cap {MAX_FIXPOINT_ITERS}); typestate unavailable"
                )
            });
            return None;
        }
        reached[idx] = true;
        let cur: RegState = state_in[idx].clone()?;
        let insn: &DalvikInsn = &insns[idx];

        if let Some(handlers) = handler_edges.get(&insn.pc) {
            for &hpc in handlers {
                let hidx: usize = *pc_to_idx.get(&hpc)?;
                match &mut state_in[hidx] {
                    Some(existing) => {
                        if lattice.join_state(existing, &cur) {
                            worklist.push(hidx);
                        }
                    }
                    slot @ None => {
                        *slot = Some(cur.clone());
                        worklist.push(hidx);
                    }
                }
            }
        }

        let mut out: RegState = cur;
        transfer(dex, insn, parsed, &mut out, &tctx)?;

        for spc in successor_pcs(insns, idx, switch_targets) {
            let sidx: usize = *pc_to_idx.get(&spc)?;
            let propagate: RegState = out.clone();
            match &mut state_in[sidx] {
                Some(existing) => {
                    if lattice.join_state(existing, &propagate) {
                        worklist.push(sidx);
                    }
                }
                slot @ None => {
                    *slot = Some(propagate);
                    worklist.push(sidx);
                }
            }
        }
    }

    let null_refs: usize = resolve_null_constants(
        dex,
        insns,
        parsed,
        &tctx,
        edges,
        &pc_to_idx,
        &reached,
        &mut state_in,
    );

    crate::debug::dbg_kv("dalvik-typestate", || {
        let reached_count: usize = reached.iter().filter(|&&r: &&bool| r).count();
        format!(
            "{class_internal} fixpoint converged: insns={n} reached={reached_count} iterations={iters} null_refs={null_refs}"
        )
    });
    let entry_state: Vec<RegState> = state_in
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect();
    Some(TypeStates {
        entry_state,
        reached,
    })
}

fn successor_pcs(
    insns: &[DalvikInsn],
    idx: usize,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
) -> Vec<u32> {
    let Some(insn): Option<&DalvikInsn> = insns.get(idx) else {
        return Vec::new();
    };
    let mut succs: Vec<u32> = Vec::new();
    if let Some(t) = insn.branch_target_pc() {
        succs.push(t);
    }
    if insn.is_switch()
        && let Some(targets) = switch_targets.get(&insn.pc)
    {
        succs.extend(targets.iter().copied());
    }
    if !insn.is_unconditional_goto()
        && !insn.is_return()
        && !insn.is_throw()
        && let Some(next) = insns.get(idx + 1)
    {
        succs.push(next.pc);
    }
    succs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NullDemand {
    Free,
    Integral,
    Reference,
    Conflict,
}

impl NullDemand {
    const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Free, resolved) => resolved,
            (resolved, Self::Free) => resolved,
            (Self::Integral, Self::Integral) => Self::Integral,
            (Self::Reference, Self::Reference) => Self::Reference,
            _ => Self::Conflict,
        }
    }
}

const fn edge_demand(ty: &RegType) -> NullDemand {
    match ty {
        RegType::Int => NullDemand::Integral,
        RegType::Ref(_)
        | RegType::NullRef
        | RegType::UninitializedThis
        | RegType::Uninitialized(_) => NullDemand::Reference,
        RegType::ZeroOrNull | RegType::Top | RegType::Long | RegType::Float | RegType::Double => {
            NullDemand::Free
        }
    }
}

#[derive(Debug)]
struct NullClasses {
    parent: Vec<usize>,
    demand: Vec<NullDemand>,
    index: BTreeMap<(usize, u16), usize>,
}

impl NullClasses {
    const fn new() -> Self {
        Self {
            parent: Vec::new(),
            demand: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    fn node(&mut self, idx: usize, reg: u16) -> usize {
        if let Some(&existing) = self.index.get(&(idx, reg)) {
            return existing;
        }
        let fresh: usize = self.parent.len();
        self.parent.push(fresh);
        self.demand.push(NullDemand::Free);
        self.index.insert((idx, reg), fresh);
        fresh
    }

    fn root(&mut self, node: usize) -> usize {
        let mut cursor: usize = node;
        loop {
            let Some(&parent) = self.parent.get(cursor) else {
                return cursor;
            };
            if parent == cursor {
                return cursor;
            }
            let Some(&grand) = self.parent.get(parent) else {
                return parent;
            };
            if let Some(slot) = self.parent.get_mut(cursor) {
                *slot = grand;
            }
            cursor = grand;
        }
    }

    fn at_root(&self, root: usize) -> NullDemand {
        self.demand.get(root).copied().unwrap_or(NullDemand::Free)
    }

    fn unite(&mut self, left: usize, right: usize) {
        let keep: usize = self.root(left);
        let folded: usize = self.root(right);
        if keep == folded {
            return;
        }
        let merged: NullDemand = self.at_root(keep).join(self.at_root(folded));
        if let Some(slot) = self.parent.get_mut(folded) {
            *slot = keep;
        }
        if let Some(slot) = self.demand.get_mut(keep) {
            *slot = merged;
        }
    }

    fn require(&mut self, node: usize, demand: NullDemand) {
        let root: usize = self.root(node);
        let merged: NullDemand = self.at_root(root).join(demand);
        if let Some(slot) = self.demand.get_mut(root) {
            *slot = merged;
        }
    }

    fn settled(&mut self, idx: usize, reg: u16) -> NullDemand {
        let Some(&node) = self.index.get(&(idx, reg)) else {
            return NullDemand::Free;
        };
        let root: usize = self.root(node);
        self.at_root(root)
    }
}

fn link_null_edge(
    classes: &mut NullClasses,
    carried: &RegState,
    state_in: &[Option<RegState>],
    reached: &[bool],
    from: usize,
    to: usize,
) {
    if !reached.get(to).copied().unwrap_or(false) {
        return;
    }
    let Some(Some(target)): Option<&Option<RegState>> = state_in.get(to) else {
        return;
    };
    for (&reg, ty) in carried {
        if !matches!(ty, RegType::ZeroOrNull) {
            continue;
        }
        let node: usize = classes.node(from, reg);
        match target.get(&reg) {
            Some(RegType::ZeroOrNull) => {
                let joined: usize = classes.node(to, reg);
                classes.unite(node, joined);
            }
            Some(other) => classes.require(node, edge_demand(other)),
            None => {}
        }
    }
}

fn resolve_null_constants(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
    tctx: &TransferCtx<'_>,
    edges: &CfgEdges<'_>,
    pc_to_idx: &BTreeMap<u32, usize>,
    reached: &[bool],
    state_in: &mut [Option<RegState>],
) -> usize {
    let mut classes: NullClasses = NullClasses::new();
    for (idx, insn) in insns.iter().enumerate() {
        if !reached.get(idx).copied().unwrap_or(false) {
            continue;
        }
        let Some(Some(cur)): Option<&Option<RegState>> = state_in.get(idx) else {
            continue;
        };
        let cur: RegState = cur.clone();
        if let Some(handlers) = edges.handler_edges.get(&insn.pc) {
            for &hpc in handlers {
                let Some(&hidx): Option<&usize> = pc_to_idx.get(&hpc) else {
                    continue;
                };
                link_null_edge(&mut classes, &cur, state_in, reached, idx, hidx);
            }
        }
        let mut out: RegState = cur;
        if transfer(dex, insn, parsed, &mut out, tctx).is_none() {
            continue;
        }
        for spc in successor_pcs(insns, idx, edges.switch_targets) {
            let Some(&sidx): Option<&usize> = pc_to_idx.get(&spc) else {
                continue;
            };
            link_null_edge(&mut classes, &out, state_in, reached, idx, sidx);
        }
    }

    let mut null_refs: usize = 0;
    for idx in 0..insns.len() {
        if !reached.get(idx).copied().unwrap_or(false) {
            continue;
        }
        let Some(Some(st)): Option<&mut Option<RegState>> = state_in.get_mut(idx) else {
            continue;
        };
        for (&reg, ty) in st.iter_mut() {
            if !matches!(ty, RegType::ZeroOrNull) {
                continue;
            }
            if matches!(classes.settled(idx, reg), NullDemand::Reference) {
                *ty = RegType::NullRef;
                null_refs += 1;
            } else {
                *ty = RegType::Int;
            }
        }
    }
    null_refs
}

struct TransferCtx<'a> {
    move_result_type: &'a BTreeMap<u32, RegType>,
    wide_double_pcs: &'a BTreeSet<u32>,
    narrow_floats: &'a BTreeSet<u16>,
    move_exception_type: &'a BTreeMap<u32, String>,
    class_internal: &'a str,
    materialize_new_pcs: &'a BTreeSet<u32>,
}

#[allow(clippy::too_many_lines)]
fn transfer(
    dex: &DexFile,
    insn: &DalvikInsn,
    parsed: &MethodDescriptor,
    regs: &mut RegState,
    ctx: &TransferCtx<'_>,
) -> Option<()> {
    let move_result_type: &BTreeMap<u32, RegType> = ctx.move_result_type;
    let wide_double_pcs: &BTreeSet<u32> = ctx.wide_double_pcs;
    let narrow_floats: &BTreeSet<u16> = ctx.narrow_floats;
    let move_exception_type: &BTreeMap<u32, String> = ctx.move_exception_type;
    let class_internal: &str = ctx.class_internal;
    let materialize_new_pcs: &BTreeSet<u32> = ctx.materialize_new_pcs;
    let op: u8 = insn.op;
    let r: &[u16] = &insn.regs;

    let set = |regs: &mut RegState, reg: Option<u16>, ty: RegType| {
        if let Some(d) = reg {
            define(regs, d, ty);
        }
    };

    match op {
        0x00 | 0x1D | 0x1E => {}
        0x01..=0x09 => {
            if let (Some(&d), Some(&s)) = (r.first(), r.get(1)) {
                let t: RegType = regs.get(&s).cloned().unwrap_or(RegType::Top);
                define(regs, d, t);
            }
        }
        0x0A => {
            let t: RegType = move_result_type
                .get(&insn.pc)
                .cloned()
                .unwrap_or(RegType::Int);
            set(regs, r.first().copied(), t);
        }
        0x0B => {
            let t: RegType = move_result_type
                .get(&insn.pc)
                .cloned()
                .unwrap_or(RegType::Long);
            set(regs, r.first().copied(), t);
        }
        0x0C => {
            let t: RegType = move_result_type
                .get(&insn.pc)
                .cloned()
                .unwrap_or_else(|| RegType::Ref("java/lang/Object".to_string()));
            set(regs, r.first().copied(), t);
        }
        0x0D => {
            let ty: String = move_exception_type
                .get(&insn.pc)
                .cloned()
                .unwrap_or_else(|| "java/lang/Throwable".to_string());
            set(regs, r.first().copied(), RegType::Ref(ty));
        }
        0x0E => {}
        0x0F..=0x11 => {}
        0x12..=0x13 => {
            let lit: i64 = insn.literal.unwrap_or(0);
            let is_float: bool = r.first().is_some_and(|d: &u16| narrow_floats.contains(d));
            set(
                regs,
                r.first().copied(),
                if is_float {
                    RegType::Float
                } else if lit == 0 {
                    RegType::ZeroOrNull
                } else {
                    RegType::Int
                },
            );
        }
        0x14 | 0x15 => {
            let is_float: bool = r.first().is_some_and(|d: &u16| narrow_floats.contains(d));
            set(
                regs,
                r.first().copied(),
                if is_float {
                    RegType::Float
                } else {
                    RegType::Int
                },
            );
        }
        0x16..=0x19 => {
            let is_double: bool = wide_double_pcs.contains(&insn.pc);
            set(
                regs,
                r.first().copied(),
                if is_double {
                    RegType::Double
                } else {
                    RegType::Long
                },
            );
        }
        0x1A | 0x1B => set(
            regs,
            r.first().copied(),
            RegType::Ref("java/lang/String".to_string()),
        ),
        0x1C => set(
            regs,
            r.first().copied(),
            RegType::Ref("java/lang/Class".to_string()),
        ),
        0x1F => {
            let ty: String = type_name_at(dex, insn.index)?;
            set(regs, r.first().copied(), RegType::Ref(strip_object(&ty)));
        }
        0x20 | 0x21 => set(regs, r.first().copied(), RegType::Int),
        0x22 => {
            let _ty: String = type_name_at(dex, insn.index)?;
            if materialize_new_pcs.contains(&insn.pc) {
                set(regs, r.first().copied(), RegType::Uninitialized(insn.pc));
            }
        }
        0x23 => {
            let ty: String = type_name_at(dex, insn.index)?;
            set(regs, r.first().copied(), RegType::Ref(strip_object(&ty)));
        }
        0x24 | 0x25 => {}
        0x26 => {}
        0x27 => {}
        0x28..=0x2A => {}
        0x2B | 0x2C => {}
        0x2D..=0x31 => set(regs, r.first().copied(), RegType::Int),
        0x32..=0x3D => {}
        0x44..=0x4A => {
            let result: RegType = aget_result_type(regs, r.get(1).copied(), op);
            set(regs, r.first().copied(), result);
        }
        0x4B..=0x51 => {}
        0x52..=0x58 => {
            let t: RegType = field_type(dex, insn.index)?;
            set(regs, r.first().copied(), t);
        }
        0x59..=0x5F => {}
        0x60..=0x66 => {
            let t: RegType = field_type(dex, insn.index)?;
            set(regs, r.first().copied(), t);
        }
        0x67..=0x6D => {}
        0x70 | 0x76 => {
            let init_owner: Option<String> = method_id(dex, insn.index)
                .filter(|m| m.name == "<init>")
                .map(|m| strip_object(&m.class));
            if let Some(owner) = init_owner
                && let Some(&recv) = r.first()
            {
                match regs.get(&recv).cloned() {
                    Some(RegType::UninitializedThis) => {
                        let init_ty: RegType = RegType::Ref(strip_object(class_internal));
                        reinitialize_aliases(regs, &RegType::UninitializedThis, &init_ty);
                    }
                    Some(marker @ RegType::Uninitialized(_)) => {
                        let init_ty: RegType = RegType::Ref(owner);
                        reinitialize_aliases(regs, &marker, &init_ty);
                    }
                    _ => define(regs, recv, RegType::Ref(owner)),
                }
            }
        }
        0x6E | 0x6F | 0x71 | 0x72 | 0x74 | 0x75 | 0x77 | 0x78 => {}
        0x7B..=0x80 => {
            if let (Some(&d), Some(&s)) = (r.first(), r.get(1)) {
                let t: RegType = regs.get(&s).cloned().unwrap_or(RegType::Int);
                define(regs, d, t);
            }
        }
        0x81..=0x8F => set(regs, r.first().copied(), numeric_cast_result(op)),
        0x90..=0xAF => set(regs, r.first().copied(), arith_result(op)),
        0xB0..=0xCF => set(regs, r.first().copied(), arith_result(op - 0x20)),
        0xD0..=0xE2 => set(regs, r.first().copied(), RegType::Int),
        _ => return None,
    }
    let _ = parsed;
    Some(())
}

fn aget_result_type(regs: &RegState, array_reg: Option<u16>, op: u8) -> RegType {
    let elem: Option<&str> = array_reg
        .and_then(|a: u16| regs.get(&a))
        .and_then(|t: &RegType| match t {
            RegType::Ref(desc) => desc.strip_prefix('['),
            _ => None,
        });
    let elem_first: Option<u8> = elem.and_then(|e: &str| e.bytes().next());
    match op {
        0x44 => {
            if elem_first == Some(b'F') {
                RegType::Float
            } else {
                RegType::Int
            }
        }
        0x45 => {
            if elem_first == Some(b'D') {
                RegType::Double
            } else {
                RegType::Long
            }
        }
        0x46 => match elem {
            Some(desc) => RegType::from_descriptor(desc),
            None => RegType::Ref("java/lang/Object".to_string()),
        },
        _ => RegType::Int,
    }
}

const fn numeric_cast_result(op: u8) -> RegType {
    match op {
        0x81 | 0x88 | 0x8B => RegType::Long,
        0x82 | 0x85 | 0x8C => RegType::Float,
        0x83 | 0x86 | 0x89 => RegType::Double,
        _ => RegType::Int,
    }
}

const fn arith_result(op: u8) -> RegType {
    match op {
        0x9B..=0xA5 => RegType::Long,
        0xA6..=0xAA => RegType::Float,
        0xAB..=0xAF => RegType::Double,
        _ => RegType::Int,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dex_builder::{ClassDef, DexBuilder};

    const HIERARCHY: &[(&str, &str)] = &[
        ("Lp/Base;", "Ljava/lang/Object;"),
        ("Lp/Mid;", "Lp/Base;"),
        ("Lp/Left;", "Lp/Mid;"),
        ("Lp/Right;", "Lp/Mid;"),
        ("Lp/Other;", "Lp/Base;"),
        ("Lp/Iface;", "Ljava/lang/Object;"),
        ("Lp/Framework;", "Landroid/app/Activity;"),
        ("Lp/Framework2;", "Landroid/app/Activity;"),
        ("Lp/Detached;", "Landroid/content/Context;"),
        ("Lp/CycleA;", "Lp/CycleB;"),
        ("Lp/CycleB;", "Lp/CycleA;"),
    ];

    fn hierarchy_dex() -> DexFile {
        let mut builder: DexBuilder = DexBuilder::new();
        for (class, super_class) in HIERARCHY {
            builder.add_class(ClassDef {
                class: (*class).to_owned(),
                super_class: (*super_class).to_owned(),
                access_flags: 0x1,
                static_fields: Vec::new(),
                static_values: Vec::new(),
                direct_methods: Vec::new(),
                virtual_methods: Vec::new(),
            });
        }
        crate::dex::parse(&builder.build()).expect("the crafted hierarchy dex parses")
    }

    fn universe() -> Vec<RegType> {
        let mut out: Vec<RegType> = vec![
            RegType::Top,
            RegType::Int,
            RegType::Float,
            RegType::Long,
            RegType::Double,
            RegType::ZeroOrNull,
            RegType::NullRef,
            RegType::UninitializedThis,
            RegType::Uninitialized(4),
            RegType::Uninitialized(12),
        ];
        for name in [
            "java/lang/Object",
            "p/Base",
            "p/Mid",
            "p/Left",
            "p/Right",
            "p/Other",
            "p/Iface",
            "p/Framework",
            "p/Framework2",
            "p/Detached",
            "p/CycleA",
            "p/CycleB",
            "absent/Unknown",
            "[I",
            "[J",
            "[Lp/Left;",
            "[Lp/Right;",
            "[Lp/Base;",
            "[[Lp/Left;",
            "[[I",
            "[Ljava/lang/Cloneable;",
        ] {
            out.push(RegType::Ref(name.to_owned()));
        }
        out
    }

    #[test]
    fn the_register_join_is_a_semilattice_over_every_regtype_variant() {
        let dex: DexFile = hierarchy_dex();
        let lattice: TypeLattice<'_> = TypeLattice::new(&dex);
        let values: Vec<RegType> = universe();
        for a in &values {
            assert_eq!(
                lattice.join(a, a),
                a.clone(),
                "the join is not idempotent at {a:?}"
            );
            for b in &values {
                assert_eq!(
                    lattice.join(a, b),
                    lattice.join(b, a),
                    "the join is not commutative at {a:?} and {b:?}"
                );
                for c in &values {
                    let left: RegType = lattice.join(&lattice.join(a, b), c);
                    let right: RegType = lattice.join(a, &lattice.join(b, c));
                    assert_eq!(
                        left, right,
                        "the join is not associative at {a:?}, {b:?} and {c:?}; a fixpoint over a \
                         non-associative join reaches a different answer per visit order"
                    );
                }
            }
        }
    }

    #[test]
    fn the_register_join_is_monotone_in_both_arguments() {
        let dex: DexFile = hierarchy_dex();
        let lattice: TypeLattice<'_> = TypeLattice::new(&dex);
        let values: Vec<RegType> = universe();
        let below = |low: &RegType, high: &RegType| -> bool { lattice.join(low, high) == *high };
        for a in &values {
            for b in &values {
                for upper in &values {
                    if !below(a, upper) {
                        continue;
                    }
                    let widened: RegType = lattice.join(upper, b);
                    let narrow: RegType = lattice.join(a, b);
                    assert!(
                        below(&narrow, &widened),
                        "the join is not monotone: {a:?} sits below {upper:?}, yet joining each \
                         with {b:?} gives {narrow:?} which is not below {widened:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn sibling_classes_join_to_their_nearest_common_superclass() {
        let dex: DexFile = hierarchy_dex();
        let lattice: TypeLattice<'_> = TypeLattice::new(&dex);
        let cases: &[(&str, &str, &str)] = &[
            ("p/Left", "p/Right", "p/Mid"),
            ("p/Left", "p/Other", "p/Base"),
            ("p/Left", "p/Mid", "p/Mid"),
            ("p/Mid", "p/Left", "p/Mid"),
            ("p/Left", "java/lang/Object", "java/lang/Object"),
            ("p/Left", "p/Iface", "java/lang/Object"),
            ("p/Framework", "p/Framework2", "android/app/Activity"),
            ("p/Framework", "p/Detached", "java/lang/Object"),
            ("p/Left", "absent/Unknown", "java/lang/Object"),
            ("p/CycleA", "p/CycleB", "java/lang/Object"),
        ];
        for (a, b, expected) in cases {
            let joined: RegType = lattice.join(
                &RegType::Ref((*a).to_owned()),
                &RegType::Ref((*b).to_owned()),
            );
            assert_eq!(
                joined,
                RegType::Ref((*expected).to_owned()),
                "{a} joined with {b} must reach {expected}; widening every unequal reference pair \
                 to java/lang/Object types the frame with something no later use site accepts"
            );
        }
    }

    #[test]
    fn array_joins_follow_component_assignability() {
        let dex: DexFile = hierarchy_dex();
        let lattice: TypeLattice<'_> = TypeLattice::new(&dex);
        let cases: &[(&str, &str, &str)] = &[
            ("[Lp/Left;", "[Lp/Right;", "[Lp/Mid;"),
            ("[Lp/Left;", "[Lp/Base;", "[Lp/Base;"),
            ("[I", "[J", "java/lang/Object"),
            ("[[Lp/Left;", "[Lp/Left;", "[Ljava/lang/Object;"),
            ("[[I", "[I", "java/lang/Object"),
            ("[Lp/Left;", "p/Left", "java/lang/Object"),
            ("[Lp/Left;", "[Ljava/lang/Cloneable;", "[Ljava/lang/Object;"),
        ];
        for (a, b, expected) in cases {
            let joined: RegType = lattice.join(
                &RegType::Ref((*a).to_owned()),
                &RegType::Ref((*b).to_owned()),
            );
            assert_eq!(
                joined,
                RegType::Ref((*expected).to_owned()),
                "{a} joined with {b} must reach {expected}"
            );
        }
    }

    #[test]
    fn a_superclass_cycle_terminates_and_stays_symmetric() {
        let dex: DexFile = hierarchy_dex();
        let lattice: TypeLattice<'_> = TypeLattice::new(&dex);
        let forward: RegType = lattice.join(
            &RegType::Ref("p/CycleA".to_owned()),
            &RegType::Ref("p/CycleB".to_owned()),
        );
        let backward: RegType = lattice.join(
            &RegType::Ref("p/CycleB".to_owned()),
            &RegType::Ref("p/CycleA".to_owned()),
        );
        assert_eq!(forward, backward);
        assert_eq!(forward, RegType::Ref(OBJECT_INTERNAL.to_owned()));
    }

    #[test]
    fn a_register_absent_from_one_predecessor_joins_to_top() {
        let dex: DexFile = hierarchy_dex();
        let lattice: TypeLattice<'_> = TypeLattice::new(&dex);
        let mut into: RegState = RegState::new();
        into.insert(0, RegType::Ref("p/Left".to_owned()));
        into.insert(1, RegType::Int);
        let mut from: RegState = RegState::new();
        from.insert(0, RegType::Ref("p/Right".to_owned()));
        assert!(lattice.join_state(&mut into, &from));
        assert_eq!(into.get(&0), Some(&RegType::Ref("p/Mid".to_owned())));
        assert_eq!(into.get(&1), Some(&RegType::Top));
        assert!(!lattice.join_state(&mut into, &from));
    }
}
