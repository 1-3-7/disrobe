//! Abstract type-state propagation over the Dalvik register file.
//!
//! Dalvik is register based and untyped at the bytecode level: the same `const
//! v0, 0` may later be read as an `int`, a `float`, or a `null` reference, and a
//! register's type at a basic-block join is the merge of every predecessor's
//! type. Reconstructing verifiable JVM bodies (with the exact `StackMapTable`
//! frames the verifier demands) therefore requires a forward dataflow that
//! computes, at every basic-block boundary, the type of each live register.
//!
//! This module implements that analysis as a single source of truth: the same
//! per-block-entry [`RegState`] drives both the register->local lowering and the
//! synthesized verification frames, so the two can never disagree (the failure
//! mode of an emit-time-only model). Clean-room: the register-typing approach
//! follows dex2jar / jadx (both Apache-2.0); the Rust here is original and the
//! references are recorded in INFORMATION.md.

use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::dex::DexFile;

const MAX_FIXPOINT_ITERS: usize = 50_000;

/// Verification-relevant type of one Dalvik register. The lattice top is
/// [`RegType::Top`] (conflicting / dead); `ZeroOrNull` is the untyped Dalvik
/// `const 0` that resolves to `int 0` or `null` only at the use site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegType {
    Top,
    Int,
    Float,
    Long,
    Double,
    ZeroOrNull,
    Ref(String),
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

/// Least-upper-bound of two register types across a control-flow join. The only
/// non-`Top` widenings kept are exact-match, the `ZeroOrNull` chameleon
/// collapsing toward whichever concrete type it meets, and two object types
/// widening to `java/lang/Object`; disagreeing categories go to `Top` (the
/// register is dead at the join, which the emitter must not read there).
fn merge(a: &RegType, b: &RegType) -> RegType {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (RegType::ZeroOrNull, RegType::Int) | (RegType::Int, RegType::ZeroOrNull) => RegType::Int,
        (RegType::ZeroOrNull, RegType::Ref(r)) | (RegType::Ref(r), RegType::ZeroOrNull) => {
            RegType::Ref(r.clone())
        }
        (RegType::Ref(x), RegType::Ref(y)) if x == y => RegType::Ref(x.clone()),
        (RegType::Ref(_), RegType::Ref(_)) => RegType::Ref("java/lang/Object".to_string()),
        _ => RegType::Top,
    }
}

/// Abstract type of the full register file at a program point. A `None` for a
/// register means "not yet defined on any reaching path".
pub(crate) type RegState = BTreeMap<u16, RegType>;

/// Merges the `from` predecessor exit-state into the `into` join-entry state.
/// A register defined on only one of the two paths becomes `Top`: the JVM
/// verifier requires a local to be definitely assigned with a consistent type
/// on every reaching path, so a partially-defined register is dead at the join
/// and must not be loaded there (matching the verifier's own frame inference).
fn merge_state(into: &mut RegState, from: &RegState) -> bool {
    let mut changed: bool = false;
    let keys: BTreeSet<u16> = into.keys().chain(from.keys()).copied().collect();
    for k in keys {
        let merged: RegType = match (into.get(&k), from.get(&k)) {
            (Some(x), Some(y)) => merge(x, y),
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

/// Result of the type-state analysis: the register state on entry to every
/// instruction whose PC is a basic-block leader (specifically every branch
/// target, plus the method entry).
#[derive(Debug)]
pub(crate) struct TypeStates {
    pub(crate) entry_state: Vec<RegState>,
    pub(crate) reached: Vec<bool>,
}

/// The pending result type a `move-result*` will read, keyed by the PC of the
/// `move-result` instruction (it must follow the producing invoke/filled-array).
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

/// Pre-scans the linear instruction stream to bind every `move-result*` to the
/// return type of the invoke (or `filled-new-array`) it immediately follows.
/// Done linearly because the Dalvik contract requires that adjacency, which a
/// CFG worklist would otherwise scramble.
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

/// Classifies each `const-wide`-defined register as `Double` (vs the default
/// `Long`) by scanning for a later double-typed consumer. Dalvik `const-wide`
/// is type-ambiguous, so the producing register must take the type its use
/// demands, exactly as the straight-line emitter's float/double const inference
/// does; without this a double accumulator would type as `Long` at the const
/// and `Double` at the `add-double`, merging to `Top` at the loop header.
fn wide_const_doubles(dex: &DexFile, insns: &[DalvikInsn]) -> BTreeSet<u16> {
    let mut defs: BTreeSet<u16> = BTreeSet::new();
    let mut doubles: BTreeSet<u16> = BTreeSet::new();
    let mark = |reg: u16, defs: &BTreeSet<u16>, doubles: &mut BTreeSet<u16>| {
        if defs.contains(&reg) {
            doubles.insert(reg);
        }
    };
    for insn in insns {
        let op: u8 = insn.op;
        let r: &[u16] = &insn.regs;
        match op {
            0x16..=0x19 => {
                if let Some(&d) = r.first() {
                    defs.insert(d);
                }
            }
            0xAB..=0xAF => {
                for &reg in r.iter().skip(1) {
                    mark(reg, &defs, &mut doubles);
                }
            }
            0xCB..=0xCF => {
                for &reg in r {
                    mark(reg, &defs, &mut doubles);
                }
            }
            0x2F | 0x30 => {
                for &reg in r.iter().skip(1) {
                    mark(reg, &defs, &mut doubles);
                }
            }
            0x10 if matches!(insn.op, 0x10) => {}
            0x6E..=0x72 | 0x74..=0x78 => {
                mark_invoke_double_args(dex, insn, &defs, &mut doubles);
            }
            _ => {}
        }
    }
    doubles
}

fn mark_invoke_double_args(
    dex: &DexFile,
    insn: &DalvikInsn,
    defs: &BTreeSet<u16>,
    doubles: &mut BTreeSet<u16>,
) {
    let Some(m): Option<&MethodId> = method_id(dex, insn.index) else {
        return;
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut it: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static {
        let _ = it.next();
    }
    for param in &m.proto.parameters {
        let two: bool = matches!(param.as_bytes().first(), Some(b'J' | b'D'));
        if let Some(&reg) = it.next()
            && param == "D"
            && defs.contains(&reg)
        {
            doubles.insert(reg);
        }
        if two {
            let _ = it.next();
        }
    }
}

/// Runs the forward type-state fixpoint over a single method. Returns `None`
/// when the body contains a construct the analysis cannot soundly type (e.g.
/// `filled-new-array`, `move-exception` outside a modeled handler), keeping the
/// method on the verifiable stub.
pub(crate) fn analyze(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
    registers_size: u16,
    ins_size: u16,
    is_static: bool,
    class_internal: &str,
) -> Option<TypeStates> {
    let n: usize = insns.len();
    let pc_to_idx: BTreeMap<u32, usize> =
        insns.iter().enumerate().map(|(i, n)| (n.pc, i)).collect();
    let wide_doubles: BTreeSet<u16> = wide_const_doubles(dex, insns);

    let mut entry: RegState = RegState::new();
    let mut cursor: u16 = registers_size.saturating_sub(ins_size);
    if !is_static {
        entry.insert(cursor, RegType::Ref(strip_object(class_internal)));
        cursor = cursor.saturating_add(1);
    }
    for ty in &parsed.params {
        let rt: RegType = RegType::from_java(ty);
        let wide: bool = rt.is_wide();
        entry.insert(cursor, rt);
        cursor = cursor.saturating_add(if wide { 2 } else { 1 });
    }

    let move_result_type: BTreeMap<u32, RegType> = precompute_move_results(dex, insns);

    let mut state_in: Vec<Option<RegState>> = vec![None; n];
    let mut reached: Vec<bool> = vec![false; n];
    state_in[0] = Some(entry);

    let mut worklist: Vec<usize> = vec![0];
    let mut iters: usize = 0;

    while let Some(idx) = worklist.pop() {
        iters += 1;
        if iters > MAX_FIXPOINT_ITERS {
            return None;
        }
        reached[idx] = true;
        let cur: RegState = state_in[idx].clone()?;
        let insn: &DalvikInsn = &insns[idx];

        let mut out: RegState = cur;
        transfer(
            dex,
            insn,
            parsed,
            &mut out,
            &move_result_type,
            &wide_doubles,
        )?;

        let mut succs: Vec<u32> = Vec::new();
        if let Some(t) = insn.branch_target_pc() {
            succs.push(t);
        }
        if !insn.is_unconditional_goto()
            && !insn.is_return()
            && !insn.is_throw()
            && let Some(next) = insns.get(idx + 1)
        {
            succs.push(next.pc);
        }

        for spc in succs {
            let sidx: usize = *pc_to_idx.get(&spc)?;
            let propagate: RegState = out.clone();
            match &mut state_in[sidx] {
                Some(existing) => {
                    if merge_state(existing, &propagate) {
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

    let entry_state: Vec<RegState> = state_in
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect();
    Some(TypeStates {
        entry_state,
        reached,
    })
}

/// Updates the register state for one instruction. Returns the pending
/// `move-result` type to carry to the next instruction (or `None`). Bails
/// (returns `None`) on any opcode the lowering does not support, so the caller
/// can fall back to the stub.
#[allow(clippy::too_many_lines)]
fn transfer(
    dex: &DexFile,
    insn: &DalvikInsn,
    parsed: &MethodDescriptor,
    regs: &mut RegState,
    move_result_type: &BTreeMap<u32, RegType>,
    wide_doubles: &BTreeSet<u16>,
) -> Option<()> {
    let op: u8 = insn.op;
    let r: &[u16] = &insn.regs;

    let set = |regs: &mut RegState, reg: Option<u16>, ty: RegType| {
        if let Some(d) = reg {
            regs.insert(d, ty);
        }
    };

    match op {
        0x00 | 0x1D | 0x1E => {}
        0x01..=0x09 => {
            if let (Some(&d), Some(&s)) = (r.first(), r.get(1)) {
                let t: RegType = regs.get(&s).cloned().unwrap_or(RegType::Top);
                regs.insert(d, t);
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
        0x0D => return None,
        0x0E => {}
        0x0F..=0x11 => {}
        0x12..=0x13 => {
            let lit: i64 = insn.literal.unwrap_or(0);
            set(
                regs,
                r.first().copied(),
                if lit == 0 {
                    RegType::ZeroOrNull
                } else {
                    RegType::Int
                },
            );
        }
        0x14 | 0x15 => set(regs, r.first().copied(), RegType::Int),
        0x16..=0x19 => {
            let is_double: bool = r.first().is_some_and(|d| wide_doubles.contains(d));
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
            let ty: String = type_name_at(dex, insn.index)?;
            set(regs, r.first().copied(), RegType::Ref(strip_object(&ty)));
        }
        0x23 => {
            let ty: String = type_name_at(dex, insn.index)?;
            set(regs, r.first().copied(), RegType::Ref(strip_object(&ty)));
        }
        0x24 | 0x25 => return None,
        0x26 => {}
        0x27 => {}
        0x28..=0x2A => {}
        0x2B | 0x2C => return None,
        0x2D..=0x31 => set(regs, r.first().copied(), RegType::Int),
        0x32..=0x3D => {}
        0x44 => set(
            regs,
            r.first().copied(),
            RegType::Ref("java/lang/Object".to_string()),
        ),
        0x45 => set(regs, r.first().copied(), RegType::Long),
        0x46 => set(regs, r.first().copied(), RegType::Float),
        0x47 => set(regs, r.first().copied(), RegType::Double),
        0x48..=0x4A => set(regs, r.first().copied(), RegType::Int),
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
        0x6E..=0x72 | 0x74..=0x78 => {}
        0x7B..=0x80 => {
            if let (Some(&d), Some(&s)) = (r.first(), r.get(1)) {
                let t: RegType = regs.get(&s).cloned().unwrap_or(RegType::Int);
                regs.insert(d, t);
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

const fn numeric_cast_result(op: u8) -> RegType {
    match op {
        0x81 | 0x86 => RegType::Long,
        0x82 | 0x89 => RegType::Float,
        0x83 | 0x8A => RegType::Double,
        0x84 | 0x87 => RegType::Int,
        0x85 | 0x88 => RegType::Float,
        0x8B | 0x8E => RegType::Double,
        0x8C => RegType::Float,
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
