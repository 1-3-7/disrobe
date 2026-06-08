//! Abstract type-state propagation over the Dalvik register file.

use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::dex::DexFile;

const MAX_FIXPOINT_ITERS: usize = 50_000;

/// Verification-relevant type of one Dalvik register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegType {
    Top,
    Int,
    Float,
    Long,
    Double,
    ZeroOrNull,
    Ref(String),
    /// JVM `uninitializedThis` (verification tag 6): the receiver `this` of an `<init>` before its
    /// own super/this constructor call has run. It must transition to `Ref(class)` at that call and
    /// be initialized on every path before any return, field access, or use as an argument.
    UninitializedThis,
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

/// Least-upper-bound of two register types across a control-flow join.
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

/// Abstract type of the full register file at a program point.
pub(crate) type RegState = BTreeMap<u16, RegType>;

/// Merges the `from` predecessor exit-state into the `into` join-entry state.
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

/// Result of the type-state analysis: the register state on entry to every instruction.
#[derive(Debug)]
pub(crate) struct TypeStates {
    pub(crate) entry_state: Vec<RegState>,
    pub(crate) reached: Vec<bool>,
}

/// The result type an invoke produces for a following `move-result*`.
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

/// Binds every `move-result*` to the return type of the invoke or `filled-new-array` it follows.
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

/// Non-fall-through control-flow edges the analysis must model: switch targets and exception-handler edges.
pub(crate) struct CfgEdges<'a> {
    pub(crate) switch_targets: &'a BTreeMap<u32, Vec<u32>>,
    pub(crate) handler_edges: &'a BTreeMap<u32, Vec<u32>>,
    pub(crate) move_exception_type: &'a BTreeMap<u32, String>,
}

/// Scalar shape of the method under analysis: its register layout and whether `this` enters as
/// `uninitializedThis` (a non-static `<init>`).
pub(crate) struct MethodShape<'a> {
    pub(crate) registers_size: u16,
    pub(crate) ins_size: u16,
    pub(crate) is_static: bool,
    pub(crate) is_init_ctor: bool,
    pub(crate) class_internal: &'a str,
}

/// Runs the forward type-state fixpoint over a single method.
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
    let (wide_doubles, narrow_floats): (BTreeSet<u16>, BTreeSet<u16>) =
        crate::dalvik_to_jvm::const_wide_double_and_float_regs(dex, insns, parsed);

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
        wide_doubles: &wide_doubles,
        narrow_floats: &narrow_floats,
        move_exception_type,
        class_internal,
    };

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

        if let Some(handlers) = handler_edges.get(&insn.pc) {
            for &hpc in handlers {
                let hidx: usize = *pc_to_idx.get(&hpc)?;
                match &mut state_in[hidx] {
                    Some(existing) => {
                        if merge_state(existing, &cur) {
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

/// Precomputed per-method lookups the transfer function consults, plus the enclosing class so a
/// receiver `<init>` can retype `uninitializedThis` to `Ref(class)`.
struct TransferCtx<'a> {
    move_result_type: &'a BTreeMap<u32, RegType>,
    wide_doubles: &'a BTreeSet<u16>,
    narrow_floats: &'a BTreeSet<u16>,
    move_exception_type: &'a BTreeMap<u32, String>,
    class_internal: &'a str,
}

/// Updates the register state for one instruction, returning `None` on any unsupported opcode.
#[allow(clippy::too_many_lines)]
fn transfer(
    dex: &DexFile,
    insn: &DalvikInsn,
    parsed: &MethodDescriptor,
    regs: &mut RegState,
    ctx: &TransferCtx<'_>,
) -> Option<()> {
    let move_result_type: &BTreeMap<u32, RegType> = ctx.move_result_type;
    let wide_doubles: &BTreeSet<u16> = ctx.wide_doubles;
    let narrow_floats: &BTreeSet<u16> = ctx.narrow_floats;
    let move_exception_type: &BTreeMap<u32, String> = ctx.move_exception_type;
    let class_internal: &str = ctx.class_internal;
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
            let is_init: bool = method_id(dex, insn.index).is_some_and(|m| m.name == "<init>");
            if is_init
                && let Some(&recv) = r.first()
                && regs.get(&recv) == Some(&RegType::UninitializedThis)
            {
                regs.insert(recv, RegType::Ref(strip_object(class_internal)));
            }
        }
        0x6E | 0x6F | 0x71 | 0x72 | 0x74 | 0x75 | 0x77 | 0x78 => {}
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

/// Result [`RegType`] of an `aget*` (0x44-0x4A), derived from the array register's element descriptor so
/// the `StackMapTable` frame agrees with the typed JVM array-load the emitter picks (`iaload`/`faload`/
/// `laload`/`daload`/`aaload`/`baload`/`caload`/`saload`). Falls back to the width-correct primitive when
/// the array's element type is not known at this point.
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
