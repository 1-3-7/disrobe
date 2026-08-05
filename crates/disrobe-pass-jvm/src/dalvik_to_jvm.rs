use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::descriptor::{self, JavaType, MethodDescriptor};
use crate::dex::{CodeItem, DexFile, FieldId, MethodId};
use crate::dex2jar::ConstantPool;

const MAX_METHOD_INSNS: usize = 8192;
const MAX_CODE_BYTES: usize = 60_000;

#[cfg(any(test, feature = "lifter-diag"))]
thread_local! {
    pub(crate) static LAST_BAIL_OP: std::cell::Cell<i32> = const { std::cell::Cell::new(-1) };
    pub(crate) static LAST_BAIL_KIND: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
}

#[cfg(any(test, feature = "lifter-diag"))]
#[inline]
pub(crate) fn record_bail_kind(kind: &'static str) {
    LAST_BAIL_KIND.with(|c: &std::cell::Cell<&'static str>| {
        if c.get().is_empty() {
            c.set(kind);
        }
    });
}

#[cfg(any(test, feature = "lifter-diag"))]
#[inline]
pub(crate) fn take_bail_kind() -> &'static str {
    LAST_BAIL_KIND.with(|c: &std::cell::Cell<&'static str>| c.get())
}

#[cfg(any(test, feature = "lifter-diag"))]
#[inline]
pub(crate) fn record_bail_op(op: u8) {
    LAST_BAIL_OP.with(|c: &std::cell::Cell<i32>| {
        if c.get() < 0 {
            c.set(i32::from(op));
        }
    });
}

#[cfg(any(test, feature = "lifter-diag"))]
#[inline]
pub(crate) fn reset_bail_op() {
    LAST_BAIL_OP.with(|c: &std::cell::Cell<i32>| c.set(-1));
    LAST_BAIL_KIND.with(|c: &std::cell::Cell<&'static str>| c.set(""));
}

#[cfg(any(test, feature = "lifter-diag"))]
#[inline]
pub(crate) fn take_bail_op() -> i32 {
    LAST_BAIL_OP.with(|c: &std::cell::Cell<i32>| c.get())
}

#[cfg(any(test, feature = "lifter-diag"))]
pub(crate) fn diag_is_synthetic_class(descriptor: &str) -> bool {
    is_synthetic_class(descriptor)
}

#[cfg(any(test, feature = "lifter-diag"))]
pub(crate) fn diag_has_width_conflict(dex: &DexFile, item: &CodeItem, is_static: bool) -> bool {
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    let Some(parsed): Option<MethodDescriptor> = descriptor::parse_method(&item.method_descriptor)
    else {
        return false;
    };
    has_width_conflict(dex, &insns, &parsed, item, is_static)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Int,
    Long,
    Float,
    Double,
    Ref,
}

impl Slot {
    const fn category_two(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    const fn width(self) -> i32 {
        if self.category_two() { 2 } else { 1 }
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

pub(crate) struct EmittedCode {
    pub(crate) bytes: Vec<u8>,
    pub(crate) max_stack: u16,
    pub(crate) max_locals: u16,

    pub(crate) attributes: Vec<u8>,

    pub(crate) attribute_count: u16,

    pub(crate) exception_table: Vec<u8>,

    pub(crate) exception_count: u16,
}

struct Emitter<'a> {
    dex: &'a DexFile,
    cp: &'a mut ConstantPool,
    code: Vec<u8>,
    reg_type: BTreeMap<u16, Slot>,
    const_kind: BTreeMap<u16, Slot>,
    wide_double_pcs: BTreeSet<u32>,
    reg_array_elem: BTreeMap<u16, Slot>,
    param_array_elem: BTreeMap<u16, Slot>,
    array_elem_desc: BTreeMap<u16, u8>,
    param_array_elem_desc: BTreeMap<u16, u8>,
    fill_payloads: BTreeMap<u32, crate::dalvik::ArrayDataPayload>,
    poisoned_regs: BTreeSet<u16>,
    const_zero: BTreeSet<u16>,
    pending_new: BTreeMap<u16, String>,
    eager_new_pcs: BTreeSet<u32>,
    iinc_suppressed: BTreeSet<u32>,
    eager_new_active: BTreeMap<u16, String>,
    materialize_new_pcs: BTreeSet<u32>,
    materialize_active: BTreeMap<u16, (String, u32)>,
    pending_result: Option<Slot>,
    cur_stack: i32,
    max_stack: i32,
    registers_size: u16,
    first_param_reg: u16,
    param_local_slots: u16,
    max_locals: u16,
    virtual_local: BTreeMap<u16, u16>,
    bailed: bool,
    cfg: Option<CfgEmit>,
}

struct CfgEmit {
    cur_pc: u32,
    block_leaders: BTreeSet<u32>,
    jvm_offset_of_pc: BTreeMap<u32, usize>,
    fixups: Vec<BranchFixup>,
    switch_fixups: Vec<SwitchFixup>,
    switch_payloads: BTreeMap<u32, crate::dalvik::SwitchPayload>,
    block_entry_slots: BTreeMap<u32, BTreeMap<u16, Slot>>,
    frame_types: BTreeMap<u32, BTreeMap<u16, crate::dalvik_typestate::RegType>>,

    pc_post_slot: BTreeMap<u32, BTreeMap<u16, Slot>>,

    pc_post_array_elem: BTreeMap<u32, BTreeMap<u16, Slot>>,

    pc_entry_ref: BTreeMap<u32, BTreeMap<u16, String>>,
    pc_entry_null: BTreeMap<u32, BTreeSet<u16>>,

    pc_exit_ref_regs: BTreeMap<u32, BTreeSet<u16>>,
    tries: Vec<TryRegion>,

    handler_stack: BTreeMap<u32, String>,
    handler_stub_offset: BTreeMap<u32, usize>,
}

struct TryRegion {
    start_pc: u32,
    end_pc: u32,
    handlers: Vec<(Option<String>, u32)>,
}

struct BranchFixup {
    insn_offset: usize,
    operand_offset: usize,
    target_pc: u32,
}

struct SwitchFixup {
    insn_offset: usize,
    default_operand_offset: usize,
    default_target_pc: u32,
    case_operands: Vec<(usize, u32)>,
}

type SwitchPatch = (usize, usize, u32, Vec<(usize, u32)>);

type StackMapFrame = (usize, Vec<crate::dalvik_typestate::RegType>, Option<String>);

fn dedup_frames_by_offset(frames: Vec<StackMapFrame>) -> Option<Vec<StackMapFrame>> {
    let mut out: Vec<StackMapFrame> = Vec::with_capacity(frames.len());
    for frame in frames {
        match out.last() {
            Some(prev) if prev.0 == frame.0 => {
                if prev.1 != frame.1 || prev.2 != frame.2 {
                    #[cfg(any(test, feature = "lifter-diag"))]
                    record_bail_kind("frame-offset-conflict");
                    return None;
                }
            }
            _ => out.push(frame),
        }
    }
    Some(out)
}

#[must_use]
pub(crate) fn emit_method_code(
    dex: &DexFile,
    cp: &mut ConstantPool,
    item: &CodeItem,
    is_static: bool,
) -> Option<EmittedCode> {
    if item.insns.is_empty() || item.insns.len() > MAX_METHOD_INSNS {
        return None;
    }
    if !item.tries.is_empty() {
        return None;
    }
    let mut insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.is_empty() {
        return None;
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x0D) {
        return None;
    }
    let terminator: Option<usize> = insns
        .iter()
        .position(|i: &DalvikInsn| matches!(i.op, 0x0E..=0x11 | 0x27));
    if let Some(end) = terminator {
        insns.truncate(end + 1);
    }
    let parsed: MethodDescriptor = descriptor::parse_method(&item.method_descriptor)?;
    let const_kind: BTreeMap<u16, Slot> = infer_const_kinds(dex, &insns, &parsed);
    let wide_double_pcs: BTreeSet<u32> = wide_const_double_pcs(dex, &insns, &parsed);
    if has_width_conflict(dex, &insns, &parsed, item, is_static) {
        return None;
    }
    let first_param_reg: u16 = item.registers_size.saturating_sub(item.ins_size);
    let param_local_slots: u16 = u16::from(!is_static)
        + parsed
            .params
            .iter()
            .map(|p: &JavaType| if p.category_two() { 2u16 } else { 1u16 })
            .sum::<u16>();
    let max_locals: u16 = first_param_reg
        .saturating_add(param_local_slots)
        .saturating_add(1)
        .max(param_local_slots)
        .max(1);
    let eager_new_pcs: BTreeSet<u32> = collect_eager_new_pcs(dex, &insns, &collect_leaders(&insns));
    let iinc_suppressed: BTreeSet<u32> = collect_iinc_suppressed(dex, &insns);
    let fill_payloads: BTreeMap<u32, crate::dalvik::ArrayDataPayload> =
        collect_fill_payloads(&insns, &item.insns);
    let mut emitter: Emitter<'_> = Emitter {
        dex,
        cp,
        code: Vec::with_capacity(insns.len() * 3),
        reg_type: BTreeMap::new(),
        const_kind,
        wide_double_pcs,
        reg_array_elem: BTreeMap::new(),
        param_array_elem: BTreeMap::new(),
        array_elem_desc: BTreeMap::new(),
        param_array_elem_desc: BTreeMap::new(),
        fill_payloads,
        poisoned_regs: BTreeSet::new(),
        const_zero: BTreeSet::new(),
        pending_new: BTreeMap::new(),
        eager_new_pcs,
        iinc_suppressed,
        eager_new_active: BTreeMap::new(),
        materialize_new_pcs: BTreeSet::new(),
        materialize_active: BTreeMap::new(),
        pending_result: None,
        cur_stack: 0,
        max_stack: 0,
        registers_size: item.registers_size,
        first_param_reg,
        param_local_slots,
        max_locals,
        virtual_local: BTreeMap::new(),
        bailed: false,
        cfg: None,
    };
    emitter.seed_parameter_types(&parsed, is_static);
    for insn in &insns {
        if emitter.bailed || emitter.code.len() > MAX_CODE_BYTES {
            return None;
        }
        emitter.translate(insn, &parsed);
        #[cfg(any(test, feature = "lifter-diag"))]
        if emitter.bailed {
            record_bail_op(insn.op);
        }
        if emitter.bailed && crate::debug::dbg_enabled() {
            crate::debug::dbg_kv("dalvik-lift-bail", || {
                format!(
                    "{}->{}{} at pc={:#x} op={:#04x}: linear lifter could not model this opcode",
                    item.class, item.method_name, item.method_descriptor, insn.pc, insn.op
                )
            });
        }
    }
    if emitter.bailed
        || !emitter.pending_new.is_empty()
        || !emitter.eager_new_active.is_empty()
        || !emitter.materialize_active.is_empty()
    {
        return None;
    }
    Some(EmittedCode {
        bytes: emitter.code,
        max_stack: emitter.max_stack.max(2) as u16,
        max_locals: emitter.max_locals,
        attributes: Vec::new(),
        attribute_count: 0,
        exception_table: Vec::new(),
        exception_count: 0,
    })
}

const MAX_BRANCH_INSNS: usize = 2048;

#[inline]
const fn regtype_to_slot(ty: &crate::dalvik_typestate::RegType) -> Slot {
    use crate::dalvik_typestate::RegType;
    match ty {
        RegType::Long => Slot::Long,
        RegType::Float => Slot::Float,
        RegType::Double => Slot::Double,
        RegType::Ref(_)
        | RegType::NullRef
        | RegType::UninitializedThis
        | RegType::Uninitialized(_) => Slot::Ref,
        RegType::Int | RegType::ZeroOrNull | RegType::Top => Slot::Int,
    }
}

#[must_use]
pub(crate) fn emit_branch_method_code(
    dex: &DexFile,
    cp: &mut ConstantPool,
    item: &CodeItem,
    is_static: bool,
) -> Option<EmittedCode> {
    if item.insns.is_empty() || item.insns.len() > MAX_BRANCH_INSNS {
        return None;
    }
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.is_empty() {
        return None;
    }
    let has_branch: bool = insns.iter().any(|i: &DalvikInsn| {
        i.is_conditional_branch() || i.is_unconditional_goto() || i.is_switch()
    }) || !item.tries.is_empty();
    if !has_branch {
        return None;
    }
    if item.method_name == "<init>" && !init_this_call_is_trackable(dex, item, &insns) {
        return None;
    }
    let tries: Vec<TryRegion> = build_try_regions(item, &insns)?;
    if !tries.is_empty() && !move_exceptions_are_handler_entries(&insns, &tries) {
        return None;
    }
    let shared_handler_pcs: BTreeSet<u32> = if tries.is_empty() {
        BTreeSet::new()
    } else {
        fallthrough_reachable_handler_pcs(&insns, &tries)
    };
    if shared_handler_pcs.iter().any(|hpc: &u32| {
        insns
            .iter()
            .any(|i: &DalvikInsn| i.pc == *hpc && i.op == 0x0D)
    }) {
        return None;
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x22)
        && !new_instance_pairs_are_trackable(dex, &insns)
    {
        return None;
    }
    let switch_payloads: BTreeMap<u32, crate::dalvik::SwitchPayload> =
        parse_switch_payloads(&insns, &item.insns)?;
    let switch_targets: BTreeMap<u32, Vec<u32>> = switch_target_map(&insns, &switch_payloads);
    let fill_payloads: BTreeMap<u32, crate::dalvik::ArrayDataPayload> =
        collect_fill_payloads(&insns, &item.insns);
    let entry_pc: u32 = insns.first().map_or(0, |i: &DalvikInsn| i.pc);
    let entry_is_branch_target: bool = insns
        .iter()
        .any(|i: &DalvikInsn| i.branch_target_pc() == Some(entry_pc))
        || switch_targets
            .values()
            .any(|ts: &Vec<u32>| ts.contains(&entry_pc));
    let parsed: MethodDescriptor = descriptor::parse_method(&item.method_descriptor)?;

    let handler_edges: BTreeMap<u32, Vec<u32>> = try_handler_edges(&insns, &tries);
    let move_exception_type: BTreeMap<u32, String> = move_exception_types(&insns, &tries);
    let handler_stack: BTreeMap<u32, String> = handler_stack_types(&tries)
        .into_iter()
        .filter(|(pc, _): &(u32, String)| !shared_handler_pcs.contains(pc))
        .collect();

    let base_first_param_reg: u16 = item.registers_size.saturating_sub(item.ins_size);
    let base_param_local_slots: u16 = u16::from(!is_static)
        + parsed
            .params
            .iter()
            .map(|p: &JavaType| if p.category_two() { 2u16 } else { 1u16 })
            .sum::<u16>();
    let base_max_locals: u16 = base_first_param_reg
        .saturating_add(base_param_local_slots)
        .saturating_add(2)
        .max(base_param_local_slots)
        .max(1);
    let split: Option<crate::dalvik_split::SplitPlan> = crate::dalvik_split::plan_split(
        dex,
        &insns,
        &crate::dalvik_split::SplitShape {
            registers_size: item.registers_size,
            ins_size: item.ins_size,
            is_static,
            first_param_reg: base_first_param_reg,
            base_max_locals,
            parsed: &parsed,
        },
        &switch_targets,
        &handler_edges,
    );
    let (insns, virtual_local, split_max_locals): (Vec<DalvikInsn>, BTreeMap<u16, u16>, u16) =
        match split {
            Some(plan) => (plan.insns, plan.virtual_local, plan.max_locals),
            None => (insns, BTreeMap::new(), base_max_locals),
        };

    let mut block_leaders: BTreeSet<u32> = collect_leaders_with_switch(&insns, &switch_targets);
    for tr in &tries {
        block_leaders.insert(tr.start_pc);
        block_leaders.insert(tr.end_pc);
        for (_ty, hpc) in &tr.handlers {
            block_leaders.insert(*hpc);
        }
    }
    let eager_new_pcs: BTreeSet<u32> = collect_eager_new_pcs(dex, &insns, &block_leaders);
    let materialize_new_pcs: BTreeSet<u32> = collect_materialize_new_pcs(
        dex,
        &insns,
        &block_leaders,
        &eager_new_pcs,
        &switch_targets,
        &handler_edges,
    );

    let edges: crate::dalvik_typestate::CfgEdges<'_> = crate::dalvik_typestate::CfgEdges {
        switch_targets: &switch_targets,
        handler_edges: &handler_edges,
        move_exception_type: &move_exception_type,
    };
    let is_init_ctor: bool = item.method_name == "<init>" && !is_static;
    let shape: crate::dalvik_typestate::MethodShape<'_> = crate::dalvik_typestate::MethodShape {
        registers_size: item.registers_size,
        ins_size: item.ins_size,
        is_static,
        is_init_ctor,
        class_internal: &item.class,
        materialize_new_pcs: &materialize_new_pcs,
    };
    let states: crate::dalvik_typestate::TypeStates =
        crate::dalvik_typestate::analyze(dex, &insns, &parsed, &shape, &edges)?;

    let pc_to_idx: BTreeMap<u32, usize> =
        insns.iter().enumerate().map(|(i, n)| (n.pc, i)).collect();

    let mut block_entry_slots: BTreeMap<u32, BTreeMap<u16, Slot>> = BTreeMap::new();
    let mut frame_types: BTreeMap<u32, BTreeMap<u16, crate::dalvik_typestate::RegType>> =
        BTreeMap::new();
    for &leader in &block_leaders {
        let Some(&idx): Option<&usize> = pc_to_idx.get(&leader) else {
            continue;
        };
        if !states.reached[idx] {
            continue;
        }
        let st: &crate::dalvik_typestate::RegState = &states.entry_state[idx];
        let slots: BTreeMap<u16, Slot> = st.iter().map(|(&r, t)| (r, regtype_to_slot(t))).collect();
        block_entry_slots.insert(leader, slots);
        frame_types.insert(leader, st.clone());
    }

    let mut pc_post_slot: BTreeMap<u32, BTreeMap<u16, Slot>> = BTreeMap::new();
    let mut pc_entry_ref: BTreeMap<u32, BTreeMap<u16, String>> = BTreeMap::new();
    let mut pc_entry_null: BTreeMap<u32, BTreeSet<u16>> = BTreeMap::new();
    let mut pc_post_array_elem: BTreeMap<u32, BTreeMap<u16, Slot>> = BTreeMap::new();
    for (i, insn) in insns.iter().enumerate() {
        if !states.reached[i] {
            continue;
        }
        let entry: &crate::dalvik_typestate::RegState = &states.entry_state[i];
        let refs: BTreeMap<u16, String> = entry
            .iter()
            .filter_map(
                |(&r, t): (&u16, &crate::dalvik_typestate::RegType)| match t {
                    crate::dalvik_typestate::RegType::Ref(name) => Some((r, name.clone())),
                    _ => None,
                },
            )
            .collect();
        if !refs.is_empty() {
            pc_entry_ref.insert(insn.pc, refs);
        }
        let nulls: BTreeSet<u16> = entry
            .iter()
            .filter_map(|(&r, t): (&u16, &crate::dalvik_typestate::RegType)| {
                matches!(t, crate::dalvik_typestate::RegType::NullRef).then_some(r)
            })
            .collect();
        if !nulls.is_empty() {
            pc_entry_null.insert(insn.pc, nulls);
        }
        let Some(next): Option<&DalvikInsn> = insns.get(i + 1) else {
            continue;
        };
        let next_state: &crate::dalvik_typestate::RegState = &states.entry_state[i + 1];
        let slots: BTreeMap<u16, Slot> = next_state
            .iter()
            .map(|(&r, t)| (r, regtype_to_slot(t)))
            .collect();
        let elems: BTreeMap<u16, Slot> = next_state
            .iter()
            .filter_map(|(&r, t): (&u16, &crate::dalvik_typestate::RegType)| {
                array_elem_from_regtype(t).map(|e: Slot| (r, e))
            })
            .collect();
        if !elems.is_empty() {
            pc_post_array_elem.insert(insn.pc, elems);
        }
        let _ = next;
        pc_post_slot.insert(insn.pc, slots);
    }

    let pc_exit_ref_regs: BTreeMap<u32, BTreeSet<u16>> = compute_exit_ref_regs(
        dex,
        &insns,
        &states,
        &block_leaders,
        &switch_targets,
        &handler_edges,
        &pc_to_idx,
    );

    let first_param_reg: u16 = item.registers_size.saturating_sub(item.ins_size);
    let param_local_slots: u16 = u16::from(!is_static)
        + parsed
            .params
            .iter()
            .map(|p: &JavaType| if p.category_two() { 2u16 } else { 1u16 })
            .sum::<u16>();
    let max_locals: u16 = first_param_reg
        .saturating_add(param_local_slots)
        .saturating_add(2)
        .max(param_local_slots)
        .max(1)
        .max(split_max_locals);
    let const_kind: BTreeMap<u16, Slot> = infer_const_kinds(dex, &insns, &parsed);
    let wide_double_pcs: BTreeSet<u32> = wide_const_double_pcs(dex, &insns, &parsed);
    let iinc_suppressed: BTreeSet<u32> = collect_iinc_suppressed(dex, &insns);

    let mut emitter: Emitter<'_> = Emitter {
        dex,
        cp,
        code: Vec::with_capacity(insns.len() * 3),
        reg_type: BTreeMap::new(),
        const_kind,
        wide_double_pcs,
        reg_array_elem: BTreeMap::new(),
        param_array_elem: BTreeMap::new(),
        array_elem_desc: BTreeMap::new(),
        param_array_elem_desc: BTreeMap::new(),
        fill_payloads,
        poisoned_regs: BTreeSet::new(),
        const_zero: BTreeSet::new(),
        pending_new: BTreeMap::new(),
        eager_new_pcs,
        iinc_suppressed,
        eager_new_active: BTreeMap::new(),
        materialize_new_pcs,
        materialize_active: BTreeMap::new(),
        pending_result: None,
        cur_stack: 0,
        max_stack: 0,
        registers_size: item.registers_size,
        first_param_reg,
        param_local_slots,
        max_locals,
        virtual_local,
        bailed: false,
        cfg: Some(CfgEmit {
            cur_pc: 0,
            block_leaders,
            jvm_offset_of_pc: BTreeMap::new(),
            fixups: Vec::new(),
            switch_fixups: Vec::new(),
            switch_payloads,
            block_entry_slots,
            frame_types,
            pc_post_slot,
            pc_post_array_elem,
            pc_entry_ref,
            pc_entry_null,
            pc_exit_ref_regs,
            tries,
            handler_stack,
            handler_stub_offset: BTreeMap::new(),
        }),
    };
    emitter.seed_parameter_types(&parsed, is_static);
    if entry_is_branch_target {
        emitter.push(0x00);
    }
    for insn in &insns {
        if emitter.bailed || emitter.code.len() > MAX_CODE_BYTES {
            return None;
        }
        emitter.translate(insn, &parsed);
        emitter.apply_post_array_elem(insn.pc);
        #[cfg(any(test, feature = "lifter-diag"))]
        if emitter.bailed {
            record_bail_op(insn.op);
        }
    }
    if emitter.bailed
        || !emitter.pending_new.is_empty()
        || !emitter.eager_new_active.is_empty()
        || !emitter.materialize_active.is_empty()
    {
        return None;
    }
    emitter.emit_handler_dispatch_stubs(&shared_handler_pcs);
    if emitter.bailed {
        return None;
    }
    emitter.resolve_branches()?;
    let (exception_table, exception_count): (Vec<u8>, u16) = emitter.build_exception_table()?;
    let attr: Vec<u8> = emitter.build_stack_map_table(first_param_reg, param_local_slots)?;
    let (attributes, attribute_count): (Vec<u8>, u16) = if attr.is_empty() {
        (Vec::new(), 0)
    } else {
        (attr, 1)
    };

    Some(EmittedCode {
        bytes: emitter.code,
        max_stack: emitter.max_stack.max(2) as u16,
        max_locals: emitter.max_locals,
        attributes,
        attribute_count,
        exception_table,
        exception_count,
    })
}

fn catch_internal(ty: Option<&str>) -> String {
    match ty {
        Some(d) => internal_of(d),
        None => "java/lang/Throwable".to_string(),
    }
}

fn build_try_regions(item: &CodeItem, insns: &[DalvikInsn]) -> Option<Vec<TryRegion>> {
    let valid: BTreeSet<u32> = insns.iter().map(|i: &DalvikInsn| i.pc).collect();
    let end_pc: u32 = insns
        .last()
        .map(|i: &DalvikInsn| i.pc + u32::from(i.width))
        .unwrap_or(0);
    let mut out: Vec<TryRegion> = Vec::with_capacity(item.tries.len());
    for t in &item.tries {
        let start: u32 = t.start_addr;
        let stop: u32 = t.start_addr + u32::from(t.insn_count);
        if !valid.contains(&start) || (!valid.contains(&stop) && stop != end_pc) {
            return None;
        }
        let mut handlers: Vec<(Option<String>, u32)> = Vec::new();
        for (ty, hpc) in &t.handlers {
            if !valid.contains(hpc) {
                return None;
            }
            handlers.push((ty.clone(), *hpc));
        }
        if let Some(hpc) = t.catch_all {
            if !valid.contains(&hpc) {
                return None;
            }
            handlers.push((None, hpc));
        }
        if handlers.is_empty() {
            return None;
        }
        out.push(TryRegion {
            start_pc: start,
            end_pc: stop,
            handlers,
        });
    }
    Some(out)
}

fn fallthrough_reachable_handler_pcs(insns: &[DalvikInsn], tries: &[TryRegion]) -> BTreeSet<u32> {
    let handler_pcs: BTreeSet<u32> = tries
        .iter()
        .flat_map(|t: &TryRegion| t.handlers.iter().map(|(_ty, hpc)| *hpc))
        .collect();
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for (i, insn) in insns.iter().enumerate() {
        if i == 0 || !handler_pcs.contains(&insn.pc) {
            continue;
        }
        let prev: &DalvikInsn = &insns[i - 1];
        let diverts: bool = prev.is_unconditional_goto() || prev.is_return() || prev.is_throw();
        if !diverts {
            out.insert(insn.pc);
        }
    }
    out
}

fn move_exceptions_are_handler_entries(insns: &[DalvikInsn], tries: &[TryRegion]) -> bool {
    let handler_pcs: BTreeSet<u32> = tries
        .iter()
        .flat_map(|t: &TryRegion| t.handlers.iter().map(|(_ty, hpc)| *hpc))
        .collect();
    insns
        .iter()
        .filter(|i: &&DalvikInsn| i.op == 0x0D)
        .all(|i: &DalvikInsn| handler_pcs.contains(&i.pc))
}

fn try_handler_edges(insns: &[DalvikInsn], tries: &[TryRegion]) -> BTreeMap<u32, Vec<u32>> {
    let mut out: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for t in tries {
        let handler_pcs: Vec<u32> = t.handlers.iter().map(|(_ty, hpc)| *hpc).collect();
        for insn in insns {
            if insn.pc >= t.start_pc && insn.pc < t.end_pc {
                out.entry(insn.pc)
                    .or_default()
                    .extend(handler_pcs.iter().copied());
            }
        }
    }
    out
}

fn move_exception_types(insns: &[DalvikInsn], tries: &[TryRegion]) -> BTreeMap<u32, String> {
    let stack: BTreeMap<u32, String> = handler_stack_types(tries);
    let mut out: BTreeMap<u32, String> = BTreeMap::new();
    for insn in insns {
        if insn.op == 0x0D
            && let Some(ty) = stack.get(&insn.pc)
        {
            out.insert(insn.pc, ty.clone());
        }
    }
    out
}

fn handler_stack_types(tries: &[TryRegion]) -> BTreeMap<u32, String> {
    let mut seen: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for t in tries {
        for (ty, hpc) in &t.handlers {
            seen.entry(*hpc)
                .or_default()
                .insert(catch_internal(ty.as_deref()));
        }
    }
    seen.into_iter()
        .map(|(hpc, types): (u32, BTreeSet<String>)| {
            let resolved: String = if types.len() == 1 {
                types
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| "java/lang/Throwable".to_string())
            } else {
                "java/lang/Throwable".to_string()
            };
            (hpc, resolved)
        })
        .collect()
}

fn parse_switch_payloads(
    insns: &[DalvikInsn],
    code: &[u16],
) -> Option<BTreeMap<u32, crate::dalvik::SwitchPayload>> {
    let mut out: BTreeMap<u32, crate::dalvik::SwitchPayload> = BTreeMap::new();
    for insn in insns {
        if !insn.is_switch() {
            continue;
        }
        let payload_off: u32 = insn.payload_off?;
        let payload: crate::dalvik::SwitchPayload = if insn.op == 0x2B {
            crate::dalvik::parse_packed_switch(code, insn.pc, payload_off)?
        } else {
            crate::dalvik::parse_sparse_switch(code, insn.pc, payload_off)?
        };
        out.insert(insn.pc, payload);
    }
    Some(out)
}

fn collect_fill_payloads(
    insns: &[DalvikInsn],
    code: &[u16],
) -> BTreeMap<u32, crate::dalvik::ArrayDataPayload> {
    let mut out: BTreeMap<u32, crate::dalvik::ArrayDataPayload> = BTreeMap::new();
    for insn in insns {
        if insn.op != 0x26 {
            continue;
        }
        let Some(payload_off): Option<u32> = insn.payload_off else {
            continue;
        };
        if let Some(payload) = crate::dalvik::parse_fill_array_data(code, payload_off) {
            out.insert(insn.pc, payload);
        }
    }
    out
}

fn switch_target_map(
    insns: &[DalvikInsn],
    payloads: &BTreeMap<u32, crate::dalvik::SwitchPayload>,
) -> BTreeMap<u32, Vec<u32>> {
    let mut out: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (i, insn) in insns.iter().enumerate() {
        if !insn.is_switch() {
            continue;
        }
        let Some(payload) = payloads.get(&insn.pc) else {
            continue;
        };
        let mut targets: Vec<u32> = payload.targets.clone();
        if let Some(next) = insns.get(i + 1) {
            targets.push(next.pc);
        }
        out.insert(insn.pc, targets);
    }
    out
}

fn is_contiguous(keys: &[i32]) -> bool {
    keys.windows(2)
        .all(|w: &[i32]| w[1].checked_sub(w[0]) == Some(1))
}

fn compute_exit_ref_regs(
    dex: &DexFile,
    insns: &[DalvikInsn],
    states: &crate::dalvik_typestate::TypeStates,
    block_leaders: &BTreeSet<u32>,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
    pc_to_idx: &BTreeMap<u32, usize>,
) -> BTreeMap<u32, BTreeSet<u16>> {
    use crate::dalvik_typestate::RegType;
    let mut out: BTreeMap<u32, BTreeSet<u16>> = BTreeMap::new();
    let mut block_start: usize = 0;
    for i in 0..insns.len() {
        let is_block_end: bool = insns
            .get(i + 1)
            .is_none_or(|n: &DalvikInsn| block_leaders.contains(&n.pc));
        if !is_block_end {
            continue;
        }
        let term: &DalvikInsn = &insns[i];
        let mut succ_leaders: Vec<u32> = Vec::new();
        if let Some(t) = term.branch_target_pc() {
            succ_leaders.push(t);
        }
        if term.is_switch()
            && let Some(targets) = switch_targets.get(&term.pc)
        {
            succ_leaders.extend(targets.iter().copied());
        }
        if !term.is_unconditional_goto()
            && !term.is_return()
            && !term.is_throw()
            && let Some(next) = insns.get(i + 1)
        {
            succ_leaders.push(next.pc);
        }
        for insn in &insns[block_start..=i] {
            if let Some(edges) = handler_edges.get(&insn.pc) {
                succ_leaders.extend(edges.iter().copied());
            }
        }

        let mut ref_regs: BTreeSet<u16> = BTreeSet::new();
        let mut disq: BTreeSet<u16> = BTreeSet::new();
        let mut any_reached: bool = false;
        for spc in &succ_leaders {
            let Some(&sidx): Option<&usize> = pc_to_idx.get(spc) else {
                continue;
            };
            if !states.reached[sidx] {
                continue;
            }
            any_reached = true;
            let st: &crate::dalvik_typestate::RegState = &states.entry_state[sidx];
            for (&reg, ty) in st {
                match ty {
                    RegType::Ref(_) | RegType::NullRef | RegType::UninitializedThis => {
                        ref_regs.insert(reg);
                    }
                    RegType::ZeroOrNull => {}
                    _ => {
                        disq.insert(reg);
                    }
                }
            }
        }
        if any_reached {
            for reg in &disq {
                ref_regs.remove(reg);
            }
            if !ref_regs.is_empty() {
                for (k, insn) in insns[block_start..=i].iter().enumerate() {
                    let def_idx: usize = block_start + k;
                    if !matches!(insn.op, 0x12 | 0x13 | 0x15) || insn.literal.unwrap_or(0) != 0 {
                        continue;
                    }
                    let Some(&dest): Option<&u16> = insn.regs.first() else {
                        continue;
                    };
                    if !ref_regs.contains(&dest) {
                        continue;
                    }
                    if zero_def_promotion_blocked(
                        dex,
                        insns,
                        states,
                        block_leaders,
                        def_idx,
                        dest,
                        switch_targets,
                        handler_edges,
                        pc_to_idx,
                    ) {
                        continue;
                    }
                    out.entry(insn.pc).or_default().insert(dest);
                }
            }
        }
        block_start = i + 1;
    }
    for (idx, insn) in insns.iter().enumerate() {
        if !matches!(insn.op, 0x12 | 0x13 | 0x15) || insn.literal.unwrap_or(0) != 0 {
            continue;
        }
        if !states.reached[idx] {
            continue;
        }
        let Some(&dest): Option<&u16> = insn.regs.first() else {
            continue;
        };
        if out
            .get(&insn.pc)
            .is_some_and(|s: &BTreeSet<u16>| s.contains(&dest))
        {
            continue;
        }
        if zero_const_reaches_ref_frame(
            dex,
            insns,
            states,
            block_leaders,
            idx,
            dest,
            switch_targets,
            handler_edges,
            pc_to_idx,
        ) {
            out.entry(insn.pc).or_default().insert(dest);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn zero_const_reaches_ref_frame(
    dex: &DexFile,
    insns: &[DalvikInsn],
    states: &crate::dalvik_typestate::TypeStates,
    block_leaders: &BTreeSet<u32>,
    def_idx: usize,
    reg: u16,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
    pc_to_idx: &BTreeMap<u32, usize>,
) -> bool {
    use crate::dalvik_typestate::RegType;
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut work: Vec<usize> = successors(insns, def_idx, switch_targets, handler_edges, pc_to_idx);
    let mut found_ref: bool = false;
    while let Some(idx) = work.pop() {
        if !visited.insert(idx) {
            continue;
        }
        let Some(insn): Option<&DalvikInsn> = insns.get(idx) else {
            continue;
        };
        if block_leaders.contains(&insn.pc) && states.reached[idx] {
            match states.entry_state[idx].get(&reg) {
                Some(RegType::Ref(_) | RegType::UninitializedThis) => {
                    found_ref = true;
                }
                Some(
                    RegType::Int | RegType::Float | RegType::Long | RegType::Double | RegType::Top,
                ) => {
                    return false;
                }
                _ => {}
            }
        }
        match reg_use_kind(dex, insn, reg) {
            RegUse::Int => return false,
            RegUse::Redefined => continue,
            RegUse::Ref | RegUse::Neutral => {}
        }
        work.extend(successors(
            insns,
            idx,
            switch_targets,
            handler_edges,
            pc_to_idx,
        ));
    }
    found_ref
}

#[allow(clippy::too_many_arguments)]
fn zero_def_promotion_blocked(
    dex: &DexFile,
    insns: &[DalvikInsn],
    states: &crate::dalvik_typestate::TypeStates,
    block_leaders: &BTreeSet<u32>,
    def_idx: usize,
    reg: u16,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
    pc_to_idx: &BTreeMap<u32, usize>,
) -> bool {
    use crate::dalvik_typestate::RegType;
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut work: Vec<usize> = successors(insns, def_idx, switch_targets, handler_edges, pc_to_idx);
    while let Some(idx) = work.pop() {
        if !visited.insert(idx) {
            continue;
        }
        let Some(insn): Option<&DalvikInsn> = insns.get(idx) else {
            continue;
        };
        if block_leaders.contains(&insn.pc)
            && states.reached[idx]
            && matches!(
                states.entry_state[idx].get(&reg),
                Some(RegType::Int | RegType::Float | RegType::Long | RegType::Double)
            )
        {
            return true;
        }
        match reg_use_kind(dex, insn, reg) {
            RegUse::Int => return true,
            RegUse::Redefined => continue,
            RegUse::Ref | RegUse::Neutral => {}
        }
        work.extend(successors(
            insns,
            idx,
            switch_targets,
            handler_edges,
            pc_to_idx,
        ));
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegUse {
    Int,

    Ref,

    Neutral,

    Redefined,
}

fn successors(
    insns: &[DalvikInsn],
    idx: usize,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
    pc_to_idx: &BTreeMap<u32, usize>,
) -> Vec<usize> {
    let Some(insn): Option<&DalvikInsn> = insns.get(idx) else {
        return Vec::new();
    };
    let mut out: Vec<usize> = Vec::new();
    let push_pc = |pc: u32, out: &mut Vec<usize>| {
        if let Some(&j) = pc_to_idx.get(&pc) {
            out.push(j);
        }
    };
    if let Some(t) = insn.branch_target_pc() {
        push_pc(t, &mut out);
    }
    if insn.is_switch()
        && let Some(targets) = switch_targets.get(&insn.pc)
    {
        for &t in targets {
            push_pc(t, &mut out);
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
            push_pc(t, &mut out);
        }
    }
    out
}

fn reg_use_kind(dex: &DexFile, insn: &DalvikInsn, reg: u16) -> RegUse {
    let op: u8 = insn.op;
    let r: &[u16] = &insn.regs;
    if !r.contains(&reg) {
        return RegUse::Neutral;
    }
    let is_first: bool = r.first() == Some(&reg);
    match op {
        0x07..=0x09 => {
            if is_first {
                RegUse::Redefined
            } else {
                RegUse::Ref
            }
        }
        0x01..=0x06 => {
            if is_first {
                RegUse::Redefined
            } else {
                RegUse::Int
            }
        }
        0x0A..=0x0D | 0x12..=0x1C | 0x1F..=0x23 => {
            if is_first {
                RegUse::Redefined
            } else {
                RegUse::Neutral
            }
        }
        0x11 => RegUse::Ref,
        0x0F | 0x10 => RegUse::Int,
        0x1D | 0x1E | 0x27 => RegUse::Ref,
        0x32 | 0x33 | 0x38 | 0x39 => RegUse::Neutral,
        0x34..=0x37 | 0x3A..=0x3D => RegUse::Int,
        0x2D..=0x31 => {
            if is_first {
                RegUse::Redefined
            } else {
                RegUse::Int
            }
        }
        0x44..=0x4A => {
            if is_first {
                RegUse::Redefined
            } else if r.get(1) == Some(&reg) {
                RegUse::Ref
            } else {
                RegUse::Int
            }
        }
        0x4B..=0x51 => {
            if r.get(1) == Some(&reg) || (op == 0x4D && r.first() == Some(&reg)) {
                RegUse::Ref
            } else {
                RegUse::Int
            }
        }
        0x52..=0x58 => {
            if is_first {
                RegUse::Redefined
            } else {
                RegUse::Ref
            }
        }
        0x59..=0x5F => {
            if r.get(1) == Some(&reg) || (op == 0x5B && r.first() == Some(&reg)) {
                RegUse::Ref
            } else {
                RegUse::Int
            }
        }
        0x60..=0x66 => {
            if is_first {
                RegUse::Redefined
            } else {
                RegUse::Neutral
            }
        }
        0x67..=0x6D => {
            if op == 0x69 {
                RegUse::Ref
            } else {
                RegUse::Int
            }
        }
        0x6E..=0x72 | 0x74..=0x78 => invoke_reg_use(dex, insn, reg),
        0x7B..=0xAF => {
            if is_first {
                RegUse::Redefined
            } else {
                RegUse::Int
            }
        }
        0xB0..=0xE2 => RegUse::Int,
        _ => RegUse::Neutral,
    }
}

fn invoke_reg_use(dex: &DexFile, insn: &DalvikInsn, reg: u16) -> RegUse {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| dex.method_ids.get(i as usize))
    else {
        return RegUse::Neutral;
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static && reg_iter.next() == Some(&reg) {
        return RegUse::Ref;
    }
    for param in &method.proto.parameters {
        let slot: Slot = field_slot(param);
        if let Some(&used) = reg_iter.next()
            && used == reg
        {
            return if matches!(slot, Slot::Ref) {
                RegUse::Ref
            } else {
                RegUse::Int
            };
        }
        if slot.category_two() {
            let _ = reg_iter.next();
        }
    }
    RegUse::Neutral
}

fn collect_leaders_with_switch(
    insns: &[DalvikInsn],
    switch_targets: &BTreeMap<u32, Vec<u32>>,
) -> BTreeSet<u32> {
    let mut leaders: BTreeSet<u32> = collect_leaders(insns);
    for targets in switch_targets.values() {
        for &t in targets {
            leaders.insert(t);
        }
    }
    leaders
}

fn collect_leaders(insns: &[DalvikInsn]) -> BTreeSet<u32> {
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    if let Some(first) = insns.first() {
        leaders.insert(first.pc);
    }
    for (i, insn) in insns.iter().enumerate() {
        if let Some(t) = insn.branch_target_pc() {
            leaders.insert(t);
        }
        if (insn.is_conditional_branch() || insn.is_unconditional_goto())
            && let Some(next) = insns.get(i + 1)
        {
            leaders.insert(next.pc);
        }
    }
    leaders
}

fn collect_iinc_suppressed(dex: &DexFile, insns: &[DalvikInsn]) -> BTreeSet<u32> {
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for (k, insn) in insns.iter().enumerate() {
        if !matches!(insn.op, 0xD0 | 0xD8) {
            continue;
        }
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) =
            (insn.regs.first(), insn.regs.get(1))
        else {
            continue;
        };
        if dest != src {
            continue;
        }
        let Some(next): Option<&DalvikInsn> = insns.get(k + 1) else {
            continue;
        };
        if matches!(reg_use_kind(dex, next, dest), RegUse::Int) {
            out.insert(insn.pc);
        }
    }
    out
}

fn new_instance_pairs_are_trackable(dex: &DexFile, insns: &[DalvikInsn]) -> bool {
    for (k, insn) in insns.iter().enumerate() {
        if insn.op != 0x22 {
            continue;
        }
        let Some(&dest): Option<&u16> = insn.regs.first() else {
            return false;
        };
        let Some(owner): Option<String> = insn.index.and_then(|i: u32| {
            dex.type_names
                .get(i as usize)
                .map(|t: &String| internal_of(t))
        }) else {
            return false;
        };
        if paired_init_pc(dex, insns, k, dest, &owner).is_none()
            && !new_dest_discarded_by_renew(dex, insns, k, dest)
        {
            return false;
        }
    }
    true
}

fn new_dest_discarded_by_renew(
    dex: &DexFile,
    insns: &[DalvikInsn],
    from_idx: usize,
    dest: u16,
) -> bool {
    for follow in &insns[from_idx + 1..] {
        match reg_use_kind(dex, follow, dest) {
            RegUse::Redefined => return follow.op == 0x22,
            RegUse::Int | RegUse::Ref => return false,
            RegUse::Neutral => {}
        }
    }
    false
}

fn init_invoke_owner(dex: &DexFile, insn: &DalvikInsn) -> Option<String> {
    if !matches!(insn.op, 0x70 | 0x76) {
        return None;
    }
    let method: &MethodId = insn
        .index
        .and_then(|i: u32| dex.method_ids.get(i as usize))?;
    if method.name != "<init>" {
        return None;
    }
    Some(internal_of(&method.class))
}

fn collect_eager_new_pcs(
    dex: &DexFile,
    insns: &[DalvikInsn],
    leaders: &BTreeSet<u32>,
) -> BTreeSet<u32> {
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for (k, insn) in insns.iter().enumerate() {
        if insn.op != 0x22 {
            continue;
        }
        let Some(&dest): Option<&u16> = insn.regs.first() else {
            continue;
        };
        let Some(owner): Option<String> = insn.index.and_then(|i: u32| {
            dex.type_names
                .get(i as usize)
                .map(|t: &String| internal_of(t))
        }) else {
            continue;
        };
        let mut ok: bool = false;
        for follow in &insns[k + 1..] {
            if leaders.contains(&follow.pc) {
                break;
            }
            if let Some(init_owner) = init_invoke_owner(dex, follow) {
                let recv: Option<u16> = follow.regs.first().copied();
                if recv == Some(dest) && init_owner == owner {
                    ok = true;
                }
                break;
            }
            if follow.op == 0x22 {
                break;
            }
            if follow.regs.contains(&dest) {
                break;
            }
        }
        if ok {
            out.insert(insn.pc);
        }
    }
    out
}

const fn is_move_object(op: u8) -> bool {
    matches!(op, 0x07..=0x09)
}

fn paired_init_pc(
    dex: &DexFile,
    insns: &[DalvikInsn],
    from_idx: usize,
    dest: u16,
    owner: &str,
) -> Option<u32> {
    let mut aliases: BTreeSet<u16> = BTreeSet::from([dest]);
    for follow in &insns[from_idx + 1..] {
        if let Some(init_owner) = init_invoke_owner(dex, follow)
            && follow
                .regs
                .first()
                .is_some_and(|r: &u16| aliases.contains(r))
        {
            return (init_owner == owner).then_some(follow.pc);
        }
        if is_move_object(follow.op)
            && let (Some(&d), Some(&s)) = (follow.regs.first(), follow.regs.get(1))
        {
            if aliases.contains(&s) {
                aliases.insert(d);
            } else if aliases.remove(&d) && aliases.is_empty() {
                return None;
            }
            continue;
        }
        if follow.regs.iter().any(|r: &u16| aliases.contains(r)) {
            return None;
        }
    }
    None
}

fn new_dominates_init(
    insns: &[DalvikInsn],
    pc_to_idx: &BTreeMap<u32, usize>,
    new_pc: u32,
    init_pc: u32,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
) -> bool {
    let entry_pc: u32 = insns.first().map_or(0, |i: &DalvikInsn| i.pc);
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut work: Vec<u32> = vec![entry_pc];
    while let Some(pc) = work.pop() {
        if pc == new_pc {
            continue;
        }
        if pc == init_pc {
            return false;
        }
        if !visited.insert(pc) {
            continue;
        }
        let Some(&idx): Option<&usize> = pc_to_idx.get(&pc) else {
            return false;
        };
        let insn: &DalvikInsn = &insns[idx];
        if let Some(t) = insn.branch_target_pc() {
            work.push(t);
        }
        if insn.is_switch()
            && let Some(targets) = switch_targets.get(&pc)
        {
            work.extend(targets.iter().copied());
        }
        if let Some(edges) = handler_edges.get(&pc) {
            work.extend(edges.iter().copied());
        }
        if !insn.is_unconditional_goto()
            && !insn.is_return()
            && !insn.is_throw()
            && let Some(next) = insns.get(idx + 1)
        {
            work.push(next.pc);
        }
    }
    true
}

fn collect_materialize_new_pcs(
    dex: &DexFile,
    insns: &[DalvikInsn],
    leaders: &BTreeSet<u32>,
    eager: &BTreeSet<u32>,
    switch_targets: &BTreeMap<u32, Vec<u32>>,
    handler_edges: &BTreeMap<u32, Vec<u32>>,
) -> BTreeSet<u32> {
    let pc_to_idx: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, n): (usize, &DalvikInsn)| (n.pc, i))
        .collect();
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for (k, insn) in insns.iter().enumerate() {
        if insn.op != 0x22 || eager.contains(&insn.pc) {
            continue;
        }
        let Some(&dest): Option<&u16> = insn.regs.first() else {
            continue;
        };
        let Some(owner): Option<String> = insn.index.and_then(|i: u32| {
            dex.type_names
                .get(i as usize)
                .map(|t: &String| internal_of(t))
        }) else {
            continue;
        };
        let Some(init_pc): Option<u32> = paired_init_pc(dex, insns, k, dest, &owner) else {
            continue;
        };
        let cross_block: bool = leaders.iter().any(|&l: &u32| l > insn.pc && l <= init_pc);
        if !cross_block {
            continue;
        }
        if !new_dominates_init(
            insns,
            &pc_to_idx,
            insn.pc,
            init_pc,
            switch_targets,
            handler_edges,
        ) {
            continue;
        }
        out.insert(insn.pc);
    }
    out
}

fn sole_init_call_on_this(dex: &DexFile, this_reg: u16, insns: &[DalvikInsn]) -> Option<u32> {
    let mut found: Option<u32> = None;
    for insn in insns {
        if !matches!(insn.op, 0x70 | 0x76) {
            continue;
        }
        let Some(&recv): Option<&u16> = insn.regs.first() else {
            continue;
        };
        if recv != this_reg {
            continue;
        }
        let is_init: bool = insn
            .index
            .and_then(|i: u32| dex.method_ids.get(i as usize))
            .is_some_and(|m: &MethodId| m.name == "<init>");
        if !is_init {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(insn.pc);
    }
    found
}

fn init_call_dominates_leaders(item: &CodeItem, insns: &[DalvikInsn], init_pc: u32) -> bool {
    let mut leaders: BTreeSet<u32> = collect_leaders(insns);
    for t in &item.tries {
        leaders.insert(t.start_addr);
        leaders.insert(t.start_addr + u32::from(t.insn_count));
        for (_ty, hpc) in &t.handlers {
            leaders.insert(*hpc);
        }
        if let Some(hpc) = t.catch_all {
            leaders.insert(hpc);
        }
    }
    let entry_pc: u32 = insns.first().map_or(0, |i: &DalvikInsn| i.pc);
    let min_non_entry_leader: u32 = leaders
        .iter()
        .copied()
        .filter(|&pc: &u32| pc != entry_pc)
        .min()
        .unwrap_or(u32::MAX);
    init_pc < min_non_entry_leader
}

fn init_this_call_is_trackable(dex: &DexFile, item: &CodeItem, insns: &[DalvikInsn]) -> bool {
    let this_reg: u16 = item.registers_size.saturating_sub(item.ins_size);
    let Some(init_pc): Option<u32> = sole_init_call_on_this(dex, this_reg, insns) else {
        return false;
    };
    if init_call_dominates_leaders(item, insns, init_pc) {
        return true;
    }

    let pc_to_idx: BTreeMap<u32, usize> =
        insns.iter().enumerate().map(|(i, n)| (n.pc, i)).collect();
    let switch_targets: BTreeMap<u32, Vec<u32>> = parse_switch_payloads(insns, &item.insns)
        .map(|p: BTreeMap<u32, crate::dalvik::SwitchPayload>| switch_target_map(insns, &p))
        .unwrap_or_default();
    let mut handler_pcs: BTreeSet<u32> = BTreeSet::new();
    for t in &item.tries {
        for (_ty, hpc) in &t.handlers {
            handler_pcs.insert(*hpc);
        }
        if let Some(hpc) = t.catch_all {
            handler_pcs.insert(hpc);
        }
    }

    let parsed: Option<MethodDescriptor> = descriptor::parse_method(&item.method_descriptor);
    let first_param_reg: u16 = this_reg;
    let entry_pc: u32 = insns.first().map_or(0, |i: &DalvikInsn| i.pc);
    let mut reachable_pre_init: BTreeSet<u32> = BTreeSet::new();
    let mut work: Vec<u32> = vec![entry_pc];
    while let Some(pc) = work.pop() {
        if pc == init_pc || !reachable_pre_init.insert(pc) {
            continue;
        }
        let Some(&idx): Option<&usize> = pc_to_idx.get(&pc) else {
            return false;
        };
        let insn: &DalvikInsn = &insns[idx];
        if uses_register_before_init(insn, this_reg) {
            return false;
        }
        if let Some(p) = parsed.as_ref() {
            let (def, _cat, _uses): (Option<u16>, Cat, Vec<(u16, Cat)>) =
                register_effects(dex, insn, p);
            if let Some(d) = def
                && d >= first_param_reg
                && d < item.registers_size
            {
                return false;
            }
        }
        if let Some(t) = insn.branch_target_pc() {
            work.push(t);
        }
        if insn.is_switch()
            && let Some(targets) = switch_targets.get(&pc)
        {
            work.extend(targets.iter().copied());
        }
        if !insn.is_unconditional_goto()
            && !insn.is_return()
            && !insn.is_throw()
            && let Some(next) = insns.get(idx + 1)
        {
            work.push(next.pc);
        }
    }

    if reachable_pre_init
        .iter()
        .any(|pc: &u32| handler_pcs.contains(pc))
    {
        return false;
    }
    !reachable_pre_init.is_empty()
}

fn uses_register_before_init(insn: &DalvikInsn, this_reg: u16) -> bool {
    if insn.is_return() {
        return true;
    }
    let names_this: bool = insn.regs.contains(&this_reg);
    if insn.is_throw() {
        return names_this;
    }
    match insn.op {
        0x01..=0x09
        | 0x1F
        | 0x20
        | 0x21
        | 0x44..=0x51
        | 0x52..=0x6D
        | 0x6E..=0x72
        | 0x74..=0x78 => names_this,
        _ => false,
    }
}

impl Emitter<'_> {
    fn seed_parameter_types(&mut self, parsed: &MethodDescriptor, is_static: bool) {
        let mut cursor: u16 = self.first_param_reg;
        if !is_static {
            self.reg_type.insert(cursor, Slot::Ref);
            cursor = cursor.saturating_add(1);
        }
        for ty in &parsed.params {
            let slot: Slot = Slot::from_java(ty);
            self.reg_type.insert(cursor, slot);
            if let Some(elem) = array_elem_slot_jt(ty) {
                self.reg_array_elem.insert(cursor, elem);
                self.param_array_elem.insert(cursor, elem);
            }
            if let Some(desc) = array_elem_desc_jt(ty) {
                self.array_elem_desc.insert(cursor, desc);
                self.param_array_elem_desc.insert(cursor, desc);
            }
            cursor = cursor.saturating_add(if slot.category_two() { 2 } else { 1 });
        }
    }

    const fn bail(&mut self) {
        self.bailed = true;
    }

    fn push(&mut self, byte: u8) {
        self.code.push(byte);
    }

    fn push_u16(&mut self, value: u16) {
        self.code.extend_from_slice(&value.to_be_bytes());
    }

    fn adjust_stack(&mut self, delta: i32) {
        self.cur_stack = (self.cur_stack + delta).max(0);
        if self.cur_stack > self.max_stack {
            self.max_stack = self.cur_stack;
        }
    }

    fn reg_slot(&self, reg: u16) -> Slot {
        self.reg_type.get(&reg).copied().unwrap_or(Slot::Int)
    }

    fn set_reg(&mut self, reg: u16, slot: Slot) {
        if let Some(prev) = reg.checked_sub(1)
            && self
                .reg_type
                .get(&prev)
                .is_some_and(|s: &Slot| s.category_two())
        {
            self.reg_type.remove(&prev);
            self.poisoned_regs.insert(prev);
        }
        self.reg_type.insert(reg, slot);
        if slot.category_two() {
            let high: u16 = reg.saturating_add(1);
            self.reg_type.remove(&high);
            self.poisoned_regs.insert(high);
        }
    }

    fn analyzer_post_slot(&self, reg: u16) -> Option<Slot> {
        let cfg: &CfgEmit = self.cfg.as_ref()?;
        cfg.pc_post_slot.get(&cfg.cur_pc)?.get(&reg).copied()
    }

    fn entry_holds_null(&self, reg: u16) -> bool {
        self.cfg.as_ref().is_some_and(|c: &CfgEmit| {
            c.pc_entry_null
                .get(&c.cur_pc)
                .is_some_and(|s: &BTreeSet<u16>| s.contains(&reg))
        })
    }

    fn emit_zero_operand(&mut self, slot: Slot) {
        let opcode: u8 = match slot {
            Slot::Int => 0x03,
            Slot::Long => 0x09,
            Slot::Float => 0x0B,
            Slot::Double => 0x0E,
            Slot::Ref => 0x01,
        };
        self.push(opcode);
        self.adjust_stack(slot.width());
    }

    fn apply_post_array_elem(&mut self, pc: u32) {
        let Some(elems): Option<BTreeMap<u16, Slot>> = self
            .cfg
            .as_ref()
            .and_then(|c: &CfgEmit| c.pc_post_array_elem.get(&pc).cloned())
        else {
            return;
        };
        for (reg, elem) in elems {
            self.reg_array_elem.insert(reg, elem);
        }
    }

    fn entry_ref_name(&self, reg: u16) -> Option<String> {
        let cfg: &CfgEmit = self.cfg.as_ref()?;
        cfg.pc_entry_ref.get(&cfg.cur_pc)?.get(&reg).cloned()
    }

    fn emit_ref_param(&mut self, reg: u16, formal: &str) {
        if self.const_zero.contains(&reg) || !matches!(self.reg_slot(reg), Slot::Ref) {
            self.push(0x01);
            self.adjust_stack(1);
            return;
        }
        self.emit_load(reg);
        if !formal.starts_with('L') && !formal.starts_with('[') {
            return;
        }
        let formal_internal: String = internal_of(formal);
        if formal_internal == "java/lang/Object" {
            return;
        }
        let Some(actual): Option<String> = self.entry_ref_name(reg) else {
            return;
        };
        if actual == formal_internal {
            return;
        }
        let idx: u16 = self.cp.class_const(&formal_internal);
        self.push(0xC0);
        self.push_u16(idx);
    }

    fn exit_ref_reg(&self, reg: u16) -> bool {
        self.cfg.as_ref().is_some_and(|c: &CfgEmit| {
            c.pc_exit_ref_regs
                .get(&c.cur_pc)
                .is_some_and(|s: &BTreeSet<u16>| s.contains(&reg))
        })
    }

    fn enter_cfg_instruction(&mut self, insn: &DalvikInsn) {
        let is_leader: bool = self
            .cfg
            .as_ref()
            .is_some_and(|c: &CfgEmit| c.block_leaders.contains(&insn.pc));
        if is_leader {
            self.discard_pending_result();
        }
        let off: usize = self.code.len();
        let Some(cfg): Option<&mut CfgEmit> = self.cfg.as_mut() else {
            return;
        };
        cfg.cur_pc = insn.pc;
        cfg.jvm_offset_of_pc.insert(insn.pc, off);
        let is_handler: bool = cfg.handler_stack.contains_key(&insn.pc);
        if is_leader {
            if let Some(slots) = cfg.block_entry_slots.get(&insn.pc) {
                self.reg_type = slots.clone();
            } else {
                #[cfg(any(test, feature = "lifter-diag"))]
                record_bail_kind("leader-no-entry-slots");
                self.bail();
                return;
            }
            self.poisoned_regs = cfg.frame_types.get(&insn.pc).map_or_else(
                BTreeSet::new,
                |ft: &BTreeMap<u16, crate::dalvik_typestate::RegType>| {
                    ft.iter()
                        .filter(|(_, t): &(&u16, &crate::dalvik_typestate::RegType)| {
                            matches!(t, crate::dalvik_typestate::RegType::Top)
                        })
                        .map(|(&r, _): (&u16, &crate::dalvik_typestate::RegType)| r)
                        .collect()
                },
            );
            let mut entry_elems: BTreeMap<u16, Slot> = self.param_array_elem.clone();
            if let Some(ft) = cfg.frame_types.get(&insn.pc) {
                for (&reg, ty) in ft {
                    match array_elem_from_regtype(ty) {
                        Some(elem) => {
                            entry_elems.insert(reg, elem);
                        }
                        None => {
                            entry_elems.remove(&reg);
                        }
                    }
                }
            }
            self.reg_array_elem = entry_elems;
            let mut entry_descs: BTreeMap<u16, u8> = self.param_array_elem_desc.clone();
            if let Some(ft) = cfg.frame_types.get(&insn.pc) {
                for (&reg, ty) in ft {
                    match array_elem_desc_from_regtype(ty) {
                        Some(desc) => {
                            entry_descs.insert(reg, desc);
                        }
                        None => {
                            entry_descs.remove(&reg);
                        }
                    }
                }
            }
            self.array_elem_desc = entry_descs;
            self.const_zero.clear();
            self.pending_result = None;
            self.cur_stack = 0;
            if is_handler {
                self.cur_stack = 1;
                if self.cur_stack > self.max_stack {
                    self.max_stack = self.cur_stack;
                }
                if insn.op != 0x0D {
                    self.push(0x57);
                    self.adjust_stack(-1);
                }
            }
        }
    }

    fn emit_branch(&mut self, insn: &DalvikInsn) {
        let Some(target_pc): Option<u32> = insn.branch_target_pc() else {
            self.bail();
            return;
        };
        let op: u8 = insn.op;
        if matches!(op, 0x28..=0x2A) {
            self.emit_jump(0xA7, target_pc);
            return;
        }
        if matches!(op, 0x32..=0x37) {
            let (Some(&a), Some(&b)): (Option<&u16>, Option<&u16>) =
                (insn.regs.first(), insn.regs.get(1))
            else {
                self.bail();
                return;
            };
            let a_ref: bool = matches!(self.reg_slot(a), Slot::Ref);
            let b_ref: bool = matches!(self.reg_slot(b), Slot::Ref);
            if a_ref || b_ref {
                if !matches!(op, 0x32 | 0x33) {
                    #[cfg(any(test, feature = "lifter-diag"))]
                    record_bail_kind("ref-ordered-cmp");
                    self.bail();
                    return;
                }
                self.emit_ref_arg(a);
                self.emit_ref_arg(b);
                self.adjust_stack(-2);
                self.emit_jump(if op == 0x32 { 0xA5 } else { 0xA6 }, target_pc);
            } else {
                self.emit_int_operand(a);
                self.emit_int_operand(b);
                self.adjust_stack(-2);
                self.emit_jump(0x9F + (op - 0x32), target_pc);
            }
            return;
        }
        if matches!(op, 0x38..=0x3D) {
            let Some(&a): Option<&u16> = insn.regs.first() else {
                self.bail();
                return;
            };
            let a_ref: bool =
                matches!(self.reg_slot(a), Slot::Ref) && !self.const_zero.contains(&a);
            if a_ref {
                if !matches!(op, 0x38 | 0x39) {
                    #[cfg(any(test, feature = "lifter-diag"))]
                    record_bail_kind("ref-ordered-cmpz");
                    self.bail();
                    return;
                }
                self.emit_load(a);
                self.adjust_stack(-1);
                self.emit_jump(if op == 0x38 { 0xC6 } else { 0xC7 }, target_pc);
            } else {
                self.emit_int_operand(a);
                self.adjust_stack(-1);
                self.emit_jump(0x99 + (op - 0x38), target_pc);
            }
            return;
        }
        self.bail();
    }

    fn emit_jump(&mut self, jvm_op: u8, target_pc: u32) {
        let insn_offset: usize = self.code.len();
        self.push(jvm_op);
        let operand_offset: usize = self.code.len();
        self.push_u16(0);
        if let Some(cfg) = self.cfg.as_mut() {
            cfg.fixups.push(BranchFixup {
                insn_offset,
                operand_offset,
                target_pc,
            });
        }
    }

    fn emit_handler_dispatch_stubs(&mut self, shared: &BTreeSet<u32>) {
        if shared.is_empty() {
            return;
        }
        if self.max_stack < 1 {
            self.max_stack = 1;
        }
        for &hpc in shared {
            let offset_known: bool = self
                .cfg
                .as_ref()
                .is_some_and(|c: &CfgEmit| c.jvm_offset_of_pc.contains_key(&hpc));
            if !offset_known {
                self.bail();
                return;
            }
            let stub_off: usize = self.code.len();
            self.push(0x57);
            self.emit_jump(0xA7, hpc);
            if let Some(cfg) = self.cfg.as_mut() {
                cfg.handler_stub_offset.insert(hpc, stub_off);
            }
        }
    }

    fn emit_switch(&mut self, insn: &DalvikInsn) {
        let Some(&value_reg): Option<&u16> = insn.regs.first() else {
            self.bail();
            return;
        };
        let payload: crate::dalvik::SwitchPayload = match self
            .cfg
            .as_ref()
            .and_then(|c| c.switch_payloads.get(&insn.pc))
        {
            Some(p) => p.clone(),
            None => {
                self.bail();
                return;
            }
        };
        if payload.keys.is_empty() || payload.keys.len() != payload.targets.len() {
            self.bail();
            return;
        }
        let default_pc: u32 = insn.pc.wrapping_add(u32::from(insn.width));
        self.emit_int_operand(value_reg);
        self.adjust_stack(-1);

        let insn_offset: usize = self.code.len();
        let contiguous: bool = is_contiguous(&payload.keys);
        let mut case_operands: Vec<(usize, u32)> = Vec::with_capacity(payload.keys.len());

        if contiguous {
            self.push(0xAA);
            self.pad_to_align(insn_offset);
            let default_operand_offset: usize = self.code.len();
            self.push_u32(0);
            let low: i32 = payload.keys[0];
            let high: i32 = payload.keys[payload.keys.len() - 1];
            self.push_u32(low as u32);
            self.push_u32(high as u32);
            for &target in &payload.targets {
                let off: usize = self.code.len();
                self.push_u32(0);
                case_operands.push((off, target));
            }
            self.record_switch_fixup(
                insn_offset,
                default_operand_offset,
                default_pc,
                case_operands,
            );
        } else {
            self.push(0xAB);
            self.pad_to_align(insn_offset);
            let default_operand_offset: usize = self.code.len();
            self.push_u32(0);
            self.push_u32(payload.keys.len() as u32);
            let mut pairs: Vec<(i32, u32)> = payload
                .keys
                .iter()
                .copied()
                .zip(payload.targets.iter().copied())
                .collect();
            pairs.sort_by_key(|(k, _)| *k);
            for (key, target) in pairs {
                self.push_u32(key as u32);
                let off: usize = self.code.len();
                self.push_u32(0);
                case_operands.push((off, target));
            }
            self.record_switch_fixup(
                insn_offset,
                default_operand_offset,
                default_pc,
                case_operands,
            );
        }
    }

    fn push_u32(&mut self, value: u32) {
        self.code.extend_from_slice(&value.to_be_bytes());
    }

    fn pad_to_align(&mut self, insn_offset: usize) {
        let _ = insn_offset;
        while !self.code.len().is_multiple_of(4) {
            self.push(0);
        }
    }

    fn record_switch_fixup(
        &mut self,
        insn_offset: usize,
        default_operand_offset: usize,
        default_target_pc: u32,
        case_operands: Vec<(usize, u32)>,
    ) {
        if let Some(cfg) = self.cfg.as_mut() {
            cfg.switch_fixups.push(SwitchFixup {
                insn_offset,
                default_operand_offset,
                default_target_pc,
                case_operands,
            });
        }
    }

    fn resolve_branches(&mut self) -> Option<()> {
        let fixups: Vec<(usize, usize, u32)> = self
            .cfg
            .as_ref()?
            .fixups
            .iter()
            .map(|f: &BranchFixup| (f.insn_offset, f.operand_offset, f.target_pc))
            .collect();
        let offsets: BTreeMap<u32, usize> = self.cfg.as_ref()?.jvm_offset_of_pc.clone();
        for (insn_offset, operand_offset, target_pc) in fixups {
            let &target_off: &usize = offsets.get(&target_pc)?;
            let delta: isize = target_off as isize - insn_offset as isize;
            let delta16: i16 = i16::try_from(delta).ok()?;
            let bytes: [u8; 2] = delta16.to_be_bytes();
            *self.code.get_mut(operand_offset)? = bytes[0];
            *self.code.get_mut(operand_offset + 1)? = bytes[1];
        }

        let switch_fixups: Vec<SwitchPatch> = self
            .cfg
            .as_ref()?
            .switch_fixups
            .iter()
            .map(|f: &SwitchFixup| {
                (
                    f.insn_offset,
                    f.default_operand_offset,
                    f.default_target_pc,
                    f.case_operands.clone(),
                )
            })
            .collect();
        for (insn_offset, default_off, default_pc, cases) in switch_fixups {
            self.patch_u32_delta(default_off, insn_offset, default_pc, &offsets)?;
            for (op_off, target_pc) in cases {
                self.patch_u32_delta(op_off, insn_offset, target_pc, &offsets)?;
            }
        }
        Some(())
    }

    fn patch_u32_delta(
        &mut self,
        operand_offset: usize,
        base_offset: usize,
        target_pc: u32,
        offsets: &BTreeMap<u32, usize>,
    ) -> Option<()> {
        let &target_off: &usize = offsets.get(&target_pc)?;
        let delta: isize = target_off as isize - base_offset as isize;
        let delta32: i32 = i32::try_from(delta).ok()?;
        let bytes: [u8; 4] = delta32.to_be_bytes();
        for (k, b) in bytes.iter().enumerate() {
            *self.code.get_mut(operand_offset + k)? = *b;
        }
        Some(())
    }

    fn build_exception_table(&mut self) -> Option<(Vec<u8>, u16)> {
        let cfg: &CfgEmit = self.cfg.as_ref()?;
        if cfg.tries.is_empty() {
            return Some((Vec::new(), 0));
        }
        let offsets: BTreeMap<u32, usize> = cfg.jvm_offset_of_pc.clone();
        let end_jvm: usize = self.code.len();
        let mut entries: Vec<(u16, u16, u16, u16)> = Vec::new();
        for tr in &cfg.tries {
            let start: u16 = u16::try_from(*offsets.get(&tr.start_pc)?).ok()?;
            let end: u16 = match offsets.get(&tr.end_pc) {
                Some(&o) => u16::try_from(o).ok()?,
                None => u16::try_from(end_jvm).ok()?,
            };
            for (ty, hpc) in &tr.handlers {
                let handler_off: usize = match cfg.handler_stub_offset.get(hpc) {
                    Some(&stub) => stub,
                    None => *offsets.get(hpc)?,
                };
                let handler: u16 = u16::try_from(handler_off).ok()?;
                let catch_idx: u16 = match ty {
                    Some(_) => self.cp.class_const(&catch_internal(ty.as_deref())),
                    None => 0,
                };
                entries.push((start, end, handler, catch_idx));
            }
        }
        let mut out: Vec<u8> = Vec::with_capacity(entries.len() * 8);
        for (start, end, handler, catch) in &entries {
            out.extend_from_slice(&start.to_be_bytes());
            out.extend_from_slice(&end.to_be_bytes());
            out.extend_from_slice(&handler.to_be_bytes());
            out.extend_from_slice(&catch.to_be_bytes());
        }
        Some((out, u16::try_from(entries.len()).ok()?))
    }

    fn build_stack_map_table(
        &mut self,
        first_param_reg: u16,
        param_local_slots: u16,
    ) -> Option<Vec<u8>> {
        let cfg: &CfgEmit = self.cfg.as_ref()?;
        let registers_size: u16 = self.registers_size;
        let virtual_local: BTreeMap<u16, u16> = self.virtual_local.clone();
        let to_local = |reg: u16| -> u16 {
            if let Some(&local) = virtual_local.get(&reg) {
                local
            } else if reg >= first_param_reg {
                reg - first_param_reg
            } else {
                param_local_slots.saturating_add(reg)
            }
        };

        let mut branch_target_pcs: BTreeSet<u32> = cfg
            .fixups
            .iter()
            .map(|f: &BranchFixup| f.target_pc)
            .collect();
        for sf in &cfg.switch_fixups {
            branch_target_pcs.insert(sf.default_target_pc);
            for (_off, target_pc) in &sf.case_operands {
                branch_target_pcs.insert(*target_pc);
            }
        }
        for &hpc in cfg.handler_stack.keys() {
            branch_target_pcs.insert(hpc);
        }
        let handler_stack: BTreeMap<u32, String> = cfg.handler_stack.clone();
        let frame_locals = |regs: &BTreeMap<u16, crate::dalvik_typestate::RegType>|
         -> Vec<crate::dalvik_typestate::RegType> {
            let mut by_slot: BTreeMap<u16, crate::dalvik_typestate::RegType> = BTreeMap::new();
            for (&reg, ty) in regs {
                if reg >= registers_size && !virtual_local.contains_key(&reg) {
                    continue;
                }
                if matches!(ty, crate::dalvik_typestate::RegType::Top) {
                    continue;
                }
                by_slot.insert(to_local(reg), ty.clone());
            }
            let max_slot: u16 = by_slot
                .keys()
                .copied()
                .max()
                .unwrap_or(0)
                .max(param_local_slots.saturating_sub(1));
            let mut locals: Vec<crate::dalvik_typestate::RegType> = Vec::new();
            let mut slot: u16 = 0;
            while slot <= max_slot {
                let ty: crate::dalvik_typestate::RegType = by_slot
                    .get(&slot)
                    .cloned()
                    .unwrap_or(crate::dalvik_typestate::RegType::Top);
                let wide: bool = ty.is_wide();
                locals.push(ty);
                slot += if wide { 2 } else { 1 };
            }
            locals
        };
        let mut frames: Vec<StackMapFrame> = Vec::new();
        for (&pc, regs) in &cfg.frame_types {
            if !branch_target_pcs.contains(&pc) {
                continue;
            }
            let &offset: &usize = cfg.jvm_offset_of_pc.get(&pc)?;
            frames.push((offset, frame_locals(regs), handler_stack.get(&pc).cloned()));
        }
        let stub_exc_types: BTreeMap<u32, String> = handler_stack_types(&cfg.tries);
        for (&hpc, &stub_off) in &cfg.handler_stub_offset {
            let regs: &BTreeMap<u16, crate::dalvik_typestate::RegType> =
                cfg.frame_types.get(&hpc)?;
            frames.push((
                stub_off,
                frame_locals(regs),
                stub_exc_types.get(&hpc).cloned(),
            ));
        }
        frames.sort_by_key(|(off, _, _)| *off);
        let frames: Vec<StackMapFrame> = dedup_frames_by_offset(frames)?;
        if frames.is_empty() {
            return Some(Vec::new());
        }
        let jvm_off: BTreeMap<u32, usize> = cfg.jvm_offset_of_pc.clone();

        let Ok(frame_count): Result<u16, _> = u16::try_from(frames.len()) else {
            #[cfg(any(test, feature = "lifter-diag"))]
            record_bail_kind("stackmap-frame-count-limit");
            return None;
        };
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&frame_count.to_be_bytes());
        let mut prev: Option<usize> = None;
        for (offset, locals, stack) in &frames {
            let delta: usize = match prev {
                None => *offset,
                Some(p) => offset.checked_sub(p)?.checked_sub(1)?,
            };
            body.push(255);
            body.extend_from_slice(&u16::try_from(delta).ok()?.to_be_bytes());
            let Ok(local_count): Result<u16, _> = u16::try_from(locals.len()) else {
                #[cfg(any(test, feature = "lifter-diag"))]
                record_bail_kind("stackmap-local-count-limit");
                return None;
            };
            body.extend_from_slice(&local_count.to_be_bytes());
            for ty in locals {
                self.append_verification_type(&mut body, ty, &jvm_off)?;
            }
            match stack {
                Some(throwable) => {
                    body.extend_from_slice(&1u16.to_be_bytes());
                    let ty: crate::dalvik_typestate::RegType =
                        crate::dalvik_typestate::RegType::Ref(throwable.clone());
                    self.append_verification_type(&mut body, &ty, &jvm_off)?;
                }
                None => body.extend_from_slice(&0u16.to_be_bytes()),
            }
            prev = Some(*offset);
        }

        let name_idx: u16 = self.cp.utf8("StackMapTable");
        let mut attr: Vec<u8> = Vec::with_capacity(body.len() + 6);
        attr.extend_from_slice(&name_idx.to_be_bytes());
        attr.extend_from_slice(&(body.len() as u32).to_be_bytes());
        attr.extend_from_slice(&body);
        Some(attr)
    }

    fn append_verification_type(
        &mut self,
        out: &mut Vec<u8>,
        ty: &crate::dalvik_typestate::RegType,
        jvm_off: &BTreeMap<u32, usize>,
    ) -> Option<()> {
        use crate::dalvik_typestate::RegType;
        match ty {
            RegType::Top => out.push(0),
            RegType::Int | RegType::ZeroOrNull => out.push(1),
            RegType::NullRef => out.push(5),
            RegType::Float => out.push(2),
            RegType::Double => out.push(3),
            RegType::Long => out.push(4),
            RegType::UninitializedThis => out.push(6),
            RegType::Uninitialized(new_pc) => {
                let &offset: &usize = jvm_off.get(new_pc)?;
                let offset16: u16 = u16::try_from(offset).ok()?;
                out.push(8);
                out.extend_from_slice(&offset16.to_be_bytes());
            }
            RegType::Ref(name) => {
                let idx: u16 = self.cp.class_const(name);
                out.push(7);
                out.extend_from_slice(&idx.to_be_bytes());
            }
        }
        Some(())
    }

    fn local_index(&mut self, reg: u16) -> Option<u16> {
        if let Some(&local) = self.virtual_local.get(&reg) {
            if local >= self.max_locals {
                #[cfg(any(test, feature = "lifter-diag"))]
                record_bail_kind("local-slot-oob");
                self.bail();
                return None;
            }
            return Some(local);
        }
        if reg >= self.registers_size {
            #[cfg(any(test, feature = "lifter-diag"))]
            record_bail_kind("local-reg-oob");
            self.bail();
            return None;
        }
        let local: u16 = if reg >= self.first_param_reg {
            reg - self.first_param_reg
        } else {
            self.param_local_slots.saturating_add(reg)
        };
        if local >= self.max_locals {
            #[cfg(any(test, feature = "lifter-diag"))]
            record_bail_kind("local-slot-oob");
            self.bail();
            return None;
        }
        Some(local)
    }

    fn emit_load(&mut self, reg: u16) {
        if self.poisoned_regs.contains(&reg) {
            #[cfg(any(test, feature = "lifter-diag"))]
            record_bail_kind("poisoned-load");
            self.bail();
            return;
        }
        if self.pending_new.contains_key(&reg) {
            #[cfg(any(test, feature = "lifter-diag"))]
            record_bail_kind("pending-new-load");
            self.bail();
            return;
        }
        if self.eager_new_active.contains_key(&reg) {
            #[cfg(any(test, feature = "lifter-diag"))]
            record_bail_kind("eager-new-load");
            self.bail();
            return;
        }
        if self.materialize_active.contains_key(&reg) {
            #[cfg(any(test, feature = "lifter-diag"))]
            record_bail_kind("materialize-new-load");
            self.bail();
            return;
        }
        let slot: Slot = self.reg_slot(reg);
        if !matches!(slot, Slot::Ref) && self.entry_holds_null(reg) {
            self.emit_zero_operand(slot);
            return;
        }
        let Some(index): Option<u16> = self.local_index(reg) else {
            return;
        };
        let (fast, family): (u8, u8) = match slot {
            Slot::Int => (0x1A, 0x15),
            Slot::Long => (0x1E, 0x16),
            Slot::Float => (0x22, 0x17),
            Slot::Double => (0x26, 0x18),
            Slot::Ref => (0x2A, 0x19),
        };
        self.emit_local_op(index, fast, family);
        self.adjust_stack(slot.width());
    }

    fn emit_ref_arg(&mut self, reg: u16) {
        if self.const_zero.contains(&reg) || !matches!(self.reg_slot(reg), Slot::Ref) {
            self.push(0x01);
            self.adjust_stack(1);
        } else {
            self.emit_load(reg);
        }
    }

    fn emit_int_operand(&mut self, reg: u16) {
        if matches!(self.reg_slot(reg), Slot::Ref) && self.entry_holds_null(reg) {
            self.emit_zero_operand(Slot::Int);
            return;
        }
        self.emit_load(reg);
    }

    fn emit_value_operand(&mut self, value: u16, slot: Slot) {
        if matches!(slot, Slot::Ref) {
            self.emit_ref_arg(value);
        } else {
            self.set_reg(value, slot);
            self.emit_load(value);
        }
    }

    fn emit_store(&mut self, reg: u16, slot: Slot) {
        let Some(index): Option<u16> = self.local_index(reg) else {
            return;
        };
        let (fast, family): (u8, u8) = match slot {
            Slot::Int => (0x3B, 0x36),
            Slot::Long => (0x3F, 0x37),
            Slot::Float => (0x43, 0x38),
            Slot::Double => (0x47, 0x39),
            Slot::Ref => (0x4B, 0x3A),
        };
        self.emit_local_op(index, fast, family);
        self.adjust_stack(-slot.width());
        self.set_reg(reg, slot);
        self.const_zero.remove(&reg);
        self.poisoned_regs.remove(&reg);
    }

    fn emit_local_op(&mut self, index: u16, fast_base: u8, slow_family: u8) {
        if index <= 3 {
            self.push(fast_base + index as u8);
        } else if u8::try_from(index).is_ok() {
            self.push(slow_family);
            self.push(index as u8);
        } else {
            self.push(0xC4);
            self.push(slow_family);
            self.push_u16(index);
        }
    }

    fn method_id(&self, index: Option<u32>) -> Option<&MethodId> {
        index.and_then(|i| self.dex.method_ids.get(i as usize))
    }

    fn field_id(&self, index: Option<u32>) -> Option<&FieldId> {
        index.and_then(|i| self.dex.field_ids.get(i as usize))
    }

    fn string_at(&self, index: Option<u32>) -> Option<String> {
        index.and_then(|i| self.dex.strings.get(i as usize).cloned())
    }

    fn type_at(&self, index: Option<u32>) -> Option<String> {
        index.and_then(|i| self.dex.type_names.get(i as usize).cloned())
    }

    #[allow(clippy::too_many_lines)]
    fn translate(&mut self, insn: &DalvikInsn, parsed: &MethodDescriptor) {
        let op: u8 = insn.op;
        if self.cfg.is_some() {
            self.enter_cfg_instruction(insn);
            if self.bailed {
                return;
            }
            if matches!(op, 0x28..=0x2A | 0x32..=0x3D) {
                self.discard_pending_result();
                self.emit_branch(insn);
                return;
            }
            if matches!(op, 0x2B | 0x2C) {
                self.discard_pending_result();
                self.emit_switch(insn);
                return;
            }
        }
        if !matches!(op, 0x0A..=0x0C) {
            self.discard_pending_result();
        }
        let regs: &[u16] = &insn.regs;
        match op {
            0x0D => self.move_exception(regs),
            0x00 | 0x1D | 0x1E => {}
            0x01..=0x09 => self.move_reg(regs),
            0x0A => self.move_result(regs, Slot::Int),
            0x0B => self.move_result(regs, Slot::Long),
            0x0C => self.move_result(regs, Slot::Ref),
            0x0E => self.push(0xB1),
            0x0F..=0x11 => self.return_value(regs, parsed),
            0x12..=0x14 => self.const_int(regs, insn),
            0x15 => self.const_high16_int(regs, insn),
            0x16..=0x18 => self.const_long(regs, insn),
            0x19 => self.const_high16_long(regs, insn),
            0x1A | 0x1B => self.const_string(regs, insn),
            0x1C => self.const_class(regs, insn),
            0x1F => self.check_cast(regs, insn),
            0x20 => self.instance_of(regs, insn),
            0x21 => self.array_length(regs),
            0x22 => self.new_instance(regs, insn),
            0x23 => self.new_array(regs, insn),
            0x24 | 0x25 => self.filled_new_array(insn),
            0x26 => self.fill_array_data(regs, insn),
            0x27 => self.throw(regs),
            0x2D..=0x31 => self.cmp(op, regs),
            0x44..=0x4A => self.array_get(op, regs),
            0x4B..=0x51 => self.array_put(op, regs),
            0x52..=0x58 => self.instance_get(regs, insn),
            0x59..=0x5F => self.instance_put(regs, insn),
            0x60..=0x66 => self.static_get(regs, insn),
            0x67..=0x6D => self.static_put(regs, insn),
            0x6E..=0x72 | 0x74..=0x78 => self.invoke(op, insn),
            0x7B..=0x80 => self.neg(op, regs),
            0x81..=0x8F => self.numeric_cast(op, regs),
            0x90..=0xAF => self.binary_three(op, regs),
            0xB0..=0xCF => self.binary_two_addr(op, regs),
            0xD0..=0xE2 => self.binary_lit(op, regs, insn),
            _ => self.bail(),
        }
    }

    fn move_reg(&mut self, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let src_marker: Option<(String, u32)> = self.materialize_active.get(&src).cloned();
        if let Some(marker) = src_marker {
            self.move_uninitialized_alias(dest, src, marker);
            return;
        }
        let slot: Slot = self.reg_slot(src);
        self.emit_load(src);
        self.emit_store(dest, slot);
        match self.reg_array_elem.get(&src).copied() {
            Some(elem) => {
                self.reg_array_elem.insert(dest, elem);
            }
            None => {
                self.reg_array_elem.remove(&dest);
            }
        }
        match self.array_elem_desc.get(&src).copied() {
            Some(desc) => {
                self.array_elem_desc.insert(dest, desc);
            }
            None => {
                self.array_elem_desc.remove(&dest);
            }
        }
        self.materialize_active.remove(&dest);
    }

    fn move_uninitialized_alias(&mut self, dest: u16, src: u16, marker: (String, u32)) {
        let Some(src_index): Option<u16> = self.local_index(src) else {
            return;
        };
        self.emit_local_op(src_index, 0x2A, 0x19);
        self.adjust_stack(1);
        self.emit_store(dest, Slot::Ref);
        self.materialize_active.insert(dest, marker);
        self.reg_array_elem.remove(&dest);
        self.array_elem_desc.remove(&dest);
    }

    fn move_result(&mut self, regs: &[u16], default: Slot) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let slot: Slot = self.pending_result.take().unwrap_or(default);
        self.emit_store(dest, slot);
    }

    fn move_exception(&mut self, regs: &[u16]) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        self.emit_store(dest, Slot::Ref);
    }

    fn discard_pending_result(&mut self) {
        let Some(slot): Option<Slot> = self.pending_result.take() else {
            return;
        };
        if slot.category_two() {
            self.push(0x58);
        } else {
            self.push(0x57);
        }
        self.adjust_stack(-slot.width());
    }

    fn return_value(&mut self, regs: &[u16], parsed: &MethodDescriptor) {
        let slot: Slot = Slot::from_java(&parsed.returns);
        if let Some(&src) = regs.first() {
            self.emit_value_operand(src, slot);
        }
        let op: u8 = match slot {
            Slot::Int => 0xAC,
            Slot::Long => 0xAD,
            Slot::Float => 0xAE,
            Slot::Double => 0xAF,
            Slot::Ref => 0xB0,
        };
        self.push(op);
        self.adjust_stack(-slot.width());
    }

    fn const_int(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        self.emit_narrow_const(dest, insn.literal.unwrap_or(0) as i32);
    }

    fn const_high16_int(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let value: i32 = (insn.literal.unwrap_or(0) as i32) << 16;
        self.emit_narrow_const(dest, value);
    }

    fn const_long(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        self.emit_wide_const(dest, insn.literal.unwrap_or(0), insn.pc);
    }

    fn const_high16_long(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        self.emit_wide_const(dest, insn.literal.unwrap_or(0) << 48, insn.pc);
    }

    fn emit_narrow_const(&mut self, dest: u16, bits: i32) {
        if matches!(self.const_kind.get(&dest), Some(Slot::Float)) {
            let idx: u16 = self.cp.float_bits(bits as u32);
            self.emit_ldc(idx);
            self.emit_store(dest, Slot::Float);
        } else if bits == 0
            && (matches!(self.analyzer_post_slot(dest), Some(Slot::Ref)) || self.exit_ref_reg(dest))
        {
            self.push(0x01);
            self.adjust_stack(1);
            self.emit_store(dest, Slot::Ref);
            self.const_zero.insert(dest);
        } else {
            self.push_int_const(bits);
            self.emit_store(dest, Slot::Int);
            if bits == 0 {
                self.const_zero.insert(dest);
            }
        }
    }

    fn emit_wide_const(&mut self, dest: u16, bits: i64, pc: u32) {
        if self.wide_double_pcs.contains(&pc) {
            let idx: u16 = self.cp.double_bits(bits as u64);
            self.push(0x14);
            self.push_u16(idx);
            self.adjust_stack(2);
            self.emit_store(dest, Slot::Double);
        } else {
            self.push_long_const(bits);
            self.emit_store(dest, Slot::Long);
        }
    }

    fn const_string(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some(text): Option<String> = self.string_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.string(&text);
        self.emit_ldc(idx);
        self.emit_store(dest, Slot::Ref);
    }

    fn const_class(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.class_const(&internal_of(&ty));
        self.emit_ldc(idx);
        self.emit_store(dest, Slot::Ref);
    }

    fn check_cast(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&reg): Option<&u16> = regs.first() else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.class_const(&internal_of(&ty));
        self.emit_load(reg);
        self.push(0xC0);
        self.push_u16(idx);
        self.emit_store(reg, Slot::Ref);
        self.note_array_elem(reg, &ty);
    }

    fn instance_of(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.class_const(&internal_of(&ty));
        self.emit_load(src);
        self.push(0xC1);
        self.push_u16(idx);
        self.emit_store(dest, Slot::Int);
    }

    fn array_length(&mut self, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        self.emit_load(src);
        self.push(0xBE);
        self.emit_store(dest, Slot::Int);
    }

    fn new_instance(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let owner: String = internal_of(&ty);
        if self.eager_new_pcs.contains(&insn.pc) {
            let class_idx: u16 = self.cp.class_const(&owner);
            self.push(0xBB);
            self.push_u16(class_idx);
            self.adjust_stack(1);
            self.push(0x59);
            self.adjust_stack(1);
            self.eager_new_active.insert(dest, owner);
            return;
        }
        if self.materialize_new_pcs.contains(&insn.pc) {
            let class_idx: u16 = self.cp.class_const(&owner);
            self.push(0xBB);
            self.push_u16(class_idx);
            self.adjust_stack(1);
            self.emit_store(dest, Slot::Ref);
            self.materialize_active.insert(dest, (owner, insn.pc));
            return;
        }
        self.pending_new.insert(dest, owner);
    }

    fn new_array(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&size)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let element: &str = ty.strip_prefix('[').unwrap_or(&ty);
        self.emit_int_operand(size);
        match primitive_atype(element) {
            Some(atype) => {
                self.push(0xBC);
                self.push(atype);
            }
            None => {
                let idx: u16 = self.cp.class_const(&internal_of(element));
                self.push(0xBD);
                self.push_u16(idx);
            }
        }
        self.emit_store(dest, Slot::Ref);
        self.note_array_elem(dest, &ty);
    }

    fn filled_new_array(&mut self, insn: &DalvikInsn) {
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let element: String = ty.strip_prefix('[').unwrap_or(&ty).to_string();
        let count: usize = insn.regs.len();
        if count > i32::MAX as usize {
            self.bail();
            return;
        }
        let elem_slot: Slot = field_slot(&element);
        let store_op: u8 = match element.as_bytes().first() {
            Some(b'L' | b'[') => 0x53,
            Some(b'Z' | b'B') => 0x54,
            Some(b'C') => 0x55,
            Some(b'S') => 0x56,
            Some(b'I') => 0x4F,
            Some(b'J') => 0x50,
            Some(b'F') => 0x51,
            Some(b'D') => 0x52,
            _ => {
                self.bail();
                return;
            }
        };
        self.push_int_const(count as i32);
        match primitive_atype(&element) {
            Some(atype) => {
                self.push(0xBC);
                self.push(atype);
            }
            None => {
                let idx: u16 = self.cp.class_const(&internal_of(&element));
                self.push(0xBD);
                self.push_u16(idx);
            }
        }
        let regs: Vec<u16> = insn.regs.clone();
        for (i, &reg) in regs.iter().enumerate() {
            self.push(0x59);
            self.adjust_stack(1);
            self.push_int_const(i as i32);
            self.set_reg(reg, elem_slot);
            self.emit_load(reg);
            self.push(store_op);
            self.adjust_stack(-2 - elem_slot.width());
        }
        self.pending_result = Some(Slot::Ref);
    }

    fn throw(&mut self, regs: &[u16]) {
        if let Some(&reg) = regs.first() {
            self.set_reg(reg, Slot::Ref);
            self.emit_load(reg);
        }
        self.push(0xBF);
        self.adjust_stack(-1);
    }

    fn cmp(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
            (regs.first(), regs.get(1), regs.get(2))
        else {
            return;
        };
        let (operand, opcode): (Slot, u8) = match op {
            0x2D => (Slot::Float, 0x95),
            0x2E => (Slot::Float, 0x96),
            0x2F => (Slot::Double, 0x97),
            0x30 => (Slot::Double, 0x98),
            0x31 => (Slot::Long, 0x94),
            _ => {
                self.bail();
                return;
            }
        };
        self.set_reg(lhs, operand);
        self.set_reg(rhs, operand);
        self.emit_load(lhs);
        self.emit_load(rhs);
        self.push(opcode);
        self.adjust_stack(-2 * operand.width() + 1);
        self.emit_store(dest, Slot::Int);
    }

    fn array_get(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
            (regs.first(), regs.get(1), regs.get(2))
        else {
            return;
        };
        let elem: Option<Slot> = self.reg_array_elem.get(&array).copied();
        let (opcode, slot): (u8, Slot) = match op {
            0x44 => match elem {
                Some(Slot::Int) => (0x2E, Slot::Int),
                Some(Slot::Float) => (0x30, Slot::Float),
                _ => {
                    self.bail();
                    return;
                }
            },
            0x45 => match elem {
                Some(Slot::Long) => (0x2F, Slot::Long),
                Some(Slot::Double) => (0x31, Slot::Double),
                _ => {
                    self.bail();
                    return;
                }
            },
            0x46 => (0x32, Slot::Ref),
            0x47 | 0x48 => (0x33, Slot::Int),
            0x49 => (0x34, Slot::Int),
            0x4A => (0x35, Slot::Int),
            _ => {
                self.bail();
                return;
            }
        };
        self.set_reg(array, Slot::Ref);
        self.emit_load(array);
        self.emit_int_operand(index);
        self.push(opcode);
        self.adjust_stack(-2 + slot.width());
        self.emit_store(dest, slot);
    }

    fn array_put(&mut self, op: u8, regs: &[u16]) {
        let (Some(&value), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
            (regs.first(), regs.get(1), regs.get(2))
        else {
            return;
        };
        let elem: Option<Slot> = self.reg_array_elem.get(&array).copied();
        let (opcode, slot): (u8, Slot) = match op {
            0x4B => match elem {
                Some(Slot::Int) => (0x4F, Slot::Int),
                Some(Slot::Float) => (0x51, Slot::Float),
                _ => {
                    self.bail();
                    return;
                }
            },
            0x4C => match elem {
                Some(Slot::Long) => (0x50, Slot::Long),
                Some(Slot::Double) => (0x52, Slot::Double),
                _ => {
                    self.bail();
                    return;
                }
            },
            0x4D => (0x53, Slot::Ref),
            0x4E | 0x4F => (0x54, Slot::Int),
            0x50 => (0x55, Slot::Int),
            0x51 => (0x56, Slot::Int),
            _ => {
                self.bail();
                return;
            }
        };
        self.set_reg(array, Slot::Ref);
        self.emit_load(array);
        self.emit_int_operand(index);
        self.emit_value_operand(value, slot);
        self.push(opcode);
        self.adjust_stack(-2 - slot.width());
    }

    fn fill_array_data(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&array): Option<&u16> = regs.first() else {
            return;
        };
        let Some(payload): Option<crate::dalvik::ArrayDataPayload> =
            self.fill_payloads.get(&insn.pc).cloned()
        else {
            self.bail();
            return;
        };
        let width: usize = usize::from(payload.element_width);
        if width == 0 || !payload.data.len().is_multiple_of(width) {
            self.bail();
            return;
        }
        let elem: Option<Slot> = self.reg_array_elem.get(&array).copied();
        let elem_desc: Option<u8> = self.fill_elem_desc(array);
        let (store_op, slot): (u8, Slot) = match width {
            1 if matches!(elem, Some(Slot::Int)) => (0x54, Slot::Int),
            2 => match elem_desc {
                Some(b'C') => (0x55, Slot::Int),
                Some(b'S') => (0x56, Slot::Int),
                _ => {
                    self.bail();
                    return;
                }
            },
            4 => match elem {
                Some(Slot::Int) => (0x4F, Slot::Int),
                Some(Slot::Float) => (0x51, Slot::Float),
                _ => {
                    self.bail();
                    return;
                }
            },
            8 => match elem {
                Some(Slot::Long) => (0x50, Slot::Long),
                Some(Slot::Double) => (0x52, Slot::Double),
                _ => {
                    self.bail();
                    return;
                }
            },
            _ => {
                self.bail();
                return;
            }
        };
        self.set_reg(array, Slot::Ref);
        let count: usize = payload.data.len() / width;
        for i in 0..count {
            let off: usize = i * width;
            let Some(chunk): Option<&[u8]> = payload.data.get(off..off + width) else {
                self.bail();
                return;
            };
            self.emit_load(array);
            if self.bailed {
                return;
            }
            self.push_int_const(i as i32);
            match (width, slot) {
                (1, _) => {
                    let value: i32 = i32::from(chunk[0] as i8);
                    self.push_int_const(value);
                }
                (2, _) => {
                    let raw: u16 = u16::from_le_bytes([chunk[0], chunk[1]]);
                    let value: i32 = if store_op == 0x55 {
                        i32::from(raw)
                    } else {
                        i32::from(raw as i16)
                    };
                    self.push_int_const(value);
                }
                (4, Slot::Int) => {
                    let value: i32 = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    self.push_int_const(value);
                }
                (4, Slot::Float) => {
                    let bits: u32 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let idx: u16 = self.cp.float_bits(bits);
                    self.emit_ldc(idx);
                }
                (8, Slot::Long) => {
                    let value: i64 = i64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ]);
                    self.push_long_const(value);
                }
                (8, Slot::Double) => {
                    let bits: u64 = u64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ]);
                    let idx: u16 = self.cp.double_bits(bits);
                    self.push(0x14);
                    self.push_u16(idx);
                    self.adjust_stack(2);
                }
                _ => {
                    self.bail();
                    return;
                }
            }
            self.push(store_op);
            self.adjust_stack(-2 - slot.width());
        }
    }

    fn note_array_elem(&mut self, reg: u16, array_descriptor: &str) {
        match array_descriptor.strip_prefix('[').and_then(array_elem_slot) {
            Some(elem) => {
                self.reg_array_elem.insert(reg, elem);
            }
            None => {
                self.reg_array_elem.remove(&reg);
            }
        }
        match array_descriptor
            .strip_prefix('[')
            .and_then(|s: &str| s.bytes().next())
            .filter(|b: &u8| is_primitive_elem(*b))
        {
            Some(desc) => {
                self.array_elem_desc.insert(reg, desc);
            }
            None => {
                self.array_elem_desc.remove(&reg);
            }
        }
    }

    fn fill_elem_desc(&self, array: u16) -> Option<u8> {
        if let Some(&desc) = self.array_elem_desc.get(&array) {
            return Some(desc);
        }
        let name: String = self.entry_ref_name(array)?;
        name.strip_prefix('[')
            .and_then(|s: &str| s.bytes().next())
            .filter(|b: &u8| is_primitive_elem(*b))
    }

    fn instance_get(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.set_reg(obj, Slot::Ref);
        self.emit_load(obj);
        self.push(0xB4);
        self.push_u16(idx);
        self.adjust_stack(-1 + slot.width());
        self.emit_store(dest, slot);
        self.note_array_elem(dest, &ftype);
    }

    fn instance_put(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&value), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.set_reg(obj, Slot::Ref);
        self.emit_load(obj);
        self.emit_value_operand(value, slot);
        self.push(0xB5);
        self.push_u16(idx);
        self.adjust_stack(-1 - slot.width());
    }

    fn static_get(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.push(0xB2);
        self.push_u16(idx);
        self.adjust_stack(slot.width());
        self.emit_store(dest, slot);
        self.note_array_elem(dest, &ftype);
    }

    fn static_put(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&value): Option<&u16> = regs.first() else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.emit_value_operand(value, slot);
        self.push(0xB3);
        self.push_u16(idx);
        self.adjust_stack(-slot.width());
    }

    fn field_parts(&mut self, index: Option<u32>) -> Option<(String, String, String)> {
        match self.field_id(index) {
            Some(field) => Some((
                internal_of(&field.class),
                field.name.clone(),
                field.type_name.clone(),
            )),
            None => {
                self.bail();
                None
            }
        }
    }

    fn invoke(&mut self, op: u8, insn: &DalvikInsn) {
        let parts: Option<(String, String, String, Vec<String>)> =
            self.method_id(insn.index).map(|m: &MethodId| {
                (
                    internal_of(&m.class),
                    m.name.clone(),
                    m.proto.return_type.clone(),
                    m.proto.parameters.clone(),
                )
            });
        let Some((owner, name, return_type, param_types)): Option<(
            String,
            String,
            String,
            Vec<String>,
        )> = parts
        else {
            self.bail();
            return;
        };
        let descriptor: String = build_descriptor(&param_types, &return_type);
        let is_static: bool = matches!(op, 0x71 | 0x77);
        let is_interface: bool = matches!(op, 0x72 | 0x78);
        let is_special: bool = matches!(op, 0x70 | 0x76);

        if is_special
            && name == "<init>"
            && let Some(&recv) = insn.regs.first()
            && self
                .eager_new_active
                .get(&recv)
                .is_some_and(|t: &String| *t == owner)
        {
            self.emit_constructor_eager(recv, &owner, &name, &descriptor, &param_types, &insn.regs);
            return;
        }

        if is_special
            && name == "<init>"
            && let Some(&recv) = insn.regs.first()
            && self
                .materialize_active
                .get(&recv)
                .is_some_and(|(t, _): &(String, u32)| *t == owner)
        {
            self.emit_constructor_materialized(
                recv,
                &owner,
                &name,
                &descriptor,
                &param_types,
                &insn.regs,
            );
            return;
        }

        if is_special
            && name == "<init>"
            && let Some(&recv) = insn.regs.first()
            && self
                .pending_new
                .get(&recv)
                .is_some_and(|t: &String| *t == owner)
        {
            self.emit_constructor(recv, &owner, &name, &descriptor, &param_types, &insn.regs);
            return;
        }

        let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
        let mut consumed: i32 = 0;
        if !is_static && let Some(&recv) = reg_iter.next() {
            self.set_reg(recv, Slot::Ref);
            self.emit_load(recv);
            consumed += 1;
        }
        for param in &param_types {
            let slot: Slot = field_slot(param);
            if let Some(&reg) = reg_iter.next() {
                if matches!(slot, Slot::Ref) {
                    self.emit_ref_param(reg, param);
                } else {
                    self.set_reg(reg, slot);
                    self.emit_load(reg);
                }
                consumed += slot.width();
            }
            if slot.category_two() {
                let _ = reg_iter.next();
            }
        }

        let idx: u16 = if is_interface {
            self.cp.interface_methodref(&owner, &name, &descriptor)
        } else {
            self.cp.methodref(&owner, &name, &descriptor)
        };
        let invoke_op: u8 = match op {
            0x71 | 0x77 => 0xB8,
            0x72 | 0x78 => 0xB9,
            _ if is_special => 0xB7,
            _ => 0xB6,
        };
        self.push(invoke_op);
        self.push_u16(idx);
        if invoke_op == 0xB9 {
            let count: u8 = consumed.clamp(1, 255) as u8;
            self.push(count);
            self.push(0);
        }
        self.adjust_stack(-consumed);
        if return_type == "V" {
            self.pending_result = None;
        } else {
            let slot: Slot = field_slot(&return_type);
            self.adjust_stack(slot.width());
            self.pending_result = Some(slot);
        }
    }

    fn emit_constructor(
        &mut self,
        recv: u16,
        owner: &str,
        name: &str,
        descriptor: &str,
        param_types: &[String],
        regs: &[u16],
    ) {
        self.pending_new.remove(&recv);
        let class_idx: u16 = self.cp.class_const(owner);
        self.push(0xBB);
        self.push_u16(class_idx);
        self.adjust_stack(1);
        self.push(0x59);
        self.adjust_stack(1);
        let mut reg_iter: std::slice::Iter<'_, u16> = regs.iter();
        let _ = reg_iter.next();
        let mut consumed: i32 = 0;
        for param in param_types {
            let slot: Slot = field_slot(param);
            if let Some(&reg) = reg_iter.next() {
                if matches!(slot, Slot::Ref) {
                    self.emit_ref_param(reg, param);
                } else {
                    self.set_reg(reg, slot);
                    self.emit_load(reg);
                }
                consumed += slot.width();
            }
            if slot.category_two() {
                let _ = reg_iter.next();
            }
        }
        let method_idx: u16 = self.cp.methodref(owner, name, descriptor);
        self.push(0xB7);
        self.push_u16(method_idx);
        self.adjust_stack(-consumed - 1);
        self.emit_store(recv, Slot::Ref);
        self.pending_result = None;
    }

    fn emit_constructor_materialized(
        &mut self,
        recv: u16,
        owner: &str,
        name: &str,
        descriptor: &str,
        param_types: &[String],
        regs: &[u16],
    ) {
        let aliases: Vec<u16> = match self
            .materialize_active
            .get(&recv)
            .map(|(_, pc): &(String, u32)| *pc)
        {
            Some(new_pc) => self
                .materialize_active
                .iter()
                .filter_map(|(&reg, (_, pc)): (&u16, &(String, u32))| {
                    (*pc == new_pc).then_some(reg)
                })
                .collect(),
            None => vec![recv],
        };
        for &reg in &aliases {
            self.materialize_active.remove(&reg);
        }
        let Some(index): Option<u16> = self.local_index(recv) else {
            return;
        };
        self.emit_local_op(index, 0x2A, 0x19);
        self.adjust_stack(1);
        let mut reg_iter: std::slice::Iter<'_, u16> = regs.iter();
        let _ = reg_iter.next();
        let mut consumed: i32 = 0;
        for param in param_types {
            let slot: Slot = field_slot(param);
            if let Some(&reg) = reg_iter.next() {
                if matches!(slot, Slot::Ref) {
                    self.emit_ref_param(reg, param);
                } else {
                    self.set_reg(reg, slot);
                    self.emit_load(reg);
                }
                consumed += slot.width();
            }
            if slot.category_two() {
                let _ = reg_iter.next();
            }
        }
        let method_idx: u16 = self.cp.methodref(owner, name, descriptor);
        self.push(0xB7);
        self.push_u16(method_idx);
        self.adjust_stack(-consumed - 1);
        for &reg in &aliases {
            self.set_reg(reg, Slot::Ref);
        }
        self.pending_result = None;
    }

    fn emit_constructor_eager(
        &mut self,
        recv: u16,
        owner: &str,
        name: &str,
        descriptor: &str,
        param_types: &[String],
        regs: &[u16],
    ) {
        self.eager_new_active.remove(&recv);
        let mut reg_iter: std::slice::Iter<'_, u16> = regs.iter();
        let _ = reg_iter.next();
        let mut consumed: i32 = 0;
        for param in param_types {
            let slot: Slot = field_slot(param);
            if let Some(&reg) = reg_iter.next() {
                if matches!(slot, Slot::Ref) {
                    self.emit_ref_param(reg, param);
                } else {
                    self.set_reg(reg, slot);
                    self.emit_load(reg);
                }
                consumed += slot.width();
            }
            if slot.category_two() {
                let _ = reg_iter.next();
            }
        }
        let method_idx: u16 = self.cp.methodref(owner, name, descriptor);
        self.push(0xB7);
        self.push_u16(method_idx);
        self.adjust_stack(-consumed - 1);
        self.emit_store(recv, Slot::Ref);
        self.pending_result = None;
    }

    fn neg(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        match op {
            0x7C => {
                self.set_reg(src, Slot::Int);
                self.emit_load(src);
                self.push_int_const(-1);
                self.push(0x82);
                self.adjust_stack(-1);
                self.emit_store(dest, Slot::Int);
            }
            0x7E => {
                self.set_reg(src, Slot::Long);
                self.emit_load(src);
                self.push_long_const(-1);
                self.push(0x83);
                self.adjust_stack(-2);
                self.emit_store(dest, Slot::Long);
            }
            _ => {
                let (slot, opcode): (Slot, u8) = match op {
                    0x7B => (Slot::Int, 0x74),
                    0x7D => (Slot::Long, 0x75),
                    0x7F => (Slot::Float, 0x76),
                    0x80 => (Slot::Double, 0x77),
                    _ => (Slot::Int, 0x74),
                };
                self.set_reg(src, slot);
                self.emit_load(src);
                self.push(opcode);
                self.emit_store(dest, slot);
            }
        }
    }

    fn numeric_cast(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let (opcode, from, to): (u8, Slot, Slot) = match op {
            0x81 => (0x85, Slot::Int, Slot::Long),
            0x82 => (0x86, Slot::Int, Slot::Float),
            0x83 => (0x87, Slot::Int, Slot::Double),
            0x84 => (0x88, Slot::Long, Slot::Int),
            0x85 => (0x89, Slot::Long, Slot::Float),
            0x86 => (0x8A, Slot::Long, Slot::Double),
            0x87 => (0x8B, Slot::Float, Slot::Int),
            0x88 => (0x8C, Slot::Float, Slot::Long),
            0x89 => (0x8D, Slot::Float, Slot::Double),
            0x8A => (0x8E, Slot::Double, Slot::Int),
            0x8B => (0x8F, Slot::Double, Slot::Long),
            0x8C => (0x90, Slot::Double, Slot::Float),
            0x8D => (0x91, Slot::Int, Slot::Int),
            0x8E => (0x92, Slot::Int, Slot::Int),
            0x8F => (0x93, Slot::Int, Slot::Int),
            _ => (0x88, Slot::Int, Slot::Int),
        };
        self.set_reg(src, from);
        self.emit_load(src);
        self.push(opcode);
        self.adjust_stack(to.width() - from.width());
        self.emit_store(dest, to);
    }

    fn binary_three(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
            (regs.first(), regs.get(1), regs.get(2))
        else {
            return;
        };
        let (opcode, slot): (u8, Slot) = arith_three(op);
        let rhs_slot: Slot = if is_shift(op) { Slot::Int } else { slot };
        self.set_reg(lhs, slot);
        self.set_reg(rhs, rhs_slot);
        self.emit_load(lhs);
        self.emit_load(rhs);
        self.push(opcode);
        self.adjust_stack(-rhs_slot.width());
        self.emit_store(dest, slot);
    }

    fn binary_two_addr(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&rhs)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let (opcode, slot): (u8, Slot) = arith_three(op - 0x20);
        let rhs_slot: Slot = if is_shift(op - 0x20) { Slot::Int } else { slot };
        self.set_reg(dest, slot);
        self.set_reg(rhs, rhs_slot);
        self.emit_load(dest);
        self.emit_load(rhs);
        self.push(opcode);
        self.adjust_stack(-rhs_slot.width());
        self.emit_store(dest, slot);
    }

    fn binary_lit(&mut self, op: u8, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let literal: i32 = insn.literal.unwrap_or(0) as i32;
        if matches!(op, 0xD0 | 0xD8)
            && dest == src
            && !self.iinc_suppressed.contains(&insn.pc)
            && self.try_emit_iinc(dest, literal)
        {
            return;
        }
        if matches!(op, 0xD0 | 0xD8)
            && literal < 0
            && let Some(negated) = literal.checked_neg()
        {
            let negated: i32 = negated;
            self.set_reg(src, Slot::Int);
            self.emit_load(src);
            self.push_int_const(negated);
            self.push(0x64);
            self.adjust_stack(-1);
            self.emit_store(dest, Slot::Int);
            return;
        }
        let reverse: bool = matches!(op, 0xD1 | 0xD9);
        let opcode: u8 = arith_lit_op(op);
        self.set_reg(src, Slot::Int);
        if reverse {
            self.push_int_const(literal);
            self.emit_load(src);
        } else {
            self.emit_load(src);
            self.push_int_const(literal);
        }
        self.push(opcode);
        self.adjust_stack(-1);
        self.emit_store(dest, Slot::Int);
    }

    fn try_emit_iinc(&mut self, reg: u16, delta: i32) -> bool {
        if !matches!(self.reg_slot(reg), Slot::Int) {
            return false;
        }
        let Some(index): Option<u16> = self.local_index(reg) else {
            return false;
        };
        match (u8::try_from(index), i8::try_from(delta)) {
            (Ok(idx), Ok(c)) => {
                self.push(0x84);
                self.push(idx);
                self.push(c as u8);
            }
            _ => {
                let Ok(c): Result<i16, _> = i16::try_from(delta) else {
                    return false;
                };
                self.push(0xC4);
                self.push(0x84);
                self.push_u16(index);
                self.push_u16(c as u16);
            }
        }
        self.set_reg(reg, Slot::Int);
        self.const_zero.remove(&reg);
        true
    }

    fn push_int_const(&mut self, value: i32) {
        match value {
            -1..=5 => {
                self.push((0x03 + value) as u8);
                self.adjust_stack(1);
            }
            -128..=127 => {
                self.push(0x10);
                self.push(value as u8);
                self.adjust_stack(1);
            }
            -32768..=32767 => {
                self.push(0x11);
                self.push_u16(value as u16);
                self.adjust_stack(1);
            }
            _ => {
                let idx: u16 = self.cp.integer(value);
                self.emit_ldc(idx);
            }
        }
    }

    fn push_long_const(&mut self, value: i64) {
        if value == 0 {
            self.push(0x09);
        } else if value == 1 {
            self.push(0x0A);
        } else {
            let idx: u16 = self.cp.long(value);
            self.push(0x14);
            self.push_u16(idx);
        }
        self.adjust_stack(2);
    }

    fn emit_ldc(&mut self, idx: u16) {
        if u8::try_from(idx).is_ok() {
            self.push(0x12);
            self.push(idx as u8);
        } else {
            self.push(0x13);
            self.push_u16(idx);
        }
        self.adjust_stack(1);
    }
}

const fn is_shift(op: u8) -> bool {
    matches!(op, 0x98 | 0x99 | 0x9A | 0xA3 | 0xA4 | 0xA5)
}

#[cfg(any(test, feature = "lifter-diag"))]
fn is_synthetic_class(descriptor: &str) -> bool {
    let inner: &str = descriptor.trim_start_matches('L').trim_end_matches(';');
    inner
        .rsplit('$')
        .next()
        .is_some_and(|seg: &str| !seg.is_empty() && seg.bytes().all(|b: u8| b.is_ascii_digit()))
}

pub(crate) fn const_wide_double_and_float_regs(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
) -> (BTreeSet<u16>, BTreeSet<u16>) {
    let kinds: BTreeMap<u16, Slot> = infer_const_kinds(dex, insns, parsed);
    let mut doubles: BTreeSet<u16> = BTreeSet::new();
    let mut floats: BTreeSet<u16> = BTreeSet::new();
    for (&reg, slot) in &kinds {
        match slot {
            Slot::Double => {
                doubles.insert(reg);
            }
            Slot::Float => {
                floats.insert(reg);
            }
            _ => {}
        }
    }
    (doubles, floats)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WideUse {
    Double,
    Long,
    Redefined,
    None,
}

fn wide_use_kind(dex: &DexFile, insn: &DalvikInsn, parsed: &MethodDescriptor, reg: u16) -> WideUse {
    let op: u8 = insn.op;
    let r: &[u16] = &insn.regs;
    let reads_skip1 = |kind: WideUse| -> WideUse {
        if r.iter().skip(1).any(|&x: &u16| x == reg) {
            kind
        } else {
            WideUse::None
        }
    };
    let reads_two_addr = |kind: WideUse| -> WideUse {
        if r.first() == Some(&reg) || r.get(1) == Some(&reg) {
            kind
        } else {
            WideUse::None
        }
    };
    match op {
        0x16..=0x19 => {
            if r.first() == Some(&reg) {
                WideUse::Redefined
            } else {
                WideUse::None
            }
        }
        0x04..=0x06 => {
            if r.first() == Some(&reg) {
                WideUse::Redefined
            } else {
                WideUse::None
            }
        }
        0x31 => reads_skip1(WideUse::Long),
        0x2F | 0x30 => reads_skip1(WideUse::Double),
        0x9B..=0xA5 => reads_skip1(WideUse::Long),
        0xAB..=0xAF => reads_skip1(WideUse::Double),
        0xBB..=0xC5 => reads_two_addr(WideUse::Long),
        0xCB..=0xCF => reads_two_addr(WideUse::Double),
        0x10 => {
            if r.first() == Some(&reg) {
                match Slot::from_java(&parsed.returns) {
                    Slot::Double => WideUse::Double,
                    _ => WideUse::Long,
                }
            } else {
                WideUse::None
            }
        }
        0x5A | 0x68 => wide_field_use(dex, insn, reg),
        0x6E..=0x72 | 0x74..=0x78 => wide_invoke_use(dex, insn, reg),
        _ => {
            if r.contains(&reg) && defines_register(insn) && r.first() == Some(&reg) {
                WideUse::Redefined
            } else {
                WideUse::None
            }
        }
    }
}

fn wide_field_use(dex: &DexFile, insn: &DalvikInsn, reg: u16) -> WideUse {
    if insn.regs.first() != Some(&reg) {
        return WideUse::None;
    }
    let slot: Slot = insn
        .index
        .and_then(|i| dex.field_ids.get(i as usize))
        .map_or(Slot::Long, |f: &FieldId| field_slot(&f.type_name));
    match slot {
        Slot::Double => WideUse::Double,
        _ => WideUse::Long,
    }
}

fn wide_invoke_use(dex: &DexFile, insn: &DalvikInsn, reg: u16) -> WideUse {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| dex.method_ids.get(i as usize))
    else {
        return WideUse::None;
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static {
        let _ = reg_iter.next();
    }
    for param in &method.proto.parameters {
        let slot: Slot = field_slot(param);
        if let Some(&used) = reg_iter.next()
            && used == reg
        {
            return match slot {
                Slot::Double => WideUse::Double,
                Slot::Long => WideUse::Long,
                _ => WideUse::None,
            };
        }
        if slot.category_two() {
            let _ = reg_iter.next();
        }
    }
    WideUse::None
}

fn wide_const_reaches_double_use(
    dex: &DexFile,
    insns: &[DalvikInsn],
    pc_to_idx: &BTreeMap<u32, usize>,
    parsed: &MethodDescriptor,
    reg: u16,
    start: usize,
) -> bool {
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut work: Vec<usize> = vec![start + 1];
    while let Some(idx) = work.pop() {
        if !visited.insert(idx) {
            continue;
        }
        let Some(insn): Option<&DalvikInsn> = insns.get(idx) else {
            continue;
        };
        match wide_use_kind(dex, insn, parsed, reg) {
            WideUse::Double => return true,
            WideUse::Long | WideUse::Redefined => continue,
            WideUse::None => {}
        }
        if insn.is_switch() {
            continue;
        }
        if let Some(t) = insn.branch_target_pc()
            && let Some(&j) = pc_to_idx.get(&t)
        {
            work.push(j);
        }
        if !insn.is_unconditional_goto()
            && !insn.is_return()
            && !insn.is_throw()
            && insns.get(idx + 1).is_some()
        {
            work.push(idx + 1);
        }
    }
    false
}

pub(crate) fn wide_const_double_pcs(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
) -> BTreeSet<u32> {
    let pc_to_idx: BTreeMap<u32, usize> =
        insns.iter().enumerate().map(|(i, n)| (n.pc, i)).collect();
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for (idx, insn) in insns.iter().enumerate() {
        if !matches!(insn.op, 0x16..=0x19) {
            continue;
        }
        let Some(&dest): Option<&u16> = insn.regs.first() else {
            continue;
        };
        if wide_const_reaches_double_use(dex, insns, &pc_to_idx, parsed, dest, idx) {
            out.insert(insn.pc);
        }
    }
    out
}

fn infer_const_kinds(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
) -> BTreeMap<u16, Slot> {
    let mut const_defs: BTreeSet<u16> = BTreeSet::new();
    let mut kinds: BTreeMap<u16, Slot> = BTreeMap::new();
    let record = |reg: u16, slot: Slot, defs: &BTreeSet<u16>, kinds: &mut BTreeMap<u16, Slot>| {
        if defs.contains(&reg) && matches!(slot, Slot::Float | Slot::Double) {
            kinds.entry(reg).or_insert(slot);
        }
    };
    for insn in insns {
        let op: u8 = insn.op;
        let regs: &[u16] = &insn.regs;
        match op {
            0x12..=0x15 => {
                if let Some(&d) = regs.first() {
                    const_defs.insert(d);
                }
            }
            0x16..=0x19 => {
                if let Some(&d) = regs.first() {
                    const_defs.insert(d);
                }
            }
            0xA6..=0xAA => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Float, &const_defs, &mut kinds);
                }
            }
            0xAB..=0xAF => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Double, &const_defs, &mut kinds);
                }
            }
            0xC6..=0xCA => {
                if let Some(&r) = regs.get(1) {
                    record(r, Slot::Float, &const_defs, &mut kinds);
                }
            }
            0xCB..=0xCF => {
                if let Some(&r) = regs.get(1) {
                    record(r, Slot::Double, &const_defs, &mut kinds);
                }
            }
            0x2D | 0x2E => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Float, &const_defs, &mut kinds);
                }
            }
            0x2F | 0x30 => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Double, &const_defs, &mut kinds);
                }
            }
            0x0F..=0x11 => {
                if let Some(&r) = regs.first() {
                    record(r, Slot::from_java(&parsed.returns), &const_defs, &mut kinds);
                }
            }
            0x6E..=0x72 | 0x74..=0x78 => {
                infer_invoke_arg_kinds(dex, insn, &const_defs, &mut kinds);
            }
            0x59..=0x5F | 0x67..=0x6D => {
                let field: Option<&FieldId> =
                    insn.index.and_then(|i| dex.field_ids.get(i as usize));
                if let (Some(field), Some(&r)) = (field, regs.first()) {
                    record(r, field_slot(&field.type_name), &const_defs, &mut kinds);
                }
            }
            _ => {}
        }
    }
    let pc_to_idx: BTreeMap<u32, usize> =
        insns.iter().enumerate().map(|(i, n)| (n.pc, i)).collect();
    if method_has_const_split_conflict(dex, insns, &pc_to_idx, parsed) {
        return kinds;
    }
    kinds.retain(|&reg, &mut slot| {
        const_def_reaches_float_use(dex, insns, &pc_to_idx, parsed, reg, slot)
    });
    kinds
}

fn method_has_const_split_conflict(
    dex: &DexFile,
    insns: &[DalvikInsn],
    pc_to_idx: &BTreeMap<u32, usize>,
    parsed: &MethodDescriptor,
) -> bool {
    let mut const_regs: BTreeSet<u16> = BTreeSet::new();
    for insn in insns {
        if matches!(insn.op, 0x12..=0x19)
            && let Some(&d) = insn.regs.first()
        {
            const_regs.insert(d);
        }
    }
    for &reg in &const_regs {
        let mut reaches_fp: bool = false;
        let mut reaches_int: bool = false;
        for probe in [Slot::Float, Slot::Double] {
            for (start, insn) in insns.iter().enumerate() {
                if !(matches!(insn.op, 0x12..=0x19) && insn.regs.first() == Some(&reg)) {
                    continue;
                }
                match const_value_int_or_float_use(dex, insns, pc_to_idx, parsed, reg, probe, start)
                {
                    ConstFlow::Float => reaches_fp = true,
                    ConstFlow::Int => reaches_int = true,
                    ConstFlow::Unknown => {}
                }
            }
        }
        if reaches_fp && reaches_int {
            return true;
        }
    }
    false
}

fn const_def_reaches_float_use(
    dex: &DexFile,
    insns: &[DalvikInsn],
    pc_to_idx: &BTreeMap<u32, usize>,
    parsed: &MethodDescriptor,
    reg: u16,
    slot: Slot,
) -> bool {
    let is_const_def = |insn: &DalvikInsn| -> bool {
        matches!(insn.op, 0x12..=0x19) && insn.regs.first() == Some(&reg)
    };
    for (start, insn) in insns.iter().enumerate() {
        if !is_const_def(insn) {
            continue;
        }
        if const_value_reaches_float_use(dex, insns, pc_to_idx, parsed, reg, slot, start) {
            return true;
        }
    }
    false
}

fn const_value_reaches_float_use(
    dex: &DexFile,
    insns: &[DalvikInsn],
    pc_to_idx: &BTreeMap<u32, usize>,
    parsed: &MethodDescriptor,
    reg: u16,
    slot: Slot,
    start: usize,
) -> bool {
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut work: Vec<usize> = vec![start + 1];
    while let Some(idx) = work.pop() {
        if !visited.insert(idx) {
            continue;
        }
        let Some(insn): Option<&DalvikInsn> = insns.get(idx) else {
            continue;
        };
        match float_use_kind(dex, insn, parsed, reg, slot) {
            FloatUse::Match => return true,
            FloatUse::Redefined => continue,
            FloatUse::Ambiguous => return true,
            FloatUse::None => {}
        }
        if insn.is_switch() {
            return true;
        }
        let mut followed_any: bool = false;
        if let Some(t) = insn.branch_target_pc() {
            match pc_to_idx.get(&t) {
                Some(&j) => {
                    work.push(j);
                    followed_any = true;
                }
                None => return true,
            }
        }
        if !insn.is_unconditional_goto()
            && !insn.is_return()
            && !insn.is_throw()
            && insns.get(idx + 1).is_some()
        {
            work.push(idx + 1);
            followed_any = true;
        }
        if !followed_any && !insn.is_return() && !insn.is_throw() {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstFlow {
    Float,
    Int,
    Unknown,
}

fn const_value_int_or_float_use(
    dex: &DexFile,
    insns: &[DalvikInsn],
    pc_to_idx: &BTreeMap<u32, usize>,
    parsed: &MethodDescriptor,
    reg: u16,
    slot: Slot,
    start: usize,
) -> ConstFlow {
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut work: Vec<usize> = vec![start + 1];
    let mut saw_int: bool = false;
    while let Some(idx) = work.pop() {
        if !visited.insert(idx) {
            continue;
        }
        let Some(insn): Option<&DalvikInsn> = insns.get(idx) else {
            continue;
        };
        match float_use_kind(dex, insn, parsed, reg, slot) {
            FloatUse::Match => return ConstFlow::Float,
            FloatUse::Redefined => continue,
            FloatUse::Ambiguous | FloatUse::None => {}
        }
        if const_int_use(dex, insn, reg) {
            saw_int = true;
            continue;
        }
        if let Some(t) = insn.branch_target_pc()
            && let Some(&j) = pc_to_idx.get(&t)
        {
            work.push(j);
        }
        if !insn.is_unconditional_goto()
            && !insn.is_return()
            && !insn.is_throw()
            && insns.get(idx + 1).is_some()
        {
            work.push(idx + 1);
        }
    }
    if saw_int {
        ConstFlow::Int
    } else {
        ConstFlow::Unknown
    }
}

fn const_int_use(dex: &DexFile, insn: &DalvikInsn, reg: u16) -> bool {
    let op: u8 = insn.op;
    let r: &[u16] = &insn.regs;
    if !r.contains(&reg) {
        return false;
    }
    match op {
        0x0F => r.first() == Some(&reg),
        0xB0..=0xE2 => true,
        0x90..=0xAF => r.iter().skip(1).any(|&x: &u16| x == reg),
        0x44 | 0x47..=0x4A => r.iter().skip(1).any(|&x: &u16| x == reg),
        0x4B | 0x4E..=0x51 => r.first() == Some(&reg),
        0x59..=0x5F | 0x67..=0x6D => {
            r.first() == Some(&reg)
                && !matches!(
                    field_value_use(dex, insn, reg, Slot::Float),
                    FloatUse::Match
                )
                && !matches!(
                    field_value_use(dex, insn, reg, Slot::Double),
                    FloatUse::Match
                )
                && {
                    let fs: Slot = insn
                        .index
                        .and_then(|i| dex.field_ids.get(i as usize))
                        .map_or(Slot::Int, |f: &FieldId| field_slot(&f.type_name));
                    matches!(fs, Slot::Int)
                }
        }
        0x6E..=0x72 | 0x74..=0x78 => matches!(invoke_int_use(dex, insn, reg), Some(true)),
        _ => false,
    }
}

fn invoke_int_use(dex: &DexFile, insn: &DalvikInsn, reg: u16) -> Option<bool> {
    let method: &MethodId = insn.index.and_then(|i| dex.method_ids.get(i as usize))?;
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static {
        let _ = reg_iter.next();
    }
    for param in &method.proto.parameters {
        let pslot: Slot = field_slot(param);
        if let Some(&used) = reg_iter.next()
            && used == reg
        {
            return Some(matches!(pslot, Slot::Int));
        }
        if pslot.category_two() {
            let _ = reg_iter.next();
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloatUse {
    Match,

    Redefined,

    Ambiguous,

    None,
}

fn float_use_kind(
    dex: &DexFile,
    insn: &DalvikInsn,
    parsed: &MethodDescriptor,
    reg: u16,
    slot: Slot,
) -> FloatUse {
    let op: u8 = insn.op;
    let r: &[u16] = &insn.regs;
    let want_float: bool = matches!(slot, Slot::Float);
    let reads_skip1_as = |kind: Slot| -> FloatUse {
        if r.iter().skip(1).any(|&x: &u16| x == reg) {
            if kind == slot {
                FloatUse::Match
            } else {
                FloatUse::Ambiguous
            }
        } else {
            FloatUse::None
        }
    };
    let defines_first = |insn: &DalvikInsn| -> bool { insn.regs.first() == Some(&reg) };
    match op {
        0x12..=0x19 => {
            if defines_first(insn) {
                FloatUse::Redefined
            } else {
                FloatUse::None
            }
        }
        0x2D | 0x2E => reads_skip1_as(Slot::Float),
        0x2F | 0x30 => reads_skip1_as(Slot::Double),
        0xA6..=0xAA => reads_skip1_as(Slot::Float),
        0xAB..=0xAF => reads_skip1_as(Slot::Double),
        0xC6..=0xCA => second_use(r, reg, Slot::Float, slot),
        0xCB..=0xCF => second_use(r, reg, Slot::Double, slot),
        0x0F => {
            if r.first() == Some(&reg) {
                return_use(parsed, want_float)
            } else {
                FloatUse::None
            }
        }
        0x10 => {
            if r.first() == Some(&reg) {
                FloatUse::Ambiguous
            } else {
                FloatUse::None
            }
        }
        0x59..=0x5F | 0x67..=0x6D => field_value_use(dex, insn, reg, slot),
        0x6E..=0x72 | 0x74..=0x78 => invoke_float_use(dex, insn, reg, slot),
        _ => {
            if r.first() == Some(&reg) && defines_register(insn) {
                FloatUse::Redefined
            } else if r.contains(&reg) {
                FloatUse::Ambiguous
            } else {
                FloatUse::None
            }
        }
    }
}

fn second_use(regs: &[u16], reg: u16, kind: Slot, slot: Slot) -> FloatUse {
    if regs.get(1) == Some(&reg) {
        if kind == slot {
            FloatUse::Match
        } else {
            FloatUse::Ambiguous
        }
    } else {
        FloatUse::None
    }
}

const fn return_use(parsed: &MethodDescriptor, want_float: bool) -> FloatUse {
    let returns: Slot = Slot::from_java(&parsed.returns);
    if matches!(returns, Slot::Float) && want_float {
        FloatUse::Match
    } else {
        FloatUse::None
    }
}

fn field_value_use(dex: &DexFile, insn: &DalvikInsn, reg: u16, slot: Slot) -> FloatUse {
    if insn.regs.first() != Some(&reg) {
        return FloatUse::None;
    }
    let field_slot: Slot = insn
        .index
        .and_then(|i| dex.field_ids.get(i as usize))
        .map_or(Slot::Int, |f: &FieldId| field_slot(&f.type_name));
    if field_slot == slot {
        FloatUse::Match
    } else {
        FloatUse::None
    }
}

fn invoke_float_use(dex: &DexFile, insn: &DalvikInsn, reg: u16, slot: Slot) -> FloatUse {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| dex.method_ids.get(i as usize))
    else {
        return if insn.regs.contains(&reg) {
            FloatUse::Ambiguous
        } else {
            FloatUse::None
        };
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static {
        let _ = reg_iter.next();
    }
    for param in &method.proto.parameters {
        let pslot: Slot = field_slot(param);
        if let Some(&used) = reg_iter.next()
            && used == reg
        {
            return if pslot == slot {
                FloatUse::Match
            } else {
                FloatUse::None
            };
        }
        if pslot.category_two() {
            let _ = reg_iter.next();
        }
    }
    FloatUse::None
}

const fn defines_register(insn: &DalvikInsn) -> bool {
    matches!(
        insn.op,
        0x01..=0x0D
            | 0x1A..=0x23
            | 0x44..=0x4A
            | 0x52..=0x58
            | 0x60..=0x66
            | 0x7B..=0x8F
            | 0x90..=0xAF
            | 0xB0..=0xCF
            | 0xD0..=0xE2
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cat {
    One,
    Two,
}

fn has_width_conflict(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
    item: &CodeItem,
    is_static: bool,
) -> bool {
    let mut cat: BTreeMap<u16, Cat> = BTreeMap::new();
    let first_param_reg: u16 = item.registers_size.saturating_sub(item.ins_size);
    let mut cursor: u16 = first_param_reg;
    if !is_static {
        cat.insert(cursor, Cat::One);
        cursor = cursor.saturating_add(1);
    }
    for ty in &parsed.params {
        let c: Cat = if Slot::from_java(ty).category_two() {
            Cat::Two
        } else {
            Cat::One
        };
        cat.insert(cursor, c);
        cursor = cursor.saturating_add(if c == Cat::Two { 2 } else { 1 });
    }

    for insn in insns {
        let (def, def_cat, uses): (Option<u16>, Cat, Vec<(u16, Cat)>) =
            register_effects(dex, insn, parsed);
        for (reg, want) in &uses {
            if matches!(cat.get(reg), Some(have) if *have != *want) {
                return true;
            }
        }
        if let Some(d) = def {
            cat.insert(d, def_cat);
        }
    }
    false
}

#[allow(clippy::too_many_lines)]
fn register_effects(
    dex: &DexFile,
    insn: &DalvikInsn,
    _parsed: &MethodDescriptor,
) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let op: u8 = insn.op;
    let regs: &[u16] = &insn.regs;
    let first: Option<u16> = regs.first().copied();
    let second: Option<u16> = regs.get(1).copied();
    match op {
        0x12..=0x15 | 0x1A | 0x1B | 0x1C => (first, Cat::One, Vec::new()),
        0x16..=0x19 => (first, Cat::Two, Vec::new()),
        0x0A | 0x0C | 0x0D => (first, Cat::One, Vec::new()),
        0x0B => (first, Cat::Two, Vec::new()),
        0x01 | 0x02 | 0x03 | 0x07 | 0x08 | 0x09 => (
            first,
            Cat::One,
            second.map(|r| vec![(r, Cat::One)]).unwrap_or_default(),
        ),
        0x04..=0x06 => (
            first,
            Cat::Two,
            second.map(|r| vec![(r, Cat::Two)]).unwrap_or_default(),
        ),
        0x45 => (first, Cat::Two, Vec::new()),
        0x4C => (
            None,
            Cat::One,
            first.map(|r| vec![(r, Cat::Two)]).unwrap_or_default(),
        ),
        0x0F | 0x11 => (
            None,
            Cat::One,
            first.map(|r| vec![(r, Cat::One)]).unwrap_or_default(),
        ),
        0x10 => (
            None,
            Cat::One,
            first.map(|r| vec![(r, Cat::Two)]).unwrap_or_default(),
        ),
        0x52..=0x58 | 0x60..=0x66 => {
            let c: Cat = field_cat(dex, insn.index);
            (
                first,
                c,
                second.map(|r| vec![(r, Cat::One)]).unwrap_or_default(),
            )
        }
        0x59..=0x5F => {
            let c: Cat = field_cat(dex, insn.index);
            let mut uses: Vec<(u16, Cat)> = Vec::new();
            if let Some(v) = first {
                uses.push((v, c));
            }
            if let Some(o) = second {
                uses.push((o, Cat::One));
            }
            (None, Cat::One, uses)
        }
        0x67..=0x6D => {
            let c: Cat = field_cat(dex, insn.index);
            (
                None,
                Cat::One,
                first.map(|r| vec![(r, c)]).unwrap_or_default(),
            )
        }
        0x90..=0xAF => binary_three_effects(op, regs),
        0xB0..=0xCF => binary_two_addr_effects(op, regs),
        0x81..=0x8F => cast_effects(op, first, second),
        0x6E..=0x72 | 0x74..=0x78 => invoke_effects(dex, insn),
        _ => (None, Cat::One, Vec::new()),
    }
}

fn field_cat(dex: &DexFile, index: Option<u32>) -> Cat {
    let slot: Slot = index
        .and_then(|i| dex.field_ids.get(i as usize))
        .map(|f: &FieldId| field_slot(&f.type_name))
        .unwrap_or(Slot::Int);
    if slot.category_two() {
        Cat::Two
    } else {
        Cat::One
    }
}

const fn arith_cat(op: u8) -> Cat {
    if arith_three(op).1.category_two() {
        Cat::Two
    } else {
        Cat::One
    }
}

fn binary_three_effects(op: u8, regs: &[u16]) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let c: Cat = arith_cat(op);
    let rhs_cat: Cat = if is_shift(op) { Cat::One } else { c };
    let mut uses: Vec<(u16, Cat)> = Vec::new();
    if let Some(&l) = regs.get(1) {
        uses.push((l, c));
    }
    if let Some(&r) = regs.get(2) {
        uses.push((r, rhs_cat));
    }
    (regs.first().copied(), c, uses)
}

fn binary_two_addr_effects(op: u8, regs: &[u16]) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let base: u8 = op - 0x20;
    let c: Cat = arith_cat(base);
    let rhs_cat: Cat = if is_shift(base) { Cat::One } else { c };
    let mut uses: Vec<(u16, Cat)> = Vec::new();
    if let Some(&d) = regs.first() {
        uses.push((d, c));
    }
    if let Some(&r) = regs.get(1) {
        uses.push((r, rhs_cat));
    }
    (regs.first().copied(), c, uses)
}

fn cast_effects(
    op: u8,
    dest: Option<u16>,
    src: Option<u16>,
) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let (from, to): (Cat, Cat) = match op {
        0x81 => (Cat::One, Cat::Two),
        0x82 => (Cat::One, Cat::One),
        0x83 => (Cat::One, Cat::Two),
        0x84 => (Cat::Two, Cat::One),
        0x85 => (Cat::Two, Cat::One),
        0x86 => (Cat::Two, Cat::Two),
        0x87 => (Cat::One, Cat::One),
        0x88 => (Cat::One, Cat::Two),
        0x89 => (Cat::One, Cat::Two),
        0x8A => (Cat::Two, Cat::One),
        0x8B => (Cat::Two, Cat::Two),
        0x8C => (Cat::Two, Cat::One),
        _ => (Cat::One, Cat::One),
    };
    (dest, to, src.map(|r| vec![(r, from)]).unwrap_or_default())
}

fn invoke_effects(dex: &DexFile, insn: &DalvikInsn) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| dex.method_ids.get(i as usize))
    else {
        return (None, Cat::One, Vec::new());
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut uses: Vec<(u16, Cat)> = Vec::new();
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static && let Some(&recv) = reg_iter.next() {
        uses.push((recv, Cat::One));
    }
    for param in &method.proto.parameters {
        let two: bool = field_slot(param).category_two();
        if let Some(&reg) = reg_iter.next() {
            uses.push((reg, if two { Cat::Two } else { Cat::One }));
        }
        if two {
            let _ = reg_iter.next();
        }
    }
    (None, Cat::One, uses)
}

fn infer_invoke_arg_kinds(
    dex: &DexFile,
    insn: &DalvikInsn,
    const_defs: &BTreeSet<u16>,
    kinds: &mut BTreeMap<u16, Slot>,
) {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| dex.method_ids.get(i as usize))
    else {
        return;
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static {
        let _ = reg_iter.next();
    }
    for param in &method.proto.parameters {
        let slot: Slot = field_slot(param);
        if let Some(&reg) = reg_iter.next()
            && const_defs.contains(&reg)
            && matches!(slot, Slot::Float | Slot::Double)
        {
            kinds.entry(reg).or_insert(slot);
        }
        if slot.category_two() {
            let _ = reg_iter.next();
        }
    }
}

const fn arith_three(op: u8) -> (u8, Slot) {
    match op {
        0x90 => (0x60, Slot::Int),
        0x91 => (0x64, Slot::Int),
        0x92 => (0x68, Slot::Int),
        0x93 => (0x6C, Slot::Int),
        0x94 => (0x70, Slot::Int),
        0x95 => (0x7E, Slot::Int),
        0x96 => (0x80, Slot::Int),
        0x97 => (0x82, Slot::Int),
        0x98 => (0x78, Slot::Int),
        0x99 => (0x7A, Slot::Int),
        0x9A => (0x7C, Slot::Int),
        0x9B => (0x61, Slot::Long),
        0x9C => (0x65, Slot::Long),
        0x9D => (0x69, Slot::Long),
        0x9E => (0x6D, Slot::Long),
        0x9F => (0x71, Slot::Long),
        0xA0 => (0x7F, Slot::Long),
        0xA1 => (0x81, Slot::Long),
        0xA2 => (0x83, Slot::Long),
        0xA3 => (0x79, Slot::Long),
        0xA4 => (0x7B, Slot::Long),
        0xA5 => (0x7D, Slot::Long),
        0xA6 => (0x62, Slot::Float),
        0xA7 => (0x66, Slot::Float),
        0xA8 => (0x6A, Slot::Float),
        0xA9 => (0x6E, Slot::Float),
        0xAA => (0x72, Slot::Float),
        0xAB => (0x63, Slot::Double),
        0xAC => (0x67, Slot::Double),
        0xAD => (0x6B, Slot::Double),
        0xAE => (0x6F, Slot::Double),
        0xAF => (0x73, Slot::Double),
        _ => (0x60, Slot::Int),
    }
}

const fn arith_lit_op(op: u8) -> u8 {
    match op {
        0xD0 | 0xD8 => 0x60,
        0xD1 | 0xD9 => 0x64,
        0xD2 | 0xDA => 0x68,
        0xD3 | 0xDB => 0x6C,
        0xD4 | 0xDC => 0x70,
        0xD5 | 0xDD => 0x7E,
        0xD6 | 0xDE => 0x80,
        0xD7 | 0xDF => 0x82,
        0xE0 => 0x78,
        0xE1 => 0x7A,
        0xE2 => 0x7C,
        _ => 0x60,
    }
}

const fn array_elem_slot(element_descriptor: &str) -> Option<Slot> {
    match element_descriptor.as_bytes().first() {
        Some(b'I') => Some(Slot::Int),
        Some(b'F') => Some(Slot::Float),
        Some(b'J') => Some(Slot::Long),
        Some(b'D') => Some(Slot::Double),
        Some(b'B' | b'Z' | b'C' | b'S') => Some(Slot::Int),
        _ => None,
    }
}

fn array_elem_from_regtype(ty: &crate::dalvik_typestate::RegType) -> Option<Slot> {
    let crate::dalvik_typestate::RegType::Ref(desc) = ty else {
        return None;
    };
    desc.strip_prefix('[').and_then(array_elem_slot)
}

const fn is_primitive_elem(b: u8) -> bool {
    matches!(b, b'I' | b'F' | b'J' | b'D' | b'B' | b'Z' | b'C' | b'S')
}

fn array_elem_desc_jt(ty: &JavaType) -> Option<u8> {
    let JavaType::Array(inner): &JavaType = ty else {
        return None;
    };
    Some(match inner.as_ref() {
        JavaType::Byte => b'B',
        JavaType::Char => b'C',
        JavaType::Short => b'S',
        JavaType::Boolean => b'Z',
        JavaType::Int => b'I',
        JavaType::Long => b'J',
        JavaType::Float => b'F',
        JavaType::Double => b'D',
        _ => return None,
    })
}

fn array_elem_desc_from_regtype(ty: &crate::dalvik_typestate::RegType) -> Option<u8> {
    let crate::dalvik_typestate::RegType::Ref(desc) = ty else {
        return None;
    };
    desc.strip_prefix('[')
        .and_then(|s: &str| s.bytes().next())
        .filter(|b: &u8| is_primitive_elem(*b))
}

fn array_elem_slot_jt(ty: &JavaType) -> Option<Slot> {
    let JavaType::Array(inner): &JavaType = ty else {
        return None;
    };
    Some(match inner.as_ref() {
        JavaType::Long => Slot::Long,
        JavaType::Float => Slot::Float,
        JavaType::Double => Slot::Double,
        JavaType::Object(_) | JavaType::Array(_) => return None,
        _ => Slot::Int,
    })
}

const fn field_slot(descriptor: &str) -> Slot {
    match descriptor.as_bytes().first() {
        Some(b'J') => Slot::Long,
        Some(b'F') => Slot::Float,
        Some(b'D') => Slot::Double,
        Some(b'L' | b'[') => Slot::Ref,
        _ => Slot::Int,
    }
}

fn internal_of(descriptor: &str) -> String {
    if descriptor.starts_with('L') && descriptor.ends_with(';') {
        descriptor[1..descriptor.len() - 1].to_string()
    } else {
        descriptor.to_string()
    }
}

fn build_descriptor(params: &[String], return_type: &str) -> String {
    let mut out: String = String::with_capacity(2 + return_type.len());
    out.push('(');
    for p in params {
        out.push_str(p);
    }
    out.push(')');
    out.push_str(return_type);
    out
}

fn primitive_atype(descriptor: &str) -> Option<u8> {
    match descriptor {
        "Z" => Some(4),
        "C" => Some(5),
        "F" => Some(6),
        "D" => Some(7),
        "B" => Some(8),
        "S" => Some(9),
        "I" => Some(10),
        "J" => Some(11),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dalvik_typestate::RegType;

    fn frame(offset: usize, local: RegType, stack: Option<&str>) -> StackMapFrame {
        (offset, vec![local], stack.map(str::to_owned))
    }

    #[test]
    fn frames_computed_twice_at_one_offset_collapse_to_one_entry() {
        let frames: Vec<StackMapFrame> = vec![
            frame(0, RegType::Int, None),
            frame(14, RegType::Ref("p/Left".to_owned()), None),
            frame(14, RegType::Ref("p/Left".to_owned()), None),
            frame(40, RegType::Int, Some("java/lang/Throwable")),
        ];
        let deduped: Vec<StackMapFrame> =
            dedup_frames_by_offset(frames).expect("two identical frames at one offset collapse");
        let offsets: Vec<usize> = deduped.iter().map(|f: &StackMapFrame| f.0).collect();
        assert_eq!(
            offsets,
            vec![0, 14, 40],
            "a duplicate offset survived, and the delta loop that follows subtracts one from a zero \
             gap and rejects the whole method"
        );
    }

    #[test]
    fn two_frames_at_one_offset_that_disagree_reject_the_method() {
        let frames: Vec<StackMapFrame> = vec![
            frame(0, RegType::Int, None),
            frame(14, RegType::Ref("p/Left".to_owned()), None),
            frame(14, RegType::Int, None),
        ];
        assert!(
            dedup_frames_by_offset(frames).is_none(),
            "two disagreeing frames at one offset have no single correct entry, so the method has \
             to be rejected rather than have one of the two picked"
        );
    }

    #[test]
    fn a_handler_stub_frame_sharing_a_branch_target_offset_still_emits_a_table() {
        let stack: Option<&str> = Some("java/lang/Throwable");
        let frames: Vec<StackMapFrame> = vec![
            frame(6, RegType::Ref("p/Left".to_owned()), stack),
            frame(6, RegType::Ref("p/Left".to_owned()), stack),
        ];
        let deduped: Vec<StackMapFrame> = dedup_frames_by_offset(frames)
            .expect("a handler stub landing on a branch target offset is not a conflict");
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped.first().map(|f: &StackMapFrame| f.0), Some(6));
    }
}
