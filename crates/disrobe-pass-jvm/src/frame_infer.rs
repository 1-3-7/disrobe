use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::bytecode::{Instruction, Operands};
use crate::decompile_struct::{BlockId, Cfg};
use crate::descriptor::{JavaType, MethodDescriptor, parse_field, parse_method};
use crate::stackmap::VerificationType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameState {
    pub locals: Vec<VerificationType>,
    pub stack: Vec<VerificationType>,
}

impl FrameState {
    const fn entry(locals: Vec<VerificationType>) -> Self {
        Self {
            locals,
            stack: Vec::new(),
        }
    }

    fn set_local(&mut self, index: usize, ty: VerificationType) {
        if self.locals.len() <= index {
            self.locals.resize(index + 1, VerificationType::Top);
        }
        self.locals[index] = ty;
    }

    fn local(&self, index: usize) -> VerificationType {
        self.locals
            .get(index)
            .cloned()
            .unwrap_or(VerificationType::Top)
    }

    fn push(&mut self, ty: VerificationType) {
        self.stack.push(ty);
    }

    fn push_wide(&mut self, ty: VerificationType) {
        self.stack.push(ty);
        self.stack.push(VerificationType::Top);
    }

    fn pop(&mut self) -> VerificationType {
        self.stack.pop().unwrap_or(VerificationType::Top)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrameInferOutcome {
    Converged,
    UnmodeledOpcode,
    StackUnderflow,
    Diverged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameInferReport {
    pub outcome: FrameInferOutcome,
    pub block_entry_frames: BTreeMap<u32, FrameState>,
    pub modeled_instructions: usize,
    pub total_instructions: usize,
    pub first_unmodeled: Option<(u32, String)>,
}

impl FrameInferReport {
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.total_instructions == 0 {
            return 1.0;
        }
        self.modeled_instructions as f64 / self.total_instructions as f64
    }
}

fn merge_type(a: &VerificationType, b: &VerificationType) -> VerificationType {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (VerificationType::Object(_), VerificationType::Null)
        | (VerificationType::Null, VerificationType::Object(_)) => {
            if let VerificationType::Object(name) = a {
                VerificationType::Object(name.clone())
            } else if let VerificationType::Object(name) = b {
                VerificationType::Object(name.clone())
            } else {
                VerificationType::Top
            }
        }
        (VerificationType::Object(_), VerificationType::Object(_)) => {
            VerificationType::Object("java/lang/Object".to_owned())
        }
        _ => VerificationType::Top,
    }
}

fn merge_frames(into: &mut FrameState, other: &FrameState) -> bool {
    let mut changed: bool = false;
    let local_len: usize = into.locals.len().max(other.locals.len());
    if into.locals.len() < local_len {
        into.locals.resize(local_len, VerificationType::Top);
        changed = true;
    }
    for i in 0..local_len {
        let a: VerificationType = into.local(i);
        let b: VerificationType = other.local(i);
        let merged: VerificationType = merge_type(&a, &b);
        if merged != a {
            into.locals[i] = merged;
            changed = true;
        }
    }
    if into.stack.len() == other.stack.len() {
        for i in 0..into.stack.len() {
            let merged: VerificationType = merge_type(&into.stack[i], &other.stack[i]);
            if merged != into.stack[i] {
                into.stack[i] = merged;
                changed = true;
            }
        }
    }
    changed
}

fn field_type_from_descriptor(desc: &str) -> VerificationType {
    match parse_field(desc) {
        Some(ty) => java_type_to_vt(&ty),
        None => VerificationType::Top,
    }
}

fn java_type_to_vt(ty: &JavaType) -> VerificationType {
    match ty {
        JavaType::Byte | JavaType::Char | JavaType::Int | JavaType::Short | JavaType::Boolean => {
            VerificationType::Integer
        }
        JavaType::Float => VerificationType::Float,
        JavaType::Long => VerificationType::Long,
        JavaType::Double => VerificationType::Double,
        JavaType::Object(name) => VerificationType::Object(name.clone()),
        JavaType::Array(_) => VerificationType::Object("[".to_owned()),
        JavaType::Void => VerificationType::Top,
    }
}

const fn is_wide(ty: &VerificationType) -> bool {
    matches!(ty, VerificationType::Long | VerificationType::Double)
}

struct OpcodeResolver<'a> {
    field_ref: &'a dyn Fn(u16) -> Option<String>,
    method_ref: &'a dyn Fn(u16) -> Option<(String, String)>,
    class_ref: &'a dyn Fn(u16) -> Option<String>,
    ldc_type: &'a dyn Fn(u16) -> Option<VerificationType>,
}

#[allow(clippy::too_many_lines)]
fn apply_transfer(
    insn: &Instruction,
    state: &mut FrameState,
    resolver: &OpcodeResolver<'_>,
) -> Result<(), FrameInferOutcome> {
    let opcode: u8 = insn.opcode;
    match opcode {
        0x00 => {}
        0x01 => state.push(VerificationType::Null),
        0x02..=0x08 => state.push(VerificationType::Integer),
        0x09..=0x0A => state.push_wide(VerificationType::Long),
        0x0B..=0x0D => state.push(VerificationType::Float),
        0x0E..=0x0F => state.push_wide(VerificationType::Double),
        0x10 | 0x11 => state.push(VerificationType::Integer),
        0x12 => {
            let ty: VerificationType = match insn.operands {
                Operands::ConstPool(idx) => {
                    (resolver.ldc_type)(idx).unwrap_or(VerificationType::Top)
                }
                _ => VerificationType::Top,
            };
            state.push(ty);
        }
        0x13 => {
            let ty: VerificationType = match insn.operands {
                Operands::ConstPool(idx) => {
                    (resolver.ldc_type)(idx).unwrap_or(VerificationType::Top)
                }
                _ => VerificationType::Top,
            };
            state.push(ty);
        }
        0x14 => {
            let ty: VerificationType = match insn.operands {
                Operands::ConstPool(idx) => {
                    (resolver.ldc_type)(idx).unwrap_or(VerificationType::Long)
                }
                _ => VerificationType::Long,
            };
            state.push_wide(ty);
        }
        0x15 => push_local(insn, state, VerificationType::Integer, false),
        0x16 => push_local(insn, state, VerificationType::Long, true),
        0x17 => push_local(insn, state, VerificationType::Float, false),
        0x18 => push_local(insn, state, VerificationType::Double, true),
        0x19 => {
            let idx: usize = local_index(insn);
            let ty: VerificationType = state.local(idx);
            state.push(ty);
        }
        0x1A..=0x1D => {
            let idx: usize = usize::from(opcode - 0x1A);
            state.push(state.local(idx));
        }
        0x1E..=0x21 => {
            let idx: usize = usize::from(opcode - 0x1E);
            state.push_wide(state.local(idx));
        }
        0x22..=0x25 => {
            let idx: usize = usize::from(opcode - 0x22);
            state.push(state.local(idx));
        }
        0x26..=0x29 => {
            let idx: usize = usize::from(opcode - 0x26);
            state.push_wide(state.local(idx));
        }
        0x2A..=0x2D => {
            let idx: usize = usize::from(opcode - 0x2A);
            state.push(state.local(idx));
        }
        0x2E | 0x30 | 0x32 | 0x33 | 0x34 | 0x35 => {
            let element: VerificationType = array_element_type(opcode);
            state.pop();
            state.pop();
            if is_wide(&element) {
                state.push_wide(element);
            } else {
                state.push(element);
            }
        }
        0x2F | 0x31 => {
            state.pop();
            state.pop();
            state.push_wide(array_element_type(opcode));
        }
        0x36 => store_local(insn, state, false),
        0x37 => store_local(insn, state, true),
        0x38 => store_local(insn, state, false),
        0x39 => store_local(insn, state, true),
        0x3A => {
            let idx: usize = local_index(insn);
            let ty: VerificationType = state.pop();
            state.set_local(idx, ty);
        }
        0x3B..=0x3E => store_indexed(state, usize::from(opcode - 0x3B), false),
        0x3F..=0x42 => store_indexed(state, usize::from(opcode - 0x3F), true),
        0x43..=0x46 => store_indexed(state, usize::from(opcode - 0x43), false),
        0x47..=0x4A => store_indexed(state, usize::from(opcode - 0x47), true),
        0x4B..=0x4E => {
            let idx: usize = usize::from(opcode - 0x4B);
            let ty: VerificationType = state.pop();
            state.set_local(idx, ty);
        }
        0x4F | 0x51 | 0x54 | 0x55 | 0x56 => {
            state.pop();
            state.pop();
            state.pop();
        }
        0x50 | 0x52 => {
            state.pop();
            state.pop();
            state.pop();
            state.pop();
        }
        0x53 => {
            state.pop();
            state.pop();
            state.pop();
        }
        0x57 => {
            state.pop();
        }
        0x58 => {
            state.pop();
            state.pop();
        }
        0x59 => {
            let top: VerificationType = state.pop();
            state.push(top.clone());
            state.push(top);
        }
        0x5A => {
            let v1: VerificationType = state.pop();
            let v2: VerificationType = state.pop();
            state.push(v1.clone());
            state.push(v2);
            state.push(v1);
        }
        0x5B => {
            let v1: VerificationType = state.pop();
            let v2: VerificationType = state.pop();
            let v3: VerificationType = state.pop();
            state.push(v1.clone());
            state.push(v3);
            state.push(v2);
            state.push(v1);
        }
        0x5C => {
            let v1: VerificationType = state.pop();
            let v2: VerificationType = state.pop();
            state.push(v2.clone());
            state.push(v1.clone());
            state.push(v2);
            state.push(v1);
        }
        0x5D | 0x5E => return Err(FrameInferOutcome::UnmodeledOpcode),
        0x5F => {
            let v1: VerificationType = state.pop();
            let v2: VerificationType = state.pop();
            state.push(v1);
            state.push(v2);
        }
        0x60 | 0x64 | 0x68 | 0x6C | 0x70 | 0x74 => {
            state.pop();
            state.pop();
            let ty: VerificationType = arith_result(opcode);
            push_arith(state, ty);
        }
        0x61 | 0x65 | 0x69 | 0x6D | 0x71 | 0x75 => {
            state.pop();
            state.pop();
            state.pop();
            state.pop();
            push_arith(state, arith_result(opcode));
        }
        0x62 | 0x66 | 0x6A | 0x6E | 0x72 | 0x76 => {
            state.pop();
            state.pop();
            push_arith(state, arith_result(opcode));
        }
        0x63 | 0x67 | 0x6B | 0x6F | 0x73 | 0x77 => {
            state.pop();
            state.pop();
            state.pop();
            state.pop();
            push_arith(state, arith_result(opcode));
        }
        0x78 | 0x7A | 0x7C | 0x7E | 0x80 | 0x82 => {
            state.pop();
            push_arith(state, arith_result(opcode));
        }
        0x79 | 0x7B | 0x7D | 0x7F | 0x81 | 0x83 => {
            state.pop();
            state.pop();
            push_arith(state, arith_result(opcode));
        }
        0x84 => {}
        0x85 => {
            state.pop();
            state.push_wide(VerificationType::Long);
        }
        0x86 => {
            state.pop();
            state.push(VerificationType::Float);
        }
        0x87 => {
            state.pop();
            state.push_wide(VerificationType::Double);
        }
        0x88 => {
            state.pop();
            state.pop();
            state.push(VerificationType::Integer);
        }
        0x89 => {
            state.pop();
            state.pop();
            state.push(VerificationType::Float);
        }
        0x8A => {
            state.pop();
            state.pop();
            state.push_wide(VerificationType::Double);
        }
        0x8B => {
            state.pop();
            state.push(VerificationType::Integer);
        }
        0x8C => {
            state.pop();
            state.push(VerificationType::Long);
        }
        0x8D => {
            state.pop();
            state.pop();
            state.push_wide(VerificationType::Long);
        }
        0x8E => {
            state.pop();
            state.pop();
            state.push(VerificationType::Float);
        }
        0x8F => {
            state.pop();
            state.pop();
            state.push_wide(VerificationType::Double);
        }
        0x90 => {
            state.pop();
            state.pop();
            state.push(VerificationType::Integer);
        }
        0x91..=0x93 => {
            state.pop();
            state.push(VerificationType::Integer);
        }
        0x94 => {
            state.pop();
            state.pop();
            state.pop();
            state.pop();
            state.push(VerificationType::Integer);
        }
        0x95..=0x98 => {
            state.pop();
            state.pop();
            state.pop();
            state.pop();
            state.push(VerificationType::Integer);
        }
        0x99..=0x9E | 0xC6 | 0xC7 => {
            state.pop();
        }
        0x9F..=0xA4 => {
            state.pop();
            state.pop();
        }
        0xA5 | 0xA6 => {
            state.pop();
            state.pop();
        }
        0xA7 | 0xA8 => {}
        0xAA | 0xAB => {
            state.pop();
        }
        0xAC | 0xAE | 0xB0 => {
            state.pop();
        }
        0xAD | 0xAF => {
            state.pop();
            state.pop();
        }
        0xB1 => {}
        0xB2 => {
            let ty: VerificationType = field_ref_type(insn, resolver);
            if is_wide(&ty) {
                state.push_wide(ty);
            } else {
                state.push(ty);
            }
        }
        0xB3 => {
            let ty: VerificationType = field_ref_type(insn, resolver);
            if is_wide(&ty) {
                state.pop();
            }
            state.pop();
        }
        0xB4 => {
            state.pop();
            let ty: VerificationType = field_ref_type(insn, resolver);
            if is_wide(&ty) {
                state.push_wide(ty);
            } else {
                state.push(ty);
            }
        }
        0xB5 => {
            let ty: VerificationType = field_ref_type(insn, resolver);
            if is_wide(&ty) {
                state.pop();
            }
            state.pop();
            state.pop();
        }
        0xB6..=0xBA => invoke_transfer(insn, state, resolver, opcode),
        0xBB => {
            let name: String = match insn.operands {
                Operands::ConstPool(idx) => {
                    (resolver.class_ref)(idx).unwrap_or_else(|| "java/lang/Object".to_owned())
                }
                _ => "java/lang/Object".to_owned(),
            };
            state.push(VerificationType::Object(name));
        }
        0xBC | 0xBD => {
            state.pop();
            state.push(VerificationType::Object("[".to_owned()));
        }
        0xBE => {
            state.pop();
            state.push(VerificationType::Integer);
        }
        0xBF => {
            state.pop();
        }
        0xC0 => {
            state.pop();
            let name: String = match insn.operands {
                Operands::ConstPool(idx) => {
                    (resolver.class_ref)(idx).unwrap_or_else(|| "java/lang/Object".to_owned())
                }
                _ => "java/lang/Object".to_owned(),
            };
            state.push(VerificationType::Object(name));
        }
        0xC1 => {
            state.pop();
            state.push(VerificationType::Integer);
        }
        0xC2 | 0xC3 => {
            state.pop();
        }
        0xC5 => {
            if let Operands::MultiANewArray { dimensions, .. } = insn.operands {
                for _ in 0..dimensions {
                    state.pop();
                }
            }
            state.push(VerificationType::Object("[".to_owned()));
        }
        0xC4 => {}
        _ => return Err(FrameInferOutcome::UnmodeledOpcode),
    }
    Ok(())
}

fn push_local(insn: &Instruction, state: &mut FrameState, ty: VerificationType, wide: bool) {
    let _ = insn;
    if wide {
        state.push_wide(ty);
    } else {
        state.push(ty);
    }
}

fn store_local(insn: &Instruction, state: &mut FrameState, wide: bool) {
    let idx: usize = local_index(insn);
    if wide {
        state.pop();
        let ty: VerificationType = state.pop();
        state.set_local(idx, ty);
        state.set_local(idx + 1, VerificationType::Top);
    } else {
        let ty: VerificationType = state.pop();
        state.set_local(idx, ty);
    }
}

fn store_indexed(state: &mut FrameState, slot: usize, wide: bool) {
    if wide {
        state.pop();
        let ty: VerificationType = state.pop();
        state.set_local(slot, ty);
        state.set_local(slot + 1, VerificationType::Top);
    } else {
        let ty: VerificationType = state.pop();
        state.set_local(slot, ty);
    }
}

fn local_index(insn: &Instruction) -> usize {
    match insn.operands {
        Operands::Local(i) => usize::from(i),
        Operands::Iinc { index, .. } => usize::from(index),
        _ => 0,
    }
}

fn array_element_type(opcode: u8) -> VerificationType {
    match opcode {
        0x2F | 0x3F..=0x42 => VerificationType::Long,
        0x30 | 0x43..=0x46 => VerificationType::Float,
        0x31 | 0x47..=0x4A => VerificationType::Double,
        0x32 => VerificationType::Object("java/lang/Object".to_owned()),
        _ => VerificationType::Integer,
    }
}

const fn arith_result(opcode: u8) -> VerificationType {
    match opcode {
        0x61 | 0x65 | 0x69 | 0x6D | 0x71 | 0x75 | 0x79 | 0x7B | 0x7D | 0x7F | 0x81 | 0x83
        | 0x8D => VerificationType::Long,
        0x62 | 0x66 | 0x6A | 0x6E | 0x72 | 0x76 | 0x8E => VerificationType::Float,
        0x63 | 0x67 | 0x6B | 0x6F | 0x73 | 0x77 | 0x8F => VerificationType::Double,
        _ => VerificationType::Integer,
    }
}

fn push_arith(state: &mut FrameState, ty: VerificationType) {
    if is_wide(&ty) {
        state.push_wide(ty);
    } else {
        state.push(ty);
    }
}

fn field_ref_type(insn: &Instruction, resolver: &OpcodeResolver<'_>) -> VerificationType {
    match insn.operands {
        Operands::ConstPool(idx) => match (resolver.field_ref)(idx) {
            Some(desc) => field_type_from_descriptor(&desc),
            None => VerificationType::Top,
        },
        _ => VerificationType::Top,
    }
}

fn invoke_transfer(
    insn: &Instruction,
    state: &mut FrameState,
    resolver: &OpcodeResolver<'_>,
    opcode: u8,
) {
    let descriptor: Option<String> = match insn.operands {
        Operands::ConstPool(idx) | Operands::InvokeDynamic(idx) => {
            (resolver.method_ref)(idx).map(|(_, d): (String, String)| d)
        }
        Operands::InvokeInterface { index, .. } => {
            (resolver.method_ref)(index).map(|(_, d): (String, String)| d)
        }
        _ => None,
    };
    let parsed: Option<MethodDescriptor> = descriptor.as_deref().and_then(parse_method);
    if let Some(md) = parsed {
        for param in md.params.iter().rev() {
            let vt: VerificationType = java_type_to_vt(param);
            if is_wide(&vt) {
                state.pop();
            }
            state.pop();
        }
        if opcode != 0xB8 && opcode != 0xBA {
            state.pop();
        }
        match md.returns {
            JavaType::Void => {}
            ref other => {
                let vt: VerificationType = java_type_to_vt(other);
                if is_wide(&vt) {
                    state.push_wide(vt);
                } else {
                    state.push(vt);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn infer_frames(
    cfg: &Cfg,
    insns: &[Instruction],
    descriptor: &MethodDescriptor,
    is_static: bool,
    is_init_ctor: bool,
    this_class: &str,
    field_ref: &dyn Fn(u16) -> Option<String>,
    method_ref: &dyn Fn(u16) -> Option<(String, String)>,
    class_ref: &dyn Fn(u16) -> Option<String>,
    ldc_type: &dyn Fn(u16) -> Option<VerificationType>,
) -> FrameInferReport {
    let resolver: OpcodeResolver<'_> = OpcodeResolver {
        field_ref,
        method_ref,
        class_ref,
        ldc_type,
    };
    let entry_locals: Vec<VerificationType> =
        crate::stackmap::entry_frame_locals(descriptor, is_static, is_init_ctor, this_class);

    let mut block_entry: BTreeMap<BlockId, FrameState> = BTreeMap::new();
    block_entry.insert(cfg.entry, FrameState::entry(entry_locals));

    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    let mut queued: BTreeSet<BlockId> = BTreeSet::new();
    worklist.push_back(cfg.entry);
    queued.insert(cfg.entry);

    let mut modeled: usize = 0;
    let mut total: usize = 0;
    let mut first_unmodeled: Option<(u32, String)> = None;
    let mut outcome: FrameInferOutcome = FrameInferOutcome::Converged;
    let mut iterations: usize = 0;
    let max_iterations: usize = cfg.blocks.len().saturating_mul(8).max(64);

    while let Some(bid) = worklist.pop_front() {
        queued.remove(&bid);
        iterations += 1;
        if iterations > max_iterations {
            outcome = FrameInferOutcome::Diverged;
            break;
        }
        let Some(block) = cfg.blocks.iter().find(|b| b.id == bid) else {
            continue;
        };
        let Some(entry_state) = block_entry.get(&bid).cloned() else {
            continue;
        };
        let mut state: FrameState = entry_state;
        let (lo, hi): (usize, usize) = block.insn_range;
        for insn in insns.get(lo..hi).unwrap_or(&[]) {
            total += 1;
            match apply_transfer(insn, &mut state, &resolver) {
                Ok(()) => modeled += 1,
                Err(reason) => {
                    if first_unmodeled.is_none() {
                        first_unmodeled = Some((insn.pc, insn.mnemonic.to_owned()));
                    }
                    if outcome == FrameInferOutcome::Converged {
                        outcome = reason;
                    }
                }
            }
        }
        for edge in &block.successors {
            let succ: BlockId = edge.target;
            let mut succ_state: FrameState = state.clone();
            if matches!(edge.kind, crate::decompile_struct::EdgeKind::Exception) {
                succ_state.stack.clear();
                succ_state
                    .stack
                    .push(VerificationType::Object("java/lang/Throwable".to_owned()));
            }
            match block_entry.get_mut(&succ) {
                Some(existing) => {
                    if merge_frames(existing, &succ_state) && queued.insert(succ) {
                        worklist.push_back(succ);
                    }
                }
                None => {
                    block_entry.insert(succ, succ_state);
                    queued.insert(succ);
                    worklist.push_back(succ);
                }
            }
        }
    }

    let block_entry_frames: BTreeMap<u32, FrameState> = block_entry
        .into_iter()
        .filter_map(|(bid, state): (BlockId, FrameState)| {
            cfg.blocks
                .iter()
                .find(|b| b.id == bid)
                .map(|b| (b.start_pc, state))
        })
        .collect();

    FrameInferReport {
        outcome,
        block_entry_frames,
        modeled_instructions: modeled,
        total_instructions: total,
        first_unmodeled,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::bytecode::{CodeAttribute, disassemble};
    use crate::decompile_struct::build_cfg;
    use crate::descriptor::JavaType;

    fn code_attr(code: Vec<u8>) -> CodeAttribute {
        CodeAttribute {
            max_stack: 16,
            max_locals: 16,
            code,
            exception_table: Vec::new(),
            dropped_exception_entries: 0,
        }
    }

    #[test]
    fn straight_line_iadd_converges() {
        let code: Vec<u8> = vec![0x03, 0x04, 0x60, 0xAC];
        let insns: Vec<Instruction> = disassemble(&code).unwrap();
        let attr: CodeAttribute = code_attr(code);
        let cfg: Cfg = build_cfg(&insns, &attr, |_| None).unwrap();
        let desc: MethodDescriptor = MethodDescriptor {
            params: Vec::new(),
            returns: JavaType::Int,
        };
        let report: FrameInferReport = infer_frames(
            &cfg,
            &insns,
            &desc,
            true,
            false,
            "Sample",
            &|_| None,
            &|_| None,
            &|_| None,
            &|_| None,
        );
        assert_eq!(report.outcome, FrameInferOutcome::Converged);
        assert!(report.coverage() > 0.99);
        assert_eq!(report.modeled_instructions, report.total_instructions);
    }

    #[test]
    fn branch_join_propagates_entry_local() {
        let code: Vec<u8> = vec![0x1B, 0x99, 0x00, 0x04, 0x04, 0xAC, 0x05, 0xAC];
        let insns: Vec<Instruction> = disassemble(&code).unwrap();
        let attr: CodeAttribute = code_attr(code);
        let cfg: Cfg = build_cfg(&insns, &attr, |_| None).unwrap();
        let desc: MethodDescriptor = MethodDescriptor {
            params: vec![JavaType::Int],
            returns: JavaType::Int,
        };
        let report: FrameInferReport = infer_frames(
            &cfg,
            &insns,
            &desc,
            true,
            false,
            "Sample",
            &|_| None,
            &|_| None,
            &|_| None,
            &|_| None,
        );
        assert_eq!(report.outcome, FrameInferOutcome::Converged);
        let entry: &FrameState = report.block_entry_frames.get(&0).unwrap();
        assert_eq!(entry.locals.first(), Some(&VerificationType::Integer));
    }

    #[test]
    fn getstatic_pushes_field_type() {
        let code: Vec<u8> = vec![0xB2, 0x00, 0x05, 0x57, 0xB1];
        let insns: Vec<Instruction> = disassemble(&code).unwrap();
        let attr: CodeAttribute = code_attr(code);
        let cfg: Cfg = build_cfg(&insns, &attr, |_| None).unwrap();
        let desc: MethodDescriptor = MethodDescriptor {
            params: Vec::new(),
            returns: JavaType::Void,
        };
        let report: FrameInferReport = infer_frames(
            &cfg,
            &insns,
            &desc,
            true,
            false,
            "Sample",
            &|idx: u16| (idx == 5).then(|| "Ljava/io/PrintStream;".to_owned()),
            &|_| None,
            &|_| None,
            &|_| None,
        );
        assert_eq!(report.outcome, FrameInferOutcome::Converged);
        assert_eq!(report.modeled_instructions, report.total_instructions);
    }
}
