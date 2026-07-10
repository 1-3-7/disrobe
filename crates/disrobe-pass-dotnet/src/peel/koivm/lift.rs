use std::collections::{BTreeMap, BTreeSet};

use super::descriptors::KoiDescriptors;
use super::disasm::{KoiBlock, KoiInstr, KoiInstrOperand, KoiMethodDisasm};
use super::koistream::KoiStream;
use super::opcodes::{KoiOp, KoiReg};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftedOp {
    LoadArg(u32),
    LoadLocal(u32),
    StoreArg(u32),
    StoreLocal(u32),
    LoadConstI32(i32),
    LoadConstI64(i64),
    Binary(BinOp),
    Compare(CmpOp),
    BranchTrue(u32),
    BranchFalse(u32),
    Branch(u32),
    Switch,
    Call(u32),
    VirtualCall(&'static str),
    LoadField(u32),
    StoreField(u32),
    LoadString(u32),
    LoadToken(u32),
    Convert(ConvKind),
    Throw,
    EnterProtectedRegion,
    Return,
    Unknown(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvKind {
    SignExtendByte,
    SignExtendWord,
    SignExtendDword,
    FloatToFloat32,
    FloatToFloat64,
    IntToFloat32,
    IntToFloat64,
    IntToPointer,
    IntToInt64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Shl,
    Shr,
    Nor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Equal,
    Less,
    Greater,
    LessOrEqual,
    GreaterOrEqual,
    NotEqual,
    Raw,
}

#[derive(Debug, Clone)]
pub struct LiftedMethod {
    pub arg_count: u32,
    pub local_count: u32,
    pub ops: Vec<LiftedOp>,
    pub unknown_op_count: u32,
}

impl LiftedMethod {
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        self.ops
            .iter()
            .enumerate()
            .map(|(i, op): (usize, &LiftedOp)| format!("IL_{i:04} {}", render_op(op)))
            .collect()
    }
}

fn render_op(op: &LiftedOp) -> String {
    match op {
        LiftedOp::LoadArg(i) => format!("ldarg {i}"),
        LiftedOp::LoadLocal(i) => format!("ldloc {i}"),
        LiftedOp::StoreArg(i) => format!("starg {i}"),
        LiftedOp::StoreLocal(i) => format!("stloc {i}"),
        LiftedOp::LoadConstI32(v) => format!("ldc.i4 {v}"),
        LiftedOp::LoadConstI64(v) => format!("ldc.i8 {v}"),
        LiftedOp::Binary(b) => render_binop(*b).to_string(),
        LiftedOp::Compare(c) => format!("cmp.{}", render_cmpop(*c)),
        LiftedOp::BranchTrue(t) => format!("brtrue IL_{t:04}"),
        LiftedOp::BranchFalse(t) => format!("brfalse IL_{t:04}"),
        LiftedOp::Branch(t) => format!("br IL_{t:04}"),
        LiftedOp::Switch => "switch".to_string(),
        LiftedOp::Call(t) => format!("call token#{t:08X}"),
        LiftedOp::VirtualCall(name) => format!("vcall {name}"),
        LiftedOp::LoadField(t) => format!("ldfld member#{t:08X}"),
        LiftedOp::StoreField(t) => format!("stfld member#{t:08X}"),
        LiftedOp::LoadString(k) => format!("ldstr string#{k:08X}"),
        LiftedOp::LoadToken(t) => format!("ldtoken token#{t:08X}"),
        LiftedOp::Convert(k) => format!("conv.{}", render_conv(*k)),
        LiftedOp::Throw => "throw".to_string(),
        LiftedOp::EnterProtectedRegion => "try".to_string(),
        LiftedOp::Return => "ret".to_string(),
        LiftedOp::Unknown(tag) => format!("unknown.{tag}"),
    }
}

const fn render_binop(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::Div => "div",
        BinOp::Rem => "rem",
        BinOp::Shl => "shl",
        BinOp::Shr => "shr",
        BinOp::Nor => "nor",
    }
}

const fn render_cmpop(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Equal => "eq",
        CmpOp::Less => "lt",
        CmpOp::Greater => "gt",
        CmpOp::LessOrEqual => "le",
        CmpOp::GreaterOrEqual => "ge",
        CmpOp::NotEqual => "ne",
        CmpOp::Raw => "raw",
    }
}

const fn render_conv(kind: ConvKind) -> &'static str {
    match kind {
        ConvKind::SignExtendByte => "i1",
        ConvKind::SignExtendWord => "i2",
        ConvKind::SignExtendDword => "i4",
        ConvKind::FloatToFloat32 => "r4",
        ConvKind::FloatToFloat64 => "r8",
        ConvKind::IntToFloat32 => "r4.un",
        ConvKind::IntToFloat64 => "r8.un",
        ConvKind::IntToPointer => "ptr",
        ConvKind::IntToInt64 => "i8",
    }
}

#[derive(Debug, Clone)]
enum Value {
    Arg(u32),
    Local(u32),
    ConstI32(i32),
    ConstI64,
    FrameAddr(i32),
    Register,
    BpRel,
    CodeAddr,
    Computed,
    Flags,
}

#[derive(Debug, Clone, Copy)]
pub struct FrameLayout {
    pub arg_count: u32,
    pub local_count: u32,
}

impl FrameLayout {
    const fn classify(self, slot: i32) -> Value {
        if slot < 0 {
            let arg_base: i32 = -(self.arg_count.cast_signed() + 1);
            let index: i32 = slot - arg_base;
            if index >= 0 && index.cast_unsigned() < self.arg_count {
                return Value::Arg(index.cast_unsigned());
            }
        } else if slot > 0 {
            let local_index: i32 = slot - 1;
            if local_index >= 0 {
                return Value::Local(local_index.cast_unsigned());
            }
        }
        Value::FrameAddr(slot)
    }
}

pub fn infer_frame_layout(disasm: &KoiMethodDisasm, declared_args: u32) -> FrameLayout {
    let mut max_local: i32 = -1;
    for block in &disasm.blocks {
        let mut window: Vec<&KoiInstr> = Vec::new();
        for ins in &block.instrs {
            window.push(ins);
            if window.len() > 4 {
                window.remove(0);
            }
            if matches!(
                ins.op,
                KoiOp::LindDword | KoiOp::SindDword | KoiOp::LindQword | KoiOp::SindQword
            ) && let Some(slot) = frame_slot_from_window(&window)
                && slot > 0
            {
                max_local = max_local.max(slot - 1);
            }
        }
    }
    FrameLayout {
        arg_count: declared_args,
        local_count: u32::try_from(max_local + 1).unwrap_or(0),
    }
}

fn frame_slot_from_window(window: &[&KoiInstr]) -> Option<i32> {
    if window.len() < 4 {
        return None;
    }
    let n: usize = window.len();
    let pushr_bp: &KoiInstr = window[n - 4];
    let pushi: &KoiInstr = window[n - 3];
    let add: &KoiInstr = window[n - 2];
    if !matches!(pushr_bp.operand, KoiInstrOperand::Register(KoiReg::Bp)) {
        return None;
    }
    if !matches!(add.op, KoiOp::AddDword) {
        return None;
    }
    match pushi.operand {
        KoiInstrOperand::ImmU32(v) => Some(v.cast_signed()),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
struct LiftCtx<'a> {
    descriptors: &'a KoiDescriptors,
    stream: &'a KoiStream,
}

pub fn lift_method(
    disasm: &KoiMethodDisasm,
    declared_args: u32,
    descriptors: &KoiDescriptors,
    stream: &KoiStream,
) -> LiftedMethod {
    let layout: FrameLayout = infer_frame_layout(disasm, declared_args);
    let ctx: LiftCtx<'_> = LiftCtx {
        descriptors,
        stream,
    };
    let body_blocks: Vec<&KoiBlock> = order_body_blocks(disasm);
    let known_entries: BTreeSet<u32> = body_blocks
        .iter()
        .map(|block: &&KoiBlock| block.entry_offset)
        .collect();
    let epilogue_entries: BTreeSet<u32> = disasm
        .blocks
        .iter()
        .filter(|block: &&KoiBlock| is_epilogue(block))
        .map(|block: &KoiBlock| block.entry_offset)
        .collect();
    let mut block_ops: Vec<(u32, Vec<LiftedOp>)> = Vec::with_capacity(body_blocks.len());

    for (index, block) in body_blocks.iter().enumerate() {
        let next_entry: Option<u32> = body_blocks
            .get(index + 1)
            .map(|next: &&KoiBlock| next.entry_offset);
        let mut lifted: Vec<LiftedOp> = Vec::new();
        lift_block(
            block,
            layout,
            ctx,
            next_entry,
            &known_entries,
            &epilogue_entries,
            &mut lifted,
        );
        block_ops.push((block.entry_offset, lifted));
    }

    let (mut ops, block_starts): (Vec<LiftedOp>, BTreeMap<u32, u32>) = flatten_block_ops(block_ops);
    rebase_branch_targets(&mut ops, &block_starts);
    let explicit_unresolved: usize = ops
        .iter()
        .filter(|op: &&LiftedOp| matches!(op, LiftedOp::Unknown("branch-target")))
        .count();
    let missing_markers: usize = disasm
        .unresolved_offsets
        .len()
        .saturating_sub(explicit_unresolved);
    ops.extend((0..missing_markers).map(|_index: usize| LiftedOp::Unknown("branch-target")));

    let unknown_op_count: u32 = ops
        .iter()
        .filter(|o: &&LiftedOp| matches!(o, LiftedOp::Unknown(_)))
        .count()
        .try_into()
        .unwrap_or(u32::MAX);

    LiftedMethod {
        arg_count: layout.arg_count,
        local_count: layout.local_count,
        ops,
        unknown_op_count,
    }
}

fn flatten_block_ops(block_ops: Vec<(u32, Vec<LiftedOp>)>) -> (Vec<LiftedOp>, BTreeMap<u32, u32>) {
    let mut block_starts: BTreeMap<u32, u32> = BTreeMap::new();
    let mut ops: Vec<LiftedOp> = Vec::new();
    for (entry_offset, lifted) in block_ops {
        if let Ok(start) = u32::try_from(ops.len()) {
            block_starts.insert(entry_offset, start);
        }
        ops.extend(lifted);
    }
    block_starts.retain(|_entry: &u32, start: &mut u32| {
        usize::try_from(*start).is_ok_and(|index: usize| index < ops.len())
    });
    (ops, block_starts)
}

fn order_body_blocks(disasm: &KoiMethodDisasm) -> Vec<&KoiBlock> {
    let epilogue_entries: BTreeSet<u32> = disasm
        .blocks
        .iter()
        .filter(|block: &&KoiBlock| is_epilogue(block))
        .map(|block: &KoiBlock| block.entry_offset)
        .collect();
    let conditional_epilogues: BTreeSet<u32> = disasm
        .blocks
        .iter()
        .filter_map(|block: &KoiBlock| {
            let terminal: &KoiInstr = block.instrs.last()?;
            if matches!(terminal.op, KoiOp::Jz | KoiOp::Jnz) {
                terminal.rel_target
            } else {
                None
            }
        })
        .filter(|target: &u32| epilogue_entries.contains(target))
        .collect();
    let retained: BTreeMap<u32, &KoiBlock> = disasm
        .blocks
        .iter()
        .filter(|block: &&KoiBlock| {
            !is_prologue(block)
                && (!epilogue_entries.contains(&block.entry_offset)
                    || conditional_epilogues.contains(&block.entry_offset))
        })
        .map(|block: &KoiBlock| (block.entry_offset, block))
        .collect();
    let entry: Option<u32> = disasm
        .blocks
        .iter()
        .find(|block: &&KoiBlock| is_prologue(block))
        .and_then(|block: &KoiBlock| block.instrs.last())
        .and_then(|terminal: &KoiInstr| terminal.rel_target)
        .filter(|target: &u32| retained.contains_key(target))
        .or_else(|| retained.keys().next().copied());
    let mut ordered: Vec<&KoiBlock> = Vec::with_capacity(retained.len());
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut pending: Vec<u32> = entry.into_iter().collect();

    while ordered.len() < retained.len() {
        let Some(start): Option<u32> = pending.pop().or_else(|| {
            retained
                .keys()
                .find(|offset: &&u32| !visited.contains(offset))
                .copied()
        }) else {
            break;
        };
        let mut current: Option<u32> = Some(start);
        while let Some(offset) = current {
            if !visited.insert(offset) {
                break;
            }
            let Some(block): Option<&&KoiBlock> = retained.get(&offset) else {
                break;
            };
            ordered.push(*block);
            let Some(terminal): Option<&KoiInstr> = block.instrs.last() else {
                break;
            };
            current = match terminal.op {
                KoiOp::Jz | KoiOp::Jnz => {
                    if let Some(target) = terminal.rel_target
                        && retained.contains_key(&target)
                        && !visited.contains(&target)
                    {
                        pending.push(target);
                    }
                    block
                        .fallthrough_offset
                        .filter(|target: &u32| retained.contains_key(target))
                }
                KoiOp::Jmp => terminal
                    .rel_target
                    .filter(|target: &u32| retained.contains_key(target)),
                _ => None,
            };
        }
    }
    ordered
}

fn rebase_branch_targets(ops: &mut [LiftedOp], block_starts: &BTreeMap<u32, u32>) {
    for op in ops {
        let raw_target: Option<u32> = match op {
            LiftedOp::BranchTrue(target)
            | LiftedOp::BranchFalse(target)
            | LiftedOp::Branch(target) => Some(*target),
            _ => None,
        };
        let Some(raw_target) = raw_target else {
            continue;
        };
        let Some(lifted_target): Option<&u32> = block_starts.get(&raw_target) else {
            *op = LiftedOp::Unknown("branch-target");
            continue;
        };
        match op {
            LiftedOp::BranchTrue(target)
            | LiftedOp::BranchFalse(target)
            | LiftedOp::Branch(target) => *target = *lifted_target,
            _ => {}
        }
    }
}

fn is_prologue(block: &KoiBlock) -> bool {
    let has_bp_sp: bool = block.instrs.windows(3).any(|w: &[KoiInstr]| {
        matches!(w[0].operand, KoiInstrOperand::Register(KoiReg::Bp))
            && matches!(w[1].operand, KoiInstrOperand::Register(KoiReg::Sp))
            && matches!(w[2].op, KoiOp::Pop)
            && matches!(w[2].operand, KoiInstrOperand::Register(KoiReg::Bp))
    });
    let has_jmp: bool = block
        .instrs
        .iter()
        .any(|i: &KoiInstr| matches!(i.op, KoiOp::Jmp));
    has_bp_sp && has_jmp
}

fn is_epilogue(block: &KoiBlock) -> bool {
    let Some(tail): Option<&[KoiInstr]> = block.instrs.get(block.instrs.len().saturating_sub(4)..)
    else {
        return false;
    };
    matches!(
        tail,
        [
            KoiInstr {
                op: KoiOp::PushrDword,
                operand: KoiInstrOperand::Register(KoiReg::Bp),
                ..
            },
            KoiInstr {
                op: KoiOp::Pop,
                operand: KoiInstrOperand::Register(KoiReg::Sp),
                ..
            },
            KoiInstr {
                op: KoiOp::Pop,
                operand: KoiInstrOperand::Register(KoiReg::Bp),
                ..
            },
            KoiInstr { op: KoiOp::Ret, .. },
        ]
    )
}

fn lift_block(
    block: &KoiBlock,
    layout: FrameLayout,
    ctx: LiftCtx<'_>,
    next_entry: Option<u32>,
    known_entries: &BTreeSet<u32>,
    epilogue_entries: &BTreeSet<u32>,
    out: &mut Vec<LiftedOp>,
) {
    let mut stack: Vec<Value> = Vec::new();
    let mut regs: BTreeMap<KoiReg, Value> = BTreeMap::new();
    let mut last_cmp: Option<CmpOp> = None;
    let instrs: &[KoiInstr] = &block.instrs;
    let mut i: usize = 0;

    while i < instrs.len() {
        let ins: &KoiInstr = &instrs[i];
        match ins.op {
            KoiOp::PushiDword => {
                if let KoiInstrOperand::ImmU32(v) = ins.operand {
                    stack.push(Value::ConstI32(v.cast_signed()));
                }
            }
            KoiOp::PushiQword => {
                if matches!(ins.operand, KoiInstrOperand::ImmU64(_)) {
                    stack.push(Value::ConstI64);
                }
            }
            KoiOp::PushrDword | KoiOp::PushrQword | KoiOp::PushrObject => match ins.operand {
                KoiInstrOperand::Register(KoiReg::Bp) => stack.push(Value::BpRel),
                KoiInstrOperand::Register(KoiReg::Fl) => stack.push(Value::Flags),
                KoiInstrOperand::Register(KoiReg::Sp | KoiReg::Ip) => stack.push(Value::CodeAddr),
                KoiInstrOperand::Register(r) => {
                    let value: Value = regs.get(&r).cloned().unwrap_or(Value::Register);
                    stack.push(value);
                }
                _ => stack.push(Value::Computed),
            },
            KoiOp::AddDword | KoiOp::AddQword | KoiOp::AddR32 | KoiOp::AddR64 => {
                lift_add(&mut stack, out);
            }
            KoiOp::SubR32 | KoiOp::SubR64 => apply_binary(&mut stack, BinOp::Sub, out),
            KoiOp::MulDword | KoiOp::MulQword | KoiOp::MulR32 | KoiOp::MulR64 => {
                apply_binary(&mut stack, BinOp::Mul, out);
            }
            KoiOp::DivDword | KoiOp::DivQword | KoiOp::DivR32 | KoiOp::DivR64 => {
                apply_binary(&mut stack, BinOp::Div, out);
            }
            KoiOp::RemDword | KoiOp::RemQword | KoiOp::RemR32 | KoiOp::RemR64 => {
                apply_binary(&mut stack, BinOp::Rem, out);
            }
            KoiOp::ShlDword | KoiOp::ShlQword => apply_binary(&mut stack, BinOp::Shl, out),
            KoiOp::ShrDword | KoiOp::ShrQword => apply_binary(&mut stack, BinOp::Shr, out),
            KoiOp::NorDword | KoiOp::NorQword => {
                let _ = stack.pop();
                let _ = stack.pop();
                stack.push(Value::Computed);
            }
            KoiOp::LindDword | KoiOp::LindQword | KoiOp::LindByte | KoiOp::LindWord => {
                let addr: Option<Value> = stack.pop();
                match addr {
                    Some(Value::FrameAddr(slot)) => {
                        emit_load(layout, slot, out);
                        stack.push(Value::Computed);
                    }
                    _ => stack.push(Value::Computed),
                }
            }
            KoiOp::SindDword | KoiOp::SindQword | KoiOp::SindByte | KoiOp::SindWord => {
                let addr: Option<Value> = stack.pop();
                let _value: Option<Value> = stack.pop();
                if let Some(Value::FrameAddr(slot)) = addr {
                    emit_store(layout, slot, out);
                }
            }
            KoiOp::Pop => {
                let value: Value = stack.pop().unwrap_or(Value::Computed);
                if let KoiInstrOperand::Register(r) = ins.operand
                    && !matches!(r, KoiReg::Sp | KoiReg::Bp | KoiReg::Ip)
                {
                    regs.insert(r, value);
                }
            }
            KoiOp::Cmp | KoiOp::CmpDword | KoiOp::CmpQword | KoiOp::CmpR32 | KoiOp::CmpR64 => {
                let _b: Option<Value> = stack.pop();
                let _a: Option<Value> = stack.pop();
                last_cmp = Some(infer_cmp(instrs, i));
                stack.push(Value::Flags);
            }
            KoiOp::Jz => {
                if let Some(cmp) = last_cmp {
                    out.push(LiftedOp::Compare(cmp));
                }
                if let Some(target) = ins.rel_target
                    && known_entries.contains(&target)
                {
                    out.push(LiftedOp::BranchFalse(target));
                } else {
                    out.push(LiftedOp::Unknown("branch-target"));
                }
                emit_nonadjacent_fallthrough(
                    block,
                    next_entry,
                    known_entries,
                    epilogue_entries,
                    out,
                );
            }
            KoiOp::Jnz => {
                if let Some(cmp) = last_cmp {
                    out.push(LiftedOp::Compare(cmp));
                }
                if let Some(target) = ins.rel_target
                    && known_entries.contains(&target)
                {
                    out.push(LiftedOp::BranchTrue(target));
                } else {
                    out.push(LiftedOp::Unknown("branch-target"));
                }
                emit_nonadjacent_fallthrough(
                    block,
                    next_entry,
                    known_entries,
                    epilogue_entries,
                    out,
                );
            }
            KoiOp::Jmp => match ins.rel_target {
                Some(target) if epilogue_entries.contains(&target) => {
                    out.push(LiftedOp::Return);
                }
                Some(target) if Some(target) == next_entry => {}
                Some(target) if known_entries.contains(&target) => {
                    out.push(LiftedOp::Branch(target));
                }
                _ => out.push(LiftedOp::Unknown("branch-target")),
            },
            KoiOp::SxByte => emit_convert(&mut stack, ConvKind::SignExtendByte, out),
            KoiOp::SxWord => emit_convert(&mut stack, ConvKind::SignExtendWord, out),
            KoiOp::SxDword => emit_convert(&mut stack, ConvKind::SignExtendDword, out),
            KoiOp::FconvR32R64 => emit_convert(&mut stack, ConvKind::FloatToFloat64, out),
            KoiOp::FconvR64R32 => emit_convert(&mut stack, ConvKind::FloatToFloat32, out),
            KoiOp::FconvR32 => emit_convert(&mut stack, ConvKind::IntToFloat32, out),
            KoiOp::FconvR64 => emit_convert(&mut stack, ConvKind::IntToFloat64, out),
            KoiOp::IconvPtr => emit_convert(&mut stack, ConvKind::IntToPointer, out),
            KoiOp::IconvR64 => emit_convert(&mut stack, ConvKind::IntToInt64, out),
            KoiOp::Call => {
                let token: Option<u32> = resolve_ref_token(ctx, stack.pop());
                out.push(LiftedOp::Call(token.unwrap_or(0)));
                stack.push(Value::Computed);
            }
            KoiOp::Vcall => emit_vcall(ctx, &mut stack, out),
            KoiOp::Swt => {
                let _ = stack.pop();
                out.push(LiftedOp::Switch);
            }
            KoiOp::Try => out.push(LiftedOp::EnterProtectedRegion),
            KoiOp::Ret | KoiOp::Leave => out.push(LiftedOp::Return),
            KoiOp::Nop => {}
            KoiOp::LindPtr | KoiOp::LindObject => {
                let _ = stack.pop();
                stack.push(Value::Computed);
            }
            KoiOp::SindPtr | KoiOp::SindObject => {
                let _ = stack.pop();
                let _ = stack.pop();
            }
            KoiOp::PushrByte | KoiOp::PushrWord => match ins.operand {
                KoiInstrOperand::Register(KoiReg::Fl) => stack.push(Value::Flags),
                KoiInstrOperand::Register(r) => {
                    let value: Value = regs.get(&r).cloned().unwrap_or(Value::Register);
                    stack.push(value);
                }
                _ => stack.push(Value::Computed),
            },
        }
        i += 1;
    }
}

fn emit_nonadjacent_fallthrough(
    block: &KoiBlock,
    next_entry: Option<u32>,
    known_entries: &BTreeSet<u32>,
    epilogue_entries: &BTreeSet<u32>,
    out: &mut Vec<LiftedOp>,
) {
    match block.fallthrough_offset {
        Some(target) if Some(target) == next_entry => {}
        Some(target) if epilogue_entries.contains(&target) => out.push(LiftedOp::Return),
        Some(target) if known_entries.contains(&target) => out.push(LiftedOp::Branch(target)),
        _ => out.push(LiftedOp::Unknown("branch-target")),
    }
}

fn is_address_math(stack: &[Value]) -> bool {
    let len: usize = stack.len();
    if len < 2 {
        return false;
    }
    matches!(stack[len - 1], Value::CodeAddr) || matches!(stack[len - 2], Value::CodeAddr)
}

fn try_frame_address(stack: &mut Vec<Value>) -> bool {
    let len: usize = stack.len();
    if len < 2 {
        return false;
    }
    let top: &Value = &stack[len - 1];
    let below: &Value = &stack[len - 2];
    let (base_is_bp, slot): (bool, i32) = match (below, top) {
        (Value::BpRel, Value::ConstI32(k)) => (true, *k),
        _ => (false, 0),
    };
    if base_is_bp {
        stack.pop();
        stack.pop();
        stack.push(Value::FrameAddr(slot));
        return true;
    }
    false
}

fn apply_binary(stack: &mut Vec<Value>, op: BinOp, out: &mut Vec<LiftedOp>) {
    let _b: Option<Value> = stack.pop();
    let _a: Option<Value> = stack.pop();
    out.push(LiftedOp::Binary(op));
    stack.push(Value::Computed);
}

fn lift_add(stack: &mut Vec<Value>, out: &mut Vec<LiftedOp>) {
    if try_frame_address(stack) {
        return;
    }
    if is_address_math(stack) {
        let _ = stack.pop();
        let _ = stack.pop();
        stack.push(Value::CodeAddr);
        return;
    }
    apply_binary(stack, BinOp::Add, out);
}

fn emit_load(layout: FrameLayout, slot: i32, out: &mut Vec<LiftedOp>) {
    match layout.classify(slot) {
        Value::Arg(index) => out.push(LiftedOp::LoadArg(index)),
        Value::Local(index) => out.push(LiftedOp::LoadLocal(index)),
        _ => out.push(LiftedOp::Unknown("load")),
    }
}

fn emit_store(layout: FrameLayout, slot: i32, out: &mut Vec<LiftedOp>) {
    match layout.classify(slot) {
        Value::Arg(index) => out.push(LiftedOp::StoreArg(index)),
        Value::Local(index) => out.push(LiftedOp::StoreLocal(index)),
        _ => out.push(LiftedOp::Unknown("store")),
    }
}

fn emit_convert(stack: &mut Vec<Value>, kind: ConvKind, out: &mut Vec<LiftedOp>) {
    let _ = stack.pop();
    out.push(LiftedOp::Convert(kind));
    stack.push(Value::Computed);
}

const fn const_key(value: &Value) -> Option<u32> {
    match value {
        Value::ConstI32(k) => Some(k.cast_unsigned()),
        _ => None,
    }
}

fn resolve_ref_token(ctx: LiftCtx<'_>, top: Option<Value>) -> Option<u32> {
    let key: u32 = const_key(&top?)?;
    ctx.stream
        .ref_map
        .get(&key)
        .map(|t: &super::koistream::CodedToken| t.metadata_token())
        .or(Some(key))
}

fn emit_vcall(ctx: LiftCtx<'_>, stack: &mut Vec<Value>, out: &mut Vec<LiftedOp>) {
    let code_value: Option<Value> = stack.pop();
    let code: Option<u32> = code_value.as_ref().and_then(const_key);
    let name: Option<&'static str> = code.and_then(|c: u32| ctx.descriptors.vcall_name(c));
    match name {
        Some("LDFLD") => {
            let token: Option<u32> = resolve_ref_token(ctx, stack.pop());
            out.push(LiftedOp::LoadField(token.unwrap_or(0)));
            stack.push(Value::Computed);
        }
        Some("STFLD") => {
            let token: Option<u32> = resolve_ref_token(ctx, stack.pop());
            let _ = stack.pop();
            out.push(LiftedOp::StoreField(token.unwrap_or(0)));
        }
        Some("TOKEN") => {
            let operand: Option<Value> = stack.pop();
            let key: Option<u32> = operand.as_ref().and_then(const_key);
            match key {
                Some(k) if ctx.stream.str_map.contains_key(&k) => {
                    out.push(LiftedOp::LoadString(k));
                }
                Some(k) => {
                    let token: u32 = ctx
                        .stream
                        .ref_map
                        .get(&k)
                        .map_or(k, |t: &super::koistream::CodedToken| t.metadata_token());
                    out.push(LiftedOp::LoadToken(token));
                }
                None => out.push(LiftedOp::Unknown("VCALL")),
            }
            stack.push(Value::Computed);
        }
        Some("THROW") => {
            let _ = stack.pop();
            out.push(LiftedOp::Throw);
        }
        Some(other) => {
            out.push(LiftedOp::VirtualCall(vcall_static_name(other)));
            stack.push(Value::Computed);
        }
        None => out.push(LiftedOp::Unknown("VCALL")),
    }
}

const fn vcall_static_name(name: &str) -> &'static str {
    match name.as_bytes() {
        b"EXIT" => "EXIT",
        b"BREAK" => "BREAK",
        b"ECALL" => "ECALL",
        b"CAST" => "CAST",
        b"CKFINITE" => "CKFINITE",
        b"CKOVERFLOW" => "CKOVERFLOW",
        b"RANGECHK" => "RANGECHK",
        b"INITOBJ" => "INITOBJ",
        b"LDFTN" => "LDFTN",
        b"SIZEOF" => "SIZEOF",
        b"BOX" => "BOX",
        b"UNBOX" => "UNBOX",
        b"LOCALLOC" => "LOCALLOC",
        _ => "VCALL",
    }
}

fn infer_cmp(instrs: &[KoiInstr], cmp_index: usize) -> CmpOp {
    let mut mask: Option<i32> = None;
    let end: usize = (cmp_index + 12).min(instrs.len());
    for ins in &instrs[cmp_index + 1..end] {
        if matches!(ins.op, KoiOp::PushiDword)
            && let KoiInstrOperand::ImmU32(v) = ins.operand
        {
            let value: i32 = v.cast_signed();
            if value == 0x80 || value == 0x40 || value == 0x01 || value == 137 || value == 9 {
                mask = Some(value);
                break;
            }
        }
        if matches!(ins.op, KoiOp::Jz | KoiOp::Jnz) {
            break;
        }
    }
    match mask {
        Some(0x80) => CmpOp::GreaterOrEqual,
        Some(0x40) => CmpOp::NotEqual,
        Some(137) => CmpOp::LessOrEqual,
        Some(9) => CmpOp::Greater,
        Some(0x01) => CmpOp::Less,
        _ => CmpOp::Raw,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::descriptors::KoiDescriptors;
    use super::super::disasm::disassemble_method;
    use super::super::koistream::{KoiSig, KoiStream, parse_koistream};
    use super::*;

    fn lift_sig(id: u32, args: u32) -> LiftedMethod {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.koistream.bin");
        let bytes: Vec<u8> = std::fs::read(path).unwrap();
        let stream: KoiStream = parse_koistream(&bytes).unwrap();
        let descriptors: KoiDescriptors = KoiDescriptors::from_seed(0);
        let sig: &KoiSig = stream.sig_by_id(id).unwrap();
        let disasm: KoiMethodDisasm =
            disassemble_method(&stream.raw, sig.entry_offset, sig.entry_key, &descriptors).unwrap();
        lift_method(&disasm, args, &descriptors, &stream)
    }

    #[test]
    fn add_lifts_to_two_loads_and_add() {
        let m: LiftedMethod = lift_sig(2, 2);
        assert_eq!(m.arg_count, 2);
        let loads: usize = m
            .ops
            .iter()
            .filter(|o: &&LiftedOp| matches!(o, LiftedOp::LoadArg(_)))
            .count();
        assert_eq!(loads, 2, "Add reads two args; got {:?}", m.ops);
        assert!(
            m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::Binary(BinOp::Add))),
            "Add must have an add binop; got {:?}",
            m.ops
        );
        assert!(
            m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::Return))
        );
    }

    #[test]
    fn square_lifts_to_multiply() {
        let m: LiftedMethod = lift_sig(3, 1);
        assert!(
            m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::Binary(BinOp::Mul))),
            "Square must multiply; got {:?}",
            m.ops
        );
    }

    #[test]
    fn sumto_recovers_locals_and_loop_store() {
        let m: LiftedMethod = lift_sig(4, 1);
        assert_eq!(m.arg_count, 1);
        assert!(
            m.local_count >= 2,
            "SumTo has two locals; got {}",
            m.local_count
        );
        assert!(
            m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::StoreLocal(_))),
            "SumTo writes locals; got {:?}",
            m.ops
        );
        assert!(
            m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::Binary(BinOp::Add))),
            "SumTo accumulates with add"
        );
    }

    #[test]
    fn factorial_recovers_multiply_and_branch() {
        let m: LiftedMethod = lift_sig(6, 1);
        assert!(
            m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::Binary(BinOp::Mul))),
            "Factorial multiplies; got {:?}",
            m.ops
        );
        assert!(
            m.ops.iter().any(|o: &LiftedOp| matches!(
                o,
                LiftedOp::BranchTrue(_) | LiftedOp::BranchFalse(_)
            )),
            "Factorial loop has a conditional branch"
        );
    }

    #[test]
    fn factorial_sign_extends_no_longer_silently_dropped() {
        let m: LiftedMethod = lift_sig(6, 1);
        assert!(
            m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::Convert(ConvKind::SignExtendDword))),
            "Factorial's conv.i8 must lift to a Convert op, not vanish; got {:?}",
            m.ops
        );
        assert_eq!(
            m.unknown_op_count, 0,
            "every Factorial op is handled; got {:?}",
            m.ops
        );
    }

    #[test]
    fn all_real_methods_report_zero_unknown_ops() {
        for (id, args) in [(2u32, 2u32), (3, 1), (4, 1), (5, 1), (6, 1), (7, 3)] {
            let m: LiftedMethod = lift_sig(id, args);
            assert_eq!(
                m.unknown_op_count, 0,
                "method id {id} lifted with unhandled ops: {:?}",
                m.ops
            );
        }
    }

    #[test]
    fn missing_or_invalid_real_branch_target_is_marked_unknown() {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.koistream.bin");
        let bytes: Vec<u8> = std::fs::read(path).unwrap();
        let stream: KoiStream = parse_koistream(&bytes).unwrap();
        let descriptors: KoiDescriptors = KoiDescriptors::from_seed(0);
        let sig: &KoiSig = stream.sig_by_id(2).unwrap();
        let disasm: KoiMethodDisasm =
            disassemble_method(&stream.raw, sig.entry_offset, sig.entry_key, &descriptors).unwrap();
        for replacement in [None, Some(u32::MAX)] {
            let mut changed: KoiMethodDisasm = disasm.clone();
            let body: &mut KoiBlock = changed
                .blocks
                .iter_mut()
                .find(|block: &&mut KoiBlock| !is_prologue(block))
                .unwrap();
            let branch: &mut KoiInstr = body.instrs.last_mut().unwrap();
            assert!(matches!(branch.op, KoiOp::Jmp));
            branch.rel_target = replacement;

            let lifted: LiftedMethod = lift_method(&changed, 2, &descriptors, &stream);
            assert!(
                lifted
                    .ops
                    .iter()
                    .any(|op: &LiftedOp| matches!(op, LiftedOp::Unknown("branch-target"))),
                "unresolved branch target must be explicit; got {:?}",
                lifted.ops
            );
        }
    }

    #[test]
    fn empty_transport_block_rebases_to_next_emitted_op() {
        let block_ops: Vec<(u32, Vec<LiftedOp>)> = vec![
            (10, vec![LiftedOp::Branch(20)]),
            (20, Vec::new()),
            (30, vec![LiftedOp::Return]),
        ];
        let (mut ops, starts): (Vec<LiftedOp>, BTreeMap<u32, u32>) = flatten_block_ops(block_ops);
        rebase_branch_targets(&mut ops, &starts);
        assert_eq!(ops, vec![LiftedOp::Branch(1), LiftedOp::Return]);
        assert_eq!(starts.get(&20), Some(&1));
    }

    struct BlockEncoder {
        key: u8,
        bytes: Vec<u8>,
    }

    impl BlockEncoder {
        fn new(entry_key: u8) -> Self {
            Self {
                key: entry_key,
                bytes: Vec::new(),
            }
        }

        fn push_plain(&mut self, plain: u8) {
            let cipher: u8 = plain ^ self.key;
            self.key = self.key.wrapping_mul(7).wrapping_add(plain);
            self.bytes.push(cipher);
        }

        fn instr_none(&mut self, op_byte: u8) {
            self.push_plain(op_byte);
            self.push_plain(0);
        }

        fn instr_reg(&mut self, op_byte: u8, reg_byte: u8) {
            self.push_plain(op_byte);
            self.push_plain(0);
            self.push_plain(reg_byte);
        }

        fn instr_imm(&mut self, op_byte: u8, value: u32) {
            self.push_plain(op_byte);
            self.push_plain(0);
            for b in value.to_le_bytes() {
                self.push_plain(b);
            }
        }
    }

    fn handcrafted_stream() -> (KoiStream, u32, u8) {
        use super::super::koistream::{CodedToken, KoiTable};

        const PUSHR_DWORD: u8 = 245;
        const PUSHI_DWORD: u8 = 231;
        const VCALL: u8 = 43;
        const CALL: u8 = 119;
        const SX_DWORD: u8 = 181;
        const RET: u8 = 229;
        const REG_R0: u8 = 1;
        const VC_LDFLD: u32 = 173;
        const VC_STFLD: u32 = 111;
        const VC_TOKEN: u32 = 28;

        const FIELD_KEY: u32 = 7;
        const METHOD_KEY: u32 = 9;
        const TOKEN_KEY: u32 = 11;
        const STRING_KEY: u32 = 13;

        let entry_key: u8 = 0x5A;
        let mut enc: BlockEncoder = BlockEncoder::new(entry_key);

        enc.instr_reg(PUSHR_DWORD, REG_R0);
        enc.instr_imm(PUSHI_DWORD, FIELD_KEY);
        enc.instr_imm(PUSHI_DWORD, VC_LDFLD);
        enc.instr_none(VCALL);

        enc.instr_none(SX_DWORD);

        enc.instr_reg(PUSHR_DWORD, REG_R0);
        enc.instr_reg(PUSHR_DWORD, REG_R0);
        enc.instr_imm(PUSHI_DWORD, FIELD_KEY);
        enc.instr_imm(PUSHI_DWORD, VC_STFLD);
        enc.instr_none(VCALL);

        enc.instr_imm(PUSHI_DWORD, METHOD_KEY);
        enc.instr_none(CALL);

        enc.instr_imm(PUSHI_DWORD, TOKEN_KEY);
        enc.instr_imm(PUSHI_DWORD, VC_TOKEN);
        enc.instr_none(VCALL);

        enc.instr_imm(PUSHI_DWORD, STRING_KEY);
        enc.instr_imm(PUSHI_DWORD, VC_TOKEN);
        enc.instr_none(VCALL);

        enc.instr_none(RET);

        let mut ref_map: std::collections::BTreeMap<u32, CodedToken> =
            std::collections::BTreeMap::new();
        ref_map.insert(
            FIELD_KEY,
            CodedToken {
                table: KoiTable::Field,
                rid: 4,
            },
        );
        ref_map.insert(
            METHOD_KEY,
            CodedToken {
                table: KoiTable::Method,
                rid: 42,
            },
        );
        ref_map.insert(
            TOKEN_KEY,
            CodedToken {
                table: KoiTable::TypeDef,
                rid: 7,
            },
        );

        let mut str_map: std::collections::BTreeMap<u32, String> =
            std::collections::BTreeMap::new();
        str_map.insert(STRING_KEY, "koivm sample".to_string());

        let stream: KoiStream = KoiStream {
            ref_map,
            str_map,
            sigs: Vec::new(),
            raw: enc.bytes,
        };
        (stream, 0, entry_key)
    }

    #[test]
    fn handcrafted_call_field_token_string_convert_all_lift() {
        use super::super::koistream::{CodedToken, KoiTable};

        let (stream, entry_offset, entry_key): (KoiStream, u32, u8) = handcrafted_stream();
        let descriptors: KoiDescriptors = KoiDescriptors::from_seed(0);
        let disasm: KoiMethodDisasm =
            disassemble_method(&stream.raw, entry_offset, entry_key, &descriptors).unwrap();
        let m: LiftedMethod = lift_method(&disasm, 0, &descriptors, &stream);

        let field_token: u32 = CodedToken {
            table: KoiTable::Field,
            rid: 4,
        }
        .metadata_token();
        let method_token: u32 = CodedToken {
            table: KoiTable::Method,
            rid: 42,
        }
        .metadata_token();
        let type_token: u32 = CodedToken {
            table: KoiTable::TypeDef,
            rid: 7,
        }
        .metadata_token();

        assert!(
            m.ops.contains(&LiftedOp::LoadField(field_token)),
            "ldfld must lift to LoadField({field_token:#x}); got {:?}",
            m.ops
        );
        assert!(
            m.ops.contains(&LiftedOp::StoreField(field_token)),
            "stfld must lift to StoreField; got {:?}",
            m.ops
        );
        assert!(
            m.ops.contains(&LiftedOp::Call(method_token)),
            "call must lift to Call({method_token:#x}); got {:?}",
            m.ops
        );
        assert!(
            m.ops.contains(&LiftedOp::LoadToken(type_token)),
            "ldtoken must lift to LoadToken; got {:?}",
            m.ops
        );
        assert!(
            m.ops.contains(&LiftedOp::LoadString(13)),
            "the user-string token must lift to LoadString; got {:?}",
            m.ops
        );
        assert!(
            m.ops
                .contains(&LiftedOp::Convert(ConvKind::SignExtendDword)),
            "sx.dword must lift to Convert; got {:?}",
            m.ops
        );
        assert!(
            m.ops.contains(&LiftedOp::Return),
            "block must terminate in Return; got {:?}",
            m.ops
        );
        assert_eq!(
            m.unknown_op_count, 0,
            "a fully-handled method must report zero unknown ops; got {:?}",
            m.ops
        );
        assert!(
            !m.ops
                .iter()
                .any(|o: &LiftedOp| matches!(o, LiftedOp::Unknown(_))),
            "no op may fall through to Unknown; got {:?}",
            m.ops
        );
    }

    #[test]
    fn genuinely_unresolvable_vcall_surfaces_unknown_with_count() {
        use super::super::koistream::KoiStream;

        const PUSHI_DWORD: u8 = 231;
        const VCALL: u8 = 43;
        const RET: u8 = 229;

        let entry_key: u8 = 0x11;
        let mut enc: BlockEncoder = BlockEncoder::new(entry_key);
        enc.instr_imm(PUSHI_DWORD, 250);
        enc.instr_none(VCALL);
        enc.instr_none(RET);

        let stream: KoiStream = KoiStream {
            ref_map: std::collections::BTreeMap::new(),
            str_map: std::collections::BTreeMap::new(),
            sigs: Vec::new(),
            raw: enc.bytes,
        };
        let descriptors: KoiDescriptors = KoiDescriptors::from_seed(0);
        let disasm: KoiMethodDisasm =
            disassemble_method(&stream.raw, 0, entry_key, &descriptors).unwrap();
        let m: LiftedMethod = lift_method(&disasm, 0, &descriptors, &stream);

        assert!(
            m.ops.contains(&LiftedOp::Unknown("VCALL")),
            "an unmapped vcall code must surface as Unknown, never silently drop; got {:?}",
            m.ops
        );
        assert_eq!(
            m.unknown_op_count, 1,
            "the unresolved vcall must be counted exactly once; got {:?}",
            m.ops
        );
    }
}
