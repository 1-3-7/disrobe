use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

const MAX_SCAN_INSNS: usize = 200_000;
const MIN_PRINTABLE_RUN: usize = 4;
const MAX_GROUP_SPAN: i64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StackBase {
    Rsp,
    Rbp,
    Esp,
    Ebp,
}

impl StackBase {
    const fn from_register(reg: Register) -> Option<Self> {
        match reg {
            Register::RSP => Some(Self::Rsp),
            Register::RBP => Some(Self::Rbp),
            Register::ESP => Some(Self::Esp),
            Register::EBP => Some(Self::Ebp),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rsp => "rsp",
            Self::Rbp => "rbp",
            Self::Esp => "esp",
            Self::Ebp => "ebp",
        }
    }

    const fn is_64(self) -> bool {
        matches!(self, Self::Rsp | Self::Rbp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReassembledStackString {
    pub first_store: u64,
    pub base: StackBase,
    pub base_displacement: i64,
    pub value: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadOnlyWindow<'a> {
    pub address: u64,
    pub bytes: &'a [u8],
}

impl ReadOnlyWindow<'_> {
    fn read(&self, address: u64, len: usize) -> Option<&[u8]> {
        let start: u64 = address.checked_sub(self.address)?;
        let start: usize = usize::try_from(start).ok()?;
        let end: usize = start.checked_add(len)?;
        self.bytes.get(start..end)
    }
}

#[derive(Debug, Clone, Copy)]
struct ImmStore {
    ip: u64,
    base: StackBase,
    disp: i64,
    bytes: [u8; 16],
    width: usize,
}

#[must_use]
pub fn reassemble_stack_strings(
    bitness: u32,
    base: u64,
    code: &[u8],
) -> Vec<ReassembledStackString> {
    reassemble_stack_strings_with_rodata(bitness, base, code, &[])
}

#[must_use]
pub fn reassemble_stack_strings_with_rodata(
    bitness: u32,
    base: u64,
    code: &[u8],
    rodata: &[ReadOnlyWindow<'_>],
) -> Vec<ReassembledStackString> {
    let stores: Vec<ImmStore> = harvest_stack_stores(bitness, base, code, rodata);
    let groups: BTreeMap<StackBase, Vec<ImmStore>> = group_by_base(stores);
    let mut out: Vec<ReassembledStackString> = Vec::new();
    for (base_reg, mut group) in groups {
        group.sort_by(|a: &ImmStore, b: &ImmStore| a.disp.cmp(&b.disp).then(a.ip.cmp(&b.ip)));
        out.extend(reassemble_group(base_reg, &group));
    }
    out.sort_by(|a: &ReassembledStackString, b: &ReassembledStackString| {
        a.first_store
            .cmp(&b.first_store)
            .then(a.base_displacement.cmp(&b.base_displacement))
            .then(a.value.cmp(&b.value))
    });
    out.dedup();
    out
}

fn harvest_stack_stores(
    bitness: u32,
    base: u64,
    code: &[u8],
    rodata: &[ReadOnlyWindow<'_>],
) -> Vec<ImmStore> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, code, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut out: Vec<ImmStore> = Vec::new();
    let mut xmm: [Option<[u8; 16]>; 32] = [None; 32];
    let mut push_chain: PushChain = PushChain::new(bitness);
    let mut count: usize = 0;
    while decoder.can_decode() {
        if count >= MAX_SCAN_INSNS {
            break;
        }
        count += 1;
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            push_chain.flush_into(&mut out);
            continue;
        }
        track_xmm_literal(&insn, rodata, &mut xmm);
        if let Some(store) = immediate_store(&insn) {
            push_chain.flush_into(&mut out);
            out.push(store);
            continue;
        }
        if let Some(store) = sse_block_store(&insn, &xmm) {
            push_chain.flush_into(&mut out);
            out.push(store);
            continue;
        }
        if let Some(store) = push_chain.absorb(&insn) {
            out.push(store);
            continue;
        }
        if let Some((base_reg, disp, key, op)) = inplace_byte_op(&insn) {
            apply_inplace_op(&mut out, base_reg, disp, key, op);
            continue;
        }
        if breaks_push_chain(&insn) {
            push_chain.flush_into(&mut out);
        }
    }
    push_chain.flush_into(&mut out);
    out
}

#[derive(Debug, Clone, Copy)]
enum ByteOp {
    Xor,
    Add,
    Sub,
}

fn apply_inplace_op(stores: &mut [ImmStore], base: StackBase, disp: i64, key: u8, op: ByteOp) {
    for store in stores.iter_mut() {
        if store.base != base {
            continue;
        }
        let start: i64 = store.disp;
        let end: i64 = store.disp + store.width as i64;
        if disp < start || disp >= end {
            continue;
        }
        let index: usize = (disp - start) as usize;
        let cur: u8 = store.bytes[index];
        store.bytes[index] = match op {
            ByteOp::Xor => cur ^ key,
            ByteOp::Add => cur.wrapping_add(key),
            ByteOp::Sub => cur.wrapping_sub(key),
        };
    }
}

fn inplace_byte_op(insn: &Instruction) -> Option<(StackBase, i64, u8, ByteOp)> {
    let op: ByteOp = match insn.mnemonic() {
        Mnemonic::Xor => ByteOp::Xor,
        Mnemonic::Add => ByteOp::Add,
        Mnemonic::Sub => ByteOp::Sub,
        _ => return None,
    };
    if insn.op0_kind() != OpKind::Memory || insn.memory_index() != Register::None {
        return None;
    }
    if insn.memory_size().size() != 1 {
        return None;
    }
    let base: StackBase = StackBase::from_register(insn.memory_base())?;
    let key: u8 = match insn.op1_kind() {
        OpKind::Immediate8 => insn.immediate8(),
        OpKind::Immediate8to16 => insn.immediate8to16().cast_unsigned() as u8,
        OpKind::Immediate8to32 => insn.immediate8to32().cast_unsigned() as u8,
        OpKind::Immediate8to64 => insn.immediate8to64().cast_unsigned() as u8,
        _ => return None,
    };
    let disp: i64 = insn.memory_displacement64().cast_signed();
    Some((base, disp, key, op))
}

fn track_xmm_literal(
    insn: &Instruction,
    rodata: &[ReadOnlyWindow<'_>],
    xmm: &mut [Option<[u8; 16]>; 32],
) {
    if !is_xmm_block_move(insn.mnemonic()) {
        return;
    }
    let Some(dest): Option<usize> = xmm_register_index(insn.op0_register()) else {
        return;
    };
    if insn.op1_kind() != OpKind::Memory || !insn.is_ip_rel_memory_operand() {
        if insn.op1_kind() == OpKind::Register
            && let Some(src) = xmm_register_index(insn.op1_register())
        {
            xmm[dest] = xmm[src];
            return;
        }
        xmm[dest] = None;
        return;
    }
    let address: u64 = insn.ip_rel_memory_address();
    xmm[dest] = read_window_bytes(rodata, address, 16);
}

fn read_window_bytes(rodata: &[ReadOnlyWindow<'_>], address: u64, len: usize) -> Option<[u8; 16]> {
    for window in rodata {
        if let Some(slice) = window.read(address, len) {
            let mut bytes: [u8; 16] = [0u8; 16];
            bytes[..len].copy_from_slice(slice);
            return Some(bytes);
        }
    }
    None
}

fn sse_block_store(insn: &Instruction, xmm: &[Option<[u8; 16]>; 32]) -> Option<ImmStore> {
    if !is_xmm_block_move(insn.mnemonic()) {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory || insn.memory_index() != Register::None {
        return None;
    }
    let base: StackBase = StackBase::from_register(insn.memory_base())?;
    let src: usize = xmm_register_index(insn.op1_register())?;
    let literal: [u8; 16] = xmm[src]?;
    let disp: i64 = insn.memory_displacement64().cast_signed();
    Some(ImmStore {
        ip: insn.ip(),
        base,
        disp,
        bytes: literal,
        width: 16,
    })
}

const fn is_xmm_block_move(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Movups | Mnemonic::Movaps | Mnemonic::Movdqu | Mnemonic::Movdqa
    )
}

fn xmm_register_index(reg: Register) -> Option<usize> {
    if reg.is_xmm() {
        Some((reg as usize).wrapping_sub(Register::XMM0 as usize))
    } else {
        None
    }
}

struct PushChain {
    bitness: u32,
    pending: Vec<[u8; 8]>,
    widths: Vec<usize>,
    first_ip: Option<u64>,
}

impl PushChain {
    fn new(bitness: u32) -> Self {
        Self {
            bitness,
            pending: Vec::new(),
            widths: Vec::new(),
            first_ip: None,
        }
    }

    fn ptr_width(&self) -> usize {
        if self.bitness == 64 { 8 } else { 4 }
    }

    fn absorb(&mut self, insn: &Instruction) -> Option<ImmStore> {
        if insn.mnemonic() != Mnemonic::Push {
            return None;
        }
        let (value, width): (u64, usize) = match insn.op0_kind() {
            OpKind::Immediate8 => (u64::from(insn.immediate8()), self.ptr_width()),
            OpKind::Immediate16 => (u64::from(insn.immediate16()), 2),
            OpKind::Immediate32 => (u64::from(insn.immediate32()), self.ptr_width()),
            OpKind::Immediate8to16 => (insn.immediate8to16().cast_unsigned().into(), 2),
            OpKind::Immediate8to32 => (
                insn.immediate8to32().cast_unsigned().into(),
                self.ptr_width(),
            ),
            OpKind::Immediate8to64 => (insn.immediate8to64().cast_unsigned(), self.ptr_width()),
            OpKind::Immediate32to64 => (insn.immediate32to64().cast_unsigned(), self.ptr_width()),
            _ => return None,
        };
        if self.first_ip.is_none() {
            self.first_ip = Some(insn.ip());
        }
        self.pending.push(value.to_le_bytes());
        self.widths.push(width);
        None
    }

    fn flush_into(&mut self, out: &mut Vec<ImmStore>) {
        if self.pending.is_empty() {
            return;
        }
        let mut buffer: Vec<u8> = Vec::new();
        for (chunk, width) in self.pending.iter().rev().zip(self.widths.iter().rev()) {
            buffer.extend_from_slice(&chunk[..*width]);
        }
        let mut offset: usize = 0;
        while offset < buffer.len() {
            let take: usize = (buffer.len() - offset).min(16);
            let mut bytes: [u8; 16] = [0u8; 16];
            bytes[..take].copy_from_slice(&buffer[offset..offset + take]);
            out.push(ImmStore {
                ip: self.first_ip.unwrap_or(0),
                base: StackBase::Rsp,
                disp: offset as i64,
                bytes,
                width: take,
            });
            offset += take;
        }
        self.pending.clear();
        self.widths.clear();
        self.first_ip = None;
    }
}

fn breaks_push_chain(insn: &Instruction) -> bool {
    matches!(
        insn.mnemonic(),
        Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::Pop
            | Mnemonic::Leave
            | Mnemonic::Jmp
            | Mnemonic::Je
            | Mnemonic::Jne
    ) || insn.flow_control() != iced_x86::FlowControl::Next
}

fn immediate_store(insn: &Instruction) -> Option<ImmStore> {
    if insn.mnemonic() != Mnemonic::Mov {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if insn.memory_index() != Register::None {
        return None;
    }
    let base: StackBase = StackBase::from_register(insn.memory_base())?;
    let (value, width): (u64, usize) = match insn.op1_kind() {
        OpKind::Immediate8 => (u64::from(insn.immediate8()), 1),
        OpKind::Immediate16 => (u64::from(insn.immediate16()), 2),
        OpKind::Immediate32 => (u64::from(insn.immediate32()), 4),
        OpKind::Immediate8to16 => (insn.immediate8to16().cast_unsigned().into(), 2),
        OpKind::Immediate8to32 => (insn.immediate8to32().cast_unsigned().into(), 4),
        OpKind::Immediate8to64 => (insn.immediate8to64().cast_unsigned(), 8),
        OpKind::Immediate32to64 => (insn.immediate32to64().cast_unsigned(), 8),
        OpKind::Immediate64 => (insn.immediate64(), 8),
        _ => return None,
    };
    let disp: i64 = insn.memory_displacement64().cast_signed();
    let mut bytes: [u8; 16] = [0u8; 16];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    let _ = base.is_64();
    Some(ImmStore {
        ip: insn.ip(),
        base,
        disp,
        bytes,
        width,
    })
}

fn group_by_base(stores: Vec<ImmStore>) -> BTreeMap<StackBase, Vec<ImmStore>> {
    let mut groups: BTreeMap<StackBase, Vec<ImmStore>> = BTreeMap::new();
    for store in stores {
        groups.entry(store.base).or_default().push(store);
    }
    groups
}

fn reassemble_group(base: StackBase, group: &[ImmStore]) -> Vec<ReassembledStackString> {
    let mut out: Vec<ReassembledStackString> = Vec::new();
    let mut run: Vec<ImmStore> = Vec::new();
    let mut expected_disp: Option<i64> = None;

    for &store in group {
        let contiguous: bool = expected_disp.map_or(true, |disp: i64| {
            store.disp == disp && span_within_limit(&run, store.disp)
        });
        if !contiguous {
            flush_run(base, &run, &mut out);
            run.clear();
        }
        run.push(store);
        expected_disp = Some(store.disp + store.width as i64);
    }
    flush_run(base, &run, &mut out);
    out
}

fn span_within_limit(run: &[ImmStore], next_disp: i64) -> bool {
    run.first().map_or(true, |first: &ImmStore| {
        next_disp.saturating_sub(first.disp) <= MAX_GROUP_SPAN
    })
}

fn flush_run(base: StackBase, run: &[ImmStore], out: &mut Vec<ReassembledStackString>) {
    let Some(first): Option<&ImmStore> = run.first() else {
        return;
    };
    let mut buffer: Vec<u8> = Vec::new();
    for store in run {
        buffer.extend_from_slice(&store.bytes[..store.width]);
    }
    for (offset, value) in printable_runs(&buffer) {
        out.push(ReassembledStackString {
            first_store: first.ip,
            base,
            base_displacement: first.disp + offset as i64,
            value,
        });
    }
}

fn printable_runs(buffer: &[u8]) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut start: usize = 0;
    let mut current: Vec<u8> = Vec::new();
    for (index, &byte) in buffer.iter().enumerate() {
        if is_printable(byte) {
            if current.is_empty() {
                start = index;
            }
            current.push(byte);
            continue;
        }
        emit_run(start, &current, &mut out);
        current.clear();
    }
    emit_run(start, &current, &mut out);
    out
}

fn emit_run(start: usize, current: &[u8], out: &mut Vec<(usize, String)>) {
    if current.len() < MIN_PRINTABLE_RUN {
        return;
    }
    if let Ok(text) = std::str::from_utf8(current) {
        out.push((start, text.to_owned()));
    }
}

const fn is_printable(byte: u8) -> bool {
    byte == b'\t' || (0x20 <= byte && byte <= 0x7e)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
