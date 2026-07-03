use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol};
use serde::{Deserialize, Serialize};

use super::{MAX_BYTECODE_INSNS, MAX_HANDLERS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl Bitness {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    #[must_use]
    pub const fn ptr_size(self) -> u64 {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispatchKind {
    SwitchJumpTable,
    IndirectThreaded,
    CallThreaded,
    IfNest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmDetection {
    pub dispatch_kind: DispatchKind,
    pub dispatcher_va: u64,
    pub handler_table_va: u64,
    pub handler_count: usize,
    pub bytecode_va: u64,
    pub bytecode_len: usize,
    pub entry_vip: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerEntry {
    pub index: usize,
    pub va: u64,
    pub code: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmStructure {
    pub bitness: Bitness,
    pub image_base: u64,
    pub dispatcher_va: u64,
    pub dispatch_kind: DispatchKind,
    pub handlers: Vec<HandlerEntry>,
    pub bytecode_va: u64,
    pub bytecode: Vec<u8>,
    pub entry_vip: u64,
    pub loaded: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub va: u64,
    pub bytes: Vec<u8>,
    pub executable: bool,
}

impl VmStructure {
    #[must_use]
    pub fn read_va(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        for seg in &self.loaded {
            if let Some(off) = segment_offset(seg, va) {
                let avail: usize = (seg.bytes.len() - off).min(addressable_len(va));
                let take: usize = len.min(avail);
                let end: usize = off.checked_add(take)?;
                return Some(seg.bytes[off..end].to_vec());
            }
        }
        None
    }

    #[must_use]
    pub fn handler_by_va(&self, va: u64) -> Option<&HandlerEntry> {
        self.handlers.iter().find(|h: &&HandlerEntry| h.va == va)
    }
}

const VM_PROG_SYMBOL: &str = "dr_vm_prog";
const VM_PROG_LEN_SYMBOL: &str = "dr_vm_prog_len";
const VM_ENTRY_SYMBOL: &str = "dr_vm_entry";
const VM_DISPATCH_SYMBOL: &str = "dr_vm_dispatch";

#[must_use]
pub fn detect_vm(bytes: &[u8], bitness: Bitness) -> Option<VmDetection> {
    let structure: VmStructure = recover_structure_inner(bytes, bitness)?;
    let kind: DispatchKind = structure.dispatch_kind;
    Some(VmDetection {
        dispatch_kind: kind,
        dispatcher_va: structure.dispatcher_va,
        handler_table_va: 0,
        handler_count: structure.handlers.len(),
        bytecode_va: structure.bytecode_va,
        bytecode_len: structure.bytecode.len(),
        entry_vip: structure.entry_vip,
    })
}

#[must_use]
pub fn recover_structure(
    bytes: &[u8],
    bitness: Bitness,
    _detection: &VmDetection,
) -> Option<VmStructure> {
    recover_structure_inner(bytes, bitness)
}

#[must_use]
pub fn recover_structure_codescan_only(bytes: &[u8], bitness: Bitness) -> Option<VmStructure> {
    let obj: object::File<'_> = object::File::parse(bytes).ok()?;
    let image_base: u64 = obj.relative_address_base();
    let mut segments: Vec<Segment> = Vec::new();
    for section in obj.sections() {
        if let Ok(data) = section.data()
            && !data.is_empty()
        {
            let flags_exec: bool = section_is_executable(&section);
            segments.push(Segment {
                va: section.address(),
                bytes: data.to_vec(),
                executable: flags_exec,
            });
        }
    }
    if segments.is_empty() {
        return None;
    }
    recover_via_codescan(&segments, bitness, image_base)
}

fn recover_structure_inner(bytes: &[u8], bitness: Bitness) -> Option<VmStructure> {
    let obj: object::File<'_> = object::File::parse(bytes).ok()?;
    let image_base: u64 = obj.relative_address_base();

    let mut segments: Vec<Segment> = Vec::new();
    for section in obj.sections() {
        if let Ok(data) = section.data()
            && !data.is_empty()
        {
            let flags_exec: bool = section_is_executable(&section);
            segments.push(Segment {
                va: section.address(),
                bytes: data.to_vec(),
                executable: flags_exec,
            });
        }
    }
    if segments.is_empty() {
        return None;
    }

    if let Some(structure) = recover_via_exports(&obj, &segments, bitness, image_base) {
        return Some(structure);
    }
    recover_via_codescan(&segments, bitness, image_base)
}

fn recover_via_exports(
    obj: &object::File<'_>,
    segments: &[Segment],
    bitness: Bitness,
    image_base: u64,
) -> Option<VmStructure> {
    let bytecode_va: u64 = symbol_address(obj, VM_PROG_SYMBOL)?;
    let prog_len_va: u64 = symbol_address(obj, VM_PROG_LEN_SYMBOL)?;
    let entry_vip_va: u64 = symbol_address(obj, VM_ENTRY_SYMBOL)?;
    let dispatcher_va: u64 = symbol_address(obj, VM_DISPATCH_SYMBOL)?;

    let bytecode_len: usize = read_u32_at(segments, prog_len_va)? as usize;
    if bytecode_len == 0 || bytecode_len > MAX_BYTECODE_INSNS * 8 {
        return None;
    }
    let bytecode: Vec<u8> = read_segment_bytes(segments, bytecode_va, bytecode_len)?;
    let entry_vip: u64 = u64::from(read_u32_at(segments, entry_vip_va)?);

    let dispatch_kind: DispatchKind = classify_dispatch(segments, bitness, dispatcher_va)?;

    let handlers: Vec<HandlerEntry> = recover_handler_table(obj, segments, bitness, dispatcher_va)?;
    if handlers.is_empty() || handlers.len() > MAX_HANDLERS {
        return None;
    }

    Some(VmStructure {
        bitness,
        image_base,
        dispatcher_va,
        dispatch_kind,
        handlers,
        bytecode_va,
        bytecode,
        entry_vip,
        loaded: segments.to_vec(),
    })
}

fn recover_via_codescan(
    segments: &[Segment],
    bitness: Bitness,
    image_base: u64,
) -> Option<VmStructure> {
    let dispatch: DispatchSite = scan_for_dispatch(segments, bitness)?;
    let table_va: u64 = dispatch.table_va;
    let handler_addrs: Vec<u64> = walk_handler_table(segments, bitness, table_va)?;
    if handler_addrs.len() < 2 || handler_addrs.len() > MAX_HANDLERS {
        return None;
    }
    let mut handlers: Vec<HandlerEntry> = Vec::with_capacity(handler_addrs.len());
    for (index, va) in handler_addrs.into_iter().enumerate() {
        let code: Vec<u8> = extract_handler_code(segments, bitness, va)?;
        handlers.push(HandlerEntry { index, va, code });
    }
    let bytecode_va: u64 = dispatch.bytecode_va?;
    let bytecode: Vec<u8> = read_to_section_end(segments, bytecode_va)?;
    if bytecode.is_empty() {
        return None;
    }

    Some(VmStructure {
        bitness,
        image_base,
        dispatcher_va: dispatch.dispatcher_va,
        dispatch_kind: dispatch.kind,
        handlers,
        bytecode_va,
        bytecode,
        entry_vip: 0,
        loaded: segments.to_vec(),
    })
}

#[derive(Debug, Clone)]
struct DispatchSite {
    dispatcher_va: u64,
    table_va: u64,
    bytecode_va: Option<u64>,
    kind: DispatchKind,
}

fn scan_for_dispatch(segments: &[Segment], bitness: Bitness) -> Option<DispatchSite> {
    for seg in segments.iter().filter(|s: &&Segment| s.executable) {
        if let Some(site) = scan_segment_for_dispatch(seg, segments, bitness) {
            return Some(site);
        }
    }
    None
}

fn scan_segment_for_dispatch(
    seg: &Segment,
    segments: &[Segment],
    bitness: Bitness,
) -> Option<DispatchSite> {
    const SCAN_INSN_CAP: u64 = 4_000_000;
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.bits(), &seg.bytes, seg.va, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut lea_targets: Vec<(Register, u64, u64)> = Vec::new();
    let mut decoded: u64 = 0;
    while decoder.can_decode() {
        decoded += 1;
        if decoded > SCAN_INSN_CAP {
            break;
        }
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        if insn.code() == Code::Lea_r64_m || insn.code() == Code::Lea_r32_m {
            if insn.memory_base() == Register::RIP || insn.memory_base() == Register::EIP {
                let target: u64 = insn.memory_displacement64();
                lea_targets.push((insn.op0_register(), target, insn.ip()));
                if lea_targets.len() > 64 {
                    lea_targets.remove(0);
                }
            }
            continue;
        }
        let is_indirect: bool = matches!(
            insn.flow_control(),
            FlowControl::IndirectCall | FlowControl::IndirectBranch
        );
        if is_indirect
            && insn.op0_kind() == OpKind::Memory
            && insn.memory_index() != Register::None
            && insn.memory_index_scale() as u64 == bitness.ptr_size()
        {
            let base_reg: Register = insn.memory_base();
            let table_va: u64 = if base_reg == Register::RIP || base_reg == Register::EIP {
                insn.memory_displacement64()
            } else {
                most_recent_lea(&lea_targets, base_reg)?
            };
            if !va_in_segment(segments, table_va) {
                continue;
            }
            let kind: DispatchKind = match insn.flow_control() {
                FlowControl::IndirectCall => DispatchKind::CallThreaded,
                _ => DispatchKind::SwitchJumpTable,
            };
            let bytecode_va: Option<u64> = guess_bytecode_va(&lea_targets, segments, table_va);
            return Some(DispatchSite {
                dispatcher_va: seg.va,
                table_va,
                bytecode_va,
                kind,
            });
        }
    }
    None
}

fn most_recent_lea(leas: &[(Register, u64, u64)], reg: Register) -> Option<u64> {
    leas.iter()
        .rev()
        .find(|(r, _, _): &&(Register, u64, u64)| *r == reg)
        .map(|(_, target, _): &(Register, u64, u64)| *target)
}

fn guess_bytecode_va(
    leas: &[(Register, u64, u64)],
    segments: &[Segment],
    table_va: u64,
) -> Option<u64> {
    leas.iter()
        .rev()
        .map(|(_, target, _): &(Register, u64, u64)| *target)
        .find(|target: &u64| {
            *target != table_va
                && va_in_segment(segments, *target)
                && !va_in_executable_segment(segments, *target)
        })
}

fn va_in_segment(segments: &[Segment], va: u64) -> bool {
    segments
        .iter()
        .any(|s: &Segment| segment_offset(s, va).is_some())
}

fn va_in_executable_segment(segments: &[Segment], va: u64) -> bool {
    segments
        .iter()
        .any(|s: &Segment| s.executable && segment_offset(s, va).is_some())
}

fn walk_handler_table(segments: &[Segment], bitness: Bitness, table_va: u64) -> Option<Vec<u64>> {
    let ptr: u64 = bitness.ptr_size();
    let mut out: Vec<u64> = Vec::new();
    let mut i: u64 = 0;
    while out.len() < MAX_HANDLERS {
        let slot_va: u64 = pointer_slot_va(table_va, i, ptr)?;
        let target: u64 = match bitness {
            Bitness::Bits32 => u64::from(read_u32_at(segments, slot_va)?),
            Bitness::Bits64 => match read_u64_at(segments, slot_va) {
                Some(v) => v,
                None => break,
            },
        };
        if !va_in_executable_segment(segments, target) {
            break;
        }
        out.push(target);
        i = i.checked_add(1)?;
    }
    if out.is_empty() { None } else { Some(out) }
}

fn read_to_section_end(segments: &[Segment], va: u64) -> Option<Vec<u8>> {
    const MAX_BYTECODE: usize = MAX_BYTECODE_INSNS;
    for seg in segments {
        if let Some(off) = segment_offset(seg, va) {
            let avail: usize = (seg.bytes.len() - off).min(addressable_len(va));
            let take: usize = avail.min(MAX_BYTECODE);
            let end: usize = off.checked_add(take)?;
            return Some(seg.bytes[off..end].to_vec());
        }
    }
    None
}

fn segment_offset(seg: &Segment, va: u64) -> Option<usize> {
    let len: u64 = u64::try_from(seg.bytes.len()).ok()?;
    let delta: u64 = va.checked_sub(seg.va)?;
    if delta < len {
        usize::try_from(delta).ok()
    } else {
        None
    }
}

fn addressable_len(va: u64) -> usize {
    let remaining: u64 = u64::MAX - va;
    match usize::try_from(remaining) {
        Ok(value) => value.saturating_add(1),
        Err(_) => usize::MAX,
    }
}

fn section_is_executable(section: &object::Section<'_, '_>) -> bool {
    matches!(
        section.kind(),
        object::SectionKind::Text | object::SectionKind::OtherString
    ) || section
        .name()
        .is_ok_and(|n: &str| n == ".text" || n.starts_with(".text") || n == "__text")
}

fn symbol_address(obj: &object::File<'_>, name: &str) -> Option<u64> {
    if let Ok(exports) = obj.exports() {
        for e in &exports {
            if let Ok(export_name) = core::str::from_utf8(e.name())
                && symbol_name_matches(export_name, name)
            {
                return Some(e.address());
            }
        }
    }
    for sym in obj.symbols() {
        if let Ok(sym_name) = sym.name()
            && symbol_name_matches(sym_name, name)
        {
            return Some(sym.address());
        }
    }
    for sym in obj.dynamic_symbols() {
        if let Ok(sym_name) = sym.name()
            && symbol_name_matches(sym_name, name)
        {
            return Some(sym.address());
        }
    }
    None
}

fn symbol_name_matches(actual: &str, want: &str) -> bool {
    actual == want || actual == format!("_{want}")
}

fn read_segment_bytes(segments: &[Segment], va: u64, len: usize) -> Option<Vec<u8>> {
    for seg in segments {
        if let Some(off) = segment_offset(seg, va) {
            let avail: usize = (seg.bytes.len() - off).min(addressable_len(va));
            let take: usize = len.min(avail);
            let end: usize = off.checked_add(take)?;
            return Some(seg.bytes[off..end].to_vec());
        }
    }
    None
}

fn read_u32_at(segments: &[Segment], va: u64) -> Option<u32> {
    let raw: Vec<u8> = read_segment_bytes(segments, va, 4)?;
    if raw.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64_at(segments: &[Segment], va: u64) -> Option<u64> {
    let raw: Vec<u8> = read_segment_bytes(segments, va, 8)?;
    if raw.len() < 8 {
        return None;
    }
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(&raw[..8]);
    Some(u64::from_le_bytes(arr))
}

fn classify_dispatch(
    segments: &[Segment],
    bitness: Bitness,
    dispatcher_va: u64,
) -> Option<DispatchKind> {
    let window: Vec<u8> = read_segment_bytes(segments, dispatcher_va, 512)?;
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.bits(), &window, dispatcher_va, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        if insn.flow_control() == FlowControl::IndirectBranch
            && insn.op0_kind() == OpKind::Memory
            && insn.memory_index() != Register::None
        {
            return Some(DispatchKind::SwitchJumpTable);
        }
        if insn.flow_control() == FlowControl::IndirectCall
            && insn.op0_kind() == OpKind::Memory
            && insn.memory_index() != Register::None
        {
            return Some(DispatchKind::CallThreaded);
        }
    }
    None
}

fn recover_handler_table(
    obj: &object::File<'_>,
    segments: &[Segment],
    bitness: Bitness,
    dispatcher_va: u64,
) -> Option<Vec<HandlerEntry>> {
    let table_va: u64 = symbol_address(obj, "dr_vm_handlers")
        .or_else(|| find_jumptable_va(segments, bitness, dispatcher_va))?;
    let count: usize = symbol_address(obj, "dr_vm_handler_count")
        .and_then(|va: u64| read_u32_at(segments, va))
        .map_or(0, |c: u32| c as usize);
    let entries: Vec<u64> = read_pointer_table(segments, bitness, table_va, count)?;
    let mut handlers: Vec<HandlerEntry> = Vec::with_capacity(entries.len());
    for (index, va) in entries.into_iter().enumerate() {
        let code: Vec<u8> = extract_handler_code(segments, bitness, va)?;
        handlers.push(HandlerEntry { index, va, code });
    }
    Some(handlers)
}

fn read_pointer_table(
    segments: &[Segment],
    bitness: Bitness,
    table_va: u64,
    count: usize,
) -> Option<Vec<u64>> {
    if count == 0 || count > MAX_HANDLERS {
        return None;
    }
    let ptr: u64 = bitness.ptr_size();
    let mut out: Vec<u64> = Vec::with_capacity(count);
    for i in 0..count {
        let index: u64 = u64::try_from(i).ok()?;
        let slot_va: u64 = pointer_slot_va(table_va, index, ptr)?;
        let target: u64 = match bitness {
            Bitness::Bits32 => u64::from(read_u32_at(segments, slot_va)?),
            Bitness::Bits64 => read_u64_at(segments, slot_va)?,
        };
        if target == 0 {
            return None;
        }
        out.push(target);
    }
    Some(out)
}

fn pointer_slot_va(table_va: u64, index: u64, ptr: u64) -> Option<u64> {
    let offset: u64 = index.checked_mul(ptr)?;
    table_va.checked_add(offset)
}

fn find_jumptable_va(segments: &[Segment], bitness: Bitness, dispatcher_va: u64) -> Option<u64> {
    let window: Vec<u8> = read_segment_bytes(segments, dispatcher_va, 512)?;
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.bits(), &window, dispatcher_va, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        let is_table_branch: bool = matches!(
            insn.flow_control(),
            FlowControl::IndirectBranch | FlowControl::IndirectCall
        ) && insn.op0_kind() == OpKind::Memory
            && insn.memory_index() != Register::None;
        let is_table_load: bool = matches!(insn.code(), Code::Mov_r64_rm64 | Code::Mov_r32_rm32)
            && insn.op1_kind() == OpKind::Memory
            && insn.memory_index() != Register::None;
        if is_table_branch || is_table_load {
            let disp: u64 = insn.memory_displacement64();
            if insn.memory_base() == Register::RIP || insn.memory_base() == Register::EIP {
                return Some(disp);
            }
            if insn.memory_base() == Register::None && disp != 0 {
                return Some(disp);
            }
        }
    }
    None
}

fn extract_handler_code(segments: &[Segment], bitness: Bitness, va: u64) -> Option<Vec<u8>> {
    const MAX_HANDLER_BYTES: usize = 4096;
    let window: Vec<u8> = read_segment_bytes(segments, va, MAX_HANDLER_BYTES)?;
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.bits(), &window, va, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut end_off: usize = 0;
    while decoder.can_decode() {
        let start: usize = (decoder.ip() - va) as usize;
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        end_off = (insn.ip() - va) as usize + insn.len();
        match insn.flow_control() {
            FlowControl::Return
            | FlowControl::IndirectBranch
            | FlowControl::UnconditionalBranch => {
                break;
            }
            _ => {}
        }
        if end_off >= window.len() {
            break;
        }
        let _ = start;
    }
    if end_off == 0 {
        return None;
    }
    Some(window[..end_off.min(window.len())].to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bitness_ptr_sizes() {
        assert_eq!(Bitness::Bits32.ptr_size(), 4);
        assert_eq!(Bitness::Bits64.ptr_size(), 8);
    }

    #[test]
    fn read_va_returns_none_outside_segments() {
        let s: VmStructure = VmStructure {
            bitness: Bitness::Bits64,
            image_base: 0x1000,
            dispatcher_va: 0x1000,
            dispatch_kind: DispatchKind::SwitchJumpTable,
            handlers: vec![],
            bytecode_va: 0x2000,
            bytecode: vec![],
            entry_vip: 0,
            loaded: vec![Segment {
                va: 0x1000,
                bytes: vec![1, 2, 3, 4],
                executable: true,
            }],
        };
        assert_eq!(s.read_va(0x1000, 2), Some(vec![1, 2]));
        assert_eq!(s.read_va(0x9000, 2), None);
    }

    #[test]
    fn read_va_does_not_wrap_high_segment_to_low_addresses() {
        let s: VmStructure = VmStructure {
            bitness: Bitness::Bits64,
            image_base: u64::MAX - 1,
            dispatcher_va: u64::MAX - 1,
            dispatch_kind: DispatchKind::SwitchJumpTable,
            handlers: vec![],
            bytecode_va: u64::MAX - 1,
            bytecode: vec![],
            entry_vip: 0,
            loaded: vec![Segment {
                va: u64::MAX - 1,
                bytes: vec![9, 10, 11, 12],
                executable: true,
            }],
        };
        assert_eq!(s.read_va(0, 2), None);
        assert_eq!(s.read_va(u64::MAX - 1, 2), Some(vec![9, 10]));
        assert_eq!(s.read_va(u64::MAX, 4), Some(vec![10]));
        assert!(va_in_segment(&s.loaded, u64::MAX));
        assert!(!va_in_segment(&s.loaded, 0));
    }

    #[test]
    fn pointer_table_rejects_wrapped_slot_addresses() {
        let segments: Vec<Segment> = vec![
            Segment {
                va: u64::MAX - 7,
                bytes: vec![0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                executable: false,
            },
            Segment {
                va: 0x2000,
                bytes: vec![0x90],
                executable: true,
            },
        ];
        assert_eq!(
            read_pointer_table(&segments, Bitness::Bits64, u64::MAX - 7, 1),
            Some(vec![0x2000])
        );
        assert_eq!(
            read_pointer_table(&segments, Bitness::Bits64, u64::MAX - 7, 2),
            None
        );
    }

    #[test]
    fn unrecognized_dispatch_window_is_not_classified_as_switch() {
        let segments: Vec<Segment> = vec![Segment {
            va: 0x1000,
            bytes: vec![0xC3],
            executable: true,
        }];
        let kind: Option<DispatchKind> = classify_dispatch(&segments, Bitness::Bits64, 0x1000);
        assert_eq!(kind, None);
    }
}
