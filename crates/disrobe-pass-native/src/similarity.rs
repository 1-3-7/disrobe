use std::collections::BTreeMap;

use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, InsnFlow};
use disrobe_similarity::{DataReference, FunctionFeatures, FunctionId};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::arch::Arch;
use crate::desync::ReadOnlyWindow;
use crate::disasm_ir::{
    FunctionSpan, build_disasm_payload, function_spans, image_arch, mapped_address_extent,
    read_only_windows, span_instructions,
};
use crate::error::{Error, Result};
use crate::fingerprint::{ASCII_XREF_MIN_LEN, StringXref, extract_ascii_xrefs};
use crate::plt_resolve::{ImportStub, resolve_elf_plt_imports, resolve_pe_iat_imports};
use crate::pseudo_c::aarch64::{
    aarch64_adr_target, aarch64_adrp_target, immediate_field, register_field,
};

const ADRP_PAIR_SCAN_LIMIT: usize = 16;

const WIDE_MOVE_CHAIN_LIMIT: usize = 3;

const ADDRESS_IMMEDIATE_MIN_BITS: u32 = 32;

const ADD_IMMEDIATE_64: u32 = 0x9100_0000;

const ADD_IMMEDIATE_MASK: u32 = 0xffc0_0000;

const WIDE_MOVE_MASK: u32 = 0x7f80_0000;

const MOVN: u32 = 0x1280_0000;

const MOVZ: u32 = 0x5280_0000;

const MOVK: u32 = 0x7280_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureArch {
    X86 { bits: u32 },
    Aarch64,
}

impl FeatureArch {
    const fn from_arch(arch: Arch) -> Option<Self> {
        match arch {
            Arch::X86 => Some(Self::X86 { bits: 32 }),
            Arch::X86_64 => Some(Self::X86 { bits: 64 }),
            Arch::Aarch64 => Some(Self::Aarch64),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct ImageIndex {
    strings: BTreeMap<u64, String>,
    import_slots: BTreeMap<u64, String>,
    import_stubs: BTreeMap<u64, String>,
    mapped: Option<(u64, u64)>,
}

impl ImageIndex {
    fn build(bytes: &[u8], payload: &DisasmPayload, arch: FeatureArch) -> Self {
        let (import_slots, mut import_stubs): (BTreeMap<u64, String>, BTreeMap<u64, String>) =
            index_imports(bytes, arch);
        if let FeatureArch::X86 { bits } = arch {
            import_stubs.extend(index_import_thunks(payload, bits, &import_slots));
        }
        Self {
            strings: index_strings(bytes),
            import_slots,
            import_stubs,
            mapped: mapped_address_extent(bytes),
        }
    }

    fn string_at(&self, address: u64) -> Option<&String> {
        self.strings.get(&address)
    }

    fn is_mapped_address(&self, value: u64) -> bool {
        self.mapped
            .is_some_and(|(low, high): (u64, u64)| value >= low && value < high)
    }

    fn constant(&self, value: u64) -> Option<DataReference> {
        if self.is_mapped_address(value) || is_packed_ascii(value) {
            return None;
        }
        DataReference::constant(value)
    }
}

pub fn extract_function_features(bytes: &[u8]) -> Result<Vec<FunctionFeatures>> {
    let payload: DisasmPayload = build_disasm_payload(bytes)?;
    let arch: Arch = image_arch(bytes).ok_or_else(|| {
        Error::UnsupportedArch("image carries no architecture the disassembler maps".to_owned())
    })?;
    let Some(feature_arch): Option<FeatureArch> = FeatureArch::from_arch(arch) else {
        return Err(Error::UnsupportedArch(format!(
            "{} has no data-reference extractor",
            arch.label()
        )));
    };

    let index: ImageIndex = ImageIndex::build(bytes, &payload, feature_arch);
    let spans: Vec<FunctionSpan> = function_spans(&payload);
    let mut features: Vec<FunctionFeatures> = Vec::with_capacity(spans.len());
    for span in &spans {
        let body: &[DisasmInstruction] = span_instructions(&payload.instructions, span);
        if body.is_empty() {
            continue;
        }
        let references: Vec<DataReference> = match feature_arch {
            FeatureArch::X86 { bits } => x86_references(bits, body, &index),
            FeatureArch::Aarch64 => aarch64_references(body, &index),
        };
        features.push(FunctionFeatures::new(
            FunctionId::from(span.address),
            references,
        ));
    }
    Ok(features)
}

fn index_strings(bytes: &[u8]) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    for window in read_only_windows(bytes) {
        let window: ReadOnlyWindow<'_> = window;
        for xref in extract_ascii_xrefs(window.bytes, ASCII_XREF_MIN_LEN) {
            let xref: StringXref = xref;
            let Some(address): Option<u64> = window.address.checked_add(xref.offset) else {
                continue;
            };
            out.insert(address, xref.value);
        }
    }
    out
}

fn index_imports(
    bytes: &[u8],
    arch: FeatureArch,
) -> (BTreeMap<u64, String>, BTreeMap<u64, String>) {
    let mut slots: BTreeMap<u64, String> = BTreeMap::new();
    let mut stubs: BTreeMap<u64, String> = BTreeMap::new();
    if !matches!(arch, FeatureArch::X86 { .. }) {
        return (slots, stubs);
    }
    for stub in resolve_elf_plt_imports(bytes) {
        let stub: ImportStub = stub;
        slots.insert(stub.slot_address, stub.name.clone());
        stubs.insert(stub.stub_address, stub.name);
    }
    for stub in resolve_pe_iat_imports(bytes) {
        let stub: ImportStub = stub;
        slots.insert(stub.slot_address, stub.name);
    }
    (slots, stubs)
}

fn index_import_thunks(
    payload: &DisasmPayload,
    bits: u32,
    slots: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    if slots.is_empty() {
        return out;
    }
    for insn in &payload.instructions {
        if !matches!(insn.flow, InsnFlow::IndirectBranch) {
            continue;
        }
        let Some(decoded): Option<Instruction> = decode_x86(bits, insn) else {
            continue;
        };
        if decoded.mnemonic() != Mnemonic::Jmp {
            continue;
        }
        let Some(slot): Option<u64> = absolute_memory_target(&decoded) else {
            continue;
        };
        let Some(name): Option<&String> = slots.get(&slot) else {
            continue;
        };
        out.insert(insn.offset, name.clone());
    }
    out
}

fn decode_x86(bits: u32, insn: &DisasmInstruction) -> Option<Instruction> {
    if insn.bytes.is_empty() {
        return None;
    }
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bits, &insn.bytes, insn.offset, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let mut decoded: Instruction = Instruction::default();
    decoder.decode_out(&mut decoded);
    if decoded.is_invalid() || decoded.len() != insn.bytes.len() {
        return None;
    }
    Some(decoded)
}

fn absolute_memory_target(decoded: &Instruction) -> Option<u64> {
    if !(0..decoded.op_count()).any(|operand: u32| decoded.op_kind(operand) == OpKind::Memory) {
        return None;
    }
    if decoded.is_ip_rel_memory_operand() {
        return Some(decoded.ip_rel_memory_address());
    }
    if decoded.memory_base() == Register::None && decoded.memory_index() == Register::None {
        return Some(decoded.memory_displacement64());
    }
    None
}

fn x86_references(bits: u32, body: &[DisasmInstruction], index: &ImageIndex) -> Vec<DataReference> {
    let mut out: Vec<DataReference> = Vec::new();
    for insn in body {
        let Some(decoded): Option<Instruction> = decode_x86(bits, insn) else {
            continue;
        };
        if let Some(reference) = x86_reference(insn, &decoded, index) {
            out.push(reference);
        }
    }
    out
}

fn x86_reference(
    insn: &DisasmInstruction,
    decoded: &Instruction,
    index: &ImageIndex,
) -> Option<DataReference> {
    if let Some(name) = x86_import_name(insn, decoded, index) {
        return Some(DataReference::imported_call(name));
    }
    if let Some(target) = absolute_memory_target(decoded)
        && let Some(text) = index.string_at(target)
    {
        return Some(DataReference::string_literal(text.clone()));
    }
    x86_immediate_reference(decoded, index)
}

fn x86_import_name(
    insn: &DisasmInstruction,
    decoded: &Instruction,
    index: &ImageIndex,
) -> Option<String> {
    match insn.flow {
        InsnFlow::Call => index.import_stubs.get(&insn.branch_target?).cloned(),
        InsnFlow::IndirectCall => index
            .import_slots
            .get(&absolute_memory_target(decoded)?)
            .cloned(),
        _ => None,
    }
}

fn x86_immediate_reference(decoded: &Instruction, index: &ImageIndex) -> Option<DataReference> {
    if touches_frame_register(decoded) {
        return None;
    }
    for operand in 0..decoded.op_count() {
        let Some(width): Option<u32> = harvestable_immediate_width(decoded.op_kind(operand)) else {
            continue;
        };
        let value: u64 = decoded.immediate(operand);
        if width >= ADDRESS_IMMEDIATE_MIN_BITS
            && let Some(text) = index.string_at(value)
        {
            return Some(DataReference::string_literal(text.clone()));
        }
        if let Some(reference) = index.constant(value) {
            return Some(reference);
        }
    }
    None
}

const fn harvestable_immediate_width(kind: OpKind) -> Option<u32> {
    match kind {
        OpKind::Immediate16 => Some(16),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(32),
        OpKind::Immediate64 => Some(64),
        _ => None,
    }
}

fn touches_frame_register(decoded: &Instruction) -> bool {
    if is_frame_register(decoded.memory_base()) || is_frame_register(decoded.memory_index()) {
        return true;
    }
    (0..decoded.op_count()).any(|operand: u32| is_frame_register(decoded.op_register(operand)))
}

const fn is_frame_register(register: Register) -> bool {
    matches!(
        register,
        Register::RSP
            | Register::ESP
            | Register::SP
            | Register::SPL
            | Register::RBP
            | Register::EBP
            | Register::BP
            | Register::BPL
    )
}

fn is_packed_ascii(value: u64) -> bool {
    let mut remaining: u64 = value;
    let mut printable: u32 = 0;
    while remaining != 0 {
        let byte: u8 = (remaining & 0xff) as u8;
        if !(0x20..=0x7e).contains(&byte) {
            return false;
        }
        printable += 1;
        remaining >>= 8;
    }
    printable >= 2
}

fn aarch64_references(body: &[DisasmInstruction], index: &ImageIndex) -> Vec<DataReference> {
    let words: Vec<Option<u32>> = body.iter().map(instruction_word).collect();
    let mut out: Vec<DataReference> = Vec::new();
    let mut position: usize = 0;
    while position < body.len() {
        let (Some(insn), Some(word)): (Option<&DisasmInstruction>, Option<u32>) =
            (body.get(position), words.get(position).copied().flatten())
        else {
            position += 1;
            continue;
        };
        match insn.mnemonic.as_str() {
            "adr" | "adrp" => {
                for target in aarch64_address_targets(insn, word, body, &words, position) {
                    if let Some(text) = index.string_at(target) {
                        out.push(DataReference::string_literal(text.clone()));
                    }
                }
                position += 1;
            }
            "mov" | "movn" | "movz" => {
                let (value, consumed): (Option<u64>, usize) =
                    fold_wide_move(body, &words, position);
                if let Some(value) = value
                    && let Some(reference) = index.constant(value)
                {
                    out.push(reference);
                }
                position += consumed;
            }
            _ => position += 1,
        }
    }
    out
}

fn instruction_word(insn: &DisasmInstruction) -> Option<u32> {
    <[u8; 4]>::try_from(insn.bytes.as_slice())
        .ok()
        .map(u32::from_le_bytes)
}

fn aarch64_address_targets(
    insn: &DisasmInstruction,
    word: u32,
    body: &[DisasmInstruction],
    words: &[Option<u32>],
    position: usize,
) -> Vec<u64> {
    if insn.mnemonic == "adr" {
        return aarch64_adr_target(insn.offset, word)
            .map(|target: u64| vec![target])
            .unwrap_or_default();
    }
    let Some(page): Option<u64> = aarch64_adrp_target(insn.offset, word) else {
        return Vec::new();
    };
    let destination: u8 = register_field(word, 0);
    paired_low_bits(destination, body, words, position)
        .into_iter()
        .filter_map(|low: u64| page.checked_add(low))
        .collect()
}

fn paired_low_bits(
    destination: u8,
    body: &[DisasmInstruction],
    words: &[Option<u32>],
    position: usize,
) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    for step in 1..=ADRP_PAIR_SCAN_LIMIT {
        let index: usize = position.saturating_add(step);
        let (Some(insn), Some(word)): (Option<&DisasmInstruction>, Option<u32>) =
            (body.get(index), words.get(index).copied().flatten())
        else {
            return out;
        };
        if word & ADD_IMMEDIATE_MASK == ADD_IMMEDIATE_64 && register_field(word, 5) == destination {
            out.push(u64::from(immediate_field(word, 10, 12)));
            if register_field(word, 0) == destination {
                return out;
            }
            continue;
        }
        if is_branch(&insn.mnemonic) || register_field(word, 0) == destination {
            return out;
        }
    }
    out
}

fn is_branch(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz" | "svc" | "brk" | "hlt"
    ) || mnemonic.starts_with("b.")
        || is_conditional_branch(mnemonic)
}

fn is_conditional_branch(mnemonic: &str) -> bool {
    let Some(condition): Option<&str> = mnemonic.strip_prefix('b') else {
        return false;
    };
    matches!(
        condition,
        "eq" | "ne"
            | "cs"
            | "hs"
            | "cc"
            | "lo"
            | "mi"
            | "pl"
            | "vs"
            | "vc"
            | "hi"
            | "ls"
            | "ge"
            | "lt"
            | "gt"
            | "le"
            | "al"
            | "nv"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WideMove {
    register: u8,
    shift: u32,
    immediate: u64,
    mask: u64,
}

fn wide_move(word: u32, expected: u32) -> Option<WideMove> {
    if word & WIDE_MOVE_MASK != expected {
        return None;
    }
    let wide: bool = word & 0x8000_0000 != 0;
    let half: u32 = immediate_field(word, 21, 2);
    if !wide && half > 1 {
        return None;
    }
    let shift: u32 = half.checked_mul(16)?;
    Some(WideMove {
        register: register_field(word, 0),
        shift,
        immediate: u64::from(immediate_field(word, 5, 16)).checked_shl(shift)?,
        mask: if wide { u64::MAX } else { u64::from(u32::MAX) },
    })
}

fn fold_wide_move(
    body: &[DisasmInstruction],
    words: &[Option<u32>],
    position: usize,
) -> (Option<u64>, usize) {
    let Some(word): Option<u32> = words.get(position).copied().flatten() else {
        return (None, 1);
    };
    let negated = |negated: WideMove| WideMove {
        immediate: !negated.immediate & negated.mask,
        ..negated
    };
    let Some(start): Option<WideMove> =
        wide_move(word, MOVZ).or_else(|| wide_move(word, MOVN).map(negated))
    else {
        return (None, 1);
    };

    let mut value: u64 = start.immediate & start.mask;
    let mut consumed: usize = 1;
    while consumed <= WIDE_MOVE_CHAIN_LIMIT {
        let index: usize = position.saturating_add(consumed);
        let (Some(insn), Some(word)): (Option<&DisasmInstruction>, Option<u32>) =
            (body.get(index), words.get(index).copied().flatten())
        else {
            break;
        };
        if insn.mnemonic != "movk" {
            break;
        }
        let Some(patch): Option<WideMove> = wide_move(word, MOVK) else {
            break;
        };
        if patch.register != start.register || patch.mask != start.mask {
            break;
        }
        let Some(halfword): Option<u64> = 0xffff_u64.checked_shl(patch.shift) else {
            break;
        };
        value = (value & !halfword) | patch.immediate;
        value &= start.mask;
        consumed += 1;
    }

    let complete: bool = body
        .get(position.saturating_add(consumed))
        .is_some_and(|insn: &DisasmInstruction| !is_branch(&insn.mnemonic));
    (complete.then_some(value), consumed)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
