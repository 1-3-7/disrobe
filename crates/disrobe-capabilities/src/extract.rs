use disrobe_binfmt::native::{Arch, NativeFile, NativeFormat, SectionInfo, parse_native};
use disrobe_core::strings::{self, ExtractedString, Options};
use disrobe_query::{BasicBlock, Function, InsnClass, InsnView, Module, SymbolKind};

use crate::feature::{Characteristic, FeatureHit, FeatureSet, FeatureValue, OperandValue};
use crate::imports::{ImportMap, parse_operand_memory_address};

#[derive(Debug, Clone)]
pub struct ScopedFeatures {
    pub file: FeatureSet,
    pub functions: Vec<FunctionFeatures>,
}

#[derive(Debug, Clone)]
pub struct FunctionFeatures {
    pub name: String,
    pub address: u64,
    pub features: FeatureSet,
    pub blocks: Vec<BlockFeatures>,
}

#[derive(Debug, Clone)]
pub struct BlockFeatures {
    pub start: u64,
    pub features: FeatureSet,
    pub instructions: Vec<InstructionFeatures>,
}

#[derive(Debug, Clone)]
pub struct InstructionFeatures {
    pub address: u64,
    pub features: FeatureSet,
}

const MIN_STRING_LEN: usize = 4;
const MAX_NUMBER_FEATURES_PER_INSN: usize = 4;
const PE_HEADER_SCAN_CAP: usize = 1 << 20;
const MAX_FILE_STRING_SCAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILE_STRING_FEATURES: usize = 4096;
const MAX_FILE_STRING_FEATURE_BYTES: usize = 4096;

#[derive(Debug, Clone, Default)]
struct GlobalFeatures {
    os: Option<String>,
    arch: Option<String>,
    format: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct LayoutInfo {
    sections: Vec<SectionInfo>,
}

#[derive(Debug, Clone, Copy)]
struct StringFeatureLimits {
    scan_bytes: usize,
    feature_count: usize,
    feature_bytes: usize,
}

impl StringFeatureLimits {
    const fn production() -> Self {
        Self {
            scan_bytes: MAX_FILE_STRING_SCAN_BYTES,
            feature_count: MAX_FILE_STRING_FEATURES,
            feature_bytes: MAX_FILE_STRING_FEATURE_BYTES,
        }
    }
}

impl LayoutInfo {
    fn section_index_at(&self, va: u64) -> Option<usize> {
        self.sections
            .iter()
            .position(|s: &SectionInfo| section_contains(s, va))
    }
}

const fn section_contains(section: &SectionInfo, va: u64) -> bool {
    match section.address.checked_add(section.size) {
        Some(end) => va >= section.address && va < end,
        None => false,
    }
}

#[must_use]
pub fn extract(module: &Module, bytes: &[u8], imports: &ImportMap) -> ScopedFeatures {
    let native: Option<NativeFile> = parse_native(bytes).ok();
    let global: GlobalFeatures = global_features(native.as_ref());
    let layout: LayoutInfo = LayoutInfo {
        sections: native
            .as_ref()
            .map_or_else(Vec::new, |value: &NativeFile| value.sections.clone()),
    };

    let mut file: FeatureSet = FeatureSet::new();
    push_globals(&mut file, &global, 0);
    push_file_strings(&mut file, bytes);
    push_file_native(&mut file, native.as_ref(), imports);
    push_embedded_pe(&mut file, bytes);

    let functions: Vec<FunctionFeatures> = module
        .functions()
        .iter()
        .map(|f: &Function| extract_function(module, f, imports, &global, &layout, &mut file))
        .collect();

    ScopedFeatures { file, functions }
}

fn global_features(native: Option<&NativeFile>) -> GlobalFeatures {
    let Some(native): Option<&NativeFile> = native else {
        return GlobalFeatures::default();
    };
    GlobalFeatures {
        os: os_for(native.format).map(str::to_owned),
        arch: Some(arch_label(native.arch).to_owned()),
        format: Some(format_label(native.format).to_owned()),
    }
}

const fn os_for(format: NativeFormat) -> Option<&'static str> {
    match format {
        NativeFormat::Pe32 | NativeFormat::Pe64 | NativeFormat::NeWindows => Some("windows"),
        NativeFormat::NeOs2 => Some("os2"),
        NativeFormat::Elf32 | NativeFormat::Elf64 => Some("linux"),
        NativeFormat::MachO32 | NativeFormat::MachO64 | NativeFormat::MachOFat => Some("macos"),
        NativeFormat::Coff | NativeFormat::Wasm => None,
    }
}

const fn format_label(format: NativeFormat) -> &'static str {
    match format {
        NativeFormat::Pe32 | NativeFormat::Pe64 => "pe",
        NativeFormat::Elf32 | NativeFormat::Elf64 => "elf",
        NativeFormat::MachO32 | NativeFormat::MachO64 | NativeFormat::MachOFat => "macho",
        NativeFormat::Coff => "coff",
        NativeFormat::NeWindows | NativeFormat::NeOs2 => "ne",
        NativeFormat::Wasm => "wasm",
    }
}

const fn arch_label(arch: Arch) -> &'static str {
    match arch {
        Arch::X86 => "i386",
        Arch::X86_64 => "amd64",
        other => other.label(),
    }
}

fn push_globals(set: &mut FeatureSet, global: &GlobalFeatures, base: u64) {
    if let Some(os) = &global.os {
        set.push(FeatureHit::new(FeatureValue::Os(os.clone()), base));
    }
    if let Some(arch) = &global.arch {
        set.push(FeatureHit::new(FeatureValue::Arch(arch.clone()), base));
    }
    if let Some(format) = &global.format {
        set.push(FeatureHit::new(FeatureValue::Format(format.clone()), base));
    }
}

fn push_file_native(set: &mut FeatureSet, native: Option<&NativeFile>, imports: &ImportMap) {
    let Some(native): Option<&NativeFile> = native else {
        return;
    };
    for name in imports.names() {
        set.push(FeatureHit::new(FeatureValue::Import(name.clone()), 0));
    }
    for imp in &native.imports {
        let qualified: String = if imp.library.is_empty() {
            imp.name.clone()
        } else {
            let lib: &str = imp
                .library
                .strip_suffix(".dll")
                .map_or(imp.library.as_str(), |value: &str| value);
            format!("{lib}!{}", imp.name)
        };
        set.push(FeatureHit::new(FeatureValue::Import(qualified), 0));
    }
    for export in &native.exports {
        set.push(FeatureHit::new(
            FeatureValue::Export(export.name.clone()),
            export.address,
        ));
    }
    for section in &native.sections {
        set.push(FeatureHit::new(
            FeatureValue::Section(section.name.clone()),
            section.address,
        ));
    }
}

fn extract_function(
    module: &Module,
    function: &Function,
    imports: &ImportMap,
    global: &GlobalFeatures,
    layout: &LayoutInfo,
    file: &mut FeatureSet,
) -> FunctionFeatures {
    let mut features: FeatureSet = FeatureSet::new();
    push_globals(&mut features, global, function.address);
    let blocks: Vec<BlockFeatures> = function
        .basic_blocks()
        .iter()
        .map(|b: &BasicBlock| {
            extract_block(module, b, imports, global, layout, &mut features, file)
        })
        .collect();

    if function_has_back_edge(function) {
        push_to_scopes(
            &mut features,
            file,
            FeatureValue::Characteristic(Characteristic::Loop),
            function.address,
        );
    }
    if let Some(site) = recursive_call_site(module, function) {
        push_to_scopes(
            &mut features,
            file,
            FeatureValue::Characteristic(Characteristic::RecursiveCall),
            site,
        );
    }

    FunctionFeatures {
        name: function.name.clone(),
        address: function.address,
        features,
        blocks,
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_block(
    module: &Module,
    block: &BasicBlock,
    imports: &ImportMap,
    global: &GlobalFeatures,
    layout: &LayoutInfo,
    function: &mut FeatureSet,
    file: &mut FeatureSet,
) -> BlockFeatures {
    let mut features: FeatureSet = FeatureSet::new();
    push_globals(&mut features, global, block.start);
    let mut instructions: Vec<InstructionFeatures> = Vec::with_capacity(block.instructions.len());

    for insn in &block.instructions {
        let mut insn_set: FeatureSet = FeatureSet::new();
        push_globals(&mut insn_set, global, insn.offset);
        for hit in instruction_features(module, insn, imports, layout) {
            insn_set.push(hit.clone());
            features.push(hit.clone());
            function.push(hit.clone());
            file.push(hit);
        }
        instructions.push(InstructionFeatures {
            address: insn.offset,
            features: insn_set,
        });
    }

    if let Some((address, value)) = stack_string_value(block) {
        push_block_string(&mut features, function, file, &value, address);
    }
    if let Some(back_edge) = loop_back_edge(block) {
        let value: FeatureValue = FeatureValue::Characteristic(Characteristic::TightLoop);
        features.push(FeatureHit::new(value.clone(), back_edge));
        function.push(FeatureHit::new(value.clone(), back_edge));
        file.push(FeatureHit::new(value, back_edge));
    }

    BlockFeatures {
        start: block.start,
        features,
        instructions,
    }
}

fn push_to_scopes(
    scope: &mut FeatureSet,
    file: &mut FeatureSet,
    value: FeatureValue,
    address: u64,
) {
    scope.push(FeatureHit::new(value.clone(), address));
    file.push(FeatureHit::new(value, address));
}

fn push_block_string(
    block: &mut FeatureSet,
    function: &mut FeatureSet,
    file: &mut FeatureSet,
    value: &str,
    address: u64,
) {
    let characteristic: FeatureValue = FeatureValue::Characteristic(Characteristic::StackString);
    block.push(FeatureHit::new(characteristic.clone(), address));
    function.push(FeatureHit::new(characteristic.clone(), address));
    file.push(FeatureHit::new(characteristic, address));

    let string_value: FeatureValue = FeatureValue::String(value.to_owned());
    block.push(FeatureHit::new(string_value.clone(), address));
    function.push(FeatureHit::new(string_value.clone(), address));
    file.push(FeatureHit::new(string_value, address));
}

fn loop_back_edge(block: &BasicBlock) -> Option<u64> {
    block
        .instructions
        .iter()
        .filter(|i: &&InsnView| {
            matches!(
                i.class,
                InsnClass::ConditionalJump | InsnClass::UnconditionalJump
            )
        })
        .find_map(|i: &InsnView| {
            i.branch_target
                .filter(|t: &u64| *t <= i.offset)
                .map(|_| i.offset)
        })
}

fn function_has_back_edge(function: &Function) -> bool {
    let blocks: Vec<BasicBlock> = function.basic_blocks();
    blocks.iter().any(|block: &BasicBlock| {
        block
            .successors
            .iter()
            .any(|succ: &u64| *succ <= block.start)
    })
}

fn recursive_call_site(module: &Module, function: &Function) -> Option<u64> {
    function
        .instructions
        .iter()
        .filter(|i: &&InsnView| i.class == InsnClass::Call)
        .find_map(|i: &InsnView| {
            let target: u64 = i.branch_target?;
            if target == function.address {
                return Some(i.offset);
            }
            module
                .symbol_ref(target)
                .filter(|sym: &&disrobe_query::SymbolRef| {
                    matches!(sym.kind, SymbolKind::Function | SymbolKind::Export)
                        && sym.name == function.name
                })
                .map(|_| i.offset)
        })
}

fn instruction_features(
    module: &Module,
    insn: &InsnView,
    imports: &ImportMap,
    layout: &LayoutInfo,
) -> Vec<FeatureHit> {
    let mut hits: Vec<FeatureHit> = Vec::new();
    hits.push(FeatureHit::new(
        FeatureValue::Mnemonic(insn.mnemonic.clone()),
        insn.offset,
    ));
    hits.push(FeatureHit::new(
        FeatureValue::Offset(insn.offset),
        insn.offset,
    ));

    if let Some(name) = resolve_call_target(module, insn, imports) {
        hits.push(FeatureHit::new(FeatureValue::Api(name), insn.offset));
    }
    if insn.class == InsnClass::Call && insn.branch_target.is_none() {
        hits.push(FeatureHit::new(
            FeatureValue::Characteristic(Characteristic::IndirectCall),
            insn.offset,
        ));
    }
    if is_non_zeroing_xor(insn) {
        hits.push(FeatureHit::new(
            FeatureValue::Characteristic(Characteristic::NonZeroingXor),
            insn.offset,
        ));
    }
    push_segment_access(&mut hits, insn);
    if let Some(characteristic) = cross_section_flow(insn, layout) {
        hits.push(FeatureHit::new(
            FeatureValue::Characteristic(characteristic),
            insn.offset,
        ));
    }

    let mut numbers: usize = 0;
    for (index, operand) in insn.operands.iter().enumerate() {
        let slot: u8 = u8::try_from(index).map_or(u8::MAX, |value: u8| value);
        for value in operand_numbers(operand) {
            hits.push(FeatureHit::new(
                FeatureValue::Operand {
                    index: slot,
                    inner: OperandValue::Number(value),
                },
                insn.offset,
            ));
            if numbers < MAX_NUMBER_FEATURES_PER_INSN {
                hits.push(FeatureHit::new(FeatureValue::Number(value), insn.offset));
                numbers += 1;
            }
        }
    }
    hits
}

fn push_segment_access(hits: &mut Vec<FeatureHit>, insn: &InsnView) {
    let mut fs: bool = false;
    let mut gs: bool = false;
    for operand in &insn.operands {
        let lower: String = operand.to_ascii_lowercase();
        if lower.contains("fs:") {
            fs = true;
        }
        if lower.contains("gs:") {
            gs = true;
        }
    }
    if fs {
        hits.push(FeatureHit::new(
            FeatureValue::Characteristic(Characteristic::FsAccess),
            insn.offset,
        ));
    }
    if gs {
        hits.push(FeatureHit::new(
            FeatureValue::Characteristic(Characteristic::GsAccess),
            insn.offset,
        ));
    }
    if is_peb_access(insn, fs, gs) {
        hits.push(FeatureHit::new(
            FeatureValue::Characteristic(Characteristic::PebAccess),
            insn.offset,
        ));
    }
}

fn is_peb_access(insn: &InsnView, fs: bool, gs: bool) -> bool {
    for operand in &insn.operands {
        let lower: String = operand.to_ascii_lowercase();
        if fs && segment_offset_is(&lower, "fs", 0x30) {
            return true;
        }
        if gs && segment_offset_is(&lower, "gs", 0x60) {
            return true;
        }
    }
    false
}

fn segment_offset_is(operand: &str, segment: &str, offset: u64) -> bool {
    let Some(seg_at): Option<usize> = operand.find(&format!("{segment}:")) else {
        return false;
    };
    let tail: &str = &operand[seg_at + segment.len() + 1..];
    let token: &str = tail
        .trim_start_matches(['[', ' '])
        .split([']', '+', '*', ' ', ','])
        .next()
        .map_or("", |value: &str| value);
    parse_immediate(token) == Some(offset) || token.parse::<u64>().ok() == Some(offset)
}

fn cross_section_flow(insn: &InsnView, layout: &LayoutInfo) -> Option<Characteristic> {
    if layout.sections.is_empty() {
        return None;
    }
    if !matches!(
        insn.class,
        InsnClass::Call | InsnClass::UnconditionalJump | InsnClass::ConditionalJump
    ) {
        return None;
    }
    let target: u64 = insn.branch_target?;
    let here: usize = layout.section_index_at(insn.offset)?;
    let there: usize = layout.section_index_at(target)?;
    (here != there).then_some(Characteristic::CrossSectionFlow)
}

fn resolve_call_target(module: &Module, insn: &InsnView, imports: &ImportMap) -> Option<String> {
    if !matches!(insn.class, InsnClass::Call | InsnClass::UnconditionalJump) {
        return None;
    }
    if let Some(target) = insn.branch_target
        && target != 0
    {
        if let Some(sym) = module.symbol_ref(target)
            && matches!(sym.kind, SymbolKind::Import)
        {
            return Some(sym.name.clone());
        }
        if let Some(name) = imports.name_at_thunk(target) {
            return Some(name.to_owned());
        }
    }
    for operand in &insn.operands {
        if let Some(va) = parse_operand_memory_address(operand)
            && let Some(name) = imports.name_at_iat(va)
        {
            return Some(name.to_owned());
        }
    }
    None
}

fn is_non_zeroing_xor(insn: &InsnView) -> bool {
    let m: &str = insn.mnemonic.as_str();
    if !matches!(m, "xor" | "pxor" | "xorps" | "xorpd" | "vpxor") {
        return false;
    }
    if insn.operands.len() < 2 {
        return false;
    }
    let lhs: String = insn.operands[0].trim().to_ascii_lowercase();
    let rhs: String = insn.operands[1].trim().to_ascii_lowercase();
    lhs != rhs
}

fn stack_string_value(block: &BasicBlock) -> Option<(u64, String)> {
    let mut bytes: Vec<(i64, Vec<u8>)> = Vec::new();
    let mut first_store: Option<u64> = None;
    for insn in &block.instructions {
        if !insn.mnemonic.eq_ignore_ascii_case("mov") || insn.operands.len() != 2 {
            continue;
        }
        let Some(disp): Option<i64> = stack_store_disp(&insn.operands[0]) else {
            continue;
        };
        let Some(imm): Option<u64> = parse_immediate(&insn.operands[1].to_ascii_lowercase()) else {
            continue;
        };
        let width: usize = mov_store_width(&insn.operands[0]);
        let mut chunk: Vec<u8> = imm.to_le_bytes().to_vec();
        chunk.truncate(width);
        bytes.push((disp, chunk));
        first_store.get_or_insert(insn.offset);
    }
    if bytes.len() < 2 {
        return None;
    }
    bytes.sort_by_key(|(disp, _): &(i64, Vec<u8>)| *disp);
    let mut assembled: Vec<u8> = Vec::new();
    for (_, chunk) in &bytes {
        assembled.extend_from_slice(chunk);
    }
    let printable: String = assembled
        .iter()
        .take_while(|b: &&u8| **b != 0)
        .filter(|b: &&u8| (0x20..0x7f).contains(*b))
        .map(|b: &u8| *b as char)
        .collect();
    let address: u64 = first_store?;
    (printable.len() >= MIN_STRING_LEN).then_some((address, printable))
}

fn stack_store_disp(dest: &str) -> Option<i64> {
    let lower: String = dest.to_ascii_lowercase();
    if !(lower.contains("rsp")
        || lower.contains("esp")
        || lower.contains("rbp")
        || lower.contains("ebp"))
    {
        return None;
    }
    let open: usize = lower.find('[')?;
    let close: usize = lower[open + 1..].find(']')? + open + 1;
    let inner: &str = &lower[open + 1..close];
    let plus: Option<usize> = inner.find('+');
    let minus: Option<usize> = inner.find('-');
    match (plus, minus) {
        (Some(p), _) => parse_disp_token(&inner[p + 1..]),
        (_, Some(m)) => parse_disp_token(&inner[m + 1..]).map(|v: i64| -v),
        _ => Some(0),
    }
}

fn parse_disp_token(token: &str) -> Option<i64> {
    let trimmed: &str = token.trim();
    if let Some(value) = parse_immediate(trimmed) {
        return i64::try_from(value).ok();
    }
    trimmed.parse::<i64>().ok()
}

fn mov_store_width(dest: &str) -> usize {
    let lower: String = dest.to_ascii_lowercase();
    if lower.contains("qword") {
        8
    } else if lower.contains("dword") {
        4
    } else if lower.contains("word") {
        2
    } else if lower.contains("byte") {
        1
    } else {
        4
    }
}

fn operand_numbers(operand: &str) -> Vec<u64> {
    let lower: String = operand.to_ascii_lowercase();
    let mut out: Vec<u64> = Vec::new();
    for token in lower.split(['[', ']', '+', '-', '*', ' ', ',', '(', ')', ':']) {
        if let Some(value) = parse_immediate(token) {
            out.push(value);
        }
    }
    out
}

fn parse_immediate(token: &str) -> Option<u64> {
    let trimmed: &str = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = trimmed.strip_suffix('h')
        && hex.len() > 1
        && hex.chars().all(|c: char| c.is_ascii_hexdigit())
        && hex.chars().any(|c: char| c.is_ascii_digit())
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    None
}

fn push_file_strings(file: &mut FeatureSet, bytes: &[u8]) {
    push_file_strings_with_limits(file, bytes, StringFeatureLimits::production());
}

fn push_file_strings_with_limits(file: &mut FeatureSet, bytes: &[u8], limits: StringFeatureLimits) {
    let scan_len: usize = bytes.len().min(limits.scan_bytes);
    let extracted: Vec<ExtractedString> = strings::extract(
        &bytes[..scan_len],
        Options {
            min_len: MIN_STRING_LEN,
            decode: true,
        },
    );
    for s in extracted.into_iter().take(limits.feature_count) {
        let value: &str = strings::head(&s.value, limits.feature_bytes);
        if value.len() < MIN_STRING_LEN {
            continue;
        }
        file.push(FeatureHit::new(
            FeatureValue::String(value.to_owned()),
            usize_u64(s.offset),
        ));
    }
}

fn push_embedded_pe(file: &mut FeatureSet, bytes: &[u8]) {
    if let Some(offset) = embedded_pe_offset(bytes) {
        file.push(FeatureHit::new(
            FeatureValue::Characteristic(Characteristic::EmbeddedPe),
            usize_u64(offset),
        ));
    }
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).map_or(u64::MAX, std::convert::identity)
}

fn embedded_pe_offset(bytes: &[u8]) -> Option<usize> {
    let scan_end: usize = bytes.len().min(PE_HEADER_SCAN_CAP);
    let mut search: usize = 1;
    while search.saturating_add(0x40) < scan_end {
        let Some(rel): Option<usize> = find_mz(&bytes[search..scan_end]) else {
            break;
        };
        let mz: usize = search.checked_add(rel)?;
        if mz != 0 && has_pe_header(bytes, mz) {
            return Some(mz);
        }
        search = mz.checked_add(1)?;
    }
    None
}

fn find_mz(window: &[u8]) -> Option<usize> {
    window.windows(2).position(|w: &[u8]| w == b"MZ")
}

fn has_pe_header(bytes: &[u8], mz: usize) -> bool {
    let e_lfanew_pos: usize = mz + 0x3c;
    let Some(slice): Option<&[u8; 4]> = bytes
        .get(e_lfanew_pos..e_lfanew_pos + 4)
        .and_then(|s: &[u8]| s.try_into().ok())
    else {
        return false;
    };
    let Some(e_lfanew): Option<usize> = usize::try_from(u32::from_le_bytes(*slice)).ok() else {
        return false;
    };
    let Some(end): Option<usize> = mz
        .checked_add(e_lfanew)
        .and_then(|p: usize| p.checked_add(4))
    else {
        return false;
    };
    bytes.get(end - 4..end) == Some(b"PE\0\0")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::feature::{Feature, OperandFeature};
    use disrobe_ir::payload::{
        DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow,
    };

    fn insn(
        offset: u64,
        mnemonic: &str,
        operands: &[&str],
        flow: InsnFlow,
        branch_target: Option<u64>,
    ) -> DisasmInstruction {
        DisasmInstruction {
            offset,
            bytes: vec![0x90],
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            flow,
            branch_target,
            ..DisasmInstruction::default()
        }
    }

    #[test]
    fn elf_import_call_yields_api_feature_at_call_site() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x0, "call", &["0x100"], InsnFlow::Call, Some(0x100)),
                insn(0x5, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![
                DisasmSymbol {
                    address: 0x0,
                    name: "main".to_owned(),
                    kind: DisasmSymbolKind::Function,
                },
                DisasmSymbol {
                    address: 0x100,
                    name: "connect".to_owned(),
                    kind: DisasmSymbolKind::Import,
                },
            ],
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, b"", &ImportMap::default());
        let main: &FunctionFeatures = scoped
            .functions
            .iter()
            .find(|f: &&FunctionFeatures| f.name == "main")
            .expect("main");
        assert_eq!(
            main.features.matches(&Feature::Api("connect".to_owned())),
            vec![0x0]
        );
        assert_eq!(
            scoped.file.matches(&Feature::Api("connect".to_owned())),
            vec![0x0]
        );
    }

    #[test]
    fn a_branch_to_address_zero_does_not_borrow_an_undefined_symbol_name() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x10, "call", &["0x0"], InsnFlow::Call, Some(0x0)),
                insn(0x15, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![
                DisasmSymbol {
                    address: 0x10,
                    name: "main".to_owned(),
                    kind: DisasmSymbolKind::Function,
                },
                DisasmSymbol {
                    address: 0x0,
                    name: "connect".to_owned(),
                    kind: DisasmSymbolKind::Import,
                },
            ],
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, b"", &ImportMap::default());
        assert!(
            scoped
                .file
                .matches(&Feature::Api("connect".to_owned()))
                .is_empty(),
            "an undefined symbol parked at address zero is not a call target"
        );
    }

    #[test]
    fn a_branch_to_a_registered_thunk_resolves_to_its_import() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x10, "call", &["0x1030"], InsnFlow::Call, Some(0x1030)),
                insn(0x15, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x10,
                name: "main".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let module: Module = Module::from_disasm(&payload);
        let imports: ImportMap = ImportMap::from_thunks(&[(0x1030, "connect".to_owned())]);
        let scoped: ScopedFeatures = extract(&module, b"", &imports);
        assert_eq!(
            scoped.file.matches(&Feature::Api("connect".to_owned())),
            vec![0x10]
        );
    }

    #[test]
    fn immediate_and_mnemonic_features_attach_to_offset() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x10, "xor", &["al", "0x5a"], InsnFlow::Sequential, None),
                insn(0x12, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x10,
                name: "dec".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, b"", &ImportMap::default());
        let dec: &FunctionFeatures = &scoped.functions[0];
        assert_eq!(dec.features.matches(&Feature::Number(0x5a)), vec![0x10]);
        assert_eq!(
            dec.features.matches(&Feature::Mnemonic("xor".to_owned())),
            vec![0x10]
        );
    }

    #[test]
    fn operand_indexed_number_keys_to_its_slot() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x10, "mov", &["eax", "0x60"], InsnFlow::Sequential, None),
                insn(0x15, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x10,
                name: "f".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, b"", &ImportMap::default());
        let f: &FunctionFeatures = &scoped.functions[0];
        assert_eq!(
            f.features.matches(&Feature::Operand {
                index: 1,
                inner: OperandFeature::Number(0x60)
            }),
            vec![0x10]
        );
        assert!(
            f.features
                .matches(&Feature::Operand {
                    index: 0,
                    inner: OperandFeature::Number(0x60)
                })
                .is_empty()
        );
    }

    #[test]
    fn segment_access_marks_fs_and_peb() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(
                    0x10,
                    "mov",
                    &["eax", "fs:[30h]"],
                    InsnFlow::Sequential,
                    None,
                ),
                insn(0x16, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x10,
                name: "peb".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, b"", &ImportMap::default());
        let f: &FunctionFeatures = &scoped.functions[0];
        assert_eq!(
            f.features
                .matches(&Feature::Characteristic(Characteristic::FsAccess)),
            vec![0x10]
        );
        assert_eq!(
            f.features
                .matches(&Feature::Characteristic(Characteristic::PebAccess)),
            vec![0x10]
        );
    }

    #[test]
    fn recursive_call_to_self_is_flagged() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x10, "call", &["0x10"], InsnFlow::Call, Some(0x10)),
                insn(0x15, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x10,
                name: "fac".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, b"", &ImportMap::default());
        let f: &FunctionFeatures = &scoped.functions[0];
        assert_eq!(
            f.features
                .matches(&Feature::Characteristic(Characteristic::RecursiveCall)),
            vec![0x10]
        );
    }

    #[test]
    fn inlined_stack_string_is_reassembled() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(
                    0x10,
                    "mov",
                    &["dword [rsp+0]", "0x64636261"],
                    InsnFlow::Sequential,
                    None,
                ),
                insn(
                    0x18,
                    "mov",
                    &["dword [rsp+4]", "0x68676665"],
                    InsnFlow::Sequential,
                    None,
                ),
                insn(0x20, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x10,
                name: "build".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, b"", &ImportMap::default());
        let f: &FunctionFeatures = &scoped.functions[0];
        assert!(
            !f.features
                .matches(&Feature::Characteristic(Characteristic::StackString))
                .is_empty()
        );
        assert!(
            !f.features
                .matches(&Feature::StringSubstring("abcdefgh".to_owned()))
                .is_empty()
        );
    }

    #[test]
    fn embedded_pe_is_detected_at_nonzero_offset() {
        let mut blob: Vec<u8> = vec![0u8; 0x100];
        let mz: usize = 0x80;
        blob[mz] = b'M';
        blob[mz + 1] = b'Z';
        let e_lfanew: u32 = 0x40;
        blob[mz + 0x3c..mz + 0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe: usize = mz.saturating_add(0x40);
        blob[pe] = b'P';
        blob[pe + 1] = b'E';
        let mut set: FeatureSet = FeatureSet::new();
        push_embedded_pe(&mut set, &blob);
        assert_eq!(
            set.matches(&Feature::Characteristic(Characteristic::EmbeddedPe)),
            vec![usize_u64(mz)]
        );
    }

    #[test]
    fn embedded_pe_rejects_out_of_range_header_offset() {
        let mut blob: Vec<u8> = vec![0u8; 0x80];
        blob[0] = b'M';
        blob[1] = b'Z';
        blob[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!has_pe_header(&blob, 0));
    }

    #[test]
    fn overflowing_section_range_matches_no_address() {
        let layout: LayoutInfo = LayoutInfo {
            sections: vec![SectionInfo {
                name: ".x".to_owned(),
                address: u64::MAX - 8,
                size: 16,
            }],
        };
        assert_eq!(layout.section_index_at(u64::MAX - 1), None);
    }

    #[test]
    fn oversized_stack_displacement_is_rejected() {
        assert_eq!(stack_store_disp("[rsp+0x8000000000000000]"), None);
    }

    #[test]
    fn file_strings_become_string_features_at_byte_offset() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![insn(0x0, "ret", &[], InsnFlow::Return, None)],
            symbol_table: vec![DisasmSymbol {
                address: 0x0,
                name: "f".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let module: Module = Module::from_disasm(&payload);
        let blob: &[u8] = b"\x00\x00SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00";
        let scoped: ScopedFeatures = extract(&module, blob, &ImportMap::default());
        let hits: Vec<u64> = scoped
            .file
            .matches(&Feature::StringSubstring("currentversion\\run".to_owned()));
        assert_eq!(hits, vec![2]);
    }

    #[test]
    fn file_string_features_stop_at_count_limit() {
        let mut blob: Vec<u8> = Vec::new();
        for index in 0..16 {
            blob.extend_from_slice(format!("word{index:04}").as_bytes());
            blob.push(0);
        }
        let limits: StringFeatureLimits = StringFeatureLimits {
            scan_bytes: blob.len(),
            feature_count: 5,
            feature_bytes: 32,
        };
        let mut set: FeatureSet = FeatureSet::new();
        push_file_strings_with_limits(&mut set, &blob, limits);
        let strings: usize = set
            .hits()
            .iter()
            .filter(|hit: &&FeatureHit| matches!(hit.value, FeatureValue::String(_)))
            .count();
        assert_eq!(strings, 5);
    }

    #[test]
    fn file_string_features_stop_at_scan_limit() {
        let blob: Vec<u8> = b"nearby\0padding\0aftercap\0".to_vec();
        let limits: StringFeatureLimits = StringFeatureLimits {
            scan_bytes: b"nearby\0padding\0".len(),
            feature_count: 32,
            feature_bytes: 32,
        };
        let mut set: FeatureSet = FeatureSet::new();
        push_file_strings_with_limits(&mut set, &blob, limits);
        assert!(
            set.matches(&Feature::StringSubstring("nearby".to_owned()))
                .contains(&0)
        );
        assert!(
            set.matches(&Feature::StringSubstring("aftercap".to_owned()))
                .is_empty()
        );
    }

    #[test]
    fn file_string_features_stop_at_utf8_boundary() {
        let blob: Vec<u8> = "abcdéfg\0".as_bytes().to_vec();
        let limits: StringFeatureLimits = StringFeatureLimits {
            scan_bytes: blob.len(),
            feature_count: 32,
            feature_bytes: 5,
        };
        let mut set: FeatureSet = FeatureSet::new();
        push_file_strings_with_limits(&mut set, &blob, limits);
        assert!(
            set.matches(&Feature::StringExact("abcd".to_owned()))
                .contains(&0)
        );
    }

    #[test]
    fn ne_metadata_reaches_capability_features() {
        const REAL_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: Vec::new(),
            symbol_table: Vec::new(),
        };
        let module: Module = Module::from_disasm(&payload);
        let scoped: ScopedFeatures = extract(&module, REAL_NE, &ImportMap::default());
        assert_eq!(
            scoped.file.matches(&Feature::Os("windows".to_owned())),
            vec![0]
        );
        assert_eq!(
            scoped.file.matches(&Feature::Format("ne".to_owned())),
            vec![0]
        );
        assert!(scoped.file.hits().iter().any(|hit: &FeatureHit| {
            matches!(&hit.value, FeatureValue::Import(name) if name.starts_with("KERNEL!"))
        }));
    }
}
