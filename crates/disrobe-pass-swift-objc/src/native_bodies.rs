use disrobe_nir::{NirModule, SourceLang};
use serde::{Deserialize, Serialize};

use crate::macho::ParsedSlice;
use crate::objc_dispatch::ObjcMessageSend;

#[cfg(not(target_arch = "wasm32"))]
use std::collections::BTreeMap;

#[cfg(not(target_arch = "wasm32"))]
use crate::macho::{CpuKind, FunctionSymbol, Section, function_symbols};
#[cfg(not(target_arch = "wasm32"))]
use crate::swift;
#[cfg(not(target_arch = "wasm32"))]
use disrobe_nir::{BinaryOp, NirFunction, NirInstr, NirOp, NirSymbol, SourceRef, SymbolKind};
#[cfg(not(target_arch = "wasm32"))]
use disrobe_pass_native::{
    Arch, CoverageScore, DisasmInsn, DwarfSourcemap, ReconstructedType, SplitDwarfInfo, TypeKind,
    TypeMember, TypeReconstruction, disassemble, reconstruct_dwarf_types,
    synthesize_dwarf_sourcemap,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceGrade {
    None,
    SymbolsOnly,
    TypesAndLines,
}

impl SourceGrade {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SymbolsOnly => "symbols-only",
            Self::TypesAndLines => "types-and-lines",
        }
    }

    #[must_use]
    pub const fn recoverable(self) -> bool {
        matches!(self, Self::TypesAndLines)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructedMember {
    pub name: String,
    pub type_name: String,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructedTypeReport {
    pub name: String,
    pub kind: String,
    pub byte_size: Option<u64>,
    pub members: Vec<ReconstructedMember>,
    pub template_params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLine {
    pub pc: u64,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmInstruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionBody {
    pub native_name: String,
    pub recovered_name: String,
    pub start: u64,
    pub end: u64,
    pub byte_len: u64,
    pub source_lines: Vec<SourceLine>,
    pub instructions: Vec<DisasmInstruction>,
    pub truncated: bool,
    pub objc_sends: Vec<ObjcMessageSend>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeBodyReport {
    pub dwarf_present: bool,
    pub grade: SourceGrade,
    pub source_recoverable: bool,
    pub nir_function_count: u32,
    pub nir_symbol_count: u32,
    pub nir: NirModule,
    pub reconstructed_types: Vec<ReconstructedTypeReport>,
    pub named_type_count: u32,
    pub text_size: u64,
    pub line_covered_bytes: u64,
    pub line_coverage_pct: f64,
    pub has_skeleton_units: bool,
    pub dwo_names: Vec<String>,
    pub disasm_arch_supported: bool,
    pub function_count: u32,
    pub functions: Vec<FunctionBody>,
}

impl NativeBodyReport {
    #[must_use]
    pub const fn empty(grade: SourceGrade) -> Self {
        Self {
            dwarf_present: false,
            grade,
            source_recoverable: false,
            nir_function_count: 0,
            nir_symbol_count: 0,
            nir: NirModule::new([0u8; 32], SourceLang::Unknown),
            reconstructed_types: Vec::new(),
            named_type_count: 0,
            text_size: 0,
            line_covered_bytes: 0,
            line_coverage_pct: 0.0,
            has_skeleton_units: false,
            dwo_names: Vec::new(),
            disasm_arch_supported: false,
            function_count: 0,
            functions: Vec::new(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[must_use]
pub const fn recover_native_bodies(_slice: &[u8], _parsed: &ParsedSlice) -> NativeBodyReport {
    NativeBodyReport::empty(SourceGrade::None)
}

#[cfg(not(target_arch = "wasm32"))]
const LINE_COVERAGE_GRADE_FLOOR: f64 = 50.0;
#[cfg(not(target_arch = "wasm32"))]
const MAX_REPORTED_TYPES: usize = 1 << 16;
#[cfg(not(target_arch = "wasm32"))]
const MAX_LISTED_FUNCTIONS: usize = 4096;
#[cfg(not(target_arch = "wasm32"))]
const MAX_FUNCTION_BYTES: u64 = 256 * 1024;
#[cfg(not(target_arch = "wasm32"))]
const MAX_INSTRUCTIONS_PER_FUNCTION: usize = 8192;
#[cfg(not(target_arch = "wasm32"))]
const MAX_LINES_PER_FUNCTION: usize = 4096;

#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn recover_native_bodies(slice: &[u8], parsed: &ParsedSlice) -> NativeBodyReport {
    let symbols: Vec<FunctionSymbol> = function_symbols(slice, parsed);
    let has_symbols: bool = !symbols.is_empty();
    let types: Option<TypeReconstruction> = reconstruct_dwarf_types(slice).ok();
    let sourcemap: Option<DwarfSourcemap> = synthesize_dwarf_sourcemap(slice).ok();
    let dwarf_present: bool = types.is_some();

    let (reconstructed_types, named_type_count, coverage, split): (
        Vec<ReconstructedTypeReport>,
        u32,
        CoverageScore,
        SplitDwarfInfo,
    ) = match types {
        Some(rec) => {
            let named: u32 = u32::try_from(rec.named_type_count()).unwrap_or(u32::MAX);
            let coverage: CoverageScore = rec.coverage;
            let split: SplitDwarfInfo = rec.split_dwarf;
            let mapped: Vec<ReconstructedTypeReport> = rec
                .types
                .into_iter()
                .take(MAX_REPORTED_TYPES)
                .map(render_type)
                .collect();
            (mapped, named, coverage, split)
        }
        None => (
            Vec::new(),
            0,
            CoverageScore {
                text_size: 0,
                covered_bytes: 0,
            },
            SplitDwarfInfo {
                has_skeleton_units: false,
                dwo_names: Vec::new(),
                has_str_offsets: false,
                has_addr_index: false,
            },
        ),
    };

    let line_coverage_pct: f64 = coverage.pct();
    let grade: SourceGrade = grade_for(named_type_count, line_coverage_pct, has_symbols);

    let arch: Option<Arch> = map_arch(parsed.header.cpu);
    let mut functions: Vec<FunctionBody> =
        build_function_bodies(slice, parsed, &symbols, sourcemap.as_ref(), arch);
    annotate_objc_sends(slice, parsed, &mut functions);
    let nir: NirModule = lift_native_nir(slice, parsed.header.cpu, &symbols, &functions);

    NativeBodyReport {
        dwarf_present,
        grade,
        source_recoverable: grade.recoverable(),
        nir_function_count: u32::try_from(nir.functions.len()).unwrap_or(u32::MAX),
        nir_symbol_count: u32::try_from(nir.symbols.len()).unwrap_or(u32::MAX),
        nir,
        named_type_count,
        text_size: coverage.text_size,
        line_covered_bytes: coverage.covered_bytes,
        line_coverage_pct,
        has_skeleton_units: split.has_skeleton_units,
        dwo_names: split.dwo_names,
        disasm_arch_supported: arch.is_some(),
        function_count: u32::try_from(functions.len()).unwrap_or(u32::MAX),
        functions,
        reconstructed_types,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn annotate_objc_sends(slice: &[u8], parsed: &ParsedSlice, functions: &mut [FunctionBody]) {
    use crate::objc_dispatch::{
        DispatchArch, DispatchMaps, annotate_instructions, build_dispatch_maps,
    };

    let arch: DispatchArch = match parsed.header.cpu {
        CpuKind::X86_64 => DispatchArch::X86_64,
        CpuKind::Arm64 | CpuKind::Arm64_32 => DispatchArch::Arm64,
        _ => return,
    };
    let maps: DispatchMaps = build_dispatch_maps(slice, parsed, arch);
    if maps.is_empty() {
        return;
    }
    for function in functions.iter_mut() {
        function.objc_sends = annotate_instructions(&function.instructions, arch, &maps);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn lift_native_nir(
    slice: &[u8],
    cpu: CpuKind,
    symbols: &[FunctionSymbol],
    functions: &[FunctionBody],
) -> NirModule {
    let lang: SourceLang = source_lang(cpu);
    let source_hash: [u8; 32] = *blake3::hash(slice).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, lang);

    let mut symbol_names: BTreeMap<u64, String> = BTreeMap::new();
    for symbol in symbols.iter().take(MAX_NIR_SYMBOLS) {
        let name: String = swift::demangle(&symbol.name).unwrap_or_else(|_| symbol.name.clone());
        symbol_names.entry(symbol.address).or_insert(name);
    }
    module.symbols = symbol_names
        .into_iter()
        .map(|(address, name): (u64, String)| NirSymbol {
            address,
            name,
            kind: SymbolKind::Function,
        })
        .collect();

    module.functions = functions
        .iter()
        .filter(|function: &&FunctionBody| !function.instructions.is_empty())
        .take(MAX_LISTED_FUNCTIONS)
        .map(|function: &FunctionBody| lift_function(lang, function))
        .collect();
    module
}

#[cfg(not(target_arch = "wasm32"))]
const MAX_NIR_SYMBOLS: usize = 8192;

#[cfg(not(target_arch = "wasm32"))]
const fn source_lang(cpu: CpuKind) -> SourceLang {
    match cpu {
        CpuKind::X86 | CpuKind::X86_64 => SourceLang::NativeX86,
        CpuKind::Arm | CpuKind::Arm64 | CpuKind::Arm64_32 => SourceLang::NativeArm,
        CpuKind::PowerPc | CpuKind::PowerPc64 | CpuKind::Unknown(_) => SourceLang::Unknown,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn lift_function(lang: SourceLang, function: &FunctionBody) -> NirFunction {
    let instructions: Vec<NirInstr> = function
        .instructions
        .iter()
        .map(|instruction: &DisasmInstruction| lift_instruction(lang, instruction))
        .collect();
    NirFunction {
        name: function.recovered_name.clone(),
        address: function.start,
        end: function.end,
        is_export: false,
        instructions,
        source: SourceRef::labelled(lang, function.start, function.native_name.clone()),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn lift_instruction(lang: SourceLang, instruction: &DisasmInstruction) -> NirInstr {
    let mnemonic: String = instruction.mnemonic.to_ascii_lowercase();
    let operands: Vec<String> = split_operands(&instruction.operands);
    let op: NirOp = classify(&mnemonic, &instruction.operands, &operands);
    let (reads_memory, writes_memory): (bool, bool) = memory_facets(&mnemonic, &operands);
    let byte_width: bool = instruction.bytes.len() == 2 || mnemonic.ends_with('b');
    NirInstr {
        address: instruction.address,
        op,
        mnemonic,
        operands,
        reads_memory,
        writes_memory,
        byte_width,
        source: SourceRef::new(lang, instruction.address),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn split_operands(operands: &str) -> Vec<String> {
    operands
        .split(',')
        .map(str::trim)
        .filter(|operand: &&str| !operand.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn classify(mnemonic: &str, raw_operands: &str, operands: &[String]) -> NirOp {
    if is_return(mnemonic) {
        return NirOp::Return;
    }
    if is_call(mnemonic) {
        return direct_target(raw_operands).map_or(NirOp::IndirectCall, |target: u64| {
            NirOp::Call {
                target: Some(target),
            }
        });
    }
    if is_unconditional_branch(mnemonic) {
        return NirOp::Branch {
            target: direct_target(raw_operands),
        };
    }
    if is_conditional_branch(mnemonic) {
        return NirOp::CondBranch {
            target: direct_target(raw_operands),
        };
    }
    if let Some(op) = binary_op(mnemonic) {
        return NirOp::BinOp { op };
    }
    if is_store(mnemonic, operands) {
        return NirOp::Store;
    }
    if is_load(mnemonic, operands) {
        return NirOp::Load;
    }
    if is_const(mnemonic, operands) {
        return NirOp::Const;
    }
    NirOp::Nop
}

#[cfg(not(target_arch = "wasm32"))]
fn direct_target(operands: &str) -> Option<u64> {
    let mut head: &str = operands.split(',').next()?.trim();
    for prefix in [
        "near ", "short ", "far ", "qword ", "dword ", "word ", "ptr ",
    ] {
        head = head.strip_prefix(prefix).unwrap_or(head).trim();
    }
    let stripped: &str = head.strip_prefix("0x").or_else(|| head.strip_suffix('h'))?;
    let cleaned: &str = stripped.strip_prefix("0x").unwrap_or(stripped);
    u64::from_str_radix(cleaned, 16).ok()
}

#[cfg(not(target_arch = "wasm32"))]
const fn is_return(mnemonic: &str) -> bool {
    starts_with_bytes(mnemonic, b"ret")
}

#[cfg(not(target_arch = "wasm32"))]
const fn is_call(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"call" | b"callq" | b"bl" | b"blr" | b"jal" | b"jalr"
    )
}

#[cfg(not(target_arch = "wasm32"))]
const fn is_unconditional_branch(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"jmp" | b"jmpq" | b"b" | b"br" | b"bra" | b"jr"
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn is_conditional_branch(mnemonic: &str) -> bool {
    (mnemonic.starts_with('j') && !is_unconditional_branch(mnemonic) && !is_call(mnemonic))
        || mnemonic.starts_with("b.")
        || matches!(mnemonic, "cbz" | "cbnz" | "tbz" | "tbnz" | "beq" | "bne")
}

#[cfg(not(target_arch = "wasm32"))]
const fn starts_with_bytes(value: &str, prefix: &[u8]) -> bool {
    let bytes: &[u8] = value.as_bytes();
    if bytes.len() < prefix.len() {
        return false;
    }
    let mut index: usize = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(not(target_arch = "wasm32"))]
const fn binary_op(mnemonic: &str) -> Option<BinaryOp> {
    match mnemonic.as_bytes() {
        b"add" | b"adc" | b"inc" => Some(BinaryOp::Add),
        b"sub" | b"sbb" | b"dec" | b"cmp" => Some(BinaryOp::Sub),
        b"imul" | b"mul" => Some(BinaryOp::Mul),
        b"idiv" | b"div" => Some(BinaryOp::Div),
        b"and" | b"test" => Some(BinaryOp::And),
        b"or" => Some(BinaryOp::Or),
        b"xor" => Some(BinaryOp::Xor),
        b"shl" | b"sal" => Some(BinaryOp::Shl),
        b"shr" | b"sar" => Some(BinaryOp::Shr),
        b"rol" => Some(BinaryOp::Rol),
        b"ror" => Some(BinaryOp::Ror),
        b"not" => Some(BinaryOp::Not),
        b"neg" => Some(BinaryOp::Neg),
        _ => None,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn is_store(mnemonic: &str, operands: &[String]) -> bool {
    let dest_memory: bool = operands
        .first()
        .is_some_and(|operand: &String| is_memory_operand(operand));
    dest_memory
        || matches!(
            mnemonic,
            "stos" | "stosb" | "stosw" | "stosd" | "stosq" | "push" | "pushfq" | "pushfd"
        )
}

#[cfg(not(target_arch = "wasm32"))]
fn is_load(mnemonic: &str, operands: &[String]) -> bool {
    let source_memory: bool = operands
        .iter()
        .skip(1)
        .any(|operand: &String| is_memory_operand(operand));
    source_memory
        || matches!(
            mnemonic,
            "lods" | "lodsb" | "lodsw" | "lodsd" | "lodsq" | "pop" | "popfq" | "popfd"
        )
}

#[cfg(not(target_arch = "wasm32"))]
fn is_const(mnemonic: &str, operands: &[String]) -> bool {
    mnemonic == "lea"
        || operands
            .iter()
            .any(|operand: &String| immediate_operand(operand).is_some())
}

#[cfg(not(target_arch = "wasm32"))]
fn memory_facets(mnemonic: &str, operands: &[String]) -> (bool, bool) {
    let reads_memory: bool = is_load(mnemonic, operands)
        || is_return(mnemonic)
        || operands
            .iter()
            .skip(1)
            .any(|operand: &String| is_memory_operand(operand));
    let writes_memory: bool = is_store(mnemonic, operands)
        || is_call(mnemonic)
        || operands
            .first()
            .is_some_and(|operand: &String| is_memory_operand(operand));
    (reads_memory, writes_memory)
}

#[cfg(not(target_arch = "wasm32"))]
fn is_memory_operand(operand: &str) -> bool {
    operand.contains('[')
        || operand.contains(']')
        || operand.starts_with("byte ptr ")
        || operand.starts_with("word ptr ")
        || operand.starts_with("dword ptr ")
        || operand.starts_with("qword ptr ")
}

#[cfg(not(target_arch = "wasm32"))]
fn immediate_operand(operand: &str) -> Option<u64> {
    let head: &str = operand.trim_start_matches("0x");
    if head != operand {
        return u64::from_str_radix(head, 16).ok();
    }
    if let Some(hex) = operand.strip_suffix('h') {
        return u64::from_str_radix(hex, 16).ok();
    }
    operand.parse::<u64>().ok()
}

#[cfg(not(target_arch = "wasm32"))]
fn build_function_bodies(
    slice: &[u8],
    parsed: &ParsedSlice,
    symbols: &[FunctionSymbol],
    sourcemap: Option<&DwarfSourcemap>,
    arch: Option<Arch>,
) -> Vec<FunctionBody> {
    if symbols.is_empty() {
        return Vec::new();
    }
    let mut sorted: Vec<&FunctionSymbol> = symbols.iter().collect();
    sorted.sort_by_key(|s: &&FunctionSymbol| s.address);
    sorted.dedup_by_key(|s: &mut &FunctionSymbol| s.address);

    let mut bodies: Vec<FunctionBody> = Vec::new();
    for (idx, sym) in sorted.iter().enumerate() {
        if bodies.len() >= MAX_LISTED_FUNCTIONS {
            break;
        }
        let next_addr: Option<u64> = sorted.get(idx + 1).map(|s: &&FunctionSymbol| s.address);
        let Some(end): Option<u64> =
            end_boundary(parsed, sym.address, sym.section_index, next_addr)
        else {
            continue;
        };
        let recovered_name: String =
            swift::demangle(&sym.name).unwrap_or_else(|_| sym.name.clone());
        let source_lines: Vec<SourceLine> = sourcemap
            .map_or_else(Vec::new, |m: &DwarfSourcemap| {
                lines_for(m, sym.address, end)
            });
        let instructions: Vec<DisasmInstruction> =
            disasm_for(slice, parsed, sym.address, end, arch);
        let truncated: bool = instructions.len() >= MAX_INSTRUCTIONS_PER_FUNCTION;
        if instructions.is_empty() && source_lines.is_empty() {
            continue;
        }
        bodies.push(FunctionBody {
            native_name: sym.name.clone(),
            recovered_name,
            start: sym.address,
            end,
            byte_len: end.saturating_sub(sym.address),
            source_lines,
            instructions,
            truncated,
            objc_sends: Vec::new(),
        });
    }
    bodies
}

#[cfg(not(target_arch = "wasm32"))]
fn disasm_for(
    slice: &[u8],
    parsed: &ParsedSlice,
    start: u64,
    end: u64,
    arch: Option<Arch>,
) -> Vec<DisasmInstruction> {
    let Some(arch): Option<Arch> = arch else {
        return Vec::new();
    };
    let Some(code): Option<&[u8]> = carve(slice, parsed, start, end) else {
        return Vec::new();
    };
    let Ok(decoded): Result<Vec<DisasmInsn>, _> = disassemble(arch, start, code) else {
        return Vec::new();
    };
    decoded
        .into_iter()
        .take(MAX_INSTRUCTIONS_PER_FUNCTION)
        .map(render_insn)
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn lines_for(map: &DwarfSourcemap, start: u64, end: u64) -> Vec<SourceLine> {
    map.line_rows
        .iter()
        .filter(|r| r.pc >= start && r.pc < end)
        .take(MAX_LINES_PER_FUNCTION)
        .map(|r| SourceLine {
            pc: r.pc,
            file: r.file.clone(),
            line: r.line,
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn end_boundary(
    parsed: &ParsedSlice,
    start: u64,
    section_index: u8,
    next_addr: Option<u64>,
) -> Option<u64> {
    let section: &Section = nth_section(parsed, section_index)?;
    let sec_end: u64 = section.addr.saturating_add(section.size);
    if start < section.addr || start >= sec_end {
        return None;
    }
    let bounded_next: Option<u64> = next_addr.filter(|n: &u64| *n > start && *n <= sec_end);
    let end: u64 = bounded_next.unwrap_or(sec_end);
    if end <= start {
        return None;
    }
    Some(end.min(start.saturating_add(MAX_FUNCTION_BYTES)))
}

#[cfg(not(target_arch = "wasm32"))]
fn nth_section(parsed: &ParsedSlice, section_index: u8) -> Option<&Section> {
    let mut running: u32 = 0;
    for seg in &parsed.segments {
        for sect in &seg.sections {
            running = running.saturating_add(1);
            if u32::from(section_index) == running {
                return Some(sect);
            }
        }
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn carve<'a>(slice: &'a [u8], parsed: &ParsedSlice, start: u64, end: u64) -> Option<&'a [u8]> {
    let len: u64 = end.checked_sub(start)?;
    if len == 0 || len > MAX_FUNCTION_BYTES {
        return None;
    }
    for seg in &parsed.segments {
        for sect in &seg.sections {
            let sec_end: u64 = sect.addr.saturating_add(sect.size);
            if start >= sect.addr && end <= sec_end {
                if crate::macho::section_is_encrypted_at_rest(parsed, sect) {
                    return None;
                }
                let rel: usize = usize::try_from(start - sect.addr).ok()?;
                let file_start: usize = (sect.offset as usize).checked_add(rel)?;
                let span: usize = usize::try_from(len).ok()?;
                return slice.get(file_start..file_start.checked_add(span)?);
            }
        }
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn grade_for(named_type_count: u32, line_coverage_pct: f64, has_symbols: bool) -> SourceGrade {
    if named_type_count > 0 && line_coverage_pct >= LINE_COVERAGE_GRADE_FLOOR {
        SourceGrade::TypesAndLines
    } else if has_symbols || named_type_count > 0 {
        SourceGrade::SymbolsOnly
    } else {
        SourceGrade::None
    }
}

#[cfg(not(target_arch = "wasm32"))]
const fn map_arch(cpu: CpuKind) -> Option<Arch> {
    match cpu {
        CpuKind::X86 => Some(Arch::X86),
        CpuKind::X86_64 => Some(Arch::X86_64),
        CpuKind::Arm64 | CpuKind::Arm64_32 => Some(Arch::Aarch64),
        CpuKind::Arm | CpuKind::PowerPc | CpuKind::PowerPc64 | CpuKind::Unknown(_) => None,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn render_type(t: ReconstructedType) -> ReconstructedTypeReport {
    ReconstructedTypeReport {
        name: t.name,
        kind: kind_label(t.kind).to_owned(),
        byte_size: t.byte_size,
        members: t.members.into_iter().map(render_member).collect(),
        template_params: t.template_params,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn render_member(m: TypeMember) -> ReconstructedMember {
    ReconstructedMember {
        name: m.name,
        type_name: m.type_name,
        offset: m.offset,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn render_insn(insn: DisasmInsn) -> DisasmInstruction {
    DisasmInstruction {
        address: insn.address,
        bytes: hex_bytes(&insn.bytes),
        mnemonic: insn.mnemonic,
        operands: insn.operands,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn hex_bytes(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

#[cfg(not(target_arch = "wasm32"))]
const fn nibble(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        _ => (b'a' + (v - 10)) as char,
    }
}

#[cfg(not(target_arch = "wasm32"))]
const fn kind_label(kind: TypeKind) -> &'static str {
    match kind {
        TypeKind::Base => "base",
        TypeKind::Pointer => "pointer",
        TypeKind::Reference => "reference",
        TypeKind::Structure => "structure",
        TypeKind::Class => "class",
        TypeKind::Union => "union",
        TypeKind::Enumeration => "enumeration",
        TypeKind::Array => "array",
        TypeKind::Typedef => "typedef",
        TypeKind::Const => "const",
        TypeKind::Volatile => "volatile",
        TypeKind::Subroutine => "subroutine",
        TypeKind::Unspecified => "unspecified",
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn grade_promotes_only_with_types_and_line_coverage() {
        assert_eq!(grade_for(10, 90.0, true), SourceGrade::TypesAndLines);
        assert_eq!(grade_for(10, 90.0, false), SourceGrade::TypesAndLines);
        assert_eq!(grade_for(0, 90.0, true), SourceGrade::SymbolsOnly);
        assert_eq!(grade_for(4, 20.0, true), SourceGrade::SymbolsOnly);
        assert_eq!(grade_for(0, 0.0, true), SourceGrade::SymbolsOnly);
        assert_eq!(grade_for(0, 0.0, false), SourceGrade::None);
    }

    #[test]
    fn recoverable_only_on_types_and_lines() {
        assert!(SourceGrade::TypesAndLines.recoverable());
        assert!(!SourceGrade::SymbolsOnly.recoverable());
        assert!(!SourceGrade::None.recoverable());
    }

    #[test]
    fn empty_report_carries_requested_grade() {
        let r: NativeBodyReport = NativeBodyReport::empty(SourceGrade::SymbolsOnly);
        assert!(!r.dwarf_present);
        assert_eq!(r.grade, SourceGrade::SymbolsOnly);
        assert!(!r.source_recoverable);
        assert!(r.nir.functions.is_empty());
        assert_eq!(r.nir.lang, SourceLang::Unknown);
    }

    #[test]
    fn map_arch_covers_apple_cpus() {
        assert_eq!(map_arch(CpuKind::Arm64), Some(Arch::Aarch64));
        assert_eq!(map_arch(CpuKind::X86_64), Some(Arch::X86_64));
        assert_eq!(map_arch(CpuKind::PowerPc), None);
    }

    fn instruction(address: u64, mnemonic: &str, operands: &str, bytes: &str) -> DisasmInstruction {
        DisasmInstruction {
            address,
            bytes: bytes.to_owned(),
            mnemonic: mnemonic.to_owned(),
            operands: operands.to_owned(),
        }
    }

    #[test]
    fn function_body_lifts_control_flow_to_nir() {
        let body: FunctionBody = FunctionBody {
            native_name: "_greet".to_owned(),
            recovered_name: "greet".to_owned(),
            start: 0x1000,
            end: 0x1010,
            byte_len: 0x10,
            source_lines: Vec::new(),
            instructions: vec![
                instruction(0x1000, "bl", "0x2000", "94000400"),
                instruction(0x1004, "b.eq", "0x3000", "54000020"),
                instruction(0x1008, "ret", "", "d65f03c0"),
            ],
            truncated: false,
            objc_sends: Vec::new(),
        };
        let function: NirFunction = lift_function(SourceLang::NativeArm, &body);
        assert_eq!(function.name, "greet");
        assert!(matches!(function.instructions[0].op, NirOp::Call { .. }));
        assert_eq!(function.instructions[0].direct_target(), Some(0x2000));
        assert!(matches!(
            function.instructions[1].op,
            NirOp::CondBranch { .. }
        ));
        assert_eq!(function.instructions[1].direct_target(), Some(0x3000));
        assert!(matches!(function.instructions[2].op, NirOp::Return));
    }
}
