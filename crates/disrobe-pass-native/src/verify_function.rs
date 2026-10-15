use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, Register};
use object::{
    Architecture, BinaryFormat, Object as _, ObjectSection as _, ObjectSymbol as _, RelocationKind,
    RelocationTarget, SectionFlags, SectionKind, SymbolKind, SymbolSection,
};
use serde::{Deserialize, Serialize};

use crate::pseudo_c::{Abi, recover_leaf_function_abi};
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

pub const DEFAULT_CASES: u32 = 2_000;
pub const DEFAULT_SEED: u64 = 0xD15B_0BE5_51A7_1C5E;
pub const DEFAULT_STEP_CAP: u64 = 100_000;
pub const MAX_CASES: u32 = 100_000;
pub const MAX_DIVERGENCES: usize = 32;
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const SCRATCH_BYTES: usize = 256;

const STACK_BYTES: u64 = 1024 * 1024;
const STACK_BASE_32: u64 = 0x7000_0000;
const STACK_BASE_64: u64 = 0x0000_7FFE_0000_0000;
const SCRATCH_BASE_32: u64 = 0x5000_0000;
const SCRATCH_BASE_64: u64 = 0x0000_5000_0000_0000;
const CANDIDATE_BASE_32: u64 = 0x2000_0000;
const CANDIDATE_BASE_64: u64 = 0x2000_0000;
const RETURN_SENTINEL_32: u64 = 0x7FFE_0000;
const RETURN_SENTINEL_64: u64 = 0x0000_7FFF_FFFE_0000;
const MAX_SECTIONS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum VerifyFunctionError {
    #[error("DR-NATIVE-0250: cannot parse {side} object: {message}")]
    Object { side: &'static str, message: String },
    #[error(
        "DR-NATIVE-0251: unsupported architecture {0:?}; verify-function supports x86 and x86-64"
    )]
    Architecture(Architecture),
    #[error("DR-NATIVE-0252: function selector `{0}` did not resolve to executable code")]
    FunctionNotFound(String),
    #[error("DR-NATIVE-0253: candidate object does not define function `{0}`")]
    CandidateFunctionNotFound(String),
    #[error("DR-NATIVE-0254: invalid signature `{signature}`: {message}")]
    Signature { signature: String, message: String },
    #[error("DR-NATIVE-0255: candidate references external symbol `{0}`")]
    ExternalSymbol(String),
    #[error(
        "DR-NATIVE-0256: unsupported candidate relocation {kind:?} ({size} bits) for `{target}`"
    )]
    Relocation {
        kind: RelocationKind,
        size: u8,
        target: String,
    },
    #[error("DR-NATIVE-0257: verification limit refused: {0}")]
    Limit(String),
    #[error("DR-NATIVE-0258: emulator image setup failed: {0}")]
    Emulator(String),
    #[error(
        "DR-NATIVE-0259: the decompiler could not recover a default signature for `{function}`: {message}; pass --signature"
    )]
    SignatureRecovery { function: String, message: String },
}

pub type VerifyFunctionResult<T> = Result<T, VerifyFunctionError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallingConvention {
    SysV,
    MsX64,
    Cdecl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgumentKind {
    Integer { width: u8, signed: bool },
    Pointer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionSignature {
    return_width: u8,
    arguments: Vec<ArgumentKind>,
    convention: CallingConvention,
}

#[derive(Debug, Clone)]
pub struct VerifyFunctionOptions {
    pub function: String,
    pub signature: Option<String>,
    pub cases: u32,
    pub seed: u64,
    pub step_cap: u64,
    pub divergence_limit: usize,
}

impl VerifyFunctionOptions {
    #[must_use]
    pub fn new(function: impl Into<String>) -> Self {
        Self {
            function: function.into(),
            signature: None,
            cases: DEFAULT_CASES,
            seed: DEFAULT_SEED,
            step_cap: DEFAULT_STEP_CAP,
            divergence_limit: MAX_DIVERGENCES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseClassification {
    Match,
    Mismatch,
    OriginalFaulted,
    CandidateFaulted,
    StepCap,
    Escaped,
}

impl CaseClassification {
    const fn label(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Mismatch => "mismatch",
            Self::OriginalFaulted => "original-faulted",
            Self::CandidateFaulted => "candidate-faulted",
            Self::StepCap => "step-cap",
            Self::Escaped => "escaped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseDivergence {
    pub case_index: u32,
    pub inputs: Vec<String>,
    pub classification: CaseClassification,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyFunctionReport {
    pub schema: String,
    pub function: String,
    pub address: u64,
    pub signature: String,
    pub calling_convention: CallingConvention,
    pub cases: u32,
    pub seed: u64,
    pub step_cap: u64,
    pub totals: BTreeMap<String, u32>,
    pub divergences: Vec<CaseDivergence>,
    pub verdict: String,
}

#[derive(Debug, Clone)]
struct DataSection {
    name: String,
    address: u64,
    size: u64,
}

#[derive(Debug, Clone)]
struct LoadedImage {
    memory: Memory,
    entry: u64,
    mode: CpuMode,
    data_sections: Vec<DataSection>,
    symbols: BTreeMap<u64, String>,
}

#[derive(Debug, Clone)]
struct GeneratedCase {
    arguments: Vec<u64>,
    scratch: Vec<u8>,
}

#[derive(Debug)]
struct Execution {
    termination: Termination,
    return_value: u64,
    scratch: Vec<u8>,
    data_writes: Vec<(String, u64, u8)>,
}

#[derive(Debug)]
enum Termination {
    Returned,
    StepCap,
    Fault(String),
    Escaped(String),
}

#[derive(Debug, Default)]
struct EscapeHost {
    target: Option<u64>,
}

impl HostCall for EscapeHost {
    fn dispatch(
        &mut self,
        target: u64,
        _regs: &mut Regs,
        _memory: &mut Memory,
    ) -> crate::Result<bool> {
        self.target = Some(target);
        Ok(false)
    }
}

#[must_use]
pub fn signature_for_format(format: BinaryFormat, mode: CpuMode) -> CallingConvention {
    match mode {
        CpuMode::Bits32 => CallingConvention::Cdecl,
        CpuMode::Bits64 if format == BinaryFormat::Coff || format == BinaryFormat::Pe => {
            CallingConvention::MsX64
        }
        CpuMode::Bits64 => CallingConvention::SysV,
    }
}

pub fn verify_function(
    original: &[u8],
    candidate: &[u8],
    options: &VerifyFunctionOptions,
) -> VerifyFunctionResult<VerifyFunctionReport> {
    validate_options(options)?;
    let original_file: object::File<'_> =
        object::File::parse(original).map_err(|error| VerifyFunctionError::Object {
            side: "original",
            message: error.to_string(),
        })?;
    let mode: CpuMode = mode_for_architecture(original_file.architecture())?;
    let convention: CallingConvention = signature_for_format(original_file.format(), mode);
    let (original_address, original_name): (u64, String) =
        resolve_function(&original_file, &options.function)?;
    let signature: FunctionSignature = match options.signature.as_deref() {
        Some(text) => parse_signature(text, convention)?,
        None => recover_signature(
            &original_file,
            original,
            original_address,
            &original_name,
            convention,
        )?,
    };
    let original_image: LoadedImage = load_original(&original_file, original_address, mode)?;
    let candidate_file: object::File<'_> =
        object::File::parse(candidate).map_err(|error| VerifyFunctionError::Object {
            side: "candidate",
            message: error.to_string(),
        })?;
    let candidate_mode: CpuMode = mode_for_architecture(candidate_file.architecture())?;
    if candidate_mode != mode {
        return Err(VerifyFunctionError::Limit(format!(
            "candidate architecture {:?} does not match original {:?}",
            candidate_file.architecture(),
            original_file.architecture()
        )));
    }
    let candidate_image: LoadedImage = load_candidate(&candidate_file, &original_name, mode)?;
    let mut totals: BTreeMap<String, u32> = BTreeMap::new();
    for classification in [
        CaseClassification::Match,
        CaseClassification::Mismatch,
        CaseClassification::OriginalFaulted,
        CaseClassification::CandidateFaulted,
        CaseClassification::StepCap,
        CaseClassification::Escaped,
    ] {
        totals.insert(classification.label().to_owned(), 0);
    }
    let mut divergences: Vec<CaseDivergence> = Vec::new();
    let mut generator: CaseGenerator = CaseGenerator::new(options.seed, &signature);
    for case_index in 0..options.cases {
        let generated: GeneratedCase = generator.generate(case_index);
        let original_execution: Execution =
            execute(&original_image, &signature, &generated, options.step_cap)?;
        let candidate_execution: Execution =
            execute(&candidate_image, &signature, &generated, options.step_cap)?;
        let (classification, detail): (CaseClassification, String) = compare_executions(
            &original_execution,
            &candidate_execution,
            signature.return_width,
        );
        if let Some(total) = totals.get_mut(classification.label()) {
            *total = total.saturating_add(1);
        }
        if classification != CaseClassification::Match
            && divergences.len() < options.divergence_limit
        {
            divergences.push(CaseDivergence {
                case_index,
                inputs: render_inputs(&generated, &signature),
                classification,
                detail,
            });
        }
    }
    let non_matches: u32 = totals
        .iter()
        .filter(|(label, _count): &(&String, &u32)| label.as_str() != "match")
        .map(|(_label, count): (&String, &u32)| *count)
        .sum();
    Ok(VerifyFunctionReport {
        schema: "disrobe.native.verify-function/v1".to_owned(),
        function: original_name,
        address: original_address,
        signature: render_signature(&signature),
        calling_convention: convention,
        cases: options.cases,
        seed: options.seed,
        step_cap: options.step_cap,
        totals,
        divergences,
        verdict: if non_matches == 0 {
            "equivalent-on-cases".to_owned()
        } else {
            "diverged-on-cases".to_owned()
        },
    })
}

fn validate_options(options: &VerifyFunctionOptions) -> VerifyFunctionResult<()> {
    if options.cases == 0 || options.cases > MAX_CASES {
        return Err(VerifyFunctionError::Limit(format!(
            "cases must be between 1 and {MAX_CASES}"
        )));
    }
    if options.step_cap == 0 || options.step_cap > 10_000_000 {
        return Err(VerifyFunctionError::Limit(
            "step cap must be between 1 and 10000000".to_owned(),
        ));
    }
    if options.divergence_limit > MAX_DIVERGENCES {
        return Err(VerifyFunctionError::Limit(format!(
            "divergence limit exceeds {MAX_DIVERGENCES}"
        )));
    }
    Ok(())
}

fn mode_for_architecture(architecture: Architecture) -> VerifyFunctionResult<CpuMode> {
    match architecture {
        Architecture::I386 => Ok(CpuMode::Bits32),
        Architecture::X86_64 | Architecture::X86_64_X32 => Ok(CpuMode::Bits64),
        other => Err(VerifyFunctionError::Architecture(other)),
    }
}

fn resolve_function(
    file: &object::File<'_>,
    selector: &str,
) -> VerifyFunctionResult<(u64, String)> {
    if let Some(raw) = selector.strip_prefix("0x") {
        let address: u64 = u64::from_str_radix(raw, 16)
            .map_err(|_| VerifyFunctionError::FunctionNotFound(selector.to_owned()))?;
        let name: String = file
            .symbols()
            .find(|symbol: &object::Symbol<'_, '_>| {
                symbol.kind() == SymbolKind::Text && symbol.address() == address
            })
            .and_then(|symbol: object::Symbol<'_, '_>| symbol.name().ok())
            .unwrap_or(selector)
            .to_owned();
        return executable_address(file, address)
            .then_some((address, name))
            .ok_or_else(|| VerifyFunctionError::FunctionNotFound(selector.to_owned()));
    }
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name): Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        if symbol.kind() == SymbolKind::Text
            && (name == selector || name.strip_prefix('_') == Some(selector))
            && executable_address(file, symbol.address())
        {
            return Ok((symbol.address(), selector.to_owned()));
        }
    }
    if let Ok(exports) = file.exports() {
        for export in exports {
            let Ok(name): Result<&str, std::str::Utf8Error> = std::str::from_utf8(export.name())
            else {
                continue;
            };
            if name != selector && name.strip_prefix('_') != Some(selector) {
                continue;
            }
            if let Some(address) = normalized_export_address(file, export.address()) {
                return Ok((address, selector.to_owned()));
            }
        }
    }
    Err(VerifyFunctionError::FunctionNotFound(selector.to_owned()))
}

fn normalized_export_address(file: &object::File<'_>, address: u64) -> Option<u64> {
    if executable_address(file, address) {
        return Some(address);
    }
    let absolute: u64 = file.relative_address_base().saturating_add(address);
    executable_address(file, absolute).then_some(absolute)
}

fn executable_address(file: &object::File<'_>, address: u64) -> bool {
    file.sections().any(|section: object::Section<'_, '_>| {
        section.kind() == SectionKind::Text
            && address >= section.address()
            && address < section.address().saturating_add(section.size())
    })
}

fn recover_signature(
    file: &object::File<'_>,
    _bytes: &[u8],
    address: u64,
    function: &str,
    convention: CallingConvention,
) -> VerifyFunctionResult<FunctionSignature> {
    let section: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            address >= section.address()
                && address < section.address().saturating_add(section.size())
        })
        .ok_or_else(|| VerifyFunctionError::FunctionNotFound(function.to_owned()))?;
    let section_data: &[u8] = section
        .data()
        .map_err(|error| VerifyFunctionError::Object {
            side: "original",
            message: error.to_string(),
        })?;
    let start: usize =
        usize::try_from(address.saturating_sub(section.address())).map_err(|_| {
            VerifyFunctionError::Limit("function offset does not fit memory".to_owned())
        })?;
    let declared_size: Option<usize> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .find(|symbol: &object::Symbol<'_, '_>| symbol.address() == address)
        .and_then(|symbol: object::Symbol<'_, '_>| usize::try_from(symbol.size()).ok())
        .filter(|size: &usize| *size > 0);
    let mut next_address: u64 = section.address().saturating_add(section.size());
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let candidate: u64 = symbol.address();
        if candidate > address && candidate < next_address {
            next_address = candidate;
        }
    }
    if let Ok(exports) = file.exports() {
        for export in exports {
            if let Some(candidate) = normalized_export_address(file, export.address())
                && candidate > address
                && candidate < next_address
            {
                next_address = candidate;
            }
        }
    }
    let inferred_size: usize = usize::try_from(next_address.saturating_sub(address))
        .unwrap_or(usize::MAX)
        .min(64 * 1024);
    let symbol_size: usize = declared_size.unwrap_or(inferred_size);
    let end: usize = start.saturating_add(symbol_size).min(section_data.len());
    let code: &[u8] =
        section_data
            .get(start..end)
            .ok_or_else(|| VerifyFunctionError::SignatureRecovery {
                function: function.to_owned(),
                message: "function bytes are outside the containing section".to_owned(),
            })?;
    if convention == CallingConvention::Cdecl {
        return Ok(recover_cdecl_signature(code, address));
    }
    let abi: Abi = match convention {
        CallingConvention::SysV => Abi::SysV,
        CallingConvention::MsX64 => Abi::MsX64,
        CallingConvention::Cdecl => unreachable!(),
    };
    let recovered: crate::pseudo_c::LeafRecovery = recover_leaf_function_abi(code, address, abi)
        .map_err(|error| VerifyFunctionError::SignatureRecovery {
            function: function.to_owned(),
            message: error.to_string(),
        })?;
    let arguments: Vec<ArgumentKind> = recovered
        .signature
        .integer_width_bits()
        .into_iter()
        .map(|width: u32| ArgumentKind::Integer {
            width: u8::try_from(width).unwrap_or(64),
            signed: false,
        })
        .collect();
    Ok(FunctionSignature {
        return_width: u8::try_from(recovered.return_width_bits).unwrap_or(64),
        arguments,
        convention,
    })
}

fn recover_cdecl_signature(code: &[u8], address: u64) -> FunctionSignature {
    let mut decoder: Decoder<'_> = Decoder::with_ip(32, code, address, DecoderOptions::NONE);
    let mut instruction: Instruction = Instruction::default();
    let mut arity: usize = 0;
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }
        let first_offset: u64 = match instruction.memory_base() {
            Register::ESP => 4,
            Register::EBP => 8,
            _ => continue,
        };
        let displacement: u64 = instruction.memory_displacement64();
        if displacement < first_offset || displacement.saturating_sub(first_offset) % 4 != 0 {
            continue;
        }
        let slot: usize =
            usize::try_from((displacement.saturating_sub(first_offset) / 4) + 1).unwrap_or(0);
        arity = arity.max(slot.min(16));
    }
    FunctionSignature {
        return_width: 32,
        arguments: vec![
            ArgumentKind::Integer {
                width: 32,
                signed: false,
            };
            arity
        ],
        convention: CallingConvention::Cdecl,
    }
}

fn parse_signature(
    text: &str,
    convention: CallingConvention,
) -> VerifyFunctionResult<FunctionSignature> {
    let trimmed: &str = text.trim();
    let Some(open): Option<usize> = trimmed.find('(') else {
        return signature_error(text, "missing `(`");
    };
    if !trimmed.ends_with(')') {
        return signature_error(text, "missing closing `)`");
    }
    let return_token: &str = trimmed[..open].trim();
    let return_width: u8 = parse_integer_type(return_token)
        .map(|(width, _signed): (u8, bool)| width)
        .ok_or_else(|| VerifyFunctionError::Signature {
            signature: text.to_owned(),
            message: "return type must be an 8, 16, 32 or 64-bit integer".to_owned(),
        })?;
    let body: &str = &trimmed[open + 1..trimmed.len() - 1];
    let mut arguments: Vec<ArgumentKind> = Vec::new();
    if !body.trim().is_empty() && body.trim() != "void" {
        for token in body.split(',') {
            let arg: &str = token.trim();
            if matches!(arg, "ptr" | "pointer" | "void*" | "u8*" | "char*") {
                arguments.push(ArgumentKind::Pointer);
            } else if let Some((width, signed)) = parse_integer_type(arg) {
                arguments.push(ArgumentKind::Integer { width, signed });
            } else {
                return signature_error(text, &format!("unsupported argument type `{arg}`"));
            }
        }
    }
    let max_args: usize = match convention {
        CallingConvention::SysV => 12,
        CallingConvention::MsX64 => 12,
        CallingConvention::Cdecl => 16,
    };
    if arguments.len() > max_args {
        return signature_error(text, &format!("more than {max_args} arguments"));
    }
    Ok(FunctionSignature {
        return_width,
        arguments,
        convention,
    })
}

fn parse_integer_type(token: &str) -> Option<(u8, bool)> {
    match token.trim() {
        "i8" | "int8_t" => Some((8, true)),
        "u8" | "uint8_t" => Some((8, false)),
        "i16" | "int16_t" | "short" => Some((16, true)),
        "u16" | "uint16_t" | "unsigned short" => Some((16, false)),
        "i32" | "int32_t" | "int" => Some((32, true)),
        "u32" | "uint32_t" | "unsigned" | "unsigned int" => Some((32, false)),
        "i64" | "int64_t" | "long long" => Some((64, true)),
        "u64" | "uint64_t" | "unsigned long long" => Some((64, false)),
        _ => None,
    }
}

fn signature_error<T>(text: &str, message: &str) -> VerifyFunctionResult<T> {
    Err(VerifyFunctionError::Signature {
        signature: text.to_owned(),
        message: message.to_owned(),
    })
}

fn render_signature(signature: &FunctionSignature) -> String {
    let arguments: Vec<String> = signature
        .arguments
        .iter()
        .map(|argument: &ArgumentKind| match argument {
            ArgumentKind::Pointer => "ptr".to_owned(),
            ArgumentKind::Integer { width, signed } => {
                format!("{}{width}", if *signed { 'i' } else { 'u' })
            }
        })
        .collect();
    format!("u{}({})", signature.return_width, arguments.join(","))
}

fn load_original(
    file: &object::File<'_>,
    entry: u64,
    mode: CpuMode,
) -> VerifyFunctionResult<LoadedImage> {
    let mut memory: Memory = Memory::new();
    let mut mapped_bytes: u64 = 0;
    let mut data_sections: Vec<DataSection> = Vec::new();
    let mut section_count: usize = 0;
    for section in file.sections() {
        if !loadable_section(section.kind()) || section.size() == 0 {
            continue;
        }
        section_count = section_count.saturating_add(1);
        if section_count > MAX_SECTIONS {
            return Err(VerifyFunctionError::Limit(format!(
                "original has more than {MAX_SECTIONS} loadable sections"
            )));
        }
        mapped_bytes = mapped_bytes.saturating_add(section.size());
        if mapped_bytes > MAX_IMAGE_BYTES {
            return Err(VerifyFunctionError::Limit(format!(
                "original loadable sections exceed {MAX_IMAGE_BYTES} bytes"
            )));
        }
        let address: u64 = section.address();
        let perm: Perm = section_perm(section.kind(), section.flags());
        memory
            .map(address, section.size(), perm)
            .map_err(|error| VerifyFunctionError::Emulator(error.to_string()))?;
        let data: &[u8] = section
            .data()
            .map_err(|error| VerifyFunctionError::Object {
                side: "original",
                message: error.to_string(),
            })?;
        if u64::try_from(data.len()).unwrap_or(u64::MAX) > section.size() {
            return Err(VerifyFunctionError::Limit(
                "original section data exceeds its mapped size".to_owned(),
            ));
        }
        memory.write_unchecked(address, data);
        if perm.write {
            data_sections.push(DataSection {
                name: section.name().unwrap_or("<data>").to_owned(),
                address,
                size: section.size(),
            });
        }
    }
    let symbols: BTreeMap<u64, String> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter_map(|symbol: object::Symbol<'_, '_>| {
            let name: &str = symbol.name().ok()?;
            (!name.is_empty()).then(|| (symbol.address(), name.to_owned()))
        })
        .collect();
    Ok(LoadedImage {
        memory,
        entry,
        mode,
        data_sections,
        symbols,
    })
}

fn load_candidate(
    file: &object::File<'_>,
    requested_name: &str,
    mode: CpuMode,
) -> VerifyFunctionResult<LoadedImage> {
    let mut memory: Memory = Memory::new();
    let mut bases: BTreeMap<usize, u64> = BTreeMap::new();
    let mut data_sections: Vec<DataSection> = Vec::new();
    let mut cursor: u64 = match mode {
        CpuMode::Bits32 => CANDIDATE_BASE_32,
        CpuMode::Bits64 => CANDIDATE_BASE_64,
    };
    let mut mapped_bytes: u64 = 0;
    let mut section_count: usize = 0;
    for section in file.sections() {
        if !loadable_section(section.kind()) || section.size() == 0 {
            continue;
        }
        section_count = section_count.saturating_add(1);
        if section_count > MAX_SECTIONS {
            return Err(VerifyFunctionError::Limit(format!(
                "candidate has more than {MAX_SECTIONS} loadable sections"
            )));
        }
        let alignment: u64 = section.align().clamp(1, 0x1000);
        cursor = align_up(cursor, alignment.max(0x1000))?;
        let size: u64 = align_up(section.size(), 0x1000)?;
        mapped_bytes = mapped_bytes.saturating_add(size);
        if mapped_bytes > MAX_IMAGE_BYTES {
            return Err(VerifyFunctionError::Limit(format!(
                "candidate loadable sections exceed {MAX_IMAGE_BYTES} bytes"
            )));
        }
        let perm: Perm = section_perm(section.kind(), section.flags());
        memory
            .map(cursor, size, perm)
            .map_err(|error| VerifyFunctionError::Emulator(error.to_string()))?;
        let data: &[u8] = section
            .data()
            .map_err(|error| VerifyFunctionError::Object {
                side: "candidate",
                message: error.to_string(),
            })?;
        if u64::try_from(data.len()).unwrap_or(u64::MAX) > section.size() {
            return Err(VerifyFunctionError::Limit(
                "candidate section data exceeds its mapped size".to_owned(),
            ));
        }
        memory.write_unchecked(cursor, data);
        bases.insert(section.index().0, cursor);
        if perm.write {
            data_sections.push(DataSection {
                name: section.name().unwrap_or("<data>").to_owned(),
                address: cursor,
                size: section.size(),
            });
        }
        cursor = cursor
            .checked_add(size)
            .ok_or_else(|| VerifyFunctionError::Limit("candidate address overflow".to_owned()))?;
    }
    apply_relocations(file, &bases, &mut memory)?;
    let entry: u64 = candidate_entry(file, &bases, requested_name)?;
    let symbols: BTreeMap<u64, String> = file
        .symbols()
        .filter_map(|symbol: object::Symbol<'_, '_>| {
            let address: u64 = relocated_symbol_address(file, &bases, &symbol).ok()?;
            let name: &str = symbol.name().ok()?;
            (!name.is_empty()).then(|| (address, name.to_owned()))
        })
        .collect();
    Ok(LoadedImage {
        memory,
        entry,
        mode,
        data_sections,
        symbols,
    })
}

fn loadable_section(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::Text
            | SectionKind::Data
            | SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyString
            | SectionKind::ReadOnlyDataWithRel
            | SectionKind::UninitializedData
            | SectionKind::Tls
            | SectionKind::UninitializedTls
            | SectionKind::Common
    )
}

fn section_perm(kind: SectionKind, flags: SectionFlags) -> Perm {
    let mut execute: bool = kind == SectionKind::Text;
    let mut write: bool = matches!(
        kind,
        SectionKind::Data
            | SectionKind::UninitializedData
            | SectionKind::Tls
            | SectionKind::UninitializedTls
            | SectionKind::Common
    );
    match flags {
        SectionFlags::Elf { sh_flags } => {
            write |= sh_flags & u64::from(object::elf::SHF_WRITE) != 0;
            execute |= sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0;
        }
        SectionFlags::Coff { characteristics } => {
            write |= characteristics & object::pe::IMAGE_SCN_MEM_WRITE != 0;
            execute |= characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0;
        }
        SectionFlags::MachO { .. } | SectionFlags::Xcoff { .. } | SectionFlags::None => {}
        _ => {}
    }
    Perm {
        read: true,
        write,
        execute,
    }
}

fn align_up(value: u64, alignment: u64) -> VerifyFunctionResult<u64> {
    let mask: u64 = alignment.saturating_sub(1);
    value
        .checked_add(mask)
        .map(|sum: u64| sum & !mask)
        .ok_or_else(|| VerifyFunctionError::Limit("address alignment overflow".to_owned()))
}

fn candidate_entry(
    file: &object::File<'_>,
    bases: &BTreeMap<usize, u64>,
    requested_name: &str,
) -> VerifyFunctionResult<u64> {
    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text || symbol.is_undefined() {
            continue;
        }
        let Ok(name): Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        let address: u64 = relocated_symbol_address(file, bases, &symbol)?;
        if name == requested_name || name.strip_prefix('_') == Some(requested_name) {
            return Ok(address);
        }
    }
    Err(VerifyFunctionError::CandidateFunctionNotFound(
        requested_name.to_owned(),
    ))
}

fn relocated_symbol_address(
    file: &object::File<'_>,
    bases: &BTreeMap<usize, u64>,
    symbol: &object::Symbol<'_, '_>,
) -> VerifyFunctionResult<u64> {
    match symbol.section() {
        SymbolSection::Section(index) => {
            let base: u64 = *bases.get(&index.0).ok_or_else(|| {
                VerifyFunctionError::CandidateFunctionNotFound(
                    symbol.name().unwrap_or("<symbol>").to_owned(),
                )
            })?;
            let section: object::Section<'_, '_> =
                file.section_by_index(index)
                    .map_err(|error| VerifyFunctionError::Object {
                        side: "candidate",
                        message: error.to_string(),
                    })?;
            Ok(base.saturating_add(symbol.address().saturating_sub(section.address())))
        }
        SymbolSection::Absolute => Ok(symbol.address()),
        SymbolSection::Undefined | SymbolSection::Common | SymbolSection::Unknown => Err(
            VerifyFunctionError::ExternalSymbol(symbol.name().unwrap_or("<unknown>").to_owned()),
        ),
        _ => Err(VerifyFunctionError::CandidateFunctionNotFound(
            symbol.name().unwrap_or("<symbol>").to_owned(),
        )),
    }
}

fn apply_relocations(
    file: &object::File<'_>,
    bases: &BTreeMap<usize, u64>,
    memory: &mut Memory,
) -> VerifyFunctionResult<()> {
    let image_base: u64 = bases.values().copied().min().ok_or_else(|| {
        VerifyFunctionError::Limit("candidate has no loadable sections".to_owned())
    })?;
    for section in file.sections() {
        let Some(section_base): Option<&u64> = bases.get(&section.index().0) else {
            continue;
        };
        for (offset, relocation) in section.relocations() {
            let relocation_bytes: u64 = u64::from(relocation.size()).div_ceil(8);
            if relocation_bytes == 0
                || offset
                    .checked_add(relocation_bytes)
                    .is_none_or(|end: u64| end > section.size())
            {
                return Err(VerifyFunctionError::Limit(
                    "candidate relocation is outside its section".to_owned(),
                ));
            }
            let place: u64 = section_base.checked_add(offset).ok_or_else(|| {
                VerifyFunctionError::Limit("candidate relocation address overflow".to_owned())
            })?;
            let (target, target_section_base, target_name): (u64, Option<u64>, String) =
                match relocation.target() {
                    RelocationTarget::Symbol(index) => {
                        let symbol: object::Symbol<'_, '_> =
                            file.symbol_by_index(index).map_err(|error| {
                                VerifyFunctionError::Object {
                                    side: "candidate",
                                    message: error.to_string(),
                                }
                            })?;
                        if symbol.is_undefined() {
                            return Err(VerifyFunctionError::ExternalSymbol(
                                symbol.name().unwrap_or("<unknown>").to_owned(),
                            ));
                        }
                        let target_section_base: Option<u64> = match symbol.section() {
                            SymbolSection::Section(index) => bases.get(&index.0).copied(),
                            _ => None,
                        };
                        (
                            relocated_symbol_address(file, bases, &symbol)?,
                            target_section_base,
                            symbol.name().unwrap_or("<symbol>").to_owned(),
                        )
                    }
                    RelocationTarget::Section(index) => {
                        let target_base: u64 = *bases.get(&index.0).ok_or_else(|| {
                            VerifyFunctionError::Limit(
                                "relocation targets unloaded section".to_owned(),
                            )
                        })?;
                        (
                            target_base,
                            Some(target_base),
                            file.section_by_index(index)
                                .ok()
                                .and_then(|target: object::Section<'_, '_>| target.name().ok())
                                .unwrap_or("<section>")
                                .to_owned(),
                        )
                    }
                    RelocationTarget::Absolute => (0, None, "<absolute>".to_owned()),
                    other => {
                        return Err(VerifyFunctionError::Relocation {
                            kind: relocation.kind(),
                            size: relocation.size(),
                            target: format!("{other:?}"),
                        });
                    }
                };
            let addend: i128 = i128::from(relocation.addend());
            let target_value: i128 = i128::from(target);
            let place_value: i128 = i128::from(place);
            let value: i128 = match relocation.kind() {
                RelocationKind::Absolute => target_value + addend,
                RelocationKind::Relative | RelocationKind::PltRelative => {
                    target_value + addend - place_value
                }
                RelocationKind::ImageOffset => {
                    i128::from(target.checked_sub(image_base).ok_or_else(|| {
                        VerifyFunctionError::Limit(
                            "image-relative relocation precedes the candidate image".to_owned(),
                        )
                    })?) + addend
                }
                RelocationKind::SectionOffset => {
                    let target_section_base: u64 =
                        target_section_base.ok_or_else(|| VerifyFunctionError::Relocation {
                            kind: relocation.kind(),
                            size: relocation.size(),
                            target: target_name.clone(),
                        })?;
                    i128::from(target.saturating_sub(target_section_base)) + addend
                }
                kind => {
                    return Err(VerifyFunctionError::Relocation {
                        kind,
                        size: relocation.size(),
                        target: target_name,
                    });
                }
            };
            write_relocation(
                memory,
                place,
                relocation.size(),
                value,
                relocation.kind(),
                &target_name,
            )?;
        }
    }
    Ok(())
}

fn write_relocation(
    memory: &mut Memory,
    address: u64,
    size: u8,
    value: i128,
    kind: RelocationKind,
    target: &str,
) -> VerifyFunctionResult<()> {
    if !matches!(size, 8 | 16 | 32 | 64) {
        return Err(VerifyFunctionError::Relocation {
            kind,
            size,
            target: target.to_owned(),
        });
    }
    let width: u32 = u32::from(size);
    let signed_min: i128 = -(1i128 << width.saturating_sub(1));
    let signed_max: i128 = (1i128 << width.saturating_sub(1)).saturating_sub(1);
    let unsigned_max: i128 = (1i128 << width).saturating_sub(1);
    let representable: bool = match kind {
        RelocationKind::Relative | RelocationKind::PltRelative => {
            value >= signed_min && value <= signed_max
        }
        _ => value >= signed_min && value <= unsigned_max,
    };
    if !representable {
        return Err(VerifyFunctionError::Relocation {
            kind,
            size,
            target: target.to_owned(),
        });
    }
    let encoded: [u8; 16] = value.to_le_bytes();
    let byte_count: usize = usize::from(size / 8);
    let bytes: &[u8] = &encoded[..byte_count];
    memory.write_unchecked(address, bytes);
    Ok(())
}

fn execute(
    image: &LoadedImage,
    signature: &FunctionSignature,
    generated: &GeneratedCase,
    step_cap: u64,
) -> VerifyFunctionResult<Execution> {
    let stack_base: u64 = match image.mode {
        CpuMode::Bits32 => STACK_BASE_32,
        CpuMode::Bits64 => STACK_BASE_64,
    };
    let scratch_base: u64 = match image.mode {
        CpuMode::Bits32 => SCRATCH_BASE_32,
        CpuMode::Bits64 => SCRATCH_BASE_64,
    };
    let sentinel: u64 = match image.mode {
        CpuMode::Bits32 => RETURN_SENTINEL_32,
        CpuMode::Bits64 => RETURN_SENTINEL_64,
    };
    let mut cpu: Cpu = Cpu::new(image.mode);
    cpu.mem = image.memory.clone();
    cpu.mem
        .map(stack_base, STACK_BYTES, Perm::RW)
        .map_err(|error| VerifyFunctionError::Emulator(error.to_string()))?;
    cpu.mem
        .map(scratch_base, SCRATCH_BYTES as u64, Perm::RW)
        .map_err(|error| VerifyFunctionError::Emulator(error.to_string()))?;
    cpu.mem.write_unchecked(scratch_base, &generated.scratch);
    let stack_top: u64 = stack_base.saturating_add(STACK_BYTES).saturating_sub(0x100);
    let pointer_size: u64 = u64::from(image.mode.ptr_size());
    let initial_sp: u64 = stack_top.saturating_sub(pointer_size);
    cpu.regs.set(Reg::Rsp, initial_sp);
    write_pointer(&mut cpu.mem, image.mode, initial_sp, sentinel)?;
    install_arguments(
        &mut cpu,
        signature,
        &generated.arguments,
        scratch_base,
        initial_sp,
    )?;
    cpu.regs.rip = image.entry;
    cpu.mem.enable_write_log();
    let mut host: EscapeHost = EscapeHost::default();
    let exit: ExitReason = cpu
        .run(&mut host, step_cap)
        .map_err(|error| VerifyFunctionError::Emulator(error.to_string()))?;
    let termination: Termination = match exit {
        ExitReason::JumpedOutOfRange { to, .. } if to == sentinel => Termination::Returned,
        ExitReason::StepCap(_) | ExitReason::RepLimit(_) => Termination::StepCap,
        ExitReason::HostHalt(_message) if host.target.is_some() => {
            let target: u64 = host.target.unwrap_or(0);
            Termination::Escaped(
                symbol_name(image, target).unwrap_or_else(|| format!("0x{target:x}")),
            )
        }
        ExitReason::JumpedOutOfRange { to, .. } => {
            Termination::Escaped(symbol_name(image, to).unwrap_or_else(|| format!("0x{to:x}")))
        }
        ExitReason::HostHalt(message) => Termination::Fault(message),
        ExitReason::UnsupportedInstr { ip, mnemonic } => {
            if matches!(
                mnemonic.as_str(),
                "Syscall" | "Sysenter" | "Int" | "Int1" | "Into"
            ) {
                Termination::Escaped(mnemonic.to_ascii_lowercase())
            } else {
                Termination::Fault(format!("unsupported {mnemonic} at 0x{ip:x}"))
            }
        }
        ExitReason::GuestFault(message) => Termination::Fault(message),
    };
    if cpu.mem.write_log_truncated() {
        return Err(VerifyFunctionError::Limit(
            "memory write log exceeded its bounded capacity".to_owned(),
        ));
    }
    let scratch: Vec<u8> = cpu
        .mem
        .read(scratch_base, SCRATCH_BYTES)
        .map_err(|error| VerifyFunctionError::Emulator(error.to_string()))?;
    let data_writes: Vec<(String, u64, u8)> = canonical_data_writes(&cpu.mem, &image.data_sections);
    Ok(Execution {
        termination,
        return_value: cpu.regs.get(Reg::Rax),
        scratch,
        data_writes,
    })
}

fn write_pointer(
    memory: &mut Memory,
    mode: CpuMode,
    address: u64,
    value: u64,
) -> VerifyFunctionResult<()> {
    let result: crate::Result<()> = match mode {
        CpuMode::Bits32 => memory.write_u32(address, value as u32),
        CpuMode::Bits64 => memory.write_u64(address, value),
    };
    result.map_err(|error| VerifyFunctionError::Emulator(error.to_string()))
}

fn install_arguments(
    cpu: &mut Cpu,
    signature: &FunctionSignature,
    values: &[u64],
    scratch_base: u64,
    initial_sp: u64,
) -> VerifyFunctionResult<()> {
    let materialized: Vec<u64> = signature
        .arguments
        .iter()
        .zip(values.iter())
        .map(|(kind, value): (&ArgumentKind, &u64)| match kind {
            ArgumentKind::Pointer => scratch_base.saturating_add(*value % 32),
            ArgumentKind::Integer { width, .. } => *value & width_mask(*width),
        })
        .collect();
    let registers: &[Reg] = match signature.convention {
        CallingConvention::SysV => &[Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9],
        CallingConvention::MsX64 => &[Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9],
        CallingConvention::Cdecl => &[],
    };
    for (index, value) in materialized.iter().enumerate() {
        if let Some(register) = registers.get(index) {
            cpu.regs.set(*register, *value);
            continue;
        }
        let stack_index: usize = index.saturating_sub(registers.len());
        let shadow: u64 = if signature.convention == CallingConvention::MsX64 {
            32
        } else {
            0
        };
        let address: u64 = initial_sp
            .saturating_add(u64::from(cpu.mode.ptr_size()))
            .saturating_add(shadow)
            .saturating_add((stack_index as u64).saturating_mul(u64::from(cpu.mode.ptr_size())));
        write_pointer(&mut cpu.mem, cpu.mode, address, *value)?;
    }
    Ok(())
}

fn canonical_data_writes(memory: &Memory, sections: &[DataSection]) -> Vec<(String, u64, u8)> {
    let mut writes: Vec<(String, u64, u8)> = Vec::new();
    for (address, value) in memory.write_log() {
        let Some(section): Option<&DataSection> = sections.iter().find(|section: &&DataSection| {
            *address >= section.address && *address < section.address.saturating_add(section.size)
        }) else {
            continue;
        };
        writes.push((
            section.name.clone(),
            address.saturating_sub(section.address),
            *value,
        ));
    }
    writes
}

fn symbol_name(image: &LoadedImage, target: u64) -> Option<String> {
    image.symbols.get(&target).cloned().or_else(|| {
        image
            .symbols
            .range(..=target)
            .next_back()
            .and_then(|(address, name)| {
                target
                    .saturating_sub(*address)
                    .lt(&0x1000)
                    .then(|| format!("{name}+0x{:x}", target.saturating_sub(*address)))
            })
    })
}

fn compare_executions(
    original: &Execution,
    candidate: &Execution,
    return_width: u8,
) -> (CaseClassification, String) {
    match (&original.termination, &candidate.termination) {
        (Termination::StepCap, _) | (_, Termination::StepCap) => {
            return (CaseClassification::StepCap, "step cap reached".to_owned());
        }
        (Termination::Escaped(target), _) => {
            return (
                CaseClassification::Escaped,
                format!("original escaped to {target}"),
            );
        }
        (_, Termination::Escaped(target)) => {
            return (
                CaseClassification::Escaped,
                format!("candidate escaped to {target}"),
            );
        }
        (Termination::Fault(message), _) => {
            return (
                CaseClassification::OriginalFaulted,
                format!("original faulted: {message}"),
            );
        }
        (_, Termination::Fault(message)) => {
            return (
                CaseClassification::CandidateFaulted,
                format!("candidate faulted: {message}"),
            );
        }
        (Termination::Returned, Termination::Returned) => {}
    }
    let mask: u64 = width_mask(return_width);
    let original_return: u64 = original.return_value & mask;
    let candidate_return: u64 = candidate.return_value & mask;
    if original_return != candidate_return {
        return (
            CaseClassification::Mismatch,
            format!(
                "return differs: original 0x{original_return:x}, candidate 0x{candidate_return:x}"
            ),
        );
    }
    if let Some(index) = original
        .scratch
        .iter()
        .zip(candidate.scratch.iter())
        .position(|(left, right): (&u8, &u8)| left != right)
    {
        return (
            CaseClassification::Mismatch,
            format!(
                "scratch[0x{index:x}] differs: original 0x{:02x}, candidate 0x{:02x}",
                original.scratch[index], candidate.scratch[index]
            ),
        );
    }
    if original.data_writes != candidate.data_writes {
        let first: usize = original
            .data_writes
            .iter()
            .zip(candidate.data_writes.iter())
            .position(|(original_write, candidate_write)| original_write != candidate_write)
            .unwrap_or_else(|| original.data_writes.len().min(candidate.data_writes.len()));
        let detail: String = format!(
            "data write {first} differs: original {:?}, candidate {:?}",
            original.data_writes.get(first),
            candidate.data_writes.get(first)
        );
        return (CaseClassification::Mismatch, detail);
    }
    (CaseClassification::Match, "outputs match".to_owned())
}

fn width_mask(width: u8) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width).saturating_sub(1)
    }
}

struct CaseGenerator {
    state: u64,
    boundaries: Vec<Vec<u64>>,
    argument_kinds: Vec<ArgumentKind>,
}

impl CaseGenerator {
    fn new(seed: u64, signature: &FunctionSignature) -> Self {
        let boundaries: Vec<Vec<u64>> = signature
            .arguments
            .iter()
            .copied()
            .map(boundary_values)
            .collect();
        Self {
            state: seed.max(1),
            boundaries,
            argument_kinds: signature.arguments.clone(),
        }
    }

    fn generate(&mut self, case_index: u32) -> GeneratedCase {
        let mut arguments: Vec<u64> = Vec::with_capacity(self.boundaries.len());
        for argument_index in 0..self.boundaries.len() {
            let shifted: usize =
                (case_index as usize).saturating_add(argument_index.saturating_mul(7));
            let boundary: Option<u64> = self
                .boundaries
                .get(argument_index)
                .and_then(|boundaries: &Vec<u64>| boundaries.get(shifted))
                .copied();
            let value: u64 = boundary.unwrap_or_else(|| self.next_random());
            arguments.push(value);
        }
        for index in 0..self.argument_kinds.len().saturating_sub(1) {
            if self.argument_kinds[index] == ArgumentKind::Pointer {
                let offset: usize = arguments[index] as usize % 32;
                let remaining: u64 = (SCRATCH_BYTES.saturating_sub(offset)) as u64;
                arguments[index + 1] %= remaining.saturating_add(1);
            }
        }
        let scratch: Vec<u8> = (0..SCRATCH_BYTES)
            .map(|_| self.next_random() as u8)
            .collect();
        GeneratedCase { arguments, scratch }
    }

    fn next_random(&mut self) -> u64 {
        let mut value: u64 = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }
}

fn boundary_values(kind: ArgumentKind) -> Vec<u64> {
    let (width, signed): (u8, bool) = match kind {
        ArgumentKind::Pointer => (64, false),
        ArgumentKind::Integer { width, signed } => (width, signed),
    };
    let mask: u64 = width_mask(width);
    let mut values: Vec<u64> = vec![0, 1, mask];
    if signed {
        let sign: u64 = 1u64 << width.saturating_sub(1);
        values.push(sign);
        values.push(sign.saturating_sub(1));
    }
    for value in -8i64..=8i64 {
        values.push((value as u64) & mask);
    }
    for power in 0..u32::from(width.min(63)) {
        let base: u64 = 1u64 << power;
        values.push(base.saturating_sub(1) & mask);
        values.push(base & mask);
        values.push(base.saturating_add(1) & mask);
    }
    values.sort_unstable();
    values.dedup();
    values
}

fn render_inputs(generated: &GeneratedCase, signature: &FunctionSignature) -> Vec<String> {
    let mut inputs: Vec<String> = generated
        .arguments
        .iter()
        .zip(signature.arguments.iter())
        .map(|(value, kind): (&u64, &ArgumentKind)| match kind {
            ArgumentKind::Pointer => format!("ptr+0x{:x}", value % 32),
            ArgumentKind::Integer { width, .. } => format!("0x{:x}", value & width_mask(*width)),
        })
        .collect();
    let digits: &[u8; 16] = b"0123456789abcdef";
    let mut prefix: String = String::with_capacity(32);
    for byte in generated.scratch.iter().take(16) {
        prefix.push(char::from(digits[usize::from(byte >> 4)]));
        prefix.push(char::from(digits[usize::from(byte & 0x0f)]));
    }
    inputs.push(format!("scratch={prefix}..."));
    inputs
}
