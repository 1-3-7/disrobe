use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol};
use serde::{Deserialize, Serialize};

use disrobe_bytes::read_uleb128_at;
use disrobe_core::byte_search::find as byte_find;

use crate::entropy::{ENTROPY_WINDOW_4K, EntropyBlock, windowed_entropy};
use crate::lang::{
    FunctionNameConfidence, FunctionNameEvidence, FunctionNameEvidenceSource, InputByteRange,
    RecoveredFunctionName, sanitize_function_name,
};
use crate::packers::parse_pe_image;
use crate::packers::pe_sections::{PeImage, PeSection};
use crate::plt_resolve::{ImportStub, resolve_elf_plt_imports, resolve_pe_iat_imports};

const PE_MAGIC: &[u8; 2] = b"MZ";
const ELF_MAGIC: &[u8; 4] = &[0x7F, b'E', b'L', b'F'];
const MACHO_LE: &[u8; 4] = &[0xCF, 0xFA, 0xED, 0xFE];
const MACHO_BE: &[u8; 4] = &[0xFE, 0xED, 0xFA, 0xCF];
const MACHO_FAT: &[u8; 4] = &[0xCA, 0xFE, 0xBA, 0xBE];
const SCAN_LIMIT: usize = 16 * 1024 * 1024;
const VERSION_TAIL_CAP: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct FunctionNameSubject<'a> {
    pub name: &'a str,
    pub address: u64,
    pub code: &'a [u8],
}

fn subject_has_address_placeholder(subject: &FunctionNameSubject<'_>) -> bool {
    subject.name == format!("sub_{:x}", subject.address)
        || subject.name == format!("sub_{:X}", subject.address)
}

fn borrowed_input_range(bytes: &[u8], evidence: &[u8]) -> Option<InputByteRange> {
    if evidence.is_empty() {
        return None;
    }
    let base: usize = bytes.as_ptr() as usize;
    let start_index: usize = (evidence.as_ptr() as usize).checked_sub(base)?;
    let end_index: usize = start_index.checked_add(evidence.len())?;
    if bytes.get(start_index..end_index)? != evidence {
        return None;
    }
    Some(InputByteRange {
        start: u64::try_from(start_index).ok()?,
        end: u64::try_from(end_index).ok()?,
    })
}

fn address_is_text(file: &object::File<'_>, address: u64) -> bool {
    file.sections().any(|section| {
        let start: u64 = section.address();
        let Some(end): Option<u64> = start.checked_add(section.size()) else {
            return false;
        };
        section.kind() == object::SectionKind::Text && address >= start && address < end
    })
}

fn static_function_symbols(file: &object::File<'_>) -> (BTreeSet<u64>, BTreeSet<String>) {
    let mut addresses: BTreeSet<u64> = BTreeSet::new();
    let mut names: BTreeSet<String> = BTreeSet::new();
    for symbol in file.symbols() {
        if symbol.is_undefined()
            || symbol.address() == 0
            || symbol.kind() != object::SymbolKind::Text
        {
            continue;
        }
        let Ok(raw_name): core::result::Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        if raw_name.is_empty() {
            continue;
        }
        let _: bool = addresses.insert(symbol.address());
        if let Some(name) = sanitize_function_name(raw_name) {
            let _: bool = names.insert(name);
        }
    }
    (addresses, names)
}

#[must_use]
pub fn exported_function_names(
    bytes: &[u8],
    subjects: &[FunctionNameSubject<'_>],
) -> Vec<RecoveredFunctionName> {
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return Vec::new();
    };
    let Ok(exports): core::result::Result<Vec<object::Export<'_>>, object::Error> = file.exports()
    else {
        return Vec::new();
    };
    let (real_addresses, mut reserved_names): (BTreeSet<u64>, BTreeSet<String>) =
        static_function_symbols(&file);
    for subject in subjects {
        if !subject_has_address_placeholder(subject)
            && let Some(name) = sanitize_function_name(subject.name)
        {
            let _: bool = reserved_names.insert(name);
        }
    }
    let mut subjects_by_address: BTreeMap<u64, Vec<&FunctionNameSubject<'_>>> = BTreeMap::new();
    for subject in subjects {
        subjects_by_address
            .entry(subject.address)
            .or_default()
            .push(subject);
    }
    let mut exports_by_address: BTreeMap<u64, Vec<(String, String, InputByteRange)>> =
        BTreeMap::new();
    for export in exports {
        let address: u64 = export.address();
        if address == 0
            || address == file.relative_address_base()
            || !address_is_text(&file, address)
        {
            continue;
        }
        let raw_name_bytes: &[u8] = export.name();
        let Ok(raw_name): core::result::Result<&str, core::str::Utf8Error> =
            core::str::from_utf8(raw_name_bytes)
        else {
            continue;
        };
        let Some(name): Option<String> = sanitize_function_name(raw_name) else {
            continue;
        };
        let Some(input_bytes): Option<InputByteRange> = borrowed_input_range(bytes, raw_name_bytes)
        else {
            continue;
        };
        exports_by_address.entry(address).or_default().push((
            raw_name.to_owned(),
            name,
            input_bytes,
        ));
    }
    let mut candidates: BTreeMap<String, Vec<RecoveredFunctionName>> = BTreeMap::new();
    for (address, exports_at_address) in exports_by_address {
        let [(identity, name, input_bytes)]: &[(String, String, InputByteRange)] =
            exports_at_address.as_slice()
        else {
            continue;
        };
        let Some([subject]): Option<&[&FunctionNameSubject<'_>; 1]> =
            subjects_by_address.get(&address).and_then(
                |at_address: &Vec<&FunctionNameSubject<'_>>| at_address.as_slice().try_into().ok(),
            )
        else {
            continue;
        };
        if real_addresses.contains(&address)
            || !subject_has_address_placeholder(subject)
            || reserved_names.contains(name)
            || input_byte_range(bytes, &file, subject).is_none()
        {
            continue;
        }
        candidates
            .entry(name.clone())
            .or_default()
            .push(RecoveredFunctionName {
                function_address: address,
                name: name.clone(),
                evidence: FunctionNameEvidence {
                    confidence: FunctionNameConfidence::High,
                    source: FunctionNameEvidenceSource::ExportedName,
                    input_bytes: *input_bytes,
                    identity: identity.clone(),
                    target_address: address,
                    target_is_indirect: false,
                },
            });
    }
    let mut recovered: Vec<RecoveredFunctionName> = candidates
        .into_values()
        .filter_map(|mut proposals: Vec<RecoveredFunctionName>| {
            if proposals.len() != 1 {
                return None;
            }
            proposals.pop()
        })
        .collect();
    recovered.sort_by_key(|proposal: &RecoveredFunctionName| proposal.function_address);
    recovered
}

fn insert_unique_import(imports: &mut BTreeMap<u64, Option<String>>, address: u64, name: &str) {
    match imports.get_mut(&address) {
        Some(identity) if identity.as_deref() != Some(name) => *identity = None,
        Some(_) => {}
        None => {
            let _: Option<Option<String>> = imports.insert(address, Some(name.to_owned()));
        }
    }
}

fn resolved_import_identities(bytes: &[u8]) -> BTreeMap<u64, Option<String>> {
    let mut imports: BTreeMap<u64, Option<String>> = BTreeMap::new();
    let resolved: Vec<ImportStub> = resolve_elf_plt_imports(bytes)
        .into_iter()
        .chain(resolve_pe_iat_imports(bytes))
        .collect();
    for import in resolved {
        insert_unique_import(&mut imports, import.stub_address, &import.name);
        insert_unique_import(&mut imports, import.slot_address, &import.name);
    }
    imports
}

fn nul_terminated_utf8_input_range(
    bytes: &[u8],
    file: &object::File<'_>,
    address: u64,
) -> Option<(String, InputByteRange)> {
    const MAX_ASSERT_FUNCTION_NAME_BYTES: usize = 1024;
    for section in file.sections() {
        let section_start: u64 = section.address();
        let section_end: u64 = section_start.checked_add(section.size())?;
        if address < section_start || address >= section_end {
            continue;
        }
        let relative: u64 = address.checked_sub(section_start)?;
        let (file_start, file_size): (u64, u64) = section.file_range()?;
        if relative >= file_size {
            continue;
        }
        let input_start: u64 = file_start.checked_add(relative)?;
        let available: u64 = file_size.checked_sub(relative)?;
        let byte_limit: usize = usize::try_from(available)
            .ok()?
            .min(MAX_ASSERT_FUNCTION_NAME_BYTES);
        let start: usize = usize::try_from(input_start).ok()?;
        let end: usize = start.checked_add(byte_limit)?;
        let raw: &[u8] = bytes.get(start..end)?;
        let terminator: usize = raw.iter().position(|byte: &u8| *byte == 0)?;
        let raw_name: &str = core::str::from_utf8(raw.get(..terminator)?).ok()?;
        if raw_name.is_empty() {
            return None;
        }
        let input_end: u64 = input_start.checked_add(u64::try_from(terminator).ok()?)?;
        return Some((
            raw_name.to_owned(),
            InputByteRange {
                start: input_start,
                end: input_end,
            },
        ));
    }
    None
}

fn assert_fail_function_argument(
    bits: u32,
    file: &object::File<'_>,
    bytes: &[u8],
    subject: &FunctionNameSubject<'_>,
    imports: &BTreeMap<u64, Option<String>>,
) -> Option<(String, InputByteRange, u64)> {
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bits, subject.code, subject.address, DecoderOptions::NONE);
    let mut fourth_argument: Option<u64> = None;
    let mut candidates: BTreeMap<String, (InputByteRange, u64)> = BTreeMap::new();
    while decoder.can_decode() {
        let mut instruction: Instruction = Instruction::default();
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            return None;
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::RCX
            && instruction.op1_kind() == OpKind::Memory
            && instruction.is_ip_rel_memory_operand()
        {
            fourth_argument = Some(instruction.ip_rel_memory_address());
            continue;
        }
        if instruction.op0_kind() == OpKind::Register && instruction.op0_register() == Register::RCX
        {
            fourth_argument = None;
        }
        if instruction.mnemonic() != Mnemonic::Call
            || !matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            continue;
        }
        let target: u64 = instruction.near_branch_target();
        let imported_name: Option<&str> = imports
            .get(&target)
            .or_else(|| {
                target
                    .checked_sub(4)
                    .and_then(|entry: u64| imports.get(&entry))
            })
            .and_then(Option::as_deref);
        if imported_name != Some("__assert_fail") {
            continue;
        }
        let Some(fourth_argument): Option<u64> = fourth_argument else {
            continue;
        };
        let Some((identity, input_bytes)): Option<(String, InputByteRange)> =
            nul_terminated_utf8_input_range(bytes, file, fourth_argument)
        else {
            continue;
        };
        candidates.entry(identity).or_insert((input_bytes, target));
    }
    let [(identity, (input_bytes, target))]: [(String, (InputByteRange, u64)); 1] =
        candidates.into_iter().collect::<Vec<_>>().try_into().ok()?;
    Some((identity, input_bytes, target))
}

#[must_use]
pub fn assert_fail_function_names(
    bytes: &[u8],
    subjects: &[FunctionNameSubject<'_>],
) -> Vec<RecoveredFunctionName> {
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return Vec::new();
    };
    if !file.is_little_endian() {
        return Vec::new();
    }
    let bits: u32 = match file.architecture() {
        object::Architecture::X86_64 => 64,
        _ => return Vec::new(),
    };
    let imports: BTreeMap<u64, Option<String>> = resolved_import_identities(bytes);
    if imports.is_empty() {
        return Vec::new();
    }
    let (real_addresses, mut reserved_names): (BTreeSet<u64>, BTreeSet<String>) =
        real_function_symbols(&file);
    for subject in subjects {
        if !subject_has_address_placeholder(subject)
            && let Some(name) = sanitize_function_name(subject.name)
        {
            let _: bool = reserved_names.insert(name);
        }
    }
    let mut candidates: BTreeMap<String, Vec<RecoveredFunctionName>> = BTreeMap::new();
    for subject in subjects {
        if real_addresses.contains(&subject.address) || !subject_has_address_placeholder(subject) {
            continue;
        }
        let Some((identity, input_bytes, target)): Option<(String, InputByteRange, u64)> =
            assert_fail_function_argument(bits, &file, bytes, subject, &imports)
        else {
            continue;
        };
        let Some(name): Option<String> = sanitize_function_name(&identity) else {
            continue;
        };
        if reserved_names.contains(&name) {
            continue;
        }
        candidates
            .entry(name.clone())
            .or_default()
            .push(RecoveredFunctionName {
                function_address: subject.address,
                name,
                evidence: FunctionNameEvidence {
                    confidence: FunctionNameConfidence::High,
                    source: FunctionNameEvidenceSource::AssertFailFunction,
                    input_bytes,
                    identity,
                    target_address: target,
                    target_is_indirect: false,
                },
            });
    }
    let mut recovered: Vec<RecoveredFunctionName> = candidates
        .into_values()
        .filter_map(|mut proposals: Vec<RecoveredFunctionName>| {
            if proposals.len() != 1 {
                return None;
            }
            proposals.pop()
        })
        .collect();
    recovered.sort_by_key(|proposal: &RecoveredFunctionName| proposal.function_address);
    recovered
}

fn real_function_symbols(file: &object::File<'_>) -> (BTreeSet<u64>, BTreeSet<String>) {
    let mut addresses: BTreeSet<u64> = BTreeSet::new();
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut ingest = |symbol: object::Symbol<'_, '_>| {
        if symbol.is_undefined()
            || symbol.address() == 0
            || symbol.kind() != object::SymbolKind::Text
        {
            return;
        }
        let Ok(raw_name): core::result::Result<&str, object::Error> = symbol.name() else {
            return;
        };
        if raw_name.is_empty() {
            return;
        }
        addresses.insert(symbol.address());
        if let Some(name) = sanitize_function_name(raw_name) {
            let _: bool = names.insert(name);
        }
    };
    for symbol in file.symbols() {
        ingest(symbol);
    }
    for symbol in file.dynamic_symbols() {
        ingest(symbol);
    }
    if let Ok(exports) = file.exports() {
        for export in exports {
            if export.address() == 0 {
                continue;
            }
            let Ok(raw_name): core::result::Result<&str, core::str::Utf8Error> =
                core::str::from_utf8(export.name())
            else {
                continue;
            };
            addresses.insert(export.address());
            if let Some(name) = sanitize_function_name(raw_name) {
                let _: bool = names.insert(name);
            }
        }
    }
    (addresses, names)
}

fn input_byte_range(
    bytes: &[u8],
    file: &object::File<'_>,
    subject: &FunctionNameSubject<'_>,
) -> Option<InputByteRange> {
    let code_len: u64 = u64::try_from(subject.code.len()).ok()?;
    let address_end: u64 = subject.address.checked_add(code_len)?;
    for section in file.sections() {
        let section_start: u64 = section.address();
        let section_end: u64 = section_start.checked_add(section.size())?;
        if subject.address < section_start || address_end > section_end {
            continue;
        }
        let relative: u64 = subject.address.checked_sub(section_start)?;
        let (section_file_start, section_file_size): (u64, u64) = section.file_range()?;
        let relative_end: u64 = relative.checked_add(code_len)?;
        if relative_end > section_file_size {
            continue;
        }
        let start: u64 = section_file_start.checked_add(relative)?;
        let end: u64 = start.checked_add(code_len)?;
        let start_index: usize = usize::try_from(start).ok()?;
        let end_index: usize = usize::try_from(end).ok()?;
        if bytes.get(start_index..end_index)? != subject.code {
            continue;
        }
        return Some(InputByteRange { start, end });
    }
    None
}

fn one_instruction_jump_target(
    bits: u32,
    subject: &FunctionNameSubject<'_>,
) -> Option<(u64, bool)> {
    if subject.code.is_empty() {
        return None;
    }
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bits, subject.code, subject.address, DecoderOptions::NONE);
    let mut instruction: Instruction = Instruction::default();
    decoder.decode_out(&mut instruction);
    if instruction.is_invalid()
        || instruction.mnemonic() != Mnemonic::Jmp
        || instruction.len() != subject.code.len()
    {
        return None;
    }
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some((instruction.near_branch_target(), false))
        }
        OpKind::Memory if instruction.is_ip_rel_memory_operand() => {
            Some((instruction.ip_rel_memory_address(), true))
        }
        OpKind::Memory
            if instruction.memory_base() == Register::None
                && instruction.memory_index() == Register::None =>
        {
            Some((instruction.memory_displacement64(), true))
        }
        _ => None,
    }
}

#[must_use]
pub fn resolved_import_thunk_names(
    bytes: &[u8],
    subjects: &[FunctionNameSubject<'_>],
) -> Vec<RecoveredFunctionName> {
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return Vec::new();
    };
    if !file.is_little_endian() {
        return Vec::new();
    }
    let bits: u32 = match file.architecture() {
        object::Architecture::I386 => 32,
        object::Architecture::X86_64 => 64,
        _ => return Vec::new(),
    };
    let imports: BTreeMap<u64, Option<String>> = resolved_import_identities(bytes);
    if imports.is_empty() {
        return Vec::new();
    }
    let (real_addresses, real_names): (BTreeSet<u64>, BTreeSet<String>) =
        real_function_symbols(&file);
    let mut candidates: BTreeMap<String, Vec<RecoveredFunctionName>> = BTreeMap::new();
    for subject in subjects {
        if real_addresses.contains(&subject.address) {
            continue;
        }
        let Some(input_bytes): Option<InputByteRange> = input_byte_range(bytes, &file, subject)
        else {
            continue;
        };
        let Some((target, target_is_indirect)): Option<(u64, bool)> =
            one_instruction_jump_target(bits, subject)
        else {
            continue;
        };
        let Some(Some(identity)): Option<&Option<String>> = imports.get(&target) else {
            continue;
        };
        let Some(name): Option<String> = sanitize_function_name(identity) else {
            continue;
        };
        let proposal: RecoveredFunctionName = RecoveredFunctionName {
            function_address: subject.address,
            name: name.clone(),
            evidence: FunctionNameEvidence {
                confidence: FunctionNameConfidence::High,
                source: FunctionNameEvidenceSource::ImportThunk,
                input_bytes,
                identity: identity.clone(),
                target_address: target,
                target_is_indirect,
            },
        };
        candidates.entry(name).or_default().push(proposal);
    }
    let mut recovered: Vec<RecoveredFunctionName> = candidates
        .into_iter()
        .filter_map(
            |(name, mut proposals): (String, Vec<RecoveredFunctionName>)| {
                if proposals.len() != 1 || real_names.contains(&name) {
                    return None;
                }
                proposals.pop()
            },
        )
        .collect();
    recovered.sort_by_key(|proposal: &RecoveredFunctionName| proposal.function_address);
    recovered
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigKind {
    MagicByte,
    SectionName,
    ImportHeuristic,
    CompilerMarker,
    EntropyBand,
    BytePattern,
}

impl SigKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MagicByte => "magic-byte",
            Self::SectionName => "section-name",
            Self::ImportHeuristic => "import-heuristic",
            Self::CompilerMarker => "compiler-marker",
            Self::EntropyBand => "entropy-band",
            Self::BytePattern => "byte-pattern",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackerFamily {
    Upx,
    Aspack,
    Pecompact,
    Fsg,
    Mew,
    Mpress,
    Petite,
    Nspack,
    Kkrunchy,
    Molebox,
    Rlpack,
    Exestealth,
}

impl PackerFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Upx => "upx",
            Self::Aspack => "aspack",
            Self::Pecompact => "pecompact",
            Self::Fsg => "fsg",
            Self::Mew => "mew",
            Self::Mpress => "mpress",
            Self::Petite => "petite",
            Self::Nspack => "nspack",
            Self::Kkrunchy => "kkrunchy",
            Self::Molebox => "molebox",
            Self::Rlpack => "rlpack",
            Self::Exestealth => "exestealth",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectorFamily {
    VmProtect,
    Themida,
    WinLicense,
    Enigma,
    Armadillo,
    Obsidium,
    Asprotect,
    CodeVirtualizer,
    DotNetReactor,
    ConfuserEx,
}

impl ProtectorFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VmProtect => "vmprotect",
            Self::Themida => "themida",
            Self::WinLicense => "winlicense",
            Self::Enigma => "enigma",
            Self::Armadillo => "armadillo",
            Self::Obsidium => "obsidium",
            Self::Asprotect => "asprotect",
            Self::CodeVirtualizer => "code-virtualizer",
            Self::DotNetReactor => "dotnet-reactor",
            Self::ConfuserEx => "confuserex",
        }
    }

    #[must_use]
    pub const fn is_native_vm(self) -> bool {
        matches!(
            self,
            Self::VmProtect
                | Self::Themida
                | Self::WinLicense
                | Self::Enigma
                | Self::Armadillo
                | Self::Obsidium
                | Self::CodeVirtualizer
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompilerFamily {
    Msvc,
    Gcc,
    Clang,
    MinGw,
    Rust,
    Go,
    Nim,
    Zig,
    Delphi,
    FreePascal,
    DotNet,
    CodeWarrior,
}

impl CompilerFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Msvc => "msvc",
            Self::Gcc => "gcc",
            Self::Clang => "clang",
            Self::MinGw => "mingw",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Nim => "nim",
            Self::Zig => "zig",
            Self::Delphi => "delphi",
            Self::FreePascal => "free-pascal",
            Self::DotNet => "dotnet",
            Self::CodeWarrior => "codewarrior",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkerFamily {
    MsvcLink,
    GnuLd,
    GnuGold,
    Lld,
    Mold,
}

impl LinkerFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MsvcLink => "msvc-link",
            Self::GnuLd => "gnu-ld",
            Self::GnuGold => "gnu-gold",
            Self::Lld => "lld",
            Self::Mold => "mold",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallerFamily {
    Nsis,
    InnoSetup,
    InstallShield,
    WixBurn,
    AutoIt,
}

impl InstallerFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nsis => "nsis",
            Self::InnoSetup => "inno-setup",
            Self::InstallShield => "installshield",
            Self::WixBurn => "wix-burn",
            Self::AutoIt => "autoit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "class", content = "family", rename_all = "kebab-case")]
pub enum Target {
    Packer(PackerFamily),
    Protector(ProtectorFamily),
    Compiler(CompilerFamily),
    Linker(LinkerFamily),
    Installer(InstallerFamily),
}

impl Target {
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Packer(_) => "packer",
            Self::Protector(_) => "protector",
            Self::Compiler(_) => "compiler",
            Self::Linker(_) => "linker",
            Self::Installer(_) => "installer",
        }
    }

    #[must_use]
    pub const fn family_label(self) -> &'static str {
        match self {
            Self::Packer(p) => p.label(),
            Self::Protector(p) => p.label(),
            Self::Compiler(c) => c.label(),
            Self::Linker(l) => l.label(),
            Self::Installer(i) => i.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    #[must_use]
    pub const fn as_score(self) -> f32 {
        match self {
            Self::Low => 0.60,
            Self::Medium => 0.80,
            Self::High => 0.95,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionRule {
    None,
    DottedAfterMarker { marker: &'static [u8] },
    LiteralTail { marker: &'static [u8] },
    UpxPackHeader,
    EntropyBandClassify,
}

#[derive(Debug, Clone, Copy)]
struct EngineSignature {
    kind: SigKind,
    target: Target,
    pattern: &'static [u8],
    marker_label: &'static str,
    confidence: Confidence,
    specificity: u16,
    version: VersionRule,
}

const SIGNATURES: &[EngineSignature] = &[
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Upx),
        pattern: b"UPX0",
        marker_label: "UPX0 section name",
        confidence: Confidence::High,
        specificity: 40,
        version: VersionRule::UpxPackHeader,
    },
    EngineSignature {
        kind: SigKind::MagicByte,
        target: Target::Packer(PackerFamily::Upx),
        pattern: b"UPX!",
        marker_label: "UPX! pack-header magic",
        confidence: Confidence::High,
        specificity: 45,
        version: VersionRule::UpxPackHeader,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Aspack),
        pattern: b".aspack",
        marker_label: ".aspack section name",
        confidence: Confidence::High,
        specificity: 38,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::MagicByte,
        target: Target::Packer(PackerFamily::Pecompact),
        pattern: b"PEC2",
        marker_label: "PEC2 marker",
        confidence: Confidence::High,
        specificity: 36,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::MagicByte,
        target: Target::Packer(PackerFamily::Fsg),
        pattern: b"FSG!",
        marker_label: "FSG! pack-header magic",
        confidence: Confidence::High,
        specificity: 36,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Mpress),
        pattern: b".MPRESS1",
        marker_label: ".MPRESS1 section name",
        confidence: Confidence::High,
        specificity: 40,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Petite),
        pattern: b".petite",
        marker_label: ".petite section name",
        confidence: Confidence::High,
        specificity: 38,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Nspack),
        pattern: b".nsp0",
        marker_label: ".nsp0 section name",
        confidence: Confidence::High,
        specificity: 36,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Packer(PackerFamily::Kkrunchy),
        pattern: b"kkrunchy",
        marker_label: "kkrunchy stub marker",
        confidence: Confidence::High,
        specificity: 36,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Mew),
        pattern: b"MEW",
        marker_label: "MEW section name",
        confidence: Confidence::Medium,
        specificity: 24,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Rlpack),
        pattern: b".RLPack",
        marker_label: ".RLPack section name",
        confidence: Confidence::High,
        specificity: 34,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Packer(PackerFamily::Exestealth),
        pattern: b"exeStealth",
        marker_label: "exeStealth marker",
        confidence: Confidence::Medium,
        specificity: 28,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Packer(PackerFamily::Molebox),
        pattern: b".mbx",
        marker_label: ".mbx section name",
        confidence: Confidence::Medium,
        specificity: 26,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Protector(ProtectorFamily::VmProtect),
        pattern: b".vmp0",
        marker_label: ".vmp0 section name",
        confidence: Confidence::High,
        specificity: 42,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Protector(ProtectorFamily::Themida),
        pattern: b".themida",
        marker_label: ".themida section name",
        confidence: Confidence::High,
        specificity: 42,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Protector(ProtectorFamily::WinLicense),
        pattern: b".winlice",
        marker_label: ".winlice section name",
        confidence: Confidence::High,
        specificity: 40,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Protector(ProtectorFamily::Enigma),
        pattern: b".enigma1",
        marker_label: ".enigma1 section name",
        confidence: Confidence::High,
        specificity: 40,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Protector(ProtectorFamily::Obsidium),
        pattern: b"obsidium",
        marker_label: "obsidium marker",
        confidence: Confidence::Medium,
        specificity: 30,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Protector(ProtectorFamily::Asprotect),
        pattern: b".asprotect",
        marker_label: ".asprotect section name",
        confidence: Confidence::High,
        specificity: 38,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Protector(ProtectorFamily::CodeVirtualizer),
        pattern: b"CodeVirtualizer",
        marker_label: "Oreans Code Virtualizer marker",
        confidence: Confidence::Medium,
        specificity: 32,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Protector(ProtectorFamily::DotNetReactor),
        pattern: b".NET Reactor",
        marker_label: ".NET Reactor marker",
        confidence: Confidence::Medium,
        specificity: 30,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Protector(ProtectorFamily::ConfuserEx),
        pattern: b"ConfusedByAttribute",
        marker_label: "ConfuserEx attribute marker",
        confidence: Confidence::High,
        specificity: 34,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::Rust),
        pattern: b"rustc/",
        marker_label: "rustc commit-hash path",
        confidence: Confidence::High,
        specificity: 34,
        version: VersionRule::LiteralTail { marker: b"rustc/" },
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::Clang),
        pattern: b"clang version ",
        marker_label: "clang version banner",
        confidence: Confidence::High,
        specificity: 34,
        version: VersionRule::DottedAfterMarker {
            marker: b"clang version ",
        },
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::Gcc),
        pattern: b"GCC: (",
        marker_label: "GCC compiler comment",
        confidence: Confidence::High,
        specificity: 32,
        version: VersionRule::DottedAfterMarker { marker: b") " },
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::MinGw),
        pattern: b"Mingw-w64 runtime",
        marker_label: "MinGW-w64 runtime marker",
        confidence: Confidence::High,
        specificity: 32,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::Zig),
        pattern: b"zig 0.",
        marker_label: "zig version banner",
        confidence: Confidence::High,
        specificity: 34,
        version: VersionRule::DottedAfterMarker { marker: b"zig " },
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::Nim),
        pattern: b"NimMainModule",
        marker_label: "Nim runtime entry symbol",
        confidence: Confidence::Medium,
        specificity: 30,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::Go),
        pattern: b"Go build ID:",
        marker_label: "Go build id",
        confidence: Confidence::High,
        specificity: 32,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::Delphi),
        pattern: b"Borland Delphi",
        marker_label: "Borland Delphi marker",
        confidence: Confidence::High,
        specificity: 30,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::FreePascal),
        pattern: b"FPC ",
        marker_label: "Free Pascal marker",
        confidence: Confidence::Medium,
        specificity: 24,
        version: VersionRule::DottedAfterMarker { marker: b"FPC " },
    },
    EngineSignature {
        kind: SigKind::ImportHeuristic,
        target: Target::Compiler(CompilerFamily::DotNet),
        pattern: b"_CorExeMain",
        marker_label: "_CorExeMain CLR entry import",
        confidence: Confidence::Medium,
        specificity: 28,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Compiler(CompilerFamily::CodeWarrior),
        pattern: b"MW CodeWarrior",
        marker_label: "Metrowerks CodeWarrior compiler comment",
        confidence: Confidence::High,
        specificity: 32,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Linker(LinkerFamily::Lld),
        pattern: b"Linker: LLD ",
        marker_label: "LLVM lld linker comment",
        confidence: Confidence::High,
        specificity: 30,
        version: VersionRule::DottedAfterMarker {
            marker: b"Linker: LLD ",
        },
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Linker(LinkerFamily::GnuLd),
        pattern: b"GNU ld ",
        marker_label: "GNU ld linker comment",
        confidence: Confidence::Medium,
        specificity: 26,
        version: VersionRule::DottedAfterMarker { marker: b"GNU ld " },
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Linker(LinkerFamily::GnuGold),
        pattern: b"GNU gold ",
        marker_label: "GNU gold linker comment",
        confidence: Confidence::Medium,
        specificity: 26,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::CompilerMarker,
        target: Target::Linker(LinkerFamily::Mold),
        pattern: b"mold ",
        marker_label: "mold linker comment",
        confidence: Confidence::Low,
        specificity: 18,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Installer(InstallerFamily::Nsis),
        pattern: b"NullsoftInst",
        marker_label: "NSIS installer marker",
        confidence: Confidence::High,
        specificity: 36,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Installer(InstallerFamily::InnoSetup),
        pattern: b"Inno Setup Setup Data",
        marker_label: "Inno Setup data marker",
        confidence: Confidence::High,
        specificity: 38,
        version: VersionRule::LiteralTail {
            marker: b"Inno Setup Setup Data (",
        },
    },
    EngineSignature {
        kind: SigKind::BytePattern,
        target: Target::Installer(InstallerFamily::InstallShield),
        pattern: b"InstallShield",
        marker_label: "InstallShield marker",
        confidence: Confidence::Medium,
        specificity: 28,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::SectionName,
        target: Target::Installer(InstallerFamily::WixBurn),
        pattern: b".wixburn",
        marker_label: ".wixburn section name",
        confidence: Confidence::High,
        specificity: 34,
        version: VersionRule::None,
    },
    EngineSignature {
        kind: SigKind::MagicByte,
        target: Target::Installer(InstallerFamily::AutoIt),
        pattern: b"AU3!EA06",
        marker_label: "compiled AutoIt3 magic",
        confidence: Confidence::High,
        specificity: 38,
        version: VersionRule::None,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntropyBand {
    Plain,
    Mixed,
    Compressed,
    Encrypted,
}

impl EntropyBand {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Mixed => "mixed",
            Self::Compressed => "compressed",
            Self::Encrypted => "encrypted",
        }
    }

    #[must_use]
    pub fn classify(mean_bits: f64) -> Self {
        if mean_bits >= 7.95 {
            Self::Encrypted
        } else if mean_bits >= 7.2 {
            Self::Compressed
        } else if mean_bits >= 5.0 {
            Self::Mixed
        } else {
            Self::Plain
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyProfile {
    pub mean_bits: f64,
    pub peak_bits: f64,
    pub high_block_ratio: f64,
    pub band: EntropyBand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerIdentity {
    pub compiler: CompilerFamily,
    pub version: Option<String>,
    pub marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkerIdentity {
    pub linker: LinkerFamily,
    pub version: Option<String>,
    pub marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigMatch {
    pub kind: SigKind,
    pub target: Target,
    pub class: &'static str,
    pub family: &'static str,
    pub marker: &'static str,
    pub matched_offset: u64,
    pub confidence: Confidence,
    pub specificity: u16,
    pub version: Option<String>,
}

impl SigMatch {
    #[inline]
    #[must_use]
    pub fn rank(&self) -> i64 {
        let conf: i64 = match self.confidence {
            Confidence::High => 2,
            Confidence::Medium => 1,
            Confidence::Low => 0,
        };
        conf * 1000 + i64::from(self.specificity)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigReport {
    pub format: &'static str,
    pub matches: Vec<SigMatch>,
    pub structured: Vec<StructFinding>,
    pub compiler: Option<CompilerIdentity>,
    pub linker: Option<LinkerIdentity>,
    pub entropy: Option<EntropyProfile>,
}

impl SigReport {
    #[must_use]
    pub fn best(&self) -> Option<&SigMatch> {
        self.matches.first()
    }
}

#[must_use]
pub fn detect_format(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(PE_MAGIC) {
        "pe"
    } else if bytes.starts_with(ELF_MAGIC) {
        "elf"
    } else if bytes.starts_with(MACHO_LE) || bytes.starts_with(MACHO_BE) {
        "macho"
    } else if bytes.starts_with(MACHO_FAT) {
        "macho-fat"
    } else {
        "unknown"
    }
}

#[must_use]
pub fn analyze(bytes: &[u8]) -> SigReport {
    let format: &'static str = detect_format(bytes);
    let window: &[u8] = &bytes[..bytes.len().min(SCAN_LIMIT)];
    let section_names: Vec<[u8; 8]> = pe_section_names(bytes);
    let mut matches: Vec<SigMatch> = Vec::new();
    for sig in SIGNATURES {
        if let Some(offset) = signature_offset(sig, window, &section_names) {
            let version: Option<String> = extract_version(sig.version, bytes, window);
            matches.push(SigMatch {
                kind: sig.kind,
                target: sig.target,
                class: sig.target.class(),
                family: sig.target.family_label(),
                marker: sig.marker_label,
                matched_offset: offset as u64,
                confidence: sig.confidence,
                specificity: sig.specificity,
                version,
            });
        }
    }
    dedup_and_rank(&mut matches);
    let structured: Vec<StructFinding> = struct_findings(bytes);
    let compiler: Option<CompilerIdentity> = best_compiler(&matches);
    let linker: Option<LinkerIdentity> = best_linker(&matches);
    let entropy: Option<EntropyProfile> = entropy_profile(bytes);
    SigReport {
        format,
        matches,
        structured,
        compiler,
        linker,
        entropy,
    }
}

fn pe_section_names(bytes: &[u8]) -> Vec<[u8; 8]> {
    if !bytes.starts_with(PE_MAGIC) {
        return Vec::new();
    }
    match parse_pe_image(bytes) {
        Ok(img) => img.sections.iter().map(|s| s.name).collect(),
        Err(_) => Vec::new(),
    }
}

fn signature_offset(
    sig: &EngineSignature,
    window: &[u8],
    section_names: &[[u8; 8]],
) -> Option<usize> {
    if sig.kind == SigKind::SectionName
        && let Some(pos) = section_name_offset(section_names, sig.pattern)
    {
        return Some(pos);
    }
    byte_find(window, sig.pattern)
}

fn section_name_offset(section_names: &[[u8; 8]], pattern: &[u8]) -> Option<usize> {
    let trimmed_target: &[u8] = pattern;
    for (index, raw) in section_names.iter().enumerate() {
        let end: usize = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let name: &[u8] = &raw[..end];
        if name == trimmed_target || (trimmed_target.len() <= 8 && raw.starts_with(trimmed_target))
        {
            return Some(index);
        }
    }
    None
}

fn dedup_and_rank(matches: &mut Vec<SigMatch>) {
    matches.sort_by(|a: &SigMatch, b: &SigMatch| {
        b.rank()
            .cmp(&a.rank())
            .then_with(|| a.class.cmp(b.class))
            .then_with(|| a.family.cmp(b.family))
    });
    let mut seen: std::collections::BTreeSet<(&'static str, &'static str)> =
        std::collections::BTreeSet::new();
    matches.retain(|m: &SigMatch| seen.insert((m.class, m.family)));
}

fn extract_version(rule: VersionRule, bytes: &[u8], window: &[u8]) -> Option<String> {
    match rule {
        VersionRule::None | VersionRule::EntropyBandClassify => None,
        VersionRule::DottedAfterMarker { marker } => dotted_after(window, marker),
        VersionRule::LiteralTail { marker } => literal_tail(window, marker),
        VersionRule::UpxPackHeader => upx_pack_header(bytes),
    }
}

fn dotted_after(window: &[u8], marker: &[u8]) -> Option<String> {
    let start: usize = byte_find(window, marker)? + marker.len();
    let tail: &[u8] = &window[start..window.len().min(start + VERSION_TAIL_CAP)];
    let mut out: Vec<u8> = Vec::with_capacity(16);
    let mut saw_digit: bool = false;
    for &b in tail {
        if b.is_ascii_digit() {
            saw_digit = true;
            out.push(b);
        } else if b == b'.' && saw_digit {
            out.push(b);
        } else {
            break;
        }
    }
    if !saw_digit || !out.contains(&b'.') {
        return None;
    }
    while out.last() == Some(&b'.') {
        out.pop();
    }
    String::from_utf8(out).ok()
}

fn literal_tail(window: &[u8], marker: &[u8]) -> Option<String> {
    let start: usize = byte_find(window, marker)? + marker.len();
    let tail: &[u8] = &window[start..window.len().min(start + VERSION_TAIL_CAP)];
    let mut out: Vec<u8> = Vec::with_capacity(40);
    for &b in tail {
        if b == 0 || b == b'\n' || b == b'\r' || b == b')' || b == b'/' {
            break;
        }
        if !(0x20..=0x7e).contains(&b) {
            break;
        }
        out.push(b);
    }
    if out.is_empty() {
        return None;
    }
    String::from_utf8(out).ok()
}

fn upx_pack_header(bytes: &[u8]) -> Option<String> {
    let window: &[u8] = &bytes[..bytes.len().min(SCAN_LIMIT)];
    let pos: usize = byte_find(window, b"UPX!")?;
    let hdr: &[u8] = window.get(pos..pos + 8)?;
    let hdr_version: u8 = hdr[4];
    let format_id: u8 = hdr[5];
    let method: u8 = hdr[6];
    let level: u8 = hdr[7];
    if hdr_version == 0 || hdr_version > 0x20 {
        return None;
    }
    let format_name: &str = match format_id {
        1 | 2 => "elf/i386",
        4 => "elf/amd64",
        16 => "linux/elf64",
        36 => "win32/pe",
        37 => "win64/pe",
        _ => "pe",
    };
    let method_name: &str = match method {
        2 => "nrv2b",
        3 => "nrv2d",
        4 => "nrv2e",
        14 => "lzma",
        _ => "unknown",
    };
    Some(format!(
        "pack-header v{hdr_version} format={format_name} method={method_name} level={level}"
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EpByte {
    Exact(u8),
    Any,
    Skip4,
}

#[derive(Debug, Clone, Copy)]
struct EpTemplate {
    pattern: &'static [EpByte],
    version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructFamily {
    Aspack,
    Petite,
    Mpress,
    Fsg,
    Nspack,
    Pecompact,
    VmProtect,
    Themida,
    Enigma,
    Armadillo,
    Obsidium,
    Msvc,
    Go,
    DotNet,
    Nsis,
    InnoSetup,
    InstallShield,
    Wise,
    AutoIt,
    Inject2Pe,
    FatPack,
    PkrCe1a,
    DotNetBundle,
}

impl StructFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Aspack => "aspack",
            Self::Petite => "petite",
            Self::Mpress => "mpress",
            Self::Fsg => "fsg",
            Self::Nspack => "nspack",
            Self::Pecompact => "pecompact",
            Self::VmProtect => "vmprotect",
            Self::Themida => "themida",
            Self::Enigma => "enigma",
            Self::Armadillo => "armadillo",
            Self::Obsidium => "obsidium",
            Self::Msvc => "msvc",
            Self::Go => "go",
            Self::DotNet => "dotnet",
            Self::Nsis => "nsis",
            Self::InnoSetup => "innosetup",
            Self::InstallShield => "installshield",
            Self::Wise => "wise",
            Self::AutoIt => "autoit",
            Self::Inject2Pe => "inject2pe",
            Self::FatPack => "fatpack",
            Self::PkrCe1a => "pkr-ce1a",
            Self::DotNetBundle => "dotnet-bundle",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructClass {
    Packer,
    Protector,
    Compiler,
    Linker,
    Installer,
}

impl StructClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Packer => "packer",
            Self::Protector => "protector",
            Self::Compiler => "compiler",
            Self::Linker => "linker",
            Self::Installer => "installer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructFinding {
    pub class: StructClass,
    pub family: StructFamily,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub locus: String,
    pub detail: String,
    pub native_vm: bool,
}

const ASPACK_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x60),
            EpByte::Exact(0xE8),
            EpByte::Exact(0x03),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0xE9),
            EpByte::Exact(0xEB),
            EpByte::Exact(0x04),
            EpByte::Exact(0x5D),
            EpByte::Exact(0x45),
            EpByte::Exact(0x55),
            EpByte::Exact(0xC3),
        ],
        version: "2.12-2.42",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x60),
            EpByte::Exact(0xE8),
            EpByte::Exact(0x70),
            EpByte::Exact(0x05),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0xEB),
            EpByte::Exact(0x4C),
        ],
        version: "2.000",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x60),
            EpByte::Exact(0xE8),
            EpByte::Exact(0x72),
            EpByte::Exact(0x05),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0xEB),
            EpByte::Exact(0x4C),
        ],
        version: "2.001",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x60),
            EpByte::Exact(0xE8),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x5D),
            EpByte::Exact(0x81),
            EpByte::Exact(0xED),
        ],
        version: "1.00b-1.08.03",
    },
];

const PETITE_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x66),
            EpByte::Exact(0x9C),
            EpByte::Exact(0x60),
            EpByte::Exact(0x50),
            EpByte::Exact(0x8D),
            EpByte::Exact(0x88),
            EpByte::Exact(0x00),
            EpByte::Exact(0xF0),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
        ],
        version: "1.3",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x66),
            EpByte::Exact(0x9C),
            EpByte::Exact(0x60),
            EpByte::Exact(0x50),
            EpByte::Exact(0x8B),
            EpByte::Exact(0xD8),
            EpByte::Exact(0x03),
            EpByte::Exact(0x00),
            EpByte::Exact(0x68),
            EpByte::Exact(0x54),
            EpByte::Exact(0xBC),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
        ],
        version: "1.4",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x64),
            EpByte::Exact(0xFF),
            EpByte::Exact(0x35),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x64),
            EpByte::Exact(0x89),
            EpByte::Exact(0x25),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x66),
            EpByte::Exact(0x9C),
            EpByte::Exact(0x60),
            EpByte::Exact(0x50),
            EpByte::Exact(0x8B),
            EpByte::Exact(0xD8),
        ],
        version: "2.1-2.4",
    },
];

const MPRESS_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x57),
            EpByte::Exact(0x56),
            EpByte::Exact(0x53),
            EpByte::Exact(0x51),
            EpByte::Exact(0x52),
            EpByte::Exact(0x55),
            EpByte::Exact(0xE8),
            EpByte::Skip4,
            EpByte::Exact(0xE8),
            EpByte::Skip4,
            EpByte::Exact(0x58),
            EpByte::Exact(0x05),
        ],
        version: "0.71-0.75",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x57),
            EpByte::Exact(0x56),
            EpByte::Exact(0x53),
            EpByte::Exact(0x51),
            EpByte::Exact(0x52),
            EpByte::Exact(0x41),
            EpByte::Exact(0x50),
            EpByte::Exact(0xE8),
            EpByte::Skip4,
            EpByte::Exact(0x48),
            EpByte::Exact(0x8D),
            EpByte::Exact(0x05),
        ],
        version: "0.71-0.92 (x64)",
    },
];

const FSG_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[
            EpByte::Exact(0xBB),
            EpByte::Skip4,
            EpByte::Exact(0xBF),
            EpByte::Skip4,
            EpByte::Exact(0xBE),
            EpByte::Skip4,
            EpByte::Exact(0x53),
            EpByte::Exact(0xE8),
        ],
        version: "1.0",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0xBE),
            EpByte::Skip4,
            EpByte::Exact(0xAD),
            EpByte::Exact(0x93),
            EpByte::Exact(0xAD),
            EpByte::Exact(0x97),
            EpByte::Exact(0xAD),
            EpByte::Exact(0x56),
            EpByte::Exact(0x96),
            EpByte::Exact(0xB2),
            EpByte::Exact(0x80),
        ],
        version: "1.31",
    },
];

const NSPACK_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x9C),
            EpByte::Exact(0x60),
            EpByte::Exact(0xE8),
            EpByte::Skip4,
            EpByte::Exact(0x5D),
            EpByte::Exact(0xB8),
            EpByte::Skip4,
            EpByte::Exact(0x2B),
            EpByte::Exact(0xE8),
            EpByte::Exact(0x8D),
            EpByte::Exact(0xB5),
        ],
        version: "2.9",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x9C),
            EpByte::Exact(0x60),
            EpByte::Exact(0xE8),
            EpByte::Skip4,
            EpByte::Exact(0x5D),
            EpByte::Exact(0x83),
            EpByte::Exact(0xED),
            EpByte::Any,
            EpByte::Exact(0x8D),
            EpByte::Exact(0x9D),
        ],
        version: "3.x",
    },
];

const VMPROTECT_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[EpByte::Exact(0x68), EpByte::Skip4, EpByte::Exact(0xE8)],
        version: "push/call vm-entry",
    },
    EpTemplate {
        pattern: &[EpByte::Exact(0x68), EpByte::Skip4, EpByte::Exact(0xE9)],
        version: "push/jmp vm-entry",
    },
];

const THEMIDA_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x83),
            EpByte::Exact(0xEC),
            EpByte::Exact(0x04),
            EpByte::Exact(0x50),
            EpByte::Exact(0x53),
            EpByte::Exact(0xE8),
            EpByte::Exact(0x01),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0xCC),
            EpByte::Exact(0x58),
        ],
        version: "2.0.1.0-2.1.8.0",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0x48),
            EpByte::Exact(0x83),
            EpByte::Exact(0xEC),
            EpByte::Exact(0x08),
            EpByte::Exact(0x50),
            EpByte::Exact(0x53),
            EpByte::Exact(0xE8),
            EpByte::Exact(0x01),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0xCC),
        ],
        version: "2.x (x64)",
    },
];

const ARMADILLO_TEMPLATES: &[EpTemplate] = &[EpTemplate {
    pattern: &[
        EpByte::Exact(0x60),
        EpByte::Exact(0xE8),
        EpByte::Exact(0x00),
        EpByte::Exact(0x00),
        EpByte::Exact(0x00),
        EpByte::Exact(0x00),
        EpByte::Exact(0x5D),
        EpByte::Exact(0x50),
        EpByte::Exact(0x51),
        EpByte::Exact(0x0F),
        EpByte::Exact(0xCA),
        EpByte::Exact(0xF7),
        EpByte::Exact(0xD2),
    ],
    version: "3.x-9.x",
}];

const OBSIDIUM_TEMPLATES: &[EpTemplate] = &[
    EpTemplate {
        pattern: &[
            EpByte::Exact(0xEB),
            EpByte::Exact(0x02),
            EpByte::Any,
            EpByte::Any,
            EpByte::Exact(0xE8),
            EpByte::Exact(0xE7),
            EpByte::Exact(0x1C),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
        ],
        version: "1.1.1.1",
    },
    EpTemplate {
        pattern: &[
            EpByte::Exact(0xE8),
            EpByte::Exact(0x0E),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x00),
            EpByte::Exact(0x8B),
            EpByte::Exact(0x54),
            EpByte::Exact(0x24),
            EpByte::Exact(0x0C),
        ],
        version: "1.2.5.0",
    },
];

struct EpFamily {
    family: StructFamily,
    class: StructClass,
    templates: &'static [EpTemplate],
    native_vm: bool,
}

const EP_FAMILIES: &[EpFamily] = &[
    EpFamily {
        family: StructFamily::Aspack,
        class: StructClass::Packer,
        templates: ASPACK_TEMPLATES,
        native_vm: false,
    },
    EpFamily {
        family: StructFamily::Petite,
        class: StructClass::Packer,
        templates: PETITE_TEMPLATES,
        native_vm: false,
    },
    EpFamily {
        family: StructFamily::Mpress,
        class: StructClass::Packer,
        templates: MPRESS_TEMPLATES,
        native_vm: false,
    },
    EpFamily {
        family: StructFamily::Fsg,
        class: StructClass::Packer,
        templates: FSG_TEMPLATES,
        native_vm: false,
    },
    EpFamily {
        family: StructFamily::Nspack,
        class: StructClass::Packer,
        templates: NSPACK_TEMPLATES,
        native_vm: false,
    },
    EpFamily {
        family: StructFamily::VmProtect,
        class: StructClass::Protector,
        templates: VMPROTECT_TEMPLATES,
        native_vm: true,
    },
    EpFamily {
        family: StructFamily::Themida,
        class: StructClass::Protector,
        templates: THEMIDA_TEMPLATES,
        native_vm: true,
    },
    EpFamily {
        family: StructFamily::Armadillo,
        class: StructClass::Protector,
        templates: ARMADILLO_TEMPLATES,
        native_vm: true,
    },
    EpFamily {
        family: StructFamily::Obsidium,
        class: StructClass::Protector,
        templates: OBSIDIUM_TEMPLATES,
        native_vm: true,
    },
];

fn entry_point_file_offset(image: &PeImage) -> Option<usize> {
    let section: &PeSection = image.section_containing_rva(image.entry_point_rva)?;
    let delta: u32 = image.entry_point_rva.checked_sub(section.virtual_address)?;
    (section.raw_pointer as usize).checked_add(delta as usize)
}

fn match_ep_template(window: &[u8], template: &EpTemplate) -> bool {
    let mut cursor: usize = 0;
    for byte in template.pattern {
        match byte {
            EpByte::Exact(expected) => {
                let Some(actual): Option<&u8> = window.get(cursor) else {
                    return false;
                };
                if actual != expected {
                    return false;
                }
                cursor += 1;
            }
            EpByte::Any => {
                if cursor >= window.len() {
                    return false;
                }
                cursor += 1;
            }
            EpByte::Skip4 => {
                cursor += 4;
                if cursor > window.len() {
                    return false;
                }
            }
        }
    }
    true
}

const EP_MATCH_WINDOW: usize = 64;

fn ep_anchored_findings(image: &PeImage, bytes: &[u8], out: &mut Vec<StructFinding>) {
    let Some(ep_off): Option<usize> = entry_point_file_offset(image) else {
        return;
    };
    let end: usize = ep_off.saturating_add(EP_MATCH_WINDOW).min(bytes.len());
    let Some(window): Option<&[u8]> = bytes.get(ep_off..end) else {
        return;
    };
    for fam in EP_FAMILIES {
        for template in fam.templates {
            if match_ep_template(window, template) {
                out.push(StructFinding {
                    class: fam.class,
                    family: fam.family,
                    version: Some(template.version.to_owned()),
                    confidence: Confidence::High,
                    locus: format!("entry point file-offset 0x{ep_off:X}"),
                    detail: format!(
                        "{} entry-point stub variant {}",
                        fam.family.label(),
                        template.version
                    ),
                    native_vm: fam.native_vm,
                });
                break;
            }
        }
    }
}

const PECOMPACT_RELOC_MARKER: u32 = u32::from_le_bytes(*b"PEC2");

fn pecompact_struct_finding(image: &PeImage, out: &mut Vec<StructFinding>) {
    let Some(first): Option<&PeSection> = image.sections.first() else {
        return;
    };
    if first.pointer_to_relocations == PECOMPACT_RELOC_MARKER {
        out.push(StructFinding {
            class: StructClass::Packer,
            family: StructFamily::Pecompact,
            version: Some("2.x".to_owned()),
            confidence: Confidence::High,
            locus: "section[0] PointerToRelocations".to_owned(),
            detail: "PEC2 stored in the first section's PointerToRelocations field".to_owned(),
            native_vm: false,
        });
    }
}

fn nspack_split_finding(image: &PeImage, out: &mut Vec<StructFinding>) {
    let has_nsp: bool = image
        .sections
        .iter()
        .any(|s: &PeSection| s.name_trimmed().starts_with(b".nsp"));
    if !has_nsp {
        return;
    }
    let Some(first): Option<&PeSection> = image.sections.first() else {
        return;
    };
    let version: &str = if first.raw_size > 0 && first.raw_pointer < 0x200 {
        "2.x"
    } else if first.raw_size == 0 && first.raw_pointer >= 0x200 {
        "3.x"
    } else {
        "2.x-3.x"
    };
    out.push(StructFinding {
        class: StructClass::Packer,
        family: StructFamily::Nspack,
        version: Some(version.to_owned()),
        confidence: Confidence::High,
        locus: "section[0] raw-size/raw-pointer".to_owned(),
        detail: format!("NsPack first-section layout pins version range {version}"),
        native_vm: false,
    });
}

const RICH_TAG: &[u8; 4] = b"Rich";
const DANS_TAG: u32 = 0x536E_6144;
const RICH_SCAN: usize = 4096;

struct RichBucket {
    min_id: u16,
    max_id: u16,
    vs: &'static str,
    toolset: &'static str,
}

const RICH_BUCKETS: &[RichBucket] = &[
    RichBucket {
        min_id: 0x005F,
        max_id: 0x006D,
        vs: "VS2002",
        toolset: "7.0",
    },
    RichBucket {
        min_id: 0x006E,
        max_id: 0x0083,
        vs: "VS2005",
        toolset: "8.0",
    },
    RichBucket {
        min_id: 0x0084,
        max_id: 0x009E,
        vs: "VS2008",
        toolset: "9.0",
    },
    RichBucket {
        min_id: 0x009F,
        max_id: 0x00AB,
        vs: "VS2010",
        toolset: "10.0",
    },
    RichBucket {
        min_id: 0x00AC,
        max_id: 0x00CB,
        vs: "VS2012",
        toolset: "11.0",
    },
    RichBucket {
        min_id: 0x00CC,
        max_id: 0x00FF,
        vs: "VS2013",
        toolset: "12.0",
    },
    RichBucket {
        min_id: 0x0100,
        max_id: 0x0105,
        vs: "VS2015",
        toolset: "14.0",
    },
    RichBucket {
        min_id: 0x0106,
        max_id: 0x010F,
        vs: "VS2017",
        toolset: "14.1",
    },
    RichBucket {
        min_id: 0x0110,
        max_id: 0x0125,
        vs: "VS2019",
        toolset: "14.2",
    },
    RichBucket {
        min_id: 0x0126,
        max_id: 0x0150,
        vs: "VS2022",
        toolset: "14.3",
    },
];

fn rich_bucket(product_id: u16) -> Option<&'static RichBucket> {
    RICH_BUCKETS
        .iter()
        .find(|b: &&RichBucket| product_id >= b.min_id && product_id <= b.max_id)
}

fn rich_compiler_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    let scan: &[u8] = &bytes[..bytes.len().min(RICH_SCAN)];
    let Some(rich_pos): Option<usize> = byte_find(scan, RICH_TAG) else {
        return;
    };
    let Some(key): Option<u32> = read_u32_le(scan, rich_pos + 4) else {
        return;
    };
    let mut cursor: usize = rich_pos;
    let mut dans: Option<usize> = None;
    while cursor >= 4 {
        cursor -= 4;
        let Some(raw): Option<u32> = read_u32_le(scan, cursor) else {
            break;
        };
        if raw ^ key == DANS_TAG {
            dans = Some(cursor);
            break;
        }
    }
    let Some(dans_pos): Option<usize> = dans else {
        return;
    };
    let mut best: Option<(u16, u16)> = None;
    let mut entry: usize = dans_pos + 16;
    while entry + 8 <= rich_pos {
        let Some(comp_id): Option<u32> = read_u32_le(scan, entry) else {
            break;
        };
        let decoded: u32 = comp_id ^ key;
        let product_id: u16 = (decoded >> 16) as u16;
        let build: u16 = (decoded & 0xFFFF) as u16;
        if rich_bucket(product_id).is_some() {
            let take: bool = best.is_none_or(|(prev, _): (u16, u16)| product_id > prev);
            if take {
                best = Some((product_id, build));
            }
        }
        entry += 8;
    }
    let Some((product_id, build)): Option<(u16, u16)> = best else {
        return;
    };
    let Some(bucket): Option<&RichBucket> = rich_bucket(product_id) else {
        return;
    };
    let version: String = format!("{}.{build} ({})", bucket.toolset, bucket.vs);
    out.push(StructFinding {
        class: StructClass::Compiler,
        family: StructFamily::Msvc,
        version: Some(version),
        confidence: Confidence::Medium,
        locus: format!("rich comp.id product 0x{product_id:04X}"),
        detail: format!(
            "Rich header decodes MSVC toolset build {}.{build}",
            bucket.toolset
        ),
        native_vm: false,
    });
}

const GO_BUILDINFO_MAGIC: &[u8; 14] = b"\xff Go buildinf:";

fn read_uvarint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let (value, consumed): (u64, usize) = read_uleb128_at(bytes, at).ok()?;
    Some((value, at.checked_add(consumed)?))
}

fn go_buildinfo_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    let Some(pos): Option<usize> = byte_find(bytes, GO_BUILDINFO_MAGIC) else {
        return;
    };
    let flags: u8 = match bytes.get(pos + 15) {
        Some(value) => *value,
        None => return,
    };
    let version: Option<String> = if flags & 0x2 != 0 {
        read_uvarint(bytes, pos + 32).and_then(|(len, next): (u64, usize)| {
            let len_usize: usize = usize::try_from(len).ok()?;
            let slice: &[u8] = bytes.get(next..next.checked_add(len_usize)?)?;
            String::from_utf8(slice.to_vec()).ok()
        })
    } else {
        None
    };
    out.push(StructFinding {
        class: StructClass::Compiler,
        family: StructFamily::Go,
        version,
        confidence: Confidence::High,
        locus: format!("go buildinfo blob at 0x{pos:X}"),
        detail: "Go buildinfo header (\\xff Go buildinf:) decoded".to_owned(),
        native_vm: false,
    });
}

fn dotnet_bsjb_finding(image: &PeImage, bytes: &[u8], out: &mut Vec<StructFinding>) {
    const CLR_DIR: usize = 14;
    let Some(clr): Option<&crate::packers::pe_sections::DataDirectory> =
        image.data_directories.get(CLR_DIR)
    else {
        return;
    };
    if clr.virtual_address == 0 {
        return;
    }
    let Some(host): Option<&PeSection> = image.section_containing_rva(clr.virtual_address) else {
        return;
    };
    let clr_off: usize =
        match host
            .raw_range(bytes.len())
            .and_then(|(start, _end): (usize, usize)| {
                let delta: u32 = clr.virtual_address.checked_sub(host.virtual_address)?;
                start.checked_add(delta as usize)
            }) {
            Some(value) => value,
            None => return,
        };
    let meta_rva: u32 = match read_u32_le(bytes, clr_off + 8) {
        Some(value) => value,
        None => return,
    };
    if meta_rva == 0 {
        return;
    }
    let Some(meta_host): Option<&PeSection> = image.section_containing_rva(meta_rva) else {
        return;
    };
    let meta_off: usize =
        match meta_host
            .raw_range(bytes.len())
            .and_then(|(start, _end): (usize, usize)| {
                let delta: u32 = meta_rva.checked_sub(meta_host.virtual_address)?;
                start.checked_add(delta as usize)
            }) {
            Some(value) => value,
            None => return,
        };
    if read_u32_le(bytes, meta_off) != Some(0x424A_5342) {
        return;
    }
    let ver_len: u32 = match read_u32_le(bytes, meta_off + 12) {
        Some(value) => value,
        None => return,
    };
    let ver_start: usize = meta_off + 16;
    let ver_len_usize: usize = ver_len as usize;
    let version: Option<String> = bytes
        .get(ver_start..ver_start.saturating_add(ver_len_usize))
        .map(|raw: &[u8]| {
            let end: usize = raw.iter().position(|b: &u8| *b == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..end]).into_owned()
        });
    out.push(StructFinding {
        class: StructClass::Compiler,
        family: StructFamily::DotNet,
        version,
        confidence: Confidence::High,
        locus: format!("BSJB metadata root at 0x{meta_off:X}"),
        detail: "CLR metadata-root version string decoded".to_owned(),
        native_vm: false,
    });
}

fn nsis_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    const NSIS_MAGIC: u32 = 0xDEAD_BEEF;
    let mut firstheader: Option<usize> = None;
    let mut cursor: usize = 0;
    while cursor + 4 <= bytes.len() {
        if read_u32_le(bytes, cursor) == Some(NSIS_MAGIC) {
            firstheader = Some(cursor);
            break;
        }
        cursor += 4;
    }
    let nullsoft: bool = byte_find(bytes, b"Nullsoft").is_some();
    if firstheader.is_none() && !nullsoft {
        return;
    }
    let version: Option<String> = nsis_manifest_version(bytes);
    let (locus, detail): (String, String) = firstheader.map_or_else(
        || {
            (
                "overlay".to_owned(),
                "Nullsoft installer overlay marker".to_owned(),
            )
        },
        |off: usize| {
            let compression: &str = nsis_compression(bytes, off);
            (
                format!("firstheader 0xDEADBEEF at 0x{off:X}"),
                format!("NSIS firstheader present, compression={compression}"),
            )
        },
    );
    out.push(StructFinding {
        class: StructClass::Installer,
        family: StructFamily::Nsis,
        version,
        confidence: Confidence::High,
        locus,
        detail,
        native_vm: false,
    });
}

fn nsis_compression(bytes: &[u8], firstheader: usize) -> &'static str {
    match read_u32_le(bytes, firstheader + 0x1C) {
        Some(value) if value & 0x8000_0000 != 0 => "solid",
        Some(_) => "non-solid",
        None => "unknown",
    }
}

fn nsis_manifest_version(bytes: &[u8]) -> Option<String> {
    let marker: &[u8] = b"Nullsoft Install System v";
    let pos: usize = byte_find(bytes, marker)? + marker.len();
    let tail: &[u8] = &bytes[pos..bytes.len().min(pos + 32)];
    let mut out: Vec<u8> = Vec::with_capacity(16);
    for &b in tail {
        if b.is_ascii_digit() || b == b'.' {
            out.push(b);
        } else {
            break;
        }
    }
    if out.contains(&b'.') {
        String::from_utf8(out).ok()
    } else {
        None
    }
}

fn inno_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    let marker: &[u8] = b"Inno Setup Setup Data (";
    let Some(start): Option<usize> = byte_find(bytes, marker) else {
        if byte_find(bytes, b"zlb\x1a").is_some() {
            out.push(StructFinding {
                class: StructClass::Installer,
                family: StructFamily::InnoSetup,
                version: None,
                confidence: Confidence::Medium,
                locus: "overlay".to_owned(),
                detail: "Inno Setup zlb compression marker".to_owned(),
                native_vm: false,
            });
        }
        return;
    };
    let ver_start: usize = start + marker.len();
    let tail: &[u8] = &bytes[ver_start..bytes.len().min(ver_start + 32)];
    let mut version: Vec<u8> = Vec::with_capacity(16);
    for &b in tail {
        if b == b')' {
            break;
        }
        version.push(b);
    }
    out.push(StructFinding {
        class: StructClass::Installer,
        family: StructFamily::InnoSetup,
        version: String::from_utf8(version).ok(),
        confidence: Confidence::High,
        locus: format!("data marker at 0x{start:X}"),
        detail: "Inno Setup data block version extracted at marker+23".to_owned(),
        native_vm: false,
    });
}

fn installshield_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    let present: bool = byte_find(bytes, b"InstallShield").is_some()
        || byte_find(bytes, b"ISSetupStream").is_some()
        || byte_find(bytes, b"ISc(").is_some();
    if present {
        out.push(StructFinding {
            class: StructClass::Installer,
            family: StructFamily::InstallShield,
            version: None,
            confidence: Confidence::Medium,
            locus: "byte scan".to_owned(),
            detail: "InstallShield setup marker".to_owned(),
            native_vm: false,
        });
    }
}

fn wise_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    if byte_find(bytes, b"Wise Installation").is_some() || byte_find(bytes, b"WiseMain").is_some() {
        out.push(StructFinding {
            class: StructClass::Installer,
            family: StructFamily::Wise,
            version: None,
            confidence: Confidence::Medium,
            locus: "byte scan".to_owned(),
            detail: "Wise Installation Wizard marker".to_owned(),
            native_vm: false,
        });
    }
}

fn autoit_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    let version: Option<&str> = if byte_find(bytes, b"AU3!EA06").is_some() {
        Some("EA06")
    } else if byte_find(bytes, b"AU3!EA05").is_some() {
        Some("EA05")
    } else {
        None
    };
    if let Some(tag) = version {
        out.push(StructFinding {
            class: StructClass::Installer,
            family: StructFamily::AutoIt,
            version: Some(tag.to_owned()),
            confidence: Confidence::High,
            locus: "byte scan".to_owned(),
            detail: format!("compiled AutoIt3 script ({tag})"),
            native_vm: false,
        });
    }
}

#[inline]
fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

const SECTION_CHARACTERISTIC_CODE_EXEC_READ: u32 = 0xE000_0020;
const SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const DATA_DIRECTORY_IMPORT: usize = 1;
const DATA_DIRECTORY_RESOURCE: usize = 2;

fn pe_optional_header_offset(bytes: &[u8]) -> Option<usize> {
    let e_lfanew: usize = read_u32_le(bytes, 0x3C)? as usize;
    let coff_off: usize = e_lfanew.checked_add(4)?;
    if bytes.get(e_lfanew..e_lfanew.checked_add(4)?)? != b"PE\x00\x00" {
        return None;
    }
    Some(coff_off + 20)
}

fn pe_size_of_headers(bytes: &[u8]) -> Option<u32> {
    let opt_off: usize = pe_optional_header_offset(bytes)?;
    read_u32_le(bytes, opt_off + 60)
}

fn pe_subsystem(bytes: &[u8]) -> Option<u16> {
    let opt_off: usize = pe_optional_header_offset(bytes)?;
    let magic: u16 = u16::from_le_bytes([*bytes.get(opt_off)?, *bytes.get(opt_off + 1)?]);
    let subsystem_off: usize = match magic {
        0x010B | 0x020B => opt_off + 68,
        _ => return None,
    };
    Some(u16::from_le_bytes([
        *bytes.get(subsystem_off)?,
        *bytes.get(subsystem_off + 1)?,
    ]))
}

fn inject2pe_finding(image: &PeImage, bytes: &[u8], out: &mut Vec<StructFinding>) {
    if image.sections.len() != 1 {
        return;
    }
    let import_empty: bool = image
        .data_directories
        .get(DATA_DIRECTORY_IMPORT)
        .is_none_or(|d| d.virtual_address == 0 && d.size == 0);
    if !import_empty {
        return;
    }
    let Some(size_of_headers): Option<u32> = pe_size_of_headers(bytes) else {
        return;
    };
    if size_of_headers != 0x200 {
        return;
    }
    let Some(first): Option<&PeSection> = image.sections.first() else {
        return;
    };
    if first.characteristics != SECTION_CHARACTERISTIC_CODE_EXEC_READ {
        return;
    }
    let Some(subsystem): Option<u16> = pe_subsystem(bytes) else {
        return;
    };
    if subsystem != SUBSYSTEM_WINDOWS_GUI {
        return;
    }
    out.push(StructFinding {
        class: StructClass::Packer,
        family: StructFamily::Inject2Pe,
        version: None,
        confidence: Confidence::Medium,
        locus: "single-section PE layout".to_owned(),
        detail: "no imports, one code-exec-read section, SizeOfHeaders=0x200, GUI subsystem"
            .to_owned(),
        native_vm: false,
    });
}

const FATPACK_LZMA_PROPS: &[u8; 5] = &[0x5D, 0x00, 0x00, 0x10, 0x00];

fn fatpack_finding(image: &PeImage, bytes: &[u8], out: &mut Vec<StructFinding>) {
    let Some(rsrc): Option<&crate::packers::pe_sections::DataDirectory> =
        image.data_directories.get(DATA_DIRECTORY_RESOURCE)
    else {
        return;
    };
    if rsrc.virtual_address == 0 || rsrc.size == 0 {
        return;
    }
    let Some(host): Option<&PeSection> = image.section_containing_rva(rsrc.virtual_address) else {
        return;
    };
    let Some((start, end)): Option<(usize, usize)> = host.raw_range(bytes.len()) else {
        return;
    };
    let region: &[u8] = &bytes[start..end];
    let Some(rel): Option<usize> = byte_find(region, FATPACK_LZMA_PROPS) else {
        return;
    };
    out.push(StructFinding {
        class: StructClass::Packer,
        family: StructFamily::FatPack,
        version: None,
        confidence: Confidence::Medium,
        locus: format!("resource section file-offset 0x{:X}", start + rel),
        detail: "LZMA props 5D 00 00 10 00 inside the PE resource section".to_owned(),
        native_vm: false,
    });
}

struct WildcardSig {
    head: &'static [u8],
    tail: &'static [u8],
    version: &'static str,
}

const PKR_CE1A_SIGS: &[WildcardSig] = &[
    WildcardSig {
        head: &[0x00, 0x69, 0x9A, 0xF9, 0x74],
        tail: &[0x96, 0xAA, 0xCB, 0x46, 0x00],
        version: "shellcode-size",
    },
    WildcardSig {
        head: &[0x00, 0x94, 0x48, 0x8D, 0x6A],
        tail: &[0xF2, 0x16, 0x0B, 0x68, 0x00],
        version: "shellcode-addr",
    },
];

fn wildcard4_offset(window: &[u8], sig: &WildcardSig) -> Option<usize> {
    let span: usize = sig.head.len() + 4 + sig.tail.len();
    let mut from: usize = 0;
    while let Some(rel) = byte_find(&window[from..], sig.head) {
        let at: usize = from + rel;
        let tail_at: usize = at + sig.head.len() + 4;
        if let Some(slice) = window.get(tail_at..tail_at + sig.tail.len())
            && slice == sig.tail
        {
            return Some(at);
        }
        from = at + 1;
        if from + span > window.len() {
            break;
        }
    }
    None
}

fn pkr_ce1a_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    let window: &[u8] = &bytes[..bytes.len().min(SCAN_LIMIT)];
    for sig in PKR_CE1A_SIGS {
        if let Some(off) = wildcard4_offset(window, sig) {
            out.push(StructFinding {
                class: StructClass::Packer,
                family: StructFamily::PkrCe1a,
                version: Some(sig.version.to_owned()),
                confidence: Confidence::High,
                locus: format!("byte pattern at 0x{off:X}"),
                detail: format!("pkr_ce1a stable {} byte sequence", sig.version),
                native_vm: false,
            });
            return;
        }
    }
}

const DOTNET_BUNDLE_SIGNATURE: &[u8; 32] = &[
    0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38, 0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
    0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18, 0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE,
];

fn dotnet_bundle_finding(bytes: &[u8], out: &mut Vec<StructFinding>) {
    let window: &[u8] = &bytes[..bytes.len().min(SCAN_LIMIT)];
    let Some(off): Option<usize> = byte_find(window, DOTNET_BUNDLE_SIGNATURE) else {
        return;
    };
    out.push(StructFinding {
        class: StructClass::Installer,
        family: StructFamily::DotNetBundle,
        version: None,
        confidence: Confidence::High,
        locus: format!("bundle signature at 0x{off:X}"),
        detail: ".NET single-file bundle signature placeholder GUID present".to_owned(),
        native_vm: false,
    });
}

#[must_use]
pub fn struct_findings(bytes: &[u8]) -> Vec<StructFinding> {
    let mut out: Vec<StructFinding> = Vec::new();
    if bytes.starts_with(PE_MAGIC)
        && let Ok(image) = parse_pe_image(bytes)
    {
        ep_anchored_findings(&image, bytes, &mut out);
        pecompact_struct_finding(&image, &mut out);
        nspack_split_finding(&image, &mut out);
        rich_compiler_finding(bytes, &mut out);
        dotnet_bsjb_finding(&image, bytes, &mut out);
        nsis_finding(bytes, &mut out);
        inno_finding(bytes, &mut out);
        installshield_finding(bytes, &mut out);
        wise_finding(bytes, &mut out);
        autoit_finding(bytes, &mut out);
        inject2pe_finding(&image, bytes, &mut out);
        fatpack_finding(&image, bytes, &mut out);
        pkr_ce1a_finding(bytes, &mut out);
        dotnet_bundle_finding(bytes, &mut out);
    }
    go_buildinfo_finding(bytes, &mut out);
    out
}

fn best_compiler(matches: &[SigMatch]) -> Option<CompilerIdentity> {
    matches.iter().find_map(|m: &SigMatch| match m.target {
        Target::Compiler(c) => Some(CompilerIdentity {
            compiler: c,
            version: m.version.clone(),
            marker: m.marker.to_owned(),
        }),
        _ => None,
    })
}

fn best_linker(matches: &[SigMatch]) -> Option<LinkerIdentity> {
    matches.iter().find_map(|m: &SigMatch| match m.target {
        Target::Linker(l) => Some(LinkerIdentity {
            linker: l,
            version: m.version.clone(),
            marker: m.marker.to_owned(),
        }),
        _ => None,
    })
}

fn entropy_profile(bytes: &[u8]) -> Option<EntropyProfile> {
    let blocks: Vec<EntropyBlock> = windowed_entropy(bytes, ENTROPY_WINDOW_4K);
    if blocks.is_empty() {
        return None;
    }
    let total: f64 = blocks.iter().map(|b: &EntropyBlock| b.entropy).sum();
    let mean_bits: f64 = total / blocks.len() as f64;
    let peak_bits: f64 = blocks
        .iter()
        .map(|b: &EntropyBlock| b.entropy)
        .fold(0.0_f64, f64::max);
    let high: usize = blocks.iter().filter(|b: &&EntropyBlock| b.high).count();
    let high_block_ratio: f64 = high as f64 / blocks.len() as f64;
    Some(EntropyProfile {
        mean_bits,
        peak_bits,
        high_block_ratio,
        band: EntropyBand::classify(mean_bits),
    })
}

#[cfg(feature = "chain")]
mod chain_impl {
    use super::{SigMatch, SigReport, StructFinding, Target, analyze};
    use disrobe_core::chain::{
        CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput, ObfuscatorCatalog,
        SupportQuality,
    };
    use disrobe_core::pass::PassId;

    pub const PASS_ID: PassId = "native.sig-engine";
    const FAMILY_NATIVE_FORMAT: &str = "native-format";

    #[derive(Debug)]
    pub struct SigEngineDetector;

    fn explain(report: &SigReport, best: &SigMatch) -> String {
        let version: String = best
            .version
            .as_deref()
            .map(|v: &str| format!(" version={v}"))
            .unwrap_or_default();
        let compiler: String = report
            .compiler
            .as_ref()
            .map(|c| {
                let cv: String = c
                    .version
                    .as_deref()
                    .map(|v: &str| format!(" {v}"))
                    .unwrap_or_default();
                format!(" compiler={}{cv}", c.compiler.label())
            })
            .unwrap_or_default();
        let linker: String = report
            .linker
            .as_ref()
            .map(|l| {
                let lv: String = l
                    .version
                    .as_deref()
                    .map(|v: &str| format!(" {v}"))
                    .unwrap_or_default();
                format!(" linker={}{lv}", l.linker.label())
            })
            .unwrap_or_default();
        let band: String = report
            .entropy
            .as_ref()
            .map(|e| format!(" entropy-band={}", e.band.label()))
            .unwrap_or_default();
        let structured: String = report
            .structured
            .first()
            .map(|s: &StructFinding| {
                let sv: String = s
                    .version
                    .as_deref()
                    .map(|v: &str| format!(" {v}"))
                    .unwrap_or_default();
                format!(" struct={}:{}{sv}", s.class.label(), s.family.label())
            })
            .unwrap_or_default();
        format!(
            "{class}={family}{version}{compiler}{linker}{structured}{band} marker={marker}",
            class = best.class,
            family = best.family,
            marker = best.marker,
        )
    }

    impl Detector for SigEngineDetector {
        #[inline]
        fn id(&self) -> PassId {
            PASS_ID
        }

        fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
            let report: SigReport = analyze(ctx.bytes);
            let best: &SigMatch = report.best()?;
            let explain: String = explain(&report, best);
            Some(DetectVerdict::new(
                PASS_ID,
                best.class,
                FAMILY_NATIVE_FORMAT,
                best.confidence.as_score(),
                best.specificity,
                vec!["sig-engine-composite"],
                explain,
            ))
        }
    }

    #[derive(Debug)]
    struct EngineEntry {
        id: &'static str,
        display: &'static str,
        quality: SupportQuality,
    }

    impl CatalogEntry for EngineEntry {
        #[inline]
        fn id(&self) -> &'static str {
            self.id
        }
        #[inline]
        fn display_name(&self) -> &'static str {
            self.display
        }
        #[inline]
        fn aliases(&self) -> &'static [&'static str] {
            &[]
        }
        #[inline]
        fn support_quality(&self) -> SupportQuality {
            self.quality
        }
    }

    static CATALOG: [EngineEntry; 5] = [
        EngineEntry {
            id: "packer",
            display: "Packer family (sig-engine)",
            quality: SupportQuality::DetectOnly,
        },
        EngineEntry {
            id: "protector",
            display: "Protector family (sig-engine)",
            quality: SupportQuality::DetectOnly,
        },
        EngineEntry {
            id: "compiler",
            display: "Compiler identity (sig-engine)",
            quality: SupportQuality::DetectOnly,
        },
        EngineEntry {
            id: "linker",
            display: "Linker identity (sig-engine)",
            quality: SupportQuality::DetectOnly,
        },
        EngineEntry {
            id: "installer",
            display: "Installer family (sig-engine)",
            quality: SupportQuality::DetectOnly,
        },
    ];

    impl ObfuscatorCatalog for SigEngineDetector {
        #[inline]
        fn pass_id(&self) -> PassId {
            PASS_ID
        }

        fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
            CATALOG
                .iter()
                .map(|e: &'static EngineEntry| e as &'static dyn CatalogEntry)
                .collect()
        }

        fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
            let report: SigReport = analyze(ctx.bytes);
            let best: &SigMatch = report.best()?;
            let entry_id: &'static str = match best.target {
                Target::Packer(_) => "packer",
                Target::Protector(_) => "protector",
                Target::Compiler(_) => "compiler",
                Target::Linker(_) => "linker",
                Target::Installer(_) => "installer",
            };
            let mut markers: Vec<String> = vec![format!(
                "{family}:{marker}",
                family = best.family,
                marker = best.marker
            )];
            if let Some(v) = best.version.as_deref() {
                markers.push(format!("version={v}"));
            }
            for finding in &report.structured {
                let sv: String = finding
                    .version
                    .as_deref()
                    .map(|v: &str| format!("={v}"))
                    .unwrap_or_default();
                markers.push(format!(
                    "struct:{}:{}{sv}",
                    finding.class.label(),
                    finding.family.label()
                ));
            }
            Some(DetectorOutput::new(
                entry_id,
                best.confidence.as_score(),
                markers,
            ))
        }
    }
}

#[cfg(feature = "chain")]
pub use chain_impl::{PASS_ID, SigEngineDetector};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn reference_uvarint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
        let tail: &[u8] = bytes.get(at..)?;
        let mut value: u64 = 0;
        for (index, byte) in tail.iter().copied().take(10).enumerate() {
            let shift: u32 = u32::try_from(index).ok()?.checked_mul(7)?;
            if shift == 63 && !matches!(byte, 0x00 | 0x01) {
                return None;
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some((value, at.checked_add(index + 1)?));
            }
        }
        None
    }

    #[test]
    fn go_buildinfo_uvarint_rejects_terminal_payload_overflow() {
        let encoded: [u8; 10] = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(read_uvarint(&encoded, 0), None);
        assert_eq!(
            read_uvarint(&[0xAA, 0xE5, 0x8E, 0x26], 1),
            Some((624_485, 4))
        );
    }

    #[test]
    fn go_buildinfo_uvarint_matches_an_independent_bounded_reference() {
        assert_eq!(read_uvarint(&[], 0), None);
        assert_eq!(read_uvarint(&[0x81, 0x00], 0), Some((1, 2)));
        let redundant_zero: [u8; 11] = [
            0xAA, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ];
        let redundant_actual: Option<(u64, usize)> = read_uvarint(&redundant_zero, 1);
        let redundant_expected: Option<(u64, usize)> = reference_uvarint(&redundant_zero, 1);
        assert_eq!(
            redundant_actual.map(|(value, _): (u64, usize)| value),
            Some(0)
        );
        assert_eq!(
            redundant_expected.map(|(value, _): (u64, usize)| value),
            Some(0)
        );
        assert_eq!(
            redundant_actual.map(|(_, next): (u64, usize)| next),
            Some(11)
        );
        assert_eq!(
            redundant_expected.map(|(_, next): (u64, usize)| next),
            Some(11)
        );
        let maximum: [u8; 11] = [
            0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ];
        let maximum_actual: Option<(u64, usize)> = read_uvarint(&maximum, 1);
        let maximum_expected: Option<(u64, usize)> = reference_uvarint(&maximum, 1);
        assert_eq!(
            maximum_actual.map(|(value, _): (u64, usize)| value),
            Some(u64::MAX)
        );
        assert_eq!(
            maximum_expected.map(|(value, _): (u64, usize)| value),
            Some(u64::MAX)
        );
        assert_eq!(maximum_actual.map(|(_, next): (u64, usize)| next), Some(11));
        assert_eq!(
            maximum_expected.map(|(_, next): (u64, usize)| next),
            Some(11)
        );
        for length in 1..=10usize {
            let truncated: Vec<u8> = vec![0x80; length];
            assert_eq!(read_uvarint(&truncated, 0), None);
        }

        let mut state: u64 = 0x8cb9_2baa_3f19_4d27;
        for length in 0..=32usize {
            for offset in 0..=length + 1 {
                let bytes: Vec<u8> = (0..length)
                    .map(|_: usize| {
                        state = state
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        (state >> 56) as u8
                    })
                    .collect();
                let actual: Option<(u64, usize)> = read_uvarint(&bytes, offset);
                let expected: Option<(u64, usize)> = reference_uvarint(&bytes, offset);
                assert_eq!(
                    actual.map(|(value, _): (u64, usize)| value),
                    expected.map(|(value, _): (u64, usize)| value)
                );
                assert_eq!(
                    actual.map(|(_, next): (u64, usize)| next),
                    expected.map(|(_, next): (u64, usize)| next)
                );
            }
        }
    }

    const UPX_PACKED: &[u8] =
        include_bytes!("../../../corpus/native/packers/upx/hello.packed.nrv2b.exe");
    const RUST_HELLO: &[u8] =
        include_bytes!("../../../corpus/native/packers/upx/hello.original.exe");
    const NIM_ELF: &[u8] = include_bytes!("../../../corpus/native/nim/hello.nim.elf");
    const ZIG_ELF: &[u8] = include_bytes!("../../../corpus/native/zig/hello.zig.elf");
    const DISC_ELF: &[u8] = include_bytes!("../../../corpus/native/discovery/disc.unstripped.elf");

    #[test]
    fn real_upx_sample_detects_packer_and_extracts_pack_header() {
        let report: SigReport = analyze(UPX_PACKED);
        assert_eq!(report.format, "pe");
        let upx: &SigMatch = report
            .matches
            .iter()
            .find(|m: &&SigMatch| m.family == "upx")
            .expect("upx packer detected in real sample");
        assert_eq!(upx.class, "packer");
        let version: &str = upx.version.as_deref().expect("upx pack-header extracted");
        assert!(
            version.contains("method=nrv2b"),
            "real nrv2b sample must report nrv2b method, got {version}"
        );
        assert!(
            version.contains("format=win32/pe"),
            "real x86 PE sample must report win32/pe format, got {version}"
        );
    }

    #[test]
    fn real_rust_binary_reports_rust_compiler_with_commit() {
        let report: SigReport = analyze(RUST_HELLO);
        let id: &CompilerIdentity = report.compiler.as_ref().expect("compiler identity");
        assert_eq!(id.compiler, CompilerFamily::Rust);
        let commit: &str = id.version.as_deref().expect("rustc commit hash");
        assert_eq!(commit, "59807616e1fa2540724bfbac14d7976d7e4a3860");
    }

    #[test]
    fn real_nim_elf_reports_clang_18() {
        let report: SigReport = analyze(NIM_ELF);
        assert_eq!(report.format, "elf");
        let id: &CompilerIdentity = report.compiler.as_ref().expect("compiler identity");
        assert_eq!(id.compiler, CompilerFamily::Clang);
        assert_eq!(id.version.as_deref(), Some("18.1.6"));
    }

    #[test]
    fn real_zig_elf_reports_zig_version() {
        let report: SigReport = analyze(ZIG_ELF);
        let zig: &SigMatch = report
            .matches
            .iter()
            .find(|m: &&SigMatch| m.family == "zig")
            .expect("zig compiler detected");
        assert_eq!(zig.version.as_deref(), Some("0.13.0"));
    }

    #[test]
    fn real_discovery_elf_reports_clang_22_and_lld_linker() {
        let report: SigReport = analyze(DISC_ELF);
        let id: &CompilerIdentity = report.compiler.as_ref().expect("compiler identity");
        assert_eq!(id.compiler, CompilerFamily::Clang);
        assert_eq!(id.version.as_deref(), Some("22.1.6"));
        let linker: &LinkerIdentity = report.linker.as_ref().expect("linker identity");
        assert_eq!(linker.linker, LinkerFamily::Lld);
        assert_eq!(linker.version.as_deref(), Some("22.1.6"));
    }

    #[test]
    fn real_upx_sample_high_entropy_band() {
        let report: SigReport = analyze(UPX_PACKED);
        let profile: &EntropyProfile = report.entropy.as_ref().expect("entropy profile");
        assert!(
            profile.mean_bits > 6.0,
            "a packed binary must have elevated mean entropy, got {}",
            profile.mean_bits
        );
        assert!(matches!(
            profile.band,
            EntropyBand::Compressed | EntropyBand::Encrypted | EntropyBand::Mixed
        ));
    }

    #[test]
    fn clean_low_entropy_buffer_is_plain_band() {
        let buf: Vec<u8> = vec![0u8; 8192];
        assert_eq!(EntropyBand::classify(0.0), EntropyBand::Plain);
        let report: SigReport = analyze(&buf);
        assert_eq!(
            report.entropy.as_ref().expect("entropy").band,
            EntropyBand::Plain
        );
        assert!(report.matches.is_empty());
    }

    #[test]
    fn dotted_after_parses_clean_version() {
        assert_eq!(
            dotted_after(b"clang version 18.1.6 (extra)", b"clang version "),
            Some("18.1.6".to_owned())
        );
        assert_eq!(
            dotted_after(b"clang version (bad)", b"clang version "),
            None
        );
    }

    #[test]
    fn dotted_after_requires_a_dot() {
        assert_eq!(dotted_after(b"GNU ld 9 abc", b"GNU ld "), None);
        assert_eq!(
            dotted_after(b"GNU ld 2.40 abc", b"GNU ld "),
            Some("2.40".to_owned())
        );
    }

    #[test]
    fn version_band_thresholds() {
        assert_eq!(EntropyBand::classify(7.99), EntropyBand::Encrypted);
        assert_eq!(EntropyBand::classify(7.5), EntropyBand::Compressed);
        assert_eq!(EntropyBand::classify(6.0), EntropyBand::Mixed);
        assert_eq!(EntropyBand::classify(2.0), EntropyBand::Plain);
    }

    #[test]
    fn synthetic_random_does_not_yield_family_match() {
        let buf: Vec<u8> = (0..4096u16)
            .map(|i: u16| (i.wrapping_mul(37) & 0xff) as u8)
            .collect();
        let report: SigReport = analyze(&buf);
        assert!(
            report.matches.is_empty(),
            "noise must not match: {:?}",
            report.matches
        );
    }

    #[test]
    fn dedup_keeps_one_per_class_family() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b"UPX! padding UPX! again");
        let report: SigReport = analyze(&buf);
        let upx_count: usize = report
            .matches
            .iter()
            .filter(|m: &&SigMatch| m.family == "upx")
            .count();
        assert_eq!(upx_count, 1);
    }

    #[test]
    fn target_serializes_class_and_family() {
        let t: Target = Target::Compiler(CompilerFamily::Rust);
        assert_eq!(t.class(), "compiler");
        assert_eq!(t.family_label(), "rust");
        let json: String = serde_json::to_string(&t).expect("serialize");
        assert!(json.contains("compiler") && json.contains("rust"), "{json}");
    }

    #[test]
    fn native_vm_protectors_flagged() {
        assert!(ProtectorFamily::VmProtect.is_native_vm());
        assert!(ProtectorFamily::Themida.is_native_vm());
        assert!(!ProtectorFamily::DotNetReactor.is_native_vm());
        assert!(!ProtectorFamily::ConfuserEx.is_native_vm());
    }

    struct PeBlueprint {
        section_name: [u8; 8],
        section_characteristics: u32,
        section_count: u16,
        size_of_headers: u32,
        subsystem: u16,
        import_dir: (u32, u32),
        resource_dir: (u32, u32),
        rsrc_payload: Vec<u8>,
    }

    impl Default for PeBlueprint {
        fn default() -> Self {
            Self {
                section_name: *b".text\x00\x00\x00",
                section_characteristics: 0xE000_0020,
                section_count: 1,
                size_of_headers: 0x200,
                subsystem: 2,
                import_dir: (0, 0),
                resource_dir: (0, 0),
                rsrc_payload: Vec::new(),
            }
        }
    }

    fn build_pe(bp: &PeBlueprint) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 0x600];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
        let coff_off: usize = pe_off + 4;
        buf[coff_off..coff_off + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&bp.section_count.to_le_bytes());
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt_off: usize = coff_off + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 24..opt_off + 32].copy_from_slice(&0x0040_0000u64.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        buf[opt_off + 60..opt_off + 64].copy_from_slice(&bp.size_of_headers.to_le_bytes());
        buf[opt_off + 68..opt_off + 70].copy_from_slice(&bp.subsystem.to_le_bytes());
        buf[opt_off + 108..opt_off + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir_off: usize = opt_off + 112;
        buf[dir_off + 8..dir_off + 12].copy_from_slice(&bp.import_dir.0.to_le_bytes());
        buf[dir_off + 12..dir_off + 16].copy_from_slice(&bp.import_dir.1.to_le_bytes());
        buf[dir_off + 16..dir_off + 20].copy_from_slice(&bp.resource_dir.0.to_le_bytes());
        buf[dir_off + 20..dir_off + 24].copy_from_slice(&bp.resource_dir.1.to_le_bytes());
        let sec_off: usize = opt_off + 0xF0;
        buf[sec_off..sec_off + 8].copy_from_slice(&bp.section_name);
        buf[sec_off + 8..sec_off + 12].copy_from_slice(&0x300u32.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&0x300u32.to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec_off + 36..sec_off + 40].copy_from_slice(&bp.section_characteristics.to_le_bytes());
        if !bp.rsrc_payload.is_empty() {
            let at: usize = 0x200;
            let end: usize = (at + bp.rsrc_payload.len()).min(buf.len());
            buf[at..end].copy_from_slice(&bp.rsrc_payload[..end - at]);
        }
        buf
    }

    #[test]
    fn inject2pe_structural_heuristic_detects_and_stays_clean() {
        let bp: PeBlueprint = PeBlueprint::default();
        let buf: Vec<u8> = build_pe(&bp);
        let findings: Vec<StructFinding> = struct_findings(&buf);
        assert!(
            findings
                .iter()
                .any(|f: &StructFinding| f.family == StructFamily::Inject2Pe),
            "inject2pe layout must be flagged"
        );

        let benign: PeBlueprint = PeBlueprint {
            import_dir: (0x2000, 0x40),
            ..PeBlueprint::default()
        };
        let benign_buf: Vec<u8> = build_pe(&benign);
        let benign_findings: Vec<StructFinding> = struct_findings(&benign_buf);
        assert!(
            !benign_findings
                .iter()
                .any(|f: &StructFinding| f.family == StructFamily::Inject2Pe),
            "a PE with an import directory must not be flagged inject2pe"
        );

        let two_sections: PeBlueprint = PeBlueprint {
            section_count: 2,
            ..PeBlueprint::default()
        };
        let two_buf: Vec<u8> = build_pe(&two_sections);
        assert!(
            !struct_findings(&two_buf)
                .iter()
                .any(|f: &StructFinding| f.family == StructFamily::Inject2Pe),
            "a multi-section PE must not be flagged inject2pe"
        );
    }

    #[test]
    fn fatpack_resource_lzma_props_detects_and_stays_clean() {
        let mut payload: Vec<u8> = vec![0u8; 16];
        payload[4..9].copy_from_slice(&[0x5D, 0x00, 0x00, 0x10, 0x00]);
        let bp: PeBlueprint = PeBlueprint {
            resource_dir: (0x1000, 0x100),
            rsrc_payload: payload,
            ..PeBlueprint::default()
        };
        let buf: Vec<u8> = build_pe(&bp);
        let findings: Vec<StructFinding> = struct_findings(&buf);
        assert!(
            findings
                .iter()
                .any(|f: &StructFinding| f.family == StructFamily::FatPack),
            "FatPack LZMA props in resource section must be flagged"
        );

        let clean: PeBlueprint = PeBlueprint {
            resource_dir: (0x1000, 0x100),
            rsrc_payload: vec![0u8; 16],
            ..PeBlueprint::default()
        };
        let clean_buf: Vec<u8> = build_pe(&clean);
        assert!(
            !struct_findings(&clean_buf)
                .iter()
                .any(|f: &StructFinding| f.family == StructFamily::FatPack),
            "a resource section without the LZMA props must not match FatPack"
        );
    }

    #[test]
    fn pkr_ce1a_wildcard_sequences_detect_and_stay_clean() {
        let bp: PeBlueprint = PeBlueprint {
            import_dir: (0x2000, 0x40),
            ..PeBlueprint::default()
        };
        let mut buf: Vec<u8> = build_pe(&bp);
        let seq: [u8; 14] = [
            0x00, 0x69, 0x9A, 0xF9, 0x74, 0xAA, 0xBB, 0xCC, 0xDD, 0x96, 0xAA, 0xCB, 0x46, 0x00,
        ];
        buf.extend_from_slice(&seq);
        let findings: Vec<StructFinding> = struct_findings(&buf);
        let hit: &StructFinding = findings
            .iter()
            .find(|f: &&StructFinding| f.family == StructFamily::PkrCe1a)
            .expect("pkr_ce1a stable sequence must be flagged");
        assert_eq!(hit.version.as_deref(), Some("shellcode-size"));

        let clean_buf: Vec<u8> = build_pe(&bp);
        assert!(
            !struct_findings(&clean_buf)
                .iter()
                .any(|f: &StructFinding| f.family == StructFamily::PkrCe1a),
            "a PE without the pkr_ce1a sequence must not match"
        );
    }

    #[test]
    fn dotnet_bundle_signature_detects_and_stays_clean() {
        let bp: PeBlueprint = PeBlueprint {
            import_dir: (0x2000, 0x40),
            ..PeBlueprint::default()
        };
        let mut buf: Vec<u8> = build_pe(&bp);
        buf.extend_from_slice(DOTNET_BUNDLE_SIGNATURE);
        let findings: Vec<StructFinding> = struct_findings(&buf);
        let hit: &StructFinding = findings
            .iter()
            .find(|f: &&StructFinding| f.family == StructFamily::DotNetBundle)
            .expect(".NET bundle signature must be flagged");
        assert_eq!(hit.class, StructClass::Installer);

        let clean_buf: Vec<u8> = build_pe(&bp);
        assert!(
            !struct_findings(&clean_buf)
                .iter()
                .any(|f: &StructFinding| f.family == StructFamily::DotNetBundle),
            "a PE without the bundle GUID must not match"
        );
    }

    #[test]
    fn codewarrior_compiler_marker_detects() {
        let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b"MW CodeWarrior compiler comment");
        let report: SigReport = analyze(&buf);
        let id: &CompilerIdentity = report.compiler.as_ref().expect("compiler identity");
        assert_eq!(id.compiler, CompilerFamily::CodeWarrior);
    }
}

#[cfg(all(test, feature = "chain"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod chain_tests {
    use super::*;
    use disrobe_core::chain::{
        CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput, ObfuscatorCatalog,
        SupportQuality,
    };

    const UPX_PACKED: &[u8] =
        include_bytes!("../../../corpus/native/packers/upx/hello.packed.nrv2b.exe");
    const NIM_ELF: &[u8] = include_bytes!("../../../corpus/native/nim/hello.nim.elf");

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(SigEngineDetector.id(), PASS_ID);
    }

    #[test]
    fn detector_classifies_real_upx_as_packer() {
        let v: DetectVerdict =
            Detector::detect(&SigEngineDetector, &ctx(UPX_PACKED)).expect("verdict");
        assert_eq!(v.format_tag, "packer");
        assert!(v.explain.contains("upx"), "{}", v.explain);
        assert!(v.explain.contains("method=nrv2b"), "{}", v.explain);
    }

    #[test]
    fn detector_surfaces_compiler_and_version_in_explain() {
        let v: DetectVerdict =
            Detector::detect(&SigEngineDetector, &ctx(NIM_ELF)).expect("verdict");
        assert!(
            v.explain.contains("compiler=clang 18.1.6"),
            "explain must carry the extracted clang version: {}",
            v.explain
        );
    }

    #[test]
    fn catalog_detect_returns_compiler_entry_for_real_nim() {
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&SigEngineDetector, &ctx(NIM_ELF)).expect("catalog hit");
        assert_eq!(out.entry_id, "compiler");
        assert!(
            out.markers.iter().any(|m: &String| m.contains("18.1.6")),
            "markers must carry the version: {:?}",
            out.markers
        );
    }

    #[test]
    fn catalog_lists_five_detect_only_classes() {
        let entries: Vec<&'static dyn CatalogEntry> = SigEngineDetector.catalog();
        assert_eq!(entries.len(), 5);
        for e in &entries {
            assert_eq!(e.support_quality(), SupportQuality::DetectOnly);
            assert!(!e.display_name().is_empty());
        }
    }

    #[test]
    fn catalog_detect_misses_clean_bytes() {
        let buf: Vec<u8> = vec![0x33u8; 2048];
        assert!(ObfuscatorCatalog::detect(&SigEngineDetector, &ctx(&buf)).is_none());
        assert!(Detector::detect(&SigEngineDetector, &ctx(&buf)).is_none());
    }
}
