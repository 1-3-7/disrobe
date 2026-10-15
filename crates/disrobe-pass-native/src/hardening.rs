use std::collections::BTreeSet;
use std::fmt;

use disrobe_bytes::{
    ByteReadError, read_u16_le_at, read_u32_be_at, read_u32_le_at, read_u64_le_at,
};
use object::read::elf::{
    Dyn as _, FileHeader, GnuProperty, GnuPropertyIterator, Note, NoteIterator, ProgramHeader as _,
    SectionTable, SymbolTable,
};
use object::read::macho::{
    FatArch, LoadCommandIterator, LoadCommandVariant, MachHeader, MachOFatFile, Nlist as _,
    Section as _, Segment as _,
};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader as _, PeFile};
use object::{Endianness, FileKind, LittleEndian as LE, elf, macho, pe};
use serde::{Deserialize, Serialize};

use crate::elf::{DynamicSymbol, ElfDynamicReport};

pub const HARDENING_SCHEMA: &str = "disrobe.native.hardening/v1";

const MAX_FAT_SLICES: usize = 64;
const MAX_NOTES: usize = 1024;
const MAX_GNU_PROPERTIES: usize = 1024;
const MAX_DYNAMIC_ENTRIES: usize = 65_536;
const MAX_LOAD_COMMANDS: usize = 65_536;
const MAX_DEBUG_DIRECTORIES: usize = 256;
const MAX_BLOB_INDICES: usize = 64;
const MAX_CITED_NAME_BYTES: usize = 4096;
const DEBUG_DIRECTORY_BYTES: usize = 28;

const IMAGE_GUARD_XFG_ENABLED: u32 = 0x0080_0000;
const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: u32 = 20;
const IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT: u32 = 0x1;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const CSSLOT_ALTERNATE_CODEDIRECTORY_END: u32 = 0x1005;
const CS_ADHOC: u32 = 0x0000_0002;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;

const ELF_CANARY_IMPORTS: [&str; 3] = [
    "__intel_security_cookie",
    "__stack_chk_fail",
    "__stack_chk_guard",
];
const ELF_CANARY_STATIC_SYMBOLS: [&str; 4] = [
    "__intel_security_cookie",
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__stack_chk_guard",
];
const MACHO_CANARY_IMPORTS: [&str; 2] = ["___stack_chk_fail", "___stack_chk_guard"];
const MACHO_OBJC_PREFIX: &str = "_objc_";
const MACHO_ARC_IMPORTS: [&str; 6] = [
    "_objc_autoreleaseReturnValue",
    "_objc_claimAutoreleasedReturnValue",
    "_objc_retainAutoreleaseReturnValue",
    "_objc_retainAutoreleasedReturnValue",
    "_objc_storeStrong",
    "_objc_unsafeClaimAutoreleasedReturnValue",
];

const FORTIFIED_FUNCTIONS: [&str; 85] = [
    "__asprintf_chk",
    "__confstr_chk",
    "__dprintf_chk",
    "__explicit_bzero_chk",
    "__fdelt_chk",
    "__fgets_chk",
    "__fgets_unlocked_chk",
    "__fgetws_chk",
    "__fgetws_unlocked_chk",
    "__fprintf_chk",
    "__fread_chk",
    "__fread_unlocked_chk",
    "__fwprintf_chk",
    "__getcwd_chk",
    "__getdomainname_chk",
    "__getgroups_chk",
    "__gethostname_chk",
    "__getlogin_r_chk",
    "__gets_chk",
    "__getwd_chk",
    "__inet_ntop_chk",
    "__inet_pton_chk",
    "__longjmp_chk",
    "__mbsnrtowcs_chk",
    "__mbsrtowcs_chk",
    "__mbstowcs_chk",
    "__memcpy_chk",
    "__memmove_chk",
    "__mempcpy_chk",
    "__memset_chk",
    "__obstack_printf_chk",
    "__obstack_vprintf_chk",
    "__poll_chk",
    "__ppoll_chk",
    "__pread64_chk",
    "__pread_chk",
    "__printf_chk",
    "__ptsname_r_chk",
    "__read_chk",
    "__readlink_chk",
    "__readlinkat_chk",
    "__realpath_chk",
    "__recv_chk",
    "__recvfrom_chk",
    "__snprintf_chk",
    "__sprintf_chk",
    "__stpcpy_chk",
    "__stpncpy_chk",
    "__strcat_chk",
    "__strcpy_chk",
    "__strlcat_chk",
    "__strlcpy_chk",
    "__strncat_chk",
    "__strncpy_chk",
    "__swprintf_chk",
    "__syslog_chk",
    "__ttyname_r_chk",
    "__vasprintf_chk",
    "__vdprintf_chk",
    "__vfprintf_chk",
    "__vfwprintf_chk",
    "__vprintf_chk",
    "__vsnprintf_chk",
    "__vsprintf_chk",
    "__vswprintf_chk",
    "__vsyslog_chk",
    "__vwprintf_chk",
    "__wcpcpy_chk",
    "__wcpncpy_chk",
    "__wcrtomb_chk",
    "__wcscat_chk",
    "__wcscpy_chk",
    "__wcslcat_chk",
    "__wcslcpy_chk",
    "__wcsncat_chk",
    "__wcsncpy_chk",
    "__wcsnrtombs_chk",
    "__wcsrtombs_chk",
    "__wcstombs_chk",
    "__wctomb_chk",
    "__wmemcpy_chk",
    "__wmemmove_chk",
    "__wmempcpy_chk",
    "__wmemset_chk",
    "__wprintf_chk",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImageFormat {
    #[serde(rename = "elf")]
    Elf,
    #[serde(rename = "pe")]
    Pe,
    #[serde(rename = "macho")]
    MachO,
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Elf => "ELF",
            Self::Pe => "PE",
            Self::MachO => "Mach-O",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageKind {
    Executable,
    SharedLibrary,
}

impl fmt::Display for ImageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Executable => "executable",
            Self::SharedLibrary => "shared library",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Property {
    Nx,
    Pie,
    Relro,
    StackCanary,
    Fortify,
    Rpath,
    Runpath,
    Ibt,
    Shstk,
    Bti,
    Pac,
    Symbols,
    DynamicBase,
    HighEntropyVa,
    NxCompat,
    ForceIntegrity,
    NoSeh,
    Appcontainer,
    SafeSeh,
    Gs,
    Cfg,
    Xfg,
    CetShadowStack,
    Authenticode,
    NxHeap,
    NxStack,
    Arc,
    CodeSignature,
    HardenedRuntime,
    Encrypted,
    Restrict,
}

impl Property {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nx => "nx",
            Self::Pie => "pie",
            Self::Relro => "relro",
            Self::StackCanary => "stack-canary",
            Self::Fortify => "fortify",
            Self::Rpath => "rpath",
            Self::Runpath => "runpath",
            Self::Ibt => "ibt",
            Self::Shstk => "shstk",
            Self::Bti => "bti",
            Self::Pac => "pac",
            Self::Symbols => "symbols",
            Self::DynamicBase => "dynamic-base",
            Self::HighEntropyVa => "high-entropy-va",
            Self::NxCompat => "nx-compat",
            Self::ForceIntegrity => "force-integrity",
            Self::NoSeh => "no-seh",
            Self::Appcontainer => "appcontainer",
            Self::SafeSeh => "safe-seh",
            Self::Gs => "gs",
            Self::Cfg => "cfg",
            Self::Xfg => "xfg",
            Self::CetShadowStack => "cet-shadow-stack",
            Self::Authenticode => "authenticode",
            Self::NxHeap => "nx-heap",
            Self::NxStack => "nx-stack",
            Self::Arc => "arc",
            Self::CodeSignature => "code-signature",
            Self::HardenedRuntime => "hardened-runtime",
            Self::Encrypted => "encrypted",
            Self::Restrict => "restrict",
        }
    }
}

impl fmt::Display for Property {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Present,
    Partial,
    Absent,
    NotApplicable,
    Undetermined,
}

impl Status {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Partial => "partial",
            Self::Absent => "absent",
            Self::NotApplicable => "not-applicable",
            Self::Undetermined => "undetermined",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub property: Property,
    pub status: Status,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FortifyCounts {
    pub fortified: usize,
    pub fortifiable: usize,
    pub fortified_functions: Vec<String>,
    pub unfortified_functions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageHardening {
    pub format: ImageFormat,
    pub machine: String,
    pub bits: u8,
    pub kind: ImageKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice_offset: Option<u64>,
    pub checks: Vec<Check>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fortify: Option<FortifyCounts>,
}

impl ImageHardening {
    #[must_use]
    pub fn check(&self, property: Property) -> Option<&Check> {
        self.checks
            .iter()
            .find(|check: &&Check| check.property == property)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningReport {
    pub schema: String,
    pub images: Vec<ImageHardening>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HardeningError {
    #[error("DR-NATIVE-0260: not an ELF, PE or Mach-O image ({detail})")]
    UnknownFormat { detail: String },
    #[error("DR-NATIVE-0261: {kind} has no exploit-mitigation report")]
    Unsupported { kind: &'static str },
    #[error("DR-NATIVE-0262: the {format} image cannot be read: {detail}")]
    Malformed { format: ImageFormat, detail: String },
    #[error(
        "DR-NATIVE-0263: the {format} file is {kind}, not a linked image, so it carries no load-time mitigations"
    )]
    NotLinkedImage {
        format: ImageFormat,
        kind: &'static str,
    },
    #[error(
        "DR-NATIVE-0264: the universal Mach-O declares {count} slices; at most {limit} are read"
    )]
    TooManySlices { count: usize, limit: usize },
}

pub fn analyze(data: &[u8]) -> Result<HardeningReport, HardeningError> {
    let kind: FileKind = FileKind::parse(data).map_err(|error: object::Error| {
        if data.starts_with(b"MZ") {
            HardeningError::Unsupported {
                kind: "an MS-DOS executable without a readable PE header",
            }
        } else {
            HardeningError::UnknownFormat {
                detail: error.to_string(),
            }
        }
    })?;
    let images: Vec<ImageHardening> = match kind {
        FileKind::Elf32 => vec![elf_image::<elf::FileHeader32<Endianness>>(data)?],
        FileKind::Elf64 => vec![elf_image::<elf::FileHeader64<Endianness>>(data)?],
        FileKind::Pe32 => vec![pe_image::<pe::ImageNtHeaders32>(data)?],
        FileKind::Pe64 => vec![pe_image::<pe::ImageNtHeaders64>(data)?],
        FileKind::MachO32 => vec![macho_image::<macho::MachHeader32<Endianness>>(data, None)?],
        FileKind::MachO64 => vec![macho_image::<macho::MachHeader64<Endianness>>(data, None)?],
        FileKind::MachOFat32 => fat_images::<macho::FatArch32>(data)?,
        FileKind::MachOFat64 => fat_images::<macho::FatArch64>(data)?,
        FileKind::Coff | FileKind::CoffBig | FileKind::CoffImport => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::Pe,
                kind: "a COFF object",
            });
        }
        FileKind::Archive => {
            return Err(HardeningError::Unsupported {
                kind: "a static library archive",
            });
        }
        FileKind::DyldCache => {
            return Err(HardeningError::Unsupported {
                kind: "a dyld shared cache",
            });
        }
        _ => {
            return Err(HardeningError::Unsupported {
                kind: "this object format",
            });
        }
    };
    Ok(HardeningReport {
        schema: HARDENING_SCHEMA.to_owned(),
        images,
    })
}

fn cite(field: &str, value: impl Into<String>) -> Evidence {
    Evidence {
        field: field.to_owned(),
        value: value.into(),
    }
}

fn check(property: Property, status: Status, evidence: Vec<Evidence>) -> Check {
    Check {
        property,
        status,
        evidence,
    }
}

fn malformed(format: ImageFormat, detail: impl fmt::Display) -> HardeningError {
    HardeningError::Malformed {
        format,
        detail: detail.to_string(),
    }
}

fn bounded_text(bytes: &[u8]) -> String {
    let end: usize = bytes.len().min(MAX_CITED_NAME_BYTES);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn cited_names(names: &BTreeSet<String>) -> String {
    names
        .iter()
        .map(String::as_str)
        .collect::<Vec<&str>>()
        .join(", ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfLinkage {
    Dynamic,
    SharedObject,
    Static,
}

#[derive(Debug, Default)]
struct ElfDynamicFacts {
    present: bool,
    flags: Option<u64>,
    flags_1: Option<u64>,
    bind_now_tag: bool,
    rpath: bool,
    runpath: bool,
}

#[derive(Debug, Default)]
struct ElfPropertyFacts {
    note_seen: bool,
    x86_features: Option<u32>,
    aarch64_features: Option<u32>,
    unreadable: Option<String>,
}

fn elf_image<Elf: FileHeader<Endian = Endianness>>(
    data: &[u8],
) -> Result<ImageHardening, HardeningError> {
    let header: &Elf =
        Elf::parse(data).map_err(|error: object::Error| malformed(ImageFormat::Elf, error))?;
    let endian: Endianness = header
        .endian()
        .map_err(|error: object::Error| malformed(ImageFormat::Elf, error))?;
    let e_type: u16 = header.e_type(endian);
    match e_type {
        elf::ET_EXEC | elf::ET_DYN => {}
        elf::ET_REL => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::Elf,
                kind: "an ET_REL relocatable object",
            });
        }
        elf::ET_CORE => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::Elf,
                kind: "an ET_CORE core dump",
            });
        }
        _ => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::Elf,
                kind: "an image of unknown e_type",
            });
        }
    }
    let machine: u16 = header.e_machine(endian);
    let segments: &[Elf::ProgramHeader] = header
        .program_headers(endian, data)
        .map_err(|error: object::Error| malformed(ImageFormat::Elf, error))?;

    let mut gnu_stack: Option<u32> = None;
    let mut relro: bool = false;
    let mut interpreter: Option<String> = None;
    let mut dynamic: ElfDynamicFacts = ElfDynamicFacts::default();
    let mut properties: ElfPropertyFacts = ElfPropertyFacts::default();
    for segment in segments {
        match segment.p_type(endian) {
            elf::PT_GNU_STACK => {
                gnu_stack.get_or_insert_with(|| segment.p_flags(endian));
            }
            elf::PT_GNU_RELRO => relro = true,
            elf::PT_INTERP => {
                let path: Option<&[u8]> = segment
                    .interpreter(endian, data)
                    .map_err(|error: object::Error| malformed(ImageFormat::Elf, error))?;
                if interpreter.is_none() {
                    interpreter = path.map(bounded_text);
                }
            }
            elf::PT_DYNAMIC if !dynamic.present => {
                let entries: &[Elf::Dyn] = segment
                    .dynamic(endian, data)
                    .map_err(|error: object::Error| malformed(ImageFormat::Elf, error))?
                    .unwrap_or_default();
                dynamic = elf_dynamic_facts::<Elf>(entries, endian)?;
            }
            elf::PT_NOTE | elf::PT_GNU_PROPERTY => {
                elf_scan_properties::<Elf>(segment, endian, data, &mut properties);
            }
            _ => {}
        }
    }

    let pie_flag: bool = dynamic
        .flags_1
        .is_some_and(|value: u64| value & u64::from(elf::DF_1_PIE) != 0);
    let linkage: ElfLinkage = if interpreter.is_some() {
        ElfLinkage::Dynamic
    } else if e_type == elf::ET_DYN && !pie_flag {
        ElfLinkage::SharedObject
    } else {
        ElfLinkage::Static
    };
    let kind: ImageKind = if linkage == ElfLinkage::SharedObject {
        ImageKind::SharedLibrary
    } else {
        ImageKind::Executable
    };
    let sections: Result<SectionTable<'_, Elf>, object::Error> = header.sections(endian, data);
    let dynamic_report: Option<ElfDynamicReport> = if dynamic.present {
        crate::elf::analyze(data)
    } else {
        None
    };
    let imports: Option<BTreeSet<String>> =
        dynamic_report.as_ref().map(|report: &ElfDynamicReport| {
            report
                .symbols
                .iter()
                .filter(|symbol: &&DynamicSymbol| !symbol.defined && !symbol.name.is_empty())
                .map(|symbol: &DynamicSymbol| symbol.name.clone())
                .collect()
        });

    let mut checks: Vec<Check> = vec![
        elf_nx(gnu_stack),
        elf_pie(e_type, linkage, interpreter.as_deref(), &dynamic),
        elf_relro(relro, &dynamic),
        elf_canary::<Elf>(linkage, imports.as_ref(), &sections, endian, data),
    ];
    let (fortify_check, fortify): (Check, Option<FortifyCounts>) =
        elf_fortify(linkage, imports.as_ref());
    checks.push(fortify_check);
    checks.push(elf_search_path(
        Property::Rpath,
        "DT_RPATH",
        dynamic.rpath,
        dynamic_report
            .as_ref()
            .and_then(|report: &ElfDynamicReport| report.rpath.as_deref()),
    ));
    checks.push(elf_search_path(
        Property::Runpath,
        "DT_RUNPATH",
        dynamic.runpath,
        dynamic_report
            .as_ref()
            .and_then(|report: &ElfDynamicReport| report.runpath.as_deref()),
    ));
    match machine {
        elf::EM_X86_64 | elf::EM_386 => {
            checks.push(elf_feature(
                Property::Ibt,
                &properties,
                properties.x86_features,
                elf::GNU_PROPERTY_X86_FEATURE_1_IBT,
                "GNU_PROPERTY_X86_FEATURE_1_AND",
                "IBT",
            ));
            checks.push(elf_feature(
                Property::Shstk,
                &properties,
                properties.x86_features,
                elf::GNU_PROPERTY_X86_FEATURE_1_SHSTK,
                "GNU_PROPERTY_X86_FEATURE_1_AND",
                "SHSTK",
            ));
        }
        elf::EM_AARCH64 => {
            checks.push(elf_feature(
                Property::Bti,
                &properties,
                properties.aarch64_features,
                elf::GNU_PROPERTY_AARCH64_FEATURE_1_BTI,
                "GNU_PROPERTY_AARCH64_FEATURE_1_AND",
                "BTI",
            ));
            checks.push(elf_feature(
                Property::Pac,
                &properties,
                properties.aarch64_features,
                elf::GNU_PROPERTY_AARCH64_FEATURE_1_PAC,
                "GNU_PROPERTY_AARCH64_FEATURE_1_AND",
                "PAC",
            ));
        }
        _ => {}
    }
    checks.push(elf_symbols::<Elf>(&sections, endian, data));

    Ok(ImageHardening {
        format: ImageFormat::Elf,
        machine: elf_machine_label(machine),
        bits: if header.is_type_64() { 64 } else { 32 },
        kind,
        slice_offset: None,
        checks,
        fortify,
    })
}

fn elf_dynamic_facts<Elf: FileHeader<Endian = Endianness>>(
    entries: &[Elf::Dyn],
    endian: Endianness,
) -> Result<ElfDynamicFacts, HardeningError> {
    let mut facts: ElfDynamicFacts = ElfDynamicFacts {
        present: true,
        ..ElfDynamicFacts::default()
    };
    for (index, entry) in entries.iter().enumerate() {
        if index == MAX_DYNAMIC_ENTRIES {
            return Err(malformed(
                ImageFormat::Elf,
                format!("PT_DYNAMIC holds more than {MAX_DYNAMIC_ENTRIES} entries before DT_NULL"),
            ));
        }
        let tag: u64 = entry.d_tag(endian).into();
        let value: u64 = entry.d_val(endian).into();
        if tag == u64::from(elf::DT_NULL) {
            break;
        }
        if tag == u64::from(elf::DT_FLAGS) {
            facts.flags = Some(value);
        } else if tag == u64::from(elf::DT_FLAGS_1) {
            facts.flags_1 = Some(value);
        } else if tag == u64::from(elf::DT_BIND_NOW) {
            facts.bind_now_tag = true;
        } else if tag == u64::from(elf::DT_RPATH) {
            facts.rpath = true;
        } else if tag == u64::from(elf::DT_RUNPATH) {
            facts.runpath = true;
        }
    }
    Ok(facts)
}

fn elf_scan_properties<Elf: FileHeader<Endian = Endianness>>(
    segment: &Elf::ProgramHeader,
    endian: Endianness,
    data: &[u8],
    facts: &mut ElfPropertyFacts,
) {
    if let Err(error) = elf_read_property_notes::<Elf>(segment, endian, data, facts) {
        facts.unreadable.get_or_insert(error);
    }
}

fn elf_read_property_notes<Elf: FileHeader<Endian = Endianness>>(
    segment: &Elf::ProgramHeader,
    endian: Endianness,
    data: &[u8],
    facts: &mut ElfPropertyFacts,
) -> Result<(), String> {
    let mut notes: NoteIterator<'_, Elf> = if segment.p_type(endian) == elf::PT_NOTE {
        let Some(notes): Option<NoteIterator<'_, Elf>> = segment
            .notes(endian, data)
            .map_err(|error: object::Error| error.to_string())?
        else {
            return Ok(());
        };
        notes
    } else {
        let bytes: &[u8] = segment
            .data(endian, data)
            .map_err(|()| "PT_GNU_PROPERTY lies outside the file".to_owned())?;
        NoteIterator::new(endian, segment.p_align(endian), bytes)
            .map_err(|error: object::Error| error.to_string())?
    };
    for _ in 0..MAX_NOTES {
        let Some(note): Option<Note<'_, Elf>> = notes
            .next()
            .map_err(|error: object::Error| error.to_string())?
        else {
            return Ok(());
        };
        let Some(properties): Option<GnuPropertyIterator<'_, Endianness>> =
            note.gnu_properties(endian)
        else {
            continue;
        };
        facts.note_seen = true;
        elf_read_gnu_properties(properties, endian, facts)?;
    }
    Err(format!(
        "the note segment holds more than {MAX_NOTES} notes"
    ))
}

fn elf_read_gnu_properties(
    mut properties: GnuPropertyIterator<'_, Endianness>,
    endian: Endianness,
    facts: &mut ElfPropertyFacts,
) -> Result<(), String> {
    for _ in 0..MAX_GNU_PROPERTIES {
        let Some(property): Option<GnuProperty<'_>> = properties
            .next()
            .map_err(|error: object::Error| error.to_string())?
        else {
            return Ok(());
        };
        let slot: &mut Option<u32> = match property.pr_type() {
            elf::GNU_PROPERTY_X86_FEATURE_1_AND => &mut facts.x86_features,
            elf::GNU_PROPERTY_AARCH64_FEATURE_1_AND => &mut facts.aarch64_features,
            _ => continue,
        };
        let bits: u32 = property
            .data_u32(endian)
            .map_err(|error: object::Error| error.to_string())?;
        slot.get_or_insert(bits);
    }
    Err(format!(
        "a GNU property note holds more than {MAX_GNU_PROPERTIES} properties"
    ))
}

fn segment_permissions(flags: u32) -> String {
    let mut label: String = String::new();
    if flags & elf::PF_R != 0 {
        label.push('R');
    }
    if flags & elf::PF_W != 0 {
        label.push('W');
    }
    if flags & elf::PF_X != 0 {
        label.push('E');
    }
    if label.is_empty() {
        label.push_str("none");
    }
    format!("{label} ({flags:#x})")
}

fn elf_nx(gnu_stack: Option<u32>) -> Check {
    match gnu_stack {
        Some(flags) if flags & elf::PF_X != 0 => check(
            Property::Nx,
            Status::Absent,
            vec![cite("PT_GNU_STACK.p_flags", segment_permissions(flags))],
        ),
        Some(flags) => check(
            Property::Nx,
            Status::Present,
            vec![cite("PT_GNU_STACK.p_flags", segment_permissions(flags))],
        ),
        None => check(
            Property::Nx,
            Status::Absent,
            vec![cite(
                "PT_GNU_STACK",
                "missing: the image never asks for a non-executable stack",
            )],
        ),
    }
}

fn elf_flags_text(dynamic: &ElfDynamicFacts) -> Vec<Evidence> {
    let mut evidence: Vec<Evidence> = Vec::new();
    if let Some(flags) = dynamic.flags {
        let named: &str = if flags & u64::from(elf::DF_BIND_NOW) != 0 {
            " (BIND_NOW)"
        } else {
            ""
        };
        evidence.push(cite("DT_FLAGS", format!("{flags:#x}{named}")));
    }
    if let Some(flags) = dynamic.flags_1 {
        let mut names: Vec<&str> = Vec::new();
        if flags & u64::from(elf::DF_1_NOW) != 0 {
            names.push("NOW");
        }
        if flags & u64::from(elf::DF_1_PIE) != 0 {
            names.push("PIE");
        }
        let named: String = if names.is_empty() {
            String::new()
        } else {
            format!(" ({})", names.join(", "))
        };
        evidence.push(cite("DT_FLAGS_1", format!("{flags:#x}{named}")));
    }
    if dynamic.bind_now_tag {
        evidence.push(cite("DT_BIND_NOW", "present"));
    }
    evidence
}

fn elf_pie(
    e_type: u16,
    linkage: ElfLinkage,
    interpreter: Option<&str>,
    dynamic: &ElfDynamicFacts,
) -> Check {
    if e_type == elf::ET_EXEC {
        return check(
            Property::Pie,
            Status::Absent,
            vec![cite("e_type", "ET_EXEC: loaded at its link-time address")],
        );
    }
    match (linkage, interpreter) {
        (_, Some(path)) => check(
            Property::Pie,
            Status::Present,
            vec![cite("e_type", "ET_DYN"), cite("PT_INTERP", path)],
        ),
        (ElfLinkage::SharedObject, None) => check(
            Property::Pie,
            Status::NotApplicable,
            vec![cite(
                "e_type",
                "ET_DYN without PT_INTERP or DF_1_PIE: a shared object, position-independent by construction",
            )],
        ),
        (ElfLinkage::Dynamic | ElfLinkage::Static, None) => {
            let mut evidence: Vec<Evidence> = vec![cite("e_type", "ET_DYN without PT_INTERP")];
            evidence.extend(elf_flags_text(dynamic));
            check(Property::Pie, Status::Present, evidence)
        }
    }
}

fn elf_relro(relro: bool, dynamic: &ElfDynamicFacts) -> Check {
    if !relro {
        return check(
            Property::Relro,
            Status::Absent,
            vec![cite("PT_GNU_RELRO", "missing")],
        );
    }
    let bind_now: bool = dynamic.bind_now_tag
        || dynamic
            .flags
            .is_some_and(|flags: u64| flags & u64::from(elf::DF_BIND_NOW) != 0)
        || dynamic
            .flags_1
            .is_some_and(|flags: u64| flags & u64::from(elf::DF_1_NOW) != 0);
    let mut evidence: Vec<Evidence> = vec![cite("PT_GNU_RELRO", "present")];
    if !dynamic.present {
        evidence.push(cite("PT_DYNAMIC", "missing, so nothing is bound lazily"));
        return check(Property::Relro, Status::Present, evidence);
    }
    evidence.extend(elf_flags_text(dynamic));
    if bind_now {
        check(Property::Relro, Status::Present, evidence)
    } else {
        evidence.push(cite(
            "bind-now",
            "neither DT_BIND_NOW, DF_BIND_NOW nor DF_1_NOW: the PLT GOT stays writable for lazy binding",
        ));
        check(Property::Relro, Status::Partial, evidence)
    }
}

fn elf_canary<Elf: FileHeader<Endian = Endianness>>(
    linkage: ElfLinkage,
    imports: Option<&BTreeSet<String>>,
    sections: &Result<SectionTable<'_, Elf>, object::Error>,
    endian: Endianness,
    data: &[u8],
) -> Check {
    if linkage != ElfLinkage::Static {
        let Some(imports): Option<&BTreeSet<String>> = imports else {
            return check(
                Property::StackCanary,
                Status::Undetermined,
                vec![cite(
                    "dynamic symbols",
                    "the dynamic symbol table cannot be read",
                )],
            );
        };
        let found: BTreeSet<String> = imports
            .iter()
            .filter(|name: &&String| ELF_CANARY_IMPORTS.contains(&name.as_str()))
            .cloned()
            .collect();
        return if found.is_empty() {
            check(
                Property::StackCanary,
                Status::Absent,
                vec![cite(
                    "imports",
                    format!(
                        "{} undefined dynamic symbols, none of {}",
                        imports.len(),
                        ELF_CANARY_IMPORTS.join(", ")
                    ),
                )],
            )
        } else {
            check(
                Property::StackCanary,
                Status::Present,
                vec![cite("imports", cited_names(&found))],
            )
        };
    }
    let table: &SectionTable<'_, Elf> = match sections {
        Ok(table) => table,
        Err(error) => {
            return check(
                Property::StackCanary,
                Status::Undetermined,
                vec![cite("section headers", error.to_string())],
            );
        }
    };
    let symbols: SymbolTable<'_, Elf> = match table.symbols(endian, data, elf::SHT_SYMTAB) {
        Ok(symbols) => symbols,
        Err(error) => {
            return check(
                Property::StackCanary,
                Status::Undetermined,
                vec![cite(".symtab", error.to_string())],
            );
        }
    };
    if symbols.len() <= 1 {
        return check(
            Property::StackCanary,
            Status::Undetermined,
            vec![cite(
                ".symtab",
                "missing: a stripped static image keeps no record of the canary",
            )],
        );
    }
    let found: BTreeSet<String> = symbols
        .iter()
        .filter_map(|symbol: &Elf::Sym| symbols.symbol_name(endian, symbol).ok())
        .filter_map(|name: &[u8]| std::str::from_utf8(name).ok())
        .filter(|name: &&str| ELF_CANARY_STATIC_SYMBOLS.contains(name))
        .map(str::to_owned)
        .collect();
    if found.is_empty() {
        check(
            Property::StackCanary,
            Status::Absent,
            vec![cite(
                ".symtab",
                format!(
                    "{} symbols, none of {}",
                    symbols.len().saturating_sub(1),
                    ELF_CANARY_STATIC_SYMBOLS.join(", ")
                ),
            )],
        )
    } else {
        check(
            Property::StackCanary,
            Status::Present,
            vec![cite(".symtab", cited_names(&found))],
        )
    }
}

fn plain_counterpart(fortified: &str) -> Option<&str> {
    fortified.strip_prefix("__")?.strip_suffix("_chk")
}

fn elf_fortify(
    linkage: ElfLinkage,
    imports: Option<&BTreeSet<String>>,
) -> (Check, Option<FortifyCounts>) {
    if linkage == ElfLinkage::Static {
        return (
            check(
                Property::Fortify,
                Status::Undetermined,
                vec![cite(
                    "linkage",
                    "statically linked: libc is inside the image, so there are no imports to count",
                )],
            ),
            None,
        );
    }
    let Some(imports): Option<&BTreeSet<String>> = imports else {
        return (
            check(
                Property::Fortify,
                Status::Undetermined,
                vec![cite(
                    "dynamic symbols",
                    "the dynamic symbol table cannot be read",
                )],
            ),
            None,
        );
    };
    let fortified: BTreeSet<String> = imports
        .iter()
        .filter(|name: &&String| FORTIFIED_FUNCTIONS.contains(&name.as_str()))
        .cloned()
        .collect();
    let unfortified: BTreeSet<String> = imports
        .iter()
        .filter(|name: &&String| {
            FORTIFIED_FUNCTIONS
                .iter()
                .filter_map(|function: &&str| plain_counterpart(function))
                .any(|plain: &str| plain == name.as_str())
        })
        .cloned()
        .collect();
    let counts: FortifyCounts = FortifyCounts {
        fortified: fortified.len(),
        fortifiable: fortified.len().saturating_add(unfortified.len()),
        fortified_functions: fortified.iter().cloned().collect(),
        unfortified_functions: unfortified.iter().cloned().collect(),
    };
    let status: Status = if !fortified.is_empty() {
        Status::Present
    } else if !unfortified.is_empty() {
        Status::Absent
    } else {
        Status::NotApplicable
    };
    let mut evidence: Vec<Evidence> = Vec::new();
    if !fortified.is_empty() {
        evidence.push(cite("fortified imports", cited_names(&fortified)));
    }
    if !unfortified.is_empty() {
        evidence.push(cite("unfortified imports", cited_names(&unfortified)));
    }
    if evidence.is_empty() {
        evidence.push(cite(
            "imports",
            "none of the libc functions FORTIFY_SOURCE replaces",
        ));
    }
    (check(Property::Fortify, status, evidence), Some(counts))
}

fn elf_search_path(property: Property, tag: &str, declared: bool, value: Option<&str>) -> Check {
    match (declared, value) {
        (true, Some(path)) => check(property, Status::Present, vec![cite(tag, path)]),
        (true, None) => check(
            property,
            Status::Present,
            vec![cite(tag, "present, but its string is outside DT_STRTAB")],
        ),
        (false, _) => check(property, Status::Absent, vec![cite(tag, "missing")]),
    }
}

fn elf_feature(
    property: Property,
    facts: &ElfPropertyFacts,
    features: Option<u32>,
    bit: u32,
    field: &str,
    name: &str,
) -> Check {
    if let Some(bits) = features {
        let set: bool = bits & bit != 0;
        let verb: &str = if set { "sets" } else { "lacks" };
        return check(
            property,
            if set { Status::Present } else { Status::Absent },
            vec![cite(field, format!("{bits:#x} {verb} {name}"))],
        );
    }
    if let Some(error) = &facts.unreadable {
        return check(
            property,
            Status::Undetermined,
            vec![cite("NT_GNU_PROPERTY_TYPE_0", error.clone())],
        );
    }
    let value: String = if facts.note_seen {
        format!("the GNU property note has no {field} entry")
    } else {
        "no GNU property note".to_owned()
    };
    check(
        property,
        Status::Absent,
        vec![cite("NT_GNU_PROPERTY_TYPE_0", value)],
    )
}

fn elf_symbols<Elf: FileHeader<Endian = Endianness>>(
    sections: &Result<SectionTable<'_, Elf>, object::Error>,
    endian: Endianness,
    data: &[u8],
) -> Check {
    let table: &SectionTable<'_, Elf> = match sections {
        Ok(table) => table,
        Err(error) => {
            return check(
                Property::Symbols,
                Status::Undetermined,
                vec![cite("section headers", error.to_string())],
            );
        }
    };
    match table.symbols(endian, data, elf::SHT_SYMTAB) {
        Ok(symbols) if symbols.len() > 1 => check(
            Property::Symbols,
            Status::Present,
            vec![cite(
                ".symtab",
                format!("{} symbols", symbols.len().saturating_sub(1)),
            )],
        ),
        Ok(_) => check(
            Property::Symbols,
            Status::Absent,
            vec![cite("SHT_SYMTAB", "missing: stripped")],
        ),
        Err(error) => check(
            Property::Symbols,
            Status::Undetermined,
            vec![cite(".symtab", error.to_string())],
        ),
    }
}

fn elf_machine_label(machine: u16) -> String {
    match machine {
        elf::EM_386 => "i386".to_owned(),
        elf::EM_X86_64 => "x86-64".to_owned(),
        elf::EM_AARCH64 => "aarch64".to_owned(),
        elf::EM_ARM => "arm".to_owned(),
        elf::EM_RISCV => "riscv".to_owned(),
        elf::EM_MIPS => "mips".to_owned(),
        elf::EM_PPC => "powerpc".to_owned(),
        elf::EM_PPC64 => "powerpc64".to_owned(),
        elf::EM_S390 => "s390".to_owned(),
        elf::EM_SPARCV9 => "sparcv9".to_owned(),
        elf::EM_LOONGARCH => "loongarch".to_owned(),
        other => format!("e_machine {other}"),
    }
}

#[derive(Debug, Clone, Copy)]
struct LoadConfigLayout {
    name: &'static str,
    pointer: usize,
    security_cookie: usize,
    se_handler_table: usize,
    se_handler_count: usize,
    guard_cf_function_count: usize,
    guard_flags: usize,
    guard_xfg_check: usize,
}

const LOAD_CONFIG_32: LoadConfigLayout = LoadConfigLayout {
    name: "IMAGE_LOAD_CONFIG_DIRECTORY32",
    pointer: 4,
    security_cookie: 60,
    se_handler_table: 64,
    se_handler_count: 68,
    guard_cf_function_count: 84,
    guard_flags: 88,
    guard_xfg_check: 172,
};

const LOAD_CONFIG_64: LoadConfigLayout = LoadConfigLayout {
    name: "IMAGE_LOAD_CONFIG_DIRECTORY64",
    pointer: 8,
    security_cookie: 88,
    se_handler_table: 96,
    se_handler_count: 104,
    guard_cf_function_count: 136,
    guard_flags: 144,
    guard_xfg_check: 280,
};

#[derive(Debug)]
enum LoadConfig<'data> {
    Missing,
    Unreadable(String),
    Present {
        bytes: &'data [u8],
        layout: LoadConfigLayout,
    },
}

impl LoadConfig<'_> {
    fn pointer(&self, offset: usize) -> Option<u64> {
        let Self::Present { bytes, layout }: &Self = self else {
            return None;
        };
        if layout.pointer == 8 {
            read_u64_le_at(bytes, offset).ok()
        } else {
            read_u32_le_at(bytes, offset).ok().map(u64::from)
        }
    }

    fn word(&self, offset: usize) -> Option<u32> {
        let Self::Present { bytes, .. }: &Self = self else {
            return None;
        };
        read_u32_le_at(bytes, offset).ok()
    }

    fn field_name(&self, field: &str) -> String {
        match self {
            Self::Present { layout, .. } => format!("{}.{field}", layout.name),
            Self::Missing | Self::Unreadable(_) => format!("IMAGE_LOAD_CONFIG_DIRECTORY.{field}"),
        }
    }

    fn size_text(&self) -> String {
        match self {
            Self::Present { bytes, .. } => format!("{:#x} bytes", bytes.len()),
            Self::Missing => "missing".to_owned(),
            Self::Unreadable(error) => error.clone(),
        }
    }
}

#[derive(Debug)]
enum ExtendedCharacteristics {
    Missing,
    Unreadable(String),
    Present(u32),
}

fn pe_image<Pe: ImageNtHeaders>(data: &[u8]) -> Result<ImageHardening, HardeningError> {
    let file: PeFile<'_, Pe> =
        PeFile::parse(data).map_err(|error: object::Error| malformed(ImageFormat::Pe, error))?;
    let nt: &Pe = file.nt_headers();
    let machine: u16 = nt.file_header().machine.get(LE);
    let characteristics: u16 = nt.file_header().characteristics.get(LE);
    let dll_characteristics: u16 = nt.optional_header().dll_characteristics();
    let is_64: bool = nt.is_type_64();
    let layout: LoadConfigLayout = if is_64 {
        LOAD_CONFIG_64
    } else {
        LOAD_CONFIG_32
    };
    let load_config: LoadConfig<'_> = pe_load_config(&file, data, layout);
    let extended: ExtendedCharacteristics = pe_extended_characteristics(&file, data);
    let x86_family: bool = matches!(
        machine,
        pe::IMAGE_FILE_MACHINE_I386 | pe::IMAGE_FILE_MACHINE_AMD64
    );

    let mut checks: Vec<Check> = vec![
        pe_dynamic_base(dll_characteristics, characteristics),
        if is_64 {
            pe_flag(
                Property::HighEntropyVa,
                dll_characteristics,
                pe::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
                "HIGH_ENTROPY_VA",
            )
        } else {
            check(
                Property::HighEntropyVa,
                Status::NotApplicable,
                vec![cite(
                    "IMAGE_OPTIONAL_HEADER32.Magic",
                    "PE32: a 32-bit address space has no high-entropy layout",
                )],
            )
        },
        pe_flag(
            Property::NxCompat,
            dll_characteristics,
            pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
            "NX_COMPAT",
        ),
        pe_flag(
            Property::ForceIntegrity,
            dll_characteristics,
            pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
            "FORCE_INTEGRITY",
        ),
        pe_flag(
            Property::NoSeh,
            dll_characteristics,
            pe::IMAGE_DLLCHARACTERISTICS_NO_SEH,
            "NO_SEH",
        ),
        pe_flag(
            Property::Appcontainer,
            dll_characteristics,
            pe::IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
            "APPCONTAINER",
        ),
        pe_safe_seh(machine, dll_characteristics, &load_config, layout),
        pe_gs(&load_config, layout),
        pe_cfg(dll_characteristics, &load_config, layout),
        pe_xfg(&load_config, layout),
    ];
    checks.push(if x86_family {
        pe_cet(&extended)
    } else {
        check(
            Property::CetShadowStack,
            Status::NotApplicable,
            vec![cite(
                "IMAGE_FILE_HEADER.Machine",
                format!(
                    "{}: CET shadow stacks exist only on x86",
                    pe_machine_label(machine)
                ),
            )],
        )
    });
    checks.push(pe_authenticode(&file, data));

    Ok(ImageHardening {
        format: ImageFormat::Pe,
        machine: pe_machine_label(machine),
        bits: if is_64 { 64 } else { 32 },
        kind: if characteristics & pe::IMAGE_FILE_DLL != 0 {
            ImageKind::SharedLibrary
        } else {
            ImageKind::Executable
        },
        slice_offset: None,
        checks,
        fortify: None,
    })
}

fn pe_load_config<'data, Pe: ImageNtHeaders>(
    file: &PeFile<'data, Pe>,
    data: &'data [u8],
    layout: LoadConfigLayout,
) -> LoadConfig<'data> {
    let Some(directory): Option<&pe::ImageDataDirectory> =
        file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
    else {
        return LoadConfig::Missing;
    };
    let rva: u32 = directory.virtual_address.get(LE);
    let Some(tail): Option<&[u8]> = file.section_table().pe_data_at(data, rva) else {
        return LoadConfig::Unreadable(format!(
            "the load configuration RVA {rva:#x} maps to no section data"
        ));
    };
    let Ok(declared): Result<u32, ByteReadError> = read_u32_le_at(tail, 0) else {
        return LoadConfig::Unreadable(format!(
            "the load configuration at RVA {rva:#x} is shorter than its Size field"
        ));
    };
    let Some(bytes): Option<&[u8]> = usize::try_from(declared)
        .ok()
        .and_then(|size: usize| tail.get(..size))
    else {
        return LoadConfig::Unreadable(format!(
            "the load configuration declares {declared:#x} bytes, the file holds {:#x} at RVA {rva:#x}",
            tail.len()
        ));
    };
    LoadConfig::Present { bytes, layout }
}

#[derive(Debug, Clone, Copy)]
struct DebugEntry {
    kind: u32,
    size: u32,
    rva: u32,
    offset: u32,
}

fn debug_entry(entry: &[u8]) -> Result<DebugEntry, ByteReadError> {
    Ok(DebugEntry {
        kind: read_u32_le_at(entry, 12)?,
        size: read_u32_le_at(entry, 16)?,
        rva: read_u32_le_at(entry, 20)?,
        offset: read_u32_le_at(entry, 24)?,
    })
}

fn pe_extended_characteristics<Pe: ImageNtHeaders>(
    file: &PeFile<'_, Pe>,
    data: &[u8],
) -> ExtendedCharacteristics {
    let Some(directory): Option<&pe::ImageDataDirectory> =
        file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_DEBUG)
    else {
        return ExtendedCharacteristics::Missing;
    };
    let table: &[u8] = match directory.data(data, &file.section_table()) {
        Ok(table) => table,
        Err(error) => return ExtendedCharacteristics::Unreadable(error.to_string()),
    };
    let count: usize = table.len() / DEBUG_DIRECTORY_BYTES;
    if count > MAX_DEBUG_DIRECTORIES {
        return ExtendedCharacteristics::Unreadable(format!(
            "the debug directory holds {count} entries, more than {MAX_DEBUG_DIRECTORIES}"
        ));
    }
    for entry in table.chunks_exact(DEBUG_DIRECTORY_BYTES) {
        let Ok(DebugEntry {
            kind,
            size,
            rva,
            offset,
        }): Result<DebugEntry, ByteReadError> = debug_entry(entry)
        else {
            continue;
        };
        if kind != IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS {
            continue;
        }
        if size < 4 {
            return ExtendedCharacteristics::Unreadable(format!(
                "the IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS entry holds {size} bytes"
            ));
        }
        let value: Option<u32> = if offset != 0 {
            usize::try_from(offset)
                .ok()
                .and_then(|offset: usize| read_u32_le_at(data, offset).ok())
        } else {
            file.section_table()
                .pe_data_at(data, rva)
                .and_then(|bytes: &[u8]| read_u32_le_at(bytes, 0).ok())
        };
        return value.map_or_else(
            || {
                ExtendedCharacteristics::Unreadable(format!(
                    "the IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS data at file offset {offset:#x} is outside the file"
                ))
            },
            ExtendedCharacteristics::Present,
        );
    }
    ExtendedCharacteristics::Missing
}

fn dll_characteristics_text(value: u16, name: &str, set: bool) -> String {
    let state: &str = if set { "set" } else { "clear" };
    format!("{value:#06x} ({name} {state})")
}

fn pe_flag(property: Property, value: u16, flag: u16, name: &str) -> Check {
    let set: bool = value & flag != 0;
    check(
        property,
        if set { Status::Present } else { Status::Absent },
        vec![cite(
            "IMAGE_OPTIONAL_HEADER.DllCharacteristics",
            dll_characteristics_text(value, name, set),
        )],
    )
}

fn pe_dynamic_base(dll_characteristics: u16, characteristics: u16) -> Check {
    let set: bool = dll_characteristics & pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0;
    let mut evidence: Vec<Evidence> = vec![cite(
        "IMAGE_OPTIONAL_HEADER.DllCharacteristics",
        dll_characteristics_text(dll_characteristics, "DYNAMIC_BASE", set),
    )];
    if !set {
        return check(Property::DynamicBase, Status::Absent, evidence);
    }
    if characteristics & pe::IMAGE_FILE_RELOCS_STRIPPED != 0 {
        evidence.push(cite(
            "IMAGE_FILE_HEADER.Characteristics",
            format!(
                "{characteristics:#06x} (RELOCS_STRIPPED set: the loader cannot move the image)"
            ),
        ));
        return check(Property::DynamicBase, Status::Partial, evidence);
    }
    check(Property::DynamicBase, Status::Present, evidence)
}

fn load_config_missing(property: Property, load_config: &LoadConfig<'_>) -> Option<Check> {
    match load_config {
        LoadConfig::Missing => Some(check(
            property,
            Status::Absent,
            vec![cite("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "missing")],
        )),
        LoadConfig::Unreadable(error) => Some(check(
            property,
            Status::Undetermined,
            vec![cite("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", error.clone())],
        )),
        LoadConfig::Present { .. } => None,
    }
}

fn field_absent(load_config: &LoadConfig<'_>, field: &str) -> Evidence {
    cite(
        &load_config.field_name(field),
        format!(
            "beyond the load configuration ({})",
            load_config.size_text()
        ),
    )
}

fn pe_safe_seh(
    machine: u16,
    dll_characteristics: u16,
    load_config: &LoadConfig<'_>,
    layout: LoadConfigLayout,
) -> Check {
    if machine != pe::IMAGE_FILE_MACHINE_I386 {
        return check(
            Property::SafeSeh,
            Status::NotApplicable,
            vec![cite(
                "IMAGE_FILE_HEADER.Machine",
                format!(
                    "{}: exception handling is table-based, SafeSEH is x86-only",
                    pe_machine_label(machine)
                ),
            )],
        );
    }
    if dll_characteristics & pe::IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
        return check(
            Property::SafeSeh,
            Status::NotApplicable,
            vec![cite(
                "IMAGE_OPTIONAL_HEADER.DllCharacteristics",
                dll_characteristics_text(dll_characteristics, "NO_SEH", true),
            )],
        );
    }
    if let Some(missing) = load_config_missing(Property::SafeSeh, load_config) {
        return missing;
    }
    let (Some(table), Some(count)): (Option<u64>, Option<u32>) = (
        load_config.pointer(layout.se_handler_table),
        load_config.word(layout.se_handler_count),
    ) else {
        return check(
            Property::SafeSeh,
            Status::Absent,
            vec![field_absent(load_config, "SEHandlerTable")],
        );
    };
    let evidence: Vec<Evidence> = vec![
        cite(
            &load_config.field_name("SEHandlerTable"),
            format!("{table:#x}"),
        ),
        cite(&load_config.field_name("SEHandlerCount"), count.to_string()),
    ];
    let status: Status = if table != 0 {
        Status::Present
    } else {
        Status::Absent
    };
    check(Property::SafeSeh, status, evidence)
}

fn pe_gs(load_config: &LoadConfig<'_>, layout: LoadConfigLayout) -> Check {
    if let Some(missing) = load_config_missing(Property::Gs, load_config) {
        return missing;
    }
    let Some(cookie): Option<u64> = load_config.pointer(layout.security_cookie) else {
        return check(
            Property::Gs,
            Status::Absent,
            vec![field_absent(load_config, "SecurityCookie")],
        );
    };
    check(
        Property::Gs,
        if cookie != 0 {
            Status::Present
        } else {
            Status::Absent
        },
        vec![cite(
            &load_config.field_name("SecurityCookie"),
            format!("{cookie:#x}"),
        )],
    )
}

fn pe_cfg(
    dll_characteristics: u16,
    load_config: &LoadConfig<'_>,
    layout: LoadConfigLayout,
) -> Check {
    let set: bool = dll_characteristics & pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0;
    let mut evidence: Vec<Evidence> = vec![cite(
        "IMAGE_OPTIONAL_HEADER.DllCharacteristics",
        dll_characteristics_text(dll_characteristics, "GUARD_CF", set),
    )];
    if !set {
        if let Some(flags) = load_config.word(layout.guard_flags) {
            evidence.push(cite(
                &load_config.field_name("GuardFlags"),
                format!("{flags:#x}"),
            ));
        }
        return check(Property::Cfg, Status::Absent, evidence);
    }
    match load_config {
        LoadConfig::Missing => {
            evidence.push(cite("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "missing"));
            return check(Property::Cfg, Status::Partial, evidence);
        }
        LoadConfig::Unreadable(error) => {
            evidence.push(cite("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", error.clone()));
            return check(Property::Cfg, Status::Undetermined, evidence);
        }
        LoadConfig::Present { .. } => {}
    }
    let Some(flags): Option<u32> = load_config.word(layout.guard_flags) else {
        evidence.push(field_absent(load_config, "GuardFlags"));
        return check(Property::Cfg, Status::Partial, evidence);
    };
    evidence.push(cite(
        &load_config.field_name("GuardFlags"),
        format!("{flags:#x}"),
    ));
    if let Some(count) = load_config.pointer(layout.guard_cf_function_count) {
        evidence.push(cite(
            &load_config.field_name("GuardCFFunctionCount"),
            count.to_string(),
        ));
    }
    let status: Status = if flags & pe::IMAGE_GUARD_CF_INSTRUMENTED != 0 {
        Status::Present
    } else {
        Status::Partial
    };
    check(Property::Cfg, status, evidence)
}

fn pe_xfg(load_config: &LoadConfig<'_>, layout: LoadConfigLayout) -> Check {
    if let Some(missing) = load_config_missing(Property::Xfg, load_config) {
        return missing;
    }
    let Some(flags): Option<u32> = load_config.word(layout.guard_flags) else {
        return check(
            Property::Xfg,
            Status::Absent,
            vec![field_absent(load_config, "GuardFlags")],
        );
    };
    let mut evidence: Vec<Evidence> = vec![cite(
        &load_config.field_name("GuardFlags"),
        format!(
            "{flags:#x} ({} XFG_ENABLED)",
            if flags & IMAGE_GUARD_XFG_ENABLED != 0 {
                "sets"
            } else {
                "lacks"
            }
        ),
    )];
    if flags & IMAGE_GUARD_XFG_ENABLED == 0 {
        return check(Property::Xfg, Status::Absent, evidence);
    }
    match load_config.pointer(layout.guard_xfg_check) {
        Some(pointer) if pointer != 0 => {
            evidence.push(cite(
                &load_config.field_name("GuardXFGCheckFunctionPointer"),
                format!("{pointer:#x}"),
            ));
            check(Property::Xfg, Status::Present, evidence)
        }
        Some(_) => {
            evidence.push(cite(
                &load_config.field_name("GuardXFGCheckFunctionPointer"),
                "0x0",
            ));
            check(Property::Xfg, Status::Partial, evidence)
        }
        None => {
            evidence.push(field_absent(load_config, "GuardXFGCheckFunctionPointer"));
            check(Property::Xfg, Status::Partial, evidence)
        }
    }
}

fn pe_cet(extended: &ExtendedCharacteristics) -> Check {
    match extended {
        ExtendedCharacteristics::Present(value) => {
            let set: bool = value & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT != 0;
            check(
                Property::CetShadowStack,
                if set { Status::Present } else { Status::Absent },
                vec![cite(
                    "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
                    format!(
                        "{value:#x} (CET_COMPAT {})",
                        if set { "set" } else { "clear" }
                    ),
                )],
            )
        }
        ExtendedCharacteristics::Missing => check(
            Property::CetShadowStack,
            Status::Absent,
            vec![cite(
                "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
                "no such debug directory entry",
            )],
        ),
        ExtendedCharacteristics::Unreadable(error) => check(
            Property::CetShadowStack,
            Status::Undetermined,
            vec![cite("IMAGE_DIRECTORY_ENTRY_DEBUG", error.clone())],
        ),
    }
}

fn pe_authenticode<Pe: ImageNtHeaders>(file: &PeFile<'_, Pe>, data: &[u8]) -> Check {
    let Some(directory): Option<&pe::ImageDataDirectory> = file
        .data_directories()
        .get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)
    else {
        return check(
            Property::Authenticode,
            Status::Absent,
            vec![cite("IMAGE_DIRECTORY_ENTRY_SECURITY", "missing")],
        );
    };
    let offset: u32 = directory.virtual_address.get(LE);
    let size: u32 = directory.size.get(LE);
    let location: Evidence = cite(
        "IMAGE_DIRECTORY_ENTRY_SECURITY",
        format!("file offset {offset:#x}, {size:#x} bytes"),
    );
    if size == 0 {
        return check(Property::Authenticode, Status::Absent, vec![location]);
    }
    let start: Option<usize> = usize::try_from(offset).ok();
    let in_file: bool = start
        .zip(usize::try_from(size).ok())
        .and_then(|(start, size): (usize, usize)| start.checked_add(size))
        .is_some_and(|end: usize| end <= data.len());
    let header: Option<(u32, u16, u16)> = start.and_then(|start: usize| {
        Some((
            read_u32_le_at(data, start).ok()?,
            read_u16_le_at(data, start.checked_add(4)?).ok()?,
            read_u16_le_at(data, start.checked_add(6)?).ok()?,
        ))
    });
    match header {
        Some((length, revision, kind)) if in_file && length >= 8 => {
            let kind_text: String = if kind == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
                format!("{kind:#x} (PKCS_SIGNED_DATA)")
            } else {
                format!("{kind:#x}")
            };
            check(
                Property::Authenticode,
                Status::Present,
                vec![
                    location,
                    cite("WIN_CERTIFICATE.wRevision", format!("{revision:#06x}")),
                    cite("WIN_CERTIFICATE.wCertificateType", kind_text),
                ],
            )
        }
        _ => check(
            Property::Authenticode,
            Status::Undetermined,
            vec![
                location,
                cite(
                    "WIN_CERTIFICATE",
                    "the certificate table is truncated or lies outside the file",
                ),
            ],
        ),
    }
}

fn pe_machine_label(machine: u16) -> String {
    match machine {
        pe::IMAGE_FILE_MACHINE_I386 => "i386".to_owned(),
        pe::IMAGE_FILE_MACHINE_AMD64 => "x86-64".to_owned(),
        pe::IMAGE_FILE_MACHINE_ARM64 => "aarch64".to_owned(),
        pe::IMAGE_FILE_MACHINE_ARM64EC => "arm64ec".to_owned(),
        pe::IMAGE_FILE_MACHINE_ARMNT
        | pe::IMAGE_FILE_MACHINE_ARM
        | pe::IMAGE_FILE_MACHINE_THUMB => "arm".to_owned(),
        other => format!("machine {other:#06x}"),
    }
}

#[derive(Debug, Default)]
struct MachoFacts {
    code_signature: Option<(u32, u32)>,
    encryption: Option<(&'static str, u32, u32, u32)>,
    restrict: Option<bool>,
    imports: Option<Result<BTreeSet<String>, String>>,
}

fn fat_images<Fat: FatArch>(data: &[u8]) -> Result<Vec<ImageHardening>, HardeningError> {
    let fat: MachOFatFile<'_, Fat> = MachOFatFile::parse(data)
        .map_err(|error: object::Error| malformed(ImageFormat::MachO, error))?;
    let arches: &[Fat] = fat.arches();
    if arches.len() > MAX_FAT_SLICES {
        return Err(HardeningError::TooManySlices {
            count: arches.len(),
            limit: MAX_FAT_SLICES,
        });
    }
    let mut images: Vec<ImageHardening> = Vec::new();
    for arch in arches {
        let offset: u64 = arch.offset().into();
        let slice: &[u8] = arch.data(data).map_err(|error: object::Error| {
            malformed(ImageFormat::MachO, format!("slice at {offset:#x}: {error}"))
        })?;
        let image: ImageHardening = match FileKind::parse(slice) {
            Ok(FileKind::MachO32) => {
                macho_image::<macho::MachHeader32<Endianness>>(slice, Some(offset))?
            }
            Ok(FileKind::MachO64) => {
                macho_image::<macho::MachHeader64<Endianness>>(slice, Some(offset))?
            }
            _ => {
                return Err(malformed(
                    ImageFormat::MachO,
                    format!("the slice at {offset:#x} is not a thin Mach-O image"),
                ));
            }
        };
        images.push(image);
    }
    Ok(images)
}

fn fixed_name(raw: &[u8]) -> &[u8] {
    let end: usize = raw
        .iter()
        .position(|&byte: &u8| byte == 0)
        .unwrap_or(raw.len());
    &raw[..end]
}

fn macho_image<Mach: MachHeader<Endian = Endianness>>(
    data: &[u8],
    slice_offset: Option<u64>,
) -> Result<ImageHardening, HardeningError> {
    let header: &Mach = Mach::parse(data, 0)
        .map_err(|error: object::Error| malformed(ImageFormat::MachO, error))?;
    let endian: Endianness = header
        .endian()
        .map_err(|error: object::Error| malformed(ImageFormat::MachO, error))?;
    let filetype: u32 = header.filetype(endian);
    let kind: ImageKind = match filetype {
        macho::MH_EXECUTE | macho::MH_DYLINKER => ImageKind::Executable,
        macho::MH_DYLIB | macho::MH_BUNDLE | macho::MH_KEXT_BUNDLE => ImageKind::SharedLibrary,
        macho::MH_OBJECT => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::MachO,
                kind: "an MH_OBJECT relocatable object",
            });
        }
        macho::MH_DSYM => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::MachO,
                kind: "an MH_DSYM debug-symbol companion",
            });
        }
        macho::MH_CORE => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::MachO,
                kind: "an MH_CORE core dump",
            });
        }
        _ => {
            return Err(HardeningError::NotLinkedImage {
                format: ImageFormat::MachO,
                kind: "an image of unsupported filetype",
            });
        }
    };
    let flags: u32 = header.flags(endian);
    let declared: u32 = header.ncmds(endian);
    if usize::try_from(declared).map_or(true, |count: usize| count > MAX_LOAD_COMMANDS) {
        return Err(malformed(
            ImageFormat::MachO,
            format!("ncmds {declared} exceeds {MAX_LOAD_COMMANDS} load commands"),
        ));
    }
    let mut commands: LoadCommandIterator<'_, Endianness> =
        header
            .load_commands(endian, data, 0)
            .map_err(|error: object::Error| malformed(ImageFormat::MachO, error))?;
    let mut facts: MachoFacts = MachoFacts::default();
    while let Some(command) = commands
        .next()
        .map_err(|error: object::Error| malformed(ImageFormat::MachO, error))?
    {
        let variant: LoadCommandVariant<'_, Endianness> = command
            .variant()
            .map_err(|error: object::Error| malformed(ImageFormat::MachO, error))?;
        match variant {
            LoadCommandVariant::LinkeditData(linkedit)
                if command.cmd() == macho::LC_CODE_SIGNATURE =>
            {
                facts.code_signature.get_or_insert_with(|| {
                    (linkedit.dataoff.get(endian), linkedit.datasize.get(endian))
                });
            }
            LoadCommandVariant::EncryptionInfo32(info) => {
                facts.encryption.get_or_insert_with(|| {
                    (
                        "LC_ENCRYPTION_INFO",
                        info.cryptid.get(endian),
                        info.cryptoff.get(endian),
                        info.cryptsize.get(endian),
                    )
                });
            }
            LoadCommandVariant::EncryptionInfo64(info) => {
                facts.encryption.get_or_insert_with(|| {
                    (
                        "LC_ENCRYPTION_INFO_64",
                        info.cryptid.get(endian),
                        info.cryptoff.get(endian),
                        info.cryptsize.get(endian),
                    )
                });
            }
            LoadCommandVariant::Segment32(segment, section_data) => {
                if fixed_name(&segment.segname) == b"__RESTRICT" {
                    let has_section: bool = segment.sections(endian, section_data).is_ok_and(
                        |sections: &[macho::Section32<Endianness>]| {
                            sections
                                .iter()
                                .any(|section: &macho::Section32<Endianness>| {
                                    fixed_name(section.name()) == b"__restrict"
                                })
                        },
                    );
                    facts.restrict = Some(facts.restrict.unwrap_or(false) || has_section);
                }
            }
            LoadCommandVariant::Segment64(segment, section_data) => {
                if fixed_name(&segment.segname) == b"__RESTRICT" {
                    let has_section: bool = segment.sections(endian, section_data).is_ok_and(
                        |sections: &[macho::Section64<Endianness>]| {
                            sections
                                .iter()
                                .any(|section: &macho::Section64<Endianness>| {
                                    fixed_name(section.name()) == b"__restrict"
                                })
                        },
                    );
                    facts.restrict = Some(facts.restrict.unwrap_or(false) || has_section);
                }
            }
            LoadCommandVariant::Symtab(symtab) if facts.imports.is_none() => {
                facts.imports = Some(
                    symtab
                        .symbols::<Mach, &[u8]>(endian, data)
                        .map_err(|error: object::Error| error.to_string())
                        .map(|table: object::read::macho::SymbolTable<'_, Mach>| {
                            table
                                .iter()
                                .filter(|symbol: &&Mach::Nlist| {
                                    symbol.is_undefined() && symbol.n_type() & macho::N_EXT != 0
                                })
                                .filter_map(|symbol: &Mach::Nlist| {
                                    symbol.name(endian, table.strings()).ok()
                                })
                                .map(bounded_text)
                                .collect()
                        }),
                );
            }
            _ => {}
        }
    }

    let mut checks: Vec<Check> = Vec::new();
    checks.push(if filetype == macho::MH_EXECUTE {
        macho_flag(Property::Pie, flags, macho::MH_PIE, "MH_PIE", true)
    } else {
        check(
            Property::Pie,
            Status::NotApplicable,
            vec![cite(
                "mach_header.filetype",
                format!(
                    "{filetype:#x}: only MH_EXECUTE images carry MH_PIE; libraries always slide"
                ),
            )],
        )
    });
    checks.push(macho_flag(
        Property::NxHeap,
        flags,
        macho::MH_NO_HEAP_EXECUTION,
        "MH_NO_HEAP_EXECUTION",
        true,
    ));
    checks.push(macho_flag(
        Property::NxStack,
        flags,
        macho::MH_ALLOW_STACK_EXECUTION,
        "MH_ALLOW_STACK_EXECUTION",
        false,
    ));
    checks.push(macho_canary(facts.imports.as_ref()));
    checks.push(macho_arc(facts.imports.as_ref()));
    let (signature, runtime): (Check, Check) = macho_signature(facts.code_signature, data);
    checks.push(signature);
    checks.push(runtime);
    checks.push(match facts.encryption {
        Some((command, cryptid, cryptoff, cryptsize)) => check(
            Property::Encrypted,
            if cryptid != 0 {
                Status::Present
            } else {
                Status::Absent
            },
            vec![cite(
                &format!("{command}.cryptid"),
                format!("{cryptid} (cryptoff {cryptoff:#x}, cryptsize {cryptsize:#x})"),
            )],
        ),
        None => check(
            Property::Encrypted,
            Status::Absent,
            vec![cite("LC_ENCRYPTION_INFO", "missing")],
        ),
    });
    checks.push(match facts.restrict {
        Some(true) => check(
            Property::Restrict,
            Status::Present,
            vec![cite("LC_SEGMENT", "__RESTRICT,__restrict")],
        ),
        Some(false) => check(
            Property::Restrict,
            Status::Absent,
            vec![cite(
                "LC_SEGMENT",
                "__RESTRICT without a __restrict section, which dyld ignores",
            )],
        ),
        None => check(
            Property::Restrict,
            Status::Absent,
            vec![cite("LC_SEGMENT", "no __RESTRICT segment")],
        ),
    });

    let cputype: u32 = header.cputype(endian);
    let cpusubtype: u32 = header.cpusubtype(endian);
    Ok(ImageHardening {
        format: ImageFormat::MachO,
        machine: macho_machine_label(cputype, cpusubtype),
        bits: if header.is_type_64() { 64 } else { 32 },
        kind,
        slice_offset,
        checks,
        fortify: None,
    })
}

fn macho_flag(
    property: Property,
    flags: u32,
    flag: u32,
    name: &str,
    set_is_present: bool,
) -> Check {
    let set: bool = flags & flag != 0;
    let present: bool = set == set_is_present;
    check(
        property,
        if present {
            Status::Present
        } else {
            Status::Absent
        },
        vec![cite(
            "mach_header.flags",
            format!("{flags:#x} ({name} {})", if set { "set" } else { "clear" }),
        )],
    )
}

fn macho_imports(
    property: Property,
    imports: Option<&Result<BTreeSet<String>, String>>,
) -> Result<&BTreeSet<String>, Check> {
    match imports {
        Some(Ok(names)) => Ok(names),
        Some(Err(error)) => Err(check(
            property,
            Status::Undetermined,
            vec![cite("LC_SYMTAB", error.clone())],
        )),
        None => Err(check(
            property,
            Status::Undetermined,
            vec![cite(
                "LC_SYMTAB",
                "missing, so the imports cannot be listed",
            )],
        )),
    }
}

fn macho_canary(imports: Option<&Result<BTreeSet<String>, String>>) -> Check {
    let names: &BTreeSet<String> = match macho_imports(Property::StackCanary, imports) {
        Ok(names) => names,
        Err(undetermined) => return undetermined,
    };
    let found: BTreeSet<String> = names
        .iter()
        .filter(|name: &&String| MACHO_CANARY_IMPORTS.contains(&name.as_str()))
        .cloned()
        .collect();
    if found.is_empty() {
        check(
            Property::StackCanary,
            Status::Absent,
            vec![cite(
                "imports",
                format!(
                    "{} undefined external symbols, none of {}",
                    names.len(),
                    MACHO_CANARY_IMPORTS.join(", ")
                ),
            )],
        )
    } else {
        check(
            Property::StackCanary,
            Status::Present,
            vec![cite("imports", cited_names(&found))],
        )
    }
}

fn macho_arc(imports: Option<&Result<BTreeSet<String>, String>>) -> Check {
    let names: &BTreeSet<String> = match macho_imports(Property::Arc, imports) {
        Ok(names) => names,
        Err(undetermined) => return undetermined,
    };
    let runtime: usize = names
        .iter()
        .filter(|name: &&String| name.starts_with(MACHO_OBJC_PREFIX))
        .count();
    if runtime == 0 {
        return check(
            Property::Arc,
            Status::NotApplicable,
            vec![cite("imports", "no Objective-C runtime entry point")],
        );
    }
    let found: BTreeSet<String> = names
        .iter()
        .filter(|name: &&String| MACHO_ARC_IMPORTS.contains(&name.as_str()))
        .cloned()
        .collect();
    if found.is_empty() {
        check(
            Property::Arc,
            Status::Absent,
            vec![cite(
                "imports",
                format!(
                    "Objective-C runtime entry points imported: {runtime}; ARC-only entry points: none"
                ),
            )],
        )
    } else {
        check(
            Property::Arc,
            Status::Present,
            vec![cite("imports", cited_names(&found))],
        )
    }
}

fn code_directory_flags(data: &[u8], dataoff: u32, datasize: u32) -> Result<u32, String> {
    let start: usize = usize::try_from(dataoff)
        .map_err(|_: std::num::TryFromIntError| "dataoff exceeds the address space".to_owned())?;
    let length: usize = usize::try_from(datasize)
        .map_err(|_: std::num::TryFromIntError| "datasize exceeds the address space".to_owned())?;
    let blob: &[u8] = start
        .checked_add(length)
        .and_then(|end: usize| data.get(start..end))
        .ok_or_else(|| {
            format!("the signature at {dataoff:#x}+{datasize:#x} lies outside the file")
        })?;
    let magic: u32 = read_u32_be_at(blob, 0).map_err(|error: ByteReadError| error.to_string())?;
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(format!(
            "SuperBlob magic {magic:#x} is not CSMAGIC_EMBEDDED_SIGNATURE"
        ));
    }
    let declared: u32 =
        read_u32_be_at(blob, 8).map_err(|error: ByteReadError| error.to_string())?;
    let count: usize = usize::try_from(declared)
        .ok()
        .filter(|count: &usize| *count <= MAX_BLOB_INDICES)
        .ok_or_else(|| {
            format!("the SuperBlob declares {declared} blobs, more than {MAX_BLOB_INDICES}")
        })?;
    let mut alternate: Option<u32> = None;
    for index in 0..count {
        let entry: usize = 12 + index * 8;
        let (Ok(slot), Ok(offset)): (Result<u32, ByteReadError>, Result<u32, ByteReadError>) =
            (read_u32_be_at(blob, entry), read_u32_be_at(blob, entry + 4))
        else {
            break;
        };
        let primary: bool = slot == CSSLOT_CODEDIRECTORY;
        if !primary
            && !(CSSLOT_ALTERNATE_CODEDIRECTORIES..CSSLOT_ALTERNATE_CODEDIRECTORY_END)
                .contains(&slot)
        {
            continue;
        }
        let Ok(offset): Result<usize, std::num::TryFromIntError> = usize::try_from(offset) else {
            continue;
        };
        let Some(directory): Option<&[u8]> = blob.get(offset..) else {
            continue;
        };
        if read_u32_be_at(directory, 0).ok() != Some(CSMAGIC_CODEDIRECTORY) {
            continue;
        }
        let Ok(flags): Result<u32, ByteReadError> = read_u32_be_at(directory, 12) else {
            continue;
        };
        if primary {
            return Ok(flags);
        }
        alternate.get_or_insert(flags);
    }
    alternate.ok_or_else(|| "the SuperBlob holds no readable CodeDirectory".to_owned())
}

fn code_signature_flags_text(flags: u32) -> String {
    let mut names: Vec<&str> = Vec::new();
    if flags & CS_ADHOC != 0 {
        names.push("adhoc");
    }
    if flags & CS_RUNTIME != 0 {
        names.push("runtime");
    }
    if flags & CS_LINKER_SIGNED != 0 {
        names.push("linker-signed");
    }
    if names.is_empty() {
        format!("{flags:#x}")
    } else {
        format!("{flags:#x} ({})", names.join(", "))
    }
}

fn macho_signature(code_signature: Option<(u32, u32)>, data: &[u8]) -> (Check, Check) {
    let Some((dataoff, datasize)): Option<(u32, u32)> = code_signature else {
        return (
            check(
                Property::CodeSignature,
                Status::Absent,
                vec![cite("LC_CODE_SIGNATURE", "missing")],
            ),
            check(
                Property::HardenedRuntime,
                Status::Absent,
                vec![cite(
                    "LC_CODE_SIGNATURE",
                    "missing, so no CodeDirectory can request the hardened runtime",
                )],
            ),
        );
    };
    let location: Evidence = cite(
        "LC_CODE_SIGNATURE",
        format!("dataoff {dataoff:#x}, datasize {datasize:#x}"),
    );
    let signature: Check = check(Property::CodeSignature, Status::Present, vec![location]);
    let runtime: Check = match code_directory_flags(data, dataoff, datasize) {
        Ok(flags) => check(
            Property::HardenedRuntime,
            if flags & CS_RUNTIME != 0 {
                Status::Present
            } else {
                Status::Absent
            },
            vec![cite(
                "CodeDirectory.flags",
                code_signature_flags_text(flags),
            )],
        ),
        Err(error) => check(
            Property::HardenedRuntime,
            Status::Undetermined,
            vec![cite("CodeDirectory", error)],
        ),
    };
    (signature, runtime)
}

fn macho_machine_label(cputype: u32, cpusubtype: u32) -> String {
    match cputype {
        macho::CPU_TYPE_X86 => "i386".to_owned(),
        macho::CPU_TYPE_X86_64 => "x86-64".to_owned(),
        macho::CPU_TYPE_ARM64
            if cpusubtype & !macho::CPU_SUBTYPE_MASK == macho::CPU_SUBTYPE_ARM64E =>
        {
            "arm64e".to_owned()
        }
        macho::CPU_TYPE_ARM64 => "aarch64".to_owned(),
        macho::CPU_TYPE_ARM64_32 => "arm64_32".to_owned(),
        macho::CPU_TYPE_ARM => "arm".to_owned(),
        macho::CPU_TYPE_POWERPC => "powerpc".to_owned(),
        macho::CPU_TYPE_POWERPC64 => "powerpc64".to_owned(),
        other => format!("cputype {other:#x}"),
    }
}
