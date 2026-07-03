use object::Endianness as ObjEndianness;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSegment as _;
use object::ObjectSymbol as _;
use object::read::{
    Architecture as ObjArchitecture, File as ObjFile, FileKind, SymbolKind as ObjSymbolKind,
};
use serde::{Deserialize, Serialize};

use crate::elf_dynamic::{ElfDynamic, parse_elf_dynamic};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeFormat {
    Pe32,
    Pe64,
    Elf32,
    Elf64,
    MachO32,
    MachO64,
    MachOFat,
    Coff,
    Wasm,
}

impl NativeFormat {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pe32 => "pe32",
            Self::Pe64 => "pe64",
            Self::Elf32 => "elf32",
            Self::Elf64 => "elf64",
            Self::MachO32 => "macho32",
            Self::MachO64 => "macho64",
            Self::MachOFat => "macho-fat",
            Self::Coff => "coff",
            Self::Wasm => "wasm",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    RiscV32,
    RiscV64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    Sparc,
    Sparc64,
    Avr,
    Ebpf,
    LoongArch64,
    S390x,
    Wasm32,
    Wasm64,
    Unknown(u16),
}

impl Arch {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Aarch64 => "aarch64",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::PowerPc => "powerpc",
            Self::PowerPc64 => "powerpc64",
            Self::Sparc => "sparc",
            Self::Sparc64 => "sparc64",
            Self::Avr => "avr",
            Self::Ebpf => "ebpf",
            Self::LoongArch64 => "loongarch64",
            Self::S390x => "s390x",
            Self::Wasm32 => "wasm32",
            Self::Wasm64 => "wasm64",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub name: Option<String>,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolRole {
    Text,
    Data,
    Section,
    File,
    Label,
    Tls,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportInfo {
    pub library: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeFile {
    pub format: NativeFormat,
    pub arch: Arch,
    pub bits: u32,
    pub endian: Endian,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub debug_info_present: bool,
    pub segments: Vec<SegmentInfo>,
    pub dynamic: Option<ElfDynamic>,
}

const PE32_MIN: usize = 64;
const ELF_MIN: usize = 52;
const MACHO_MIN: usize = 28;
const MACHO_FAT_MIN: usize = 8;

#[allow(clippy::too_many_lines)]
pub fn parse_native(bytes: &[u8]) -> Result<NativeFile> {
    if bytes.len() < MACHO_FAT_MIN {
        return Err(Error::NativeParse(
            "input too small for any native format".to_owned(),
        ));
    }
    let kind: FileKind = FileKind::parse(bytes).map_err(|e| Error::NativeParse(e.to_string()))?;
    let format: NativeFormat = match kind {
        FileKind::Pe32 => {
            if bytes.len() < PE32_MIN {
                return Err(Error::NativeParse("pe32 image too short".to_owned()));
            }
            NativeFormat::Pe32
        }
        FileKind::Pe64 => {
            if bytes.len() < PE32_MIN {
                return Err(Error::NativeParse("pe64 image too short".to_owned()));
            }
            NativeFormat::Pe64
        }
        FileKind::Elf32 => {
            if bytes.len() < ELF_MIN {
                return Err(Error::NativeParse("elf32 image too short".to_owned()));
            }
            NativeFormat::Elf32
        }
        FileKind::Elf64 => {
            if bytes.len() < ELF_MIN {
                return Err(Error::NativeParse("elf64 image too short".to_owned()));
            }
            NativeFormat::Elf64
        }
        FileKind::MachO32 => {
            if bytes.len() < MACHO_MIN {
                return Err(Error::NativeParse("mach-o 32 too short".to_owned()));
            }
            NativeFormat::MachO32
        }
        FileKind::MachO64 => {
            if bytes.len() < MACHO_MIN {
                return Err(Error::NativeParse("mach-o 64 too short".to_owned()));
            }
            NativeFormat::MachO64
        }
        FileKind::MachOFat32 | FileKind::MachOFat64 => NativeFormat::MachOFat,
        FileKind::Coff | FileKind::CoffBig => NativeFormat::Coff,
        other => {
            return Err(Error::NativeParse(format!(
                "unsupported file kind for native parse: {other:?}"
            )));
        }
    };

    if matches!(format, NativeFormat::MachOFat) {
        return Ok(NativeFile {
            format,
            arch: Arch::Unknown(0),
            bits: 0,
            endian: Endian::Little,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            debug_info_present: false,
            segments: Vec::new(),
            dynamic: None,
        });
    }

    let file: ObjFile<'_, &[u8]> =
        ObjFile::parse(bytes).map_err(|e| Error::NativeParse(e.to_string()))?;
    let arch: Arch = map_arch(file.architecture());
    let bits: u32 = if file.is_64() { 64 } else { 32 };
    let endian: Endian = match file.endianness() {
        ObjEndianness::Little => Endian::Little,
        ObjEndianness::Big => Endian::Big,
    };

    let mut sections: Vec<SectionInfo> = Vec::new();
    for sec in file.sections() {
        let name: String = sec.name().map_or("", |value: &str| value).to_owned();
        sections.push(SectionInfo {
            name,
            address: sec.address(),
            size: sec.size(),
        });
    }

    if matches!(format, NativeFormat::Elf32 | NativeFormat::Elf64) && sections.is_empty() {
        return Err(Error::NativeParse(
            "elf has no parseable sections (header table missing)".to_owned(),
        ));
    }

    let mut segments: Vec<SegmentInfo> = Vec::new();
    for seg in file.segments() {
        let raw: Option<&[u8]> = seg.name_bytes().ok().flatten();
        let name: Option<String> = raw.map(|b: &[u8]| String::from_utf8_lossy(b).into_owned());
        segments.push(SegmentInfo {
            name,
            address: seg.address(),
            size: seg.size(),
        });
    }

    let mut symbols: Vec<SymbolInfo> = Vec::new();
    for sym in file.symbols() {
        let name_str: String = sym.name().map_or("", |value: &str| value).to_owned();
        if name_str.is_empty() {
            continue;
        }
        symbols.push(SymbolInfo {
            name: name_str,
            address: sym.address(),
            size: sym.size(),
            kind: map_symbol(sym.kind()),
        });
    }

    let imports: Vec<ImportInfo> = file
        .imports()
        .map_err(|e| Error::NativeParse(e.to_string()))?
        .into_iter()
        .map(|i| ImportInfo {
            library: String::from_utf8_lossy(i.library()).into_owned(),
            name: String::from_utf8_lossy(i.name()).into_owned(),
        })
        .collect();

    let exports: Vec<ExportInfo> = file
        .exports()
        .map_err(|e| Error::NativeParse(e.to_string()))?
        .into_iter()
        .map(|e: object::read::Export<'_>| ExportInfo {
            name: String::from_utf8_lossy(e.name()).into_owned(),
            address: e.address(),
        })
        .collect();

    let debug_info_present: bool = file.has_debug_symbols();

    let dynamic: Option<ElfDynamic> = if matches!(format, NativeFormat::Elf32 | NativeFormat::Elf64)
    {
        parse_elf_dynamic(bytes)
    } else {
        None
    };

    Ok(NativeFile {
        format,
        arch,
        bits,
        endian,
        sections,
        symbols,
        imports,
        exports,
        debug_info_present,
        segments,
        dynamic,
    })
}

const fn map_arch(a: ObjArchitecture) -> Arch {
    match a {
        ObjArchitecture::I386 => Arch::X86,
        ObjArchitecture::X86_64 | ObjArchitecture::X86_64_X32 => Arch::X86_64,
        ObjArchitecture::Arm => Arch::Arm,
        ObjArchitecture::Aarch64 | ObjArchitecture::Aarch64_Ilp32 => Arch::Aarch64,
        ObjArchitecture::Riscv32 => Arch::RiscV32,
        ObjArchitecture::Riscv64 => Arch::RiscV64,
        ObjArchitecture::Mips => Arch::Mips,
        ObjArchitecture::Mips64 | ObjArchitecture::Mips64_N32 => Arch::Mips64,
        ObjArchitecture::PowerPc => Arch::PowerPc,
        ObjArchitecture::PowerPc64 => Arch::PowerPc64,
        ObjArchitecture::Sparc | ObjArchitecture::Sparc32Plus => Arch::Sparc,
        ObjArchitecture::Sparc64 => Arch::Sparc64,
        ObjArchitecture::Avr => Arch::Avr,
        ObjArchitecture::Bpf | ObjArchitecture::Sbf => Arch::Ebpf,
        ObjArchitecture::LoongArch64 => Arch::LoongArch64,
        ObjArchitecture::S390x => Arch::S390x,
        ObjArchitecture::Wasm32 => Arch::Wasm32,
        ObjArchitecture::Wasm64 => Arch::Wasm64,
        _ => Arch::Unknown(0),
    }
}

const fn map_symbol(k: ObjSymbolKind) -> SymbolRole {
    match k {
        ObjSymbolKind::Text => SymbolRole::Text,
        ObjSymbolKind::Data => SymbolRole::Data,
        ObjSymbolKind::Section => SymbolRole::Section,
        ObjSymbolKind::File => SymbolRole::File,
        ObjSymbolKind::Label => SymbolRole::Label,
        ObjSymbolKind::Tls => SymbolRole::Tls,
        _ => SymbolRole::Unknown,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use object::write::{
        Object as WriteObject, StandardSection, Symbol as WriteSymbol,
        SymbolFlags as WriteSymbolFlags, SymbolKind as WriteSymbolKind, SymbolScope,
    };
    use object::{Architecture, BinaryFormat, Endianness};

    use super::*;

    fn build_elf(arch: Architecture, bit64: bool) -> Vec<u8> {
        let mut obj: WriteObject<'_> =
            WriteObject::new(BinaryFormat::Elf, arch, Endianness::Little);
        let text_id: object::write::SectionId = obj.section_id(StandardSection::Text);
        let _ = obj.append_section_data(text_id, &[0x90u8; 32], 16);
        let sym: WriteSymbol = WriteSymbol {
            name: b"start".to_vec(),
            value: 0,
            size: 16,
            kind: WriteSymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(text_id),
            flags: WriteSymbolFlags::None,
        };
        let _ = obj.add_symbol(sym);
        let _ = bit64;
        obj.write().expect("elf write")
    }

    fn build_macho(arch: Architecture, bit64: bool) -> Vec<u8> {
        let mut obj: WriteObject<'_> =
            WriteObject::new(BinaryFormat::MachO, arch, Endianness::Little);
        let text_id: object::write::SectionId = obj.section_id(StandardSection::Text);
        let _ = obj.append_section_data(text_id, &[0x90u8; 32], 16);
        let _ = bit64;
        obj.write().expect("macho write")
    }

    fn build_coff(arch: Architecture) -> Vec<u8> {
        let mut obj: WriteObject<'_> =
            WriteObject::new(BinaryFormat::Coff, arch, Endianness::Little);
        let text_id: object::write::SectionId = obj.section_id(StandardSection::Text);
        let _ = obj.append_section_data(text_id, &[0x90u8; 32], 16);
        obj.write().expect("coff write")
    }

    #[test]
    fn parse_elf32_x86() {
        let bytes: Vec<u8> = build_elf(Architecture::I386, false);
        let nf: NativeFile = parse_native(&bytes).expect("parse elf32");
        assert_eq!(nf.format, NativeFormat::Elf32);
        assert_eq!(nf.arch, Arch::X86);
        assert_eq!(nf.bits, 32);
        assert_eq!(nf.endian, Endian::Little);
        assert!(!nf.sections.is_empty());
    }

    #[test]
    fn parse_elf64_x86_64() {
        let bytes: Vec<u8> = build_elf(Architecture::X86_64, true);
        let nf: NativeFile = parse_native(&bytes).expect("parse elf64");
        assert_eq!(nf.format, NativeFormat::Elf64);
        assert_eq!(nf.arch, Arch::X86_64);
        assert_eq!(nf.bits, 64);
    }

    #[test]
    fn parse_elf64_aarch64() {
        let bytes: Vec<u8> = build_elf(Architecture::Aarch64, true);
        let nf: NativeFile = parse_native(&bytes).expect("parse elf64 arm64");
        assert_eq!(nf.format, NativeFormat::Elf64);
        assert_eq!(nf.arch, Arch::Aarch64);
    }

    #[test]
    fn parse_elf64_riscv64() {
        let bytes: Vec<u8> = build_elf(Architecture::Riscv64, true);
        let nf: NativeFile = parse_native(&bytes).expect("parse elf64 riscv64");
        assert_eq!(nf.format, NativeFormat::Elf64);
        assert_eq!(nf.arch, Arch::RiscV64);
    }

    #[test]
    fn parse_elf32_arm() {
        let bytes: Vec<u8> = build_elf(Architecture::Arm, false);
        let nf: NativeFile = parse_native(&bytes).expect("parse elf32 arm");
        assert_eq!(nf.format, NativeFormat::Elf32);
        assert_eq!(nf.arch, Arch::Arm);
    }

    #[test]
    fn parse_macho32_i386() {
        let bytes: Vec<u8> = build_macho(Architecture::I386, false);
        let nf: NativeFile = parse_native(&bytes).expect("parse macho32");
        assert_eq!(nf.format, NativeFormat::MachO32);
        assert_eq!(nf.arch, Arch::X86);
        assert_eq!(nf.bits, 32);
    }

    #[test]
    fn parse_macho64_x86_64() {
        let bytes: Vec<u8> = build_macho(Architecture::X86_64, true);
        let nf: NativeFile = parse_native(&bytes).expect("parse macho64");
        assert_eq!(nf.format, NativeFormat::MachO64);
        assert_eq!(nf.arch, Arch::X86_64);
        assert_eq!(nf.bits, 64);
    }

    #[test]
    fn parse_macho_fat_does_not_decode_inner_archs() {
        let mut bytes: Vec<u8> = Vec::with_capacity(32);
        bytes.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 24]);
        let nf: NativeFile = parse_native(&bytes).expect("parse macho fat");
        assert_eq!(nf.format, NativeFormat::MachOFat);
        assert_eq!(nf.bits, 0);
    }

    #[test]
    fn parse_pe32_via_coff_synthetic() {
        let coff_bytes: Vec<u8> = build_coff(Architecture::I386);
        let nf: NativeFile = parse_native(&coff_bytes).expect("parse coff");
        assert_eq!(nf.format, NativeFormat::Coff);
        assert_eq!(nf.arch, Arch::X86);
    }

    #[test]
    fn parse_pe64_via_coff_synthetic() {
        let coff_bytes: Vec<u8> = build_coff(Architecture::X86_64);
        let nf: NativeFile = parse_native(&coff_bytes).expect("parse coff64");
        assert_eq!(nf.format, NativeFormat::Coff);
        assert_eq!(nf.arch, Arch::X86_64);
    }

    #[test]
    fn malformed_pe_is_rejected() {
        let mut bytes: Vec<u8> = b"MZ".to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 256));
        let err: Error = parse_native(&bytes).unwrap_err();
        assert!(matches!(err, Error::NativeParse(_)));
    }

    #[test]
    fn elf_missing_section_table_is_rejected() {
        let mut bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F'];
        bytes.extend(std::iter::repeat_n(0u8, 60));
        let err: Error = parse_native(&bytes).unwrap_err();
        assert!(matches!(err, Error::NativeParse(_)));
    }

    #[test]
    fn too_small_input_is_rejected() {
        let err: Error = parse_native(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, Error::NativeParse(_)));
    }
}
