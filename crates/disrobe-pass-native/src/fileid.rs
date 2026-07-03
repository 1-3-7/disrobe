use std::collections::BTreeMap;

use object::Object as _;
use object::ObjectSection as _;
use object::read::File as ObjFile;
use serde::{Deserialize, Serialize};

use crate::format::{NativeFormat, detect as detect_format};
use crate::identify::{IdentityKind, SupportRoute, detect as detect_byte_identity};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

const RICH_TAG: &[u8; 4] = b"Rich";
const DANS_TAG: u32 = 0x536E_6144;
const HEADER_SCAN: usize = 4096;
const CLR_DATA_DIRECTORY_INDEX: usize = 14;
const OVERLAY_SCAN_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub locus: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    SectionName,
    DataDirectory,
    RichHeader,
    EntryStub,
    Import,
    Overlay,
    Magic,
    ByteSignature,
    Entropy,
    SymbolName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: IdentityKind,
    pub family: String,
    pub name: String,
    pub version: Option<String>,
    pub confidence: u8,
    pub support: SupportRoute,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdReport {
    pub format: String,
    pub bits: u8,
    pub subsystem: Option<String>,
    pub findings: Vec<Finding>,
}

impl FileIdReport {
    #[must_use]
    pub fn has_family(&self, family: &str) -> bool {
        self.findings.iter().any(|f: &Finding| f.family == family)
    }

    pub fn of_kind(&self, kind: IdentityKind) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(move |f: &&Finding| f.kind == kind)
    }
}

struct Builder {
    findings: BTreeMap<(IdentityKind, &'static str), Finding>,
}

impl Builder {
    fn new() -> Self {
        Self {
            findings: BTreeMap::new(),
        }
    }

    fn record(
        &mut self,
        kind: IdentityKind,
        family: &'static str,
        name: &'static str,
        version: Option<String>,
        confidence: u8,
        support: SupportRoute,
        evidence: Evidence,
    ) {
        let slot: &mut Finding = self
            .findings
            .entry((kind, family))
            .or_insert_with(|| Finding {
                kind,
                family: family.to_owned(),
                name: name.to_owned(),
                version: None,
                confidence: 0,
                support,
                evidence: Vec::new(),
            });
        if confidence > slot.confidence {
            slot.confidence = confidence;
            name.clone_into(&mut slot.name);
            slot.support = support;
        }
        if version.is_some() && slot.version.is_none() {
            slot.version = version;
        }
        if !slot.evidence.contains(&evidence) {
            slot.evidence.push(evidence);
        }
    }

    fn finish(self) -> Vec<Finding> {
        let mut out: Vec<Finding> = self.findings.into_values().collect();
        out.sort_by(|a: &Finding, b: &Finding| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.family.cmp(&b.family))
        });
        out
    }
}

struct SectionSig {
    name: &'static [u8],
    kind: IdentityKind,
    family: &'static str,
    display: &'static str,
    confidence: u8,
    support: SupportRoute,
}

const PE_SECTION_SIGNATURES: &[SectionSig] = &[
    SectionSig {
        name: b"UPX0",
        kind: IdentityKind::Packer,
        family: "upx",
        display: "UPX",
        confidence: 96,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b"UPX1",
        kind: IdentityKind::Packer,
        family: "upx",
        display: "UPX",
        confidence: 96,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b"UPX2",
        kind: IdentityKind::Packer,
        family: "upx",
        display: "UPX",
        confidence: 80,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".aspack",
        kind: IdentityKind::Packer,
        family: "aspack",
        display: "ASPack",
        confidence: 94,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".adata",
        kind: IdentityKind::Packer,
        family: "aspack",
        display: "ASPack",
        confidence: 72,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".MPRESS1",
        kind: IdentityKind::Packer,
        family: "mpress",
        display: "MPRESS",
        confidence: 94,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".MPRESS2",
        kind: IdentityKind::Packer,
        family: "mpress",
        display: "MPRESS",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".petite",
        kind: IdentityKind::Packer,
        family: "petite",
        display: "Petite",
        confidence: 94,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".nsp0",
        kind: IdentityKind::Packer,
        family: "nspack",
        display: "NSPack",
        confidence: 88,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".nsp1",
        kind: IdentityKind::Packer,
        family: "nspack",
        display: "NSPack",
        confidence: 82,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b"PEC2",
        kind: IdentityKind::Packer,
        family: "pecompact",
        display: "PECompact",
        confidence: 88,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".pec 1",
        kind: IdentityKind::Packer,
        family: "pecompact",
        display: "PECompact",
        confidence: 78,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b"MEW",
        kind: IdentityKind::Packer,
        family: "mew",
        display: "MEW",
        confidence: 84,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b"kkrunchy",
        kind: IdentityKind::Packer,
        family: "kkrunchy",
        display: "kkrunchy",
        confidence: 92,
        support: SupportRoute::NativeUnpack,
    },
    SectionSig {
        name: b".themida",
        kind: IdentityKind::Protector,
        family: "themida",
        display: "Themida/WinLicense",
        confidence: 95,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".winlice",
        kind: IdentityKind::Protector,
        family: "themida",
        display: "Themida/WinLicense",
        confidence: 92,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".vmp0",
        kind: IdentityKind::Protector,
        family: "vmprotect",
        display: "VMProtect",
        confidence: 95,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".vmp1",
        kind: IdentityKind::Protector,
        family: "vmprotect",
        display: "VMProtect",
        confidence: 92,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".vmp2",
        kind: IdentityKind::Protector,
        family: "vmprotect",
        display: "VMProtect",
        confidence: 88,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".enigma1",
        kind: IdentityKind::Protector,
        family: "enigma",
        display: "Enigma Protector",
        confidence: 90,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".enigma2",
        kind: IdentityKind::Protector,
        family: "enigma",
        display: "Enigma Protector",
        confidence: 88,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".boom",
        kind: IdentityKind::Protector,
        family: "themida",
        display: "Themida (BoxedApp/Boom)",
        confidence: 70,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".gentee",
        kind: IdentityKind::Installer,
        family: "gentee",
        display: "Gentee installer",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
    },
    SectionSig {
        name: b".rmnet",
        kind: IdentityKind::Protector,
        family: "armadillo",
        display: "Armadillo/SoftwarePassport",
        confidence: 70,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b".yP",
        kind: IdentityKind::Protector,
        family: "yodas-protector",
        display: "Yoda's Protector",
        confidence: 88,
        support: SupportRoute::DetectCarveOnly,
    },
    SectionSig {
        name: b"yC",
        kind: IdentityKind::Packer,
        family: "yodas-crypter",
        display: "Yoda's Crypter",
        confidence: 86,
        support: SupportRoute::NativeUnpack,
    },
];

const ELF_SECTION_SIGNATURES: &[SectionSig] = &[
    SectionSig {
        name: b".note.go.buildid",
        kind: IdentityKind::Compiler,
        family: "go",
        display: "Go",
        confidence: 95,
        support: SupportRoute::GoDecompile,
    },
    SectionSig {
        name: b".gopclntab",
        kind: IdentityKind::Compiler,
        family: "go",
        display: "Go",
        confidence: 92,
        support: SupportRoute::GoDecompile,
    },
    SectionSig {
        name: b".note.gnu.build-id",
        kind: IdentityKind::Library,
        family: "gnu-build-id",
        display: "GNU build-id",
        confidence: 55,
        support: SupportRoute::NativeDecompile,
    },
    SectionSig {
        name: b".comment",
        kind: IdentityKind::Compiler,
        family: "toolchain-comment",
        display: "toolchain .comment",
        confidence: 30,
        support: SupportRoute::NativeDecompile,
    },
];

const MACHO_SECTION_SIGNATURES: &[SectionSig] = &[
    SectionSig {
        name: b"__swift5_proto",
        kind: IdentityKind::Compiler,
        family: "swift",
        display: "Swift",
        confidence: 92,
        support: SupportRoute::NativeLangDemangle,
    },
    SectionSig {
        name: b"__swift5_types",
        kind: IdentityKind::Compiler,
        family: "swift",
        display: "Swift",
        confidence: 90,
        support: SupportRoute::NativeLangDemangle,
    },
    SectionSig {
        name: b"__objc_classlist",
        kind: IdentityKind::Library,
        family: "objc",
        display: "Objective-C",
        confidence: 86,
        support: SupportRoute::NativeLangDemangle,
    },
    SectionSig {
        name: b"__objc_classname",
        kind: IdentityKind::Library,
        family: "objc",
        display: "Objective-C",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
    },
    SectionSig {
        name: b"__gopclntab",
        kind: IdentityKind::Compiler,
        family: "go",
        display: "Go",
        confidence: 92,
        support: SupportRoute::GoDecompile,
    },
    SectionSig {
        name: b"__go_buildinfo",
        kind: IdentityKind::Compiler,
        family: "go",
        display: "Go",
        confidence: 90,
        support: SupportRoute::GoDecompile,
    },
];

struct RichProduct {
    min_id: u16,
    max_id: u16,
    name: &'static str,
}

const RICH_PRODUCTS: &[RichProduct] = &[
    RichProduct {
        min_id: 0x000A,
        max_id: 0x000F,
        name: "MSVC 6.0 / 7.x (Visual C++ 6-2003)",
    },
    RichProduct {
        min_id: 0x005F,
        max_id: 0x006D,
        name: "MSVC 7.0 (Visual Studio .NET 2002)",
    },
    RichProduct {
        min_id: 0x006E,
        max_id: 0x0083,
        name: "MSVC 8.0 (Visual Studio 2005)",
    },
    RichProduct {
        min_id: 0x0084,
        max_id: 0x009E,
        name: "MSVC 9.0 (Visual Studio 2008)",
    },
    RichProduct {
        min_id: 0x009F,
        max_id: 0x00AB,
        name: "MSVC 10.0 (Visual Studio 2010)",
    },
    RichProduct {
        min_id: 0x00AC,
        max_id: 0x00CB,
        name: "MSVC 11.0 (Visual Studio 2012)",
    },
    RichProduct {
        min_id: 0x00CC,
        max_id: 0x00FF,
        name: "MSVC 12.0 (Visual Studio 2013)",
    },
    RichProduct {
        min_id: 0x0100,
        max_id: 0x0105,
        name: "MSVC 14.0 (Visual Studio 2015)",
    },
    RichProduct {
        min_id: 0x0106,
        max_id: 0x010F,
        name: "MSVC 14.1 (Visual Studio 2017)",
    },
    RichProduct {
        min_id: 0x0110,
        max_id: 0x0125,
        name: "MSVC 14.2 (Visual Studio 2019)",
    },
    RichProduct {
        min_id: 0x0126,
        max_id: 0x0150,
        name: "MSVC 14.3+ (Visual Studio 2022)",
    },
];

#[must_use]
pub fn identify(bytes: &[u8]) -> FileIdReport {
    let detected: crate::format::DetectedFormat =
        detect_format(bytes).unwrap_or_else(|_| crate::format::DetectedFormat {
            kind: NativeFormat::Unknown,
            bits: 0,
            subsystem: None,
            notes: Vec::new(),
        });
    let mut builder: Builder = Builder::new();

    match detected.kind {
        NativeFormat::Pe32 | NativeFormat::Pe64 | NativeFormat::EfiPe => {
            analyze_pe(bytes, &mut builder);
        }
        NativeFormat::Elf32 | NativeFormat::Elf64 | NativeFormat::KernelModule => {
            analyze_object(bytes, ELF_SECTION_SIGNATURES, &mut builder);
        }
        NativeFormat::MachO32 | NativeFormat::MachO64 => {
            analyze_object(bytes, MACHO_SECTION_SIGNATURES, &mut builder);
        }
        NativeFormat::MachOFat => {
            analyze_fat(bytes, &mut builder);
        }
        _ => {}
    }

    merge_byte_identity(bytes, &mut builder);
    merge_struct_findings(bytes, &mut builder);

    FileIdReport {
        format: detected.kind.label().to_owned(),
        bits: detected.bits,
        subsystem: detected.subsystem,
        findings: builder.finish(),
    }
}

fn merge_struct_findings(bytes: &[u8], builder: &mut Builder) {
    use crate::sig_engine::{StructClass, StructFinding, struct_findings};
    for finding in struct_findings(bytes) {
        let StructFinding {
            class,
            family,
            version,
            confidence,
            locus,
            detail,
            native_vm,
        } = finding;
        let kind: IdentityKind = match class {
            StructClass::Packer => IdentityKind::Packer,
            StructClass::Protector => IdentityKind::Protector,
            StructClass::Compiler => IdentityKind::Compiler,
            StructClass::Linker => IdentityKind::Linker,
            StructClass::Installer => IdentityKind::Installer,
        };
        let (family_key, display): (&'static str, &'static str) = struct_family_meta(family);
        let support: SupportRoute = struct_family_support(family, native_vm);
        let score: u8 = (confidence.as_score() * 100.0) as u8;
        builder.record(
            kind,
            family_key,
            display,
            version,
            score,
            support,
            Evidence {
                kind: EvidenceKind::EntryStub,
                locus,
                detail,
            },
        );
    }
}

fn struct_family_meta(family: crate::sig_engine::StructFamily) -> (&'static str, &'static str) {
    use crate::sig_engine::StructFamily;
    match family {
        StructFamily::Aspack => ("aspack", "ASPack"),
        StructFamily::Petite => ("petite", "Petite"),
        StructFamily::Mpress => ("mpress", "MPRESS"),
        StructFamily::Fsg => ("fsg", "FSG"),
        StructFamily::Nspack => ("nspack", "NSPack"),
        StructFamily::Pecompact => ("pecompact", "PECompact"),
        StructFamily::VmProtect => ("vmprotect", "VMProtect"),
        StructFamily::Themida => ("themida", "Themida/WinLicense"),
        StructFamily::Enigma => ("enigma", "Enigma Protector"),
        StructFamily::Armadillo => ("armadillo", "Armadillo"),
        StructFamily::Obsidium => ("obsidium", "Obsidium"),
        StructFamily::Msvc => ("msvc", "MSVC (Visual C++)"),
        StructFamily::Go => ("go", "Go"),
        StructFamily::DotNet => ("dotnet", ".NET / CLR"),
        StructFamily::Nsis => ("nsis", "NSIS"),
        StructFamily::InnoSetup => ("innosetup", "Inno Setup"),
        StructFamily::InstallShield => ("installshield", "InstallShield"),
        StructFamily::Wise => ("wise", "Wise Installer"),
        StructFamily::AutoIt => ("autoit", "AutoIt"),
        StructFamily::Inject2Pe => ("inject2pe", "inject2pe"),
        StructFamily::FatPack => ("fatpack", "FatPack"),
        StructFamily::PkrCe1a => ("pkr-ce1a", "pkr_ce1a"),
        StructFamily::DotNetBundle => ("dotnet-bundle", ".NET single-file bundle"),
    }
}

fn struct_family_support(family: crate::sig_engine::StructFamily, native_vm: bool) -> SupportRoute {
    use crate::sig_engine::StructFamily;
    if native_vm {
        return SupportRoute::DetectCarveOnly;
    }
    match family {
        StructFamily::Aspack
        | StructFamily::Petite
        | StructFamily::Mpress
        | StructFamily::Fsg
        | StructFamily::Nspack
        | StructFamily::Pecompact
        | StructFamily::Inject2Pe
        | StructFamily::FatPack
        | StructFamily::PkrCe1a => SupportRoute::NativeUnpack,
        StructFamily::VmProtect
        | StructFamily::Themida
        | StructFamily::Enigma
        | StructFamily::Armadillo
        | StructFamily::Obsidium => SupportRoute::DetectCarveOnly,
        StructFamily::Msvc => SupportRoute::NativeDecompile,
        StructFamily::Go => SupportRoute::GoDecompile,
        StructFamily::DotNet => SupportRoute::DotnetDecompile,
        StructFamily::Nsis
        | StructFamily::InnoSetup
        | StructFamily::InstallShield
        | StructFamily::Wise
        | StructFamily::AutoIt
        | StructFamily::DotNetBundle => SupportRoute::ContainerExtract,
    }
}

fn analyze_pe(bytes: &[u8], builder: &mut Builder) {
    let Ok(image): Result<PeImage, _> = parse_pe_image(bytes) else {
        return;
    };
    for section in &image.sections {
        let name: &[u8] = section.name_trimmed();
        for sig in PE_SECTION_SIGNATURES {
            if name == sig.name {
                builder.record(
                    sig.kind,
                    sig.family,
                    sig.display,
                    None,
                    sig.confidence,
                    sig.support,
                    Evidence {
                        kind: EvidenceKind::SectionName,
                        locus: format!("section {}", display_name(name)),
                        detail: format!("{} characteristic section", sig.display),
                    },
                );
            }
        }
    }

    detect_dotnet(&image, bytes, builder);
    detect_packed_entry(&image, builder);
    detect_high_entropy_sections(&image, bytes, builder);
    detect_rich(bytes, builder);
    detect_pe_imports(bytes, builder);
    detect_pe_installers(bytes, builder);
}

const ENTROPY_PACKED_THRESHOLD: f64 = 7.2;
const ENTROPY_MIN_SECTION_BYTES: usize = 512;

fn detect_high_entropy_sections(image: &PeImage, bytes: &[u8], builder: &mut Builder) {
    let mut flagged: u32 = 0;
    let mut peak: f64 = 0.0;
    let mut peak_name: String = String::new();
    for section in &image.sections {
        let Some((start, end)): Option<(usize, usize)> = section.raw_range(bytes.len()) else {
            continue;
        };
        let data: &[u8] = &bytes[start..end];
        if data.len() < ENTROPY_MIN_SECTION_BYTES {
            continue;
        }
        let executable: bool = section.characteristics & 0x2000_0000 != 0;
        let entropy: f64 = crate::entropy::shannon_entropy_bits(data);
        if entropy > peak {
            peak = entropy;
            peak_name = display_name(section.name_trimmed());
        }
        if entropy >= ENTROPY_PACKED_THRESHOLD && executable {
            flagged += 1;
        }
    }
    if flagged > 0 {
        builder.record(
            IdentityKind::Packer,
            "high-entropy-code",
            "compressed or encrypted code section",
            None,
            58 + u8::try_from(flagged.min(6)).unwrap_or(6) * 4,
            SupportRoute::NativeUnpack,
            Evidence {
                kind: EvidenceKind::Entropy,
                locus: format!("section {peak_name}"),
                detail: format!(
                    "{flagged} executable section(s) above {ENTROPY_PACKED_THRESHOLD:.1} bits/byte (peak {peak:.2})"
                ),
            },
        );
    }
}

fn detect_dotnet(image: &PeImage, bytes: &[u8], builder: &mut Builder) {
    let Some(clr): Option<&crate::packers::pe_sections::DataDirectory> =
        image.data_directories.get(CLR_DATA_DIRECTORY_INDEX)
    else {
        return;
    };
    if clr.virtual_address == 0 || clr.size < 0x48 {
        return;
    }
    let Some(host): Option<&PeSection> = image.section_containing_rva(clr.virtual_address) else {
        return;
    };
    let file_offset: Option<usize> =
        host.raw_range(bytes.len())
            .and_then(|(start, _end): (usize, usize)| {
                let delta: u32 = clr.virtual_address.checked_sub(host.virtual_address)?;
                start.checked_add(delta as usize)
            });
    let header_size_ok: bool = file_offset
        .and_then(|off: usize| read_u32_le(bytes, off))
        .is_some_and(|cb: u32| (0x48..=0x100).contains(&cb));
    if !header_size_ok {
        return;
    }
    builder.record(
        IdentityKind::Compiler,
        "dotnet",
        ".NET / CLR",
        None,
        92,
        SupportRoute::DotnetDecompile,
        Evidence {
            kind: EvidenceKind::DataDirectory,
            locus: format!("data directory 14 rva=0x{:X}", clr.virtual_address),
            detail: "CLR runtime header present (COM descriptor) inside a mapped section"
                .to_owned(),
        },
    );
    if find_in_window(bytes, b"#~", bytes.len()).is_some() {
        builder.record(
            IdentityKind::Compiler,
            "dotnet",
            ".NET (compressed metadata)",
            None,
            70,
            SupportRoute::DotnetDecompile,
            Evidence {
                kind: EvidenceKind::ByteSignature,
                locus: "metadata stream".to_owned(),
                detail: "#~ compressed metadata table stream".to_owned(),
            },
        );
    } else if find_in_window(bytes, b"#-", bytes.len()).is_some() {
        builder.record(
            IdentityKind::Protector,
            "dotnet-tamper",
            "obfuscated .NET (#- metadata)",
            None,
            72,
            SupportRoute::DotnetDecompile,
            Evidence {
                kind: EvidenceKind::ByteSignature,
                locus: "metadata stream".to_owned(),
                detail: "#- uncompressed metadata indicates a tampered/obfuscated assembly"
                    .to_owned(),
            },
        );
    }
}

fn detect_packed_entry(image: &PeImage, builder: &mut Builder) {
    let Some(entry_section): Option<&PeSection> =
        image.section_containing_rva(image.entry_point_rva)
    else {
        return;
    };
    let is_last: bool = image
        .sections
        .last()
        .is_some_and(|last: &PeSection| last.virtual_address == entry_section.virtual_address);
    let writable_exec: bool = entry_section.characteristics & 0x8000_0000 != 0
        && entry_section.characteristics & 0x2000_0000 != 0;
    if image.sections.len() >= 2 && is_last && writable_exec {
        builder.record(
            IdentityKind::Packer,
            "generic-packer",
            "unknown packer (heuristic)",
            None,
            55,
            SupportRoute::NativeUnpack,
            Evidence {
                kind: EvidenceKind::EntryStub,
                locus: format!(
                    "entry section {}",
                    display_name(entry_section.name_trimmed())
                ),
                detail: "entry point in the last, writable+executable section".to_owned(),
            },
        );
    }
}

fn detect_rich(bytes: &[u8], builder: &mut Builder) {
    let scan: &[u8] = &bytes[..bytes.len().min(HEADER_SCAN)];
    let Some(rich_pos): Option<usize> = find_subslice(scan, RICH_TAG) else {
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
    let mut best: Option<(u16, &'static RichProduct)> = None;
    let mut entry: usize = dans_pos + 16;
    while entry + 8 <= rich_pos {
        let Some(comp_id): Option<u32> = read_u32_le(scan, entry) else {
            break;
        };
        let product_id: u16 = ((comp_id ^ key) >> 16) as u16;
        for product in RICH_PRODUCTS {
            if product_id >= product.min_id && product_id <= product.max_id {
                let take: bool = best.is_none_or(|(prev, _): (u16, _)| product_id > prev);
                if take {
                    best = Some((product_id, product));
                }
            }
        }
        entry += 8;
    }
    builder.record(
        IdentityKind::Linker,
        "msvc-link",
        "MSVC link.exe",
        None,
        82,
        SupportRoute::NativeDecompile,
        Evidence {
            kind: EvidenceKind::RichHeader,
            locus: format!("rich header at 0x{rich_pos:X}"),
            detail: "DanS/Rich build-stamp block present".to_owned(),
        },
    );
    if let Some((product_id, product)) = best {
        builder.record(
            IdentityKind::Compiler,
            "msvc",
            "MSVC (Visual C++)",
            None,
            86,
            SupportRoute::NativeDecompile,
            Evidence {
                kind: EvidenceKind::RichHeader,
                locus: format!("rich comp.id product 0x{product_id:04X}"),
                detail: format!("rich-header product id maps to {}", product.name),
            },
        );
    }
}

fn detect_pe_imports(bytes: &[u8], builder: &mut Builder) {
    let Ok(file): Result<ObjFile, _> = ObjFile::parse(bytes) else {
        return;
    };
    let Ok(imports): Result<Vec<object::read::Import>, _> = file.imports() else {
        return;
    };
    let mut saw_msvcrt: bool = false;
    let mut saw_ucrt: bool = false;
    let mut saw_mingw: bool = false;
    let mut saw_vcruntime: bool = false;
    for import in imports {
        let lib: &[u8] = import.library();
        if contains_ascii_ci(lib, b"msvcr") || contains_ascii_ci(lib, b"msvcrt") {
            saw_msvcrt = true;
        }
        if contains_ascii_ci(lib, b"api-ms-win-crt") || contains_ascii_ci(lib, b"ucrtbase") {
            saw_ucrt = true;
        }
        if contains_ascii_ci(lib, b"vcruntime") {
            saw_vcruntime = true;
        }
        if contains_ascii_ci(lib, b"libgcc") || contains_ascii_ci(lib, b"libstdc++") {
            saw_mingw = true;
        }
    }
    if saw_ucrt || saw_vcruntime {
        builder.record(
            IdentityKind::Library,
            "ucrt",
            "Universal CRT (UCRT)",
            None,
            70,
            SupportRoute::NativeDecompile,
            Evidence {
                kind: EvidenceKind::Import,
                locus: "import directory".to_owned(),
                detail: "imports api-ms-win-crt / ucrtbase / vcruntime".to_owned(),
            },
        );
    }
    if saw_msvcrt && !saw_mingw {
        builder.record(
            IdentityKind::Library,
            "msvcrt",
            "legacy MSVC CRT (msvcrt.dll)",
            None,
            55,
            SupportRoute::NativeDecompile,
            Evidence {
                kind: EvidenceKind::Import,
                locus: "import directory".to_owned(),
                detail: "imports msvcrt / msvcrNN runtime".to_owned(),
            },
        );
    }
    if saw_mingw {
        builder.record(
            IdentityKind::Compiler,
            "mingw",
            "MinGW-w64 (GCC)",
            None,
            72,
            SupportRoute::NativeDecompile,
            Evidence {
                kind: EvidenceKind::Import,
                locus: "import directory".to_owned(),
                detail: "imports libgcc / libstdc++ runtime".to_owned(),
            },
        );
    }
}

fn detect_pe_installers(bytes: &[u8], builder: &mut Builder) {
    let overlay: &[u8] = if bytes.len() > OVERLAY_SCAN_CAP {
        &bytes[bytes.len() - OVERLAY_SCAN_CAP..]
    } else {
        bytes
    };
    if find_subslice(overlay, b"Nullsoft").is_some() {
        builder.record(
            IdentityKind::Installer,
            "nsis",
            "NSIS",
            None,
            90,
            SupportRoute::ContainerExtract,
            Evidence {
                kind: EvidenceKind::Overlay,
                locus: "overlay".to_owned(),
                detail: "Nullsoft installer overlay marker".to_owned(),
            },
        );
    }
    if find_subslice(overlay, b"Inno Setup").is_some() || find_subslice(bytes, b"zlb\x1a").is_some()
    {
        builder.record(
            IdentityKind::Installer,
            "innosetup",
            "Inno Setup",
            None,
            85,
            SupportRoute::ContainerExtract,
            Evidence {
                kind: EvidenceKind::Overlay,
                locus: "overlay".to_owned(),
                detail: "Inno Setup data marker".to_owned(),
            },
        );
    }
}

fn analyze_object(bytes: &[u8], sigs: &'static [SectionSig], builder: &mut Builder) {
    let Ok(file): Result<ObjFile, _> = ObjFile::parse(bytes) else {
        return;
    };
    for section in file.sections() {
        let Ok(name): Result<&str, _> = section.name() else {
            continue;
        };
        for sig in sigs {
            if name.as_bytes() == sig.name {
                builder.record(
                    sig.kind,
                    sig.family,
                    sig.display,
                    None,
                    sig.confidence,
                    sig.support,
                    Evidence {
                        kind: EvidenceKind::SectionName,
                        locus: format!("section {name}"),
                        detail: format!("{} characteristic section", sig.display),
                    },
                );
            }
        }
    }
}

fn analyze_fat(bytes: &[u8], builder: &mut Builder) {
    builder.record(
        IdentityKind::Format,
        "macho-fat",
        "Mach-O universal binary",
        None,
        90,
        SupportRoute::NativeDecompile,
        Evidence {
            kind: EvidenceKind::Magic,
            locus: "fat header".to_owned(),
            detail: "Mach-O fat/universal container".to_owned(),
        },
    );
    analyze_object(bytes, MACHO_SECTION_SIGNATURES, builder);
}

fn merge_byte_identity(bytes: &[u8], builder: &mut Builder) {
    let report: crate::identify::IdentityReport = detect_byte_identity(bytes);
    for hit in report.hits {
        let family: &'static str = canonical_family(&hit.name);
        let display: &'static str = canonical_display(family);
        builder.record(
            hit.kind,
            family,
            display,
            None,
            hit.confidence,
            hit.support,
            Evidence {
                kind: EvidenceKind::ByteSignature,
                locus: "byte scan".to_owned(),
                detail: hit.detail,
            },
        );
    }
}

fn canonical_family(name: &str) -> &'static str {
    match name {
        "UPX" => "upx",
        "ASPack" => "aspack",
        "PECompact" => "pecompact",
        "FSG" => "fsg",
        "MEW" => "mew",
        "MPRESS" => "mpress",
        "Petite" => "petite",
        "NSPack" => "nspack",
        "kkrunchy" => "kkrunchy",
        "Themida/WinLicense" => "themida",
        "VMProtect" => "vmprotect",
        "Enigma" => "enigma",
        "Obsidium" => "obsidium",
        "Armadillo" => "armadillo",
        "ConfuserEx" => "confuserex",
        ".NET Reactor" => "dotnet-reactor",
        "Eazfuscator.NET" => "eazfuscator",
        "Go" => "go",
        "Rust" => "rust",
        "MinGW" => "mingw",
        "GCC" => "gcc",
        "Clang/LLVM" => "clang",
        "Delphi" | "Embarcadero" => "delphi",
        "Nim" => "nim",
        "Free Pascal" => "freepascal",
        ".NET" => "dotnet",
        "Nuitka" => "nuitka",
        "py2exe" => "py2exe",
        "PyInstaller" => "pyinstaller",
        "Electron" => "electron",
        "Bun" => "bun",
        "Zig" => "zig",
        "Crystal" => "crystal",
        "Swift" | "Swift runtime" => "swift",
        "Objective-C" => "objc",
        "Haskell/GHC" => "ghc",
        "GNU ld" => "gnu-ld",
        "LLD" => "lld",
        "musl libc" => "musl",
        "glibc" => "glibc",
        "GNU build-id" => "gnu-build-id",
        "Flutter/Dart AOT" => "dart",
        "OCaml" => "ocaml",
        "NSIS" => "nsis",
        "Inno Setup" => "innosetup",
        "InstallShield" => "installshield",
        "WiX/MSI" => "msi",
        "AutoIt" => "autoit",
        "Authenticode" => "authenticode",
        "MSVC link" => "msvc-link",
        _ => "other",
    }
}

fn canonical_display(family: &'static str) -> &'static str {
    match family {
        "upx" => "UPX",
        "aspack" => "ASPack",
        "pecompact" => "PECompact",
        "fsg" => "FSG",
        "mew" => "MEW",
        "mpress" => "MPRESS",
        "petite" => "Petite",
        "nspack" => "NSPack",
        "kkrunchy" => "kkrunchy",
        "themida" => "Themida/WinLicense",
        "vmprotect" => "VMProtect",
        "enigma" => "Enigma Protector",
        "obsidium" => "Obsidium",
        "armadillo" => "Armadillo",
        "confuserex" => "ConfuserEx",
        "dotnet-reactor" => ".NET Reactor",
        "eazfuscator" => "Eazfuscator.NET",
        "go" => "Go",
        "rust" => "Rust",
        "mingw" => "MinGW-w64 (GCC)",
        "gcc" => "GCC",
        "clang" => "Clang/LLVM",
        "delphi" => "Delphi/Embarcadero",
        "nim" => "Nim",
        "freepascal" => "Free Pascal",
        "dotnet" => ".NET / CLR",
        "nuitka" => "Nuitka",
        "py2exe" => "py2exe",
        "pyinstaller" => "PyInstaller",
        "electron" => "Electron",
        "bun" => "Bun",
        "zig" => "Zig",
        "crystal" => "Crystal",
        "swift" => "Swift",
        "objc" => "Objective-C",
        "ghc" => "Haskell/GHC",
        "gnu-ld" => "GNU ld",
        "lld" => "LLVM lld",
        "musl" => "musl libc",
        "glibc" => "glibc",
        "gnu-build-id" => "GNU build-id",
        "dart" => "Flutter/Dart AOT",
        "ocaml" => "OCaml",
        "nsis" => "NSIS",
        "innosetup" => "Inno Setup",
        "installshield" => "InstallShield",
        "msi" => "WiX/MSI",
        "autoit" => "AutoIt",
        "authenticode" => "Authenticode",
        "msvc-link" => "MSVC link.exe",
        _ => "unclassified",
    }
}

#[inline]
fn display_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

#[inline]
fn contains_ascii_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return false;
    }
    haystack
        .windows(needle_lower.len())
        .any(|w: &[u8]| w.eq_ignore_ascii_case(needle_lower))
}

fn find_in_window(haystack: &[u8], needle: &[u8], cap: usize) -> Option<usize> {
    let window: &[u8] = &haystack[..haystack.len().min(cap)];
    find_subslice(window, needle)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first: u8 = needle[0];
    let mut from: usize = 0;
    while let Some(rel) = haystack[from..].iter().position(|&b: &u8| b == first) {
        let at: usize = from + rel;
        if haystack[at..].starts_with(needle) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

#[inline]
fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let s: &[u8] = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn unknown_format_yields_empty_findings() {
        let report: FileIdReport = identify(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(report.format, "unknown");
        assert!(report.findings.is_empty());
    }

    #[test]
    fn rich_product_table_is_monotone_and_nonoverlapping() {
        assert!(!RICH_PRODUCTS.is_empty());
        let mut prev_max: Option<u16> = None;
        for product in RICH_PRODUCTS {
            assert!(product.min_id <= product.max_id);
            assert!(!product.name.is_empty());
            if let Some(prev) = prev_max {
                assert!(
                    product.min_id > prev,
                    "rich product ranges overlap at 0x{:04X}",
                    product.min_id
                );
            }
            prev_max = Some(product.max_id);
        }
    }

    #[test]
    fn every_section_signature_routes_somewhere() {
        for sig in PE_SECTION_SIGNATURES
            .iter()
            .chain(ELF_SECTION_SIGNATURES)
            .chain(MACHO_SECTION_SIGNATURES)
        {
            assert!(!sig.support.command().is_empty());
            assert!(!sig.family.is_empty());
        }
    }

    #[test]
    fn canonical_family_round_trips_to_display() {
        assert_eq!(canonical_family("UPX"), "upx");
        assert_eq!(canonical_display("upx"), "UPX");
        assert_eq!(canonical_family("VMProtect"), "vmprotect");
        assert_eq!(canonical_display("vmprotect"), "VMProtect");
    }

    fn corpus_bytes(rel: &str) -> Option<Vec<u8>> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel);
        std::fs::read(path).ok()
    }

    fn has_packer_or_protector_family(report: &FileIdReport, family: &str) -> bool {
        report.findings.iter().any(|f: &Finding| {
            f.family == family && matches!(f.kind, IdentityKind::Packer | IdentityKind::Protector)
        })
    }

    #[test]
    fn labeled_packed_corpus_is_identified_by_family_with_honest_precision() {
        let cases: &[(&str, &str)] = &[
            ("native/packers/upx/hello.packed.nrv2b.exe", "upx"),
            (
                "native/packers/aspack/AccessEnum.packed.aspack.exe",
                "aspack",
            ),
            ("native/packers/aspack/Clockres.packed.aspack.exe", "aspack"),
            (
                "native/packers/pecompact/AccessEnum.packed.pecompact.exe",
                "pecompact",
            ),
            (
                "native/packers/pecompact/Clockres.packed.pecompact.exe",
                "pecompact",
            ),
            ("native/packers/mew/AccessEnum.packed.mew.exe", "mew"),
            ("native/packers/mew/Autologon.packed.mew.exe", "mew"),
            ("native/packers/mew/Clockres.packed.mew.exe", "mew"),
            (
                "native/packers/yodas_crypter/AccessEnum.packed.yodascrypter.exe",
                "yodas-crypter",
            ),
            (
                "native/packers/yodas_crypter/Clockres.packed.yodascrypter.exe",
                "yodas-crypter",
            ),
            (
                "native/packers/yodas_protector/AccessEnum.packed.yodasprotector.exe",
                "yodas-protector",
            ),
            (
                "native/packers/yodas_protector/Clockres.packed.yodasprotector.exe",
                "yodas-protector",
            ),
        ];

        let mut present: usize = 0;
        let mut hit: usize = 0;
        for (rel, family) in cases {
            let Some(bytes): Option<Vec<u8>> = corpus_bytes(rel) else {
                continue;
            };
            present += 1;
            let report: FileIdReport = identify(&bytes);
            if has_packer_or_protector_family(&report, family) {
                hit += 1;
            } else {
                panic!(
                    "labeled {family} sample {rel} was not identified; findings = {:?}",
                    report
                        .findings
                        .iter()
                        .map(|f: &Finding| (f.family.clone(), f.kind, f.confidence))
                        .collect::<Vec<(String, IdentityKind, u8)>>()
                );
            }
        }

        if present == 0 {
            return;
        }
        let recall: f64 = hit as f64 / present as f64;
        assert!(
            (recall - 1.0).abs() < f64::EPSILON,
            "packed-corpus family recall {recall:.3} ({hit}/{present}) is below the asserted 1.0"
        );
    }

    #[test]
    fn clean_originals_carry_no_false_packer_or_protector_finding() {
        let originals: &[(&str, &str)] = &[
            ("native/packers/aspack/AccessEnum.original.exe", "aspack"),
            (
                "native/packers/pecompact/AccessEnum.original.exe",
                "pecompact",
            ),
            ("native/packers/mew/AccessEnum.original.exe", "mew"),
            ("native/packers/upx/hello.original.exe", "upx"),
            (
                "native/packers/yodas_crypter/AccessEnum.original.exe",
                "yodas-crypter",
            ),
            (
                "native/packers/yodas_protector/AccessEnum.original.exe",
                "yodas-protector",
            ),
        ];
        let mut checked: usize = 0;
        for (rel, family) in originals {
            let Some(bytes): Option<Vec<u8>> = corpus_bytes(rel) else {
                continue;
            };
            checked += 1;
            let report: FileIdReport = identify(&bytes);
            assert!(
                !has_packer_or_protector_family(&report, family),
                "clean original {rel} falsely flagged as {family}: {:?}",
                report
                    .findings
                    .iter()
                    .map(|f: &Finding| (f.family.clone(), f.kind, f.confidence))
                    .collect::<Vec<(String, IdentityKind, u8)>>()
            );
        }
        if checked == 0 {
            return;
        }
        assert!(
            checked >= 3,
            "expected several clean originals, saw {checked}"
        );
    }

    #[test]
    fn entropy_evidence_fires_on_packed_but_not_clean() {
        let Some(packed): Option<Vec<u8>> =
            corpus_bytes("native/packers/upx/hello.packed.nrv2b.exe")
        else {
            return;
        };
        let clean: Vec<u8> = corpus_bytes("native/packers/upx/hello.original.exe")
            .expect("clean upx original present");

        let packed_report: FileIdReport = identify(&packed);
        let clean_report: FileIdReport = identify(&clean);

        let packed_entropy: bool = packed_report.findings.iter().any(|f: &Finding| {
            f.evidence
                .iter()
                .any(|e: &Evidence| e.kind == EvidenceKind::Entropy)
        });
        let clean_entropy: bool = clean_report.findings.iter().any(|f: &Finding| {
            f.evidence
                .iter()
                .any(|e: &Evidence| e.kind == EvidenceKind::Entropy)
        });
        assert!(
            packed_entropy,
            "a UPX-packed PE carries a high-entropy executable section"
        );
        assert!(
            !clean_entropy,
            "the unpacked original PE must not trip the high-entropy packer heuristic"
        );
    }
}
