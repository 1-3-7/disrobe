use std::collections::BTreeMap;

use object::Object as _;
use object::ObjectSection as _;
use object::read::File as ObjFile;
use serde::{Deserialize, Serialize};

use disrobe_bytes::read_u32_le_at;

use crate::format::{NativeFormat, detect as detect_format};
use crate::identify::{IdentityKind, SupportRoute, detect as detect_byte_identity};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use crate::runtime_image::{
    RUNTIME_DECRYPTED_VERDICT, RuntimeDecryptedImage, detect_runtime_decrypted,
};

const RICH_TAG: &[u8; 4] = b"Rich";
const DANS_TAG: u32 = 0x536E_6144;
const HEADER_SCAN: usize = 4096;
const CLR_DATA_DIRECTORY_INDEX: usize = 14;
const OVERLAY_SCAN_CAP: usize = 64 * 1024;
const HIGH_ENTROPY_CODE_FAMILY: &str = "high-entropy-code";
const GENERIC_PACKER_FAMILY: &str = "generic-packer";
const RUNTIME_DECRYPTED_FAMILY: &str = "runtime-decrypted";

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

    fn has_named_unpacker(&self) -> bool {
        self.findings.values().any(|finding: &Finding| {
            finding.kind == IdentityKind::Packer
                && finding.support == SupportRoute::NativeUnpack
                && !matches!(
                    finding.family.as_str(),
                    HIGH_ENTROPY_CODE_FAMILY | GENERIC_PACKER_FAMILY
                )
        })
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

#[must_use]
pub fn identify(bytes: &[u8], now_secs: u64) -> FileIdReport {
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

    merge_byte_identity(bytes, now_secs, &mut builder);
    merge_struct_findings(bytes, &mut builder);
    if matches!(detected.kind, NativeFormat::Pe32 | NativeFormat::Pe64) {
        record_runtime_decrypted(bytes, &mut builder);
    }

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
    detect_pe_installers(&image, bytes, builder);
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
            HIGH_ENTROPY_CODE_FAMILY,
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
        .and_then(|off: usize| read_u32_le_at(bytes, off).ok())
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
            GENERIC_PACKER_FAMILY,
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
    let Some(key): Option<u32> = read_u32_le_at(scan, rich_pos + 4).ok() else {
        return;
    };
    let mut cursor: usize = rich_pos;
    let mut dans: Option<usize> = None;
    while cursor >= 4 {
        cursor -= 4;
        let Some(raw): Option<u32> = read_u32_le_at(scan, cursor).ok() else {
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
            detail: format!("DanS/Rich build-stamp block present at 0x{dans_pos:X}"),
        },
    );
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

fn detect_pe_installers(image: &PeImage, bytes: &[u8], builder: &mut Builder) {
    let tail: &[u8] = if bytes.len() > OVERLAY_SCAN_CAP {
        &bytes[bytes.len() - OVERLAY_SCAN_CAP..]
    } else {
        bytes
    };
    let overlay_start: usize = image
        .sections
        .iter()
        .filter_map(|section: &PeSection| section.raw_range(bytes.len()))
        .map(|(_, end): (usize, usize)| end)
        .max()
        .unwrap_or(image.size_of_headers as usize);
    let zlib_block_at_overlay: bool = bytes
        .get(overlay_start..)
        .is_some_and(|overlay: &[u8]| overlay.starts_with(b"zlb\x1a"));
    if find_subslice(tail, b"Inno Setup").is_some() || zlib_block_at_overlay {
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

fn record_runtime_decrypted(bytes: &[u8], builder: &mut Builder) {
    if builder.has_named_unpacker() {
        return;
    }
    let Some(runtime): Option<RuntimeDecryptedImage> = detect_runtime_decrypted(bytes) else {
        return;
    };
    builder
        .findings
        .remove(&(IdentityKind::Packer, HIGH_ENTROPY_CODE_FAMILY));
    builder.record(
        IdentityKind::Protector,
        RUNTIME_DECRYPTED_FAMILY,
        RUNTIME_DECRYPTED_VERDICT,
        None,
        90,
        SupportRoute::RuntimeOnly,
        Evidence {
            kind: EvidenceKind::Entropy,
            locus: format!("section {}", runtime.entry_section),
            detail: format!(
                "entry point 0x{:X} lies in this executable section: {} bytes on disk at {:.2} bits/byte",
                runtime.entry_point_rva, runtime.entry_section_raw_bytes, runtime.entry_section_entropy
            ),
        },
    );
    for section in &runtime.unbacked_code {
        builder.record(
            IdentityKind::Protector,
            RUNTIME_DECRYPTED_FAMILY,
            RUNTIME_DECRYPTED_VERDICT,
            None,
            90,
            SupportRoute::RuntimeOnly,
            Evidence {
                kind: EvidenceKind::SectionName,
                locus: format!("section {}", section.name),
                detail: format!(
                    "code section declares {} bytes at RVA 0x{:X} with no bytes on disk",
                    section.virtual_size, section.virtual_address
                ),
            },
        );
    }
}

fn merge_byte_identity(bytes: &[u8], now_secs: u64, builder: &mut Builder) {
    let report: crate::identify::IdentityReport = detect_byte_identity(bytes, now_secs);
    for hit in report.hits {
        if hit.support == SupportRoute::RuntimeOnly {
            continue;
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const NOW_SECS: u64 = 1_798_761_600;

    fn layout_noise(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn runtime_decrypted_image_is_named_and_routed_to_refusal() {
        use crate::test_support::{SyntheticSection, pe64_layout};
        let bytes: Vec<u8> = pe64_layout(
            &[
                SyntheticSection::unbacked(*b".text\0\0\0", 0x1000, 0x80_0000, 0x6000_0020),
                SyntheticSection::unbacked(*b".pdata\0\0", 0x81_0000, 0x4000, 0x4000_0040),
                SyntheticSection::backed(
                    *b".enc1\0\0\0",
                    0x82_0000,
                    layout_noise(0x4_0000),
                    0x6000_0020,
                ),
                SyntheticSection::backed(*b".rsrc\0\0\0", 0x87_0000, vec![0u8; 0x400], 0x4000_0040),
            ],
            0x83_0000,
        );
        let report: FileIdReport = identify(&bytes, NOW_SECS);
        let runtime: &Finding = report
            .findings
            .iter()
            .find(|f: &&Finding| f.family == RUNTIME_DECRYPTED_FAMILY)
            .unwrap_or_else(|| panic!("runtime-decrypted verdict missing: {:?}", report.findings));
        assert_eq!(runtime.kind, IdentityKind::Protector);
        assert_eq!(runtime.name, RUNTIME_DECRYPTED_VERDICT);
        assert_eq!(runtime.support, SupportRoute::RuntimeOnly);
        assert!(
            runtime.evidence.iter().any(
                |e: &Evidence| e.locus == "section .text" && e.detail.contains("8388608 bytes")
            ),
            "{:?}",
            runtime.evidence
        );
        assert!(
            runtime
                .evidence
                .iter()
                .any(|e: &Evidence| e.locus == "section .enc1"),
            "{:?}",
            runtime.evidence
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f: &Finding| f.support == SupportRoute::NativeUnpack),
            "no unpacker route is offered for code that exists only at run time: {:?}",
            report.findings
        );
    }

    #[test]
    fn rich_product_ids_shared_by_every_14x_toolset_do_not_name_a_release() {
        use crate::test_support::{SyntheticSection, pe64_layout};
        let mut bytes: Vec<u8> = pe64_layout(
            &[SyntheticSection::backed(
                *b".text\0\0\0",
                0x1000,
                vec![0xC3; 0x10],
                0x6000_0020,
            )],
            0x1000,
        );
        let key: u32 = 0x2468_ACE1;
        let mut rich: Vec<u8> = Vec::new();
        for word in [DANS_TAG, 0, 0, 0] {
            rich.extend_from_slice(&(word ^ key).to_le_bytes());
        }
        for (product, build) in [(0x0108u32, 30795u32), (0x0102, 30795)] {
            rich.extend_from_slice(&(((product << 16) | build) ^ key).to_le_bytes());
            rich.extend_from_slice(&(1u32 ^ key).to_le_bytes());
        }
        rich.extend_from_slice(RICH_TAG);
        rich.extend_from_slice(&key.to_le_bytes());
        bytes[0x40..0x40 + rich.len()].copy_from_slice(&rich);
        let report: FileIdReport = identify(&bytes, NOW_SECS);
        let msvc: &Finding = report
            .findings
            .iter()
            .find(|f: &&Finding| f.family == "msvc")
            .unwrap_or_else(|| panic!("msvc finding missing: {:?}", report.findings));
        assert_eq!(msvc.version.as_deref(), Some("14.3.30795 (VS2022)"));
        assert!(
            !msvc
                .evidence
                .iter()
                .any(|e: &Evidence| e.detail.contains("2017") || e.detail.contains("2015")),
            "a product id shared by VS2015-VS2022 names no release: {:?}",
            msvc.evidence
        );
    }

    #[test]
    fn inno_zlib_marker_inside_a_section_is_not_an_installer() {
        use crate::test_support::{SyntheticSection, pe64_layout};
        let mut data: Vec<u8> = vec![0u8; 0x200];
        data[0x20..0x24].copy_from_slice(b"zlb\x1a");
        let bytes: Vec<u8> = pe64_layout(
            &[
                SyntheticSection::backed(*b".text\0\0\0", 0x1000, vec![0xC3; 0x10], 0x6000_0020),
                SyntheticSection::backed(*b".rdata\0\0", 0x2000, data, 0x4000_0040),
            ],
            0x1000,
        );
        let report: FileIdReport = identify(&bytes, NOW_SECS);
        assert!(
            !report
                .findings
                .iter()
                .any(|f: &Finding| f.family == "innosetup"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn unknown_format_yields_empty_findings() {
        let report: FileIdReport = identify(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05], NOW_SECS);
        assert_eq!(report.format, "unknown");
        assert!(report.findings.is_empty());
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

    fn corpus_bytes(rel: &str) -> Vec<u8> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel);
        std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "the labeled packer corpus is tracked, so every checkout carries {}; it could not be read ({error}), and skipping it would let this case report success while grading nothing",
                path.display()
            )
        })
    }

    fn has_packer_or_protector_family(report: &FileIdReport, family: &str) -> bool {
        report.findings.iter().any(|f: &Finding| {
            f.family == family && matches!(f.kind, IdentityKind::Packer | IdentityKind::Protector)
        })
    }

    #[test]
    fn labeled_packed_corpus_is_identified_by_family_with_measured_precision() {
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
            let bytes: Vec<u8> = corpus_bytes(rel);
            present += 1;
            let report: FileIdReport = identify(&bytes, NOW_SECS);
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

        assert_eq!(
            present,
            cases.len(),
            "every labeled case must be graded, otherwise recall is computed over survivors and identifying one file of {} would still read as 1.0",
            cases.len()
        );
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
            let bytes: Vec<u8> = corpus_bytes(rel);
            checked += 1;
            let report: FileIdReport = identify(&bytes, NOW_SECS);
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
        assert_eq!(
            checked,
            originals.len(),
            "every clean original must be checked, otherwise a shrinking population hides a false positive"
        );
    }

    #[test]
    fn entropy_evidence_fires_on_packed_but_not_clean() {
        let packed: Vec<u8> = corpus_bytes("native/packers/upx/hello.packed.nrv2b.exe");
        let clean: Vec<u8> = corpus_bytes("native/packers/upx/hello.original.exe");

        let packed_report: FileIdReport = identify(&packed, NOW_SECS);
        let clean_report: FileIdReport = identify(&clean, NOW_SECS);

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
