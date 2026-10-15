use serde::{Deserialize, Serialize};

use disrobe_bytes::read_u32_le_at;

use crate::authenticode::{AuthenticodeReport, AuthenticodeVerdict};
use crate::packers::anchor::AnchorRegions;
use crate::packers::pe_sections::{PeImage, parse_pe_image};

const PE_MAGIC: &[u8; 2] = b"MZ";
const ELF_MAGIC: &[u8; 4] = &[0x7F, b'E', b'L', b'F'];
const MACHO_LE: &[u8; 4] = &[0xCF, 0xFA, 0xED, 0xFE];
const MACHO_BE: &[u8; 4] = &[0xFE, 0xED, 0xFA, 0xCF];
const MACHO_FAT: &[u8; 4] = &[0xCA, 0xFE, 0xBA, 0xBE];
const RICH_TAG: &[u8; 4] = b"Rich";
const DANS_TAG: u32 = 0x536E_6144;
const SCAN_LIMIT: usize = 4 * 1024 * 1024;
const DOTNET_METADATA_ROOT: &[u8; 4] = b"BSJB";
const MAX_METADATA_ROOT_PROBES: usize = 64;
const MAX_METADATA_VERSION_BYTES: usize = 255;
const MAX_METADATA_STREAMS: usize = 16;
const MAX_METADATA_STREAM_NAME: usize = 32;
const RICH_LINKER_1400_PRODUCT: u16 = 0x0102;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKind {
    Compiler,
    Linker,
    Packer,
    Protector,
    Installer,
    Library,
    Sign,
    Format,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportRoute {
    DotnetDecompile,
    GoDecompile,
    RustRecover,
    NativeDecompile,
    NativeLangDemangle,
    PyDecompile,
    NativeUnpack,
    ContainerExtract,
    DetectCarveOnly,
    SignatureInspect,
    RuntimeOnly,
}

impl SupportRoute {
    pub const ALL: [Self; 11] = [
        Self::DotnetDecompile,
        Self::GoDecompile,
        Self::RustRecover,
        Self::NativeDecompile,
        Self::NativeLangDemangle,
        Self::PyDecompile,
        Self::NativeUnpack,
        Self::ContainerExtract,
        Self::DetectCarveOnly,
        Self::SignatureInspect,
        Self::RuntimeOnly,
    ];

    #[must_use]
    pub const fn invocations(self) -> &'static [&'static str] {
        match self {
            Self::DotnetDecompile => &["dotnet decompile"],
            Self::GoDecompile => &["go recover"],
            Self::RustRecover | Self::NativeDecompile | Self::NativeLangDemangle => {
                &["native decompile"]
            }
            Self::PyDecompile => &["py extract", "py decompile"],
            Self::NativeUnpack => &["native unpack"],
            Self::ContainerExtract => &["auto"],
            Self::DetectCarveOnly => &["native devirt", "native unpack"],
            Self::SignatureInspect | Self::RuntimeOnly => &[],
        }
    }

    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::DotnetDecompile => "disrobe dotnet decompile",
            Self::GoDecompile => "disrobe go recover",
            Self::RustRecover => "disrobe native decompile (Rust symbol + panic recovery)",
            Self::NativeDecompile => "disrobe native decompile",
            Self::NativeLangDemangle => "disrobe native decompile (demangle + symbol recovery)",
            Self::PyDecompile => "disrobe py extract then disrobe py decompile",
            Self::NativeUnpack => "disrobe native unpack",
            Self::ContainerExtract => "disrobe auto (container extract + recurse)",
            Self::DetectCarveOnly => {
                "disrobe native devirt (generic VM lift) + section carve via disrobe native unpack"
            }
            Self::SignatureInspect => "signature inspection only",
            Self::RuntimeOnly => {
                "none: the code is decrypted only at run time, so static recovery is refused"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityHit {
    pub kind: IdentityKind,
    pub name: String,
    pub detail: String,
    pub confidence: u8,
    pub support: SupportRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityReport {
    pub format: String,
    pub hits: Vec<IdentityHit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticode: Option<AuthenticodeReport>,
}

struct ByteSig {
    kind: IdentityKind,
    name: &'static str,
    pattern: &'static [u8],
    detail: &'static str,
    confidence: u8,
    support: SupportRoute,
    anchor: SigAnchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigAnchor {
    Anywhere,
    PeSectionName,
    Structural,
}

const SIGNATURES: &[ByteSig] = &[
    ByteSig {
        kind: IdentityKind::Packer,
        name: "UPX",
        pattern: b"UPX!",
        detail: "UPX packer magic",
        confidence: 95,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::Structural,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "ASPack",
        pattern: b".aspack",
        detail: "ASPack section",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "ASPack",
        pattern: b".adata",
        detail: "ASPack data section",
        confidence: 70,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "PECompact",
        pattern: b"PEC2",
        detail: "PECompact marker",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::Structural,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "FSG",
        pattern: b"FSG!",
        detail: "FSG packer magic",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::Structural,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "MEW",
        pattern: b"MEW",
        detail: "MEW packer marker",
        confidence: 70,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "MPRESS",
        pattern: b".MPRESS1",
        detail: "MPRESS section",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "Petite",
        pattern: b".petite",
        detail: "Petite section",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "NSPack",
        pattern: b".nsp0",
        detail: "NSPack section",
        confidence: 85,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "kkrunchy",
        pattern: b"kkrunchy",
        detail: "kkrunchy marker",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::Structural,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Themida/WinLicense",
        pattern: b".themida",
        detail: "Themida section",
        confidence: 95,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Themida/WinLicense",
        pattern: b".winlice",
        detail: "WinLicense section",
        confidence: 90,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "VMProtect",
        pattern: b".vmp0",
        detail: "VMProtect section",
        confidence: 95,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "VMProtect",
        pattern: b".vmp1",
        detail: "VMProtect section",
        confidence: 90,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Enigma",
        pattern: b".enigma1",
        detail: "Enigma Protector section",
        confidence: 90,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Obsidium",
        pattern: b"obsidium",
        detail: "Obsidium marker",
        confidence: 85,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Armadillo",
        pattern: b"PVZURY",
        detail: "Armadillo string marker",
        confidence: 80,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "ConfuserEx",
        pattern: b"ConfusedByAttribute",
        detail: ".NET ConfuserEx marker",
        confidence: 90,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Go",
        pattern: b"Go build ID:",
        detail: "Go build id",
        confidence: 95,
        support: SupportRoute::GoDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Go",
        pattern: b"go.buildid",
        detail: "Go build id section",
        confidence: 90,
        support: SupportRoute::GoDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Rust",
        pattern: b"rustc/",
        detail: "Rust compiler path",
        confidence: 90,
        support: SupportRoute::RustRecover,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Rust",
        pattern: b"/rust/library/",
        detail: "Rust stdlib path",
        confidence: 85,
        support: SupportRoute::RustRecover,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "MinGW",
        pattern: b"Mingw-w64",
        detail: "MinGW runtime marker",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GCC",
        pattern: b"GCC: (",
        detail: "GCC compiler comment",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Clang/LLVM",
        pattern: b"clang version",
        detail: "Clang version string",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Delphi",
        pattern: b"Borland Delphi",
        detail: "Delphi marker",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Embarcadero",
        pattern: b"Embarcadero Delphi",
        detail: "Embarcadero Delphi marker",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Nim",
        pattern: b"NimMain",
        detail: "Nim runtime symbol",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Free Pascal",
        pattern: b"FPC ",
        detail: "Free Pascal marker",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: ".NET",
        pattern: b"_CorExeMain",
        detail: ".NET CLR entry import",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "NSIS",
        pattern: b"NullsoftInst",
        detail: "NSIS installer",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Inno Setup",
        pattern: b"Inno Setup Setup Data",
        detail: "Inno Setup data",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "InstallShield",
        pattern: b"InstallShield",
        detail: "InstallShield marker",
        confidence: 85,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "WiX/MSI",
        pattern: b"Windows Installer",
        detail: "MSI/WiX marker",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "AutoIt",
        pattern: b"AU3!EA06",
        detail: "compiled AutoIt3 script",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "PyInstaller",
        pattern: b"pyi-windows-manifest-filename",
        detail: "PyInstaller marker",
        confidence: 85,
        support: SupportRoute::PyDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Nuitka",
        pattern: b"NUITKA_VERSION",
        detail: "Nuitka onefile/standalone marker",
        confidence: 90,
        support: SupportRoute::PyDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "py2exe",
        pattern: b"PYTHONSCRIPT",
        detail: "py2exe embedded script resource",
        confidence: 85,
        support: SupportRoute::PyDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Electron",
        pattern: b"electron.asar",
        detail: "Electron app.asar archive",
        confidence: 85,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Bun",
        pattern: b"\n---- Bun! ----\n",
        detail: "Bun standalone executable trailer",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: ".NET Reactor",
        pattern: b".NET Reactor",
        detail: ".NET Reactor protector marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Eazfuscator.NET",
        pattern: b"Eazfuscator.NET",
        detail: "Eazfuscator.NET protector marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Zig",
        pattern: b"zig_panic",
        detail: "Zig panic handler symbol",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Crystal",
        pattern: b"__crystal_main",
        detail: "Crystal runtime entry symbol",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Swift",
        pattern: b"swift_getTypeByMangledNameInContext",
        detail: "Swift runtime symbol",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Haskell/GHC",
        pattern: b"GHC ",
        detail: "GHC runtime marker",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "GNU ld",
        pattern: b"GNU ld ",
        detail: "GNU linker comment",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "LLD",
        pattern: b"Linker: LLD ",
        detail: "LLVM lld linker comment",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Go",
        pattern: b".note.go.buildid",
        detail: "Go ELF build-id note section",
        confidence: 90,
        support: SupportRoute::GoDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "musl libc",
        pattern: b"/lib/ld-musl-",
        detail: "musl dynamic loader path",
        confidence: 85,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "glibc",
        pattern: b"GNU C Library",
        detail: "glibc runtime banner",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "GNU build-id",
        pattern: b".note.gnu.build-id",
        detail: "GNU ELF build-id note section",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Swift",
        pattern: b"__swift5_proto",
        detail: "Swift 5 protocol-conformance Mach-O section",
        confidence: 90,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Objective-C",
        pattern: b"__objc_classlist",
        detail: "Objective-C class-list Mach-O section",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Swift runtime",
        pattern: b"libswiftCore",
        detail: "Swift core runtime dylib reference",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Flutter/Dart AOT",
        pattern: b"kDartIsolateSnapshotInstructions",
        detail: "Dart AOT isolate snapshot symbol",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "OCaml",
        pattern: b"caml_program",
        detail: "OCaml native runtime entry symbol",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "TinyCC",
        pattern: b"TCC: ",
        detail: "Tiny C Compiler banner",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Intel C++",
        pattern: b"Intel(R) C++",
        detail: "Intel C++ compiler banner",
        confidence: 85,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Intel Fortran",
        pattern: b"Intel(R) Fortran",
        detail: "Intel Fortran compiler banner",
        confidence: 85,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Watcom",
        pattern: b"WATCOM C/C++",
        detail: "Open Watcom compiler banner",
        confidence: 82,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "AdaCore GNAT",
        pattern: b"GNAT Pro",
        detail: "GNAT Ada runtime marker",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "V Lang",
        pattern: b"v_panic",
        detail: "V language panic symbol",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "D (DMD/LDC)",
        pattern: b"_d_run_main",
        detail: "D runtime entry symbol",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "PyOxidizer",
        pattern: b"pyoxidizer",
        detail: "experimental, unvalidated PyOxidizer embedded interpreter marker",
        confidence: 85,
        support: SupportRoute::PyDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Node SEA",
        pattern: b"NODE_SEA_BLOB",
        detail: "Node.js single-executable-application blob",
        confidence: 90,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Deno compile",
        pattern: b"d3n0l4nd",
        detail: "Deno compiled binary trailer magic",
        confidence: 90,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "pkg (Vercel)",
        pattern: b"PKG_DUMMY_ENTRYPOINT",
        detail: "Vercel pkg Node snapshot marker",
        confidence: 85,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "WiX Burn",
        pattern: b".wixburn",
        detail: "WiX Burn bootstrapper section",
        confidence: 88,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Squirrel",
        pattern: b"SquirrelTemp",
        detail: "Squirrel.Windows installer marker",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "InstallAnywhere",
        pattern: b"InstallAnywhere",
        detail: "InstallAnywhere installer marker",
        confidence: 82,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Setup Factory",
        pattern: b"Setup Factory",
        detail: "Setup Factory installer marker",
        confidence: 82,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Advanced Installer",
        pattern: b"Advanced Installer",
        detail: "Advanced Installer marker",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Wise Installer",
        pattern: b"WiseMain",
        detail: "Wise installation system marker",
        confidence: 78,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "MoleBox",
        pattern: b".mbx",
        detail: "MoleBox virtualizing packer section",
        confidence: 82,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "Molebox Ultra",
        pattern: b"MoleBox",
        detail: "MoleBox runtime marker",
        confidence: 80,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "RLPack",
        pattern: b".RLPack",
        detail: "RLPack section marker",
        confidence: 82,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "exeStealth",
        pattern: b"exeStealth",
        detail: "exeStealth packer marker",
        confidence: 80,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "ASProtect",
        pattern: b".asprotect",
        detail: "ASProtect protector section",
        confidence: 85,
        support: SupportRoute::NativeUnpack,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Code Virtualizer",
        pattern: b"CodeVirtualizer",
        detail: "Oreans Code Virtualizer marker",
        confidence: 85,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "SmartAssembly",
        pattern: b"SmartAssembly.Attributes",
        detail: ".NET SmartAssembly protector marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Dotfuscator",
        pattern: b"DotfuscatorAttribute",
        detail: ".NET Dotfuscator marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Agile.NET",
        pattern: b"AgileDotNetRT",
        detail: "Agile.NET (CliSecure) runtime marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Babel.NET",
        pattern: b"BabelAttribute",
        detail: "Babel.NET obfuscator marker",
        confidence: 82,
        support: SupportRoute::DotnetDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Themida",
        pattern: b"Themida",
        detail: "Themida runtime banner",
        confidence: 80,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "Turbo Linker",
        pattern: b"Turbo Link",
        detail: "Borland Turbo linker marker",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "GNU gold",
        pattern: b"GNU gold ",
        detail: "GNU gold linker comment",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "mold",
        pattern: b"mold ",
        detail: "mold linker comment",
        confidence: 72,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "OpenSSL",
        pattern: b"OpenSSL ",
        detail: "OpenSSL version banner",
        confidence: 65,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Qt",
        pattern: b"Qt 6.",
        detail: "Qt 6 runtime version string",
        confidence: 65,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Boost",
        pattern: b"boost_version",
        detail: "Boost C++ libraries marker",
        confidence: 60,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "CodeWarrior",
        pattern: b"MW CodeWarrior",
        detail: "Metrowerks CodeWarrior compiler comment",
        confidence: 88,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "CodeWarrior",
        pattern: b"Metrowerks",
        detail: "Metrowerks toolchain marker",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"Ada Core Technologies",
        detail: "AdaCore vendor marker",
        confidence: 82,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"GNAT_FILE_NAME_CASE_SENSITIVE",
        detail: "GNAT runtime configuration symbol",
        confidence: 84,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"ada__io_exceptions",
        detail: "GNAT Ada.IO_Exceptions runtime unit symbol",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"ada__strings",
        detail: "GNAT Ada.Strings runtime unit symbol",
        confidence: 78,
        support: SupportRoute::NativeDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "cx_Freeze",
        pattern: b"cx_Freeze: Python error in main script",
        detail: "cx_Freeze frozen main-script bootstrap banner",
        confidence: 90,
        support: SupportRoute::PyDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "cx_Freeze",
        pattern: b"cx_Freeze Fatal Error",
        detail: "cx_Freeze frozen bootstrap fatal-error banner",
        confidence: 88,
        support: SupportRoute::PyDecompile,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: ".NET single-file bundle",
        pattern: b"DOTNET_BUNDLE_EXTRACT_BASE_DIR",
        detail: ".NET apphost single-file bundle extraction env-var marker",
        confidence: 88,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Safengine",
        pattern: b"Safengine",
        detail: "Safengine Shielden protector banner",
        confidence: 82,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Safengine",
        pattern: b".sedata",
        detail: "Safengine Shielden section",
        confidence: 84,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Denuvo",
        pattern: b".arch",
        detail: "Denuvo Anti-Tamper section marker",
        confidence: 78,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::PeSectionName,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Denuvo",
        pattern: b"Denuvo",
        detail: "Denuvo Anti-Tamper banner",
        confidence: 80,
        support: SupportRoute::DetectCarveOnly,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Makeself",
        pattern: b"This archive was made with makeself",
        detail: "Makeself self-extracting shell archive header",
        confidence: 90,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Makeself",
        pattern: b"# This script was generated using Makeself",
        detail: "Makeself generated launcher script marker",
        confidence: 88,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Anywhere,
    },
    ByteSig {
        kind: IdentityKind::Format,
        name: "DxLib archive",
        pattern: b"DX\x01\x00",
        detail: "DxLib DXA archive magic (version 1)",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Structural,
    },
    ByteSig {
        kind: IdentityKind::Format,
        name: "DxLib archive",
        pattern: b"DX\x02\x00",
        detail: "DxLib DXA archive magic (version 2)",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
        anchor: SigAnchor::Structural,
    },
];

fn dotnet_metadata_stream(bytes: &[u8]) -> Option<&'static str> {
    let window: &[u8] = &bytes[..bytes.len().min(SCAN_LIMIT)];
    let mut from: usize = 0;
    for _ in 0..MAX_METADATA_ROOT_PROBES {
        let at: usize = from + find_subslice(window.get(from..)?, DOTNET_METADATA_ROOT)?;
        if let Some(stream) = metadata_root_stream(window, at) {
            return Some(stream);
        }
        from = at + 1;
    }
    None
}

fn metadata_root_stream(bytes: &[u8], root: usize) -> Option<&'static str> {
    let u16_at = |offset: usize| -> Option<u16> {
        let raw: &[u8] = bytes.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_le_bytes([raw[0], raw[1]]))
    };
    if u16_at(root + 4)? != 1
        || u16_at(root + 6)? != 1
        || read_u32_le_at(bytes, root + 8).ok()? != 0
    {
        return None;
    }
    let version_len: usize = read_u32_le_at(bytes, root + 12).ok()? as usize;
    if version_len == 0 || version_len > MAX_METADATA_VERSION_BYTES {
        return None;
    }
    let version: &[u8] = bytes.get(root + 16..root + 16 + version_len)?;
    if version.first() != Some(&b'v') {
        return None;
    }
    let streams_at: usize = root + 16 + version_len.next_multiple_of(4);
    let stream_count: usize = usize::from(u16_at(streams_at + 2)?);
    if stream_count == 0 || stream_count > MAX_METADATA_STREAMS {
        return None;
    }
    let mut cursor: usize = streams_at + 4;
    let mut found: Option<&'static str> = None;
    for _ in 0..stream_count {
        let name_at: usize = cursor + 8;
        let tail: &[u8] = bytes.get(name_at..)?;
        let name_len: usize = tail
            .iter()
            .take(MAX_METADATA_STREAM_NAME)
            .position(|&b: &u8| b == 0)?;
        let name: &[u8] = &tail[..name_len];
        if name.first() != Some(&b'#') {
            return None;
        }
        match name {
            b"#~" => found = Some("#~"),
            b"#-" => found = found.or(Some("#-")),
            _ => {}
        }
        cursor = name_at + (name_len + 1).next_multiple_of(4);
    }
    found
}

fn detect_format(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(PE_MAGIC) {
        "pe"
    } else if bytes.starts_with(ELF_MAGIC) {
        "elf"
    } else if bytes.starts_with(MACHO_LE) || bytes.starts_with(MACHO_BE) {
        "macho"
    } else if bytes.starts_with(MACHO_FAT) {
        "macho-fat"
    } else {
        detect_format_structural(bytes)
    }
}

fn detect_format_structural(bytes: &[u8]) -> &'static str {
    use disrobe_binfmt::StructuralFormat;
    match disrobe_binfmt::identify_by_structure(bytes) {
        Some(StructuralFormat::Pe) => "pe",
        Some(StructuralFormat::Elf) => "elf",
        Some(StructuralFormat::MachO) => "macho",
        Some(StructuralFormat::MachOFat) => "macho-fat",
        _ => "unknown",
    }
}

fn bytes_find(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let window: &[u8] = &haystack[..haystack.len().min(SCAN_LIMIT)];
    let first: u8 = needle[0];
    let mut from: usize = 0;
    while let Some(rel) = window[from..].iter().position(|&b: &u8| b == first) {
        let at: usize = from + rel;
        if window[at..].starts_with(needle) {
            return true;
        }
        from = at + 1;
    }
    false
}

fn signature_matches(
    sig: &ByteSig,
    bytes: &[u8],
    pe: Option<&PeImage>,
    anchors: &AnchorRegions,
) -> bool {
    match sig.anchor {
        SigAnchor::Anywhere => bytes_find(bytes, sig.pattern),
        SigAnchor::PeSectionName => pe.is_some_and(|image: &PeImage| {
            image
                .sections
                .iter()
                .any(|section| section.name_trimmed() == sig.pattern)
        }),
        SigAnchor::Structural => anchors.find(bytes, sig.pattern).is_some(),
    }
}

#[must_use]
pub fn detect(bytes: &[u8], now_secs: u64) -> IdentityReport {
    let format: &'static str = detect_format(bytes);
    let pe: Option<PeImage> = if format == "pe" {
        parse_pe_image(bytes).ok()
    } else {
        None
    };
    let anchors: AnchorRegions = AnchorRegions::of(bytes, pe.as_ref());
    let mut hits: Vec<IdentityHit> = Vec::new();
    for sig in SIGNATURES {
        if signature_matches(sig, bytes, pe.as_ref(), &anchors) {
            hits.push(IdentityHit {
                kind: sig.kind,
                name: sig.name.to_owned(),
                detail: sig.detail.to_owned(),
                confidence: sig.confidence,
                support: sig.support,
            });
        }
    }
    if let Some(stream) = dotnet_metadata_stream(bytes) {
        hits.push(IdentityHit {
            kind: IdentityKind::Compiler,
            name: ".NET".to_owned(),
            detail: format!(".NET metadata root (BSJB) declaring a {stream} table stream"),
            confidence: 70,
            support: SupportRoute::DotnetDecompile,
        });
    }
    if format == "pe"
        && let Some(rich) = pe_rich_summary(bytes)
    {
        let detail: String = rich.linker_build.map_or_else(
            || {
                format!(
                    "Rich header build stamp with {} comp.id entries",
                    rich.entries
                )
            },
            |build: u16| format!("Rich header lists link.exe 14.x build {build}"),
        );
        hits.push(IdentityHit {
            kind: IdentityKind::Linker,
            name: "MSVC link".to_owned(),
            detail,
            confidence: 85,
            support: SupportRoute::NativeDecompile,
        });
    }
    if format == "pe"
        && !hits.iter().any(|h: &IdentityHit| {
            h.kind == IdentityKind::Packer && h.support == SupportRoute::NativeUnpack
        })
        && let Some(runtime) = crate::runtime_image::detect_runtime_decrypted(bytes)
    {
        hits.push(IdentityHit {
            kind: IdentityKind::Protector,
            name: crate::runtime_image::RUNTIME_DECRYPTED_VERDICT.to_owned(),
            detail: runtime.summary(),
            confidence: 90,
            support: SupportRoute::RuntimeOnly,
        });
    }
    let authenticode: Option<AuthenticodeReport> = if format == "pe" {
        let report: AuthenticodeReport = crate::authenticode::verify(bytes, now_secs);
        (report.verdict != AuthenticodeVerdict::NoSignature).then(|| {
            hits.push(IdentityHit {
                kind: IdentityKind::Sign,
                name: "Authenticode".to_owned(),
                detail: format!(
                    "certificate table in the security directory; Authenticode verdict: {}",
                    report.verdict.label()
                ),
                confidence: 95,
                support: SupportRoute::SignatureInspect,
            });
            report
        })
    } else {
        None
    };
    dedup_hits(&mut hits);
    IdentityReport {
        format: format.to_owned(),
        hits,
        authenticode,
    }
}

fn dedup_hits(hits: &mut Vec<IdentityHit>) {
    hits.sort_by(|a: &IdentityHit, b: &IdentityHit| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.name.cmp(&b.name))
    });
    let mut seen: std::collections::BTreeSet<(IdentityKind, String)> =
        std::collections::BTreeSet::new();
    hits.retain(|h: &IdentityHit| seen.insert((h.kind, h.name.clone())));
}

struct RichSummary {
    entries: usize,
    linker_build: Option<u16>,
}

fn pe_rich_summary(bytes: &[u8]) -> Option<RichSummary> {
    let scan: &[u8] = &bytes[..bytes.len().min(4096)];
    let rich_pos: usize = find_subslice(scan, RICH_TAG)?;
    let key: u32 = read_u32_le_at(scan, rich_pos + 4).ok()?;
    let mut cursor: usize = rich_pos;
    let mut dans: Option<usize> = None;
    while cursor >= 4 {
        cursor -= 4;
        if read_u32_le_at(scan, cursor).ok()? ^ key == DANS_TAG {
            dans = Some(cursor);
            break;
        }
    }
    let mut entry: usize = dans? + 16;
    let mut summary: RichSummary = RichSummary {
        entries: 0,
        linker_build: None,
    };
    while entry + 8 <= rich_pos {
        let comp_id: u32 = read_u32_le_at(scan, entry).ok()? ^ key;
        summary.entries += 1;
        if (comp_id >> 16) as u16 == RICH_LINKER_1400_PRODUCT {
            summary.linker_build = Some((comp_id & 0xFFFF) as u16);
        }
        entry += 8;
    }
    Some(summary)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const NOW_SECS: u64 = 1_798_761_600;

    use crate::test_support::{SyntheticSection, pe64_layout};

    const CODE: u32 = 0x6000_0020;
    const DATA: u32 = 0x4000_0040;

    fn hit_names(bytes: &[u8]) -> Vec<String> {
        detect(bytes, NOW_SECS)
            .hits
            .into_iter()
            .map(|h: IdentityHit| h.name)
            .collect()
    }

    fn pe_with_rdata(name: [u8; 8], rdata: &[u8]) -> Vec<u8> {
        let mut data: Vec<u8> = vec![0u8; 0x200];
        data[0x40..0x40 + rdata.len()].copy_from_slice(rdata);
        pe64_layout(
            &[
                SyntheticSection::backed(*b".text\0\0\0", 0x1000, vec![0xC3; 0x200], CODE),
                SyntheticSection::backed(name, 0x2000, data, DATA),
            ],
            0x1000,
        )
    }

    #[test]
    fn detects_upx_in_pe() {
        let mut bytes: Vec<u8> = pe_with_rdata(*b".rdata\0\0", b"");
        bytes[0x3E0..0x3E4].copy_from_slice(b"UPX!");
        let report: IdentityReport = detect(&bytes, NOW_SECS);
        assert_eq!(report.format, "pe");
        let hit: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == "UPX")
            .expect("upx hit");
        assert_eq!(hit.kind, IdentityKind::Packer);
        assert_eq!(hit.support, SupportRoute::NativeUnpack);
    }

    #[test]
    fn packer_magic_inside_section_data_is_not_a_packer() {
        for magic in [&b"UPX!"[..], b"PEC2", b"FSG!", b"DX\x02\x00"] {
            let names: Vec<String> = hit_names(&pe_with_rdata(*b".rdata\0\0", magic));
            assert!(
                !names.iter().any(|n: &String| {
                    matches!(n.as_str(), "UPX" | "PECompact" | "FSG" | "DxLib archive")
                }),
                "{:?} inside .rdata claimed {names:?}",
                String::from_utf8_lossy(magic)
            );
        }
    }

    #[test]
    fn section_marker_counts_only_as_a_section_name() {
        let cases: &[([u8; 8], &str, SupportRoute)] = &[
            (*b".vmp0\0\0\0", "VMProtect", SupportRoute::DetectCarveOnly),
            (*b"MEW\0\0\0\0\0", "MEW", SupportRoute::NativeUnpack),
            (*b".wixburn", "WiX Burn", SupportRoute::ContainerExtract),
            (*b".sedata\0", "Safengine", SupportRoute::DetectCarveOnly),
            (*b".arch\0\0\0", "Denuvo", SupportRoute::DetectCarveOnly),
        ];
        for (name, family, route) in cases {
            let report: IdentityReport = detect(&pe_with_rdata(*name, b""), NOW_SECS);
            let hit: &IdentityHit = report
                .hits
                .iter()
                .find(|h: &&IdentityHit| h.name == *family)
                .unwrap_or_else(|| panic!("section {family} not detected: {:?}", report.hits));
            assert_eq!(hit.support, *route, "{family} route");
            let text: String = String::from_utf8_lossy(name)
                .trim_end_matches('\0')
                .to_owned();
            let in_data: Vec<String> = hit_names(&pe_with_rdata(
                *b".rdata\0\0",
                format!("{text}\0").as_bytes(),
            ));
            assert!(
                !in_data.iter().any(|n: &String| n == family),
                "{text} inside .rdata claimed {family}: {in_data:?}"
            );
        }
    }

    #[test]
    fn dxlib_archive_magic_at_the_file_start_is_an_archive() {
        let mut archive: Vec<u8> = b"DX\x02\x00".to_vec();
        archive.extend(std::iter::repeat_n(0u8, 60));
        assert!(
            hit_names(&archive)
                .iter()
                .any(|n: &String| n == "DxLib archive")
        );
    }

    #[test]
    fn authenticode_is_claimed_from_the_security_directory_only() {
        let oid: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
        let report: IdentityReport = detect(&pe_with_rdata(*b".rdata\0\0", oid), NOW_SECS);
        assert!(
            !report
                .hits
                .iter()
                .any(|h: &IdentityHit| h.kind == IdentityKind::Sign),
            "a PKCS#7 OID in section data is not a signature: {:?}",
            report.hits
        );
        assert!(report.authenticode.is_none());
        let mut signed: Vec<u8> = pe_with_rdata(*b".rdata\0\0", b"");
        let table_at: u32 = signed.len() as u32;
        let mut certificate: Vec<u8> = Vec::new();
        certificate.extend_from_slice(&16u32.to_le_bytes());
        certificate.extend_from_slice(&0x0200u16.to_le_bytes());
        certificate.extend_from_slice(&0x0002u16.to_le_bytes());
        certificate.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x01, 0, 0, 0]);
        signed.extend_from_slice(&certificate);
        let directory: usize = 0x80 + 4 + 20 + 112 + 4 * 8;
        signed[directory..directory + 4].copy_from_slice(&table_at.to_le_bytes());
        signed[directory + 4..directory + 8].copy_from_slice(&16u32.to_le_bytes());
        let report: IdentityReport = detect(&signed, NOW_SECS);
        let sign: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.kind == IdentityKind::Sign)
            .unwrap_or_else(|| panic!("security directory signature missing: {:?}", report.hits));
        assert!(
            sign.detail.contains("security directory"),
            "{}",
            sign.detail
        );
        assert!(report.authenticode.is_some());
    }

    #[test]
    fn rich_linker_detail_names_the_link_build() {
        let mut bytes: Vec<u8> = pe_with_rdata(*b".rdata\0\0", b"");
        let key: u32 = 0x1357_9BDF;
        let mut rich: Vec<u8> = Vec::new();
        for word in [0x536E_6144u32, 0, 0, 0] {
            rich.extend_from_slice(&(word ^ key).to_le_bytes());
        }
        for (product, build, count) in [(0x0104u32, 35207u32, 8u32), (0x0102, 35229, 1)] {
            rich.extend_from_slice(&(((product << 16) | build) ^ key).to_le_bytes());
            rich.extend_from_slice(&(count ^ key).to_le_bytes());
        }
        rich.extend_from_slice(b"Rich");
        rich.extend_from_slice(&key.to_le_bytes());
        bytes[0x40..0x40 + rich.len()].copy_from_slice(&rich);
        let report: IdentityReport = detect(&bytes, NOW_SECS);
        let link: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == "MSVC link")
            .unwrap_or_else(|| panic!("rich linker missing: {:?}", report.hits));
        assert_eq!(link.detail, "Rich header lists link.exe 14.x build 35229");
    }

    #[test]
    fn runtime_decrypted_image_is_a_named_hit() {
        use crate::test_support::{SyntheticSection, pe64_layout};
        let mut state: u32 = 0x1234_5678;
        let sealed: Vec<u8> = (0..0x4_0000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 8) as u8
            })
            .collect();
        let bytes: Vec<u8> = pe64_layout(
            &[
                SyntheticSection::unbacked(*b".text\0\0\0", 0x1000, 0x20_0000, 0x6000_0020),
                SyntheticSection::backed(*b".seal\0\0\0", 0x21_0000, sealed, 0xE000_0020),
            ],
            0x21_0400,
        );
        let report: IdentityReport = detect(&bytes, NOW_SECS);
        let hit: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == crate::runtime_image::RUNTIME_DECRYPTED_VERDICT)
            .unwrap_or_else(|| panic!("runtime-decrypted hit missing: {:?}", report.hits));
        assert_eq!(hit.kind, IdentityKind::Protector);
        assert_eq!(hit.support, SupportRoute::RuntimeOnly);
        assert!(
            hit.detail.contains(".text (2097152 bytes)"),
            "{}",
            hit.detail
        );
        assert!(hit.detail.contains(".seal"), "{}", hit.detail);
    }

    #[test]
    fn detects_go_and_routes_to_go_decompile() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b" Go build ID: \"abc\"");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        let go: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == "Go")
            .expect("go hit");
        assert_eq!(go.support, SupportRoute::GoDecompile);
    }

    #[test]
    fn detects_elf_compiler_routes_native() {
        let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b"GCC: (Ubuntu 13.2.0) 13.2.0");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        assert_eq!(report.format, "elf");
        let gcc: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == "GCC")
            .expect("gcc hit");
        assert_eq!(gcc.support, SupportRoute::NativeDecompile);
    }

    #[test]
    fn detects_elf_go_buildid_note() {
        let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b"section .note.go.buildid here");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        assert_eq!(report.format, "elf");
        let go: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == "Go")
            .expect("go hit");
        assert_eq!(go.support, SupportRoute::GoDecompile);
    }

    #[test]
    fn detects_macho_swift_sections() {
        let mut buf: Vec<u8> = vec![0xCF, 0xFA, 0xED, 0xFE];
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b"__swift5_proto __objc_classlist");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        assert_eq!(report.format, "macho");
        assert!(report.hits.iter().any(|h: &IdentityHit| h.name == "Swift"));
        assert!(
            report
                .hits
                .iter()
                .any(|h: &IdentityHit| h.name == "Objective-C")
        );
    }

    #[test]
    fn every_signature_has_a_real_support_route() {
        for sig in SIGNATURES {
            assert!(
                !sig.support.command().is_empty(),
                "signature {} must map to a disrobe support command",
                sig.name
            );
        }
    }

    #[test]
    fn signature_table_has_no_duplicate_pattern() {
        let mut seen: std::collections::BTreeSet<&[u8]> = std::collections::BTreeSet::new();
        for sig in SIGNATURES {
            assert!(
                seen.insert(sig.pattern),
                "duplicate signature pattern {:?} ({})",
                String::from_utf8_lossy(sig.pattern),
                sig.name
            );
        }
    }

    #[test]
    fn new_packer_and_installer_markers_detect_and_route() {
        let cases: &[(&[u8], &str, IdentityKind, SupportRoute)] = &[
            (
                b"NODE_SEA_BLOB",
                "Node SEA",
                IdentityKind::Installer,
                SupportRoute::ContainerExtract,
            ),
            (
                b"CodeVirtualizer",
                "Code Virtualizer",
                IdentityKind::Protector,
                SupportRoute::DetectCarveOnly,
            ),
            (
                b"DotfuscatorAttribute",
                "Dotfuscator",
                IdentityKind::Protector,
                SupportRoute::DotnetDecompile,
            ),
            (
                b".asprotect",
                "ASProtect",
                IdentityKind::Packer,
                SupportRoute::NativeUnpack,
            ),
            (
                b"Intel(R) C++",
                "Intel C++",
                IdentityKind::Compiler,
                SupportRoute::NativeDecompile,
            ),
        ];
        for (marker, name, kind, route) in cases {
            let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
            buf.extend(std::iter::repeat_n(0u8, 64));
            buf.extend_from_slice(marker);
            let report: IdentityReport = detect(&buf, NOW_SECS);
            let hit: &IdentityHit = report
                .hits
                .iter()
                .find(|h: &&IdentityHit| h.name == *name)
                .unwrap_or_else(|| panic!("marker {name} not detected"));
            assert_eq!(hit.kind, *kind, "{name} kind");
            assert_eq!(hit.support, *route, "{name} route");
        }
    }

    #[test]
    fn clean_binary_has_no_false_hits() {
        let buf: Vec<u8> = (0..2048u16)
            .map(|i: u16| (i.wrapping_mul(7) & 0xff) as u8)
            .collect();
        let report: IdentityReport = detect(&buf, NOW_SECS);
        assert!(
            report.hits.is_empty(),
            "random data must not match: {:?}",
            report.hits
        );
    }

    #[test]
    fn new_format_compiler_markers_detect_and_route() {
        let cases: &[(&[u8], &str, IdentityKind, SupportRoute)] = &[
            (
                b"MW CodeWarrior",
                "CodeWarrior",
                IdentityKind::Compiler,
                SupportRoute::NativeDecompile,
            ),
            (
                b"GNAT_FILE_NAME_CASE_SENSITIVE",
                "GNAT (FSF/community)",
                IdentityKind::Compiler,
                SupportRoute::NativeDecompile,
            ),
            (
                b"Ada Core Technologies",
                "GNAT (FSF/community)",
                IdentityKind::Compiler,
                SupportRoute::NativeDecompile,
            ),
            (
                b"cx_Freeze: Python error in main script",
                "cx_Freeze",
                IdentityKind::Installer,
                SupportRoute::PyDecompile,
            ),
            (
                b"DOTNET_BUNDLE_EXTRACT_BASE_DIR",
                ".NET single-file bundle",
                IdentityKind::Installer,
                SupportRoute::ContainerExtract,
            ),
            (
                b"Denuvo",
                "Denuvo",
                IdentityKind::Protector,
                SupportRoute::DetectCarveOnly,
            ),
            (
                b"This archive was made with makeself",
                "Makeself",
                IdentityKind::Installer,
                SupportRoute::ContainerExtract,
            ),
        ];
        for (marker, name, kind, route) in cases {
            let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
            buf.extend(std::iter::repeat_n(0u8, 64));
            buf.extend_from_slice(marker);
            let report: IdentityReport = detect(&buf, NOW_SECS);
            let hit: &IdentityHit = report
                .hits
                .iter()
                .find(|h: &&IdentityHit| h.name == *name)
                .unwrap_or_else(|| panic!("marker {name} not detected"));
            assert_eq!(hit.kind, *kind, "{name} kind");
            assert_eq!(hit.support, *route, "{name} route");
        }
    }

    #[test]
    fn lone_metadata_stream_marker_does_not_flag_dotnet() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 512));
        buf.extend_from_slice(b"random compressed bytes \x00#~\xb5 more \x00#- tail");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        assert!(
            !report.hits.iter().any(|h: &IdentityHit| h.name == ".NET"),
            "#~/#- without a BSJB metadata root must not be flagged as .NET: {:?}",
            report.hits
        );
    }

    fn metadata_root(streams: &[&[u8]]) -> Vec<u8> {
        let mut root: Vec<u8> = b"BSJB".to_vec();
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&0u32.to_le_bytes());
        root.extend_from_slice(&12u32.to_le_bytes());
        root.extend_from_slice(b"v4.0.30319\0\0");
        root.extend_from_slice(&0u16.to_le_bytes());
        root.extend_from_slice(&(streams.len() as u16).to_le_bytes());
        for name in streams {
            root.extend_from_slice(&0x6Cu32.to_le_bytes());
            root.extend_from_slice(&0x10u32.to_le_bytes());
            root.extend_from_slice(name);
            root.push(0);
            while root.len() % 4 != 0 {
                root.push(0);
            }
        }
        root
    }

    #[test]
    fn bsjb_constant_and_stream_strings_outside_a_root_do_not_flag_dotnet() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 256));
        buf.extend_from_slice(b"\x81\x38BSJB\x0f\x85 cmp; strings: #~\x00#-\x00#Strings\x00");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        assert!(
            !report.hits.iter().any(|h: &IdentityHit| h.name == ".NET"),
            "BSJB in code beside stream-name strings is not a metadata root: {:?}",
            report.hits
        );
    }

    #[test]
    fn metadata_stream_under_bsjb_root_flags_dotnet() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 256));
        buf.extend_from_slice(&metadata_root(&[
            b"#~",
            b"#Strings",
            b"#US",
            b"#GUID",
            b"#Blob",
        ]));
        let report: IdentityReport = detect(&buf, NOW_SECS);
        let dotnet: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == ".NET")
            .expect(".NET metadata stream under a BSJB root must be flagged");
        assert_eq!(dotnet.kind, IdentityKind::Compiler);
        assert_eq!(dotnet.support, SupportRoute::DotnetDecompile);
    }

    #[test]
    fn bsjb_root_without_stream_marker_does_not_flag() {
        let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
        buf.extend_from_slice(b"BSJB but no metadata stream marker present here");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        assert!(
            !report.hits.iter().any(|h: &IdentityHit| h.name == ".NET"),
            "BSJB alone (no #~/#-) must not be flagged as .NET: {:?}",
            report.hits
        );
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let inputs: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0u8],
            b"M".to_vec(),
            b"MZ".to_vec(),
            vec![0x7F, b'E', b'L'],
            b"Rich".to_vec(),
            b"DanS".to_vec(),
            vec![0xFF; 3],
            b"BSJB".to_vec(),
            b"#~".to_vec(),
            (0..255u8).collect(),
            (0..4096u16)
                .map(|i: u16| (i.wrapping_mul(31) & 0xff) as u8)
                .collect(),
        ];
        for input in &inputs {
            let report: IdentityReport = detect(input, NOW_SECS);
            let _ = report.format;
            let _ = report.hits.len();
        }
        let mut header_only: Vec<u8> = b"MZ".to_vec();
        header_only.extend(std::iter::repeat_n(0x90u8, 60));
        header_only.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        let report: IdentityReport = detect(&header_only, NOW_SECS);
        assert_eq!(report.format, "pe");
    }

    #[test]
    fn dedups_repeated_signatures() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend_from_slice(b"UPX! padding UPX! again UPX!");
        let report: IdentityReport = detect(&buf, NOW_SECS);
        let upx_count: usize = report
            .hits
            .iter()
            .filter(|h: &&IdentityHit| h.name == "UPX")
            .count();
        assert_eq!(upx_count, 1, "repeated UPX markers collapse to one hit");
    }
}
