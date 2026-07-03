use serde::{Deserialize, Serialize};

const PE_MAGIC: &[u8; 2] = b"MZ";
const ELF_MAGIC: &[u8; 4] = &[0x7F, b'E', b'L', b'F'];
const MACHO_LE: &[u8; 4] = &[0xCF, 0xFA, 0xED, 0xFE];
const MACHO_BE: &[u8; 4] = &[0xFE, 0xED, 0xFA, 0xCF];
const MACHO_FAT: &[u8; 4] = &[0xCA, 0xFE, 0xBA, 0xBE];
const RICH_TAG: &[u8; 4] = b"Rich";
const DANS_TAG: u32 = 0x536E_6144;
const SCAN_LIMIT: usize = 4 * 1024 * 1024;
const DOTNET_METADATA_ROOT: &[u8; 4] = b"BSJB";

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
}

impl SupportRoute {
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
}

struct ByteSig {
    kind: IdentityKind,
    name: &'static str,
    pattern: &'static [u8],
    detail: &'static str,
    confidence: u8,
    support: SupportRoute,
}

const SIGNATURES: &[ByteSig] = &[
    ByteSig {
        kind: IdentityKind::Packer,
        name: "UPX",
        pattern: b"UPX!",
        detail: "UPX packer magic",
        confidence: 95,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "ASPack",
        pattern: b".aspack",
        detail: "ASPack section",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "ASPack",
        pattern: b".adata",
        detail: "ASPack data section",
        confidence: 70,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "PECompact",
        pattern: b"PEC2",
        detail: "PECompact marker",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "FSG",
        pattern: b"FSG!",
        detail: "FSG packer magic",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "MEW",
        pattern: b"MEW",
        detail: "MEW packer marker",
        confidence: 70,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "MPRESS",
        pattern: b".MPRESS1",
        detail: "MPRESS section",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "Petite",
        pattern: b".petite",
        detail: "Petite section",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "NSPack",
        pattern: b".nsp0",
        detail: "NSPack section",
        confidence: 85,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "kkrunchy",
        pattern: b"kkrunchy",
        detail: "kkrunchy marker",
        confidence: 90,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Themida/WinLicense",
        pattern: b".themida",
        detail: "Themida section",
        confidence: 95,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Themida/WinLicense",
        pattern: b".winlice",
        detail: "WinLicense section",
        confidence: 90,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "VMProtect",
        pattern: b".vmp0",
        detail: "VMProtect section",
        confidence: 95,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "VMProtect",
        pattern: b".vmp1",
        detail: "VMProtect section",
        confidence: 90,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Enigma",
        pattern: b".enigma1",
        detail: "Enigma Protector section",
        confidence: 90,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Obsidium",
        pattern: b"obsidium",
        detail: "Obsidium marker",
        confidence: 85,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Armadillo",
        pattern: b"PVZURY",
        detail: "Armadillo string marker",
        confidence: 80,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "ConfuserEx",
        pattern: b"ConfusedByAttribute",
        detail: ".NET ConfuserEx marker",
        confidence: 90,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Go",
        pattern: b"Go build ID:",
        detail: "Go build id",
        confidence: 95,
        support: SupportRoute::GoDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Go",
        pattern: b"go.buildid",
        detail: "Go build id section",
        confidence: 90,
        support: SupportRoute::GoDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Rust",
        pattern: b"rustc/",
        detail: "Rust compiler path",
        confidence: 90,
        support: SupportRoute::RustRecover,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Rust",
        pattern: b"/rust/library/",
        detail: "Rust stdlib path",
        confidence: 85,
        support: SupportRoute::RustRecover,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "MinGW",
        pattern: b"Mingw-w64",
        detail: "MinGW runtime marker",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GCC",
        pattern: b"GCC: (",
        detail: "GCC compiler comment",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Clang/LLVM",
        pattern: b"clang version",
        detail: "Clang version string",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Delphi",
        pattern: b"Borland Delphi",
        detail: "Delphi marker",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Embarcadero",
        pattern: b"Embarcadero Delphi",
        detail: "Embarcadero Delphi marker",
        confidence: 90,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Nim",
        pattern: b"NimMain",
        detail: "Nim runtime symbol",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Free Pascal",
        pattern: b"FPC ",
        detail: "Free Pascal marker",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: ".NET",
        pattern: b"_CorExeMain",
        detail: ".NET CLR entry import",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "NSIS",
        pattern: b"NullsoftInst",
        detail: "NSIS installer",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Inno Setup",
        pattern: b"Inno Setup Setup Data",
        detail: "Inno Setup data",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "InstallShield",
        pattern: b"InstallShield",
        detail: "InstallShield marker",
        confidence: 85,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "WiX/MSI",
        pattern: b"Windows Installer",
        detail: "MSI/WiX marker",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "AutoIt",
        pattern: b"AU3!EA06",
        detail: "compiled AutoIt3 script",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "PyInstaller",
        pattern: b"pyi-windows-manifest-filename",
        detail: "PyInstaller marker",
        confidence: 85,
        support: SupportRoute::PyDecompile,
    },
    ByteSig {
        kind: IdentityKind::Sign,
        name: "Authenticode",
        pattern: b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02",
        detail: "PKCS#7 signature OID",
        confidence: 70,
        support: SupportRoute::SignatureInspect,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Nuitka",
        pattern: b"NUITKA_VERSION",
        detail: "Nuitka onefile/standalone marker",
        confidence: 90,
        support: SupportRoute::PyDecompile,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "py2exe",
        pattern: b"PYTHONSCRIPT",
        detail: "py2exe embedded script resource",
        confidence: 85,
        support: SupportRoute::PyDecompile,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Electron",
        pattern: b"electron.asar",
        detail: "Electron app.asar archive",
        confidence: 85,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Bun",
        pattern: b"\n---- Bun! ----\n",
        detail: "Bun standalone executable trailer",
        confidence: 95,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: ".NET Reactor",
        pattern: b".NET Reactor",
        detail: ".NET Reactor protector marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Eazfuscator.NET",
        pattern: b"Eazfuscator.NET",
        detail: "Eazfuscator.NET protector marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Zig",
        pattern: b"zig_panic",
        detail: "Zig panic handler symbol",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Crystal",
        pattern: b"__crystal_main",
        detail: "Crystal runtime entry symbol",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Swift",
        pattern: b"swift_getTypeByMangledNameInContext",
        detail: "Swift runtime symbol",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Haskell/GHC",
        pattern: b"GHC ",
        detail: "GHC runtime marker",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "GNU ld",
        pattern: b"GNU ld ",
        detail: "GNU linker comment",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "LLD",
        pattern: b"Linker: LLD ",
        detail: "LLVM lld linker comment",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Go",
        pattern: b".note.go.buildid",
        detail: "Go ELF build-id note section",
        confidence: 90,
        support: SupportRoute::GoDecompile,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "musl libc",
        pattern: b"/lib/ld-musl-",
        detail: "musl dynamic loader path",
        confidence: 85,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "glibc",
        pattern: b"GNU C Library",
        detail: "glibc runtime banner",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "GNU build-id",
        pattern: b".note.gnu.build-id",
        detail: "GNU ELF build-id note section",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Swift",
        pattern: b"__swift5_proto",
        detail: "Swift 5 protocol-conformance Mach-O section",
        confidence: 90,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Objective-C",
        pattern: b"__objc_classlist",
        detail: "Objective-C class-list Mach-O section",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Swift runtime",
        pattern: b"libswiftCore",
        detail: "Swift core runtime dylib reference",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Flutter/Dart AOT",
        pattern: b"kDartIsolateSnapshotInstructions",
        detail: "Dart AOT isolate snapshot symbol",
        confidence: 85,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "OCaml",
        pattern: b"caml_program",
        detail: "OCaml native runtime entry symbol",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "TinyCC",
        pattern: b"TCC: ",
        detail: "Tiny C Compiler banner",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Intel C++",
        pattern: b"Intel(R) C++",
        detail: "Intel C++ compiler banner",
        confidence: 85,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Intel Fortran",
        pattern: b"Intel(R) Fortran",
        detail: "Intel Fortran compiler banner",
        confidence: 85,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "Watcom",
        pattern: b"WATCOM C/C++",
        detail: "Open Watcom compiler banner",
        confidence: 82,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "AdaCore GNAT",
        pattern: b"GNAT Pro",
        detail: "GNAT Ada runtime marker",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "V Lang",
        pattern: b"v_panic",
        detail: "V language panic symbol",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "D (DMD/LDC)",
        pattern: b"_d_run_main",
        detail: "D runtime entry symbol",
        confidence: 80,
        support: SupportRoute::NativeLangDemangle,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "PyOxidizer",
        pattern: b"pyoxidizer",
        detail: "PyOxidizer embedded interpreter marker",
        confidence: 85,
        support: SupportRoute::PyDecompile,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Node SEA",
        pattern: b"NODE_SEA_BLOB",
        detail: "Node.js single-executable-application blob",
        confidence: 90,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Deno compile",
        pattern: b"d3n0l4nd",
        detail: "Deno compiled binary trailer magic",
        confidence: 90,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "pkg (Vercel)",
        pattern: b"PKG_DUMMY_ENTRYPOINT",
        detail: "Vercel pkg Node snapshot marker",
        confidence: 85,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "WiX Burn",
        pattern: b".wixburn",
        detail: "WiX Burn bootstrapper section",
        confidence: 88,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Squirrel",
        pattern: b"SquirrelTemp",
        detail: "Squirrel.Windows installer marker",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "InstallAnywhere",
        pattern: b"InstallAnywhere",
        detail: "InstallAnywhere installer marker",
        confidence: 82,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Setup Factory",
        pattern: b"Setup Factory",
        detail: "Setup Factory installer marker",
        confidence: 82,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Advanced Installer",
        pattern: b"Advanced Installer",
        detail: "Advanced Installer marker",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Wise Installer",
        pattern: b"WiseMain",
        detail: "Wise installation system marker",
        confidence: 78,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "MoleBox",
        pattern: b".mbx",
        detail: "MoleBox virtualizing packer section",
        confidence: 82,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "Molebox Ultra",
        pattern: b"MoleBox",
        detail: "MoleBox runtime marker",
        confidence: 80,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "RLPack",
        pattern: b".RLPack",
        detail: "RLPack section marker",
        confidence: 82,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "exeStealth",
        pattern: b"exeStealth",
        detail: "exeStealth packer marker",
        confidence: 80,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Packer,
        name: "ASProtect",
        pattern: b".asprotect",
        detail: "ASProtect protector section",
        confidence: 85,
        support: SupportRoute::NativeUnpack,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Code Virtualizer",
        pattern: b"CodeVirtualizer",
        detail: "Oreans Code Virtualizer marker",
        confidence: 85,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "SmartAssembly",
        pattern: b"SmartAssembly.Attributes",
        detail: ".NET SmartAssembly protector marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Dotfuscator",
        pattern: b"DotfuscatorAttribute",
        detail: ".NET Dotfuscator marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Agile.NET",
        pattern: b"AgileDotNetRT",
        detail: "Agile.NET (CliSecure) runtime marker",
        confidence: 85,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Babel.NET",
        pattern: b"BabelAttribute",
        detail: "Babel.NET obfuscator marker",
        confidence: 82,
        support: SupportRoute::DotnetDecompile,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Themida",
        pattern: b"Themida",
        detail: "Themida runtime banner",
        confidence: 80,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "Turbo Linker",
        pattern: b"Turbo Link",
        detail: "Borland Turbo linker marker",
        confidence: 70,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "GNU gold",
        pattern: b"GNU gold ",
        detail: "GNU gold linker comment",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Linker,
        name: "mold",
        pattern: b"mold ",
        detail: "mold linker comment",
        confidence: 72,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "OpenSSL",
        pattern: b"OpenSSL ",
        detail: "OpenSSL version banner",
        confidence: 65,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Qt",
        pattern: b"Qt 6.",
        detail: "Qt 6 runtime version string",
        confidence: 65,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Library,
        name: "Boost",
        pattern: b"boost_version",
        detail: "Boost C++ libraries marker",
        confidence: 60,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "CodeWarrior",
        pattern: b"MW CodeWarrior",
        detail: "Metrowerks CodeWarrior compiler comment",
        confidence: 88,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "CodeWarrior",
        pattern: b"Metrowerks",
        detail: "Metrowerks toolchain marker",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"Ada Core Technologies",
        detail: "AdaCore vendor marker",
        confidence: 82,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"GNAT_FILE_NAME_CASE_SENSITIVE",
        detail: "GNAT runtime configuration symbol",
        confidence: 84,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"ada__io_exceptions",
        detail: "GNAT Ada.IO_Exceptions runtime unit symbol",
        confidence: 80,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Compiler,
        name: "GNAT (FSF/community)",
        pattern: b"ada__strings",
        detail: "GNAT Ada.Strings runtime unit symbol",
        confidence: 78,
        support: SupportRoute::NativeDecompile,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "cx_Freeze",
        pattern: b"cx_Freeze: Python error in main script",
        detail: "cx_Freeze frozen main-script bootstrap banner",
        confidence: 90,
        support: SupportRoute::PyDecompile,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "cx_Freeze",
        pattern: b"cx_Freeze Fatal Error",
        detail: "cx_Freeze frozen bootstrap fatal-error banner",
        confidence: 88,
        support: SupportRoute::PyDecompile,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: ".NET single-file bundle",
        pattern: b"DOTNET_BUNDLE_EXTRACT_BASE_DIR",
        detail: ".NET apphost single-file bundle extraction env-var marker",
        confidence: 88,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Safengine",
        pattern: b"Safengine",
        detail: "Safengine Shielden protector banner",
        confidence: 82,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Safengine",
        pattern: b".sedata",
        detail: "Safengine Shielden section",
        confidence: 84,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Denuvo",
        pattern: b".arch\x00",
        detail: "Denuvo Anti-Tamper section marker",
        confidence: 78,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Protector,
        name: "Denuvo",
        pattern: b"Denuvo",
        detail: "Denuvo Anti-Tamper banner",
        confidence: 80,
        support: SupportRoute::DetectCarveOnly,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Makeself",
        pattern: b"This archive was made with makeself",
        detail: "Makeself self-extracting shell archive header",
        confidence: 90,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Installer,
        name: "Makeself",
        pattern: b"# This script was generated using Makeself",
        detail: "Makeself generated launcher script marker",
        confidence: 88,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Format,
        name: "DxLib archive",
        pattern: b"DX\x01\x00",
        detail: "DxLib DXA archive magic (version 1)",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
    },
    ByteSig {
        kind: IdentityKind::Format,
        name: "DxLib archive",
        pattern: b"DX\x02\x00",
        detail: "DxLib DXA archive magic (version 2)",
        confidence: 80,
        support: SupportRoute::ContainerExtract,
    },
];

fn dotnet_stream_marker(bytes: &[u8]) -> Option<&'static str> {
    if bytes_find(bytes, b"#~") {
        Some("#~")
    } else if bytes_find(bytes, b"#-") {
        Some("#-")
    } else {
        None
    }
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

#[must_use]
pub fn detect(bytes: &[u8]) -> IdentityReport {
    let format: &'static str = detect_format(bytes);
    let mut hits: Vec<IdentityHit> = Vec::new();
    for sig in SIGNATURES {
        if bytes_find(bytes, sig.pattern) {
            hits.push(IdentityHit {
                kind: sig.kind,
                name: sig.name.to_owned(),
                detail: sig.detail.to_owned(),
                confidence: sig.confidence,
                support: sig.support,
            });
        }
    }
    if bytes_find(bytes, DOTNET_METADATA_ROOT)
        && let Some(stream) = dotnet_stream_marker(bytes)
    {
        hits.push(IdentityHit {
            kind: IdentityKind::Compiler,
            name: ".NET".to_owned(),
            detail: format!(".NET metadata stream ({stream}) under a BSJB metadata root"),
            confidence: 70,
            support: SupportRoute::DotnetDecompile,
        });
    }
    if format == "pe"
        && let Some((linker_major, linker_minor)) = pe_rich_linker(bytes)
    {
        hits.push(IdentityHit {
            kind: IdentityKind::Linker,
            name: "MSVC link".to_owned(),
            detail: format!("Rich header linker {linker_major}.{linker_minor}"),
            confidence: 85,
            support: SupportRoute::NativeDecompile,
        });
    }
    dedup_hits(&mut hits);
    IdentityReport {
        format: format.to_owned(),
        hits,
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

fn pe_rich_linker(bytes: &[u8]) -> Option<(u16, u16)> {
    let scan: &[u8] = &bytes[..bytes.len().min(4096)];
    let rich_pos: usize = find_subslice(scan, RICH_TAG)?;
    let key: u32 = read_u32_le(scan, rich_pos + 4)?;
    let mut cursor: usize = rich_pos;
    while cursor >= 4 {
        cursor -= 4;
        let raw: u32 = read_u32_le(scan, cursor)?;
        if raw ^ key == DANS_TAG {
            let entry: u32 = read_u32_le(scan, cursor + 8)? ^ key;
            let product_id: u16 = (entry >> 16) as u16;
            let build: u16 = (entry & 0xFFFF) as u16;
            return Some((product_id, build));
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
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
    fn detects_upx_in_pe() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 512));
        buf.extend_from_slice(b"some data UPX! more data");
        let report: IdentityReport = detect(&buf);
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
    fn detects_go_and_routes_to_go_decompile() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b".vmp0\x00\x00\x00 Go build ID: \"abc\"");
        let report: IdentityReport = detect(&buf);
        let go: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == "Go")
            .expect("go hit");
        assert_eq!(go.support, SupportRoute::GoDecompile);
        let vmp: &IdentityHit = report
            .hits
            .iter()
            .find(|h: &&IdentityHit| h.name == "VMProtect")
            .expect("vmp hit");
        assert_eq!(vmp.support, SupportRoute::DetectCarveOnly);
    }

    #[test]
    fn detects_elf_compiler_routes_native() {
        let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
        buf.extend(std::iter::repeat_n(0u8, 64));
        buf.extend_from_slice(b"GCC: (Ubuntu 13.2.0) 13.2.0");
        let report: IdentityReport = detect(&buf);
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
        let report: IdentityReport = detect(&buf);
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
        let report: IdentityReport = detect(&buf);
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
                b".wixburn",
                "WiX Burn",
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
            let report: IdentityReport = detect(&buf);
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
        let report: IdentityReport = detect(&buf);
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
                b".sedata",
                "Safengine",
                IdentityKind::Protector,
                SupportRoute::DetectCarveOnly,
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
            (
                b"DX\x01\x00",
                "DxLib archive",
                IdentityKind::Format,
                SupportRoute::ContainerExtract,
            ),
        ];
        for (marker, name, kind, route) in cases {
            let mut buf: Vec<u8> = vec![0x7F, b'E', b'L', b'F'];
            buf.extend(std::iter::repeat_n(0u8, 64));
            buf.extend_from_slice(marker);
            let report: IdentityReport = detect(&buf);
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
        let report: IdentityReport = detect(&buf);
        assert!(
            !report.hits.iter().any(|h: &IdentityHit| h.name == ".NET"),
            "#~/#- without a BSJB metadata root must not be flagged as .NET: {:?}",
            report.hits
        );
    }

    #[test]
    fn metadata_stream_under_bsjb_root_flags_dotnet() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend(std::iter::repeat_n(0u8, 256));
        buf.extend_from_slice(b"BSJBv4.0.30319\x00\x00#~\x00#Strings\x00#Blob");
        let report: IdentityReport = detect(&buf);
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
        let report: IdentityReport = detect(&buf);
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
            let report: IdentityReport = detect(input);
            let _ = report.format;
            let _ = report.hits.len();
        }
        let mut header_only: Vec<u8> = b"MZ".to_vec();
        header_only.extend(std::iter::repeat_n(0x90u8, 60));
        header_only.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        let report: IdentityReport = detect(&header_only);
        assert_eq!(report.format, "pe");
    }

    #[test]
    fn dedups_repeated_signatures() {
        let mut buf: Vec<u8> = b"MZ".to_vec();
        buf.extend_from_slice(b"UPX! padding UPX! again UPX!");
        let report: IdentityReport = detect(&buf);
        let upx_count: usize = report
            .hits
            .iter()
            .filter(|h: &&IdentityHit| h.name == "UPX")
            .count();
        assert_eq!(upx_count, 1, "repeated UPX markers collapse to one hit");
    }
}
