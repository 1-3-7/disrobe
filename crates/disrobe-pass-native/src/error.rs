use disrobe_bytes::AddressError;
use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-NATIVE-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-NATIVE-0002: input shorter than required ({needed} bytes, had {had})")]
    Truncated { needed: usize, had: usize },

    #[error(
        "DR-NATIVE-0003: unrecognized native container (no PE/ELF/Mach-O/COFF/MZ/NE/LE/LX magic)"
    )]
    UnknownFormat,

    #[error("DR-NATIVE-0004: object-crate parse failure: {0}")]
    ObjectParse(String),

    #[error("DR-NATIVE-0005: goblin parse failure: {0}")]
    GoblinParse(String),

    #[error("DR-NATIVE-0006: gimli DWARF read failure: {0}")]
    Dwarf(String),

    #[error("DR-NATIVE-0007: PDB read failure: {0}")]
    Pdb(String),

    #[error("DR-NATIVE-0008: STABS table malformed at offset {0}")]
    Stabs(usize),

    #[error("DR-NATIVE-0009: unsupported architecture {0:?} for disasm dispatch")]
    UnsupportedArch(String),

    #[error("DR-NATIVE-0010: disassembler error in {engine}: {message}")]
    Disasm {
        engine: &'static str,
        message: String,
    },

    #[error("DR-NATIVE-0011: required external backend not on PATH: {0}")]
    MissingTool(String),

    #[error("DR-NATIVE-0012: external tool '{tool}' exited with status {status}: {stderr}")]
    BackendFailed {
        tool: String,
        status: i32,
        stderr: String,
    },

    #[error("DR-NATIVE-0013: external tool '{0}' exceeded {1} ms timeout")]
    BackendTimeout(String, u64),

    #[error("DR-NATIVE-0014: license-restricted backend required (no FOSS substitute): {0}")]
    LicenseRequired(&'static str),

    #[error(
        "DR-NATIVE-0015: grey-zone protector detected ({0}); detection-only per docs/legal/{0}-stance.md"
    )]
    GreyZoneDetectOnly(&'static str),

    #[error(
        "DR-NATIVE-0016: packer signature matched ({0}) but unpacker not yet wired (FIXTURE PENDING)"
    )]
    PackerUnpackerNotImplemented(&'static str),

    #[error("DR-NATIVE-0017: demangle failed ({lang}): {message}")]
    Demangle { lang: &'static str, message: String },

    #[error("DR-NATIVE-0018: llvm-ir text parse failed: {0}")]
    LlvmIr(String),

    #[error("DR-NATIVE-0019: signature database corrupt: {0}")]
    SignatureDb(String),

    #[error("DR-NATIVE-0020: authorization required for {0}; re-run with --i-have-authorization")]
    AuthorizationRequired(&'static str),

    #[error(
        "DR-NATIVE-0021: stub-emulation provider required for {packer}; \
         enable the `stub-emulation` Cargo feature and supply a {trait_name} implementation. \
         See {pr_hint}"
    )]
    EmulatorNotConfigured {
        packer: &'static str,
        trait_name: &'static str,
        pr_hint: &'static str,
    },

    #[error("DR-NATIVE-0022: UPX decode failure ({stage}): {detail}")]
    UpxDecode { stage: &'static str, detail: String },

    #[error("DR-NATIVE-0023: backend export failure ({stage}): {detail}")]
    Export { stage: &'static str, detail: String },

    #[error("DR-NATIVE-0024: x86 re-encode failure ({stage}): {detail}")]
    Encode { stage: &'static str, detail: String },

    #[error("DR-NATIVE-0025: eBPF decode failure: {0}")]
    EbpfDecode(String),

    #[error("DR-NATIVE-0026: loader recovery failure ({stage}): {detail}")]
    LoaderRecovery { stage: &'static str, detail: String },

    #[error(
        "DR-NATIVE-0027: RVA 0x{rva:08X} in section '{section}' has no readable file bytes: {cause}"
    )]
    RvaNotFileBacked {
        section: String,
        rva: u32,
        cause: AddressError,
    },

    #[error("DR-NATIVE-0028: PDB build provenance failure: {0}")]
    PdbProvenance(#[from] crate::debug_info::PdbProvenanceError),
}
