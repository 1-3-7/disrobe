use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(
        "DR-PYFRZ-0001: input is not a recognized Python freezer/wheel-pack container (cx_Freeze, py2exe, shiv, pex, zipapp, pyc)"
    )]
    UnknownFormat,

    #[error("DR-PYFRZ-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "DR-PYFRZ-0003: cx_Freeze sibling layout missing required {missing:?} (searched alongside {binary})"
    )]
    CxFreezeMissingSibling {
        binary: String,
        missing: Vec<String>,
    },

    #[error("DR-PYFRZ-0004: py2exe PE resource `PYTHONSCRIPT` not found")]
    Py2exeScriptResourceMissing,

    #[error("DR-PYFRZ-0005: py2exe scriptinfo tag mismatch (expected 0x78563412, got 0x{0:08x})")]
    Py2exeScriptInfoBadTag(u32),

    #[error("DR-PYFRZ-0006: py2exe scriptinfo truncated ({need} bytes needed, {got} available)")]
    Py2exeScriptInfoTruncated { need: usize, got: usize },

    #[error(
        "DR-PYFRZ-0007: shiv archive missing required `_bootstrap/` directory inside trailing zip"
    )]
    ShivBootstrapMissing,

    #[error("DR-PYFRZ-0008: shiv archive missing `environment.json` manifest")]
    ShivEnvironmentMissing,

    #[error("DR-PYFRZ-0009: pex archive missing `PEX-INFO` manifest")]
    PexInfoMissing,

    #[error("DR-PYFRZ-0010: trailing-zip end-of-central-directory record not found")]
    ZipTailNotFound,

    #[error("DR-PYFRZ-0011: zip archive parse failed: {0}")]
    Zip(String),

    #[error("DR-PYFRZ-0012: zip entry `{0}` extraction failed: {1}")]
    ZipEntry(String, String),

    #[error("DR-PYFRZ-0013: PE parse failed: {0}")]
    PeParse(String),

    #[error("DR-PYFRZ-0014: shebang manifest line is not a valid shiv/pex bootstrap header")]
    ShebangInvalid,

    #[error("DR-PYFRZ-0015: archive entry path escapes container root: {0}")]
    UnsafeEntryPath(String),

    #[error("DR-PYFRZ-0016: payload decompression failed: {0}")]
    Decompression(String),

    #[error("DR-PYFRZ-0017: json manifest parse failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("DR-PYFRZ-0018: extraction quota exceeded on entry `{entry}`: {reason}")]
    QuotaExceeded { entry: String, reason: String },

    #[error("DR-PYFRZ-0019: PyOxidizer detection found no embedded Python configuration block")]
    PyOxidizerConfigMissing,

    #[error(
        "DR-PYFRZ-0020: Briefcase sibling layout missing required `{missing:?}` (searched alongside {binary})"
    )]
    BriefcaseMissingSibling {
        binary: String,
        missing: Vec<String>,
    },

    #[error("DR-PYFRZ-0021: frozen bytecode `{module}` could not be decompiled: {reason}")]
    Decompile { module: String, reason: String },

    #[error(
        "DR-PYFRZ-0022: bare `.pyc` magic unrecognized (0x{0:08x}); not a known CPython release"
    )]
    UnknownPycMagic(u32),

    #[error("DR-PYFRZ-0023: native extension `{module}` disassembly failed: {reason}")]
    NativeSurface { module: String, reason: String },

    #[error("DR-PYFRZ-0024: Briefcase source walk bounded at `{path}`: {reason}")]
    BriefcaseWalkBounded { path: String, reason: String },

    #[error("DR-PYFRZ-0025: zipapp archive has no Python module entry")]
    ZipappPythonEntryMissing,

    #[error("DR-PYFRZ-0026: PyOxidizer packed-resources module index malformed: {0}")]
    PyOxidizerResourceIndex(String),
}

impl From<disrobe_binfmt::Error> for Error {
    fn from(err: disrobe_binfmt::Error) -> Self {
        match err {
            disrobe_binfmt::Error::Zip(s) => Self::Zip(s),
            disrobe_binfmt::Error::ZipEntry { name, reason } => Self::ZipEntry(name, reason),
            disrobe_binfmt::Error::UnsafeEntryPath(p) => Self::UnsafeEntryPath(p),
            disrobe_binfmt::Error::QuotaExceeded { entry, reason } => {
                Self::QuotaExceeded { entry, reason }
            }
            disrobe_binfmt::Error::Io(io) => Self::Io(io),
            other => Self::Zip(other.to_string()),
        }
    }
}
