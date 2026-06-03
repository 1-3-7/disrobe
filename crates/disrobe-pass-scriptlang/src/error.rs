use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-SCRIPT-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-SCRIPT-0100: input is not a recognized scriptlang artifact")]
    Unrecognized,

    #[error("DR-SCRIPT-0200: not a B::Concise op-tree dump")]
    NotPerlConcise,

    #[error("DR-SCRIPT-0201: B::Concise dump declared no subroutines or main program")]
    PerlEmptyDump,

    #[error("DR-SCRIPT-0300: not an RDS stream: bad magic {0:?}")]
    NotRds([u8; 2]),

    #[error("DR-SCRIPT-0301: unsupported RDS format byte {0:?} (expected 'X', 'A', or 'B')")]
    RdsFormat(u8),

    #[error("DR-SCRIPT-0302: truncated RDS stream at offset {offset}: needed {needed}, had {had}")]
    RdsTruncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-SCRIPT-0303: RDS nesting depth exceeded limit {0}")]
    RdsDepthExceeded(usize),

    #[error("DR-SCRIPT-0304: unsupported RDS SEXPTYPE {0}")]
    RdsUnsupportedType(u32),

    #[error("DR-SCRIPT-0400: not a Tcl starkit/tclkit container")]
    NotStarkit,

    #[error("DR-SCRIPT-0401: starkit zip archive error: {0}")]
    StarkitZip(String),

    #[error("DR-SCRIPT-0402: unsafe starkit entry path '{0}' (path traversal or absolute path)")]
    StarkitUnsafePath(String),

    #[error("DR-SCRIPT-0403: starkit Metakit schema not found")]
    StarkitNoSchema,

    #[error("DR-SCRIPT-0500: input is not a Haxe-emitted target")]
    NotHaxe,
}

impl From<zip::result::ZipError> for Error {
    fn from(value: zip::result::ZipError) -> Self {
        Self::StarkitZip(value.to_string())
    }
}
