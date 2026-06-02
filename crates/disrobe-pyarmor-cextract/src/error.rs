use core::fmt;

use pyo3::PyErr;
use pyo3::exceptions::{PyOSError, PyRuntimeError};

pub(crate) type Result<T> = core::result::Result<T, CextractError>;

#[derive(Debug)]
pub(crate) enum CextractError {
    LockPoisoned(&'static str),
    AlreadyInstalled,
    NotInstalled,
    OutDirCreate {
        path: String,
        source: std::io::Error,
    },
    OutDirNotWritable {
        path: String,
        source: std::io::Error,
    },
    PycWrite {
        path: String,
        source: std::io::Error,
    },
    MarshalDumpFailed(String),
    MonitoringUnavailable,
    MonitoringSetup(String),
    PythonApi(String),
    HotpatchFailed {
        stage: &'static str,
        reason: String,
    },
}

impl fmt::Display for CextractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned(name) => write!(f, "CEXT-0001: lock poisoned: {name}"),
            Self::AlreadyInstalled => write!(f, "CEXT-0002: intercept already installed"),
            Self::NotInstalled => write!(f, "CEXT-0003: intercept not installed"),
            Self::OutDirCreate { path, source } => {
                write!(f, "CEXT-0004: cannot create out_dir {path}: {source}")
            }
            Self::OutDirNotWritable { path, source } => {
                write!(f, "CEXT-0005: out_dir {path} not writable: {source}")
            }
            Self::PycWrite { path, source } => {
                write!(f, "CEXT-0006: cannot write pyc {path}: {source}")
            }
            Self::MarshalDumpFailed(reason) => {
                write!(f, "CEXT-0007: marshal.dumps failed: {reason}")
            }
            Self::MonitoringUnavailable => write!(
                f,
                "CEXT-0008: sys.monitoring unavailable (Python < 3.12 path uses PyEval_SetProfile)"
            ),
            Self::MonitoringSetup(reason) => write!(f, "CEXT-0009: sys.monitoring setup: {reason}"),
            Self::PythonApi(reason) => write!(f, "CEXT-0011: python api: {reason}"),
            Self::HotpatchFailed { stage, reason } => {
                write!(f, "CEXT-0014: hotpatch failed at stage '{stage}': {reason}")
            }
        }
    }
}

impl std::error::Error for CextractError {}

impl From<CextractError> for PyErr {
    fn from(value: CextractError) -> Self {
        match value {
            CextractError::OutDirCreate { .. }
            | CextractError::OutDirNotWritable { .. }
            | CextractError::PycWrite { .. } => PyOSError::new_err(value.to_string()),
            other => PyRuntimeError::new_err(other.to_string()),
        }
    }
}

impl From<PyErr> for CextractError {
    fn from(value: PyErr) -> Self {
        Self::PythonApi(value.to_string())
    }
}
