#[cfg(feature = "alt-runtimes-native")]
pub mod brython;
#[cfg(feature = "alt-runtimes-native")]
pub mod ironpython;
#[cfg(feature = "alt-runtimes-native")]
pub mod jython;
pub mod micropython;
pub mod micropython_native;
pub mod mpy_static_qstr;
pub mod pypy;
pub mod recover;

use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = core::result::Result<T, AltRuntimeError>;

#[derive(Debug, Error, Diagnostic)]
pub enum AltRuntimeError {
    #[error("DR-PYALT-0001: truncated payload at offset {offset} (needed {needed}, had {had})")]
    Truncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-PYALT-0002: bad magic for {runtime} (got 0x{got:08X})")]
    BadMagic { runtime: &'static str, got: u32 },

    #[error("DR-PYALT-0003: unsupported {runtime} format version: {version}")]
    UnsupportedVersion { runtime: &'static str, version: u32 },

    #[error("DR-PYALT-0004: detection negative for {0}")]
    NotDetected(&'static str),

    #[error("DR-PYALT-0005: delegation to {target} failed: {reason}")]
    DelegationFailed {
        target: &'static str,
        reason: String,
    },

    #[error("DR-PYALT-0006: invalid {field} encoding at offset {offset}")]
    BadEncoding { field: &'static str, offset: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AltRuntime {
    PyPy,
    MicroPython,
    MicroPythonNative,
    Jython,
    IronPython,
    Brython,
}

#[must_use]
pub fn detect_runtime(bytes: &[u8]) -> Option<AltRuntime> {
    #[cfg(feature = "alt-runtimes-native")]
    if jython::detect(bytes) {
        return Some(AltRuntime::Jython);
    }
    #[cfg(feature = "alt-runtimes-native")]
    if ironpython::detect(bytes) {
        return Some(AltRuntime::IronPython);
    }
    if micropython_native::detect(bytes) {
        return Some(AltRuntime::MicroPythonNative);
    }
    if micropython::detect(bytes) {
        return Some(AltRuntime::MicroPython);
    }
    if pypy::detect(bytes) {
        return Some(AltRuntime::PyPy);
    }
    #[cfg(feature = "alt-runtimes-native")]
    if brython::detect(bytes) {
        return Some(AltRuntime::Brython);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_empty_returns_none() {
        let bytes: &[u8] = &[];
        assert!(detect_runtime(bytes).is_none());
    }
}
