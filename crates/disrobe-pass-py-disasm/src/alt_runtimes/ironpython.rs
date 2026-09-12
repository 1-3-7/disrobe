use disrobe_pass_dotnet::{PassSummary, RuntimeLabel, analyze as analyze_dotnet};
use serde::{Deserialize, Serialize};

use crate::alt_runtimes::{AltRuntimeError, Result};

const PE_DOS_MAGIC: u16 = 0x5A4D;
const IRONPYTHON_ASSEMBLY: &str = "IronPython";
const IRONPYTHON_RUNTIME: &str = "IronPython.Runtime";
const IRONPYTHON_TYPE_PROVIDER: &str = "IronPython.Modules";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IronPythonModule {
    pub runtime_label: RuntimeLabel,
    pub assembly_markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DotnetAnalysis {
    pub pe_bitness: String,
    pub runtime_label: RuntimeLabel,
    pub clr_runtime_version: String,
    pub stream_names: Vec<String>,
    pub is_ironpython: bool,
    pub markers: Vec<String>,
}

pub fn parse(bytes: &[u8]) -> Result<IronPythonModule> {
    let summary: PassSummary =
        analyze_dotnet(bytes).map_err(|e: disrobe_pass_dotnet::Error| -> AltRuntimeError {
            AltRuntimeError::DelegationFailed {
                target: "dotnet.pe",
                reason: format!("{e}"),
            }
        })?;
    let assembly_markers: Vec<String> = scan_assembly_markers(bytes);
    if assembly_markers.is_empty() {
        return Err(AltRuntimeError::NotDetected("ironpython"));
    }
    Ok(IronPythonModule {
        runtime_label: summary.runtime_label,
        assembly_markers,
    })
}

pub fn analyze(bytes: &[u8]) -> Result<DotnetAnalysis> {
    let summary: PassSummary =
        analyze_dotnet(bytes).map_err(|e: disrobe_pass_dotnet::Error| -> AltRuntimeError {
            AltRuntimeError::DelegationFailed {
                target: "dotnet.pe",
                reason: format!("{e}"),
            }
        })?;
    let markers: Vec<String> = scan_assembly_markers(bytes);
    let is_ironpython: bool = !markers.is_empty();
    Ok(DotnetAnalysis {
        pe_bitness: summary.pe_bitness,
        runtime_label: summary.runtime_label,
        clr_runtime_version: summary.clr_runtime_version,
        stream_names: summary.stream_names,
        is_ironpython,
        markers,
    })
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let dos: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    if dos != PE_DOS_MAGIC {
        return false;
    }
    has_marker(bytes, IRONPYTHON_ASSEMBLY.as_bytes())
        || has_marker(bytes, IRONPYTHON_RUNTIME.as_bytes())
        || has_marker(bytes, IRONPYTHON_TYPE_PROVIDER.as_bytes())
}

fn scan_assembly_markers(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for needle in [
        IRONPYTHON_ASSEMBLY,
        IRONPYTHON_RUNTIME,
        IRONPYTHON_TYPE_PROVIDER,
    ] {
        if has_marker(bytes, needle.as_bytes()) {
            out.push(needle.to_owned());
        }
    }
    out
}

fn has_marker(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_rejects_non_pe() {
        let bytes: [u8; 16] = [0u8; 16];
        assert!(!detect(&bytes));
    }

    #[test]
    fn analyze_returns_delegation_error_on_garbage() {
        let bytes: [u8; 64] = [0u8; 64];
        let err: AltRuntimeError = analyze(&bytes).expect_err("must fail");
        assert!(matches!(err, AltRuntimeError::DelegationFailed { .. }));
    }

    #[test]
    fn marker_scan_finds_ironpython_token() {
        let mut bytes: Vec<u8> = vec![b'M', b'Z'];
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(IRONPYTHON_RUNTIME.as_bytes());
        assert!(detect(&bytes));
        let found: Vec<String> = scan_assembly_markers(&bytes);
        assert!(found.contains(&IRONPYTHON_RUNTIME.to_owned()));
    }
}
