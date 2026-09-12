use disrobe_pass_jvm::{ClassFile, JavaVersion, parse_classfile};
use serde::{Deserialize, Serialize};

use crate::alt_runtimes::{AltRuntimeError, Result};

const CLASS_MAGIC: u32 = 0xCAFE_BABE;
const JYTHON_PACKAGE_PREFIX: &str = "org/python/";
const JYTHON_CORE_PYCODE: &str = "org/python/core/PyCode";
const JYTHON_PYFUNCTION: &str = "org/python/core/PyFunction";
const JYTHON_BYTECODE_MARKER: &str = "$py";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JythonModule {
    pub this_class: String,
    pub super_class: String,
    pub java_version: Option<JavaVersion>,
    pub jython_markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JvmAnalysis {
    pub this_class: String,
    pub super_class: String,
    pub java_version: Option<JavaVersion>,
    pub method_count: u32,
    pub field_count: u32,
    pub constant_pool_size: u32,
    pub is_jython_generated: bool,
    pub markers: Vec<String>,
}

pub fn parse(bytes: &[u8]) -> Result<JythonModule> {
    let cf: ClassFile = parse_classfile(bytes).map_err(|e: disrobe_pass_jvm::Error| {
        AltRuntimeError::DelegationFailed {
            target: "jvm.classfile",
            reason: format!("{e}"),
        }
    })?;
    let this_class: String =
        cf.this_class_name()
            .map(str::to_owned)
            .map_err(|_: disrobe_pass_jvm::Error| AltRuntimeError::BadEncoding {
                field: "this_class",
                offset: 0,
            })?;
    let super_class: String = cf
        .class_name(cf.super_class)
        .map(str::to_owned)
        .unwrap_or_default();
    let java_version: Option<JavaVersion> = cf.version();
    let jython_markers: Vec<String> = scan_markers(&cf);
    if jython_markers.is_empty() && !this_class.starts_with(JYTHON_PACKAGE_PREFIX) {
        return Err(AltRuntimeError::NotDetected("jython"));
    }
    Ok(JythonModule {
        this_class,
        super_class,
        java_version,
        jython_markers,
    })
}

pub fn analyze(bytes: &[u8]) -> Result<JvmAnalysis> {
    let cf: ClassFile = parse_classfile(bytes).map_err(|e: disrobe_pass_jvm::Error| {
        AltRuntimeError::DelegationFailed {
            target: "jvm.classfile",
            reason: format!("{e}"),
        }
    })?;
    let this_class: String = cf.this_class_name().map(str::to_owned).unwrap_or_default();
    let super_class: String = cf
        .class_name(cf.super_class)
        .map(str::to_owned)
        .unwrap_or_default();
    let markers: Vec<String> = scan_markers(&cf);
    let is_jython_generated: bool = !markers.is_empty()
        || super_class == JYTHON_CORE_PYCODE
        || super_class == JYTHON_PYFUNCTION;
    Ok(JvmAnalysis {
        this_class,
        super_class,
        java_version: cf.version(),
        method_count: u32::try_from(cf.methods.len()).unwrap_or(u32::MAX),
        field_count: u32::try_from(cf.fields.len()).unwrap_or(u32::MAX),
        constant_pool_size: u32::try_from(cf.constant_pool.len()).unwrap_or(u32::MAX),
        is_jython_generated,
        markers,
    })
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != CLASS_MAGIC {
        return false;
    }
    let needle: &[u8] = JYTHON_PACKAGE_PREFIX.as_bytes();
    bytes
        .windows(needle.len())
        .any(|w: &[u8]| -> bool { w == needle })
        || bytes
            .windows(JYTHON_BYTECODE_MARKER.len())
            .any(|w: &[u8]| -> bool { w == JYTHON_BYTECODE_MARKER.as_bytes() })
}

fn scan_markers(cf: &ClassFile) -> Vec<String> {
    let mut markers: Vec<String> = Vec::new();
    for entry in &cf.constant_pool {
        if let disrobe_pass_jvm::ConstantPoolEntry::Utf8(s) = entry
            && (s.starts_with(JYTHON_PACKAGE_PREFIX)
                || s == JYTHON_CORE_PYCODE
                || s == JYTHON_PYFUNCTION
                || s.contains(JYTHON_BYTECODE_MARKER))
        {
            markers.push(s.clone());
        }
    }
    markers
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_rejects_non_classfile() {
        let bytes: [u8; 8] = [0u8; 8];
        assert!(!detect(&bytes));
    }

    #[test]
    fn analyze_returns_delegation_error_on_garbage() {
        let bytes: [u8; 16] = [0u8; 16];
        let err: AltRuntimeError = analyze(&bytes).expect_err("must fail");
        assert!(matches!(err, AltRuntimeError::DelegationFailed { .. }));
    }
}
