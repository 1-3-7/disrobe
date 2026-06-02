use disrobe_pass_jvm::{
    BackendCapability, ClassFile, DecompiledClass, DexFile, decompile_class, detect_all,
    detect_available, parse_classfile, parse_dex,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::convert::to_py;
use crate::err::map;
use crate::llm::report_with_null_bundle;

/// Parse a JVM `.class` file (CAFEBABE-magic) into its typed constant pool,
/// field table, method table, & attribute set.
#[pyfunction]
#[pyo3(text_signature = "(class_bytes)")]
fn jvm_parse_class<'py>(py: Python<'py>, class_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let cf: ClassFile = parse_classfile(class_bytes).map_err(map("jvm parse class"))?;
    report_with_null_bundle(py, &cf)
}

/// Parse an Android DEX file. Returns the header, string pool, type ids,
/// method ids, & class definitions.
#[pyfunction]
#[pyo3(text_signature = "(dex_bytes)")]
fn jvm_parse_dex<'py>(py: Python<'py>, dex_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let dex: DexFile = parse_dex(dex_bytes).map_err(map("jvm parse dex"))?;
    report_with_null_bundle(py, &dex)
}

/// Natively decompile a JVM `.class` file to readable pseudo-Java with no
/// external decompiler/JVM present (single-binary fallback). Returns the
/// reconstructed source plus lift statistics (method/field counts, fully
/// lifted vs. fallback methods).
#[pyfunction]
#[pyo3(text_signature = "(class_bytes)")]
fn jvm_decompile_class<'py>(py: Python<'py>, class_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let cf: ClassFile = parse_classfile(class_bytes).map_err(map("jvm parse class"))?;
    let decompiled: DecompiledClass = decompile_class(&cf);
    to_py(py, &decompiled)
}

/// Run all known JVM/Android obfuscator detectors against `class_bytes`
/// (Allatori, DexGuard, Dasho, Stringer, Zelix, ProGuard). Returns the
/// matched protectors & their markers.
#[pyfunction]
#[pyo3(text_signature = "(class_bytes)")]
fn jvm_detect<'py>(py: Python<'py>, class_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let cf: ClassFile = parse_classfile(class_bytes).map_err(map("jvm parse class"))?;
    let hits: Vec<disrobe_pass_jvm::Detection> = detect_all(&cf);
    to_py(py, &hits)
}

/// Probe the host for installed JVM/Android decompiler backends (CFR,
/// Procyon, Vineflower, jd-cli, Krakatau for JVM; Jadx, Dex2Jar for
/// Android). Returns the `BackendCapability` listing.
#[pyfunction]
#[pyo3(text_signature = "()")]
fn jvm_backends<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let caps: BackendCapability = detect_available();
    report_with_null_bundle(py, &caps)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(jvm_parse_class, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_parse_dex, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_decompile_class, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_detect, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_backends, m)?)?;
    Ok(())
}
