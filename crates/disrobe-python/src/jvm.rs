use disrobe_pass_jvm::{
    ApkResourceReport, BackendCapability, ClassFile, DecompiledClass, DexFile,
    analyze_apk_resources, decompile_class, detect_all, detect_available, parse_classfile,
    parse_dex,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::convert::to_value;
use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{
    ApkResources, DetectionList, DexFileReport, JvmBackends, JvmClass, JvmDecompiledClass,
};

#[pyfunction]
#[pyo3(text_signature = "(class_bytes)")]
fn jvm_parse_class(class_bytes: &[u8]) -> PyResult<JvmClass> {
    let cf: ClassFile = parse_classfile(class_bytes).map_err(map("jvm parse class"))?;
    Ok(JvmClass::from_value(null_bundled_value(&cf)?))
}

#[pyfunction]
#[pyo3(text_signature = "(dex_bytes)")]
fn jvm_parse_dex(dex_bytes: &[u8]) -> PyResult<DexFileReport> {
    let dex: DexFile = parse_dex(dex_bytes).map_err(map("jvm parse dex"))?;
    Ok(DexFileReport::from_value(null_bundled_value(&dex)?))
}

#[pyfunction]
#[pyo3(text_signature = "(class_bytes)")]
fn jvm_decompile_class(class_bytes: &[u8]) -> PyResult<JvmDecompiledClass> {
    let cf: ClassFile = parse_classfile(class_bytes).map_err(map("jvm parse class"))?;
    let decompiled: DecompiledClass = decompile_class(&cf);
    Ok(JvmDecompiledClass::from_value(to_value(&decompiled)?))
}

#[pyfunction]
#[pyo3(text_signature = "(class_bytes)")]
fn jvm_detect(class_bytes: &[u8]) -> PyResult<DetectionList> {
    let cf: ClassFile = parse_classfile(class_bytes).map_err(map("jvm parse class"))?;
    let hits: Vec<disrobe_pass_jvm::Detection> = detect_all(&cf);
    Ok(DetectionList::from_value(to_value(&hits)?))
}

#[pyfunction]
#[pyo3(text_signature = "()")]
fn jvm_backends() -> PyResult<JvmBackends> {
    let caps: BackendCapability = detect_available();
    Ok(JvmBackends::from_value(null_bundled_value(&caps)?))
}

#[pyfunction]
#[pyo3(text_signature = "(apk_bytes)")]
fn apk_resources(apk_bytes: &[u8]) -> PyResult<ApkResources> {
    let report: ApkResourceReport =
        analyze_apk_resources(apk_bytes).map_err(map("apk resources"))?;
    Ok(ApkResources::from_value(null_bundled_value(&report)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(jvm_parse_class, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_parse_dex, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_decompile_class, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_detect, m)?)?;
    m.add_function(wrap_pyfunction!(jvm_backends, m)?)?;
    m.add_function(wrap_pyfunction!(apk_resources, m)?)?;
    Ok(())
}
