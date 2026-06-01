use pyo3::prelude::*;
use serde::Serialize;

use crate::err::DisrobeError;

#[inline]
pub(crate) fn to_py<'py, T: Serialize>(py: Python<'py>, value: &T) -> PyResult<Bound<'py, PyAny>> {
    let json: String = serde_json::to_string(value)
        .map_err(|e: serde_json::Error| DisrobeError::new_err(format!("serialize: {e}")))?;
    let value: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e: serde_json::Error| DisrobeError::new_err(format!("re-parse: {e}")))?;
    pythonize::pythonize(py, &value)
        .map_err(|e: pythonize::PythonizeError| DisrobeError::new_err(format!("pythonize: {e}")))
}
