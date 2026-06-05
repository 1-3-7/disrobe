use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyModule;

create_exception!(
    disrobe,
    DisrobeError,
    PyException,
    "Base error raised by every disrobe binding when the underlying pass fails."
);

create_exception!(
    disrobe,
    UnsupportedLanguage,
    DisrobeError,
    "Raised by `disrobe.disasm`/`parse`/`compile` when the language has no \
     backing implementation in the current build."
);

pub(crate) fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("DisrobeError", py.get_type::<DisrobeError>())?;
    m.add("UnsupportedLanguage", py.get_type::<UnsupportedLanguage>())?;
    Ok(())
}

#[inline]
pub(crate) fn map<E: std::fmt::Display>(prefix: &str) -> impl FnOnce(E) -> PyErr + use<'_, E> {
    move |e: E| DisrobeError::new_err(format!("{prefix}: {e}"))
}

#[inline]
pub(crate) fn unsupported_language(language: &str, hint: &str) -> PyErr {
    UnsupportedLanguage::new_err(format!("language `{language}` not supported: {hint}"))
}
