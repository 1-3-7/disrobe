use std::sync::Mutex;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyModule};

use crate::err::DisrobeError;

#[derive(Debug)]
struct Registered {
    name: String,
    callable: Py<PyAny>,
    kind: SlotKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotKind {
    Pass,
    Consumer,
}

static REGISTRY: Mutex<Vec<Registered>> = Mutex::new(Vec::new());

fn lock_registry<'a>() -> PyResult<std::sync::MutexGuard<'a, Vec<Registered>>> {
    REGISTRY
        .lock()
        .map_err(|_| DisrobeError::new_err("pass registry mutex poisoned".to_owned()))
}

fn insert_slot(name: String, callable: Py<PyAny>, kind: SlotKind) -> PyResult<()> {
    let mut registry: std::sync::MutexGuard<'_, Vec<Registered>> = lock_registry()?;
    registry.retain(|r: &Registered| !(r.name == name && r.kind == kind));
    registry.push(Registered {
        name,
        callable,
        kind,
    });
    drop(registry);
    Ok(())
}

#[pyfunction]
#[pyo3(text_signature = "(name, callable)")]
fn register_pass(name: String, callable: Py<PyAny>) -> PyResult<()> {
    Python::attach(|py| ensure_callable(py, &callable, "pass"))?;
    insert_slot(name, callable, SlotKind::Pass)
}

#[pyfunction]
#[pyo3(text_signature = "(name, callable)")]
fn register_consumer(name: String, callable: Py<PyAny>) -> PyResult<()> {
    Python::attach(|py| ensure_callable(py, &callable, "consumer"))?;
    insert_slot(name, callable, SlotKind::Consumer)
}

#[pyfunction]
#[pyo3(text_signature = "()")]
fn registered_passes() -> PyResult<Vec<String>> {
    let registry: std::sync::MutexGuard<'_, Vec<Registered>> = lock_registry()?;
    Ok(registry
        .iter()
        .filter(|r: &&Registered| r.kind == SlotKind::Pass)
        .map(|r: &Registered| r.name.clone())
        .collect())
}

#[pyfunction]
#[pyo3(text_signature = "()")]
fn registered_consumers() -> PyResult<Vec<String>> {
    let registry: std::sync::MutexGuard<'_, Vec<Registered>> = lock_registry()?;
    Ok(registry
        .iter()
        .filter(|r: &&Registered| r.kind == SlotKind::Consumer)
        .map(|r: &Registered| r.name.clone())
        .collect())
}

#[pyfunction]
#[pyo3(text_signature = "(name)")]
fn unregister(name: &str) -> PyResult<bool> {
    let mut registry: std::sync::MutexGuard<'_, Vec<Registered>> = lock_registry()?;
    let before: usize = registry.len();
    registry.retain(|r: &Registered| r.name != name);
    Ok(registry.len() != before)
}

fn callable_for(name: &str, kind: SlotKind) -> PyResult<Py<PyAny>> {
    let registry: std::sync::MutexGuard<'_, Vec<Registered>> = lock_registry()?;
    registry
        .iter()
        .find(|r: &&Registered| r.name == name && r.kind == kind)
        .map(|r: &Registered| Python::attach(|py| r.callable.clone_ref(py)))
        .ok_or_else(|| {
            DisrobeError::new_err(format!(
                "no {} registered under `{name}`",
                match kind {
                    SlotKind::Pass => "pass",
                    SlotKind::Consumer => "consumer",
                }
            ))
        })
}

#[pyfunction]
#[pyo3(text_signature = "(name, data)")]
fn run_pass<'py>(py: Python<'py>, name: &str, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let callable: Py<PyAny> = callable_for(name, SlotKind::Pass)?;
    let arg: Bound<'py, PyBytes> = PyBytes::new(py, data);
    callable.bind(py).call1((arg,))
}

#[pyfunction]
#[pyo3(signature = (names, data))]
#[pyo3(text_signature = "(names, data)")]
fn run_chain<'py>(py: Python<'py>, names: Vec<String>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let mut current: Py<PyAny> = PyBytes::new(py, data).into_any().unbind();
    for name in &names {
        let callable: Py<PyAny> = callable_for(name, SlotKind::Pass)?;
        let bound: Bound<'py, PyAny> = current.into_bound(py);
        current = callable.bind(py).call1((bound,))?.unbind();
    }
    Ok(current.into_bound(py))
}

#[pyfunction]
#[pyo3(signature = (name, result, **context))]
#[pyo3(text_signature = "(name, result, **context)")]
fn emit<'py>(
    py: Python<'py>,
    name: &str,
    result: &Bound<'py, PyAny>,
    context: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyAny>> {
    let callable: Py<PyAny> = callable_for(name, SlotKind::Consumer)?;
    callable.bind(py).call((result.clone(),), context)
}

fn ensure_callable(py: Python<'_>, callable: &Py<PyAny>, role: &str) -> PyResult<()> {
    if callable.bind(py).is_callable() {
        return Ok(());
    }
    Err(DisrobeError::new_err(format!(
        "{role} must be callable; got a non-callable object"
    )))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(register_pass, m)?)?;
    m.add_function(wrap_pyfunction!(register_consumer, m)?)?;
    m.add_function(wrap_pyfunction!(registered_passes, m)?)?;
    m.add_function(wrap_pyfunction!(registered_consumers, m)?)?;
    m.add_function(wrap_pyfunction!(unregister, m)?)?;
    m.add_function(wrap_pyfunction!(run_pass, m)?)?;
    m.add_function(wrap_pyfunction!(run_chain, m)?)?;
    m.add_function(wrap_pyfunction!(emit, m)?)?;
    Ok(())
}
