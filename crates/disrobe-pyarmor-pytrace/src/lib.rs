#![deny(unreachable_pub)]
use std::collections::BTreeSet;
use std::sync::Mutex;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyCFunction, PyModule};

static CAPTURED: Mutex<Vec<Py<PyAny>>> = Mutex::new(Vec::new());
static INSTALLED: Mutex<bool> = Mutex::new(false);

const MAX_CAPTURED: usize = 262_144;
const MAX_DRAIN_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_DRAIN_OUTPUTS: usize = 65_536;
const MAX_MARSHALLED_CODE_BYTES: usize = 16 * 1024 * 1024;

const FILTER_NEEDLES: [&str; 5] = [
    "/lib/",
    "\\lib\\",
    "site-packages",
    "v6v7_dynamic_hook",
    "disrobe_pytrace",
];

const LIMITATION_MESSAGE: &str = "disrobe-pyarmor-pytrace runs at the Python tracing layer \
    (sys.settrace). It cannot observe code objects executed by PyArmor v6/v7 via direct \
    C-level PyEval_EvalCode calls from the _pytransform runtime. The C-level intercept lives \
    in the companion crate disrobe-pyarmor-cextract.";

#[pyfunction]
fn hook_into(py: Python<'_>) -> PyResult<bool> {
    {
        let installed: std::sync::MutexGuard<'_, bool> = INSTALLED
            .lock()
            .map_err(|_| PyRuntimeError::new_err("install lock poisoned"))?;
        if *installed {
            return Ok(false);
        }
    }
    let sys: Bound<'_, PyModule> = py.import("sys")?;
    let trace_fn: Bound<'_, PyCFunction> = wrap_pyfunction!(_trace_callback, py)?;
    sys.call_method1("settrace", (trace_fn,))?;
    {
        let mut installed: std::sync::MutexGuard<'_, bool> = INSTALLED
            .lock()
            .map_err(|_| PyRuntimeError::new_err("install lock poisoned"))?;
        *installed = true;
    }
    Ok(true)
}

#[pyfunction]
fn drain(py: Python<'_>) -> PyResult<Vec<Vec<u8>>> {
    let sys: Bound<'_, PyModule> = py.import("sys")?;
    sys.call_method1("settrace", (py.None(),))?;

    let marshal: Bound<'_, PyModule> = py.import("marshal")?;
    let mut guard: std::sync::MutexGuard<'_, Vec<Py<PyAny>>> = CAPTURED
        .lock()
        .map_err(|_| PyRuntimeError::new_err("capture lock poisoned"))?;
    let drained: Vec<Py<PyAny>> = core::mem::take(&mut *guard);
    drop(guard);

    *INSTALLED
        .lock()
        .map_err(|_| PyRuntimeError::new_err("install lock poisoned"))? = false;

    let mut out: Vec<Vec<u8>> = Vec::with_capacity(drain_reserve(drained.len()));
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut total_bytes: usize = 0;
    for obj in drained {
        if out.len() >= MAX_DRAIN_OUTPUTS {
            return Err(PyRuntimeError::new_err(format!(
                "drain output exceeds {MAX_DRAIN_OUTPUTS} code objects"
            )));
        }
        let bound: &Bound<'_, PyAny> = obj.bind(py);
        let hash_key: Option<usize> = bound
            .call_method0("__hash__")
            .ok()
            .and_then(|h: Bound<'_, PyAny>| h.extract::<isize>().ok())
            .map(|h: isize| h.cast_unsigned());
        if let Some(key) = hash_key
            && !seen.insert(key)
        {
            continue;
        }
        let Ok(bytes_obj) = marshal.call_method1("dumps", (bound, 4i32)) else {
            continue;
        };
        let Ok(bytes) = bytes_obj.extract::<Vec<u8>>() else {
            continue;
        };
        total_bytes = checked_drain_total(total_bytes, bytes.len())?;
        out.push(bytes);
    }
    Ok(out)
}

#[pyfunction]
fn capture_count() -> PyResult<usize> {
    let guard: std::sync::MutexGuard<'_, Vec<Py<PyAny>>> = CAPTURED
        .lock()
        .map_err(|_| PyRuntimeError::new_err("capture lock poisoned"))?;
    Ok(guard.len())
}

#[pyfunction]
const fn limitation_notice() -> &'static str {
    LIMITATION_MESSAGE
}

#[inline]
fn should_skip(filename_lower: &str) -> bool {
    FILTER_NEEDLES
        .iter()
        .any(|needle: &&'static str| filename_lower.contains(needle))
}

#[pyfunction]
fn _trace_callback(
    py: Python<'_>,
    frame: Bound<'_, PyAny>,
    event: &str,
    _arg: Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    if event != "call" {
        return Ok(py.None());
    }
    let code_obj: Bound<'_, PyAny> = frame.getattr("f_code")?;
    if let Ok(filename) = code_obj
        .getattr("co_filename")
        .and_then(|f: Bound<'_, PyAny>| f.extract::<String>())
    {
        let lower: String = filename.to_lowercase();
        if should_skip(&lower) {
            return Ok(py.None());
        }
    }
    let mut guard: std::sync::MutexGuard<'_, Vec<Py<PyAny>>> = CAPTURED
        .lock()
        .map_err(|_| PyRuntimeError::new_err("capture lock poisoned"))?;
    if guard.len() < MAX_CAPTURED {
        guard.push(code_obj.unbind());
    }
    drop(guard);
    Ok(py.None())
}

#[pymodule]
fn disrobe_pytrace(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hook_into, m)?)?;
    m.add_function(wrap_pyfunction!(drain, m)?)?;
    m.add_function(wrap_pyfunction!(capture_count, m)?)?;
    m.add_function(wrap_pyfunction!(limitation_notice, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__limitation__", LIMITATION_MESSAGE)?;
    Ok(())
}

const fn drain_reserve(captured: usize) -> usize {
    if captured > MAX_DRAIN_OUTPUTS {
        MAX_DRAIN_OUTPUTS
    } else {
        captured
    }
}

fn checked_drain_total(current: usize, next: usize) -> PyResult<usize> {
    checked_drain_total_raw(current, next).map_err(drain_limit_error)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainLimitError {
    MarshalledCodeObject,
    OutputOverflow,
    OutputBytes,
}

const fn checked_drain_total_raw(current: usize, next: usize) -> Result<usize, DrainLimitError> {
    if next > MAX_MARSHALLED_CODE_BYTES {
        return Err(DrainLimitError::MarshalledCodeObject);
    }
    let Some(total): Option<usize> = current.checked_add(next) else {
        return Err(DrainLimitError::OutputOverflow);
    };
    if total > MAX_DRAIN_OUTPUT_BYTES {
        return Err(DrainLimitError::OutputBytes);
    }
    Ok(total)
}

fn drain_limit_error(error: DrainLimitError) -> PyErr {
    match error {
        DrainLimitError::MarshalledCodeObject => PyRuntimeError::new_err(format!(
            "marshalled code object exceeds {MAX_MARSHALLED_CODE_BYTES} bytes"
        )),
        DrainLimitError::OutputOverflow => {
            PyRuntimeError::new_err("drain output byte count overflow")
        }
        DrainLimitError::OutputBytes => PyRuntimeError::new_err(format!(
            "drain output exceeds {MAX_DRAIN_OUTPUT_BYTES} bytes"
        )),
    }
}

#[doc(hidden)]
pub mod test_support {
    #[must_use]
    pub fn should_skip_path(filename_lower: &str) -> bool {
        super::should_skip(filename_lower)
    }

    #[must_use]
    pub fn filter_needles_are_non_empty() -> bool {
        super::FILTER_NEEDLES
            .iter()
            .all(|needle: &&'static str| !needle.is_empty())
    }

    #[must_use]
    pub const fn limitation_message() -> &'static str {
        super::LIMITATION_MESSAGE
    }

    #[must_use]
    pub const fn max_drain_outputs() -> usize {
        super::MAX_DRAIN_OUTPUTS
    }

    #[must_use]
    pub const fn max_marshaled_code_bytes() -> usize {
        super::MAX_MARSHALLED_CODE_BYTES
    }

    #[must_use]
    pub const fn drain_reserve(captured: usize) -> usize {
        super::drain_reserve(captured)
    }

    #[must_use]
    pub const fn drain_total_is_err(current: usize, next: usize) -> bool {
        super::checked_drain_total_raw(current, next).is_err()
    }
}
