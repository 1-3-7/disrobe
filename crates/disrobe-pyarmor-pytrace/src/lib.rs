use std::collections::BTreeSet;
use std::sync::Mutex;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyCFunction, PyModule};

static CAPTURED: Mutex<Vec<Py<PyAny>>> = Mutex::new(Vec::new());
static INSTALLED: Mutex<bool> = Mutex::new(false);

const FILTER_NEEDLES: [&str; 5] = [
    "/lib/",
    "\\lib\\",
    "site-packages",
    "v6v7_dynamic_hook",
    "disrobe_pytrace",
];

const LIMITATION_MESSAGE: &str = "disrobe-pyarmor-pytrace v0.2 runs at the Python tracing layer \
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

    let mut out: Vec<Vec<u8>> = Vec::with_capacity(drained.len());
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    for obj in drained {
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
        out.push(bytes);
    }
    *INSTALLED
        .lock()
        .map_err(|_| PyRuntimeError::new_err("install lock poisoned"))? = false;
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
) -> PyResult<PyObject> {
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
    let Ok(mut guard) = CAPTURED.lock() else {
        return Ok(py.None());
    };
    guard.push(code_obj.unbind());
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

#[cfg(test)]
mod tests {
    use super::{FILTER_NEEDLES, LIMITATION_MESSAGE, should_skip};

    #[test]
    fn skip_recognizes_stdlib_unix_path() {
        let lower: &str = "/usr/lib/python3.11/runpy.py";
        assert!(should_skip(lower));
    }

    #[test]
    fn skip_recognizes_stdlib_windows_path() {
        let lower: &str = "c:\\python311\\lib\\runpy.py";
        assert!(should_skip(lower));
    }

    #[test]
    fn skip_recognizes_site_packages() {
        let lower: &str = "/home/user/.venv/lib/python3.11/site-packages/foo.py";
        assert!(should_skip(lower));
    }

    #[test]
    fn skip_recognizes_helper_script() {
        let lower: &str = "/tmp/v6v7_dynamic_hook.py";
        assert!(should_skip(lower));
    }

    #[test]
    fn skip_recognizes_self_module() {
        let lower: &str = "<disrobe_pytrace internal>";
        assert!(should_skip(lower));
    }

    #[test]
    fn skip_passes_user_wrapper() {
        let lower: &str = "c:\\users\\someone\\desktop\\hello.py";
        assert!(!should_skip(lower));
    }

    #[test]
    fn skip_passes_arbitrary_user_file() {
        let lower: &str = "/home/user/projects/myapp/main.py";
        assert!(!should_skip(lower));
    }

    #[test]
    fn filter_needles_are_non_empty() {
        let needles: &[&str; 5] = &FILTER_NEEDLES;
        assert!(!needles.is_empty());
        for needle in needles {
            assert!(!needle.is_empty());
        }
    }

    #[test]
    fn limitation_message_mentions_c_eval_gap() {
        let msg: &str = LIMITATION_MESSAGE;
        assert!(msg.contains("PyEval_EvalCode"));
        assert!(msg.contains("v0.2"));
    }
}
