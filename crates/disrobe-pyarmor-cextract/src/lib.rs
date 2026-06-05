#![allow(clippy::needless_pass_by_value, clippy::redundant_pub_crate)]

mod capture;
mod error;
mod hotpatch;
mod intercept_legacy;
mod intercept_modern;
mod marshal_writer;

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyCFunction, PyDict, PyList, PyModule};

use crate::capture::{CaptureBuffer, capture_code_object, preload_python_handles};
use crate::error::{CextractError, Result};
use crate::hotpatch::HotpatchHandle;
use crate::intercept_modern::ModernInstallInfo;
use crate::marshal_writer::{WrittenPyc, ensure_writable};

const LIMITATION_MESSAGE: &str = "disrobe-pyarmor-cextract intercepts PyEval_EvalCode-bound \
    code objects via three backends: (1) PEP 669 sys.monitoring PY_START (Python 3.12+, lowest \
    blast radius), (2) PyEval_SetProfile (Python 3.9-3.11, no kernel/userspace patches), \
    (3) hotpatch (LD_PRELOAD-style on Linux/macOS, Microsoft-Detours-style on Windows; \
    patches PyEval_EvalCode in memory, fires regardless of monitoring/profiling state, but \
    requires writable+executable page permissions). Backend selected via \
    DISROBE_CEXTRACT_BACKEND env var or auto-fallback (modern -> legacy -> hotpatch last-resort). \
    Residual gaps: (1) BCC native-body (no Python frame, out-of-scope by definition), \
    (2) PyArmor builds that don't call PyEval_EvalCode at all (e.g. directly emit native \
    machine code - would require BCC native lift in pyarmor crate), (3) hardened Linux \
    distributions with kernel.exec_writes=0 or W^X enforcement that disable mprotect-to-executable \
    (very rare in development environments).";

static ACTIVE_BUFFER: OnceLock<&'static CaptureBuffer> = OnceLock::new();
static MODERN_INSTALL: Mutex<Option<ModernInstallInfo>> = Mutex::new(None);
static LEGACY_INSTALLED: Mutex<bool> = Mutex::new(false);
static HOTPATCH_INSTALL: Mutex<Option<HotpatchHandle>> = Mutex::new(None);

#[derive(Debug)]
enum InstalledBackend {
    Modern,
    Legacy,
    Hotpatch,
    None,
}

fn current_backend() -> Result<InstalledBackend> {
    let modern: bool = MODERN_INSTALL
        .lock()
        .map_err(|_| CextractError::LockPoisoned("modern-install"))?
        .is_some();
    if modern {
        return Ok(InstalledBackend::Modern);
    }
    let legacy: bool = *LEGACY_INSTALLED
        .lock()
        .map_err(|_| CextractError::LockPoisoned("legacy-install"))?;
    if legacy {
        return Ok(InstalledBackend::Legacy);
    }
    let hot: bool = HOTPATCH_INSTALL
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-install"))?
        .is_some();
    if hot {
        return Ok(InstalledBackend::Hotpatch);
    }
    Ok(InstalledBackend::None)
}

fn buffer_or_err() -> Result<&'static CaptureBuffer> {
    ACTIVE_BUFFER
        .get()
        .copied()
        .ok_or(CextractError::NotInstalled)
}

#[pyfunction]
#[pyo3(signature = (out_dir, wrapper_stem, magic_number, prefer=None))]
fn install_intercept(
    py: Python<'_>,
    out_dir: PathBuf,
    wrapper_stem: String,
    magic_number: Vec<u8>,
    prefer: Option<String>,
) -> PyResult<String> {
    if magic_number.len() < 4 {
        return Err(PyRuntimeError::new_err(format!(
            "CEXT-0012: magic_number must be at least 4 bytes (got {})",
            magic_number.len()
        )));
    }
    if !matches!(current_backend()?, InstalledBackend::None) {
        return Err(CextractError::AlreadyInstalled.into());
    }
    ensure_writable(&out_dir)?;
    preload_python_handles(py)?;
    let mn: [u8; 4] = [
        magic_number[0],
        magic_number[1],
        magic_number[2],
        magic_number[3],
    ];
    let buffer_box: Box<CaptureBuffer> = Box::new(CaptureBuffer::new(out_dir, wrapper_stem, mn));
    let buffer_ref: &'static CaptureBuffer = Box::leak(buffer_box);
    let _ = ACTIVE_BUFFER.set(buffer_ref);

    let backend: &'static str = pick_backend(py, prefer.as_deref());
    match backend {
        "modern" => {
            install_modern(py, buffer_ref)?;
            Ok("modern".to_owned())
        }
        "legacy" => {
            install_legacy(buffer_ref)?;
            Ok("legacy".to_owned())
        }
        "hotpatch" => {
            install_hotpatch_backend(buffer_ref)?;
            Ok("hotpatch".to_owned())
        }
        _ => Err(PyRuntimeError::new_err(
            "CEXT-0013: no supported backend on this Python version".to_owned(),
        )),
    }
}

fn env_backend_override() -> Option<String> {
    std::env::var("DISROBE_CEXTRACT_BACKEND")
        .ok()
        .map(|s: String| s.to_lowercase())
}

fn pick_backend(py: Python<'_>, prefer: Option<&str>) -> &'static str {
    let env: Option<String> = env_backend_override();
    let effective: Option<&str> = prefer.or(env.as_deref());
    match effective {
        Some("modern") if intercept_modern::supported(py) => "modern",
        Some("legacy") if intercept_legacy::supported(py) => "legacy",
        Some("hotpatch") if hotpatch::supported() => "hotpatch",
        Some("modern" | "legacy" | "hotpatch") => "none",
        _ => {
            if intercept_modern::supported(py) {
                "modern"
            } else if intercept_legacy::supported(py) {
                "legacy"
            } else if hotpatch::supported() {
                "hotpatch"
            } else {
                "none"
            }
        }
    }
}

fn install_modern(py: Python<'_>, buffer: &'static CaptureBuffer) -> PyResult<()> {
    let callback: Bound<'_, PyCFunction> = wrap_pyfunction!(_modern_py_start, py)?;
    let info: ModernInstallInfo = intercept_modern::install(py, callback)?;
    *MODERN_INSTALL
        .lock()
        .map_err(|_| CextractError::LockPoisoned("modern-install"))? = Some(info);
    let _: bool = ACTIVE_BUFFER.set(buffer).is_ok();
    Ok(())
}

fn install_legacy(buffer: &'static CaptureBuffer) -> PyResult<()> {
    intercept_legacy::install(buffer)?;
    *LEGACY_INSTALLED
        .lock()
        .map_err(|_| CextractError::LockPoisoned("legacy-install"))? = true;
    Ok(())
}

fn install_hotpatch_backend(buffer: &'static CaptureBuffer) -> PyResult<()> {
    let handle: HotpatchHandle = hotpatch::install_hotpatch(buffer)?;
    *HOTPATCH_INSTALL
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-install"))? = Some(handle);
    Ok(())
}

thread_local! {
    static REENTRY_GUARD: Cell<bool> = const { Cell::new(false) };
}

#[pyfunction]
fn _modern_py_start(py: Python<'_>, code: Bound<'_, PyAny>, _offset: Bound<'_, PyAny>) -> PyObject {
    if REENTRY_GUARD.with(|g: &Cell<bool>| g.replace(true)) {
        return py.None();
    }
    let result: PyObject = inner_modern_py_start(py, &code);
    REENTRY_GUARD.with(|g: &Cell<bool>| g.set(false));
    result
}

fn inner_modern_py_start(py: Python<'_>, code: &Bound<'_, PyAny>) -> PyObject {
    let Ok(buffer): Result<&'static CaptureBuffer> = buffer_or_err() else {
        return py.None();
    };
    let _: Result<()> = capture_code_object(py, code, buffer);
    py.None()
}

#[pyfunction]
fn uninstall_intercept(py: Python<'_>) -> PyResult<usize> {
    let count: usize = match current_backend()? {
        InstalledBackend::Modern => {
            let info: ModernInstallInfo = MODERN_INSTALL
                .lock()
                .map_err(|_| CextractError::LockPoisoned("modern-install"))?
                .take()
                .ok_or(CextractError::NotInstalled)?;
            intercept_modern::uninstall(py, info)?;
            buffer_or_err().map_or(0, |b: &'static CaptureBuffer| b.count().unwrap_or(0))
        }
        InstalledBackend::Legacy => {
            intercept_legacy::uninstall()?;
            *LEGACY_INSTALLED
                .lock()
                .map_err(|_| CextractError::LockPoisoned("legacy-install"))? = false;
            buffer_or_err().map_or(0, |b: &'static CaptureBuffer| b.count().unwrap_or(0))
        }
        InstalledBackend::Hotpatch => {
            let handle: HotpatchHandle = HOTPATCH_INSTALL
                .lock()
                .map_err(|_| CextractError::LockPoisoned("hotpatch-install"))?
                .take()
                .ok_or(CextractError::NotInstalled)?;
            hotpatch::uninstall_hotpatch(handle)?;
            buffer_or_err().map_or(0, |b: &'static CaptureBuffer| b.count().unwrap_or(0))
        }
        InstalledBackend::None => 0,
    };
    Ok(count)
}

#[pyfunction]
fn captured_count() -> PyResult<usize> {
    match buffer_or_err() {
        Ok(b) => Ok(b.count()?),
        Err(_) => Ok(0),
    }
}

#[pyfunction]
fn drain_into_manifest(py: Python<'_>) -> PyResult<PyObject> {
    let buffer: &'static CaptureBuffer = buffer_or_err()?;
    let written: Vec<WrittenPyc> = buffer.drain()?;
    let list: Bound<'_, PyList> = PyList::empty(py);
    for w in written {
        let entry: Bound<'_, PyDict> = PyDict::new(py);
        entry.set_item("pyc_path", w.path.display().to_string())?;
        entry.set_item("size", w.size)?;
        entry.set_item("blake3", w.blake3_hex)?;
        list.append(entry)?;
    }
    Ok(list.into())
}

#[pyfunction]
fn backend_info(py: Python<'_>) -> PyResult<PyObject> {
    let d: Bound<'_, PyDict> = PyDict::new(py);
    d.set_item("modern_supported", intercept_modern::supported(py))?;
    d.set_item("legacy_supported", intercept_legacy::supported(py))?;
    d.set_item("hotpatch_supported", hotpatch::supported())?;
    let current: &'static str = match current_backend()? {
        InstalledBackend::Modern => "modern",
        InstalledBackend::Legacy => "legacy",
        InstalledBackend::Hotpatch => "hotpatch",
        InstalledBackend::None => "none",
    };
    d.set_item("current", current)?;
    if matches!(current_backend()?, InstalledBackend::Hotpatch)
        && let Ok(g) = HOTPATCH_INSTALL.lock()
        && let Some(handle) = g.as_ref()
    {
        d.set_item("patched_addr", format!("0x{:x}", handle.target_addr))?;
        d.set_item("trampoline_addr", format!("0x{:x}", handle.trampoline_addr))?;
        let bytes_list: Bound<'_, PyList> = PyList::empty(py);
        for &b in &handle.saved_prologue {
            bytes_list.append(b)?;
        }
        d.set_item("saved_prologue_bytes", bytes_list)?;
        d.set_item("saved_prologue_len", handle.saved_prologue_len)?;
    }
    Ok(d.into())
}

#[pyfunction]
const fn limitation_notice() -> &'static str {
    LIMITATION_MESSAGE
}

#[pyfunction]
fn _hotpatch_selftest(py: Python<'_>) -> PyResult<PyObject> {
    use pyo3::types::PyTuple;

    let tmp_dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_cextract_hotpatch_selftest_{}",
        std::process::id()
    ));
    ensure_writable(&tmp_dir)?;
    preload_python_handles(py)?;

    let mn_obj: Bound<'_, PyAny> = py.import("importlib.util")?.getattr("MAGIC_NUMBER")?;
    let mn_bytes: Bound<'_, PyBytes> = mn_obj
        .downcast_into::<PyBytes>()
        .map_err(|e: pyo3::DowncastIntoError<'_>| PyRuntimeError::new_err(e.to_string()))?;
    let mn: [u8; 4] = {
        let raw: &[u8] = mn_bytes.as_bytes();
        if raw.len() < 4 {
            return Err(PyRuntimeError::new_err("MAGIC_NUMBER too short".to_owned()));
        }
        [raw[0], raw[1], raw[2], raw[3]]
    };
    let buffer_box: Box<CaptureBuffer> = Box::new(CaptureBuffer::new(
        tmp_dir,
        "hotpatch_selftest".to_owned(),
        mn,
    ));
    let buffer_ref: &'static CaptureBuffer = Box::leak(buffer_box);
    let _ = ACTIVE_BUFFER.set(buffer_ref);

    let handle: HotpatchHandle = hotpatch::install_hotpatch(buffer_ref)
        .map_err(|e: CextractError| PyRuntimeError::new_err(e.to_string()))?;
    *HOTPATCH_INSTALL
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-install"))? = Some(handle);

    let builtins: Bound<'_, PyModule> = py.import("builtins")?;
    let code_obj: Bound<'_, PyAny> = builtins.call_method1(
        "compile",
        (
            "DISROBE_HOTPATCH_SELFTEST_SENTINEL = 0xC0FFEE\n",
            "<hotpatch_selftest>",
            "exec",
        ),
    )?;

    let ctypes_mod: Bound<'_, PyModule> = py.import("ctypes")?;
    let pyapi: Bound<'_, PyAny> = ctypes_mod.getattr("pythonapi")?;
    let eval_code_attr: Bound<'_, PyAny> = pyapi.getattr("PyEval_EvalCode")?;
    let py_object: Bound<'_, PyAny> = ctypes_mod.getattr("py_object")?;
    let argtypes: Bound<'_, PyTuple> = PyTuple::new(
        py,
        [py_object.clone(), py_object.clone(), py_object.clone()],
    )?;
    eval_code_attr.setattr("argtypes", argtypes)?;
    eval_code_attr.setattr("restype", &py_object)?;

    let globals: Bound<'_, PyDict> = PyDict::new(py);
    globals.set_item("__name__", "__hotpatch_selftest__")?;
    eval_code_attr.call1((&code_obj, &globals, &globals))?;
    let sentinel_value: i64 = globals
        .get_item("DISROBE_HOTPATCH_SELFTEST_SENTINEL")?
        .ok_or_else(|| PyRuntimeError::new_err("sentinel was not set"))?
        .extract::<i64>()?;
    if sentinel_value != 0x00C0_FFEE {
        return Err(PyRuntimeError::new_err(format!(
            "sentinel mismatch: 0x{sentinel_value:x}"
        )));
    }
    let captured_before: usize = buffer_ref.count()?;

    let handle2: HotpatchHandle = HOTPATCH_INSTALL
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-install"))?
        .take()
        .ok_or(CextractError::NotInstalled)?;
    hotpatch::uninstall_hotpatch(handle2)
        .map_err(|e: CextractError| PyRuntimeError::new_err(e.to_string()))?;

    let post_globals: Bound<'_, PyDict> = PyDict::new(py);
    post_globals.set_item("__name__", "__hotpatch_postcheck__")?;
    let post_code: Bound<'_, PyAny> = builtins.call_method1(
        "compile",
        ("DISROBE_POSTCHECK = 1\n", "<post_uninstall>", "exec"),
    )?;
    eval_code_attr.call1((&post_code, &post_globals, &post_globals))?;
    let post_ok: bool = post_globals.get_item("DISROBE_POSTCHECK")?.is_some();

    let result: Bound<'_, PyDict> = PyDict::new(py);
    result.set_item("captured", captured_before)?;
    result.set_item("post_uninstall_eval_works", post_ok)?;
    result.set_item("sentinel_value", sentinel_value)?;
    Ok(result.into())
}

#[pyfunction]
fn _selftest_marshal_roundtrip(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    let code: Bound<'_, PyAny> = py
        .import("builtins")?
        .call_method1("compile", ("x = 1\n", "<selftest>", "exec"))?;
    let marshal: Bound<'_, PyModule> = py.import("marshal")?;
    let out: Bound<'_, PyBytes> = marshal
        .call_method1("dumps", (code,))?
        .downcast_into::<PyBytes>()
        .map_err(|e: pyo3::DowncastIntoError<'_>| PyRuntimeError::new_err(e.to_string()))?;
    Ok(out.unbind())
}

#[pymodule]
fn disrobe_cextract(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(install_intercept, m)?)?;
    m.add_function(wrap_pyfunction!(uninstall_intercept, m)?)?;
    m.add_function(wrap_pyfunction!(captured_count, m)?)?;
    m.add_function(wrap_pyfunction!(drain_into_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(backend_info, m)?)?;
    m.add_function(wrap_pyfunction!(limitation_notice, m)?)?;
    m.add_function(wrap_pyfunction!(_modern_py_start, m)?)?;
    m.add_function(wrap_pyfunction!(_selftest_marshal_roundtrip, m)?)?;
    m.add_function(wrap_pyfunction!(_hotpatch_selftest, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__limitation__", LIMITATION_MESSAGE)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::LIMITATION_MESSAGE;

    #[test]
    fn limitation_message_documents_both_backends() {
        let m: &str = LIMITATION_MESSAGE;
        assert!(m.contains("sys.monitoring"));
        assert!(m.contains("PyEval_SetProfile"));
        assert!(m.contains("3.12+"));
        assert!(m.contains("3.9-3.11"));
    }

    #[test]
    fn limitation_message_documents_residual_gaps() {
        let m: &str = LIMITATION_MESSAGE;
        assert!(m.contains("BCC"));
        assert!(m.contains("hotpatch"));
    }

    #[test]
    fn limitation_message_documents_hotpatch_backend() {
        let m: &str = LIMITATION_MESSAGE;
        assert!(m.contains("hotpatch"));
        assert!(m.contains("DISROBE_CEXTRACT_BACKEND"));
        assert!(m.contains("LD_PRELOAD") || m.contains("Detours"));
    }
}
