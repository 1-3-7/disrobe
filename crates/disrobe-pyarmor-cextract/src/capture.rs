use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::error::{CextractError, Result};
use crate::marshal_writer::{WrittenPyc, blake3_hex, write_pyc};

static CACHED_CODE_TYPE: OnceLock<Py<PyAny>> = OnceLock::new();
static CACHED_MARSHAL: OnceLock<Py<PyModule>> = OnceLock::new();

pub(crate) fn preload_python_handles(py: Python<'_>) -> Result<()> {
    let types_mod: Bound<'_, PyModule> = py.import("types").map_err(CextractError::from)?;
    let code_type: Bound<'_, PyAny> = types_mod.getattr("CodeType").map_err(CextractError::from)?;
    let _ = CACHED_CODE_TYPE.set(code_type.unbind());
    let marshal: Bound<'_, PyModule> = py.import("marshal").map_err(CextractError::from)?;
    let _ = CACHED_MARSHAL.set(marshal.unbind());
    Ok(())
}

const FILTER_NEEDLES: [&str; 9] = [
    "/lib/",
    "\\lib\\",
    "site-packages",
    "v6v7_dynamic_hook",
    ".disrobe_v6v7_helper",
    ".disrobe_dynamic",
    "disrobe_cextract",
    "disrobe_pytrace",
    "<frozen importlib._bootstrap",
];

#[derive(Debug)]
pub(crate) struct CaptureBuffer {
    pub out_dir: PathBuf,
    pub wrapper_stem: String,
    pub magic_number: [u8; 4],
    pub state: Mutex<CaptureState>,
}

#[derive(Debug, Default)]
pub(crate) struct CaptureState {
    pub written: Vec<WrittenPyc>,
    pub seen: Vec<String>,
}

impl CaptureBuffer {
    pub(crate) fn new(out_dir: PathBuf, wrapper_stem: String, magic_number: [u8; 4]) -> Self {
        Self {
            out_dir,
            wrapper_stem,
            magic_number,
            state: Mutex::new(CaptureState::default()),
        }
    }

    pub(crate) fn count(&self) -> Result<usize> {
        let g: std::sync::MutexGuard<'_, CaptureState> = self
            .state
            .lock()
            .map_err(|_| CextractError::LockPoisoned("capture-state"))?;
        Ok(g.written.len())
    }

    pub(crate) fn drain(&self) -> Result<Vec<WrittenPyc>> {
        let mut g: std::sync::MutexGuard<'_, CaptureState> = self
            .state
            .lock()
            .map_err(|_| CextractError::LockPoisoned("capture-state"))?;
        g.seen.clear();
        Ok(core::mem::take(&mut g.written))
    }
}

#[inline]
fn should_skip(co_filename: &str, co_name: &str, _wrapper_stem: &str) -> bool {
    if matches!(
        co_name,
        "<frozen importlib._bootstrap>"
            | "_call_with_frames_removed"
            | "_find_and_load"
            | "_find_and_load_unlocked"
            | "_handle_fromlist"
            | "_bootstrap_inner"
    ) {
        return true;
    }
    let lower: String = co_filename.to_lowercase();
    FILTER_NEEDLES
        .iter()
        .any(|n: &&'static str| lower.contains(n))
}

pub(crate) fn capture_code_object(
    py: Python<'_>,
    code_obj: &Bound<'_, PyAny>,
    buffer: &CaptureBuffer,
) -> Result<()> {
    if !is_code_type(py, code_obj)? {
        return Ok(());
    }
    let co_filename: String = code_obj
        .getattr("co_filename")
        .and_then(|f: Bound<'_, PyAny>| f.extract::<String>())
        .unwrap_or_default();
    let co_name: String = code_obj
        .getattr("co_name")
        .and_then(|n: Bound<'_, PyAny>| n.extract::<String>())
        .unwrap_or_default();
    if should_skip(&co_filename, &co_name, &buffer.wrapper_stem) {
        return Ok(());
    }

    let marshal_handle: &Py<PyModule> = CACHED_MARSHAL.get().ok_or_else(|| {
        CextractError::MarshalDumpFailed("marshal handle not preloaded".to_owned())
    })?;
    let marshal_bound: &Bound<'_, PyModule> = marshal_handle.bind(py);
    let dumped: Bound<'_, PyAny> = marshal_bound
        .call_method1("dumps", (code_obj, 4i32))
        .map_err(|e: PyErr| CextractError::MarshalDumpFailed(e.to_string()))?;
    let bytes_obj: Bound<'_, PyBytes> =
        dumped
            .downcast_into::<PyBytes>()
            .map_err(|e: pyo3::DowncastIntoError<'_>| {
                CextractError::MarshalDumpFailed(format!("marshal.dumps returned non-bytes: {e}"))
            })?;
    let body: &[u8] = bytes_obj.as_bytes();
    let body_hash: String = blake3_hex(body);

    let next_index: usize = {
        let mut state: std::sync::MutexGuard<'_, CaptureState> = buffer
            .state
            .lock()
            .map_err(|_| CextractError::LockPoisoned("capture-state"))?;
        if state.seen.iter().any(|h: &String| h == &body_hash) {
            return Ok(());
        }
        state.seen.push(body_hash);
        state.written.len()
    };
    let written: WrittenPyc = write_pyc(
        &buffer.out_dir,
        &buffer.wrapper_stem,
        next_index,
        body,
        buffer.magic_number,
    )?;
    let mut state: std::sync::MutexGuard<'_, CaptureState> = buffer
        .state
        .lock()
        .map_err(|_| CextractError::LockPoisoned("capture-state"))?;
    state.written.push(written);
    drop(state);
    Ok(())
}

fn is_code_type(py: Python<'_>, obj: &Bound<'_, PyAny>) -> Result<bool> {
    let Some(handle): Option<&Py<PyAny>> = CACHED_CODE_TYPE.get() else {
        let types_mod: Bound<'_, PyModule> = py.import("types").map_err(CextractError::from)?;
        let code_type: Bound<'_, PyAny> =
            types_mod.getattr("CodeType").map_err(CextractError::from)?;
        return Ok(obj.is_instance(&code_type).unwrap_or(false));
    };
    Ok(obj.is_instance(handle.bind(py)).unwrap_or(false))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{FILTER_NEEDLES, should_skip};

    #[test]
    fn skip_recognizes_unix_stdlib_path() {
        assert!(should_skip(
            "/usr/lib/python3.11/runpy.py",
            "_run_code",
            "hello"
        ));
    }

    #[test]
    fn skip_recognizes_windows_stdlib_path() {
        assert!(should_skip(
            "C:\\Python311\\lib\\runpy.py",
            "_run_code",
            "hello"
        ));
    }

    #[test]
    fn skip_recognizes_site_packages() {
        assert!(should_skip(
            "/home/user/.venv/lib/python3.11/site-packages/foo.py",
            "main",
            "hello"
        ));
    }

    #[test]
    fn skip_recognizes_helper_script() {
        assert!(should_skip("/tmp/.disrobe_v6v7_helper.py", "main", "hello"));
    }

    #[test]
    fn skip_passes_wrapper_script_even_if_lib_substring_anywhere() {
        let pass: bool = !should_skip("/home/me/projects/hello.py", "<module>", "hello");
        assert!(pass);
    }

    #[test]
    fn skip_passes_arbitrary_user_module() {
        assert!(!should_skip("/home/me/myapp/main.py", "main", "main"));
    }

    #[test]
    fn skip_blocks_frozen_importlib_bootstrap() {
        assert!(should_skip(
            "<frozen importlib._bootstrap>",
            "_find_and_load",
            "hello"
        ));
    }

    #[test]
    fn skip_blocks_internal_call_with_frames_removed() {
        assert!(should_skip(
            "<frozen importlib._bootstrap>",
            "_call_with_frames_removed",
            "hello"
        ));
    }

    #[test]
    fn filter_needles_non_empty() {
        for n in FILTER_NEEDLES {
            assert!(!n.is_empty());
        }
    }

    #[test]
    fn skip_blocks_self_module_under_disrobe_cextract() {
        assert!(should_skip(
            "/tmp/disrobe_cextract/.venv/foo.py",
            "main",
            "hello"
        ));
    }
}
