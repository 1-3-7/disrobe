use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::error::{CextractError, Result};
use crate::marshal_writer::{WrittenPyc, blake3_hex, checked_pyc_len, write_pyc};

static CACHED_CODE_TYPE: OnceLock<Py<PyAny>> = OnceLock::new();
static CACHED_MARSHAL: OnceLock<Py<PyModule>> = OnceLock::new();

pub(crate) fn preload_python_handles(py: Python<'_>) -> Result<()> {
    let types_mod: Bound<'_, PyModule> = py.import("types")?;
    let code_type: Bound<'_, PyAny> = types_mod.getattr("CodeType")?;
    let _ = CACHED_CODE_TYPE.set(code_type.unbind());
    let marshal: Bound<'_, PyModule> = py.import("marshal")?;
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

const MAX_CAPTURED_CODE_OBJECTS: usize = 65_536;
const MAX_CAPTURED_PYC_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct CaptureBuffer {
    pub state: Mutex<CaptureState>,
}

#[derive(Debug, Default)]
pub(crate) struct CaptureState {
    pub out_dir: PathBuf,
    pub wrapper_stem: String,
    pub magic_number: [u8; 4],
    pub written: Vec<WrittenPyc>,
    pub seen: BTreeSet<String>,
    pub total_written_bytes: usize,
}

impl CaptureBuffer {
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(CaptureState {
                out_dir: PathBuf::new(),
                wrapper_stem: String::new(),
                magic_number: [0u8; 4],
                written: Vec::new(),
                seen: BTreeSet::new(),
                total_written_bytes: 0,
            }),
        }
    }

    pub(crate) fn reconfigure(
        &self,
        out_dir: PathBuf,
        wrapper_stem: String,
        magic_number: [u8; 4],
    ) -> Result<()> {
        let mut g: std::sync::MutexGuard<'_, CaptureState> = self
            .state
            .lock()
            .map_err(|_| CextractError::LockPoisoned("capture-state"))?;
        g.out_dir = out_dir;
        g.wrapper_stem = wrapper_stem;
        g.magic_number = magic_number;
        g.written.clear();
        g.seen.clear();
        g.total_written_bytes = 0;
        drop(g);
        Ok(())
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
        g.total_written_bytes = 0;
        Ok(core::mem::take(&mut g.written))
    }
}

#[inline]
fn should_skip(co_filename: &str, co_name: &str) -> bool {
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
        .map_err(CextractError::from)?;
    let co_name: String = code_obj
        .getattr("co_name")
        .and_then(|n: Bound<'_, PyAny>| n.extract::<String>())
        .map_err(CextractError::from)?;
    if should_skip(&co_filename, &co_name) {
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
            .cast_into::<PyBytes>()
            .map_err(|e: pyo3::CastIntoError<'_>| {
                CextractError::MarshalDumpFailed(format!("marshal.dumps returned non-bytes: {e}"))
            })?;
    let body: &[u8] = bytes_obj.as_bytes();
    let body_hash: String = blake3_hex(body);

    let mut state: std::sync::MutexGuard<'_, CaptureState> = buffer
        .state
        .lock()
        .map_err(|_| CextractError::LockPoisoned("capture-state"))?;
    if state.seen.contains(&body_hash) {
        return Ok(());
    }
    let pyc_len: usize = checked_pyc_len(body.len())?;
    let next_total: usize = checked_capture_budget(&state, pyc_len)?;
    let next_index: usize = state.written.len();
    let out_dir: PathBuf = state.out_dir.clone();
    let wrapper_stem: String = state.wrapper_stem.clone();
    let magic_number: [u8; 4] = state.magic_number;
    let written: WrittenPyc = write_pyc(&out_dir, &wrapper_stem, next_index, body, magic_number)?;
    state.seen.insert(body_hash);
    state.total_written_bytes = next_total;
    state.written.push(written);
    drop(state);
    Ok(())
}

const fn checked_capture_budget(state: &CaptureState, next_pyc_len: usize) -> Result<usize> {
    if state.written.len() >= MAX_CAPTURED_CODE_OBJECTS {
        return Err(CextractError::CaptureLimit {
            field: "code objects",
            value: state.written.len().saturating_add(1),
            limit: MAX_CAPTURED_CODE_OBJECTS,
        });
    }
    let Some(next_total): Option<usize> = state.total_written_bytes.checked_add(next_pyc_len)
    else {
        return Err(CextractError::CaptureLimit {
            field: "bytes",
            value: usize::MAX,
            limit: MAX_CAPTURED_PYC_BYTES,
        });
    };
    if next_total > MAX_CAPTURED_PYC_BYTES {
        return Err(CextractError::CaptureLimit {
            field: "bytes",
            value: next_total,
            limit: MAX_CAPTURED_PYC_BYTES,
        });
    }
    Ok(next_total)
}

fn is_code_type(py: Python<'_>, obj: &Bound<'_, PyAny>) -> Result<bool> {
    let Some(handle): Option<&Py<PyAny>> = CACHED_CODE_TYPE.get() else {
        let types_mod: Bound<'_, PyModule> = py.import("types")?;
        let code_type: Bound<'_, PyAny> = types_mod.getattr("CodeType")?;
        let is_instance: bool = obj.is_instance(&code_type)?;
        return Ok(is_instance);
    };
    let is_instance: bool = obj.is_instance(handle.bind(py))?;
    Ok(is_instance)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        CaptureState, FILTER_NEEDLES, MAX_CAPTURED_CODE_OBJECTS, MAX_CAPTURED_PYC_BYTES,
        checked_capture_budget, should_skip,
    };
    use crate::marshal_writer::{PYC_HEADER_LEN, WrittenPyc};

    #[test]
    fn skip_recognizes_unix_stdlib_path() {
        assert!(should_skip("/usr/lib/python3.11/runpy.py", "_run_code"));
    }

    #[test]
    fn skip_recognizes_windows_stdlib_path() {
        assert!(should_skip("C:\\Python311\\lib\\runpy.py", "_run_code"));
    }

    #[test]
    fn skip_recognizes_site_packages() {
        assert!(should_skip(
            "/home/user/.venv/lib/python3.11/site-packages/foo.py",
            "main"
        ));
    }

    #[test]
    fn skip_recognizes_helper_script() {
        assert!(should_skip("/tmp/.disrobe_v6v7_helper.py", "main"));
    }

    #[test]
    fn skip_passes_wrapper_script_even_if_lib_substring_anywhere() {
        let pass: bool = !should_skip("/home/me/projects/hello.py", "<module>");
        assert!(pass);
    }

    #[test]
    fn skip_passes_arbitrary_user_module() {
        assert!(!should_skip("/home/me/myapp/main.py", "main"));
    }

    #[test]
    fn skip_blocks_frozen_importlib_bootstrap() {
        assert!(should_skip(
            "<frozen importlib._bootstrap>",
            "_find_and_load"
        ));
    }

    #[test]
    fn skip_blocks_internal_call_with_frames_removed() {
        assert!(should_skip(
            "<frozen importlib._bootstrap>",
            "_call_with_frames_removed"
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
        assert!(should_skip("/tmp/disrobe_cextract/.venv/foo.py", "main"));
    }

    #[test]
    fn capture_budget_rejects_count_cap() {
        let mut state: CaptureState = CaptureState::default();
        state
            .written
            .resize_with(MAX_CAPTURED_CODE_OBJECTS, || WrittenPyc {
                path: std::path::PathBuf::new(),
                blake3_hex: String::new(),
                size: PYC_HEADER_LEN,
            });
        assert!(checked_capture_budget(&state, PYC_HEADER_LEN).is_err());
    }

    #[test]
    fn capture_budget_rejects_byte_cap() {
        let state: CaptureState = CaptureState {
            total_written_bytes: MAX_CAPTURED_PYC_BYTES,
            ..CaptureState::default()
        };
        assert!(checked_capture_budget(&state, 1).is_err());
    }
}
