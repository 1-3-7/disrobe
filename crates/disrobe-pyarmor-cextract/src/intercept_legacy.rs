use core::cell::Cell;
use core::ffi::{c_int, c_void};
use core::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{LockResult, Mutex, MutexGuard};

use pyo3::ffi::PyObject;
use pyo3::prelude::*;

use crate::capture::{CaptureBuffer, capture_code_object};
use crate::error::{CextractError, Result};

#[allow(non_camel_case_types)]
pub(crate) type Py_tracefunc = unsafe extern "C" fn(
    obj: *mut PyObject,
    frame: *mut PyObject,
    what: c_int,
    arg: *mut PyObject,
) -> c_int;

#[allow(non_camel_case_types)]
type PyEvalSetProfileFn = unsafe extern "C" fn(Option<Py_tracefunc>, *mut PyObject);

pub(crate) const PY_TRACE_CALL: c_int = 0;

static ACTIVE_BUFFER: Mutex<Option<&'static CaptureBuffer>> = Mutex::new(None);
static INSTALLED_FLAG: AtomicBool = AtomicBool::new(false);
static RESOLVED_SETPROFILE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

thread_local! {
    static LEGACY_GUARD: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "C" fn profile_callback(
    _obj: *mut PyObject,
    frame: *mut PyObject,
    what: c_int,
    _arg: *mut PyObject,
) -> c_int {
    if what != PY_TRACE_CALL {
        return 0;
    }
    if frame.is_null() {
        return 0;
    }
    if LEGACY_GUARD.with(|g: &Cell<bool>| g.replace(true)) {
        return 0;
    }
    let Ok(g): LockResult<MutexGuard<'_, Option<&'static CaptureBuffer>>> = ACTIVE_BUFFER.lock()
    else {
        LEGACY_GUARD.with(|g: &Cell<bool>| g.set(false));
        return 0;
    };
    let buffer_ref: Option<&'static CaptureBuffer> = *g;
    drop(g);
    if let Some(buffer) = buffer_ref {
        let _: Result<()> = Python::with_gil(|py: Python<'_>| {
            let frame_bound: Bound<'_, PyAny> = unsafe { Bound::from_borrowed_ptr(py, frame) };
            let code_obj: Bound<'_, PyAny> = frame_bound.getattr("f_code")?;
            capture_code_object(py, &code_obj, buffer)
        });
    }
    LEGACY_GUARD.with(|g: &Cell<bool>| g.set(false));
    0
}

#[cfg(target_os = "windows")]
fn resolve_setprofile() -> Option<PyEvalSetProfileFn> {
    use core::ffi::CStr;
    unsafe extern "system" {
        fn GetModuleHandleA(lpModuleName: *const u8) -> *mut c_void;
        fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    }
    let already: *mut c_void = RESOLVED_SETPROFILE.load(Ordering::Acquire);
    if !already.is_null() {
        return Some(unsafe { core::mem::transmute::<*mut c_void, PyEvalSetProfileFn>(already) });
    }
    let proc_name: &CStr = c"PyEval_SetProfile";
    let candidates: [&[u8]; 5] = [
        b"python314.dll\0",
        b"python313.dll\0",
        b"python312.dll\0",
        b"python311.dll\0",
        b"python310.dll\0",
    ];
    for needle in candidates {
        let h: *mut c_void = unsafe { GetModuleHandleA(needle.as_ptr()) };
        if h.is_null() {
            continue;
        }
        let p: *mut c_void = unsafe { GetProcAddress(h, proc_name.as_ptr().cast()) };
        if !p.is_null() {
            RESOLVED_SETPROFILE.store(p, Ordering::Release);
            return Some(unsafe { core::mem::transmute::<*mut c_void, PyEvalSetProfileFn>(p) });
        }
    }
    for candidate in [b"python39.dll\0".as_ref(), b"python38.dll\0".as_ref()] {
        let h: *mut c_void = unsafe { GetModuleHandleA(candidate.as_ptr()) };
        if h.is_null() {
            continue;
        }
        let p: *mut c_void = unsafe { GetProcAddress(h, proc_name.as_ptr().cast()) };
        if !p.is_null() {
            RESOLVED_SETPROFILE.store(p, Ordering::Release);
            return Some(unsafe { core::mem::transmute::<*mut c_void, PyEvalSetProfileFn>(p) });
        }
    }
    let null_h: *mut c_void = unsafe { GetModuleHandleA(ptr::null()) };
    if !null_h.is_null() {
        let p: *mut c_void = unsafe { GetProcAddress(null_h, proc_name.as_ptr().cast()) };
        if !p.is_null() {
            RESOLVED_SETPROFILE.store(p, Ordering::Release);
            return Some(unsafe { core::mem::transmute::<*mut c_void, PyEvalSetProfileFn>(p) });
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn resolve_setprofile() -> Option<PyEvalSetProfileFn> {
    use core::ffi::CStr;
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const u8) -> *mut c_void;
    }
    const RTLD_DEFAULT: *mut c_void = ptr::null_mut();
    let already: *mut c_void = RESOLVED_SETPROFILE.load(Ordering::Acquire);
    if !already.is_null() {
        return Some(unsafe { core::mem::transmute::<*mut c_void, PyEvalSetProfileFn>(already) });
    }
    let proc_name: &CStr = c"PyEval_SetProfile";
    let p: *mut c_void = unsafe { dlsym(RTLD_DEFAULT, proc_name.as_ptr().cast()) };
    if p.is_null() {
        return None;
    }
    RESOLVED_SETPROFILE.store(p, Ordering::Release);
    Some(unsafe { core::mem::transmute::<*mut c_void, PyEvalSetProfileFn>(p) })
}

pub(crate) fn install(buffer: &'static CaptureBuffer) -> Result<()> {
    if INSTALLED_FLAG.load(Ordering::SeqCst) {
        return Err(CextractError::AlreadyInstalled);
    }
    let setprofile: PyEvalSetProfileFn = resolve_setprofile().ok_or_else(|| {
        CextractError::MonitoringSetup(
            "PyEval_SetProfile symbol not found in process address space".to_owned(),
        )
    })?;
    let mut guard: std::sync::MutexGuard<'_, Option<&'static CaptureBuffer>> = ACTIVE_BUFFER
        .lock()
        .map_err(|_| CextractError::LockPoisoned("active-buffer"))?;
    *guard = Some(buffer);
    drop(guard);
    unsafe {
        setprofile(Some(profile_callback), ptr::null_mut());
    }
    INSTALLED_FLAG.store(true, Ordering::SeqCst);
    Ok(())
}

pub(crate) fn uninstall() -> Result<()> {
    if !INSTALLED_FLAG.swap(false, Ordering::SeqCst) {
        return Err(CextractError::NotInstalled);
    }
    if let Some(setprofile) = resolve_setprofile() {
        unsafe {
            setprofile(None, ptr::null_mut());
        }
    }
    let mut guard: std::sync::MutexGuard<'_, Option<&'static CaptureBuffer>> = ACTIVE_BUFFER
        .lock()
        .map_err(|_| CextractError::LockPoisoned("active-buffer"))?;
    *guard = None;
    drop(guard);
    Ok(())
}

pub(crate) fn supported(py: Python<'_>) -> bool {
    let Ok(sys): PyResult<Bound<'_, pyo3::types::PyModule>> = py.import("sys") else {
        return false;
    };
    let Ok(version_info): PyResult<Bound<'_, PyAny>> = sys.getattr("version_info") else {
        return false;
    };
    let major: i32 = version_info
        .get_item(0)
        .and_then(|o: Bound<'_, PyAny>| o.extract::<i32>())
        .unwrap_or(0);
    let minor: i32 = version_info
        .get_item(1)
        .and_then(|o: Bound<'_, PyAny>| o.extract::<i32>())
        .unwrap_or(0);
    matches!((major, minor), (3, 9..=11)) && resolve_setprofile().is_some()
}
