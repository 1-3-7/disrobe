mod x86_disasm;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
mod unix;

use core::ffi::c_void;
use std::sync::Mutex;

use pyo3::ffi::PyObject;

use crate::capture::{CaptureBuffer, capture_code_object};
use crate::error::{CextractError, Result};

pub(crate) use x86_disasm::{MAX_PROLOGUE_SCAN, MIN_HOOK_BYTES, measure_prologue};

pub(crate) type PyEvalEvalCodeFn = unsafe extern "C" fn(
    code: *mut PyObject,
    globals: *mut PyObject,
    locals: *mut PyObject,
) -> *mut PyObject;

#[derive(Debug)]
pub(crate) struct HotpatchHandle {
    pub target_addr: usize,
    pub trampoline_addr: usize,
    pub saved_prologue: Vec<u8>,
    pub saved_prologue_len: usize,
    #[allow(dead_code)]
    pub trampoline_capacity: usize,
}

static TRAMPOLINE_FN: Mutex<Option<PyEvalEvalCodeFn>> = Mutex::new(None);
static ACTIVE_BUFFER: Mutex<Option<&'static CaptureBuffer>> = Mutex::new(None);

thread_local! {
    static REENTRY_GUARD: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

pub(crate) fn set_buffer(buffer: &'static CaptureBuffer) -> Result<()> {
    let mut g: std::sync::MutexGuard<'_, Option<&'static CaptureBuffer>> = ACTIVE_BUFFER
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-buffer"))?;
    *g = Some(buffer);
    drop(g);
    Ok(())
}

pub(crate) fn clear_buffer() -> Result<()> {
    let mut g: std::sync::MutexGuard<'_, Option<&'static CaptureBuffer>> = ACTIVE_BUFFER
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-buffer"))?;
    *g = None;
    drop(g);
    Ok(())
}

pub(crate) fn store_trampoline(fp: PyEvalEvalCodeFn) -> Result<()> {
    let mut g: std::sync::MutexGuard<'_, Option<PyEvalEvalCodeFn>> = TRAMPOLINE_FN
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-trampoline"))?;
    *g = Some(fp);
    drop(g);
    Ok(())
}

pub(crate) fn clear_trampoline() -> Result<()> {
    let mut g: std::sync::MutexGuard<'_, Option<PyEvalEvalCodeFn>> = TRAMPOLINE_FN
        .lock()
        .map_err(|_| CextractError::LockPoisoned("hotpatch-trampoline"))?;
    *g = None;
    drop(g);
    Ok(())
}

pub(crate) extern "C" fn evaluate_intercept(
    code: *mut PyObject,
    globals: *mut PyObject,
    locals: *mut PyObject,
) -> *mut PyObject {
    if !REENTRY_GUARD.with(|g: &core::cell::Cell<bool>| g.replace(true)) {
        if !code.is_null()
            && let Ok(buf_guard) = ACTIVE_BUFFER.lock()
            && let Some(buffer) = *buf_guard
        {
            drop(buf_guard);
            let result: Result<()> = pyo3::Python::attach(|py: pyo3::Python<'_>| {
                let bound: pyo3::Bound<'_, pyo3::PyAny> =
                    unsafe { pyo3::Bound::from_borrowed_ptr(py, code) };
                capture_code_object(py, &bound, buffer)
            });
            if let Err(error) = result {
                buffer.record_error(error);
            }
        }
        REENTRY_GUARD.with(|g: &core::cell::Cell<bool>| g.set(false));
    }
    let trampoline: PyEvalEvalCodeFn = match TRAMPOLINE_FN.lock() {
        Ok(g) => match *g {
            Some(fp) => fp,
            None => return core::ptr::null_mut(),
        },
        Err(_) => return core::ptr::null_mut(),
    };
    unsafe { trampoline(code, globals, locals) }
}

pub(crate) fn install_hotpatch(buffer: &'static CaptureBuffer) -> Result<HotpatchHandle> {
    set_buffer(buffer)?;
    let handle: HotpatchHandle = backend_install()?;
    Ok(handle)
}

pub(crate) fn uninstall_hotpatch(handle: HotpatchHandle) -> Result<()> {
    backend_uninstall(handle)?;
    clear_trampoline()?;
    clear_buffer()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn backend_install() -> Result<HotpatchHandle> {
    windows::install()
}

#[cfg(target_os = "windows")]
fn backend_uninstall(handle: HotpatchHandle) -> Result<()> {
    windows::uninstall(handle)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn backend_install() -> Result<HotpatchHandle> {
    unix::install()
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn backend_uninstall(handle: HotpatchHandle) -> Result<()> {
    unix::uninstall(handle)
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn backend_install() -> Result<HotpatchHandle> {
    Err(CextractError::HotpatchFailed {
        stage: "platform",
        reason: "hotpatch backend unavailable on this platform".to_owned(),
    })
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn backend_uninstall(_handle: HotpatchHandle) -> Result<()> {
    Err(CextractError::HotpatchFailed {
        stage: "platform",
        reason: "hotpatch backend unavailable on this platform".to_owned(),
    })
}

pub(crate) const fn supported() -> bool {
    cfg!(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos"
    )) && cfg!(target_arch = "x86_64")
}

pub(crate) fn write_abs_jmp(buf: &mut [u8], target: usize) -> Result<()> {
    if buf.len() < 14 {
        return Err(CextractError::HotpatchFailed {
            stage: "emit-jmp",
            reason: format!("buffer too small for 14-byte absolute jmp: {}", buf.len()),
        });
    }
    buf[0] = 0xFF;
    buf[1] = 0x25;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x00;
    let target_bytes: [u8; 8] = (target as u64).to_le_bytes();
    buf[6..14].copy_from_slice(&target_bytes);
    Ok(())
}

pub(crate) const ABS_JMP_LEN: usize = 14;

pub(crate) fn fn_addr_extern_c(
    p: extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> *mut PyObject,
) -> usize {
    p as *const c_void as usize
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        ABS_JMP_LEN, MAX_PROLOGUE_SCAN, MIN_HOOK_BYTES, fn_addr_extern_c, supported, write_abs_jmp,
    };
    use pyo3::ffi::PyObject;

    #[cfg(target_arch = "x86")]
    const _: () = assert!(!supported());

    extern "C" fn probe(_a: *mut PyObject, _b: *mut PyObject, _c: *mut PyObject) -> *mut PyObject {
        core::ptr::null_mut()
    }

    #[test]
    fn abs_jmp_is_fourteen_bytes() {
        assert_eq!(ABS_JMP_LEN, 14);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn write_abs_jmp_encodes_ff25_followed_by_zero_disp_and_target() {
        let mut buf: [u8; 14] = [0u8; 14];
        write_abs_jmp(&mut buf, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(&buf[..6], &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[6..], &0x1122_3344_5566_7788u64.to_le_bytes());
    }

    #[test]
    fn write_abs_jmp_rejects_short_buffer() {
        let mut buf: [u8; 8] = [0u8; 8];
        assert!(write_abs_jmp(&mut buf, 0).is_err());
    }

    #[test]
    fn supported_matches_platform_and_absolute_jump_width() {
        let expected: bool = cfg!(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos"
        )) && usize::BITS == 64;
        assert_eq!(supported(), expected);
    }

    #[test]
    fn fn_addr_extern_c_roundtrip() {
        let a: usize = fn_addr_extern_c(probe);
        assert!(a != 0);
    }

    #[test]
    fn min_hook_bytes_matches_abs_jmp() {
        assert_eq!(MIN_HOOK_BYTES, ABS_JMP_LEN);
    }

    #[test]
    fn max_prologue_scan_is_reasonable_upper_bound() {
        const _: () = assert!(MAX_PROLOGUE_SCAN >= MIN_HOOK_BYTES);
        const _: () = assert!(MAX_PROLOGUE_SCAN <= 64);
    }
}
