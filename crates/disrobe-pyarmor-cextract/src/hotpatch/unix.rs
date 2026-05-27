use core::ffi::{CStr, c_int, c_void};
use core::ptr;

use crate::error::{CextractError, Result};

use super::{
    ABS_JMP_LEN, HotpatchHandle, MAX_PROLOGUE_SCAN, MIN_HOOK_BYTES, PyEvalEvalCodeFn,
    evaluate_intercept, fn_addr_extern_c, measure_prologue, store_trampoline, write_abs_jmp,
};

const TRAMPOLINE_SIZE: usize = 4096;

fn resolve_pyeval_evalcode() -> Result<usize> {
    let proc_name: &CStr = c"PyEval_EvalCode";
    let p: *mut c_void = unsafe { libc::dlsym(libc::RTLD_DEFAULT, proc_name.as_ptr()) };
    if p.is_null() {
        return Err(CextractError::HotpatchFailed {
            stage: "resolve",
            reason: "dlsym(RTLD_DEFAULT, PyEval_EvalCode) returned null".to_owned(),
        });
    }
    Ok(p as usize)
}

fn page_size() -> usize {
    let sz: i64 = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz <= 0 { 4096usize } else { sz as usize }
}

fn page_align_down(addr: usize, page: usize) -> usize {
    addr & !(page - 1)
}

fn mprotect_range(addr: usize, len: usize, prot: c_int) -> Result<()> {
    let page: usize = page_size();
    let base: usize = page_align_down(addr, page);
    let end: usize = addr.saturating_add(len);
    let span: usize = end - base;
    let aligned_span: usize = ((span + page - 1) / page) * page;
    let rc: c_int = unsafe { libc::mprotect(base as *mut c_void, aligned_span, prot) };
    if rc != 0 {
        let err: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(CextractError::HotpatchFailed {
            stage: "mprotect",
            reason: format!("mprotect(0x{base:x}, {aligned_span}, {prot}) failed: errno={err}"),
        });
    }
    Ok(())
}

fn make_rwx(addr: usize, len: usize) -> Result<()> {
    mprotect_range(
        addr,
        len,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    )
}

fn restore_rx(addr: usize, len: usize) -> Result<()> {
    mprotect_range(addr, len, libc::PROT_READ | libc::PROT_EXEC)
}

fn allocate_trampoline() -> Result<usize> {
    let p: *mut c_void = unsafe {
        libc::mmap(
            ptr::null_mut(),
            TRAMPOLINE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        let err: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(CextractError::HotpatchFailed {
            stage: "mmap",
            reason: format!("mmap({TRAMPOLINE_SIZE}) failed: errno={err}"),
        });
    }
    Ok(p as usize)
}

fn finalize_trampoline_executable(addr: usize) -> Result<()> {
    let rc: c_int = unsafe {
        libc::mprotect(
            addr as *mut c_void,
            TRAMPOLINE_SIZE,
            libc::PROT_READ | libc::PROT_EXEC,
        )
    };
    if rc != 0 {
        let err: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(CextractError::HotpatchFailed {
            stage: "trampoline-finalize",
            reason: format!("mprotect trampoline RX failed: errno={err}"),
        });
    }
    Ok(())
}

fn free_trampoline(addr: usize) -> Result<()> {
    let rc: c_int = unsafe { libc::munmap(addr as *mut c_void, TRAMPOLINE_SIZE) };
    if rc != 0 {
        let err: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(CextractError::HotpatchFailed {
            stage: "munmap",
            reason: format!("munmap failed: errno={err}"),
        });
    }
    Ok(())
}

pub(crate) fn install() -> Result<HotpatchHandle> {
    let target_addr: usize = resolve_pyeval_evalcode()?;
    let prologue_slice: &[u8] =
        unsafe { core::slice::from_raw_parts(target_addr as *const u8, MAX_PROLOGUE_SCAN) };
    let saved_len: usize = measure_prologue(prologue_slice, MIN_HOOK_BYTES)?;
    if saved_len < ABS_JMP_LEN {
        return Err(CextractError::HotpatchFailed {
            stage: "prologue-too-short",
            reason: format!("need {ABS_JMP_LEN} bytes, only safely measured {saved_len}"),
        });
    }
    let saved_prologue: Vec<u8> = prologue_slice[..saved_len].to_vec();

    let trampoline_addr: usize = allocate_trampoline()?;
    let trampoline_buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(trampoline_addr as *mut u8, TRAMPOLINE_SIZE) };
    trampoline_buf[..saved_len].copy_from_slice(&saved_prologue);
    if let Err(e) = write_abs_jmp(
        &mut trampoline_buf[saved_len..saved_len + ABS_JMP_LEN],
        target_addr + saved_len,
    ) {
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }

    if let Err(e) = finalize_trampoline_executable(trampoline_addr) {
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }

    let trampoline_fn: PyEvalEvalCodeFn =
        unsafe { core::mem::transmute::<usize, PyEvalEvalCodeFn>(trampoline_addr) };
    store_trampoline(trampoline_fn)?;

    if let Err(e) = make_rwx(target_addr, ABS_JMP_LEN) {
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }
    let entry_buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(target_addr as *mut u8, ABS_JMP_LEN) };
    let interceptor_addr: usize = fn_addr_extern_c(evaluate_intercept);
    if let Err(e) = write_abs_jmp(entry_buf, interceptor_addr) {
        let _: Result<()> = restore_rx(target_addr, ABS_JMP_LEN);
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }
    if let Err(e) = restore_rx(target_addr, ABS_JMP_LEN) {
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }

    Ok(HotpatchHandle {
        target_addr,
        trampoline_addr,
        saved_prologue,
        saved_prologue_len: saved_len,
        trampoline_capacity: TRAMPOLINE_SIZE,
    })
}

pub(crate) fn uninstall(handle: HotpatchHandle) -> Result<()> {
    make_rwx(handle.target_addr, handle.saved_prologue_len)?;
    let entry_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(handle.target_addr as *mut u8, handle.saved_prologue_len)
    };
    entry_buf.copy_from_slice(&handle.saved_prologue);
    restore_rx(handle.target_addr, handle.saved_prologue_len)?;
    free_trampoline(handle.trampoline_addr)?;
    Ok(())
}
