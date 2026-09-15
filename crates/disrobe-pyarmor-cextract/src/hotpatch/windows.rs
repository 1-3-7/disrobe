use core::ffi::{CStr, c_void};
use core::ptr;

use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect,
};

use crate::error::{CextractError, Result};

use super::{
    ABS_JMP_LEN, HotpatchHandle, MAX_PROLOGUE_SCAN, MIN_HOOK_BYTES, PyEvalEvalCodeFn,
    evaluate_intercept, fn_addr_extern_c, measure_prologue, store_trampoline, write_abs_jmp,
};

const PYTHON_DLL_CANDIDATES: &[&[u8]] = &[
    b"python314.dll\0",
    b"python313.dll\0",
    b"python312.dll\0",
    b"python311.dll\0",
    b"python310.dll\0",
    b"python39.dll\0",
    b"python38.dll\0",
    b"python3.dll\0",
];

fn resolve_pyeval_evalcode() -> Result<usize> {
    let proc_name: &CStr = c"PyEval_EvalCode";
    for needle in PYTHON_DLL_CANDIDATES {
        let h: HMODULE = unsafe { GetModuleHandleA(needle.as_ptr()) };
        if !h.is_null() {
            let p: Option<unsafe extern "system" fn() -> isize> =
                unsafe { GetProcAddress(h, proc_name.as_ptr().cast()) };
            if let Some(addr) = p {
                return Ok(addr as usize);
            }
        }
    }
    let main_h: HMODULE = unsafe { GetModuleHandleA(ptr::null()) };
    if !main_h.is_null() {
        let p: Option<unsafe extern "system" fn() -> isize> =
            unsafe { GetProcAddress(main_h, proc_name.as_ptr().cast()) };
        if let Some(addr) = p {
            return Ok(addr as usize);
        }
    }
    Err(CextractError::HotpatchFailed {
        stage: "resolve",
        reason: format!(
            "PyEval_EvalCode not found in any of {} python dll candidates",
            PYTHON_DLL_CANDIDATES.len()
        ),
    })
}

fn make_rwx(addr: usize, size: usize) -> Result<u32> {
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    let ok: i32 = unsafe {
        VirtualProtect(
            addr as *mut c_void,
            size,
            PAGE_EXECUTE_READWRITE,
            &raw mut old,
        )
    };
    if ok == 0 {
        let last: u32 = unsafe { GetLastError() };
        return Err(CextractError::HotpatchFailed {
            stage: "virtual-protect-rwx",
            reason: format!("VirtualProtect RWX failed: GetLastError={last}"),
        });
    }
    Ok(old)
}

fn restore_protection(addr: usize, size: usize, old: u32) -> Result<()> {
    let mut prev: PAGE_PROTECTION_FLAGS = 0;
    let ok: i32 = unsafe { VirtualProtect(addr as *mut c_void, size, old, &raw mut prev) };
    if ok == 0 {
        let last: u32 = unsafe { GetLastError() };
        return Err(CextractError::HotpatchFailed {
            stage: "virtual-protect-restore",
            reason: format!("VirtualProtect restore failed: GetLastError={last}"),
        });
    }
    Ok(())
}

const TRAMPOLINE_SIZE: usize = 4096;

fn allocate_trampoline() -> Result<usize> {
    let p: *mut c_void = unsafe {
        VirtualAlloc(
            ptr::null(),
            TRAMPOLINE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if p.is_null() {
        let last: u32 = unsafe { GetLastError() };
        return Err(CextractError::HotpatchFailed {
            stage: "virtual-alloc",
            reason: format!("VirtualAlloc({TRAMPOLINE_SIZE}) failed: GetLastError={last}"),
        });
    }
    Ok(p as usize)
}

fn finalize_trampoline_executable(addr: usize) -> Result<()> {
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    let ok: i32 = unsafe {
        VirtualProtect(
            addr as *mut c_void,
            TRAMPOLINE_SIZE,
            PAGE_EXECUTE_READ,
            &raw mut old,
        )
    };
    if ok == 0 {
        let last: u32 = unsafe { GetLastError() };
        return Err(CextractError::HotpatchFailed {
            stage: "trampoline-finalize",
            reason: format!("VirtualProtect EXECUTE_READ failed: GetLastError={last}"),
        });
    }
    Ok(())
}

fn free_trampoline(addr: usize) -> Result<()> {
    let ok: i32 = unsafe { VirtualFree(addr as *mut c_void, 0, MEM_RELEASE) };
    if ok == 0 {
        let last: u32 = unsafe { GetLastError() };
        return Err(CextractError::HotpatchFailed {
            stage: "virtual-free",
            reason: format!("VirtualFree failed: GetLastError={last}"),
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
    write_abs_jmp(
        &mut trampoline_buf[saved_len..saved_len + ABS_JMP_LEN],
        target_addr + saved_len,
    )?;

    if let Err(e) = finalize_trampoline_executable(trampoline_addr) {
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }

    let trampoline_fn: PyEvalEvalCodeFn =
        unsafe { core::mem::transmute::<usize, PyEvalEvalCodeFn>(trampoline_addr) };
    store_trampoline(trampoline_fn)?;

    let old_protect: u32 = match make_rwx(target_addr, ABS_JMP_LEN) {
        Ok(o) => o,
        Err(e) => {
            let _: Result<()> = free_trampoline(trampoline_addr);
            return Err(e);
        }
    };
    let entry_buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(target_addr as *mut u8, ABS_JMP_LEN) };
    let interceptor_addr: usize = fn_addr_extern_c(evaluate_intercept);
    if let Err(e) = write_abs_jmp(entry_buf, interceptor_addr) {
        let _: Result<()> = restore_protection(target_addr, ABS_JMP_LEN, old_protect);
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }
    if let Err(e) = restore_protection(target_addr, ABS_JMP_LEN, old_protect) {
        let _: Result<()> = free_trampoline(trampoline_addr);
        return Err(e);
    }
    flush_instruction_cache(target_addr, ABS_JMP_LEN)?;

    Ok(HotpatchHandle {
        target_addr,
        trampoline_addr,
        saved_prologue,
        saved_prologue_len: saved_len,
        trampoline_capacity: TRAMPOLINE_SIZE,
    })
}

pub(crate) fn uninstall(handle: HotpatchHandle) -> Result<()> {
    let old: u32 = make_rwx(handle.target_addr, handle.saved_prologue_len)?;
    let entry_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(handle.target_addr as *mut u8, handle.saved_prologue_len)
    };
    entry_buf.copy_from_slice(&handle.saved_prologue);
    restore_protection(handle.target_addr, handle.saved_prologue_len, old)?;
    flush_instruction_cache(handle.target_addr, handle.saved_prologue_len)?;
    free_trampoline(handle.trampoline_addr)?;
    Ok(())
}

fn flush_instruction_cache(addr: usize, size: usize) -> Result<()> {
    unsafe extern "system" {
        fn FlushInstructionCache(
            hProcess: isize,
            lpBaseAddress: *const c_void,
            dwSize: usize,
        ) -> i32;
        fn GetCurrentProcess() -> isize;
    }
    let proc: isize = unsafe { GetCurrentProcess() };
    let ok: i32 = unsafe { FlushInstructionCache(proc, addr as *const c_void, size) };
    if ok == 0 {
        let last: u32 = unsafe { GetLastError() };
        return Err(CextractError::HotpatchFailed {
            stage: "flush-icache",
            reason: format!("FlushInstructionCache failed: GetLastError={last}"),
        });
    }
    Ok(())
}
