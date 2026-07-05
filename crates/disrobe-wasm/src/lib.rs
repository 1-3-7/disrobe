#![allow(clippy::missing_safety_doc)]
use serde::Serialize;

pub mod entry;
mod getrandom_shim;

const RESULT_HEADER_LEN: usize = 4;
const MAX_GUEST_ALLOC: usize = 1 << 30;
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESULT_PAYLOAD: usize = 64 * 1024 * 1024;

fn leak_exact(bytes: Vec<u8>) -> *mut u8 {
    let mut boxed: Box<[u8]> = bytes.into_boxed_slice();
    let ptr: *mut u8 = boxed.as_mut_ptr();
    Box::leak(boxed);
    ptr
}

unsafe fn reclaim_exact(ptr: *mut u8, len: usize) {
    let slice: *mut [u8] = core::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(unsafe { Box::from_raw(slice) });
}

#[unsafe(no_mangle)]
pub extern "C" fn disrobe_alloc(len: usize) -> *mut u8 {
    if len > MAX_GUEST_ALLOC {
        return core::ptr::null_mut();
    }
    zeroed_buffer(len).map_or(core::ptr::null_mut(), leak_exact)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn disrobe_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    if len > MAX_GUEST_ALLOC {
        return;
    }
    unsafe { reclaim_exact(ptr, len) };
}

fn zeroed_buffer(len: usize) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    if bytes.try_reserve_exact(len).is_err() {
        return None;
    }
    bytes.resize(len, 0u8);
    Some(bytes)
}

#[unsafe(no_mangle)]
pub const unsafe extern "C" fn disrobe_result_len(ptr: *const u8) -> u32 {
    if ptr.is_null() {
        return 0;
    }
    let header: [u8; RESULT_HEADER_LEN] = unsafe { core::ptr::read(ptr.cast::<[u8; 4]>()) };
    u32::from_le_bytes(header)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn disrobe_result_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let payload_len: usize =
        usize::try_from(unsafe { disrobe_result_len(ptr) }).map_or(usize::MAX, |v: usize| v);
    if payload_len > MAX_RESULT_PAYLOAD {
        return;
    }
    let Some(total): Option<usize> = RESULT_HEADER_LEN.checked_add(payload_len) else {
        return;
    };
    unsafe { reclaim_exact(ptr, total) };
}

const unsafe fn input_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], &'static str> {
    if len > MAX_INPUT_BYTES {
        return Err("input exceeds wasm bridge input cap");
    }
    if ptr.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err("null input pointer with non-zero length");
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

fn pack_result(payload: &[u8]) -> *mut u8 {
    pack_result_with_cap(payload, MAX_RESULT_PAYLOAD)
}

fn pack_result_with_cap(payload: &[u8], cap: usize) -> *mut u8 {
    if payload.len() > cap {
        return pack_error("result exceeds wasm bridge output cap");
    }
    let Ok(payload_len): Result<u32, _> = u32::try_from(payload.len()) else {
        return pack_error("result length exceeds wasm bridge header");
    };
    let clamped: usize = payload.len();
    let Some(total): Option<usize> = RESULT_HEADER_LEN.checked_add(clamped) else {
        return pack_error("result buffer length overflow");
    };
    let mut buffer: Vec<u8> = Vec::new();
    if buffer.try_reserve_exact(total).is_err() {
        return pack_error("result buffer allocation failed");
    }
    buffer.extend_from_slice(&payload_len.to_le_bytes());
    buffer.extend_from_slice(&payload[..clamped]);
    leak_exact(buffer)
}

fn pack_json(value: &impl Serialize) -> *mut u8 {
    serde_json::to_vec(value).map_or_else(
        |err: serde_json::Error| pack_error(&format!("serialize result: {err}")),
        |bytes: Vec<u8>| pack_result(&bytes),
    )
}

#[derive(Serialize)]
struct ErrorReport<'a> {
    ok: bool,
    error: &'a str,
}

fn pack_error(message: &str) -> *mut u8 {
    let report: ErrorReport<'_> = ErrorReport {
        ok: false,
        error: message,
    };
    serde_json::to_vec(&report).map_or_else(
        |_: serde_json::Error| pack_result(br#"{"ok":false,"error":"error serialization failed"}"#),
        |bytes: Vec<u8>| pack_result(&bytes),
    )
}

unsafe fn dispatch<T: Serialize>(
    ptr: *const u8,
    len: usize,
    analyze: impl FnOnce(&[u8]) -> Result<T, String>,
) -> *mut u8 {
    let bytes: &[u8] = match unsafe { input_slice(ptr, len) } {
        Ok(bytes) => bytes,
        Err(message) => return pack_error(message),
    };
    analyze(bytes).map_or_else(
        |message: String| pack_error(&message),
        |value: T| pack_json(&value),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn py_disasm(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::py_disasm) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn py_decompile(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::py_decompile) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pickle_disasm(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::pickle_disasm) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pickle_safety(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::pickle_safety) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_analyze(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_analyze) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn detect(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::detect(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn auto_route(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::auto_route(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pickle_decompile(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::pickle_decompile) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pickle_trace(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::pickle_trace) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pickle_polyglot(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::pickle_polyglot(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_detect(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_detect) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_decompile_wat(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_decompile_wat) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_faithful_wat(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_faithful_wat) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_lift_rust(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_lift_rust) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_lift_ts(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_lift_ts) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_lift_c(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_lift_c) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_cfg(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_cfg) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_gc_types(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_gc_types) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_eh(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_eh) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_component(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_component) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_memories(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_memories) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_signatures(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_signatures) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_preludes(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::wasm_preludes(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_source_map(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::wasm_source_map) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pyarmor_detect(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::pyarmor_detect) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pyarmor_classify(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::pyarmor_classify) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_detect(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::lua_detect(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_decompile(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::lua_decompile) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruby_detect(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::ruby_detect) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn php_detect(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::php_detect) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beam_recover(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::beam_recover) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn as3_analyze(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::as3_analyze_entry) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scriptlang_analyze(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::scriptlang_analyze_entry) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shell_deob(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::shell_deob) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn swift_objc(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::swift_objc_entry) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mobile_detect(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::mobile_detect) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strings(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::strings(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioc(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::ioc(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn behavior(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::behavior(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secrets(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::secrets(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn anti_analysis(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::anti_analysis(bytes))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yara_gen(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, entry::yara_gen) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entropy(ptr: *const u8, len: usize) -> *mut u8 {
    unsafe { dispatch(ptr, len, |bytes: &[u8]| Ok(entry::entropy(bytes))) }
}

#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests;
