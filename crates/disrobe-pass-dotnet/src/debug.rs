use disrobe_core::debug::DebugLog;

#[must_use]
pub(crate) fn debug_log() -> DebugLog {
    #[cfg(target_arch = "wasm32")]
    {
        DebugLog::disabled("dotnet")
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        DebugLog::for_scope("dotnet")
    }
}

#[must_use]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn dbg_enabled() -> bool {
    debug_log().on()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn dbg_section(name: &str) {
    let log: DebugLog = debug_log();
    if log.on() {
        log.section(name);
    }
}

pub(crate) fn dbg_line(f: impl FnOnce() -> String) {
    let log: DebugLog = debug_log();
    if log.on() {
        log.line(f);
    }
}

pub(crate) fn dbg_kv(key: &str, f: impl FnOnce() -> String) {
    let log: DebugLog = debug_log();
    if log.on() {
        log.kv(key, f);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn dbg_kv_guarded(key: &str, f: impl FnOnce() -> String) {
    let log: DebugLog = debug_log();
    if log.on() {
        log.kv_guarded(key, f);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn dbg_hex(label: &str, bytes: &[u8], max: usize) {
    let log: DebugLog = debug_log();
    if log.on() {
        log.hex(label, bytes, max);
    }
}
