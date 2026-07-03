use disrobe_core::debug::DebugLog;

#[must_use]
pub(crate) fn debug_log() -> DebugLog {
    DebugLog::for_scope("as3")
}

#[must_use]
pub(crate) fn dbg_enabled() -> bool {
    debug_log().on()
}

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

pub(crate) fn dbg_hex(label: &str, bytes: &[u8], max: usize) {
    let log: DebugLog = debug_log();
    if log.on() {
        log.hex(label, bytes, max);
    }
}
