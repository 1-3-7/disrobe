use disrobe_core::debug::DebugLog;

#[must_use]
pub(crate) fn debug_log() -> DebugLog {
    DebugLog::for_scope("native")
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

pub(crate) fn dbg_kv_guarded(key: &str, f: impl FnOnce() -> String) {
    let log: DebugLog = debug_log();
    if log.on() {
        log.kv_guarded(key, f);
    }
}
