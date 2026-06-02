use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn lua_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Lua, version)
}

#[must_use]
pub fn lua_deobfuscated_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Deobfuscated, duration, Language::Lua, version)
}

#[must_use]
pub fn render_lua_decompiled_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    lua_decompiled_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_lua_deobfuscated_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    lua_deobfuscated_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua_decompiled_header_uses_double_dash() {
        let s: String =
            render_lua_decompiled_with_header("print(1)\n", Duration::from_millis(30), "5.4");
        assert!(s.starts_with("-- Decompiled in 30ms"));
        assert!(s.contains("\n-- Lua 5.4\n"));
    }
}
