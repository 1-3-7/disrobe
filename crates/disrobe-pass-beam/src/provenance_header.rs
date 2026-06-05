use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn core_erlang_lifted_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::CoreErlang, version)
}

#[must_use]
pub fn erlang_decompiled_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Erlang, version)
}

#[must_use]
pub fn elixir_decompiled_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Elixir, version)
}

#[must_use]
pub fn render_core_erlang_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    core_erlang_lifted_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_erlang_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    erlang_decompiled_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_elixir_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    elixir_decompiled_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_erlang_uses_pound() {
        let s: String =
            render_core_erlang_with_header("module x\n", Duration::from_millis(15), "27");
        assert!(s.starts_with("% Lifted in 15ms"));
        assert!(s.contains("\n% Core Erlang 27\n"));
    }

    #[test]
    fn elixir_uses_hash() {
        let s: String =
            render_elixir_with_header("defmodule X do\nend\n", Duration::from_millis(20), "1.17");
        assert!(s.starts_with("# Decompiled in 20ms"));
        assert!(s.contains("\n# Elixir 1.17\n"));
    }
}
