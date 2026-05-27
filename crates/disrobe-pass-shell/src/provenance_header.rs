use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn powershell_deobfuscated_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(
        Protocol::Deobfuscated,
        duration,
        Language::PowerShell,
        version,
    )
}

#[must_use]
pub fn bash_deobfuscated_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Deobfuscated, duration, Language::Bash, version)
}

#[must_use]
pub fn batch_deobfuscated_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Deobfuscated, duration, Language::Batch, version)
}

#[must_use]
pub fn vba_deobfuscated_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Deobfuscated, duration, Language::Vba, version)
}

#[must_use]
pub fn render_powershell_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    powershell_deobfuscated_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_bash_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    bash_deobfuscated_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_batch_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    batch_deobfuscated_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_vba_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    vba_deobfuscated_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_header_uses_hash() {
        let s: String =
            render_powershell_with_header("Write-Host x\n", Duration::from_millis(5), "5.1");
        assert!(s.starts_with("# Deobfuscated in 5ms"));
        assert!(s.contains("\n# PowerShell 5.1\n"));
    }

    #[test]
    fn bash_header_uses_hash() {
        let s: String = render_bash_with_header("echo x\n", Duration::from_millis(15), "5.2");
        assert!(s.starts_with("# Deobfuscated in 15ms"));
        assert!(s.contains("\n# Bash 5.2\n"));
    }
}
