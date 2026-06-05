use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatpakExternalHint {
    pub tool_binary: &'static str,
    pub install_hint: &'static str,
}

#[must_use]
pub const fn flatpak_external_hint() -> FlatpakExternalHint {
    FlatpakExternalHint {
        tool_binary: "ostree",
        install_hint: "install libostree (`apt install ostree` / `dnf install ostree` / `brew install ostree`) and re-run; flatpak archives are OSTree-backed and require the external `ostree` CLI for Apache-compatible extraction",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hint_points_to_ostree_cli() {
        let hint: FlatpakExternalHint = flatpak_external_hint();
        assert_eq!(hint.tool_binary, "ostree");
        assert!(hint.install_hint.contains("ostree"));
    }
}
