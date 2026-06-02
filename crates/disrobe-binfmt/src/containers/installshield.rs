use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallshieldExternalHint {
    pub tool_binary: &'static str,
    pub install_hint: &'static str,
}

#[must_use]
pub const fn installshield_external_hint() -> InstallshieldExternalHint {
    InstallshieldExternalHint {
        tool_binary: "i6comp",
        install_hint: "InstallShield CAB archives require `i6comp` / `isinfo` / `unshield`; install one (e.g. `apt install unshield` or build i6comp from source) - no Apache-2.0-compatible pure-Rust decoder exists for InstallShield's proprietary container",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hint_points_to_external_tool() {
        let hint: InstallshieldExternalHint = installshield_external_hint();
        assert!(matches!(hint.tool_binary, "i6comp"));
    }
}
