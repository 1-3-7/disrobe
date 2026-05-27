use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnosetupExternalHint {
    pub tool_binary: &'static str,
    pub install_hint: &'static str,
}

#[must_use]
pub const fn innosetup_external_hint() -> InnosetupExternalHint {
    InnosetupExternalHint {
        tool_binary: "innoextract",
        install_hint: "install `innoextract` (`apt install innoextract` / `brew install innoextract` / `winget install innoextract`) and re-run; Inno Setup installers require the external `innoextract` CLI (GPLv2 — kept external to preserve disrobe's Apache-2.0 license)",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hint_points_to_innoextract() {
        assert_eq!(innosetup_external_hint().tool_binary, "innoextract");
    }
}
