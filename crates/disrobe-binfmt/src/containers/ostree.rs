use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OstreeExternalHint {
    pub tool_binary: &'static str,
    pub install_hint: &'static str,
}

#[must_use]
pub const fn ostree_external_hint() -> OstreeExternalHint {
    OstreeExternalHint {
        tool_binary: "ostree",
        install_hint: "OSTree archives use deduplicated content-addressed object storage; install `ostree` (libostree) and invoke `ostree --repo=<repo> checkout <ref> <dest>` to materialize a working tree",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ostree_hint_present() {
        assert_eq!(ostree_external_hint().tool_binary, "ostree");
    }
}
