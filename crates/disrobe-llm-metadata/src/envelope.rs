use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Wire-shape wrapper used for every per-category, per-pass payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerPassEnvelope {
    pub pass: String,
    pub pass_version: String,
    pub applicable: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub value: Option<Json>,
}

impl PerPassEnvelope {
    #[must_use]
    pub fn applicable(
        pass: impl Into<String>,
        pass_version: impl Into<String>,
        value: Json,
    ) -> Self {
        Self {
            pass: pass.into(),
            pass_version: pass_version.into(),
            applicable: true,
            reason: None,
            value: Some(value),
        }
    }

    #[must_use]
    pub fn not_applicable(
        pass: impl Into<String>,
        pass_version: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            pass: pass.into(),
            pass_version: pass_version.into(),
            applicable: false,
            reason: Some(reason.into()),
            value: None,
        }
    }
}
