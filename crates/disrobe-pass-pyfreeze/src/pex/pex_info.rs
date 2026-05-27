use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexInfo {
    #[serde(default)]
    pub build_properties: serde_json::Value,
    #[serde(default)]
    pub code_hash: Option<String>,
    #[serde(default)]
    pub distributions: serde_json::Value,
    #[serde(default)]
    pub entry_point: Option<String>,
    #[serde(default)]
    pub pex_path: Option<String>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub interpreter_constraints: Vec<String>,
    #[serde(default)]
    pub pex_root: Option<String>,
    #[serde(default)]
    pub zip_safe: Option<bool>,
    #[serde(default)]
    pub inherit_path: Option<String>,
    #[serde(default)]
    pub strip_pex_env: Option<bool>,
    #[serde(default)]
    pub always_write_cache: Option<bool>,
}

pub fn parse(bytes: &[u8]) -> Result<PexInfo> {
    let info: PexInfo = serde_json::from_slice(bytes)?;
    Ok(info)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimum() {
        let raw: &[u8; 69] =
            br#"{"entry_point":"app:main","interpreter_constraints":["CPython>=3.9"]}"#;
        let info: PexInfo = parse(raw).expect("parse");
        assert_eq!(info.entry_point.as_deref(), Some("app:main"));
        assert_eq!(info.interpreter_constraints, vec!["CPython>=3.9"]);
    }
}
