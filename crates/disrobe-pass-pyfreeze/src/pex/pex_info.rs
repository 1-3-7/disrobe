use serde::{Deserialize, Serialize};

use crate::common::parse_json_manifest;
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
    parse_json_manifest(bytes, "PEX-INFO")
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

    #[test]
    fn rejects_oversized_manifest_before_deserialization() {
        let mut raw: Vec<u8> = b"{\"entry_point\":\"".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 16 * 1024 * 1024 + 1));
        raw.extend_from_slice(b"\"}");
        assert!(parse(&raw).is_err());
    }
}
