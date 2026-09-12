use serde::{Deserialize, Serialize};

use crate::common::parse_json_manifest;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShivEnvironment {
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub entry_point: Option<String>,
    #[serde(default)]
    pub shiv_version: Option<String>,
    #[serde(default)]
    pub always_write_cache: Option<bool>,
    #[serde(default)]
    pub no_modify: Option<bool>,
    #[serde(default)]
    pub compile_pyc: Option<bool>,
    #[serde(default)]
    pub extend_pythonpath: Option<bool>,
}

pub fn parse(bytes: &[u8]) -> Result<ShivEnvironment> {
    parse_json_manifest(bytes, "shiv environment")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_partial_environment() {
        let json: &str = r#"{"entry_point":"pkg.main:main","shiv_version":"1.0.4"}"#;
        let env: ShivEnvironment = parse(json.as_bytes()).expect("must parse");
        assert_eq!(env.entry_point.as_deref(), Some("pkg.main:main"));
        assert_eq!(env.shiv_version.as_deref(), Some("1.0.4"));
        assert!(env.compile_pyc.is_none());
    }

    #[test]
    fn rejects_oversized_manifest_before_deserialization() {
        let mut raw: Vec<u8> = b"{\"entry_point\":\"".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 16 * 1024 * 1024 + 1));
        raw.extend_from_slice(b"\"}");
        assert!(parse(&raw).is_err());
    }
}
