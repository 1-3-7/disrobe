use serde::{Deserialize, Serialize};

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
    let env: ShivEnvironment = serde_json::from_slice(bytes)?;
    Ok(env)
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
}
