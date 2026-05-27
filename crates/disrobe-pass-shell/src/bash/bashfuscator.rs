use serde::Serialize;

use crate::error::Result;

use super::indirect::{IndirectionReport, peel_indirection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BashfuscatorLevel {
    Token,
    String,
    Obfuscate,
    Compress,
}

#[derive(Debug, Clone, Serialize)]
pub struct BashfuscatorReport {
    pub level: BashfuscatorLevel,
    pub steps: Vec<String>,
    pub output: String,
}

pub fn reverse_bashfuscator(level: BashfuscatorLevel, input: &str) -> Result<BashfuscatorReport> {
    let indirection: IndirectionReport = peel_indirection(input)?;
    let steps: Vec<String> = indirection.steps;
    Ok(BashfuscatorReport {
        level,
        steps,
        output: indirection.output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STD;

    #[test]
    fn reverses_token_level() -> Result<()> {
        let payload: &str = "id";
        let b64: String = BASE64_STD.encode(payload);
        let src: String = format!("echo '{b64}' | base64 -d");
        let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Token, &src)?;
        assert!(r.output.contains(payload));
        Ok(())
    }
}
