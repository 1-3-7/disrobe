use std::io::Read;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use flate2::read::DeflateDecoder;
use regex::Regex;
use serde::Serialize;

use crate::error::Result;

#[derive(Debug, Clone, Serialize)]
pub struct PsobfReport {
    pub stages: Vec<String>,
    pub output: String,
}

static PSOBF_HEADER: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)psobf|TaurusOmar"));

static DEFLATE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"DeflateStream[^']*'([A-Za-z0-9+/=]+)'"#));

static OBFUS_WRAP: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?s)<obfus(.*?)cate>"));

pub fn reverse_psobf(input: &str) -> Result<PsobfReport> {
    let mut stages: Vec<String> = Vec::new();
    if PSOBF_HEADER.is_match(input) {
        stages.push("detect-psobf-banner".to_owned());
    }
    let normalised: String = normalise_wide_chars(input);
    if normalised != input {
        stages.push("normalise-utf16-wide-chars".to_owned());
    }
    if OBFUS_WRAP.is_match(&normalised) {
        let stripped: String = strip_obfus_wrappers(&normalised);
        stages.push("strip-obfus-percent-insertion".to_owned());
        return Ok(PsobfReport {
            stages,
            output: stripped,
        });
    }
    let Some(cap): Option<regex::Captures<'_>> = DEFLATE_PATTERN.captures(input) else {
        return Ok(PsobfReport {
            stages,
            output: input.to_owned(),
        });
    };
    let Some(b64): Option<regex::Match<'_>> = cap.get(1) else {
        return Ok(PsobfReport {
            stages,
            output: input.to_owned(),
        });
    };
    let raw: Vec<u8> = BASE64_STD.decode(b64.as_str())?;
    stages.push("base64-decode".to_owned());
    let mut dec: DeflateDecoder<&[u8]> = DeflateDecoder::new(&raw[..]);
    let mut out: Vec<u8> = Vec::with_capacity(raw.len() * 4);
    dec.read_to_end(&mut out)?;
    stages.push("deflate-inflate".to_owned());
    let text: String = String::from_utf8_lossy(&out).into_owned();
    Ok(PsobfReport {
        stages,
        output: text,
    })
}

/// Strip the interleaved NUL bytes and mojibake BOM that mark UTF-16LE content read as bytes.
fn normalise_wide_chars(input: &str) -> String {
    let nul_count: usize = input.chars().filter(|c: &char| *c == '\u{0}').count();
    if nul_count == 0 {
        return input.to_owned();
    }
    input
        .chars()
        .filter(|c: &char| !matches!(*c, '\u{0}' | '\u{feff}' | '\u{ff}' | '\u{fe}'))
        .collect()
}

/// Decode psobf's `<obfus%W%r%i%t%e%cate>` percent-insertion wrapper to cleartext.
fn strip_obfus_wrappers(input: &str) -> String {
    let decoded: std::borrow::Cow<'_, str> =
        OBFUS_WRAP.replace_all(input, |c: &regex::Captures<'_>| {
            c.get(1)
                .map(|m: regex::Match<'_>| m.as_str().replace('%', ""))
                .unwrap_or_default()
        });
    decoded.trim_start_matches('\u{feff}').trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    #[test]
    fn strips_obfus_percent_insertion() -> Result<()> {
        let src: &str = "<obfus%W%r%i%t%e%-%H%o%s%t%cate> <obfus%h%i%cate>\n";
        let r: PsobfReport = reverse_psobf(src)?;
        assert_eq!(r.output, "Write-Host hi");
        assert!(
            r.stages
                .contains(&"strip-obfus-percent-insertion".to_owned())
        );
        Ok(())
    }

    #[test]
    fn unwraps_deflate_base64() -> Result<()> {
        let inner: &str = "Write-Host 'psobf inner'";
        let mut enc: DeflateEncoder<Vec<u8>> =
            DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(inner.as_bytes())?;
        let compressed: Vec<u8> = enc.finish()?;
        let b64: String = BASE64_STD.encode(&compressed);
        let src: String =
            format!("# psobf TaurusOmar\nIO.Compression.DeflateStream::new('{b64}')\n");
        let r: PsobfReport = reverse_psobf(&src)?;
        assert!(r.output.contains("psobf inner"));
        Ok(())
    }
}
