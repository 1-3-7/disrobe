use std::io::Read;
use std::sync::LazyLock;

use disrobe_core::codec::{Base64Alphabet, Base64Padding, base64_decode};
use flate2::read::DeflateDecoder;
use regex::Regex;
use serde::Serialize;

use crate::error::{Error, Result, base64_error};

const MAX_DECOMPRESSED: u64 = 16 * 1024 * 1024;
const MAX_BASE64_INPUT: usize = 2 * 1024 * 1024;

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
    let normalized: String = normalize_wide_chars(input);
    if normalized != input {
        stages.push("normalize-utf16-wide-chars".to_owned());
    }
    if OBFUS_WRAP.is_match(&normalized) {
        let stripped: String = strip_obfus_wrappers(&normalized);
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
    let raw: Vec<u8> = decode_base64_bounded(b64.as_str())?;
    stages.push("base64-decode".to_owned());
    let reserve: usize = raw.len().saturating_mul(4).min(MAX_DECOMPRESSED as usize);
    let dec: DeflateDecoder<&[u8]> = DeflateDecoder::new(&raw[..]);
    let mut out: Vec<u8> = Vec::with_capacity(reserve);
    let produced: u64 = dec
        .take(MAX_DECOMPRESSED.saturating_add(1))
        .read_to_end(&mut out)
        .map(|n: usize| n as u64)?;
    if produced > MAX_DECOMPRESSED {
        out.truncate(MAX_DECOMPRESSED as usize);
        stages.push("deflate-inflate-capped".to_owned());
    } else {
        stages.push("deflate-inflate".to_owned());
    }
    let text: String = String::from_utf8_lossy(&out).into_owned();
    Ok(PsobfReport {
        stages,
        output: text,
    })
}

fn decode_base64_bounded(b64: &str) -> Result<Vec<u8>> {
    if b64.len() > MAX_BASE64_INPUT {
        return Err(Error::InputTooLarge {
            what: "psobf deflate payload",
            max_bytes: MAX_BASE64_INPUT,
        });
    }
    base64_decode(
        b64.as_bytes(),
        Base64Alphabet::Standard,
        Base64Padding::Required,
    )
    .map_err(|source: disrobe_core::codec::DecodeError| base64_error(b64.as_bytes(), source))
}

fn normalize_wide_chars(input: &str) -> String {
    let nul_count: usize = input.chars().filter(|c: &char| *c == '\u{0}').count();
    if nul_count == 0 {
        return input.to_owned();
    }
    input
        .chars()
        .filter(|c: &char| !matches!(*c, '\u{0}' | '\u{feff}' | '\u{ff}' | '\u{fe}'))
        .collect()
}

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
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
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
    fn deflate_bomb_is_capped_not_oom() -> Result<()> {
        let bomb: Vec<u8> = vec![b'A'; (MAX_DECOMPRESSED as usize) + (4 * 1024 * 1024)];
        let mut enc: DeflateEncoder<Vec<u8>> = DeflateEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&bomb)?;
        let compressed: Vec<u8> = enc.finish()?;
        let b64: String = BASE64_STD.encode(&compressed);
        let src: String = format!("IO.Compression.DeflateStream::new('{b64}')");
        let r: PsobfReport = reverse_psobf(&src)?;
        assert!(
            r.output.len() <= MAX_DECOMPRESSED as usize,
            "output {} exceeds cap",
            r.output.len()
        );
        assert!(r.stages.contains(&"deflate-inflate-capped".to_owned()));
        Ok(())
    }

    #[test]
    fn deflate_rejects_oversized_base64_input() {
        let oversized: String = "A".repeat(MAX_BASE64_INPUT + 1);
        let src: String = format!("IO.Compression.DeflateStream::new('{oversized}')");
        let result: Result<PsobfReport> = reverse_psobf(&src);
        assert!(matches!(
            result,
            Err(crate::error::Error::InputTooLarge {
                what: "psobf deflate payload",
                max_bytes: MAX_BASE64_INPUT
            })
        ));
    }

    #[test]
    fn unwraps_deflate_base64() -> Result<()> {
        assert_eq!(decode_base64_bounded("Zg==")?, b"f");
        let expected_result: std::result::Result<Vec<u8>, base64::DecodeError> =
            BASE64_STD.decode("Zg");
        let Err(expected_source): std::result::Result<Vec<u8>, base64::DecodeError> =
            expected_result
        else {
            return Err(Error::InvalidUtf16Le);
        };
        let expected: String = Error::Base64(expected_source).to_string();
        let error_result: Result<Vec<u8>> = decode_base64_bounded("Zg");
        let Err(error): Result<Vec<u8>> = error_result else {
            return Err(Error::InvalidUtf16Le);
        };
        assert!(matches!(&error, Error::Base64(_)));
        assert_eq!(error.to_string(), expected);
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
