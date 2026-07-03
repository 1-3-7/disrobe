use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PayloadKind {
    PowerShell,
    JScript,
    VBScript,
    Base64Utf8,
    Base64Utf16Le,
    XorDecrypted,
    AesCbcDecrypted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecoveryState {
    Recovered,
    UnrecoveredRuntimeKey,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmbeddedPayload {
    pub kind: PayloadKind,
    pub state: RecoveryState,
    pub content: String,
}

static POWERSHELL_INVOKE: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?is)(?:powershell|pwsh)(?:\.exe)?\b(?P<flags>[^\r\n&|]*?)(?:-c(?:ommand)?|-e(?:nc(?:odedcommand)?)?)\s+(?P<body>.+?)(?:\r?\n|$)"#,
    )
});

static PS_ENCODED_FLAG: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)-e(?:nc(?:odedcommand)?)?\b"));

static WSCRIPT_LANG: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?i)<script\s+language\s*=\s*"(?P<lang>[a-z]+)"\s*>(?P<body>.*?)</script>"#,
    )
});

static B64_RUN: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"[A-Za-z0-9+/]{32,}={0,2}"));

static PS_CONCAT_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r#"(?:'[^']*'|"[^"]*")(?:\s*\+\s*(?:'[^']*'|"[^"]*")){2,}"#)
});

const MIN_DECODE_LEN: usize = 16;
const MAX_DECODE_LEN: usize = 1 << 20;

fn decode_base64_flexible(blob: &str) -> Option<Vec<u8>> {
    if blob.len() > MAX_DECODE_LEN {
        return None;
    }
    let core: &str = blob.trim_end_matches('=');
    let mut padded: String = core.to_owned();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    B64_STANDARD.decode(&padded).ok()
}

#[must_use]
pub fn extract_embedded(source: &str) -> Vec<EmbeddedPayload> {
    let mut out: Vec<EmbeddedPayload> = Vec::new();
    extract_powershell(source, &mut out);
    extract_wsh_scripts(source, &mut out);
    extract_concat_chains(source, &mut out);
    extract_base64_blobs(source, &mut out);
    dedup(&mut out);
    out
}

fn extract_powershell(source: &str, out: &mut Vec<EmbeddedPayload>) {
    for cap in POWERSHELL_INVOKE.captures_iter(source) {
        let flags: &str = cap
            .name("flags")
            .map_or("", |m: regex::Match<'_>| m.as_str());
        let Some(body_m): Option<regex::Match<'_>> = cap.name("body") else {
            continue;
        };
        let body: &str = body_m.as_str().trim();
        let matched: &str = cap.get(0).map_or("", |m: regex::Match<'_>| m.as_str());
        let encoded: bool = PS_ENCODED_FLAG.is_match(flags)
            || PS_ENCODED_FLAG
                .is_match(matched.get(..matched.len() - body.len()).unwrap_or(matched));
        let decoded: Option<String> = if encoded {
            let token: &str = body.split_whitespace().next().unwrap_or(body);
            decode_powershell_encodedcommand(token)
        } else {
            None
        };
        let content: String = if encoded {
            let Some(decoded_content): Option<String> = decoded else {
                continue;
            };
            decoded_content
        } else {
            strip_outer_quotes(body)
        };
        if !content.is_empty() {
            out.push(EmbeddedPayload {
                kind: PayloadKind::PowerShell,
                state: RecoveryState::Recovered,
                content,
            });
        }
    }
}

fn decode_powershell_encodedcommand(token: &str) -> Option<String> {
    let cleaned: String = token
        .trim_matches(|c: char| c == '"' || c == '\'')
        .to_owned();
    if cleaned.len() < MIN_DECODE_LEN {
        return None;
    }
    let bytes: Vec<u8> = decode_base64_flexible(&cleaned)?;
    decode_utf16le(&bytes).or_else(|| printable(&bytes))
}

fn extract_wsh_scripts(source: &str, out: &mut Vec<EmbeddedPayload>) {
    for cap in WSCRIPT_LANG.captures_iter(source) {
        let lang: String = cap
            .name("lang")
            .map_or(String::new(), |m: regex::Match<'_>| {
                m.as_str().to_ascii_lowercase()
            });
        let body: String = cap
            .name("body")
            .map_or(String::new(), |m: regex::Match<'_>| {
                m.as_str().trim().to_owned()
            });
        if body.is_empty() {
            continue;
        }
        let kind: PayloadKind = if lang.contains("vb") {
            PayloadKind::VBScript
        } else {
            PayloadKind::JScript
        };
        out.push(EmbeddedPayload {
            kind,
            state: RecoveryState::Recovered,
            content: body,
        });
    }
}

fn extract_concat_chains(source: &str, out: &mut Vec<EmbeddedPayload>) {
    for m in PS_CONCAT_CHAIN.find_iter(source) {
        let reassembled: String = reassemble_concat(m.as_str());
        if reassembled.len() >= MIN_DECODE_LEN {
            out.push(EmbeddedPayload {
                kind: PayloadKind::PowerShell,
                state: RecoveryState::Recovered,
                content: reassembled,
            });
        }
    }
}

#[must_use]
pub fn reassemble_concat(chain: &str) -> String {
    let mut out: String = String::new();
    let chars: Vec<char> = chain.chars().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        let c: char = chars[i];
        i += 1;
        if c == '\'' || c == '"' {
            while i < chars.len() && chars[i] != c {
                out.push(chars[i]);
                i += 1;
            }
            i += 1;
        }
    }
    out
}

fn extract_base64_blobs(source: &str, out: &mut Vec<EmbeddedPayload>) {
    for m in B64_RUN.find_iter(source) {
        let blob: &str = m.as_str();
        if blob.len() < MIN_DECODE_LEN || blob.len() > MAX_DECODE_LEN {
            continue;
        }
        let Some(decoded): Option<Vec<u8>> = decode_base64_flexible(blob) else {
            continue;
        };
        let decoded_payload: Option<(PayloadKind, String)> = decode_utf16le(&decoded)
            .map(|t: String| (PayloadKind::Base64Utf16Le, t))
            .or_else(|| printable(&decoded).map(|t: String| (PayloadKind::Base64Utf8, t)));
        if let Some((kind, content)) = decoded_payload {
            out.push(EmbeddedPayload {
                kind,
                state: RecoveryState::Recovered,
                content,
            });
        }
    }
}

#[must_use]
pub fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nul_count: usize = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|b: &&u8| **b == 0)
        .count();
    let pair_count: usize = bytes.len() / 2;
    if pair_count == 0 || nul_count * 2 < pair_count {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text: String = String::from_utf16(&units).ok()?;
    if is_printable_text(&text) {
        Some(text)
    } else {
        None
    }
}

fn printable(bytes: &[u8]) -> Option<String> {
    let text: &str = core::str::from_utf8(bytes).ok()?;
    if is_printable_text(text) {
        Some(text.to_owned())
    } else {
        None
    }
}

fn is_printable_text(text: &str) -> bool {
    let total: usize = text.chars().count();
    if total == 0 {
        return false;
    }
    let printable: usize = text
        .chars()
        .filter(|c: &char| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    printable as f64 / total as f64 >= 0.85
}

fn strip_outer_quotes(s: &str) -> String {
    let t: &str = s.trim();
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        t[1..t.len() - 1].to_owned()
    } else {
        t.to_owned()
    }
}

fn dedup(out: &mut Vec<EmbeddedPayload>) {
    let mut seen: Vec<(PayloadKind, String)> = Vec::new();
    out.retain(|p: &EmbeddedPayload| {
        let key: (PayloadKind, String) = (p.kind, p.content.clone());
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_powershell_encodedcommand_utf16() {
        let inner: &str = "Write-Host hi";
        let utf16: Vec<u8> = inner
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
        let b64: String = B64_STANDARD.encode(&utf16);
        let src: String = format!("powershell -nop -enc {b64}\n");
        let payloads: Vec<EmbeddedPayload> = extract_embedded(&src);
        assert!(
            payloads
                .iter()
                .any(|p: &EmbeddedPayload| p.kind == PayloadKind::PowerShell
                    && p.content.contains("Write-Host hi")),
            "{payloads:?}"
        );
    }

    #[test]
    fn oversized_powershell_encodedcommand_is_not_returned() {
        let oversized: String = "A".repeat(MAX_DECODE_LEN + 1);
        let src: String = format!("powershell -nop -enc {oversized}\n");
        let payloads: Vec<EmbeddedPayload> = extract_embedded(&src);
        assert!(payloads.is_empty(), "{payloads:?}");
    }

    #[test]
    fn reassembles_concat_chain() {
        let chain: &str = "'Inv'+'oke-'+'Mimikatz'";
        assert_eq!(reassemble_concat(chain), "Invoke-Mimikatz");
    }

    #[test]
    fn extracts_base64_utf16_blob() {
        let inner: &str = "http://evil.example.com/x";
        let utf16: Vec<u8> = inner
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
        let b64: String = B64_STANDARD.encode(&utf16);
        let payloads: Vec<EmbeddedPayload> = extract_embedded(&format!("set X={b64}"));
        assert!(
            payloads
                .iter()
                .any(|p: &EmbeddedPayload| p.kind == PayloadKind::Base64Utf16Le
                    && p.content.contains("evil.example.com")),
            "{payloads:?}"
        );
    }

    #[test]
    fn extracts_jscript_block() {
        let src: &str = "<script language=\"JScript\">var x = 1; eval(x);</script>";
        let payloads: Vec<EmbeddedPayload> = extract_embedded(src);
        assert!(
            payloads
                .iter()
                .any(|p: &EmbeddedPayload| p.kind == PayloadKind::JScript),
            "{payloads:?}"
        );
    }

    #[test]
    fn utf16le_rejects_ascii() {
        assert!(decode_utf16le(b"plain ascii text here").is_none());
    }
}
