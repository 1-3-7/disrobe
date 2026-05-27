use std::collections::BTreeMap;

use crate::ast_eval::{EvalReport, evaluate_source};
use crate::codec::{
    b64_decode, b64_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    python_bytes_literal, zlib_compress, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct BlankObfPass;

impl ObfuscatorPass for BlankObfPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::BlankObf
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let full: &str = std::str::from_utf8(source).unwrap_or("");
        let banner: bool = full.contains("BlankOBF") || full.contains("__blankobf__");
        let v2_signal: BlankObfV2Signal = detect_v2_signature(full);
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("blankobf-banner".to_owned());
        }
        if v2_signal.mangled_idents >= 1 {
            markers.push(format!(
                "blankobf-v2-mangled-idents:{}",
                v2_signal.mangled_idents
            ));
        }
        if v2_signal.bytes_reversal_idiom {
            markers.push("blankobf-v2-bytes-reverse-decode".to_owned());
        }
        if v2_signal.int_arith_idiom {
            markers.push("blankobf-v2-int-arith".to_owned());
        }
        let matched: bool = banner
            || (v2_signal.mangled_idents >= 1
                && (v2_signal.bytes_reversal_idiom || v2_signal.int_arith_idiom));
        let confidence: f32 = if banner {
            0.95
        } else if matched {
            0.9
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
        let v2_signal: BlankObfV2Signal = detect_v2_signature(text);
        if v2_signal.mangled_idents >= 1
            && (v2_signal.bytes_reversal_idiom || v2_signal.int_arith_idiom)
        {
            return Ok(peel_v2_partial(self.id(), text, &v2_signal));
        }
        let literal: &str =
            extract_largest_python_bytes_literal(text).ok_or(Error::LiteralNotFound)?;
        let raw: Vec<u8> = decode_python_bytes_literal(literal)?;
        let mut stages: Vec<String> = Vec::with_capacity(2);
        let b64_decoded: Vec<u8> = b64_decode(&raw)?;
        stages.push("base64".to_owned());
        let inflated: Vec<u8> = zlib_decompress(&b64_decoded)?;
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
                "BlankOBF v2 adds junk-name renaming; not reversed by this peel".to_owned(),
            ],
            diagnostics,
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct BlankObfV2Signal {
    mangled_idents: usize,
    bytes_reversal_idiom: bool,
    int_arith_idiom: bool,
}

fn detect_v2_signature(text: &str) -> BlankObfV2Signal {
    let mangled: usize = count_mangled_identifiers(text);
    let bytes_reversal_idiom: bool = text.contains("bytes(") && text.contains("][::-1]");
    let big_int_present: bool = scan_big_int(text);
    let int_arith_idiom: bool = text.contains(") // 2 -")
        || (text.contains(") - ") && text.contains(" + ") && mangled > 0)
        || (big_int_present && mangled > 0);
    BlankObfV2Signal {
        mangled_idents: mangled,
        bytes_reversal_idiom,
        int_arith_idiom,
    }
}

fn scan_big_int(text: &str) -> bool {
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut j: usize = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - i >= 16 {
                return true;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

fn count_mangled_identifiers(text: &str) -> usize {
    let bytes: &[u8] = text.as_bytes();
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'_' && bytes[i + 1] == b'0' && bytes[i + 2] == b'x' {
            let mut end: usize = i + 3;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            let len: usize = end - i;
            if (13..=28).contains(&len) {
                count += 1;
            }
            i = end;
        } else {
            i += 1;
        }
    }
    count
}

fn peel_v2_partial(id: Obfuscator, text: &str, signal: &BlankObfV2Signal) -> PeelOutcome {
    let mut stages: Vec<String> = vec!["v2-detect".to_owned()];
    let regex_folded: String = constant_fold_blankobf_v2(text, &mut stages);
    let (ast_folded, ast_report, ast_ok): (String, EvalReport, bool) =
        match evaluate_source(&regex_folded) {
            Ok((s, r)) => {
                stages.push("ast-eval".to_owned());
                let ok: bool = r.exprs_folded > 0 || r.bindings_learned > 0;
                (s, r, ok)
            }
            Err(_) => (regex_folded.clone(), EvalReport::default(), false),
        };
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert(
        "mangled_idents".to_owned(),
        signal.mangled_idents.to_string(),
    );
    diagnostics.insert(
        "bytes_reversal_idiom".to_owned(),
        signal.bytes_reversal_idiom.to_string(),
    );
    diagnostics.insert(
        "int_arith_idiom".to_owned(),
        signal.int_arith_idiom.to_string(),
    );
    diagnostics.insert(
        "ast_exprs_folded".to_owned(),
        ast_report.exprs_folded.to_string(),
    );
    diagnostics.insert(
        "ast_bindings_learned".to_owned(),
        ast_report.bindings_learned.to_string(),
    );
    diagnostics.insert(
        "ast_bindings_skipped_dynamic".to_owned(),
        ast_report.bindings_skipped_dynamic.to_string(),
    );
    let (quality, confidence, notes): (Quality, f32, Vec<String>) = if ast_ok {
        (
            Quality::Full,
            0.9,
            vec!["BlankOBF v2 AST evaluator successfully folded arithmetic and bytes-reverse-decode patterns".to_owned()],
        )
    } else {
        (
            Quality::Partial,
            0.6,
            vec![
                "BlankOBF v2 AST evaluator did not find foldable expressions; falling back to regex fold only".to_owned(),
            ],
        )
    };
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: ast_folded,
        confidence,
        quality,
        lossy_notes: notes,
        diagnostics,
    }
}

fn constant_fold_blankobf_v2(text: &str, stages: &mut Vec<String>) -> String {
    let folded: String = fold_bytes_reverse_decode(text);
    if folded.len() != text.len() {
        stages.push("bytes-reverse-decode-fold".to_owned());
    }
    folded
}

fn fold_bytes_reverse_decode(text: &str) -> String {
    let needle: &str = "bytes([";
    let suffix: &str = "][::-1]).decode()";
    let bytes: &[u8] = text.as_bytes();
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        if let Some(start) = text[cursor..].find(needle) {
            let abs_start: usize = cursor + start;
            let inner_start: usize = abs_start + needle.len();
            if let Some(close_off) = text[inner_start..].find(suffix) {
                let inner: &str = &text[inner_start..inner_start + close_off];
                if let Some(decoded) = parse_int_list_decode(inner) {
                    out.push_str(&text[cursor..abs_start]);
                    out.push('\'');
                    for c in decoded.chars() {
                        if c == '\'' {
                            out.push_str("\\'");
                        } else if c == '\\' {
                            out.push_str("\\\\");
                        } else {
                            out.push(c);
                        }
                    }
                    out.push('\'');
                    cursor = inner_start + close_off + suffix.len();
                    continue;
                }
            }
            out.push_str(&text[cursor..=abs_start]);
            cursor = abs_start + 1;
        } else {
            out.push_str(&text[cursor..]);
            break;
        }
    }
    out
}

fn parse_int_list_decode(inner: &str) -> Option<String> {
    let mut nums: Vec<u8> = Vec::new();
    for part in inner.split(',') {
        let t: &str = part.trim();
        if t.is_empty() {
            continue;
        }
        let n: u16 = t.parse::<u16>().ok()?;
        if n > 255 {
            return None;
        }
        nums.push(u8::try_from(n).ok()?);
    }
    nums.reverse();
    String::from_utf8(nums).ok()
}

#[must_use]
pub fn bake(source: &str) -> String {
    let zipped: Vec<u8> = zlib_compress(source.as_bytes());
    let encoded: String = b64_encode(&zipped);
    let literal: String = python_bytes_literal(encoded.as_bytes());
    format!(
        "# BlankOBF v1\n__blankobf__ = '1'\nimport base64, zlib\nexec(zlib.decompress(base64.b64decode({literal})))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn blankobf_roundtrip() {
        let original: &str = "print('blankobf')\n";
        let obf: String = bake(original);
        assert!(BlankObfPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = BlankObfPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }

    #[test]
    fn blankobf_v2_detects_mangled_idents() {
        let sample: &str = "_0xabc1234567 = bytes([111, 108, 108, 101, 104][::-1]).decode()\n_0xdef9876543 = (6545115918955394424 + 6478) // 2 - 3272557959477697212 - 3198\n_0x1111aaaabbbb = _0xabc1234567 + _0xdef9876543\n_0x2222ccccdddd = _0x1111aaaabbbb\n";
        let det: DetectReport = BlankObfPass.detect(sample.as_bytes());
        assert!(det.matched, "{det:?}");
        let out: PeelOutcome = BlankObfPass.peel(sample.as_bytes()).expect("peel");
        assert_eq!(out.quality, Quality::Full);
        assert!(
            out.recovered_source.contains("'hello'"),
            "expected folded bytes literal in {}",
            out.recovered_source
        );
        assert!(
            out.recovered_source.contains("41"),
            "expected folded arith result in {}",
            out.recovered_source
        );
    }

    #[test]
    fn fold_bytes_reverse_decode_works() {
        let s: &str = "x = bytes([111, 108, 108, 101, 104][::-1]).decode()";
        let folded: String = fold_bytes_reverse_decode(s);
        assert_eq!(folded, "x = 'hello'");
    }

    #[test]
    fn count_mangled_idents_short_sample() {
        let s: &str =
            "_0xabc1234567abc = 1\n_0xdef9876543def = 2\n_0x1111aaaabbbb22 = _0xabc1234567abc\n";
        let n: usize = count_mangled_identifiers(s);
        assert!(n >= 2, "got {n} for {s}");
    }
}
