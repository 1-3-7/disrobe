use std::collections::BTreeMap;

use ruff_python_parser::{Mode, ParseOptions, Parsed, parse};

use crate::ast_eval::{EvalReport, evaluate_source};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};
use crate::unrename::{canonicalize_homoglyph_names, count_homoglyph_names};

#[derive(Debug, Clone, Copy)]
pub struct PyobfuscateComXorPass;

const HEAD_SCAN_BYTES: usize = 64 * 1024;
const MIN_HOMOGLYPH_NAMES: usize = 3;
const PRINTABLE_RATIO_NUM: usize = 90;

impl ObfuscatorPass for PyobfuscateComXorPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::PyobfuscateComXor
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(HEAD_SCAN_BYTES)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let signals: XorSignals = scan_signals(text);
        let mut markers: Vec<String> = Vec::new();
        if signals.banner {
            markers.push("pyobfuscate-com-xor-banner".to_owned());
        }
        if signals.dunder_xor {
            markers.push("int-dunder-xor".to_owned());
        }
        if signals.class_constructor {
            markers.push("literal-class-constructor".to_owned());
        }
        if signals.lambda_decode {
            markers.push("lambda-decode-iife".to_owned());
        }
        if signals.homoglyph_names >= MIN_HOMOGLYPH_NAMES {
            markers.push(format!("homoglyph-names:{}", signals.homoglyph_names));
        }
        let structural: bool = signals.lambda_decode
            && (signals.dunder_xor || signals.class_constructor)
            && signals.homoglyph_names >= MIN_HOMOGLYPH_NAMES;
        let matched: bool = signals.banner || structural;
        let confidence: f32 = if signals.banner {
            0.97
        } else if signals.lambda_decode && signals.dunder_xor && signals.class_constructor {
            0.9
        } else if structural {
            0.8
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
        let mut stages: Vec<String> = Vec::with_capacity(3);
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        let mut lossy_notes: Vec<String> = Vec::new();

        let (folded, report): (String, EvalReport) = evaluate_source(text)?;
        stages.push("lambda-xor-constant-fold".to_owned());
        diagnostics.insert("exprs_folded".to_owned(), report.exprs_folded.to_string());
        diagnostics.insert(
            "bindings_learned".to_owned(),
            report.bindings_learned.to_string(),
        );

        let (renamed, renamed_count): (String, usize) = match canonicalize_homoglyph_names(&folded)
        {
            Some((text, count)) => {
                stages.push("homoglyph-canonical-rename".to_owned());
                (text, count)
            }
            None => (folded, 0),
        };
        diagnostics.insert("names_canonicalized".to_owned(), renamed_count.to_string());

        let still_obfuscated: bool = count_lambda_decode_idioms(&renamed) > 0;
        let parses: bool = parses_as_python(&renamed);
        let printable: bool = is_mostly_printable(&renamed);
        diagnostics.insert("reparses".to_owned(), parses.to_string());
        diagnostics.insert("printable".to_owned(), printable.to_string());

        let quality: Quality = if parses && printable && !still_obfuscated {
            Quality::Full
        } else if parses && printable {
            lossy_notes.push(
                "some lambda-XOR constant idioms could not be statically folded and remain in the recovered source".to_owned(),
            );
            Quality::Partial
        } else {
            lossy_notes
                .push("recovered source did not re-parse cleanly or is not printable".to_owned());
            Quality::Partial
        };
        if quality == Quality::Full {
            lossy_notes.push(
                "pyobfuscate.com 2026 XOR/lambda variant reversed: every immediately-invoked lambda XOR/hex/to_bytes decode folded to its literal, and the homoglyph identifier renaming canonicalized to stable readable names (the obfuscator discards the original names, so canonical names are the best in-artifact recovery).".to_owned(),
            );
        }

        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: renamed,
            confidence: if quality == Quality::Full { 0.95 } else { 0.85 },
            quality,
            lossy_notes,
            diagnostics,
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct XorSignals {
    banner: bool,
    dunder_xor: bool,
    class_constructor: bool,
    lambda_decode: bool,
    homoglyph_names: usize,
}

fn scan_signals(text: &str) -> XorSignals {
    let banner: bool = text.contains("pyobfuscate.com") || text.contains("__pyobfuscate_com__");
    let dunder_xor: bool = text.contains("int.__xor__(") || text.contains(".__xor__(");
    let class_constructor: bool = text.contains(".__class__(");
    let lambda_decode: bool = text.contains("lambda")
        && (text.contains("fromhex(")
            || text.contains("to_bytes(")
            || text.contains("int.__xor__(")
            || text.contains("[::-1]"));
    XorSignals {
        banner,
        dunder_xor,
        class_constructor,
        lambda_decode,
        homoglyph_names: count_homoglyph_names(text),
    }
}

fn count_lambda_decode_idioms(text: &str) -> usize {
    text.matches(".__xor__(").count()
        + text.matches(".fromhex(").count()
        + text.matches(".to_bytes(").count()
        + text.matches(".__class__(").count()
}

fn parses_as_python(source: &str) -> bool {
    use ruff_python_ast::Mod;
    if source.trim().is_empty() {
        return false;
    }
    parse(source, ParseOptions::from(Mode::Module))
        .is_ok_and(|p: Parsed<Mod>| p.errors().is_empty())
}

fn is_mostly_printable(source: &str) -> bool {
    let bytes: &[u8] = source.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let printable: usize = bytes
        .iter()
        .filter(|&&b: &&u8| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
        .count();
    printable * 100 >= bytes.len() * PRINTABLE_RATIO_NUM
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn xor_int_list(s: &str, key: u8) -> String {
        let ints: Vec<String> = s.bytes().map(|b: u8| (b ^ key).to_string()).collect();
        format!("[{}]", ints.join(", "))
    }

    fn lambda_xor_str(s: &str, key: u8) -> String {
        format!(
            "(lambda p: ''.join((chr(int.__xor__(c, {key})) for c in p)))({list})",
            list = xor_int_list(s, key)
        )
    }

    #[test]
    fn detects_real_hello_signature() {
        let src: &[u8] =
            include_bytes!("../../../../corpus/python/obfuscators/pyobfuscate_com/real_hello.py");
        let report: DetectReport = PyobfuscateComXorPass.detect(src);
        assert!(report.matched, "must detect real pyobfuscate.com xor hello");
        assert!(
            report.confidence >= 0.8,
            "confidence: {}",
            report.confidence
        );
    }

    #[test]
    fn does_not_match_plain_python() {
        let src: &[u8] = b"def f(x):\n    return x + 1\n";
        assert!(!PyobfuscateComXorPass.detect(src).matched);
    }

    #[test]
    fn folds_lambda_xor_string_constant() {
        let expr: String = lambda_xor_str("print", 88);
        let src: String = format!("y = {expr}\n");
        let (out, _r): (String, EvalReport) = evaluate_source(&src).expect("evaluate");
        assert!(
            out.contains("'print'") || out.contains("\"print\""),
            "lambda XOR string must fold to literal; got: {out}"
        );
    }

    #[test]
    fn canonicalizes_homoglyph_names_consistently() {
        let src: &str = "IIlllllIIIIIIlllllll = 1\nlIIlIlllllIlI = IIlllllIIIIIIlllllll + 2\n";
        let (out, count): (String, usize) =
            canonicalize_homoglyph_names(src).expect("canonicalize");
        assert_eq!(count, 2, "two distinct homoglyph names; got: {out}");
        assert!(out.contains("name_0"), "got: {out}");
        assert!(out.contains("name_1"), "got: {out}");
        assert!(
            !out.contains("IIlll"),
            "homoglyph names must be gone; got: {out}"
        );
    }
}
