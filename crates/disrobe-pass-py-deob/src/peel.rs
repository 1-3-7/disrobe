use base64::Engine;
use disrobe_py_marshal::PyVersion;
use serde::Serialize;

use crate::cipher::KeyFinding;
use crate::debug::{dbg_kv, dbg_kv_guarded, dbg_line, dbg_section};
use crate::detect::{Detection, Family, detect};
use crate::error::{Error, Result};
use crate::hyperion_v2v3::{
    HyperionV2V3Detection, HyperionVariant, InnerDecodeResult as HyperionInnerDecodeResult,
    decode_inner as decode_hyperion_inner, detect as detect_hyperion,
};
use crate::layered_peel::{LayerStep, LayeredPeel, PeelBudget, WallReason, peel_layers};
use crate::marshal::{MarshalRecovery, detect_marshal, recover_marshal};
use crate::obfuscators::{
    DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality, iter_passes,
};

const MAX_DEPTH: usize = 32;
const DETECT_THRESHOLD: f32 = 0.5f32;

#[derive(Debug, Clone, Serialize)]
pub struct PeelStep {
    pub family: Family,
    pub decoder: String,
    pub byte_size_in: usize,
    pub byte_size_out: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObfuscatorPeelSummary {
    pub obfuscator: Obfuscator,
    pub detect_confidence: f32,
    pub peel_confidence: f32,
    pub quality: Quality,
    pub stages_applied: Vec<String>,
    pub lossy_notes: Vec<String>,
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeelResult {
    pub initial: Detection,
    pub steps: Vec<PeelStep>,
    pub final_source: String,
    pub converged: bool,
    pub recovered: bool,
    pub obfuscator: Option<ObfuscatorPeelSummary>,
    pub hyperion_inner: Option<HyperionInnerDecodeResult>,
    pub marshal: Option<MarshalRecovery>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_findings: Vec<KeyFinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall: Option<WallReason>,
}

pub(crate) fn best_obfuscator_detection(
    source: &[u8],
) -> Option<(&'static dyn ObfuscatorPass, DetectReport)> {
    let mut best: Option<(&'static dyn ObfuscatorPass, DetectReport)> = None;
    for pass in iter_passes() {
        let report: DetectReport = pass.detect(source);
        if !report.matched || report.confidence < DETECT_THRESHOLD {
            continue;
        }
        dbg_kv("obfuscator-candidate", || {
            format!(
                "{obf:?} confidence={c:.2} markers=[{m}]",
                obf = report.obfuscator,
                c = report.confidence,
                m = report.markers.join(",")
            )
        });
        let better: bool =
            best.as_ref()
                .is_none_or(|(_, prev): &(&'static dyn ObfuscatorPass, DetectReport)| {
                    report.confidence > prev.confidence
                });
        if better {
            best = Some((pass, report));
        }
    }
    if let Some((_, report)) = best.as_ref() {
        dbg_kv("obfuscator-selected", || {
            format!(
                "{obf:?} confidence={c:.2}",
                obf = report.obfuscator,
                c = report.confidence
            )
        });
    }
    best
}

fn try_obfuscator_peel(source: &[u8], initial: Detection) -> Option<PeelResult> {
    let (pass, report): (&'static dyn ObfuscatorPass, DetectReport) =
        best_obfuscator_detection(source)?;
    let outcome: PeelOutcome = pass.peel(source).ok()?;
    let recovered_bytes: &[u8] = outcome.recovered_source.as_bytes();
    let real_output: bool =
        !outcome.recovered_source.trim().is_empty() && recovered_bytes != source;
    if !real_output {
        dbg_kv("obfuscator-peel", || {
            format!(
                "{obf:?} produced no real output (DetectOnly)",
                obf = outcome.obfuscator
            )
        });
        return None;
    }
    let recovered: bool = matches!(outcome.quality, Quality::Full | Quality::Partial);
    dbg_kv("obfuscator-quality", || {
        format!(
            "{obf:?} quality={q:?} stages=[{s}] in={bin} out={bout}",
            obf = outcome.obfuscator,
            q = outcome.quality,
            s = outcome.stages_applied.join("+"),
            bin = source.len(),
            bout = recovered_bytes.len()
        )
    });
    let summary: ObfuscatorPeelSummary = ObfuscatorPeelSummary {
        obfuscator: outcome.obfuscator,
        detect_confidence: report.confidence,
        peel_confidence: outcome.confidence,
        quality: outcome.quality,
        stages_applied: outcome.stages_applied.clone(),
        lossy_notes: outcome.lossy_notes,
        markers: report.markers,
    };
    let step: PeelStep = PeelStep {
        family: initial.family,
        decoder: format!(
            "{obf:?}:{stages}",
            obf = outcome.obfuscator,
            stages = outcome.stages_applied.join("+")
        ),
        byte_size_in: source.len(),
        byte_size_out: recovered_bytes.len(),
    };
    Some(PeelResult {
        initial,
        steps: vec![step],
        final_source: outcome.recovered_source,
        converged: matches!(outcome.quality, Quality::Full),
        recovered,
        obfuscator: Some(summary),
        hyperion_inner: None,
        marshal: None,
        key_findings: Vec::new(),
        wall: None,
    })
}

fn try_marshal_peel(
    source: &[u8],
    initial: &Detection,
    hint: Option<PyVersion>,
) -> Option<PeelResult> {
    if detect_marshal(source) < DETECT_THRESHOLD {
        return None;
    }
    let recovery: MarshalRecovery = recover_marshal(source, hint).ok()?;
    if recovery.source.trim().is_empty() {
        return None;
    }
    let mut steps: Vec<PeelStep> = Vec::with_capacity(recovery.chain.len());
    let mut running: usize = source.len();
    for label in &recovery.chain {
        steps.push(PeelStep {
            family: Family::GenericDropper,
            decoder: format!("marshal/{label}"),
            byte_size_in: running,
            byte_size_out: recovery.source.len(),
        });
        running = recovery.source.len();
    }
    Some(PeelResult {
        initial: initial.clone(),
        steps,
        final_source: recovery.source.clone(),
        converged: true,
        recovered: true,
        obfuscator: None,
        hyperion_inner: None,
        marshal: Some(recovery),
        key_findings: Vec::new(),
        wall: None,
    })
}

fn try_layered_peel(
    source: &[u8],
    initial: &Detection,
    hint: Option<PyVersion>,
) -> Option<PeelResult> {
    let budget: PeelBudget = PeelBudget::default();
    let layered: LayeredPeel = peel_layers(source, hint, &budget).ok()?;
    if !layered.recovered || layered.steps.is_empty() {
        return None;
    }
    if layered.final_source.trim().is_empty() || layered.final_source.as_bytes() == source {
        return None;
    }
    if layered
        .steps
        .iter()
        .all(|s: &LayerStep| matches!(s.decoder.as_str(), "pyc-strip" | "marshal"))
    {
        return None;
    }
    let steps: Vec<PeelStep> = layered
        .steps
        .iter()
        .map(|s: &LayerStep| PeelStep {
            family: initial.family,
            decoder: format!("layered/{decoder}", decoder = s.decoder),
            byte_size_in: s.byte_size_in,
            byte_size_out: s.byte_size_out,
        })
        .collect();
    Some(PeelResult {
        initial: initial.clone(),
        steps,
        final_source: layered.final_source,
        converged: layered.converged,
        recovered: layered.recovered,
        obfuscator: None,
        hyperion_inner: None,
        marshal: None,
        key_findings: layered.key_findings,
        wall: layered.wall,
    })
}

pub fn peel(source: &[u8]) -> Result<PeelResult> {
    peel_with_pyver(source, None)
}

pub fn peel_with_pyver(source: &[u8], pyver_hint: Option<PyVersion>) -> Result<PeelResult> {
    dbg_section("peel");
    let initial: Detection = detect(source);
    dbg_kv("peel-family", || format!("{:?}", initial.family));

    if let Some(result) = try_marshal_peel(source, &initial, pyver_hint) {
        dbg_kv("peel-route", || "marshal".to_owned());
        dbg_recovery(&result);
        return Ok(result);
    }

    if let Some(result) = try_obfuscator_peel(source, initial.clone()) {
        dbg_kv("peel-route", || "obfuscator".to_owned());
        dbg_recovery(&result);
        return Ok(result);
    }

    let mut current: Vec<u8> = source.to_vec();
    let mut steps: Vec<PeelStep> = Vec::new();
    let mut converged: bool = false;
    let mut hyperion_inner: Option<HyperionInnerDecodeResult> = None;

    for depth in 0..MAX_DEPTH {
        let detection: Detection = detect(&current);
        let hyperion_detection: HyperionV2V3Detection = detect_hyperion(&current);
        let hyperion_inner_eligible: bool = matches!(
            hyperion_detection.variant,
            HyperionVariant::V3LzmaMarshal | HyperionVariant::KramerSuccessor
        );
        if hyperion_inner_eligible
            && hyperion_inner.is_none()
            && let Ok(inner) = decode_hyperion_inner(&current)
        {
            let inner_bytes_in: usize = current.len();
            let inner_bytes_out: usize =
                inner.stages.last().map_or(inner_bytes_in, |s| s.bytes_out);
            let inner_label: String = inner
                .stages
                .iter()
                .map(|s| format!("{kind:?}", kind = s.kind).to_ascii_lowercase())
                .collect::<Vec<String>>()
                .join("+");
            steps.push(PeelStep {
                family: Family::Hyperion,
                decoder: format!("hyperion-inner({inner_label})"),
                byte_size_in: inner_bytes_in,
                byte_size_out: inner_bytes_out,
            });
            hyperion_inner = Some(inner);
            converged = true;
            break;
        }
        let next_step: Option<(Family, String, Vec<u8>)> = match detection.family {
            Family::GenericDropper | Family::Pyfuscator => try_peel_dropper(&current)
                .map(|(label, payload)| (detection.family, label, payload)),
            Family::Hyperion => try_peel_hyperion(&current)
                .map(|payload| (Family::Hyperion, "hyperion-zlib".to_owned(), payload)),
            _ => None,
        }
        .or_else(|| {
            try_peel_exec_eval(&current)
                .map(|(label, payload)| (Family::GenericDropper, label, payload))
        });
        let Some((step_family, label, payload)): Option<(Family, String, Vec<u8>)> = next_step
        else {
            converged = true;
            break;
        };
        let bytes_in: usize = current.len();
        steps.push(PeelStep {
            family: step_family,
            decoder: label,
            byte_size_in: bytes_in,
            byte_size_out: payload.len(),
        });
        current = payload;
        if depth + 1 == MAX_DEPTH {
            return Err(Error::DepthLimit(MAX_DEPTH));
        }
    }

    let recovered: bool = !steps.is_empty() || hyperion_inner.is_some();
    if !recovered && let Some(layered) = try_layered_peel(source, &initial, pyver_hint) {
        dbg_kv("peel-route", || "layered".to_owned());
        dbg_recovery(&layered);
        return Ok(layered);
    }

    let final_source: String = String::from_utf8_lossy(&current).into_owned();
    let result: PeelResult = PeelResult {
        initial,
        steps,
        final_source,
        converged,
        recovered,
        obfuscator: None,
        hyperion_inner,
        marshal: None,
        key_findings: Vec::new(),
        wall: None,
    };
    dbg_kv("peel-route", || {
        if result.recovered {
            "source-chain".to_owned()
        } else {
            "no-recovery".to_owned()
        }
    });
    dbg_recovery(&result);
    Ok(result)
}

fn dbg_recovery(result: &PeelResult) {
    dbg_kv("recovered", || result.recovered.to_string());
    dbg_kv("converged", || result.converged.to_string());
    for step in &result.steps {
        dbg_line(|| {
            format!(
                "step {decoder}: {bin} -> {bout} bytes",
                decoder = step.decoder,
                bin = step.byte_size_in,
                bout = step.byte_size_out
            )
        });
    }
    for finding in &result.key_findings {
        dbg_kv("key-cipher", || format!("{:?}", finding.cipher));
        dbg_kv_guarded("key-hex", || finding.key_hex.clone());
    }
    if let Some(wall) = result.wall {
        dbg_kv("wall", || format!("{wall:?}"));
    }
}

fn try_peel_dropper(source: &[u8]) -> Option<(String, Vec<u8>)> {
    let text: &str = std::str::from_utf8(source).ok()?;
    let literal: &str = extract_first_bytes_literal(text)?;
    let raw: Vec<u8> = decode_python_bytes(literal).ok()?;

    if let Ok(de) = base64::engine::general_purpose::STANDARD.decode(&raw) {
        if let Ok(infl) = inflate(&de) {
            return Some(("base64+zlib".to_owned(), infl));
        }
        return Some(("base64".to_owned(), de));
    }

    if let Ok(de) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&raw) {
        return Some(("base64-urlsafe".to_owned(), de));
    }

    if let Ok(decoded) = crate::codec::b85_decode(&raw) {
        if let Ok(infl) = inflate(&decoded) {
            return Some(("base85+zlib".to_owned(), infl));
        }
        return Some(("base85".to_owned(), decoded));
    }

    if let Ok(infl) = inflate(&raw) {
        return Some(("zlib".to_owned(), infl));
    }

    None
}

fn try_peel_hyperion(source: &[u8]) -> Option<Vec<u8>> {
    let text: &str = std::str::from_utf8(source).ok()?;
    let literal: &str = find_largest_bytes_literal(text)?;
    let raw: Vec<u8> = decode_python_bytes(literal).ok()?;
    inflate(&raw).ok()
}

fn extract_first_bytes_literal(text: &str) -> Option<&str> {
    let idx: usize = text.find("b'").or_else(|| text.find("b\""))?;
    let opener: u8 = *text.as_bytes().get(idx + 1)?;
    let body_start: usize = idx + 2;
    let rest: &str = text.get(body_start..)?;
    let end_off: usize = find_unescaped(rest.as_bytes(), opener)?;
    rest.get(..end_off)
}

fn find_largest_bytes_literal(text: &str) -> Option<&str> {
    let mut best: Option<(&str, usize)> = None;
    let mut cursor: usize = 0;
    while let Some((lit, next_cursor)) = next_bytes_literal(text, cursor) {
        let score: usize = lit.len();
        if best.is_none_or(|(_, s)| score > s) {
            best = Some((lit, score));
        }
        cursor = next_cursor;
    }
    best.map(|(s, _)| s)
}

fn next_bytes_literal(text: &str, cursor: usize) -> Option<(&str, usize)> {
    let window: &str = text.get(cursor..)?;
    let rel: usize = window.find("b'").or_else(|| window.find("b\""))?;
    let idx: usize = cursor + rel;
    let &opener: &u8 = text.as_bytes().get(idx + 1)?;
    let body_start: usize = idx + 2;
    let rest: &str = text.get(body_start..)?;
    let end_off: usize = find_unescaped(rest.as_bytes(), opener)?;
    let lit: &str = rest.get(..end_off)?;
    Some((lit, body_start + end_off + 1))
}

fn find_unescaped(bytes: &[u8], opener: u8) -> Option<usize> {
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == opener {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn decode_python_bytes(s: &str) -> Result<Vec<u8>> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            break;
        }
        let escape: u8 = bytes[i + 1];
        match escape {
            b'x' => {
                if i + 3 >= bytes.len() {
                    break;
                }
                let high: u8 = hex_nibble(bytes[i + 2]).ok_or(Error::LiteralNotFound)?;
                let low: u8 = hex_nibble(bytes[i + 3]).ok_or(Error::LiteralNotFound)?;
                out.push((high << 4) | low);
                i += 4;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'\'' => {
                out.push(b'\'');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'0' => {
                out.push(0);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[inline]
const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const EXEC_EVAL_KEYWORDS: [&str; 3] = ["exec", "eval", "compile"];

fn find_exec_eval_argument(text: &str) -> Option<&str> {
    let bytes: &[u8] = text.as_bytes();
    let mut best: Option<&str> = None;
    let mut best_len: usize = 0;
    let mut open_calls: Vec<(usize, bool)> = Vec::new();
    let mut quote: Option<u8> = None;
    let mut i: usize = 0;
    while i < bytes.len() {
        let c: u8 = bytes[i];
        match quote {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                b'\'' | b'"' => quote = Some(c),
                b'(' => open_calls.push((i, paren_begins_exec_call(bytes, i))),
                b')' => {
                    if let Some((open, begins_exec_call)) = open_calls.pop()
                        && begins_exec_call
                        && let Some(arg) = text.get(open + 1..i)
                        && arg.len() > best_len
                    {
                        best_len = arg.len();
                        best = Some(arg);
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    best
}

fn paren_begins_exec_call(bytes: &[u8], open_paren: usize) -> bool {
    let prefix: &[u8] = &bytes[..open_paren];
    EXEC_EVAL_KEYWORDS
        .iter()
        .any(|kw: &&str| prefix.ends_with(kw.as_bytes()))
}

fn try_peel_exec_eval(source: &[u8]) -> Option<(String, Vec<u8>)> {
    let text: &str = std::str::from_utf8(source).ok()?;
    let argument: &str = find_exec_eval_argument(text)?;
    if let Some((label, payload)) = peel_decode_chain_in(argument) {
        return Some((format!("exec-eval/{label}"), payload));
    }
    let inner: &str = extract_first_string_literal(argument)?;
    let decoded: Vec<u8> = decode_python_text_literal(inner)?;
    Some(("exec-eval/literal".to_owned(), decoded))
}

fn peel_decode_chain_in(argument: &str) -> Option<(String, Vec<u8>)> {
    let literal: &str = extract_first_bytes_literal(argument)?;
    let raw: Vec<u8> = decode_python_bytes(literal).ok()?;
    if let Ok(de) = base64::engine::general_purpose::STANDARD.decode(&raw) {
        if let Ok(infl) = inflate(&de) {
            return Some(("base64+zlib".to_owned(), infl));
        }
        if looks_like_text_or_code(&de) {
            return Some(("base64".to_owned(), de));
        }
    }
    if let Ok(decoded) = crate::codec::b85_decode(&raw) {
        if let Ok(infl) = inflate(&decoded) {
            return Some(("base85+zlib".to_owned(), infl));
        }
        if looks_like_text_or_code(&decoded) {
            return Some(("base85".to_owned(), decoded));
        }
    }
    if let Ok(decoded) = crate::codec::b32_decode(&raw)
        && looks_like_text_or_code(&decoded)
    {
        if let Ok(infl) = inflate(&decoded) {
            return Some(("base32+zlib".to_owned(), infl));
        }
        return Some(("base32".to_owned(), decoded));
    }
    if let Ok(decoded) = crate::codec::b16_decode(&raw)
        && looks_like_text_or_code(&decoded)
    {
        if let Ok(infl) = inflate(&decoded) {
            return Some(("base16+zlib".to_owned(), infl));
        }
        return Some(("base16".to_owned(), decoded));
    }
    if let Ok(infl) = inflate(&raw) {
        return Some(("zlib".to_owned(), infl));
    }
    None
}

fn looks_like_text_or_code(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable: usize = bytes
        .iter()
        .filter(|&&b: &&u8| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
        .count();
    printable * 10 >= bytes.len() * 9
}

fn extract_first_string_literal(text: &str) -> Option<&str> {
    let idx: usize = text.find('\'').or_else(|| text.find('"'))?;
    let opener: u8 = *text.as_bytes().get(idx)?;
    let body_start: usize = idx + 1;
    let rest: &str = text.get(body_start..)?;
    let end_off: usize = find_unescaped(rest.as_bytes(), opener)?;
    rest.get(..end_off)
}

fn decode_python_text_literal(s: &str) -> Option<Vec<u8>> {
    let decoded: Vec<u8> = decode_python_bytes(s).ok()?;
    if decoded.is_empty() {
        return None;
    }
    Some(decoded)
}

fn inflate(input: &[u8]) -> Result<Vec<u8>> {
    crate::codec::zlib_decompress(input)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn no_family_returns_converged() {
        let src: &[u8] = b"def main(): return 1";
        let Ok(result): Result<PeelResult> = peel(src) else {
            panic!("peel must succeed on plain source");
        };
        assert!(result.converged);
        assert!(result.steps.is_empty());
        assert!(!result.recovered);
        assert!(result.obfuscator.is_none());
    }

    #[test]
    fn blankobf_wrapper_recovers_real_source() {
        let original: &str = "print('wired blankobf')\n";
        let obf: String = crate::obfuscators::blankobf::bake(original);
        let Ok(result): Result<PeelResult> = peel(obf.as_bytes()) else {
            panic!("peel must succeed on baked blankobf");
        };
        assert!(result.recovered);
        assert_eq!(result.final_source, original);
        let Some(summary): Option<ObfuscatorPeelSummary> = result.obfuscator else {
            panic!("expected obfuscator summary");
        };
        assert_eq!(summary.obfuscator, Obfuscator::BlankObf);
        assert_ne!(result.final_source.as_bytes(), obf.as_bytes());
    }

    #[test]
    fn plusobf_wrapper_recovers_real_source() {
        let original: &str = "x = 1 + 2\nprint(x)\n";
        let obf: String = crate::obfuscators::plusobf::bake(original);
        let Ok(result): Result<PeelResult> = peel(obf.as_bytes()) else {
            panic!("peel must succeed on baked plusobf");
        };
        assert!(result.recovered);
        let Some(summary): Option<ObfuscatorPeelSummary> = result.obfuscator else {
            panic!("expected obfuscator summary");
        };
        assert_eq!(summary.obfuscator, Obfuscator::PlusObf);
        assert_ne!(result.final_source.as_bytes(), obf.as_bytes());
    }

    #[test]
    fn extract_first_bytes_literal_basic() {
        let s: &str = "exec(b'hello world')";
        let Some(lit): Option<&str> = extract_first_bytes_literal(s) else {
            panic!("expected literal");
        };
        assert_eq!(lit, "hello world");
    }

    #[test]
    fn find_exec_eval_argument_handles_nested_parens_and_quotes() {
        let s: &str = "exec(decompress(b64decode(b'AA')) + ')')";
        let Some(arg): Option<&str> = find_exec_eval_argument(s) else {
            panic!("expected balanced argument");
        };
        assert_eq!(arg, "decompress(b64decode(b'AA')) + ')'");
    }

    #[test]
    fn find_exec_eval_argument_is_linear_on_unterminated_calls() {
        let hostile: String = "exec(".repeat(200_000);
        assert!(find_exec_eval_argument(&hostile).is_none());
    }

    #[test]
    fn exec_eval_unwraps_base64_zlib_payload() {
        let inner: &str = "print('recovered exec payload')\n";
        let compressed: Vec<u8> = crate::codec::zlib_compress(inner.as_bytes());
        let b64: String = base64::engine::general_purpose::STANDARD.encode(&compressed);
        let dropper: String =
            format!("import base64, zlib\nexec(zlib.decompress(base64.b64decode(b'{b64}')))\n");
        let Ok(result): Result<PeelResult> = peel(dropper.as_bytes()) else {
            panic!("peel must succeed on exec dropper");
        };
        assert!(result.recovered, "exec/eval payload must be recovered");
        assert!(
            result.final_source.contains("recovered exec payload"),
            "recovered source must contain the inner payload: {}",
            result.final_source
        );
        assert!(
            result
                .steps
                .iter()
                .any(|s: &PeelStep| s.decoder.starts_with("exec-eval/")),
            "an exec-eval peel step must be recorded"
        );
    }

    #[test]
    fn exec_eval_unwraps_plain_string_literal() {
        let src: &[u8] = b"eval('1 + 2 + 3')\n";
        let Ok(result): Result<PeelResult> = peel(src) else {
            panic!("peel must succeed");
        };
        assert!(result.recovered);
        assert!(result.final_source.contains("1 + 2 + 3"));
    }

    #[test]
    fn exec_eval_unwraps_base16_payload() {
        let inner: &str = "print('hex dropper payload')";
        let hex: String = crate::codec::bytes_to_hex(inner.as_bytes());
        let dropper: String = format!("import binascii\nexec(binascii.unhexlify(b'{hex}'))\n");
        let Ok(result): Result<PeelResult> = peel(dropper.as_bytes()) else {
            panic!("peel must succeed on hex dropper");
        };
        assert!(result.recovered);
        assert!(
            result.final_source.contains("hex dropper payload"),
            "recovered: {}",
            result.final_source
        );
    }

    #[test]
    fn exec_eval_unwraps_base85_partial_tail_payload() {
        let inner: &str = "print('b85 tail')\n";
        let dropper: String =
            "exec(__import__('base64').b85decode(b'aB^vGbSNicI5i-2VQFk9DGC'))\n".to_owned();
        let Ok(result): Result<PeelResult> = peel(dropper.as_bytes()) else {
            panic!("peel must succeed on base85 exec dropper");
        };
        assert!(result.recovered);
        assert_eq!(result.final_source, inner);
    }
}
