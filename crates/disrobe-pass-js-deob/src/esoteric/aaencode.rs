use serde::Serialize;

use super::sandbox::eval_to_string;

const AA_BANNER: &str = "ﾟωﾟﾉ";
const AA_BANNER_ALT: &str = "ﾟДﾟ";
const AA_INIT_TOKEN: &str = "(ﾟΘﾟ)";
const AA_INIT_TOKEN_ALT: &str = "(ﾟｰﾟ)";
const MIN_LEN: usize = 80;

#[derive(Debug, Clone, Default, Serialize)]
pub struct AaEncodeDetection {
    pub matched: bool,
    pub banner_hits: usize,
    pub kaomoji_density: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct AaEncodeDecode {
    pub detection: AaEncodeDetection,
    pub recovered: Option<String>,
}

#[must_use]
pub fn detect_aaencode(source: &str) -> AaEncodeDetection {
    let trimmed: &str = source.trim();
    if trimmed.len() < MIN_LEN {
        return AaEncodeDetection::default();
    }
    let mut hits: usize = 0;
    if trimmed.contains(AA_BANNER) {
        hits += 1;
    }
    if trimmed.contains(AA_BANNER_ALT) {
        hits += 1;
    }
    if trimmed.contains(AA_INIT_TOKEN) || trimmed.contains(AA_INIT_TOKEN_ALT) {
        hits += 1;
    }
    let mut kaomoji_chars: usize = 0;
    let mut total: usize = 0;
    for ch in trimmed.chars() {
        total += 1;
        if is_kaomoji_char(ch) {
            kaomoji_chars += 1;
        }
    }
    let density: f32 = if total == 0 {
        0.0
    } else {
        ratio(kaomoji_chars, total)
    };
    let matched: bool = hits >= 1 && density >= 0.05;
    AaEncodeDetection {
        matched,
        banner_hits: hits,
        kaomoji_density: density,
    }
}

#[must_use]
pub fn decode_aaencode(source: &str) -> AaEncodeDecode {
    let detection: AaEncodeDetection = detect_aaencode(source);
    if !detection.matched {
        return AaEncodeDecode {
            detection,
            recovered: None,
        };
    }
    let stripped: String = strip_trailing_invocation(source);
    let recovered: Option<String> = eval_to_string(&stripped);
    AaEncodeDecode {
        detection,
        recovered,
    }
}

fn strip_trailing_invocation(source: &str) -> String {
    let trimmed: &str = source.trim_end().trim_end_matches(';');
    let no_tail: &str = trimmed.strip_suffix("('_')").unwrap_or(trimmed);
    no_tail.to_owned()
}

#[allow(clippy::cast_precision_loss)]
fn ratio(num: usize, den: usize) -> f32 {
    (num as f32) / (den as f32)
}

const fn is_kaomoji_char(ch: char) -> bool {
    matches!(
        ch,
        'ﾟ' | 'ω' | 'ﾉ' | 'Θ' | 'ｰ' | 'Д' | 'Σ' | 'ε' | 'ノ' | '∇' | '°' | '・'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_normal_javascript() {
        let det: AaEncodeDetection = detect_aaencode("function foo(){return 42;}");
        assert!(!det.matched);
    }

    #[test]
    fn detects_typical_banner() {
        let mut src: String = String::new();
        src.push_str("ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇`*/ ['_'];");
        src.push_str("o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ)=(ﾟｰﾟ)-(ﾟｰﾟ);");
        for _ in 0..20 {
            src.push_str("(ﾟΘﾟ)");
        }
        let det: AaEncodeDetection = detect_aaencode(&src);
        assert!(det.matched, "should detect aaencode shape: {det:?}");
    }
}
