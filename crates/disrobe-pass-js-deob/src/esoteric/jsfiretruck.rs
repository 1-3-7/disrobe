use serde::Serialize;

use super::sandbox::eval_to_string;

const FIRETRUCK_CHARS: [u8; 8] = *b"[]()!+./";
const MIN_LEN_FOR_VARIANT: usize = 256;
const MIN_PURE_RATIO_NUM: usize = 90;
const MIN_PURE_RATIO_DEN: usize = 100;

#[derive(Debug, Clone, Default, Serialize)]
pub struct JsFireTruckDetection {
    pub matched: bool,
    pub total_chars: usize,
    pub firetruck_chars: usize,
    pub purity_ratio: f32,
    pub dot_slash_density: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsFireTruckDecode {
    pub detection: JsFireTruckDetection,
    pub recovered: Option<String>,
}

#[must_use]
pub fn detect_jsfiretruck(source: &str) -> JsFireTruckDetection {
    let trimmed: &str = source.trim();
    let total: usize = trimmed.chars().count();
    if total < MIN_LEN_FOR_VARIANT {
        return JsFireTruckDetection::default();
    }
    let bytes: &[u8] = trimmed.as_bytes();
    let mut hits: usize = 0;
    let mut dot_slash: usize = 0;
    let mut whitespace: usize = 0;
    for &b in bytes {
        if FIRETRUCK_CHARS.contains(&b) {
            hits += 1;
            if b == b'.' || b == b'/' {
                dot_slash += 1;
            }
        } else if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
            whitespace += 1;
        }
    }
    let counted: usize = bytes.len().saturating_sub(whitespace);
    if counted == 0 {
        return JsFireTruckDetection::default();
    }
    let purity: f32 = ratio(hits, counted);
    let dot_slash_density: f32 = ratio(dot_slash, counted);
    let matched: bool = hits * MIN_PURE_RATIO_DEN >= counted * MIN_PURE_RATIO_NUM
        && dot_slash_density > 0.005
        && hits >= MIN_LEN_FOR_VARIANT;
    JsFireTruckDetection {
        matched,
        total_chars: total,
        firetruck_chars: hits,
        purity_ratio: purity,
        dot_slash_density,
    }
}

#[must_use]
pub fn decode_jsfiretruck(source: &str) -> JsFireTruckDecode {
    let detection: JsFireTruckDetection = detect_jsfiretruck(source);
    if !detection.matched {
        return JsFireTruckDecode {
            detection,
            recovered: None,
        };
    }
    let recovered: Option<String> = eval_to_string(source);
    JsFireTruckDecode {
        detection,
        recovered,
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(num: usize, den: usize) -> f32 {
    (num as f32) / (den as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_normal_javascript() {
        let det: JsFireTruckDetection =
            detect_jsfiretruck("function foo(){return 42 + 'a'.length;}");
        assert!(!det.matched);
    }

    #[test]
    fn detects_synthetic_firetruck_payload() {
        let mut payload: String = String::with_capacity(4096);
        for _ in 0..512 {
            payload.push_str("([]+[])./.+!+[].(./.)+");
        }
        payload.push_str("[]");
        let det: JsFireTruckDetection = detect_jsfiretruck(&payload);
        assert!(det.matched, "should detect firetruck shape: {det:?}");
        assert!(det.dot_slash_density > 0.005);
    }

    #[test]
    fn rejects_pure_jsfuck_short_form() {
        let src: &str = "[][(![]+[])[+[]]]+([][[]]+[])[+!+[]]";
        let det: JsFireTruckDetection = detect_jsfiretruck(src);
        assert!(!det.matched);
    }
}
