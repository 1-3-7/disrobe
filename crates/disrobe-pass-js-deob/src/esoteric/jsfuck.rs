use serde::Serialize;

use super::sandbox::eval_to_string;

const JSFUCK_CHARS: [u8; 6] = *b"[]()!+";
const MIN_DETECTION_LEN: usize = 12;
const MIN_PURE_RATIO_NUM: usize = 95;
const MIN_PURE_RATIO_DEN: usize = 100;

#[derive(Debug, Clone, Default, Serialize)]
pub struct JsFuckDetection {
    pub matched: bool,
    pub total_chars: usize,
    pub jsfuck_chars: usize,
    pub purity_ratio: f32,
    pub symbolic_atoms_recognized: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsFuckDecode {
    pub detection: JsFuckDetection,
    pub recovered: Option<String>,
    pub symbolic_only: bool,
}

#[must_use]
pub fn detect_jsfuck(source: &str) -> JsFuckDetection {
    let trimmed: &str = source.trim();
    let total: usize = trimmed.chars().count();
    if total < MIN_DETECTION_LEN {
        return JsFuckDetection::default();
    }
    let bytes: &[u8] = trimmed.as_bytes();
    let mut hits: usize = 0;
    let mut whitespace: usize = 0;
    for &b in bytes {
        if JSFUCK_CHARS.contains(&b) {
            hits += 1;
        } else if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
            whitespace += 1;
        }
    }
    let counted: usize = bytes.len().saturating_sub(whitespace);
    if counted == 0 {
        return JsFuckDetection::default();
    }
    let purity: f32 = ratio(hits, counted);
    let matched: bool =
        hits * MIN_PURE_RATIO_DEN >= counted * MIN_PURE_RATIO_NUM && hits >= MIN_DETECTION_LEN;
    let atoms: usize = if matched {
        count_recognized_atoms(trimmed)
    } else {
        0
    };
    JsFuckDetection {
        matched,
        total_chars: total,
        jsfuck_chars: hits,
        purity_ratio: purity,
        symbolic_atoms_recognized: atoms,
    }
}

#[must_use]
pub fn decode_jsfuck(source: &str) -> JsFuckDecode {
    let detection: JsFuckDetection = detect_jsfuck(source);
    if !detection.matched {
        return JsFuckDecode {
            detection,
            recovered: None,
            symbolic_only: false,
        };
    }
    if detection.symbolic_atoms_recognized == 0 {
        return JsFuckDecode {
            detection,
            recovered: None,
            symbolic_only: false,
        };
    }
    let recovered: Option<String> = eval_to_string(source);
    let symbolic_only: bool = recovered.is_none();
    JsFuckDecode {
        detection,
        recovered,
        symbolic_only,
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(num: usize, den: usize) -> f32 {
    (num as f32) / (den as f32)
}

fn count_recognized_atoms(source: &str) -> usize {
    const ATOMS: [&str; 8] = [
        "![]",
        "!+[]",
        "+!+[]",
        "+[]",
        "[][[]]",
        "(+!+[])",
        "[][\"filter\"]",
        "[]+{}",
    ];
    let mut total: usize = 0;
    for atom in ATOMS {
        total += source.matches(atom).count();
    }
    total
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    const FALSE_LITERAL: &str = "![]";
    const TRUE_LITERAL: &str = "!+[]";
    const ONE_LITERAL: &str = "+!+[]";
    const ZERO_LITERAL: &str = "+[]";

    #[test]
    fn detects_pure_jsfuck() {
        let src: &str = "[][(![]+[])[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]]";
        let det: JsFuckDetection = detect_jsfuck(src);
        assert!(det.matched, "should detect pure JSFuck: {det:?}");
        assert!(det.purity_ratio >= 0.95);
        assert!(det.symbolic_atoms_recognized >= 1);
    }

    #[test]
    fn ignores_normal_javascript() {
        let src: &str = "function add(a, b) { return a + b; }";
        let det: JsFuckDetection = detect_jsfuck(src);
        assert!(!det.matched);
    }

    #[test]
    fn evaluates_canonical_false_atom() {
        let res: Option<String> = eval_to_string(FALSE_LITERAL);
        assert_eq!(res.as_deref(), Some("false"));
    }

    #[test]
    fn evaluates_canonical_true_atom() {
        let res: Option<String> = eval_to_string(TRUE_LITERAL);
        assert_eq!(res.as_deref(), Some("true"));
    }

    #[test]
    fn evaluates_canonical_one_atom() {
        let res: Option<String> = eval_to_string(ONE_LITERAL);
        assert_eq!(res.as_deref(), Some("1"));
    }

    #[test]
    fn evaluates_canonical_zero_atom() {
        let res: Option<String> = eval_to_string(ZERO_LITERAL);
        assert_eq!(res.as_deref(), Some("0"));
    }
}
