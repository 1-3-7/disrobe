use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct JsObfuDetection {
    pub matched: bool,
    pub confidence: f32,
    pub bracket_string_access_count: usize,
    pub array_join_count: usize,
    pub eval_call_count: usize,
    pub markers: Vec<String>,
}

const HEAD_SCAN_BYTES: usize = 64 * 1024;
const BRACKET_STRING_DENSITY_FLOOR: usize = 3;

#[must_use]
pub fn detect_jsobfu(source: &str) -> JsObfuDetection {
    let head: &str = &source[..source.len().min(HEAD_SCAN_BYTES)];
    let bracket_string_access_count: usize = count_bracket_string_access(head);
    let bracket_computed_access_count: usize = count_bracket_computed_access(head);
    let string_from_charcode_count: usize = count_string_from_charcode(head);
    let array_join_count: usize = count_array_join_pattern(head);
    let eval_call_count: usize = count_eval_calls(head);
    let iife_return_string_count: usize = count_iife_return_string(head);

    let total_bracket_density: usize = bracket_string_access_count + bracket_computed_access_count;

    let mut markers: Vec<String> = Vec::new();
    if bracket_string_access_count >= BRACKET_STRING_DENSITY_FLOOR {
        markers.push(format!(
            "bracket-string-access-density:{bracket_string_access_count}"
        ));
    }
    if bracket_computed_access_count >= BRACKET_STRING_DENSITY_FLOOR {
        markers.push(format!(
            "bracket-computed-access-density:{bracket_computed_access_count}"
        ));
    }
    if string_from_charcode_count > 0 {
        markers.push(format!("String.fromCharCode:{string_from_charcode_count}"));
    }
    if array_join_count > 0 {
        markers.push(format!("array-string-split-join:{array_join_count}"));
    }
    if eval_call_count > 0 {
        markers.push(format!("eval-call:{eval_call_count}"));
    }
    if iife_return_string_count > 0 {
        markers.push(format!("iife-return-string:{iife_return_string_count}"));
    }

    let dense_brackets: bool = total_bracket_density >= BRACKET_STRING_DENSITY_FLOOR;
    let has_eval_or_join: bool = eval_call_count > 0 || array_join_count > 0;
    let has_charcode_signal: bool = string_from_charcode_count >= 3;
    let has_iife_string_signal: bool = iife_return_string_count >= 5;
    let matched: bool =
        (dense_brackets && has_eval_or_join) || (has_charcode_signal && has_iife_string_signal);
    let bracket_term: f32 =
        f32::from(u16::try_from(total_bracket_density.min(50)).unwrap_or(0)) * 0.02;
    let confidence: f32 = if matched {
        let bonus: f32 = if (array_join_count > 0 && eval_call_count > 0) || has_charcode_signal {
            0.15
        } else {
            0.0
        };
        (bracket_term.mul_add(1.0, 0.55) + bonus).min(0.95)
    } else if dense_brackets {
        0.35
    } else {
        0.0
    };

    JsObfuDetection {
        matched,
        confidence,
        bracket_string_access_count,
        array_join_count,
        eval_call_count,
        markers,
    }
}

fn count_bracket_string_access(text: &str) -> usize {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"\[(?:'[A-Za-z_$][A-Za-z0-9_$]*'|"[A-Za-z_$][A-Za-z0-9_$]*")\]"#)
    else {
        return 0;
    };
    re.find_iter(text).count()
}

fn count_array_join_pattern(text: &str) -> usize {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"\[\s*(?:'[^'\\]'|"[^"\\]")(?:\s*,\s*(?:'[^'\\]'|"[^"\\]")){2,}\s*\]\s*\[\s*(?:'join'|"join")\s*\]\s*\(\s*(?:''|"")\s*\)"#,
    ) else {
        return 0;
    };
    re.find_iter(text).count()
}

fn count_eval_calls(text: &str) -> usize {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"\beval\s*\(") else {
        return 0;
    };
    re.find_iter(text).count()
}

fn count_bracket_computed_access(text: &str) -> usize {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"\[\s*(?:String\.fromCharCode|\(\s*function|\(\s*\(\s*\)\s*=>)")
    else {
        return 0;
    };
    re.find_iter(text).count()
}

fn count_string_from_charcode(text: &str) -> usize {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"String\.fromCharCode\s*\(") else {
        return 0;
    };
    re.find_iter(text).count()
}

fn count_iife_return_string(text: &str) -> usize {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"function\s*\(\s*\)\s*\{\s*var\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*["'][^"']*["'][^}]{0,200}return\s+"#,
    ) else {
        return 0;
    };
    re.find_iter(text).count()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_dense_bracket_access_with_eval() {
        let src: &str =
            "var a = obj['toString'](); var b = obj['valueOf'](); var c = obj['x']; eval('1');";
        let det: JsObfuDetection = detect_jsobfu(src);
        assert!(det.matched, "expected jsobfu match");
        assert!(det.bracket_string_access_count >= 3);
        assert!(det.eval_call_count >= 1);
    }

    #[test]
    fn detects_array_join_split_shape() {
        let src: &str = "var s = ['h','e','l','l','o']['join']('');";
        let det: JsObfuDetection = detect_jsobfu(src);
        assert!(det.array_join_count >= 1);
    }

    #[test]
    fn does_not_match_clean_code() {
        let src: &str = "const x: number = 1; function add(a: number, b: number) { return a + b; }";
        let det: JsObfuDetection = detect_jsobfu(src);
        assert!(!det.matched);
        assert!(det.confidence < f32::EPSILON);
    }

    #[test]
    fn does_not_match_dense_brackets_without_eval_or_join() {
        let src: &str = "obj['a']; obj['b']; obj['c']; obj['d'];";
        let det: JsObfuDetection = detect_jsobfu(src);
        assert!(!det.matched);
    }
}
