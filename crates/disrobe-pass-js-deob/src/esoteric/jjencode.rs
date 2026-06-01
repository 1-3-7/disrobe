use serde::Serialize;

use super::sandbox::eval_to_string;

const JJ_SIG_PRIMARY: &str = "=~[]";
const JJ_SIG_INIT: &str = "{___:++";
const JJ_SIG_ALT_INIT: &str = "{ ___:++";
const MIN_LEN: usize = 80;

#[derive(Debug, Clone, Default, Serialize)]
pub struct JjEncodeDetection {
    pub matched: bool,
    pub global_var: Option<String>,
    pub charset_size: usize,
    pub signature_hits: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct JjEncodeDecode {
    pub detection: JjEncodeDetection,
    pub recovered: Option<String>,
}

#[must_use]
pub fn detect_jjencode(source: &str) -> JjEncodeDetection {
    let trimmed: &str = source.trim();
    if trimmed.len() < MIN_LEN {
        return JjEncodeDetection::default();
    }
    let mut hits: usize = 0;
    if trimmed.contains(JJ_SIG_PRIMARY) {
        hits += 1;
    }
    if trimmed.contains(JJ_SIG_INIT) || trimmed.contains(JJ_SIG_ALT_INIT) {
        hits += 1;
    }
    if trimmed.contains("$.___") || trimmed.contains("[$.___]") {
        hits += 1;
    }
    let matched: bool = hits >= 2;
    let global: Option<String> = if matched {
        extract_global(trimmed)
    } else {
        None
    };
    let charset: usize = if matched { count_charset(trimmed) } else { 0 };
    JjEncodeDetection {
        matched,
        global_var: global,
        charset_size: charset,
        signature_hits: hits,
    }
}

#[must_use]
pub fn decode_jjencode(source: &str) -> JjEncodeDecode {
    let detection: JjEncodeDetection = detect_jjencode(source);
    if !detection.matched {
        return JjEncodeDecode {
            detection,
            recovered: None,
        };
    }
    let intercepted: String = wrap_with_eval_capture(source);
    let recovered: Option<String> = eval_to_string(&intercepted);
    JjEncodeDecode {
        detection,
        recovered,
    }
}

fn wrap_with_eval_capture(source: &str) -> String {
    let mut wrapped: String = String::with_capacity(source.len() + 512);
    wrapped.push_str("(function(){");
    wrapped.push_str("var __DR_CAPTURE__ = '';");
    wrapped
        .push_str("var Function = function(s){__DR_CAPTURE__ = String(s); return function(){};};");
    wrapped.push_str("var eval = function(s){__DR_CAPTURE__ = String(s); return undefined;};");
    wrapped.push_str("try{");
    wrapped.push_str(source);
    wrapped.push_str("}catch(e){}");
    wrapped.push_str("return __DR_CAPTURE__;");
    wrapped.push_str("})()");
    wrapped
}

fn extract_global(source: &str) -> Option<String> {
    let idx: usize = source.find(JJ_SIG_PRIMARY)?;
    let head: &str = source[..idx].trim_end();
    let identifier_end: usize = head.len();
    let bytes: &[u8] = head.as_bytes();
    let mut start: usize = identifier_end;
    while start > 0 {
        let prev: u8 = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'$' {
            start -= 1;
        } else {
            break;
        }
    }
    let name: &str = &head[start..identifier_end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn count_charset(source: &str) -> usize {
    let mut seen: std::collections::BTreeSet<char> = std::collections::BTreeSet::new();
    for ch in source.chars() {
        if matches!(
            ch,
            '$' | '_'
                | '+'
                | '!'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '='
                | ','
                | ';'
                | '~'
                | '.'
                | '"'
                | '\\'
                | '/'
                | ':'
        ) {
            seen.insert(ch);
        }
    }
    seen.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_normal_javascript() {
        let det: JjEncodeDetection = detect_jjencode("function foo(){return 42;}");
        assert!(!det.matched);
    }

    #[test]
    fn detects_signature_shape() {
        let src: &str = "$=~[];$={___:++$,$$$$:(![]+\"\")[$],__$:++$,$_$_:(![]+\"\")[$],_$_:++$,$_$$:({}+\"\")[$]};$.___;$.___;";
        let det: JjEncodeDetection = detect_jjencode(src);
        assert!(det.matched, "should detect jjencode signature");
        assert_eq!(det.global_var.as_deref(), Some("$"));
        assert!(det.charset_size >= 8);
    }
}
