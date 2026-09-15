use std::collections::BTreeSet;

use regex::Regex;
use serde::Serialize;

use super::controls::ObfControl;
use super::presets::Preset;

#[derive(Debug, Clone, Serialize)]
pub struct ObfuscatorIoDetection {
    pub matched: bool,
    pub confidence: f32,
    pub controls: BTreeSet<ObfControl>,
    pub likely_preset: Option<Preset>,
    pub markers: Vec<String>,
}

const HEAD_SCAN_BYTES: usize = 256 * 1024;

#[must_use]
pub fn detect(source: &str) -> ObfuscatorIoDetection {
    let head: &str = crate::scan_utils::head(source, HEAD_SCAN_BYTES);
    let mut controls: BTreeSet<ObfControl> = BTreeSet::new();
    let mut markers: Vec<String> = Vec::new();

    if has_obfuscator_io_banner(head) {
        markers.push("obfuscator-io-banner".to_owned());
    }
    if has_hex_string_array(head) {
        controls.insert(ObfControl::Statements);
        markers.push("hex-string-array".to_owned());
    }
    if has_rotator_iife(head) {
        controls.insert(ObfControl::Statements);
        markers.push("string-array-rotator".to_owned());
    }
    if has_base64_decoder(head) {
        controls.insert(ObfControl::Statements);
        markers.push("base64-decoder".to_owned());
    }
    if has_rc4_decoder(head) {
        controls.insert(ObfControl::Statements);
        markers.push("rc4-decoder".to_owned());
    }
    if has_hex_identifiers(head) {
        controls.insert(ObfControl::Identifiers);
        markers.push("hex-identifiers".to_owned());
    }
    if has_switch_dispatcher(head) {
        controls.insert(ObfControl::ControlFlowFlattening);
        markers.push("switch-dispatcher".to_owned());
    }
    if has_object_property_proxy(head) {
        controls.insert(ObfControl::Objects);
        markers.push("object-property-proxy".to_owned());
    }
    if has_split_string_concat(head) {
        controls.insert(ObfControl::Strings);
        markers.push("split-string-concat".to_owned());
    }
    if has_bool_shorthand(head) {
        controls.insert(ObfControl::Booleans);
        markers.push("bool-shorthand".to_owned());
    }
    if has_number_hex_literal(head) {
        controls.insert(ObfControl::Numbers);
        markers.push("hex-numbers".to_owned());
    }
    if has_self_defending_or_debug(head) {
        controls.insert(ObfControl::Minification);
        markers.push("self-defending-or-debug-protection".to_owned());
    }
    if has_opaque_predicate(head) {
        controls.insert(ObfControl::Predicates);
        markers.push("opaque-predicate".to_owned());
    }
    if has_console_disable(head) {
        controls.insert(ObfControl::RegularExpressions);
        markers.push("console-output-disabled".to_owned());
    }
    if has_renamed_properties(head) {
        controls.insert(ObfControl::Variables);
        markers.push("property-rename".to_owned());
    }
    if has_function_inlining(head) {
        controls.insert(ObfControl::FunctionInlining);
        markers.push("dead-code-injection".to_owned());
    }

    let banner_score: f32 = if markers.iter().any(|m: &String| m == "obfuscator-io-banner") {
        0.4
    } else {
        0.0
    };
    let controls_len_u16: u16 = u16::try_from(controls.len()).unwrap_or(u16::MAX);
    let total_len_u16: u16 = u16::try_from(ObfControl::ALL.len())
        .unwrap_or(u16::MAX)
        .max(1);
    let control_score: f32 = (f32::from(controls_len_u16) / f32::from(total_len_u16)) * 0.6;
    let confidence: f32 = (banner_score + control_score).min(0.97);
    let matched: bool = confidence >= 0.15;
    let likely_preset: Option<Preset> = if matched {
        Some(infer_preset(&controls))
    } else {
        None
    };
    ObfuscatorIoDetection {
        matched,
        confidence,
        controls,
        likely_preset,
        markers,
    }
}

fn infer_preset(controls: &BTreeSet<ObfControl>) -> Preset {
    let high: BTreeSet<ObfControl> = Preset::High.controls();
    let medium: BTreeSet<ObfControl> = Preset::Medium.controls();
    let high_overlap: usize = controls.intersection(&high).count();
    let medium_overlap: usize = controls.intersection(&medium).count();
    if controls.contains(&ObfControl::FunctionInlining)
        || controls.contains(&ObfControl::Predicates)
    {
        return Preset::High;
    }
    if high_overlap >= medium_overlap && high_overlap >= 8 {
        Preset::High
    } else if medium_overlap >= 6 {
        Preset::Medium
    } else {
        Preset::Low
    }
}

const QUOTE_CLASS: &str = r#"['"]"#;

fn has_obfuscator_io_banner(text: &str) -> bool {
    text.contains("obfuscator.io") || text.contains("javascript-obfuscator")
}

fn has_hex_string_array(text: &str) -> bool {
    let pattern: String =
        format!(r"(?ms)(?:var|let|const)\s+_0x[0-9a-fA-F]+\s*=\s*\[\s*{QUOTE_CLASS}");
    matches_regex(text, &pattern)
}

fn has_rotator_iife(text: &str) -> bool {
    matches_regex(
        text,
        r"(?s)\(\s*function\s*\([^)]*\)\s*\{.{0,600}?\bpush\b.{0,200}?\bshift\b.{0,600}?\}\s*\(\s*[A-Za-z_$][\w$]*\s*,",
    )
}

fn has_base64_decoder(text: &str) -> bool {
    text.contains("atob(") || text.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

fn has_rc4_decoder(text: &str) -> bool {
    matches_regex(
        text,
        r"(?ms)function\s*\w*\s*\([^)]*\)\s*\{[^{}]{0,400}charCodeAt[^{}]{0,400}fromCharCode",
    )
}

fn has_hex_identifiers(text: &str) -> bool {
    matches_regex(text, r"\b_0x[0-9a-fA-F]{3,}\b")
}

fn has_switch_dispatcher(text: &str) -> bool {
    let pattern: String = format!(
        r"(?ms){QUOTE_CLASS}[\d|]+{QUOTE_CLASS}\s*\.\s*split\s*\(\s*{QUOTE_CLASS}\|{QUOTE_CLASS}\s*\)"
    );
    matches_regex(text, &pattern)
}

fn has_object_property_proxy(text: &str) -> bool {
    let pattern: String = format!(
        r"(?ms)(?:var|let|const)\s+_0x[0-9a-fA-F]+\s*=\s*\{{[^{{}}]*{QUOTE_CLASS}\w+{QUOTE_CLASS}\s*:\s*function\s*\("
    );
    matches_regex(text, &pattern)
}

fn has_split_string_concat(text: &str) -> bool {
    let pattern: String = format!(
        r"(?ms){QUOTE_CLASS}[^'\x22\n]{{0,8}}{QUOTE_CLASS}\s*\+\s*{QUOTE_CLASS}[^'\x22\n]{{0,8}}{QUOTE_CLASS}"
    );
    matches_regex(text, &pattern)
}

fn has_bool_shorthand(text: &str) -> bool {
    text.contains("!![]") || text.contains("![]")
}

fn has_number_hex_literal(text: &str) -> bool {
    matches_regex(text, r"=\s*0x[0-9a-fA-F]{1,8}\b")
}

fn has_self_defending_or_debug(text: &str) -> bool {
    if text.contains("debugger") || text.contains("setInterval") {
        return true;
    }
    let pattern: String = format!(
        r"(?ms)Function\s*\(\s*{QUOTE_CLASS}debu{QUOTE_CLASS}\s*\+\s*{QUOTE_CLASS}gger{QUOTE_CLASS}\s*\)"
    );
    matches_regex(text, &pattern)
}

fn has_opaque_predicate(text: &str) -> bool {
    let pattern: String = format!(
        r"(?ms){QUOTE_CLASS}\w+{QUOTE_CLASS}\s*===?\s*{QUOTE_CLASS}\w+{QUOTE_CLASS}\s*\)\s*\{{[^{{}}]{{0,200}}\}}\s*else"
    );
    matches_regex(text, &pattern)
}

fn has_console_disable(text: &str) -> bool {
    let pattern: String =
        format!(r"console\s*\[\s*{QUOTE_CLASS}(?:log|warn|info|error|debug){QUOTE_CLASS}\s*\]\s*=");
    matches_regex(text, &pattern)
}

fn has_renamed_properties(text: &str) -> bool {
    matches_regex(text, r"\.\s*_0x[0-9a-fA-F]{3,}\b")
}

fn has_function_inlining(text: &str) -> bool {
    let pattern: String = format!(
        r"(?ms)if\s*\(\s*{QUOTE_CLASS}\w+{QUOTE_CLASS}\s*===?\s*{QUOTE_CLASS}\w+{QUOTE_CLASS}\s*\)\s*\{{[^{{}}]{{0,1000}}return\s+"
    );
    matches_regex(text, &pattern)
}

fn matches_regex(text: &str, pattern: &str) -> bool {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(pattern) else {
        return false;
    };
    re.is_match(text)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_banner_only() {
        let src: &str = "// obfuscator.io output\nconst x = 1;";
        let det: ObfuscatorIoDetection = detect(src);
        assert!(
            det.markers
                .iter()
                .any(|m: &String| m == "obfuscator-io-banner")
        );
    }

    #[test]
    fn detects_hex_string_array() {
        let src: &str = r"var _0xabc = ['hello', 'world']; var x = _0xabc[0];";
        let det: ObfuscatorIoDetection = detect(src);
        assert!(det.controls.contains(&ObfControl::Statements));
        assert!(det.controls.contains(&ObfControl::Identifiers));
    }

    #[test]
    fn detects_bool_shorthand() {
        let src: &str = "if (!![]) { var _0xfeed = 1; }";
        let det: ObfuscatorIoDetection = detect(src);
        assert!(det.controls.contains(&ObfControl::Booleans));
    }

    #[test]
    fn unknown_for_clean_js() {
        let src: &str = "function hello(name) { return 'hi ' + name; }";
        let det: ObfuscatorIoDetection = detect(src);
        assert!(!det.matched);
        assert!(!det.controls.contains(&ObfControl::Statements));
    }

    #[test]
    fn high_preset_inferred_when_function_inlining_present() {
        let src: &str = r"
            var _0xabc = ['a', 'b'];
            (function(_0x1, _0x2){ _0x1.push(_0x1.shift()); }(_0xabc, 0x1));
            var _0xdef = function(_0x3){ return _0xabc[_0x3]; };
            if ('aaa' === 'bbb') { return _0xdef(0); }
        ";
        let det: ObfuscatorIoDetection = detect(src);
        assert!(det.matched);
        assert!(
            det.likely_preset == Some(Preset::High)
                || det.controls.contains(&ObfControl::FunctionInlining)
        );
    }
}
