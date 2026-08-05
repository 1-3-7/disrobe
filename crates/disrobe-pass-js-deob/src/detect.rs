use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

static STATE_SUM_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?ms)(?:while|switch)\s*\(\s*[A-Za-z_$][\w$]*(?:\s*\+\s*[A-Za-z_$][\w$]*){1,}\s*(?:!==|===|\))",
    )
    .ok()
});

static DEAD_GUARD_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)if\s*\(\s*["'][^"'\n]{2,}["']\s*in\s+[A-Za-z_$][\w$]*\s*\)\s*\{\s*[A-Za-z_$][\w$]*\s*\(\s*\)\s*\}"#,
    )
    .ok()
});

static INTEGRITY_TRAP_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"else\s*\{\s*(?:while\s*\(\s*(?:true|!0|!!\[\])\s*\)|for\s*\(\s*;\s*;\s*\))\s*\{\s*\}\s*\}",
    )
    .ok()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum JsObfuscator {
    ObfuscatorIo,
    JsConfuser,
    Jscrambler,
    JsObfu,
    Webpack,
    Vite,
    Rollup,
    Esbuild,
    Turbopack,
    Bun,
    Minified,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub family: JsObfuscator,
    pub confidence: f32,
    pub markers: Vec<String>,
}

const OBF_IO_MARKER: &str = "obfuscator.io";
const JSCRAMBLER_MARKER: &str = "jscrambler";
const HEAD_BYTES: usize = 4096;
const JSCONFUSER_SCAN_BYTES: usize = 262_144;

#[must_use]
pub fn detect(source: &[u8]) -> Detection {
    let text: &str = std::str::from_utf8(source).unwrap_or("");
    let head: &str = crate::scan_utils::head(text, HEAD_BYTES);
    let mut markers: Vec<String> = Vec::new();

    crate::debug::dbg_section("js-deob detect");
    if crate::debug::dbg_enabled() {
        crate::debug::dbg_kv("input-bytes", || source.len().to_string());
        crate::debug::dbg_kv("utf8", || {
            (!text.is_empty() || source.is_empty()).to_string()
        });
        crate::debug::dbg_kv("head-window", || head.len().to_string());
        crate::debug::dbg_hex("head-prefix", head.as_bytes(), 32);
    }

    if head.contains(OBF_IO_MARKER) {
        markers.push("obfuscator-io-banner".to_owned());
        return classified(
            JsObfuscator::ObfuscatorIo,
            0.95,
            markers,
            "obfuscator-io-banner",
        );
    }
    if head.contains(JSCRAMBLER_MARKER) {
        markers.push("jscrambler-banner".to_owned());
        return classified(JsObfuscator::Jscrambler, 0.95, markers, "jscrambler-banner");
    }
    if let Some(detection) = detect_jsconfuser(text) {
        crate::debug::dbg_kv("family", || format!("{:?}", detection.family));
        crate::debug::dbg_kv("confidence", || format!("{:.2}", detection.confidence));
        crate::debug::dbg_kv("markers", || detection.markers.join(","));
        return detection;
    }
    let state_machines: usize = crate::jscrambler::detect::state_machine_dispatcher_count(head);
    if state_machines >= crate::jscrambler::detect::STATE_MACHINE_DENSITY_FLOOR {
        markers.push(format!(
            "jscrambler-state-machine-dispatcher:{state_machines}"
        ));
        return classified(
            JsObfuscator::Jscrambler,
            0.85,
            markers,
            "jscrambler-state-machine-dispatcher",
        );
    }
    if head.contains("var _0x") && head.contains("function _0x") {
        markers.push("hex-prefix-identifiers".to_owned());
        return classified(
            JsObfuscator::ObfuscatorIo,
            0.85,
            markers,
            "hex-prefix-identifiers",
        );
    }
    if is_modern_obfuscator_io(head) {
        markers.push("modern-string-array-provider".to_owned());
        return classified(
            JsObfuscator::ObfuscatorIo,
            0.85,
            markers,
            "modern-string-array-provider",
        );
    }
    if let Some(detection) = detect_jsobfu_family(text) {
        crate::debug::dbg_kv("family", || format!("{:?}", detection.family));
        crate::debug::dbg_kv("confidence", || format!("{:.2}", detection.confidence));
        crate::debug::dbg_kv("markers", || detection.markers.join(","));
        return detection;
    }
    if head.contains("webpackChunk") || head.contains("__webpack_require__") {
        markers.push("webpack-runtime".to_owned());
        return classified(JsObfuscator::Webpack, 0.95, markers, "webpack-runtime");
    }
    if head.contains("import.meta.glob") || head.contains("Vite") {
        markers.push("vite-runtime".to_owned());
        return classified(JsObfuscator::Vite, 0.85, markers, "vite-runtime");
    }
    if head.contains("define_property")
        && head.contains("__esModule")
        && head.contains("module.exports")
    {
        markers.push("rollup-output".to_owned());
        return classified(JsObfuscator::Rollup, 0.7, markers, "rollup-output");
    }
    if !head.contains('\n') && head.len() > 200 {
        markers.push("single-line-large".to_owned());
        return classified(JsObfuscator::Minified, 0.5, markers, "single-line-large");
    }
    crate::debug::dbg_kv("family", || format!("{:?}", JsObfuscator::Unknown));
    crate::debug::dbg_line(|| "no obfuscator/bundler family recognized".to_owned());
    Detection {
        family: JsObfuscator::Unknown,
        confidence: 0.0,
        markers,
    }
}

fn classified(
    family: JsObfuscator,
    confidence: f32,
    markers: Vec<String>,
    reason: &str,
) -> Detection {
    crate::debug::dbg_kv("family", || format!("{family:?}"));
    crate::debug::dbg_kv("confidence", || format!("{confidence:.2}"));
    crate::debug::dbg_kv("reason", || reason.to_owned());
    Detection {
        family,
        confidence,
        markers,
    }
}

fn detect_jsconfuser(text: &str) -> Option<Detection> {
    let scan: &str = crate::scan_utils::head(text, JSCONFUSER_SCAN_BYTES);
    let mut markers: Vec<String> = Vec::new();
    let mut score: u32 = 0;

    let has_rgf_eval: bool = scan.contains("_rgf_eval") || scan.contains("_rgf=[");
    if has_rgf_eval {
        markers.push("rgf-eval-payload".to_owned());
        score += 2;
    }
    let has_state_sum: bool = STATE_SUM_RE
        .as_ref()
        .is_some_and(|re: &Regex| re.is_match(scan));
    if has_state_sum {
        markers.push("state-sum-control-flow".to_owned());
        score += 2;
    }
    let has_base91: bool = scan.contains("indexOf")
        && (scan.contains("* 91") || scan.contains("*91"))
        && (scan.contains("bufferToString")
            || scan.contains("(v&8191)")
            || scan.contains("(v & 8191)"));
    if has_base91 {
        markers.push("base91-string-concealing".to_owned());
        score += 2;
    }
    let has_lzstring_compression: bool = scan.contains("decompressFromBase64")
        && scan.contains("_decompress")
        && scan.contains("_compress");
    if has_lzstring_compression {
        markers.push("lzstring-string-compression".to_owned());
        score += 2;
    }
    let has_get_global: bool = scan.contains("getGlobal")
        || scan.contains("return globalThis") && scan.contains("return window");
    if has_get_global {
        markers.push("jsconfuser-global-shim".to_owned());
        score += 1;
    }
    let dead_guard_count: usize = DEAD_GUARD_RE
        .as_ref()
        .map_or(0, |re: &Regex| re.find_iter(scan).count());
    if dead_guard_count >= 2 {
        markers.push(format!("deadcode-dummy-guards:{dead_guard_count}"));
        score += 2;
    } else if dead_guard_count == 1 {
        markers.push("deadcode-dummy-guard".to_owned());
        score += 1;
    }
    let has_integrity_trap: bool = INTEGRITY_TRAP_RE
        .as_ref()
        .is_some_and(|re: &Regex| re.is_match(scan));
    if has_integrity_trap {
        markers.push("integrity-tamper-trap".to_owned());
        score += 2;
    }

    if score >= 2 {
        let confidence: f32 = if score >= 4 { 0.95 } else { 0.85 };
        return Some(Detection {
            family: JsObfuscator::JsConfuser,
            confidence,
            markers,
        });
    }
    None
}

const JSOBFU_SCAN_BYTES: usize = 262_144;
const JSOBFU_FROM_CHAR_CODE_FLOOR: usize = 8;

fn detect_jsobfu_family(text: &str) -> Option<Detection> {
    let scan: &str = crate::scan_utils::head(text, JSOBFU_SCAN_BYTES);
    let from_char_code: usize = scan.matches("String.fromCharCode").count();
    if from_char_code < JSOBFU_FROM_CHAR_CODE_FLOOR {
        return None;
    }
    let det: crate::jsobfu::JsObfuDetection = crate::jsobfu::detect_jsobfu(text);
    if !det.matched {
        return None;
    }
    let iife_string_fragment: bool = scan.contains("return ") && scan.contains(".length");
    if !iife_string_fragment {
        return None;
    }
    let mut markers: Vec<String> = Vec::new();
    markers.push(format!("string-fromcharcode-density:{from_char_code}"));
    markers.extend(det.markers);
    Some(Detection {
        family: JsObfuscator::JsObfu,
        confidence: det.confidence.max(0.6),
        markers,
    })
}

fn is_modern_obfuscator_io(head: &str) -> bool {
    let has_hex_idents: bool = head.contains("_0x") || head.contains("a0_0x");
    let has_self_reassigning_provider: bool =
        head.contains("=function(){return ") && head.contains("];");
    let has_rotation_iife: bool = (head.contains("while(!![])") || head.contains("while (!![])"))
        && head.contains("push")
        && head.contains("shift")
        && head.contains("parseInt");
    has_hex_idents && (has_self_reassigning_provider || has_rotation_iife)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_obfuscator_io_by_banner() {
        let src: &[u8] = b"// obfuscator.io output\nvar _0xabcd = function(){};";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::ObfuscatorIo);
    }

    #[test]
    fn detects_webpack_chunk() {
        let src: &[u8] = b"webpackChunkmyapp.push([[123],{}])";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::Webpack);
    }

    #[test]
    fn detects_hex_prefix() {
        let src: &[u8] = b"var _0x1234 = 'a'; function _0xabcd() { return _0x1234; }";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::ObfuscatorIo);
    }

    #[test]
    fn unknown_for_clean_js() {
        let src: &[u8] = b"const x = 1;\nfunction foo() { return x + 1; }";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::Unknown);
    }

    #[test]
    fn detects_modern_string_array_provider() {
        let src: &[u8] = b"function a0_0x2484(){const _0x2afdf6=['log','add'];a0_0x2484=function(){return _0x2afdf6;};return a0_0x2484();}";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::ObfuscatorIo);
    }

    #[test]
    fn detects_modern_rotation_iife() {
        let src: &[u8] = b"(function(_0xa,_0xb){const _0xc=_0xa();while(!![]){try{if(parseInt(_0xd(0x1))===_0xb)break;else _0xc['push'](_0xc['shift']());}catch(_0xe){_0xc['push'](_0xc['shift']());}}}(a0_0x2484,0x1));";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::ObfuscatorIo);
    }

    #[test]
    fn clean_js_with_return_function_not_misdetected() {
        let src: &[u8] = b"const make = () => { return function () { return 42; }; };\nmake();";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::Unknown);
    }

    #[test]
    fn detects_jsconfuser_rgf_eval() {
        let src: &[u8] = b"var z_rgf=[z_rgf_eval(\"function f(){}\")];\nfunction add(){return z_rgf[0].apply(this,[z_rgf,arguments]);}";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::JsConfuser);
        assert!(det.markers.iter().any(|m: &String| m == "rgf-eval-payload"));
    }

    #[test]
    fn detects_jsconfuser_state_sum_cff() {
        let src: &[u8] = b"function f(n){var a=n;var s0=1,s1=2,s2=3;while(s0+s1+s2!==9){switch(s0+s1+s2){case 6:a=a+1;s0+=2,s1+=1;break;}}return a;}";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::JsConfuser);
        assert!(
            det.markers
                .iter()
                .any(|m: &String| m == "state-sum-control-flow")
        );
    }

    #[test]
    fn detects_jsconfuser_base91_with_global_shim() {
        let src: &[u8] = b"function d(s){var table=\"abc\";var p=table.indexOf(s[0]);var v=p*91;n+=(v&8191)>88?13:14;return bufferToString(ret);}function getGlobal(){return globalThis;}";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::JsConfuser);
        assert!(
            det.markers
                .iter()
                .any(|m: &String| m == "base91-string-concealing")
        );
    }

    #[test]
    fn detects_jsconfuser_lzstring_compression() {
        let src: &[u8] = b"var P=function(){var N={compressToBase64:function(a){return N._compress(a,6,function(x){return e.charAt(x)})},decompressFromBase64:function(a){return N._decompress(a.length,32,function(i){return d.charAt(i)})},_compress:function(){},_decompress:function(){}};return N}();var s=P.decompressFromBase64(\"BYUwNmD2Q===\");";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::JsConfuser);
        assert!(
            det.markers
                .iter()
                .any(|m: &String| m == "lzstring-string-compression")
        );
    }

    #[test]
    fn detects_jsconfuser_deadcode_dummy_guards() {
        let src: &[u8] = b"if(\"dgOw3X\"in dummy){dead4()}function dead4(){console.log(1)}if(\"KpZfAU\"in dummy){dead3()}function dead3(){console.log(2)}function dummy(){}function real(n){return n+1}console.log(real(3));";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::JsConfuser);
        assert!(
            det.markers
                .iter()
                .any(|m: &String| m.starts_with("deadcode-dummy-guards"))
        );
    }

    #[test]
    fn detects_jsconfuser_integrity_tamper_trap() {
        let src: &[u8] = b"function add(){var h=add.g||(add.g=hash(inner,6385901));if(h===2044549640226477){return inner.apply(this,arguments)}else{while(true){}}}function inner(a,b){return a+b}console.log(add(1,2));";
        let det: Detection = detect(src);
        assert_eq!(det.family, JsObfuscator::JsConfuser);
        assert!(
            det.markers
                .iter()
                .any(|m: &String| m == "integrity-tamper-trap")
        );
    }

    #[test]
    fn single_in_property_guard_not_misdetected_as_jsconfuser() {
        let src: &[u8] =
            b"if(\"foo\"in window){init()}function init(){console.log(1)}console.log(2);";
        let det: Detection = detect(src);
        assert_ne!(det.family, JsObfuscator::JsConfuser);
    }

    #[test]
    fn clean_arithmetic_sum_not_misdetected_as_jsconfuser() {
        let src: &[u8] =
            b"function total(a, b, c) { return a + b + c; }\nconsole.log(total(1, 2, 3));";
        let det: Detection = detect(src);
        assert_ne!(det.family, JsObfuscator::JsConfuser);
    }

    #[test]
    fn multibyte_input_straddling_the_head_window_does_not_panic() {
        let payload: String =
            "\u{65e5}\u{672c}\u{8a9e}\u{30b3}\u{30e1}\u{30f3}\u{30c8} ".repeat(2000);
        let det: Detection = detect(payload.as_bytes());
        assert_ne!(det.family, JsObfuscator::JsConfuser);
    }
}
