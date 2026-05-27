use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum JsObfuscator {
    ObfuscatorIo,
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

#[must_use]
pub fn detect(source: &[u8]) -> Detection {
    let text: &str = std::str::from_utf8(source).unwrap_or("");
    let head: &str = &text[..text.len().min(HEAD_BYTES)];
    let mut markers: Vec<String> = Vec::new();

    if head.contains(OBF_IO_MARKER) {
        markers.push("obfuscator-io-banner".to_owned());
        return Detection {
            family: JsObfuscator::ObfuscatorIo,
            confidence: 0.95,
            markers,
        };
    }
    if head.contains(JSCRAMBLER_MARKER) {
        markers.push("jscrambler-banner".to_owned());
        return Detection {
            family: JsObfuscator::Jscrambler,
            confidence: 0.95,
            markers,
        };
    }
    if head.contains("var _0x") && head.contains("function _0x") {
        markers.push("hex-prefix-identifiers".to_owned());
        return Detection {
            family: JsObfuscator::ObfuscatorIo,
            confidence: 0.85,
            markers,
        };
    }
    if head.contains("webpackChunk") || head.contains("__webpack_require__") {
        markers.push("webpack-runtime".to_owned());
        return Detection {
            family: JsObfuscator::Webpack,
            confidence: 0.95,
            markers,
        };
    }
    if head.contains("import.meta.glob") || head.contains("Vite") {
        markers.push("vite-runtime".to_owned());
        return Detection {
            family: JsObfuscator::Vite,
            confidence: 0.85,
            markers,
        };
    }
    if head.contains("define_property")
        && head.contains("__esModule")
        && head.contains("module.exports")
    {
        markers.push("rollup-output".to_owned());
        return Detection {
            family: JsObfuscator::Rollup,
            confidence: 0.7,
            markers,
        };
    }
    if !head.contains('\n') && head.len() > 200 {
        markers.push("single-line-large".to_owned());
        return Detection {
            family: JsObfuscator::Minified,
            confidence: 0.5,
            markers,
        };
    }
    Detection {
        family: JsObfuscator::Unknown,
        confidence: 0.0,
        markers,
    }
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
}
