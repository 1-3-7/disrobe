use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(b64_pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(b64_pattern()) else {
        return TransformOutput::noop(source);
    };
    let mut stats: TransformStats = TransformStats::default();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for cap in re.captures_iter(source) {
        stats.matched += 1;
        let Some(whole) = cap.get(0) else { continue };
        let Some(payload) = cap.get(1) else { continue };
        let Ok(decoded_bytes): Result<Vec<u8>, _> = base64_decode_padded(payload.as_str()) else {
            stats.skipped += 1;
            continue;
        };
        let Ok(decoded): Result<String, _> = String::from_utf8(decoded_bytes) else {
            stats.skipped += 1;
            continue;
        };
        let literal: String = crate::jscrambler::scanner::js_quote(&decoded, '"');
        edits.push((whole.range(), Some(literal)));
    }
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let (out, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    stats.reversed = applied;
    TransformOutput { source: out, stats }
}

const fn b64_pattern() -> &'static str {
    r"atob\(\s*['\x22]([A-Za-z0-9+/=]+)['\x22]\s*\)"
}

fn base64_decode_padded(s: &str) -> core::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_atob_call() {
        let src: &str = "var x = atob('aGVsbG8=');";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn reverses_atob_to_literal() {
        let src: &str = "var x = atob('aGVsbG8=');";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("\"hello\""));
    }

    #[test]
    fn skips_invalid_base64() {
        let src: &str = "var x = atob('!!');";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("atob"));
    }
}
