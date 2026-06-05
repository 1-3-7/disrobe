use std::collections::BTreeSet;

use regex::Regex;

use super::{
    LegalStance, ProtectorDetection, ProtectorFamily, ProtectorOptions, ProtectorOutput,
    ProtectorStats,
};
use crate::error::{Error, Result};
use crate::jscrambler::{
    JscramblerTransform, TransformOpts as JscramblerOpts, TransformOutput,
    dispatch_reverse_strict as jscrambler_reverse,
};
use crate::string_array::{StringArrayRecovery, recover as recover_string_array};

pub const FAMILY: ProtectorFamily = ProtectorFamily::JsDefender;
pub const LEGAL: LegalStance = LegalStance::AmberLeaningGreen;

const MARKERS: &[(&str, &str)] = &[
    (r"(?i)preemptive\s+solutions", "preemptive-copyright"),
    (r"(?i)jsdefender", "jsdefender-banner"),
    (r"_PreEmptive", "preemptive-prefix"),
    (r"__JSD__", "jsd-runtime-token"),
];

#[must_use]
pub fn detect(source: &str) -> Option<ProtectorDetection> {
    let mut markers: BTreeSet<String> = BTreeSet::new();
    let mut confidence: f32 = 0.0;
    for (pat, label) in MARKERS {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
            continue;
        };
        if re.is_match(source) {
            markers.insert((*label).to_owned());
            confidence += 0.35;
        }
    }
    if has_cff_with_string_array(source) {
        markers.insert("cff+string-array".to_owned());
        confidence += 0.45;
    }
    if has_dead_code_idiom(source) {
        markers.insert("dead-code-injection".to_owned());
        confidence += 0.10;
    }
    if confidence <= 0.0 {
        return None;
    }
    let confidence_clamped: f32 = confidence.min(0.99_f32);
    let markers_vec: Vec<String> = markers.into_iter().collect();
    Some(ProtectorDetection::new(
        FAMILY,
        confidence_clamped,
        markers_vec,
    ))
}

fn has_cff_with_string_array(source: &str) -> bool {
    let cff_pat: &str = r"switch\s*\(\s*[A-Za-z_$][\w$]*\s*\)\s*\{\s*case";
    let arr_pat: &str = r"var\s+[A-Za-z_$][\w$]*\s*=\s*\[\s*['\x22]";
    let Ok(re_cff): core::result::Result<Regex, regex::Error> = Regex::new(cff_pat) else {
        return false;
    };
    let Ok(re_arr): core::result::Result<Regex, regex::Error> = Regex::new(arr_pat) else {
        return false;
    };
    re_cff.is_match(source) && re_arr.is_match(source)
}

fn has_dead_code_idiom(source: &str) -> bool {
    let pat: &str = r"if\s*\(\s*(?:!!\[\]|!\[\]|true|false)\s*\)";
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
        return false;
    };
    re.find_iter(source).count() >= 2
}

pub fn deobfuscate(source: &str, opts: &ProtectorOptions) -> Result<ProtectorOutput> {
    let detection: Option<ProtectorDetection> = detect(source);
    let bytes_in: usize = source.len();
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired {
            transform: "jsdefender",
        });
    }
    let mut stats: ProtectorStats = ProtectorStats::default();
    let mut current: String = source.to_owned();
    let maybe_recovery: Option<StringArrayRecovery> = recover_string_array(&current)?;
    if let Some(recovery) = maybe_recovery {
        stats.matched += recovery.call_sites_total;
        stats.reversed += recovery.call_sites_inlined;
        current = recovery.rewritten_source;
    }
    let js_opts: JscramblerOpts = JscramblerOpts {
        i_have_authorization: true,
    };
    let cff_out: TransformOutput = jscrambler_reverse(
        JscramblerTransform::ControlFlowFlattening,
        &current,
        &js_opts,
    )?;
    stats.matched += cff_out.stats.matched;
    stats.reversed += cff_out.stats.reversed;
    stats.skipped += cff_out.stats.skipped;
    for e in cff_out.stats.errors {
        stats.errors.push(e);
    }
    current = cff_out.source;
    let dead_out: TransformOutput =
        jscrambler_reverse(JscramblerTransform::DeadCodeInjection, &current, &js_opts)?;
    stats.matched += dead_out.stats.matched;
    stats.reversed += dead_out.stats.reversed;
    stats.skipped += dead_out.stats.skipped;
    for e in dead_out.stats.errors {
        stats.errors.push(e);
    }
    current = dead_out.source;
    let enc_out: TransformOutput =
        jscrambler_reverse(JscramblerTransform::StringEncoding, &current, &js_opts)?;
    stats.matched += enc_out.stats.matched;
    stats.reversed += enc_out.stats.reversed;
    stats.skipped += enc_out.stats.skipped;
    for e in enc_out.stats.errors {
        stats.errors.push(e);
    }
    current = enc_out.source;
    let bytes_out: usize = current.len();
    Ok(ProtectorOutput {
        source: current,
        bytes_in,
        bytes_out,
        family: FAMILY,
        legal_stance: LEGAL,
        stance_doc: LEGAL.stance_doc(),
        detection,
        stats,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn legal_stance_const_matches_family() {
        assert_eq!(LEGAL, FAMILY.legal_stance());
        assert!(LEGAL.allows_bypass_with_authorization());
        assert_eq!(LEGAL.stance_doc(), "docs/legal/jsdefender-stance.md");
    }

    #[test]
    fn detects_preemptive_banner() {
        let src: &str = "/* PreEmptive Solutions JSDefender */ var x = 1; switch(x) { case 0: break; } var s = ['a'];";
        let det: ProtectorDetection = detect(src).expect("detected");
        assert_eq!(det.family, FAMILY);
        assert!(det.confidence > 0.0);
    }

    #[test]
    fn detects_cff_string_array_signature() {
        let src: &str = "var s = ['hello','world']; var i = 0; switch(i) { case 0: return s[0]; }";
        assert!(detect(src).is_some());
    }

    #[test]
    fn no_detect_on_clean_js() {
        let src: &str = "const x = 1; function add(a, b) { return a + b; }";
        assert!(detect(src).is_none());
    }

    #[test]
    fn deobfuscate_requires_authorization() {
        let src: &str = "var s = ['a','b']; var i = 0; switch(i) { case 0: return s[0]; }";
        let err: Error = deobfuscate(src, &ProtectorOptions::default()).unwrap_err();
        assert!(matches!(err, Error::AuthorizationRequired { .. }));
    }
}
