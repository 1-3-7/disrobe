mod aaencode;
mod atob_indirection;
mod eval_indirection;
mod jjencode;
mod jsfiretruck;
mod jsfuck;
mod packer;
mod sandbox;

pub(crate) use sandbox::eval_to_string;

pub use aaencode::{AaEncodeDecode, AaEncodeDetection, decode_aaencode, detect_aaencode};
pub use atob_indirection::{AtobIndirectionResult, AtobIndirectionStats, peel_atob_indirection};
pub use eval_indirection::{EvalIndirectionResult, EvalIndirectionStats, peel_eval_indirection};
pub use jjencode::{JjEncodeDecode, JjEncodeDetection, decode_jjencode, detect_jjencode};
pub use jsfiretruck::{
    JsFireTruckDecode, JsFireTruckDetection, decode_jsfiretruck, detect_jsfiretruck,
};
pub use jsfuck::{JsFuckDecode, JsFuckDetection, decode_jsfuck, detect_jsfuck};
pub use packer::{PackerDecode, PackerDetection, detect_packer, unpack as unpack_packer};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum EsotericFamily {
    JsFuck,
    JsFireTruck,
    JjEncode,
    AaEncode,
    DeanEdwardsPacker,
    EvalIndirection,
    AtobIndirection,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct EsotericClassification {
    pub family: EsotericFamily,
    pub confidence: f32,
    pub markers: Vec<String>,
}

#[must_use]
pub fn classify(source: &str) -> EsotericClassification {
    let mut markers: Vec<String> = Vec::new();
    let packer_det: PackerDetection = detect_packer(source);
    if packer_det.matched {
        markers.push(format!(
            "dean-edwards-packer base={} words={}",
            packer_det.base, packer_det.word_count
        ));
        return EsotericClassification {
            family: EsotericFamily::DeanEdwardsPacker,
            confidence: 0.99,
            markers,
        };
    }
    let aaencode_det: AaEncodeDetection = detect_aaencode(source);
    if aaencode_det.matched {
        markers.push(format!(
            "aaencode banner_hits={} density={:.3}",
            aaencode_det.banner_hits, aaencode_det.kaomoji_density
        ));
        return EsotericClassification {
            family: EsotericFamily::AaEncode,
            confidence: 0.95,
            markers,
        };
    }
    let jj_det: JjEncodeDetection = detect_jjencode(source);
    if jj_det.matched {
        markers.push(format!(
            "jjencode signature_hits={} global={:?}",
            jj_det.signature_hits, jj_det.global_var
        ));
        return EsotericClassification {
            family: EsotericFamily::JjEncode,
            confidence: 0.95,
            markers,
        };
    }
    let firetruck_det: JsFireTruckDetection = detect_jsfiretruck(source);
    if firetruck_det.matched {
        markers.push(format!(
            "jsfiretruck purity={:.3} dot_slash_density={:.3}",
            firetruck_det.purity_ratio, firetruck_det.dot_slash_density
        ));
        return EsotericClassification {
            family: EsotericFamily::JsFireTruck,
            confidence: 0.9,
            markers,
        };
    }
    let jsfuck_det: JsFuckDetection = detect_jsfuck(source);
    if jsfuck_det.matched {
        markers.push(format!(
            "jsfuck purity={:.3} atoms={}",
            jsfuck_det.purity_ratio, jsfuck_det.symbolic_atoms_recognized
        ));
        return EsotericClassification {
            family: EsotericFamily::JsFuck,
            confidence: 0.95,
            markers,
        };
    }
    if source.contains("atob(") {
        markers.push("atob-call-present".to_owned());
        return EsotericClassification {
            family: EsotericFamily::AtobIndirection,
            confidence: 0.4,
            markers,
        };
    }
    if source.contains("eval(") || source.contains("Function(") {
        markers.push("eval-or-Function-call-present".to_owned());
        return EsotericClassification {
            family: EsotericFamily::EvalIndirection,
            confidence: 0.4,
            markers,
        };
    }
    EsotericClassification {
        family: EsotericFamily::Unknown,
        confidence: 0.0,
        markers,
    }
}
