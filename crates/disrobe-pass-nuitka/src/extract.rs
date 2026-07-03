use serde::Serialize;

use crate::error::{Error, Result};
use crate::onefile::{OnefilePayload, extract_onefile};
use crate::signed::{AuthenticodeSummary, strip_authenticode};
use crate::variant::{NuitkaVariant, VariantClassification, classify};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VariantExtraction {
    Onefile(OnefileExtraction),
    Standalone(StandaloneSurface),
    Module(ModuleSurface),
    SignedPe(SignedPeExtraction),
    NotExtractable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OnefileExtraction {
    pub compressed: bool,
    pub payload_size: u64,
    pub entry_count: u32,
    pub payload_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StandaloneSurface {
    pub image_size: u64,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleSurface {
    pub image_size: u64,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedPeExtraction {
    pub stripped_size: u64,
    pub authenticode: AuthenticodeSummary,
    pub inner: Box<VariantExtraction>,
}

pub fn extract_variant(image: &[u8]) -> Result<VariantExtraction> {
    let classification: VariantClassification = classify(image)?;
    extract_for_classification(image, &classification)
}

pub fn extract_for_classification(
    image: &[u8],
    classification: &VariantClassification,
) -> Result<VariantExtraction> {
    match classification.variant {
        NuitkaVariant::OnefileKax | NuitkaVariant::OnefileKay => extract_onefile_path(image, classification),
        NuitkaVariant::Standalone => Ok(VariantExtraction::Standalone(StandaloneSurface {
            image_size: image.len() as u64,
            note: "standalone distribution: payload lives in sibling files (.dist/), not embedded".to_owned(),
        })),
        NuitkaVariant::Module => Ok(VariantExtraction::Module(ModuleSurface {
            image_size: image.len() as u64,
            note: "single module: PyInit_<name> entry; constants blob and impl_ symbols extracted via symbols/markers passes".to_owned(),
        })),
        NuitkaVariant::Wheel => Ok(VariantExtraction::NotExtractable {
            reason: "wheel: route via disrobe-pass-pyfreeze wheel extractor".to_owned(),
        }),
        NuitkaVariant::SignedPe => extract_signed_pe(image, classification),
        NuitkaVariant::Unknown => Ok(VariantExtraction::NotExtractable {
            reason: "unrecognised variant".to_owned(),
        }),
    }
}

fn extract_onefile_path(
    image: &[u8],
    classification: &VariantClassification,
) -> Result<VariantExtraction> {
    let payload_offset: usize = classification
        .onefile_offset
        .ok_or(Error::BadOnefileMagic(*b"???"))?;
    let payload: OnefilePayload = extract_onefile(image, payload_offset)?;
    Ok(VariantExtraction::Onefile(OnefileExtraction {
        compressed: payload.compressed,
        payload_size: payload.payload_size as u64,
        entry_count: u32::try_from(payload.entries.len()).unwrap_or(u32::MAX),
        payload_offset: payload_offset as u64,
    }))
}

fn extract_signed_pe(
    image: &[u8],
    classification: &VariantClassification,
) -> Result<VariantExtraction> {
    let authenticode: AuthenticodeSummary = classification
        .authenticode
        .clone()
        .ok_or_else(|| Error::ObjectParse("signed-pe classification without summary".to_owned()))?;
    let stripped: &[u8] = strip_authenticode(image, &authenticode)?;
    let inner_classification: VariantClassification = classify(stripped)?;
    let inner: VariantExtraction = match inner_classification.variant {
        NuitkaVariant::SignedPe => VariantExtraction::NotExtractable {
            reason: "nested signed-pe after strip; refusing to recurse".to_owned(),
        },
        _ => extract_for_classification(stripped, &inner_classification)?,
    };
    Ok(VariantExtraction::SignedPe(SignedPeExtraction {
        stripped_size: stripped.len() as u64,
        authenticode,
        inner: Box::new(inner),
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn real_kax_payload(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = b"KAX".to_vec();
        for (name, data) in entries {
            for unit in name.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&[0u8, 0u8]);
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(&[0u8, 0u8]);
        out
    }

    #[test]
    fn extract_onefile_kax_returns_payload() {
        let mut bytes: Vec<u8> = b"MZ\x90\x00".to_vec();
        bytes.extend_from_slice(b"NUITKA_ONEFILE_PARENT");
        bytes.extend_from_slice(&real_kax_payload(&[("hello.exe", b"MZ\x90\x00inner")]));
        let extraction: VariantExtraction = extract_variant(&bytes).expect("kax extract");
        let VariantExtraction::Onefile(o): VariantExtraction = extraction else {
            panic!("expected onefile variant");
        };
        assert!(!o.compressed);
        assert_eq!(o.entry_count, 1);
    }

    #[test]
    fn extract_standalone_yields_surface_note() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..119].copy_from_slice(b"nuitka_distribution");
        bytes[200..218].copy_from_slice(b"__nuitka_version__");
        bytes[400..412].copy_from_slice(b"__compiled__");
        let extraction: VariantExtraction = extract_variant(&bytes).expect("standalone");
        assert!(matches!(extraction, VariantExtraction::Standalone(_)));
    }

    #[test]
    fn extract_module_yields_surface_note() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..107].copy_from_slice(b"PyInit_");
        bytes[200..218].copy_from_slice(b"__nuitka_version__");
        bytes[400..412].copy_from_slice(b"__compiled__");
        let extraction: VariantExtraction = extract_variant(&bytes).expect("module");
        assert!(matches!(extraction, VariantExtraction::Module(_)));
    }
}
