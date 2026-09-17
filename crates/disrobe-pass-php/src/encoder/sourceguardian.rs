use crate::encoder::{
    AuthorizationToken, DecodeOutcome, EncoderDetection, EncoderFamily, EncoderHeader,
};
use crate::error::{Error, Result};
use memchr::memmem;

const SG_MARKERS: &[(&[u8], &str)] = &[
    (b"sg_load(", "loader-call"),
    (b"<?php @Zend;", "zend-misuse"),
    (b"// PHP SourceGuardian Loader v", "version-comment"),
    (b"<?php\n//SGV", "sgv-banner"),
];

#[must_use]
pub fn detect(bytes: &[u8]) -> Option<EncoderDetection> {
    for (needle, label) in SG_MARKERS {
        if let Some(idx) = memmem::find(bytes, needle) {
            return Some(EncoderDetection {
                family: EncoderFamily::SourceGuardian,
                version_label: (*label).to_string(),
                marker_offset: idx,
                confident: true,
            });
        }
    }
    None
}

pub fn decode(bytes: &[u8], auth: Option<AuthorizationToken>) -> Result<DecodeOutcome> {
    let Some(detection): Option<EncoderDetection> = detect(bytes) else {
        return Err(Error::SourceGuardianBadHeader("no SG marker"));
    };
    let recognized: bool = matches!(
        detection.version_label.as_str(),
        "version-comment" | "sgv-banner" | "loader-call"
    );
    if !recognized {
        return Err(Error::SourceGuardianUnsupportedVersion(
            detection.version_label,
        ));
    }
    let start: usize = detection.marker_offset;
    let payload_start: usize = start.saturating_add(64).min(bytes.len());
    let header: EncoderHeader = EncoderHeader {
        family: EncoderFamily::SourceGuardian,
        version_label: detection.version_label,
        flags: 0,
        payload_offset: payload_start,
        payload_len: bytes.len() - payload_start,
    };
    if let Ok(surface) = super::container::reverse_sourceguardian_container(bytes) {
        return Ok(DecodeOutcome::PartialPlaintext {
            header,
            recovered: surface.stripped_payload,
            residual_ciphertext: Vec::new(),
        });
    }
    if auth.is_none() {
        return Err(Error::SourceGuardianRequiresAuthorization);
    }
    if payload_start >= bytes.len() {
        return Err(Error::SourceGuardianBadHeader("payload truncated"));
    }
    let ciphertext: Vec<u8> = bytes[payload_start..].to_vec();
    Ok(DecodeOutcome::StructuralOnly { header, ciphertext })
}
