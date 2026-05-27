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
    if auth.is_none() {
        return Err(Error::SourceGuardianRequiresAuthorization);
    }
    let Some(detection): Option<EncoderDetection> = detect(bytes) else {
        return Err(Error::SourceGuardianBadHeader("no SG marker"));
    };
    if detection.version_label == "version-comment" || detection.version_label == "sgv-banner" {
        let start: usize = detection.marker_offset;
        let payload_start: usize = start.saturating_add(64);
        if payload_start >= bytes.len() {
            return Err(Error::SourceGuardianBadHeader("payload truncated"));
        }
        let header: EncoderHeader = EncoderHeader {
            family: EncoderFamily::SourceGuardian,
            version_label: detection.version_label,
            flags: 0,
            payload_offset: payload_start,
            payload_len: bytes.len() - payload_start,
        };
        let ciphertext: Vec<u8> = bytes[payload_start..].to_vec();
        return Ok(DecodeOutcome::StructuralOnly { header, ciphertext });
    }
    Err(Error::SourceGuardianUnsupportedVersion(
        detection.version_label,
    ))
}
