use crate::encoder::{
    AuthorizationToken, DecodeOutcome, EncoderDetection, EncoderFamily, EncoderHeader,
};
use crate::error::{Error, Result};
use memchr::memmem;

const ZG_MARKERS: &[(&[u8], &str)] = &[
    (b"<?php @Zend;\n3", "zend-3"),
    (b"<?php @Zend;\n2", "zend-2"),
    (b"<?php @Zend;\n4", "zend-4"),
    (b"Zend Optimizer", "optimizer-banner"),
    (b"Zend Guard Loader", "guard-loader-banner"),
];

pub fn detect(bytes: &[u8]) -> Option<EncoderDetection> {
    for (needle, label) in ZG_MARKERS {
        if let Some(idx) = memmem::find(bytes, needle) {
            return Some(EncoderDetection {
                family: EncoderFamily::ZendGuard,
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
        return Err(Error::ZendGuardRequiresAuthorization);
    }
    let Some(detection): Option<EncoderDetection> = detect(bytes) else {
        return Err(Error::ZendGuardBadHeader("no Zend Guard marker"));
    };
    let header_skip: usize = match detection.version_label.as_str() {
        "zend-2" | "zend-3" | "zend-4" => 16,
        _ => return Err(Error::ZendGuardUnsupportedVersion(detection.version_label)),
    };
    let payload_start: usize = detection.marker_offset.saturating_add(header_skip);
    if payload_start >= bytes.len() {
        return Err(Error::ZendGuardBadHeader("payload truncated"));
    }
    let header: EncoderHeader = EncoderHeader {
        family: EncoderFamily::ZendGuard,
        version_label: detection.version_label,
        flags: 0,
        payload_offset: payload_start,
        payload_len: bytes.len() - payload_start,
    };
    let ciphertext: Vec<u8> = bytes[payload_start..].to_vec();
    Ok(DecodeOutcome::StructuralOnly { header, ciphertext })
}
