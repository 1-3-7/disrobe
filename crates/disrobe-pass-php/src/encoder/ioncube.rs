use crate::encoder::{
    AuthorizationToken, DecodeOutcome, EncoderDetection, EncoderFamily, EncoderHeader,
};
use crate::error::{Error, Result};
use memchr::memmem;

const IONCUBE_MARKERS: &[&[u8]] = &[
    b"<?php //00",
    b"<?php //0046",
    b"<?php //004f",
    b"ioncube_loader",
    b"ioncube_event_handler",
];

const IONCUBE_VERSION_MARKERS: &[(&[u8], &str)] = &[
    (b"//00400", "v4-legacy"),
    (b"//0046", "v6"),
    (b"//004F", "v9"),
    (b"//0080", "v10"),
    (b"//00A0", "v11+"),
];

pub fn detect(bytes: &[u8]) -> Option<EncoderDetection> {
    let mut best: Option<(usize, &str)> = None;
    for (needle, label) in IONCUBE_VERSION_MARKERS {
        if let Some(idx) = memmem::find(bytes, needle)
            && best.is_none_or(|(prev_idx, _): (usize, &str)| idx < prev_idx)
        {
            best = Some((idx, label));
        }
    }
    if let Some((idx, label)) = best {
        return Some(EncoderDetection {
            family: EncoderFamily::IonCube,
            version_label: label.to_string(),
            marker_offset: idx,
            confident: true,
        });
    }
    for needle in IONCUBE_MARKERS {
        if let Some(idx) = memmem::find(bytes, needle) {
            return Some(EncoderDetection {
                family: EncoderFamily::IonCube,
                version_label: "unknown".to_string(),
                marker_offset: idx,
                confident: false,
            });
        }
    }
    None
}

pub fn decode(bytes: &[u8], auth: Option<AuthorizationToken>) -> Result<DecodeOutcome> {
    if auth.is_none() {
        return Err(Error::IonCubeRequiresAuthorization);
    }
    let Some(detection): Option<EncoderDetection> = detect(bytes) else {
        return Err(Error::IonCubeBadHeader("no ionCube marker"));
    };
    let supported: bool = matches!(
        detection.version_label.as_str(),
        "v4-legacy" | "v6" | "v9" | "v10"
    );
    if !supported {
        return Err(Error::IonCubeUnsupportedVersion(detection.version_label));
    }
    let body_start: usize = detection.marker_offset;
    let header_end: usize = body_start
        .checked_add(64)
        .ok_or(Error::IonCubeBadHeader("header offset overflow"))?;
    if header_end >= bytes.len() {
        return Err(Error::IonCubeBadHeader("payload shorter than header"));
    }
    let header: EncoderHeader = EncoderHeader {
        family: EncoderFamily::IonCube,
        version_label: detection.version_label,
        flags: u32::from_le_bytes(read4(bytes, body_start + 8)?),
        payload_offset: header_end,
        payload_len: bytes.len() - header_end,
    };
    let ciphertext: Vec<u8> = bytes[header_end..].to_vec();
    Ok(DecodeOutcome::StructuralOnly { header, ciphertext })
}

fn read4(bytes: &[u8], at: usize) -> Result<[u8; 4]> {
    let end: usize = at
        .checked_add(4)
        .ok_or(Error::IonCubeBadHeader("offset overflow"))?;
    if end > bytes.len() {
        return Err(Error::IonCubeBadHeader("read past EOF"));
    }
    Ok([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
