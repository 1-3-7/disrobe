use aes::Aes128;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;

use crate::detect::{Detection, DetectionConfidence, PyarmorVersion};
use crate::error::{Error, Result};

pub(crate) const LEGACY_KEY_DES3: [u8; 24] = [
    0x70, 0x79, 0x61, 0x72, 0x6d, 0x6f, 0x72, 0x2d, 0x76, 0x33, 0x2d, 0x65, 0x64, 0x65, 0x33, 0x2d,
    0x64, 0x65, 0x73, 0x2d, 0x6b, 0x65, 0x79, 0x5f,
];

pub(crate) const LEGACY_KEY_AES: [u8; 16] = [
    0x70, 0x79, 0x61, 0x72, 0x6d, 0x6f, 0x72, 0x2d, 0x76, 0x35, 0x2d, 0x61, 0x65, 0x73, 0x21, 0x21,
];

pub(crate) const LEGACY_IV: [u8; 16] = [
    0x50, 0x59, 0x41, 0x52, 0x4d, 0x4f, 0x52, 0x49, 0x56, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
];

pub(crate) const LEGACY_IV_DES: [u8; 8] = [0x50, 0x59, 0x41, 0x52, 0x4d, 0x4f, 0x52, 0x49];

type Des3CbcDec = cbc::Decryptor<TdesEde3>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDecryptedPayload {
    pub version: PyarmorVersion,
    pub plaintext: Vec<u8>,
    pub confidence: DetectionConfidence,
    pub unverified_against_real_sample: bool,
    pub diagnostics: Vec<String>,
}

#[inline]
#[cfg(test)]
const fn version_from_mode_byte(b: u8) -> Option<PyarmorVersion> {
    match b {
        0x01 => Some(PyarmorVersion::V3),
        0x02 => Some(PyarmorVersion::V4),
        0x05 => Some(PyarmorVersion::V5),
        _ => None,
    }
}

pub(crate) fn decrypt_legacy(
    payload: &[u8],
    detection: &Detection,
) -> Result<LegacyDecryptedPayload> {
    if payload.is_empty() {
        return Err(Error::HeaderTruncated { need: 1, got: 0 });
    }
    let version: PyarmorVersion = detection.version;
    let body: &[u8] = &payload[1..];

    let diagnostics: Vec<String> = vec![
        "DR-PYARM-INFO: legacy v3/v4/v5 best-effort decryption; algorithm per documented spec, not validated against a real wrapper".to_owned(),
    ];

    let plaintext: Vec<u8> = match version {
        PyarmorVersion::V3 => decrypt_des3_cbc_pkcs7(body).map_err(Error::LegacyV3Decrypt)?,
        PyarmorVersion::V4 => decrypt_v4_mixed(body).map_err(Error::LegacyV4Decrypt)?,
        PyarmorVersion::V5 => decrypt_aes128_cbc_pkcs7(body).map_err(Error::LegacyV5Decrypt)?,
        _ => return Err(Error::LegacyNotImplemented),
    };

    Ok(LegacyDecryptedPayload {
        version,
        plaintext,
        confidence: DetectionConfidence::Low,
        unverified_against_real_sample: true,
        diagnostics,
    })
}

fn decrypt_des3_cbc_pkcs7(ciphertext: &[u8]) -> core::result::Result<Vec<u8>, String> {
    if ciphertext.is_empty() {
        return Err("empty ciphertext".to_owned());
    }
    if !ciphertext.len().is_multiple_of(8) {
        return Err(format!(
            "ciphertext length {} not multiple of DES block size 8",
            ciphertext.len()
        ));
    }
    let dec: Des3CbcDec = Des3CbcDec::new(LEGACY_KEY_DES3[..].into(), LEGACY_IV_DES[..].into());
    let buf: Vec<u8> = dec
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "DES3 PKCS7 unpad failed".to_owned())?;
    Ok(buf)
}

fn decrypt_aes128_cbc_pkcs7(ciphertext: &[u8]) -> core::result::Result<Vec<u8>, String> {
    if ciphertext.is_empty() {
        return Err("empty ciphertext".to_owned());
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err(format!(
            "ciphertext length {} not multiple of AES block size 16",
            ciphertext.len()
        ));
    }
    let dec: Aes128CbcDec = Aes128CbcDec::new(LEGACY_KEY_AES[..].into(), LEGACY_IV[..].into());
    let buf: Vec<u8> = dec
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "AES128 PKCS7 unpad failed".to_owned())?;
    Ok(buf)
}

fn decrypt_v4_mixed(ciphertext: &[u8]) -> core::result::Result<Vec<u8>, String> {
    if ciphertext.len() < 16 {
        return Err(format!(
            "v4 body length {} shorter than AES block 16",
            ciphertext.len()
        ));
    }
    let aes_part_len: usize = (ciphertext.len() / 2) & !0xf;
    if aes_part_len == 0 {
        return decrypt_des3_cbc_pkcs7(ciphertext);
    }
    let aes_part: &[u8] = &ciphertext[..aes_part_len];
    let des_part: &[u8] = &ciphertext[aes_part_len..];
    let aes_dec: Aes128CbcDec = Aes128CbcDec::new(LEGACY_KEY_AES[..].into(), LEGACY_IV[..].into());
    let mut aes_buf: Vec<u8> = aes_part.to_vec();
    let aes_plain: &[u8] = aes_dec
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut aes_buf)
        .map_err(|_| "v4 AES-no-pad decrypt failed".to_owned())?;
    let aes_plain_owned: Vec<u8> = aes_plain.to_vec();
    let des_plain: Vec<u8> = if des_part.is_empty() {
        Vec::new()
    } else if des_part.len().is_multiple_of(8) {
        decrypt_des3_cbc_pkcs7(des_part)?
    } else {
        return Err(format!(
            "v4 DES tail length {} not multiple of 8",
            des_part.len()
        ));
    };
    let mut out: Vec<u8> = aes_plain_owned;
    out.extend_from_slice(&des_plain);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::detect::detect_from_wrapper;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit as KeyIvInitEnc};
    use core::fmt::Write as _;

    type Des3CbcEnc = cbc::Encryptor<TdesEde3>;
    type Aes128CbcEnc = cbc::Encryptor<Aes128>;

    fn encrypt_des3_cbc_pkcs7_test(plaintext: &[u8]) -> Vec<u8> {
        let enc: Des3CbcEnc = Des3CbcEnc::new(LEGACY_KEY_DES3[..].into(), LEGACY_IV_DES[..].into());
        enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    fn encrypt_aes128_cbc_pkcs7_test(plaintext: &[u8]) -> Vec<u8> {
        let enc: Aes128CbcEnc = Aes128CbcEnc::new(LEGACY_KEY_AES[..].into(), LEGACY_IV[..].into());
        enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    fn encrypt_v4_mixed_test(plaintext: &[u8]) -> Vec<u8> {
        let half: usize = (plaintext.len() / 2) & !0xf;
        if half == 0 {
            return encrypt_des3_cbc_pkcs7_test(plaintext);
        }
        let aes_in: &[u8] = &plaintext[..half];
        let des_in: &[u8] = &plaintext[half..];
        let aes_enc: Aes128CbcEnc =
            Aes128CbcEnc::new(LEGACY_KEY_AES[..].into(), LEGACY_IV[..].into());
        let mut aes_buf: Vec<u8> = vec![0u8; aes_in.len()];
        let aes_out: &[u8] = aes_enc
            .encrypt_padded_b2b_mut::<cbc::cipher::block_padding::NoPadding>(aes_in, &mut aes_buf)
            .expect("test-side noPadding aligned");
        let mut out: Vec<u8> = aes_out.to_vec();
        out.extend_from_slice(&encrypt_des3_cbc_pkcs7_test(des_in));
        out
    }

    fn encrypt_legacy_synthetic_test(version: PyarmorVersion, plaintext: &[u8]) -> Vec<u8> {
        let mode_byte: u8 = match version {
            PyarmorVersion::V3 => 0x01,
            PyarmorVersion::V4 => 0x02,
            PyarmorVersion::V5 => 0x05,
            _ => panic!("test helper only supports v3/v4/v5"),
        };
        let body: Vec<u8> = match version {
            PyarmorVersion::V3 => encrypt_des3_cbc_pkcs7_test(plaintext),
            PyarmorVersion::V4 => encrypt_v4_mixed_test(plaintext),
            PyarmorVersion::V5 => encrypt_aes128_cbc_pkcs7_test(plaintext),
            _ => panic!("test helper only supports v3/v4/v5"),
        };
        let mut wrapper: Vec<u8> = Vec::with_capacity(1 + body.len());
        wrapper.push(mode_byte);
        wrapper.extend_from_slice(&body);
        wrapper
    }

    fn make_detection(version: PyarmorVersion) -> Detection {
        Detection {
            version,
            protection: crate::detect::ProtectionKind::Standard,
            serial: None,
            python_major: None,
            python_minor: None,
            pyc_magic: None,
            payload_offset_in_payload: 1,
            payload_size_in_payload: 0,
            iv: None,
            raw_header: Vec::new(),
            confidence: DetectionConfidence::Low,
            diagnostics: Vec::new(),
        }
    }

    fn escape_bytes(payload: &[u8]) -> String {
        payload
            .iter()
            .fold(String::with_capacity(payload.len() * 4), |mut s, b| {
                let _ = write!(s, "\\x{b:02x}");
                s
            })
    }

    #[test]
    fn version_mapping_round_trips_known_mode_bytes() {
        assert_eq!(version_from_mode_byte(0x01), Some(PyarmorVersion::V3));
        assert_eq!(version_from_mode_byte(0x02), Some(PyarmorVersion::V4));
        assert_eq!(version_from_mode_byte(0x05), Some(PyarmorVersion::V5));
        assert_eq!(version_from_mode_byte(0x07), None);
    }

    #[test]
    fn v3_des3_encrypt_decrypt_round_trip_synthetic() {
        let plaintext: Vec<u8> =
            b"PyArmor v3 synthetic wrapper plaintext body, multi-block.".to_vec();
        let wrapper: Vec<u8> = encrypt_legacy_synthetic_test(PyarmorVersion::V3, &plaintext);
        assert_eq!(wrapper[0], 0x01);
        let det: Detection = make_detection(PyarmorVersion::V3);
        let out: LegacyDecryptedPayload = decrypt_legacy(&wrapper, &det).expect("decrypts");
        assert_eq!(out.plaintext, plaintext);
        assert_eq!(out.version, PyarmorVersion::V3);
        assert_eq!(out.confidence, DetectionConfidence::Low);
        assert!(out.unverified_against_real_sample);
    }

    #[test]
    fn v4_mixed_encrypt_decrypt_round_trip_synthetic() {
        let plaintext: Vec<u8> = b"PyArmor v4 mixed AES/DES synthetic plaintext spanning multiple 16-byte cells with extra DES tail bytes."
            .to_vec();
        let wrapper: Vec<u8> = encrypt_legacy_synthetic_test(PyarmorVersion::V4, &plaintext);
        assert_eq!(wrapper[0], 0x02);
        let det: Detection = make_detection(PyarmorVersion::V4);
        let out: LegacyDecryptedPayload = decrypt_legacy(&wrapper, &det).expect("decrypts");
        assert_eq!(out.plaintext, plaintext);
        assert_eq!(out.version, PyarmorVersion::V4);
    }

    #[test]
    fn v5_aes_encrypt_decrypt_round_trip_synthetic() {
        let plaintext: Vec<u8> =
            b"PyArmor v5 synthetic AES wrapper body content, exact AES PKCS7 round-trip.".to_vec();
        let wrapper: Vec<u8> = encrypt_legacy_synthetic_test(PyarmorVersion::V5, &plaintext);
        assert_eq!(wrapper[0], 0x05);
        let det: Detection = make_detection(PyarmorVersion::V5);
        let out: LegacyDecryptedPayload = decrypt_legacy(&wrapper, &det).expect("decrypts");
        assert_eq!(out.plaintext, plaintext);
        assert_eq!(out.version, PyarmorVersion::V5);
    }

    #[test]
    fn v3_wrapper_detect_then_decrypt_via_wrapper_text() {
        let plaintext: Vec<u8> = b"v3 detect-and-decrypt synthetic round-trip body.".to_vec();
        let wrapper: Vec<u8> = encrypt_legacy_synthetic_test(PyarmorVersion::V3, &plaintext);
        let text: String = format!(
            "from pytransform import __pyarmor__\n__pyarmor__(__name__, __file__, b'{}')\n",
            escape_bytes(&wrapper)
        );
        let (det, payload): (Detection, Vec<u8>) = detect_from_wrapper(&text).expect("detects");
        assert_eq!(det.version, PyarmorVersion::V3);
        let out: LegacyDecryptedPayload = decrypt_legacy(&payload, &det).expect("decrypts");
        assert_eq!(out.plaintext, plaintext);
    }

    #[test]
    fn v5_invalid_ciphertext_length_returns_typed_error() {
        let mut wrapper: Vec<u8> = Vec::with_capacity(8);
        wrapper.push(0x05);
        wrapper.extend_from_slice(&[0u8; 7]);
        let det: Detection = make_detection(PyarmorVersion::V5);
        let err: Error = decrypt_legacy(&wrapper, &det).unwrap_err();
        assert!(matches!(err, Error::LegacyV5Decrypt(_)));
    }

    #[test]
    fn empty_wrapper_returns_truncated_header() {
        let det: Detection = make_detection(PyarmorVersion::V3);
        let err: Error = decrypt_legacy(&[], &det).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { need: 1, got: 0 }));
    }
}
