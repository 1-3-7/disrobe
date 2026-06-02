use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{DecryptStatus, InnerCipherStats, UnpackConfig, VersionedOutcome};
use crate::v8v9::{BccArch, BccBlob};

pub(crate) fn run(
    bytes: &[u8],
    detection: &Detection,
    runtime: Option<&RuntimeInfoSummary>,
    cfg: &UnpackConfig,
) -> Result<VersionedOutcome> {
    let Some(runtime_info): Option<&RuntimeInfoSummary> = runtime else {
        if cfg.strict {
            return Err(Error::RuntimeNotFound {
                searched: vec!["<runtime not supplied to unpack_static_with_config>".to_owned()],
            });
        }
        return Ok(VersionedOutcome {
            plaintext: Vec::new(),
            original_bytecode: None,
            bcc_blobs: Vec::new(),
            encrypted_funcs_recovered: 0,
            inner_cipher_stats: InnerCipherStats::empty(),
            status: DecryptStatus::DetectOnly,
            diagnostics: vec![
                "DR-PYARM-STATIC: v8 detect-only (no runtime supplied; pass UnpackConfig.runtime_bytes for full decrypt)"
                    .to_owned(),
            ],
        });
    };

    if detection.serial.as_deref().is_some()
        && detection
            .serial
            .as_deref()
            .is_some_and(|s: &str| s != runtime_info.serial)
    {
        tracing::warn!(
            payload_serial = ?detection.serial,
            runtime_serial = %runtime_info.serial,
            "v8 payload serial does not match runtime serial"
        );
    }

    decrypt_with_runtime_key(bytes, &runtime_info.aes_key, DecryptStatus::Functional)
}

pub(crate) fn decrypt_with_runtime_key(
    bytes: &[u8],
    aes_key: &[u8; 16],
    base_status: DecryptStatus,
) -> Result<VersionedOutcome> {
    if bytes.len() < 64 {
        return Err(Error::HeaderTruncated {
            need: 64,
            got: bytes.len(),
        });
    }
    let protection_type: u32 = u32_le(bytes, 20)?;
    let (bcc_blobs, working_start, status): (Vec<BccBlob>, usize, DecryptStatus) =
        if protection_type == 9 {
            let (blobs, start): (Vec<BccBlob>, usize) = peel_bcc(bytes, aes_key)?;
            (blobs, start, DecryptStatus::BccPartial)
        } else {
            (Vec::new(), 0usize, base_status)
        };

    if working_start >= bytes.len() {
        return Err(Error::HeaderTruncated {
            need: working_start,
            got: bytes.len(),
        });
    }
    let working: &[u8] = &bytes[working_start..];

    let cipher_offset: usize = u32_le(working, 28)? as usize;
    let cipher_len: usize = u32_le(working, 32)? as usize;

    if cipher_offset
        .checked_add(cipher_len)
        .is_none_or(|n: usize| n > working.len())
    {
        return Err(Error::HeaderTruncated {
            need: cipher_offset.saturating_add(cipher_len),
            got: working.len(),
        });
    }

    let nonce: [u8; 12] = build_nonce(working)?;
    let mut ciphertext: Vec<u8> = working[cipher_offset..cipher_offset + cipher_len].to_vec();
    aes_ctr_initial2(aes_key, &nonce, &mut ciphertext);

    let original_bytecode: Option<Vec<u8>> = Some(ciphertext.clone());

    let diagnostics: Vec<String> = if status == DecryptStatus::BccPartial {
        vec![format!(
            "DR-PYARM-STATIC: BCC mode payload - {} native segment(s) extracted; Python bytecode after BCC decrypted, native functions remain opaque without --allow-bcc",
            bcc_blobs.len()
        )]
    } else {
        Vec::new()
    };

    Ok(VersionedOutcome {
        plaintext: ciphertext,
        original_bytecode,
        bcc_blobs,
        encrypted_funcs_recovered: 0,
        inner_cipher_stats: InnerCipherStats::empty(),
        status,
        diagnostics,
    })
}

fn peel_bcc(payload: &[u8], aes_key: &[u8; 16]) -> Result<(Vec<BccBlob>, usize)> {
    let cipher_off: usize = u32_le(payload, 28)? as usize;
    let cipher_len: usize = u32_le(payload, 32)? as usize;
    let next_segment: usize = u32_le(payload, 56)? as usize;

    if cipher_off
        .checked_add(cipher_len)
        .is_none_or(|n: usize| n > payload.len())
    {
        return Err(Error::HeaderTruncated {
            need: cipher_off.saturating_add(cipher_len),
            got: payload.len(),
        });
    }
    let nonce: [u8; 12] = build_nonce(payload)?;
    let mut bcc_plain: Vec<u8> = payload[cipher_off..cipher_off + cipher_len].to_vec();
    aes_ctr_initial2(aes_key, &nonce, &mut bcc_plain);

    let mut blobs: Vec<BccBlob> = Vec::new();
    let mut view: &[u8] = bcc_plain.as_slice();
    while view.len() >= 16 {
        let seg_off: usize = u32_le(view, 0)? as usize;
        let seg_len: usize = u32_le(view, 4)? as usize;
        let arch_id: u32 = u32_le(view, 8)?;
        let next_off: usize = u32_le(view, 12)? as usize;
        let segment_end: usize = seg_off.checked_add(seg_len).ok_or(Error::HeaderTruncated {
            need: usize::MAX,
            got: view.len(),
        })?;
        if segment_end > view.len() {
            return Err(Error::HeaderTruncated {
                need: segment_end,
                got: view.len(),
            });
        }
        blobs.push(BccBlob {
            architecture: BccArch::from_id(arch_id),
            bytes: view[seg_off..segment_end].to_vec(),
        });
        if next_off == 0 || next_off >= view.len() {
            break;
        }
        view = &view[next_off..];
    }
    Ok((blobs, next_segment))
}

fn build_nonce(payload: &[u8]) -> Result<[u8; 12]> {
    if payload.len() < 52 {
        return Err(Error::HeaderTruncated {
            need: 52,
            got: payload.len(),
        });
    }
    let mut nonce: [u8; 12] = [0u8; 12];
    nonce[..4].copy_from_slice(&payload[36..40]);
    nonce[4..].copy_from_slice(&payload[44..52]);
    Ok(nonce)
}

fn aes_ctr_initial2(key: &[u8; 16], nonce: &[u8; 12], data: &mut [u8]) {
    let mut iv: [u8; 16] = [0u8; 16];
    iv[..12].copy_from_slice(nonce);
    iv[15] = 2;
    let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(key.into(), &iv.into());
    cipher.apply_keystream(data);
}

fn u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    let end: usize = offset.checked_add(4).ok_or(Error::HeaderTruncated {
        need: usize::MAX,
        got: buf.len(),
    })?;
    let slice: &[u8] = buf.get(offset..end).ok_or(Error::HeaderTruncated {
        need: end,
        got: buf.len(),
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::detect::{DetectionConfidence, ProtectionKind, PyarmorVersion};

    fn detection() -> Detection {
        Detection {
            version: PyarmorVersion::V8,
            protection: ProtectionKind::Standard,
            serial: Some("008106".to_owned()),
            python_major: Some(3),
            python_minor: Some(11),
            pyc_magic: Some(0xa70d),
            payload_offset_in_payload: 64,
            payload_size_in_payload: 0,
            iv: None,
            raw_header: Vec::new(),
            confidence: DetectionConfidence::High,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn detect_only_without_runtime_nonstrict() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..8].copy_from_slice(b"PY008106");
        bytes[20] = 0x08;
        let outcome: VersionedOutcome =
            run(&bytes, &detection(), None, &UnpackConfig::default()).unwrap();
        assert_eq!(outcome.status, DecryptStatus::DetectOnly);
    }

    #[test]
    fn strict_without_runtime_errors() {
        let cfg: UnpackConfig = UnpackConfig {
            strict: true,
            ..UnpackConfig::default()
        };
        let err: Error = run(&[], &detection(), None, &cfg).unwrap_err();
        assert!(matches!(err, Error::RuntimeNotFound { .. }));
    }

    #[test]
    fn roundtrip_aes_ctr_initial2() {
        let key: [u8; 16] = [0x42u8; 16];
        let nonce: [u8; 12] = [0x11u8; 12];
        let original: Vec<u8> = b"hello pyarmor static unpack roundtrip".to_vec();
        let mut buf: Vec<u8> = original.clone();
        aes_ctr_initial2(&key, &nonce, &mut buf);
        assert_ne!(buf, original);
        let mut back: Vec<u8> = buf;
        aes_ctr_initial2(&key, &nonce, &mut back);
        assert_eq!(back, original);
    }

    #[test]
    fn decrypt_with_runtime_key_roundtrip() {
        let key: [u8; 16] = [0x99u8; 16];
        let plaintext_marshal: &[u8] = b"\xe3\x00\x00\x00\x00 imaginary marshal stream body";
        let nonce: [u8; 12] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        let cipher_offset: u32 = 64u32;
        let cipher_len: u32 = u32::try_from(plaintext_marshal.len()).unwrap();
        let mut payload: Vec<u8> = vec![0u8; 64 + plaintext_marshal.len()];
        payload[..8].copy_from_slice(b"PY008106");
        payload[20] = 0x08;
        payload[28..32].copy_from_slice(&cipher_offset.to_le_bytes());
        payload[32..36].copy_from_slice(&cipher_len.to_le_bytes());
        payload[36..40].copy_from_slice(&nonce[..4]);
        payload[44..52].copy_from_slice(&nonce[4..]);
        let mut encrypted: Vec<u8> = plaintext_marshal.to_vec();
        aes_ctr_initial2(&key, &nonce, &mut encrypted);
        payload[64..].copy_from_slice(&encrypted);

        let outcome: VersionedOutcome =
            decrypt_with_runtime_key(&payload, &key, DecryptStatus::Functional).unwrap();
        assert_eq!(outcome.plaintext, plaintext_marshal);
        assert_eq!(outcome.status, DecryptStatus::Functional);
    }
}
