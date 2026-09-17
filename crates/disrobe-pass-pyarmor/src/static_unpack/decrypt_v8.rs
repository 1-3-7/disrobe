use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{DecryptStatus, InnerCipherStats, UnpackConfig, VersionedOutcome};
use crate::v8v9::{BccArch, BccBlob};

const MODULE_FLAGS_OFFSET: usize = 37;
const MODULE_FLAG_BODY_ENCRYPTED: u8 = 0x01;
const MAX_BCC_SEGMENTS: usize = 4096;

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
                "DR-PYARM-STATIC: v8 detect-only. The AES key is not present in the payload; it is derived from the pyarmor_runtime native module. Supply that runtime (UnpackConfig.runtime_bytes / --runtime pyarmor_runtime.{so,pyd,dylib}) for static decrypt, OR run the target under the dynamic capture path (disrobe-pyarmor-cextract / disrobe-pyarmor-pytrace) to snapshot the decrypted code objects. No plaintext is emitted without one of these."
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

    let body_encrypted: bool = working
        .get(MODULE_FLAGS_OFFSET)
        .is_none_or(|f: &u8| f & MODULE_FLAG_BODY_ENCRYPTED != 0);

    let mut ciphertext: Vec<u8> = working[cipher_offset..cipher_offset + cipher_len].to_vec();
    let mut diagnostics: Vec<String> = Vec::new();
    if body_encrypted {
        let nonce: [u8; 12] = build_nonce(working)?;
        aes_ctr_initial2(aes_key, &nonce, &mut ciphertext);
    } else {
        diagnostics.push(
            "DR-PYARM-STATIC: obf_mod 0 plaintext module body (encrypt-flag clear); AES step skipped, marshal lifted directly"
                .to_owned(),
        );
    }

    let original_bytecode: Option<Vec<u8>> = Some(ciphertext.clone());

    if status == DecryptStatus::BccPartial {
        diagnostics.push(format!(
            "DR-PYARM-STATIC: BCC mode payload - {} native segment(s) extracted; Python bytecode after BCC decrypted, native functions remain opaque without --allow-bcc",
            bcc_blobs.len()
        ));
    }

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

    let byte_budget: usize = bcc_plain.len().saturating_mul(2);
    let mut blobs: Vec<BccBlob> = Vec::new();
    let mut total: usize = 0;
    let mut view: &[u8] = bcc_plain.as_slice();
    while view.len() >= 16 && blobs.len() < MAX_BCC_SEGMENTS {
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
        total = total
            .checked_add(seg_len)
            .filter(|running: &usize| *running <= byte_budget)
            .ok_or_else(|| Error::HeaderTruncated {
                need: total.saturating_add(seg_len),
                got: byte_budget,
            })?;
        blobs.push(BccBlob {
            architecture: BccArch::from_id(arch_id),
            bytes: view[seg_off..segment_end].to_vec(),
        });
        if next_off == 0 || next_off >= view.len() || next_off < 16 {
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
        assert!(
            outcome.plaintext.is_empty(),
            "no plaintext without a runtime"
        );
        let verdict: &str = outcome.diagnostics.first().map_or("", String::as_str);
        assert!(
            verdict.contains("pyarmor_runtime") && verdict.contains("cextract"),
            "no-runtime verdict must name both the runtime-key static path and the dynamic capture route: {verdict}"
        );
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
    fn plaintext_body_when_encrypt_flag_clear() {
        let key: [u8; 16] = [0x99u8; 16];
        let plaintext_marshal: &[u8] = b"\x20\x00\x00\x00 plaintext obf_mod 0 marshal body";
        let cipher_offset: u32 = 64u32;
        let cipher_len: u32 = u32::try_from(plaintext_marshal.len()).unwrap();
        let mut payload: Vec<u8> = vec![0u8; 64 + plaintext_marshal.len()];
        payload[..8].copy_from_slice(b"PY008106");
        payload[20] = 0x08;
        payload[36] = 0x12;
        payload[37] = 0x08;
        payload[28..32].copy_from_slice(&cipher_offset.to_le_bytes());
        payload[32..36].copy_from_slice(&cipher_len.to_le_bytes());
        payload[64..].copy_from_slice(plaintext_marshal);

        let outcome: VersionedOutcome =
            decrypt_with_runtime_key(&payload, &key, DecryptStatus::Functional).unwrap();
        assert_eq!(outcome.plaintext, plaintext_marshal);
        assert_eq!(outcome.status, DecryptStatus::Functional);
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|d: &String| d.contains("obf_mod 0")),
            "plaintext-body path emits the obf_mod 0 diagnostic"
        );
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
        assert!(
            nonce[1] & MODULE_FLAG_BODY_ENCRYPTED != 0,
            "fixture nonce keeps encrypt flag set"
        );
        let mut encrypted: Vec<u8> = plaintext_marshal.to_vec();
        aes_ctr_initial2(&key, &nonce, &mut encrypted);
        payload[64..].copy_from_slice(&encrypted);

        let outcome: VersionedOutcome =
            decrypt_with_runtime_key(&payload, &key, DecryptStatus::Functional).unwrap();
        assert_eq!(outcome.plaintext, plaintext_marshal);
        assert_eq!(outcome.status, DecryptStatus::Functional);
    }

    fn put_record(plain: &mut [u8], at: usize, seg_off: u32, seg_len: u32, arch: u32, next: u32) {
        plain[at..at + 4].copy_from_slice(&seg_off.to_le_bytes());
        plain[at + 4..at + 8].copy_from_slice(&seg_len.to_le_bytes());
        plain[at + 8..at + 12].copy_from_slice(&arch.to_le_bytes());
        plain[at + 12..at + 16].copy_from_slice(&next.to_le_bytes());
    }

    fn bcc_payload_from_plain(bcc_plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
        let cipher_len: u32 = u32::try_from(bcc_plain.len()).expect("len fits u32");
        let mut payload: Vec<u8> = vec![0u8; 64 + bcc_plain.len()];
        payload[20] = 0x09;
        payload[28..32].copy_from_slice(&64u32.to_le_bytes());
        payload[32..36].copy_from_slice(&cipher_len.to_le_bytes());
        payload[56..60].copy_from_slice(&0u32.to_le_bytes());
        let nonce: [u8; 12] = build_nonce(&payload).expect("nonce");
        let mut encrypted: Vec<u8> = bcc_plain.to_vec();
        aes_ctr_initial2(key, &nonce, &mut encrypted);
        payload[64..].copy_from_slice(&encrypted);
        payload
    }

    #[test]
    fn peel_bcc_aliased_segments_are_bounded_by_byte_budget() {
        let key: [u8; 16] = [0x5au8; 16];
        let mut plain: Vec<u8> = vec![0u8; 256];
        put_record(&mut plain, 0, 16, 200, 0x2001, 16);
        put_record(&mut plain, 16, 16, 200, 0x2001, 16);
        put_record(&mut plain, 32, 16, 200, 0x2001, 16);
        let payload: Vec<u8> = bcc_payload_from_plain(&plain, &key);
        let err: Error = peel_bcc(&payload, &key).unwrap_err();
        assert!(
            matches!(err, Error::HeaderTruncated { .. }),
            "overlapping segments whose copied bytes exceed twice the region must stop, not amplify"
        );
    }

    #[test]
    fn peel_bcc_many_empty_segments_capped_by_count() {
        let key: [u8; 16] = [0x77u8; 16];
        let region: usize = (MAX_BCC_SEGMENTS + 64) * 16;
        let mut plain: Vec<u8> = vec![0u8; region];
        let mut at: usize = 0;
        while at + 16 <= plain.len() {
            put_record(&mut plain, at, 0, 0, 0x2001, 16);
            at += 16;
        }
        let payload: Vec<u8> = bcc_payload_from_plain(&plain, &key);
        let (blobs, _start): (Vec<BccBlob>, usize) =
            peel_bcc(&payload, &key).expect("empty-segment table peels bounded");
        assert!(
            blobs.len() <= MAX_BCC_SEGMENTS,
            "segment count is capped at {MAX_BCC_SEGMENTS}, got {}",
            blobs.len()
        );
    }

    #[test]
    fn peel_bcc_valid_multi_segment_table_peels_every_segment() {
        let key: [u8; 16] = [0x33u8; 16];
        let mut plain: Vec<u8> = vec![0u8; 48];
        put_record(&mut plain, 0, 16, 8, 0x2001, 24);
        plain[16..24].fill(0xAAu8);
        put_record(&mut plain, 24, 16, 8, 0x2003, 0);
        plain[40..48].fill(0xBBu8);
        let payload: Vec<u8> = bcc_payload_from_plain(&plain, &key);
        let (blobs, _start): (Vec<BccBlob>, usize) =
            peel_bcc(&payload, &key).expect("valid table peels");
        assert_eq!(blobs.len(), 2, "both non-overlapping segments are peeled");
        assert_eq!(blobs[0].architecture, BccArch::WinX64);
        assert_eq!(blobs[0].bytes, vec![0xAAu8; 8]);
        assert_eq!(blobs[1].architecture, BccArch::LinuxX64);
        assert_eq!(blobs[1].bytes, vec![0xBBu8; 8]);
    }
}
