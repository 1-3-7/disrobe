use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::key::{RuntimeKeyMaterial, extract_runtime_key};
use crate::runtime::RuntimeLocation;
use crate::{MAX_RUNTIME_FILE_BYTES, read_file_bounded};

const MAX_BCC_SEGMENTS: usize = 4096;

pub(crate) struct V8V9DecryptedPayload {
    pub(crate) key: [u8; 16],
    pub(crate) nonce: [u8; 12],
    pub(crate) serial_from_runtime: String,
    pub(crate) mix_str_nonce: [u8; 12],
    pub(crate) plaintext: Vec<u8>,
    pub(crate) bcc_blobs: Vec<BccBlob>,
}

impl core::fmt::Debug for V8V9DecryptedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("V8V9DecryptedPayload")
            .field("key", &"[redacted; 16]")
            .field("nonce", &"[redacted; 12]")
            .field("serial_from_runtime", &self.serial_from_runtime)
            .field("mix_str_nonce", &"[redacted; 12]")
            .field("plaintext_len", &self.plaintext.len())
            .field("bcc_blobs", &self.bcc_blobs.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BccBlob {
    pub architecture: BccArch,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BccArch {
    WinX64,
    LinuxX64,
    DarwinArm64,
    Other(u32),
}

impl BccArch {
    pub(crate) const fn from_id(id: u32) -> Self {
        match id {
            0x2001 => Self::WinX64,
            0x2003 => Self::LinuxX64,
            0x3002 => Self::DarwinArm64,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WinX64 => "win-x64",
            Self::LinuxX64 => "linux-x64",
            Self::DarwinArm64 => "darwin-arm64",
            Self::Other(_) => "other",
        }
    }
}

pub(crate) fn decrypt(
    payload: &[u8],
    detection: &Detection,
    runtime: &RuntimeLocation,
) -> Result<V8V9DecryptedPayload> {
    let runtime_bytes: Vec<u8> = read_file_bounded(&runtime.path, MAX_RUNTIME_FILE_BYTES)?;
    let material: RuntimeKeyMaterial = extract_runtime_key(&runtime_bytes)?;
    let RuntimeKeyMaterial {
        serial,
        aes_key,
        mix_str_nonce,
        runtime_descriptor: _,
    }: RuntimeKeyMaterial = material;

    if let Some(det_serial) = detection.serial.as_ref()
        && det_serial != &serial
    {
        tracing::warn!(
            detection_serial = %det_serial,
            runtime_serial   = %serial,
            "detection serial differs from runtime serial; proceeding with runtime key"
        );
    }

    let (bcc_blobs, working_payload_start): (Vec<BccBlob>, usize) =
        peel_bcc_if_present(payload, &aes_key)?;
    let working_payload: &[u8] =
        payload
            .get(working_payload_start..)
            .ok_or(Error::HeaderTruncated {
                need: working_payload_start,
                got: payload.len(),
            })?;

    let cipher_offset: usize = u32_le(working_payload, 28)? as usize;
    let cipher_len: usize = u32_le(working_payload, 32)? as usize;

    if cipher_offset
        .checked_add(cipher_len)
        .is_none_or(|end: usize| end > working_payload.len())
    {
        return Err(Error::HeaderTruncated {
            need: cipher_offset.saturating_add(cipher_len),
            got: working_payload.len(),
        });
    }
    let cipher_end: usize = cipher_offset + cipher_len;

    let nonce: [u8; 12] = build_nonce(working_payload)?;
    let mut ciphertext: Vec<u8> = working_payload
        .get(cipher_offset..cipher_end)
        .ok_or(Error::HeaderTruncated {
            need: cipher_end,
            got: working_payload.len(),
        })?
        .to_vec();
    aes_ctr_init2(&aes_key, &nonce, &mut ciphertext);

    Ok(V8V9DecryptedPayload {
        key: aes_key,
        nonce,
        serial_from_runtime: serial,
        mix_str_nonce,
        plaintext: ciphertext,
        bcc_blobs,
    })
}

fn peel_bcc_if_present(payload: &[u8], aes_key: &[u8; 16]) -> Result<(Vec<BccBlob>, usize)> {
    if payload.len() < 24 {
        return Ok((Vec::new(), 0));
    }
    let protection_type: u32 = u32_le(payload, 20)?;
    if protection_type != 9 {
        return Ok((Vec::new(), 0));
    }
    let cipher_off: usize = u32_le(payload, 28)? as usize;
    let cipher_len: usize = u32_le(payload, 32)? as usize;
    let main_start: usize = u32_le(payload, 56)? as usize;

    if cipher_off
        .checked_add(cipher_len)
        .is_none_or(|end: usize| end > payload.len())
    {
        return Err(Error::HeaderTruncated {
            need: cipher_off.saturating_add(cipher_len),
            got: payload.len(),
        });
    }
    let cipher_end: usize = cipher_off + cipher_len;

    let nonce: [u8; 12] = build_nonce(payload)?;
    let mut bcc_plain: Vec<u8> = payload
        .get(cipher_off..cipher_end)
        .ok_or(Error::HeaderTruncated {
            need: cipher_end,
            got: payload.len(),
        })?
        .to_vec();
    aes_ctr_init2(aes_key, &nonce, &mut bcc_plain);

    let byte_budget: usize = bcc_plain.len().saturating_mul(2);
    let mut blobs: Vec<BccBlob> = Vec::new();
    let mut total: usize = 0;
    let mut view: &[u8] = bcc_plain.as_slice();
    while view.len() >= 16 && blobs.len() < MAX_BCC_SEGMENTS {
        let seg_off: usize = u32_le(view, 0)? as usize;
        let seg_len: usize = u32_le(view, 4)? as usize;
        let arch_id: u32 = u32_le(view, 8)?;
        let next_off: usize = u32_le(view, 12)? as usize;

        let seg_end: usize = seg_off.checked_add(seg_len).ok_or(Error::HeaderTruncated {
            need: usize::MAX,
            got: view.len(),
        })?;
        total = total
            .checked_add(seg_len)
            .filter(|running: &usize| *running <= byte_budget)
            .ok_or_else(|| Error::HeaderTruncated {
                need: total.saturating_add(seg_len),
                got: byte_budget,
            })?;
        let bytes: Vec<u8> = view
            .get(seg_off..seg_end)
            .ok_or(Error::HeaderTruncated {
                need: seg_end,
                got: view.len(),
            })?
            .to_vec();
        blobs.push(BccBlob {
            architecture: BccArch::from_id(arch_id),
            bytes,
        });
        if next_off == 0 || next_off >= view.len() || next_off < 16 {
            break;
        }
        view = &view[next_off..];
    }

    Ok((blobs, main_start))
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

fn aes_ctr_init2(key: &[u8; 16], nonce: &[u8; 12], data: &mut [u8]) {
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

#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "code_object_offset and xor_key_procedure_length surface plaintext-header fields parsed for parity with the PyArmor v8/v9 spec and for parse_plaintext_header_basic test; only marshal_offset is consumed by the unpack path today"
)]
pub(crate) struct PlaintextHeader {
    pub(crate) code_object_offset: usize,
    pub(crate) xor_key_procedure_length: usize,
    pub(crate) marshal_offset: usize,
}

pub(crate) fn parse_plaintext_header(plaintext: &[u8]) -> Result<PlaintextHeader> {
    let code_object_offset: usize = u32_le(plaintext, 0)? as usize;
    let xor_key_procedure_length: usize = u32_le(plaintext, 4)? as usize;
    let marshal_offset: usize = code_object_offset
        .checked_add(xor_key_procedure_length)
        .ok_or(Error::HeaderTruncated {
            need: usize::MAX,
            got: plaintext.len(),
        })?;
    if marshal_offset > plaintext.len() {
        return Err(Error::HeaderTruncated {
            need: marshal_offset,
            got: plaintext.len(),
        });
    }
    Ok(PlaintextHeader {
        code_object_offset,
        xor_key_procedure_length,
        marshal_offset,
    })
}

pub fn marshal_stream_start(plaintext: &[u8]) -> Result<usize> {
    Ok(parse_plaintext_header(plaintext)?.marshal_offset)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn nonce_assembly_uses_bytes_36_40_then_44_52() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        for (i, byte) in payload.iter_mut().enumerate().take(40).skip(36) {
            *byte = u8::try_from(i - 36).expect("0..4 fits u8");
        }
        for (i, byte) in payload.iter_mut().enumerate().take(52).skip(44) {
            *byte = 0x40 + u8::try_from(i - 44).expect("0..8 fits u8");
        }
        let nonce: [u8; 12] = build_nonce(&payload).expect("nonce");
        assert_eq!(&nonce[..4], &[0, 1, 2, 3]);
        assert_eq!(
            &nonce[4..],
            &[0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
        );
    }

    #[test]
    fn parse_plaintext_header_basic() {
        let mut data: Vec<u8> = vec![0u8; 64];
        data[..4].copy_from_slice(&0x20u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x10u32.to_le_bytes());
        let h: PlaintextHeader = parse_plaintext_header(&data).expect("header parses");
        assert_eq!(h.code_object_offset, 0x20);
        assert_eq!(h.xor_key_procedure_length, 0x10);
        assert_eq!(h.marshal_offset, 0x30);
    }

    #[test]
    fn marshal_stream_start_uses_plaintext_header() {
        let mut data: Vec<u8> = vec![0u8; 64];
        data[..4].copy_from_slice(&0x20u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x10u32.to_le_bytes());
        assert_eq!(marshal_stream_start(&data).expect("header parses"), 0x30);
    }

    #[test]
    fn peel_bcc_hostile_cipher_offset_returns_structured_error() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[20..24].copy_from_slice(&9u32.to_le_bytes());
        payload[28..32].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        payload[32..36].copy_from_slice(&0x10u32.to_le_bytes());
        let err: Error = peel_bcc_if_present(&payload, &[0u8; 16]).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { .. }));
    }

    #[test]
    fn peel_bcc_cipher_offset_plus_len_overflow_returns_structured_error() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[20..24].copy_from_slice(&9u32.to_le_bytes());
        payload[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        payload[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        let err: Error = peel_bcc_if_present(&payload, &[0u8; 16]).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { .. }));
    }

    #[test]
    fn peel_bcc_inner_segment_offset_overflow_returns_structured_error() {
        let mut bcc_plain: Vec<u8> = vec![0u8; 16];
        bcc_plain[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        bcc_plain[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let key: [u8; 16] = [0u8; 16];
        let cipher_len: u32 = u32::try_from(bcc_plain.len()).expect("len fits u32");
        let mut payload: Vec<u8> = vec![0u8; 64 + bcc_plain.len()];
        payload[20..24].copy_from_slice(&9u32.to_le_bytes());
        payload[28..32].copy_from_slice(&64u32.to_le_bytes());
        payload[32..36].copy_from_slice(&cipher_len.to_le_bytes());
        payload[56..60].copy_from_slice(&0u32.to_le_bytes());
        let mut encrypted: Vec<u8> = bcc_plain.clone();
        let nonce: [u8; 12] = build_nonce(&payload).expect("nonce");
        aes_ctr_init2(&key, &nonce, &mut encrypted);
        payload[64..].copy_from_slice(&encrypted);
        let err: Error = peel_bcc_if_present(&payload, &key).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { .. }));
    }

    #[test]
    fn u32_le_saturated_offset_returns_structured_error() {
        let err: Error = u32_le(&[0u8; 8], usize::MAX).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { .. }));
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
        payload[20..24].copy_from_slice(&9u32.to_le_bytes());
        payload[28..32].copy_from_slice(&64u32.to_le_bytes());
        payload[32..36].copy_from_slice(&cipher_len.to_le_bytes());
        payload[56..60].copy_from_slice(&0u32.to_le_bytes());
        let nonce: [u8; 12] = build_nonce(&payload).expect("nonce");
        let mut encrypted: Vec<u8> = bcc_plain.to_vec();
        aes_ctr_init2(key, &nonce, &mut encrypted);
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
        let err: Error = peel_bcc_if_present(&payload, &key).unwrap_err();
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
        let (blobs, _main): (Vec<BccBlob>, usize) =
            peel_bcc_if_present(&payload, &key).expect("empty-segment table peels bounded");
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
        let (blobs, main_start): (Vec<BccBlob>, usize) =
            peel_bcc_if_present(&payload, &key).expect("valid table peels");
        assert_eq!(blobs.len(), 2, "both non-overlapping segments are peeled");
        assert_eq!(blobs[0].architecture, BccArch::WinX64);
        assert_eq!(blobs[0].bytes, vec![0xAAu8; 8]);
        assert_eq!(blobs[1].architecture, BccArch::LinuxX64);
        assert_eq!(blobs[1].bytes, vec![0xBBu8; 8]);
        assert_eq!(main_start, 0);
    }
}
