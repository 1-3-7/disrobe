use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::key::{RuntimeKeyMaterial, extract_runtime_key};
use crate::runtime::RuntimeLocation;

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
    let runtime_bytes: Vec<u8> = std::fs::read(&runtime.path)?;
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
    let working_payload: &[u8] = &payload[working_payload_start..];

    let cipher_offset: usize = u32_le(working_payload, 28)? as usize;
    let cipher_len: usize = u32_le(working_payload, 32)? as usize;

    if cipher_offset + cipher_len > working_payload.len() {
        return Err(Error::HeaderTruncated {
            need: cipher_offset + cipher_len,
            got: working_payload.len(),
        });
    }

    let nonce: [u8; 12] = build_nonce(working_payload)?;
    let mut ciphertext: Vec<u8> =
        working_payload[cipher_offset..cipher_offset + cipher_len].to_vec();
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

    if cipher_off + cipher_len > payload.len() {
        return Err(Error::HeaderTruncated {
            need: cipher_off + cipher_len,
            got: payload.len(),
        });
    }

    let nonce: [u8; 12] = build_nonce(payload)?;
    let mut bcc_plain: Vec<u8> = payload[cipher_off..cipher_off + cipher_len].to_vec();
    aes_ctr_init2(aes_key, &nonce, &mut bcc_plain);

    let mut blobs: Vec<BccBlob> = Vec::new();
    let mut view: &[u8] = bcc_plain.as_slice();
    while view.len() >= 16 {
        let seg_off: usize = u32_le(view, 0)? as usize;
        let seg_len: usize = u32_le(view, 4)? as usize;
        let arch_id: u32 = u32_le(view, 8)?;
        let next_off: usize = u32_le(view, 12)? as usize;

        let bytes: Vec<u8> = view
            .get(seg_off..seg_off + seg_len)
            .ok_or(Error::HeaderTruncated {
                need: seg_off + seg_len,
                got: view.len(),
            })?
            .to_vec();
        blobs.push(BccBlob {
            architecture: BccArch::from_id(arch_id),
            bytes,
        });
        if next_off == 0 || next_off >= view.len() {
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
    let slice: &[u8] = buf.get(offset..offset + 4).ok_or(Error::HeaderTruncated {
        need: offset + 4,
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
}
