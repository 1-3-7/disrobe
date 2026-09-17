use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use disrobe_bytes::ByteReader;
use disrobe_core::{CryptoWall, CryptoWallKind};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::{Choice, ConstantTimeEq};

use crate::error::{Error, Result};
use crate::extract::{ExtractionResult, extract_to_with_quota};
use crate::quota::ExtractionQuota;

pub const LUKS1_HEADER_BYTES: usize = 592;
const SECTOR_BYTES: usize = 512;
const ACTIVE_KEY_SLOT: u32 = 0x00ac_71f3;
const DISABLED_KEY_SLOT: u32 = 0x0000_dead;
const KEY_MATERIAL_ALIGNMENT_SECTORS: u64 = 8;
const MAX_LUKS1_KEY_BYTES: usize = 4096;
pub const MAX_LUKS1_DIGEST_ITERATIONS: u32 = 1_000_000;
pub const MAX_LUKS1_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_LUKS1_PAYLOAD_OFFSET_BYTES: u64 = 64 * 1024 * 1024;

type Aes128Cbc = cbc::Decryptor<aes::Aes128>;
type Aes192Cbc = cbc::Decryptor<aes::Aes192>;
type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Luks1Header {
    pub payload_offset: u64,
    pub key_bytes: usize,
    pub cipher_name: String,
    pub cipher_mode: String,
    pub hash_spec: String,
    pub digest_iterations: u32,
    digest: [u8; 20],
    digest_salt: [u8; 32],
}

pub fn detect_luks1(bytes: &[u8]) -> bool {
    bytes.starts_with(b"LUKS\xba\xbe") && bytes.get(6..8) == Some(&[0, 1])
}

pub fn parse_luks1(bytes: &[u8]) -> Result<Luks1Header> {
    if bytes.len() < LUKS1_HEADER_BYTES {
        return Err(Error::Luks1Malformed);
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let magic: &[u8] = reader.read_bytes(6).map_err(|_| Error::Luks1Malformed)?;
    if magic != b"LUKS\xba\xbe" {
        return Err(Error::Luks1Malformed);
    }
    let version: u16 = reader.read_u16_be().map_err(|_| Error::Luks1Malformed)?;
    if version != 1 {
        return Err(Error::LuksUnsupportedVersion { version });
    }
    let cipher_name: String = read_name(reader.read_bytes(32).map_err(|_| Error::Luks1Malformed)?)?;
    let cipher_mode: String = read_name(reader.read_bytes(32).map_err(|_| Error::Luks1Malformed)?)?;
    let hash_spec: String = read_name(reader.read_bytes(32).map_err(|_| Error::Luks1Malformed)?)?;
    let payload_offset: u64 = u64::from(reader.read_u32_be().map_err(|_| Error::Luks1Malformed)?);
    if payload_offset == 0 {
        return Err(Error::Luks1DetachedPayload);
    }
    if payload_offset < 2 {
        return Err(Error::Luks1Malformed);
    }
    let payload_offset_bytes: u64 = payload_offset
        .checked_mul(SECTOR_BYTES as u64)
        .ok_or(Error::Luks1Malformed)?;
    if payload_offset_bytes > MAX_LUKS1_PAYLOAD_OFFSET_BYTES {
        return Err(Error::Luks1PayloadOffsetTooLarge {
            bytes: payload_offset_bytes,
            cap: MAX_LUKS1_PAYLOAD_OFFSET_BYTES,
        });
    }
    let key_bytes: usize =
        usize::try_from(reader.read_u32_be().map_err(|_| Error::Luks1Malformed)?)
            .map_err(|_| Error::Luks1Malformed)?;
    if !(1..=MAX_LUKS1_KEY_BYTES).contains(&key_bytes) {
        return Err(Error::Luks1Malformed);
    }
    let mut digest: [u8; 20] = [0; 20];
    digest.copy_from_slice(reader.read_bytes(20).map_err(|_| Error::Luks1Malformed)?);
    let mut digest_salt: [u8; 32] = [0; 32];
    digest_salt.copy_from_slice(reader.read_bytes(32).map_err(|_| Error::Luks1Malformed)?);
    let digest_iterations: u32 = reader.read_u32_be().map_err(|_| Error::Luks1Malformed)?;
    if !(1..=MAX_LUKS1_DIGEST_ITERATIONS).contains(&digest_iterations) {
        return Err(Error::Luks1KdfCost {
            iterations: digest_iterations,
        });
    }
    let _uuid: String = read_name(reader.read_bytes(40).map_err(|_| Error::Luks1Malformed)?)?;
    let mut active_key_material: Vec<(u64, u64)> = Vec::with_capacity(8);
    for _ in 0..8 {
        let state: u32 = reader.read_u32_be().map_err(|_| Error::Luks1Malformed)?;
        let iterations: u32 = reader.read_u32_be().map_err(|_| Error::Luks1Malformed)?;
        let _salt: &[u8] = reader.read_bytes(32).map_err(|_| Error::Luks1Malformed)?;
        let material_offset: u64 =
            u64::from(reader.read_u32_be().map_err(|_| Error::Luks1Malformed)?);
        let stripes: u32 = reader.read_u32_be().map_err(|_| Error::Luks1Malformed)?;
        if !matches!(state, ACTIVE_KEY_SLOT | DISABLED_KEY_SLOT) {
            return Err(Error::Luks1Malformed);
        }
        if state == ACTIVE_KEY_SLOT {
            if iterations == 0 {
                return Err(Error::Luks1Malformed);
            }
            let material_bytes: u64 = u64::try_from(key_bytes)
                .ok()
                .and_then(|bytes: u64| bytes.checked_mul(u64::from(stripes)))
                .ok_or(Error::Luks1Malformed)?;
            let material_sectors: u64 = material_bytes
                .checked_add((SECTOR_BYTES - 1) as u64)
                .ok_or(Error::Luks1Malformed)?
                / SECTOR_BYTES as u64;
            let material_end: u64 = material_offset
                .checked_add(material_sectors)
                .ok_or(Error::Luks1Malformed)?;
            if stripes == 0
                || material_offset < 2
                || !material_offset.is_multiple_of(KEY_MATERIAL_ALIGNMENT_SECTORS)
                || material_offset >= payload_offset
                || material_end > payload_offset
            {
                return Err(Error::Luks1Malformed);
            }
            if active_key_material
                .iter()
                .any(|&(start, end): &(u64, u64)| material_offset < end && start < material_end)
            {
                return Err(Error::Luks1Malformed);
            }
            active_key_material.push((material_offset, material_end));
        }
    }
    if reader.position() != LUKS1_HEADER_BYTES {
        return Err(Error::Luks1Malformed);
    }
    Ok(Luks1Header {
        payload_offset,
        key_bytes,
        cipher_name,
        cipher_mode,
        hash_spec,
        digest_iterations,
        digest,
        digest_salt,
    })
}

pub fn luks1_raw_volume_key_wall(bytes: &[u8]) -> Result<CryptoWall> {
    let header: Luks1Header = parse_luks1(bytes)?;
    validate_luks1_raw_key_support(&header)?;
    Ok(CryptoWall {
        kind: CryptoWallKind::Luks1RawVolumeKey,
        offset: 0,
        evidence: format!(
            "luks1 cipher={} mode={} kdf=pbkdf2-{} iterations={}; missing raw volume key",
            header.cipher_name, header.cipher_mode, header.hash_spec, header.digest_iterations
        ),
        runtime_key_absent: true,
    })
}

pub fn decrypt_luks1_aes_cbc_plain_with_raw_volume_key(
    bytes: &[u8],
    raw_volume_key: &[u8],
) -> Result<Vec<u8>> {
    let header: Luks1Header = parse_luks1(bytes)?;
    validate_luks1_raw_key_support(&header)?;
    validate_luks1_image_length(&header, bytes.len() as u64)?;
    let payload_start: usize = usize::try_from(header.payload_offset * SECTOR_BYTES as u64)
        .map_err(|_| Error::Luks1Malformed)?;
    let payload: &[u8] = bytes
        .get(payload_start..)
        .ok_or(Error::Luks1TruncatedPayload)?;
    decrypt_luks1_payload(&header, payload, raw_volume_key)
}

pub fn validate_luks1_raw_key_support(header: &Luks1Header) -> Result<()> {
    if header.cipher_name != "aes" || header.cipher_mode != "cbc-plain" {
        return Err(Error::Luks1UnsupportedCipher {
            cipher: header.cipher_name.clone(),
            mode: header.cipher_mode.clone(),
        });
    }
    if !matches!(header.key_bytes, 16 | 24 | 32) {
        return Err(Error::Luks1UnsupportedKeyBytes {
            key_bytes: header.key_bytes,
        });
    }
    if !matches!(header.hash_spec.as_str(), "sha1" | "sha256" | "sha512") {
        return Err(Error::Luks1UnsupportedHash {
            hash: header.hash_spec.clone(),
        });
    }
    Ok(())
}

pub fn validate_luks1_image_length(header: &Luks1Header, image_bytes: u64) -> Result<()> {
    let payload_start: u64 = header.payload_offset * SECTOR_BYTES as u64;
    let payload_bytes: u64 = image_bytes
        .checked_sub(payload_start)
        .ok_or(Error::Luks1TruncatedPayload)?;
    if payload_bytes == 0 || !payload_bytes.is_multiple_of(SECTOR_BYTES as u64) {
        return Err(Error::Luks1TruncatedPayload);
    }
    if payload_bytes > MAX_LUKS1_PAYLOAD_BYTES as u64 {
        return Err(Error::Luks1PayloadTooLarge {
            bytes: usize::try_from(payload_bytes).unwrap_or(usize::MAX),
            cap: MAX_LUKS1_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

fn decrypt_luks1_payload(
    header: &Luks1Header,
    payload: &[u8],
    raw_volume_key: &[u8],
) -> Result<Vec<u8>> {
    if raw_volume_key.len() != header.key_bytes {
        return Err(Error::Luks1WrongKey);
    }
    let mut derived: [u8; 20] = [0; 20];
    match header.hash_spec.as_str() {
        "sha1" => pbkdf2_hmac::<Sha1>(
            raw_volume_key,
            &header.digest_salt,
            header.digest_iterations,
            &mut derived,
        ),
        "sha256" => pbkdf2_hmac::<Sha256>(
            raw_volume_key,
            &header.digest_salt,
            header.digest_iterations,
            &mut derived,
        ),
        "sha512" => pbkdf2_hmac::<Sha512>(
            raw_volume_key,
            &header.digest_salt,
            header.digest_iterations,
            &mut derived,
        ),
        _ => return Err(Error::Luks1Malformed),
    }
    let digest_matches: Choice = derived.ct_eq(&header.digest);
    if !bool::from(digest_matches) {
        return Err(Error::Luks1WrongKey);
    }
    let mut plain: Vec<u8> = Vec::with_capacity(payload.len());
    for (index, encrypted_sector) in payload.chunks_exact(SECTOR_BYTES).enumerate() {
        let sector_number: u32 = u32::try_from(index).map_err(|_| Error::Luks1Malformed)?;
        let mut iv: [u8; 16] = [0; 16];
        iv[..4].copy_from_slice(&sector_number.to_le_bytes());
        let mut sector: [u8; SECTOR_BYTES] = [0; SECTOR_BYTES];
        sector.copy_from_slice(encrypted_sector);
        decrypt_sector(&mut sector, raw_volume_key, &iv)?;
        plain.extend_from_slice(&sector);
    }
    Ok(plain)
}

pub fn extract_luks1_aes_cbc_plain_with_raw_volume_key(
    bytes: &[u8],
    raw_volume_key: &[u8],
    out_dir: &std::path::Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let plaintext: Vec<u8> =
        decrypt_luks1_aes_cbc_plain_with_raw_volume_key(bytes, raw_volume_key)?;
    let kind: crate::container::ContainerKind =
        crate::container::detect_container(&plaintext).ok_or(Error::UnknownContainer)?;
    extract_to_with_quota(kind, &plaintext, out_dir, quota)
}

fn decrypt_sector(sector: &mut [u8], key: &[u8], iv: &[u8; 16]) -> Result<()> {
    match key.len() {
        16 => Aes128Cbc::new_from_slices(key, iv)
            .map_err(|_| Error::Luks1WrongKey)?
            .decrypt_padded_mut::<NoPadding>(sector)
            .map(|_| ())
            .map_err(|_| Error::Luks1WrongKey),
        24 => Aes192Cbc::new_from_slices(key, iv)
            .map_err(|_| Error::Luks1WrongKey)?
            .decrypt_padded_mut::<NoPadding>(sector)
            .map(|_| ())
            .map_err(|_| Error::Luks1WrongKey),
        32 => Aes256Cbc::new_from_slices(key, iv)
            .map_err(|_| Error::Luks1WrongKey)?
            .decrypt_padded_mut::<NoPadding>(sector)
            .map(|_| ())
            .map_err(|_| Error::Luks1WrongKey),
        _ => Err(Error::Luks1WrongKey),
    }
}

fn read_name(raw: &[u8]) -> Result<String> {
    let end: usize = raw
        .iter()
        .position(|&byte: &u8| byte == 0)
        .ok_or(Error::Luks1Malformed)?;
    if raw[..end]
        .iter()
        .any(|&byte: &u8| !(0x20..=0x7e).contains(&byte))
    {
        return Err(Error::Luks1Malformed);
    }
    let value: &str = core::str::from_utf8(&raw[..end]).map_err(|_| Error::Luks1Malformed)?;
    if value.is_empty() {
        return Err(Error::Luks1Malformed);
    }
    Ok(value.to_owned())
}
