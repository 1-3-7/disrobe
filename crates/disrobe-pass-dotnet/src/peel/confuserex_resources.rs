#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use std::collections::BTreeSet;
use std::io::Cursor;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cil::{MethodBody, OperandValue, parse_method_body};
use crate::error::{Error, Result};
use crate::metadata::{StreamHeader, parse_metadata_root};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::tables::{
    ClassLayoutRow, FieldRvaRow, ManifestResourceRow, MethodDefRow, Tables, parse_tables,
};

pub const CONFUSEREX_LZMA_PROPS: u8 = 0x5D;

pub const CONFUSEREX_LZMA_DICT: u32 = 1 << 23;

pub const CONFUSEREX_BLOCK_BYTES: usize = 64;

pub const MAX_DECRYPTED_RESOURCE_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_ENCRYPTED_BLOB_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_SEED_CANDIDATES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfuserExRecovery {
    FullyDecrypted {
        blob_rva: u32,
        blob_size: u32,
        blob_sha256: [u8; 32],
        key_seed: u32,
        size_div_four: u32,
        decrypted_sha256: [u8; 32],
        lzma_uncompressed_size: u32,
    },

    BlobExtractedKeyedWall {
        blob_rva: u32,
        blob_size: u32,
        blob_sha256: [u8; 32],
        candidate_seeds_tried: u32,
        runtime_key_derivation: KeyDerivation,
    },

    NoEncryptedResourceFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyDerivation {
    AntiTamperImageHash,

    NotStaticallyPresent,
}

impl ConfuserExRecovery {
    #[must_use]
    pub const fn blob_located(&self) -> bool {
        matches!(
            self,
            Self::FullyDecrypted { .. } | Self::BlobExtractedKeyedWall { .. }
        )
    }

    #[must_use]
    pub const fn blob_sha256(&self) -> Option<[u8; 32]> {
        match self {
            Self::FullyDecrypted { blob_sha256, .. }
            | Self::BlobExtractedKeyedWall { blob_sha256, .. } => Some(*blob_sha256),
            Self::NoEncryptedResourceFound => None,
        }
    }
}

pub fn peel_confuserex_resources(image: &[u8]) -> Result<ConfuserExRecovery> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: crate::metadata::MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] =
        pe.slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)?;
    let table_header: &StreamHeader =
        match root.streams.get("#~").or_else(|| root.streams.get("#-")) {
            Some(h) => h,
            None => return Ok(ConfuserExRecovery::NoEncryptedResourceFound),
        };
    let tables: Tables = parse_tables(metadata_slice, *table_header)?;

    let Some(candidate): Option<EncryptedBlobLocator> = locate_encrypted_blob(&tables) else {
        return Ok(ConfuserExRecovery::NoEncryptedResourceFound);
    };

    let blob: Vec<u8> = extract_blob_bytes(image, &pe, candidate.rva, candidate.size)?;
    let blob_size: u32 = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    let blob_sha256: [u8; 32] = sha256(&blob);

    let mut seed_pool: Vec<u32> = collect_ldc_i4_immediates(image, &pe, &tables.methods);
    for emulated in
        crate::peel::confuserex_seed::recover_seeds_by_emulation(image, &pe, &tables.methods)
    {
        if !seed_pool.contains(&emulated) {
            seed_pool.push(emulated);
        }
    }
    let mut tried: u32 = 0;
    for seed in &seed_pool {
        tried = tried.saturating_add(1);
        if tried as usize > MAX_SEED_CANDIDATES {
            break;
        }
        let Some(plaintext): Option<Vec<u8>> = decrypt_blob(&blob, *seed) else {
            continue;
        };
        if !matches_lzma_oracle(&plaintext) {
            continue;
        }
        let lzma_uncompressed_size: u32 =
            u32::from_le_bytes([plaintext[5], plaintext[6], plaintext[7], plaintext[8]]);
        let decrypted_sha256: [u8; 32] = sha256(&plaintext);
        return Ok(ConfuserExRecovery::FullyDecrypted {
            blob_rva: candidate.rva,
            blob_size,
            blob_sha256,
            key_seed: *seed,
            size_div_four: blob_size / 4,
            decrypted_sha256,
            lzma_uncompressed_size,
        });
    }

    let runtime_key_derivation: KeyDerivation = if detect_anti_tamper(image, &pe, &tables.methods) {
        KeyDerivation::AntiTamperImageHash
    } else {
        KeyDerivation::NotStaticallyPresent
    };
    Ok(ConfuserExRecovery::BlobExtractedKeyedWall {
        blob_rva: candidate.rva,
        blob_size,
        blob_sha256,
        candidate_seeds_tried: tried,
        runtime_key_derivation,
    })
}

const MIN_IMAGE_WALK_DEREFS: usize = 3;

#[must_use]
pub fn body_walks_runtime_image(body: &MethodBody) -> bool {
    let mut resolves_runtime_handle: bool = false;
    let mut native_pointer_cast: bool = false;
    let mut pointer_derefs: usize = 0;
    for instr in &body.instructions {
        match instr.name.as_str() {
            "ldtoken" => resolves_runtime_handle = true,
            "conv.u" | "conv.i" => native_pointer_cast = true,
            "ldind.u2" | "ldind.u4" | "ldind.u1" | "ldind.i4" | "ldind.i2" => {
                pointer_derefs += 1;
            }
            _ => {}
        }
    }
    resolves_runtime_handle && native_pointer_cast && pointer_derefs >= MIN_IMAGE_WALK_DEREFS
}

fn detect_anti_tamper(image: &[u8], pe: &PeImage, methods: &[MethodDefRow]) -> bool {
    for method in methods {
        if method.rva == 0 {
            continue;
        }
        let Some(off): Option<usize> = pe.rva_to_offset(method.rva) else {
            continue;
        };
        if off >= image.len() {
            continue;
        }
        let Ok(body): Result<MethodBody> = parse_method_body(&image[off..]) else {
            continue;
        };
        if body_walks_runtime_image(&body) {
            return true;
        }
    }
    false
}

pub fn lzma_decompress(plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() < 9 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 9,
            had: plaintext.len(),
        });
    }
    let uncompressed_size: u32 =
        u32::from_le_bytes([plaintext[5], plaintext[6], plaintext[7], plaintext[8]]);
    let uncompressed_size_usize: usize = uncompressed_size as usize;
    if uncompressed_size_usize > MAX_DECRYPTED_RESOURCE_BYTES {
        return Err(Error::Truncated {
            offset: 5,
            needed: uncompressed_size_usize,
            had: MAX_DECRYPTED_RESOURCE_BYTES,
        });
    }
    let mut padded: Vec<u8> = Vec::with_capacity(plaintext.len() + 4);
    padded.extend_from_slice(&plaintext[..9]);
    padded.extend_from_slice(&[0u8; 4]);
    if plaintext.len() > 9 {
        padded.extend_from_slice(&plaintext[9..]);
    }
    let mut reader: Cursor<&[u8]> = Cursor::new(padded.as_slice());
    let mut out: Vec<u8> = Vec::with_capacity(uncompressed_size_usize.min(1 << 20));
    lzma_rs::lzma_decompress(&mut reader, &mut out).map_err(|_e: lzma_rs::error::Error| {
        Error::Truncated {
            offset: 0,
            needed: uncompressed_size_usize,
            had: out.len(),
        }
    })?;
    Ok(out)
}

#[must_use]
pub fn encrypt_blob(plaintext: &[u8], key_seed: u32) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0u8; plaintext.len()];
    if !plaintext.len().is_multiple_of(CONFUSEREX_BLOCK_BYTES) || plaintext.is_empty() {
        return out;
    }
    let mut key: [u32; 16] = derive_key(key_seed);
    let mut offset: usize = 0;
    while offset < plaintext.len() {
        let mut pt_block: [u32; 16] = [0u32; 16];
        for (i, word) in pt_block.iter_mut().enumerate() {
            let base: usize = offset + i * 4;
            *word = u32::from_le_bytes([
                plaintext[base],
                plaintext[base + 1],
                plaintext[base + 2],
                plaintext[base + 3],
            ]);
        }
        for i in 0..16 {
            let enc: u32 = pt_block[i] ^ key[i];
            let base: usize = offset + i * 4;
            out[base..base + 4].copy_from_slice(&enc.to_le_bytes());
        }
        for i in 0..16 {
            key[i] ^= pt_block[i];
        }
        offset += CONFUSEREX_BLOCK_BYTES;
    }
    out
}

#[must_use]
pub fn decrypt_blob(encrypted: &[u8], key_seed: u32) -> Option<Vec<u8>> {
    if encrypted.is_empty() || !encrypted.len().is_multiple_of(CONFUSEREX_BLOCK_BYTES) {
        return None;
    }
    let mut out: Vec<u8> = vec![0u8; encrypted.len()];
    let mut key: [u32; 16] = derive_key(key_seed);
    let mut offset: usize = 0;
    while offset < encrypted.len() {
        let mut enc_block: [u32; 16] = [0u32; 16];
        for (i, word) in enc_block.iter_mut().enumerate() {
            let base: usize = offset + i * 4;
            *word = u32::from_le_bytes([
                encrypted[base],
                encrypted[base + 1],
                encrypted[base + 2],
                encrypted[base + 3],
            ]);
        }
        let mut pt_block: [u32; 16] = [0u32; 16];
        for i in 0..16 {
            pt_block[i] = enc_block[i] ^ key[i];
            let base: usize = offset + i * 4;
            out[base..base + 4].copy_from_slice(&pt_block[i].to_le_bytes());
        }
        for i in 0..16 {
            key[i] ^= pt_block[i];
        }
        offset += CONFUSEREX_BLOCK_BYTES;
    }
    Some(out)
}

#[must_use]
pub const fn derive_key(key_seed: u32) -> [u32; 16] {
    let mut key: [u32; 16] = [0u32; 16];
    let mut state: u32 = key_seed;
    let mut i: usize = 0;
    while i < 16 {
        state ^= state >> 13;
        state ^= state << 25;
        state ^= state >> 27;
        key[i] = state;
        i += 1;
    }
    key
}

#[must_use]
pub fn matches_lzma_oracle(bytes: &[u8]) -> bool {
    if bytes.len() < 13 {
        return false;
    }
    if bytes[0] != CONFUSEREX_LZMA_PROPS {
        return false;
    }
    let dict: u32 = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if dict != CONFUSEREX_LZMA_DICT {
        return false;
    }
    let uncompressed: usize = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    uncompressed > 0 && uncompressed <= MAX_DECRYPTED_RESOURCE_BYTES
}

#[must_use]
pub fn classify_manifest_resources(rows: &[ManifestResourceRow]) -> ManifestResourceClassification {
    let mut embedded: u32 = 0;
    let mut linked: u32 = 0;
    for row in rows {
        match row.implementation {
            None => embedded = embedded.saturating_add(1),
            Some(_) => linked = linked.saturating_add(1),
        }
    }
    ManifestResourceClassification {
        total: u32::try_from(rows.len()).unwrap_or(u32::MAX),
        embedded,
        linked,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestResourceClassification {
    pub total: u32,

    pub embedded: u32,

    pub linked: u32,
}

#[derive(Debug, Clone, Copy)]
struct EncryptedBlobLocator {
    rva: u32,
    size: u32,
}

fn locate_encrypted_blob(tables: &Tables) -> Option<EncryptedBlobLocator> {
    let layouts: Vec<&ClassLayoutRow> = tables
        .class_layouts
        .iter()
        .filter(|cl: &&ClassLayoutRow| {
            cl.packing_size == 1
                && cl.class_size > 0
                && (cl.class_size as usize).is_multiple_of(CONFUSEREX_BLOCK_BYTES)
                && (cl.class_size as usize) <= MAX_ENCRYPTED_BLOB_BYTES
        })
        .collect();
    let candidate_size: u32 = layouts
        .iter()
        .map(|cl: &&ClassLayoutRow| cl.class_size)
        .max()?;
    let layout: &ClassLayoutRow = *layouts
        .iter()
        .find(|cl: &&&ClassLayoutRow| cl.class_size == candidate_size)?;
    let parent_typedef: u32 = layout.parent;
    let owner_field_range: Option<(u32, u32)> = field_range_for_typedef(tables, parent_typedef);
    let candidate_rva: u32 = tables
        .field_rvas
        .iter()
        .find_map(|fr: &FieldRvaRow| {
            if let Some((lo, hi)) = owner_field_range
                && (lo..=hi).contains(&fr.field)
            {
                Some(fr.rva)
            } else {
                None
            }
        })
        .or_else(|| {
            tables
                .field_rvas
                .iter()
                .max_by_key(|fr: &&FieldRvaRow| fr.rva)
                .map(|fr: &FieldRvaRow| fr.rva)
        })?;
    Some(EncryptedBlobLocator {
        rva: candidate_rva,
        size: layout.class_size,
    })
}

fn field_range_for_typedef(tables: &Tables, parent_typedef: u32) -> Option<(u32, u32)> {
    if parent_typedef == 0 {
        return None;
    }
    let idx: usize = (parent_typedef as usize).checked_sub(1)?;
    let typedef: &crate::tables::TypeDefRow = tables.type_defs.get(idx)?;
    let lo: u32 = typedef.field_list;
    let hi: u32 = tables.type_defs.get(idx + 1).map_or_else(
        || u32::try_from(tables.fields.len()).unwrap_or(u32::MAX),
        |next: &crate::tables::TypeDefRow| next.field_list.saturating_sub(1),
    );
    if lo == 0 || hi == 0 || hi < lo {
        return None;
    }
    Some((lo, hi))
}

fn extract_blob_bytes(image: &[u8], pe: &PeImage, rva: u32, size: u32) -> Result<Vec<u8>> {
    let size_usize: usize = size as usize;
    if size_usize > MAX_ENCRYPTED_BLOB_BYTES {
        return Err(Error::Truncated {
            offset: rva as usize,
            needed: size_usize,
            had: MAX_ENCRYPTED_BLOB_BYTES,
        });
    }
    let slice: &[u8] = pe.slice_at_rva(image, rva, size_usize)?;
    Ok(slice.to_vec())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let digest: sha2::digest::generic_array::GenericArray<u8, _> = hasher.finalize();
    let mut out: [u8; 32] = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

fn collect_ldc_i4_immediates(image: &[u8], pe: &PeImage, methods: &[MethodDefRow]) -> Vec<u32> {
    let mut pool: BTreeSet<u32> = BTreeSet::new();
    for method in methods {
        if method.rva == 0 {
            continue;
        }
        let Some(off): Option<usize> = pe.rva_to_offset(method.rva) else {
            continue;
        };
        if off >= image.len() {
            continue;
        }
        let Ok(body): Result<MethodBody> = parse_method_body(&image[off..]) else {
            continue;
        };
        for instr in &body.instructions {
            match (&instr.name, &instr.operand) {
                (name, OperandValue::I32(v)) if name == "ldc.i4" => {
                    pool.insert(*v as u32);
                }
                (name, OperandValue::U8(v)) if name == "ldc.i4.s" => {
                    pool.insert(i32::from(*v as i8) as u32);
                }
                _ => {}
            }
        }
        if pool.len() > MAX_SEED_CANDIDATES {
            break;
        }
    }
    pool.into_iter().collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_plaintext(uncompressed_size: u32) -> Vec<u8> {
        let mut pt: Vec<u8> = Vec::with_capacity(64);
        pt.push(CONFUSEREX_LZMA_PROPS);
        pt.extend_from_slice(&CONFUSEREX_LZMA_DICT.to_le_bytes());
        pt.extend_from_slice(&uncompressed_size.to_le_bytes());
        while pt.len() < 64 {
            pt.push((pt.len() as u8).wrapping_mul(31));
        }
        pt
    }

    #[test]
    fn derive_key_is_deterministic_for_a_seed() {
        let a: [u32; 16] = derive_key(0x1234_5678);
        let b: [u32; 16] = derive_key(0x1234_5678);
        assert_eq!(a, b);
        let c: [u32; 16] = derive_key(0x1234_5679);
        assert_ne!(a, c);
    }

    #[test]
    fn derive_key_matches_xorshift_first_step() {
        let mut state: u32 = 0x1000_0010;
        state ^= state >> 13;
        state ^= state << 25;
        state ^= state >> 27;
        let key: [u32; 16] = derive_key(0x1000_0010);
        assert_eq!(key[0], state);
    }

    #[test]
    fn synthetic_round_trip_recovers_plaintext() {
        let pt: Vec<u8> = synth_plaintext(1024);
        assert_eq!(pt.len() % CONFUSEREX_BLOCK_BYTES, 0);
        let seed: u32 = 0xDEAD_BEEF | 0x10;
        let enc: Vec<u8> = encrypt_blob(&pt, seed);
        let dec: Vec<u8> = decrypt_blob(&enc, seed).expect("decrypt ok");
        assert_eq!(dec, pt, "round-trip must recover identical bytes");
    }

    #[test]
    fn synthetic_round_trip_two_block_buffer() {
        let mut pt: Vec<u8> = Vec::with_capacity(128);
        pt.push(CONFUSEREX_LZMA_PROPS);
        pt.extend_from_slice(&CONFUSEREX_LZMA_DICT.to_le_bytes());
        pt.extend_from_slice(&777u32.to_le_bytes());
        while pt.len() < 128 {
            pt.push(((pt.len() ^ 0xAB) & 0xFF) as u8);
        }
        let seed: u32 = 1;
        let enc: Vec<u8> = encrypt_blob(&pt, seed);
        let dec: Vec<u8> = decrypt_blob(&enc, seed).expect("decrypt ok");
        assert_eq!(dec, pt);
    }

    #[test]
    fn synthetic_oracle_validates_recovered_plaintext() {
        let pt: Vec<u8> = synth_plaintext(512);
        assert!(matches_lzma_oracle(&pt));
        let mut bad: Vec<u8> = pt.clone();
        bad[0] ^= 0xFF;
        assert!(!matches_lzma_oracle(&bad));
        let mut bad2: Vec<u8> = pt;
        bad2[1] = 0xFF;
        assert!(!matches_lzma_oracle(&bad2));
    }

    #[test]
    fn wrong_seed_does_not_satisfy_oracle() {
        let pt: Vec<u8> = synth_plaintext(2048);
        let seed: u32 = 0xCAFE_F00D;
        let enc: Vec<u8> = encrypt_blob(&pt, seed);
        let wrong: Vec<u8> = decrypt_blob(&enc, seed.wrapping_add(1)).expect("dec");
        assert!(!matches_lzma_oracle(&wrong));
    }

    #[test]
    fn decrypt_rejects_unaligned_blob() {
        assert!(decrypt_blob(&[], 1).is_none());
        let unaligned: Vec<u8> = vec![0u8; 63];
        assert!(decrypt_blob(&unaligned, 1).is_none());
        let aligned: Vec<u8> = vec![0u8; 64];
        assert!(decrypt_blob(&aligned, 1).is_some());
    }

    #[test]
    fn oracle_rejects_short_buffers() {
        assert!(!matches_lzma_oracle(&[]));
        assert!(!matches_lzma_oracle(&[CONFUSEREX_LZMA_PROPS; 12]));
    }

    #[test]
    fn round_trip_then_decrypt_then_lzma_oracle_passes() {
        let mut pt: Vec<u8> = Vec::with_capacity(192);
        pt.push(CONFUSEREX_LZMA_PROPS);
        pt.extend_from_slice(&CONFUSEREX_LZMA_DICT.to_le_bytes());
        pt.extend_from_slice(&5_000u32.to_le_bytes());
        while pt.len() < 192 {
            pt.push(((pt.len() as u32).wrapping_mul(0x9E37_79B9) & 0xFF) as u8);
        }
        let seed: u32 = 0xFEED_BEEF;
        let enc: Vec<u8> = encrypt_blob(&pt, seed);
        let dec: Vec<u8> = decrypt_blob(&enc, seed).expect("dec");
        assert!(matches_lzma_oracle(&dec));
    }

    #[test]
    fn classify_handles_empty_table() {
        let r: ManifestResourceClassification = classify_manifest_resources(&[]);
        assert_eq!(r.total, 0);
        assert_eq!(r.embedded, 0);
        assert_eq!(r.linked, 0);
    }
}
