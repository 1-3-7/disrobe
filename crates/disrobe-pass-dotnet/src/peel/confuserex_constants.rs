#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cil::{MethodBody, OperandValue, parse_method_body};
use crate::debug::{dbg_hex, dbg_kv};
use crate::error::Result;
use crate::metadata::{StreamHeader, parse_metadata_root};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::confuserex_resources::lzma_decompress;
use crate::tables::{ClassLayoutRow, FieldRow, FieldRvaRow, MethodDefRow, Tables, parse_tables};

pub const CONSTANTS_BLOCK_BYTES: usize = 64;

pub const CONSTANTS_POOL_ALIGN: usize = 4;

pub const CONSTANTS_LZMA_PROPS: u8 = 0x5D;

pub const MAX_CONSTANTS_BLOB_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_CONSTANTS_POOL_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_SEED_CANDIDATES: usize = 65_536;

pub const MAX_DECODE_ATTEMPTS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredString {
    pub call_site_id: u32,
    pub mutated_offset: u32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfuserConstantsRecovery {
    pub blob_rva: u32,
    pub blob_size: u32,
    pub blob_sha256: [u8; 32],
    pub seed: u32,
    pub constant_pool_len: u32,
    pub constant_pool_sha256: [u8; 32],
    pub strings_recovered: Vec<RecoveredString>,
}

#[derive(Debug, Clone, Copy)]
struct BlobLocator {
    rva: u32,
    size: u32,
}

#[derive(Debug, Clone, Copy)]
struct DecoderMutation {
    mul: u32,
    xor: u32,
}

pub fn peel_confuserex_constants(image: &[u8]) -> Result<Option<ConfuserConstantsRecovery>> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: crate::metadata::MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, &pe, &clr, &root)?;
    let Some(table_header): Option<&StreamHeader> =
        root.streams.get("#~").or_else(|| root.streams.get("#-"))
    else {
        return Ok(None);
    };
    let tables: Tables = parse_tables(metadata_slice, *table_header)?;

    let Some(locator): Option<BlobLocator> = locate_constants_blob(&tables) else {
        return Ok(None);
    };
    let blob: Vec<u8> = match pe.slice_at_rva(image, locator.rva, locator.size as usize) {
        Ok(slice) => slice.to_vec(),
        Err(_) => return Ok(None),
    };
    let blob_sha256: [u8; 32] = sha256(&blob);
    dbg_kv("confuserex-constants", || {
        format!(
            "blob@rva=0x{:x} size={} (encrypted constants pool located)",
            locator.rva, locator.size
        )
    });
    dbg_hex("confuserex-blob-head", &blob, 32);

    let mut seeds: Vec<u32> = collect_ldc_i4_immediates(image, &pe, &tables.methods);
    for emulated in
        crate::peel::confuserex_seed::recover_seeds_by_emulation(image, &pe, &tables.methods)
    {
        if !seeds.contains(&emulated) {
            seeds.push(emulated);
        }
    }
    let Some((seed, pool)): Option<(u32, Vec<u8>)> = recover_pool(&blob, &seeds) else {
        dbg_kv("confuserex-constants", || {
            format!(
                "decrypt bail: no seed in {} candidate(s) decrypts the constants blob to a valid lzma pool",
                seeds.len()
            )
        });
        return Ok(None);
    };
    let pool_sha256: [u8; 32] = sha256(&pool);

    let mutations: Vec<DecoderMutation> = collect_decoder_mutations(image, &pe, &tables.methods);
    let mut strings_recovered: Vec<RecoveredString> = recover_strings(&pool, &mutations, &seeds);
    let segmented: Vec<RecoveredString> = segment_pool_strings(&pool, &strings_recovered);
    let segmented_count: usize = segmented.len();
    strings_recovered.extend(segmented);
    dbg_kv("confuserex-constants", || {
        format!(
            "seed=0x{seed:x} decrypted_pool_bytes={} strings_recovered={} \
             (call_site_attributed={} pool_segmented={})",
            pool.len(),
            strings_recovered.len(),
            strings_recovered.len() - segmented_count,
            segmented_count,
        )
    });

    Ok(Some(ConfuserConstantsRecovery {
        blob_rva: locator.rva,
        blob_size: locator.size,
        blob_sha256,
        seed,
        constant_pool_len: u32::try_from(pool.len()).unwrap_or(u32::MAX),
        constant_pool_sha256: pool_sha256,
        strings_recovered,
    }))
}

#[must_use]
pub const fn derive_constants_key(seed: u32) -> [u32; 16] {
    let mut key: [u32; 16] = [0u32; 16];
    let mut state: u32 = seed;
    let mut i: usize = 0;
    while i < 16 {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        key[i] = state;
        i += 1;
    }
    key
}

#[must_use]
pub fn decrypt_constants_blob(encrypted: &[u8], seed: u32) -> Option<Vec<u8>> {
    if encrypted.is_empty() || !encrypted.len().is_multiple_of(CONSTANTS_BLOCK_BYTES) {
        return None;
    }
    let mut out: Vec<u8> = vec![0u8; encrypted.len()];
    let mut key: [u32; 16] = derive_constants_key(seed);
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
        offset += CONSTANTS_BLOCK_BYTES;
    }
    Some(out)
}

#[must_use]
pub const fn mutate_id(id: u32, mutation_mul: u32, mutation_xor: u32) -> (u32, u32) {
    let mutated: u32 = id.wrapping_mul(mutation_mul) ^ mutation_xor;
    let tag: u32 = mutated >> 30;
    let offset: u32 = (mutated & 0x3FFF_FFFF) << 2;
    (tag, offset)
}

#[must_use]
pub fn decode_pool_string(pool: &[u8], byte_offset: u32) -> Option<String> {
    let off: usize = byte_offset as usize;
    let count_end: usize = off.checked_add(4)?;
    if count_end > pool.len() {
        return None;
    }
    let count: usize =
        u32::from_le_bytes([pool[off], pool[off + 1], pool[off + 2], pool[off + 3]]) as usize;
    if count == 0 || count > pool.len() {
        return None;
    }
    let data_end: usize = count_end.checked_add(count)?;
    if data_end > pool.len() {
        return None;
    }
    core::str::from_utf8(&pool[count_end..data_end])
        .ok()
        .map(str::to_owned)
}

fn locate_constants_blob(tables: &Tables) -> Option<BlobLocator> {
    let mut best: Option<BlobLocator> = None;
    for layout in &tables.class_layouts {
        let layout: &ClassLayoutRow = layout;
        let size: usize = layout.class_size as usize;
        if size == 0
            || !size.is_multiple_of(CONSTANTS_BLOCK_BYTES)
            || size > MAX_CONSTANTS_BLOB_BYTES
        {
            continue;
        }
        let Some(field_range): Option<(u32, u32)> = field_range_for_typedef(tables, layout.parent)
        else {
            continue;
        };
        let Some(rva): Option<u32> = tables.field_rvas.iter().find_map(|fr: &FieldRvaRow| {
            (field_range.0..=field_range.1)
                .contains(&fr.field)
                .then_some(fr.rva)
        }) else {
            continue;
        };
        let candidate: BlobLocator = BlobLocator {
            rva,
            size: layout.class_size,
        };
        if best.is_none_or(|b: BlobLocator| candidate.size > b.size) {
            best = Some(candidate);
        }
    }
    if best.is_some() {
        return best;
    }
    let max_rva: u32 = tables
        .field_rvas
        .iter()
        .max_by_key(|fr: &&FieldRvaRow| fr.rva)
        .map(|fr: &FieldRvaRow| fr.rva)?;
    let size: u32 = tables
        .class_layouts
        .iter()
        .map(|cl: &ClassLayoutRow| cl.class_size)
        .filter(|s: &u32| {
            *s != 0
                && (*s as usize).is_multiple_of(CONSTANTS_BLOCK_BYTES)
                && (*s as usize) <= MAX_CONSTANTS_BLOB_BYTES
        })
        .max()?;
    Some(BlobLocator { rva: max_rva, size })
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
    let _owner: Option<&FieldRow> = tables.fields.get((lo as usize).saturating_sub(1));
    Some((lo, hi))
}

fn recover_pool(blob: &[u8], seeds: &[u32]) -> Option<(u32, Vec<u8>)> {
    for (tried, seed) in seeds.iter().enumerate() {
        if tried >= MAX_SEED_CANDIDATES {
            break;
        }
        let Some(plaintext): Option<Vec<u8>> = decrypt_constants_blob(blob, *seed) else {
            continue;
        };
        if plaintext.first() != Some(&CONSTANTS_LZMA_PROPS) || plaintext.len() < 9 {
            continue;
        }
        let uncompressed: usize =
            u32::from_le_bytes([plaintext[5], plaintext[6], plaintext[7], plaintext[8]]) as usize;
        if uncompressed == 0 || uncompressed > MAX_CONSTANTS_POOL_BYTES {
            continue;
        }
        let Ok(pool): Result<Vec<u8>> = lzma_decompress(&plaintext) else {
            continue;
        };
        if pool.len() == uncompressed {
            return Some((*seed, pool));
        }
    }
    None
}

fn recover_strings(
    pool: &[u8],
    mutations: &[DecoderMutation],
    call_site_ids: &[u32],
) -> Vec<RecoveredString> {
    let mut recovered: Vec<RecoveredString> = Vec::new();
    let mut attempts: usize = 0;
    for id in call_site_ids {
        for mutation in mutations {
            attempts += 1;
            if attempts > MAX_DECODE_ATTEMPTS {
                return recovered;
            }
            let (tag, offset): (u32, u32) = mutate_id(*id, mutation.mul, mutation.xor);
            if tag != 0 {
                continue;
            }
            let Some(text): Option<String> = decode_pool_string(pool, offset) else {
                continue;
            };
            if recovered
                .iter()
                .any(|r: &RecoveredString| r.call_site_id == *id && r.text == text)
            {
                continue;
            }
            recovered.push(RecoveredString {
                call_site_id: *id,
                mutated_offset: offset,
                text,
            });
        }
    }
    recovered
}

fn segment_pool_strings(pool: &[u8], attributed: &[RecoveredString]) -> Vec<RecoveredString> {
    if attributed.is_empty() {
        return Vec::new();
    }
    let Some(walk): Option<Vec<(u32, String)>> = walk_length_prefixed_pool(pool) else {
        return Vec::new();
    };
    for entry in attributed {
        let reproduced: bool = walk.iter().any(|(offset, text): &(u32, String)| {
            *offset == entry.mutated_offset && *text == entry.text
        });
        if !reproduced {
            return Vec::new();
        }
    }
    let mut extra: Vec<RecoveredString> = Vec::new();
    for (offset, text) in walk {
        if attributed
            .iter()
            .any(|entry: &RecoveredString| entry.mutated_offset == offset)
        {
            continue;
        }
        extra.push(RecoveredString {
            call_site_id: 0,
            mutated_offset: offset,
            text,
        });
    }
    extra
}

fn walk_length_prefixed_pool(pool: &[u8]) -> Option<Vec<(u32, String)>> {
    let mut walk: Vec<(u32, String)> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < pool.len() {
        let count_end: usize = cursor
            .checked_add(4)
            .filter(|end: &usize| *end <= pool.len())?;
        let count: usize = u32::from_le_bytes([
            pool[cursor],
            pool[cursor + 1],
            pool[cursor + 2],
            pool[cursor + 3],
        ]) as usize;
        if count == 0 {
            return None;
        }
        let data_end: usize = count_end
            .checked_add(count)
            .filter(|end: &usize| *end <= pool.len())?;
        let text: &str = core::str::from_utf8(&pool[count_end..data_end]).ok()?;
        let offset: u32 = u32::try_from(cursor).ok()?;
        walk.push((offset, text.to_owned()));
        let padded: usize = data_end
            .checked_add(CONSTANTS_POOL_ALIGN - 1)
            .map(|end: usize| end / CONSTANTS_POOL_ALIGN * CONSTANTS_POOL_ALIGN)?;
        cursor = padded;
    }
    (cursor == pool.len() && !walk.is_empty()).then_some(walk)
}

fn collect_decoder_mutations(
    image: &[u8],
    pe: &PeImage,
    methods: &[MethodDefRow],
) -> Vec<DecoderMutation> {
    let mut mutations: Vec<DecoderMutation> = Vec::new();
    for method in methods {
        let Some(body): Option<MethodBody> = method_body(image, pe, method) else {
            continue;
        };
        for window in body.instructions.windows(4) {
            let (a, mul_op, b, xor_op): (
                &crate::cil::Instruction,
                &crate::cil::Instruction,
                &crate::cil::Instruction,
                &crate::cil::Instruction,
            ) = (&window[0], &window[1], &window[2], &window[3]);
            if mul_op.name == "mul"
                && xor_op.name == "xor"
                && let Some(mul) = ldc_i4_value(a)
                && let Some(xor) = ldc_i4_value(b)
            {
                let mutation: DecoderMutation = DecoderMutation { mul, xor };
                if !mutations
                    .iter()
                    .any(|m: &DecoderMutation| m.mul == mul && m.xor == xor)
                {
                    mutations.push(mutation);
                }
            }
        }
    }
    mutations
}

fn collect_ldc_i4_immediates(image: &[u8], pe: &PeImage, methods: &[MethodDefRow]) -> Vec<u32> {
    let mut pool: Vec<u32> = Vec::new();
    for method in methods {
        let Some(body): Option<MethodBody> = method_body(image, pe, method) else {
            continue;
        };
        for instr in &body.instructions {
            if let Some(v) = ldc_i4_value(instr)
                && !pool.contains(&v)
            {
                pool.push(v);
            }
        }
        if pool.len() > MAX_SEED_CANDIDATES {
            break;
        }
    }
    pool
}

fn ldc_i4_value(instr: &crate::cil::Instruction) -> Option<u32> {
    match (&instr.name, &instr.operand) {
        (name, OperandValue::I32(v)) if name == "ldc.i4" => Some(*v as u32),
        (name, OperandValue::U8(v)) if name == "ldc.i4.s" => Some(i32::from(*v as i8) as u32),
        _ => None,
    }
}

fn method_body(image: &[u8], pe: &PeImage, method: &MethodDefRow) -> Option<MethodBody> {
    if method.rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(method.rva)?;
    if off >= image.len() {
        return None;
    }
    parse_method_body(&image[off..]).ok()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let digest: sha2::digest::generic_array::GenericArray<u8, _> = hasher.finalize();
    let mut out: [u8; 32] = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_matches_xorshift_first_step() {
        let mut state: u32 = 0xF5F4_A2BF;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let key: [u32; 16] = derive_constants_key(0xF5F4_A2BF);
        assert_eq!(key[0], state);
    }

    #[test]
    fn mutate_id_string_decoder_resolves_offset_zero() {
        let (tag, offset): (u32, u32) =
            mutate_id(1_242_836_064, (-2_012_459_531_i32) as u32, 0x0B27_57E0);
        assert_eq!(tag, 0);
        assert_eq!(offset, 0);
    }

    #[test]
    fn decode_pool_string_reads_count_prefixed_utf8() {
        let mut pool: Vec<u8> = Vec::new();
        let text: &[u8] = b"hello";
        pool.extend_from_slice(&(text.len() as u32).to_le_bytes());
        pool.extend_from_slice(text);
        assert_eq!(decode_pool_string(&pool, 0).as_deref(), Some("hello"));
        assert_eq!(decode_pool_string(&pool, 4), None);
    }

    #[test]
    fn decrypt_rejects_unaligned_blob() {
        assert!(decrypt_constants_blob(&[], 1).is_none());
        assert!(decrypt_constants_blob(&[0u8; 63], 1).is_none());
        assert!(decrypt_constants_blob(&[0u8; 64], 1).is_some());
    }

    fn packed_pool(entries: &[&str]) -> Vec<u8> {
        let mut pool: Vec<u8> = Vec::new();
        for entry in entries {
            pool.extend_from_slice(&(entry.len() as u32).to_le_bytes());
            pool.extend_from_slice(entry.as_bytes());
            while !pool.len().is_multiple_of(CONSTANTS_POOL_ALIGN) {
                pool.push(0);
            }
        }
        pool
    }

    #[test]
    fn segmentation_recovers_unattributed_leading_entry() {
        let pool: Vec<u8> = packed_pool(&["Server=db;", "second"]);
        let second_offset: u32 = {
            let first_len: usize = "Server=db;".len();
            let padded: usize =
                (4 + first_len).div_ceil(CONSTANTS_POOL_ALIGN) * CONSTANTS_POOL_ALIGN;
            u32::try_from(padded).expect("offset")
        };
        let attributed: Vec<RecoveredString> = vec![RecoveredString {
            call_site_id: 0x1234,
            mutated_offset: second_offset,
            text: "second".to_owned(),
        }];
        let extra: Vec<RecoveredString> = segment_pool_strings(&pool, &attributed);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].mutated_offset, 0);
        assert_eq!(extra[0].call_site_id, 0);
        assert_eq!(extra[0].text, "Server=db;");
    }

    #[test]
    fn segmentation_rejects_when_attributed_offset_absent_from_walk() {
        let pool: Vec<u8> = packed_pool(&["alpha", "beta"]);
        let attributed: Vec<RecoveredString> = vec![RecoveredString {
            call_site_id: 0x1,
            mutated_offset: 999,
            text: "alpha".to_owned(),
        }];
        assert!(segment_pool_strings(&pool, &attributed).is_empty());
    }

    #[test]
    fn segmentation_rejects_non_utf8_or_untiled_pool() {
        let attributed: Vec<RecoveredString> = vec![RecoveredString {
            call_site_id: 0x1,
            mutated_offset: 0,
            text: "x".to_owned(),
        }];
        let mut non_utf8: Vec<u8> = Vec::new();
        non_utf8.extend_from_slice(&2u32.to_le_bytes());
        non_utf8.extend_from_slice(&[0xFF, 0xFE]);
        non_utf8.extend_from_slice(&[0, 0]);
        assert!(segment_pool_strings(&non_utf8, &attributed).is_empty());

        let mut untiled: Vec<u8> = Vec::new();
        untiled.extend_from_slice(&64u32.to_le_bytes());
        untiled.extend_from_slice(b"short");
        assert!(segment_pool_strings(&untiled, &attributed).is_empty());
    }

    #[test]
    fn segmentation_ignores_empty_attributed_set() {
        let pool: Vec<u8> = packed_pool(&["one", "two"]);
        assert!(segment_pool_strings(&pool, &[]).is_empty());
    }
}
