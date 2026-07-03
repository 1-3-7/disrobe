#![allow(clippy::doc_markdown)]
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::{
    MetadataRoot, StreamHeader, decompress_uint, parse_metadata_root, read_strings_heap,
};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::dotnet_crypto::{
    CryptoError, aes256_cbc_decrypt_no_pad, des_cbc_decrypt, strip_pkcs7,
};
use crate::tables::{
    AssemblyRow, FieldRow, FieldRvaRow, ManifestResourceRow, Tables, parse_tables,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceStringRecovery {
    pub resource_name: String,
    pub resource_size: u32,
    pub scheme: String,
    pub strings: Vec<String>,
    pub dynamic_wall: Option<String>,
}

const MAX_RESOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STRINGS: usize = 65_536;

struct ImageView {
    pe: PeImage,
    clr: ClrHeader,
    tables: Tables,
    strings: std::collections::BTreeMap<u32, String>,
    blob: Vec<u8>,
}

fn load_image(image: &[u8]) -> Result<ImageView> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] =
        pe.slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)?;
    let table_header: StreamHeader = *root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .ok_or_else(|| crate::error::Error::UnknownStream("#~".to_string()))?;
    let tables: Tables = parse_tables(metadata_slice, table_header)?;
    let strings: std::collections::BTreeMap<u32, String> = root
        .streams
        .get("#Strings")
        .map(|h: &StreamHeader| read_strings_heap(metadata_slice, *h))
        .unwrap_or_default();
    let blob: Vec<u8> = root
        .streams
        .get("#Blob")
        .map_or_else(Vec::new, |h: &StreamHeader| {
            let off: usize = h.offset as usize;
            let end: usize = off
                .saturating_add(h.size as usize)
                .min(metadata_slice.len());
            metadata_slice
                .get(off..end)
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        });
    Ok(ImageView {
        pe,
        clr,
        tables,
        strings,
        blob,
    })
}

fn blob_at(blob: &[u8], offset: u32) -> Option<&[u8]> {
    let off: usize = offset as usize;
    let (len, consumed): (u32, usize) = decompress_uint(blob.get(off..)?)?;
    let start: usize = off + consumed;
    blob.get(start..start + len as usize)
}

fn string_at(strings: &std::collections::BTreeMap<u32, String>, off: u32) -> Option<String> {
    strings.get(&off).cloned()
}

fn assembly_simple_name(view: &ImageView) -> Option<String> {
    let asm: &AssemblyRow = view.tables.assembly.as_ref()?;
    string_at(&view.strings, asm.name)
}

fn embedded_resource_bytes(
    image: &[u8],
    view: &ImageView,
    row: &ManifestResourceRow,
) -> Option<Vec<u8>> {
    if row.implementation.is_some() {
        return None;
    }
    let base_rva: u32 = view.clr.resources.rva.checked_add(row.offset)?;
    let header: &[u8] = view.pe.slice_at_rva(image, base_rva, 4).ok()?;
    let len: usize = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if len == 0 || len > MAX_RESOURCE_BYTES {
        return None;
    }
    let body: &[u8] = view
        .pe
        .slice_at_rva(image, base_rva.checked_add(4)?, len)
        .ok()?;
    Some(body.to_vec())
}

fn field_rva_blob(image: &[u8], view: &ImageView, field_rid: u32, len: usize) -> Option<Vec<u8>> {
    let row: &FieldRvaRow = view
        .tables
        .field_rvas
        .iter()
        .find(|fr: &&FieldRvaRow| fr.field == field_rid)?;
    let slice: &[u8] = view.pe.slice_at_rva(image, row.rva, len).ok()?;
    Some(slice.to_vec())
}

fn field_rid_by_name(view: &ImageView, name: &str) -> Option<u32> {
    view.tables
        .fields
        .iter()
        .enumerate()
        .find_map(|(i, f): (usize, &FieldRow)| {
            (string_at(&view.strings, f.name).as_deref() == Some(name))
                .then(|| u32::try_from(i + 1).unwrap_or(u32::MAX))
        })
}

fn first_resource(view: &ImageView) -> Option<&ManifestResourceRow> {
    view.tables
        .manifest_resources
        .iter()
        .find(|r: &&ManifestResourceRow| r.implementation.is_none())
}

fn parse_varint(data: &[u8], pos: &mut usize) -> Option<usize> {
    let b0: u8 = *data.get(*pos)?;
    *pos += 1;
    if b0 & 0x80 == 0 {
        return Some(usize::from(b0));
    }
    if b0 & 0xC0 == 0x80 {
        let b1: u8 = *data.get(*pos)?;
        *pos += 1;
        return Some(((usize::from(b0) & 0x3F) << 8) | usize::from(b1));
    }
    let b1: u8 = *data.get(*pos)?;
    let b2: u8 = *data.get(*pos + 1)?;
    let b3: u8 = *data.get(*pos + 2)?;
    *pos += 3;
    Some(
        ((usize::from(b0) & 0x1F) << 24)
            | (usize::from(b1) << 16)
            | (usize::from(b2) << 8)
            | usize::from(b3),
    )
}

fn read_unicode_records_varint(blob: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pos: usize = 0;
    while pos < blob.len() {
        let Some(byte_len): Option<usize> = parse_varint(blob, &mut pos) else {
            break;
        };
        if byte_len == 0 || pos.saturating_add(byte_len) > blob.len() || !byte_len.is_multiple_of(2)
        {
            break;
        }
        let units: Vec<u16> = blob[pos..pos + byte_len]
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(String::from_utf16_lossy(&units));
        pos += byte_len;
        if out.len() >= MAX_STRINGS {
            break;
        }
    }
    out
}

fn read_unicode_records_varint_strict(blob: &[u8]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut pos: usize = 0;
    while pos < blob.len() {
        let byte_len: usize = parse_varint(blob, &mut pos)?;
        if byte_len == 0 || pos.saturating_add(byte_len) > blob.len() || !byte_len.is_multiple_of(2)
        {
            return None;
        }
        let units: Vec<u16> = blob[pos..pos + byte_len]
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(String::from_utf16_lossy(&units));
        pos += byte_len;
        if out.len() >= MAX_STRINGS {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn read_unicode_records_int32(blob: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pos: usize = 0;
    while pos + 4 <= blob.len() {
        let byte_len: usize =
            u32::from_le_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]) as usize;
        pos += 4;
        if byte_len == 0 || pos.saturating_add(byte_len) > blob.len() || !byte_len.is_multiple_of(2)
        {
            break;
        }
        let units: Vec<u16> = blob[pos..pos + byte_len]
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(String::from_utf16_lossy(&units));
        pos += byte_len;
        if out.len() >= MAX_STRINGS {
            break;
        }
    }
    out
}

fn read_binaryreader_strings_utf8(blob: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pos: usize = 0;
    while pos < blob.len() {
        let mut byte_len: usize = 0;
        let mut shift: u32 = 0;
        loop {
            let b: u8 = match blob.get(pos) {
                Some(&b) => b,
                None => return out,
            };
            pos += 1;
            byte_len |= usize::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return out;
            }
        }
        if byte_len == 0 || pos.saturating_add(byte_len) > blob.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&blob[pos..pos + byte_len]).into_owned());
        pos += byte_len;
        if out.len() >= MAX_STRINGS {
            break;
        }
    }
    out
}

pub const CRYPTO_OBFUSCATOR_DES_FLAG: u8 = 1;
pub const CRYPTO_OBFUSCATOR_DEFLATE_FLAG: u8 = 2;
pub const CRYPTO_OBFUSCATOR_NOT_FLAG: u8 = 4;

#[must_use]
pub fn recover_crypto_obfuscator_strings(image: &[u8]) -> Option<ResourceStringRecovery> {
    let view: ImageView = load_image(image).ok()?;
    let asm_name: Option<String> = assembly_simple_name(&view);
    let target: Option<(String, Vec<u8>)> =
        pick_crypto_obfuscator_resource(image, &view, asm_name.as_deref());
    let (resource_name, blob): (String, Vec<u8>) = target?;
    let resource_size: u32 = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    let mut recovery: ResourceStringRecovery = ResourceStringRecovery {
        resource_name,
        resource_size,
        scheme: "CryptoObfuscator DES-CBC resource (inline IV+key), varint-prefixed UTF-16 records"
            .to_string(),
        strings: Vec::new(),
        dynamic_wall: None,
    };
    match crypto_obfuscator_decrypt_blob(&blob) {
        Ok((plain, ignored_flags)) => {
            if ignored_flags != 0 {
                recovery.scheme = format!(
                    "{}; ignored unsupported flag mask 0x{ignored_flags:02X} after resource-stage validation",
                    recovery.scheme
                );
                match read_unicode_records_varint_strict(&plain) {
                    Some(strings) => recovery.strings = strings,
                    None => {
                        recovery.dynamic_wall = Some(format!(
                            "CryptoObfuscator resource carries unsupported encryption flag mask \
                             0x{ignored_flags:02X}; the supported stages decoded to data that is not \
                             a valid UTF-16 record stream, so the unknown bit is not an ignorable \
                             no-op here and the layout is not statically determined"
                        ));
                    }
                }
            } else {
                recovery.strings = read_unicode_records_varint(&plain);
            }
        }
        Err(reason) => {
            recovery.dynamic_wall = Some(reason);
        }
    }
    Some(recovery)
}

fn pick_crypto_obfuscator_resource(
    image: &[u8],
    view: &ImageView,
    asm_name: Option<&str>,
) -> Option<(String, Vec<u8>)> {
    let preferred: Option<String> = asm_name.map(|n: &str| format!("{n}{n}"));
    let mut fallback: Option<(String, Vec<u8>)> = None;
    for row in &view.tables.manifest_resources {
        if row.implementation.is_some() {
            continue;
        }
        let name: String = string_at(&view.strings, row.name).unwrap_or_default();
        let Some(bytes): Option<Vec<u8>> = embedded_resource_bytes(image, view, row) else {
            continue;
        };
        if Some(&name) == preferred.as_ref() {
            return Some((name, bytes));
        }
        if fallback.is_none() {
            fallback = Some((name, bytes));
        }
    }
    fallback
}

fn crypto_obfuscator_decrypt_blob(blob: &[u8]) -> std::result::Result<(Vec<u8>, u8), String> {
    if blob.is_empty() {
        return Err("CryptoObfuscator resource is empty".to_string());
    }
    let flags: u8 = blob[0];
    let all_flags: u8 =
        CRYPTO_OBFUSCATOR_DES_FLAG | CRYPTO_OBFUSCATOR_DEFLATE_FLAG | CRYPTO_OBFUSCATOR_NOT_FLAG;
    let supported_flags: u8 = flags & all_flags;
    let ignored_flags: u8 = flags & !all_flags;
    if ignored_flags != 0 && supported_flags == 0 {
        let candidate: &[u8] = &blob[1..];
        if read_unicode_records_varint_strict(candidate).is_some() {
            return Ok((candidate.to_vec(), ignored_flags));
        }
        return Err(format!(
            "CryptoObfuscator resource carries unsupported encryption flag mask 0x{ignored_flags:02X} \
             with no supported resource stages set; plaintext UTF-16 record probe failed"
        ));
    }
    let mut data: Vec<u8> = if flags & CRYPTO_OBFUSCATOR_DES_FLAG != 0 {
        if blob.len() < 17 {
            return Err(
                "CryptoObfuscator DES header truncated (need 8-byte IV + 8-byte key)".to_string(),
            );
        }
        let mut iv: [u8; 8] = [0u8; 8];
        iv.copy_from_slice(&blob[1..9]);
        let mut key: [u8; 8] = [0u8; 8];
        key.copy_from_slice(&blob[9..17]);
        if key.iter().all(|&b: &u8| b == 0) {
            return Err(
                "CryptoObfuscator DES key is all-zero; the reference algorithm falls back to the \
                 assembly PublicKeyToken, which is absent from this unsigned image"
                    .to_string(),
            );
        }
        match des_cbc_decrypt(key, iv, &blob[17..]) {
            Ok(d) => d,
            Err(CryptoError::BadBlockAlignment) => {
                return Err(
                    "CryptoObfuscator DES ciphertext is not an 8-byte multiple after the header"
                        .to_string(),
                );
            }
            Err(_) => return Err("CryptoObfuscator DES ciphertext empty".to_string()),
        }
    } else {
        blob[1..].to_vec()
    };
    if flags & CRYPTO_OBFUSCATOR_DEFLATE_FLAG != 0 {
        data = inflate_raw(&data).map_err(|_e: ()| {
            "CryptoObfuscator deflate block (block-size/complement) failed to inflate; this is the \
             documented deflate-failure edge case"
                .to_string()
        })?;
    }
    if flags & CRYPTO_OBFUSCATOR_NOT_FLAG != 0 {
        for b in &mut data {
            *b = !*b;
        }
    }
    Ok((data, ignored_flags))
}

fn inflate_raw(data: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    inflate_raw_to_limit(data, MAX_RESOURCE_BYTES)
}

fn inflate_raw_to_limit(data: &[u8], limit: usize) -> std::result::Result<Vec<u8>, ()> {
    use std::io::Read;
    let limit_u64: u64 = u64::try_from(limit).map_err(|_e: std::num::TryFromIntError| ())?;
    let decoder: flate2::read::DeflateDecoder<&[u8]> = flate2::read::DeflateDecoder::new(data);
    let mut limited: std::io::Take<flate2::read::DeflateDecoder<&[u8]>> =
        decoder.take(limit_u64.saturating_add(1));
    let mut out: Vec<u8> = Vec::with_capacity(data.len().saturating_mul(4).min(limit));
    limited
        .read_to_end(&mut out)
        .map_err(|_e: std::io::Error| ())?;
    if out.len() > limit {
        return Err(());
    }
    Ok(out)
}

#[must_use]
pub fn recover_babel_strings(image: &[u8]) -> Option<ResourceStringRecovery> {
    let view: ImageView = load_image(image).ok()?;
    let row: &ManifestResourceRow = first_resource(&view)?;
    let resource_name: String = string_at(&view.strings, row.name).unwrap_or_default();
    let blob: Vec<u8> = embedded_resource_bytes(image, &view, row)?;
    let resource_size: u32 = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    let mut recovery: ResourceStringRecovery = ResourceStringRecovery {
        resource_name,
        resource_size,
        scheme: "Babel DES-CBC resource (header IV+embedded key), BinaryReader UTF-8 records"
            .to_string(),
        strings: Vec::new(),
        dynamic_wall: None,
    };
    match babel_decrypt_blob(&blob, assembly_public_key(&view).as_deref()) {
        Ok(plain) => {
            recovery.strings = read_binaryreader_strings_utf8(&plain);
        }
        Err(reason) => {
            recovery.dynamic_wall = Some(reason);
        }
    }
    Some(recovery)
}

fn assembly_public_key(view: &ImageView) -> Option<Vec<u8>> {
    let asm: &AssemblyRow = view.tables.assembly.as_ref()?;
    if asm.public_key == 0 {
        return None;
    }
    let pk: &[u8] = blob_at(&view.blob, asm.public_key)?;
    (!pk.is_empty()).then(|| pk.to_vec())
}

fn babel_decrypt_blob(
    blob: &[u8],
    public_key: Option<&[u8]>,
) -> std::result::Result<Vec<u8>, String> {
    if blob.len() < 2 {
        return Err("Babel resource header truncated".to_string());
    }
    let mut pos: usize = 0;
    let iv_len: usize = usize::from(blob[pos]);
    pos += 1;
    if pos + iv_len + 1 > blob.len() || iv_len != 8 {
        return Err(format!(
            "Babel resource IV length {iv_len} is not the 8-byte DES IV this decrypter handles"
        ));
    }
    let mut iv: [u8; 8] = [0u8; 8];
    iv.copy_from_slice(&blob[pos..pos + 8]);
    pos += 8;
    let has_embedded_key: bool = blob[pos] != 0;
    pos += 1;
    let key_len: usize = usize::from(*blob.get(pos).ok_or("Babel key length truncated")?);
    pos += 1;
    if key_len != 8 {
        return Err(format!(
            "Babel key length {key_len} is not the 8-byte DES key this decrypter handles"
        ));
    }
    let mut key: [u8; 8] = [0u8; 8];
    if has_embedded_key {
        if pos + key_len > blob.len() {
            return Err("Babel embedded key truncated".to_string());
        }
        key.copy_from_slice(&blob[pos..pos + 8]);
        pos += 8;
    } else {
        let Some(pk): Option<&[u8]> = public_key else {
            return Err(
                "Babel resource keys off the assembly PublicKey, which is absent from this \
                 unsigned image; the key is not statically present"
                    .to_string(),
            );
        };
        if pk.len() < 8 {
            return Err("Babel PublicKey-derived key shorter than the 8-byte DES key".to_string());
        }
        key.copy_from_slice(&pk[..8]);
    }
    let cipher: &[u8] = blob.get(pos..).unwrap_or(&[]);
    match des_cbc_decrypt(key, iv, cipher) {
        Ok(plain) => Ok(strip_pkcs7(&plain, 8)),
        Err(CryptoError::BadBlockAlignment) => {
            Err("Babel DES ciphertext is not an 8-byte multiple".to_string())
        }
        Err(_) => Err("Babel DES ciphertext empty".to_string()),
    }
}

#[must_use]
pub fn recover_dotnet_reactor_strings(image: &[u8]) -> Option<ResourceStringRecovery> {
    let view: ImageView = load_image(image).ok()?;
    let row: &ManifestResourceRow = first_resource(&view)?;
    let resource_name: String = string_at(&view.strings, row.name).unwrap_or_default();
    let blob: Vec<u8> = embedded_resource_bytes(image, &view, row)?;
    let resource_size: u32 = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    let mut recovery: ResourceStringRecovery = ResourceStringRecovery {
        resource_name,
        resource_size,
        scheme: "Reactor AES-256-CBC resource (key/IV in initialized data fields), int32-prefixed \
                 UTF-16 records"
            .to_string(),
        strings: Vec::new(),
        dynamic_wall: None,
    };
    match reactor_decrypt_blob(image, &view, &blob) {
        Ok(plain) => {
            recovery.strings = read_unicode_records_int32(&plain);
        }
        Err(reason) => {
            recovery.dynamic_wall = Some(reason);
        }
    }
    Some(recovery)
}

const REACTOR_KEY_FIELD: &str = "rk";
const REACTOR_IV_FIELD: &str = "ri";

fn reactor_decrypt_blob(
    image: &[u8],
    view: &ImageView,
    blob: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    let key_rid: u32 = field_rid_by_name(view, REACTOR_KEY_FIELD)
        .or_else(|| reactor_field_rid_by_len(image, view, 32))
        .ok_or_else(|| {
            "Reactor 32-byte Rijndael key field not located in the initialized-data fields"
                .to_string()
        })?;
    let iv_rid: u32 = field_rid_by_name(view, REACTOR_IV_FIELD)
        .or_else(|| reactor_field_rid_by_len(image, view, 16))
        .ok_or_else(|| {
            "Reactor 16-byte Rijndael IV field not located in the initialized-data fields"
                .to_string()
        })?;
    let key_vec: Vec<u8> = field_rva_blob(image, view, key_rid, 32)
        .ok_or_else(|| "Reactor key field has no readable 32-byte static data".to_string())?;
    let iv_vec: Vec<u8> = field_rva_blob(image, view, iv_rid, 16)
        .ok_or_else(|| "Reactor IV field has no readable 16-byte static data".to_string())?;
    let mut key: [u8; 32] = [0u8; 32];
    key.copy_from_slice(&key_vec);
    let mut iv: [u8; 16] = [0u8; 16];
    iv.copy_from_slice(&iv_vec);
    if reactor_uses_pkt_mix(image, view) {
        return Err(
            "Reactor mixes the assembly PublicKeyToken into the IV (pkt-index pattern present); the \
             effective IV is only complete in a signed image, so this build's IV is not fully \
             static"
                .to_string(),
        );
    }
    match aes256_cbc_decrypt_no_pad(&key, &iv, blob) {
        Ok(plain) => Ok(strip_pkcs7(&plain, 16)),
        Err(CryptoError::BadBlockAlignment) => {
            Err("Reactor AES ciphertext is not a 16-byte multiple".to_string())
        }
        Err(_) => Err("Reactor AES ciphertext empty".to_string()),
    }
}

fn reactor_field_rid_by_len(image: &[u8], view: &ImageView, len: usize) -> Option<u32> {
    view.tables.field_rvas.iter().find_map(|fr: &FieldRvaRow| {
        field_rva_blob(image, view, fr.field, len).map(|_b: Vec<u8>| fr.field)
    })
}

const REACTOR_PKT_INDEX_PATTERN: [i64; 16] = [1, 0, 3, 1, 5, 2, 7, 3, 9, 4, 11, 5, 13, 6, 15, 7];

fn reactor_uses_pkt_mix(image: &[u8], view: &ImageView) -> bool {
    use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
    for method in &view.tables.methods {
        if method.rva == 0 {
            continue;
        }
        let Some(off): Option<usize> = view.pe.rva_to_offset(method.rva) else {
            continue;
        };
        let Some(slice): Option<&[u8]> = image.get(off..) else {
            continue;
        };
        let Ok(body): Result<MethodBody> = parse_method_body(slice) else {
            continue;
        };
        let mut matched: usize = 0;
        for ins in &body.instructions {
            let value: Option<i64> = match (&ins.name, &ins.operand) {
                (name, OperandValue::I32(v)) if name == "ldc.i4" => Some(i64::from(*v)),
                (name, OperandValue::U8(v)) if name == "ldc.i4.s" => Some(i64::from(*v as i8)),
                (name, _) if name.starts_with("ldc.i4.") => name
                    .rsplit('.')
                    .next()
                    .and_then(|d: &str| d.parse::<i64>().ok()),
                _ => None,
            };
            let _: &Instruction = ins;
            if let Some(v) = value {
                if v == REACTOR_PKT_INDEX_PATTERN[matched] {
                    matched += 1;
                    if matched == REACTOR_PKT_INDEX_PATTERN.len() {
                        return true;
                    }
                } else {
                    matched = usize::from(v == REACTOR_PKT_INDEX_PATTERN[0]);
                }
            }
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::*;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder: DeflateEncoder<Vec<u8>> =
            DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("deflate write");
        encoder.finish().expect("deflate finish")
    }

    #[test]
    fn varint_decodes_one_two_four_byte_forms() {
        let mut p: usize = 0;
        assert_eq!(parse_varint(&[0x03], &mut p), Some(3));
        let mut p2: usize = 0;
        assert_eq!(parse_varint(&[0x80, 0x80], &mut p2), Some(0x80));
        let mut p3: usize = 0;
        assert_eq!(
            parse_varint(&[0xC0, 0x00, 0x40, 0x00], &mut p3),
            Some(0x4000)
        );
    }

    #[test]
    fn unsupported_only_flag_is_walled_not_faked() {
        let blob: Vec<u8> = vec![0x08, 0, 0, 0];
        let err: String = crypto_obfuscator_decrypt_blob(&blob).unwrap_err();
        assert!(err.contains("0x08"));
    }

    #[test]
    fn mixed_flag_decode_returns_raw_data_and_reports_ignored_bits() {
        let payload: Vec<u8> = vec![1, 0, 65, 0];
        let compressed: Vec<u8> = deflate(&payload);
        let mut blob: Vec<u8> = vec![CRYPTO_OBFUSCATOR_DEFLATE_FLAG | 0x08];
        blob.extend_from_slice(&compressed);
        let (plain, ignored_flags): (Vec<u8>, u8) = crypto_obfuscator_decrypt_blob(&blob).unwrap();
        assert_eq!(plain, payload);
        assert_eq!(ignored_flags, 0x08);
    }

    #[test]
    fn mixed_flag_decode_to_non_utf16_walls_at_recovery_layer() {
        let garbage: Vec<u8> = vec![0xFFu8; 7];
        let compressed: Vec<u8> = deflate(&garbage);
        let mut blob: Vec<u8> = vec![CRYPTO_OBFUSCATOR_DEFLATE_FLAG | 0x08];
        blob.extend_from_slice(&compressed);
        let (plain, ignored_flags): (Vec<u8>, u8) = crypto_obfuscator_decrypt_blob(&blob).unwrap();
        assert_eq!(ignored_flags, 0x08);
        assert!(read_unicode_records_varint_strict(&plain).is_none());
    }

    #[test]
    fn babel_unsigned_image_walls_public_key_keyed_path() {
        let mut blob: Vec<u8> = Vec::new();
        blob.push(8);
        blob.extend_from_slice(&[0u8; 8]);
        blob.push(0);
        blob.push(8);
        blob.extend_from_slice(&[0u8; 8]);
        let err: String = babel_decrypt_blob(&blob, None).unwrap_err();
        assert!(err.contains("PublicKey"));
    }

    #[test]
    fn crypto_obfuscator_walls_all_zero_des_key() {
        let mut blob: Vec<u8> = vec![CRYPTO_OBFUSCATOR_DES_FLAG];
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(&[0u8; 8]);
        let err: String = crypto_obfuscator_decrypt_blob(&blob).unwrap_err();
        assert!(err.contains("all-zero"));
    }

    #[test]
    fn raw_deflate_over_limit_errors() {
        let payload: Vec<u8> = vec![0u8; 33];
        let compressed: Vec<u8> = deflate(&payload);
        assert!(inflate_raw_to_limit(&compressed, 32).is_err());
    }
}
