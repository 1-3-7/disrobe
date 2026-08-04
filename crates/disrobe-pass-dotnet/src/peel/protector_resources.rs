#![allow(clippy::doc_markdown)]
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::{
    MetadataRoot, StreamHeader, decompress_uint, parse_metadata_root, read_strings_heap,
};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
#[cfg(test)]
use crate::peel::dotnet_crypto::strip_pkcs7;
use crate::peel::dotnet_crypto::{CryptoError, des_cbc_decrypt};
use crate::tables::{
    AssemblyRow, ManifestResourceRow, Tables, parse_single_assembly_row, parse_tables,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceStringRecovery {
    pub resource_name: String,
    pub resource_size: u32,
    pub scheme: String,
    pub strings: Vec<String>,
    pub dynamic_wall: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredResource {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub(crate) const MAX_RESOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STRINGS: usize = 65_536;
const MAX_EMBEDDED_RESOURCES: usize = 65_536;

struct ImageView {
    pe: PeImage,
    clr: ClrHeader,
    tables: Tables,
    strings: BTreeMap<u32, String>,
}

fn load_image(image: &[u8]) -> Result<ImageView> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, &pe, &clr, &root)?;
    let table_header: StreamHeader = *root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .ok_or_else(|| crate::error::Error::UnknownStream("#~".to_string()))?;
    let tables: Tables = parse_tables(metadata_slice, table_header)?;
    let strings: BTreeMap<u32, String> = root
        .streams
        .get("#Strings")
        .map(|h: &StreamHeader| read_strings_heap(metadata_slice, *h))
        .unwrap_or_default();
    Ok(ImageView {
        pe,
        clr,
        tables,
        strings,
    })
}

fn string_at(strings: &BTreeMap<u32, String>, off: u32) -> Option<String> {
    strings.get(&off).cloned()
}

fn assembly_simple_name(view: &ImageView) -> Option<String> {
    let asm: &AssemblyRow = view.tables.assembly.as_ref()?;
    string_at(&view.strings, asm.name)
}

fn embedded_resource_bytes<'a>(
    image: &'a [u8],
    view: &ImageView,
    row: &ManifestResourceRow,
) -> Option<&'a [u8]> {
    if row.implementation.is_some() {
        return None;
    }
    let directory_end: u32 = row.offset.checked_add(4)?;
    if directory_end > view.clr.resources.size {
        return None;
    }
    let header_rva: u32 = view.clr.resources.rva.checked_add(row.offset)?;
    let header: &[u8] = view.pe.slice_at_rva(image, header_rva, 4).ok()?;
    let len_u32: u32 = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let len: usize = usize::try_from(len_u32).ok()?;
    if len > MAX_RESOURCE_BYTES {
        return None;
    }
    let body_directory_end: u32 = directory_end.checked_add(len_u32)?;
    if body_directory_end > view.clr.resources.size {
        return None;
    }
    let body_rva: u32 = view.clr.resources.rva.checked_add(directory_end)?;
    view.pe.slice_at_rva(image, body_rva, len).ok()
}

pub(crate) fn map_embedded_resources<T, F>(image: &[u8], mut map: F) -> Option<Vec<T>>
where
    F: FnMut(&str, &[u8]) -> Option<T>,
{
    let view: ImageView = load_image(image).ok()?;
    let embedded_count: usize = view
        .tables
        .manifest_resources
        .iter()
        .filter(|row: &&ManifestResourceRow| row.implementation.is_none())
        .count();
    if embedded_count == 0 || embedded_count > MAX_EMBEDDED_RESOURCES {
        return None;
    }
    let mut mapped: Vec<T> = Vec::new();
    for row in &view.tables.manifest_resources {
        if row.implementation.is_some() {
            continue;
        }
        let Some(name): Option<String> = string_at(&view.strings, row.name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(bytes): Option<&[u8]> = embedded_resource_bytes(image, &view, row) else {
            continue;
        };
        if let Some(value) = map(&name, bytes) {
            mapped.push(value);
        }
    }
    Some(mapped)
}

pub(crate) fn recover_embedded_resources(image: &[u8]) -> Option<Vec<RecoveredResource>> {
    let mut total_bytes: usize = 0;
    let mut limit_exceeded: bool = false;
    let recovered: Vec<RecoveredResource> = map_embedded_resources(image, |name, bytes| {
        if limit_exceeded {
            return None;
        }
        let Some(next_total): Option<usize> = total_bytes.checked_add(bytes.len()) else {
            limit_exceeded = true;
            return None;
        };
        if next_total > MAX_RESOURCE_BYTES {
            limit_exceeded = true;
            return None;
        }
        total_bytes = next_total;
        Some(RecoveredResource {
            name: name.to_string(),
            bytes: bytes.to_vec(),
        })
    })?;
    (!limit_exceeded && !recovered.is_empty()).then_some(recovered)
}

pub(crate) fn is_complete_managed_assembly(image: &[u8]) -> bool {
    let Ok(pe): Result<PeImage> = parse(image) else {
        return false;
    };
    let Some(directory): Option<crate::pe::DataDirectory> = pe.clr_directory() else {
        return false;
    };
    let Ok(clr): Result<ClrHeader> = parse_clr_header(image, &pe) else {
        return false;
    };
    if directory.size < 72 || clr.cb < 72 || clr.cb > directory.size || clr.metadata.size == 0 {
        return false;
    }
    let Ok(root): Result<MetadataRoot> = parse_metadata_root(image, &pe, &clr) else {
        return false;
    };
    let Ok(metadata_size): std::result::Result<usize, std::num::TryFromIntError> =
        usize::try_from(clr.metadata.size)
    else {
        return false;
    };
    let Ok(metadata): Result<&[u8]> = pe.slice_at_rva(image, clr.metadata.rva, metadata_size)
    else {
        return false;
    };
    let Some(table_header): Option<StreamHeader> = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
    else {
        return false;
    };
    let Ok(Some(assembly)): Result<Option<AssemblyRow>> =
        parse_single_assembly_row(metadata, table_header)
    else {
        return false;
    };
    let Some(strings_header): Option<StreamHeader> = root.streams.get("#Strings").copied() else {
        return false;
    };
    let Some(strings): Option<&[u8]> = metadata_stream(metadata, strings_header) else {
        return false;
    };
    if metadata_string(strings, assembly.name).is_none() {
        return false;
    }
    if assembly.culture != 0 && metadata_string(strings, assembly.culture).is_none() {
        return false;
    }
    if assembly.public_key == 0 {
        return true;
    }
    let Some(blob_header): Option<StreamHeader> = root.streams.get("#Blob").copied() else {
        return false;
    };
    metadata_stream(metadata, blob_header)
        .and_then(|blob: &[u8]| metadata_blob(blob, assembly.public_key))
        .is_some()
}

fn metadata_stream(metadata: &[u8], header: StreamHeader) -> Option<&[u8]> {
    let offset: usize = usize::try_from(header.offset).ok()?;
    let size: usize = usize::try_from(header.size).ok()?;
    let end: usize = offset.checked_add(size)?;
    metadata.get(offset..end)
}

fn metadata_string(heap: &[u8], index: u32) -> Option<&str> {
    let offset: usize = usize::try_from(index).ok()?;
    if offset == 0 {
        return None;
    }
    let tail: &[u8] = heap.get(offset..)?;
    let end: usize = tail.iter().position(|byte: &u8| *byte == 0)?;
    if end == 0 {
        return None;
    }
    std::str::from_utf8(tail.get(..end)?).ok()
}

fn metadata_blob(heap: &[u8], index: u32) -> Option<&[u8]> {
    let offset: usize = usize::try_from(index).ok()?;
    let tail: &[u8] = heap.get(offset..)?;
    let (length_u32, prefix): (u32, usize) = decompress_uint(tail)?;
    let length: usize = usize::try_from(length_u32).ok()?;
    let end: usize = prefix.checked_add(length)?;
    tail.get(prefix..end)
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

fn read_unicode_records_int32_strict(blob: &[u8]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut pos: usize = 0;
    while pos < blob.len() {
        let length_end: usize = pos.checked_add(4)?;
        let length_bytes: [u8; 4] = blob.get(pos..length_end)?.try_into().ok()?;
        let signed_len: i32 = i32::from_le_bytes(length_bytes);
        let byte_len: usize = usize::try_from(signed_len).ok()?;
        if !byte_len.is_multiple_of(2) || byte_len > MAX_RESOURCE_BYTES {
            return None;
        }
        pos = length_end;
        let data_end: usize = pos.checked_add(byte_len)?;
        let data: &[u8] = blob.get(pos..data_end)?;
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(String::from_utf16(&units).ok()?);
        pos = data_end;
        if out.len() > MAX_STRINGS {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
fn read_7bit_encoded_len(blob: &[u8], pos: &mut usize) -> Option<usize> {
    let mut byte_len: usize = 0;
    let mut shift: u32 = 0;
    loop {
        let b: u8 = *blob.get(*pos)?;
        *pos += 1;
        if shift > 0 && b == 0 {
            return None;
        }
        byte_len |= usize::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some(byte_len);
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

#[cfg(test)]
fn is_plausible_literal(text: &str) -> bool {
    text.chars()
        .all(|c: char| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
}

#[cfg(test)]
fn read_binaryreader_strings_utf8_strict(blob: &[u8]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut pos: usize = 0;
    let mut non_empty: usize = 0;
    while pos < blob.len() {
        let byte_len: usize = read_7bit_encoded_len(blob, &mut pos)?;
        let end: usize = pos.checked_add(byte_len)?;
        let text: &str = std::str::from_utf8(blob.get(pos..end)?).ok()?;
        if !is_plausible_literal(text) {
            return None;
        }
        non_empty += usize::from(!text.is_empty());
        out.push(text.to_string());
        pos = end;
        if out.len() > MAX_STRINGS {
            return None;
        }
    }
    (non_empty > 0).then_some(out)
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
        let Some(bytes): Option<&[u8]> = embedded_resource_bytes(image, view, row) else {
            continue;
        };
        if Some(&name) == preferred.as_ref() {
            return Some((name, bytes.to_vec()));
        }
        if fallback.is_none() {
            fallback = Some((name, bytes.to_vec()));
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
#[allow(clippy::missing_const_for_fn)]
pub fn recover_babel_strings(_image: &[u8]) -> Option<ResourceStringRecovery> {
    None
}

#[cfg(test)]
fn babel_decrypt_blob(
    blob: &[u8],
    public_key: Option<&[u8]>,
) -> std::result::Result<Vec<String>, String> {
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
    let padded: Vec<u8> = match des_cbc_decrypt(key, iv, cipher) {
        Ok(plain) => plain,
        Err(CryptoError::BadBlockAlignment) => {
            return Err("Babel DES ciphertext is not an 8-byte multiple".to_string());
        }
        Err(_) => return Err("Babel DES ciphertext empty".to_string()),
    };
    let Some(plain): Option<Vec<u8>> = strip_pkcs7(&padded, 8) else {
        return Err(
            "Babel DES plaintext carries no valid PKCS7 padding, so the header IV and key do not \
             decrypt this resource; no strings are reported"
                .to_string(),
        );
    };
    read_binaryreader_strings_utf8_strict(&plain).ok_or_else(|| {
        "Babel DES plaintext does not parse as a complete BinaryWriter UTF-8 record stream of \
         printable literals, so the decryption is rejected and no strings are reported"
            .to_string()
    })
}

mod reactor;

#[must_use]
pub fn recover_dotnet_reactor_strings(image: &[u8]) -> Option<ResourceStringRecovery> {
    reactor::recover(image)
}

#[cfg(test)]
use reactor::{
    ReactorCallShape, ReactorFlow, call_shape_matches, contiguous_dominating,
    direct_static_helper_token, framework_assembly_name_allowed,
    instruction_calls_framework_member, reactor_method_body, resource_result_store, row_ref_token,
    validate_reactor_method_sections,
};
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use crate::cil::{Instruction, MethodBody, OperandValue};
    use crate::model::{MethodModel, Resolver, TypeModel};
    use crate::tables::{RowRef, TableId};

    use super::*;

    const BABEL_HEADER_SELF_AUTHENTICATING: &[u8] =
        include!("../../tests/fixtures/babel_header_self_authenticating.rs.inc");

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
    fn babel_legacy_decoder_accepts_fixture_and_rejects_truncated_ciphertext() {
        let expected: Vec<String> = vec![
            "fabricated-from-header-selected-ciphertext".to_string(),
            "OAuthClientSecret=zZ9-qP1-rT4".to_string(),
            "https://license.example.net/validate".to_string(),
        ];
        let decoded: Vec<String> = babel_decrypt_blob(BABEL_HEADER_SELF_AUTHENTICATING, None)
            .expect("legacy Babel decoder accepts the self-authenticating fixture");
        assert_eq!(decoded, expected);

        let mut truncated: Vec<u8> = BABEL_HEADER_SELF_AUTHENTICATING.to_vec();
        let removed: Option<u8> = truncated.pop();
        assert!(removed.is_some());
        assert!(babel_decrypt_blob(&truncated, None).is_err());
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
    fn invalid_embedded_rows_do_not_report_empty_success() {
        let mut image: Vec<u8> =
            include_bytes!("../../tests/fixtures/smartassembly_resources/SmartAssemblyCompat.dll")
                .to_vec();
        let pe: PeImage = parse(&image).expect("PE");
        let directory: crate::pe::DataDirectory = pe.clr_directory().expect("CLR directory");
        let clr_offset: usize = pe.rva_to_offset(directory.rva).expect("CLR offset");
        let size_offset: usize = clr_offset.checked_add(28).expect("resource size offset");
        let size_end: usize = size_offset.checked_add(4).expect("resource size range");
        image[size_offset..size_end].fill(0);
        assert!(recover_embedded_resources(&image).is_none());
    }

    #[test]
    fn raw_deflate_over_limit_errors() {
        let payload: Vec<u8> = vec![0u8; 33];
        let compressed: Vec<u8> = deflate(&payload);
        assert!(inflate_raw_to_limit(&compressed, 32).is_err());
    }

    #[test]
    fn reactor_records_accept_empty_and_supplementary_strings() {
        let data: Vec<u8> = vec![0, 0, 0, 0, 4, 0, 0, 0, 0x34, 0xD8, 0x1E, 0xDD];
        assert_eq!(
            read_unicode_records_int32_strict(&data),
            Some(vec![String::new(), "\u{1d11e}".to_string()])
        );
    }

    #[test]
    fn reactor_records_reject_incomplete_or_invalid_streams() {
        let cases: [Vec<u8>; 5] = [
            vec![0xFF, 0xFF, 0xFF, 0xFF],
            vec![1, 0, 0, 0, 0],
            vec![2, 0, 0, 0, 65],
            vec![2, 0, 0, 0, 0, 0xD8],
            vec![2, 0, 0, 0, 65, 0, 0],
        ];
        for data in cases {
            assert!(read_unicode_records_int32_strict(&data).is_none());
        }
    }

    #[test]
    fn reactor_framework_shape_rejects_invalid_call_opcode() {
        let image: &[u8] =
            include_bytes!("../../tests/fixtures/dotnet_reactor_strings/ReactorStringsCompat.dll");
        let view: ImageView = load_image(image).expect("managed fixture");
        let root: MetadataRoot =
            parse_metadata_root(image, &view.pe, &view.clr).expect("metadata root");
        let resolver: Resolver =
            Resolver::build(image, &view.pe, &view.clr, &root).expect("resolver");
        let model: crate::model::AssemblyModel = resolver.model();
        let method: &MethodModel = model
            .types
            .iter()
            .flat_map(|ty: &TypeModel| ty.methods.iter())
            .find(|method: &&MethodModel| method.name == "DecryptResource")
            .expect("resource helper");
        let body: MethodBody =
            reactor_method_body(image, &view.pe, method.rva).expect("method body");
        let instruction: &Instruction = body
            .instructions
            .iter()
            .find(|instruction: &&Instruction| {
                instruction_calls_framework_member(
                    &resolver,
                    instruction,
                    "System.Security.Cryptography",
                    "Aes",
                    "Create",
                )
            })
            .expect("AES factory");
        assert!(call_shape_matches(
            &resolver,
            instruction,
            ReactorCallShape::AesCreate
        ));
        let mut invalid: Instruction = instruction.clone();
        invalid.name = "newobj".to_string();
        assert!(!call_shape_matches(
            &resolver,
            &invalid,
            ReactorCallShape::AesCreate
        ));
        let owner: &TypeModel = model
            .types
            .iter()
            .find(|ty: &&TypeModel| {
                ty.methods
                    .iter()
                    .any(|candidate: &MethodModel| candidate.token == method.token)
            })
            .expect("helper owner");
        let entry: &MethodModel = owner
            .methods
            .iter()
            .find(|candidate: &&MethodModel| candidate.name == "Decode")
            .expect("string entry");
        let stack_mutations: [(&MethodModel, &str); 2] = [
            (entry, "Unknown: Reactor string entry max stack is below 4"),
            (method, "Unknown: Reactor helper max stack is below 3"),
        ];
        for (target, expected_note) in stack_mutations {
            let mut mutated: Vec<u8> = image.to_vec();
            let method_offset: usize = view.pe.rva_to_offset(target.rva).expect("method offset");
            let stack_start: usize = method_offset.checked_add(2).expect("max stack offset");
            let stack_end: usize = stack_start.checked_add(2).expect("max stack end");
            mutated
                .get_mut(stack_start..stack_end)
                .expect("max stack bytes")
                .fill(0);
            let recovery: ResourceStringRecovery =
                recover_dotnet_reactor_strings(&mutated).expect("mutated recovery");
            assert!(recovery.strings.is_empty());
            assert!(
                recovery
                    .dynamic_wall
                    .as_deref()
                    .is_some_and(|note: &str| note.contains(expected_note))
            );
        }
        let method_tokens: BTreeSet<u32> = owner
            .methods
            .iter()
            .map(|candidate: &MethodModel| candidate.token)
            .collect();
        let entry_body: MethodBody =
            reactor_method_body(image, &view.pe, entry.rva).expect("entry body");
        let helper_call: &Instruction = entry_body
            .instructions
            .iter()
            .find(|candidate: &&Instruction| {
                direct_static_helper_token(candidate, &method_tokens) == Some(method.token)
            })
            .expect("static helper call");
        let mut invalid_helper: Instruction = helper_call.clone();
        invalid_helper.name = "callvirt".to_string();
        assert_eq!(
            direct_static_helper_token(&invalid_helper, &method_tokens),
            None
        );

        let reverse: &Instruction = body
            .instructions
            .iter()
            .find(|candidate: &&Instruction| {
                instruction_calls_framework_member(
                    &resolver, candidate, "System", "Array", "Reverse",
                )
            })
            .expect("array reversal");
        assert!(call_shape_matches(
            &resolver,
            reverse,
            ReactorCallShape::ReverseArray
        ));
        let OperandValue::Token(method_spec_token): &OperandValue = &reverse.operand else {
            panic!("array reversal token");
        };
        let method_spec_token: u32 = *method_spec_token;
        assert_eq!(
            TableId::from_index(method_spec_token.to_be_bytes()[0]),
            Some(TableId::MethodSpec)
        );
        let method_spec_rid: usize = usize::try_from(method_spec_token & 0x00FF_FFFF)
            .expect("method spec rid")
            .checked_sub(1)
            .expect("nonzero method spec rid");
        let method_spec = resolver
            .tables()
            .method_specs
            .get(method_spec_rid)
            .expect("method spec row");
        let metadata_offset: usize = view
            .pe
            .rva_to_offset(view.clr.metadata.rva)
            .expect("metadata offset");
        let blob_stream: &StreamHeader = root.streams.get("#Blob").expect("blob stream");
        let blob_start: usize = metadata_offset
            .checked_add(usize::try_from(blob_stream.offset).expect("blob offset"))
            .and_then(|offset: usize| {
                offset.checked_add(
                    usize::try_from(method_spec.instantiation).expect("instantiation offset"),
                )
            })
            .expect("method spec blob offset");
        let mut wrong_instantiation: Vec<u8> = image.to_vec();
        let (blob_len, prefix_len): (u32, usize) =
            decompress_uint(&wrong_instantiation[blob_start..]).expect("method spec blob");
        assert_eq!(blob_len, 3);
        let argument_offset: usize = blob_start
            .checked_add(prefix_len)
            .and_then(|offset: usize| offset.checked_add(2))
            .expect("method spec argument offset");
        wrong_instantiation[argument_offset] = 0x08;
        let wrong_view: ImageView = load_image(&wrong_instantiation).expect("mutated fixture");
        let wrong_root: MetadataRoot =
            parse_metadata_root(&wrong_instantiation, &wrong_view.pe, &wrong_view.clr)
                .expect("mutated metadata");
        let wrong_resolver: Resolver = Resolver::build(
            &wrong_instantiation,
            &wrong_view.pe,
            &wrong_view.clr,
            &wrong_root,
        )
        .expect("mutated resolver");
        let wrong_model: crate::model::AssemblyModel = wrong_resolver.model();
        let wrong_method: &MethodModel = wrong_model
            .types
            .iter()
            .flat_map(|ty: &TypeModel| ty.methods.iter())
            .find(|candidate: &&MethodModel| candidate.name == "DecryptResource")
            .expect("mutated helper");
        let wrong_body: MethodBody =
            reactor_method_body(&wrong_instantiation, &wrong_view.pe, wrong_method.rva)
                .expect("mutated method body");
        let wrong_reverse: &Instruction = wrong_body
            .instructions
            .iter()
            .find(|candidate: &&Instruction| {
                instruction_calls_framework_member(
                    &wrong_resolver,
                    candidate,
                    "System",
                    "Array",
                    "Reverse",
                )
            })
            .expect("mutated array reversal");
        assert!(!call_shape_matches(
            &wrong_resolver,
            wrong_reverse,
            ReactorCallShape::ReverseArray
        ));
    }

    #[test]
    fn reactor_rejects_inverted_guards_and_partial_eh_sections() {
        let image: &[u8] =
            include_bytes!("../../tests/fixtures/dotnet_reactor_strings/ReactorStringsCompat.dll");
        let view: ImageView = load_image(image).expect("managed fixture");
        let root: MetadataRoot =
            parse_metadata_root(image, &view.pe, &view.clr).expect("metadata root");
        let resolver: Resolver =
            Resolver::build(image, &view.pe, &view.clr, &root).expect("resolver");
        let model: crate::model::AssemblyModel = resolver.model();
        let method: &MethodModel = model
            .types
            .iter()
            .flat_map(|ty: &TypeModel| ty.methods.iter())
            .find(|method: &&MethodModel| method.name == "DecryptResource")
            .expect("resource helper");
        let body: MethodBody =
            reactor_method_body(image, &view.pe, method.rva).expect("method body");
        let flow: ReactorFlow = ReactorFlow::build(&body).expect("helper flow");
        let key_call: usize = body
            .instructions
            .iter()
            .enumerate()
            .find(|(_, instruction): &(usize, &Instruction)| {
                instruction_calls_framework_member(
                    &resolver,
                    instruction,
                    "System.Security.Cryptography",
                    "SymmetricAlgorithm",
                    "set_Key",
                )
            })
            .map(|(index, _): (usize, &Instruction)| index)
            .expect("key setter");
        let key_start: usize = key_call.checked_sub(2).expect("key operands");
        let mut bypassed_key: ReactorFlow = flow.clone();
        bypassed_key
            .successors
            .get_mut(0)
            .expect("entry successors")
            .push(key_call);
        assert!(!contiguous_dominating(
            &bypassed_key,
            &[key_start, key_start + 1, key_call],
        ));
        let initializer_calls: Vec<usize> = body
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, instruction): &(usize, &Instruction)| {
                instruction_calls_framework_member(
                    &resolver,
                    instruction,
                    "System.Runtime.CompilerServices",
                    "RuntimeHelpers",
                    "InitializeArray",
                )
            })
            .map(|(index, _): (usize, &Instruction)| index)
            .collect();
        let initializer_call: usize = *initializer_calls.last().expect("array initializer");
        let initializer_start: usize = initializer_call
            .checked_sub(4)
            .expect("initializer operands");
        let initializer_store: usize = initializer_call.checked_add(1).expect("initializer store");
        let initializer_indices: Vec<usize> = (initializer_start..=initializer_store).collect();
        let mut bypassed_initializer: ReactorFlow = flow.clone();
        bypassed_initializer
            .successors
            .get_mut(0)
            .expect("entry successors")
            .push(initializer_store);
        assert!(!contiguous_dominating(
            &bypassed_initializer,
            &initializer_indices,
        ));
        let return_index: usize = body
            .instructions
            .iter()
            .enumerate()
            .find(|(_, instruction): &(usize, &Instruction)| instruction.name == "ret")
            .map(|(index, _): (usize, &Instruction)| index)
            .expect("return");
        let return_load: usize = return_index.checked_sub(1).expect("return load");
        let mut bypassed_return: ReactorFlow = flow.clone();
        bypassed_return
            .successors
            .get_mut(0)
            .expect("entry successors")
            .push(return_index);
        assert!(!contiguous_dominating(
            &bypassed_return,
            &[return_load, return_index],
        ));
        let reverse_index: usize = body
            .instructions
            .iter()
            .enumerate()
            .find(|(_, instruction): &(usize, &Instruction)| {
                instruction_calls_framework_member(
                    &resolver,
                    instruction,
                    "System",
                    "Array",
                    "Reverse",
                )
            })
            .map(|(index, _): (usize, &Instruction)| index)
            .expect("array reversal");
        let mut cyclic: ReactorFlow = flow.clone();
        cyclic
            .successors
            .get_mut(reverse_index)
            .expect("reverse successors")
            .push(reverse_index);
        assert!(cyclic.has_reachable_cycle());
        let resource_call: usize = body
            .instructions
            .iter()
            .enumerate()
            .find(|(_, instruction): &(usize, &Instruction)| {
                instruction_calls_framework_member(
                    &resolver,
                    instruction,
                    "System.Reflection",
                    "Assembly",
                    "GetManifestResourceStream",
                )
            })
            .map(|(index, _): (usize, &Instruction)| index)
            .expect("resource call");
        resource_result_store(&resolver, &body, &flow, resource_call)
            .expect("supported resource binding");
        let guard: usize = resource_call.checked_add(2).expect("resource guard");
        let mut inverted_resource: ReactorFlow = flow.clone();
        inverted_resource
            .successors
            .get_mut(guard)
            .expect("resource guard successors")
            .reverse();
        assert!(
            resource_result_store(&resolver, &body, &inverted_resource, resource_call).is_err()
        );
        let failure_index: usize = *flow
            .successors
            .get(guard)
            .and_then(|successors: &Vec<usize>| successors.get(1))
            .expect("resource failure edge");
        let throw_index: usize = failure_index.checked_add(3).expect("throw index");
        let mut rethrow_body: MethodBody = body;
        rethrow_body
            .instructions
            .get_mut(throw_index)
            .expect("throw instruction")
            .name = "rethrow".to_string();
        assert!(resource_result_store(&resolver, &rethrow_body, &flow, resource_call).is_err());

        let malformed: Vec<u8> = vec![
            0x0B, 0x30, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00,
            0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00,
        ];
        assert!(validate_reactor_method_sections(&malformed, malformed.len()).is_err());

        let unsupported_flags: Vec<u8> = vec![
            0x23, 0x30, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A,
        ];
        assert!(
            validate_reactor_method_sections(&unsupported_flags, unsupported_flags.len()).is_err()
        );
        let extended_header: Vec<u8> = vec![
            0x03, 0x40, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A,
        ];
        assert!(validate_reactor_method_sections(&extended_header, extended_header.len()).is_err());
        assert_eq!(
            row_ref_token(RowRef {
                table: TableId::TypeRef,
                row: 0x0100_0000,
            }),
            None
        );
        assert!(framework_assembly_name_allowed(
            "System.Security.Cryptography",
            "Aes",
            "System.Security.Cryptography.Algorithms",
        ));
        assert!(!framework_assembly_name_allowed(
            "System.Security.Cryptography",
            "Aes",
            "System.Security.Cryptography.Primitives",
        ));
        assert!(framework_assembly_name_allowed(
            "System.Security.Cryptography",
            "CryptoStream",
            "System.Security.Cryptography.Primitives",
        ));
        assert!(!framework_assembly_name_allowed(
            "System.Security.Cryptography",
            "CryptoStream",
            "System.Security.Cryptography.Algorithms",
        ));
    }
}
