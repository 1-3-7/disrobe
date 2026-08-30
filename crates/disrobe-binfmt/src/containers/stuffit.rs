use crate::error::{Error, Result};

const SIT_SIGNATURE: &[u8; 4] = b"SIT!";
const SIT_SIGNATURE2: &[u8; 4] = b"rLau";
const ARCHIVE_HEADER_LEN: usize = 22;
const FILE_HEADER_LEN: usize = 112;
const NAME_FIELD_LEN: usize = 31;
const MAX_RECORDS: usize = 65_535;
const MAX_FOLDER_DEPTH: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
const METHOD_STORED: u8 = 0;
const METHOD_COMPRESS_14: u8 = 2;
const METHOD_LZAH: u8 = 5;
const METHOD_MW: u8 = 8;
const METHOD_13: u8 = 13;
const FLAG_ENCRYPTED: u8 = 0x80;
const FLAG_FOLDER_CONTAINS_ENCRYPTED: u8 = 0x10;
const FLAG_FOLDER_START: u8 = 0x20;
const FLAG_FOLDER_END: u8 = 0x21;
const STREAM_BUFFER_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SitCompression {
    Stored,
    Compress14,
    Lzah,
    Method8,
    Method13,
}

#[derive(Debug, Clone)]
pub struct SitFork {
    pub compression: SitCompression,
    pub uncompressed_len: u32,
    pub compressed_len: u32,
    pub expected_crc: u16,
    pub data_offset: usize,
}

#[derive(Debug, Clone)]
pub struct SitEntry {
    pub name: String,
    pub resource: SitFork,
    pub data: SitFork,
}

#[derive(Debug, Clone)]
pub struct SitArchive {
    pub entries: Vec<SitEntry>,
}

fn stuffit_error(message: impl Into<String>) -> Error {
    Error::StuffIt(message.into())
}

fn rd_u16_be(bytes: &[u8], offset: usize) -> Result<u16> {
    disrobe_bytes::read_u16_be_at(bytes, offset)
        .map_err(|_| stuffit_error("stuffit: truncated u16"))
}

fn rd_u32_be(bytes: &[u8], offset: usize) -> Result<u32> {
    disrobe_bytes::read_u32_be_at(bytes, offset)
        .map_err(|_| stuffit_error("stuffit: truncated u32"))
}

fn checked_end(offset: usize, len: u32, limit: usize) -> Result<usize> {
    let length: usize = usize::try_from(len)
        .map_err(|_| stuffit_error("stuffit: fork length exceeds address space"))?;
    let end: usize = offset
        .checked_add(length)
        .ok_or_else(|| stuffit_error("stuffit: fork range overflow"))?;
    if end > limit {
        return Err(stuffit_error("stuffit: fork data out of bounds"));
    }
    Ok(end)
}

pub(crate) fn crc16_ibm(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0u16, |mut crc: u16, byte: &u8| {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
        crc
    })
}

fn decode_name(header: &[u8]) -> Result<String> {
    let name_len: usize = usize::from(header[2]);
    if name_len == 0 || name_len > NAME_FIELD_LEN {
        return Err(stuffit_error(format!(
            "stuffit: filename length {name_len} is outside 1..={NAME_FIELD_LEN}"
        )));
    }
    let encoded: &[u8] = &header[3..3 + name_len];
    let decoded: String = encoding_rs::MACINTOSH
        .decode_without_bom_handling(encoded)
        .0
        .into_owned();
    if decoded.contains('\0') {
        return Err(stuffit_error("stuffit: filename contains a null byte"));
    }
    Ok(decoded)
}

fn compression(method: u8) -> Result<SitCompression> {
    if method & FLAG_ENCRYPTED != 0 {
        return Err(stuffit_error(
            "stuffit: encrypted forks require a password and key derivation metadata",
        ));
    }
    match method {
        METHOD_STORED => Ok(SitCompression::Stored),
        METHOD_COMPRESS_14 => Ok(SitCompression::Compress14),
        METHOD_LZAH => Ok(SitCompression::Lzah),
        METHOD_MW => Ok(SitCompression::Method8),
        METHOD_13 => Ok(SitCompression::Method13),
        other => Err(stuffit_error(format!(
            "stuffit: unsupported compression method {other}"
        ))),
    }
}

fn fork(
    header: &[u8],
    method: u8,
    uncompressed_offset: usize,
    compressed_offset: usize,
    crc_offset: usize,
    data_offset: usize,
) -> Result<SitFork> {
    Ok(SitFork {
        compression: compression(method)?,
        uncompressed_len: rd_u32_be(header, uncompressed_offset)?,
        compressed_len: rd_u32_be(header, compressed_offset)?,
        expected_crc: rd_u16_be(header, crc_offset)?,
        data_offset,
    })
}

pub fn parse_classic(bytes: &[u8]) -> Result<SitArchive> {
    let header: &[u8] = bytes
        .get(..ARCHIVE_HEADER_LEN)
        .ok_or_else(|| stuffit_error("stuffit: truncated archive header"))?;
    if !header.starts_with(SIT_SIGNATURE) {
        return Err(stuffit_error("stuffit: missing SIT! signature"));
    }
    if header.get(10..14) != Some(SIT_SIGNATURE2.as_slice()) {
        return Err(stuffit_error("stuffit: missing rLau secondary signature"));
    }
    let declared_entries: usize = usize::from(rd_u16_be(header, 4)?);
    if declared_entries == 0 || declared_entries > MAX_RECORDS {
        return Err(stuffit_error("stuffit: invalid declared entry count"));
    }
    let total_len: usize = usize::try_from(rd_u32_be(header, 6)?)
        .map_err(|_| stuffit_error("stuffit: archive length exceeds address space"))?;
    if total_len != bytes.len() {
        return Err(stuffit_error(format!(
            "stuffit: declared archive length {total_len} differs from input length {}",
            bytes.len()
        )));
    }

    let mut cursor: usize = ARCHIVE_HEADER_LEN;
    let mut record_count: usize = 0;
    let mut entries: Vec<SitEntry> = Vec::with_capacity(declared_entries.min(MAX_RECORDS));
    let mut folders: Vec<String> = Vec::new();
    while cursor < total_len {
        if record_count >= MAX_RECORDS {
            return Err(stuffit_error("stuffit: record limit exceeded"));
        }
        let header_end: usize = cursor
            .checked_add(FILE_HEADER_LEN)
            .ok_or_else(|| stuffit_error("stuffit: record header range overflow"))?;
        let file_header: &[u8] = bytes
            .get(cursor..header_end)
            .ok_or_else(|| stuffit_error("stuffit: truncated record header"))?;
        let expected_header_crc: u16 = rd_u16_be(file_header, 110)?;
        if crc16_ibm(&file_header[..110]) != expected_header_crc {
            return Err(stuffit_error(format!(
                "stuffit: record {record_count} header CRC mismatch"
            )));
        }
        let resource_method: u8 = file_header[0];
        let data_method: u8 = file_header[1];
        let folder_method: u8 = data_method & !(FLAG_ENCRYPTED | FLAG_FOLDER_CONTAINS_ENCRYPTED);
        record_count += 1;

        if folder_method == FLAG_FOLDER_START || folder_method == FLAG_FOLDER_END {
            if (resource_method | data_method) & (FLAG_ENCRYPTED | FLAG_FOLDER_CONTAINS_ENCRYPTED)
                != 0
            {
                return Err(stuffit_error(
                    "stuffit: encrypted folders require a password and key derivation metadata",
                ));
            }
            let fork_lengths: [u32; 4] = [
                rd_u32_be(file_header, 84)?,
                rd_u32_be(file_header, 88)?,
                rd_u32_be(file_header, 92)?,
                rd_u32_be(file_header, 96)?,
            ];
            if fork_lengths != [0, 0, 0, 0] {
                return Err(stuffit_error("stuffit: folder record carries fork data"));
            }
            cursor = header_end;
            if folder_method == FLAG_FOLDER_START {
                if folders.len() >= MAX_FOLDER_DEPTH {
                    return Err(stuffit_error("stuffit: folder depth limit exceeded"));
                }
                folders.push(decode_name(file_header)?);
            } else if folders.pop().is_none() {
                return Err(stuffit_error("stuffit: unmatched folder end record"));
            }
            continue;
        }

        let name: String = decode_name(file_header)?;
        let resource_offset: usize = header_end;
        let resource: SitFork = fork(file_header, resource_method, 84, 92, 100, resource_offset)?;
        let data_offset: usize = checked_end(resource_offset, resource.compressed_len, total_len)?;
        let data: SitFork = fork(file_header, data_method, 88, 96, 102, data_offset)?;
        cursor = checked_end(data_offset, data.compressed_len, total_len)?;
        let path: String = if folders.is_empty() {
            name
        } else {
            format!("{}/{}", folders.join("/"), name)
        };
        if path.len() > MAX_PATH_BYTES {
            return Err(stuffit_error("stuffit: entry path limit exceeded"));
        }
        entries.push(SitEntry {
            name: path,
            resource,
            data,
        });
    }
    if cursor != total_len || !folders.is_empty() {
        return Err(stuffit_error(
            "stuffit: unbalanced or truncated folder structure",
        ));
    }
    if entries.len() != declared_entries {
        return Err(stuffit_error(format!(
            "stuffit: parsed {} files but archive declares {declared_entries}",
            entries.len()
        )));
    }
    Ok(SitArchive { entries })
}

pub(crate) fn decode_bounded<D: compcol::Decoder>(
    decoder: &mut D,
    raw: &[u8],
    expected_len: usize,
    max_output: usize,
    label: &str,
) -> Result<(Vec<u8>, usize)> {
    if expected_len > max_output {
        return Err(stuffit_error(format!(
            "stuffit: decoded fork length {expected_len} exceeds cap {max_output}"
        )));
    }
    let declared: u64 = u64::try_from(expected_len)
        .map_err(|_| stuffit_error("stuffit: declared fork length exceeds u64"))?;
    let mut output: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(declared));
    let mut scratch: Vec<u8> = vec![0u8; STREAM_BUFFER_LEN.min(max_output.max(1))];
    let mut consumed: usize = 0;
    loop {
        let (progress, status): (compcol::Progress, compcol::Status) = decoder
            .decode(&raw[consumed..], &mut scratch)
            .map_err(|error: compcol::Error| {
                stuffit_error(format!("stuffit: {label} decode failed: {error}"))
            })?;
        consumed = consumed
            .checked_add(progress.consumed)
            .ok_or_else(|| stuffit_error(format!("stuffit: {label} input count overflow")))?;
        let next_len: usize = output
            .len()
            .checked_add(progress.written)
            .ok_or_else(|| stuffit_error(format!("stuffit: {label} output count overflow")))?;
        if next_len > max_output || next_len > expected_len {
            return Err(stuffit_error(format!(
                "stuffit: {label} output limit exceeded"
            )));
        }
        output.extend_from_slice(&scratch[..progress.written]);
        match status {
            compcol::Status::StreamEnd => break,
            compcol::Status::InputEmpty if consumed == raw.len() => {
                let (finish_progress, finish_status): (compcol::Progress, compcol::Status) =
                    decoder
                        .finish(&mut scratch)
                        .map_err(|error: compcol::Error| {
                            stuffit_error(format!("stuffit: {label} stream is incomplete: {error}"))
                        })?;
                if finish_progress.written > 0 {
                    let finish_len: usize = output
                        .len()
                        .checked_add(finish_progress.written)
                        .ok_or_else(|| {
                            stuffit_error(format!("stuffit: {label} output count overflow"))
                        })?;
                    if finish_len > max_output || finish_len > expected_len {
                        return Err(stuffit_error(format!(
                            "stuffit: {label} output limit exceeded"
                        )));
                    }
                    output.extend_from_slice(&scratch[..finish_progress.written]);
                }
                if finish_status != compcol::Status::StreamEnd {
                    return Err(stuffit_error(format!(
                        "stuffit: {label} stream is truncated"
                    )));
                }
                break;
            }
            _ if progress.consumed == 0 && progress.written == 0 => {
                return Err(stuffit_error(format!("stuffit: {label} decoder stalled")));
            }
            _ => {}
        }
    }
    if output.len() != expected_len {
        return Err(stuffit_error(format!(
            "stuffit: {label} produced {} bytes, expected {expected_len}",
            output.len()
        )));
    }
    Ok((output, consumed))
}

fn decode_method13(raw: &[u8], expected_len: usize, max_output: usize) -> Result<Vec<u8>> {
    let mut decoder: compcol::sit13::Decoder = compcol::sit13::Decoder::with_len(expected_len);
    let (output, consumed): (Vec<u8>, usize) =
        decode_bounded(&mut decoder, raw, expected_len, max_output, "method 13")?;
    if consumed != raw.len() {
        return Err(stuffit_error(
            "stuffit: method 13 stream has trailing bytes",
        ));
    }
    Ok(output)
}

fn decode_lzah(raw: &[u8], expected_len: usize, max_output: usize) -> Result<Vec<u8>> {
    let mut decoder: compcol::lzah::Decoder =
        <compcol::lzah::Lzah as compcol::Algorithm>::decoder_with(
            compcol::lzah::DecoderConfig::with_len(expected_len),
        );
    let (output, consumed): (Vec<u8>, usize) =
        decode_bounded(&mut decoder, raw, expected_len, max_output, "method 5")?;
    if consumed != raw.len() {
        return Err(stuffit_error("stuffit: method 5 stream has trailing bytes"));
    }
    Ok(output)
}

fn mw_bits_low(raw: &[u8], bit_offset: &mut usize, bits: usize) -> Result<usize> {
    let available: usize = raw
        .len()
        .checked_mul(8)
        .and_then(|total: usize| total.checked_sub(*bit_offset))
        .ok_or_else(|| stuffit_error("stuffit: method 8 bit position overflow"))?;
    if available < bits {
        return Err(stuffit_error("stuffit: method 8 stream is truncated"));
    }
    let mut value: usize = 0;
    for shift in 0..bits {
        let position: usize = bit_offset
            .checked_add(shift)
            .ok_or_else(|| stuffit_error("stuffit: method 8 bit position overflow"))?;
        let byte: u8 = raw[position / 8];
        value |= usize::from((byte >> (position % 8)) & 1) << shift;
    }
    *bit_offset = bit_offset
        .checked_add(bits)
        .ok_or_else(|| stuffit_error("stuffit: method 8 bit position overflow"))?;
    Ok(value)
}

fn mw_emit(
    dictionary: &[u16],
    stack: &mut [u16],
    code: usize,
    output: &mut Vec<u8>,
    expected_len: usize,
) -> Result<()> {
    let mut stack_len: usize = 1;
    stack[0] = u16::try_from(code)
        .map_err(|_| stuffit_error("stuffit: method 8 dictionary code exceeds u16"))?;
    while stack_len != 0 {
        stack_len -= 1;
        let mut value: usize = usize::from(stack[stack_len]);
        while value >= 256 {
            if value >= dictionary.len() || stack_len == stack.len() {
                return Err(stuffit_error(
                    "stuffit: method 8 dictionary chain is invalid",
                ));
            }
            stack[stack_len] = dictionary[value];
            stack_len += 1;
            value = usize::from(dictionary[value - 1]);
        }
        if output.len() == expected_len {
            return Err(stuffit_error("stuffit: method 8 output limit exceeded"));
        }
        output.push(
            u8::try_from(value)
                .map_err(|_| stuffit_error("stuffit: method 8 literal exceeds u8"))?,
        );
    }
    Ok(())
}

fn decode_method8(raw: &[u8], expected_len: usize, max_output: usize) -> Result<Vec<u8>> {
    if expected_len > max_output {
        return Err(stuffit_error(format!(
            "stuffit: decoded fork length {expected_len} exceeds cap {max_output}"
        )));
    }
    if expected_len == 0 {
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        return Err(stuffit_error("stuffit: method 8 stream has trailing bytes"));
    }

    let mut dictionary: Box<[u16]> = vec![0; 16_385].into_boxed_slice();
    let mut stack: Box<[u16]> = vec![0; 16_384].into_boxed_slice();
    let declared: u64 = u64::try_from(expected_len)
        .map_err(|_| stuffit_error("stuffit: declared fork length exceeds u64"))?;
    let mut output: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(declared));
    let mut bit_offset: usize = 0;
    while output.len() < expected_len {
        let mut max_code: usize = 256;
        let mut width_limit: usize = 512;
        let mut bit_width: usize = 9;
        let first: usize = mw_bits_low(raw, &mut bit_offset, bit_width)?;
        if first > max_code {
            return Err(stuffit_error(
                "stuffit: method 8 first code is not a literal or reset",
            ));
        }
        if first == max_code {
            continue;
        }
        dictionary[255] = u16::try_from(first)
            .map_err(|_| stuffit_error("stuffit: method 8 literal exceeds u16"))?;
        mw_emit(&dictionary, &mut stack, first, &mut output, expected_len)?;

        while output.len() < expected_len {
            let code: usize = mw_bits_low(raw, &mut bit_offset, bit_width)?;
            if code >= max_code {
                if code == max_code {
                    break;
                }
                return Err(stuffit_error(
                    "stuffit: method 8 dictionary code is invalid",
                ));
            }
            if max_code >= dictionary.len() {
                return Err(stuffit_error("stuffit: method 8 dictionary is full"));
            }
            dictionary[max_code] = u16::try_from(code)
                .map_err(|_| stuffit_error("stuffit: method 8 dictionary code exceeds u16"))?;
            max_code += 1;
            if max_code == width_limit {
                width_limit = width_limit
                    .checked_mul(2)
                    .ok_or_else(|| stuffit_error("stuffit: method 8 code-width overflow"))?;
                bit_width = bit_width
                    .checked_add(1)
                    .ok_or_else(|| stuffit_error("stuffit: method 8 code-width overflow"))?;
            }
            mw_emit(&dictionary, &mut stack, code, &mut output, expected_len)?;
        }
    }
    let consumed_bytes: usize = bit_offset
        .checked_add(7)
        .ok_or_else(|| stuffit_error("stuffit: method 8 input count overflow"))?
        / 8;
    if consumed_bytes != raw.len() {
        return Err(stuffit_error("stuffit: method 8 stream has trailing bytes"));
    }
    Ok(output)
}

pub fn fork_bytes_bounded(bytes: &[u8], fork: &SitFork, max_output: usize) -> Result<Vec<u8>> {
    let end: usize = checked_end(fork.data_offset, fork.compressed_len, bytes.len())?;
    let raw: &[u8] = &bytes[fork.data_offset..end];
    let expected_len: usize = usize::try_from(fork.uncompressed_len)
        .map_err(|_| stuffit_error("stuffit: uncompressed length exceeds address space"))?;
    let output: Vec<u8> = match fork.compression {
        SitCompression::Stored => {
            if fork.compressed_len != fork.uncompressed_len {
                return Err(stuffit_error("stuffit: stored fork length mismatch"));
            }
            if expected_len > max_output {
                return Err(stuffit_error("stuffit: stored fork exceeds output cap"));
            }
            raw.to_vec()
        }
        SitCompression::Compress14 => {
            if expected_len > max_output {
                return Err(stuffit_error(format!(
                    "stuffit: decoded fork length {expected_len} exceeds cap {max_output}"
                )));
            }
            let cap: u64 = u64::try_from(max_output)
                .map_err(|_| stuffit_error("stuffit: output cap exceeds u64"))?;
            let decoded: Vec<u8> = super::bare_stream::decompress_stuffit_compress14(raw, cap)
                .map_err(|error: Error| {
                    stuffit_error(format!("stuffit: method 2 decode failed: {error}"))
                })?;
            if decoded.len() != expected_len {
                return Err(stuffit_error(format!(
                    "stuffit: method 2 produced {} bytes, expected {expected_len}",
                    decoded.len()
                )));
            }
            decoded
        }
        SitCompression::Lzah => decode_lzah(raw, expected_len, max_output)?,
        SitCompression::Method8 => decode_method8(raw, expected_len, max_output)?,
        SitCompression::Method13 => decode_method13(raw, expected_len, max_output)?,
    };
    let actual_crc: u16 = crc16_ibm(&output);
    if actual_crc != fork.expected_crc {
        return Err(stuffit_error(format!(
            "stuffit: fork CRC mismatch: expected {:04x}, got {actual_crc:04x}",
            fork.expected_crc
        )));
    }
    Ok(output)
}

#[must_use]
pub const fn fork_is_stored(fork: &SitFork) -> bool {
    matches!(fork.compression, SitCompression::Stored)
}

#[cfg(test)]
fn build_record(
    name: &str,
    resource_method: u8,
    data_method: u8,
    resource: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut record: Vec<u8> = vec![0u8; FILE_HEADER_LEN];
    record[0] = resource_method;
    record[1] = data_method;
    let name_bytes: &[u8] = name.as_bytes();
    record[2] = name_bytes.len() as u8;
    record[3..3 + name_bytes.len()].copy_from_slice(name_bytes);
    record[84..88].copy_from_slice(&(resource.len() as u32).to_be_bytes());
    record[88..92].copy_from_slice(&(data.len() as u32).to_be_bytes());
    record[92..96].copy_from_slice(&(resource.len() as u32).to_be_bytes());
    record[96..100].copy_from_slice(&(data.len() as u32).to_be_bytes());
    record[100..102].copy_from_slice(&crc16_ibm(resource).to_be_bytes());
    record[102..104].copy_from_slice(&crc16_ibm(data).to_be_bytes());
    let header_crc: u16 = crc16_ibm(&record[..110]);
    record[110..112].copy_from_slice(&header_crc.to_be_bytes());
    record.extend_from_slice(resource);
    record.extend_from_slice(data);
    record
}

#[cfg(test)]
fn wrap_archive(declared_entries: u16, records: &[Vec<u8>]) -> Vec<u8> {
    let body_len: usize = records.iter().map(Vec::len).sum();
    let mut output: Vec<u8> = Vec::new();
    output.extend_from_slice(SIT_SIGNATURE);
    output.extend_from_slice(&declared_entries.to_be_bytes());
    let total: u32 = (ARCHIVE_HEADER_LEN + body_len) as u32;
    output.extend_from_slice(&total.to_be_bytes());
    output.extend_from_slice(SIT_SIGNATURE2);
    output.extend_from_slice(&[0u8; 8]);
    for record in records {
        output.extend_from_slice(record);
    }
    output
}

#[cfg(test)]
pub(crate) fn build_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let records: Vec<Vec<u8>> = entries
        .iter()
        .map(|(name, data): &(&str, &[u8])| {
            build_record(name, METHOD_STORED, METHOD_STORED, &[], data)
        })
        .collect();
    wrap_archive(entries.len() as u16, &records)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_stored_forks_byte_exact() {
        let payload_a: &[u8] = b"first stuffit member data fork stored verbatim";
        let payload_b: &[u8] = b"second member, also stored, different bytes here";
        let archive: Vec<u8> = build_archive(&[("alpha.txt", payload_a), ("beta.txt", payload_b)]);
        let parsed: SitArchive = parse_classic(&archive).expect("parse");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "alpha.txt");
        assert!(fork_is_stored(&parsed.entries[0].data));
        assert_eq!(
            fork_bytes_bounded(&archive, &parsed.entries[0].data, 1024).expect("fork a"),
            payload_a
        );
        assert_eq!(
            fork_bytes_bounded(&archive, &parsed.entries[1].data, 1024).expect("fork b"),
            payload_b
        );
    }

    #[test]
    fn empty_data_resource_and_dual_forks_publish_exact_members() {
        let records: Vec<Vec<u8>> = vec![
            build_record("empty", METHOD_STORED, METHOD_STORED, &[], &[]),
            build_record("data", METHOD_STORED, METHOD_STORED, &[], b"data-fork"),
            build_record(
                "resource",
                METHOD_STORED,
                METHOD_STORED,
                b"resource-fork",
                &[],
            ),
            build_record(
                "dual",
                METHOD_STORED,
                METHOD_STORED,
                b"dual-resource",
                b"dual-data",
            ),
        ];
        let archive: Vec<u8> = wrap_archive(4, &records);
        let directory: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-fork-shapes")
                .expect("create fork-shape directory");
        let result: crate::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::StuffIt,
            &archive,
            directory.path(),
        )
        .expect("extract fork shapes");
        let expected: [(&str, &[u8]); 5] = [
            ("data", b"data-fork"),
            ("dual", b"dual-data"),
            ("dual.rsrc", b"dual-resource"),
            ("empty", b""),
            ("resource.rsrc", b"resource-fork"),
        ];
        assert_eq!(result.entries.len(), expected.len());
        for (name, bytes) in expected {
            assert_eq!(
                std::fs::read(directory.path().join(name)).expect("read extracted fork"),
                bytes
            );
        }
    }

    #[test]
    fn header_and_fork_crc_mutations_fail_closed() {
        let payload: &[u8] = b"crc guarded payload";
        let archive: Vec<u8> = build_archive(&[("crc.bin", payload)]);
        let mut header_mutation: Vec<u8> = archive.clone();
        header_mutation[ARCHIVE_HEADER_LEN + 40] ^= 1;
        assert!(parse_classic(&header_mutation).is_err());

        let parsed: SitArchive = parse_classic(&archive).expect("parse");
        let mut fork_mutation: Vec<u8> = archive;
        let data_offset: usize = parsed.entries[0].data.data_offset;
        fork_mutation[data_offset] ^= 1;
        assert!(fork_bytes_bounded(&fork_mutation, &parsed.entries[0].data, 1024).is_err());
    }

    #[test]
    fn folders_build_bounded_member_paths_and_must_balance() {
        let start: Vec<u8> = build_record("Folder", 0, FLAG_FOLDER_START, &[], &[]);
        let member: Vec<u8> =
            build_record("inside.txt", METHOD_STORED, METHOD_STORED, &[], b"inside");
        let end: Vec<u8> = build_record("", 0, FLAG_FOLDER_END, &[], &[]);
        let archive: Vec<u8> = wrap_archive(1, &[start.clone(), member, end]);
        let parsed: SitArchive = parse_classic(&archive).expect("parse folder archive");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "Folder/inside.txt");

        let unbalanced: Vec<u8> = wrap_archive(1, &[start]);
        assert!(parse_classic(&unbalanced).is_err());
        let underflow: Vec<u8> = wrap_archive(1, &[build_record("", 0, FLAG_FOLDER_END, &[], &[])]);
        assert!(parse_classic(&underflow).is_err());
        let encrypted_folder: Vec<u8> = wrap_archive(
            1,
            &[
                build_record("Folder", 0, 0x30, &[], &[]),
                build_record("inside.txt", 0, 0, &[], b"inside"),
                build_record("", 0, FLAG_FOLDER_END, &[], &[]),
            ],
        );
        assert!(parse_classic(&encrypted_folder).is_err());
    }

    #[test]
    fn encrypted_forks_fail_and_case_collisions_retain_the_first_member() {
        let mut encrypted: Vec<u8> = build_archive(&[("secret.bin", b"secret")]);
        let method_offset: usize = ARCHIVE_HEADER_LEN + 1;
        encrypted[method_offset] |= FLAG_ENCRYPTED;
        let header_start: usize = ARCHIVE_HEADER_LEN;
        let header_crc: u16 = crc16_ibm(&encrypted[header_start..header_start + 110]);
        encrypted[header_start + 110..header_start + 112]
            .copy_from_slice(&header_crc.to_be_bytes());
        assert!(parse_classic(&encrypted).is_err());

        let collision: Vec<u8> = build_archive(&[("Name", b"first"), ("name", b"second")]);
        let directory: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-collision")
                .expect("create collision directory");
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::StuffIt,
            &collision,
            directory.path(),
        )
        .expect("retain the first non-colliding member");
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "Name");
        assert_eq!(
            std::fs::read(
                result.entries[0]
                    .disk_path
                    .as_deref()
                    .expect("retained member path")
            )
            .expect("read retained member"),
            b"first"
        );
        assert_eq!(
            result.integrity_violations,
            [
                "stuffit-path `name`: DR-BINFMT-0063: stuffit archive parse failed: stuffit: case-insensitive path collision at `name`"
            ]
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("read collision directory")
                .count(),
            1
        );
    }

    #[test]
    fn quota_refusal_is_transactional() {
        let archive: Vec<u8> = build_archive(&[("large.bin", &[7u8; 32])]);
        let directory: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-quota")
                .expect("create quota directory");
        let quota: crate::quota::ExtractionQuota = crate::quota::ExtractionQuota {
            max_entries: 1,
            max_total_uncompressed: 16,
            max_per_entry_uncompressed: 16,
            max_per_entry_ratio: 100,
            max_aggregate_ratio: 100,
        };
        let result: crate::extract::ExtractionResult = crate::extract::extract_to_with_quota(
            crate::container::ContainerKind::StuffIt,
            &archive,
            directory.path(),
            quota,
        )
        .expect("retain the archive-level recovery result");
        assert!(result.entries.is_empty());
        assert_eq!(
            result.integrity_violations,
            [
                "stuffit-quota `large.bin`: DR-BINFMT-0009: extraction quota exceeded on entry `large.bin`: uncompressed=32 exceeds per-entry cap 16"
            ]
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("read quota directory")
                .count(),
            0
        );
    }

    #[test]
    fn macroman_names_and_method13_failure_boundaries_are_explicit() {
        let mut archive: Vec<u8> = build_archive(&[("x", b"body")]);
        let header_start: usize = ARCHIVE_HEADER_LEN;
        archive[header_start + 3] = 0x80;
        let header_crc: u16 = crc16_ibm(&archive[header_start..header_start + 110]);
        archive[header_start + 110..header_start + 112].copy_from_slice(&header_crc.to_be_bytes());
        let parsed: SitArchive = parse_classic(&archive).expect("parse MacRoman name");
        assert_eq!(parsed.entries[0].name, "Ä");

        let malformed: SitFork = SitFork {
            compression: SitCompression::Method13,
            uncompressed_len: 1,
            compressed_len: 1,
            expected_crc: 0,
            data_offset: 0,
        };
        assert!(fork_bytes_bounded(&[0x60], &malformed, 1).is_err());

        let fixture: &[u8] = include_bytes!("../../tests/fixtures/stuffit/stuffit45-method13.sit");
        let real: SitArchive = parse_classic(fixture).expect("parse real fixture");
        let resource: &SitFork = &real.entries[0].resource;
        assert!(
            fork_bytes_bounded(
                fixture,
                resource,
                usize::try_from(resource.uncompressed_len).expect("resource length") - 1,
            )
            .is_err()
        );
        let truncated_len: usize = resource.compressed_len as usize / 2;
        let truncated_bytes: Vec<u8> =
            fixture[resource.data_offset..resource.data_offset + truncated_len].to_vec();
        let mut truncated: SitFork = resource.clone();
        truncated.data_offset = 0;
        truncated.compressed_len = truncated_len as u32;
        assert!(
            fork_bytes_bounded(
                &truncated_bytes,
                &truncated,
                resource.uncompressed_len as usize,
            )
            .is_err()
        );
    }

    #[test]
    fn method13_control_huffman_and_distance_failures_are_typed() {
        let failures: [(&[u8], &str); 3] = [
            (&[0xf0, 0, 0, 0], "encoded stream is corrupt"),
            (
                &[
                    0x00, 0x85, 0x5c, 0x2c, 0x12, 0xa2, 0x67, 0x8f, 0x78, 0x28, 0xda, 0x51, 0xcb,
                    0xc2, 0x43, 0x5f,
                ],
                "invalid Huffman code lengths",
            ),
            (
                &[
                    0x10, 0xad, 0x76, 0x36, 0x74, 0xec, 0x79, 0xcf, 0xea, 0x8b, 0x8e, 0x15, 0x03,
                    0xfd, 0x9e, 0x1f,
                ],
                "invalid LZ77 back-reference distance",
            ),
        ];
        for (raw, expected) in failures {
            let error: Error = decode_method13(raw, 16, 16).expect_err(expected);
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn method2_truncation_trailing_bytes_quota_and_crc_fail_closed() {
        let fixture: &[u8] = include_bytes!("../../tests/fixtures/stuffit/stuffit-method2.sit");
        let parsed: SitArchive = parse_classic(fixture).expect("parse method 2 fixture");
        let data: &SitFork = &parsed.entries[0].data;
        let expected_len: usize =
            usize::try_from(data.uncompressed_len).expect("method 2 output length");
        assert!(fork_bytes_bounded(fixture, data, expected_len - 1).is_err());

        let raw_end: usize = data.data_offset + data.compressed_len as usize;
        let raw: &[u8] = &fixture[data.data_offset..raw_end];
        let mut truncated: SitFork = data.clone();
        truncated.data_offset = 0;
        truncated.compressed_len -= 1;
        assert!(fork_bytes_bounded(&raw[..raw.len() - 1], &truncated, expected_len).is_err());

        let mut with_trailing: Vec<u8> = raw.to_vec();
        with_trailing.push(0);
        let mut trailing: SitFork = data.clone();
        trailing.data_offset = 0;
        trailing.compressed_len += 1;
        assert!(fork_bytes_bounded(&with_trailing, &trailing, expected_len).is_err());

        let mut wrong_crc: SitFork = data.clone();
        wrong_crc.expected_crc ^= 1;
        assert!(fork_bytes_bounded(fixture, &wrong_crc, expected_len).is_err());

        let invalid_forward_code: SitFork = SitFork {
            compression: SitCompression::Compress14,
            uncompressed_len: 1,
            compressed_len: 2,
            expected_crc: 0,
            data_offset: 0,
        };
        assert!(fork_bytes_bounded(&[1, 1], &invalid_forward_code, 1).is_err());

        let trailing_clear: SitFork = SitFork {
            compression: SitCompression::Compress14,
            uncompressed_len: 1,
            compressed_len: 3,
            expected_crc: crc16_ibm(b"A"),
            data_offset: 0,
        };
        assert!(fork_bytes_bounded(&[0x41, 0x00, 0x02], &trailing_clear, 1).is_err());
    }

    #[test]
    fn method5_truncation_trailing_bytes_quota_and_crc_fail_closed() {
        let fixture: &[u8] = include_bytes!("../../tests/fixtures/stuffit/stuffit-method5.sit");
        let parsed: SitArchive = parse_classic(fixture).expect("parse method 5 fixture");
        let data: &SitFork = &parsed.entries[1].data;
        assert_eq!(data.compression, SitCompression::Lzah);
        let expected_len: usize =
            usize::try_from(data.uncompressed_len).expect("method 5 output length");
        assert_eq!(expected_len, 1405);

        let baseline: Vec<u8> =
            fork_bytes_bounded(fixture, data, expected_len).expect("method 5 baseline decode");
        assert_eq!(baseline.len(), expected_len);

        assert!(fork_bytes_bounded(fixture, data, expected_len - 1).is_err());

        let raw_end: usize = data.data_offset + data.compressed_len as usize;
        let raw: &[u8] = &fixture[data.data_offset..raw_end];

        let mut truncated: SitFork = data.clone();
        truncated.data_offset = 0;
        truncated.compressed_len -= 1;
        assert!(fork_bytes_bounded(&raw[..raw.len() - 1], &truncated, expected_len).is_err());

        let mut wrong_crc: SitFork = data.clone();
        wrong_crc.expected_crc ^= 1;
        assert!(fork_bytes_bounded(fixture, &wrong_crc, expected_len).is_err());

        let mut wrong_length: SitFork = data.clone();
        wrong_length.uncompressed_len -= 1;
        assert!(fork_bytes_bounded(fixture, &wrong_length, expected_len).is_err());

        let mut refused: usize = 0;
        let mut crc_refused: usize = 0;
        let mut inert: Vec<usize> = Vec::new();
        for index in 0..raw.len() {
            let mut corrupted: Vec<u8> = raw.to_vec();
            corrupted[index] ^= 0x01;
            let mut fork_at_zero: SitFork = data.clone();
            fork_at_zero.data_offset = 0;
            match fork_bytes_bounded(&corrupted, &fork_at_zero, expected_len) {
                Ok(decoded) => {
                    assert_eq!(
                        decoded, baseline,
                        "byte {index}: an accepted corruption must reproduce the reference bytes"
                    );
                    inert.push(index);
                }
                Err(error) => {
                    refused += 1;
                    if error.to_string().contains("fork CRC mismatch") {
                        crc_refused += 1;
                    }
                }
            }
        }
        assert_eq!(
            refused + inert.len(),
            raw.len(),
            "every corruption is either refused or provably inert"
        );
        assert!(
            crc_refused > 0,
            "the CRC StuffIt stored must catch corruption the codec itself accepts"
        );
        assert!(
            inert.len() <= 8,
            "at most a handful of bits may be inert, saw {} at {inert:?}",
            inert.len()
        );
    }

    #[test]
    fn method5_bounds_refuse_crafted_streams_without_unbounded_work() {
        let oversized: SitFork = SitFork {
            compression: SitCompression::Lzah,
            uncompressed_len: u32::MAX,
            compressed_len: 4,
            expected_crc: 0,
            data_offset: 0,
        };
        let error: Error = fork_bytes_bounded(&[0u8; 4], &oversized, 1024)
            .expect_err("declared length above the cap must be refused before decoding");
        assert!(
            error.to_string().contains("exceeds cap"),
            "expected an output cap refusal, got {error}"
        );

        let stalled: SitFork = SitFork {
            compression: SitCompression::Lzah,
            uncompressed_len: 4096,
            compressed_len: 1,
            expected_crc: 0,
            data_offset: 0,
        };
        assert!(fork_bytes_bounded(&[0x00], &stalled, 4096).is_err());

        let empty_input: SitFork = SitFork {
            compression: SitCompression::Lzah,
            uncompressed_len: 16,
            compressed_len: 0,
            expected_crc: 0,
            data_offset: 0,
        };
        assert!(fork_bytes_bounded(&[], &empty_input, 16).is_err());
    }

    #[test]
    fn method8_bounds_resets_and_integrity_fail_closed() {
        let raw: &[u8] = &[0x41, 0x84, 0x00, 0x0c, 0x08];
        let fork: SitFork = SitFork {
            compression: SitCompression::Method8,
            uncompressed_len: 7,
            compressed_len: raw.len() as u32,
            expected_crc: crc16_ibm(b"ABABBAB"),
            data_offset: 0,
        };
        assert_eq!(
            fork_bytes_bounded(raw, &fork, 7).expect("decode method 8 dictionary vector"),
            b"ABABBAB"
        );

        let initial_reset: SitFork = SitFork {
            uncompressed_len: 1,
            compressed_len: 3,
            expected_crc: crc16_ibm(b"A"),
            ..fork
        };
        assert_eq!(
            fork_bytes_bounded(&[0x00, 0x83, 0x00], &initial_reset, 1)
                .expect("decode initial method 8 reset"),
            b"A"
        );
        let repeated_resets: SitFork = SitFork {
            compressed_len: 4,
            ..initial_reset
        };
        assert_eq!(
            fork_bytes_bounded(&[0x00, 0x01, 0x06, 0x01], &repeated_resets, 1)
                .expect("decode repeated method 8 resets"),
            b"A"
        );

        let invalid_first: SitFork = SitFork {
            compressed_len: 2,
            ..initial_reset
        };
        let first_error: Error = fork_bytes_bounded(&[0x01, 0x01], &invalid_first, 1)
            .expect_err("a first code above the reset marker must be refused");
        assert!(first_error.to_string().contains("literal or reset"));

        let invalid_later: SitFork = SitFork {
            uncompressed_len: 2,
            compressed_len: 3,
            expected_crc: crc16_ibm(b"AA"),
            ..initial_reset
        };
        let later_error: Error = fork_bytes_bounded(&[0x41, 0x02, 0x02], &invalid_later, 2)
            .expect_err("a dictionary code above the next slot must be refused");
        assert!(
            later_error
                .to_string()
                .contains("dictionary code is invalid")
        );

        let truncated: SitFork = SitFork {
            compressed_len: 4,
            ..fork
        };
        assert!(fork_bytes_bounded(&raw[..4], &truncated, 7).is_err());

        let mut trailing_raw: Vec<u8> = raw.to_vec();
        trailing_raw.push(0);
        let trailing: SitFork = SitFork {
            compressed_len: trailing_raw.len() as u32,
            ..fork
        };
        let trailing_error: Error = fork_bytes_bounded(&trailing_raw, &trailing, 7)
            .expect_err("whole trailing bytes must be refused");
        assert!(trailing_error.to_string().contains("trailing bytes"));

        let cap_error: Error = fork_bytes_bounded(raw, &fork, 6)
            .expect_err("the declared output must fit the caller cap");
        assert!(cap_error.to_string().contains("exceeds cap"));

        let wrong_crc: SitFork = SitFork {
            expected_crc: fork.expected_crc ^ 1,
            ..fork
        };
        let crc_error: Error =
            fork_bytes_bounded(raw, &wrong_crc, 7).expect_err("CRC mismatch must be refused");
        assert!(crc_error.to_string().contains("fork CRC mismatch"));

        let empty: SitFork = SitFork {
            compression: SitCompression::Method8,
            uncompressed_len: 0,
            compressed_len: 0,
            expected_crc: 0,
            data_offset: 0,
        };
        assert_eq!(
            fork_bytes_bounded(&[], &empty, 0).expect("empty method 8 fork"),
            b""
        );
        let nonempty_zero: SitFork = SitFork {
            compressed_len: 1,
            ..empty
        };
        assert!(fork_bytes_bounded(&[0], &nonempty_zero, 0).is_err());
    }

    #[test]
    fn extract_to_writes_stored_data_forks() {
        let payload: &[u8] = b"stuffit classic stored data fork written to disk by extract_to";
        let archive: Vec<u8> = build_archive(&[("doc.txt", payload)]);
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::StuffIt,
            &archive,
            dir.path(),
        )
        .expect("sit extract");
        assert_eq!(result.kind, crate::container::ContainerKind::StuffIt);
        assert_eq!(
            std::fs::read(dir.path().join("doc.txt")).expect("doc"),
            payload
        );
    }

    #[test]
    fn rejects_non_sit_and_truncated_archives() {
        assert!(parse_classic(b"PK\x03\x04 not a sit archive at all").is_err());
        let archive: Vec<u8> = build_archive(&[("x", b"y")]);
        assert!(parse_classic(&archive[..archive.len() - 1]).is_err());
    }
}
