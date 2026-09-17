use crate::error::{Error, Result};

use super::lzms::{lzms_compress, lzms_decompress};

const CAB_MAGIC: [u8; 4] = *b"MSCF";
const CFHEADER_FIXED_LEN: usize = 36;
const CFFOLDER_FIXED_LEN: usize = 8;
const CFFILE_FIXED_LEN: usize = 16;
const CFDATA_FIXED_LEN: usize = 8;

const CFHDR_RESERVE_PRESENT: u16 = 0x0004;
const CFHDR_PREV_CABINET: u16 = 0x0001;
const CFHDR_NEXT_CABINET: u16 = 0x0002;

const COMPTYPE_MASK: u16 = 0x000f;
const COMPTYPE_LZMS: u16 = 5;

const MAX_FOLDERS: usize = 1 << 16;
const MAX_FILES: usize = 1 << 20;
const MAX_BLOCKS_PER_FOLDER: usize = 1 << 24;

#[derive(Debug, Clone)]
pub struct CabLzmsFile {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Folder {
    coff_cab_start: u32,
    num_blocks: u16,
    comp_type: u16,
}

#[derive(Debug, Clone)]
struct File {
    size: u32,
    folder_offset: u32,
    folder_index: u16,
    name: String,
}

#[must_use]
pub fn cab_uses_lzms(bytes: &[u8]) -> bool {
    parse_header_and_folders(bytes).is_ok_and(|(_, folders, _): (Header, Vec<Folder>, usize)| {
        folders
            .iter()
            .any(|f: &Folder| f.comp_type & COMPTYPE_MASK == COMPTYPE_LZMS)
    })
}

#[derive(Debug, Clone, Copy)]
struct Header {
    num_files: u16,
    coff_files: u32,
    data_reserve: usize,
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at).map_err(|_| cab_err("truncated reading u16"))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at).map_err(|_| cab_err("truncated reading u32"))
}

fn parse_header_and_folders(bytes: &[u8]) -> Result<(Header, Vec<Folder>, usize)> {
    if bytes.len() < CFHEADER_FIXED_LEN || bytes[..4] != CAB_MAGIC {
        return Err(cab_err("not a cabinet (missing MSCF signature)"));
    }
    let coff_files: u32 = read_u32(bytes, 16)?;
    let num_folders: u16 = read_u16(bytes, 26)?;
    let num_files: u16 = read_u16(bytes, 28)?;
    let flags: u16 = read_u16(bytes, 30)?;
    if num_folders as usize > MAX_FOLDERS || num_files as usize > MAX_FILES {
        return Err(cab_err("implausible folder or file count"));
    }

    let mut cursor: usize = CFHEADER_FIXED_LEN;
    let (mut folder_reserve, mut data_reserve): (usize, usize) = (0, 0);
    if flags & CFHDR_RESERVE_PRESENT != 0 {
        let cb_cf_header: u16 = read_u16(bytes, 36)?;
        let cb_cf_folder: u8 = *bytes
            .get(38)
            .ok_or_else(|| cab_err("truncated reserve sizes"))?;
        let cb_cf_data: u8 = *bytes
            .get(39)
            .ok_or_else(|| cab_err("truncated reserve sizes"))?;
        folder_reserve = cb_cf_folder as usize;
        data_reserve = cb_cf_data as usize;
        cursor = 40 + cb_cf_header as usize;
    }
    if flags & CFHDR_PREV_CABINET != 0 {
        cursor = skip_cstring(bytes, cursor)?;
        cursor = skip_cstring(bytes, cursor)?;
    }
    if flags & CFHDR_NEXT_CABINET != 0 {
        cursor = skip_cstring(bytes, cursor)?;
        cursor = skip_cstring(bytes, cursor)?;
    }

    let mut folders: Vec<Folder> = Vec::with_capacity(num_folders as usize);
    for _ in 0..num_folders {
        let coff_cab_start: u32 = read_u32(bytes, cursor)?;
        let num_blocks: u16 = read_u16(bytes, cursor + 4)?;
        let comp_type: u16 = read_u16(bytes, cursor + 6)?;
        folders.push(Folder {
            coff_cab_start,
            num_blocks,
            comp_type,
        });
        cursor = cursor
            .checked_add(CFFOLDER_FIXED_LEN + folder_reserve)
            .ok_or_else(|| cab_err("folder table overflow"))?;
    }

    let header: Header = Header {
        num_files,
        coff_files,
        data_reserve,
    };
    Ok((header, folders, cursor))
}

fn parse_files(bytes: &[u8], header: &Header) -> Result<Vec<File>> {
    let mut cursor: usize = header.coff_files as usize;
    let mut files: Vec<File> = Vec::with_capacity(header.num_files as usize);
    for _ in 0..header.num_files {
        let size: u32 = read_u32(bytes, cursor)?;
        let folder_offset: u32 = read_u32(bytes, cursor + 4)?;
        let folder_index: u16 = read_u16(bytes, cursor + 8)?;
        let name_start: usize = cursor + CFFILE_FIXED_LEN;
        let name_end: usize = bytes
            .get(name_start..)
            .and_then(|tail: &[u8]| tail.iter().position(|&b: &u8| b == 0))
            .map(|rel: usize| name_start + rel)
            .ok_or_else(|| cab_err("unterminated file name"))?;
        let raw: &[u8] = &bytes[name_start..name_end];
        let name: String = String::from_utf8_lossy(raw).into_owned();
        files.push(File {
            size,
            folder_offset,
            folder_index,
            name,
        });
        cursor = name_end + 1;
    }
    Ok(files)
}

fn decode_folder(bytes: &[u8], folder: Folder, header: &Header) -> Result<Vec<u8>> {
    if folder.comp_type & COMPTYPE_MASK != COMPTYPE_LZMS {
        return Err(cab_err("folder is not lzms-compressed"));
    }
    if folder.num_blocks as usize > MAX_BLOCKS_PER_FOLDER {
        return Err(cab_err("implausible block count"));
    }
    let mut cursor: usize = folder.coff_cab_start as usize;
    let mut out: Vec<u8> = Vec::new();
    for _ in 0..folder.num_blocks {
        let cb_data: u16 = read_u16(bytes, cursor + 4)?;
        let cb_uncomp: u16 = read_u16(bytes, cursor + 6)?;
        let data_start: usize = cursor
            .checked_add(CFDATA_FIXED_LEN + header.data_reserve)
            .ok_or_else(|| cab_err("data block header overflow"))?;
        let data_end: usize = data_start
            .checked_add(cb_data as usize)
            .ok_or_else(|| cab_err("data block overflow"))?;
        let block: &[u8] = bytes
            .get(data_start..data_end)
            .ok_or_else(|| cab_err("data block out of bounds"))?;
        if cb_uncomp == 0 {
            out.extend_from_slice(block);
        } else {
            let decoded: Vec<u8> = lzms_decompress(block, cb_uncomp as usize)
                .map_err(|e: Error| cab_err_owned(format!("cab lzms block decode failed: {e}")))?;
            if decoded.len() != cb_uncomp as usize {
                return Err(cab_err("cab lzms block produced unexpected length"));
            }
            out.extend_from_slice(&decoded);
        }
        cursor = data_end;
    }
    Ok(out)
}

pub fn extract_cab_lzms(bytes: &[u8], cap: u64) -> Result<Vec<CabLzmsFile>> {
    let (header, folders, _): (Header, Vec<Folder>, usize) = parse_header_and_folders(bytes)?;
    let files: Vec<File> = parse_files(bytes, &header)?;
    let mut decoded_folders: Vec<Option<Vec<u8>>> = vec![None; folders.len()];
    let mut out: Vec<CabLzmsFile> = Vec::with_capacity(files.len());
    for file in &files {
        let folder_index: usize = file.folder_index as usize;
        let folder: &Folder = folders
            .get(folder_index)
            .ok_or_else(|| cab_err("file references missing folder"))?;
        if folder.comp_type & COMPTYPE_MASK != COMPTYPE_LZMS {
            continue;
        }
        if decoded_folders[folder_index].is_none() {
            let folder_bytes: Vec<u8> = decode_folder(bytes, *folder, &header)?;
            decoded_folders[folder_index] = Some(folder_bytes);
        }
        let folder_bytes: &[u8] = decoded_folders[folder_index]
            .as_deref()
            .ok_or_else(|| cab_err("folder decode state missing"))?;
        let start: usize = file.folder_offset as usize;
        let end: usize = start
            .checked_add(file.size as usize)
            .ok_or_else(|| cab_err("file extent overflow"))?;
        if end as u64 > cap {
            return Err(cab_err("cab lzms file exceeds size cap"));
        }
        let data: Vec<u8> = folder_bytes
            .get(start..end)
            .ok_or_else(|| cab_err("file extent escapes folder data"))?
            .to_vec();
        out.push(CabLzmsFile {
            name: file.name.clone(),
            data,
        });
    }
    Ok(out)
}

const CFDATA_MAX_UNCOMP: usize = 32_768;
const LZMS_WINDOW_LOG: u16 = 20;

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[must_use]
pub fn build_lzms_cab(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut folder_stream: Vec<u8> = Vec::new();
    let mut file_offsets: Vec<(u32, u32)> = Vec::with_capacity(files.len());
    for (_, data) in files {
        let start: u32 = folder_stream.len() as u32;
        folder_stream.extend_from_slice(data);
        file_offsets.push((start, data.len() as u32));
    }

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut block_uncomp: Vec<u16> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < folder_stream.len() {
        let end: usize = (cursor + CFDATA_MAX_UNCOMP).min(folder_stream.len());
        let chunk: &[u8] = &folder_stream[cursor..end];
        let compressed: Vec<u8> = lzms_compress(chunk);
        if compressed.len() < chunk.len() {
            blocks.push(compressed);
            block_uncomp.push(chunk.len() as u16);
        } else {
            blocks.push(chunk.to_vec());
            block_uncomp.push(0);
        }
        cursor = end;
    }
    if blocks.is_empty() {
        blocks.push(Vec::new());
        block_uncomp.push(0);
    }

    let num_files: u16 = files.len() as u16;
    let num_blocks: u16 = blocks.len() as u16;
    let header_len: usize = CFHEADER_FIXED_LEN;
    let folder_len: usize = CFFOLDER_FIXED_LEN;
    let cffiles_len: usize = files
        .iter()
        .map(|(name, _): &(&str, &[u8])| CFFILE_FIXED_LEN + name.len() + 1)
        .sum();
    let coff_files: u32 = (header_len + folder_len) as u32;
    let data_start: u32 = coff_files + cffiles_len as u32;
    let data_total: usize = blocks
        .iter()
        .map(|b: &Vec<u8>| CFDATA_FIXED_LEN + b.len())
        .sum();
    let total_size: u32 = data_start + data_total as u32;

    let mut cab: Vec<u8> = Vec::with_capacity(total_size as usize);
    cab.extend_from_slice(&CAB_MAGIC);
    push_u32(&mut cab, 0);
    push_u32(&mut cab, total_size);
    push_u32(&mut cab, 0);
    push_u32(&mut cab, coff_files);
    push_u32(&mut cab, 0);
    cab.push(3);
    cab.push(1);
    push_u16(&mut cab, 1);
    push_u16(&mut cab, num_files);
    push_u16(&mut cab, 0);
    push_u16(&mut cab, 0);
    push_u16(&mut cab, 0);

    push_u32(&mut cab, data_start);
    push_u16(&mut cab, num_blocks);
    push_u16(&mut cab, COMPTYPE_LZMS | (LZMS_WINDOW_LOG << 8));

    for ((name, _), (offset, size)) in files.iter().zip(file_offsets.iter()) {
        push_u32(&mut cab, *size);
        push_u32(&mut cab, *offset);
        push_u16(&mut cab, 0);
        push_u16(&mut cab, 0);
        push_u16(&mut cab, 0);
        push_u16(&mut cab, 0);
        cab.extend_from_slice(name.as_bytes());
        cab.push(0);
    }

    for (block, uncomp) in blocks.iter().zip(block_uncomp.iter()) {
        push_u32(&mut cab, 0);
        push_u16(&mut cab, block.len() as u16);
        push_u16(&mut cab, *uncomp);
        cab.extend_from_slice(block);
    }

    cab
}

fn skip_cstring(bytes: &[u8], start: usize) -> Result<usize> {
    let rel: usize = bytes
        .get(start..)
        .and_then(|tail: &[u8]| tail.iter().position(|&b: &u8| b == 0))
        .ok_or_else(|| cab_err("unterminated cabinet name string"))?;
    Ok(start + rel + 1)
}

#[inline]
fn cab_err(message: &'static str) -> Error {
    Error::Cab(format!("cab-lzms: {message}"))
}

#[inline]
fn cab_err_owned(message: String) -> Error {
    Error::Cab(format!("cab-lzms: {message}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_raw_block_cab(file_name: &str, block_payload: &[u8], cb_uncomp: u16) -> Vec<u8> {
        let mut cab: Vec<u8> = Vec::new();
        let num_blocks: u16 = 1;
        let header_len: usize = CFHEADER_FIXED_LEN;
        let folder_len: usize = CFFOLDER_FIXED_LEN;
        let cffile_len: usize = CFFILE_FIXED_LEN + file_name.len() + 1;
        let coff_files: u32 = (header_len + folder_len) as u32;
        let data_start: u32 = coff_files + cffile_len as u32;

        cab.extend_from_slice(&CAB_MAGIC);
        cab.extend_from_slice(&0u32.to_le_bytes());
        let total: u32 = data_start + CFDATA_FIXED_LEN as u32 + block_payload.len() as u32;
        cab.extend_from_slice(&total.to_le_bytes());
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&coff_files.to_le_bytes());
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.push(3);
        cab.push(1);
        cab.extend_from_slice(&1u16.to_le_bytes());
        cab.extend_from_slice(&1u16.to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes());

        cab.extend_from_slice(&data_start.to_le_bytes());
        cab.extend_from_slice(&num_blocks.to_le_bytes());
        cab.extend_from_slice(&COMPTYPE_LZMS.to_le_bytes());

        cab.extend_from_slice(&(block_payload.len() as u32).to_le_bytes());
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes());
        cab.extend_from_slice(file_name.as_bytes());
        cab.push(0);

        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&(block_payload.len() as u16).to_le_bytes());
        cab.extend_from_slice(&cb_uncomp.to_le_bytes());
        cab.extend_from_slice(block_payload);
        cab
    }

    #[test]
    fn detects_lzms_folder() {
        let cab: Vec<u8> = build_raw_block_cab("a.txt", b"hello world", 11);
        assert!(cab_uses_lzms(&cab));
    }

    #[test]
    fn stored_block_passthrough_extracts() {
        let payload: &[u8] = b"uncompressed stored bytes in an lzms folder block";
        let cab: Vec<u8> = build_raw_block_cab("stored.bin", payload, 0);
        let files: Vec<CabLzmsFile> = extract_cab_lzms(&cab, 1 << 20).expect("extract stored");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "stored.bin");
        assert_eq!(files[0].data, payload);
    }

    #[test]
    fn odd_length_lzms_block_fails_honestly() {
        let cab: Vec<u8> = build_raw_block_cab("x.bin", &[0u8; 13], 64);
        let err: Error = extract_cab_lzms(&cab, 1 << 20).expect_err("odd-length block must fail");
        match err {
            Error::Cab(message) => assert!(message.contains("cab-lzms")),
            other => panic!("expected cab error, got {other:?}"),
        }
    }

    #[test]
    fn non_cab_is_rejected() {
        assert!(!cab_uses_lzms(b"not a cab at all"));
        assert!(extract_cab_lzms(b"not a cab", 1024).is_err());
    }

    #[test]
    fn real_lzms_cab_single_file_round_trips() {
        let mut payload: Vec<u8> = Vec::new();
        for _ in 0..120 {
            payload.extend_from_slice(b"cabinet lzms payload, the quick brown fox. ");
        }
        let cab: Vec<u8> = build_lzms_cab(&[("doc.txt", &payload)]);
        assert!(cab_uses_lzms(&cab));
        let files: Vec<CabLzmsFile> =
            extract_cab_lzms(&cab, 1 << 24).expect("extract real lzms cab");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "doc.txt");
        assert_eq!(
            files[0].data, payload,
            "lzms cab single-file decode is not byte-identical to the original"
        );
    }

    #[test]
    fn real_lzms_cab_multi_file_and_multi_block_round_trips() {
        let mut big: Vec<u8> = Vec::with_capacity(80_000);
        let mut state: u32 = 0x0bad_f00d;
        for _ in 0..80_000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            big.push((state >> 16) as u8);
        }
        let small: &[u8] = b"second member, short and sweet";
        let mut texty: Vec<u8> = Vec::new();
        for _ in 0..400 {
            texty.extend_from_slice(b"AAAABBBBCCCCDDDD");
        }

        let files: [(&str, &[u8]); 3] =
            [("rand.bin", &big), ("note.txt", small), ("rle.dat", &texty)];
        let cab: Vec<u8> = build_lzms_cab(&files);
        let extracted: Vec<CabLzmsFile> =
            extract_cab_lzms(&cab, 1 << 24).expect("extract multi-file lzms cab");
        assert_eq!(extracted.len(), 3);
        for ((name, original), got) in files.iter().zip(extracted.iter()) {
            assert_eq!(&got.name, name);
            assert_eq!(
                &got.data, original,
                "lzms cab member `{name}` is not byte-identical after round trip"
            );
        }
    }
}
