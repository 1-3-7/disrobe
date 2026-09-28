use super::lzms::lzms_compress;

const CAB_MAGIC: [u8; 4] = *b"MSCF";
const CFHEADER_FIXED_LEN: usize = 36;
const CFFOLDER_FIXED_LEN: usize = 8;
const CFFILE_FIXED_LEN: usize = 16;
const CFDATA_FIXED_LEN: usize = 8;
const COMPTYPE_LZMS: u16 = 5;

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
