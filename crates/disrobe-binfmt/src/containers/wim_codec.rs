use crate::error::{Error, Result};
use crate::quota::{ExtractionQuota, QuotaGuard};

use super::wim::{WimCompression, WimHeader, WimResource};

const XPRESS_NUM_SYMBOLS: usize = 512;
const XPRESS_NUM_CHARS: u32 = 256;
const XPRESS_MIN_MATCH_LEN: u32 = 3;
const XPRESS_TABLE_BYTES: usize = XPRESS_NUM_SYMBOLS / 2;
const XPRESS_MAX_CODEWORD_LEN: u32 = 15;

const LZX_MIN_MATCH_LEN: u32 = 2;
const LZX_NUM_CHARS: u32 = 256;
const LZX_NUM_PRIMARY_LENS: u32 = 7;
const LZX_NUM_LEN_HEADERS: u32 = LZX_NUM_PRIMARY_LENS + 1;
const LZX_NUM_RECENT_OFFSETS: usize = 3;
const LZX_NUM_ALIGNED_BITS: u32 = 3;
const LZX_ALIGNEDCODE_NUM_SYMBOLS: usize = 1 << LZX_NUM_ALIGNED_BITS;
const LZX_PRECODE_NUM_SYMBOLS: usize = 20;
const LZX_LENCODE_NUM_SYMBOLS: usize = 249;
const LZX_OFFSET_OFFSET: u32 = 2;
const LZX_WIM_MAGIC_FILESIZE: i64 = 12_000_000;
const LZX_BLOCKTYPE_VERBATIM: u32 = 1;
const LZX_BLOCKTYPE_ALIGNED: u32 = 2;
const LZX_BLOCKTYPE_UNCOMPRESSED: u32 = 3;
const LZX_DEFAULT_BLOCK_SIZE: usize = 32_768;
const LZX_MAX_CODEWORD_LEN: u32 = 16;
const LZX_PRECODE_MAX_CODEWORD_LEN: u32 = 15;
const LZX_ALIGNED_MAX_CODEWORD_LEN: u32 = 7;
const LZX_READ_BLOCKSIZE_BITS: u32 = 16;

const LZX_OFFSET_SLOT_BASE: [u32; 51] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12_288, 16_384, 24_576, 32_768, 49_152, 65_536, 98_304, 131_072,
    196_608, 262_144, 393_216, 524_288, 655_360, 786_432, 917_504, 1_048_576, 1_179_648, 1_310_720,
    1_441_792, 1_572_864, 1_703_936, 1_835_008, 1_966_080, 2_097_152,
];

const LZX_EXTRA_OFFSET_BITS: [u32; 51] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
];

#[derive(Debug)]
struct BitReader<'a> {
    data: &'a [u8],
    next: usize,
    bitbuf: u32,
    bitsleft: u32,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            next: 0,
            bitbuf: 0,
            bitsleft: 0,
        }
    }

    fn ensure(&mut self, need: u32) {
        while self.bitsleft < need {
            if self.next + 2 > self.data.len() {
                self.bitsleft = 32;
                return;
            }
            let lo: u8 = self.data[self.next];
            let hi: u8 = self.data[self.next + 1];
            self.next += 2;
            let word: u32 = u32::from(u16::from_le_bytes([lo, hi]));
            self.bitbuf |= word << (16 - self.bitsleft);
            self.bitsleft += 16;
        }
    }

    fn peek(&mut self, count: u32) -> u32 {
        if count == 0 {
            return 0;
        }
        self.ensure(count);
        self.bitbuf >> (32 - count)
    }

    const fn remove(&mut self, count: u32) {
        self.bitbuf <<= count;
        self.bitsleft -= count;
    }

    fn read_bits(&mut self, count: u32) -> u32 {
        let value: u32 = self.peek(count);
        self.remove(count);
        value
    }

    const fn align_to_word(&mut self) {
        self.bitbuf = 0;
        self.bitsleft = 0;
    }

    fn read_raw_byte(&mut self) -> Result<u8> {
        let byte: u8 = *self
            .data
            .get(self.next)
            .ok_or_else(|| Error::Decompression("wim bitstream underrun".to_owned()))?;
        self.next += 1;
        Ok(byte)
    }

    fn read_raw_u16(&mut self) -> Result<u16> {
        let lo: u8 = self.read_raw_byte()?;
        let hi: u8 = self.read_raw_byte()?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    fn read_aligned_u32_le(&mut self) -> Result<u32> {
        let b0: u8 = self.read_raw_byte()?;
        let b1: u8 = self.read_raw_byte()?;
        let b2: u8 = self.read_raw_byte()?;
        let b3: u8 = self.read_raw_byte()?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }
}

#[derive(Debug)]
struct HuffmanDecoder {
    counts: Vec<u32>,
    symbols: Vec<u16>,
    max_len: u32,
}

impl HuffmanDecoder {
    fn from_lengths(lengths: &[u8], max_len: u32) -> Result<Self> {
        let mut counts: Vec<u32> = vec![0u32; (max_len + 1) as usize];
        for &len in lengths {
            let len_usize: usize = len as usize;
            if len_usize > max_len as usize {
                return Err(Error::Decompression(
                    "wim huffman code length out of range".to_owned(),
                ));
            }
            counts[len_usize] += 1;
        }
        counts[0] = 0;
        let mut total: u32 = 0;
        for len in 1..=max_len {
            total += counts[len as usize];
            if total > (1u32 << len) {
                return Err(Error::Decompression(
                    "wim huffman code is over-subscribed".to_owned(),
                ));
            }
        }
        let mut offsets: Vec<u32> = vec![0u32; (max_len + 2) as usize];
        for len in 1..=max_len {
            offsets[(len + 1) as usize] = offsets[len as usize] + counts[len as usize];
        }
        let assigned: u32 = offsets[(max_len + 1) as usize];
        let mut symbols: Vec<u16> = vec![0u16; assigned as usize];
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let slot: u32 = offsets[len as usize];
                symbols[slot as usize] = sym as u16;
                offsets[len as usize] += 1;
            }
        }
        Ok(Self {
            counts,
            symbols,
            max_len,
        })
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        let mut code: u32 = 0;
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        for len in 1..=self.max_len {
            code |= reader.read_bits(1);
            let count: u32 = self.counts[len as usize];
            if code < first + count {
                let slot: u32 = index + (code - first);
                let symbol: u16 = *self.symbols.get(slot as usize).ok_or_else(|| {
                    Error::Decompression("wim huffman symbol slot overflow".to_owned())
                })?;
                return Ok(symbol);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::Decompression(
            "wim huffman code not found".to_owned(),
        ))
    }
}

fn xpress_read_lengths(data: &[u8]) -> Result<[u8; XPRESS_NUM_SYMBOLS]> {
    if data.len() < XPRESS_TABLE_BYTES {
        return Err(Error::Decompression(
            "wim xpress chunk shorter than huffman table".to_owned(),
        ));
    }
    let mut lengths: [u8; XPRESS_NUM_SYMBOLS] = [0u8; XPRESS_NUM_SYMBOLS];
    for (byte_index, &packed) in data[..XPRESS_TABLE_BYTES].iter().enumerate() {
        lengths[byte_index * 2] = packed & 0x0f;
        lengths[byte_index * 2 + 1] = packed >> 4;
    }
    Ok(lengths)
}

fn decompress_xpress_chunk(chunk: &[u8], out_len: usize, out: &mut Vec<u8>) -> Result<()> {
    let lengths: [u8; XPRESS_NUM_SYMBOLS] = xpress_read_lengths(chunk)?;
    let decoder: HuffmanDecoder = HuffmanDecoder::from_lengths(&lengths, XPRESS_MAX_CODEWORD_LEN)?;
    let mut reader: BitReader<'_> = BitReader::new(&chunk[XPRESS_TABLE_BYTES..]);
    let start: usize = out.len();
    let target: usize = start + out_len;
    while out.len() < target {
        let symbol: u32 = decoder.decode(&mut reader)? as u32;
        if symbol < XPRESS_NUM_CHARS {
            out.push(symbol as u8);
            continue;
        }
        let length_header: u32 = symbol & 0x0f;
        let offset_bits: u32 = (symbol >> 4) & 0x0f;
        reader.ensure(16);
        let offset_low: u32 = reader.read_bits(offset_bits);
        let match_offset: u32 = (1u32 << offset_bits) + offset_low;
        let mut match_len: u32 = length_header;
        if length_header == 0x0f {
            let extra: u8 = reader.read_raw_byte()?;
            match_len += u32::from(extra);
            if match_len == 0x0f + 0xff {
                match_len = u32::from(reader.read_raw_u16()?);
            }
        }
        match_len += XPRESS_MIN_MATCH_LEN;
        copy_match(out, start, match_offset as usize, match_len as usize)?;
    }
    Ok(())
}

fn copy_match(out: &mut Vec<u8>, floor: usize, offset: usize, length: usize) -> Result<()> {
    if offset == 0 || offset > out.len().saturating_sub(floor) {
        return Err(Error::Decompression(
            "wim match offset escapes output window".to_owned(),
        ));
    }
    let mut src: usize = out.len() - offset;
    let end: usize = src + length;
    while src < end {
        let byte: u8 = out[src];
        out.push(byte);
        src += 1;
    }
    Ok(())
}

#[derive(Debug)]
struct LzxState {
    recent: [u32; LZX_NUM_RECENT_OFFSETS],
    main_num_symbols: usize,
}

impl LzxState {
    const fn new(window_size: usize) -> Self {
        let num_offset_slots: usize = lzx_num_offset_slots(window_size);
        let main_num_symbols: usize =
            LZX_NUM_CHARS as usize + num_offset_slots * LZX_NUM_LEN_HEADERS as usize;
        Self {
            recent: [1u32; LZX_NUM_RECENT_OFFSETS],
            main_num_symbols,
        }
    }
}

const fn lzx_num_offset_slots(window_size: usize) -> usize {
    let mut slots: usize = 1;
    while slots < LZX_OFFSET_SLOT_BASE.len() && (LZX_OFFSET_SLOT_BASE[slots] as usize) < window_size
    {
        slots += 1;
    }
    slots
}

fn lzx_read_precode_lengths(reader: &mut BitReader<'_>) -> [u8; LZX_PRECODE_NUM_SYMBOLS] {
    let mut lengths: [u8; LZX_PRECODE_NUM_SYMBOLS] = [0u8; LZX_PRECODE_NUM_SYMBOLS];
    for slot in &mut lengths {
        *slot = reader.read_bits(4) as u8;
    }
    lengths
}

fn lzx_read_code_lengths(
    reader: &mut BitReader<'_>,
    lengths: &mut [u8],
    count: usize,
) -> Result<()> {
    let precode_lengths: [u8; LZX_PRECODE_NUM_SYMBOLS] = lzx_read_precode_lengths(reader);
    let precode: HuffmanDecoder =
        HuffmanDecoder::from_lengths(&precode_lengths, LZX_PRECODE_MAX_CODEWORD_LEN)?;
    let mut index: usize = 0;
    while index < count {
        let sym: u32 = precode.decode(reader)? as u32;
        match sym {
            17 => {
                let run: u32 = reader.read_bits(4) + 4;
                for _ in 0..run {
                    if index >= count {
                        break;
                    }
                    lengths[index] = 0;
                    index += 1;
                }
            }
            18 => {
                let run: u32 = reader.read_bits(5) + 20;
                for _ in 0..run {
                    if index >= count {
                        break;
                    }
                    lengths[index] = 0;
                    index += 1;
                }
            }
            19 => {
                let run: u32 = reader.read_bits(1) + 4;
                let value_sym: u32 = precode.decode(reader)? as u32;
                let new_len: u8 = lzx_delta_length(lengths[index], value_sym)?;
                for _ in 0..run {
                    if index >= count {
                        break;
                    }
                    lengths[index] = new_len;
                    index += 1;
                }
            }
            0..=16 => {
                lengths[index] = lzx_delta_length(lengths[index], sym)?;
                index += 1;
            }
            _ => {
                return Err(Error::Decompression(
                    "wim lzx precode symbol out of range".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn lzx_delta_length(previous: u8, symbol: u32) -> Result<u8> {
    let delta: i32 = i32::from(previous) - symbol as i32;
    let normalized: i32 = delta.rem_euclid(17);
    u8::try_from(normalized)
        .map_err(|_| Error::Decompression("wim lzx delta length overflow".to_owned()))
}

#[derive(Debug)]
struct LzxBlockCodes {
    main: HuffmanDecoder,
    length: HuffmanDecoder,
    aligned: Option<HuffmanDecoder>,
}

fn lzx_read_block_codes(
    reader: &mut BitReader<'_>,
    state: &LzxState,
    block_type: u32,
    main_lengths: &mut [u8],
    length_lengths: &mut [u8],
) -> Result<LzxBlockCodes> {
    let aligned: Option<HuffmanDecoder> = if block_type == LZX_BLOCKTYPE_ALIGNED {
        let mut aligned_lengths: [u8; LZX_ALIGNEDCODE_NUM_SYMBOLS] =
            [0u8; LZX_ALIGNEDCODE_NUM_SYMBOLS];
        for slot in &mut aligned_lengths {
            *slot = reader.read_bits(3) as u8;
        }
        Some(HuffmanDecoder::from_lengths(
            &aligned_lengths,
            LZX_ALIGNED_MAX_CODEWORD_LEN,
        )?)
    } else {
        None
    };
    lzx_read_code_lengths(
        reader,
        &mut main_lengths[..LZX_NUM_CHARS as usize],
        LZX_NUM_CHARS as usize,
    )?;
    lzx_read_code_lengths(
        reader,
        &mut main_lengths[LZX_NUM_CHARS as usize..state.main_num_symbols],
        state.main_num_symbols - LZX_NUM_CHARS as usize,
    )?;
    let main: HuffmanDecoder = HuffmanDecoder::from_lengths(
        &main_lengths[..state.main_num_symbols],
        LZX_MAX_CODEWORD_LEN,
    )?;
    lzx_read_code_lengths(
        reader,
        &mut length_lengths[..LZX_LENCODE_NUM_SYMBOLS],
        LZX_LENCODE_NUM_SYMBOLS,
    )?;
    let length: HuffmanDecoder = HuffmanDecoder::from_lengths(
        &length_lengths[..LZX_LENCODE_NUM_SYMBOLS],
        LZX_MAX_CODEWORD_LEN,
    )?;
    Ok(LzxBlockCodes {
        main,
        length,
        aligned,
    })
}

fn lzx_decode_match(
    reader: &mut BitReader<'_>,
    codes: &LzxBlockCodes,
    state: &mut LzxState,
    main_sym: u32,
) -> Result<(u32, u32)> {
    let length_header: u32 = (main_sym - LZX_NUM_CHARS) % LZX_NUM_LEN_HEADERS;
    let offset_slot: u32 = (main_sym - LZX_NUM_CHARS) / LZX_NUM_LEN_HEADERS;
    let mut match_len: u32 = length_header + LZX_MIN_MATCH_LEN;
    if length_header == LZX_NUM_PRIMARY_LENS {
        let extra: u32 = codes.length.decode(reader)? as u32;
        match_len += extra;
    }
    let match_offset: u32 = if (offset_slot as usize) < LZX_NUM_RECENT_OFFSETS {
        let recovered: u32 = state.recent[offset_slot as usize];
        if offset_slot != 0 {
            state.recent.swap(0, offset_slot as usize);
        }
        recovered
    } else {
        let slot_index: usize = offset_slot as usize;
        if slot_index >= LZX_EXTRA_OFFSET_BITS.len() {
            return Err(Error::Decompression(
                "wim lzx offset slot out of range".to_owned(),
            ));
        }
        let num_extra: u32 = LZX_EXTRA_OFFSET_BITS[slot_index];
        let base: u32 = LZX_OFFSET_SLOT_BASE[slot_index];
        let verbatim_bits: u32;
        let aligned_bits: u32;
        match codes.aligned.as_ref() {
            Some(aligned_decoder) if num_extra >= LZX_NUM_ALIGNED_BITS => {
                verbatim_bits =
                    reader.read_bits(num_extra - LZX_NUM_ALIGNED_BITS) << LZX_NUM_ALIGNED_BITS;
                aligned_bits = aligned_decoder.decode(reader)? as u32;
            }
            _ => {
                verbatim_bits = reader.read_bits(num_extra);
                aligned_bits = 0;
            }
        }
        let formatted_offset: u32 = base + verbatim_bits + aligned_bits;
        let offset: u32 = formatted_offset - LZX_OFFSET_OFFSET;
        state.recent[2] = state.recent[1];
        state.recent[1] = state.recent[0];
        state.recent[0] = offset;
        offset
    };
    Ok((match_len, match_offset))
}

fn lzx_decode_block(
    reader: &mut BitReader<'_>,
    codes: &LzxBlockCodes,
    state: &mut LzxState,
    block_size: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    let start: usize = out.len();
    let target: usize = start + block_size;
    while out.len() < target {
        let main_sym: u32 = codes.main.decode(reader)? as u32;
        if main_sym < LZX_NUM_CHARS {
            out.push(main_sym as u8);
            continue;
        }
        if main_sym as usize >= state.main_num_symbols {
            return Err(Error::Decompression(
                "wim lzx main symbol out of range".to_owned(),
            ));
        }
        let (match_len, match_offset): (u32, u32) =
            lzx_decode_match(reader, codes, state, main_sym)?;
        copy_match(out, start, match_offset as usize, match_len as usize)?;
    }
    Ok(())
}

fn lzx_undo_e8(data: &mut [u8]) {
    if data.len() <= 10 {
        return;
    }
    let limit: usize = data.len() - 10;
    let mut i: usize = 0;
    while i < limit {
        if data[i] == 0xe8 {
            let target: [u8; 4] = [data[i + 1], data[i + 2], data[i + 3], data[i + 4]];
            let abs_offset: i32 = i32::from_le_bytes(target);
            let input_pos: i32 = i as i32;
            if abs_offset >= 0 {
                if (abs_offset as i64) < LZX_WIM_MAGIC_FILESIZE {
                    let rel: i32 = abs_offset - input_pos;
                    let bytes: [u8; 4] = rel.to_le_bytes();
                    data[i + 1..i + 5].copy_from_slice(&bytes);
                }
            } else if i64::from(abs_offset) >= -i64::from(input_pos) {
                let rel: i32 = (i64::from(abs_offset) + LZX_WIM_MAGIC_FILESIZE) as i32;
                let bytes: [u8; 4] = rel.to_le_bytes();
                data[i + 1..i + 5].copy_from_slice(&bytes);
            }
            i += 5;
        } else {
            i += 1;
        }
    }
}

fn decompress_lzx_chunk(chunk: &[u8], out_len: usize, out: &mut Vec<u8>) -> Result<()> {
    let window_size: usize = LZX_DEFAULT_BLOCK_SIZE.max(out_len);
    let mut state: LzxState = LzxState::new(window_size);
    let mut reader: BitReader<'_> = BitReader::new(chunk);
    let chunk_start: usize = out.len();
    let target: usize = chunk_start + out_len;
    let mut main_lengths: Vec<u8> = vec![0u8; state.main_num_symbols];
    let mut length_lengths: Vec<u8> = vec![0u8; LZX_LENCODE_NUM_SYMBOLS];
    let window_order: u32 = window_size.next_power_of_two().trailing_zeros();
    while out.len() < target {
        let block_type: u32 = reader.read_bits(3);
        let block_size: usize = lzx_read_block_size(&mut reader, window_order);
        let remaining: usize = target - out.len();
        let effective: usize = block_size.min(remaining);
        match block_type {
            LZX_BLOCKTYPE_UNCOMPRESSED => {
                reader.align_to_word();
                state.recent[0] = reader.read_aligned_u32_le()?;
                state.recent[1] = reader.read_aligned_u32_le()?;
                state.recent[2] = reader.read_aligned_u32_le()?;
                for _ in 0..effective {
                    out.push(reader.read_raw_byte()?);
                }
                if effective % 2 == 1 {
                    let _: u8 = reader.read_raw_byte()?;
                }
            }
            LZX_BLOCKTYPE_VERBATIM | LZX_BLOCKTYPE_ALIGNED => {
                let codes: LzxBlockCodes = lzx_read_block_codes(
                    &mut reader,
                    &state,
                    block_type,
                    &mut main_lengths,
                    &mut length_lengths,
                )?;
                lzx_decode_block(&mut reader, &codes, &mut state, effective, out)?;
            }
            _ => {
                return Err(Error::Decompression(
                    "wim lzx unknown block type".to_owned(),
                ));
            }
        }
    }
    lzx_undo_e8(&mut out[chunk_start..]);
    Ok(())
}

#[cfg(test)]
pub(crate) fn decompress_lzx_chunk_for_test(
    chunk: &[u8],
    out_len: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    decompress_lzx_chunk(chunk, out_len, out)
}

fn lzx_read_block_size(reader: &mut BitReader<'_>, window_order: u32) -> usize {
    if reader.read_bits(1) == 1 {
        return LZX_DEFAULT_BLOCK_SIZE;
    }
    let mut size: u32 = reader.read_bits(LZX_READ_BLOCKSIZE_BITS);
    if window_order >= 16 {
        size <<= 8;
        size |= reader.read_bits(8);
    }
    size as usize
}

#[derive(Debug, Clone, Copy)]
struct ChunkTable {
    chunk_size: usize,
    num_chunks: usize,
    entry_width: usize,
    table_bytes: usize,
}

fn chunk_table_layout(original_size: u64, chunk_size: u32) -> Result<ChunkTable> {
    let chunk_size_usize: usize = usize::try_from(chunk_size)
        .map_err(|_| Error::Decompression("wim chunk size overflow".to_owned()))?;
    if chunk_size_usize == 0 {
        return Err(Error::Decompression("wim chunk size is zero".to_owned()));
    }
    let original_usize: usize = usize::try_from(original_size)
        .map_err(|_| Error::Decompression("wim resource size overflow".to_owned()))?;
    let num_chunks: usize = original_usize.div_ceil(chunk_size_usize).max(1);
    let entry_width: usize = if original_size > u64::from(u32::MAX) {
        8
    } else {
        4
    };
    let table_bytes: usize = (num_chunks - 1) * entry_width;
    Ok(ChunkTable {
        chunk_size: chunk_size_usize,
        num_chunks,
        entry_width,
        table_bytes,
    })
}

fn read_chunk_offsets(resource: &[u8], layout: ChunkTable) -> Result<Vec<usize>> {
    if resource.len() < layout.table_bytes {
        return Err(Error::Decompression(
            "wim compressed resource shorter than chunk table".to_owned(),
        ));
    }
    let mut offsets: Vec<usize> = Vec::with_capacity(layout.num_chunks + 1);
    offsets.push(0);
    let mut cursor: usize = 0;
    for _ in 0..(layout.num_chunks - 1) {
        let value: u64 = if layout.entry_width == 8 {
            let mut buf: [u8; 8] = [0u8; 8];
            buf.copy_from_slice(&resource[cursor..cursor + 8]);
            u64::from_le_bytes(buf)
        } else {
            let mut buf: [u8; 4] = [0u8; 4];
            buf.copy_from_slice(&resource[cursor..cursor + 4]);
            u64::from(u32::from_le_bytes(buf))
        };
        let offset: usize = usize::try_from(value)
            .map_err(|_| Error::Decompression("wim chunk offset overflow".to_owned()))?;
        offsets.push(offset);
        cursor += layout.entry_width;
    }
    let payload_len: usize = resource.len() - layout.table_bytes;
    offsets.push(payload_len);
    Ok(offsets)
}

pub fn decompress_wim_resource(
    resource: &[u8],
    compression: WimCompression,
    original_size: u64,
    chunk_size: u32,
    quota: &ExtractionQuota,
) -> Result<Vec<u8>> {
    let original_usize: usize = usize::try_from(original_size)
        .map_err(|_| Error::Decompression("wim resource size overflow".to_owned()))?;
    let mut guard: QuotaGuard = QuotaGuard::new(*quota);
    guard.admit_entry("wim-resource", original_size, resource.len() as u64)?;
    if matches!(compression, WimCompression::None) {
        return resource
            .get(..original_usize)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error::Decompression("wim uncompressed resource truncated".to_owned()));
    }
    let layout: ChunkTable = chunk_table_layout(original_size, chunk_size)?;
    let offsets: Vec<usize> = read_chunk_offsets(resource, layout)?;
    let payload: &[u8] = &resource[layout.table_bytes..];
    let mut out: Vec<u8> = Vec::with_capacity(original_usize);
    for chunk_index in 0..layout.num_chunks {
        let begin: usize = offsets[chunk_index];
        let end: usize = offsets[chunk_index + 1];
        let chunk: &[u8] = payload
            .get(begin..end)
            .ok_or_else(|| Error::Decompression("wim chunk bounds escape payload".to_owned()))?;
        let produced: usize = out.len();
        let remaining: usize = original_usize - produced;
        let chunk_out_len: usize = layout.chunk_size.min(remaining);
        if chunk.len() == chunk_out_len {
            out.extend_from_slice(chunk);
            continue;
        }
        match compression {
            WimCompression::Xpress => decompress_xpress_chunk(chunk, chunk_out_len, &mut out)?,
            WimCompression::Lzx => decompress_lzx_chunk(chunk, chunk_out_len, &mut out)?,
            WimCompression::Lzms => {
                let decoded: Vec<u8> = super::lzms::lzms_decompress(chunk, chunk_out_len)?;
                out.extend_from_slice(&decoded);
            }
            WimCompression::None | WimCompression::Unknown => {
                return Err(Error::Decompression(
                    "wim resource has no chunk codec".to_owned(),
                ));
            }
        }
        if out.len() != produced + chunk_out_len {
            return Err(Error::Decompression(
                "wim chunk produced unexpected length".to_owned(),
            ));
        }
    }
    out.truncate(original_usize);
    Ok(out)
}

#[must_use]
pub const fn codec_is_implemented(compression: WimCompression) -> bool {
    matches!(
        compression,
        WimCompression::None | WimCompression::Xpress | WimCompression::Lzx | WimCompression::Lzms
    )
}

pub fn decompress_named_resource(
    bytes: &[u8],
    header: &WimHeader,
    resource: &WimResource,
    quota: &ExtractionQuota,
) -> Result<Vec<u8>> {
    let offset: usize = usize::try_from(resource.offset)
        .map_err(|_| Error::Decompression("wim resource offset overflow".to_owned()))?;
    let size: usize = usize::try_from(resource.size)
        .map_err(|_| Error::Decompression("wim resource size overflow".to_owned()))?;
    let slice: &[u8] = bytes
        .get(
            offset
                ..offset.checked_add(size).ok_or_else(|| {
                    Error::Decompression("wim resource range overflow".to_owned())
                })?,
        )
        .ok_or_else(|| Error::Decompression("wim resource out of bounds".to_owned()))?;
    let compression: WimCompression = if resource.is_compressed() {
        header.compression
    } else {
        WimCompression::None
    };
    let chunk_size: u32 = if header.chunk_size == 0 {
        LZX_DEFAULT_BLOCK_SIZE as u32
    } else {
        header.chunk_size
    };
    decompress_wim_resource(
        slice,
        compression,
        resource.original_size,
        chunk_size,
        quota,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const MS_XCA_ALPHABET_COMPRESSED: [u8; 276] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x45,
        0x44, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xd8, 0x52, 0x3e, 0xd7, 0x94, 0x11, 0x5b, 0xe9, 0x19, 0x5f, 0xf9, 0xd6, 0x7c, 0xdf,
        0x8d, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];

    const MS_XCA_ABC_COMPRESSED: [u8; 263] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x30, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xa8, 0xdc, 0x00, 0x00, 0xff, 0x26, 0x01,
    ];

    #[test]
    fn xpress_decodes_ms_xca_alphabet_vector() {
        let expected: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        let mut out: Vec<u8> = Vec::new();
        decompress_xpress_chunk(&MS_XCA_ALPHABET_COMPRESSED, expected.len(), &mut out)
            .expect("decode alphabet vector");
        assert_eq!(out, expected);
    }

    #[test]
    fn xpress_decodes_ms_xca_abc_match_vector() {
        let unit: &[u8] = b"abc";
        let mut expected: Vec<u8> = Vec::with_capacity(300);
        for _ in 0..100 {
            expected.extend_from_slice(unit);
        }
        let mut out: Vec<u8> = Vec::new();
        decompress_xpress_chunk(&MS_XCA_ABC_COMPRESSED, expected.len(), &mut out)
            .expect("decode abc match vector");
        assert_eq!(out.len(), 300);
        assert_eq!(out, expected);
    }

    #[test]
    fn xpress_resource_single_chunk_routes_via_chunk_table() {
        let expected: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        let decoded: Vec<u8> = decompress_wim_resource(
            &MS_XCA_ALPHABET_COMPRESSED,
            WimCompression::Xpress,
            expected.len() as u64,
            32_768,
            &ExtractionQuota::default_safe(),
        )
        .expect("route single-chunk xpress");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn bit_reader_reads_msb_first_from_le_words() {
        let data: [u8; 4] = [0x34, 0x12, 0x78, 0x56];
        let mut reader: BitReader<'_> = BitReader::new(&data);
        assert_eq!(reader.read_bits(4), 0x1);
        assert_eq!(reader.read_bits(4), 0x2);
        assert_eq!(reader.read_bits(8), 0x34);
        assert_eq!(reader.read_bits(16), 0x5678);
    }

    #[test]
    fn canonical_huffman_decodes_known_assignment() {
        let mut lengths: Vec<u8> = vec![0u8; 4];
        lengths[0] = 1;
        lengths[1] = 2;
        lengths[2] = 3;
        lengths[3] = 3;
        let decoder: HuffmanDecoder = HuffmanDecoder::from_lengths(&lengths, 3).expect("build");
        let stream: [u8; 2] = [0x80, 0x5b];
        let mut reader: BitReader<'_> = BitReader::new(&stream);
        assert_eq!(decoder.decode(&mut reader).expect("sym0"), 0);
        assert_eq!(decoder.decode(&mut reader).expect("sym1"), 1);
        assert_eq!(decoder.decode(&mut reader).expect("sym2"), 2);
        assert_eq!(decoder.decode(&mut reader).expect("sym3"), 3);
    }

    #[test]
    fn huffman_rejects_oversubscribed_code() {
        let lengths: Vec<u8> = vec![1, 1, 1];
        assert!(HuffmanDecoder::from_lengths(&lengths, 4).is_err());
    }

    #[test]
    fn huffman_single_symbol_length_one_decodes() {
        let mut lengths: Vec<u8> = vec![0u8; 4];
        lengths[2] = 1;
        let decoder: HuffmanDecoder = HuffmanDecoder::from_lengths(&lengths, 15).expect("build");
        let stream: [u8; 2] = [0x00, 0x00];
        let mut reader: BitReader<'_> = BitReader::new(&stream);
        assert_eq!(decoder.decode(&mut reader).expect("only symbol"), 2);
        assert_eq!(decoder.decode(&mut reader).expect("again"), 2);
    }

    #[test]
    fn chunk_table_layout_matches_wim_formula() {
        let layout: ChunkTable = chunk_table_layout(100_000, 32_768).expect("layout");
        assert_eq!(layout.num_chunks, 4);
        assert_eq!(layout.entry_width, 4);
        assert_eq!(layout.table_bytes, 12);
        let layout_single: ChunkTable = chunk_table_layout(1000, 32_768).expect("single");
        assert_eq!(layout_single.num_chunks, 1);
        assert_eq!(layout_single.table_bytes, 0);
    }

    #[test]
    fn lzx_offset_slot_count_for_default_window() {
        assert_eq!(lzx_num_offset_slots(32_768), 30);
    }

    #[test]
    fn lzx_e8_undo_reverses_good_translation() {
        let mut data: Vec<u8> = vec![0u8; 64];
        data[16] = 0xe8;
        let absolute: i32 = 5000;
        data[17..21].copy_from_slice(&absolute.to_le_bytes());
        lzx_undo_e8(&mut data);
        let relative: i32 = i32::from_le_bytes([data[17], data[18], data[19], data[20]]);
        assert_eq!(relative, absolute - 16);
    }

    #[test]
    fn lzms_resource_routes_through_decoder() {
        let resource: [u8; 5] = [0u8; 5];
        let err: Error = decompress_wim_resource(
            &resource,
            WimCompression::Lzms,
            4,
            32_768,
            &ExtractionQuota::unrestricted(),
        )
        .expect_err("odd-length lzms chunk must be rejected by the decoder");
        match err {
            Error::Decompression(message) => {
                assert!(
                    message.contains("lzms"),
                    "error must come from the lzms decoder, got: {message}"
                );
            }
            other => panic!("expected lzms decode failure, got {other:?}"),
        }
    }

    #[test]
    fn lzx_uncompressed_block_round_trips_raw_payload() {
        let chunk: [u8; 56] = [
            0x02, 0x60, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        ];
        let expected: Vec<u8> = (0u8..40u8).collect();
        let mut out: Vec<u8> = Vec::new();
        decompress_lzx_chunk(&chunk, expected.len(), &mut out).expect("lzx uncompressed block");
        assert_eq!(out, expected);
    }

    #[test]
    fn lzx_xpress_lzms_report_as_implemented() {
        assert!(codec_is_implemented(WimCompression::Xpress));
        assert!(codec_is_implemented(WimCompression::Lzx));
        assert!(codec_is_implemented(WimCompression::None));
        assert!(codec_is_implemented(WimCompression::Lzms));
        assert!(!codec_is_implemented(WimCompression::Unknown));
    }
}
