use crate::error::{Error, Result};

const LZX_NUM_CHARS: usize = 256;
const LZX_NUM_PRIMARY_LENS: u32 = 7;
const LZX_NUM_LEN_HEADERS: u32 = LZX_NUM_PRIMARY_LENS + 1;
const LZX_NUM_ALIGNED_BITS: u32 = 3;
const LZX_ALIGNEDCODE_NUM_SYMBOLS: usize = 1 << LZX_NUM_ALIGNED_BITS;
const LZX_PRECODE_NUM_SYMBOLS: usize = 20;
const LZX_LENCODE_NUM_SYMBOLS: usize = 249;
const LZX_OFFSET_OFFSET: u32 = 2;
const LZX_MIN_MATCH_LEN: u32 = 2;
const LZX_MAX_MATCH_LEN: u32 =
    LZX_NUM_PRIMARY_LENS + LZX_MIN_MATCH_LEN + LZX_LENCODE_NUM_SYMBOLS as u32 - 1;
const LZX_BLOCKTYPE_VERBATIM: u32 = 1;
const LZX_BLOCKTYPE_ALIGNED: u32 = 2;
const LZX_DEFAULT_BLOCK_SIZE: usize = 32_768;
const LZX_MAX_CODEWORD_LEN: u32 = 16;
const LZX_PRECODE_MAX_CODEWORD_LEN: u32 = 15;
const LZX_ALIGNED_MAX_CODEWORD_LEN: u32 = 7;
const LZX_READ_BLOCKSIZE_BITS: u32 = 16;
const LZX_WIM_MAGIC_FILESIZE: i64 = 12_000_000;

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
struct BitWriter {
    bitbuf: u32,
    bitcount: u32,
    units: Vec<u16>,
}

impl BitWriter {
    const fn new() -> Self {
        Self {
            bitbuf: 0,
            bitcount: 0,
            units: Vec::new(),
        }
    }

    fn write_bits(&mut self, value: u32, count: u32) {
        if count == 0 {
            return;
        }
        let masked: u32 = if count >= 32 {
            value
        } else {
            value & ((1u32 << count) - 1)
        };
        self.bitbuf = (self.bitbuf << count) | masked;
        self.bitcount += count;
        while self.bitcount >= 16 {
            self.bitcount -= 16;
            let unit: u16 = (self.bitbuf >> self.bitcount) as u16;
            self.units.push(unit);
        }
    }

    fn align_to_unit(&mut self) {
        if self.bitcount != 0 {
            let pad: u32 = 16 - self.bitcount;
            self.write_bits(0, pad);
        }
    }

    fn into_bytes(mut self) -> Vec<u8> {
        self.align_to_unit();
        let mut bytes: Vec<u8> = Vec::with_capacity(self.units.len() * 2);
        for unit in &self.units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
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

fn offset_slot_for(formatted_offset: u32, num_slots: usize) -> usize {
    let mut slot: usize = 0;
    for (candidate, &base) in LZX_OFFSET_SLOT_BASE.iter().enumerate().take(num_slots) {
        if base <= formatted_offset {
            slot = candidate;
        } else {
            break;
        }
    }
    slot
}

fn gen_codewords(lens: &[u8], max_len: u32) -> Vec<u32> {
    let mut bl_count: Vec<u32> = vec![0u32; (max_len + 1) as usize];
    for &len in lens {
        if len != 0 {
            bl_count[len as usize] += 1;
        }
    }
    let mut next_code: Vec<u32> = vec![0u32; (max_len + 2) as usize];
    let mut code: u32 = 0;
    for bits in 1..=max_len {
        code = (code + bl_count[(bits - 1) as usize]) << 1;
        next_code[bits as usize] = code;
    }
    let mut codewords: Vec<u32> = vec![0u32; lens.len()];
    for (sym, &len) in lens.iter().enumerate() {
        if len != 0 {
            codewords[sym] = next_code[len as usize];
            next_code[len as usize] += 1;
        }
    }
    codewords
}

#[derive(Debug, Clone)]
enum Token {
    Literal(u8),
    Match { length: u32, offset: u32 },
}

fn lzx_apply_e8(data: &mut [u8]) {
    if data.len() <= 10 {
        return;
    }
    let limit: usize = data.len() - 10;
    let magic: i64 = LZX_WIM_MAGIC_FILESIZE;
    let mut i: usize = 0;
    while i < limit {
        if data[i] == 0xe8 {
            let rel: i64 = i64::from(i32::from_le_bytes([
                data[i + 1],
                data[i + 2],
                data[i + 3],
                data[i + 4],
            ]));
            let input_pos: i64 = i as i64;
            let stored: i64 = if rel >= -input_pos && rel < magic - input_pos {
                rel + input_pos
            } else if rel >= magic - input_pos && rel < magic {
                rel - magic
            } else {
                rel
            };
            data[i + 1..i + 5].copy_from_slice(&(stored as i32).to_le_bytes());
            i += 5;
        } else {
            i += 1;
        }
    }
}

const ENC_HASH_BITS: u32 = 15;
const ENC_HASH_SIZE: usize = 1 << ENC_HASH_BITS;
const ENC_MAX_CHAIN: u32 = 64;

fn enc_hash3(data: &[u8], pos: usize) -> usize {
    let a: u32 = u32::from(data[pos]);
    let b: u32 = u32::from(data[pos + 1]);
    let c: u32 = u32::from(data[pos + 2]);
    let h: u32 = (a << 16) ^ (b << 8) ^ c;
    ((h.wrapping_mul(2_654_435_761)) >> (32 - ENC_HASH_BITS)) as usize
}

fn find_match(
    data: &[u8],
    pos: usize,
    head: &[i32],
    prev: &[i32],
    max_offset: usize,
) -> Option<(u32, u32)> {
    let limit: usize = data.len();
    if pos + 3 > limit {
        return None;
    }
    let max_len: usize = (limit - pos).min(LZX_MAX_MATCH_LEN as usize);
    let mut best_len: usize = 0;
    let mut best_off: usize = 0;
    let mut cand: i32 = head[enc_hash3(data, pos)];
    let mut chain: u32 = 0;
    while cand >= 0 && chain < ENC_MAX_CHAIN {
        let cand_pos: usize = cand as usize;
        let offset: usize = pos - cand_pos;
        if offset == 0 || offset > max_offset {
            break;
        }
        let mut len: usize = 0;
        while len < max_len && data[cand_pos + len] == data[pos + len] {
            len += 1;
        }
        if len > best_len {
            best_len = len;
            best_off = offset;
            if len >= max_len {
                break;
            }
        }
        cand = prev[cand_pos];
        chain += 1;
    }
    if best_len >= LZX_MIN_MATCH_LEN as usize {
        Some((best_len as u32, best_off as u32))
    } else {
        None
    }
}

fn tokenize(data: &[u8], max_offset: usize) -> Vec<Token> {
    let mut tokens: Vec<Token> = Vec::new();
    if data.is_empty() {
        return tokens;
    }
    let mut head: Vec<i32> = vec![-1i32; ENC_HASH_SIZE];
    let mut prev: Vec<i32> = vec![-1i32; data.len()];
    let mut pos: usize = 0;
    while pos < data.len() {
        let found: Option<(u32, u32)> = if pos + LZX_MIN_MATCH_LEN as usize <= data.len() {
            find_match(data, pos, &head, &prev, max_offset)
        } else {
            None
        };
        let advance: usize = if let Some((length, offset)) = found {
            tokens.push(Token::Match { length, offset });
            length as usize
        } else {
            tokens.push(Token::Literal(data[pos]));
            1
        };
        let insert_end: usize = (pos + advance).min(data.len().saturating_sub(2));
        let mut ins: usize = pos;
        while ins < insert_end {
            let h: usize = enc_hash3(data, ins);
            prev[ins] = head[h];
            head[h] = ins as i32;
            ins += 1;
        }
        pos += advance;
    }
    tokens
}

struct SymbolFreqs {
    main: Vec<u32>,
    length: Vec<u32>,
    aligned: Vec<u32>,
}

fn classify_match(
    length: u32,
    offset: u32,
    num_slots: usize,
) -> (u32, u32, Option<u32>, usize, u32) {
    let formatted_offset: u32 = offset + LZX_OFFSET_OFFSET;
    let slot: usize = offset_slot_for(formatted_offset, num_slots);
    let footer: u32 = formatted_offset - LZX_OFFSET_SLOT_BASE[slot];
    let length_header: u32 = if length - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS {
        length - LZX_MIN_MATCH_LEN
    } else {
        LZX_NUM_PRIMARY_LENS
    };
    let extra_len_sym: Option<u32> = if length_header == LZX_NUM_PRIMARY_LENS {
        Some(length - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS)
    } else {
        None
    };
    let main_sym: u32 = LZX_NUM_CHARS as u32 + (slot as u32) * LZX_NUM_LEN_HEADERS + length_header;
    (main_sym, footer, extra_len_sym, slot, length_header)
}

fn collect_frequencies(tokens: &[Token], num_slots: usize, main_num_symbols: usize) -> SymbolFreqs {
    let mut main: Vec<u32> = vec![0u32; main_num_symbols];
    let mut length: Vec<u32> = vec![0u32; LZX_LENCODE_NUM_SYMBOLS];
    let mut aligned: Vec<u32> = vec![0u32; LZX_ALIGNEDCODE_NUM_SYMBOLS];
    for token in tokens {
        match *token {
            Token::Literal(byte) => main[byte as usize] += 1,
            Token::Match {
                length: match_len,
                offset,
            } => {
                let (main_sym, footer, extra_len_sym, slot, _): (
                    u32,
                    u32,
                    Option<u32>,
                    usize,
                    u32,
                ) = classify_match(match_len, offset, num_slots);
                main[main_sym as usize] += 1;
                if let Some(sym) = extra_len_sym {
                    length[sym as usize] += 1;
                }
                let num_extra: u32 = LZX_EXTRA_OFFSET_BITS[slot];
                if num_extra >= LZX_NUM_ALIGNED_BITS {
                    aligned[(footer & 7) as usize] += 1;
                }
            }
        }
    }
    SymbolFreqs {
        main,
        length,
        aligned,
    }
}

fn balanced_lengths(freqs: &[u32], max_len: u32) -> Vec<u8> {
    let mut lens: Vec<u8> = vec![0u8; freqs.len()];
    crate::containers::lzms::canonical_lengths(freqs, max_len, &mut lens);
    lens
}

fn delta_symbols(lens: &[u8]) -> Vec<u8> {
    let mut symbols: Vec<u8> = Vec::with_capacity(lens.len());
    for &len in lens {
        let delta: i32 = (-i32::from(len)).rem_euclid(17);
        symbols.push(delta as u8);
    }
    symbols
}

fn emit_precode(writer: &mut BitWriter, lens: &[u8]) {
    let symbols: Vec<u8> = delta_symbols(lens);
    let mut sym_freqs: Vec<u32> = vec![0u32; LZX_PRECODE_NUM_SYMBOLS];
    for &sym in &symbols {
        sym_freqs[sym as usize] += 1;
    }
    let precode_lens: Vec<u8> = balanced_lengths(&sym_freqs, LZX_PRECODE_MAX_CODEWORD_LEN);
    let precode_codes: Vec<u32> = gen_codewords(&precode_lens, LZX_PRECODE_MAX_CODEWORD_LEN);
    for &len in &precode_lens {
        writer.write_bits(u32::from(len), 4);
    }
    for &sym in &symbols {
        let s: usize = sym as usize;
        writer.write_bits(precode_codes[s], u32::from(precode_lens[s]));
    }
}

fn emit_main_lengths(writer: &mut BitWriter, main_lens: &[u8], main_num_symbols: usize) {
    emit_precode(writer, &main_lens[..LZX_NUM_CHARS]);
    emit_precode(writer, &main_lens[LZX_NUM_CHARS..main_num_symbols]);
}

struct BlockCodes {
    main_codes: Vec<u32>,
    main_lens: Vec<u8>,
    length_codes: Vec<u32>,
    length_lens: Vec<u8>,
    aligned_codes: Vec<u32>,
    aligned_lens: Vec<u8>,
    num_slots: usize,
    block_type: u32,
}

fn write_token(writer: &mut BitWriter, token: &Token, codes: &BlockCodes) {
    match *token {
        Token::Literal(byte) => {
            let sym: usize = byte as usize;
            writer.write_bits(codes.main_codes[sym], u32::from(codes.main_lens[sym]));
        }
        Token::Match { length, offset } => {
            let (main_sym, footer, extra_len_sym, slot, _): (u32, u32, Option<u32>, usize, u32) =
                classify_match(length, offset, codes.num_slots);
            let sym: usize = main_sym as usize;
            writer.write_bits(codes.main_codes[sym], u32::from(codes.main_lens[sym]));
            if let Some(len_sym) = extra_len_sym {
                let ls: usize = len_sym as usize;
                writer.write_bits(codes.length_codes[ls], u32::from(codes.length_lens[ls]));
            }
            let num_extra: u32 = LZX_EXTRA_OFFSET_BITS[slot];
            if codes.block_type == LZX_BLOCKTYPE_ALIGNED && num_extra >= LZX_NUM_ALIGNED_BITS {
                let verbatim_bits: u32 = footer >> LZX_NUM_ALIGNED_BITS;
                writer.write_bits(verbatim_bits, num_extra - LZX_NUM_ALIGNED_BITS);
                let aligned_sym: usize = (footer & 7) as usize;
                writer.write_bits(
                    codes.aligned_codes[aligned_sym],
                    u32::from(codes.aligned_lens[aligned_sym]),
                );
            } else {
                writer.write_bits(footer, num_extra);
            }
        }
    }
}

fn compress_block(
    tokens: &[Token],
    block_size: usize,
    window_size: usize,
    block_type: u32,
) -> Vec<u8> {
    let num_slots: usize = lzx_num_offset_slots(window_size);
    let main_num_symbols: usize = LZX_NUM_CHARS + num_slots * LZX_NUM_LEN_HEADERS as usize;
    let freqs: SymbolFreqs = collect_frequencies(tokens, num_slots, main_num_symbols);
    let main_lens: Vec<u8> = balanced_lengths(&freqs.main, LZX_MAX_CODEWORD_LEN);
    let length_lens: Vec<u8> = balanced_lengths(&freqs.length, LZX_MAX_CODEWORD_LEN);
    let aligned_lens: Vec<u8> = if block_type == LZX_BLOCKTYPE_ALIGNED {
        let used: usize = freqs.aligned.iter().filter(|&&f: &&u32| f != 0).count();
        if used == 0 {
            vec![3u8; LZX_ALIGNEDCODE_NUM_SYMBOLS]
        } else {
            balanced_lengths(&freqs.aligned, LZX_ALIGNED_MAX_CODEWORD_LEN)
        }
    } else {
        vec![0u8; LZX_ALIGNEDCODE_NUM_SYMBOLS]
    };
    let codes: BlockCodes = BlockCodes {
        main_codes: gen_codewords(&main_lens, LZX_MAX_CODEWORD_LEN),
        main_lens,
        length_codes: gen_codewords(&length_lens, LZX_MAX_CODEWORD_LEN),
        length_lens,
        aligned_codes: gen_codewords(&aligned_lens, LZX_ALIGNED_MAX_CODEWORD_LEN),
        aligned_lens,
        num_slots,
        block_type,
    };

    let mut writer: BitWriter = BitWriter::new();
    writer.write_bits(block_type, 3);
    if block_size == LZX_DEFAULT_BLOCK_SIZE {
        writer.write_bits(1, 1);
    } else {
        writer.write_bits(0, 1);
        let window_order: u32 = window_size.next_power_of_two().trailing_zeros();
        if window_order >= 16 {
            writer.write_bits((block_size as u32) >> 8, LZX_READ_BLOCKSIZE_BITS);
            writer.write_bits((block_size as u32) & 0xff, 8);
        } else {
            writer.write_bits(block_size as u32, LZX_READ_BLOCKSIZE_BITS);
        }
    }
    if block_type == LZX_BLOCKTYPE_ALIGNED {
        for &len in &codes.aligned_lens {
            writer.write_bits(u32::from(len), 3);
        }
    }
    emit_main_lengths(&mut writer, &codes.main_lens, main_num_symbols);
    emit_precode(&mut writer, &codes.length_lens[..LZX_LENCODE_NUM_SYMBOLS]);
    for token in tokens {
        write_token(&mut writer, token, &codes);
    }
    writer.into_bytes()
}

pub fn lzx_compress_chunk(data: &[u8], aligned: bool) -> Result<Vec<u8>> {
    if data.len() > LZX_DEFAULT_BLOCK_SIZE {
        return Err(Error::Decompression(
            "lzx compressor handles a single chunk of at most 32768 bytes".to_owned(),
        ));
    }
    if data.is_empty() {
        let mut writer: BitWriter = BitWriter::new();
        writer.write_bits(LZX_BLOCKTYPE_VERBATIM, 3);
        writer.write_bits(0, 1);
        writer.write_bits(0, LZX_READ_BLOCKSIZE_BITS);
        return Ok(writer.into_bytes());
    }
    let window_size: usize = LZX_DEFAULT_BLOCK_SIZE.max(data.len());
    let mut filtered: Vec<u8> = data.to_vec();
    lzx_apply_e8(&mut filtered);
    let tokens: Vec<Token> = tokenize(&filtered, window_size);
    let block_type: u32 = if aligned {
        LZX_BLOCKTYPE_ALIGNED
    } else {
        LZX_BLOCKTYPE_VERBATIM
    };
    Ok(compress_block(&tokens, data.len(), window_size, block_type))
}

#[must_use]
pub fn lzx_build_resource_body(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut offsets: Vec<u8> = Vec::new();
    let mut cumulative: u32 = 0;
    for chunk in chunks.iter().take(chunks.len().saturating_sub(1)) {
        cumulative += chunk.len() as u32;
        offsets.extend_from_slice(&cumulative.to_le_bytes());
    }
    let mut body: Vec<u8> = offsets;
    for chunk in chunks {
        body.extend_from_slice(chunk);
    }
    body
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::containers::wim_codec::decompress_lzx_chunk_for_test as decompress_lzx_chunk;

    fn round_trip(data: &[u8], aligned: bool) {
        let compressed: Vec<u8> = lzx_compress_chunk(data, aligned).expect("compress lzx chunk");
        let mut out: Vec<u8> = Vec::new();
        decompress_lzx_chunk(&compressed, data.len(), &mut out)
            .unwrap_or_else(|e| panic!("decompress lzx chunk failed: {e}"));
        if out != data {
            let first: Option<usize> =
                (0..data.len().min(out.len())).find(|&i: &usize| data[i] != out[i]);
            panic!(
                "lzx round trip not byte-identical (aligned={aligned}); len got={} want={}; first diff at {first:?}",
                out.len(),
                data.len()
            );
        }
    }

    #[test]
    fn verbatim_round_trips_short_text() {
        round_trip(b"the quick brown fox jumps over the lazy dog", false);
    }

    #[test]
    fn verbatim_round_trips_repetitive_text() {
        let mut data: Vec<u8> = Vec::new();
        for _ in 0..400 {
            data.extend_from_slice(b"the quick brown fox 0123456789 ");
        }
        data.truncate(LZX_DEFAULT_BLOCK_SIZE);
        round_trip(&data, false);
    }

    #[test]
    fn aligned_round_trips_repetitive_text() {
        let mut data: Vec<u8> = Vec::new();
        for _ in 0..400 {
            data.extend_from_slice(b"PACKAGE_DESCRIPTOR field=value field=value <node/> ");
        }
        data.truncate(LZX_DEFAULT_BLOCK_SIZE);
        round_trip(&data, true);
    }

    #[test]
    fn verbatim_round_trips_pseudo_random_bytes() {
        let mut data: Vec<u8> = Vec::with_capacity(8000);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..8000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            data.push((state >> 16) as u8);
        }
        round_trip(&data, false);
    }

    #[test]
    fn verbatim_round_trips_overlapping_run() {
        let mut data: Vec<u8> = vec![b'A'];
        data.extend(std::iter::repeat_n(b'A', 5000));
        round_trip(&data, false);
    }

    #[test]
    fn aligned_round_trips_large_offsets() {
        let mut data: Vec<u8> = Vec::with_capacity(20_000);
        let mut state: u32 = 0x9e37_79b9;
        for _ in 0..10_000 {
            state = state.wrapping_mul(214_013).wrapping_add(2_531_011);
            data.push((state >> 24) as u8);
        }
        let head: Vec<u8> = data.clone();
        data.extend_from_slice(&head);
        data.truncate(LZX_DEFAULT_BLOCK_SIZE);
        round_trip(&data, true);
    }

    #[test]
    fn e8_filter_is_self_inverse() {
        let mut data: Vec<u8> = Vec::with_capacity(2048);
        let mut state: u32 = 0x0bad_f00d;
        while data.len() < 2048 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            if state.trailing_zeros() >= 3 {
                data.push(0xe8);
            } else {
                data.push((state >> 11) as u8);
            }
        }
        round_trip(&data, false);
    }

    #[test]
    fn empty_chunk_round_trips() {
        round_trip(b"", false);
    }
}
