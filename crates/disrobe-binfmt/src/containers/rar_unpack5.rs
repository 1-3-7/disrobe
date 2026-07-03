use crate::error::{Error, Result};

const NC: usize = 306;
const DC: usize = 64;
const LDC: usize = 16;
const RC: usize = 44;
const BC: usize = 20;
const HUFF_TABLE_SIZE: usize = NC + DC + LDC + RC;
const MAX_LENGTH: usize = 15;

const FILTER_DELTA: u8 = 0;
const FILTER_E8: u8 = 1;
const FILTER_E8E9: u8 = 2;
const FILTER_ARM: u8 = 3;
const E8_FILE_SIZE: u32 = 0x0100_0000;
const MAX_FILTER_BLOCK_SIZE: u64 = 0x40_0000;
const MAX_FILTERS: usize = 1 << 20;

#[derive(Debug, Clone, Copy)]
struct Rar5Filter {
    start: u64,
    length: u64,
    kind: u8,
    channels: u32,
}

#[derive(Debug, Default)]
struct DecodeTable {
    decode_len: [u32; MAX_LENGTH + 1],
    decode_pos: [u32; MAX_LENGTH + 1],
    decode_num: Vec<u16>,
    max_num: usize,
}

#[derive(Debug, Default)]
struct BlockTables {
    bd: DecodeTable,
    ld: DecodeTable,
    dd: DecodeTable,
    ldd: DecodeTable,
    rd: DecodeTable,
}

#[derive(Debug, Default, Clone, Copy)]
struct BlockHeader {
    block_size: u64,
    block_bit_size: u32,
    table_present: bool,
    last_block_in_file: bool,
    block_start_bit: u64,
}

struct BitInput<'a> {
    data: &'a [u8],
    bit_pos: u64,
}

impl<'a> BitInput<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn peek16(&self) -> u32 {
        let byte_index: usize = (self.bit_pos / 8) as usize;
        let bit_in_byte: u32 = (self.bit_pos % 8) as u32;
        let b0: u32 = u32::from(
            self.data
                .get(byte_index)
                .copied()
                .map_or(0, |value: u8| value),
        );
        let b1: u32 = u32::from(
            self.data
                .get(byte_index + 1)
                .copied()
                .map_or(0, |value: u8| value),
        );
        let b2: u32 = u32::from(
            self.data
                .get(byte_index + 2)
                .copied()
                .map_or(0, |value: u8| value),
        );
        let window: u32 = (b0 << 16) | (b1 << 8) | b2;
        (window >> (8 - bit_in_byte)) & 0xffff
    }

    fn peek32(&self) -> u32 {
        let byte_index: usize = (self.bit_pos / 8) as usize;
        let bit_in_byte: u64 = self.bit_pos % 8;
        let mut acc: u64 = 0;
        for i in 0..5 {
            let byte: u8 = self
                .data
                .get(byte_index + i)
                .copied()
                .map_or(0, |value: u8| value);
            acc = (acc << 8) | u64::from(byte);
        }
        ((acc >> (8 - bit_in_byte)) & 0xffff_ffff) as u32
    }

    fn addbits(&mut self, bits: u32) {
        self.bit_pos += u64::from(bits);
    }

    fn getbits16(&mut self, bits: u32) -> u32 {
        let value: u32 = (self.peek16() >> (16 - bits)) & ((1u32 << bits) - 1);
        self.addbits(bits);
        value
    }

    const fn align_byte(&mut self) {
        let rem: u64 = self.bit_pos % 8;
        if rem != 0 {
            self.bit_pos += 8 - rem;
        }
    }

    const fn total_bits(&self) -> u64 {
        (self.data.len() as u64) * 8
    }
}

fn make_decode_table(length_table: &[u8], table: &mut DecodeTable, size: usize) {
    let mut length_count: [u32; MAX_LENGTH + 1] = [0; MAX_LENGTH + 1];
    for &raw in length_table.iter().take(size) {
        let len: usize = (raw & 0x0f) as usize;
        length_count[len] += 1;
    }
    length_count[0] = 0;

    table.decode_pos[0] = 0;
    table.decode_len[0] = 0;
    let mut upper_limit: u32 = 0;
    for i in 1..=MAX_LENGTH {
        upper_limit += length_count[i];
        let left_aligned: u32 = upper_limit.wrapping_shl((16 - i) as u32);
        upper_limit = upper_limit.wrapping_mul(2);
        table.decode_len[i] = left_aligned;
        table.decode_pos[i] = table.decode_pos[i - 1] + length_count[i - 1];
    }

    let mut copy_pos: [u32; MAX_LENGTH + 1] = table.decode_pos;
    table.decode_num = vec![0u16; size];
    for (symbol, &raw) in length_table.iter().take(size).enumerate() {
        let len: usize = (raw & 0x0f) as usize;
        if len != 0 {
            let pos: usize = copy_pos[len] as usize;
            if pos < size {
                table.decode_num[pos] = symbol as u16;
            }
            copy_pos[len] += 1;
        }
    }
    table.max_num = size;
}

fn decode_number(inp: &mut BitInput<'_>, table: &DecodeTable) -> u16 {
    let bit_field: u32 = inp.peek16();
    let mut bits: usize = 1;
    while bits < MAX_LENGTH {
        if bit_field < table.decode_len[bits] {
            break;
        }
        bits += 1;
    }
    inp.addbits(bits as u32);
    let dist: u32 = (bit_field - table.decode_len[bits - 1]) >> (16 - bits);
    let pos: usize = table.decode_pos[bits] as usize + dist as usize;
    if pos < table.max_num {
        table.decode_num[pos]
    } else {
        0
    }
}

fn read_block_header(inp: &mut BitInput<'_>) -> Result<BlockHeader> {
    inp.align_byte();
    if inp.bit_pos + 16 > inp.total_bits() {
        return Err(Error::Decompression(
            "rar5 block header past end of stream".to_owned(),
        ));
    }
    let block_flags: u8 = inp.getbits16(8) as u8;
    let byte_count: u32 = ((u32::from(block_flags) >> 3) & 3) + 1;
    if byte_count == 4 {
        return Err(Error::Decompression(
            "rar5 block size byte count invalid".to_owned(),
        ));
    }
    let block_bit_size: u32 = (u32::from(block_flags) & 7) + 1;
    let saved_checksum: u8 = inp.getbits16(8) as u8;
    let mut block_size: u64 = 0;
    for i in 0..byte_count {
        let b: u64 = u64::from(inp.getbits16(8));
        block_size |= b << (i * 8);
    }
    let checksum: u8 = 0x5a
        ^ block_flags
        ^ (block_size as u8)
        ^ ((block_size >> 8) as u8)
        ^ ((block_size >> 16) as u8);
    if checksum != saved_checksum {
        return Err(Error::Decompression(
            "rar5 block header checksum mismatch".to_owned(),
        ));
    }
    Ok(BlockHeader {
        block_size,
        block_bit_size,
        table_present: block_flags & 0x80 != 0,
        last_block_in_file: block_flags & 0x40 != 0,
        block_start_bit: inp.bit_pos,
    })
}

impl BlockHeader {
    const fn end_bit(&self) -> u64 {
        self.block_start_bit + self.block_size.saturating_sub(1) * 8 + self.block_bit_size as u64
    }
}

fn read_tables(inp: &mut BitInput<'_>, tables: &mut BlockTables) -> Result<()> {
    let mut bit_length: [u8; BC] = [0u8; BC];
    let mut i: usize = 0;
    while i < BC {
        let length: u8 = (inp.getbits16(4)) as u8;
        if length == 15 {
            let mut zero_count: u32 = inp.getbits16(4);
            if zero_count == 0 {
                bit_length[i] = 15;
                i += 1;
            } else {
                zero_count += 2;
                while zero_count > 0 && i < BC {
                    bit_length[i] = 0;
                    i += 1;
                    zero_count -= 1;
                }
            }
        } else {
            bit_length[i] = length;
            i += 1;
        }
    }
    make_decode_table(&bit_length, &mut tables.bd, BC);

    let mut table: [u8; HUFF_TABLE_SIZE] = [0u8; HUFF_TABLE_SIZE];
    let mut index: usize = 0;
    while index < HUFF_TABLE_SIZE {
        if inp.bit_pos >= inp.total_bits() {
            return Err(Error::Decompression(
                "rar5 table stream truncated".to_owned(),
            ));
        }
        let number: u16 = decode_number(inp, &tables.bd);
        if number < 16 {
            table[index] = number as u8;
            index += 1;
        } else if number < 18 {
            let count: u32 = if number == 16 {
                inp.getbits16(3) + 3
            } else {
                inp.getbits16(7) + 11
            };
            if index == 0 {
                return Err(Error::Decompression(
                    "rar5 table rle repeat at position zero".to_owned(),
                ));
            }
            let prev: u8 = table[index - 1];
            let mut remaining: u32 = count;
            while remaining > 0 && index < HUFF_TABLE_SIZE {
                table[index] = prev;
                index += 1;
                remaining -= 1;
            }
        } else {
            let count: u32 = if number == 18 {
                inp.getbits16(3) + 3
            } else {
                inp.getbits16(7) + 11
            };
            let mut remaining: u32 = count;
            while remaining > 0 && index < HUFF_TABLE_SIZE {
                table[index] = 0;
                index += 1;
                remaining -= 1;
            }
        }
    }

    make_decode_table(&table[0..NC], &mut tables.ld, NC);
    make_decode_table(&table[NC..NC + DC], &mut tables.dd, DC);
    make_decode_table(&table[NC + DC..NC + DC + LDC], &mut tables.ldd, LDC);
    make_decode_table(&table[NC + DC + LDC..HUFF_TABLE_SIZE], &mut tables.rd, RC);
    Ok(())
}

fn slot_to_length(inp: &mut BitInput<'_>, slot: u32) -> u32 {
    let mut length: u32 = 2;
    let l_bits: u32 = if slot < 8 {
        length += slot;
        0
    } else {
        let bits: u32 = slot / 4 - 1;
        length += (4 | (slot & 3)) << bits;
        bits
    };
    if l_bits > 0 {
        length += inp.peek16() >> (16 - l_bits);
        inp.addbits(l_bits);
    }
    length
}

fn read_filter_data(inp: &mut BitInput<'_>) -> u32 {
    let byte_count: u32 = (inp.peek16() >> 14) + 1;
    inp.addbits(2);
    let mut data: u32 = 0;
    for i in 0..byte_count {
        let octet: u32 = inp.peek16() >> 8;
        inp.addbits(8);
        data = data.wrapping_add(octet << (i * 8));
    }
    data
}

fn read_filter(inp: &mut BitInput<'_>, out_pos: u64) -> Result<Rar5Filter> {
    let raw_start: u32 = read_filter_data(inp);
    let raw_length: u32 = read_filter_data(inp);
    let kind: u8 = (inp.peek16() >> 13) as u8;
    inp.addbits(3);
    let channels: u32 = if kind == FILTER_DELTA {
        let value: u32 = (inp.peek16() >> 11) + 1;
        inp.addbits(5);
        value
    } else {
        0
    };
    let length: u64 = {
        let candidate: u64 = u64::from(raw_length);
        if candidate > MAX_FILTER_BLOCK_SIZE {
            0
        } else {
            candidate
        }
    };
    if kind > FILTER_ARM {
        return Err(Error::Decompression(format!(
            "rar5 filter type {kind} is not a known rar5 filter (delta, e8, e8e9, arm)"
        )));
    }
    Ok(Rar5Filter {
        start: out_pos + u64::from(raw_start),
        length,
        kind,
        channels,
    })
}

fn apply_filters(out: &mut [u8], filters: &[Rar5Filter]) -> Result<()> {
    let total: u64 = out.len() as u64;
    for filter in filters {
        if filter.length == 0 {
            continue;
        }
        let start: usize =
            usize::try_from(filter.start).map_err(|_e: std::num::TryFromIntError| {
                Error::Decompression("rar5 filter start overflow".to_owned())
            })?;
        let end_u64: u64 = filter.start.saturating_add(filter.length);
        if end_u64 > total {
            return Err(Error::Decompression(format!(
                "rar5 filter range [{}, {end_u64}) exceeds output length {total}",
                filter.start
            )));
        }
        let end: usize = usize::try_from(end_u64).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("rar5 filter end overflow".to_owned())
        })?;
        let region: &mut [u8] = out
            .get_mut(start..end)
            .ok_or_else(|| Error::Decompression("rar5 filter region out of bounds".to_owned()))?;
        let file_offset: u32 = filter.start as u32;
        match filter.kind {
            FILTER_E8 => apply_e8e9(region, file_offset, false),
            FILTER_E8E9 => apply_e8e9(region, file_offset, true),
            FILTER_DELTA => apply_delta(region, filter.channels)?,
            FILTER_ARM => apply_arm(region, file_offset),
            other => {
                return Err(Error::Decompression(format!(
                    "rar5 filter type {other} is not decoded in-tree (only delta, e8, e8e9, arm)"
                )));
            }
        }
    }
    Ok(())
}

fn apply_e8e9(data: &mut [u8], file_offset: u32, e9_too: bool) {
    let data_size: usize = data.len();
    if data_size < 5 {
        return;
    }
    let cmp2: u8 = if e9_too { 0xe9 } else { 0xe8 };
    let mut cur_pos: usize = 0;
    while cur_pos + 4 < data_size {
        let cur_byte: u8 = data[cur_pos];
        cur_pos += 1;
        if cur_byte == 0xe8 || cur_byte == cmp2 {
            let offset: u32 = (cur_pos as u32).wrapping_add(file_offset) % E8_FILE_SIZE;
            let addr: u32 = u32::from_le_bytes([
                data[cur_pos],
                data[cur_pos + 1],
                data[cur_pos + 2],
                data[cur_pos + 3],
            ]);
            if addr & 0x8000_0000 != 0 {
                if addr.wrapping_add(offset) & 0x8000_0000 == 0 {
                    let patched: u32 = addr.wrapping_add(E8_FILE_SIZE);
                    data[cur_pos..cur_pos + 4].copy_from_slice(&patched.to_le_bytes());
                }
            } else if addr.wrapping_sub(E8_FILE_SIZE) & 0x8000_0000 != 0 {
                let patched: u32 = addr.wrapping_sub(offset);
                data[cur_pos..cur_pos + 4].copy_from_slice(&patched.to_le_bytes());
            }
            cur_pos += 4;
        }
    }
}

fn apply_arm(data: &mut [u8], file_offset: u32) {
    let data_size: usize = data.len();
    let mut cur_pos: usize = 0;
    while cur_pos + 3 < data_size {
        if data[cur_pos + 3] == 0xeb {
            let raw: u32 = u32::from(data[cur_pos])
                + u32::from(data[cur_pos + 1]) * 0x100
                + u32::from(data[cur_pos + 2]) * 0x10000;
            let offset: u32 = raw.wrapping_sub((file_offset + cur_pos as u32) / 4);
            data[cur_pos] = offset as u8;
            data[cur_pos + 1] = (offset >> 8) as u8;
            data[cur_pos + 2] = (offset >> 16) as u8;
        }
        cur_pos += 4;
    }
}

fn apply_delta(data: &mut [u8], channels: u32) -> Result<()> {
    if channels == 0 {
        return Err(Error::Decompression(
            "rar5 delta filter channel count is zero".to_owned(),
        ));
    }
    let channels: usize = channels as usize;
    let data_size: usize = data.len();
    let src: Vec<u8> = data.to_vec();
    let mut src_pos: usize = 0;
    for cur_channel in 0..channels {
        let mut prev_byte: u8 = 0;
        let mut dest_pos: usize = cur_channel;
        while dest_pos < data_size {
            prev_byte = prev_byte.wrapping_sub(src[src_pos]);
            data[dest_pos] = prev_byte;
            src_pos += 1;
            dest_pos += channels;
        }
    }
    Ok(())
}

pub fn unpack5(packed: &[u8], unpacked_size: u64, cap: u64) -> Result<Vec<u8>> {
    if unpacked_size > cap {
        return Err(Error::Decompression(format!(
            "rar5 unpacked size {unpacked_size} exceeds cap {cap}"
        )));
    }
    let want: usize = usize::try_from(unpacked_size).map_err(|_e: std::num::TryFromIntError| {
        Error::Decompression("rar5 size overflow".to_owned())
    })?;
    let mut out: Vec<u8> = Vec::with_capacity(want);
    let mut inp: BitInput<'_> = BitInput::new(packed);
    let mut tables: BlockTables = BlockTables::default();
    let mut old_dist: [u32; 4] = [0u32; 4];
    let mut last_length: u32 = 0;
    let mut filters: Vec<Rar5Filter> = Vec::new();

    let mut header: BlockHeader = read_block_header(&mut inp)?;
    read_tables(&mut inp, &mut tables)?;
    let mut block_end_bit: u64 = header.end_bit();

    let mut guard: usize = 0;
    let max_iters: usize = want.saturating_mul(4).saturating_add(1024);
    while out.len() < want {
        guard += 1;
        if guard > max_iters {
            return Err(Error::Decompression(
                "rar5 decode exceeded iteration budget".to_owned(),
            ));
        }
        if inp.bit_pos >= block_end_bit {
            if header.last_block_in_file {
                break;
            }
            header = read_block_header(&mut inp)?;
            if header.table_present {
                read_tables(&mut inp, &mut tables)?;
            }
            block_end_bit = header.end_bit();
            continue;
        }
        if inp.bit_pos + 16 > inp.total_bits() + 16 {
            break;
        }
        let main_slot: u16 = decode_number(&mut inp, &tables.ld);
        if main_slot < 256 {
            out.push(main_slot as u8);
            continue;
        }
        if main_slot == 256 {
            if filters.len() >= MAX_FILTERS {
                return Err(Error::Decompression(
                    "rar5 filter count exceeds sanity bound".to_owned(),
                ));
            }
            let filter: Rar5Filter = read_filter(&mut inp, out.len() as u64)?;
            filters.push(filter);
            continue;
        }
        let (length, distance): (u32, u32) = if main_slot == 257 {
            (last_length, old_dist[0])
        } else if main_slot < 262 {
            let dist_num: usize = (main_slot - 258) as usize;
            let distance: u32 = old_dist[dist_num];
            for n in (1..=dist_num).rev() {
                old_dist[n] = old_dist[n - 1];
            }
            old_dist[0] = distance;
            let length_slot: u16 = decode_number(&mut inp, &tables.rd);
            let length: u32 = slot_to_length(&mut inp, u32::from(length_slot));
            (length, distance)
        } else {
            let mut length: u32 = slot_to_length(&mut inp, u32::from(main_slot - 262));
            let dist_slot: u32 = u32::from(decode_number(&mut inp, &tables.dd));
            let mut distance: u32 = 1;
            let d_bits: u32 = if dist_slot < 4 {
                distance += dist_slot;
                0
            } else {
                let bits: u32 = dist_slot / 2 - 1;
                distance += (2 | (dist_slot & 1)) << bits;
                bits
            };
            if d_bits > 0 {
                if d_bits >= 4 {
                    if d_bits > 4 {
                        distance += (inp.peek32() >> (36 - d_bits)) << 4;
                        inp.addbits(d_bits - 4);
                    }
                    let low_dist: u16 = decode_number(&mut inp, &tables.ldd);
                    distance += u32::from(low_dist);
                } else {
                    distance += inp.getbits16(d_bits);
                }
            }
            if distance > 0x100 {
                length += 1;
                if distance > 0x2000 {
                    length += 1;
                    if distance > 0x4_0000 {
                        length += 1;
                    }
                }
            }
            old_dist[3] = old_dist[2];
            old_dist[2] = old_dist[1];
            old_dist[1] = old_dist[0];
            old_dist[0] = distance;
            (length, distance)
        };

        last_length = length;
        copy_string(&mut out, length, distance, want)?;
    }

    out.truncate(want);
    if out.len() != want {
        return Err(Error::Decompression(format!(
            "rar5 produced {} of {want} bytes",
            out.len()
        )));
    }
    apply_filters(&mut out, &filters)?;
    Ok(out)
}

fn copy_string(out: &mut Vec<u8>, length: u32, distance: u32, want: usize) -> Result<()> {
    let dist: usize = distance as usize;
    if dist == 0 || dist > out.len() {
        return Err(Error::Decompression(format!(
            "rar5 match distance {dist} out of range (have {} bytes)",
            out.len()
        )));
    }
    let mut remaining: usize = length as usize;
    let mut src: usize = out.len() - dist;
    while remaining > 0 && out.len() < want {
        let byte: u8 = out[src];
        out.push(byte);
        src += 1;
        remaining -= 1;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn slot_to_length_low_slots_are_literal_offsets() {
        let data: [u8; 4] = [0u8; 4];
        let mut inp: BitInput<'_> = BitInput::new(&data);
        assert_eq!(slot_to_length(&mut inp, 0), 2);
        let mut inp2: BitInput<'_> = BitInput::new(&data);
        assert_eq!(slot_to_length(&mut inp2, 7), 9);
    }

    #[test]
    fn bit_input_reads_msb_first() {
        let data: [u8; 2] = [0b1010_0000, 0b0000_0000];
        let mut inp: BitInput<'_> = BitInput::new(&data);
        assert_eq!(inp.getbits16(1), 1);
        assert_eq!(inp.getbits16(1), 0);
        assert_eq!(inp.getbits16(1), 1);
    }
}
