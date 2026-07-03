use crate::error::{Error, Result};

const NC30: usize = 299;
const DC30: usize = 60;
const LDC30: usize = 17;
const RC30: usize = 28;
const BC30: usize = 20;
const HUFF_TABLE_SIZE30: usize = NC30 + DC30 + LDC30 + RC30;
const MAX_LENGTH: usize = 15;
const LOW_DIST_REP_COUNT: u32 = 16;

const LDECODE: [u32; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LBITS: [u32; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const SDDECODE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];
const DBIT_LENGTH_COUNTS: [u32; 19] = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];

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

#[derive(Debug)]
struct DistTables {
    ddecode: [u32; DC30],
    dbits: [u32; DC30],
}

impl DistTables {
    fn build() -> Self {
        let mut ddecode: [u32; DC30] = [0u32; DC30];
        let mut dbits: [u32; DC30] = [0u32; DC30];
        let mut slot: usize = 0;
        let mut dist: u32 = 0;
        for (bit_length, &count) in (0u32..).zip(DBIT_LENGTH_COUNTS.iter()) {
            for _ in 0..count {
                if slot < DC30 {
                    ddecode[slot] = dist;
                    dbits[slot] = bit_length;
                }
                slot += 1;
                dist = dist.wrapping_add(1 << bit_length);
            }
        }
        Self { ddecode, dbits }
    }
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

    fn addbits(&mut self, bits: u32) {
        self.bit_pos += u64::from(bits);
    }

    fn getbits16(&mut self, bits: u32) -> u32 {
        let value: u32 = self.peek16() >> (16 - bits);
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

    const fn exhausted(&self) -> bool {
        self.bit_pos >= self.total_bits()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Lz,
    Unsupported,
}

fn read_tables(
    inp: &mut BitInput<'_>,
    tables: &mut BlockTables,
    old_table: &mut [u8; HUFF_TABLE_SIZE30],
) -> Result<BlockKind> {
    inp.align_byte();
    if inp.bit_pos + 16 > inp.total_bits() {
        return Err(Error::Decompression(
            "rar 2.9/3.x table header past end of stream".to_owned(),
        ));
    }
    let bit_field: u32 = inp.peek16();
    if bit_field & 0x8000 != 0 {
        return Ok(BlockKind::Unsupported);
    }
    let keep_old: bool = bit_field & 0x4000 != 0;
    if !keep_old {
        *old_table = [0u8; HUFF_TABLE_SIZE30];
    }
    inp.addbits(2);

    let mut bit_length: [u8; BC30] = [0u8; BC30];
    let mut i: usize = 0;
    while i < BC30 {
        let length: u8 = inp.getbits16(4) as u8;
        if length == 15 {
            let zero_count: u32 = inp.getbits16(4);
            if zero_count == 0 {
                bit_length[i] = 15;
                i += 1;
            } else {
                let mut remaining: u32 = zero_count + 2;
                while remaining > 0 && i < BC30 {
                    bit_length[i] = 0;
                    i += 1;
                    remaining -= 1;
                }
            }
        } else {
            bit_length[i] = length;
            i += 1;
        }
    }
    make_decode_table(&bit_length, &mut tables.bd, BC30);

    let mut table: [u8; HUFF_TABLE_SIZE30] = [0u8; HUFF_TABLE_SIZE30];
    let mut index: usize = 0;
    while index < HUFF_TABLE_SIZE30 {
        if inp.exhausted() {
            return Err(Error::Decompression(
                "rar 2.9/3.x table stream truncated".to_owned(),
            ));
        }
        let number: u16 = decode_number(inp, &tables.bd);
        if number < 16 {
            table[index] = ((u32::from(number) + u32::from(old_table[index])) & 0x0f) as u8;
            index += 1;
        } else if number < 18 {
            let count: u32 = if number == 16 {
                inp.getbits16(3) + 3
            } else {
                inp.getbits16(7) + 11
            };
            if index == 0 {
                return Err(Error::Decompression(
                    "rar 2.9/3.x table rle repeat at position zero".to_owned(),
                ));
            }
            let mut remaining: u32 = count;
            while remaining > 0 && index < HUFF_TABLE_SIZE30 {
                table[index] = table[index - 1];
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
            while remaining > 0 && index < HUFF_TABLE_SIZE30 {
                table[index] = 0;
                index += 1;
                remaining -= 1;
            }
        }
    }

    if inp.bit_pos > inp.total_bits() {
        return Err(Error::Decompression(
            "rar 2.9/3.x table read past end of stream".to_owned(),
        ));
    }
    make_decode_table(&table[0..NC30], &mut tables.ld, NC30);
    make_decode_table(&table[NC30..NC30 + DC30], &mut tables.dd, DC30);
    make_decode_table(
        &table[NC30 + DC30..NC30 + DC30 + LDC30],
        &mut tables.ldd,
        LDC30,
    );
    make_decode_table(
        &table[NC30 + DC30 + LDC30..HUFF_TABLE_SIZE30],
        &mut tables.rd,
        RC30,
    );
    *old_table = table;
    Ok(BlockKind::Lz)
}

fn read_end_of_block(
    inp: &mut BitInput<'_>,
    tables: &mut BlockTables,
    old_table: &mut [u8; HUFF_TABLE_SIZE30],
) -> Result<bool> {
    let bit_field: u32 = inp.peek16();
    let new_table: bool;
    let new_file: bool;
    if bit_field & 0x8000 != 0 {
        new_table = true;
        new_file = false;
        inp.addbits(1);
    } else {
        new_file = true;
        new_table = bit_field & 0x4000 != 0;
        inp.addbits(2);
    }
    if new_file {
        return Ok(false);
    }
    if new_table {
        match read_tables(inp, tables, old_table)? {
            BlockKind::Lz => Ok(true),
            BlockKind::Unsupported => Err(Error::Decompression(
                "rar 2.9/3.x ppmii (ppmd) compressed block is not decoded in-tree; only the standard lz method is".to_owned(),
            )),
        }
    } else {
        Ok(true)
    }
}

struct LowDistState {
    prev_low_dist: u32,
    low_dist_rep_count: u32,
}

pub fn unpack3(packed: &[u8], unpacked_size: u64, cap: u64) -> Result<Vec<u8>> {
    if unpacked_size > cap {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x unpacked size {unpacked_size} exceeds cap {cap}"
        )));
    }
    if packed.first().is_some_and(|&b: &u8| b & 0x80 != 0) {
        return crate::containers::rar_ppmd::unpack3_ppmd(packed, unpacked_size, cap);
    }
    let want: usize = usize::try_from(unpacked_size).map_err(|_e: std::num::TryFromIntError| {
        Error::Decompression("rar 2.9/3.x size overflow".to_owned())
    })?;
    let dist_tables: DistTables = DistTables::build();
    let mut out: Vec<u8> = Vec::with_capacity(want);
    let mut inp: BitInput<'_> = BitInput::new(packed);
    let mut tables: BlockTables = BlockTables::default();
    let mut old_table: [u8; HUFF_TABLE_SIZE30] = [0u8; HUFF_TABLE_SIZE30];
    let mut old_dist: [u32; 4] = [0u32; 4];
    let mut last_length: u32 = 0;
    let mut low: LowDistState = LowDistState {
        prev_low_dist: 0,
        low_dist_rep_count: 0,
    };

    match read_tables(&mut inp, &mut tables, &mut old_table)? {
        BlockKind::Lz => {}
        BlockKind::Unsupported => {
            return Err(Error::Decompression(
                "rar 2.9/3.x ppmii (ppmd) compressed block is not decoded in-tree; only the standard lz method is".to_owned(),
            ));
        }
    }

    let mut guard: usize = 0;
    let max_iters: usize = want.saturating_mul(4).saturating_add(4096);
    while out.len() < want {
        guard += 1;
        if guard > max_iters {
            return Err(Error::Decompression(
                "rar 2.9/3.x decode exceeded iteration budget".to_owned(),
            ));
        }
        if inp.bit_pos >= inp.total_bits() {
            break;
        }
        let number: u16 = decode_number(&mut inp, &tables.ld);
        if number < 256 {
            out.push(number as u8);
            continue;
        }
        if number == 256 {
            if !read_end_of_block(&mut inp, &mut tables, &mut old_table)? {
                break;
            }
            continue;
        }
        if number == 257 {
            return Err(Error::Decompression(
                "rar 2.9/3.x member carries a rarvm filter program (the executable e8/e8e9, delta, rgb and audio transforms run as rarvm bytecode here, not as fixed filter ids); the standard lz method is decoded in-tree but the rarvm interpreter is not".to_owned(),
            ));
        }
        if number == 258 {
            if last_length != 0 {
                copy_string(&mut out, last_length, old_dist[0], want)?;
            }
            continue;
        }
        if number < 263 {
            let dist_num: usize = (number - 259) as usize;
            let distance: u32 = old_dist[dist_num];
            for n in (1..=dist_num).rev() {
                old_dist[n] = old_dist[n - 1];
            }
            old_dist[0] = distance;
            let length_number: u16 = decode_number(&mut inp, &tables.rd);
            let length: u32 = read_length(&mut inp, length_number, 2);
            last_length = length;
            copy_string(&mut out, length, distance, want)?;
            continue;
        }
        if number >= 271 {
            let length_index: usize = (number - 271) as usize;
            let mut length: u32 = read_length(&mut inp, length_index as u16, 3);
            let dist_number: u16 = decode_number(&mut inp, &tables.dd);
            let dist_index: usize = dist_number as usize;
            let mut distance: u32 = dist_tables.ddecode[dist_index.min(DC30 - 1)] + 1;
            let bits: u32 = dist_tables.dbits[dist_index.min(DC30 - 1)];
            if bits > 0 {
                if dist_index > 9 {
                    if bits > 4 {
                        distance += (inp.peek16() >> (20 - bits)) << 4;
                        inp.addbits(bits - 4);
                    }
                    if low.low_dist_rep_count > 0 {
                        low.low_dist_rep_count -= 1;
                        distance += low.prev_low_dist;
                    } else {
                        let low_dist: u16 = decode_number(&mut inp, &tables.ldd);
                        if low_dist == 16 {
                            low.low_dist_rep_count = LOW_DIST_REP_COUNT - 1;
                            distance += low.prev_low_dist;
                        } else {
                            distance += u32::from(low_dist);
                            low.prev_low_dist = u32::from(low_dist);
                        }
                    }
                } else {
                    distance += inp.peek16() >> (16 - bits);
                    inp.addbits(bits);
                }
            }
            if distance >= 0x2000 {
                length += 1;
                if distance >= 0x4_0000 {
                    length += 1;
                }
            }
            insert_old_dist(&mut old_dist, distance);
            last_length = length;
            copy_string(&mut out, length, distance, want)?;
            continue;
        }
        let short_index: usize = (number - 263) as usize;
        let mut distance: u32 = SDDECODE[short_index.min(SDDECODE.len() - 1)] + 1;
        let bits: u32 = SDBITS[short_index.min(SDBITS.len() - 1)];
        if bits > 0 {
            distance += inp.peek16() >> (16 - bits);
            inp.addbits(bits);
        }
        insert_old_dist(&mut old_dist, distance);
        last_length = 2;
        copy_string(&mut out, 2, distance, want)?;
    }

    out.truncate(want);
    if out.len() != want {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x produced {} of {want} bytes",
            out.len()
        )));
    }
    Ok(out)
}

fn read_length(inp: &mut BitInput<'_>, length_number: u16, base: u32) -> u32 {
    let idx: usize = (length_number as usize).min(LDECODE.len() - 1);
    let mut length: u32 = LDECODE[idx] + base;
    let bits: u32 = LBITS[idx];
    if bits > 0 {
        length += inp.peek16() >> (16 - bits);
        inp.addbits(bits);
    }
    length
}

const fn insert_old_dist(old_dist: &mut [u32; 4], distance: u32) {
    old_dist[3] = old_dist[2];
    old_dist[2] = old_dist[1];
    old_dist[1] = old_dist[0];
    old_dist[0] = distance;
}

fn copy_string(out: &mut Vec<u8>, length: u32, distance: u32, want: usize) -> Result<()> {
    let dist: usize = distance as usize;
    if dist == 0 || dist > out.len() {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x match distance {dist} out of range (have {} bytes)",
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
    fn dist_table_first_entries_match_spec() {
        let t: DistTables = DistTables::build();
        assert_eq!(t.ddecode[0], 0);
        assert_eq!(t.dbits[0], 0);
        assert_eq!(t.ddecode[1], 1);
        assert_eq!(t.ddecode[2], 2);
        assert_eq!(t.ddecode[3], 3);
        assert_eq!(t.ddecode[4], 4);
        assert_eq!(t.dbits[4], 1);
    }

    #[test]
    fn ldecode_bounds() {
        assert_eq!(LDECODE.len(), 28);
        assert_eq!(LBITS.len(), 28);
        assert_eq!(LDECODE[27], 224);
    }
}
