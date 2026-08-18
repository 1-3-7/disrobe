use crate::containers::rar_filters::FilterSet;
use crate::containers::rar_ppmd::{DecodeCtx, Ppmd7};
use crate::error::{Error, Result};

const NC30: usize = 299;
const DC30: usize = 60;
const LDC30: usize = 17;
const RC30: usize = 28;
const BC30: usize = 20;
const HUFF_TABLE_SIZE30: usize = NC30 + DC30 + LDC30 + RC30;
const MAX_LENGTH: usize = 15;
const LOW_DIST_REP_COUNT: u32 = 16;
const DECODE_WORK_PER_BYTE: u64 = 4;
const DECODE_WORK_BASE: u64 = 65_536;
const MAX_BLOCKS_PER_MEMBER: u32 = 8_192;
const MAX_FILTER_RECORD: usize = 0xffff;
const PPM_MEMORY_CEILING: u32 = 256 * 1024 * 1024;

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

    const fn byte_pos(&self) -> usize {
        (self.bit_pos / 8) as usize
    }

    const fn set_byte_pos(&mut self, pos: usize) {
        self.bit_pos = (pos as u64) * 8;
    }

    fn get_byte(&mut self) -> Result<u8> {
        if self.bit_pos + 8 > self.total_bits() {
            return Err(Error::Decompression(
                "rar 2.9/3.x stream ended inside a byte-aligned field".to_owned(),
            ));
        }
        let value: u8 = (self.peek16() >> 8) as u8;
        self.addbits(8);
        Ok(value)
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
    Ppm,
}

fn read_tables(inp: &mut BitInput<'_>, lz: &mut LzState) -> Result<BlockKind> {
    inp.align_byte();
    if inp.bit_pos + 16 > inp.total_bits() {
        return Err(Error::Decompression(
            "rar 2.9/3.x table header past end of stream".to_owned(),
        ));
    }
    let bit_field: u32 = inp.peek16();
    if bit_field & 0x8000 != 0 {
        return Ok(BlockKind::Ppm);
    }
    lz.low.prev_low_dist = 0;
    lz.low.low_dist_rep_count = 0;
    let tables: &mut BlockTables = &mut lz.tables;
    let old_table: &mut [u8; HUFF_TABLE_SIZE30] = &mut lz.old_table;
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

struct LowDistState {
    prev_low_dist: u32,
    low_dist_rep_count: u32,
}

struct LzState {
    tables: BlockTables,
    old_table: [u8; HUFF_TABLE_SIZE30],
    old_dist: [u32; 4],
    last_length: u32,
    low: LowDistState,
    dist_tables: DistTables,
}

impl LzState {
    fn new() -> Self {
        Self {
            tables: BlockTables::default(),
            old_table: [0u8; HUFF_TABLE_SIZE30],
            old_dist: [0u32; 4],
            last_length: 0,
            low: LowDistState {
                prev_low_dist: 0,
                low_dist_rep_count: 0,
            },
            dist_tables: DistTables::build(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockExit {
    Filled,
    EndOfData,
    ReadTables,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BlockProfile {
    pub(crate) lz_blocks: u32,
    pub(crate) ppm_blocks: u32,
    pub(crate) lz_to_ppm: u32,
    pub(crate) ppm_to_lz: u32,
    pub(crate) filter_invocations: usize,
    pub(crate) filter_kinds: [usize; 5],
}

struct Member<'a> {
    packed: &'a [u8],
    window: Vec<u8>,
    want: usize,
    filters: FilterSet,
    budget: u64,
    profile: BlockProfile,
}

impl Member<'_> {
    fn spend(&mut self, work: u64) -> Result<()> {
        self.budget = self.budget.checked_sub(work).ok_or_else(|| {
            Error::Decompression(
                "rar 2.9/3.x decode exceeded the work budget derived from the declared output size"
                    .to_owned(),
            )
        })?;
        Ok(())
    }
}

fn record_length_from_flags(flags: u8) -> Option<usize> {
    match (flags & 0x07) + 1 {
        7 | 8 => None,
        other => Some(usize::from(other)),
    }
}

fn read_filter_record_lz(inp: &mut BitInput<'_>) -> Result<(u8, Vec<u8>)> {
    let flags: u8 = inp.get_byte()?;
    let length: usize = match record_length_from_flags(flags) {
        Some(direct) => direct,
        None if (flags & 0x07) + 1 == 7 => usize::from(inp.get_byte()?) + 7,
        None => {
            let high: u8 = inp.get_byte()?;
            let low: u8 = inp.get_byte()?;
            (usize::from(high) << 8) | usize::from(low)
        }
    };
    let mut code: Vec<u8> = Vec::with_capacity(length.min(MAX_FILTER_RECORD));
    for _ in 0..length {
        code.push(inp.get_byte()?);
    }
    Ok((flags, code))
}

fn read_filter_record_ppm(ctx: &mut DecodeCtx<'_, '_>) -> Result<(u8, Vec<u8>)> {
    let byte = |ctx: &mut DecodeCtx<'_, '_>| -> Result<u8> {
        let value: i32 = ctx.decode_char();
        if value < 0 {
            return Err(Error::Decompression(
                "rar 2.9/3.x ppmd filter record ended inside the model stream".to_owned(),
            ));
        }
        Ok(value as u8)
    };
    let flags: u8 = byte(ctx)?;
    let length: usize = match record_length_from_flags(flags) {
        Some(direct) => direct,
        None if (flags & 0x07) + 1 == 7 => usize::from(byte(ctx)?) + 7,
        None => {
            let high: u8 = byte(ctx)?;
            let low: u8 = byte(ctx)?;
            (usize::from(high) << 8) | usize::from(low)
        }
    };
    let mut code: Vec<u8> = Vec::with_capacity(length.min(MAX_FILTER_RECORD));
    for _ in 0..length {
        code.push(byte(ctx)?);
    }
    Ok((flags, code))
}

fn decode_lz_block(
    inp: &mut BitInput<'_>,
    lz: &mut LzState,
    member: &mut Member<'_>,
) -> Result<BlockExit> {
    loop {
        if member.window.len() >= member.want {
            return Ok(BlockExit::Filled);
        }
        member.spend(1)?;
        if inp.bit_pos >= inp.total_bits() {
            return Ok(BlockExit::EndOfData);
        }
        let number: u16 = decode_number(inp, &lz.tables.ld);
        if number < 256 {
            member.window.push(number as u8);
            continue;
        }
        if number == 256 {
            let bit_field: u32 = inp.peek16();
            if bit_field & 0x8000 == 0 {
                inp.addbits(2);
                return Ok(BlockExit::EndOfData);
            }
            inp.addbits(1);
            return Ok(BlockExit::ReadTables);
        }
        if number == 257 {
            let (flags, code): (u8, Vec<u8>) = read_filter_record_lz(inp)?;
            member.spend(code.len() as u64 + 8)?;
            let position: u64 = member.window.len() as u64;
            member.filters.record(flags, &code, position)?;
            continue;
        }
        if number == 258 {
            if lz.last_length != 0 {
                let length: u32 = lz.last_length;
                let distance: u32 = lz.old_dist[0];
                copy_string(&mut member.window, length, distance, member.want)?;
            }
            continue;
        }
        if number < 263 {
            let dist_num: usize = (number - 259) as usize;
            let distance: u32 = lz.old_dist[dist_num];
            for n in (1..=dist_num).rev() {
                lz.old_dist[n] = lz.old_dist[n - 1];
            }
            lz.old_dist[0] = distance;
            let length_number: u16 = decode_number(inp, &lz.tables.rd);
            let length: u32 = read_length(inp, length_number, 2);
            lz.last_length = length;
            copy_string(&mut member.window, length, distance, member.want)?;
            continue;
        }
        if number >= 271 {
            let length_index: usize = (number - 271) as usize;
            let mut length: u32 = read_length(inp, length_index as u16, 3);
            let dist_number: u16 = decode_number(inp, &lz.tables.dd);
            let dist_index: usize = dist_number as usize;
            let mut distance: u32 = lz.dist_tables.ddecode[dist_index.min(DC30 - 1)] + 1;
            let bits: u32 = lz.dist_tables.dbits[dist_index.min(DC30 - 1)];
            if bits > 0 {
                if dist_index > 9 {
                    if bits > 4 {
                        distance += (inp.peek16() >> (20 - bits)) << 4;
                        inp.addbits(bits - 4);
                    }
                    if lz.low.low_dist_rep_count > 0 {
                        lz.low.low_dist_rep_count -= 1;
                        distance += lz.low.prev_low_dist;
                    } else {
                        let low_dist: u16 = decode_number(inp, &lz.tables.ldd);
                        if low_dist == 16 {
                            lz.low.low_dist_rep_count = LOW_DIST_REP_COUNT - 1;
                            distance += lz.low.prev_low_dist;
                        } else {
                            distance += u32::from(low_dist);
                            lz.low.prev_low_dist = u32::from(low_dist);
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
            insert_old_dist(&mut lz.old_dist, distance);
            lz.last_length = length;
            copy_string(&mut member.window, length, distance, member.want)?;
            continue;
        }
        let short_index: usize = (number - 263) as usize;
        let mut distance: u32 = SDDECODE[short_index.min(SDDECODE.len() - 1)] + 1;
        let bits: u32 = SDBITS[short_index.min(SDBITS.len() - 1)];
        if bits > 0 {
            distance += inp.peek16() >> (16 - bits);
            inp.addbits(bits);
        }
        insert_old_dist(&mut lz.old_dist, distance);
        lz.last_length = 2;
        copy_string(&mut member.window, 2, distance, member.want)?;
    }
}

fn read_ppm_header(
    inp: &mut BitInput<'_>,
    model: &mut Option<Ppmd7>,
    esc_char: &mut u8,
) -> Result<()> {
    let max_order_raw: u8 = inp.get_byte()?;
    let reset: bool = max_order_raw & 0x20 != 0;
    let max_mb: u8 = if reset { inp.get_byte()? } else { 0 };
    if max_order_raw & 0x40 != 0 {
        *esc_char = inp.get_byte()?;
    }
    if !reset {
        if model.is_none() {
            return Err(Error::Decompression(
                "rar 2.9/3.x ppmd block continues a model that this member never started; solid state carried across archive entries is not decoded".to_owned(),
            ));
        }
        return Ok(());
    }
    let mut max_order: u32 = u32::from(max_order_raw & 0x1f) + 1;
    if max_order > 16 {
        max_order = 16 + (max_order - 16) * 3;
    }
    if max_order == 1 {
        return Err(Error::Decompression(
            "rar 2.9/3.x ppmd model order resolves to 1 (invalid)".to_owned(),
        ));
    }
    let mem_bytes: u32 = (u32::from(max_mb) + 1)
        .checked_shl(20)
        .filter(|size: &u32| *size <= PPM_MEMORY_CEILING)
        .ok_or_else(|| {
            Error::Decompression(format!(
                "rar 2.9/3.x ppmd model requests more than {PPM_MEMORY_CEILING} bytes"
            ))
        })?;
    let mut fresh: Ppmd7 = Ppmd7::new(max_order, mem_bytes);
    fresh.restart_model();
    *model = Some(fresh);
    Ok(())
}

fn decode_ppm_block(
    inp: &mut BitInput<'_>,
    model: &mut Option<Ppmd7>,
    esc_char: &mut u8,
    member: &mut Member<'_>,
) -> Result<BlockExit> {
    read_ppm_header(inp, model, esc_char)?;
    let start: usize = inp.byte_pos();
    let stream: &[u8] = member.packed.get(start..).ok_or_else(|| {
        Error::Decompression("rar 2.9/3.x ppmd stream truncated after its header".to_owned())
    })?;
    let Some(active) = model.as_mut() else {
        return Err(Error::Decompression(
            "rar 2.9/3.x ppmd block reached decoding without a model".to_owned(),
        ));
    };
    let escape: u8 = *esc_char;
    let mut ctx: DecodeCtx<'_, '_> = DecodeCtx::new(active, stream);
    let mut window: Vec<u8> = std::mem::take(&mut member.window);
    let mut filters: FilterSet = std::mem::take(&mut member.filters);
    let want: usize = member.want;

    let outcome: Result<BlockExit> = loop {
        if window.len() >= want {
            break Ok(BlockExit::Filled);
        }
        if let Err(e) = member.spend(1) {
            break Err(e);
        }
        let symbol: i32 = ctx.decode_char();
        if symbol < 0 {
            break Err(Error::Decompression(format!(
                "rar 2.9/3.x ppmd decode produced {} of {want} bytes before a model error",
                window.len()
            )));
        }
        if symbol != i32::from(escape) {
            window.push(symbol as u8);
            continue;
        }
        let next: i32 = ctx.decode_char();
        match next {
            -1 => {
                break Err(Error::Decompression(
                    "rar 2.9/3.x ppmd escape sequence hit a model error".to_owned(),
                ));
            }
            0 => break Ok(BlockExit::ReadTables),
            2 => break Ok(BlockExit::EndOfData),
            3 => {
                let record: Result<(u8, Vec<u8>)> = read_filter_record_ppm(&mut ctx);
                let (flags, code): (u8, Vec<u8>) = match record {
                    Ok(pair) => pair,
                    Err(e) => break Err(e),
                };
                if let Err(e) = member.spend(code.len() as u64 + 8) {
                    break Err(e);
                }
                if let Err(e) = filters.record(flags, &code, window.len() as u64) {
                    break Err(e);
                }
            }
            4 => {
                let mut distance: u32 = 0;
                let mut length: u32 = 0;
                let mut failed: bool = false;
                for index in 0..4 {
                    let byte: i32 = ctx.decode_char();
                    if byte < 0 {
                        failed = true;
                        break;
                    }
                    if index == 3 {
                        length = byte as u32;
                    } else {
                        distance = (distance << 8) + byte as u32;
                    }
                }
                if failed {
                    break Err(Error::Decompression(
                        "rar 2.9/3.x ppmd lz-in-ppm escape truncated".to_owned(),
                    ));
                }
                if let Err(e) = copy_string(&mut window, length + 32, distance + 2, want) {
                    break Err(e);
                }
            }
            5 => {
                let length: i32 = ctx.decode_char();
                if length < 0 {
                    break Err(Error::Decompression(
                        "rar 2.9/3.x ppmd rle-in-ppm escape truncated".to_owned(),
                    ));
                }
                if let Err(e) = copy_string(&mut window, length as u32 + 4, 1, want) {
                    break Err(e);
                }
            }
            _ => window.push(escape),
        }
    };

    let consumed: usize = ctx.consumed();
    let overread: usize = ctx.overread();
    member.window = window;
    member.filters = filters;
    let exit: BlockExit = outcome?;
    if exit == BlockExit::ReadTables {
        if overread != 0 {
            return Err(Error::Decompression(format!(
                "rar 2.9/3.x ppmd block ended {overread} bytes past the packed stream, so the following block has no input"
            )));
        }
        inp.set_byte_pos(consumed.saturating_add(start));
    }
    Ok(exit)
}

fn drive(packed: &[u8], want: usize, unpacked_size: u64) -> Result<Member<'_>> {
    let mut member: Member<'_> = Member {
        packed,
        window: Vec::with_capacity(crate::quota::bounded_prealloc(unpacked_size)),
        want,
        filters: FilterSet::default(),
        budget: (want as u64)
            .saturating_mul(DECODE_WORK_PER_BYTE)
            .saturating_add(DECODE_WORK_BASE),
        profile: BlockProfile::default(),
    };
    let mut inp: BitInput<'_> = BitInput::new(packed);
    let mut lz: LzState = LzState::new();
    let mut model: Option<Ppmd7> = None;
    let mut esc_char: u8 = 2;
    let mut kind: BlockKind = read_tables(&mut inp, &mut lz)?;

    loop {
        if member.window.len() >= want {
            break;
        }
        if member.profile.lz_blocks + member.profile.ppm_blocks >= MAX_BLOCKS_PER_MEMBER {
            return Err(Error::Decompression(format!(
                "rar 2.9/3.x member declares more than {MAX_BLOCKS_PER_MEMBER} compression blocks"
            )));
        }
        let exit: BlockExit = match kind {
            BlockKind::Lz => {
                member.profile.lz_blocks += 1;
                decode_lz_block(&mut inp, &mut lz, &mut member)?
            }
            BlockKind::Ppm => {
                member.profile.ppm_blocks += 1;
                decode_ppm_block(&mut inp, &mut model, &mut esc_char, &mut member)?
            }
        };
        match exit {
            BlockExit::Filled | BlockExit::EndOfData => break,
            BlockExit::ReadTables => {
                let next: BlockKind = read_tables(&mut inp, &mut lz)?;
                match (kind, next) {
                    (BlockKind::Lz, BlockKind::Ppm) => member.profile.lz_to_ppm += 1,
                    (BlockKind::Ppm, BlockKind::Lz) => member.profile.ppm_to_lz += 1,
                    _ => {}
                }
                kind = next;
            }
        }
    }
    Ok(member)
}

pub(crate) fn unpack3_profiled(
    packed: &[u8],
    unpacked_size: u64,
    cap: u64,
) -> Result<(Vec<u8>, BlockProfile)> {
    if unpacked_size > cap {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x unpacked size {unpacked_size} exceeds cap {cap}"
        )));
    }
    let want: usize = usize::try_from(unpacked_size).map_err(|_e: std::num::TryFromIntError| {
        Error::Decompression("rar 2.9/3.x size overflow".to_owned())
    })?;
    let member: Member<'_> = drive(packed, want, unpacked_size)?;
    if member.window.len() != want {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x produced {} of {want} bytes",
            member.window.len()
        )));
    }
    let mut profile: BlockProfile = member.profile;
    profile.filter_invocations = member.filters.len();
    profile.filter_kinds = member.filters.invocation_counts();
    if member.filters.is_empty() {
        return Ok((member.window, profile));
    }
    let filtered: Vec<u8> = member.filters.emit(&member.window, want)?;
    if filtered.len() != want {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x filters produced {} of {want} bytes",
            filtered.len()
        )));
    }
    Ok((filtered, profile))
}

pub fn unpack3(packed: &[u8], unpacked_size: u64, cap: u64) -> Result<Vec<u8>> {
    unpack3_profiled(packed, unpacked_size, cap).map(|(bytes, _profile)| bytes)
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

    fn fixture(name: &str) -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("corpus");
        path.push("binfmt");
        path.push("rar");
        path.push(name);
        std::fs::read(&path).unwrap_or_else(|_e: std::io::Error| {
            panic!("missing committed fixture corpus/binfmt/rar/{name}")
        })
    }

    fn profile_of(name: &str, member: &str) -> BlockProfile {
        let bytes: Vec<u8> = fixture(name);
        let archive: crate::containers::RarArchive =
            crate::containers::rar::parse_rar(&bytes).expect("parse rar");
        let entry: &crate::containers::RarEntry = archive
            .entries
            .iter()
            .find(|candidate: &&crate::containers::RarEntry| candidate.name == member)
            .expect("member present");
        let start: usize = entry.data_offset as usize;
        let end: usize = start + entry.packed_size as usize;
        let packed: &[u8] = &bytes[start..end];
        unpack3_profiled(packed, entry.unpacked_size, 512 * 1024 * 1024)
            .expect("decode member")
            .1
    }

    #[test]
    fn the_mixed_member_crosses_both_block_boundaries_in_both_directions() {
        let profile: BlockProfile =
            profile_of("mixed-ppmd-lz-rar3.rar", "ppmd_lzss_conversion_test.txt");
        assert!(
            profile.lz_blocks > 0 && profile.ppm_blocks > 0,
            "the fixture must carry both block kinds: {profile:?}"
        );
        assert!(
            profile.ppm_to_lz > 0,
            "the fixture must switch from ppm to lz at least once: {profile:?}"
        );
        assert!(
            profile.lz_to_ppm > 0,
            "the fixture must switch from lz back to ppm at least once: {profile:?}"
        );
    }

    #[test]
    fn the_filter_member_applies_the_delta_and_x86_programs_its_records_name() {
        let profile: BlockProfile = profile_of("filter-e8-rar3.rar", "bsdcat.exe");
        assert_eq!(
            profile.filter_kinds,
            [6, 0, 1, 0, 0],
            "bsdcat.exe carries six delta invocations and one x86 e8/e9 invocation: {profile:?}"
        );
        assert_eq!(
            profile.filter_invocations,
            profile.filter_kinds.iter().sum::<usize>(),
            "every queued invocation must map to a canonical program: {profile:?}"
        );
        assert_eq!(profile.ppm_blocks, 0, "{profile:?}");
    }

    #[test]
    fn the_multiblock_member_reads_several_lz_tables_without_any_ppm_block() {
        let profile: BlockProfile =
            profile_of("multiblock-lz-rar3.rar", "multi_lzss_blocks_test.txt");
        assert!(
            profile.lz_blocks > 1,
            "the fixture must span several lz blocks: {profile:?}"
        );
        assert_eq!(profile.ppm_blocks, 0, "{profile:?}");
        assert_eq!(profile.filter_invocations, 0, "{profile:?}");
    }

    #[test]
    fn a_member_whose_declared_size_outruns_its_packed_stream_is_refused() {
        let bytes: Vec<u8> = fixture("lowdist-reset-rar3.rar");
        let archive: crate::containers::RarArchive =
            crate::containers::rar::parse_rar(&bytes).expect("parse rar");
        let entry: &crate::containers::RarEntry =
            archive.entries.first().expect("one member present");
        let start: usize = entry.data_offset as usize;
        let end: usize = start + entry.packed_size as usize;
        let error: Error = unpack3(&bytes[start..end], 1 << 20, 1 << 30)
            .expect_err("a size far past the packed stream must be refused");
        let text: String = error.to_string();
        assert!(
            text.contains("produced") || text.contains("truncated") || text.contains("budget"),
            "{text}"
        );
    }

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
