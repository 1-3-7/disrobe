use crate::error::{Error, Result};

const BZ_MAX_ALPHA_SIZE: usize = 258;
const BZ_MAX_CODE_LEN: usize = 23;
const BZ_RUNA: u32 = 0;
const BZ_RUNB: u32 = 1;
const BZ_N_GROUPS: usize = 6;
const BZ_G_SIZE: u32 = 50;
const NSIS_BLOCK_SIZE: usize = 900_000;
const MTFA_SIZE: usize = 4096;
const MTFL_SIZE: usize = 16;

const NSIS_BLOCK_TAG: u8 = 0x31;
const NSIS_STREAM_END_TAG: u8 = 0x17;

#[derive(Debug)]
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    live: u32,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            live: 0,
        }
    }

    fn read(&mut self, count: u32) -> Result<u32> {
        while self.live < count {
            let byte: u8 = *self
                .data
                .get(self.pos)
                .ok_or_else(|| Error::Decompression("nsis bzip2 stream underrun".to_owned()))?;
            self.pos += 1;
            self.buf = (self.buf << 8) | u32::from(byte);
            self.live += 8;
        }
        let value: u32 = (self.buf >> (self.live - count)) & ((1u32 << count) - 1);
        self.live -= count;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read(8)? as u8)
    }

    fn read_bit(&mut self) -> Result<bool> {
        Ok(self.read(1)? == 1)
    }

    const fn consumed_bytes(&self) -> usize {
        self.pos - (self.live / 8) as usize
    }
}

#[derive(Debug)]
struct DecodeTable {
    limit: [i32; BZ_MAX_CODE_LEN],
    base: [i32; BZ_MAX_CODE_LEN],
    perm: [i32; BZ_MAX_ALPHA_SIZE],
    min_len: i32,
}

fn create_decode_table(length: &[u8], alpha_size: usize) -> DecodeTable {
    let mut min_len: i32 = 32;
    let mut max_len: i32 = 0;
    for &len in &length[..alpha_size] {
        let l: i32 = i32::from(len);
        if l > max_len {
            max_len = l;
        }
        if l < min_len {
            min_len = l;
        }
    }
    let mut perm: [i32; BZ_MAX_ALPHA_SIZE] = [0i32; BZ_MAX_ALPHA_SIZE];
    let mut pp: usize = 0;
    for i in min_len..=max_len {
        for (j, &len) in length[..alpha_size].iter().enumerate() {
            if i32::from(len) == i {
                perm[pp] = j as i32;
                pp += 1;
            }
        }
    }
    let mut base: [i32; BZ_MAX_CODE_LEN] = [0i32; BZ_MAX_CODE_LEN];
    for &len in &length[..alpha_size] {
        base[(len as usize) + 1] += 1;
    }
    for i in 1..BZ_MAX_CODE_LEN {
        base[i] += base[i - 1];
    }
    let mut limit: [i32; BZ_MAX_CODE_LEN] = [0i32; BZ_MAX_CODE_LEN];
    let mut vec: i32 = 0;
    for i in min_len..=max_len {
        let idx: usize = i as usize;
        vec += base[idx + 1] - base[idx];
        limit[idx] = vec - 1;
        vec <<= 1;
    }
    for i in (min_len + 1)..=max_len {
        let idx: usize = i as usize;
        base[idx] = ((limit[idx - 1] + 1) << 1) - base[idx];
    }
    DecodeTable {
        limit,
        base,
        perm,
        min_len,
    }
}

#[derive(Debug)]
struct GroupReader {
    n_selectors: usize,
    group_no: i64,
    group_pos: u32,
    selectors: Vec<u8>,
}

impl GroupReader {
    fn next_symbol(&mut self, reader: &mut BitReader<'_>, tables: &[DecodeTable]) -> Result<u32> {
        if self.group_pos == 0 {
            self.group_no += 1;
            if self.group_no as usize >= self.n_selectors {
                return Err(Error::Decompression(
                    "nsis bzip2 ran out of selector groups".to_owned(),
                ));
            }
            self.group_pos = BZ_G_SIZE;
        }
        self.group_pos -= 1;
        let sel: usize = self.selectors[self.group_no as usize] as usize;
        let table: &DecodeTable = &tables[sel];
        let mut zn: i32 = table.min_len;
        let mut zvec: i32 = reader.read(zn as u32)? as i32;
        loop {
            if zn > 20 {
                return Err(Error::Decompression(
                    "nsis bzip2 huffman code length exceeds 20".to_owned(),
                ));
            }
            if zvec <= table.limit[zn as usize] {
                break;
            }
            zn += 1;
            let bit: i32 = i32::from(reader.read_bit()?);
            zvec = (zvec << 1) | bit;
        }
        let index: i32 = zvec - table.base[zn as usize];
        if index < 0 || index as usize >= BZ_MAX_ALPHA_SIZE {
            return Err(Error::Decompression(
                "nsis bzip2 huffman symbol out of range".to_owned(),
            ));
        }
        Ok(table.perm[index as usize] as u32)
    }
}

struct BlockState {
    tt: Vec<u32>,
    unzftab: [i32; 256],
    orig_ptr: i32,
    n_block: usize,
}

fn read_block(reader: &mut BitReader<'_>) -> Result<Option<BlockState>> {
    let tag: u8 = reader.read_u8()?;
    if tag == NSIS_STREAM_END_TAG {
        return Ok(None);
    }
    if tag != NSIS_BLOCK_TAG {
        return Err(Error::Decompression(format!(
            "nsis bzip2 unexpected block tag {tag:#04x}"
        )));
    }
    let mut orig_ptr: i32 = 0;
    for _ in 0..3 {
        orig_ptr = (orig_ptr << 8) | i32::from(reader.read_u8()?);
    }
    if orig_ptr < 0 || orig_ptr > (10 + NSIS_BLOCK_SIZE) as i32 {
        return Err(Error::Decompression(
            "nsis bzip2 origPtr out of range".to_owned(),
        ));
    }

    let mut in_use16: [bool; 16] = [false; 16];
    for slot in &mut in_use16 {
        *slot = reader.read_bit()?;
    }
    let mut in_use: [bool; 256] = [false; 256];
    for (i, &present) in in_use16.iter().enumerate() {
        if present {
            for j in 0..16 {
                if reader.read_bit()? {
                    in_use[i * 16 + j] = true;
                }
            }
        }
    }
    let mut seq_to_unseq: [u8; 256] = [0u8; 256];
    let mut n_in_use: usize = 0;
    for (i, &present) in in_use.iter().enumerate() {
        if present {
            seq_to_unseq[n_in_use] = i as u8;
            n_in_use += 1;
        }
    }
    if n_in_use == 0 {
        return Err(Error::Decompression(
            "nsis bzip2 empty symbol map".to_owned(),
        ));
    }
    let alpha_size: usize = n_in_use + 2;

    let n_groups: usize = reader.read(3)? as usize;
    if !(2..=BZ_N_GROUPS).contains(&n_groups) {
        return Err(Error::Decompression(
            "nsis bzip2 group count out of range".to_owned(),
        ));
    }
    let n_selectors: usize = reader.read(15)? as usize;
    if n_selectors < 1 {
        return Err(Error::Decompression(
            "nsis bzip2 selector count is zero".to_owned(),
        ));
    }
    let mut selector_mtf: Vec<u8> = Vec::with_capacity(n_selectors);
    for _ in 0..n_selectors {
        let mut j: u32 = 0;
        loop {
            if !reader.read_bit()? {
                break;
            }
            j += 1;
            if j as usize >= n_groups {
                return Err(Error::Decompression(
                    "nsis bzip2 selector mtf value out of range".to_owned(),
                ));
            }
        }
        selector_mtf.push(j as u8);
    }
    let mut pos: [u8; BZ_N_GROUPS] = [0u8; BZ_N_GROUPS];
    for (v, slot) in pos.iter_mut().enumerate().take(n_groups) {
        *slot = v as u8;
    }
    let mut selectors: Vec<u8> = Vec::with_capacity(n_selectors);
    for &mtf in &selector_mtf {
        let v: usize = mtf as usize;
        let tmp: u8 = pos[v];
        for k in (1..=v).rev() {
            pos[k] = pos[k - 1];
        }
        pos[0] = tmp;
        selectors.push(tmp);
    }

    let mut tables: Vec<DecodeTable> = Vec::with_capacity(n_groups);
    for _ in 0..n_groups {
        let mut length: [u8; BZ_MAX_ALPHA_SIZE] = [0u8; BZ_MAX_ALPHA_SIZE];
        let mut curr: i32 = reader.read(5)? as i32;
        for slot in length.iter_mut().take(alpha_size) {
            loop {
                if !(1..=20).contains(&curr) {
                    return Err(Error::Decompression(
                        "nsis bzip2 code length out of range".to_owned(),
                    ));
                }
                if !reader.read_bit()? {
                    break;
                }
                if reader.read_bit()? {
                    curr -= 1;
                } else {
                    curr += 1;
                }
            }
            *slot = curr as u8;
        }
        tables.push(create_decode_table(&length, alpha_size));
    }

    let eob: u32 = (n_in_use + 1) as u32;
    let mut group_reader: GroupReader = GroupReader {
        n_selectors,
        group_no: -1,
        group_pos: 0,
        selectors,
    };

    let mut unzftab: [i32; 256] = [0i32; 256];
    let mut mtfa: [u8; MTFA_SIZE] = [0u8; MTFA_SIZE];
    let mut mtfbase: [i32; 256 / MTFL_SIZE] = [0i32; 256 / MTFL_SIZE];
    {
        let mut kk: i32 = MTFA_SIZE as i32 - 1;
        for ii in (0..(256 / MTFL_SIZE)).rev() {
            for jj in (0..MTFL_SIZE).rev() {
                mtfa[kk as usize] = (ii * MTFL_SIZE + jj) as u8;
                kk -= 1;
            }
            mtfbase[ii] = kk + 1;
        }
    }

    let mut tt: Vec<u32> = vec![0u32; NSIS_BLOCK_SIZE];
    let mut n_block: usize = 0;
    let mut next_sym: u32 = group_reader.next_symbol(reader, &tables)?;

    while next_sym != eob {
        if next_sym == BZ_RUNA || next_sym == BZ_RUNB {
            let mut es: i64 = -1;
            let mut shift: u32 = 0;
            while next_sym == BZ_RUNA || next_sym == BZ_RUNB {
                if next_sym == BZ_RUNA {
                    es += 1i64 << shift;
                } else {
                    es += 2i64 << shift;
                }
                shift += 1;
                next_sym = group_reader.next_symbol(reader, &tables)?;
            }
            es += 1;
            let uc: u8 = seq_to_unseq[mtfa[mtfbase[0] as usize] as usize];
            unzftab[uc as usize] += es as i32;
            if n_block + (es as usize) > NSIS_BLOCK_SIZE {
                return Err(Error::Decompression(
                    "nsis bzip2 block exceeds maximum size".to_owned(),
                ));
            }
            for _ in 0..es {
                tt[n_block] = u32::from(uc);
                n_block += 1;
            }
            continue;
        }
        if n_block >= NSIS_BLOCK_SIZE {
            return Err(Error::Decompression(
                "nsis bzip2 block exceeds maximum size".to_owned(),
            ));
        }
        let nn: usize = (next_sym - 1) as usize;
        let uc: usize = if nn < MTFL_SIZE {
            let pp: usize = mtfbase[0] as usize;
            let value: u8 = mtfa[pp + nn];
            let mut n: usize = nn;
            while n > 0 {
                mtfa[pp + n] = mtfa[pp + n - 1];
                n -= 1;
            }
            mtfa[pp] = value;
            usize::from(value)
        } else {
            let mut lno: usize = nn / MTFL_SIZE;
            let off: usize = nn % MTFL_SIZE;
            let mut pp: usize = mtfbase[lno] as usize + off;
            let value: u8 = mtfa[pp];
            while pp > mtfbase[lno] as usize {
                mtfa[pp] = mtfa[pp - 1];
                pp -= 1;
            }
            mtfbase[lno] += 1;
            while lno > 0 {
                mtfbase[lno] -= 1;
                mtfa[mtfbase[lno] as usize] = mtfa[mtfbase[lno - 1] as usize + MTFL_SIZE - 1];
                lno -= 1;
            }
            mtfbase[0] -= 1;
            mtfa[mtfbase[0] as usize] = value;
            if mtfbase[0] == 0 {
                let mut kk: i32 = MTFA_SIZE as i32 - 1;
                for ii in (0..(256 / MTFL_SIZE)).rev() {
                    for jj in (0..MTFL_SIZE).rev() {
                        mtfa[kk as usize] = mtfa[mtfbase[ii] as usize + jj];
                        kk -= 1;
                    }
                    mtfbase[ii] = kk + 1;
                }
            }
            usize::from(value)
        };
        unzftab[seq_to_unseq[uc] as usize] += 1;
        tt[n_block] = u32::from(seq_to_unseq[uc]);
        n_block += 1;
        next_sym = group_reader.next_symbol(reader, &tables)?;
    }

    if orig_ptr < 0 || orig_ptr as usize >= n_block {
        return Err(Error::Decompression(
            "nsis bzip2 origPtr exceeds block length".to_owned(),
        ));
    }

    Ok(Some(BlockState {
        tt,
        unzftab,
        orig_ptr,
        n_block,
    }))
}

fn emit_block(block: &mut BlockState, out: &mut Vec<u8>, cap: usize) -> Result<()> {
    let mut cftab: [i32; 257] = [0i32; 257];
    cftab[0] = 0;
    for i in 1..=256 {
        cftab[i] = block.unzftab[i - 1] + cftab[i - 1];
    }
    for i in 0..block.n_block {
        let uc: usize = (block.tt[i] & 0xff) as usize;
        let slot: usize = cftab[uc] as usize;
        block.tt[slot] |= (i as u32) << 8;
        cftab[uc] += 1;
    }

    let tt: &[u32] = &block.tt;
    let n_block: usize = block.n_block;
    let mut t_pos: u32 = tt[block.orig_ptr as usize] >> 8;
    let next = |t_pos: &mut u32| -> i32 {
        *t_pos = tt[*t_pos as usize];
        let byte: u8 = (*t_pos & 0xff) as u8;
        *t_pos >>= 8;
        i32::from(byte)
    };

    let mut k0: i32 = next(&mut t_pos);
    let mut n_block_used: usize = 1;
    let stop: usize = n_block + 1;

    loop {
        if n_block_used == stop {
            break;
        }
        let ch: u8 = k0 as u8;
        let mut k1: i32 = next(&mut t_pos);
        n_block_used += 1;
        if k1 != k0 {
            push_run(out, ch, 1, cap)?;
            k0 = k1;
            continue;
        }
        if n_block_used == stop {
            push_run(out, ch, 1, cap)?;
            break;
        }

        k1 = next(&mut t_pos);
        n_block_used += 1;
        if n_block_used == stop {
            push_run(out, ch, 2, cap)?;
            break;
        }
        if k1 != k0 {
            push_run(out, ch, 2, cap)?;
            k0 = k1;
            continue;
        }

        k1 = next(&mut t_pos);
        n_block_used += 1;
        if n_block_used == stop {
            push_run(out, ch, 3, cap)?;
            break;
        }
        if k1 != k0 {
            push_run(out, ch, 3, cap)?;
            k0 = k1;
            continue;
        }

        let extra: i32 = next(&mut t_pos);
        n_block_used += 1;
        let run_len: i32 = extra + 4;
        k0 = next(&mut t_pos);
        n_block_used += 1;
        push_run(out, ch, run_len, cap)?;
    }
    Ok(())
}

fn push_run(out: &mut Vec<u8>, byte: u8, count: i32, cap: usize) -> Result<()> {
    if count <= 0 {
        return Ok(());
    }
    if out.len() + count as usize > cap {
        return Err(Error::Decompression(
            "nsis bzip2 output exceeds size cap".to_owned(),
        ));
    }
    for _ in 0..count {
        out.push(byte);
    }
    Ok(())
}

/// Decompress an NSIS modified-bzip2 stream to at most `cap` bytes.
pub fn decompress(input: &[u8], cap: u64) -> Result<Vec<u8>> {
    Ok(decompress_counting(input, cap)?.0)
}

/// Like [`decompress`] but also returns the number of input bytes consumed.
pub fn decompress_counting(input: &[u8], cap: u64) -> Result<(Vec<u8>, usize)> {
    let cap_usize: usize =
        usize::try_from(cap.min(u64::from(u32::MAX) * 4)).map_or(usize::MAX, |value: usize| value);
    let mut reader: BitReader<'_> = BitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    while let Some(mut block) = read_block(&mut reader)? {
        emit_block(&mut block, &mut out, cap_usize)?;
    }
    Ok((out, reader.consumed_bytes()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const FILE_STREAM: [u8; 91] = [
        0x31, 0x00, 0x00, 0x83, 0x27, 0x00, 0x80, 0x02, 0x08, 0x00, 0x7f, 0xff, 0xff, 0xe0, 0x40,
        0x01, 0x00, 0x29, 0x52, 0x9a, 0x9a, 0x68, 0xd1, 0x84, 0xd0, 0xda, 0x9b, 0x6a, 0x42, 0x80,
        0x01, 0xa0, 0x00, 0x0c, 0x17, 0x22, 0xc9, 0x7d, 0x16, 0x4b, 0xe0, 0xb5, 0x2c, 0x16, 0xa5,
        0xd0, 0xbd, 0xcb, 0xec, 0xb0, 0x5d, 0x8b, 0x05, 0xd8, 0x5b, 0x16, 0xe2, 0xee, 0x5e, 0x0b,
        0xa9, 0x6c, 0x5e, 0x85, 0xf8, 0x58, 0x2d, 0xc5, 0x92, 0xee, 0x5a, 0x17, 0x22, 0xd4, 0xbc,
        0x16, 0x85, 0xd4, 0xbf, 0x8b, 0x62, 0xd0, 0xb2, 0x59, 0x2e, 0x84, 0x79, 0x2f, 0x25, 0xfe,
        0x2e,
    ];

    fn expected_plain() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. "
            .iter()
            .copied()
            .cycle()
            .take(540)
            .collect()
    }

    #[test]
    fn decodes_real_makensis_bzip2_file_stream() {
        let plain: Vec<u8> = expected_plain();
        let out: Vec<u8> = decompress(&FILE_STREAM, 1 << 20).expect("decode real nsis bz2 stream");
        assert_eq!(out.len(), plain.len());
        assert_eq!(out, plain, "nsis modified-bzip2 must decode byte-exact");
    }

    #[test]
    fn reports_consumed_bytes_for_real_stream() {
        let (out, consumed): (Vec<u8>, usize) =
            decompress_counting(&FILE_STREAM, 1 << 20).expect("decode counting");
        assert_eq!(out, expected_plain());
        assert!(consumed <= FILE_STREAM.len());
        assert!(consumed >= FILE_STREAM.len() - 1);
    }

    #[test]
    fn honors_output_cap() {
        let err: Error = decompress(&FILE_STREAM, 100).expect_err("cap must trip");
        match err {
            Error::Decompression(message) => assert!(message.contains("exceeds size cap")),
            other => panic!("expected cap error, got {other:?}"),
        }
    }

    #[test]
    fn stream_end_tag_yields_empty() {
        let out: Vec<u8> = decompress(&[NSIS_STREAM_END_TAG], 1024).expect("end tag");
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_unknown_block_tag() {
        let err: Error = decompress(&[0x42, 0x00, 0x00, 0x00], 1024).expect_err("bad tag");
        match err {
            Error::Decompression(message) => assert!(message.contains("block tag")),
            other => panic!("expected block tag error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_stream_does_not_panic() {
        for cut in 1..FILE_STREAM.len() {
            let _ = decompress(&FILE_STREAM[..cut], 1 << 20);
        }
    }
}
