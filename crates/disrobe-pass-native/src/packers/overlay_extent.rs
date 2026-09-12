use disrobe_bytes::{align_up_usize as align_up, read_uleb128_at};
use disrobe_core::codec::crc32_ieee;
use flate2::{Decompress, FlushDecompress, Status};

use crate::packers::overlay::ArchiveKind;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const GZIP_FIXED_HEADER: usize = 10;
const GZIP_FLAG_FHCRC: u8 = 0x02;
const GZIP_FLAG_FEXTRA: u8 = 0x04;
const GZIP_FLAG_FNAME: u8 = 0x08;
const GZIP_FLAG_FCOMMENT: u8 = 0x10;
const GZIP_FLAG_RESERVED: u8 = 0xE0;
const GZIP_TRAILER: usize = 8;
const GZIP_DEFLATE_SCRATCH: usize = 64 * 1024;

const XZ_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0x00];
const XZ_STREAM_HEADER: usize = 12;
const XZ_STREAM_FOOTER: usize = 12;
const XZ_FOOTER_MAGIC: [u8; 2] = [b'Y', b'Z'];
const XZ_BLOCK_ALIGN: usize = 4;

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const ZSTD_SKIPPABLE_LOW: u32 = 0x184d_2a50;
const ZSTD_SKIPPABLE_HIGH: u32 = 0x184d_2a5f;
const ZSTD_BLOCK_RAW: u8 = 0;
const ZSTD_BLOCK_RLE: u8 = 1;
const ZSTD_BLOCK_COMPRESSED: u8 = 2;

const BZIP2_MAGIC: [u8; 3] = [b'B', b'Z', b'h'];
const BZIP2_EOS_MAGIC: u64 = 0x1772_4538_5090;
const BZIP2_MAGIC_BITS: u32 = 48;
const BZIP2_CRC_BITS: u32 = 32;

const TAR_BLOCK: usize = 512;
const TAR_USTAR_OFFSET: usize = 257;
const TAR_SIZE_OFFSET: usize = 124;
const TAR_SIZE_LEN: usize = 12;
const TAR_MAX_BLOCKS: usize = 1 << 28;

const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const SEVENZ_SIGNATURE_HEADER: usize = 32;
const SEVENZ_NEXT_HEADER_OFFSET: usize = 12;
const SEVENZ_NEXT_HEADER_SIZE: usize = 20;

const CAB_MAGIC: [u8; 4] = [b'M', b'S', b'C', b'F'];
const CAB_CB_CABINET_OFFSET: usize = 8;

const RAR5_MAGIC: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
const RAR4_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
const RAR5_HEADER_FLAG_EXTRA: u64 = 0x0001;
const RAR5_HEADER_FLAG_DATA: u64 = 0x0002;
const RAR5_HEAD_ENDARC: u64 = 5;
const RAR5_MAX_BLOCKS: usize = 1_000_000;
const RAR4_BLOCK_HEADER: usize = 7;
const RAR4_FLAG_DATA: u16 = 0x8000;
const RAR4_FLAG_BIG_DATA: u16 = 0x0100;
const RAR4_TYPE_ENDARC: u8 = 0x7b;
const RAR4_MAX_BLOCKS: usize = 1_000_000;

#[must_use]
pub fn archive_true_extent(window: &[u8], archive: ArchiveKind) -> Option<usize> {
    let extent: usize = match archive {
        ArchiveKind::Gzip => gzip_extent(window)?,
        ArchiveKind::Xz => xz_extent(window)?,
        ArchiveKind::Zstd => zstd_extent(window)?,
        ArchiveKind::Bzip2 => bzip2_extent(window)?,
        ArchiveKind::Tar => tar_extent(window)?,
        ArchiveKind::SevenZ => sevenz_extent(window)?,
        ArchiveKind::Cab => cab_extent(window)?,
        ArchiveKind::Rar => rar_extent(window)?,
        ArchiveKind::Zip => return None,
    };
    if extent == 0 || extent > window.len() {
        None
    } else {
        Some(extent)
    }
}

fn read_u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    let s: &[u8] = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let s: &[u8] = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    let s: &[u8] = bytes.get(at..at + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn gzip_member_len(window: &[u8], start: usize) -> Option<usize> {
    let header: &[u8] = window.get(start..start + GZIP_FIXED_HEADER)?;
    if header[0..2] != GZIP_MAGIC || header[2] != 0x08 {
        return None;
    }
    let flags: u8 = header[3];
    if flags & GZIP_FLAG_RESERVED != 0 {
        return None;
    }
    let mut pos: usize = start + GZIP_FIXED_HEADER;
    if flags & GZIP_FLAG_FEXTRA != 0 {
        let xlen: usize = read_u16_le(window, pos)? as usize;
        pos = pos.checked_add(2 + xlen)?;
    }
    if flags & GZIP_FLAG_FNAME != 0 {
        pos = gzip_skip_cstr(window, pos)?;
    }
    if flags & GZIP_FLAG_FCOMMENT != 0 {
        pos = gzip_skip_cstr(window, pos)?;
    }
    if flags & GZIP_FLAG_FHCRC != 0 {
        pos = pos.checked_add(2)?;
    }
    let deflate_consumed: usize = deflate_consumed_len(window.get(pos..)?)?;
    let after_data: usize = pos.checked_add(deflate_consumed)?;
    let member_end: usize = after_data.checked_add(GZIP_TRAILER)?;
    if member_end > window.len() {
        return None;
    }
    Some(member_end)
}

fn gzip_skip_cstr(window: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let byte: u8 = *window.get(pos)?;
        pos = pos.checked_add(1)?;
        if byte == 0 {
            return Some(pos);
        }
    }
}

fn deflate_consumed_len(input: &[u8]) -> Option<usize> {
    let mut engine: Decompress = Decompress::new(false);
    let mut scratch: Vec<u8> = vec![0u8; GZIP_DEFLATE_SCRATCH];
    loop {
        let before_in: u64 = engine.total_in();
        let fed: &[u8] = input.get(before_in as usize..)?;
        let status: Status = engine
            .decompress(fed, &mut scratch, FlushDecompress::None)
            .ok()?;
        match status {
            Status::StreamEnd => return Some(engine.total_in() as usize),
            Status::Ok | Status::BufError => {
                if engine.total_in() == before_in && fed.is_empty() {
                    return None;
                }
                if engine.total_in() == before_in && status == Status::BufError {
                    return None;
                }
            }
        }
    }
}

fn gzip_extent(window: &[u8]) -> Option<usize> {
    if !window.starts_with(&GZIP_MAGIC) {
        return None;
    }
    let mut pos: usize = gzip_member_len(window, 0)?;
    while window
        .get(pos..pos + 2)
        .is_some_and(|m: &[u8]| m == GZIP_MAGIC)
    {
        match gzip_member_len(window, pos) {
            Some(member_end) => pos = member_end,
            None => break,
        }
    }
    Some(pos)
}

fn crc32(bytes: &[u8]) -> u32 {
    crc32_ieee(bytes)
}

fn xz_stream_end(window: &[u8], stream_start: usize) -> Option<usize> {
    let stream_flags: &[u8] = window.get(stream_start + 6..stream_start + 8)?;
    let mut footer_start: usize = align_up(stream_start + XZ_STREAM_HEADER, XZ_BLOCK_ALIGN);
    while footer_start + XZ_STREAM_FOOTER <= window.len() {
        let footer: &[u8] = &window[footer_start..footer_start + XZ_STREAM_FOOTER];
        if footer[10..12] == XZ_FOOTER_MAGIC && &footer[8..10] == stream_flags {
            let backward_size: u32 =
                u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
            let index_size: usize = (backward_size as usize + 1) * 4;
            if let Some(index_start) = footer_start.checked_sub(index_size)
                && index_start >= stream_start + XZ_STREAM_HEADER
                && window.get(index_start) == Some(&0x00)
            {
                let index: &[u8] = &window[index_start..footer_start];
                let n: usize = index.len();
                let stored_index_crc: u32 =
                    u32::from_le_bytes([index[n - 4], index[n - 3], index[n - 2], index[n - 1]]);
                let footer_crc: u32 =
                    u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]);
                if crc32(&index[..n - 4]) == stored_index_crc && crc32(&footer[4..10]) == footer_crc
                {
                    return Some(footer_start + XZ_STREAM_FOOTER);
                }
            }
        }
        footer_start += XZ_BLOCK_ALIGN;
    }
    None
}

fn xz_extent(window: &[u8]) -> Option<usize> {
    if !window.starts_with(&XZ_MAGIC) {
        return None;
    }
    let mut total: usize = 0;
    loop {
        if !window.get(total..)?.starts_with(&XZ_MAGIC) {
            return Some(total);
        }
        total = xz_stream_end(window, total)?;
        let padded: usize = align_up(total, XZ_BLOCK_ALIGN);
        match window.get(padded..padded + XZ_MAGIC.len()) {
            Some(magic) if magic == XZ_MAGIC => total = padded,
            _ => return Some(total),
        }
    }
}

fn zstd_frame_header_len(window: &[u8], start: usize) -> Option<usize> {
    let descriptor: u8 = *window.get(start + 4)?;
    let dict_id_flag: u8 = descriptor & 0x03;
    let single_segment: bool = descriptor & 0x20 != 0;
    let fcs_flag: u8 = (descriptor >> 6) & 0x03;
    let mut pos: usize = start + 5;
    if !single_segment {
        pos = pos.checked_add(1)?;
    }
    let dict_id_size: usize = match dict_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => return None,
    };
    pos = pos.checked_add(dict_id_size)?;
    let fcs_size: usize = match fcs_flag {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        3 => 8,
        _ => return None,
    };
    pos = pos.checked_add(fcs_size)?;
    Some(pos - start)
}

fn zstd_frame_len(window: &[u8], start: usize) -> Option<usize> {
    let header_len: usize = zstd_frame_header_len(window, start)?;
    let descriptor: u8 = *window.get(start + 4)?;
    let content_checksum: bool = descriptor & 0x04 != 0;
    let mut pos: usize = start.checked_add(header_len)?;
    loop {
        let block_header: u32 = u32::from(*window.get(pos)?)
            | (u32::from(*window.get(pos + 1)?) << 8)
            | (u32::from(*window.get(pos + 2)?) << 16);
        let last_block: bool = block_header & 1 != 0;
        let block_type: u8 = ((block_header >> 1) & 0x03) as u8;
        let block_size: usize = (block_header >> 3) as usize;
        pos = pos.checked_add(3)?;
        let payload: usize = match block_type {
            ZSTD_BLOCK_RAW | ZSTD_BLOCK_COMPRESSED => block_size,
            ZSTD_BLOCK_RLE => 1,
            _ => return None,
        };
        pos = pos.checked_add(payload)?;
        if last_block {
            break;
        }
    }
    if content_checksum {
        pos = pos.checked_add(4)?;
    }
    if pos > window.len() {
        return None;
    }
    Some(pos - start)
}

fn zstd_one_frame(window: &[u8], pos: usize) -> Option<usize> {
    let magic: u32 = read_u32_le(window, pos)?;
    if (ZSTD_SKIPPABLE_LOW..=ZSTD_SKIPPABLE_HIGH).contains(&magic) {
        let frame_size: usize = read_u32_le(window, pos + 4)? as usize;
        let end: usize = pos.checked_add(8 + frame_size)?;
        (end <= window.len()).then_some(end)
    } else if magic == u32::from_le_bytes(ZSTD_MAGIC) {
        let frame_len: usize = zstd_frame_len(window, pos)?;
        pos.checked_add(frame_len)
    } else {
        None
    }
}

fn zstd_extent(window: &[u8]) -> Option<usize> {
    if !window.starts_with(&ZSTD_MAGIC) {
        return None;
    }
    let mut pos: usize = zstd_one_frame(window, 0)?;
    while read_u32_le(window, pos).is_some_and(|m: u32| {
        m == u32::from_le_bytes(ZSTD_MAGIC)
            || (ZSTD_SKIPPABLE_LOW..=ZSTD_SKIPPABLE_HIGH).contains(&m)
    }) {
        match zstd_one_frame(window, pos) {
            Some(end) => pos = end,
            None => break,
        }
    }
    Some(pos)
}

fn bzip2_extent(window: &[u8]) -> Option<usize> {
    if !window.starts_with(&BZIP2_MAGIC) {
        return None;
    }
    let level: u8 = *window.get(3)?;
    if !(b'1'..=b'9').contains(&level) {
        return None;
    }
    let eos_bit: usize = bit_scan_be(window, 32, BZIP2_EOS_MAGIC, BZIP2_MAGIC_BITS)?;
    let end_bit: usize = eos_bit + BZIP2_MAGIC_BITS as usize + BZIP2_CRC_BITS as usize;
    let end_byte: usize = end_bit.div_ceil(8);
    if end_byte > window.len() {
        return None;
    }
    Some(end_byte)
}

fn bit_scan_be(bytes: &[u8], start_bit: usize, pattern: u64, pattern_bits: u32) -> Option<usize> {
    let total_bits: usize = bytes.len() * 8;
    let width: usize = pattern_bits as usize;
    if width == 0 || total_bits < width {
        return None;
    }
    let mask: u64 = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let target: u64 = pattern & mask;
    let mut acc: u64 = 0;
    let mut filled: usize = 0;
    for bit_index in start_bit..total_bits {
        let byte: u8 = bytes[bit_index / 8];
        let bit: u64 = u64::from((byte >> (7 - (bit_index % 8))) & 1);
        acc = ((acc << 1) | bit) & mask;
        filled += 1;
        if filled >= width && acc == target {
            return Some(bit_index + 1 - width);
        }
    }
    None
}

fn tar_octal(field: &[u8]) -> Option<u64> {
    if field.first() == Some(&0x80) || field.first() == Some(&0xff) {
        let mut value: u64 = 0;
        for &byte in &field[field.len().saturating_sub(8)..] {
            value = (value << 8) | u64::from(byte);
        }
        return Some(value);
    }
    let trimmed: &[u8] = field
        .iter()
        .position(|&b: &u8| b != b' ' && b != 0)
        .map_or(&[][..], |i: usize| &field[i..]);
    let digits: &[u8] = trimmed
        .iter()
        .position(|&b: &u8| b == 0 || b == b' ')
        .map_or(trimmed, |i: usize| &trimmed[..i]);
    if digits.is_empty() {
        return Some(0);
    }
    let mut value: u64 = 0;
    for &byte in digits {
        if !(b'0'..=b'7').contains(&byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

fn tar_is_zero_block(window: &[u8], at: usize) -> bool {
    window
        .get(at..at + TAR_BLOCK)
        .is_some_and(|block: &[u8]| block.iter().all(|&b: &u8| b == 0))
}

fn tar_extent(window: &[u8]) -> Option<usize> {
    if window.len() < TAR_USTAR_OFFSET + 5 {
        return None;
    }
    let mut pos: usize = 0;
    let mut blocks: usize = 0;
    loop {
        if blocks > TAR_MAX_BLOCKS {
            return None;
        }
        if pos + TAR_BLOCK > window.len() {
            return None;
        }
        if tar_is_zero_block(window, pos) {
            let terminator_end: usize = pos + 2 * TAR_BLOCK;
            if terminator_end <= window.len() && tar_is_zero_block(window, pos + TAR_BLOCK) {
                return Some(terminator_end);
            }
            return None;
        }
        let size_field: &[u8] =
            window.get(pos + TAR_SIZE_OFFSET..pos + TAR_SIZE_OFFSET + TAR_SIZE_LEN)?;
        let size: usize = usize::try_from(tar_octal(size_field)?).ok()?;
        let data_blocks: usize = size.div_ceil(TAR_BLOCK);
        pos = pos
            .checked_add(TAR_BLOCK)?
            .checked_add(data_blocks.checked_mul(TAR_BLOCK)?)?;
        blocks += 1 + data_blocks;
    }
}

fn sevenz_extent(window: &[u8]) -> Option<usize> {
    if !window.starts_with(&SEVENZ_MAGIC) {
        return None;
    }
    let next_header_offset: u64 = read_u64_le(window, SEVENZ_NEXT_HEADER_OFFSET)?;
    let next_header_size: u64 = read_u64_le(window, SEVENZ_NEXT_HEADER_SIZE)?;
    let end: u64 = (SEVENZ_SIGNATURE_HEADER as u64)
        .checked_add(next_header_offset)?
        .checked_add(next_header_size)?;
    usize::try_from(end).ok()
}

fn cab_extent(window: &[u8]) -> Option<usize> {
    if !window.starts_with(&CAB_MAGIC) {
        return None;
    }
    let cb_cabinet: u32 = read_u32_le(window, CAB_CB_CABINET_OFFSET)?;
    Some(cb_cabinet as usize)
}

fn rar5_vint(window: &[u8], at: usize) -> Option<(u64, usize)> {
    let (value, consumed): (u64, usize) = read_uleb128_at(window, at).ok()?;
    Some((value, at.checked_add(consumed)?))
}

fn rar5_extent(window: &[u8]) -> Option<usize> {
    let mut pos: usize = RAR5_MAGIC.len();
    let mut blocks: usize = 0;
    loop {
        if blocks > RAR5_MAX_BLOCKS {
            return None;
        }
        let block_start: usize = pos;
        let _crc: u32 = read_u32_le(window, pos)?;
        let (header_size, after_size): (u64, usize) = rar5_vint(window, pos + 4)?;
        let header_body_start: usize = after_size;
        let header_end: usize = header_body_start.checked_add(header_size as usize)?;
        if header_end > window.len() {
            return None;
        }
        let (header_type, after_type): (u64, usize) = rar5_vint(window, header_body_start)?;
        let (header_flags, after_flags): (u64, usize) = rar5_vint(window, after_type)?;
        let mut field_pos: usize = after_flags;
        if header_flags & RAR5_HEADER_FLAG_EXTRA != 0 {
            let (_extra, next): (u64, usize) = rar5_vint(window, field_pos)?;
            field_pos = next;
        }
        let data_size: u64 = if header_flags & RAR5_HEADER_FLAG_DATA != 0 {
            let (value, next): (u64, usize) = rar5_vint(window, field_pos)?;
            field_pos = next;
            value
        } else {
            0
        };
        let _ = field_pos;
        let data_end: usize = header_end.checked_add(data_size as usize)?;
        if data_end > window.len() || data_end <= block_start {
            return None;
        }
        if header_type == RAR5_HEAD_ENDARC {
            return Some(data_end);
        }
        pos = data_end;
        blocks += 1;
    }
}

fn rar4_extent(window: &[u8]) -> Option<usize> {
    let mut pos: usize = RAR4_MAGIC.len();
    let mut blocks: usize = 0;
    loop {
        if blocks > RAR4_MAX_BLOCKS {
            return None;
        }
        let header: &[u8] = window.get(pos..pos + RAR4_BLOCK_HEADER)?;
        let head_flags: u16 = u16::from_le_bytes([header[3], header[4]]);
        let head_type: u8 = header[2];
        let head_size: usize = u16::from_le_bytes([header[5], header[6]]) as usize;
        if head_size < RAR4_BLOCK_HEADER {
            return None;
        }
        let mut add_size: u64 = 0;
        if head_flags & RAR4_FLAG_DATA != 0 {
            add_size = u64::from(read_u32_le(window, pos + 7)?);
            if head_flags & RAR4_FLAG_BIG_DATA != 0 {
                let high: u64 = u64::from(read_u32_le(window, pos + 11)?);
                add_size |= high << 32;
            }
        }
        let block_end: usize = pos.checked_add(head_size)?.checked_add(add_size as usize)?;
        if block_end > window.len() || block_end <= pos {
            return None;
        }
        if head_type == RAR4_TYPE_ENDARC {
            return Some(block_end);
        }
        pos = block_end;
        blocks += 1;
    }
}

fn rar_extent(window: &[u8]) -> Option<usize> {
    if window.starts_with(&RAR5_MAGIC) {
        rar5_extent(window)
    } else if window.starts_with(&RAR4_MAGIC) {
        rar4_extent(window)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;

    fn reference_rar5_vint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
        let tail: &[u8] = bytes.get(at..)?;
        let mut value: u64 = 0;
        for (index, byte) in tail.iter().copied().take(10).enumerate() {
            let shift: u32 = u32::try_from(index).ok()?.checked_mul(7)?;
            if shift == 63 && !matches!(byte, 0x00 | 0x01) {
                return None;
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some((value, at.checked_add(index + 1)?));
            }
        }
        None
    }

    #[test]
    fn rar5_vint_rejects_terminal_payload_overflow() {
        let encoded: [u8; 10] = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(rar5_vint(&encoded, 0), None);
        assert_eq!(rar5_vint(&[0xAA, 0xE5, 0x8E, 0x26], 1), Some((624_485, 4)));
    }

    #[test]
    fn rar5_vint_matches_an_independent_bounded_reference() {
        assert_eq!(rar5_vint(&[], 0), None);
        assert_eq!(rar5_vint(&[0x81, 0x00], 0), Some((1, 2)));
        let redundant_zero: [u8; 11] = [
            0xAA, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ];
        let redundant_actual: Option<(u64, usize)> = rar5_vint(&redundant_zero, 1);
        let redundant_expected: Option<(u64, usize)> = reference_rar5_vint(&redundant_zero, 1);
        assert_eq!(
            redundant_actual.map(|(value, _): (u64, usize)| value),
            Some(0)
        );
        assert_eq!(
            redundant_expected.map(|(value, _): (u64, usize)| value),
            Some(0)
        );
        assert_eq!(
            redundant_actual.map(|(_, next): (u64, usize)| next),
            Some(11)
        );
        assert_eq!(
            redundant_expected.map(|(_, next): (u64, usize)| next),
            Some(11)
        );
        let maximum: [u8; 11] = [
            0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ];
        let maximum_actual: Option<(u64, usize)> = rar5_vint(&maximum, 1);
        let maximum_expected: Option<(u64, usize)> = reference_rar5_vint(&maximum, 1);
        assert_eq!(
            maximum_actual.map(|(value, _): (u64, usize)| value),
            Some(u64::MAX)
        );
        assert_eq!(
            maximum_expected.map(|(value, _): (u64, usize)| value),
            Some(u64::MAX)
        );
        assert_eq!(maximum_actual.map(|(_, next): (u64, usize)| next), Some(11));
        assert_eq!(
            maximum_expected.map(|(_, next): (u64, usize)| next),
            Some(11)
        );
        for length in 1..=10usize {
            let truncated: Vec<u8> = vec![0x80; length];
            assert_eq!(rar5_vint(&truncated, 0), None);
        }

        let mut state: u64 = 0xd134_2543_de82_ef95;
        for length in 0..=32usize {
            for offset in 0..=length + 1 {
                let bytes: Vec<u8> = (0..length)
                    .map(|_: usize| {
                        state = state
                            .wrapping_mul(2_862_933_555_777_941_757)
                            .wrapping_add(3_037_000_493);
                        (state >> 56) as u8
                    })
                    .collect();
                let actual: Option<(u64, usize)> = rar5_vint(&bytes, offset);
                let expected: Option<(u64, usize)> = reference_rar5_vint(&bytes, offset);
                assert_eq!(
                    actual.map(|(value, _): (u64, usize)| value),
                    expected.map(|(value, _): (u64, usize)| value)
                );
                assert_eq!(
                    actual.map(|(_, next): (u64, usize)| next),
                    expected.map(|(_, next): (u64, usize)| next)
                );
            }
        }
    }

    const PADDING: [u8; 257] = [0x5A; 257];

    fn sample() -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for i in 0..256u32 {
            out.extend_from_slice(format!("overlay-extent unit sample row {i:03}\n").as_bytes());
        }
        out
    }

    fn assert_exact(archive: &[u8], kind: ArchiveKind) {
        let real_len: usize = archive.len();
        let direct: usize = archive_true_extent(archive, kind)
            .unwrap_or_else(|| panic!("{kind:?}: no extent on the bare archive"));
        assert_eq!(
            direct, real_len,
            "{kind:?}: bare-archive extent must equal real length"
        );

        let mut padded: Vec<u8> = archive.to_vec();
        padded.extend_from_slice(&PADDING);
        let with_pad: usize = archive_true_extent(&padded, kind)
            .unwrap_or_else(|| panic!("{kind:?}: no extent with trailing padding"));
        assert_eq!(
            with_pad, real_len,
            "{kind:?}: extent must ignore trailing padding and equal real archive length"
        );
    }

    fn gz(payload: &[u8]) -> Vec<u8> {
        let mut e: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(payload).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_single_member_exact() {
        assert_exact(&gz(&sample()), ArchiveKind::Gzip);
    }

    #[test]
    fn gzip_multi_member_exact() {
        let payload: Vec<u8> = sample();
        let mut archive: Vec<u8> = gz(&payload[..payload.len() / 3]);
        archive.extend_from_slice(&gz(&payload[payload.len() / 3..]));
        assert_exact(&archive, ArchiveKind::Gzip);
    }

    #[test]
    fn gzip_with_name_and_comment_flags_exact() {
        let mut header: Vec<u8> = vec![0x1f, 0x8b, 0x08, GZIP_FLAG_FNAME | GZIP_FLAG_FCOMMENT];
        header.extend_from_slice(&[0, 0, 0, 0, 0, 0xff]);
        header.extend_from_slice(b"name.txt\0");
        header.extend_from_slice(b"a comment\0");
        let body: Vec<u8> = sample();
        let mut raw: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(&body).unwrap();
        let deflate: Vec<u8> = raw.finish().unwrap();
        let mut archive: Vec<u8> = header;
        archive.extend_from_slice(&deflate);
        archive.extend_from_slice(&crc32(&body).to_le_bytes());
        archive.extend_from_slice(&((body.len() as u32).to_le_bytes()));
        assert_exact(&archive, ArchiveKind::Gzip);
    }

    #[test]
    fn xz_exact() {
        use std::io::Read as _;
        let mut archive: Vec<u8> = Vec::new();
        liblzma::read::XzEncoder::new(sample().as_slice(), 6)
            .read_to_end(&mut archive)
            .unwrap();
        assert_exact(&archive, ArchiveKind::Xz);
    }

    #[test]
    fn xz_multi_stream_exact() {
        use std::io::Read as _;
        let make = |p: &[u8]| -> Vec<u8> {
            let mut v: Vec<u8> = Vec::new();
            liblzma::read::XzEncoder::new(p, 6)
                .read_to_end(&mut v)
                .unwrap();
            v
        };
        let payload: Vec<u8> = sample();
        let mut archive: Vec<u8> = make(&payload[..payload.len() / 2]);
        archive.extend_from_slice(&make(&payload[payload.len() / 2..]));
        assert_exact(&archive, ArchiveKind::Xz);
    }

    #[test]
    fn zstd_exact() {
        let archive: Vec<u8> = zstd::stream::encode_all(Cursor::new(sample()), 3).unwrap();
        assert_exact(&archive, ArchiveKind::Zstd);
    }

    #[test]
    fn zstd_with_trailing_skippable_frame_exact() {
        let mut archive: Vec<u8> = zstd::stream::encode_all(Cursor::new(sample()), 3).unwrap();
        archive.extend_from_slice(&ZSTD_SKIPPABLE_HIGH.to_le_bytes());
        let skip_payload: &[u8] = b"disrobe-skippable-seek-table";
        archive.extend_from_slice(&(skip_payload.len() as u32).to_le_bytes());
        archive.extend_from_slice(skip_payload);
        assert_exact(&archive, ArchiveKind::Zstd);
    }

    #[test]
    fn tar_exact() {
        let payload: Vec<u8> = sample();
        let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
        let mut header: tar::Header = tar::Header::new_ustar();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "sample.txt", Cursor::new(&payload))
            .unwrap();
        let archive: Vec<u8> = builder.into_inner().unwrap();
        assert_exact(&archive, ArchiveKind::Tar);
    }

    #[test]
    fn sevenz_exact() {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut w: sevenz_rust2::SevenZWriter<Cursor<Vec<u8>>> =
            sevenz_rust2::SevenZWriter::new(cursor).unwrap();
        let entry: sevenz_rust2::SevenZArchiveEntry =
            sevenz_rust2::SevenZArchiveEntry::new_file("s.txt");
        w.push_archive_entry(entry, Some(Cursor::new(sample())))
            .unwrap();
        let archive: Vec<u8> = w.finish().unwrap().into_inner();
        assert_exact(&archive, ArchiveKind::SevenZ);
    }

    #[test]
    fn cab_exact() {
        let payload: Vec<u8> = sample();
        let mut builder: cab::CabinetBuilder = cab::CabinetBuilder::new();
        {
            let folder: &mut cab::FolderBuilder = builder.add_folder(cab::CompressionType::None);
            folder.add_file("c.txt");
        }
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut writer: cab::CabinetWriter<Cursor<Vec<u8>>> = builder.build(cursor).unwrap();
        if let Some(mut fw) = writer.next_file().unwrap() {
            fw.write_all(&payload).unwrap();
        }
        let archive: Vec<u8> = writer.finish().unwrap().into_inner();
        assert_exact(&archive, ArchiveKind::Cab);
    }

    fn rar5_vint_write(buf: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn rar5_block(header_type: u64, header_flags: u64, data: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        rar5_vint_write(&mut body, header_type);
        rar5_vint_write(&mut body, header_flags);
        if header_flags & RAR5_HEADER_FLAG_DATA != 0 {
            rar5_vint_write(&mut body, data.len() as u64);
        }
        let mut block: Vec<u8> = Vec::new();
        block.extend_from_slice(&crc32(&body).to_le_bytes());
        rar5_vint_write(&mut block, body.len() as u64);
        block.extend_from_slice(&body);
        block.extend_from_slice(data);
        block
    }

    fn rar5_archive(file_body: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = RAR5_MAGIC.to_vec();
        out.extend_from_slice(&rar5_block(1, 0, &[]));
        out.extend_from_slice(&rar5_block(2, RAR5_HEADER_FLAG_DATA, file_body));
        out.extend_from_slice(&rar5_block(RAR5_HEAD_ENDARC, 0, &[]));
        out
    }

    #[test]
    fn rar5_exact() {
        let archive: Vec<u8> = rar5_archive(b"stored rar5 payload bytes for extent test");
        assert_exact(&archive, ArchiveKind::Rar);
    }

    fn rar4_block(head_type: u8, head_flags: u16, data: &[u8]) -> Vec<u8> {
        let has_data: bool = head_flags & RAR4_FLAG_DATA != 0;
        let head_size: u16 = if has_data {
            (RAR4_BLOCK_HEADER + 4) as u16
        } else {
            RAR4_BLOCK_HEADER as u16
        };
        let mut block: Vec<u8> = Vec::new();
        block.extend_from_slice(&[0x00, 0x00]);
        block.push(head_type);
        block.extend_from_slice(&head_flags.to_le_bytes());
        block.extend_from_slice(&head_size.to_le_bytes());
        if has_data {
            block.extend_from_slice(&(data.len() as u32).to_le_bytes());
            block.extend_from_slice(data);
        }
        block
    }

    fn rar4_archive(file_body: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = RAR4_MAGIC.to_vec();
        out.extend_from_slice(&rar4_block(0x73, 0x0000, &[]));
        out.extend_from_slice(&rar4_block(0x74, RAR4_FLAG_DATA, file_body));
        out.extend_from_slice(&rar4_block(RAR4_TYPE_ENDARC, 0x0000, &[]));
        out
    }

    #[test]
    fn rar4_exact() {
        let archive: Vec<u8> = rar4_archive(b"stored rar4 payload bytes for extent test");
        assert_exact(&archive, ArchiveKind::Rar);
    }

    #[test]
    fn zip_path_defers_to_caller() {
        assert_eq!(
            archive_true_extent(b"PK\x03\x04anything", ArchiveKind::Zip),
            None
        );
    }

    #[test]
    fn truncated_inputs_do_not_panic() {
        let payload: Vec<u8> = sample();
        let archives: [(Vec<u8>, ArchiveKind); 5] = [
            (gz(&payload), ArchiveKind::Gzip),
            (
                zstd::stream::encode_all(Cursor::new(&payload), 3).unwrap(),
                ArchiveKind::Zstd,
            ),
            (rar5_archive(b"x"), ArchiveKind::Rar),
            (rar4_archive(b"x"), ArchiveKind::Rar),
            (
                {
                    let c: Cursor<Vec<u8>> = Cursor::new(Vec::new());
                    let mut w: sevenz_rust2::SevenZWriter<Cursor<Vec<u8>>> =
                        sevenz_rust2::SevenZWriter::new(c).unwrap();
                    let e: sevenz_rust2::SevenZArchiveEntry =
                        sevenz_rust2::SevenZArchiveEntry::new_file("t");
                    w.push_archive_entry(e, Some(Cursor::new(payload.clone())))
                        .unwrap();
                    w.finish().unwrap().into_inner()
                },
                ArchiveKind::SevenZ,
            ),
        ];
        for (archive, kind) in &archives {
            for cut in 0..archive.len() {
                let _ = archive_true_extent(&archive[..cut], *kind);
            }
        }
    }

    #[test]
    fn garbage_after_magic_falls_back_to_none() {
        let mut bogus: Vec<u8> = SEVENZ_MAGIC.to_vec();
        bogus.extend_from_slice(&[0xff; 16]);
        assert_eq!(archive_true_extent(&bogus, ArchiveKind::SevenZ), None);
    }
}
