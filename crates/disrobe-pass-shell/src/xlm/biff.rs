use super::limits::{MAX_RECORD_BODY, MAX_RECORDS};

pub const REC_CONTINUE_BIFF8: u16 = 0x003C;
pub const BIFF8_MAX_RECORD_DATA: usize = 8224;

#[derive(Debug, Clone)]
pub struct BiffRecord {
    pub rt: u32,
    pub pos: usize,
    pub data: Vec<u8>,
}

pub fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    let end: usize = at.checked_add(2)?;
    let slice: &[u8] = buf.get(at..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end: usize = at.checked_add(4)?;
    let slice: &[u8] = buf.get(at..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn iter_biff8(stream: &[u8]) -> Vec<BiffRecord> {
    let mut out: Vec<BiffRecord> = Vec::new();
    let mut offset: usize = 0;
    while out.len() < MAX_RECORDS {
        let Some(rt): Option<u16> = read_u16(stream, offset) else {
            break;
        };
        let Some(cb): Option<u16> = read_u16(stream, offset + 2) else {
            break;
        };
        let body_start: usize = offset + 4;
        let Some(body_end): Option<usize> = body_start.checked_add(cb as usize) else {
            break;
        };
        let Some(body): Option<&[u8]> = stream.get(body_start..body_end) else {
            break;
        };
        if rt == REC_CONTINUE_BIFF8
            && let Some(prev) = out.last_mut()
            && prev.data.len() < MAX_RECORD_BODY
        {
            let room: usize = MAX_RECORD_BODY - prev.data.len();
            let take: usize = body.len().min(room);
            prev.data.extend_from_slice(&body[..take]);
        } else {
            out.push(BiffRecord {
                rt: u32::from(rt),
                pos: offset,
                data: body.to_vec(),
            });
        }
        offset = body_end;
    }
    out
}

pub fn read_short_xlunicode(buf: &[u8], at: usize) -> Option<(String, usize)> {
    let cch: usize = *buf.get(at)? as usize;
    let grbit: u8 = *buf.get(at + 1)?;
    decode_chars(buf, at + 2, cch, grbit & 0x01 != 0).map(|(s, n): (String, usize)| (s, 2 + n))
}

pub fn read_xlunicode(buf: &[u8], at: usize) -> Option<(String, usize)> {
    let cch: usize = read_u16(buf, at)? as usize;
    let grbit: u8 = *buf.get(at + 2)?;
    decode_chars(buf, at + 3, cch, grbit & 0x01 != 0).map(|(s, n): (String, usize)| (s, 3 + n))
}

fn decode_chars(buf: &[u8], at: usize, cch: usize, high_byte: bool) -> Option<(String, usize)> {
    let capped: usize = cch.min(super::limits::MAX_STRING_CHARS);
    if high_byte {
        let byte_len: usize = capped.checked_mul(2)?;
        let end: usize = at.checked_add(byte_len)?;
        let slice: &[u8] = buf.get(at..end)?;
        let units: Vec<u16> = slice
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some((String::from_utf16_lossy(&units), byte_len))
    } else {
        let end: usize = at.checked_add(capped)?;
        let slice: &[u8] = buf.get(at..end)?;
        let text: String = slice.iter().map(|b: &u8| char::from(*b)).collect();
        Some((text, capped))
    }
}

pub fn read_varint_u32(buf: &[u8], at: usize) -> Option<(u32, usize)> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;
    while consumed < 4 {
        let byte: u8 = *buf.get(at.checked_add(consumed)?)?;
        value |= u32::from(byte & 0x7F) << shift;
        consumed += 1;
        if byte & 0x80 == 0 {
            return Some((value, consumed));
        }
        shift += 7;
    }
    None
}

pub fn iter_biff12(stream: &[u8]) -> Vec<BiffRecord> {
    let mut out: Vec<BiffRecord> = Vec::new();
    let mut offset: usize = 0;
    while out.len() < MAX_RECORDS {
        let Some((rt, id_len)): Option<(u32, usize)> = read_varint_u32(stream, offset) else {
            break;
        };
        let size_at: usize = offset + id_len;
        let Some((cb, size_len)): Option<(u32, usize)> = read_varint_u32(stream, size_at) else {
            break;
        };
        let body_start: usize = size_at + size_len;
        let Some(body_end): Option<usize> = body_start.checked_add(cb as usize) else {
            break;
        };
        let Some(body): Option<&[u8]> = stream.get(body_start..body_end) else {
            break;
        };
        let clamped: usize = body.len().min(MAX_RECORD_BODY);
        out.push(BiffRecord {
            rt,
            pos: offset,
            data: body[..clamped].to_vec(),
        });
        offset = body_end;
    }
    out
}
