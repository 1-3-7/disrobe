use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct OnefileEntry {
    pub filename: String,
    pub size: u64,
    pub data_offset: usize,
    pub data: Vec<u8>,
    pub permissions: u8,
    pub crc32: Option<u32>,
}

#[derive(Debug)]
pub struct OnefilePayload {
    pub compressed: bool,
    pub entries: Vec<OnefileEntry>,
    pub payload_size: usize,
}

pub fn extract_onefile(image: &[u8], payload_offset: usize) -> Result<OnefilePayload> {
    if payload_offset + 3 > image.len() {
        return Err(Error::EntryTruncated(payload_offset));
    }
    let magic: [u8; 3] = [
        image[payload_offset],
        image[payload_offset + 1],
        image[payload_offset + 2],
    ];
    let compressed: bool = match &magic {
        b"KAX" => false,
        b"KAY" => true,
        _ => return Err(Error::BadOnefileMagic(magic)),
    };

    let payload_body_start: usize = payload_offset + 3;
    let raw: &[u8] = &image[payload_body_start..];

    let decompressed: Vec<u8> = if compressed {
        decompress_zstd(raw)?
    } else {
        raw.to_vec()
    };

    let entries: Vec<OnefileEntry> = walk_entries(&decompressed)?;

    Ok(OnefilePayload {
        compressed,
        entries,
        payload_size: decompressed.len(),
    })
}

fn decompress_zstd(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder: zstd::Decoder<'_, std::io::BufReader<&[u8]>> =
        zstd::Decoder::new(input).map_err(|e| Error::Zstd(format!("{e}")))?;
    let mut out: Vec<u8> = Vec::new();
    std::io::copy(&mut decoder, &mut out).map_err(|e| Error::Zstd(format!("{e}")))?;
    Ok(out)
}

fn walk_entries(payload: &[u8]) -> Result<Vec<OnefileEntry>> {
    let mut entries: Vec<OnefileEntry> = Vec::new();
    let mut cursor: usize = 0usize;
    while cursor < payload.len() {
        let Some((filename, name_end)): Option<(String, usize)> =
            read_utf16le_until_nul(payload, cursor)
                .or_else(|| read_utf8_until_nul(payload, cursor))
        else {
            return Err(Error::EntryTruncated(cursor));
        };
        if filename.is_empty() {
            break;
        }
        cursor = name_end;
        if cursor + 8 > payload.len() {
            return Err(Error::EntryTruncated(cursor));
        }
        let size: u64 = u64::from_le_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
            payload[cursor + 4],
            payload[cursor + 5],
            payload[cursor + 6],
            payload[cursor + 7],
        ]);
        cursor += 8;
        let Some(&perm_byte): Option<&u8> = payload.get(cursor) else {
            return Err(Error::EntryTruncated(cursor));
        };
        cursor += 1;
        let data_offset: usize = cursor;
        let size_usize: usize = usize::try_from(size).map_err(|_| Error::EntryTruncated(cursor))?;
        let end: usize = cursor
            .checked_add(size_usize)
            .ok_or(Error::EntryTruncated(cursor))?;
        if end > payload.len() {
            return Err(Error::EntryTruncated(cursor));
        }
        let data: Vec<u8> = payload[cursor..end].to_vec();
        cursor = end;
        entries.push(OnefileEntry {
            filename,
            size,
            data_offset,
            data,
            permissions: perm_byte,
            crc32: None,
        });
    }
    Ok(entries)
}

fn read_utf16le_until_nul(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let mut cursor: usize = start;
    let mut code_units: Vec<u16> = Vec::new();
    while cursor + 2 <= payload.len() {
        let cu: u16 = u16::from_le_bytes([payload[cursor], payload[cursor + 1]]);
        cursor += 2;
        if cu == 0 {
            break;
        }
        let high: u32 = u32::from(cu) >> 8;
        let low: u32 = u32::from(cu) & 0xFF;
        if high != 0 || !(0x20..=0x7E).contains(&low) {
            return None;
        }
        code_units.push(cu);
    }
    let s: String = String::from_utf16(&code_units).ok()?;
    Some((s, cursor))
}

fn read_utf8_until_nul(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let nul: usize = payload[start..].iter().position(|&b| b == 0)?;
    let s: &str = core::str::from_utf8(&payload[start..start + nul]).ok()?;
    Some((s.to_owned(), start + nul + 1))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_utf16le(name: &str) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(name.len() * 2 + 2);
        for ch in name.encode_utf16() {
            out.extend_from_slice(&ch.to_le_bytes());
        }
        out.extend_from_slice(&[0u8, 0u8]);
        out
    }

    fn synth_entry(name: &str, perm: u8, data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = synth_utf16le(name);
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.push(perm);
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn missing_magic_errors() {
        let bytes: Vec<u8> = vec![0u8; 1024];
        let Err(err): Result<OnefilePayload> = extract_onefile(&bytes, 0) else {
            panic!("zero bytes must trigger bad-magic");
        };
        assert!(matches!(err, Error::BadOnefileMagic(_)));
    }

    #[test]
    fn empty_payload_after_magic_is_empty_archive() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        bytes.push(0);
        bytes.push(0);
        let p: OnefilePayload = extract_onefile(&bytes, 0).expect("synthetic empty KAX");
        assert!(!p.compressed);
        assert!(p.entries.is_empty());
    }

    #[test]
    fn single_kax_entry_round_trips() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        bytes.extend_from_slice(&synth_entry("hello.txt", 0x01, b"hi"));
        bytes.extend_from_slice(&[0u8, 0u8]);
        let p: OnefilePayload = extract_onefile(&bytes, 0).expect("synthetic KAX one entry");
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.entries[0].filename, "hello.txt");
        assert_eq!(p.entries[0].data, b"hi");
        assert_eq!(p.entries[0].permissions, 0x01);
        assert_eq!(p.entries[0].size, 2);
    }

    #[test]
    fn multi_entry_payload_preserves_order() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        bytes.extend_from_slice(&synth_entry("a.bin", 0x01, b"AAA"));
        bytes.extend_from_slice(&synth_entry("b.bin", 0x00, b"BBBB"));
        bytes.extend_from_slice(&[0u8, 0u8]);
        let p: OnefilePayload = extract_onefile(&bytes, 0).expect("two-entry KAX");
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[0].filename, "a.bin");
        assert_eq!(p.entries[1].filename, "b.bin");
        assert_eq!(p.entries[0].data, b"AAA");
        assert_eq!(p.entries[1].data, b"BBBB");
    }

    #[test]
    fn truncated_size_field_errors() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        bytes.extend_from_slice(&synth_utf16le("oops"));
        bytes.extend_from_slice(&[0u8, 0u8, 0u8]);
        let Err(err): Result<OnefilePayload> = extract_onefile(&bytes, 0) else {
            panic!("truncated payload must error");
        };
        assert!(matches!(err, Error::EntryTruncated(_)));
    }

    #[test]
    fn declared_size_overruns_payload_errors() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        bytes.extend_from_slice(&synth_utf16le("big.bin"));
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.push(0);
        let Err(err): Result<OnefilePayload> = extract_onefile(&bytes, 0) else {
            panic!("overlong declared size must error");
        };
        assert!(matches!(err, Error::EntryTruncated(_)));
    }
}
