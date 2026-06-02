use core::fmt::Write;
use std::io::Read;

use flate2::read::ZlibDecoder;

use crate::error::{Error, Result};

const BASE85_ALPHABET: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

const fn build_base85_lookup() -> [u8; 256] {
    let mut table: [u8; 256] = [u8::MAX; 256];
    let mut i: u8 = 0;
    while (i as usize) < BASE85_ALPHABET.len() {
        table[BASE85_ALPHABET[i as usize] as usize] = i;
        i += 1;
    }
    table
}

const BASE85_LOOKUP: [u8; 256] = build_base85_lookup();

#[inline]
pub fn base85_decode_rfc1924(input: &[u8]) -> Result<Vec<u8>> {
    let mut trimmed: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input {
        if !b.is_ascii_whitespace() {
            trimmed.push(b);
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(trimmed.len() * 4 / 5 + 4);
    for chunk in trimmed.chunks(5) {
        if chunk.len() < 5 {
            let mut padded: [u8; 5] = [b'~'; 5];
            padded[..chunk.len()].copy_from_slice(chunk);
            let acc: u32 = decode_chunk(&padded)?;
            let bytes_to_take: usize = chunk.len() - 1;
            let chunk_bytes: [u8; 4] = acc.to_be_bytes();
            out.extend_from_slice(&chunk_bytes[..bytes_to_take]);
            continue;
        }
        let acc: u32 = decode_chunk(chunk)?;
        out.extend_from_slice(&acc.to_be_bytes());
    }
    Ok(out)
}

#[inline]
fn decode_chunk(chunk: &[u8]) -> Result<u32> {
    let mut acc: u64 = 0;
    for &c in chunk {
        let v: u8 = BASE85_LOOKUP[c as usize];
        if v == u8::MAX {
            return Err(Error::Base85 {
                field: "chunk".to_owned(),
                message: format!("invalid base85 char 0x{c:02x}"),
            });
        }
        acc = acc * 85 + u64::from(v);
    }
    if acc > u64::from(u32::MAX) {
        return Err(Error::Base85 {
            field: "chunk".to_owned(),
            message: "base85 chunk overflows u32".to_owned(),
        });
    }
    u32::try_from(acc).map_err(|_| Error::Base85 {
        field: "chunk".to_owned(),
        message: "base85 chunk overflows u32".to_owned(),
    })
}

#[inline]
pub fn ascii85_decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 4 / 5 + 4);
    let mut group: [u32; 5] = [0u32; 5];
    let mut count: usize = 0;
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'z' && count == 0 {
            out.extend_from_slice(&[0u8; 4]);
            continue;
        }
        if !(0x21..=0x75).contains(&b) {
            return Err(Error::Base85 {
                field: "ascii85".to_owned(),
                message: format!("invalid ascii85 char 0x{b:02x}"),
            });
        }
        group[count] = u32::from(b - 0x21);
        count += 1;
        if count == 5 {
            let acc: u32 = pack_ascii85_group(&group, 5)?;
            out.extend_from_slice(&acc.to_be_bytes());
            count = 0;
        }
    }
    if count == 1 {
        return Err(Error::Base85 {
            field: "ascii85".to_owned(),
            message: "dangling single ascii85 char".to_owned(),
        });
    }
    if count > 0 {
        for slot in group.iter_mut().skip(count) {
            *slot = 84;
        }
        let acc: u32 = pack_ascii85_group(&group, count)?;
        let acc_bytes: [u8; 4] = acc.to_be_bytes();
        out.extend_from_slice(&acc_bytes[..count - 1]);
    }
    Ok(out)
}

#[inline]
fn pack_ascii85_group(group: &[u32; 5], used: usize) -> Result<u32> {
    let mut acc: u64 = 0;
    for &digit in group.iter().take(5) {
        acc = acc * 85 + u64::from(digit);
    }
    if used == 5 && acc > u64::from(u32::MAX) {
        return Err(Error::Base85 {
            field: "ascii85".to_owned(),
            message: "ascii85 group overflows u32".to_owned(),
        });
    }
    Ok((acc & u64::from(u32::MAX)) as u32)
}

#[inline]
fn zlib_inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(data);
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 2);
    decoder.read_to_end(&mut out).map_err(|e| Error::Base85 {
        field: "zlib".to_owned(),
        message: format!("inflate failed: {e}"),
    })?;
    Ok(out)
}

#[inline]
pub fn decode_armored_line(input: &[u8]) -> Result<Vec<u8>> {
    if let Ok(raw) = base85_decode_rfc1924(input) {
        return Ok(raw);
    }
    let stage: Vec<u8> = ascii85_decode(input)?;
    zlib_inflate(&stage)
}

#[inline]
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _: core::fmt::Result = write!(s, "{b:02x}");
    }
    s
}

#[inline]
#[must_use]
pub fn basename_of(path: &str) -> &str {
    path.rfind(['/', '\\']).map_or(path, |idx| &path[idx + 1..])
}

#[inline]
#[must_use]
pub fn strip_extension(name: &str) -> &str {
    name.rfind('.').map_or(name, |idx| &name[..idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_roundtrip_zero() {
        assert_eq!(hex_encode(&[0u8; 4]), "00000000");
    }

    #[test]
    fn hex_encode_full_byte() {
        assert_eq!(hex_encode(&[0x0a, 0xff]), "0aff");
    }

    #[test]
    fn basename_strips_path() {
        assert_eq!(basename_of("a/b/c.pye"), "c.pye");
        assert_eq!(basename_of("c:\\dir\\foo.pye"), "foo.pye");
        assert_eq!(basename_of("plain"), "plain");
    }

    #[test]
    fn strip_extension_works() {
        assert_eq!(strip_extension("foo.pye"), "foo");
        assert_eq!(strip_extension("foo"), "foo");
        assert_eq!(strip_extension("a.b.c"), "a.b");
    }

    #[test]
    fn base85_rejects_garbage() {
        let r: Result<Vec<u8>> = base85_decode_rfc1924(b"\x01\x02\x03\x04\x05");
        assert!(r.is_err());
    }

    #[test]
    fn ascii85_decodes_known_iv_line() {
        let Ok(iv): Result<Vec<u8>> = decode_armored_line(b"GhOt7h7Jm.?sE?I;!%a(cCM6@0X(^n") else {
            unreachable!("decode iv failed")
        };
        assert_eq!(hex_encode(&iv), "310dbdb90f30b66ba95503502209b91d");
    }

    #[test]
    fn ascii85_z_shortcut_expands_to_four_zero_bytes() {
        let Ok(out): Result<Vec<u8>> = ascii85_decode(b"z") else {
            unreachable!("decode z failed")
        };
        assert_eq!(out, vec![0u8; 4]);
    }
}
