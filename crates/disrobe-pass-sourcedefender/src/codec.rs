use std::io::Read;

use flate2::read::ZlibDecoder;

use crate::debug::dbg_kv;
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
    let mut out: Vec<u8> = Vec::with_capacity(base85_output_capacity(input.len()));
    let mut group: [u8; 5] = [0u8; 5];
    let mut count: usize = 0;
    for &b in input {
        if !b.is_ascii_whitespace() {
            group[count] = b;
            count += 1;
            if count == 5 {
                let acc: u32 = decode_chunk(&group)?;
                out.extend_from_slice(&acc.to_be_bytes());
                count = 0;
            }
        }
    }
    if count == 1 {
        return Err(Error::Base85 {
            field: "chunk".to_owned(),
            message: "dangling single base85 char".to_owned(),
        });
    }
    if count > 0 {
        group[count..].fill(b'~');
        let acc: u32 = decode_chunk(&group)?;
        let bytes_to_take: usize = count - 1;
        let chunk_bytes: [u8; 4] = acc.to_be_bytes();
        out.extend_from_slice(&chunk_bytes[..bytes_to_take]);
    }
    Ok(out)
}

const fn base85_output_capacity(input_len: usize) -> usize {
    let groups: usize = input_len / 5;
    groups * 4 + 4
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
    let mut out: Vec<u8> = Vec::with_capacity(base85_output_capacity(input.len()));
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

const MAX_SOURCEDEFENDER_INFLATE: usize = 256 * 1024 * 1024;

#[inline]
fn zlib_inflate(data: &[u8]) -> Result<Vec<u8>> {
    let decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(data);
    let cap: usize = data.len().saturating_mul(2).min(MAX_SOURCEDEFENDER_INFLATE);
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    decoder
        .take(MAX_SOURCEDEFENDER_INFLATE as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::Base85 {
            field: "zlib".to_owned(),
            message: format!("inflate failed: {e}"),
        })?;
    if out.len() > MAX_SOURCEDEFENDER_INFLATE {
        dbg_kv("zlib-inflate-cap", || {
            format!("output exceeded {MAX_SOURCEDEFENDER_INFLATE}-byte cap, refusing")
        });
        return Err(Error::Base85 {
            field: "zlib".to_owned(),
            message: "inflated output exceeds cap".to_owned(),
        });
    }
    dbg_kv("zlib-inflate", || {
        format!("{} compressed -> {} inflated bytes", data.len(), out.len())
    });
    Ok(out)
}

#[inline]
pub fn decode_armored_line(input: &[u8]) -> Result<Vec<u8>> {
    if let Ok(raw) = base85_decode_rfc1924(input) {
        dbg_kv("armor-decode", || {
            format!("rfc1924-base85 -> {} bytes", raw.len())
        });
        return Ok(raw);
    }
    let stage: Vec<u8> = ascii85_decode(input)?;
    dbg_kv("armor-decode", || {
        format!("ascii85 -> {} bytes, inflating", stage.len())
    });
    zlib_inflate(&stage)
}

#[inline]
pub fn hex_decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        let v: u8 = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            other => {
                return Err(Error::Base85 {
                    field: "hex".to_owned(),
                    message: format!("invalid hex char 0x{other:02x}"),
                });
            }
        };
        nibbles.push(v);
    }
    if !nibbles.len().is_multiple_of(2) {
        return Err(Error::Base85 {
            field: "hex".to_owned(),
            message: "odd number of hex digits".to_owned(),
        });
    }
    let mut out: Vec<u8> = Vec::with_capacity(nibbles.len() / 2);
    for pair in nibbles.chunks_exact(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    Ok(out)
}

#[inline]
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut s: String = String::with_capacity(hex_output_capacity(bytes.len()));
    for byte in bytes.iter().copied() {
        s.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        s.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    s
}

const fn hex_output_capacity(len: usize) -> usize {
    len.saturating_mul(2usize)
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
    fn hex_output_capacity_saturates() {
        assert_eq!(hex_output_capacity(usize::MAX), usize::MAX);
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
    fn base85_rejects_lone_trailing_symbol() {
        let r: Result<Vec<u8>> = base85_decode_rfc1924(b"X");
        assert!(r.is_err());
    }

    #[test]
    fn base85_streams_past_whitespace() {
        let Ok(out): Result<Vec<u8>> = base85_decode_rfc1924(b"00 000\r\n") else {
            unreachable!("decode failed")
        };
        assert_eq!(out, vec![0u8; 4]);
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
