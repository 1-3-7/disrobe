use core::fmt::Write;

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
}
