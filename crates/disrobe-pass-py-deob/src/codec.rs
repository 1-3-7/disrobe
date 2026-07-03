use std::io::{Read, Write};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD as B64_URLSAFE};
use flate2::Compression;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::ZlibEncoder;
use liblzma::read::XzDecoder;
use liblzma::stream::Stream;
use liblzma::write::XzEncoder;

use crate::error::{Error, Result};

pub(crate) const DECOMPRESS_CEILING: u64 = 512 * 1024 * 1024;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

fn push_lower_hex_byte(out: &mut String, byte: u8) {
    out.push(LOWER_HEX[(byte >> 4) as usize] as char);
    out.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
}

pub(crate) fn bounded_read_to_end<R: Read>(reader: R) -> std::io::Result<Option<Vec<u8>>> {
    bounded_read_to_end_with(reader, DECOMPRESS_CEILING)
}

fn bounded_read_to_end_with<R: Read>(reader: R, ceiling: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut out: Vec<u8> = Vec::new();
    let read: u64 = reader
        .take(ceiling.saturating_add(1))
        .read_to_end(&mut out)
        .map(|n: usize| n as u64)?;
    if read > ceiling {
        return Ok(None);
    }
    Ok(Some(out))
}

#[inline]
pub(crate) fn zlib_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
    match encoder.write_all(input) {
        Ok(()) => {}
        Err(error) => unreachable!("vec-backed zlib write failed: {error}"),
    }
    match encoder.finish() {
        Ok(output) => output,
        Err(error) => unreachable!("vec-backed zlib finish failed: {error}"),
    }
}

#[inline]
pub(crate) fn zlib_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(input);
    bounded_read_to_end(decoder)
        .map_err(|e: std::io::Error| Error::Zlib(format!("{e}")))?
        .ok_or(Error::DecompressionTooLarge {
            limit: DECOMPRESS_CEILING,
        })
}

#[inline]
pub(crate) fn lzma_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder: XzEncoder<Vec<u8>> = XzEncoder::new(Vec::new(), 6);
    match encoder.write_all(input) {
        Ok(()) => {}
        Err(error) => unreachable!("vec-backed lzma write failed: {error}"),
    }
    match encoder.finish() {
        Ok(output) => output,
        Err(error) => unreachable!("vec-backed lzma finish failed: {error}"),
    }
}

#[inline]
pub(crate) fn lzma_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let decoder: XzDecoder<&[u8]> = XzDecoder::new(input);
    bounded_read_to_end(decoder)
        .map_err(|e: std::io::Error| Error::Lzma(format!("{e}")))?
        .ok_or(Error::DecompressionTooLarge {
            limit: DECOMPRESS_CEILING,
        })
}

#[inline]
pub(crate) fn lzma_alone_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let stream: Stream = Stream::new_lzma_decoder(u64::MAX)
        .map_err(|e: liblzma::stream::Error| Error::Lzma(format!("{e}")))?;
    let decoder: XzDecoder<&[u8]> = XzDecoder::new_stream(input, stream);
    bounded_read_to_end(decoder)
        .map_err(|e: std::io::Error| Error::Lzma(format!("{e}")))?
        .ok_or(Error::DecompressionTooLarge {
            limit: DECOMPRESS_CEILING,
        })
}

#[inline]
pub(crate) fn bz2_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(input);
    bounded_read_to_end(decoder)
        .map_err(|e: std::io::Error| Error::Bzip2(format!("{e}")))?
        .ok_or(Error::DecompressionTooLarge {
            limit: DECOMPRESS_CEILING,
        })
}

#[inline]
pub(crate) fn gzip_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let decoder: GzDecoder<&[u8]> = GzDecoder::new(input);
    bounded_read_to_end(decoder)
        .map_err(|e: std::io::Error| Error::Gzip(format!("{e}")))?
        .ok_or(Error::DecompressionTooLarge {
            limit: DECOMPRESS_CEILING,
        })
}

#[inline]
pub(crate) fn b64_encode(input: &[u8]) -> String {
    B64_STANDARD.encode(input)
}

#[inline]
pub(crate) fn b64_decode(input: &[u8]) -> Result<Vec<u8>> {
    B64_STANDARD
        .decode(input)
        .or_else(|_: base64::DecodeError| B64_URLSAFE.decode(input))
        .map_err(Error::Base64)
}

#[inline]
const fn b85_alphabet() -> &'static [u8] {
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
}

pub(crate) fn b85_encode(input: &[u8]) -> Vec<u8> {
    let alphabet: &[u8] = b85_alphabet();
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 5 / 4 + 5);
    let mut i: usize = 0;
    while i + 4 <= input.len() {
        let mut acc: u32 = u32::from_be_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]);
        let mut buf: [u8; 5] = [0u8; 5];
        for slot in buf.iter_mut().rev() {
            let rem: u32 = acc % 85;
            acc /= 85;
            *slot = alphabet[rem as usize];
        }
        out.extend_from_slice(&buf);
        i += 4;
    }
    out
}

pub(crate) fn b85_decode(input: &[u8]) -> Result<Vec<u8>> {
    let alphabet: &[u8] = b85_alphabet();
    let mut lookup: [u8; 256] = [u8::MAX; 256];
    for (idx, &c) in alphabet.iter().enumerate() {
        let slot: u8 = u8::try_from(idx).map_err(|_| Error::LiteralNotFound)?;
        lookup[c as usize] = slot;
    }
    let mut symbols: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        let v: u8 = lookup[b as usize];
        if v == u8::MAX {
            return Err(Error::LiteralNotFound);
        }
        symbols.push(v);
    }
    let mut out: Vec<u8> = Vec::with_capacity(symbols.len() * 4 / 5 + 4);
    for group in symbols.chunks(5) {
        if group.len() == 1 {
            return Err(Error::LiteralNotFound);
        }
        let mut acc: u32 = 0;
        for slot in 0..5 {
            let v: u8 = group.get(slot).copied().unwrap_or(84);
            acc = acc.checked_mul(85).ok_or(Error::LiteralNotFound)?;
            acc = acc
                .checked_add(u32::from(v))
                .ok_or(Error::LiteralNotFound)?;
        }
        let bytes: [u8; 4] = acc.to_be_bytes();
        let written: usize = group.len() - 1;
        out.extend_from_slice(&bytes[..written]);
    }
    Ok(out)
}

#[inline]
pub(crate) fn xor_apply(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let key_len: usize = key.len();
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    for (i, &b) in data.iter().enumerate() {
        out.push(b ^ key[i % key_len]);
    }
    out
}

pub(crate) fn python_bytes_literal(bytes: &[u8]) -> String {
    let mut s: String = String::with_capacity(bytes.len() * 4 + 4);
    s.push('b');
    s.push('\'');
    for &b in bytes {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'\'' => s.push_str("\\'"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            other => {
                s.push_str("\\x");
                push_lower_hex_byte(&mut s, other);
            }
        }
    }
    s.push('\'');
    s
}

pub(crate) fn extract_largest_python_bytes_literal(text: &str) -> Option<&str> {
    let mut best: Option<&str> = None;
    let mut cursor: usize = 0;
    while let Some((lit, next_cursor)) = next_bytes_literal(text, cursor) {
        if best.is_none_or(|b: &str| lit.len() > b.len()) {
            best = Some(lit);
        }
        cursor = next_cursor;
    }
    best
}

fn next_bytes_literal(text: &str, cursor: usize) -> Option<(&str, usize)> {
    let window: &str = text.get(cursor..)?;
    let idx_single: Option<usize> = window.find("b'");
    let idx_double: Option<usize> = window.find("b\"");
    let rel: usize = match (idx_single, idx_double) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    let idx: usize = cursor + rel;
    let opener: u8 = *text.as_bytes().get(idx + 1)?;
    let body_start: usize = idx + 2;
    let rest: &str = text.get(body_start..)?;
    let end_off: usize = scan_unescaped(rest.as_bytes(), opener)?;
    let lit: &str = rest.get(..end_off)?;
    Some((lit, body_start + end_off + 1))
}

fn scan_unescaped(bytes: &[u8], opener: u8) -> Option<usize> {
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == opener {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub(crate) fn decode_python_bytes_literal(s: &str) -> Result<Vec<u8>> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            break;
        }
        let esc: u8 = bytes[i + 1];
        match esc {
            b'x' => {
                if i + 3 >= bytes.len() {
                    return Err(Error::LiteralNotFound);
                }
                let hi: u8 = hex_nibble(bytes[i + 2]).ok_or(Error::LiteralNotFound)?;
                let lo: u8 = hex_nibble(bytes[i + 3]).ok_or(Error::LiteralNotFound)?;
                out.push((hi << 4) | lo);
                i += 4;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'\'' => {
                out.push(b'\'');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'0' => {
                out.push(0);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[inline]
const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        push_lower_hex_byte(&mut s, *b);
    }
    s
}

pub(crate) fn b16_decode(input: &[u8]) -> Result<Vec<u8>> {
    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace())
        .collect();
    if !trimmed.len().is_multiple_of(2) {
        return Err(Error::LiteralNotFound);
    }
    let mut out: Vec<u8> = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.chunks_exact(2) {
        let hi: u8 = hex_nibble(pair[0]).ok_or(Error::LiteralNotFound)?;
        let lo: u8 = hex_nibble(pair[1]).ok_or(Error::LiteralNotFound)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub(crate) fn b32_decode(input: &[u8]) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut lookup: [i8; 256] = [-1i8; 256];
    let mut i: usize = 0;
    while i < ALPHABET.len() {
        lookup[ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 5 / 8 + 1);
    for &c in input {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v: i8 = lookup[c as usize];
        if v < 0 {
            return Err(Error::LiteralNotFound);
        }
        bits = (bits << 5) | u32::from(v as u8);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bounded_read_accepts_output_within_ceiling() {
        let reader: &[u8] = b"hello world";
        let out: Option<Vec<u8>> =
            bounded_read_to_end_with(reader, 64).expect("read within ceiling");
        assert_eq!(out.as_deref(), Some(b"hello world".as_slice()));
    }

    #[test]
    fn b16_decode_roundtrips() {
        assert_eq!(b16_decode(b"48656c6c6f").expect("hex"), b"Hello");
        assert_eq!(
            b16_decode(b"DEADBEEF").expect("hex"),
            &[0xde, 0xad, 0xbe, 0xef]
        );
        assert!(b16_decode(b"abc").is_err());
        assert!(b16_decode(b"zz").is_err());
    }

    #[test]
    fn b32_decode_matches_known_vector() {
        assert_eq!(
            b32_decode(b"JBSWY3DPEBLW64TMMQ======").expect("b32"),
            b"Hello World"
        );
        assert_eq!(b32_decode(b"MFRGG===").expect("b32"), b"abc");
        assert!(b32_decode(b"0189").is_err());
    }

    #[test]
    fn bounded_read_rejects_output_above_ceiling() {
        let reader: std::io::Repeat = std::io::repeat(0u8);
        let out: Option<Vec<u8>> =
            bounded_read_to_end_with(reader, 16).expect("repeat reader never errors");
        assert!(out.is_none(), "output above the ceiling must be rejected");
    }

    #[test]
    fn zlib_roundtrip_survives_bounded_inflate() {
        let original: &[u8] = b"def f():\n    return 42\n";
        let compressed: Vec<u8> = zlib_compress(original);
        let restored: Vec<u8> = zlib_decompress(&compressed).expect("inflate");
        assert_eq!(restored, original);
    }

    #[test]
    fn b85_decode_matches_cpython_full_group_vector() {
        assert_eq!(b85_decode(b"Xk~0{").expect("b85 full group"), b"hell");
    }

    #[test]
    fn b85_decode_emits_partial_trailing_group() {
        assert_eq!(b85_decode(b"Xk~0{Zv").expect("b85 hello"), b"hello");
        assert_eq!(b85_decode(b"Xa").expect("b85 1 byte"), b"h");
        assert_eq!(b85_decode(b"Xk`").expect("b85 2 bytes"), b"he");
        assert_eq!(b85_decode(b"Xk}~").expect("b85 3 bytes"), b"hel");
    }

    #[test]
    fn b85_decode_strips_ascii_whitespace() {
        assert_eq!(b85_decode(b"Xk~0{ Zv\n").expect("b85 spaced"), b"hello");
    }

    #[test]
    fn b85_decode_rejects_group_overflow_not_masked() {
        assert!(
            b85_decode(b"~~~~~").is_err(),
            "a base85 group above u32::MAX must be rejected, never masked to a wrong value"
        );
    }

    #[test]
    fn b85_decode_rejects_lone_trailing_symbol_and_alien_bytes() {
        assert!(b85_decode(b"Xk~0{X").is_err());
        assert!(b85_decode(b"Xk~0,").is_err());
    }
}
