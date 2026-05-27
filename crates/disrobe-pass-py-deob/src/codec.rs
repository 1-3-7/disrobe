use std::io::{Read, Write};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD as B64_URLSAFE};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use liblzma::read::XzDecoder;
use liblzma::write::XzEncoder;

use crate::error::{Error, Result};

#[inline]
pub(crate) fn zlib_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
    let _: std::io::Result<()> = encoder.write_all(input);
    encoder.finish().unwrap_or_default()
}

#[inline]
pub(crate) fn zlib_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::Zlib(format!("{e}")))?;
    Ok(out)
}

#[inline]
pub(crate) fn lzma_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder: XzEncoder<Vec<u8>> = XzEncoder::new(Vec::new(), 6);
    let _: std::io::Result<()> = encoder.write_all(input);
    encoder.finish().unwrap_or_default()
}

#[inline]
pub(crate) fn lzma_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder: XzDecoder<&[u8]> = XzDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::Lzma(format!("{e}")))?;
    Ok(out)
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
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 4 / 5 + 4);
    for chunk in input.chunks(5) {
        if chunk.len() < 5 {
            break;
        }
        let mut acc: u32 = 0;
        for &c in chunk {
            let v: u8 = lookup[c as usize];
            if v == u8::MAX {
                return Err(Error::LiteralNotFound);
            }
            acc = acc.checked_mul(85).ok_or(Error::LiteralNotFound)?;
            acc = acc
                .checked_add(u32::from(v))
                .ok_or(Error::LiteralNotFound)?;
        }
        out.extend_from_slice(&acc.to_be_bytes());
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
                use core::fmt::Write as _;
                let _: core::fmt::Result = write!(s, "\\x{other:02x}");
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
    use core::fmt::Write as _;
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _: core::fmt::Result = write!(s, "{b:02x}");
    }
    s
}
