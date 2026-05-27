use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use flate2::read::ZlibDecoder;
use memchr::memmem;
use std::io::Read as _;

use crate::error::{Error, Result};
use crate::protectors::{PeelResult, ProtectorFamily};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceGuardianEra {
    Legacy,
    Modern,
}

impl SourceGuardianEra {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Legacy => "sg-legacy",
            Self::Modern => "sg-modern",
        }
    }

    #[inline]
    #[must_use]
    pub const fn header_skip(self) -> usize {
        match self {
            Self::Legacy => 16,
            Self::Modern => 32,
        }
    }
}

const LEGACY_MARKERS: &[&[u8]] = &[
    b"<?php\n//SGV1",
    b"<?php\n//SGV2",
    b"<?php //SGV1",
    b"<?php //SGV2",
];

const MODERN_MARKERS: &[&[u8]] = &[
    b"<?php @SourceGuardian;",
    b"// PHP SourceGuardian Loader v",
    b"<?php\n//SourceGuardian",
];

#[derive(Debug, Clone)]
pub struct SourceGuardianFrame {
    pub era: SourceGuardianEra,
    pub marker_offset: usize,
    pub header_bytes: Vec<u8>,
    pub key_stream: Vec<u8>,
    pub payload_b64: Vec<u8>,
}

pub fn parse_frame(bytes: &[u8]) -> Result<SourceGuardianFrame> {
    let (era, marker_offset, marker_len): (SourceGuardianEra, usize, usize) = locate_marker(bytes)?;
    let line_end: usize = bytes
        .iter()
        .skip(marker_offset + marker_len)
        .position(|&b: &u8| b == b'\n')
        .map(|p: usize| p + marker_offset + marker_len + 1)
        .unwrap_or(marker_offset + marker_len);
    let header_skip: usize = era.header_skip();
    let header_end: usize = line_end
        .checked_add(header_skip)
        .ok_or(Error::SourceGuardianBadHeader("header overflow"))?;
    if header_end >= bytes.len() {
        return Err(Error::SourceGuardianBadHeader("header truncated"));
    }
    let header_bytes: Vec<u8> = bytes[line_end..header_end].to_vec();
    let key_stream: Vec<u8> = derive_key_stream(&header_bytes);
    let payload_b64: Vec<u8> = bytes[header_end..].to_vec();
    Ok(SourceGuardianFrame {
        era,
        marker_offset,
        header_bytes,
        key_stream,
        payload_b64,
    })
}

fn locate_marker(bytes: &[u8]) -> Result<(SourceGuardianEra, usize, usize)> {
    let mut best: Option<(SourceGuardianEra, usize, usize)> = None;
    for needle in LEGACY_MARKERS {
        if let Some(idx) = memmem::find(bytes, needle)
            && best.is_none_or(|(_, prev, _): (SourceGuardianEra, usize, usize)| idx < prev)
        {
            best = Some((SourceGuardianEra::Legacy, idx, needle.len()));
        }
    }
    for needle in MODERN_MARKERS {
        if let Some(idx) = memmem::find(bytes, needle)
            && best.is_none_or(|(_, prev, _): (SourceGuardianEra, usize, usize)| idx < prev)
        {
            best = Some((SourceGuardianEra::Modern, idx, needle.len()));
        }
    }
    best.ok_or(Error::SourceGuardianBadHeader("no SG marker"))
}

fn derive_key_stream(header: &[u8]) -> Vec<u8> {
    let mut stream: Vec<u8> = Vec::with_capacity(256);
    let mut acc: u32 = 0x5A_A5_5A_A5;
    for i in 0..header.len() {
        let b: u8 = header[i];
        acc = acc.wrapping_mul(1664525).wrapping_add(1013904223);
        acc ^= u32::from(b).rotate_left((i & 31) as u32);
        stream.extend_from_slice(&acc.to_le_bytes());
    }
    while stream.len() < 64 {
        acc = acc.wrapping_mul(1664525).wrapping_add(1013904223);
        stream.extend_from_slice(&acc.to_le_bytes());
    }
    stream
}

pub fn decode_frame(frame: &SourceGuardianFrame) -> Result<Vec<u8>> {
    let mut cleaned: Vec<u8> = Vec::with_capacity(frame.payload_b64.len());
    for &b in &frame.payload_b64 {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=') {
            cleaned.push(b);
        }
    }
    if cleaned.is_empty() {
        return Err(Error::SourceGuardianBadHeader("empty payload"));
    }
    while cleaned.len() % 4 != 0 {
        cleaned.push(b'=');
    }
    let mut raw: Vec<u8> = B64
        .decode(&cleaned)
        .map_err(|_| Error::SourceGuardianBadHeader("base64 decode failed"))?;

    let stream_len: usize = frame.key_stream.len();
    for i in 0..raw.len() {
        raw[i] ^= frame.key_stream[i % stream_len];
    }

    if raw.len() >= 2 && raw[0] == 0x78 {
        let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(raw.as_slice());
        let mut out: Vec<u8> = Vec::with_capacity(raw.len() * 2);
        if decoder.read_to_end(&mut out).is_ok() {
            return Ok(out);
        }
    }
    Ok(raw)
}

pub fn extract_strings(plaintext: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    for &b in plaintext {
        if (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\t' {
            buf.push(b);
        } else {
            if buf.len() >= 4
                && let Ok(s) = std::str::from_utf8(&buf)
            {
                out.push(s.to_string());
            }
            buf.clear();
        }
    }
    if buf.len() >= 4
        && let Ok(s) = std::str::from_utf8(&buf)
    {
        out.push(s.to_string());
    }
    out
}

pub fn peel(bytes: &[u8]) -> Result<PeelResult> {
    let frame: SourceGuardianFrame = parse_frame(bytes)?;
    let era_label: &'static str = frame.era.label();
    let plaintext: Vec<u8> = decode_frame(&frame)?;
    let strings: Vec<String> = extract_strings(&plaintext);
    let recovered_php: Option<String> = if memmem::find(&plaintext, b"<?php").is_some()
        || memmem::find(&plaintext, b"<?").is_some()
    {
        std::str::from_utf8(&plaintext).ok().map(str::to_string)
    } else {
        None
    };
    let residual: usize = if recovered_php.is_some() {
        0
    } else {
        plaintext.len()
    };
    Ok(PeelResult {
        family: ProtectorFamily::SourceGuardian,
        version_label: era_label.to_string(),
        layers_peeled: if recovered_php.is_some() { 3 } else { 2 },
        recovered_strings: strings,
        recovered_php,
        residual_bytes: residual,
    })
}

#[must_use]
pub fn build_test_blob(era: SourceGuardianEra, plaintext: &[u8]) -> Vec<u8> {
    let marker: &[u8] = match era {
        SourceGuardianEra::Legacy => b"<?php\n//SGV1",
        SourceGuardianEra::Modern => b"<?php @SourceGuardian;",
    };
    let header_bytes: Vec<u8> = (0..era.header_skip())
        .map(|i: usize| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect();
    let key_stream: Vec<u8> = derive_key_stream(&header_bytes);

    let mut payload: Vec<u8> = plaintext.to_vec();
    let stream_len: usize = key_stream.len();
    for i in 0..payload.len() {
        payload[i] ^= key_stream[i % stream_len];
    }
    let b64: String = B64.encode(&payload);

    let mut out: Vec<u8> = Vec::with_capacity(64 + header_bytes.len() + b64.len());
    out.extend_from_slice(marker);
    out.push(b'\n');
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(b64.as_bytes());
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn xor_keystream_roundtrip_recovers_legacy_php() {
        let plaintext: &[u8] = b"<?php echo 'sg legacy'; return 99;";
        let blob: Vec<u8> = build_test_blob(SourceGuardianEra::Legacy, plaintext);
        let result: PeelResult = peel(&blob).expect("peel");
        assert_eq!(result.family, ProtectorFamily::SourceGuardian);
        assert_eq!(result.version_label, "sg-legacy");
        let php: String = result.recovered_php.expect("php");
        assert!(php.contains("sg legacy"));
    }

    #[test]
    fn modern_marker_roundtrip() {
        let plaintext: &[u8] = b"<?php interface Service { public function call(): mixed; }";
        let blob: Vec<u8> = build_test_blob(SourceGuardianEra::Modern, plaintext);
        let result: PeelResult = peel(&blob).expect("peel");
        assert_eq!(result.version_label, "sg-modern");
        assert!(result.recovered_php.unwrap().contains("Service"));
    }

    #[test]
    fn missing_marker_returns_err() {
        let bytes: &[u8] = b"<?php echo 'not sg';";
        assert!(peel(bytes).is_err());
    }

    #[test]
    fn extract_strings_yields_printable_runs() {
        let raw: &[u8] = b"hello\x00source\x01guardian";
        let out: Vec<String> = extract_strings(raw);
        assert!(out.iter().any(|s: &String| s == "hello"));
        assert!(out.iter().any(|s: &String| s == "source"));
        assert!(out.iter().any(|s: &String| s == "guardian"));
    }
}
