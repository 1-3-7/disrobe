use flate2::read::ZlibDecoder;
use memchr::memmem;
use std::io::Read as _;

use crate::error::{Error, Result};
use crate::protectors::{PeelResult, ProtectorFamily};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZendGuardEra {
    Zend2,
    Zend3,
    Zend4,
}

impl ZendGuardEra {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zend2 => "zend-2",
            Self::Zend3 => "zend-3",
            Self::Zend4 => "zend-4",
        }
    }
}

const ERA_MARKERS: &[(&[u8], ZendGuardEra)] = &[
    (b"<?php @Zend;\n2", ZendGuardEra::Zend2),
    (b"<?php @Zend;\n3", ZendGuardEra::Zend3),
    (b"<?php @Zend;\n4", ZendGuardEra::Zend4),
];

#[derive(Debug, Clone)]
pub struct ZendGuardFrame {
    pub era: ZendGuardEra,
    pub marker_offset: usize,
    pub declared_len: u32,
    pub flag_bits: u32,
    pub key_seed: u32,
    pub payload: Vec<u8>,
}

pub fn parse_frame(bytes: &[u8]) -> Result<ZendGuardFrame> {
    let (era, marker_offset, marker_len): (ZendGuardEra, usize, usize) = ERA_MARKERS
        .iter()
        .filter_map(|(needle, era)| {
            memmem::find(bytes, needle).map(|i: usize| (*era, i, needle.len()))
        })
        .min_by_key(|(_, i, _): &(ZendGuardEra, usize, usize)| *i)
        .ok_or(Error::ZendGuardBadHeader("no zend marker"))?;

    let header_start: usize = marker_offset + marker_len;
    let header_end: usize = header_start
        .checked_add(12)
        .ok_or(Error::ZendGuardBadHeader("header overflow"))?;
    if header_end > bytes.len() {
        return Err(Error::ZendGuardBadHeader("header truncated"));
    }
    let declared_len: u32 = u32::from_le_bytes([
        bytes[header_start],
        bytes[header_start + 1],
        bytes[header_start + 2],
        bytes[header_start + 3],
    ]);
    let flag_bits: u32 = u32::from_le_bytes([
        bytes[header_start + 4],
        bytes[header_start + 5],
        bytes[header_start + 6],
        bytes[header_start + 7],
    ]);
    let key_seed: u32 = u32::from_le_bytes([
        bytes[header_start + 8],
        bytes[header_start + 9],
        bytes[header_start + 10],
        bytes[header_start + 11],
    ]);

    let payload_end: usize = header_end
        .checked_add(declared_len as usize)
        .ok_or(Error::ZendGuardBadHeader("payload overflow"))?;
    if payload_end > bytes.len() {
        return Err(Error::ZendGuardBadHeader("payload truncated"));
    }
    let payload: Vec<u8> = bytes[header_end..payload_end].to_vec();
    Ok(ZendGuardFrame {
        era,
        marker_offset,
        declared_len,
        flag_bits,
        key_seed,
        payload,
    })
}

const ZG_FLAG_COMPRESSED: u32 = 1 << 0;
const ZG_FLAG_XOR_STREAM: u32 = 1 << 1;

fn keystream(seed: u32, len: usize) -> Vec<u8> {
    let mut state: u32 = seed.wrapping_add(0x9E37_79B9);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    while out.len() < len {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

pub fn decode_frame(frame: &ZendGuardFrame) -> Result<Vec<u8>> {
    let mut raw: Vec<u8> = frame.payload.clone();
    if frame.flag_bits & ZG_FLAG_XOR_STREAM != 0 {
        let stream: Vec<u8> = keystream(frame.key_seed, raw.len());
        for i in 0..raw.len() {
            raw[i] ^= stream[i];
        }
    }
    if frame.flag_bits & ZG_FLAG_COMPRESSED != 0 && raw.len() >= 2 && raw[0] == 0x78 {
        let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(raw.as_slice());
        let mut out: Vec<u8> = Vec::with_capacity(raw.len() * 4);
        decoder
            .read_to_end(&mut out)
            .map_err(|_| Error::ZendGuardBadHeader("zlib inflate failed"))?;
        return Ok(out);
    }
    Ok(raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcodeSummary {
    pub total_ops: u32,
    pub distinct_opcodes: u32,
}

pub fn summarize_opcodes(plaintext: &[u8]) -> OpcodeSummary {
    if plaintext.len() < 8 {
        return OpcodeSummary {
            total_ops: 0,
            distinct_opcodes: 0,
        };
    }
    let total_ops: u32 =
        u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    let mut seen: [bool; 256] = [false; 256];
    for b in plaintext.iter().skip(4).step_by(2) {
        seen[usize::from(*b)] = true;
    }
    let distinct_opcodes: u32 =
        u32::try_from(seen.iter().filter(|&&v: &&bool| v).count()).unwrap_or(0);
    OpcodeSummary {
        total_ops,
        distinct_opcodes,
    }
}

pub fn peel(bytes: &[u8]) -> Result<PeelResult> {
    let frame: ZendGuardFrame = parse_frame(bytes)?;
    let era_label: &'static str = frame.era.label();
    let plaintext: Vec<u8> = decode_frame(&frame)?;
    let summary: OpcodeSummary = summarize_opcodes(&plaintext);
    let mut strings: Vec<String> = Vec::new();
    for s in extract_strings(&plaintext) {
        strings.push(s);
    }
    let label: String = format!(
        "{era_label} ops={total} distinct={distinct}",
        total = summary.total_ops,
        distinct = summary.distinct_opcodes
    );
    Ok(PeelResult {
        family: ProtectorFamily::ZendGuard,
        version_label: label,
        layers_peeled: 2,
        recovered_strings: strings,
        recovered_php: None,
        residual_bytes: plaintext.len(),
    })
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

#[must_use]
pub fn build_test_blob(era: ZendGuardEra, plaintext: &[u8], flags: u32, key_seed: u32) -> Vec<u8> {
    let marker: &[u8] = match era {
        ZendGuardEra::Zend2 => b"<?php @Zend;\n2",
        ZendGuardEra::Zend3 => b"<?php @Zend;\n3",
        ZendGuardEra::Zend4 => b"<?php @Zend;\n4",
    };
    let mut transformed: Vec<u8> = plaintext.to_vec();
    if flags & ZG_FLAG_XOR_STREAM != 0 {
        let stream: Vec<u8> = keystream(key_seed, transformed.len());
        for i in 0..transformed.len() {
            transformed[i] ^= stream[i];
        }
    }
    let declared_len: u32 = u32::try_from(transformed.len()).unwrap_or(0);

    let mut out: Vec<u8> = Vec::with_capacity(marker.len() + 12 + transformed.len());
    out.extend_from_slice(marker);
    out.extend_from_slice(&declared_len.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&key_seed.to_le_bytes());
    out.extend_from_slice(&transformed);
    out
}

pub const FLAG_XOR_STREAM: u32 = ZG_FLAG_XOR_STREAM;
pub const FLAG_COMPRESSED: u32 = ZG_FLAG_COMPRESSED;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dummy_opcode_stream() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64);
        v.extend_from_slice(&8_u32.to_le_bytes());
        for op in 0u8..8 {
            v.push(op + 0x10);
            v.push(0);
        }
        v.extend_from_slice(b"zend_opcode_stream_marker");
        v
    }

    #[test]
    fn xor_roundtrip_zend3() {
        let plaintext: Vec<u8> = dummy_opcode_stream();
        let blob: Vec<u8> = build_test_blob(
            ZendGuardEra::Zend3,
            &plaintext,
            FLAG_XOR_STREAM,
            0xDEAD_BEEF,
        );
        let frame: ZendGuardFrame = parse_frame(&blob).expect("parse");
        assert_eq!(frame.era, ZendGuardEra::Zend3);
        let recovered: Vec<u8> = decode_frame(&frame).expect("decode");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn full_peel_yields_summary_and_strings() {
        let plaintext: Vec<u8> = dummy_opcode_stream();
        let blob: Vec<u8> = build_test_blob(
            ZendGuardEra::Zend4,
            &plaintext,
            FLAG_XOR_STREAM,
            0xCAFE_F00D,
        );
        let result: PeelResult = peel(&blob).expect("peel");
        assert_eq!(result.family, ProtectorFamily::ZendGuard);
        assert!(result.version_label.starts_with("zend-4"));
        assert!(
            result
                .recovered_strings
                .iter()
                .any(|s: &String| s.contains("zend_opcode_stream_marker"))
        );
    }

    #[test]
    fn no_xor_no_compress_returns_payload_verbatim() {
        let plaintext: Vec<u8> = b"raw opcodes bytes here".to_vec();
        let blob: Vec<u8> = build_test_blob(ZendGuardEra::Zend2, &plaintext, 0, 0);
        let frame: ZendGuardFrame = parse_frame(&blob).expect("parse");
        let recovered: Vec<u8> = decode_frame(&frame).expect("decode");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn missing_marker_errors() {
        let bytes: &[u8] = b"<?php echo 'not zend';";
        assert!(parse_frame(bytes).is_err());
    }
}
