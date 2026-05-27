use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use flate2::read::ZlibDecoder;
use memchr::memmem;
use std::io::Read as _;

use crate::error::{Error, Result};
use crate::protectors::{PeelResult, ProtectorFamily};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IonCubeEra {
    V4Legacy,
    V6,
    V9,
    V10,
}

impl IonCubeEra {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V4Legacy => "v4-legacy",
            Self::V6 => "v6",
            Self::V9 => "v9",
            Self::V10 => "v10",
        }
    }

    #[inline]
    #[must_use]
    pub const fn preamble_len(self) -> usize {
        match self {
            Self::V4Legacy => 24,
            Self::V6 => 32,
            Self::V9 => 48,
            Self::V10 => 64,
        }
    }
}

const ERA_MARKERS: &[(&[u8], IonCubeEra)] = &[
    (b"//00400", IonCubeEra::V4Legacy),
    (b"//0046", IonCubeEra::V6),
    (b"//004F", IonCubeEra::V9),
    (b"//0080", IonCubeEra::V10),
];

#[derive(Debug, Clone)]
pub struct IonCubeFrame {
    pub era: IonCubeEra,
    pub marker_offset: usize,
    pub preamble: Vec<u8>,
    pub key_seed: [u8; 16],
    pub payload_b64: Vec<u8>,
}

pub fn parse_frame(bytes: &[u8]) -> Result<IonCubeFrame> {
    let (era, marker_offset): (IonCubeEra, usize) = ERA_MARKERS
        .iter()
        .filter_map(|(needle, era)| memmem::find(bytes, needle).map(|idx: usize| (*era, idx)))
        .min_by_key(|(_, idx): &(IonCubeEra, usize)| *idx)
        .ok_or(Error::IonCubeBadHeader("no era marker"))?;

    let line_end: usize = bytes[marker_offset..]
        .iter()
        .position(|&b: &u8| b == b'\n')
        .ok_or(Error::IonCubeBadHeader("no end-of-marker newline"))?
        + marker_offset
        + 1;
    let preamble_len: usize = era.preamble_len();
    let preamble_end: usize = line_end
        .checked_add(preamble_len)
        .ok_or(Error::IonCubeBadHeader("preamble overflow"))?;
    if preamble_end > bytes.len() {
        return Err(Error::IonCubeBadHeader("preamble truncated"));
    }
    let preamble: Vec<u8> = bytes[line_end..preamble_end].to_vec();
    let key_seed: [u8; 16] = derive_key_seed(&preamble);
    let payload_b64: Vec<u8> = bytes[preamble_end..].to_vec();
    Ok(IonCubeFrame {
        era,
        marker_offset,
        preamble,
        key_seed,
        payload_b64,
    })
}

fn derive_key_seed(preamble: &[u8]) -> [u8; 16] {
    let mut seed: [u8; 16] = [0u8; 16];
    for i in 0..preamble.len() {
        let b: u8 = preamble[i];
        seed[i & 0x0F] ^= b.rotate_left((i & 7) as u32);
    }
    seed
}

pub fn rc4_init(key: &[u8]) -> [u8; 256] {
    let mut s: [u8; 256] = [0u8; 256];
    for i in 0..256_usize {
        s[i] = u8::try_from(i).unwrap_or(0);
    }
    let mut j: usize = 0;
    for i in 0..256_usize {
        j = (j + usize::from(s[i]) + usize::from(key[i % key.len()])) & 0xFF;
        s.swap(i, j);
    }
    s
}

pub fn rc4_xor(state: &mut [u8; 256], data: &mut [u8]) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    for byte in data.iter_mut() {
        i = (i + 1) & 0xFF;
        j = (j + usize::from(state[i])) & 0xFF;
        state.swap(i, j);
        let k: u8 = state[(usize::from(state[i]) + usize::from(state[j])) & 0xFF];
        *byte ^= k;
    }
}

pub fn decode_frame(frame: &IonCubeFrame) -> Result<Vec<u8>> {
    let mut cleaned: Vec<u8> = Vec::with_capacity(frame.payload_b64.len());
    for &b in &frame.payload_b64 {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=') {
            cleaned.push(b);
        }
    }
    if cleaned.is_empty() {
        return Err(Error::IonCubeBadHeader("empty base64 payload"));
    }
    while cleaned.len() % 4 != 0 {
        cleaned.push(b'=');
    }
    let mut raw: Vec<u8> = B64
        .decode(&cleaned)
        .map_err(|_| Error::IonCubeBadHeader("base64 decode failed"))?;

    let mut state: [u8; 256] = rc4_init(&frame.key_seed);
    rc4_xor(&mut state, &mut raw);

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
    let frame: IonCubeFrame = parse_frame(bytes)?;
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
        family: ProtectorFamily::IonCube,
        version_label: era_label.to_string(),
        layers_peeled: if recovered_php.is_some() { 3 } else { 2 },
        recovered_strings: strings,
        recovered_php,
        residual_bytes: residual,
    })
}

#[must_use]
pub fn build_test_blob(era: IonCubeEra, plaintext: &[u8]) -> Vec<u8> {
    let marker: &[u8] = match era {
        IonCubeEra::V4Legacy => b"<?php //00400",
        IonCubeEra::V6 => b"<?php //0046",
        IonCubeEra::V9 => b"<?php //004F",
        IonCubeEra::V10 => b"<?php //0080",
    };
    let preamble: Vec<u8> = (0..era.preamble_len())
        .map(|i: usize| (i as u8).wrapping_mul(31))
        .collect();
    let key_seed: [u8; 16] = derive_key_seed(&preamble);
    let mut state: [u8; 256] = rc4_init(&key_seed);
    let mut payload: Vec<u8> = plaintext.to_vec();
    rc4_xor(&mut state, &mut payload);
    let b64: String = B64.encode(&payload);

    let mut out: Vec<u8> = Vec::with_capacity(64 + preamble.len() + b64.len());
    out.extend_from_slice(marker);
    out.push(b'\n');
    out.extend_from_slice(&preamble);
    out.extend_from_slice(b64.as_bytes());
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rc4_roundtrip_is_identity() {
        let key: &[u8] = b"hello world key 16";
        let plaintext: &[u8] = b"sphinx of black quartz judge my vow";
        let mut s1: [u8; 256] = rc4_init(key);
        let mut buf: Vec<u8> = plaintext.to_vec();
        rc4_xor(&mut s1, &mut buf);
        let mut s2: [u8; 256] = rc4_init(key);
        rc4_xor(&mut s2, &mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn derive_seed_is_deterministic() {
        let preamble: &[u8] = &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(derive_key_seed(preamble), derive_key_seed(preamble));
    }

    #[test]
    fn build_and_peel_v6_roundtrip_recovers_php() {
        let plaintext: &[u8] = b"<?php\necho 'hello ionCube';\nreturn 42;\n";
        let blob: Vec<u8> = build_test_blob(IonCubeEra::V6, plaintext);
        let result: PeelResult = peel(&blob).expect("peel must succeed");
        assert_eq!(result.family, ProtectorFamily::IonCube);
        assert_eq!(result.version_label, "v6");
        assert!(result.recovered_php.is_some());
        let php: String = result.recovered_php.unwrap();
        assert!(php.contains("echo"));
        assert!(php.contains("hello ionCube"));
    }

    #[test]
    fn build_and_peel_v9_roundtrip() {
        let plaintext: &[u8] = b"<?php class Foo { public function bar() { return 'baz'; } }";
        let blob: Vec<u8> = build_test_blob(IonCubeEra::V9, plaintext);
        let result: PeelResult = peel(&blob).expect("peel must succeed");
        assert_eq!(result.version_label, "v9");
        assert!(result.recovered_php.unwrap().contains("class Foo"));
    }

    #[test]
    fn missing_marker_is_error() {
        let bytes: &[u8] = b"<?php echo 'clear text';";
        assert!(peel(bytes).is_err());
    }

    #[test]
    fn extract_strings_finds_printable_runs() {
        let raw: &[u8] = b"hello\x00world\x01test123\x02\x03ok";
        let strings: Vec<String> = extract_strings(raw);
        assert!(strings.iter().any(|s: &String| s == "hello"));
        assert!(strings.iter().any(|s: &String| s == "world"));
        assert!(strings.iter().any(|s: &String| s == "test123"));
    }
}
