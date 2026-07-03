use disrobe_core::TeaVariant;
use disrobe_core::codec::cipher::{
    chacha20_apply, salsa20_apply, tea_family_decrypt_bytes, xxtea_decrypt_bytes,
};
use serde::Serialize;

use crate::codec::{bytes_to_hex, xor_apply};

pub(crate) const MAX_REPEATING_KEYLEN: usize = 40;
pub(crate) const MAX_KEY_CANDIDATES: usize = 64;
const MIN_KEYED_INPUT: usize = 8;
const HAMMING_MIN_PAIRS: usize = 4;
const TEA_KEY_LEN: usize = 16;
const STREAM_KEY_LEN: usize = 32;
const CHACHA_NONCE_LEN: usize = 12;
const SALSA_NONCE_LEN: usize = 8;
const STREAM_COUNTERS: [u64; 2] = [0, 1];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CipherKind {
    XorSingle,
    XorMulti,
    Rc4,
    Tea,
    Xtea,
    Xxtea,
    ChaCha20,
    Salsa20,
}

impl CipherKind {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::XorSingle => "xor1",
            Self::XorMulti => "xor-multi",
            Self::Rc4 => "rc4",
            Self::Tea => "tea",
            Self::Xtea => "xtea",
            Self::Xxtea => "xxtea",
            Self::ChaCha20 => "chacha20",
            Self::Salsa20 => "salsa20",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum KeyProvenance {
    Literal,
    CribDerived,
    BruteForced,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyFinding {
    pub cipher: CipherKind,
    pub key_hex: String,
    pub key_len: usize,
    pub provenance: KeyProvenance,
    pub crib: &'static str,
}

impl KeyFinding {
    pub(crate) fn decoder_label(&self) -> String {
        match self.cipher {
            CipherKind::XorSingle => {
                format!("{c}:0x{k}", c = self.cipher.label(), k = self.key_hex)
            }
            CipherKind::XorMulti => {
                format!("{c}:len{n}", c = self.cipher.label(), n = self.key_len)
            }
            CipherKind::Rc4
            | CipherKind::Tea
            | CipherKind::Xtea
            | CipherKind::Xxtea
            | CipherKind::ChaCha20
            | CipherKind::Salsa20 => format!("{c}:keylit", c = self.cipher.label()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CipherResult {
    pub finding: KeyFinding,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Crib {
    bytes: &'static [u8],
    name: &'static str,
}

const CRIBS: [Crib; 16] = [
    Crib {
        bytes: &[0x78, 0x9c],
        name: "zlib-default",
    },
    Crib {
        bytes: &[0x78, 0xda],
        name: "zlib-best",
    },
    Crib {
        bytes: &[0x78, 0x01],
        name: "zlib-low",
    },
    Crib {
        bytes: &[0x78, 0x5e],
        name: "zlib-mid",
    },
    Crib {
        bytes: &[0x1f, 0x8b, 0x08],
        name: "gzip",
    },
    Crib {
        bytes: &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
        name: "xz",
    },
    Crib {
        bytes: &[0x42, 0x5a, 0x68],
        name: "bz2",
    },
    Crib {
        bytes: &[0x5d, 0x00, 0x00],
        name: "lzma-alone",
    },
    Crib {
        bytes: &[0x63],
        name: "marshal-code",
    },
    Crib {
        bytes: &[0x4d, 0x5a],
        name: "pe-mz",
    },
    Crib {
        bytes: &[0x50, 0x4b, 0x03, 0x04],
        name: "zip",
    },
    Crib {
        bytes: &[0x7f, 0x45, 0x4c, 0x46],
        name: "elf",
    },
    Crib {
        bytes: &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
        name: "png",
    },
    Crib {
        bytes: &[0xff, 0xfe],
        name: "utf-16le",
    },
    Crib {
        bytes: &[0xfe, 0xff],
        name: "utf-16be",
    },
    Crib {
        bytes: &[0x25, 0x50, 0x44, 0x46],
        name: "pdf",
    },
];

pub(crate) fn crib_magics() -> impl Iterator<Item = (&'static str, &'static [u8])> {
    CRIBS.iter().map(|crib: &Crib| (crib.name, crib.bytes))
}

pub(crate) fn validated_crib(plain: &[u8]) -> Option<&'static str> {
    let name: &'static str = matches_crib_at_zero(plain, 2)?;
    if plaintext_validates(plain) {
        Some(name)
    } else {
        None
    }
}

fn matches_crib_at_zero(plain: &[u8], min_len: usize) -> Option<&'static str> {
    for crib in CRIBS {
        if crib.bytes.len() >= min_len
            && plain.len() >= crib.bytes.len()
            && plain[..crib.bytes.len()] == *crib.bytes
        {
            return Some(crib.name);
        }
    }
    if min_len <= 4 && plain.len() >= 4 && plain[2] == 0x0d && plain[3] == 0x0a {
        return Some("pyc-header");
    }
    None
}

fn rc4_keystream(key: &[u8], len: usize) -> Vec<u8> {
    let mut state: [u8; 256] = core::array::from_fn(|i: usize| i as u8);
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let (mut i, mut j): (u8, u8) = (0, 0);
    for _ in 0..len {
        i = i.wrapping_add(1);
        j = j.wrapping_add(state[i as usize]);
        state.swap(i as usize, j as usize);
        let idx: usize = state[i as usize].wrapping_add(state[j as usize]) as usize;
        out.push(state[idx]);
    }
    out
}

pub(crate) fn rc4_apply(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let keystream: Vec<u8> = rc4_keystream(key, data.len());
    data.iter()
        .zip(keystream.iter())
        .map(|(d, k): (&u8, &u8)| d ^ k)
        .collect()
}

fn try_single_byte_xor(data: &[u8]) -> Option<CipherResult> {
    for k in 1u8..=255 {
        let prefix_len: usize = data.len().min(6);
        let probe: Vec<u8> = data[..prefix_len].iter().map(|b: &u8| b ^ k).collect();
        let Some(crib): Option<&'static str> = matches_crib_at_zero(&probe, 2) else {
            continue;
        };
        let plaintext: Vec<u8> = data.iter().map(|b: &u8| b ^ k).collect();
        if !plaintext_validates(&plaintext) {
            continue;
        }
        return Some(CipherResult {
            finding: KeyFinding {
                cipher: CipherKind::XorSingle,
                key_hex: bytes_to_hex(&[k]),
                key_len: 1,
                provenance: KeyProvenance::BruteForced,
                crib,
            },
            plaintext,
        });
    }
    None
}

fn try_literal_xor(data: &[u8], candidates: &[Vec<u8>]) -> Option<CipherResult> {
    for key in candidates {
        if key.is_empty() {
            continue;
        }
        let probe_len: usize = data.len().min(6);
        let probe: Vec<u8> = data[..probe_len]
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
            .collect();
        let Some(crib): Option<&'static str> = matches_crib_at_zero(&probe, 1) else {
            continue;
        };
        let plaintext: Vec<u8> = xor_apply(data, key);
        if !plaintext_validates(&plaintext) {
            continue;
        }
        let cipher: CipherKind = if key.len() == 1 {
            CipherKind::XorSingle
        } else {
            CipherKind::XorMulti
        };
        return Some(CipherResult {
            finding: KeyFinding {
                cipher,
                key_hex: bytes_to_hex(key),
                key_len: key.len(),
                provenance: KeyProvenance::Literal,
                crib,
            },
            plaintext,
        });
    }
    None
}

fn try_literal_rc4(data: &[u8], candidates: &[Vec<u8>]) -> Option<CipherResult> {
    for key in candidates {
        if key.is_empty() {
            continue;
        }
        let probe_len: usize = data.len().min(6);
        let keystream: Vec<u8> = rc4_keystream(key, probe_len);
        let probe: Vec<u8> = data[..probe_len]
            .iter()
            .zip(keystream.iter())
            .map(|(d, k): (&u8, &u8)| d ^ k)
            .collect();
        let Some(crib): Option<&'static str> = matches_crib_at_zero(&probe, 1) else {
            continue;
        };
        let plaintext: Vec<u8> = rc4_apply(data, key);
        if !plaintext_validates(&plaintext) {
            continue;
        }
        return Some(CipherResult {
            finding: KeyFinding {
                cipher: CipherKind::Rc4,
                key_hex: bytes_to_hex(key),
                key_len: key.len(),
                provenance: KeyProvenance::Literal,
                crib,
            },
            plaintext,
        });
    }
    None
}

fn block_cipher_crib(plain: &[u8]) -> Option<&'static str> {
    if let Some(name) = matches_crib_at_zero(plain, 2) {
        return Some(name);
    }
    looks_like_marshal_code(plain).then_some("marshal-code")
}

fn looks_like_marshal_code(plain: &[u8]) -> bool {
    plain.len() >= 16 && (plain[0] & 0x7f) == 0x63 && {
        use disrobe_py_marshal::{PyVersion, load as marshal_load};
        [PyVersion::PY312, PyVersion::PY39, PyVersion::PY27]
            .into_iter()
            .any(|v: PyVersion| marshal_load(plain, v).is_ok())
    }
}

fn key16_candidates(candidates: &[Vec<u8>]) -> Vec<[u8; TEA_KEY_LEN]> {
    let mut out: Vec<[u8; TEA_KEY_LEN]> = Vec::new();
    for cand in candidates {
        if let Ok(key) = <[u8; TEA_KEY_LEN]>::try_from(cand.as_slice()) {
            out.push(key);
        }
    }
    out
}

fn key32_candidates(candidates: &[Vec<u8>]) -> Vec<[u8; STREAM_KEY_LEN]> {
    let mut out: Vec<[u8; STREAM_KEY_LEN]> = Vec::new();
    for cand in candidates {
        if let Ok(key) = <[u8; STREAM_KEY_LEN]>::try_from(cand.as_slice()) {
            out.push(key);
        }
    }
    out
}

fn nonce_candidates<const N: usize>(candidates: &[Vec<u8>]) -> Vec<[u8; N]> {
    let mut out: Vec<[u8; N]> = vec![[0u8; N]];
    for cand in candidates {
        if let Ok(nonce) = <[u8; N]>::try_from(cand.as_slice())
            && !out.contains(&nonce)
        {
            out.push(nonce);
        }
    }
    out
}

fn try_literal_tea_family(data: &[u8], candidates: &[Vec<u8>]) -> Option<CipherResult> {
    if !data.len().is_multiple_of(8) || data.len() < 8 {
        return None;
    }
    for key in key16_candidates(candidates) {
        for variant in [TeaVariant::Tea, TeaVariant::Xtea] {
            let Ok(plaintext): Result<Vec<u8>, _> = tea_family_decrypt_bytes(data, &key, variant)
            else {
                continue;
            };
            let Some(crib): Option<&'static str> = block_cipher_crib(&plaintext) else {
                continue;
            };
            if !plaintext_validates(&plaintext) {
                continue;
            }
            return Some(CipherResult {
                finding: KeyFinding {
                    cipher: match variant {
                        TeaVariant::Tea => CipherKind::Tea,
                        TeaVariant::Xtea => CipherKind::Xtea,
                    },
                    key_hex: bytes_to_hex(&key),
                    key_len: key.len(),
                    provenance: KeyProvenance::Literal,
                    crib,
                },
                plaintext,
            });
        }
    }
    None
}

fn try_literal_xxtea(data: &[u8], candidates: &[Vec<u8>]) -> Option<CipherResult> {
    if !data.len().is_multiple_of(4) || data.len() < 8 {
        return None;
    }
    for key in key16_candidates(candidates) {
        let Ok(plaintext): Result<Vec<u8>, _> = xxtea_decrypt_bytes(data, &key) else {
            continue;
        };
        let Some(crib): Option<&'static str> = block_cipher_crib(&plaintext) else {
            continue;
        };
        if !plaintext_validates(&plaintext) {
            continue;
        }
        return Some(CipherResult {
            finding: KeyFinding {
                cipher: CipherKind::Xxtea,
                key_hex: bytes_to_hex(&key),
                key_len: key.len(),
                provenance: KeyProvenance::Literal,
                crib,
            },
            plaintext,
        });
    }
    None
}

fn try_literal_stream(data: &[u8], candidates: &[Vec<u8>]) -> Option<CipherResult> {
    let keys: Vec<[u8; STREAM_KEY_LEN]> = key32_candidates(candidates);
    if keys.is_empty() {
        return None;
    }
    let chacha_nonces: Vec<[u8; CHACHA_NONCE_LEN]> = nonce_candidates(candidates);
    let salsa_nonces: Vec<[u8; SALSA_NONCE_LEN]> = nonce_candidates(candidates);
    for key in &keys {
        for nonce in &chacha_nonces {
            for &counter in &STREAM_COUNTERS {
                let plaintext: Vec<u8> = chacha20_apply(data, key, nonce, counter as u32);
                if let Some(found) = stream_result(CipherKind::ChaCha20, key, plaintext) {
                    return Some(found);
                }
            }
        }
        for nonce in &salsa_nonces {
            for &counter in &STREAM_COUNTERS {
                let plaintext: Vec<u8> = salsa20_apply(data, key, *nonce, counter);
                if let Some(found) = stream_result(CipherKind::Salsa20, key, plaintext) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn stream_result(
    cipher: CipherKind,
    key: &[u8; STREAM_KEY_LEN],
    plaintext: Vec<u8>,
) -> Option<CipherResult> {
    let crib: &'static str = block_cipher_crib(&plaintext)?;
    if !plaintext_validates(&plaintext) {
        return None;
    }
    Some(CipherResult {
        finding: KeyFinding {
            cipher,
            key_hex: bytes_to_hex(key),
            key_len: key.len(),
            provenance: KeyProvenance::Literal,
            crib,
        },
        plaintext,
    })
}

#[inline]
fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y): (&u8, &u8)| (x ^ y).count_ones())
        .sum()
}

fn best_keylengths(data: &[u8]) -> Vec<usize> {
    let mut scored: Vec<(usize, f64)> = Vec::new();
    for keylen in 2..=MAX_REPEATING_KEYLEN.min(data.len() / (HAMMING_MIN_PAIRS + 1)) {
        let blocks: Vec<&[u8]> = data.chunks_exact(keylen).collect();
        if blocks.len() < HAMMING_MIN_PAIRS + 1 {
            continue;
        }
        let mut total: f64 = 0.0;
        let mut pairs: usize = 0;
        for window in blocks.windows(2) {
            total += f64::from(hamming(window[0], window[1])) / keylen as f64;
            pairs += 1;
        }
        if pairs == 0 {
            continue;
        }
        scored.push((keylen, total / pairs as f64));
    }
    scored.sort_by(|a: &(usize, f64), b: &(usize, f64)| {
        a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal)
    });
    scored.into_iter().take(3).map(|(l, _)| l).collect()
}

fn try_crib_derived_xor(data: &[u8]) -> Option<CipherResult> {
    for crib in CRIBS {
        let span: usize = crib.bytes.len();
        if span < 2 || data.len() < span {
            continue;
        }
        for keylen in 1..=span {
            let key: Vec<u8> = (0..keylen)
                .map(|i: usize| data[i] ^ crib.bytes[i])
                .collect();
            if periodic_key_consistent(data, &key, crib.bytes) {
                let plaintext: Vec<u8> = xor_apply(data, &key);
                if !plaintext_validates(&plaintext) {
                    continue;
                }
                return Some(CipherResult {
                    finding: KeyFinding {
                        cipher: if keylen == 1 {
                            CipherKind::XorSingle
                        } else {
                            CipherKind::XorMulti
                        },
                        key_hex: bytes_to_hex(&key),
                        key_len: keylen,
                        provenance: KeyProvenance::CribDerived,
                        crib: crib.name,
                    },
                    plaintext,
                });
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

const UTF16_MIN_UNITS: usize = 4;

fn utf16_text_validates(rest: &[u8], endian: Endian) -> bool {
    if rest.len() < UTF16_MIN_UNITS * 2 {
        return false;
    }
    let mut printable: usize = 0;
    let mut total: usize = 0;
    for pair in rest.chunks_exact(2) {
        let unit: u16 = match endian {
            Endian::Little => u16::from(pair[0]) | (u16::from(pair[1]) << 8),
            Endian::Big => u16::from(pair[1]) | (u16::from(pair[0]) << 8),
        };
        if (0xd800..=0xdfff).contains(&unit) {
            return false;
        }
        total += 1;
        if matches!(unit, 0x09 | 0x0a | 0x0d | 0x20..=0x7e) {
            printable += 1;
        }
    }
    total >= UTF16_MIN_UNITS && printable * 100 >= total * 90
}

fn plaintext_validates(plain: &[u8]) -> bool {
    match plain {
        [0x78, _, ..] => crate::codec::zlib_decompress(plain).is_ok(),
        [0x1f, 0x8b, 0x08, ..] => crate::codec::gzip_decompress(plain).is_ok(),
        [0x42, 0x5a, 0x68, ..] => crate::codec::bz2_decompress(plain).is_ok(),
        [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, ..] => crate::codec::lzma_decompress(plain).is_ok(),
        [0x5d, 0x00, 0x00, ..] => crate::codec::lzma_alone_decompress(plain).is_ok(),
        [0x4d, 0x5a, ..] => {
            plain.len() >= 64 && {
                let e_lfanew: u32 = u32::from_le_bytes(
                    plain
                        .get(60..64)
                        .and_then(|s: &[u8]| s.try_into().ok())
                        .unwrap_or([0; 4]),
                );
                (e_lfanew as usize) < plain.len().saturating_sub(4)
            }
        }
        [0x50, 0x4b, 0x03, 0x04, ..] => plain.len() >= 6 && plain[4] <= 63 && plain[5] == 0,
        [0x7f, 0x45, 0x4c, 0x46, ..] => {
            plain.len() >= 7
                && matches!(plain[4], 1 | 2)
                && matches!(plain[5], 1 | 2)
                && plain[6] == 1
        }
        [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ..] => {
            plain.len() >= 16
                && plain[8..12] == [0x00, 0x00, 0x00, 0x0D]
                && plain[12..16] == [0x49, 0x48, 0x44, 0x52]
        }
        [0xff, 0xfe, rest @ ..] => utf16_text_validates(rest, Endian::Little),
        [0xfe, 0xff, rest @ ..] => utf16_text_validates(rest, Endian::Big),
        [0x25, 0x50, 0x44, 0x46, ..] => {
            plain.len() >= 6 && plain[4] == b'-' && matches!(plain[5], b'1'..=b'2')
        }
        _ => true,
    }
}

fn periodic_key_consistent(data: &[u8], key: &[u8], crib: &[u8]) -> bool {
    if key.is_empty() {
        return false;
    }
    crib.iter()
        .enumerate()
        .all(|(i, &c): (usize, &u8)| i >= data.len() || data[i] ^ key[i % key.len()] == c)
}

fn try_keyless_repeating_xor(data: &[u8]) -> Option<CipherResult> {
    if let Some(found) = try_crib_derived_xor(data) {
        return Some(found);
    }
    for keylen in best_keylengths(data) {
        let Some(key): Option<Vec<u8>> = solve_repeating_columns(data, keylen) else {
            continue;
        };
        let probe_len: usize = data.len().min(6);
        let probe: Vec<u8> = data[..probe_len]
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
            .collect();
        let Some(crib): Option<&'static str> = matches_crib_at_zero(&probe, 2) else {
            continue;
        };
        let plaintext: Vec<u8> = xor_apply(data, &key);
        if !plaintext_validates(&plaintext) {
            continue;
        }
        return Some(CipherResult {
            finding: KeyFinding {
                cipher: CipherKind::XorMulti,
                key_hex: bytes_to_hex(&key),
                key_len: key.len(),
                provenance: KeyProvenance::CribDerived,
                crib,
            },
            plaintext,
        });
    }
    None
}

fn solve_repeating_columns(data: &[u8], keylen: usize) -> Option<Vec<u8>> {
    let mut key: Vec<u8> = Vec::with_capacity(keylen);
    for col in 0..keylen {
        let column: Vec<u8> = data.iter().skip(col).step_by(keylen).copied().collect();
        if column.is_empty() {
            return None;
        }
        let byte: u8 = best_single_byte_for_column(&column)?;
        key.push(byte);
    }
    Some(key)
}

fn best_single_byte_for_column(column: &[u8]) -> Option<u8> {
    let mut best: Option<(u8, u32)> = None;
    for k in 0u8..=255 {
        let score: u32 = column.iter().map(|c: &u8| printable_score(c ^ k)).sum();
        if best.is_none_or(|(_, s): (u8, u32)| score > s) {
            best = Some((k, score));
        }
    }
    best.map(|(k, _)| k)
}

#[inline]
const fn printable_score(b: u8) -> u32 {
    match b {
        b'a'..=b'z' | b'A'..=b'Z' | b' ' => 3,
        b'0'..=b'9' | b'\n' | b'.' | b',' | b'(' | b')' | b'_' | b':' | b'=' => 2,
        0x20..=0x7e => 1,
        _ => 0,
    }
}

pub(crate) fn try_decipher(data: &[u8], candidates: &[Vec<u8>]) -> Option<CipherResult> {
    try_decipher_keyed(data, candidates).or_else(|| try_decipher_keyless(data))
}

pub(crate) fn try_decipher_keyed(data: &[u8], candidates: &[Vec<u8>]) -> Option<CipherResult> {
    if data.len() < MIN_KEYED_INPUT {
        return None;
    }
    if let Some(found) = try_literal_xor(data, candidates) {
        return Some(found);
    }
    if let Some(found) = try_literal_rc4(data, candidates) {
        return Some(found);
    }
    if let Some(found) = try_literal_tea_family(data, candidates) {
        return Some(found);
    }
    if let Some(found) = try_literal_xxtea(data, candidates) {
        return Some(found);
    }
    try_literal_stream(data, candidates)
}

pub(crate) fn try_decipher_keyless(data: &[u8]) -> Option<CipherResult> {
    if data.len() < MIN_KEYED_INPUT {
        return None;
    }
    if let Some(found) = try_single_byte_xor(data) {
        return Some(found);
    }
    try_keyless_repeating_xor(data)
}

pub(crate) fn harvest_text_key_candidates(text: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    harvest_quoted(text, b'\'', &mut out);
    harvest_quoted(text, b'"', &mut out);
    harvest_fromhex(text, &mut out);
    dedup_and_rank(out)
}

fn harvest_quoted(text: &str, opener: u8, out: &mut Vec<Vec<u8>>) {
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] != opener {
            i += 1;
            continue;
        }
        let body_start: usize = i + 1;
        let mut j: usize = body_start;
        while j < bytes.len() {
            if bytes[j] == b'\\' {
                j += 2;
                continue;
            }
            if bytes[j] == opener {
                break;
            }
            j += 1;
        }
        if j <= bytes.len()
            && let Some(lit) = text.get(body_start..j)
        {
            let decoded: Vec<u8> =
                crate::codec::decode_python_bytes_literal(lit).unwrap_or_default();
            if !decoded.is_empty() {
                out.push(decoded);
            }
        }
        i = j + 1;
    }
}

fn harvest_fromhex(text: &str, out: &mut Vec<Vec<u8>>) {
    let mut from: usize = 0;
    while let Some(rel) = text.get(from..).and_then(|w: &str| w.find("fromhex(")) {
        let open: usize = from + rel + "fromhex(".len();
        let rest: &str = match text.get(open..) {
            Some(r) => r,
            None => break,
        };
        if let Some(hex) = first_quoted(rest)
            && let Ok(bytes) = crate::codec::b16_decode(hex.as_bytes())
            && !bytes.is_empty()
        {
            out.push(bytes);
        }
        from = open;
    }
}

fn first_quoted(text: &str) -> Option<&str> {
    let bytes: &[u8] = text.as_bytes();
    let start_rel: usize = bytes.iter().position(|&b: &u8| b == b'\'' || b == b'"')?;
    let opener: u8 = bytes[start_rel];
    let body_start: usize = start_rel + 1;
    let mut j: usize = body_start;
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            j += 2;
            continue;
        }
        if bytes[j] == opener {
            return text.get(body_start..j);
        }
        j += 1;
    }
    None
}

pub(crate) fn harvest_marshal_key_candidates(
    objects: impl IntoIterator<Item = Vec<u8>>,
) -> Vec<Vec<u8>> {
    dedup_and_rank(objects.into_iter().collect())
}

fn dedup_and_rank(mut candidates: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    candidates.retain(|c: &Vec<u8>| !c.is_empty() && c.len() <= 64);
    candidates.sort();
    candidates.dedup();
    candidates.sort_by_key(|c: &Vec<u8>| (preferred_len_rank(c.len()), c.len()));
    candidates.truncate(MAX_KEY_CANDIDATES);
    candidates
}

#[inline]
const fn preferred_len_rank(len: usize) -> u8 {
    match len {
        16 => 0,
        8 => 1,
        4..=6 => 2,
        24 | 32 => 3,
        _ => 4,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::codec::zlib_compress;

    #[test]
    fn rc4_known_vector() {
        let keystream: Vec<u8> = rc4_keystream(b"Key", 8);
        assert_eq!(
            keystream,
            vec![0xEB, 0x9F, 0x77, 0x81, 0xB7, 0x34, 0xCA, 0x72]
        );
    }

    #[test]
    fn single_byte_xor_recovers_via_crib() {
        let plain: Vec<u8> = zlib_compress(b"def f(): return 1\n");
        let key: u8 = 0x5e;
        let ct: Vec<u8> = plain.iter().map(|b: &u8| b ^ key).collect();
        let result: CipherResult = try_decipher(&ct, &[]).expect("single byte xor");
        assert_eq!(result.finding.cipher, CipherKind::XorSingle);
        assert_eq!(result.plaintext, plain);
    }

    #[test]
    fn multi_byte_xor_recovers_from_literal() {
        let plain: Vec<u8> = zlib_compress(b"class A:\n    pass\n");
        let key: &[u8] = b"sekret";
        let ct: Vec<u8> = xor_apply(&plain, key);
        let result: CipherResult = try_decipher(&ct, &[key.to_vec()]).expect("literal xor");
        assert_eq!(result.finding.cipher, CipherKind::XorMulti);
        assert_eq!(result.finding.provenance, KeyProvenance::Literal);
        assert_eq!(result.plaintext, plain);
    }

    #[test]
    fn rc4_recovers_from_literal() {
        let plain: Vec<u8> = zlib_compress(b"x = 1\ny = 2\nprint(x + y)\n");
        let key: &[u8] = b"hunter2key";
        let ct: Vec<u8> = rc4_apply(&plain, key);
        let result: CipherResult = try_decipher(&ct, &[key.to_vec()]).expect("rc4 literal");
        assert_eq!(result.finding.cipher, CipherKind::Rc4);
        assert_eq!(result.plaintext, plain);
    }

    #[test]
    fn clean_data_yields_no_cipher() {
        let plain: &[u8] = b"this is plain printable text with no cipher structure here";
        assert!(try_decipher(plain, &[]).is_none());
    }

    #[test]
    fn harvest_ranks_sixteen_byte_first() {
        let text: &str = "k = 'sixteenbytekey!!'\notherkey = 'abc'\n";
        let candidates: Vec<Vec<u8>> = harvest_text_key_candidates(text);
        assert_eq!(candidates.first().map(Vec::len), Some(16));
    }
}
