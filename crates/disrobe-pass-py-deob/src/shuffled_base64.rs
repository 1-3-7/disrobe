use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

use crate::cipher::{crib_magics, validated_crib};

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const MIN_TOKEN_CHARS: usize = 16;
const MAX_TOKEN_CHARS: usize = 8 * 1024 * 1024;

const PE_DOS_STUB_ANCHOR: &[u8] = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

struct Anchor {
    name: &'static str,
    bytes: &'static [u8],
}

const LONG_ANCHORS: [Anchor; 1] = [Anchor {
    name: "pe-mz",
    bytes: PE_DOS_STUB_ANCHOR,
}];

#[derive(Debug, Clone)]
pub(crate) struct ShuffledBase64Recovery {
    pub alphabet: [Option<u8>; 64],
    pub recovered_symbols: usize,
    pub plaintext: Vec<u8>,
    pub crib: &'static str,
}

impl ShuffledBase64Recovery {
    pub(crate) fn alphabet_string(&self) -> String {
        self.alphabet
            .iter()
            .map(|slot: &Option<u8>| slot.map_or('?', |b: u8| b as char))
            .collect()
    }
}

pub(crate) fn recover(token: &[u8]) -> Option<ShuffledBase64Recovery> {
    let cleaned: Vec<u8> = token
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    if cleaned.len() < MIN_TOKEN_CHARS || cleaned.len() > MAX_TOKEN_CHARS {
        return None;
    }
    if !cleaned.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    if let Some(found) = decode_with_known_alphabet(&cleaned, STANDARD_ALPHABET) {
        return Some(found);
    }
    if let Some(found) = decode_with_known_alphabet(&cleaned, URL_SAFE_ALPHABET) {
        return Some(found);
    }
    recover_permuted(&cleaned)
}

fn decode_with_known_alphabet(token: &[u8], alphabet: &[u8; 64]) -> Option<ShuffledBase64Recovery> {
    let engine: base64::engine::GeneralPurpose = if alphabet == STANDARD_ALPHABET {
        STANDARD_NO_PAD
    } else {
        URL_SAFE_NO_PAD
    };
    let decoded: Vec<u8> = engine.decode(token).ok()?;
    let crib: &'static str = validated_crib(&decoded)?;
    let resolved: [Option<u8>; 64] = core::array::from_fn(|i: usize| Some(alphabet[i]));
    Some(ShuffledBase64Recovery {
        alphabet: resolved,
        recovered_symbols: 64,
        plaintext: decoded,
        crib,
    })
}

fn recover_permuted(token: &[u8]) -> Option<ShuffledBase64Recovery> {
    for anchor in &LONG_ANCHORS {
        if let Some(recovery) = solve_for_crib(token, anchor.bytes, anchor.name) {
            return Some(recovery);
        }
    }
    for (crib_name, magic) in crib_magics() {
        if magic.len() < 2 {
            continue;
        }
        let Some(recovery) = solve_for_crib(token, magic, crib_name) else {
            continue;
        };
        return Some(recovery);
    }
    None
}

fn solve_for_crib(
    token: &[u8],
    magic: &[u8],
    crib_name: &'static str,
) -> Option<ShuffledBase64Recovery> {
    let mut sym_to_idx: [i16; 256] = [-1; 256];
    let mut idx_used: [bool; 64] = [false; 64];
    let pinned_indices: usize = magic.len() * 8 / 6;
    if token.len() < pinned_indices {
        return None;
    }
    for (position, &symbol) in token.iter().enumerate().take(pinned_indices) {
        let value: usize = usize::from(sextet_from_plaintext(magic, position));
        let slot: i16 = sym_to_idx[symbol as usize];
        if slot < 0 {
            if idx_used[value] {
                return None;
            }
            sym_to_idx[symbol as usize] = value as i16;
            idx_used[value] = true;
        } else if slot != value as i16 {
            return None;
        }
    }
    let all_pinned: bool = token
        .iter()
        .all(|&symbol: &u8| sym_to_idx[symbol as usize] >= 0);
    if !all_pinned {
        return None;
    }
    let decoded: Vec<u8> = decode_with_table(token, &sym_to_idx)?;
    let crib: &'static str = validated_crib(&decoded)?;
    if crib != crib_name {
        return None;
    }
    let (alphabet, recovered_symbols): ([Option<u8>; 64], usize) =
        materialize_alphabet(&sym_to_idx)?;
    Some(ShuffledBase64Recovery {
        alphabet,
        recovered_symbols,
        plaintext: decoded,
        crib,
    })
}

fn sextet_from_plaintext(plain: &[u8], position: usize) -> u8 {
    let bit_offset: usize = position * 6;
    let mut value: u8 = 0;
    for bit in 0..6 {
        let global_bit: usize = bit_offset + bit;
        let byte_index: usize = global_bit / 8;
        let in_byte: usize = 7 - (global_bit % 8);
        let bit_value: u8 = plain.get(byte_index).map_or(0, |b: &u8| (b >> in_byte) & 1);
        value = (value << 1) | bit_value;
    }
    value
}

fn decode_with_table(token: &[u8], sym_to_idx: &[i16; 256]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(token.len() * 3 / 4 + 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &symbol in token {
        let value: i16 = sym_to_idx[symbol as usize];
        if value < 0 {
            return None;
        }
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Some(out)
}

fn materialize_alphabet(sym_to_idx: &[i16; 256]) -> Option<([Option<u8>; 64], usize)> {
    let mut alphabet: [Option<u8>; 64] = [None; 64];
    let mut recovered: usize = 0;
    for symbol in 0u16..256 {
        let value: i16 = sym_to_idx[symbol as usize];
        if value < 0 {
            continue;
        }
        let index: usize = value as usize;
        if alphabet[index].is_some() {
            return None;
        }
        alphabet[index] = Some(symbol as u8);
        recovered += 1;
    }
    if recovered == 0 {
        return None;
    }
    Some((alphabet, recovered))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn shuffle_alphabet(seed: u64) -> [u8; 64] {
        let mut alphabet: [u8; 64] = *STANDARD_ALPHABET;
        let mut state: u64 = seed;
        for i in (1..64).rev() {
            state = state
                .wrapping_mul(0x5851_f42d_4c95_7f2d)
                .wrapping_add(0x1405_7b7e_f767_814f);
            let j: usize = (state >> 33) as usize % (i + 1);
            alphabet.swap(i, j);
        }
        alphabet
    }

    fn encode_with_alphabet(data: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(data.len() * 4 / 3 + 4);
        let mut accumulator: u32 = 0;
        let mut bits: u32 = 0;
        for &byte in data {
            accumulator = (accumulator << 8) | u32::from(byte);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let index: usize = ((accumulator >> bits) & 0x3f) as usize;
                out.push(alphabet[index]);
            }
        }
        if bits > 0 {
            let index: usize = ((accumulator << (6 - bits)) & 0x3f) as usize;
            out.push(alphabet[index]);
        }
        out
    }

    fn anchor_covered_pe() -> Vec<u8> {
        let mut blob: Vec<u8> = PE_DOS_STUB_ANCHOR.to_vec();
        blob.extend_from_slice(&[0u8; 384]);
        blob
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let alphabet: [u8; 64] = shuffle_alphabet(0x1234_5678_9abc_def0);
        let mut sorted: Vec<u8> = alphabet.to_vec();
        sorted.sort_unstable();
        let mut standard_sorted: Vec<u8> = STANDARD_ALPHABET.to_vec();
        standard_sorted.sort_unstable();
        assert_eq!(sorted, standard_sorted);
        assert_ne!(alphabet, *STANDARD_ALPHABET);
    }

    #[test]
    fn permuted_anchor_decode_equals_original() {
        let original: Vec<u8> = anchor_covered_pe();
        let alphabet: [u8; 64] = shuffle_alphabet(0xa5a5_5a5a_dead_c0de);
        let encoded: Vec<u8> = encode_with_alphabet(&original, &alphabet);
        let standard: Vec<u8> = encode_with_alphabet(&original, STANDARD_ALPHABET);
        assert_ne!(encoded, standard);

        let recovery: ShuffledBase64Recovery = recover(&encoded).expect("recover");
        assert_eq!(
            recovery.plaintext, original,
            "byte-exact plaintext recovery"
        );
        assert_eq!(recovery.crib, "pe-mz");
        for (index, slot) in recovery.alphabet.iter().enumerate() {
            if let Some(symbol) = slot {
                assert_eq!(*symbol, alphabet[index], "alphabet slot {index} must match");
            }
        }
        assert!(recovery.recovered_symbols >= 1);
    }

    #[test]
    fn random_token_without_crib_is_rejected() {
        let mut blob: Vec<u8> = Vec::with_capacity(128);
        let mut state: u64 = 0x1357_9bdf_2468_ace0;
        for _ in 0..128 {
            state = state
                .wrapping_mul(0x5851_f42d_4c95_7f2d)
                .wrapping_add(0x1405_7b7e_f767_814f);
            blob.push((state >> 33) as u8);
        }
        let alphabet: [u8; 64] = shuffle_alphabet(0xfeed_face_0bad_f00d);
        let encoded: Vec<u8> = encode_with_alphabet(&blob, &alphabet);
        assert!(
            recover(&encoded).is_none(),
            "random non-crib payload must not yield a recovery"
        );
    }
}
