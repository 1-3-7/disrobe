use sha2::{Digest, Sha256};

use crate::pyrandom::{MersenneTwister, words_from_be_bytes_le_order};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherOp {
    Xor,
    Perm,
    Rot,
}

fn keystream(key: &[u8], length: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(length + 32);
    let mut ctr: u64 = 0;
    while out.len() < length {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(key);
        hasher.update(ctr.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        ctr += 1;
    }
    out.truncate(length);
    out
}

pub(crate) fn stream_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    let ks: Vec<u8> = keystream(key, data.len());
    data.iter()
        .zip(ks.iter())
        .map(|(&a, &b): (&u8, &u8)| a ^ b)
        .collect()
}

fn make_perm(key: &[u8]) -> [u8; 256] {
    let digest: [u8; 32] = Sha256::digest(key).into();
    let words: Vec<u32> = words_from_be_bytes_le_order(&digest);
    let mut mt: MersenneTwister = MersenneTwister::from_u32_words_le(&words);
    let shuffled: Vec<u8> = mt.shuffle_range(256);
    let mut perm: [u8; 256] = [0u8; 256];
    perm.copy_from_slice(&shuffled);
    perm
}

pub(crate) fn perm_invert(data: &[u8], key: &[u8]) -> Vec<u8> {
    let perm: [u8; 256] = make_perm(key);
    let mut inv: [u8; 256] = [0u8; 256];
    for (i, &p) in perm.iter().enumerate() {
        inv[p as usize] = u8::try_from(i).unwrap_or(0);
    }
    data.iter().map(|&b: &u8| inv[b as usize]).collect()
}

#[inline]
const fn rot_left(b: u8, n: u32) -> u8 {
    let n: u32 = n & 7;
    if n == 0 { b } else { b.rotate_left(n) }
}

pub(crate) fn rot_invert(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let key_len: usize = key.len();
    data.iter()
        .enumerate()
        .map(|(i, &b): (usize, &u8)| {
            let shift: u32 = (0u32.wrapping_sub(u32::from(key[i % key_len]))) & 7;
            rot_left(b, shift)
        })
        .collect()
}

pub(crate) fn apply_inverse(op: CipherOp, data: &[u8], key: &[u8]) -> Vec<u8> {
    match op {
        CipherOp::Xor => stream_xor(data, key),
        CipherOp::Perm => perm_invert(data, key),
        CipherOp::Rot => rot_invert(data, key),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn keystream_matches_real_sha256_ctr() {
        let key: &[u8] = &[1u8, 2, 3, 4];
        let ks: Vec<u8> = keystream(key, 40);
        let mut expected: Sha256 = Sha256::new();
        expected.update(key);
        expected.update(0u64.to_be_bytes());
        let block0: [u8; 32] = expected.finalize().into();
        assert_eq!(&ks[..32], &block0[..]);
        assert_eq!(ks.len(), 40);
    }

    #[test]
    fn rot_invert_is_inverse_of_rot_apply() {
        let data: Vec<u8> = (0u8..=255).collect();
        let key: &[u8] = &[1u8, 3, 7, 2, 5];
        let forward: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, &b): (usize, &u8)| rot_left(b, u32::from(key[i % key.len()])))
            .collect();
        let back: Vec<u8> = rot_invert(&forward, key);
        assert_eq!(back, data);
    }

    #[test]
    fn perm_invert_is_inverse() {
        let key: &[u8] = b"a-real-permutation-key";
        let perm: [u8; 256] = make_perm(key);
        let data: Vec<u8> = (0u8..=255).collect();
        let forward: Vec<u8> = data.iter().map(|&b: &u8| perm[b as usize]).collect();
        let back: Vec<u8> = perm_invert(&forward, key);
        assert_eq!(back, data);
    }

    #[test]
    fn real_sample_chain_yields_zlib_then_marshal_header() {
        let payload_hex: &str = "3a0c82aeec6f2deb5feead0d8e5e88c0851e8f2c6903a5b77f83a303d80721964a9625f3a4532719b03cd53908c05f9253d770605b255c9aaf6d68269f4a6c04";
        let payload_head: Vec<u8> = (0..payload_hex.len())
            .step_by(2)
            .map(|i: usize| u8::from_str_radix(&payload_hex[i..i + 2], 16).expect("hex"))
            .collect();
        let perm_key: Vec<u8> =
            hex_to_bytes("6d431ef70085132618c95910cc21a56f73b68e3d82081fab46b703e4f35ce931391b");
        let after_perm: Vec<u8> = perm_invert(&payload_head, &perm_key);
        let xor_key: Vec<u8> = hex_to_bytes("4ffc9656e3c63c079e150022031ad9c09ea7c43f4ae13f");
        let after_xor: Vec<u8> = stream_xor(&after_perm, &xor_key);
        assert_eq!(
            &after_xor[..2],
            &[0x78, 0xda],
            "expected zlib best-compression header"
        );
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i: usize| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
}
