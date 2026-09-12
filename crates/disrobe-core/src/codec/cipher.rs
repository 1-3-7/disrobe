use super::DecodeError;

pub const TEA_DELTA: u32 = 0x9e37_79b9;

const TEA_ROUNDS: u32 = 32;
const SALSA_SIGMA: &[u8; 16] = b"expand 32-byte k";
const MAX_CIPHER_INPUT: usize = 1 << 26;

#[must_use]
const fn key_words(key: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
    ]
}

#[must_use]
pub fn tea_decrypt_block(block: [u32; 2], key: &[u8; 16]) -> [u32; 2] {
    let k: [u32; 4] = key_words(key);
    let [mut v0, mut v1]: [u32; 2] = block;
    let mut sum: u32 = TEA_DELTA.wrapping_mul(TEA_ROUNDS);
    for _ in 0..TEA_ROUNDS {
        v1 = v1.wrapping_sub(
            (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]),
        );
        v0 = v0.wrapping_sub(
            (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]),
        );
        sum = sum.wrapping_sub(TEA_DELTA);
    }
    [v0, v1]
}

#[must_use]
pub fn tea_encrypt_block(block: [u32; 2], key: &[u8; 16]) -> [u32; 2] {
    let k: [u32; 4] = key_words(key);
    let [mut v0, mut v1]: [u32; 2] = block;
    let mut sum: u32 = 0;
    for _ in 0..TEA_ROUNDS {
        sum = sum.wrapping_add(TEA_DELTA);
        v0 = v0.wrapping_add(
            (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]),
        );
        v1 = v1.wrapping_add(
            (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]),
        );
    }
    [v0, v1]
}

#[must_use]
pub fn xtea_decrypt_block(block: [u32; 2], key: &[u8; 16]) -> [u32; 2] {
    let k: [u32; 4] = key_words(key);
    let [mut v0, mut v1]: [u32; 2] = block;
    let mut sum: u32 = TEA_DELTA.wrapping_mul(TEA_ROUNDS);
    for _ in 0..TEA_ROUNDS {
        v1 = v1.wrapping_sub(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(k[((sum >> 11) & 3) as usize]),
        );
        sum = sum.wrapping_sub(TEA_DELTA);
        v0 = v0.wrapping_sub(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ sum.wrapping_add(k[(sum & 3) as usize]),
        );
    }
    [v0, v1]
}

#[must_use]
pub fn xtea_encrypt_block(block: [u32; 2], key: &[u8; 16]) -> [u32; 2] {
    let k: [u32; 4] = key_words(key);
    let [mut v0, mut v1]: [u32; 2] = block;
    let mut sum: u32 = 0;
    for _ in 0..TEA_ROUNDS {
        v0 = v0.wrapping_add(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ sum.wrapping_add(k[(sum & 3) as usize]),
        );
        sum = sum.wrapping_add(TEA_DELTA);
        v1 = v1.wrapping_add(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(k[((sum >> 11) & 3) as usize]),
        );
    }
    [v0, v1]
}

const fn xxtea_mx(sum: u32, y: u32, z: u32, p: u32, e: u32, key: &[u32; 4]) -> u32 {
    (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
        ^ (sum ^ y).wrapping_add(key[((p & 3) ^ e) as usize] ^ z)
}

#[allow(clippy::many_single_char_names)]
pub fn xxtea_decrypt(v: &mut [u32], key: &[u8; 16]) -> Result<(), DecodeError> {
    let n: usize = v.len();
    if n < 2 {
        return Err(DecodeError::BadLength { len: n });
    }
    let k: [u32; 4] = key_words(key);
    let rounds: u32 = 6 + 52 / n as u32;
    let mut sum: u32 = rounds.wrapping_mul(TEA_DELTA);
    let mut y: u32 = v[0];
    while sum != 0 {
        let e: u32 = (sum >> 2) & 3;
        let mut p: usize = n - 1;
        while p > 0 {
            let z: u32 = v[p - 1];
            v[p] = v[p].wrapping_sub(xxtea_mx(sum, y, z, p as u32, e, &k));
            y = v[p];
            p -= 1;
        }
        let z: u32 = v[n - 1];
        v[0] = v[0].wrapping_sub(xxtea_mx(sum, y, z, 0, e, &k));
        y = v[0];
        sum = sum.wrapping_sub(TEA_DELTA);
    }
    Ok(())
}

#[allow(clippy::many_single_char_names)]
pub fn xxtea_encrypt(v: &mut [u32], key: &[u8; 16]) -> Result<(), DecodeError> {
    let n: usize = v.len();
    if n < 2 {
        return Err(DecodeError::BadLength { len: n });
    }
    let k: [u32; 4] = key_words(key);
    let rounds: u32 = 6 + 52 / n as u32;
    let mut sum: u32 = 0;
    let mut z: u32 = v[n - 1];
    for _ in 0..rounds {
        sum = sum.wrapping_add(TEA_DELTA);
        let e: u32 = (sum >> 2) & 3;
        for p in 0..n - 1 {
            let y: u32 = v[p + 1];
            v[p] = v[p].wrapping_add(xxtea_mx(sum, y, z, p as u32, e, &k));
            z = v[p];
        }
        let y: u32 = v[0];
        v[n - 1] = v[n - 1].wrapping_add(xxtea_mx(sum, y, z, (n - 1) as u32, e, &k));
        z = v[n - 1];
    }
    Ok(())
}

fn words_from_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk: &[u8]| {
            let mut word: [u8; 4] = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(word)
        })
        .collect()
}

fn words_to_le(words: &[u32]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(words.len() * 4);
    for &word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

pub fn tea_family_decrypt_bytes(
    data: &[u8],
    key: &[u8; 16],
    variant: TeaVariant,
) -> Result<Vec<u8>, DecodeError> {
    if data.len() > MAX_CIPHER_INPUT {
        return Err(DecodeError::TooLarge { len: data.len() });
    }
    if !data.len().is_multiple_of(8) {
        return Err(DecodeError::BadLength { len: data.len() });
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let block: [u32; 2] = [
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        ];
        let plain: [u32; 2] = match variant {
            TeaVariant::Tea => tea_decrypt_block(block, key),
            TeaVariant::Xtea => xtea_decrypt_block(block, key),
        };
        out.extend_from_slice(&plain[0].to_le_bytes());
        out.extend_from_slice(&plain[1].to_le_bytes());
    }
    Ok(out)
}

pub fn xxtea_decrypt_bytes(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, DecodeError> {
    if data.len() > MAX_CIPHER_INPUT {
        return Err(DecodeError::TooLarge { len: data.len() });
    }
    if !data.len().is_multiple_of(4) {
        return Err(DecodeError::BadLength { len: data.len() });
    }
    let mut words: Vec<u32> = words_from_le(data);
    xxtea_decrypt(&mut words, key)?;
    Ok(words_to_le(&words))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeaVariant {
    Tea,
    Xtea,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCipher {
    Salsa20,
    ChaCha20,
}

#[allow(clippy::many_single_char_names)]
const fn quarter_round_chacha(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

#[allow(clippy::many_single_char_names)]
const fn quarter_round_salsa(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[b] ^= state[a].wrapping_add(state[d]).rotate_left(7);
    state[c] ^= state[b].wrapping_add(state[a]).rotate_left(9);
    state[d] ^= state[c].wrapping_add(state[b]).rotate_left(13);
    state[a] ^= state[d].wrapping_add(state[c]).rotate_left(18);
}

fn chacha20_block(state: &[u32; 16]) -> [u8; 64] {
    let mut working: [u32; 16] = *state;
    for _ in 0..10 {
        quarter_round_chacha(&mut working, 0, 4, 8, 12);
        quarter_round_chacha(&mut working, 1, 5, 9, 13);
        quarter_round_chacha(&mut working, 2, 6, 10, 14);
        quarter_round_chacha(&mut working, 3, 7, 11, 15);
        quarter_round_chacha(&mut working, 0, 5, 10, 15);
        quarter_round_chacha(&mut working, 1, 6, 11, 12);
        quarter_round_chacha(&mut working, 2, 7, 8, 13);
        quarter_round_chacha(&mut working, 3, 4, 9, 14);
    }
    let mut out: [u8; 64] = [0; 64];
    for (i, slot) in working.iter().enumerate() {
        let value: u32 = slot.wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    out
}

fn salsa20_block(state: &[u32; 16]) -> [u8; 64] {
    let mut working: [u32; 16] = *state;
    for _ in 0..10 {
        quarter_round_salsa(&mut working, 0, 4, 8, 12);
        quarter_round_salsa(&mut working, 5, 9, 13, 1);
        quarter_round_salsa(&mut working, 10, 14, 2, 6);
        quarter_round_salsa(&mut working, 15, 3, 7, 11);
        quarter_round_salsa(&mut working, 0, 1, 2, 3);
        quarter_round_salsa(&mut working, 5, 6, 7, 4);
        quarter_round_salsa(&mut working, 10, 11, 8, 9);
        quarter_round_salsa(&mut working, 15, 12, 13, 14);
    }
    let mut out: [u8; 64] = [0; 64];
    for (i, slot) in working.iter().enumerate() {
        let value: u32 = slot.wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    out
}

fn chacha20_state(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    let mut state: [u32; 16] = [0; 16];
    state[0] = u32::from_le_bytes([
        SALSA_SIGMA[0],
        SALSA_SIGMA[1],
        SALSA_SIGMA[2],
        SALSA_SIGMA[3],
    ]);
    state[1] = u32::from_le_bytes([
        SALSA_SIGMA[4],
        SALSA_SIGMA[5],
        SALSA_SIGMA[6],
        SALSA_SIGMA[7],
    ]);
    state[2] = u32::from_le_bytes([
        SALSA_SIGMA[8],
        SALSA_SIGMA[9],
        SALSA_SIGMA[10],
        SALSA_SIGMA[11],
    ]);
    state[3] = u32::from_le_bytes([
        SALSA_SIGMA[12],
        SALSA_SIGMA[13],
        SALSA_SIGMA[14],
        SALSA_SIGMA[15],
    ]);
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
    state
}

fn salsa20_state(key: &[u8; 32], nonce: [u8; 8], counter: u64) -> [u32; 16] {
    let word =
        |b: &[u8], i: usize| -> u32 { u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) };
    let mut state: [u32; 16] = [0; 16];
    state[0] = word(SALSA_SIGMA, 0);
    state[5] = word(SALSA_SIGMA, 4);
    state[10] = word(SALSA_SIGMA, 8);
    state[15] = word(SALSA_SIGMA, 12);
    for i in 0..4 {
        state[1 + i] = word(key, i * 4);
        state[11 + i] = word(key, 16 + i * 4);
    }
    state[6] = word(&nonce, 0);
    state[7] = word(&nonce, 4);
    state[8] = (counter & 0xffff_ffff) as u32;
    state[9] = (counter >> 32) as u32;
    state
}

#[must_use]
pub fn chacha20_apply(data: &[u8], key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    for (block_index, chunk) in data.chunks(64).enumerate() {
        let state: [u32; 16] = chacha20_state(key, nonce, counter.wrapping_add(block_index as u32));
        let keystream: [u8; 64] = chacha20_block(&state);
        for (i, &byte) in chunk.iter().enumerate() {
            out.push(byte ^ keystream[i]);
        }
    }
    out
}

#[must_use]
pub fn salsa20_apply(data: &[u8], key: &[u8; 32], nonce: [u8; 8], counter: u64) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    for (block_index, chunk) in data.chunks(64).enumerate() {
        let state: [u32; 16] = salsa20_state(key, nonce, counter.wrapping_add(block_index as u64));
        let keystream: [u8; 64] = salsa20_block(&state);
        for (i, &byte) in chunk.iter().enumerate() {
            out.push(byte ^ keystream[i]);
        }
    }
    out
}

#[must_use]
pub fn find_salsa_sigma(haystack: &[u8]) -> Option<usize> {
    haystack
        .windows(SALSA_SIGMA.len())
        .position(|window: &[u8]| window == SALSA_SIGMA)
}

#[must_use]
pub fn has_tea_delta(haystack: &[u8]) -> bool {
    let le: [u8; 4] = TEA_DELTA.to_le_bytes();
    let be: [u8; 4] = TEA_DELTA.to_be_bytes();
    haystack
        .windows(4)
        .any(|window: &[u8]| window == le || window == be)
}

const RC4_STATE_LEN: usize = 256;

#[must_use]
fn rc4_ksa(key: &[u8]) -> [u8; RC4_STATE_LEN] {
    let mut state: [u8; RC4_STATE_LEN] = [0; RC4_STATE_LEN];
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let key_len: usize = key.len();
    let mut j: u8 = 0;
    for i in 0..RC4_STATE_LEN {
        let key_byte: u8 = if key_len == 0 { 0 } else { key[i % key_len] };
        j = j.wrapping_add(state[i]).wrapping_add(key_byte);
        state.swap(i, j as usize);
    }
    state
}

#[derive(Debug, Clone)]
pub struct Rc4 {
    state: [u8; RC4_STATE_LEN],
    i: u8,
    j: u8,
}

impl Rc4 {
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self {
            state: rc4_ksa(key),
            i: 0,
            j: 0,
        }
    }

    #[must_use]
    pub const fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        let sum: u8 = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
        self.state[sum as usize]
    }

    #[must_use]
    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|&byte: &u8| byte ^ self.next_byte())
            .collect()
    }
}

#[must_use]
pub fn rc4_apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    Rc4::new(key).apply(data)
}

#[must_use]
pub fn rc4_keystream(key: &[u8], len: usize) -> Vec<u8> {
    let mut cipher: Rc4 = Rc4::new(key);
    (0..len).map(|_| cipher.next_byte()).collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    #[test]
    fn tea_block_roundtrip() {
        let plain: [u32; 2] = [0x0123_4567, 0x89ab_cdef];
        let cipher: [u32; 2] = tea_encrypt_block(plain, &KEY);
        assert_ne!(cipher, plain);
        assert_eq!(tea_decrypt_block(cipher, &KEY), plain);
    }

    #[test]
    fn xtea_block_roundtrip() {
        let plain: [u32; 2] = [0xdead_beef, 0xfeed_face];
        let cipher: [u32; 2] = xtea_encrypt_block(plain, &KEY);
        assert_ne!(cipher, plain);
        assert_eq!(xtea_decrypt_block(cipher, &KEY), plain);
    }

    #[test]
    fn xxtea_buffer_roundtrip() {
        let plain: &[u8] = b"XXTEA whole-message variable-length payload here.";
        let padded_len: usize = plain.len().div_ceil(4) * 4;
        let mut padded: Vec<u8> = plain.to_vec();
        padded.resize(padded_len, 0);
        let mut words: Vec<u32> = words_from_le(&padded);
        xxtea_encrypt(&mut words, &KEY).unwrap();
        let cipher: Vec<u8> = words_to_le(&words);
        let recovered: Vec<u8> = xxtea_decrypt_bytes(&cipher, &KEY).unwrap();
        assert_eq!(&recovered[..plain.len()], plain);
    }

    #[test]
    fn tea_family_bytes_roundtrip() {
        let plain: &[u8] = b"eight-byte-aligned secret block!";
        let cipher: Vec<u8> = {
            let mut out: Vec<u8> = Vec::new();
            for chunk in plain.chunks(8) {
                let block: [u32; 2] = [
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                    u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                ];
                let enc: [u32; 2] = tea_encrypt_block(block, &KEY);
                out.extend_from_slice(&enc[0].to_le_bytes());
                out.extend_from_slice(&enc[1].to_le_bytes());
            }
            out
        };
        let recovered: Vec<u8> = tea_family_decrypt_bytes(&cipher, &KEY, TeaVariant::Tea).unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn chacha20_rfc8439_keystream() {
        let key: [u8; 32] = (0u8..32).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let cipher: Vec<u8> = chacha20_apply(plaintext, &key, &nonce, 1);
        assert_eq!(&cipher[..3], &[0x6e, 0x2e, 0x35]);
        let recovered: Vec<u8> = chacha20_apply(&cipher, &key, &nonce, 1);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn salsa20_keystream_roundtrip() {
        let key: [u8; 32] = (0u8..32).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 8] = [0; 8];
        let plaintext: &[u8] = b"salsa20 symmetric stream cipher recovery payload abcdefgh";
        let cipher: Vec<u8> = salsa20_apply(plaintext, &key, nonce, 0);
        assert_ne!(cipher, plaintext);
        assert_eq!(salsa20_apply(&cipher, &key, nonce, 0), plaintext);
    }

    #[test]
    fn rc4_wikipedia_vector_key() {
        let out: Vec<u8> = rc4_apply(b"Key", b"Plaintext");
        assert_eq!(out, hex_bytes("BBF316E8D940AF0AD3"));
    }

    #[test]
    fn rc4_wikipedia_vector_wiki() {
        let out: Vec<u8> = rc4_apply(b"Wiki", b"pedia");
        assert_eq!(out, hex_bytes("1021BF0420"));
    }

    #[test]
    fn rc4_wikipedia_vector_secret() {
        let out: Vec<u8> = rc4_apply(b"Secret", b"Attack at dawn");
        assert_eq!(out, hex_bytes("45A01F645FC35B383552544B9BF5"));
    }

    #[test]
    fn rc4_apply_is_involutive() {
        let key: &[u8] = b"a shared stream cipher key";
        let plain: &[u8] = b"rc4 keystream xor is its own inverse when reapplied";
        let cipher: Vec<u8> = rc4_apply(key, plain);
        assert_ne!(cipher, plain);
        assert_eq!(rc4_apply(key, &cipher), plain);
    }

    #[test]
    fn rc4_keystream_matches_apply_against_zeroes() {
        let key: &[u8] = b"keystream-parity";
        let zeroes: Vec<u8> = vec![0u8; 32];
        assert_eq!(rc4_keystream(key, 32), rc4_apply(key, &zeroes));
    }

    #[test]
    fn rc4_struct_matches_free_functions() {
        let key: &[u8] = b"struct-vs-fn";
        let data: &[u8] = b"stateful rc4 struct application";
        let mut cipher: Rc4 = Rc4::new(key);
        assert_eq!(cipher.apply(data), rc4_apply(key, data));
    }

    #[test]
    fn rc4_empty_key_does_not_panic() {
        let out: Vec<u8> = rc4_apply(b"", b"degenerate key input");
        assert_eq!(out.len(), b"degenerate key input".len());
    }

    #[test]
    fn rc4_zero_length_data_yields_empty_output() {
        assert!(rc4_apply(b"Key", b"").is_empty());
        assert!(rc4_keystream(b"Key", 0).is_empty());
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i: usize| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex pair"))
            .collect()
    }

    #[test]
    fn fingerprints_detect_constants() {
        assert!(has_tea_delta(&TEA_DELTA.to_le_bytes()));
        assert!(has_tea_delta(&TEA_DELTA.to_be_bytes()));
        assert!(!has_tea_delta(b"no delta here at all yo"));
        assert_eq!(find_salsa_sigma(b"xxexpand 32-byte kyy"), Some(2));
        assert_eq!(find_salsa_sigma(b"nothing"), None);
    }
}
