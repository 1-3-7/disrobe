use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StageMethod {
    Base64,
    Xor,
    AesCbc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StageOutcome {
    Recovered,
    UnrecoveredRuntimeKey,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecryptedStage {
    pub method: StageMethod,
    pub outcome: StageOutcome,
    pub content: String,
}

const MIN_CIPHERTEXT: usize = 16;
const MAX_CIPHERTEXT: usize = 1 << 20;

#[must_use]
pub fn recover_stages(env: &BTreeMap<String, String>) -> Vec<DecryptedStage> {
    let mut out: Vec<DecryptedStage> = Vec::new();
    let key_text: Option<&String> =
        find_value(env, &["KEY", "XORKEY", "PASS", "PASSWORD", "SECRET"]);
    let iv_text: Option<&String> = find_value(env, &["IV", "NONCE"]);

    for value in env.values() {
        let trimmed: &str = value.trim();
        if trimmed.len() < MIN_CIPHERTEXT || trimmed.len() > MAX_CIPHERTEXT {
            continue;
        }
        let Some(cipher_bytes): Option<Vec<u8>> = decode_base64(trimmed) else {
            continue;
        };

        if let Some(key) = key_text {
            if let Some(aes) = try_aes_cbc(&cipher_bytes, key, iv_text) {
                push_unique(&mut out, aes);
                continue;
            }
            for key_candidate in key_material_candidates(key) {
                if let Some(xor) = try_xor(&cipher_bytes, &key_candidate) {
                    push_unique(&mut out, xor);
                    break;
                }
            }
        }
    }
    out
}

fn find_value<'a>(env: &'a BTreeMap<String, String>, names: &[&str]) -> Option<&'a String> {
    names
        .iter()
        .find_map(|n: &&str| env.get(&n.to_ascii_uppercase()))
}

fn decode_base64(s: &str) -> Option<Vec<u8>> {
    if !s
        .bytes()
        .all(|b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return None;
    }
    let core: &str = s.trim_end_matches('=');
    let mut padded: String = core.to_owned();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    B64_STANDARD.decode(&padded).ok()
}

fn try_xor(cipher: &[u8], key: &[u8]) -> Option<DecryptedStage> {
    if key.is_empty() {
        return None;
    }
    let plain: Vec<u8> = cipher
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect();
    let text: String = printable(&plain)?;
    Some(DecryptedStage {
        method: StageMethod::Xor,
        outcome: StageOutcome::Recovered,
        content: text,
    })
}

fn try_aes_cbc(cipher: &[u8], key_raw: &str, iv_text: Option<&String>) -> Option<DecryptedStage> {
    if cipher.is_empty() || !cipher.len().is_multiple_of(16) {
        return None;
    }
    let iv_raw: &String = iv_text?;
    let iv_candidates: Vec<Vec<u8>> = key_material_candidates(iv_raw)
        .into_iter()
        .filter(|iv: &Vec<u8>| iv.len() == 16)
        .collect();
    if iv_candidates.is_empty() {
        return None;
    }
    for key in key_material_candidates(key_raw) {
        if !matches!(key.len(), 16 | 24 | 32) {
            continue;
        }
        for iv in &iv_candidates {
            if let Some(plain) = aes_cbc_decrypt(cipher, &key, iv)
                && let Some(text) = printable(&plain)
            {
                return Some(DecryptedStage {
                    method: StageMethod::AesCbc,
                    outcome: StageOutcome::Recovered,
                    content: text,
                });
            }
        }
    }
    None
}

fn aes_cbc_decrypt(cipher: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

    let mut buf: Vec<u8> = cipher.to_vec();
    let plain: Vec<u8> = match key.len() {
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?
            .to_vec(),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?
            .to_vec(),
        32 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?
            .to_vec(),
        _ => return None,
    };
    Some(plain)
}

fn key_material_candidates(raw: &str) -> Vec<Vec<u8>> {
    let trimmed: &str = raw.trim();
    let mut out: Vec<Vec<u8>> = Vec::new();
    let ascii: Vec<u8> = trimmed.as_bytes().to_vec();
    if matches!(ascii.len(), 16 | 24 | 32) {
        out.push(ascii.clone());
    }
    if let Some(hex) = decode_hex(trimmed)
        && !out.contains(&hex)
    {
        out.push(hex);
    }
    if let Some(b64) = decode_base64(trimmed)
        && matches!(b64.len(), 16 | 24 | 32)
        && !out.contains(&b64)
    {
        out.push(b64);
    }
    if out.is_empty() {
        out.push(ascii);
    }
    out
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() < 2 || !s.len().is_multiple_of(2) || !s.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len() / 2);
    let mut i: usize = 0;
    while i < bytes.len() {
        let hi: u8 = hex_val(bytes[i])?;
        let lo: u8 = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn printable(bytes: &[u8]) -> Option<String> {
    let text: &str = core::str::from_utf8(bytes).ok()?;
    let total: usize = text.chars().count();
    if total == 0 {
        return None;
    }
    let good: usize = text
        .chars()
        .filter(|c: &char| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    if good as f64 / total as f64 >= 0.85 {
        Some(text.to_owned())
    } else {
        None
    }
}

fn push_unique(out: &mut Vec<DecryptedStage>, stage: DecryptedStage) {
    if !out
        .iter()
        .any(|s: &DecryptedStage| s.method == stage.method && s.content == stage.content)
    {
        out.push(stage);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v): &(&str, &str)| (k.to_ascii_uppercase(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn recovers_xor_stage_with_literal_key() {
        let key: &[u8] = b"sekret";
        let plain: &str = "echo http://stage2.example.com";
        let cipher: Vec<u8> = plain
            .bytes()
            .enumerate()
            .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
            .collect();
        let b64: String = B64_STANDARD.encode(&cipher);
        let env: BTreeMap<String, String> = env_of(&[("XORKEY", "sekret"), ("BLOB", &b64)]);
        let stages: Vec<DecryptedStage> = recover_stages(&env);
        assert!(
            stages
                .iter()
                .any(|s: &DecryptedStage| s.method == StageMethod::Xor
                    && s.content.contains("stage2.example.com")),
            "{stages:?}"
        );
    }

    #[test]
    fn recovers_aes_cbc_stage_with_literal_key_iv() {
        use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
        let key: [u8; 16] = *b"0123456789abcdef";
        let iv: [u8; 16] = *b"fedcba9876543210";
        let plain: &[u8] = b"start calc.exe from stage two";
        let mut buf: Vec<u8> = vec![0u8; plain.len() + 16];
        let ct_len: usize = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .expect("enc")
            .encrypt_padded_b2b_mut::<Pkcs7>(plain, &mut buf)
            .expect("pad")
            .len();
        buf.truncate(ct_len);
        let b64: String = B64_STANDARD.encode(&buf);
        let env: BTreeMap<String, String> = env_of(&[
            ("KEY", "0123456789abcdef"),
            ("IV", "fedcba9876543210"),
            ("DATA", &b64),
        ]);
        let stages: Vec<DecryptedStage> = recover_stages(&env);
        assert!(
            stages
                .iter()
                .any(|s: &DecryptedStage| s.method == StageMethod::AesCbc
                    && s.content.contains("calc.exe")),
            "{stages:?}"
        );
    }

    #[test]
    fn no_key_yields_no_stage() {
        let plain: &str = "echo hello";
        let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ 0x5A).collect();
        let b64: String = B64_STANDARD.encode(&cipher);
        let env: BTreeMap<String, String> = env_of(&[("BLOB", &b64)]);
        let stages: Vec<DecryptedStage> = recover_stages(&env);
        assert!(
            stages.is_empty(),
            "no literal key must mean no recovery: {stages:?}"
        );
    }
}
