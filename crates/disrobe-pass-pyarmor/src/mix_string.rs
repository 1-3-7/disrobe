use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use disrobe_py_marshal::{CodeObject, Object};

pub(crate) fn decrypt_mix_strings(
    code: &mut Object,
    aes_key: &[u8; 16],
    mix_str_nonce: &[u8; 12],
) -> usize {
    let mut count: usize = 0usize;
    walk_object(code, aes_key, mix_str_nonce, &mut count);
    count
}

fn walk_object(obj: &mut Object, key: &[u8; 16], nonce: &[u8; 12], count: &mut usize) {
    match obj {
        Object::Code(co) => walk_code_object(co, key, nonce, count),
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for it in items {
                walk_object(it, key, nonce, count);
            }
        }
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (_, v) in d.iter_mut() {
                walk_object(v, key, nonce, count);
            }
        }
        Object::Bytes(bytes) => {
            if let Some(decrypted) = try_decrypt_mix_bytes(bytes, key, nonce) {
                *bytes = decrypted;
                *count += 1;
            }
        }
        Object::String { value, .. } => {
            let bytes_buf: Vec<u8> = value.as_bytes().to_vec();
            if let Some(decrypted) = try_decrypt_mix_bytes(&bytes_buf, key, nonce)
                && let Ok(s) = String::from_utf8(decrypted)
            {
                *value = s;
                *count += 1;
            }
        }
        _ => {}
    }
}

fn walk_code_object(co: &mut CodeObject, key: &[u8; 16], nonce: &[u8; 12], count: &mut usize) {
    for c in &mut co.consts {
        walk_object(c, key, nonce, count);
    }
    for n in &mut co.names {
        walk_object(n, key, nonce, count);
    }
    for n in &mut co.varnames {
        walk_object(n, key, nonce, count);
    }
    for n in &mut co.localsplusnames {
        walk_object(n, key, nonce, count);
    }
}

fn try_decrypt_mix_bytes(input: &[u8], key: &[u8; 16], nonce: &[u8; 12]) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    let head: u8 = input[0];
    if head & 0x80 == 0 {
        return None;
    }
    let low: u8 = head & 0x7F;
    if !(1..=4).contains(&low) {
        return None;
    }
    let body: &[u8] = &input[1..];
    if body.is_empty() {
        return None;
    }
    let mut iv: [u8; 16] = [0u8; 16];
    iv[..12].copy_from_slice(nonce);
    iv[15] = 2;
    let mut out: Vec<u8> = body.to_vec();
    let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(key.into(), &iv.into());
    cipher.apply_keystream(&mut out);
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ignores_non_mix_string() {
        let bytes: Vec<u8> = b"plain text".to_vec();
        let key: [u8; 16] = [0u8; 16];
        let nonce: [u8; 12] = [0u8; 12];
        assert!(try_decrypt_mix_bytes(&bytes, &key, &nonce).is_none());
    }

    #[test]
    fn detects_mix_tag_low_nibble_in_range() {
        let mut bytes: Vec<u8> = vec![0x81u8];
        bytes.extend_from_slice(b"x");
        let key: [u8; 16] = [0u8; 16];
        let nonce: [u8; 12] = [0u8; 12];
        assert!(try_decrypt_mix_bytes(&bytes, &key, &nonce).is_some());
    }

    #[test]
    fn rejects_invalid_low_nibble() {
        let bytes: Vec<u8> = vec![0x85u8, 0x00];
        let key: [u8; 16] = [0u8; 16];
        let nonce: [u8; 12] = [0u8; 12];
        assert!(try_decrypt_mix_bytes(&bytes, &key, &nonce).is_none());
    }
}
