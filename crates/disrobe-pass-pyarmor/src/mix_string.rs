use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use disrobe_py_marshal::{CodeObject, Object};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MixStrGate {
    Marked,
    Unmarked,
}

pub(crate) fn decrypt_mix_strings(
    code: &mut Object,
    aes_key: &[u8; 16],
    mix_str_nonce: &[u8; 12],
    gate: MixStrGate,
) -> usize {
    let mut count: usize = 0usize;
    walk_object(code, aes_key, mix_str_nonce, gate, &mut count);
    count
}

fn walk_object(
    obj: &mut Object,
    key: &[u8; 16],
    nonce: &[u8; 12],
    gate: MixStrGate,
    count: &mut usize,
) {
    match obj {
        Object::Code(co) => walk_code_object(co, key, nonce, gate, count),
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for it in items {
                walk_object(it, key, nonce, gate, count);
            }
        }
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (_, v) in d.iter_mut() {
                walk_object(v, key, nonce, gate, count);
            }
        }
        Object::Bytes(bytes) => {
            if let Some(value) = decrypt_mix_text(bytes, key, nonce, gate) {
                *obj = Object::Unicode {
                    value,
                    interned: false,
                };
                *count += 1;
            }
        }
        _ => {}
    }
}

fn walk_code_object(
    co: &mut CodeObject,
    key: &[u8; 16],
    nonce: &[u8; 12],
    gate: MixStrGate,
    count: &mut usize,
) {
    for c in &mut co.consts {
        walk_object(c, key, nonce, gate, count);
    }
}

fn decrypt_mix_text(
    input: &[u8],
    key: &[u8; 16],
    nonce: &[u8; 12],
    gate: MixStrGate,
) -> Option<String> {
    let kind: u8 = input.first()? & 0x7F;
    let plain: Vec<u8> = try_decrypt_mix_bytes(input, key, nonce)?;
    let text: String = decode_unicode_kind(kind, &plain)?;
    (gate == MixStrGate::Marked || reads_as_text(&text)).then_some(text)
}

fn decode_unicode_kind(kind: u8, plain: &[u8]) -> Option<String> {
    match kind {
        1 => Some(plain.iter().map(|&b: &u8| char::from(b)).collect()),
        2 if plain.len().is_multiple_of(2) => char::decode_utf16(
            plain
                .chunks_exact(2)
                .map(|unit: &[u8]| u16::from_le_bytes([unit[0], unit[1]])),
        )
        .collect::<Result<String, _>>()
        .ok(),
        4 if plain.len().is_multiple_of(4) => plain
            .chunks_exact(4)
            .map(|unit: &[u8]| {
                char::from_u32(u32::from_le_bytes([unit[0], unit[1], unit[2], unit[3]]))
            })
            .collect::<Option<String>>(),
        _ => None,
    }
}

fn reads_as_text(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c: char| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
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

    fn mixed(kind: u8, plain: &[u8]) -> Vec<u8> {
        let mut tagged: Vec<u8> = vec![0x80 | kind];
        tagged.extend_from_slice(plain);
        let mut sealed: Vec<u8> = vec![0x80 | kind];
        sealed.extend(try_decrypt_mix_bytes(&tagged, &[7u8; 16], &[9u8; 12]).expect("seal"));
        sealed
    }

    fn rewrite(constant: Vec<u8>, gate: MixStrGate) -> Object {
        let mut co: CodeObject = CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
        co.consts.push(Object::Bytes(constant));
        let mut module: Object = Object::Code(Box::new(co));
        decrypt_mix_strings(&mut module, &[7u8; 16], &[9u8; 12], gate);
        let Object::Code(co) = module else {
            panic!("the module stays a code object");
        };
        co.consts.into_iter().next().expect("one constant")
    }

    #[test]
    fn an_unmarked_module_recovers_text_constants_as_str_by_kind() {
        let utf16: Vec<u8> = "héllo €"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        for (kind, plain, expected) in [
            (1u8, b"license ok".to_vec(), "license ok"),
            (2u8, utf16, "héllo €"),
            (
                4u8,
                "z😀"
                    .chars()
                    .flat_map(|c: char| u32::from(c).to_le_bytes())
                    .collect(),
                "z😀",
            ),
        ] {
            assert_eq!(
                rewrite(mixed(kind, &plain), MixStrGate::Unmarked),
                Object::Unicode {
                    value: expected.to_owned(),
                    interned: false
                }
            );
        }
    }

    #[test]
    fn an_unmarked_module_keeps_a_tagged_constant_that_does_not_decrypt_to_text() {
        let sealed: Vec<u8> = mixed(1, &[0x00, 0x01, 0x02, 0x1B]);
        assert_eq!(
            rewrite(sealed.clone(), MixStrGate::Unmarked),
            Object::Bytes(sealed.clone())
        );
        assert_eq!(
            rewrite(sealed, MixStrGate::Marked),
            Object::Unicode {
                value: "\u{0}\u{1}\u{2}\u{1b}".to_owned(),
                interned: false
            }
        );
    }

    #[test]
    fn identifier_tables_are_never_decrypted() {
        let mut co: CodeObject = CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
        let mixed_looking: Vec<u8> = vec![0x81, b'x', b'y'];
        co.names.push(Object::Bytes(mixed_looking.clone()));
        co.varnames.push(Object::Bytes(mixed_looking.clone()));
        let mut module: Object = Object::Code(Box::new(co));
        let rewritten: usize =
            decrypt_mix_strings(&mut module, &[0u8; 16], &[0u8; 12], MixStrGate::Marked);
        assert_eq!(rewritten, 0);
        let Object::Code(co) = module else {
            panic!("the module stays a code object");
        };
        assert_eq!(co.names, vec![Object::Bytes(mixed_looking.clone())]);
        assert_eq!(co.varnames, vec![Object::Bytes(mixed_looking)]);
    }
}
