use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use disrobe_py_marshal::{Object, PyVersion, load};

pub(crate) const CRYPT_BLOCK_SIZE: usize = 16;
const KEY_OBJECT_DEPTH: usize = 64;
const KEY_OBJECT_NODES: usize = 16_384;
const KEY_SCAN_VERSIONS: &[PyVersion] = &[
    PyVersion::PY10,
    PyVersion::PY11,
    PyVersion::PY13,
    PyVersion::PY14,
    PyVersion::PY15,
    PyVersion::PY16,
    PyVersion::PY20,
    PyVersion::PY21,
    PyVersion::PY22,
    PyVersion::PY23,
    PyVersion::PY24,
    PyVersion::PY25,
    PyVersion::PY26,
    PyVersion::PY27,
    PyVersion::PY30,
    PyVersion::PY31,
    PyVersion::PY32,
    PyVersion::PY33,
    PyVersion::PY34,
    PyVersion::PY35,
    PyVersion::PY36,
    PyVersion::PY37,
    PyVersion::PY38,
    PyVersion::PY39,
    PyVersion::PY310,
    PyVersion::PY311,
    PyVersion::PY312,
    PyVersion::PY313,
    PyVersion::PY314,
    PyVersion::PY315,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AesMode {
    Ctr,
    Cfb8,
}

#[must_use]
pub(crate) fn recover_key_from_module(body: &[u8], py_version: PyVersion) -> Option<[u8; 16]> {
    if let Some(key) = marshal_key_const_any_version(body, py_version) {
        return Some(key);
    }
    find_16byte_string_literal(body)
}

fn marshal_key_const_any_version(body: &[u8], py_version: PyVersion) -> Option<[u8; 16]> {
    if let Some(key) = marshal_key_const(body, py_version) {
        return Some(key);
    }
    for version in KEY_SCAN_VERSIONS {
        let version: PyVersion = *version;
        if version == py_version {
            continue;
        }
        if let Some(key) = marshal_key_const(body, version) {
            return Some(key);
        }
    }
    None
}

fn marshal_key_const(body: &[u8], py_version: PyVersion) -> Option<[u8; 16]> {
    let Ok(obj): disrobe_py_marshal::Result<Object> = load(body, py_version) else {
        return None;
    };
    let mut nodes: usize = KEY_OBJECT_NODES;
    key_from_object(&obj, 0, &mut nodes)
}

fn key_from_object(obj: &Object, depth: usize, nodes: &mut usize) -> Option<[u8; 16]> {
    if depth > KEY_OBJECT_DEPTH || *nodes == 0 {
        return None;
    }
    *nodes = nodes.saturating_sub(1);
    if let Some(key) = key_from_leaf(obj) {
        return Some(key);
    }
    let child_depth: usize = depth + 1;
    match obj {
        Object::Code(code) => key_from_code(code, child_depth, nodes),
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => key_from_objects(items, child_depth, nodes),
        Object::Dict(map) | Object::FrozenDict(map) => {
            for pair in map {
                let (key, value): (&Object, &Object) = pair;
                if let Some(candidate) = key_from_object(value, child_depth, nodes) {
                    return Some(candidate);
                }
                if let Some(candidate) = key_from_object(key, child_depth, nodes) {
                    return Some(candidate);
                }
            }
            None
        }
        Object::Slice { lower, upper, step } => key_from_object(lower, child_depth, nodes)
            .or_else(|| key_from_object(upper, child_depth, nodes))
            .or_else(|| key_from_object(step, child_depth, nodes)),
        _ => None,
    }
}

fn key_from_code(
    code: &disrobe_py_marshal::CodeObject,
    depth: usize,
    nodes: &mut usize,
) -> Option<[u8; 16]> {
    key_from_objects(&code.consts, depth, nodes)
        .or_else(|| key_from_objects(&code.names, depth, nodes))
        .or_else(|| key_from_objects(&code.varnames, depth, nodes))
        .or_else(|| key_from_objects(&code.freevars, depth, nodes))
        .or_else(|| key_from_objects(&code.cellvars, depth, nodes))
        .or_else(|| key_from_objects(&code.localsplusnames, depth, nodes))
        .or_else(|| key_from_object(&code.filename, depth, nodes))
        .or_else(|| key_from_object(&code.name, depth, nodes))
        .or_else(|| key_from_object(&code.qualname, depth, nodes))
}

fn key_from_objects(items: &[Object], depth: usize, nodes: &mut usize) -> Option<[u8; 16]> {
    for item in items {
        let item: &Object = item;
        if let Some(key) = key_from_object(item, depth, nodes) {
            return Some(key);
        }
    }
    None
}

fn key_from_leaf(obj: &Object) -> Option<[u8; 16]> {
    match obj {
        Object::Bytes(bytes) => bytes_16(bytes),
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => ascii_16(value),
        _ => None,
    }
}

const fn bytes_16(bytes: &[u8]) -> Option<[u8; 16]> {
    if bytes.len() != 16 {
        return None;
    }
    let mut out: [u8; 16] = [0u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

const fn ascii_16(text: &str) -> Option<[u8; 16]> {
    let bytes: &[u8] = text.as_bytes();
    if bytes.len() != 16 {
        return None;
    }
    let mut out: [u8; 16] = [0u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

#[must_use]
pub(crate) fn find_16byte_string_literal(blob: &[u8]) -> Option<[u8; 16]> {
    for window in blob.windows(18) {
        if matches!(window[0], b'\'' | b'"') && window[17] == window[0] {
            let tail: &[u8] = &window[1..17];
            if tail.iter().all(|b: &u8| b.is_ascii_graphic() || *b == b' ') {
                let mut out: [u8; 16] = [0u8; 16];
                out.copy_from_slice(tail);
                return Some(out);
            }
        }
    }
    None
}

#[must_use]
pub(crate) fn decrypt(raw: &[u8], key: &[u8; 16], mode: AesMode) -> Option<Vec<u8>> {
    if raw.len() < CRYPT_BLOCK_SIZE {
        return None;
    }
    let iv: [u8; 16] = raw[..CRYPT_BLOCK_SIZE].try_into().ok()?;
    let ct: &[u8] = &raw[CRYPT_BLOCK_SIZE..];
    match mode {
        AesMode::Ctr => Some(decrypt_ctr(ct, key, &iv)),
        AesMode::Cfb8 => Some(decrypt_cfb8(ct, key, &iv)),
    }
}

fn decrypt_ctr(ct: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let mut buf: Vec<u8> = ct.to_vec();
    let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(key.into(), iv.into());
    cipher.apply_keystream(&mut buf);
    buf
}

fn decrypt_cfb8(ct: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let cipher: Aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut shift: [u8; 16] = *iv;
    let mut out: Vec<u8> = Vec::with_capacity(ct.len());
    for &c in ct {
        let mut block: GenericArray<u8, _> = GenericArray::clone_from_slice(&shift);
        cipher.encrypt_block(&mut block);
        out.push(c ^ block[0]);
        shift.copy_within(1..16, 0);
        shift[15] = c;
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_py_marshal::{CodeObject, code_era_for, dump};
    use indexmap::IndexMap;

    #[test]
    fn ascii_16_requires_exact_length() {
        assert!(ascii_16("short").is_none());
        assert!(ascii_16("0123456789abcdefg").is_none());
        assert_eq!(ascii_16("0123456789abcdef"), Some(*b"0123456789abcdef"));
    }

    #[test]
    fn literal_scan_accepts_non_alphanumeric_key() {
        let symbol_key: &[u8; 16] = b"k3y!/sym-bols$#@";
        assert_eq!(symbol_key.len(), 16);
        let mut blob: Vec<u8> = b"prefix'".to_vec();
        blob.extend_from_slice(symbol_key);
        blob.extend_from_slice(b"'suffix");
        let key: [u8; 16] = find_16byte_string_literal(&blob).expect("symbol key located");
        assert_eq!(&key, symbol_key);
    }

    #[test]
    fn literal_scan_returns_none_without_quotes() {
        let blob: Vec<u8> = (b'a'..=b'p').collect();
        assert!(find_16byte_string_literal(&blob).is_none());
    }

    #[test]
    fn marshal_scan_recovers_nested_non_utf8_bytes_key() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x41, 0x42, 0x7f, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0xff,
        ];
        let version: PyVersion = PyVersion::PY312;
        let mut inner: CodeObject = CodeObject::new(code_era_for(version));
        inner.consts.push(Object::Bytes(key.to_vec()));
        let mut outer: CodeObject = CodeObject::new(code_era_for(version));
        outer.consts.push(Object::Code(Box::new(inner)));
        let body: Vec<u8> = dump(&Object::Code(Box::new(outer)), version).expect("dump code");
        assert_eq!(recover_key_from_module(&body, version), Some(key));
    }

    #[test]
    fn marshal_scan_recovers_key_from_root_dict_value() {
        let key: [u8; 16] = *b"dict-key-1234567";
        let mut globals: IndexMap<Object, Object> = IndexMap::new();
        globals.insert(
            Object::ShortAscii {
                value: "key".to_owned(),
                interned: false,
            },
            Object::Bytes(key.to_vec()),
        );
        let version: PyVersion = PyVersion::PY312;
        let body: Vec<u8> = dump(&Object::Dict(globals), version).expect("dump dict");
        assert_eq!(recover_key_from_module(&body, version), Some(key));
    }

    #[test]
    fn marshal_scan_tries_known_versions_after_hint_miss() {
        let key: [u8; 16] = *b"legacy-key-12345";
        let actual: PyVersion = PyVersion::PY27;
        let hinted: PyVersion = PyVersion::PY312;
        let mut code: CodeObject = CodeObject::new(code_era_for(actual));
        code.consts.push(Object::String {
            value: String::from_utf8_lossy(&key).into_owned(),
            interned: false,
        });
        let body: Vec<u8> = dump(&Object::Code(Box::new(code)), actual).expect("dump py27 code");
        assert_eq!(recover_key_from_module(&body, hinted), Some(key));
    }

    #[test]
    fn ctr_decrypt_inverts_ctr_encrypt() {
        let key: [u8; 16] = *b"MySecretKey12345";
        let iv: [u8; 16] = [7u8; 16];
        let plain: &[u8] = b"the quick brown fox jumps over the lazy dog 0123456789";
        let mut ct: Vec<u8> = plain.to_vec();
        let mut enc: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(&key.into(), &iv.into());
        enc.apply_keystream(&mut ct);
        let mut framed: Vec<u8> = iv.to_vec();
        framed.extend_from_slice(&ct);
        let out: Vec<u8> = decrypt(&framed, &key, AesMode::Ctr).expect("ctr decrypt");
        assert_eq!(out, plain);
    }

    #[test]
    fn cfb8_decrypt_inverts_cfb8_encrypt() {
        let key: [u8; 16] = *b"abcdefghijklmnop";
        let iv: [u8; 16] = [0x11u8; 16];
        let plain: &[u8] = b"cfb-8 segment feedback decryption round trip check";
        let ct: Vec<u8> = cfb8_encrypt_reference(plain, &key, &iv);
        let mut framed: Vec<u8> = iv.to_vec();
        framed.extend_from_slice(&ct);
        let out: Vec<u8> = decrypt(&framed, &key, AesMode::Cfb8).expect("cfb8 decrypt");
        assert_eq!(out, plain);
    }

    #[test]
    fn cfb8_matches_pycryptodome_known_answer_vector() {
        let key: [u8; 16] = *b"abcdefghijklmnop";
        let iv: [u8; 16] = [0x11u8; 16];
        let ct: [u8; 50] = [
            0x6d, 0xf0, 0x7d, 0x8c, 0x31, 0x35, 0xb4, 0x91, 0x39, 0x20, 0x2d, 0x96, 0x6e, 0x69,
            0x84, 0xf2, 0xcc, 0x14, 0xff, 0xea, 0x34, 0x82, 0xbe, 0x9c, 0x6e, 0xd1, 0x5d, 0x63,
            0x81, 0xde, 0xf4, 0xe0, 0xa7, 0x89, 0xa8, 0xc5, 0x53, 0x71, 0x23, 0x4d, 0x53, 0xb9,
            0x57, 0x2b, 0x11, 0xb9, 0xb5, 0x97, 0xe8, 0x6c,
        ];
        let mut framed: Vec<u8> = iv.to_vec();
        framed.extend_from_slice(&ct);
        let out: Vec<u8> = decrypt(&framed, &key, AesMode::Cfb8).expect("cfb8 decrypt");
        assert_eq!(
            out.as_slice(),
            b"cfb-8 segment feedback decryption round trip check",
            "our AES-CFB-8 must match PyCryptodome's default segment_size=8 output",
        );
    }

    #[test]
    fn decrypt_rejects_input_shorter_than_iv() {
        let key: [u8; 16] = [0u8; 16];
        assert!(decrypt(b"short", &key, AesMode::Ctr).is_none());
        assert!(decrypt(b"short", &key, AesMode::Cfb8).is_none());
    }

    fn cfb8_encrypt_reference(plain: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
        let cipher: Aes128 = Aes128::new(GenericArray::from_slice(key));
        let mut shift: [u8; 16] = *iv;
        let mut out: Vec<u8> = Vec::with_capacity(plain.len());
        for &p in plain {
            let mut block: GenericArray<u8, _> = GenericArray::clone_from_slice(&shift);
            cipher.encrypt_block(&mut block);
            let c: u8 = p ^ block[0];
            out.push(c);
            shift.copy_within(1..16, 0);
            shift[15] = c;
        }
        out
    }
}
