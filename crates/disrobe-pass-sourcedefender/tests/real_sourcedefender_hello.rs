use disrobe_pass_sourcedefender::{
    DecryptedPye, DerivedKey, PyeCodePayload, PyeEnvelope, Result, decrypt_pye, derive_aes_key,
    hex_encode,
};

const REAL_PYE: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");

#[test]
fn kdf_known_answer_for_hello_basename() {
    let Ok(key): Result<DerivedKey> = derive_aes_key("hello") else {
        unreachable!("derive_aes_key failed")
    };
    assert_eq!(
        hex_encode(key.as_bytes()),
        "2e8ef91afe6da4abd8e665aaf2104d5027ccfbfdb1890da81b40bf628d7d8c98"
    );
}

#[test]
fn recovers_real_hello_pye_source() {
    let Ok(decrypted): Result<DecryptedPye> = decrypt_pye(REAL_PYE, "hello.pye") else {
        unreachable!("decrypt_pye failed on the real sample")
    };

    assert_eq!(
        decrypted.iv_hex, "310dbdb90f30b66ba95503502209b91d",
        "IV must decode via ascii85+zlib"
    );
    assert_eq!(
        decrypted.key_hex, "2e8ef91afe6da4abd8e665aaf2104d5027ccfbfdb1890da81b40bf628d7d8c98",
        "key must derive solely from the basename \"hello\""
    );

    let Some(envelope): Option<PyeEnvelope> = decrypted.envelope else {
        unreachable!("msgpack envelope must parse")
    };

    let PyeCodePayload::Source(ref code): PyeCodePayload = envelope.original_code else {
        unreachable!("free-version .pye must carry a source string under `code`")
    };

    assert_eq!(code.trim_end(), "print(\"Hello World!\")");
}
