use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use disrobe_pass_sourcedefender::{
    AES_IV_LEN, DecryptedPye, DerivedKey, InlinedExtractOptions, KeyCache, PYE_BEGIN_MARKER,
    PYE_END_MARKER, PyeCodePayload, PyeEnvelope, decrypt_pye, derive_aes_key, extract_inlined,
};

const REAL_HELLO_PYE: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");

const BASE85_ALPHABET: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

fn base85_encode_rfc1924(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 5 / 4 + 4);
    for chunk in bytes.chunks(4) {
        let mut buf: [u8; 4] = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        let acc: u32 = u32::from_be_bytes(buf);
        let take: usize = if chunk.len() == 4 { 5 } else { chunk.len() + 1 };
        push_base85_chunk(&mut out, acc, take);
    }
    out
}

fn push_base85_chunk(out: &mut String, mut acc: u32, take: usize) {
    let mut digits: [u8; 5] = [0u8; 5];
    for slot in digits.iter_mut().rev() {
        let rem: u8 = u8::try_from(acc % 85).unwrap_or(0);
        *slot = rem;
        acc /= 85;
    }
    for &d in digits.iter().take(take) {
        out.push(BASE85_ALPHABET[d as usize] as char);
    }
}

fn build_msgpack_payload(source: &str) -> Vec<u8> {
    let value: rmpv::Value = rmpv::Value::Map(vec![(
        rmpv::Value::String("original_code".into()),
        rmpv::Value::String(source.into()),
    )]);
    let mut out: Vec<u8> = Vec::new();
    if rmpv::encode::write_value(&mut out, &value).is_err() {
        return Vec::new();
    }
    out
}

fn encrypt_pye(source: &str, basename: &str, iv: [u8; AES_IV_LEN]) -> Option<String> {
    let key: DerivedKey = derive_aes_key(basename).ok()?;
    let mut payload: Vec<u8> = build_msgpack_payload(source);
    if payload.is_empty() {
        return None;
    }
    let mut cipher: Ctr128BE<Aes256> = Ctr128BE::<Aes256>::new(key.as_bytes().into(), &iv.into());
    cipher.apply_keystream(&mut payload);
    let iv_b85: String = base85_encode_rfc1924(&iv);
    let ct_b85: String = base85_encode_rfc1924(&payload);
    let mut wrapped: String = String::with_capacity(ct_b85.len() + iv_b85.len() + 128);
    wrapped.push_str("---");
    wrapped.push_str(PYE_BEGIN_MARKER);
    wrapped.push_str("---\n");
    wrapped.push_str(&iv_b85);
    wrapped.push('\n');
    for line in ct_b85.as_bytes().chunks(80) {
        if let Ok(s) = core::str::from_utf8(line) {
            wrapped.push_str(s);
        }
        wrapped.push('\n');
    }
    wrapped.push_str("---");
    wrapped.push_str(PYE_END_MARKER);
    wrapped.push_str("---");
    Some(wrapped)
}

#[test]
fn real_hello_pye_is_the_authoritative_decrypt_gate() {
    let Ok(decrypted): Result<DecryptedPye, _> = decrypt_pye(REAL_HELLO_PYE, "hello.pye") else {
        unreachable!(
            "the real sourcedefender hello.pye must decrypt; this is the gate, not the \
             self-encrypt round-trip"
        )
    };
    assert_eq!(
        decrypted.key_hex, "2e8ef91afe6da4abd8e665aaf2104d5027ccfbfdb1890da81b40bf628d7d8c98",
        "the basename-only KDF must reproduce the documented known answer for the real sample"
    );
    let Some(envelope): Option<PyeEnvelope> = decrypted.envelope else {
        unreachable!("the real sample carries a msgpack envelope")
    };
    let matched: bool = matches!(
        envelope.original_code,
        PyeCodePayload::Source(ref s) if s.trim_end() == "print(\"Hello World!\")"
    );
    assert!(
        matched,
        "the real .pye must recover its documented plaintext oracle; the self-encrypt tests below \
         only prove codec self-consistency and cannot substitute for this real-sample gate"
    );
}

#[test]
fn roundtrip_single_file_via_cache() {
    let source: &str = "def f():\n    return 42\n";
    let Some(pye): Option<String> = encrypt_pye(source, "mymod", [7u8; AES_IV_LEN]) else {
        unreachable!("encrypt_pye failed")
    };
    let mut cache: KeyCache = KeyCache::new();
    let Ok(decoded): Result<disrobe_pass_sourcedefender::DecryptedPye, _> =
        cache.decrypt(pye.as_bytes(), "mymod.pye")
    else {
        unreachable!("decrypt failed")
    };
    let Some(envelope): Option<disrobe_pass_sourcedefender::PyeEnvelope> = decoded.envelope else {
        unreachable!("envelope missing")
    };
    let matched: bool =
        matches!(envelope.original_code, PyeCodePayload::Source(ref s) if s == source);
    assert!(
        matched,
        "supplementary codec self-consistency: decrypt must invert our own encrypt; the \
         real-sample gate above is what proves interop with the genuine tool"
    );
    let stats: disrobe_pass_sourcedefender::KeyCacheStats = cache.stats();
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 0);
}

#[test]
fn roundtrip_batch_reuses_cached_key() {
    let Some(pye): Option<String> = encrypt_pye("x = 1\n", "shared", [1u8; AES_IV_LEN]) else {
        unreachable!("encrypt_pye failed")
    };
    let mut cache: KeyCache = KeyCache::new();
    for _ in 0..5 {
        let Ok(r): Result<disrobe_pass_sourcedefender::DecryptedPye, _> =
            cache.decrypt(pye.as_bytes(), "shared.pye")
        else {
            unreachable!("decrypt failed")
        };
        assert_eq!(r.filename, "shared.pye");
    }
    let stats: disrobe_pass_sourcedefender::KeyCacheStats = cache.stats();
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.hits, 4);
    assert_eq!(stats.misses, 1);
}

#[test]
fn roundtrip_two_modules_create_two_entries() {
    let Some(pye_a): Option<String> = encrypt_pye("a = 1\n", "alpha", [2u8; AES_IV_LEN]) else {
        unreachable!("encrypt a failed")
    };
    let Some(pye_b): Option<String> = encrypt_pye("b = 2\n", "beta", [3u8; AES_IV_LEN]) else {
        unreachable!("encrypt b failed")
    };
    let mut cache: KeyCache = KeyCache::new();
    assert!(cache.decrypt(pye_a.as_bytes(), "alpha.pye").is_ok());
    assert!(cache.decrypt(pye_b.as_bytes(), "beta.pye").is_ok());
    assert!(cache.decrypt(pye_a.as_bytes(), "alpha.pye").is_ok());
    let stats: disrobe_pass_sourcedefender::KeyCacheStats = cache.stats();
    assert_eq!(stats.entries, 2);
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.hits, 1);
}

#[test]
fn inlined_extractor_decrypts_two_blocks() {
    let Some(pye_a): Option<String> =
        encrypt_pye("def a(): return 1\n", "alpha", [4u8; AES_IV_LEN])
    else {
        unreachable!("encrypt a failed")
    };
    let Some(pye_b): Option<String> = encrypt_pye("def b(): return 2\n", "beta", [5u8; AES_IV_LEN])
    else {
        unreachable!("encrypt b failed")
    };
    let host: String = format!(
        "import sourcedefender\n__pye_name__ = \"alpha\"\n{pye_a}\n__pye_name__ = \"beta\"\n{pye_b}\n",
    );
    let Ok(extraction): Result<disrobe_pass_sourcedefender::InlinedExtraction, _> =
        extract_inlined(&host, "host.py", InlinedExtractOptions::default())
    else {
        unreachable!("extract_inlined failed")
    };
    assert_eq!(extraction.blocks.len(), 2);
    assert_eq!(extraction.decrypted.len(), 2);
    assert!(extraction.failures.is_empty());
    let names: Vec<&str> = extraction
        .decrypted
        .iter()
        .map(|d| d.filename.as_str())
        .collect();
    assert!(names.contains(&"alpha"));
    assert!(names.contains(&"beta"));
}

#[test]
fn derive_key_matches_cache_key() {
    let mut cache: KeyCache = KeyCache::new();
    let Ok(cached): Result<DerivedKey, _> = cache.get_or_derive("mymod.pye") else {
        unreachable!("get_or_derive failed")
    };
    let Ok(derived): Result<DerivedKey, _> = derive_aes_key("mymod") else {
        unreachable!("derive_aes_key failed")
    };
    assert_eq!(cached, derived);
}

const SELF_ENCRYPTED_PYE_REALMOD_SNAPSHOT: &str = concat!(
    "--BEGIN SOURCEDEFENDER FILE---\n",
    "009C61O)~M2nh-c3=Iws\n",
    "k}XZZb!3o7Or?{~Z83s4VGEZkN9*1sKx^+|4Q5hrV^0>%H(%+!Pc2BKkp\n",
    "---END SOURCEDEFENDER FILE----\n",
);

#[test]
fn decrypts_self_encrypted_realmod_snapshot_not_external_corpus() {
    let mut cache: KeyCache = KeyCache::new();
    let Ok(decoded): Result<disrobe_pass_sourcedefender::DecryptedPye, _> = cache.decrypt(
        SELF_ENCRYPTED_PYE_REALMOD_SNAPSHOT.as_bytes(),
        "realmod.pye",
    ) else {
        unreachable!("decrypt of self-encrypted snapshot failed")
    };
    assert_eq!(
        decoded.key_hex, "468c7f753ae3bb66b3527880bc1818a3d6ad2a54ba7982233a792707261cb8a3",
        "regression snapshot of our own derive_aes_key(\"realmod\"); self-generated, \
         NOT an upstream sourcedefender known-answer vector",
    );
    let Some(envelope): Option<disrobe_pass_sourcedefender::PyeEnvelope> = decoded.envelope else {
        unreachable!("envelope missing from self-encrypted snapshot")
    };
    let matched: bool = matches!(
        envelope.original_code,
        PyeCodePayload::Source(ref s) if s == "def greet():\n    return 'hi'\n"
    );
    assert!(
        matched,
        "crate must round-trip the exact source from a .pye it itself encrypted; \
         this proves codec self-consistency, not interop with the real sourcedefender tool",
    );
}
