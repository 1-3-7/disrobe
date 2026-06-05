#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use disrobe_pass_php::key_extractor::{AesOutcome, aes_cbc_decrypt};
use disrobe_pass_php::{EncoderFamily, KeyProvenance, KeyScan, scan_key, xor_decrypt};

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[test]
fn ioncube_key_is_honestly_loader_derived_not_recovered() {
    let mut envelope: Vec<u8> = b"<?php //004F\n".to_vec();
    envelope.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\nMIIBdummyblob\n");
    envelope.extend_from_slice(&[0xAAu8; 64]);
    let scan: KeyScan = scan_key(&envelope, EncoderFamily::IonCube);
    assert_eq!(scan.provenance, KeyProvenance::LoaderDerivedRsa);
    assert!(
        scan.key.is_empty(),
        "ionCube symmetric key must NOT be fabricated"
    );
    assert!(
        scan.key_offset.is_some(),
        "RSA blob offset should be located"
    );
}

#[test]
fn sourceguardian_aes_table_located_but_session_key_runtime() {
    let mut envelope: Vec<u8> = b"<?php\n//SGV2.0\n".to_vec();
    envelope.extend_from_slice(&AES_SBOX);
    envelope.extend_from_slice(&[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]);
    envelope.extend_from_slice(&[0x99u8; 32]);
    let scan: KeyScan = scan_key(&envelope, EncoderFamily::SourceGuardian);
    assert_eq!(scan.provenance, KeyProvenance::RuntimeDerived);
    assert!(
        scan.key.is_empty(),
        "SG session key is runtime-derived, never fabricated"
    );
    assert!(scan.key_offset.is_some(), "AES S-box should be located");
    assert!(scan.note.contains("runtime"));
}

#[test]
fn sourceguardian_without_aes_table_reports_no_static_material() {
    let envelope: &[u8] = b"<?php\n//SGV1.0 no crypto table here at all";
    let scan: KeyScan = scan_key(envelope, EncoderFamily::SourceGuardian);
    assert_eq!(scan.provenance, KeyProvenance::RuntimeDerived);
    assert!(scan.key_offset.is_none());
}

#[test]
fn zend_guard_legacy_xor_key_is_statically_recovered() {
    let key: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67];
    let plaintext: &[u8] = b"<?php echo 'zend guard recovered';";
    let mut envelope: Vec<u8> = b"<?php @Zend;\n".to_vec();
    envelope.push(b'3');
    envelope.push(0x00);
    envelope.extend_from_slice(&key);
    let cipher: Vec<u8> = xor_decrypt(plaintext, &key);
    envelope.extend_from_slice(&cipher);

    let scan: KeyScan = scan_key(&envelope, EncoderFamily::ZendGuard);
    assert_eq!(scan.provenance, KeyProvenance::StaticEmbedded);
    assert_eq!(scan.key, key.to_vec(), "XOR key must be recovered verbatim");

    let cipher_start: usize = scan.key_offset.unwrap() + key.len();
    let recovered: Vec<u8> = xor_decrypt(&envelope[cipher_start..], &scan.key);
    assert_eq!(recovered, plaintext, "XOR roundtrip must recover plaintext");
}

#[test]
fn zend_guard_modern_without_static_header_is_runtime() {
    let envelope: &[u8] = b"<?php @Zend;\n9\x00 modern build with integrity";
    let scan: KeyScan = scan_key(envelope, EncoderFamily::ZendGuard);
    assert_eq!(scan.provenance, KeyProvenance::RuntimeDerived);
    assert!(scan.key.is_empty());
}

#[test]
fn aes_cbc_decrypt_roundtrips_with_known_key() {
    use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    let key: [u8; 16] = *b"0123456789abcdef";
    let iv: [u8; 16] = *b"fedcba9876543210";
    let plaintext: &[u8] = b"<?php function decoded() { return 42; }";

    let mut buf: Vec<u8> = vec![0u8; plaintext.len() + 16];
    let ct_len: usize = {
        let enc = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv).unwrap();
        enc.encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len()
    };
    buf.truncate(ct_len);

    let outcome: AesOutcome = aes_cbc_decrypt(&buf, &key, &iv);
    match outcome {
        AesOutcome::Plaintext(p) => assert_eq!(p, plaintext),
        other => panic!("expected plaintext, got {other:?}"),
    }
}

#[test]
fn aes_cbc_wrong_key_is_padding_error_not_panic() {
    use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    let key: [u8; 16] = *b"0123456789abcdef";
    let iv: [u8; 16] = *b"fedcba9876543210";
    let plaintext: &[u8] = b"sensitive payload bytes here";
    let mut buf: Vec<u8> = vec![0u8; plaintext.len() + 16];
    let ct_len: usize = {
        let enc = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv).unwrap();
        enc.encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len()
    };
    buf.truncate(ct_len);

    let wrong_key: [u8; 16] = *b"WRONGWRONGWRONGW";
    let outcome: AesOutcome = aes_cbc_decrypt(&buf, &wrong_key, &iv);
    assert!(
        matches!(outcome, AesOutcome::PaddingError | AesOutcome::Plaintext(_)),
        "wrong key must not panic; got {outcome:?}"
    );
}

#[test]
fn aes_cbc_bad_input_lengths_are_rejected() {
    assert_eq!(
        aes_cbc_decrypt(b"short", b"0123456789abcdef", b"fedcba9876543210"),
        AesOutcome::BadInput
    );
    assert_eq!(
        aes_cbc_decrypt(&[0u8; 16], b"shortkey", &[0u8; 16]),
        AesOutcome::BadInput
    );
    assert_eq!(
        aes_cbc_decrypt(&[0u8; 16], &[0u8; 16], b"shortiv"),
        AesOutcome::BadInput
    );
}

#[test]
fn xor_decrypt_empty_key_is_identity() {
    assert_eq!(xor_decrypt(b"abc", b""), b"abc".to_vec());
}
