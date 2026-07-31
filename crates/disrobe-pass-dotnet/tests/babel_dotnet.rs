#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::indexing_slicing,
    unused_must_use
)]

mod common;

use cbc::Encryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use des::Des;

use disrobe_pass_dotnet::peel::peel_babel_net;
use disrobe_pass_dotnet::peel::protector_resources::{
    ResourceStringRecovery, recover_babel_strings,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Handling, Protector, detect_all,
    plan_execution,
};

use crate::common::protector_pe::{DotnetPeSpec, build_dotnet_pe};
use crate::common::{embed_signature, synth_minimal_dotnet_pe};

fn binaryreader_string_blob(plaintexts: &[&str]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    for s in plaintexts {
        let bytes: &[u8] = s.as_bytes();
        let mut len: u32 = u32::try_from(bytes.len()).unwrap();
        loop {
            let mut byte: u8 = (len & 0x7F) as u8;
            len >>= 7;
            if len != 0 {
                byte |= 0x80;
            }
            blob.push(byte);
            if len == 0 {
                break;
            }
        }
        blob.extend_from_slice(bytes);
    }
    blob
}

fn des_cbc_encrypt_pkcs7(key: [u8; 8], iv: [u8; 8], data: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; data.len() + 8];
    let ct: &[u8] = Encryptor::<Des>::new((&key).into(), (&iv).into())
        .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf)
        .expect("enc");
    ct.to_vec()
}

const BABEL_KEY: [u8; 8] = [0x42, 0x41, 0x42, 0x45, 0x4C, 0x4E, 0x45, 0x54];
const BABEL_IV: [u8; 8] = [0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0xAF, 0xB0, 0xC1];

fn babel_resource_with_cipher(key: [u8; 8], iv: [u8; 8], cipher: &[u8]) -> Vec<u8> {
    let mut resource: Vec<u8> = Vec::new();
    resource.push(8);
    resource.extend_from_slice(&iv);
    resource.push(1);
    resource.push(8);
    resource.extend_from_slice(&key);
    resource.extend_from_slice(cipher);
    resource
}

fn build_modelled_babel_resource(plaintexts: &[&str]) -> Vec<u8> {
    let plain_blob: Vec<u8> = binaryreader_string_blob(plaintexts);
    let cipher: Vec<u8> = des_cbc_encrypt_pkcs7(BABEL_KEY, BABEL_IV, &plain_blob);
    babel_resource_with_cipher(BABEL_KEY, BABEL_IV, &cipher)
}

fn babel_image_with_resource(resource: Vec<u8>) -> Vec<u8> {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["BabelObfuscatorAttribute", "Babel.Module"]);
    spec.resource = Some(("BabelStrings", resource));
    build_dotnet_pe(&spec)
}

fn babel_recovery(resource: Vec<u8>) -> ResourceStringRecovery {
    recover_babel_strings(&babel_image_with_resource(resource)).expect("babel resource recovery")
}

fn assert_fails_closed(label: &str, resource: Vec<u8>) {
    let recovery: ResourceStringRecovery = babel_recovery(resource);
    assert!(
        recovery.strings.is_empty(),
        "{label}: no string may be reported for a resource this decrypter cannot validate, got \
         {:?}",
        recovery.strings
    );
    assert!(
        recovery.dynamic_wall.is_some(),
        "{label}: the rejection must be reported instead of silently dropped"
    );
}

const PLAINTEXTS: &[&str] = &[
    "BabelProtectedConnectionString=secret-prod",
    "OAuthClientSecret=zZ9-qP1-rT4",
    "https://license.example.net/validate",
];

fn modelled_babel_sample() -> Vec<u8> {
    babel_image_with_resource(build_modelled_babel_resource(PLAINTEXTS))
}

#[test]
fn babel_recovers_known_plaintext_from_self_built_des_resource() {
    let image: Vec<u8> = modelled_babel_sample();
    let report: PeelReport = peel_babel_net(&image).expect("peel");
    let recovered: Vec<&str> = report
        .recovered_strings
        .iter()
        .map(|r| r.text.as_str())
        .collect();
    for expected in PLAINTEXTS {
        assert!(
            recovered.contains(expected),
            "Babel must recover the known plaintext {expected:?} by reading the header IV + \
             embedded DES key and decrypting; recovered={recovered:?}"
        );
    }
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
}

#[test]
fn babel_published_signature_vector_detected_in_managed_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"BabelObfuscatorAttribute");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::BabelDotnet));
}

#[test]
fn babel_rejects_a_header_shaped_blob_that_is_not_a_string_resource() {
    let cipher: Vec<u8> = (0u8..128)
        .map(|i: u8| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    assert_fails_closed(
        "header bytes coincide with the Babel layout",
        babel_resource_with_cipher(BABEL_KEY, BABEL_IV, &cipher),
    );
}

#[test]
fn babel_rejects_a_resource_whose_embedded_key_is_off_by_one_byte() {
    let good: Vec<u8> = build_modelled_babel_resource(PLAINTEXTS);
    let recovered: ResourceStringRecovery = babel_recovery(good.clone());
    assert_eq!(recovered.strings.len(), PLAINTEXTS.len());

    let mut mutated: Vec<u8> = good;
    mutated[11] ^= 0x02;
    assert_fails_closed("one flipped bit in the embedded DES key", mutated);
}

#[test]
fn babel_rejects_padded_plaintext_that_is_not_a_complete_record_stream() {
    let truncated_record: Vec<u8> = [&[0x40u8][..], b"short"].concat();
    assert_fails_closed(
        "record length overruns the plaintext",
        babel_resource_with_cipher(
            BABEL_KEY,
            BABEL_IV,
            &des_cbc_encrypt_pkcs7(BABEL_KEY, BABEL_IV, &truncated_record),
        ),
    );

    let non_utf8: Vec<u8> = vec![0x04, 0xFF, 0xFE, 0xFD, 0xFC];
    assert_fails_closed(
        "record bytes are not UTF-8",
        babel_resource_with_cipher(
            BABEL_KEY,
            BABEL_IV,
            &des_cbc_encrypt_pkcs7(BABEL_KEY, BABEL_IV, &non_utf8),
        ),
    );

    let control_bytes: Vec<u8> = vec![0x03, b'a', 0x00, b'b'];
    assert_fails_closed(
        "record carries control bytes",
        babel_resource_with_cipher(
            BABEL_KEY,
            BABEL_IV,
            &des_cbc_encrypt_pkcs7(BABEL_KEY, BABEL_IV, &control_bytes),
        ),
    );

    let all_empty: Vec<u8> = vec![0u8; 16];
    assert_fails_closed(
        "every record is empty",
        babel_resource_with_cipher(
            BABEL_KEY,
            BABEL_IV,
            &des_cbc_encrypt_pkcs7(BABEL_KEY, BABEL_IV, &all_empty),
        ),
    );
}

#[test]
fn babel_reports_nothing_for_a_real_non_babel_assembly() {
    let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read real ConfuserEx2 corpus assembly");
    let recovery: Option<ResourceStringRecovery> = recover_babel_strings(&bytes);
    if let Some(recovery) = recovery {
        assert!(
            recovery.strings.is_empty(),
            "a real assembly protected by something other than Babel must yield no Babel strings; \
             got {:?}",
            recovery.strings
        );
        assert!(
            recovery.dynamic_wall.is_some(),
            "the rejection must be stated for resource {:?}",
            recovery.resource_name
        );
    }
}

#[test]
fn babel_still_recovers_literals_carrying_tabs_and_newlines() {
    let literals: &[&str] = &["path\tname", "line one\r\nline two", ""];
    let recovery: ResourceStringRecovery = babel_recovery(build_modelled_babel_resource(literals));
    assert_eq!(recovery.strings, literals);
    assert_eq!(recovery.dynamic_wall, None);
}

#[test]
fn babel_uses_native_strip() {
    let plan: ExecutionOutcome = plan_execution(Protector::BabelDotnet, ExecuteOptions::default());
    assert!(matches!(
        plan,
        ExecutionOutcome::Detected {
            handling: Handling::NativeStrip
        }
    ));
}
