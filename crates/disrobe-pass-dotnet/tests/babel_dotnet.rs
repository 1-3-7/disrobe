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

fn build_babel_resource(plaintexts: &[&str]) -> Vec<u8> {
    let key: [u8; 8] = [0x42, 0x41, 0x42, 0x45, 0x4C, 0x4E, 0x45, 0x54];
    let iv: [u8; 8] = [0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0xAF, 0xB0, 0xC1];
    let plain_blob: Vec<u8> = binaryreader_string_blob(plaintexts);
    let cipher: Vec<u8> = des_cbc_encrypt_pkcs7(key, iv, &plain_blob);
    let mut resource: Vec<u8> = Vec::new();
    resource.push(8);
    resource.extend_from_slice(&iv);
    resource.push(1);
    resource.push(8);
    resource.extend_from_slice(&key);
    resource.extend_from_slice(&cipher);
    resource
}

const PLAINTEXTS: &[&str] = &[
    "BabelProtectedConnectionString=secret-prod",
    "OAuthClientSecret=zZ9-qP1-rT4",
    "https://license.example.net/validate",
];

fn babel_sample() -> Vec<u8> {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["BabelObfuscatorAttribute", "Babel.Module"]);
    spec.resource = Some(("BabelStrings", build_babel_resource(PLAINTEXTS)));
    build_dotnet_pe(&spec)
}

#[test]
fn babel_recovers_known_plaintext_from_self_built_des_resource() {
    let image: Vec<u8> = babel_sample();
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
fn babel_uses_native_strip() {
    let plan: ExecutionOutcome = plan_execution(Protector::BabelDotnet, ExecuteOptions::default());
    assert!(matches!(
        plan,
        ExecutionOutcome::Detected {
            handling: Handling::NativeStrip
        }
    ));
}
