#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::indexing_slicing,
    unused_must_use
)]

mod common;

use std::io::Write;

use cbc::Encryptor;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use des::Des;
use flate2::Compression;
use flate2::write::DeflateEncoder;

use disrobe_pass_dotnet::peel::peel_crypto_obfuscator;
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Protector, detect_all, plan_execution,
};

use crate::common::protector_pe::{DotnetPeSpec, build_dotnet_pe};
use crate::common::{embed_signature, synth_minimal_dotnet_pe};

const DES_FLAG: u8 = 1;
const DEFLATE_FLAG: u8 = 2;
const UNSUPPORTED_FLAG: u8 = 8;

fn varint(out: &mut Vec<u8>, value: u32) {
    if value < 0x80 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.push((0x80 | (value >> 8)) as u8);
        out.push((value & 0xFF) as u8);
    } else {
        out.push((0xC0 | (value >> 24)) as u8);
        out.push(((value >> 16) & 0xFF) as u8);
        out.push(((value >> 8) & 0xFF) as u8);
        out.push((value & 0xFF) as u8);
    }
}

fn unicode_record_blob(plaintexts: &[&str]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    for s in plaintexts {
        let units: Vec<u8> = s
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
        varint(&mut blob, u32::try_from(units.len()).unwrap());
        blob.extend_from_slice(&units);
    }
    blob
}

fn des_cbc_encrypt(key: [u8; 8], iv: [u8; 8], data: &[u8]) -> Vec<u8> {
    let mut padded: Vec<u8> = data.to_vec();
    while !padded.len().is_multiple_of(8) {
        padded.push(0);
    }
    let len: usize = padded.len();
    Encryptor::<Des>::new((&key).into(), (&iv).into())
        .encrypt_padded_mut::<NoPadding>(&mut padded, len)
        .expect("enc");
    padded
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder: DeflateEncoder<Vec<u8>> =
        DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("deflate write");
    encoder.finish().expect("deflate finish")
}

fn build_crypto_obfuscator_resource(plaintexts: &[&str]) -> Vec<u8> {
    let key: [u8; 8] = [0x13, 0x37, 0xC0, 0xDE, 0xBA, 0xBE, 0xF0, 0x0D];
    let iv: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
    let plain_blob: Vec<u8> = unicode_record_blob(plaintexts);
    let cipher: Vec<u8> = des_cbc_encrypt(key, iv, &plain_blob);
    let mut resource: Vec<u8> = Vec::new();
    resource.push(DES_FLAG);
    resource.extend_from_slice(&iv);
    resource.extend_from_slice(&key);
    resource.extend_from_slice(&cipher);
    resource
}

fn build_crypto_obfuscator_mixed_flag_non_utf16_resource() -> Vec<u8> {
    let garbage: Vec<u8> = vec![0xFFu8; 7];
    let compressed: Vec<u8> = deflate(&garbage);
    let mut resource: Vec<u8> = Vec::new();
    resource.push(DEFLATE_FLAG | UNSUPPORTED_FLAG);
    resource.extend_from_slice(&compressed);
    resource
}

const PLAINTEXTS: &[&str] = &[
    "Server=prod-db;User=svc-app;Password=hunter2!",
    "https://api.internal.example.com/v2/secrets",
    "LICENSE-KEY-7F3A-9C21-EE05",
];

fn crypto_obfuscator_sample() -> Vec<u8> {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["CryptoObfuscator", "LogicNP"]);
    spec.resource = Some(("AppApp", build_crypto_obfuscator_resource(PLAINTEXTS)));
    build_dotnet_pe(&spec)
}

#[test]
fn crypto_obfuscator_recovers_known_plaintext_from_self_built_des_resource() {
    let image: Vec<u8> = crypto_obfuscator_sample();
    let report: PeelReport = peel_crypto_obfuscator(&image).expect("peel");
    let recovered: Vec<&str> = report
        .recovered_strings
        .iter()
        .map(|r| r.text.as_str())
        .collect();
    for expected in PLAINTEXTS {
        assert!(
            recovered.contains(expected),
            "CryptoObfuscator must recover the known plaintext {expected:?} by reading the inline \
             DES IV+key from the resource and decrypting; recovered={recovered:?}"
        );
    }
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
}

#[test]
fn crypto_obfuscator_mixed_flag_decoding_to_non_utf16_walls_not_fakes() {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["CryptoObfuscator"]);
    spec.resource = Some((
        "AppApp",
        build_crypto_obfuscator_mixed_flag_non_utf16_resource(),
    ));
    let image: Vec<u8> = build_dotnet_pe(&spec);
    let report: PeelReport = peel_crypto_obfuscator(&image).expect("peel");
    assert!(
        report.recovered_strings.is_empty(),
        "a mixed-flag (0x0A) resource whose supported stages decode to non-UTF-16 data must not \
         emit confident garbage; recovered={:?}",
        report.recovered_strings
    );
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(
        report.notes.iter().any(|n: &String| {
            n.contains("0x08") && n.contains("not a valid UTF-16 record stream")
        }),
        "the unproven 0x08 bit is only ignorable when the decode validates; otherwise it must wall; \
         notes={:?}",
        report.notes
    );
}

#[test]
fn crypto_obfuscator_plaintext_records_under_unknown_flag_recover() {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["CryptoObfuscator"]);
    let mut resource: Vec<u8> = vec![UNSUPPORTED_FLAG];
    resource.extend_from_slice(&unicode_record_blob(PLAINTEXTS));
    spec.resource = Some(("AppApp", resource));
    let image: Vec<u8> = build_dotnet_pe(&spec);
    let report: PeelReport = peel_crypto_obfuscator(&image).expect("peel");
    let recovered: Vec<&str> = report
        .recovered_strings
        .iter()
        .map(|r| r.text.as_str())
        .collect();
    for expected in PLAINTEXTS {
        assert!(
            recovered.contains(expected),
            "CryptoObfuscator unknown-only flag with valid UTF-16 records must recover {expected:?}; recovered={recovered:?}"
        );
    }
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| { n.contains("0x08") && n.contains("resource-stage validation") }),
        "unknown-only valid records must record the ignored flag bit; notes={:?}",
        report.notes
    );
}

#[test]
fn crypto_obfuscator_unsupported_only_resource_reports_flag_wall() {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["CryptoObfuscator"]);
    spec.resource = Some(("AppApp", vec![UNSUPPORTED_FLAG, 0, 0, 0]));
    let image: Vec<u8> = build_dotnet_pe(&spec);
    let report: PeelReport = peel_crypto_obfuscator(&image).expect("peel");
    assert!(report.recovered_strings.is_empty());
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(
        report.notes.iter().any(|n: &String| {
            n.contains("unsupported encryption flag mask 0x08")
                && n.contains("no supported resource stages")
        }),
        "unsupported-only resource must cite the failed flag parser refutation; notes={:?}",
        report.notes
    );
}

#[test]
fn crypto_obfuscator_published_signature_vector_detected_in_managed_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"CryptoObfuscator");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::CryptoObfuscator));
}

#[test]
fn crypto_obfuscator_gates_without_authorization() {
    let plan: ExecutionOutcome =
        plan_execution(Protector::CryptoObfuscator, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::GatedAndBlocked { .. }));
}
