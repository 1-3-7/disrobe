#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::indexing_slicing,
    unused_must_use
)]

mod common;

use aes::Aes256;
use cbc::Encryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};

use disrobe_pass_dotnet::peel::peel_dotnet_reactor;
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Protector, detect_all, plan_execution,
};

use crate::common::protector_pe::{DotnetPeSpec, FieldBlob, build_dotnet_pe};
use crate::common::{embed_signature, synth_minimal_dotnet_pe};

const KEY: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
];
const IV: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xFE, 0xED, 0xFA, 0xCE, 0x13, 0x37, 0x42, 0x99,
];

fn int32_record_blob(plaintexts: &[&str]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    for s in plaintexts {
        let units: Vec<u8> = s
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
        blob.extend_from_slice(&u32::try_from(units.len()).unwrap().to_le_bytes());
        blob.extend_from_slice(&units);
    }
    blob
}

fn aes256_cbc_encrypt_pkcs7(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; data.len() + 16];
    let ct: &[u8] = Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf)
        .expect("enc");
    ct.to_vec()
}

const PLAINTEXTS: &[&str] = &[
    "ReactorEncryptedApiToken=rk_live_8842abcd",
    "Server=10.0.0.4;Database=Billing;Pwd=Z!9q",
    "feature.flag.experimental=enabled",
];

fn reactor_sample() -> Vec<u8> {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["Eziriz", ".NET Reactor"]);
    let cipher: Vec<u8> = aes256_cbc_encrypt_pkcs7(&KEY, &IV, &int32_record_blob(PLAINTEXTS));
    spec.resource = Some(("ReactorStrings", cipher));
    spec.field_blobs = vec![
        FieldBlob {
            name: "rk",
            bytes: KEY.to_vec(),
        },
        FieldBlob {
            name: "ri",
            bytes: IV.to_vec(),
        },
    ];
    build_dotnet_pe(&spec)
}

#[test]
fn dotnet_reactor_methodless_named_fields_remain_unknown() {
    let image: Vec<u8> = reactor_sample();
    let report: PeelReport = peel_dotnet_reactor(&image).expect("peel");
    assert!(report.recovered_strings.is_empty());
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(report.notes.iter().any(|note: &String| {
        note.contains("Unknown: Reactor managed methods contain no proven static string entry")
    }));
}

#[test]
fn dotnet_reactor_signature_detected() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"Eziriz .NET Reactor");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::DotnetReactor));
}

#[test]
fn dotnet_reactor_gates_without_authorization() {
    let plan: ExecutionOutcome =
        plan_execution(Protector::DotnetReactor, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::GatedAndBlocked { .. }));
}

#[test]
fn dotnet_reactor_unblocks_with_authorization() {
    let plan: ExecutionOutcome = plan_execution(
        Protector::DotnetReactor,
        ExecuteOptions {
            authorization_granted: true,
        },
    );
    assert!(matches!(plan, ExecutionOutcome::DelegatedToDe4dot));
}
