#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

mod common;

use disrobe_pass_dotnet::peel::ilprotector::peel_ilprotector;
use disrobe_pass_dotnet::peel::ilprotector_bodies::{
    IlProtectorRecovery, KeyOrigin, recover_ilprotector_bodies,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use disrobe_pass_dotnet::protectors::{Protector, detect_all};

use crate::common::protector_pe::build_ilprotector_pe;

fn opaque_bodies() -> Vec<(u32, Vec<u8>)> {
    vec![
        (0, vec![0x9A, 0x10, 0x44, 0x21, 0x86]),
        (1, vec![0x00, 0xFF, 0x42, 0x13]),
        (2, vec![0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40]),
    ]
}

fn opaque_ciphertext_blob(records: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    for (_id, cipher) in records {
        blob.extend_from_slice(cipher);
    }
    blob
}

#[test]
fn detect_fingerprints_ilprotector_by_real_markers() {
    let bodies: Vec<(u32, Vec<u8>)> = opaque_bodies();
    let ids: Vec<u32> = bodies.iter().map(|(id, _)| *id).collect();
    let container: Vec<u8> = opaque_ciphertext_blob(&bodies);
    let image: Vec<u8> = build_ilprotector_pe(&ids, &container, None);

    let detection: disrobe_pass_dotnet::protectors::DetectionReport = detect_all(&image);
    assert!(
        detection.matches.contains_key(&Protector::Ilprotector),
        "the byte-faithful assembly must be fingerprinted as ILProtector via its real \
         Protect32.dll / ILProtector markers, not a synthetic sentinel; matches={:?}",
        detection.matches.keys().collect::<Vec<&Protector>>()
    );
}

#[test]
fn static_structure_recovers_and_walls_on_native_runtime_key() {
    let bodies: Vec<(u32, Vec<u8>)> = opaque_bodies();
    let ids: Vec<u32> = bodies.iter().map(|(id, _)| *id).collect();
    let container: Vec<u8> = opaque_ciphertext_blob(&bodies);
    let image: Vec<u8> = build_ilprotector_pe(&ids, &container, None);

    let recovery: IlProtectorRecovery = recover_ilprotector_bodies(&image).expect("recover");
    assert!(
        recovery.resource_located,
        "the ILProtector encrypted-body resource must be located through the real metadata path"
    );
    assert_eq!(
        recovery.stub_methods_classified,
        ids.len() as u32,
        "protected-method enumeration must be exact"
    );
    let mut sorted_ids: Vec<u32> = ids;
    sorted_ids.sort_unstable();
    assert_eq!(
        recovery.protected_method_ids, sorted_ids,
        "the recovered protected-method ids must match the Invoke-stub indices exactly"
    );
    assert!(
        recovery.resource_sha256.is_some(),
        "the located encrypted-body resource must be hashed, recorded as opaque ciphertext"
    );
    assert_eq!(
        recovery.key_origin,
        KeyOrigin::NativeRuntimeWall,
        "the plaintext IL is produced only by invoking the runtime decrypt delegate, so the static \
         result is the runtime-delegate wall, never fabricated bodies"
    );
    assert_eq!(recovery.bodies_recovered, 0);
    assert!(recovery.recovered_bodies.is_empty());
}

#[test]
fn real_peel_path_stays_detect_only_and_is_not_shadowed() {
    let bodies: Vec<(u32, Vec<u8>)> = opaque_bodies();
    let ids: Vec<u32> = bodies.iter().map(|(id, _)| *id).collect();
    let container: Vec<u8> = opaque_ciphertext_blob(&bodies);
    let image: Vec<u8> = build_ilprotector_pe(&ids, &container, None);

    let report: PeelReport = peel_ilprotector(&image).expect("peel");
    assert_eq!(
        report.strategy,
        PeelStrategy::DetectOnlyNativeOrVm,
        "ILProtector bodies are decrypted by a native runtime key, so the peel path must stay \
         honestly walled, not promote to EncryptedResourceExtracted"
    );
    assert_eq!(report.recovered_decoders, 0);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("RUNTIME-DELEGATE WALL")),
        "the report must state the native-runtime wall plainly; notes={:?}",
        report.notes
    );
}

#[test]
fn baseline_without_invoke_stubs_is_not_flagged_recovered() {
    let image: Vec<u8> = build_ilprotector_pe(&[], &opaque_ciphertext_blob(&[]), None);
    let recovery: IlProtectorRecovery = recover_ilprotector_bodies(&image).expect("recover");
    assert_eq!(
        recovery.stub_methods_classified, 0,
        "an assembly with no Invoke-stubs must enumerate zero protected methods"
    );
    assert_eq!(recovery.bodies_recovered, 0);
    assert_eq!(recovery.key_origin, KeyOrigin::None);
}

#[test]
fn enumeration_is_static_and_independent_of_the_body_payload() {
    let ids: Vec<u32> = vec![3, 7, 11];
    let with_resource: Vec<u8> = build_ilprotector_pe(
        &ids,
        &opaque_ciphertext_blob(&[
            (3, vec![0x01, 0x02]),
            (7, vec![0x03, 0x04, 0x05]),
            (11, vec![0x06]),
        ]),
        None,
    );
    let recovery: IlProtectorRecovery =
        recover_ilprotector_bodies(&with_resource).expect("recover");
    let mut sorted_ids: Vec<u32> = ids;
    sorted_ids.sort_unstable();
    assert_eq!(recovery.protected_method_ids, sorted_ids);
    assert!(recovery.resource_located);
    assert_eq!(recovery.key_origin, KeyOrigin::NativeRuntimeWall);
    assert_eq!(recovery.bodies_recovered, 0);
}
