#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

mod common;

use disrobe_pass_dotnet::peel::maxtocode::peel_maxtocode;
use disrobe_pass_dotnet::peel::maxtocode_bodies::{
    MaxKeyOrigin, MaxToCodeRecovery, recover_maxtocode_bodies,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use disrobe_pass_dotnet::protectors::{Protector, detect_all};

use crate::common::protector_pe::{build_maxtocode_pe, tiny_method_body};

fn plain_method() -> Vec<u8> {
    tiny_method_body(&[0x16, 0x2A])
}

fn opaque_bodies() -> Vec<(u32, Vec<u8>)> {
    vec![
        (1, vec![0xBF, 0x8E, 0x2A]),
        (2, vec![0x70, 0xF7, 0x01, 0x23]),
        (3, vec![0x45, 0x67, 0x89, 0xAB, 0xCD]),
    ]
}

fn opaque_ciphertext_section(records: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    for (_rid, cipher) in records {
        blob.extend_from_slice(cipher);
    }
    blob
}

#[test]
fn detect_fingerprints_maxtocode_by_real_markers() {
    let bodies: Vec<(u32, Vec<u8>)> = opaque_bodies();
    let section: Vec<u8> = opaque_ciphertext_section(&bodies);
    let image: Vec<u8> = build_maxtocode_pe(bodies.len() as u32, &plain_method(), &section, None);

    let detection: disrobe_pass_dotnet::protectors::DetectionReport = detect_all(&image);
    assert!(
        detection.matches.contains_key(&Protector::MaxToCode),
        "the byte-faithful assembly must be fingerprinted as MaxToCode via its real MaxtoCode / \
         NetSafe markers; matches={:?}",
        detection.matches.keys().collect::<Vec<&Protector>>()
    );
}

#[test]
fn static_structure_recovers_and_walls_on_native_loader_key() {
    let bodies: Vec<(u32, Vec<u8>)> = opaque_bodies();
    let section: Vec<u8> = opaque_ciphertext_section(&bodies);
    let image: Vec<u8> = build_maxtocode_pe(bodies.len() as u32, &plain_method(), &section, None);

    let recovery: MaxToCodeRecovery = recover_maxtocode_bodies(&image).expect("recover");
    assert!(
        recovery.encrypted_section_located,
        "the .mtc encrypted section must be located"
    );
    assert_eq!(
        recovery.zero_rva_methods,
        bodies.len() as u32,
        "every protected method must be enumerated by its zero RVA"
    );
    assert_eq!(
        recovery.protected_method_rids.len(),
        bodies.len(),
        "protected-method enumeration must be exact"
    );
    assert!(
        recovery.section_sha256.is_some(),
        "the located encrypted section must be hashed, recorded as opaque ciphertext"
    );
    assert_eq!(
        recovery.key_origin,
        MaxKeyOrigin::NativeStubWall,
        "the per-method key is computed inside the unmanaged JIT-hooked loader, so the static \
         result is the native loader wall, never fabricated bodies"
    );
    assert_eq!(recovery.bodies_recovered, 0);
    assert!(recovery.recovered_bodies.is_empty());
}

#[test]
fn real_peel_path_stays_detect_only_and_is_not_shadowed() {
    let bodies: Vec<(u32, Vec<u8>)> = opaque_bodies();
    let section: Vec<u8> = opaque_ciphertext_section(&bodies);
    let image: Vec<u8> = build_maxtocode_pe(bodies.len() as u32, &plain_method(), &section, None);

    let report: PeelReport = peel_maxtocode(&image).expect("peel");
    assert_eq!(
        report.strategy,
        PeelStrategy::DetectOnlyNativeOrVm,
        "MaxToCode bodies are restored by a native loader key at JIT time, so the peel path must \
         stay honestly walled, not promote to EncryptedResourceExtracted"
    );
    assert_eq!(report.recovered_decoders, 0);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("NATIVE-KEY WALL")),
        "the report must state the native loader wall plainly; notes={:?}",
        report.notes
    );
}

#[test]
fn baseline_without_zero_rva_methods_is_not_flagged_recovered() {
    let image: Vec<u8> =
        build_maxtocode_pe(0, &plain_method(), &opaque_ciphertext_section(&[]), None);
    let recovery: MaxToCodeRecovery = recover_maxtocode_bodies(&image).expect("recover");
    assert_eq!(
        recovery.zero_rva_methods, 0,
        "an assembly with no zero-RVA methods must enumerate zero protected methods"
    );
    assert_eq!(recovery.bodies_recovered, 0);
    assert_eq!(recovery.key_origin, MaxKeyOrigin::None);
}
