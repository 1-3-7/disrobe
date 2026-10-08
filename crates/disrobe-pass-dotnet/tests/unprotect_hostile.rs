#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_dotnet::csharp_project::{CSharpProject, emit_csharp_project};
use disrobe_pass_dotnet::pe::{PeImage, SectionHeader, parse};
use disrobe_pass_dotnet::peel::confuserex_anti_tamper::{AntiTamperOutcome, decrypt_anti_tamper};
use disrobe_pass_dotnet::unprotect::{Unprotected, unprotect};

const FIXTURES: &[&str] = &[
    "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.confuserex2.exe",
    "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll",
    "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.bitmono.dll",
    "../../corpus/dotnet/obfuscators/obfuscar/gauntlet/GauntletSample.obfuscar.dll",
];

const TRUNCATION_POINTS: [usize; 7] = [0, 1, 0x40, 0x200, 0x400, 0x1000, 0x2400];
const FLIP_STRIDE: usize = 997;

fn load(rel: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

fn exercise(image: &[u8], label: &str) {
    let outcome: Result<Option<Unprotected>, _> = unprotect(image);
    if let Ok(Some(unprotected)) = &outcome {
        assert!(
            unprotected.report.neutralised.len() + unprotected.report.residuals.len() < 100_000,
            "{label}: report size stays bounded"
        );
    }
    let project: Result<CSharpProject, _> = emit_csharp_project(image);
    if let Ok(project) = project {
        assert!(
            project.files.len() < 100_000,
            "{label}: file count stays bounded"
        );
    }
    let _ = decrypt_anti_tamper(image);
}

#[test]
fn truncated_protected_images_are_typed_errors_never_panics() {
    for rel in FIXTURES {
        let image: Vec<u8> = load(rel);
        for point in TRUNCATION_POINTS {
            let cut: usize = point.min(image.len());
            exercise(&image[..cut], &format!("{rel} truncated to {cut}"));
        }
        for fraction in 1..8 {
            let cut: usize = image.len() * fraction / 8;
            exercise(&image[..cut], &format!("{rel} truncated to {cut}"));
        }
    }
}

#[test]
fn bit_flipped_protected_images_never_panic() {
    for rel in FIXTURES {
        let image: Vec<u8> = load(rel);
        let mut offset: usize = 0x80;
        while offset < image.len() {
            let mut mutated: Vec<u8> = image.clone();
            mutated[offset] ^= 0xFF;
            exercise(&mutated, &format!("{rel} flipped at {offset:#x}"));
            offset += FLIP_STRIDE;
        }
    }
}

#[test]
fn a_zeroed_section_table_entry_is_refused_by_name() {
    let image: Vec<u8> = load("../../corpus/dotnet/HelloAppLegacy.confuserex2.dll");
    let pe: PeImage = parse(&image).unwrap();
    let lfanew: usize = u32::from_le_bytes(image[0x3C..0x40].try_into().unwrap()) as usize;
    let optional_size: usize =
        u16::from_le_bytes(image[lfanew + 20..lfanew + 22].try_into().unwrap()) as usize;
    let section_table: usize = lfanew + 24 + optional_size;
    let text_index: usize = pe
        .sections
        .iter()
        .position(|s: &SectionHeader| s.name == ".text")
        .unwrap();
    let mut mutated: Vec<u8> = image;
    let entry: usize = section_table + text_index * 40;
    for byte in &mut mutated[entry + 8..entry + 24] {
        *byte = 0;
    }
    match decrypt_anti_tamper(&mutated) {
        Ok(AntiTamperOutcome::Refused { reason, .. }) => {
            assert!(!reason.is_empty(), "the refusal names its cause");
        }
        Ok(AntiTamperOutcome::Absent) | Err(_) => {}
        Ok(AntiTamperOutcome::Decrypted { .. }) => {
            panic!("a section table with zeroed sizes must not report a decrypted section")
        }
    }
}

#[test]
fn a_corrupted_text_section_stays_a_typed_outcome() {
    let image: Vec<u8> =
        load("../../corpus/dotnet/confuserex/gauntlet/GauntletSample.confuserex2.exe");
    let project: CSharpProject = emit_csharp_project(&image).expect("the real gauntlet decompiles");
    assert!(project.fully_recovered(), "{:?}", project.protection);
    let mut mutated: Vec<u8> = image.clone();
    let pe: PeImage = parse(&image).unwrap();
    let text: &SectionHeader = pe
        .sections
        .iter()
        .find(|s: &&SectionHeader| s.name == ".text")
        .unwrap();
    let start: usize = text.raw_pointer as usize;
    let end: usize = start + text.raw_size as usize;
    let mut touched: usize = 0;
    for offset in (start..end).step_by(61) {
        mutated[offset] = mutated[offset].wrapping_add(0x11);
        touched += 1;
    }
    assert!(touched > 100);
    let _ = emit_csharp_project(&mutated);
    let _ = unprotect(&mutated);
}
