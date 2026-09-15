#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::Path;

use disrobe_binfmt::{
    Action, ContainerKind, InputClassification, Lang, StructuralFormat, classify_input,
    detect_container, identify_by_structure,
};

use common::requirement::required_corpus;

const ELF_REL: &str = "native/zig/hello.zig.elf";
const PE_REL: &str = "native/packers/upx/hello.packed.nrv2b.exe";
const MACHO_FAT_REL: &str = "mac/megafile/EdgeCases.fat";
const DEX_REL: &str = "jvm/dex/Hello.dex";
const CLASS_REL: &str = "jvm/callerkeyed/CallerKeyed.class";
const ZIP_REL: &str = "jvm/proguard/Hello-baseline.jar";

fn zero_prefix(bytes: &[u8], n: usize) -> Vec<u8> {
    let mut out: Vec<u8> = bytes.to_vec();
    for b in out.iter_mut().take(n) {
        *b = 0;
    }
    out
}

fn flip_prefix(bytes: &[u8], n: usize) -> Vec<u8> {
    let mut out: Vec<u8> = bytes.to_vec();
    for b in out.iter_mut().take(n) {
        *b = !*b;
    }
    out
}

#[test]
fn real_elf_survives_zeroed_and_flipped_magic() {
    let elf: Vec<u8> = required_corpus(ELF_REL);
    assert_eq!(
        identify_by_structure(&elf),
        Some(StructuralFormat::Elf),
        "intact ELF must validate structurally"
    );
    let zeroed: Vec<u8> = zero_prefix(&elf, 4);
    assert_eq!(
        identify_by_structure(&zeroed),
        Some(StructuralFormat::Elf),
        "zeroed \\x7fELF magic must still identify as ELF by header tables"
    );
    let flipped: Vec<u8> = flip_prefix(&elf, 4);
    assert_eq!(
        identify_by_structure(&flipped),
        Some(StructuralFormat::Elf),
        "flipped ELF magic must still identify as ELF by header tables"
    );
    let cl: InputClassification = classify_input(Path::new("scrambled"), &zeroed);
    assert!(
        matches!(cl.primary_action, Action::Decompile { lang: Lang::Native }),
        "scrambled-magic ELF must route to native handling: {}",
        cl.reason
    );
}

#[test]
fn real_pe_survives_flipped_mz_and_corrupt_e_lfanew() {
    let pe: Vec<u8> = required_corpus(PE_REL);
    assert_eq!(&pe[..2], b"MZ", "fixture must be a real MZ image");
    assert_eq!(identify_by_structure(&pe), Some(StructuralFormat::Pe));

    let flipped: Vec<u8> = flip_prefix(&pe, 2);
    assert_ne!(&flipped[..2], b"MZ");
    assert_eq!(
        identify_by_structure(&flipped),
        Some(StructuralFormat::Pe),
        "flipped MZ must still resolve via e_lfanew -> PE\\0\\0 + COFF + section table"
    );

    let mut corrupt_lfanew: Vec<u8> = pe;
    corrupt_lfanew[0] = 0x00;
    corrupt_lfanew[1] = 0x00;
    corrupt_lfanew[0x3C] ^= 0xFF;
    corrupt_lfanew[0x3D] ^= 0xFF;
    assert_eq!(
        identify_by_structure(&corrupt_lfanew),
        Some(StructuralFormat::Pe),
        "flipped MZ AND corrupted e_lfanew must still resolve via the PE-signature scan"
    );

    let cl: InputClassification = classify_input(Path::new("scrambled.bin"), &flipped);
    assert!(
        matches!(cl.primary_action, Action::Decompile { lang: Lang::Native }),
        "scrambled-MZ PE must route to native handling: {}",
        cl.reason
    );
}

#[test]
fn real_macho_fat_survives_scrambled_magic() {
    let fat: Vec<u8> = required_corpus(MACHO_FAT_REL);
    assert_eq!(
        identify_by_structure(&fat),
        Some(StructuralFormat::MachOFat),
        "intact fat Mach-O must validate via its arch table"
    );
    let scrambled: Vec<u8> = flip_prefix(&fat, 4);
    assert_eq!(
        identify_by_structure(&scrambled),
        Some(StructuralFormat::MachOFat),
        "scrambled fat magic must still validate via the arch offset/size table"
    );
}

#[test]
fn real_dex_survives_zeroed_magic_structurally() {
    let dex: Vec<u8> = required_corpus(DEX_REL);
    assert_eq!(
        identify_by_structure(&dex),
        Some(StructuralFormat::Dex),
        "intact dex must validate structurally"
    );
    let zeroed: Vec<u8> = zero_prefix(&dex, 8);
    assert_eq!(
        identify_by_structure(&zeroed),
        Some(StructuralFormat::Dex),
        "zeroed dex\\n0XX\\0 magic must still identify by header_size + section offsets"
    );
}

#[test]
fn real_class_survives_scrambled_magic_structurally() {
    let class: Vec<u8> = required_corpus(CLASS_REL);
    assert_eq!(
        identify_by_structure(&class),
        Some(StructuralFormat::JavaClass),
        "intact class must validate via constant-pool walk"
    );
    let scrambled: Vec<u8> = flip_prefix(&class, 4);
    assert_eq!(
        identify_by_structure(&scrambled),
        Some(StructuralFormat::JavaClass),
        "scrambled 0xCAFEBABE must still identify via the constant-pool walk"
    );
    let cl: InputClassification = classify_input(Path::new("scrambled"), &scrambled);
    assert!(
        matches!(cl.primary_action, Action::Decompile { lang: Lang::Java }),
        "scrambled-magic class must route to java decompile: {}",
        cl.reason
    );
}

#[test]
fn real_zip_survives_scrambled_local_header_via_eocd_anchor() {
    let zip: Vec<u8> = required_corpus(ZIP_REL);
    assert_eq!(&zip[..2], b"PK", "fixture must be a real zip");
    assert_eq!(detect_container(&zip), Some(ContainerKind::Zip));

    let scrambled: Vec<u8> = flip_prefix(&zip, 4);
    assert_ne!(&scrambled[..2], b"PK");
    assert_eq!(
        identify_by_structure(&scrambled),
        Some(StructuralFormat::Zip),
        "scrambled PK local header must still validate via the EOCD -> central-directory anchor"
    );
    assert_eq!(
        detect_container(&scrambled),
        Some(ContainerKind::Zip),
        "container detection must fall back to the EOCD structural anchor for a scrambled zip"
    );
}

#[test]
fn scrambled_wasm_routes_to_wasm_lang() {
    let mut module: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d];
    module.extend_from_slice(&1u32.to_le_bytes());
    module.push(1);
    module.push(4);
    module.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    assert_eq!(identify_by_structure(&module), Some(StructuralFormat::Wasm));

    let mut scrambled: Vec<u8> = module.clone();
    scrambled[..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(
        identify_by_structure(&scrambled),
        Some(StructuralFormat::Wasm),
        "scrambled \\0asm magic must validate via the section id/size stream"
    );
    let cl: InputClassification = classify_input(Path::new("scrambled.bin"), &scrambled);
    assert!(
        matches!(cl.primary_action, Action::Decompile { lang: Lang::Wasm }),
        "scrambled-magic wasm must route to wasm decompile: {}",
        cl.reason
    );
}

#[test]
fn unrelated_real_bytes_do_not_false_positive() {
    let dex: Vec<u8> = required_corpus(DEX_REL);
    let truncated: &[u8] = &dex[..dex.len().min(16)];
    let mut scratch: Vec<u8> = truncated.to_vec();
    for b in &mut scratch {
        *b = b.wrapping_add(0x55);
    }
    assert_eq!(
        identify_by_structure(&scratch),
        None,
        "a shifted 16-byte dex prefix carries no header table any format can validate, so naming \
         a format here is a false positive"
    );

    for size in [0usize, 1, 4, 15, 64, 1024, 4096] {
        for filler in [0x00u8, 0xff, 0x41] {
            let uniform: Vec<u8> = vec![filler; size];
            assert_eq!(
                identify_by_structure(&uniform),
                None,
                "{size} bytes of {filler:#04x} must not be named as a structural format"
            );
        }
    }
}
