#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::path::PathBuf;

use disrobe_pass_mobile::{DetectedKind, detect_kind};

const FLUTTER_AOT_IMAGE: &str = "mobile/flutter/disrobe_sample/libapp_arm64.so";

const NON_FLUTTER_ELF_FIXTURES: [&str; 17] = [
    "binfmt/ar/expected/short.o",
    "binfmt/cython/cymod.linux.so",
    "binfmt/elf-dynamic/sample.elf",
    "binfmt/elf-overlay/hello.elf",
    "native/d/hello.d.o.elf",
    "native/discovery/disc.stripped.elf",
    "native/discovery/disc.unstripped.elf",
    "native/formats/avr_firmware.elf",
    "native/formats/hello_reloc.ko.o",
    "native/nim/hello.nim.elf",
    "native/obfuscators/amice/sample.amice.elf",
    "native/obfuscators/amice/sample.clean.elf",
    "native/zig/hello.zig.elf",
    "python/pyarmor/v8/platform_linux/pyarmor_runtime_000000/pyarmor_runtime.so",
    "python/pyarmor/v8/platform_linux_aarch64/pyarmor_runtime_000000/pyarmor_runtime.so",
    "python/pyarmor/v9/platform_linux/pyarmor_runtime_000000/pyarmor_runtime.so",
    "python/pyarmor/v9/platform_linux_aarch64/pyarmor_runtime_000000/pyarmor_runtime.so",
];

fn corpus_path(rel: &str) -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("corpus").join(rel)
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(rel);
    assert!(
        path.exists(),
        "committed fixture {rel} is missing at {}; it is tracked in git, so an absent file means \
         an incomplete checkout and detection would be graded against nothing",
        path.display()
    );
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("cannot read {rel}: {e}"))
}

fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F']
}

#[test]
fn the_committed_dart_aot_image_is_detected_as_a_flutter_snapshot() {
    let bytes: Vec<u8> = read_fixture(FLUTTER_AOT_IMAGE);
    assert!(is_elf(&bytes), "{FLUTTER_AOT_IMAGE} must be an ELF image");
    assert_eq!(
        detect_kind(&bytes),
        DetectedKind::FlutterLibAppSo,
        "{FLUTTER_AOT_IMAGE} carries a real Dart AOT snapshot and must still be recognized"
    );
}

#[test]
fn no_committed_non_flutter_elf_is_detected_as_a_flutter_snapshot() {
    let mut misdetected: Vec<&str> = Vec::new();
    for rel in NON_FLUTTER_ELF_FIXTURES {
        let bytes: Vec<u8> = read_fixture(rel);
        assert!(is_elf(&bytes), "{rel} must be an ELF image to be a control");
        if detect_kind(&bytes) == DetectedKind::FlutterLibAppSo {
            misdetected.push(rel);
        }
    }
    assert!(
        misdetected.is_empty(),
        "these committed non-Flutter ELF images were reported as Flutter AOT snapshots, which is \
         the shape of a detector keyed on ELF magic rather than on Dart snapshot evidence: {}",
        misdetected.join(", ")
    );
    println!(
        "flutter detection specificity: {} committed non-Flutter ELF images, none misdetected",
        NON_FLUTTER_ELF_FIXTURES.len()
    );
}

#[test]
fn dart_aot_evidence_separates_the_flutter_image_from_every_control() {
    let flutter: Vec<u8> = read_fixture(FLUTTER_AOT_IMAGE);
    assert!(
        disrobe_pass_mobile::flutter::has_dart_aot_snapshot(&flutter),
        "the committed Dart AOT image must carry a parseable snapshot header"
    );
    for rel in NON_FLUTTER_ELF_FIXTURES {
        let bytes: Vec<u8> = read_fixture(rel);
        assert!(
            !disrobe_pass_mobile::flutter::has_dart_aot_snapshot(&bytes),
            "{rel} carries no Dart snapshot, so the evidence check must reject it"
        );
    }
}
