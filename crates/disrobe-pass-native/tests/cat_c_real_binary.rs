#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::needless_pass_by_value
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{
    DetectedFormat, NativeFormat, Packer, PackerDetection, UnpackerStatus, UpxMethod,
    UpxUnpackOutput, detect_format, detect_packers, unpack_upx,
};
use packer_fixture::{PackerFixture, load_fixture};

fn corpus_root() -> PathBuf {
    let crate_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .map(|p: &Path| p.join("corpus").join("native").join("packers"))
        .expect("workspace layout: crates/disrobe-pass-native -> ../../corpus/native/packers")
}

fn decoder_for(family: &str) -> &'static str {
    match family {
        "upx" => "UPX",
        "mpress" => "MPRESS",
        "petite" => "Petite",
        other => panic!("no decoder name is registered for packer family {other}"),
    }
}

fn read_corpus(rel: &str) -> Option<Vec<u8>> {
    let (family, name): (&str, &str) = rel
        .split_once('/')
        .unwrap_or_else(|| panic!("corpus path {rel} must be <family>/<fixture name>"));
    load_fixture(PackerFixture {
        decoder: decoder_for(family),
        family,
        name,
    })
}

fn has_packer(hits: &[PackerDetection], packer: Packer) -> bool {
    hits.iter().any(|h: &PackerDetection| h.packer == packer)
}

fn distinct_packers(hits: &[PackerDetection]) -> BTreeSet<Packer> {
    hits.iter().map(|h: &PackerDetection| h.packer).collect()
}

fn upx_available() -> bool {
    Command::new("upx")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

#[test]
fn upx_detects_hello_x64_real_binary() {
    let Some(bytes): Option<Vec<u8>> = read_corpus("upx/hello.exe") else {
        eprintln!("skipping: upx/hello.exe corpus fixture absent");
        return;
    };
    let hits: Vec<PackerDetection> = detect_packers(&bytes);
    assert!(
        has_packer(&hits, Packer::Upx),
        "real UPX-packed hello.exe must be detected: hits={hits:?}"
    );
    assert_eq!(Packer::Upx.unpacker_status(), UnpackerStatus::Implemented);
}

#[test]
fn upx_detects_ripgrep_megafile() {
    let Some(bytes): Option<Vec<u8>> = read_corpus("upx/rg.packed.upx.exe") else {
        eprintln!("skipping: upx/rg.packed.upx.exe corpus fixture absent");
        return;
    };
    assert!(
        bytes.len() > 1_000_000,
        "rg.packed.upx.exe must be the real 4 MB-class megafile, got {} bytes",
        bytes.len()
    );
    let hits: Vec<PackerDetection> = detect_packers(&bytes);
    assert!(
        has_packer(&hits, Packer::Upx),
        "real UPX-packed ripgrep must be detected: hits={hits:?}"
    );
    let detected: DetectedFormat =
        detect_format(&bytes).expect("packed rg.exe is still a valid PE container");
    assert_eq!(detected.kind, NativeFormat::Pe64);
}

#[test]
fn upx_round_trip_hello_byte_compare() {
    if !upx_available() {
        println!("SKIP: upx CLI not on PATH");
        return;
    }
    let Some(baseline): Option<Vec<u8>> = read_corpus("upx/hello.original.exe") else {
        eprintln!("skipping: upx/hello.original.exe corpus fixture absent");
        return;
    };
    let Some(unpacked): Option<Vec<u8>> = read_corpus("upx/hello.unpacked.exe") else {
        eprintln!("skipping: upx/hello.unpacked.exe corpus fixture absent");
        return;
    };
    assert_eq!(
        baseline.len(),
        unpacked.len(),
        "UPX round-trip must preserve total length for hello.exe"
    );
    let diffs: u64 = baseline
        .iter()
        .zip(unpacked.iter())
        .filter(|(a, b): &(&u8, &u8)| a != b)
        .count() as u64;
    let diff_per_million: u64 = diffs.saturating_mul(1_000_000) / baseline.len() as u64;
    assert!(
        diff_per_million < 10_000,
        "hello.exe round-trip diff_per_million {diff_per_million} must stay <10000 (=1%) modulo COFF header timestamp / padding"
    );
}

#[test]
fn upx_round_trip_ripgrep_byte_compare_and_recover_runs() {
    if !upx_available() {
        println!("SKIP: upx CLI not on PATH");
        return;
    }
    let Some(baseline): Option<Vec<u8>> = read_corpus("upx/rg.original.exe") else {
        eprintln!("skipping: upx/rg.original.exe corpus fixture absent");
        return;
    };
    let Some(unpacked): Option<Vec<u8>> = read_corpus("upx/rg.unpacked.upx.exe") else {
        eprintln!("skipping: upx/rg.unpacked.upx.exe corpus fixture absent");
        return;
    };
    assert_eq!(
        baseline.len(),
        unpacked.len(),
        "UPX round-trip must preserve total length for rg.exe megafile"
    );
    let diffs: u64 = baseline
        .iter()
        .zip(unpacked.iter())
        .filter(|(a, b): &(&u8, &u8)| a != b)
        .count() as u64;
    let diff_per_million: u64 = diffs.saturating_mul(1_000_000) / baseline.len() as u64;
    assert!(
        diff_per_million < 500,
        "rg.exe round-trip diff_per_million {diff_per_million} must stay <500 (=0.05%) across 4.27 MB; observed ~61 (~0.006%)"
    );
    let recovered_path: PathBuf = corpus_root().join("upx").join("rg.unpacked.upx.exe");
    let out: std::process::Output = Command::new(&recovered_path)
        .arg("--version")
        .output()
        .expect("recovered rg.exe must execute");
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && stdout.contains("ripgrep"),
        "recovered rg.exe --version must succeed and emit 'ripgrep'; got status={:?} stdout={stdout:?}",
        out.status.code()
    );
}

#[test]
fn in_house_nrv2b_unpacks_hello_to_original_image() {
    let Some(packed): Option<Vec<u8>> = read_corpus("upx/hello.packed.nrv2b.exe") else {
        eprintln!("skipping: upx/hello.packed.nrv2b.exe corpus fixture absent");
        return;
    };
    let out: UpxUnpackOutput =
        unpack_upx(&packed).expect("in-house NRV2B unpacker must succeed on real fixture");
    assert_eq!(out.method, UpxMethod::Nrv2b);
    assert!(
        out.adler_verified,
        "UCL adler32 over the recovered image must match the PackHeader u_adler"
    );
    assert!(out.block_count >= 1);
}

#[test]
fn mpress_detects_hello_x64_real_binary() {
    let Some(bytes): Option<Vec<u8>> = read_corpus("mpress/hello.exe") else {
        eprintln!("skipping: mpress/hello.exe corpus fixture absent");
        return;
    };
    let hits: Vec<PackerDetection> = detect_packers(&bytes);
    assert!(
        has_packer(&hits, Packer::Mpress),
        "real MPRESS-packed hello.exe must be detected: hits={hits:?}"
    );
    let detected: DetectedFormat =
        detect_format(&bytes).expect("packed hello.exe must still parse as PE");
    assert_eq!(detected.kind, NativeFormat::Pe64);
}

#[test]
fn mpress_detects_taskmgr_megafile_and_format_probe_still_works() {
    let Some(bytes): Option<Vec<u8>> = read_corpus("mpress/taskmgr.packed.mpress.exe") else {
        eprintln!("skipping: mpress/taskmgr.packed.mpress.exe corpus fixture absent");
        return;
    };
    assert!(
        bytes.len() > 1_000_000,
        "taskmgr.packed.mpress.exe must be the real megafile, got {} bytes",
        bytes.len()
    );
    let hits: Vec<PackerDetection> = detect_packers(&bytes);
    assert!(
        has_packer(&hits, Packer::Mpress),
        "MPRESS section name (.MPRESS1) must be detected in packed taskmgr.exe: hits={hits:?}"
    );
    let detected: DetectedFormat =
        detect_format(&bytes).expect("packed taskmgr must still parse as PE container");
    assert_eq!(detected.kind, NativeFormat::Pe64);
    assert_eq!(detected.bits, 64);
    assert_eq!(
        Packer::Mpress.unpacker_status(),
        UnpackerStatus::Implemented,
        "MPRESS unpack landed in sprint v0.7 Wave-A1 (from-scratch byte-recovery; see crates/disrobe-pass-native/src/packers/mpress_unpack.rs)"
    );
}

#[test]
fn petite_detects_hello_x86_real_binary() {
    let Some(bytes): Option<Vec<u8>> = read_corpus("petite/hello.exe") else {
        eprintln!("skipping: petite/hello.exe corpus fixture absent");
        return;
    };
    let hits: Vec<PackerDetection> = detect_packers(&bytes);
    assert!(
        has_packer(&hits, Packer::Petite),
        "real Petite-packed hello32.exe must be detected via 'petite' section name: hits={hits:?}"
    );
    let detected: DetectedFormat =
        detect_format(&bytes).expect("packed hello32.exe must still parse as PE32");
    assert_eq!(detected.kind, NativeFormat::Pe32);
    assert_eq!(detected.bits, 32);
    assert_eq!(
        Packer::Petite.unpacker_status(),
        UnpackerStatus::Implemented,
        "Petite unpack landed in sprint v0.7 Wave-A2 (from-scratch byte-recovery; see crates/disrobe-pass-native/src/packers/petite_unpack.rs)"
    );
}

#[test]
fn petite_megafile_skip_is_documented_in_manifest() {
    let manifest_path: PathBuf = corpus_root().join("MANIFEST.toml");
    let toml: String = std::fs::read_to_string(&manifest_path).expect("MANIFEST.toml present");
    assert!(
        toml.contains("Petite") && toml.contains("x86"),
        "MANIFEST must document petite's x86-only constraint and absence of i686 megafile"
    );
}

#[test]
fn detection_distinct_packers_per_real_fixture() {
    let Some(upx_bytes): Option<Vec<u8>> = read_corpus("upx/hello.exe") else {
        eprintln!("skipping: upx/hello.exe corpus fixture absent");
        return;
    };
    let Some(mpress_bytes): Option<Vec<u8>> = read_corpus("mpress/hello.exe") else {
        eprintln!("skipping: mpress/hello.exe corpus fixture absent");
        return;
    };
    let Some(petite_bytes): Option<Vec<u8>> = read_corpus("petite/hello.exe") else {
        eprintln!("skipping: petite/hello.exe corpus fixture absent");
        return;
    };
    let upx_hello: BTreeSet<Packer> = distinct_packers(&detect_packers(&upx_bytes));
    let mpress_hello: BTreeSet<Packer> = distinct_packers(&detect_packers(&mpress_bytes));
    let petite_hello: BTreeSet<Packer> = distinct_packers(&detect_packers(&petite_bytes));
    assert!(upx_hello.contains(&Packer::Upx));
    assert!(mpress_hello.contains(&Packer::Mpress));
    assert!(petite_hello.contains(&Packer::Petite));
    assert!(
        !upx_hello.contains(&Packer::Mpress) && !upx_hello.contains(&Packer::Petite),
        "UPX-packed binary must not false-positive as MPRESS or Petite"
    );
    assert!(
        !mpress_hello.contains(&Packer::Upx) && !mpress_hello.contains(&Packer::Petite),
        "MPRESS-packed binary must not false-positive as UPX or Petite"
    );
    assert!(
        !petite_hello.contains(&Packer::Upx) && !petite_hello.contains(&Packer::Mpress),
        "Petite-packed binary must not false-positive as UPX or MPRESS"
    );
}
