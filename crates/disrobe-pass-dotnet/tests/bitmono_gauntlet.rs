#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
//! Real `BitMono` 0.41.1 gauntlet.

use std::path::PathBuf;

use disrobe_pass_dotnet::pass::{PassSummary, analyze};
use disrobe_pass_dotnet::pe::{PeImage, parse};
use disrobe_pass_dotnet::protectors::{DetectionReport, GreyZone, Protector, detect_all};

const BITMONO_REL: &str =
    "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.bitmono.dll";
const CLEAN_REL: &str =
    "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.clean.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

fn nt_signature(image: &[u8]) -> u32 {
    let lfanew: usize = u32::from_le_bytes(image[0x3C..0x40].try_into().unwrap()) as usize;
    u32::from_le_bytes(image[lfanew..lfanew + 4].try_into().unwrap())
}

#[test]
fn real_bitmono_uses_the_antiildasm_nt_signature_flip() {
    assert_eq!(
        nt_signature(&load(CLEAN_REL)),
        0x0000_4550,
        "clean baseline has the canonical PE\\0\\0 signature"
    );
    assert_eq!(
        nt_signature(&load(BITMONO_REL)),
        0x0001_4550,
        "BitMono AntiILdasm flips bit 16 of the NT signature; the gauntlet target"
    );
}

#[test]
fn real_bitmono_detected_as_bitmono() {
    let bytes: Vec<u8> = load(BITMONO_REL);
    let report: DetectionReport = detect_all(&bytes);
    assert_eq!(
        report.primary,
        Some(Protector::BitMono),
        "real BitMono assembly must detect as BitMono; got {:?}",
        report.primary
    );
    assert!(report.matches.contains_key(&Protector::BitMono));
}

#[test]
fn clean_baseline_not_flagged_as_bitmono() {
    let bytes: Vec<u8> = load(CLEAN_REL);
    let report: DetectionReport = detect_all(&bytes);
    assert!(
        !report.matches.contains_key(&Protector::BitMono),
        "the clean pre-obfuscation baseline must NOT flag BitMono (no AntiILdasm/zeroed-CLR): {:?}",
        report.matches.keys().collect::<Vec<_>>()
    );
}

#[test]
fn real_bitmono_analyzes_despite_header_corruption() {
    let bytes: Vec<u8> = load(BITMONO_REL);
    let summary: PassSummary = analyze(&bytes).unwrap_or_else(|e| {
        panic!(
            "disrobe must parse the BitMono assembly despite AntiILdasm + zeroed CLR/metadata \
             sizes (Windows loads it fine); before the fix this errored: {e}"
        )
    });
    assert_eq!(summary.primary_protector, Some(Protector::BitMono));
}

#[test]
fn real_bitmono_parses_as_managed_pe() {
    let bytes: Vec<u8> = load(BITMONO_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe despite AntiILdasm NT-sig flip");
    let clr = pe
        .clr_directory()
        .expect("CLR data directory present (rva valid, size zeroed)");
    assert_ne!(clr.rva, 0, "CLR rva survives BitMono's size-zeroing");
}

#[test]
fn bitmono_is_green_zone_foss() {
    assert_eq!(Protector::BitMono.grey_zone(), GreyZone::Green);
}
