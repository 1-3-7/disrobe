#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

mod common;

use std::path::PathBuf;

use disrobe_pass_dotnet::metadata::{MetadataRoot, StreamHeader, parse_metadata_root};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::peel::confuserex_seed::recover_seeds_by_emulation;
use disrobe_pass_dotnet::peel::{
    ConfuserConstantsRecovery, RecoveredString, peel_confuserex_constants,
};
use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Protector, detect_all, plan_execution,
};
use disrobe_pass_dotnet::tables::{Tables, parse_tables};

const KNOWN_SEED: u32 = 0xF5F4_A2BF;

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

const FIXTURE: &str = "../../corpus/dotnet/SampleConstants.confuserex2.dll";
const KNOWN_PLAINTEXT: &str = "DISROBE_CONFUSER_CONSTANT_PROOF_8842";
const SECRET_CALL_SITE_ID: u32 = 1_242_836_064;

fn load_fixture() -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(FIXTURE);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "real ConfuserEx2 constants fixture missing at {} ({e}); a missing fixture must \
             hard-fail, never silent-skip",
            path.display()
        )
    })
}

#[test]
fn confuserex2_signature_detected_in_synth_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"ConfuserEx2 v1.6.0");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::ConfuserEx2));
}

#[test]
fn confuserex2_delegates_to_de4dot() {
    let plan: ExecutionOutcome = plan_execution(Protector::ConfuserEx2, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::DelegatedToDe4dot));
}

#[test]
fn confuserex2_constants_recovers_real_encrypted_string() {
    let bytes: Vec<u8> = load_fixture();

    assert!(
        !bytes
            .windows(KNOWN_PLAINTEXT.len())
            .any(|w: &[u8]| w == KNOWN_PLAINTEXT.as_bytes()),
        "plaintext must NOT appear in the obfuscated fixture - proves real encryption, not a \
         trivial string scan"
    );

    let recovery: ConfuserConstantsRecovery = peel_confuserex_constants(&bytes)
        .expect("peel ok")
        .expect("constants protection present in fixture");

    assert_eq!(
        recovery.seed, 0xF5F4_A2BF,
        "in-house decryptor must recover the per-build keySeed from the fixture's own injected IL"
    );
    assert_eq!(
        recovery.blob_size, 64,
        "constants blob is one 16-uint32 block (LayoutKind.Explicit Size=64)"
    );
    assert_eq!(
        recovery.constant_pool_len, 40,
        "LZMA-decompressed pool is the 4-byte length prefix plus the 36-byte string"
    );

    let hit: &RecoveredString = recovery
        .strings_recovered
        .iter()
        .find(|s: &&RecoveredString| s.text == KNOWN_PLAINTEXT)
        .unwrap_or_else(|| {
            panic!(
                "in-house decryptor must recover the ConfuserEx2-encrypted plaintext; got {:?}",
                recovery.strings_recovered
            )
        });
    assert_eq!(hit.call_site_id, SECRET_CALL_SITE_ID);
    assert_eq!(hit.mutated_offset, 0);
}

#[test]
fn emulating_the_constants_bootstrap_recovers_the_real_seed() {
    let bytes: Vec<u8> = load_fixture();
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("md");
    let md: &[u8] = pe
        .slice_at_rva(&bytes, clr.metadata.rva, clr.metadata.size as usize)
        .expect("md slice");
    let header: &StreamHeader = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .expect("table stream");
    let tables: Tables = parse_tables(md, *header).expect("tables");

    let seeds: Vec<u32> = recover_seeds_by_emulation(&bytes, &pe, &tables.methods);
    assert!(
        seeds.contains(&KNOWN_SEED),
        "executing the bootstrap seed expression must yield the same keySeed the literal scan \
         finds and that decrypts the real fixture; got {seeds:#010x?}"
    );
}
