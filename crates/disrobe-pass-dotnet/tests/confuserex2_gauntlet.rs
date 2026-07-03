#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::pass::{PassSummary, analyze};
use disrobe_pass_dotnet::peel::confuserex_constants::peel_confuserex_constants;
use disrobe_pass_dotnet::peel::{ConfuserConstantsRecovery, RecoveredString};
use disrobe_pass_dotnet::protectors::Protector;

const CLEAN_REL: &str = "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.clean.exe";
const OBFUSCATED_REL: &str =
    "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.confuserex2.exe";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("fixture missing at {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn obfuscated_binary_is_larger_and_strings_are_absent() {
    let clean: Vec<u8> = load(CLEAN_REL);
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    assert!(
        obf.len() > clean.len(),
        "ConfuserEx2 with constants+ctrlflow+rename must grow the PE: clean={} obf={}",
        clean.len(),
        obf.len()
    );
    let needles: &[&[u8]] = &[
        b"DISROBE_GAUNTLET_API_KEY_7749",
        b"DISROBE_SECRET_TOKEN_ALPHA",
        b"Server=gauntlet-db",
        b"gauntlet-build-v1",
    ];
    for needle in needles {
        let present: bool = obf.windows(needle.len()).any(|w: &[u8]| w == *needle);
        assert!(
            !present,
            "constant-encrypted string {:?} must not appear in plaintext in the obfuscated \
             binary; ConfuserEx2 constants protection encrypted it",
            std::str::from_utf8(needle).unwrap_or("?")
        );
    }
}

#[test]
fn confuserex2_detected_in_obfuscated_binary() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let summary: PassSummary = analyze(&obf).expect("analyze must succeed on real managed PE");
    let detected: bool = summary
        .protectors_detected
        .iter()
        .any(|p: &Protector| matches!(p, Protector::ConfuserEx | Protector::ConfuserEx2));
    assert!(
        detected,
        "ConfuserEx2 watermark written by v1.6.0 must be detected; got {:?}",
        summary.protectors_detected
    );
}

#[test]
fn obfuscated_binary_parses_as_managed_pe() {
    use disrobe_pass_dotnet::metadata::{METADATA_SIGNATURE, MetadataRoot, parse_metadata_root};
    use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};

    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let pe: PeImage = parse(&obf).expect("PE parse must succeed");
    let clr: ClrHeader = parse_clr_header(&obf, &pe).expect("CLR header survives obfuscation");
    let root: MetadataRoot =
        parse_metadata_root(&obf, &pe, &clr).expect("metadata root survives obfuscation");
    assert_eq!(
        root.signature, METADATA_SIGNATURE,
        "BSJB signature must be intact after ConfuserEx2"
    );
    assert!(
        !root.streams.is_empty(),
        "metadata streams must be present in obfuscated PE"
    );
}

#[test]
fn constants_protection_blob_located_and_seed_recovered() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let recovery: ConfuserConstantsRecovery = peel_confuserex_constants(&obf)
        .expect("peel must not error on real managed PE")
        .expect(
            "constants blob must be located: ConfuserEx2 constants protection injects a \
             LayoutKind.Explicit field-RVA blob",
        );
    assert!(
        recovery.blob_size > 0 && recovery.blob_size.is_multiple_of(64),
        "blob must be nonzero and a multiple of 64 (one AES-like block each); got {}",
        recovery.blob_size
    );
    assert_ne!(
        recovery.seed, 0,
        "recovered seed must be nonzero (xorshift state 0 is degenerate)"
    );
    assert!(
        recovery.constant_pool_len > 0,
        "LZMA-decompressed constant pool must be non-empty"
    );
}

#[test]
fn constants_pool_yields_known_encrypted_strings() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let recovery: ConfuserConstantsRecovery = peel_confuserex_constants(&obf)
        .expect("peel must not error")
        .expect("constants protection present");

    let required: &[&str] = &[
        "DISROBE_GAUNTLET_API_KEY_7749",
        "DISROBE_SECRET_TOKEN_ALPHA",
        "gauntlet-build-v1",
    ];

    let recovered_texts: Vec<&str> = recovery
        .strings_recovered
        .iter()
        .map(|r: &RecoveredString| r.text.as_str())
        .collect();

    for expected in required {
        assert!(
            recovered_texts.contains(expected),
            "constant-pool decryption must recover {:?} from the ConfuserEx2-encrypted pool; \
             recovered {} string(s): {:?}",
            expected,
            recovered_texts.len(),
            recovered_texts
        );
    }

    assert!(
        recovery.strings_recovered.len() >= 3,
        "at least 3 encrypted strings must be recovered; got {}",
        recovery.strings_recovered.len()
    );
}

#[test]
fn obfuscated_name_heap_contains_confuser_style_identifiers() {
    use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root, read_strings_heap};
    use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
    use disrobe_pass_dotnet::peel::name_check::is_confuser_style;
    use disrobe_pass_dotnet::peel::{NameClassification, classify_names};
    use std::collections::BTreeMap;

    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let pe: PeImage = parse(&obf).expect("pe");
    let clr: ClrHeader = parse_clr_header(&obf, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&obf, &pe, &clr).expect("md root");
    let md: &[u8] = pe
        .slice_at_rva(&obf, clr.metadata.rva, clr.metadata.size as usize)
        .expect("md slice");
    let strings_header: &disrobe_pass_dotnet::metadata::StreamHeader = root
        .streams
        .get("#Strings")
        .expect("#Strings heap must be present");
    let heap: BTreeMap<u32, String> = read_strings_heap(md, *strings_header);
    let classification: NameClassification = classify_names(&heap);
    assert!(
        classification.confuser_style > 0 || classification.renamable > 0,
        "ConfuserEx2 rename protection must produce obfuscated identifiers; \
         confuser_style={} renamable={}",
        classification.confuser_style,
        classification.renamable
    );
    let confuser_count: usize = heap
        .values()
        .filter(|n: &&String| is_confuser_style(n))
        .count();
    assert!(
        confuser_count > 0,
        "at least one ConfuserEx-style name (unprintable or _NNN pattern) must appear in rename \
         output; got {} confuser-style names in heap of {} entries",
        confuser_count,
        heap.len()
    );
}
