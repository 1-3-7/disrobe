#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

//! End-to-end recovery against a *real* Nuitka 4.1.1 `--onefile` binary (Python 3.14, MSVC
//! `cl` backend), checked in at `corpus/python/nuitka/onefile/hello.exe`. The onefile bundles
//! the full standalone distribution, so its inner `hello.dll` is the genuine compiled module
//! and is reused for the embedded-blob tests rather than committing a second large fixture.
//!
//! Honest ceiling: Nuitka lowers Python to C and then to native code, so the original
//! formatting, local-variable names, and statement structure are gone. What survives - and
//! what these tests assert is recovered from the baked binary - is the data-composer
//! constants blob: function names, parameter names, and literal constants.
//!
//! The oracle is deliberately non-circular:
//!   * onefile extraction is verified byte-for-byte (blake3) against the independently
//!     compiled `--standalone` distribution's own DLLs, whose digests are pinned below;
//!   * symbol recovery (`greet`, `fib`, `main`) is asserted against the independent
//!     `hello.pyi` stub that Nuitka emits, which this pass never produces or consumes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_pass_nuitka::{
    BinaryConstants, BlobScan, DecompSourceKind, Detection, NuitkaDecompilation, NuitkaFlavor,
    NuitkaVariant, NuitkaVersionReport, OnefilePayload, VariantClassification, VersionConfidence,
    classify_in_file, decompile_binary, detect_in_bytes, detect_in_file, detect_nuitka_version,
    extract_onefile, locate_onefile_payload, scan_constants_blob,
};

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/python/nuitka")
        .join(rel)
}

/// The seven payload entries a real Windows `--onefile` build embeds, in payload order.
const ONEFILE_ENTRY_NAMES: [&str; 7] = [
    "hello.dll",
    "_wmi.pyd",
    "_zstd.pyd",
    "python314.dll",
    "unicodedata.pyd",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
];

/// blake3 of each onefile-extracted entry. Every digest except `hello.dll` was computed from
/// the independently compiled `--standalone` distribution's own copy of that DLL (a separate
/// Nuitka invocation, different output exe), so a match proves the zstd unwrap is byte-exact
/// against an independent source rather than against this pass's own output.
const ENTRY_BLAKE3: [(&str, &str); 7] = [
    (
        "hello.dll",
        "5dbec351ece99bf0af46c6a0e7bd283994ab61143f718df6ecd9217b5bf9bbe3",
    ),
    (
        "_wmi.pyd",
        "722ab60bb0156fdec7d4480455ac05f68d5e9e711c81028cbe31b50f47e11e26",
    ),
    (
        "_zstd.pyd",
        "3c99d4b9994563b9acebfe5656eec2cbbc109e0c81b79411469d0206cf846e6e",
    ),
    (
        "python314.dll",
        "295319cd410ce4550c0340712510d1a8f91d842969831f9f7661205fc5cfb7c3",
    ),
    (
        "unicodedata.pyd",
        "cf1bc1290d4fc58b6bce03099acfcb250d148bef0cb284488c1878dc1c8c9c80",
    ),
    (
        "vcruntime140.dll",
        "5675f1e7f32381301c4a1023cde274adab869aefa5c5f76e6b87e751d72940f1",
    ),
    (
        "vcruntime140_1.dll",
        "f05c6a774c58e3bfeba090067c525bd2932e6e7fa10f3be21df799212d0488da",
    ),
];

/// Extract the inner compiled module (`hello.dll`) carried by the onefile payload. The
/// onefile bundles the same standalone distribution it was built from, so this inner module
/// is the genuine `--standalone` compiled binary - exercising the embedded-blob recovery
/// path without committing a second multi-megabyte fixture.
fn onefile_inner_module() -> Vec<u8> {
    let bytes: Vec<u8> = std::fs::read(corpus("onefile/hello.exe")).expect("onefile binary");
    let located = locate_onefile_payload(&bytes).expect("onefile payload located");
    let payload: OnefilePayload =
        extract_onefile(&bytes, located.offset).expect("payload extracted");
    payload
        .entries
        .into_iter()
        .find(|e| e.filename == "hello.dll")
        .expect("inner hello.dll module present")
        .data
}

/// Parse the function names declared in Nuitka's independent `.pyi` stub. This pass never
/// emits a `.pyi`, so using it as the expected set keeps the oracle non-circular.
fn pyi_function_names(pyi: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in pyi.lines() {
        let trimmed: &str = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("def ")
            && let Some(open) = rest.find('(')
        {
            names.insert(rest[..open].trim().to_owned());
        }
    }
    names
}

#[test]
fn onefile_extraction_is_byte_exact_against_independent_dist() {
    let bytes: Vec<u8> =
        std::fs::read(corpus("onefile/hello.exe")).expect("checked-in onefile binary");
    let located = locate_onefile_payload(&bytes).expect("onefile payload located");
    assert!(
        located.compressed,
        "default onefile is zstd-compressed (KAY)"
    );

    let payload: OnefilePayload =
        extract_onefile(&bytes, located.offset).expect("zstd payload extracted");
    assert_eq!(payload.entries.len(), ONEFILE_ENTRY_NAMES.len());

    let names: Vec<&str> = payload
        .entries
        .iter()
        .map(|e| e.filename.as_str())
        .collect();
    assert_eq!(names, ONEFILE_ENTRY_NAMES);

    for entry in &payload.entries {
        assert_eq!(entry.data.len() as u64, entry.size, "{}", entry.filename);
        let Some((_, want)): Option<&(&str, &str)> = ENTRY_BLAKE3
            .iter()
            .find(|(name, _)| *name == entry.filename)
        else {
            panic!("no pinned digest for {}", entry.filename);
        };
        let got: String = blake3::hash(&entry.data).to_hex().to_string();
        assert_eq!(
            got.as_str(),
            *want,
            "{} extracted bytes must match the independent source digest",
            entry.filename
        );
    }
}

#[test]
fn compiled_module_recovers_symbols_matching_independent_pyi() {
    let module: Vec<u8> = onefile_inner_module();
    let scan: BlobScan =
        scan_constants_blob(&module).expect("data-composer constants blob recovered");

    let pyi: String = std::fs::read_to_string(corpus("onefile/hello.pyi")).expect("pyi stub");
    let expected: BTreeSet<String> = pyi_function_names(&pyi);
    assert_eq!(
        expected,
        BTreeSet::from(["greet".to_owned(), "fib".to_owned(), "main".to_owned()]),
        "independent pyi declares greet/fib/main"
    );

    for name in &expected {
        assert!(
            scan.strings.contains(name),
            "function name '{name}' must be recovered from the baked binary blob"
        );
    }

    assert!(
        scan.ints.contains(&20),
        "literal fib(20) argument recovered from the blob"
    );
    assert!(
        scan.ints.contains(&0) && scan.ints.contains(&1),
        "fib seed literals 0 and 1 recovered from the blob"
    );
}

#[test]
fn onefile_decompile_recovers_inner_module_constants() {
    let decomp: NuitkaDecompilation =
        decompile_binary(&corpus("onefile/hello.exe")).expect("decompile onefile");
    assert_eq!(decomp.source_kind, DecompSourceKind::OnefilePayload);

    let binary_constants: &BinaryConstants = decomp
        .binary_constants
        .as_ref()
        .expect("inner-module blob constants present");

    let pyi: String = std::fs::read_to_string(corpus("onefile/hello.pyi")).expect("pyi stub");
    for name in pyi_function_names(&pyi) {
        assert!(
            binary_constants.strings.contains(&name),
            "onefile inner module must recover '{name}' from its data-composer blob"
        );
    }

    assert!(
        decomp
            .notes
            .iter()
            .any(|n: &String| n.contains("inner module") && n.contains("data-composer blob")),
        "a note must record the inner-module blob recovery"
    );
}

#[test]
fn compiled_module_blob_recovery_is_self_contained() {
    let module: Vec<u8> = onefile_inner_module();
    let scan: BlobScan = scan_constants_blob(&module).expect("blob constants present");
    let constants: BinaryConstants = BinaryConstants::from(&scan);
    assert!(constants.strings.contains("greet"));
    assert!(constants.strings.contains("fib"));
    assert!(constants.strings.contains("main"));
    assert!(constants.blob_len > 0);
}

#[test]
fn compiled_module_versions_to_modern_era_python_3_14() {
    let module: Vec<u8> = onefile_inner_module();
    let detection: Detection = detect_in_bytes(&module).expect("detect inner module");
    assert_eq!(detection.version.python_major, Some(3));
    assert_eq!(detection.version.python_minor, Some(14));

    let version: NuitkaVersionReport = detect_nuitka_version(&module, None, Some((3, 14)));
    assert_eq!(version.confidence, VersionConfidence::Range);
    assert_eq!(
        version.era_label.as_deref(),
        Some("4.x / modern 3.x loader (verified against 4.1.1 corpus)"),
        "real 4.1.1 compiled module resolves to the modern era row"
    );
}

#[test]
fn onefile_binary_classifies_as_compressed_onefile() {
    let classification: VariantClassification =
        classify_in_file(&corpus("onefile/hello.exe")).expect("classify onefile");
    assert_eq!(classification.variant, NuitkaVariant::OnefileKay);
    assert!(classification.onefile_compressed);
    assert!(classification.onefile_offset.is_some());

    let detection: Detection = detect_in_file(&corpus("onefile/hello.exe")).expect("detect");
    assert_eq!(detection.flavor, NuitkaFlavor::OnefileZstd);
    assert!(
        detection
            .hits
            .iter()
            .any(|h: &String| h == "NUITKA_ONEFILE_PARENT"),
        "onefile bootstrap env-var marker present"
    );
}
