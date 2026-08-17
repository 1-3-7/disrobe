#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    AotLiftReport, DART_POOL_ELEMENT_BASE_BYTES, DartGraphLimits, DartKernel, DartLibAppRecovery,
    DartLiftedFunction, DartPoolLiteralKind, DartPoolTable, dart_isolate_data_bytes,
    dart_vm_data_bytes, decompile_libapp_so_recovery, lift_libapp_aot, parse_dart_kernel,
};
use sha2::{Digest as _, Sha256};

const POOL_ENTRY_BYTES: u64 = 8;
const DILL_SHA256: &str = "cac616c1dad9f9033a2ac88a8637d2435c423c1bcecd022cf54fb94e6ea2ff38";
const ELF_SHA256: &str = "4445e126a7f4c9fc58b681339dfcd0f9e31de81ccf5207bbb7fe3ff05921fa32";

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("flutter_symbol_dart_3_12_2")
        .join(relative)
}

fn fixture_bytes(relative: &str) -> Vec<u8> {
    let path: PathBuf = fixture(relative);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("fixture {} must be readable: {error}", path.display()))
}

#[test]
fn real_dart_symbol_literal_is_typed_from_the_internal_symbol_class() {
    let bytes: Vec<u8> = fixture_bytes("symbol_probe_arm64.so");
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), ELF_SHA256);
    let recovery: DartLibAppRecovery =
        decompile_libapp_so_recovery(&bytes).expect("Dart libapp recovery");
    assert_eq!(recovery.version_hash, "ace654289f5abc240509fc941453ebc5");
    let vm: Vec<u8> = dart_vm_data_bytes(&bytes).expect("VM snapshot data");
    let isolate: Vec<u8> = dart_isolate_data_bytes(&bytes).expect("isolate snapshot data");
    let table: DartPoolTable = DartPoolTable::build(&vm, &isolate, DartGraphLimits::default())
        .expect("Dart 3.12.2 graph parses")
        .expect("Dart 3.12.2 layout matches");
    let symbols: Vec<(u64, String)> = (0..table.slot_count())
        .filter_map(|slot: usize| {
            let offset: u64 =
                DART_POOL_ELEMENT_BASE_BYTES + u64::try_from(slot).ok()? * POOL_ENTRY_BYTES;
            (table.kind_at_offset(offset, false) == DartPoolLiteralKind::Symbol).then(|| {
                table
                    .render_at_offset(offset, false)
                    .map(|value: String| (offset, value))
            })?
        })
        .collect();
    assert_eq!(
        symbols,
        vec![(0x4b30, "Symbol(\"shipment.status\")".to_owned())]
    );

    let dill: Vec<u8> = fixture_bytes("symbol_probe.app.dill");
    assert_eq!(format!("{:x}", Sha256::digest(&dill)), DILL_SHA256);
    let kernel: DartKernel = parse_dart_kernel(&dill).expect("app-only kernel parses");
    assert!(
        kernel
            .sources
            .iter()
            .any(|source| source.text.contains("shipment.status"))
    );
}

#[test]
fn real_dart_symbol_literal_reaches_the_public_aot_lift() {
    let report: AotLiftReport =
        lift_libapp_aot(&fixture_bytes("symbol_probe_arm64.so")).expect("public AOT lift");
    let function: &DartLiftedFunction = report
        .functions
        .iter()
        .find(|function: &&DartLiftedFunction| function.name.as_deref() == Some("symbolProbe"))
        .expect("entry-point function survives tree shaking");
    assert!(
        function
            .best_pseudo_dart()
            .contains("Symbol(\"shipment.status\")"),
        "symbolProbe body: {}",
        function.best_pseudo_dart()
    );
}

#[cfg(feature = "chain")]
#[test]
fn registered_mobile_pass_emits_the_typed_symbol_literal() {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_mobile::chain_detector::MOBILE_PASS;

    let bytes: Vec<u8> = fixture_bytes("symbol_probe_arm64.so");
    let input: Artifact = Artifact::new(Rung::Raw, bytes, [0_u8; 32]);
    let first: Artifact = MOBILE_PASS.run(&input).expect("registered mobile pass");
    let second: Artifact = MOBILE_PASS.run(&input).expect("deterministic mobile pass");
    assert_eq!(first.envelope, second.envelope);
    let report: serde_json::Value =
        serde_json::from_slice(&first.envelope).expect("mobile pass JSON");
    let functions: &[serde_json::Value] = report
        .pointer("/flutter_aot_lift/functions")
        .and_then(serde_json::Value::as_array)
        .expect("Flutter AOT functions");
    let body: &str = functions
        .iter()
        .find(|function: &&serde_json::Value| function["name"] == "symbolProbe")
        .and_then(|function: &serde_json::Value| function["structured_body"].as_str())
        .expect("symbolProbe structured body");
    assert!(body.contains("Symbol(\"shipment.status\")"));
}
