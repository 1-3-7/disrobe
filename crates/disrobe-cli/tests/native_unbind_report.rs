#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value as Json;

const PACKED: &str = "native/packers/upx/hello.packed.nrv2b.exe";

fn workspace_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn export_manifest() -> Json {
    let packed: PathBuf = workspace_root().join("corpus").join(PACKED);
    assert!(
        packed.is_file(),
        "this gate grades the unbind report on a real packed image; {} is absent",
        packed.display()
    );
    let out: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("native-unbind-report").expect("scratch dir");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("native")
        .arg("export")
        .arg(&packed)
        .arg("--out")
        .arg(out.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn disrobe native export: {error}"));
    assert!(
        process.status.success(),
        "disrobe native export failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let manifest: PathBuf = out.path().join("export.manifest.json");
    let text: String = std::fs::read_to_string(&manifest).unwrap_or_else(|error| {
        panic!("no manifest at {}: {error}", manifest.display());
    });
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("manifest is not json: {error}"))
}

#[test]
fn the_rebuild_manifest_states_whether_relocations_and_imports_were_unbound() {
    let manifest: Json = export_manifest();
    let unbind: &Json = manifest
        .get("unbind")
        .unwrap_or_else(|| panic!("the rebuild manifest carries no `unbind` section"));
    let applied: Option<bool> = unbind.get("applied").and_then(Json::as_bool);
    assert!(
        applied.is_some(),
        "`unbind` must state whether it ran; a caller cannot distinguish a repair that found \
         nothing from one that never happened"
    );
    if applied == Some(true) {
        for field in [
            "relocations_walked",
            "relocations_unapplied",
            "iat_descriptors_walked",
            "iat_thunks_restored",
            "resource_data_entries_walked",
            "resource_offsets_restored",
        ] {
            assert!(
                unbind.get(field).and_then(Json::as_u64).is_some(),
                "an applied unbind must report {field} as a number, so every count is published \
                 with the population it was drawn from"
            );
        }
    } else {
        assert!(
            unbind
                .get("reason")
                .and_then(Json::as_str)
                .is_some_and(|reason: &str| !reason.is_empty()),
            "an unbind that did not run must name why, never report a silent false"
        );
    }
}

#[test]
fn the_rebuilt_import_count_is_no_longer_a_hardcoded_zero() {
    let manifest: Json = export_manifest();
    assert!(
        manifest.get("iat_slots_rewritten").is_some(),
        "the rebuild manifest must publish `iat_slots_rewritten`; it was a struct field set to 0 \
         at every construction site and read by nothing"
    );
    let unbind: &Json = manifest.get("unbind").expect("unbind section");
    if unbind.get("applied").and_then(Json::as_bool) == Some(true) {
        assert_eq!(
            manifest.get("iat_slots_rewritten").and_then(Json::as_u64),
            unbind.get("iat_thunks_restored").and_then(Json::as_u64),
            "the published import count must be the number the unbind pass actually restored, not \
             a separately maintained figure that can drift from it"
        );
    }
}
