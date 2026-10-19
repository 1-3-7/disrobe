#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![cfg(feature = "dotnet")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}
fn image() -> PathBuf {
    root().join("corpus/dotnet/aot/aot_maps_net10_x86_64/aot_maps_net10_x86_64.exe")
}
fn run(input: &Path, resources: &Path, json: bool) -> ToolOutput {
    let binary: PathBuf = PathBuf::from(
        std::env::var_os("DISROBE_BIN")
            .expect("DISROBE_BIN must name the freshly built caller binary"),
    );
    let mut command: CommandSpec = CommandSpec::new(binary, Duration::from_secs(90))
        .arg("dotnet")
        .arg("native-aot")
        .arg(input)
        .arg("--resources")
        .arg(resources)
        .arg("--out")
        .arg(resources.with_extension("report.json"))
        .capture_limits(MAX_CAPTURE_BYTES, 1 << 20);
    if json {
        command = command.arg("--json");
    }
    let output: ToolOutput = tool_output(command).expect("run disrobe");
    assert!(
        !output.timed_out,
        "NativeAOT resource caller exceeded 90 seconds"
    );
    output
}

#[test]
fn extracts_the_committed_nativeaot_resource_bytes() {
    let scratch: ScratchDir = ScratchDir::create("disrobe-native-aot-resources").expect("scratch");
    let out: PathBuf = scratch.path().join("resources");
    let result: ToolOutput = run(&image(), &out, false);
    assert_eq!(
        result.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected_names: BTreeSet<String> = BTreeSet::from([
        "Tidewater.Gauges.gauge_curve.bin".to_owned(),
        "Tidewater.Gauges.tide_table.json".to_owned(),
    ]);
    let extracted_names: BTreeSet<String> = std::fs::read_dir(&out)
        .expect("list extracted resources")
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry
                .expect("read extracted resource entry")
                .file_name()
                .into_string()
                .expect("NativeAOT manifest names are UTF-8")
        })
        .collect();
    assert_eq!(
        extracted_names, expected_names,
        "exact resource filename set"
    );
    for name in ["tide_table.json", "gauge_curve.bin"] {
        assert_eq!(
            std::fs::read(out.join(format!("Tidewater.Gauges.{name}"))).expect("extracted"),
            std::fs::read(
                image()
                    .parent()
                    .expect("parent")
                    .join("resources")
                    .join(name)
            )
            .expect("reference")
        );
    }
}

#[test]
fn json_is_clean_and_nonempty_destination_is_preserved() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-native-aot-resources-json").expect("scratch");
    let out: PathBuf = scratch.path().join("resources");
    std::fs::create_dir(&out).expect("mkdir");
    let sentinel: PathBuf = out.join("sentinel");
    std::fs::write(&sentinel, b"keep").expect("sentinel");
    let refused: ToolOutput = run(&image(), &out, false);
    assert_ne!(refused.exit_code, Some(0));
    assert_eq!(std::fs::read(&sentinel).expect("sentinel"), b"keep");
    let clean: PathBuf = scratch.path().join("clean");
    let json: ToolOutput = run(&image(), &clean, true);
    assert_eq!(json.exit_code, Some(0));
    assert!(
        json.stdout.len() < MAX_CAPTURE_BYTES,
        "JSON capture must be complete"
    );
    serde_json::from_slice::<serde_json::Value>(&json.stdout).expect("json only");
}

#[test]
fn unsafe_resource_name_refuses_before_creating_output() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-native-aot-resource-traversal").expect("scratch");
    let mut bytes: Vec<u8> = std::fs::read(image()).expect("compiler-built NativeAOT fixture");
    let name: &[u8] = b"Tidewater.Gauges.tide_table.json";
    let positions: Vec<usize> = bytes
        .windows(name.len())
        .enumerate()
        .filter_map(|(index, window): (usize, &[u8])| (window == name).then_some(index))
        .collect();
    assert!(
        !positions.is_empty(),
        "fixture must contain the original manifest resource name"
    );
    for position in positions {
        bytes[position..position + 3].copy_from_slice(b"../");
    }
    let hostile: PathBuf = scratch.path().join("traversal.exe");
    std::fs::write(&hostile, bytes).expect("write mutated data fixture");
    let out: PathBuf = scratch.path().join("resources");
    let refused: ToolOutput = run(&hostile, &out, true);
    assert_ne!(refused.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("unsafe resource name"));
    assert!(
        !out.exists(),
        "name validation must precede output creation"
    );
}

#[test]
fn conflicting_manifest_resource_name_refuses_before_creating_output() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-native-aot-resource-conflict").expect("scratch");
    let mut bytes: Vec<u8> = std::fs::read(image()).expect("compiler-built NativeAOT fixture");
    let original: &[u8] = b"Tidewater.Gauges.gauge_curve.bin";
    let conflicting: &[u8] = b"Tidewater.Gauges.tide_table.json";
    assert_eq!(
        original.len(),
        conflicting.len(),
        "the committed names must remain a same-length binary-only mutation pair"
    );
    let positions: Vec<usize> = bytes
        .windows(original.len())
        .enumerate()
        .filter_map(|(index, window): (usize, &[u8])| (window == original).then_some(index))
        .collect();
    assert!(
        !positions.is_empty(),
        "fixture must contain the original gauge manifest resource name"
    );
    for position in positions {
        bytes[position..position + original.len()].copy_from_slice(conflicting);
    }
    let hostile: PathBuf = scratch.path().join("conflicting-resource.exe");
    std::fs::write(&hostile, bytes).expect("write mutated data fixture");
    let out: PathBuf = scratch.path().join("resources");
    let refused: ToolOutput = run(&hostile, &out, true);
    assert_ne!(refused.exit_code, Some(0));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("DR-CLI-0488"),
        "duplicate manifest resource names must produce DR-CLI-0488; stderr: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !out.exists(),
        "resource preflight must refuse duplicate manifest names before output creation"
    );
}
