#![cfg(feature = "dotnet")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::run_disrobe;

fn sample() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/dotnet/interop/Interop.dll")
        .to_str()
        .expect("utf8 path")
        .to_owned()
}

#[test]
fn dotnet_interop_lists_pinvoke_imports_exports_and_com_types() {
    let sample: String = sample();
    let run: common::Run = run_disrobe(&["dotnet", "interop", &sample, "--json"]);
    assert_eq!(run.code, 0, "disrobe dotnet interop failed: {}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON report");
    assert_eq!(report["pinvokes"].as_array().expect("pinvokes").len(), 13);
    assert_eq!(
        report["library_imports"].as_array().expect("imports").len(),
        4
    );
    assert_eq!(report["native_callable"][0]["entry_point"], "disrobe_add");
    assert_eq!(
        report["com_imports"][1]["guid"],
        "6D5140C1-7436-11CE-8034-00AA006009FA"
    );

    let text: common::Run = run_disrobe(&["dotnet", "interop", &sample]);
    assert_eq!(
        text.code, 0,
        "disrobe dotnet interop failed: {}",
        text.stderr
    );
    assert!(
        text.stdout.contains(
            "kernel32!GetModuleHandleA <- Disrobe.Samples.Interop.Kernel::ModuleHandle [ansi, winapi]"
        ),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout
            .contains("export disrobe_add -> Disrobe.Samples.Interop.Exports::Add"),
        "{}",
        text.stdout
    );
}
