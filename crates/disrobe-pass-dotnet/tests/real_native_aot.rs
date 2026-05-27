#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::aot::{AotReport, AotRuntime, detect as aot_detect};
use disrobe_pass_dotnet::pe::{DataDirectory, PeImage, parse};

const HELLOAPP_AOT_EXE_REL: &str = "../../corpus/dotnet/HelloAppAot.exe";
const EDGECASES_AOT_EXE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.nativeaot.exe";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn native_aot_helloapp_parses_as_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_AOT_EXE_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(
        bytes.len() > 256 * 1024,
        "fully linked NativeAOT exe is at least 256 KiB"
    );
    assert!(pe.number_of_sections >= 2);
}

#[test]
fn native_aot_edgecases_parses_as_pe() {
    let bytes: Vec<u8> = load(EDGECASES_AOT_EXE_REL);
    let _pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(bytes.len() > 256 * 1024);
}

#[test]
fn native_aot_helloapp_has_no_clr_data_directory() {
    let bytes: Vec<u8> = load(HELLOAPP_AOT_EXE_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let dir: Option<DataDirectory> = pe.clr_directory();
    let is_unmanaged: bool = dir.is_none_or(|d: DataDirectory| d.rva == 0 && d.size == 0);
    assert!(
        is_unmanaged,
        "NativeAOT output is fully native; CLR data directory must be zero/absent, got {dir:?}"
    );
}

#[test]
fn native_aot_helloapp_aot_report_classifies_runtime() {
    let bytes: Vec<u8> = load(HELLOAPP_AOT_EXE_REL);
    let report: AotReport = aot_detect(&bytes);
    assert!(
        matches!(
            report.runtime_label,
            AotRuntime::Net7
                | AotRuntime::Net8
                | AotRuntime::Net9
                | AotRuntime::Net10
                | AotRuntime::Unknown
        ),
        "got {:?}",
        report.runtime_label
    );
}

#[test]
fn native_aot_edgecases_aot_report_inspectable() {
    let bytes: Vec<u8> = load(EDGECASES_AOT_EXE_REL);
    let report: AotReport = aot_detect(&bytes);
    let _ = report.is_native_aot;
    let _ = report.runtime_label;
    let _ = report.modules_table_offset;
    let _ = report.eager_class_constructors;
}
