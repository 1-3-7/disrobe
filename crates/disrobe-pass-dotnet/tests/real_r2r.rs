#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
#[cfg(feature = "chain")]
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::r2r::{R2rHeader, R2rReport, detect as r2r_detect, parse_header};

const HELLOAPP_R2R_DLL_REL: &str = "../../corpus/dotnet/HelloApp.r2r.dll";
const HELLOAPP_R2R_EXE_REL: &str = "../../corpus/dotnet/HelloApp.r2r.exe";
const EDGECASES_R2R_DLL_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.r2r.dll";
const HELLOAPP_R2R_HEADER_FILE_OFFSET: usize = 0x1598;
const HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET: usize = 0x177C;

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn r2r_helloapp_dll_parses_as_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(
        pe.clr_directory().is_some(),
        "R2R DLL keeps CLR data directory"
    );
}

#[test]
fn r2r_helloapp_exe_parses_as_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_EXE_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(
        bytes.len() > 64 * 1024,
        "self-contained R2R executable is at least 64 KiB"
    );
    assert!(pe.number_of_sections >= 1);
}

#[test]
fn r2r_edgecases_dll_parses_as_pe() {
    let bytes: Vec<u8> = load(EDGECASES_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(pe.clr_directory().is_some());
    assert!(bytes.len() > 16 * 1024);
}

#[test]
fn r2r_edgecases_dll_report_inspectable() {
    let bytes: Vec<u8> = load(EDGECASES_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let report: R2rReport = r2r_detect(&bytes, &pe, &clr).expect("inspect ReadyToRun image");
    let header: R2rHeader = report
        .header
        .expect("R2R header present in EdgeCases.r2r.dll");
    assert_eq!(header.magic, disrobe_pass_dotnet::r2r::R2R_MAGIC);
    assert_eq!(header.major_version, 10);
    assert_eq!(header.minor_version, 1);
    assert_eq!(header.number_of_sections, 15);
    assert!(report.present);
    assert!(!report.composite_image);
}

#[test]
fn r2r_helloapp_dll_header_passes_invariants() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let report: R2rReport = r2r_detect(&bytes, &pe, &clr).expect("inspect ReadyToRun image");
    let header: R2rHeader = report
        .header
        .expect("R2R header present in HelloApp.r2r.dll");
    assert_eq!(header.magic, disrobe_pass_dotnet::r2r::R2R_MAGIC);
    assert_eq!(header.major_version, 10);
    assert_eq!(header.number_of_sections, 11);
}

#[test]
fn current_ready_to_run_major_version_is_accepted() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_R2R_HEADER_FILE_OFFSET + 4..HELLOAPP_R2R_HEADER_FILE_OFFSET + 6]
        .copy_from_slice(&27u16.to_le_bytes());
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let header: R2rHeader = parse_header(&bytes, &pe, &clr)
        .expect("current ReadyToRun major version must be inspectable");

    assert_eq!(header.major_version, 27);
}

#[cfg(feature = "chain")]
#[test]
fn auto_emits_real_r2r_unwind_and_gc_bounds() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let input: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let children: Vec<disrobe_core::chain::ChildArtifact> = DOTNET_PASS
        .extract_children(&input)
        .expect("the registered pass must inspect the real ReadyToRun DLL");
    let analysis: &disrobe_core::chain::ChildArtifact = children
        .iter()
        .find(|child: &&disrobe_core::chain::ChildArtifact| {
            child.handle.relative_path.ends_with(".analyze.json")
        })
        .expect("the automatic route must emit the .NET analysis artifact");
    let document: serde_json::Value = serde_json::from_slice(&analysis.bytes)
        .expect("the automatic analysis artifact must be JSON");

    assert_eq!(
        document["ready_to_run_sections"],
        serde_json::json!([
            {"type": 100, "name": "compiler_identifier", "rva": 6056, "size": 24},
            {"type": 101, "name": "import_sections", "rva": 8192, "size": 140},
            {"type": 102, "name": "runtime_functions", "rva": 6012, "size": 24},
            {"type": 103, "name": "method_def_entry_points", "rva": 5680, "size": 10},
            {"type": 105, "name": "debug_info", "rva": 7792, "size": 29},
            {"type": 106, "name": "delay_load_method_call_thunks", "rva": 6116, "size": 32},
            {"type": 108, "name": "available_types", "rva": 6000, "size": 9},
            {"type": 109, "name": "instance_method_entry_points", "rva": 6040, "size": 3},
            {"type": 112, "name": "manifest_metadata", "rva": 7548, "size": 244},
            {"type": 118, "name": "manifest_assembly_mvids", "rva": 5996, "size": 0},
            {"type": 119, "name": "cross_module_inline_info", "rva": 6048, "size": 3}
        ])
    );
    assert_eq!(
        document["ready_to_run_runtime_functions"],
        serde_json::json!({
            "layout": "amd64",
            "entries": [
                {
                    "unwind_info_start_rva": 6080,
                    "unwind_info_end_rva": 6106,
                    "gc_info_start_rva": 5968
                },
                {
                    "unwind_info_start_rva": 6112,
                    "unwind_info_end_rva": 6113,
                    "gc_info_start_rva": 5984
                }
            ]
        })
    );
}

#[test]
fn amd64_runtime_function_payload_requires_complete_entries() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let runtime_functions_size_offset: usize = HELLOAPP_R2R_HEADER_FILE_OFFSET + 16 + 2 * 12 + 8;
    assert_eq!(
        u32::from_le_bytes(
            bytes[runtime_functions_size_offset..runtime_functions_size_offset + 4]
                .try_into()
                .expect("fixture section size"),
        ),
        24
    );
    bytes[runtime_functions_size_offset..runtime_functions_size_offset + 4]
        .copy_from_slice(&23u32.to_le_bytes());
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let error: disrobe_pass_dotnet::Error =
        parse_header(&bytes, &pe, &clr).expect_err("partial amd64 entry must be refused");
    assert!(error.to_string().starts_with("DR-DOTNET-0042:"));
    let detection_error: disrobe_pass_dotnet::Error = r2r_detect(&bytes, &pe, &clr)
        .expect_err("public detection must refuse the malformed runtime-function table");
    assert!(detection_error.to_string().starts_with("DR-DOTNET-0042:"));
    let analysis_error: disrobe_pass_dotnet::Error = disrobe_pass_dotnet::analyze(&bytes)
        .expect_err("public analysis must refuse the malformed runtime-function table");
    assert!(analysis_error.to_string().starts_with("DR-DOTNET-0042:"));
    #[cfg(feature = "chain")]
    {
        let input: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let chain_error: disrobe_core::error::CoreError = DOTNET_PASS
            .run(&input)
            .expect_err("automatic recovery must refuse the malformed runtime-function table");
        assert!(chain_error.to_string().contains("DR-DOTNET-0042:"));
    }
}

#[test]
fn runtime_function_unwind_range_must_be_file_backed() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    assert_eq!(
        u32::from_le_bytes(
            bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET
                ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 4]
                .try_into()
                .expect("fixture unwind-info start"),
        ),
        0x17C0
    );
    assert_eq!(
        u32::from_le_bytes(
            bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 4
                ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 8]
                .try_into()
                .expect("fixture unwind-info end"),
        ),
        0x17DA
    );
    bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 4]
        .copy_from_slice(&0xFFFF_F000u32.to_le_bytes());
    bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 4..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 8]
        .copy_from_slice(&0xFFFF_F010u32.to_le_bytes());
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let error: disrobe_pass_dotnet::Error =
        parse_header(&bytes, &pe, &clr).expect_err("unmapped unwind range must be refused");
    assert!(error.to_string().starts_with("DR-DOTNET-0042:"));
}
