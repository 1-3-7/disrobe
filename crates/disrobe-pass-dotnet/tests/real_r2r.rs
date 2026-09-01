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
use disrobe_pass_dotnet::r2r::{
    R2rHeader, R2rMethodDefIdentityJoin, R2rReport, R2rRuntimeFunctions, detect as r2r_detect,
    parse_header,
};
use disrobe_pass_dotnet::{PassSummary, decompile_assembly};

const HELLOAPP_R2R_DLL_REL: &str = "../../corpus/dotnet/HelloApp.r2r.dll";
const HELLOAPP_R2R_EXE_REL: &str = "../../corpus/dotnet/HelloApp.r2r.exe";
const EDGECASES_R2R_DLL_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.r2r.dll";
const HELLOAPP_R2R_HEADER_FILE_OFFSET: usize = 0x1598;
const HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET: usize = 0x177C;
const HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET: usize = 0x1630;
const HELLOAPP_METHOD_DEF_ENTRY_POINTS_SIZE_OFFSET: usize =
    HELLOAPP_R2R_HEADER_FILE_OFFSET + 16 + 3 * 12 + 8;
const HELLOAPP_IMPORT_SECTIONS_FILE_OFFSET: usize = 0x2000;
const R2R_IMPORT_SECTION_LEN: usize = 20;
const HELLOAPP_STRING_HANDLE_IMPORT_INDEX: usize = 6;
const HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET: usize = 0x20fd;
const HELLOAPP_USER_STRING_HEAP_FILE_OFFSET: usize = 0x1c70;

const fn string_handle_import_field_offset(field_offset: usize) -> usize {
    HELLOAPP_IMPORT_SECTIONS_FILE_OFFSET
        + HELLOAPP_STRING_HANDLE_IMPORT_INDEX * R2R_IMPORT_SECTION_LEN
        + field_offset
}

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

fn r2r_error(bytes: &[u8]) -> disrobe_pass_dotnet::Error {
    let pe: PeImage = parse(bytes).expect("parse mutated R2R PE");
    let clr: ClrHeader = parse_clr_header(bytes, &pe).expect("mutated R2R CLR header");
    r2r_detect(bytes, &pe, &clr).expect_err("mutated MethodDef entry points must be refused")
}

fn analyzed_runtime_functions(bytes: &[u8]) -> serde_json::Value {
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(bytes).expect("analyze mutated ReadyToRun DLL");
    serde_json::to_value(summary.ready_to_run_runtime_functions)
        .expect("serialize ReadyToRun runtime functions")
}

fn assert_fixup_unsupported(bytes: &[u8]) {
    let runtime_functions: serde_json::Value = analyzed_runtime_functions(bytes);
    assert_eq!(
        runtime_functions["method_def_identity"],
        serde_json::json!({"status": "recovered", "attached": 1, "abstained": 1})
    );
    assert_eq!(
        runtime_functions["entries"][0]["method_def_abstention"],
        serde_json::json!({
            "token": 0x0600_0001,
            "name": "<Main>$",
            "reason": "fixup_unsupported"
        })
    );
}

#[cfg(feature = "chain")]
fn automatic_runtime_functions(bytes: Vec<u8>) -> serde_json::Value {
    let input: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let children: Vec<disrobe_core::chain::ChildArtifact> = DOTNET_PASS
        .extract_children(&input)
        .expect("automatic route must inspect mutated ReadyToRun DLL");
    let analysis: &disrobe_core::chain::ChildArtifact = children
        .iter()
        .find(|child: &&disrobe_core::chain::ChildArtifact| {
            child.handle.relative_path.ends_with(".analyze.json")
        })
        .expect("automatic route must emit a .NET analysis artifact");
    let document: serde_json::Value =
        serde_json::from_slice(&analysis.bytes).expect("automatic analysis artifact must be JSON");
    document["ready_to_run_runtime_functions"].clone()
}

#[test]
fn helloapp_runtime_function_has_exact_metadata_method_identity() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    assert_eq!(
        &bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET
            ..HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 10],
        &[0x10, 0x01, 0x02, 0x02, 0x02, 0x26, 0x02, 0x06, 0x00, 0x04]
    );
    let decompiled: disrobe_pass_dotnet::DecompiledAssembly =
        decompile_assembly(&bytes).expect("decompile tracked R2R metadata");
    let metadata_method: &disrobe_pass_dotnet::StructuredMethod = decompiled
        .methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::StructuredMethod| method.token == 0x0600_0002)
        .expect("tracked metadata MethodDef 0x06000002");
    assert!(
        metadata_method.signature.contains(".ctor("),
        "tracked MethodDef 0x06000002 must independently name .ctor: {}",
        metadata_method.signature
    );
    let fixup_metadata_method: &disrobe_pass_dotnet::StructuredMethod = decompiled
        .methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::StructuredMethod| method.token == 0x0600_0001)
        .expect("tracked metadata MethodDef 0x06000001");
    assert!(
        fixup_metadata_method.signature.contains("<Main>$("),
        "tracked MethodDef 0x06000001 must independently name <Main>$: {}",
        fixup_metadata_method.signature
    );
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(&bytes).expect("analyze tracked ReadyToRun DLL");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");

    assert_eq!(
        runtime_functions["entries"][1]["method_def"],
        serde_json::json!({"token": 0x0600_0002, "name": ".ctor"})
    );
    assert_eq!(
        runtime_functions["entries"][0]["method_def"],
        serde_json::json!({"token": 0x0600_0001, "name": "<Main>$"})
    );
    assert!(runtime_functions["entries"][0]["method_def_abstention"].is_null());
    assert_eq!(
        runtime_functions["method_def_identity"],
        serde_json::json!({"status": "recovered", "attached": 2, "abstained": 0})
    );
}

#[test]
fn helloapp_constructor_runtime_function_lifts_exact_unwind_bounded_body() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    assert_eq!(
        &bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12
            ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 24],
        &[
            0xE0, 0x17, 0x00, 0x00, 0xE1, 0x17, 0x00, 0x00, 0x60, 0x17, 0x00, 0x00,
        ]
    );
    let decompiled: disrobe_pass_dotnet::DecompiledAssembly =
        decompile_assembly(&bytes).expect("decompile tracked R2R metadata");
    let metadata_constructor: &disrobe_pass_dotnet::StructuredMethod = decompiled
        .methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::StructuredMethod| method.token == 0x0600_0002)
        .expect("tracked metadata constructor");
    assert_eq!(
        metadata_constructor.signature.lines().next_back(),
        Some("public void .ctor()")
    );
    let pe: PeImage = parse(&bytes).expect("parse tracked ReadyToRun PE");
    let body_offset: usize = pe
        .rva_to_offset(0x17E0)
        .expect("tracked constructor body RVA is file backed");
    assert_eq!(&bytes[body_offset..=body_offset], &[0xc3]);
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(&bytes).expect("analyze tracked ReadyToRun DLL");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");

    assert_eq!(
        runtime_functions["entries"][1]["method_body"],
        serde_json::json!({
            "range": {"start_rva": 6112, "end_rva": 6113},
            "status": "recovered",
            "signature": "registers",
            "pseudo_c": "#include <stdint.h>\nuint64_t recovered(void) {\n    uint64_t r_rax = 0;\n    return r_rax;\n}\n"
        })
    );
}

#[test]
fn unsupported_constructor_instruction_preserves_method_identity() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse tracked ReadyToRun PE");
    let body_offset: usize = pe
        .rva_to_offset(0x17E0)
        .expect("tracked constructor body RVA is file backed");
    bytes[body_offset] = 0xCC;
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(&bytes).expect("unsupported body remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");
    assert_eq!(
        runtime_functions["entries"][1]["method_def"],
        serde_json::json!({"token": 0x0600_0002, "name": ".ctor"})
    );
    assert_eq!(
        runtime_functions["entries"][1]["method_body"]["reason"],
        serde_json::json!("native_lifter_refused")
    );
}

#[test]
fn malformed_constructor_runtime_function_range_preserves_method_identity() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 8]
        .copy_from_slice(&0x17E0u32.to_le_bytes());
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(&bytes).expect("malformed body range remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");

    assert_eq!(
        runtime_functions["entries"][1]["method_def"],
        serde_json::json!({"token": 0x0600_0002, "name": ".ctor"})
    );
    assert_eq!(
        runtime_functions["entries"][1]["method_body"],
        serde_json::json!({
            "status": "refused",
            "range": {"start_rva": 6112, "end_rva": 6112},
            "reason": "range_malformed"
        })
    );
}

#[test]
fn overlapping_constructor_runtime_function_range_is_refused_with_attribution() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4]
        .copy_from_slice(&0x17C5u32.to_le_bytes());
    bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 8]
        .copy_from_slice(&0x17D0u32.to_le_bytes());
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(&bytes).expect("overlapping body range remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");

    assert_eq!(
        runtime_functions["entries"][1]["method_body"]["reason"],
        serde_json::json!("range_overlaps")
    );
    assert_eq!(
        runtime_functions["entries"][1]["method_def"]["token"],
        serde_json::json!(0x0600_0002)
    );
}

#[test]
fn oversized_constructor_runtime_function_range_is_refused_with_attribution() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 8]
        .copy_from_slice(&0x0010_17E1u32.to_le_bytes());
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(&bytes).expect("oversized body range remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");

    assert_eq!(
        runtime_functions["entries"][1]["method_body"]["reason"],
        serde_json::json!("input_budget_exhausted")
    );
    assert_eq!(
        runtime_functions["entries"][1]["method_def"]["name"],
        serde_json::json!(".ctor")
    );
}

#[test]
fn trailing_decodable_constructor_body_byte_is_boundary_ambiguous() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse tracked ReadyToRun PE");
    let trailing_offset: usize = pe
        .rva_to_offset(0x17E1)
        .expect("constructor trailing body RVA is file backed");
    bytes[trailing_offset] = 0x90;
    bytes[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 8]
        .copy_from_slice(&0x17E2u32.to_le_bytes());

    let runtime_functions: serde_json::Value = analyzed_runtime_functions(&bytes);
    assert_eq!(
        runtime_functions["entries"][1]["method_body"],
        serde_json::json!({
            "status": "refused",
            "range": {"start_rva": 6112, "end_rva": 6114},
            "reason": "boundary_ambiguous"
        })
    );
}

#[cfg(feature = "chain")]
#[test]
fn automatic_r2r_analysis_preserves_method_body_refusals() {
    let mut malformed: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    malformed[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 8]
        .copy_from_slice(&0x17E0u32.to_le_bytes());

    let mut overlapping: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    overlapping[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4]
        .copy_from_slice(&0x17C5u32.to_le_bytes());
    overlapping[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 8]
        .copy_from_slice(&0x17D0u32.to_le_bytes());

    let mut unsupported: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let pe: PeImage = parse(&unsupported).expect("parse tracked ReadyToRun PE");
    let body_offset: usize = pe
        .rva_to_offset(0x17E0)
        .expect("tracked constructor body RVA is file backed");
    unsupported[body_offset] = 0xCC;

    let mut budget_exhausted: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    budget_exhausted[HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 4
        ..HELLOAPP_RUNTIME_FUNCTIONS_FILE_OFFSET + 12 + 8]
        .copy_from_slice(&0x0010_17E1u32.to_le_bytes());

    for (case, bytes, reason) in [
        ("malformed", malformed, "range_malformed"),
        ("overlapping", overlapping, "range_overlaps"),
        ("unsupported", unsupported, "native_lifter_refused"),
        (
            "budget exhausted",
            budget_exhausted,
            "input_budget_exhausted",
        ),
    ] {
        let expected: serde_json::Value = analyzed_runtime_functions(&bytes);
        assert_eq!(
            expected["entries"][1]["method_body"]["reason"], reason,
            "{case}"
        );
        assert_eq!(automatic_runtime_functions(bytes), expected, "{case}");
    }
}

#[test]
fn truncated_method_def_native_array_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_SIZE_OFFSET
        ..HELLOAPP_METHOD_DEF_ENTRY_POINTS_SIZE_OFFSET + 4]
        .copy_from_slice(&9u32.to_le_bytes());

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn truncated_unobserved_method_def_native_array_header_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET] = 0x01;
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_SIZE_OFFSET
        ..HELLOAPP_METHOD_DEF_ENTRY_POINTS_SIZE_OFFSET + 4]
        .copy_from_slice(&1u32.to_le_bytes());

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn out_of_range_method_def_native_array_tree_offset_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 1] = u8::MAX;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn tracked_fixup_bearing_method_def_entry_point_recovers_identity_and_bounded_body() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let summary: PassSummary = disrobe_pass_dotnet::analyze(&bytes)
        .expect("analyze tracked ReadyToRun DLL with a fixup-bearing entry");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");
    assert_eq!(
        runtime_functions["method_def_identity"],
        serde_json::json!({"status": "recovered", "attached": 2, "abstained": 0})
    );
    assert_eq!(
        runtime_functions["entries"][0]["method_def"],
        serde_json::json!({"token": 0x0600_0001, "name": "<Main>$"})
    );
    assert!(runtime_functions["entries"][0]["method_def_abstention"].is_null());
    assert_eq!(
        runtime_functions["entries"][0]["method_body"],
        serde_json::json!({
            "status": "refused",
            "range": {"start_rva": 0x17c0, "end_rva": 0x17da},
            "reason": "native_lifter_refused"
        })
    );
}

#[test]
fn non_terminating_fixup_list_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 7] = 0x88;
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 8] = 0x88;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn overlapping_fixup_list_and_method_payload_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 5] = 0x16;
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 7] = 0x04;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn method_def_runtime_function_index_outside_table_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 9] = 0x08;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn method_def_native_array_rid_outside_metadata_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET] = 0x18;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn compact_leaf_method_def_native_array_is_an_explicit_refusal() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 2] = 0x00;

    let summary: PassSummary = disrobe_pass_dotnet::analyze(&bytes)
        .expect("unobserved compact-leaf NativeArray remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");
    assert_eq!(
        runtime_functions["method_def_identity"],
        serde_json::json!({"status": "unsupported_layout"})
    );
}

#[test]
fn fixup_bearing_method_def_duplicate_runtime_function_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 6] = 0x06;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn fixup_import_slot_outside_string_handle_section_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 7] = 0x07;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn fixup_string_handle_slot_outside_import_section_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 7] = 0x16;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn inconsistent_fixup_import_section_entry_size_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let entry_size_offset: usize = string_handle_import_field_offset(11);
    bytes[entry_size_offset] = 7;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn amd64_string_handle_entry_width_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[string_handle_import_field_offset(11)] = 4;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn import_section_unknown_flag_bits_are_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let flags_offset: usize = string_handle_import_field_offset(8);
    bytes[flags_offset..flags_offset + 2].copy_from_slice(&0x8000u16.to_le_bytes());

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn import_section_unknown_type_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[string_handle_import_field_offset(10)] = 1;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn valid_unsupported_import_section_preserves_explicit_abstention() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[string_handle_import_field_offset(10)] = 2;
    let signatures_rva_offset: usize = string_handle_import_field_offset(12);
    bytes[signatures_rva_offset..signatures_rva_offset + 4].fill(0);

    assert_fixup_unsupported(&bytes);
}

#[test]
fn zero_import_section_index_resolves_a_bounded_string_handle_slot() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let first_record: std::ops::Range<usize> = HELLOAPP_IMPORT_SECTIONS_FILE_OFFSET
        ..HELLOAPP_IMPORT_SECTIONS_FILE_OFFSET + R2R_IMPORT_SECTION_LEN;
    let string_record_start: usize = HELLOAPP_IMPORT_SECTIONS_FILE_OFFSET
        + HELLOAPP_STRING_HANDLE_IMPORT_INDEX * R2R_IMPORT_SECTION_LEN;
    let string_record: Vec<u8> =
        bytes[string_record_start..string_record_start + R2R_IMPORT_SECTION_LEN].to_vec();
    bytes[first_record].copy_from_slice(&string_record);
    bytes[string_record_start + 4..string_record_start + 8].fill(0);
    bytes[string_record_start + 10] = 0;
    bytes[string_record_start + 12..string_record_start + 16].fill(0);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 7] = 0;

    let runtime_functions: serde_json::Value = analyzed_runtime_functions(&bytes);
    assert_eq!(
        runtime_functions["entries"][0]["method_def"],
        serde_json::json!({"token": 0x0600_0001, "name": "<Main>$"})
    );
}

#[test]
fn non_file_backed_fixup_signature_table_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let signatures_rva_offset: usize = string_handle_import_field_offset(12);
    bytes[signatures_rva_offset..signatures_rva_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn malformed_string_handle_signature_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 1] = 0;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn string_handle_token_outside_user_string_heap_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 1] = 0x7f;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn string_handle_after_unreachable_user_string_garbage_is_accepted() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 1..HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 6]
        .copy_from_slice(&[0xff, 0x03, 0x41, 0x00, 0x00]);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 1] = 2;

    let runtime_functions: serde_json::Value = analyzed_runtime_functions(&bytes);
    assert_eq!(
        runtime_functions["entries"][0]["method_def"],
        serde_json::json!({"token": 0x0600_0001, "name": "<Main>$"})
    );
}

#[test]
fn noncanonical_user_string_length_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 1] = 0x80;
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 2] = 0x1b;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn invalid_user_string_terminal_byte_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 28] = 2;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn mismatched_plain_user_string_terminal_byte_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 28] = 1;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn matched_special_user_string_terminal_byte_is_accepted() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 2] = 0x27;
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 28] = 1;

    let runtime_functions: serde_json::Value = analyzed_runtime_functions(&bytes);
    assert_eq!(
        runtime_functions["entries"][0]["method_def"],
        serde_json::json!({"token": 0x0600_0001, "name": "<Main>$"})
    );
}

#[test]
fn mismatched_special_user_string_terminal_byte_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 2] = 0x27;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn unpaired_surrogate_user_string_is_accepted() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 2] = 0;
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 3] = 0xd8;
    bytes[HELLOAPP_USER_STRING_HEAP_FILE_OFFSET + 28] = 1;

    let runtime_functions: serde_json::Value = analyzed_runtime_functions(&bytes);
    assert_eq!(
        runtime_functions["entries"][0]["method_def"],
        serde_json::json!({"token": 0x0600_0001, "name": "<Main>$"})
    );
}

#[test]
fn noncanonical_string_handle_signature_integer_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 1] = 0x80;
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 2] = 0x01;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn malformed_string_handle_signature_integer_prefix_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 1] = 0xff;
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 2] = 0x01;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn module_override_string_handle_preserves_explicit_abstention() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET] = 0x9b;
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 1] = 1;
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET + 2] = 1;

    assert_fixup_unsupported(&bytes);
}

#[test]
fn bare_module_override_fixup_kind_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET] = 0x80;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn other_valid_fixup_kind_preserves_explicit_abstention() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET] = 0x1a;

    assert_fixup_unsupported(&bytes);
}

#[test]
fn final_v10_fixup_kind_preserves_explicit_abstention() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET] = 0x36;

    assert_fixup_unsupported(&bytes);
}

#[test]
fn post_v10_fixup_kind_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET] = 0x37;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn subsequent_fixup_import_section_delta_is_checked() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_SIZE_OFFSET
        ..HELLOAPP_METHOD_DEF_ENTRY_POINTS_SIZE_OFFSET + 4]
        .copy_from_slice(&11u32.to_le_bytes());
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 8] = 0x20;
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 9] = 0;
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 10] = 0;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn multi_byte_method_def_entry_point_is_an_explicit_refusal() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 6] = 0x01;

    let summary: PassSummary = disrobe_pass_dotnet::analyze(&bytes)
        .expect("unobserved multi-byte entry point remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");
    assert_eq!(
        runtime_functions["method_def_identity"],
        serde_json::json!({"status": "unsupported_layout"})
    );
}

#[test]
fn duplicate_method_def_runtime_function_index_is_refused() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET + 6] = 0x0a;

    assert!(r2r_error(&bytes).to_string().starts_with("DR-DOTNET-0042:"));
}

#[test]
fn unobserved_method_def_native_array_index_width_is_an_explicit_refusal() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    bytes[HELLOAPP_METHOD_DEF_ENTRY_POINTS_FILE_OFFSET] = 0x12;

    let summary: PassSummary = disrobe_pass_dotnet::analyze(&bytes)
        .expect("unobserved MethodDef NativeArray index width remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");
    assert_eq!(
        runtime_functions["method_def_identity"],
        serde_json::json!({"status": "unsupported_layout"})
    );
    assert!(runtime_functions["entries"][0]["method_def"].is_null());
    assert!(runtime_functions["entries"][0]["method_def_abstention"].is_null());
}

#[test]
fn legacy_runtime_function_json_defaults_method_identity_fields() {
    let json: &str = r#"{
        "layout":"amd64",
        "entries":[{
            "unwind_info_start_rva":6300,
            "unwind_info_end_rva":6370,
            "gc_info_start_rva":20832
        }]
    }"#;
    let runtime_functions: R2rRuntimeFunctions =
        serde_json::from_str(json).expect("deserialize legacy runtime-function report");

    match runtime_functions {
        R2rRuntimeFunctions::Amd64 {
            entries,
            method_def_identity,
        } => {
            assert_eq!(method_def_identity, R2rMethodDefIdentityJoin::NotAttempted);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].method_def, None);
            assert_eq!(entries[0].method_def_abstention, None);
        }
        other => panic!("expected legacy AMD64 runtime functions, got {other:?}"),
    }
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
    let report: R2rReport =
        r2r_detect(&bytes, &pe, &clr).expect("current ReadyToRun report must be inspectable");

    assert_eq!(header.major_version, 27);
    match report.runtime_functions {
        R2rRuntimeFunctions::Amd64 {
            method_def_identity,
            ..
        } => assert_eq!(
            method_def_identity,
            R2rMethodDefIdentityJoin::UnsupportedLayout
        ),
        other => panic!("expected AMD64 runtime functions, got {other:?}"),
    }
}

#[test]
fn composite_method_def_identity_join_is_an_explicit_refusal() {
    let mut bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let flags_offset: usize = HELLOAPP_R2R_HEADER_FILE_OFFSET + 8;
    let flags: u32 = u32::from_le_bytes(
        bytes[flags_offset..flags_offset + 4]
            .try_into()
            .expect("tracked R2R flags"),
    );
    bytes[flags_offset..flags_offset + 4].copy_from_slice(&(flags | 1).to_le_bytes());
    let summary: PassSummary =
        disrobe_pass_dotnet::analyze(&bytes).expect("composite R2R report remains inspectable");
    let runtime_functions: serde_json::Value =
        serde_json::to_value(summary.ready_to_run_runtime_functions)
            .expect("serialize ReadyToRun runtime functions");

    assert_eq!(
        runtime_functions["method_def_identity"],
        serde_json::json!({"status": "unsupported_layout"})
    );
}

#[cfg(feature = "chain")]
#[test]
fn auto_emits_real_r2r_unwind_and_gc_bounds() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let library_runtime_functions: serde_json::Value = analyzed_runtime_functions(&bytes);
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
        document["ready_to_run_runtime_functions"],
        library_runtime_functions
    );
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
                    "gc_info_start_rva": 5968,
                    "method_def": {
                        "token": 100_663_297,
                        "name": "<Main>$"
                    },
                    "method_body": {
                        "status": "refused",
                        "range": {
                            "start_rva": 6080,
                            "end_rva": 6106
                        },
                        "reason": "native_lifter_refused"
                    }
                },
                {
                    "unwind_info_start_rva": 6112,
                    "unwind_info_end_rva": 6113,
                    "gc_info_start_rva": 5984,
                    "method_def": {
                        "token": 100_663_298,
                        "name": ".ctor"
                    },
                    "method_body": {
                        "status": "recovered",
                        "range": {
                            "start_rva": 6112,
                            "end_rva": 6113
                        },
                        "pseudo_c": "#include <stdint.h>\nuint64_t recovered(void) {\n    uint64_t r_rax = 0;\n    return r_rax;\n}\n",
                        "signature": "registers"
                    }
                }
            ],
            "method_def_identity": {
                "status": "recovered",
                "attached": 2,
                "abstained": 0
            }
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
fn unclaimed_runtime_function_range_remains_a_global_malformed_table_rejection() {
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
    bytes[HELLOAPP_STRING_HANDLE_SIGNATURE_FILE_OFFSET] = 0x1a;
    let error: disrobe_pass_dotnet::Error = disrobe_pass_dotnet::analyze(&bytes)
        .expect_err("unclaimed malformed range must reject the runtime-function table");
    assert!(error.to_string().starts_with("DR-DOTNET-0042:"));
}
