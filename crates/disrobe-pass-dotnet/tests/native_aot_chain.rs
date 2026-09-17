#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use disrobe_core::chain::{DetectContext, OutputKind, Pass};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::aot::{
    AotMetadataStatus, AotReport, AotSection, decode_metadata_unsigned, detect,
};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use object::{Object as _, ObjectSection as _};

const TRACKED_NATIVE_AOT_IMAGE: &[u8] =
    include_bytes!("../../../corpus/dotnet/megafile/EdgeCases.nativeaot.exe");
const FUNCTION_POINTER_SIGNATURE_KIND: u8 = 0x25;

fn section_file_offset(image: &[u8], section: &AotSection) -> Result<usize, &'static str> {
    let file: object::File<'_, &[u8]> =
        object::File::parse(image).map_err(|_: object::Error| "native image parse failed")?;
    let base: u64 = file.relative_address_base();
    let start_address: u64 = base
        .checked_add(u64::from(section.start_rva))
        .ok_or("section start address overflowed")?;
    for object_section in file.sections() {
        let address: u64 = object_section.address();
        let Some((file_start, file_size)): Option<(u64, u64)> = object_section.file_range() else {
            continue;
        };
        let section_end: u64 = address
            .checked_add(file_size)
            .ok_or("file-backed section end overflowed")?;
        if start_address < address || start_address >= section_end {
            continue;
        }
        let delta: u64 = start_address
            .checked_sub(address)
            .ok_or("section address delta underflowed")?;
        let file_offset: u64 = file_start
            .checked_add(delta)
            .ok_or("section file offset overflowed")?;
        return usize::try_from(file_offset)
            .map_err(|_: std::num::TryFromIntError| "section file offset did not fit usize");
    }
    Err("section was not file backed")
}

fn encode_metadata_unsigned(value: u32) -> Vec<u8> {
    if value < 1 << 7 {
        return vec![(value << 1) as u8];
    }
    if value < 1 << 14 {
        return vec![((value << 2) | 1) as u8, (value >> 6) as u8];
    }
    if value < 1 << 21 {
        return vec![
            ((value << 3) | 3) as u8,
            (value >> 5) as u8,
            (value >> 13) as u8,
        ];
    }
    if value < 1 << 28 {
        return vec![
            ((value << 4) | 7) as u8,
            (value >> 4) as u8,
            (value >> 12) as u8,
            (value >> 20) as u8,
        ];
    }
    let mut encoded: Vec<u8> = vec![15];
    encoded.extend_from_slice(&value.to_le_bytes());
    encoded
}

fn metadata_file_offset(image: &[u8]) -> usize {
    let report: AotReport = detect(image);
    let metadata_section: &AotSection = report
        .ready_to_run
        .as_ref()
        .and_then(|header| header.section(313))
        .expect("the tracked image must carry NativeFormat metadata");
    section_file_offset(image, metadata_section).expect("metadata must be file backed")
}

fn rewrite_type_specification_as_function_pointer(
    image: &mut [u8],
    metadata_offset: usize,
    type_specification_offset: u32,
    target_signature_offset: u32,
) {
    let specification_offset: usize = metadata_offset
        .checked_add(
            usize::try_from(type_specification_offset)
                .expect("the type specification offset must fit usize"),
        )
        .expect("the type specification file offset must fit usize");
    let (original_handle, original_width): (u32, usize) =
        decode_metadata_unsigned(image, specification_offset)
            .expect("the type specification must carry a signature handle");
    let child_offset: u32 = original_handle >> 8;
    let function_pointer_handle: u32 =
        (child_offset << 8) | u32::from(FUNCTION_POINTER_SIGNATURE_KIND);
    let replacement_handle: Vec<u8> = encode_metadata_unsigned(function_pointer_handle);
    assert_eq!(replacement_handle.len(), original_width);
    let specification_end: usize = specification_offset
        .checked_add(original_width)
        .expect("the type specification end must fit usize");
    image[specification_offset..specification_end].copy_from_slice(&replacement_handle);

    let function_pointer_offset: usize = metadata_offset
        .checked_add(
            usize::try_from(child_offset).expect("the function pointer offset must fit usize"),
        )
        .expect("the function pointer file offset must fit usize");
    let target_signature: Vec<u8> = encode_metadata_unsigned(target_signature_offset);
    let function_pointer_end: usize = function_pointer_offset
        .checked_add(target_signature.len())
        .expect("the function pointer end must fit usize");
    assert!(function_pointer_end <= image.len());
    image[function_pointer_offset..function_pointer_end].copy_from_slice(&target_signature);
}

fn assert_transactional_signature_cycle_refusal(image: Vec<u8>) {
    let report: AotReport = detect(&image);
    let AotMetadataStatus::Rejected { reason, .. } = report.metadata_attribution.status else {
        panic!("a recursive root method signature must be rejected");
    };
    assert!(
        reason.contains("method signature type graph contains a cycle"),
        "unexpected rejection: {reason}"
    );
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
    let input: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    let error: disrobe_core::error::CoreError = DOTNET_PASS
        .run(&input)
        .expect_err("ordinary auto must refuse a recursive root method signature");
    assert!(error.to_string().contains("DR-DOTNET-0916"));
}

#[test]
fn auto_emits_recovered_native_aot_names_and_signatures() {
    let context: DetectContext<'_> = DetectContext {
        bytes: TRACKED_NATIVE_AOT_IMAGE,
        path_hint: Some("EdgeCases.nativeaot.exe"),
        parent_hint: None,
        depth: 0,
    };
    let verdict = DOTNET_PASS
        .detector()
        .detect(&context)
        .expect("the registered .NET detector must route a real NativeAOT PE");
    assert_eq!(verdict.pass_id, DOTNET_PASS.id());
    assert_eq!(verdict.format_tag, "dotnet-native-aot");

    let input: Artifact = Artifact::new(Rung::Raw, TRACKED_NATIVE_AOT_IMAGE.to_vec(), [0u8; 32]);
    let output: Artifact = DOTNET_PASS
        .run(&input)
        .expect("the registered pass must recover the real NativeAOT PE");
    assert!(matches!(
        DOTNET_PASS.output_kind(&output),
        OutputKind::Mixed { .. }
    ));
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .expect("the NativeAOT recovery artifact must be JSON");
    let children: Vec<disrobe_core::chain::ChildArtifact> = DOTNET_PASS
        .extract_children(&input)
        .expect("the registered pass must expose the NativeAOT symbols as a terminal artifact");
    assert_eq!(children.len(), 1);
    assert!(children[0].handle.is_terminal());
    assert_eq!(
        children[0].handle.relative_path,
        "nativeaot-net9-symbols.json"
    );
    let terminal_document: serde_json::Value = serde_json::from_slice(&children[0].bytes)
        .expect("the NativeAOT terminal artifact must be JSON");
    assert_eq!(terminal_document, document);
    assert_eq!(document["schema"], "disrobe.dotnet.native-aot-symbols/v1");
    assert_eq!(document["runtime"], "net9");
    let types: &[serde_json::Value] = document["types"]
        .as_array()
        .expect("the recovery artifact must carry types");
    let methods: &[serde_json::Value] = document["methods"]
        .as_array()
        .expect("the recovery artifact must carry methods");
    assert_eq!(types.len(), 425);
    assert_eq!(methods.len(), 44);
    assert!(
        methods
            .iter()
            .all(|method: &serde_json::Value| !method["signature"].is_null()),
        "every reachable method in the supported NativeFormat shape must retain its signature"
    );
    let main: &serde_json::Value = methods
        .iter()
        .find(|method: &&serde_json::Value| {
            method["declaring_type"] == "EdgeCasesAot.Program" && method["name"] == "Main"
        })
        .expect("the compiler-emitted Program.Main record must be recovered");
    assert_eq!(main["signature"]["calling_convention"], 0);
    assert_eq!(main["signature"]["generic_parameter_count"], 0);
    assert_eq!(
        main["signature"]["return_type"],
        serde_json::json!({"kind": "definition", "record_offset": 3957})
    );
    assert_eq!(
        main["signature"]["parameter_types"],
        serde_json::json!([{"kind": "specification", "record_offset": 7376}])
    );
    assert_eq!(
        main["signature"]["vararg_parameter_types"],
        serde_json::json!([])
    );
}

#[test]
fn unsupported_nativeformat_version_is_a_typed_auto_refusal() {
    let mut image: Vec<u8> = TRACKED_NATIVE_AOT_IMAGE.to_vec();
    let original: AotReport = detect(&image);
    let header_offset: usize = usize::try_from(
        original
            .ready_to_run
            .as_ref()
            .expect("the tracked image must carry a header")
            .file_offset,
    )
    .expect("the tracked header offset must fit usize");
    let minor_offset: usize = header_offset
        .checked_add(6)
        .expect("the header minor-version offset must fit usize");
    let minor_end: usize = minor_offset
        .checked_add(2)
        .expect("the header minor-version end must fit usize");
    image[minor_offset..minor_end].copy_from_slice(&2u16.to_le_bytes());

    let report: AotReport = detect(&image);
    assert!(matches!(
        report.metadata_attribution.status,
        AotMetadataStatus::UnsupportedVersion {
            major_version: 10,
            minor_version: 2,
        }
    ));
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
    let input: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    let error: disrobe_core::error::CoreError = DOTNET_PASS
        .run(&input)
        .expect_err("auto must refuse an unsupported NativeFormat version");
    assert!(error.to_string().contains("DR-DOTNET-0914"));
}

#[test]
fn absent_nativeformat_metadata_is_a_typed_auto_success() {
    let mut image: Vec<u8> = TRACKED_NATIVE_AOT_IMAGE.to_vec();
    let original: AotReport = detect(&image);
    let header = original
        .ready_to_run
        .as_ref()
        .expect("the tracked image must carry a header");
    let metadata_index: usize = header
        .sections
        .iter()
        .position(|section: &AotSection| section.id == 313)
        .expect("the tracked image must carry NativeFormat metadata");
    let header_offset: usize =
        usize::try_from(header.file_offset).expect("the tracked header offset must fit usize");
    let metadata_row_offset: usize = metadata_index
        .checked_mul(24)
        .and_then(|offset: usize| offset.checked_add(16))
        .and_then(|offset: usize| offset.checked_add(header_offset))
        .expect("the NativeFormat metadata row offset must fit usize");
    let metadata_id_end: usize = metadata_row_offset
        .checked_add(4)
        .expect("the NativeFormat metadata row end must fit usize");
    image[metadata_row_offset..metadata_id_end].copy_from_slice(&312i32.to_le_bytes());

    let report: AotReport = detect(&image);
    assert!(report.ready_to_run.is_some());
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::NotPresent
    );
    let input: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    let output: Artifact = DOTNET_PASS
        .run(&input)
        .expect("ordinary auto must retain a NativeAOT image without reflection metadata");
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .expect("the NativeAOT absence artifact must be JSON");
    assert_eq!(document["metadata_status"], "NotPresent");
    assert_eq!(document["types"], serde_json::json!([]));
    assert_eq!(document["methods"], serde_json::json!([]));
    let children: Vec<disrobe_core::chain::ChildArtifact> = DOTNET_PASS
        .extract_children(&input)
        .expect("ordinary auto must expose the NativeAOT absence artifact");
    assert_eq!(children.len(), 1);
    assert!(children[0].handle.is_terminal());
    assert_eq!(children[0].bytes, output.envelope);
}

#[test]
fn arbitrary_in_bounds_signature_type_offset_is_a_transactional_auto_refusal() {
    let mut image: Vec<u8> = TRACKED_NATIVE_AOT_IMAGE.to_vec();
    let original: AotReport = detect(&image);
    let metadata_section: &AotSection = original
        .ready_to_run
        .as_ref()
        .and_then(|header| header.section(313))
        .expect("the tracked image must carry NativeFormat metadata");
    let metadata_offset: usize =
        section_file_offset(&image, metadata_section).expect("metadata must be file backed");
    let main_signature_offset: usize = metadata_offset
        .checked_add(2915)
        .expect("the Main signature offset must fit usize");
    let (_, convention_width): (u32, usize) =
        decode_metadata_unsigned(&image, main_signature_offset)
            .expect("the Main calling convention must be encoded");
    let generic_count_offset: usize = main_signature_offset
        .checked_add(convention_width)
        .expect("the Main generic count offset must fit usize");
    let (_, generic_count_width): (u32, usize) =
        decode_metadata_unsigned(&image, generic_count_offset)
            .expect("the Main generic count must be encoded");
    let return_type_offset: usize = generic_count_offset
        .checked_add(generic_count_width)
        .expect("the Main return type offset must fit usize");
    let (_, original_width): (u32, usize) = decode_metadata_unsigned(&image, return_type_offset)
        .expect("the Main return type must be encoded");
    let invalid_type_handle: u32 = (4000 << 8) | 0x3a;
    let replacement: Vec<u8> = encode_metadata_unsigned(invalid_type_handle);
    assert_eq!(replacement.len(), original_width);
    let return_type_end: usize = return_type_offset
        .checked_add(original_width)
        .expect("the Main return type end must fit usize");
    image[return_type_offset..return_type_end].copy_from_slice(&replacement);

    let report: AotReport = detect(&image);
    assert!(matches!(
        report.metadata_attribution.status,
        AotMetadataStatus::Rejected { .. }
    ));
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
    let input: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    let error: disrobe_core::error::CoreError = DOTNET_PASS
        .run(&input)
        .expect_err("ordinary auto must refuse an unresolved signature type definition");
    assert!(error.to_string().contains("DR-DOTNET-0916"));
}

#[test]
fn root_method_signature_self_cycle_is_a_transactional_auto_refusal() {
    let mut image: Vec<u8> = TRACKED_NATIVE_AOT_IMAGE.to_vec();
    let metadata_offset: usize = metadata_file_offset(&image);
    rewrite_type_specification_as_function_pointer(&mut image, metadata_offset, 7376, 2915);
    assert_transactional_signature_cycle_refusal(image);
}

#[test]
fn root_method_signature_mutual_cycle_is_a_transactional_auto_refusal() {
    let mut image: Vec<u8> = TRACKED_NATIVE_AOT_IMAGE.to_vec();
    let metadata_offset: usize = metadata_file_offset(&image);
    rewrite_type_specification_as_function_pointer(&mut image, metadata_offset, 29194, 27455);
    rewrite_type_specification_as_function_pointer(&mut image, metadata_offset, 29706, 25765);
    assert_transactional_signature_cycle_refusal(image);
}

#[test]
fn shared_acyclic_root_method_signature_is_reused_by_auto() {
    let mut image: Vec<u8> = TRACKED_NATIVE_AOT_IMAGE.to_vec();
    let metadata_offset: usize = metadata_file_offset(&image);
    rewrite_type_specification_as_function_pointer(&mut image, metadata_offset, 29194, 7427);
    rewrite_type_specification_as_function_pointer(&mut image, metadata_offset, 29706, 7427);

    let report: AotReport = detect(&image);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    assert_eq!(report.metadata_attribution.types.len(), 425);
    assert_eq!(report.metadata_attribution.methods.len(), 44);
    let input: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    DOTNET_PASS
        .run(&input)
        .expect("ordinary auto must accept shared acyclic root method signatures");
}

#[test]
fn malformed_signature_refuses_the_entire_attribution_graph() {
    let mut image: Vec<u8> = TRACKED_NATIVE_AOT_IMAGE.to_vec();
    let original: AotReport = detect(&image);
    let header = original
        .ready_to_run
        .as_ref()
        .expect("the tracked image must carry a header");
    let metadata_section: &AotSection = header
        .section(313)
        .expect("the tracked image must carry NativeFormat metadata");
    let metadata_offset: usize =
        section_file_offset(&image, metadata_section).expect("metadata must be file backed");
    let main_signature_offset: usize = metadata_offset
        .checked_add(2915)
        .expect("the Main signature offset must fit usize");
    image[main_signature_offset] = 0x20;

    let report: AotReport = detect(&image);
    assert!(matches!(
        report.metadata_attribution.status,
        AotMetadataStatus::Rejected {
            section_offset: Some(2915),
            ..
        }
    ));
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
}
