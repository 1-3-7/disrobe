#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use disrobe_bytes::{read_u16_le_at, read_u32_le_at};
use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::aot::{AotMetadataStatus, AotReport, detect};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{PeBitness, PeImage, parse};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/invoke_map_net9_x86_64.exe");
const LINK_MAP: &str = include_str!("fixtures/native_aot/invoke_map_net9_x86_64.link.map.txt");
const UNWIND: &str = include_str!("fixtures/native_aot/invoke_map_net9_x86_64.unwind.txt");
const NET8_IMAGE: &[u8] = include_bytes!("fixtures/native_aot/invoke_map_net8_x86_64.exe");
const NET8_LINK_MAP: &str = include_str!("fixtures/native_aot/invoke_map_net8_x86_64.link.map.txt");
const NET8_UNWIND: &str = include_str!("fixtures/native_aot/invoke_map_net8_x86_64.unwind.txt");
const EXCEPTION_DIRECTORY_INDEX: usize = 3;
const AMD64_MACHINE: u16 = 0x8664;
const RUNTIME_FUNCTION_SIZE: usize = 12;

fn compiler_method_rva(symbol: &str) -> Result<u32, &'static str> {
    compiler_method_rva_from(LINK_MAP, symbol)
}

fn compiler_method_rva_from(link_map: &str, symbol: &str) -> Result<u32, &'static str> {
    let base_text: &str = link_map
        .lines()
        .find_map(|line: &str| {
            line.split_once("Preferred load address is ")
                .map(|(_, value): (&str, &str)| value)
        })
        .ok_or("compiler map load address is absent")?;
    let base: u64 = u64::from_str_radix(base_text.trim(), 16)
        .map_err(|_: std::num::ParseIntError| "compiler map load address is malformed")?;
    let address_text: &str = link_map
        .lines()
        .find(|line: &&str| line.contains(symbol))
        .and_then(|line: &str| line.split_whitespace().nth(2))
        .ok_or("compiler map method address is absent")?;
    let address: u64 = u64::from_str_radix(address_text, 16)
        .map_err(|_: std::num::ParseIntError| "compiler map method address is malformed")?;
    let rva: u64 = address
        .checked_sub(base)
        .ok_or("compiler map address precedes image base")?;
    u32::try_from(rva).map_err(|_: std::num::TryFromIntError| "compiler map RVA does not fit u32")
}

fn evidence_address_from(unwind: &str, label: &str) -> Result<u64, &'static str> {
    let address: &str = unwind
        .lines()
        .find_map(|line: &str| line.strip_prefix(label))
        .ok_or("LLVM unwind evidence field is absent")?;
    u64::from_str_radix(address.trim().trim_start_matches("0x"), 16)
        .map_err(|_: std::num::ParseIntError| "LLVM unwind evidence address is malformed")
}

fn evidence_range() -> Result<(u32, u32), &'static str> {
    evidence_range_from(UNWIND)
}

fn evidence_range_from(unwind: &str) -> Result<(u32, u32), &'static str> {
    let image_base: u64 = 0x0000_0001_4000_0000;
    let start: u64 = evidence_address_from(unwind, "StartAddress: ")?
        .checked_sub(image_base)
        .ok_or("LLVM start address precedes the image base")?;
    let end: u64 = evidence_address_from(unwind, "EndAddress: ")?
        .checked_sub(image_base)
        .ok_or("LLVM end address precedes the image base")?;
    Ok((
        u32::try_from(start)
            .map_err(|_: std::num::TryFromIntError| "start RVA does not fit u32")?,
        u32::try_from(end).map_err(|_: std::num::TryFromIntError| "end RVA does not fit u32")?,
    ))
}

#[test]
fn net8_auto_emits_the_compiler_method_with_signature_range_and_body() -> Result<(), &'static str> {
    let expected_start: u32 =
        compiler_method_rva_from(NET8_LINK_MAP, "feat017_ManifestProbe__Add")?;
    let expected_range: (u32, u32) = evidence_range_from(NET8_UNWIND)?;
    assert_eq!(expected_range, (expected_start, 0x0011_b6a4));
    let pe: PeImage = parse(NET8_IMAGE)
        .map_err(|_: disrobe_pass_dotnet::Error| "NativeAOT fixture is not a PE image")?;
    assert_eq!(
        (pe.bitness, pe.machine),
        (PeBitness::Pe32Plus, AMD64_MACHINE)
    );
    let code_offset: usize = pe
        .rva_to_offset(expected_start)
        .ok_or("compiler method body is not file backed")?;
    assert_eq!(
        NET8_IMAGE.get(code_offset..code_offset + 4),
        Some([0x8d, 0x04, 0x11, 0xc3].as_slice())
    );

    let input: Artifact = Artifact::new(Rung::Raw, NET8_IMAGE.to_vec(), [0u8; 32]);
    let output: Artifact = match DOTNET_PASS.run(&input) {
        Ok(output) => output,
        Err(error) => panic!("{error}"),
    };
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .map_err(|_: serde_json::Error| "NativeAOT artifact is not JSON")?;
    let method: &serde_json::Value = document["methods"]
        .as_array()
        .and_then(|methods: &Vec<serde_json::Value>| {
            methods.iter().find(|method: &&serde_json::Value| {
                method["declaring_type"] == "ManifestProbe" && method["name"] == "Add"
            })
        })
        .ok_or("compiler-emitted ManifestProbe.Add metadata is absent")?;
    let int32: &serde_json::Value = document["types"]
        .as_array()
        .and_then(|types: &Vec<serde_json::Value>| {
            types
                .iter()
                .find(|candidate: &&serde_json::Value| candidate["record_offset"] == 4892)
        })
        .ok_or("compiler-emitted System.Int32 type record is absent")?;
    assert_eq!(int32["qualified_name"], "System.Int32");
    assert_eq!(
        method["signature"],
        serde_json::json!({
            "record_offset": 29127,
            "calling_convention": 0,
            "generic_parameter_count": 0,
            "return_type": {"kind": "definition", "record_offset": 4892},
            "parameter_types": [
                {"kind": "definition", "record_offset": 4892},
                {"kind": "definition", "record_offset": 4892}
            ],
            "vararg_parameter_types": []
        })
    );
    assert_eq!(method["entrypoint_rva"], expected_start);
    assert_eq!(method["code_range"]["start_rva"], expected_range.0);
    assert_eq!(method["code_range"]["end_rva"], expected_range.1);
    assert_eq!(method["body"]["status"], "recovered");
    assert_eq!(
        method["body"]["pseudo_c"],
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx + r_rdx * 1ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n"
    );

    let mut unknown_header: disrobe_pass_dotnet::aot::ReadyToRunHeader = detect(NET8_IMAGE)
        .ready_to_run
        .ok_or("compiler-emitted NativeAOT header is absent")?;
    assert_eq!(
        (unknown_header.major_version, unknown_header.minor_version),
        (9, 1)
    );
    unknown_header.minor_version = 2;
    let attribution: disrobe_pass_dotnet::aot::AotMetadataAttribution =
        disrobe_pass_dotnet::aot::recover_metadata_attribution(NET8_IMAGE, &unknown_header)
            .map_err(|_: disrobe_pass_dotnet::Error| "unknown metadata version recovery failed")?;
    assert_eq!(
        attribution.status,
        AotMetadataStatus::UnsupportedVersion {
            major_version: 9,
            minor_version: 2,
        }
    );
    assert!(attribution.types.is_empty());
    assert!(attribution.methods.is_empty());
    Ok(())
}

fn directory_header_offset(image: &[u8]) -> Result<usize, &'static str> {
    let pe_offset: usize = usize::try_from(
        read_u32_le_at(image, 0x3c)
            .map_err(|_: disrobe_bytes::ByteReadError| "DOS header is truncated")?,
    )
    .map_err(|_: std::num::TryFromIntError| "PE offset does not fit usize")?;
    pe_offset
        .checked_add(24)
        .and_then(|optional: usize| optional.checked_add(112))
        .and_then(|directories: usize| {
            directories.checked_add(EXCEPTION_DIRECTORY_INDEX.saturating_mul(8))
        })
        .ok_or("exception-directory header offset overflowed")
}

fn code_section_header_offset(image: &[u8], rva: u32) -> Result<usize, &'static str> {
    let pe_offset: usize = usize::try_from(
        read_u32_le_at(image, 0x3c)
            .map_err(|_: disrobe_bytes::ByteReadError| "DOS header is truncated")?,
    )
    .map_err(|_: std::num::TryFromIntError| "PE offset does not fit usize")?;
    let optional_size: usize = usize::from(
        read_u16_le_at(image, pe_offset + 20)
            .map_err(|_: disrobe_bytes::ByteReadError| "COFF header is truncated")?,
    );
    let sections_offset: usize = pe_offset
        .checked_add(24)
        .and_then(|optional: usize| optional.checked_add(optional_size))
        .ok_or("section-table offset overflowed")?;
    let pe: PeImage = parse(image)
        .map_err(|_: disrobe_pass_dotnet::Error| "NativeAOT fixture is not a PE image")?;
    let index: usize = pe
        .sections
        .iter()
        .position(|section: &disrobe_pass_dotnet::pe::SectionHeader| {
            let end: u32 = section
                .virtual_address
                .saturating_add(section.raw_size.max(section.virtual_size));
            rva >= section.virtual_address && rva < end
        })
        .ok_or("method code section is absent")?;
    sections_offset
        .checked_add(index.saturating_mul(40))
        .ok_or("section-header offset overflowed")
}

fn exception_directory(image: &[u8]) -> Result<(PeImage, usize, usize), &'static str> {
    let pe: PeImage = parse(image)
        .map_err(|_: disrobe_pass_dotnet::Error| "NativeAOT fixture is not a PE image")?;
    if pe.bitness != PeBitness::Pe32Plus || pe.machine != AMD64_MACHINE {
        return Err("NativeAOT fixture is not PE32+ AMD64");
    }
    let directory: disrobe_pass_dotnet::pe::DataDirectory = *pe
        .data_directories
        .get(EXCEPTION_DIRECTORY_INDEX)
        .ok_or("exception directory is absent")?;
    let offset: usize = pe
        .rva_to_offset(directory.rva)
        .ok_or("exception directory is not file backed")?;
    let size: usize = usize::try_from(directory.size)
        .map_err(|_: std::num::TryFromIntError| "exception directory size does not fit usize")?;
    Ok((pe, offset, size))
}

fn runtime_function_offset(image: &[u8], start_rva: u32) -> Result<usize, &'static str> {
    let (_pe, directory_offset, directory_size): (PeImage, usize, usize) =
        exception_directory(image)?;
    let directory_end: usize = directory_offset
        .checked_add(directory_size)
        .ok_or("exception directory end overflowed")?;
    let directory: &[u8] = image
        .get(directory_offset..directory_end)
        .ok_or("exception directory is truncated")?;
    directory
        .chunks_exact(RUNTIME_FUNCTION_SIZE)
        .position(|record: &[u8]| {
            read_u32_le_at(record, 0).is_ok_and(|begin: u32| begin == start_rva)
        })
        .and_then(|index: usize| {
            index
                .checked_mul(RUNTIME_FUNCTION_SIZE)
                .and_then(|relative: usize| directory_offset.checked_add(relative))
        })
        .ok_or("compiler method has no runtime-function record")
}

fn assert_boundary_rejected(image: &[u8]) {
    let report: AotReport = detect(image);
    let AotMetadataStatus::Rejected { reason, .. } = report.metadata_attribution.status else {
        panic!("malformed method boundaries did not reject metadata attribution");
    };
    assert!(reason.contains("DR-DOTNET-0038"), "{reason}");
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
}

#[test]
fn auto_emits_the_compiler_method_boundary_with_name_and_signature() -> Result<(), &'static str> {
    let expected_start: u32 =
        compiler_method_rva("feat_017_nativeaot_manifest_probe_ManifestProbe__Add")?;
    let expected_range: (u32, u32) = evidence_range()?;
    assert_eq!(expected_range, (expected_start, 0x0008_83b4));
    let pe: PeImage = parse(IMAGE)
        .map_err(|_: disrobe_pass_dotnet::Error| "NativeAOT fixture is not a PE image")?;
    let code_offset: usize = pe
        .rva_to_offset(expected_start)
        .ok_or("compiler method body is not file backed")?;
    assert_eq!(
        IMAGE.get(code_offset..code_offset + 4),
        Some([0x8d, 0x04, 0x11, 0xc3].as_slice())
    );

    let input: Artifact = Artifact::new(Rung::Raw, IMAGE.to_vec(), [0u8; 32]);
    let output: Artifact = DOTNET_PASS
        .run(&input)
        .map_err(|_: disrobe_core::error::CoreError| "NativeAOT auto route failed")?;
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .map_err(|_: serde_json::Error| "NativeAOT artifact is not JSON")?;
    let method: &serde_json::Value = document["methods"]
        .as_array()
        .and_then(|methods: &Vec<serde_json::Value>| {
            methods.iter().find(|method: &&serde_json::Value| {
                method["declaring_type"] == "ManifestProbe" && method["name"] == "Add"
            })
        })
        .ok_or("compiler-emitted ManifestProbe.Add metadata is absent")?;
    assert!(!method["signature"].is_null());
    assert_eq!(method["entrypoint_rva"], expected_start);
    assert_eq!(method["code_range"]["start_rva"], expected_range.0);
    assert_eq!(method["code_range"]["end_rva"], expected_range.1);
    assert_eq!(method["body"]["status"], "recovered");
    let pseudo_c: &str = method["body"]["pseudo_c"]
        .as_str()
        .ok_or("ManifestProbe.Add pseudo-C body is absent")?;
    assert_eq!(
        pseudo_c,
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx + r_rdx * 1ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n"
    );
    Ok(())
}

#[test]
fn unsupported_native_body_is_a_per_method_auto_refusal() -> Result<(), &'static str> {
    let start_rva: u32 =
        compiler_method_rva("feat_017_nativeaot_manifest_probe_ManifestProbe__Add")?;
    let pe: PeImage = parse(IMAGE)
        .map_err(|_: disrobe_pass_dotnet::Error| "NativeAOT fixture is not a PE image")?;
    let code_offset: usize = pe
        .rva_to_offset(start_rva)
        .ok_or("compiler method body is not file backed")?;
    let mut unsupported: Vec<u8> = IMAGE.to_vec();
    *unsupported
        .get_mut(code_offset)
        .ok_or("compiler method body is truncated")? = 0xcc;

    let input: Artifact = Artifact::new(Rung::Raw, unsupported, [0u8; 32]);
    let output: Artifact = DOTNET_PASS
        .run(&input)
        .map_err(|_: disrobe_core::error::CoreError| {
            "NativeAOT auto route erased valid metadata for an unsupported body"
        })?;
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .map_err(|_: serde_json::Error| "NativeAOT artifact is not JSON")?;
    let method: &serde_json::Value = document["methods"]
        .as_array()
        .and_then(|methods: &Vec<serde_json::Value>| {
            methods.iter().find(|method: &&serde_json::Value| {
                method["declaring_type"] == "ManifestProbe" && method["name"] == "Add"
            })
        })
        .ok_or("compiler-emitted ManifestProbe.Add metadata is absent")?;
    assert_eq!(method["entrypoint_rva"], start_rva);
    assert_eq!(method["code_range"]["start_rva"], start_rva);
    assert_eq!(method["code_range"]["end_rva"], evidence_range()?.1);
    assert_eq!(method["body"]["status"], "refused");
    let reason: &str = method["body"]["reason"]
        .as_str()
        .ok_or("per-method body refusal reason is absent")?;
    assert!(reason.contains("DR-DOTNET-0039"), "{reason}");
    let boundary: u64 = pe
        .image_base
        .checked_add(u64::from(start_rva))
        .ok_or("compiler method boundary virtual address overflowed")?;
    assert!(reason.contains("DR-NATIVE-0029"), "{reason}");
    assert!(reason.contains("trap byte 0xCC"), "{reason}");
    assert!(
        reason.contains(&format!("declared function boundary 0x{boundary:016X}")),
        "{reason}"
    );
    Ok(())
}

#[test]
fn partial_runtime_function_record_rejects_all_attribution() -> Result<(), &'static str> {
    let (_pe, _offset, size): (PeImage, usize, usize) = exception_directory(IMAGE)?;
    let header: usize = directory_header_offset(IMAGE)?;
    let reduced: u32 = u32::try_from(size.saturating_sub(1))
        .map_err(|_: std::num::TryFromIntError| "reduced directory size does not fit u32")?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(header + 4..header + 8)
        .ok_or("exception-directory size field is truncated")?
        .copy_from_slice(&reduced.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn reversed_runtime_function_rejects_all_attribution() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let record: usize = runtime_function_offset(IMAGE, expected_start)?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(record + 4..record + 8)
        .ok_or("runtime-function end field is truncated")?
        .copy_from_slice(&expected_start.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn duplicate_runtime_function_begin_rejects_all_attribution() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let record: usize = runtime_function_offset(IMAGE, expected_start)?;
    let next: usize = record
        .checked_add(RUNTIME_FUNCTION_SIZE)
        .ok_or("next runtime-function offset overflowed")?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(next..next + 4)
        .ok_or("next runtime-function begin field is truncated")?
        .copy_from_slice(&expected_start.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn overlapping_runtime_functions_reject_all_attribution() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let record: usize = runtime_function_offset(IMAGE, expected_start)?;
    let previous: usize = record
        .checked_sub(RUNTIME_FUNCTION_SIZE)
        .ok_or("previous runtime-function offset underflowed")?;
    let previous_end: u32 = read_u32_le_at(IMAGE, previous + 4)
        .map_err(|_: disrobe_bytes::ByteReadError| "previous runtime-function end is truncated")?;
    let overlapping_start: u32 = previous_end
        .checked_sub(1)
        .ok_or("overlapping begin RVA underflowed")?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(record..record + 4)
        .ok_or("runtime-function begin field is truncated")?
        .copy_from_slice(&overlapping_start.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn unsorted_runtime_functions_reject_all_attribution() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let record: usize = runtime_function_offset(IMAGE, expected_start)?;
    let previous: usize = record
        .checked_sub(RUNTIME_FUNCTION_SIZE)
        .ok_or("previous runtime-function offset underflowed")?;
    let previous_start: u32 = read_u32_le_at(IMAGE, previous).map_err(
        |_: disrobe_bytes::ByteReadError| "previous runtime-function start is truncated",
    )?;
    let unsorted_start: u32 = previous_start
        .checked_sub(1)
        .ok_or("unsorted begin RVA underflowed")?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(record..record + 4)
        .ok_or("runtime-function begin field is truncated")?
        .copy_from_slice(&unsorted_start.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn non_file_backed_exception_directory_rejects_all_attribution() -> Result<(), &'static str> {
    let header: usize = directory_header_offset(IMAGE)?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(header..header + 4)
        .ok_or("exception-directory RVA field is truncated")?
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn non_file_backed_unwind_record_rejects_all_attribution() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let record: usize = runtime_function_offset(IMAGE, expected_start)?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(record + 8..record + 12)
        .ok_or("runtime-function unwind field is truncated")?
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn non_executable_runtime_function_rejects_all_attribution() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let section_header: usize = code_section_header_offset(IMAGE, expected_start)?;
    let characteristics_at: usize = section_header
        .checked_add(36)
        .ok_or("section characteristics offset overflowed")?;
    let characteristics: u32 = read_u32_le_at(IMAGE, characteristics_at)
        .map_err(|_: disrobe_bytes::ByteReadError| "section characteristics are truncated")?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(characteristics_at..characteristics_at + 4)
        .ok_or("section characteristics field is truncated")?
        .copy_from_slice(&(characteristics & !0x2000_0000).to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn out_of_image_runtime_function_end_rejects_all_attribution() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let record: usize = runtime_function_offset(IMAGE, expected_start)?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(record + 4..record + 8)
        .ok_or("runtime-function end field is truncated")?
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert_boundary_rejected(&malformed);
    Ok(())
}

#[test]
fn interior_entrypoint_match_is_not_inferred() -> Result<(), &'static str> {
    let expected_start: u32 = evidence_range()?.0;
    let record: usize = runtime_function_offset(IMAGE, expected_start)?;
    let expanded_start: u32 = expected_start
        .checked_sub(1)
        .ok_or("expanded begin RVA underflowed")?;
    let mut shifted: Vec<u8> = IMAGE.to_vec();
    shifted
        .get_mut(record..record + 4)
        .ok_or("runtime-function begin field is truncated")?
        .copy_from_slice(&expanded_start.to_le_bytes());
    let report: AotReport = detect(&shifted);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    let method: &disrobe_pass_dotnet::aot::AotMethod = report
        .metadata_attribution
        .methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::aot::AotMethod| {
            method.name == "Add" && method.entrypoint_rva == Some(expected_start)
        })
        .ok_or("ManifestProbe.Add attribution is absent")?;
    assert_eq!(method.code_range, None);
    Ok(())
}

#[test]
fn absent_exception_directory_keeps_methods_without_code_ranges() -> Result<(), &'static str> {
    let header: usize = directory_header_offset(IMAGE)?;
    let mut absent: Vec<u8> = IMAGE.to_vec();
    absent
        .get_mut(header..header + 8)
        .ok_or("exception-directory entry is truncated")?
        .fill(0);
    let report: AotReport = detect(&absent);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    let input: Artifact = Artifact::new(Rung::Raw, absent, [0u8; 32]);
    let output: Artifact = DOTNET_PASS
        .run(&input)
        .map_err(|_: disrobe_core::error::CoreError| {
            "NativeAOT auto route failed without an exception directory"
        })?;
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .map_err(|_: serde_json::Error| "NativeAOT artifact is not JSON")?;
    assert!(
        document["methods"]
            .as_array()
            .is_some_and(|methods: &Vec<serde_json::Value>| methods
                .iter()
                .all(|method: &serde_json::Value| { method.get("code_range").is_none() }))
    );
    Ok(())
}
