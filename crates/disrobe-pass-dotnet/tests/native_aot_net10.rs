#![cfg(feature = "chain")]
#![allow(clippy::panic)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::chain::Pass;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::aot::{AotMetadataStatus, AotReport, AotRuntime, detect};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{PeBitness, PeImage, parse};
use object::{Object as _, ObjectSection as _};
use sha2::{Digest as _, Sha256};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/invoke_map_net10_x86_64.exe");
const LEGACY_IMAGE: &[u8] = include_bytes!("fixtures/native_aot/invoke_map_net9_x86_64.exe");
const LINK_MAP: &str = include_str!("fixtures/native_aot/invoke_map_net10_x86_64.link.map.txt");
const UNWIND: &str = include_str!("fixtures/native_aot/invoke_map_net10_x86_64.unwind.txt");
const SOURCE: &str = include_str!("fixtures/native_aot/invoke_map_net10_x86_64.cs");
const PROJECT: &str = include_str!("fixtures/native_aot/invoke_map_net10_x86_64.csproj.txt");
const BUILD: &str = include_str!("fixtures/native_aot/invoke_map_net10_x86_64.build.txt");
const AMD64_MACHINE: u16 = 0x8664;
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);
const TOOL_CAPTURE_BYTES: usize = 1024 * 1024;

fn evidence_address(text: &str, prefix: &str) -> Result<u64, &'static str> {
    let value: &str = text
        .lines()
        .find_map(|line: &str| line.strip_prefix(prefix))
        .ok_or("evidence address is absent")?;
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
        .map_err(|_: std::num::ParseIntError| "evidence address is malformed")
}

fn compiler_method_range() -> Result<(u32, u32), &'static str> {
    let base: u64 = LINK_MAP
        .lines()
        .find_map(|line: &str| line.split_once("Preferred load address is "))
        .map(|(_, value): (&str, &str)| value.trim())
        .ok_or("compiler map load address is absent")
        .and_then(|value: &str| {
            u64::from_str_radix(value, 16)
                .map_err(|_: std::num::ParseIntError| "compiler map load address is malformed")
        })?;
    let address: u64 = LINK_MAP
        .lines()
        .find(|line: &&str| line.contains("invoke_map_net10_x86_64_ManifestProbe__Add"))
        .and_then(|line: &str| line.split_whitespace().nth(2))
        .ok_or("compiler map method address is absent")
        .and_then(|value: &str| {
            u64::from_str_radix(value, 16)
                .map_err(|_: std::num::ParseIntError| "compiler map method address is malformed")
        })?;
    let unwind_start: u64 = evidence_address(UNWIND, "StartAddress: ")?;
    let unwind_end: u64 = evidence_address(UNWIND, "EndAddress: ")?;
    assert_eq!(address, unwind_start);
    let start: u64 = address
        .checked_sub(base)
        .ok_or("compiler method precedes the image base")?;
    let end: u64 = unwind_end
        .checked_sub(base)
        .ok_or("compiler method end precedes the image base")?;
    Ok((
        u32::try_from(start)
            .map_err(|_: std::num::TryFromIntError| "compiler method RVA does not fit u32")?,
        u32::try_from(end)
            .map_err(|_: std::num::TryFromIntError| "compiler method end does not fit u32")?,
    ))
}

fn metadata_file_offset(
    image: &[u8],
    section: &disrobe_pass_dotnet::aot::AotSection,
) -> Result<usize, &'static str> {
    let file: object::File<'_, &[u8]> =
        object::File::parse(image).map_err(|_: object::Error| "fixture is not an object file")?;
    let address: u64 = file
        .relative_address_base()
        .checked_add(u64::from(section.start_rva))
        .ok_or("metadata address overflowed")?;
    for candidate in file.sections() {
        let Some((file_start, file_size)): Option<(u64, u64)> = candidate.file_range() else {
            continue;
        };
        let section_start: u64 = candidate.address();
        let section_end: u64 = section_start
            .checked_add(file_size)
            .ok_or("object section end overflowed")?;
        if !(section_start..section_end).contains(&address) {
            continue;
        }
        let relative: u64 = address
            .checked_sub(section_start)
            .ok_or("metadata address underflowed")?;
        let offset: u64 = file_start
            .checked_add(relative)
            .ok_or("metadata file offset overflowed")?;
        return usize::try_from(offset)
            .map_err(|_: std::num::TryFromIntError| "metadata file offset does not fit usize");
    }
    Err("metadata section is not file backed")
}

fn method(document: &serde_json::Value) -> Result<&serde_json::Value, &'static str> {
    document["methods"]
        .as_array()
        .and_then(|methods: &Vec<serde_json::Value>| {
            methods.iter().find(|candidate: &&serde_json::Value| {
                candidate["declaring_type"] == "ManifestProbe" && candidate["name"] == "Add"
            })
        })
        .ok_or("compiler-emitted ManifestProbe.Add metadata is absent")
}

fn encode_unsigned(value: u32) -> Vec<u8> {
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

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn checked_tool(
    program: &Path,
    arguments: &[OsString],
    label: &str,
) -> Result<CapturedOutput, String> {
    let output: CapturedOutput = run_captured(program, arguments, TOOL_TIMEOUT, TOOL_CAPTURE_BYTES)
        .map_err(|error: std::io::Error| format!("{label} could not start: {error}"))?
        .ok_or_else(|| format!("{label} exceeded {} seconds", TOOL_TIMEOUT.as_secs()))?;
    if output.exit_code == Some(0) {
        return Ok(output);
    }
    Err(format!(
        "{label} exited {:?}; stdout: {}; stderr: {}",
        output.exit_code,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn assert_managed_int32_runtime(pseudo_c: &str) -> Result<(), String> {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("native_aot_managed_int32")
            .map_err(|error: std::io::Error| format!("scratch directory failed: {error}"))?;
    let source_path: PathBuf = scratch.path().join("managed.c");
    let executable_path: PathBuf = scratch.path().join("managed.exe");
    let harness: &str = "\nint main(void) {\n    struct Case { int32_t left; int32_t right; int32_t expected; };\n    const struct Case cases[] = {\n        {0, 0, 0},\n        {-1, 1, 0},\n        {INT32_MAX, 1, INT32_MIN},\n        {INT32_MIN, -1, INT32_MAX},\n        {INT32_MIN, INT32_MIN, 0}\n    };\n    for (uint32_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {\n        if (recovered(cases[index].left, cases[index].right) != cases[index].expected) {\n            return (int)index + 1;\n        }\n    }\n    return 0;\n}\n";
    std::fs::write(&source_path, format!("{pseudo_c}{harness}"))
        .map_err(|error: std::io::Error| format!("managed C source write failed: {error}"))?;
    let compile_arguments: Vec<OsString> = vec![
        OsString::from("-std=c17"),
        OsString::from("-O2"),
        OsString::from("-Wall"),
        OsString::from("-Wextra"),
        OsString::from("-Werror"),
        source_path.as_os_str().to_owned(),
        OsString::from("-o"),
        executable_path.as_os_str().to_owned(),
    ];
    drop(checked_tool(
        Path::new("clang"),
        &compile_arguments,
        "clang managed pseudo-C compile",
    )?);
    drop(checked_tool(
        &executable_path,
        &[],
        "managed pseudo-C boundary runtime",
    )?);
    Ok(())
}

#[test]
fn fixture_provenance_pins_source_project_compiler_and_runtime() {
    assert_eq!(
        sha256_hex(SOURCE.as_bytes()),
        "c7770fbdd4ed862feb00f3b62dfb92371e2686bbbe8df5f16ce9686944d88a3a"
    );
    assert_eq!(
        sha256_hex(PROJECT.as_bytes()),
        "e734c0b344bcd5646acf28b334297e431165912590c360c441889560cc626ae5"
    );
    assert_eq!(
        sha256_hex(IMAGE),
        "88d89791f9811730f4423b2edb5c3aab70a12cc66369f4f59c8e6e9029e4a1d8"
    );
    assert!(SOURCE.contains("public static int Add(int left, int right) => left + right;"));
    assert!(PROJECT.contains("<TargetFramework>net10.0</TargetFramework>"));
    assert!(PROJECT.contains("<PublishAot>true</PublishAot>"));
    assert!(BUILD.contains("Microsoft.DotNet.ILCompiler 10.0.0"));
    assert!(BUILD.contains("runtime/tree/v10.0.0"));
}

#[test]
fn net10_auto_emits_compiler_name_signature_range_and_body() -> Result<(), String> {
    let expected_range: (u32, u32) = compiler_method_range()?;
    assert_eq!(expected_range, (0x0008_2520, 0x0008_2524));
    let pe: PeImage = parse(IMAGE)
        .map_err(|_: disrobe_pass_dotnet::Error| "NativeAOT fixture is not a PE image")?;
    assert_eq!(
        (pe.bitness, pe.machine),
        (PeBitness::Pe32Plus, AMD64_MACHINE)
    );
    let code_offset: usize = pe
        .rva_to_offset(expected_range.0)
        .ok_or("compiler method body is not file backed")?;
    assert_eq!(
        IMAGE.get(code_offset..code_offset + 4),
        Some([0x8d, 0x04, 0x11, 0xc3].as_slice())
    );

    let report: AotReport = detect(IMAGE);
    let header: &disrobe_pass_dotnet::aot::ReadyToRunHeader = report
        .ready_to_run
        .as_ref()
        .ok_or("ReadyToRun header is absent")?;
    assert_eq!((header.major_version, header.minor_version), (16, 0));
    assert_eq!(report.runtime_label, AotRuntime::Net10);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );

    let input: Artifact = Artifact::new(Rung::Raw, IMAGE.to_vec(), [0u8; 32]);
    let first: Artifact = match DOTNET_PASS.run(&input) {
        Ok(output) => output,
        Err(error) => panic!("{error}"),
    };
    let second: Artifact = match DOTNET_PASS.run(&input) {
        Ok(output) => output,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(first.envelope, second.envelope);
    let document: serde_json::Value = serde_json::from_slice(&first.envelope)
        .map_err(|_: serde_json::Error| "NativeAOT artifact is not JSON")?;
    assert_eq!(document["runtime"], "net10");
    let recovered: &serde_json::Value = method(&document)?;
    assert_eq!(recovered["entrypoint_rva"], expected_range.0);
    assert_eq!(recovered["code_range"]["start_rva"], expected_range.0);
    assert_eq!(recovered["code_range"]["end_rva"], expected_range.1);
    assert_eq!(recovered["body"]["status"], "recovered");
    let pseudo_c: &str = recovered["body"]["pseudo_c"]
        .as_str()
        .ok_or_else(|| "managed pseudo-C is absent".to_owned())?;
    assert_eq!(
        pseudo_c,
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx + r_rdx * 1ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n"
    );
    assert_managed_int32_runtime(pseudo_c)?;
    let signature: &serde_json::Value = &recovered["signature"];
    assert_eq!(signature["calling_convention"], 0);
    assert_eq!(signature["generic_parameter_count"], 0);
    assert_eq!(signature["return_type"]["kind"], "definition");
    assert_eq!(
        signature["parameter_types"].as_array().map(Vec::len),
        Some(2)
    );
    assert!(signature["parameter_types"].as_array().is_some_and(
        |parameters: &Vec<serde_json::Value>| {
            parameters
                .iter()
                .all(|parameter: &serde_json::Value| parameter["kind"] == "definition")
        }
    ));
    let int32_offset: &serde_json::Value = &signature["return_type"]["record_offset"];
    assert!(signature["parameter_types"].as_array().is_some_and(
        |parameters: &Vec<serde_json::Value>| {
            parameters
                .iter()
                .all(|parameter: &serde_json::Value| parameter["record_offset"] == *int32_offset)
        }
    ));
    assert!(
        document["types"]
            .as_array()
            .is_some_and(|types: &Vec<serde_json::Value>| types.iter().any(
                |candidate: &serde_json::Value| {
                    candidate["record_offset"] == *int32_offset
                        && candidate["qualified_name"] == "System.Int32"
                }
            ))
    );
    Ok(())
}

#[test]
fn net9_flagged_metadata_invoke_map_remains_compatible() -> Result<(), &'static str> {
    let report: AotReport = detect(LEGACY_IMAGE);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    let recovered: &disrobe_pass_dotnet::aot::AotMethod = report
        .metadata_attribution
        .methods
        .iter()
        .find(|candidate: &&disrobe_pass_dotnet::aot::AotMethod| {
            candidate.name == "Add" && candidate.entrypoint_rva == Some(0x0008_83b0)
        })
        .ok_or("legacy compiler invoke-map attribution changed")?;
    assert!(recovered.signature.is_some());
    Ok(())
}

#[test]
fn unknown_nativeformat_version_refuses_without_partial_attribution() -> Result<(), &'static str> {
    let mut header: disrobe_pass_dotnet::aot::ReadyToRunHeader = detect(IMAGE)
        .ready_to_run
        .ok_or("ReadyToRun header is absent")?;
    header.minor_version = 1;
    let attribution: disrobe_pass_dotnet::aot::AotMetadataAttribution =
        disrobe_pass_dotnet::aot::recover_metadata_attribution(IMAGE, &header)
            .map_err(|_: disrobe_pass_dotnet::Error| "unknown version recovery failed")?;
    assert_eq!(
        attribution.status,
        AotMetadataStatus::UnsupportedVersion {
            major_version: 16,
            minor_version: 1,
        }
    );
    assert!(attribution.types.is_empty());
    assert!(attribution.methods.is_empty());
    Ok(())
}

#[test]
fn net10_handle_discriminator_mutation_rejects_all_attribution() -> Result<(), &'static str> {
    let original: AotReport = detect(IMAGE);
    assert_eq!(
        original.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    let header: &disrobe_pass_dotnet::aot::ReadyToRunHeader = original
        .ready_to_run
        .as_ref()
        .ok_or("ReadyToRun header is absent")?;
    let metadata: &disrobe_pass_dotnet::aot::AotSection = header
        .section(313)
        .ok_or("NativeFormat metadata section is absent")?;
    let metadata_at: usize = metadata_file_offset(IMAGE, metadata)?;
    let signature: &disrobe_pass_dotnet::aot::AotMethodSignature = original
        .metadata_attribution
        .methods
        .iter()
        .find(|candidate: &&disrobe_pass_dotnet::aot::AotMethod| candidate.name == "Add")
        .and_then(|candidate: &disrobe_pass_dotnet::aot::AotMethod| candidate.signature.as_ref())
        .ok_or("ManifestProbe.Add signature record is absent")?;
    let signature_offset: u32 = signature.record_offset;
    let int32_offset: u32 = signature.return_type.record_offset;
    let signature_at: usize = metadata_at
        .checked_add(
            usize::try_from(signature_offset)
                .map_err(|_: std::num::TryFromIntError| "signature offset does not fit usize")?,
        )
        .ok_or("signature file offset overflowed")?;
    let (_, convention_width): (u32, usize) =
        disrobe_pass_dotnet::aot::decode_metadata_unsigned(IMAGE, signature_at)
            .ok_or("signature convention is malformed")?;
    let generic_at: usize = signature_at
        .checked_add(convention_width)
        .ok_or("generic count offset overflowed")?;
    let (_, generic_width): (u32, usize) =
        disrobe_pass_dotnet::aot::decode_metadata_unsigned(IMAGE, generic_at)
            .ok_or("generic count is malformed")?;
    let return_at: usize = generic_at
        .checked_add(generic_width)
        .ok_or("return handle offset overflowed")?;
    let (raw, raw_width): (u32, usize) =
        disrobe_pass_dotnet::aot::decode_metadata_unsigned(IMAGE, return_at)
            .ok_or("return handle is malformed")?;
    let mutated_raw: u32 = raw ^ 0x80;
    assert_eq!(raw & 0x7f, 0x3a);
    assert_eq!(raw >> 7, int32_offset);
    assert_eq!(raw & 0x7f, mutated_raw & 0x7f);
    assert_ne!(raw >> 7, mutated_raw >> 7);
    assert_ne!(raw & 0xff, mutated_raw & 0xff);
    assert_eq!(raw >> 8, mutated_raw >> 8);
    let encoded: Vec<u8> = encode_unsigned(mutated_raw);
    assert_eq!(encoded.len(), raw_width);
    let return_end: usize = return_at
        .checked_add(raw_width)
        .ok_or("return handle end overflowed")?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    malformed
        .get_mut(return_at..return_end)
        .ok_or("return handle is truncated")?
        .copy_from_slice(&encoded);

    let rejected: AotReport = detect(&malformed);
    let AotMetadataStatus::Rejected {
        section_offset,
        reason,
    } = rejected.metadata_attribution.status
    else {
        return Err("mutated NativeFormat handle did not reject");
    };
    assert_eq!(section_offset, Some(mutated_raw >> 7));
    assert!(reason.contains("method signature type definition is not reachable"));
    assert!(rejected.metadata_attribution.types.is_empty());
    assert!(rejected.metadata_attribution.methods.is_empty());
    Ok(())
}
