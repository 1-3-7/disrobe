#![cfg(feature = "chain")]
#![allow(clippy::panic)]

use disrobe_core::chain::{ChildArtifact, Pass};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::aot::{AotMetadataStatus, detect};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{PeBitness, PeImage, parse};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/invoke_map_net7_x86_64.exe");
const SOURCE: &str = include_str!("fixtures/native_aot/invoke_map_net7_x86_64.cs");
const PROJECT: &str = include_str!("fixtures/native_aot/invoke_map_net7_x86_64.csproj.txt");
const SDK_PIN: &str = include_str!("fixtures/native_aot/invoke_map_net7_x86_64.global.json.txt");
const BUILD: &str = include_str!("fixtures/native_aot/invoke_map_net7_x86_64.build.txt");
const LINK_MAP: &str = include_str!("fixtures/native_aot/invoke_map_net7_x86_64.link.map.txt");
const UNWIND: &str = include_str!("fixtures/native_aot/invoke_map_net7_x86_64.unwind.txt");
const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
const AMD64_MACHINE: u16 = 0x8664;

fn compiler_method_rva(symbol: &str) -> Result<u32, &'static str> {
    let base_text: &str = LINK_MAP
        .lines()
        .find_map(|line: &str| {
            line.split_once("Preferred load address is ")
                .map(|(_, value): (&str, &str)| value)
        })
        .ok_or("compiler map load address is absent")?;
    let base: u64 = u64::from_str_radix(base_text.trim(), 16)
        .map_err(|_: std::num::ParseIntError| "compiler map load address is malformed")?;
    let address_text: &str = LINK_MAP
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

fn evidence_rva(label: &str) -> Result<u32, &'static str> {
    let address_text: &str = UNWIND
        .lines()
        .find_map(|line: &str| line.strip_prefix(label))
        .ok_or("DUMPBIN unwind evidence field is absent")?;
    let address: u64 = u64::from_str_radix(address_text.trim().trim_start_matches("0x"), 16)
        .map_err(|_: std::num::ParseIntError| "DUMPBIN unwind address is malformed")?;
    let rva: u64 = address
        .checked_sub(IMAGE_BASE)
        .ok_or("DUMPBIN unwind address precedes image base")?;
    u32::try_from(rva).map_err(|_: std::num::TryFromIntError| "DUMPBIN unwind RVA does not fit u32")
}

#[test]
fn net7_auto_emits_the_compiler_method_and_unknown_minor_refuses() -> Result<(), &'static str> {
    assert!(SOURCE.contains("public static int Add(int left, int right) => left + right;"));
    assert!(PROJECT.contains("<TargetFramework>net7.0</TargetFramework>"));
    assert!(PROJECT.contains("<RuntimeIdentifier>win-x64</RuntimeIdentifier>"));
    assert!(PROJECT.contains("<AssemblyName>feat017</AssemblyName>"));
    assert!(PROJECT.contains("<PublishAot>true</PublishAot>"));
    assert!(SDK_PIN.contains("\"version\": \"7.0.410\""));
    assert!(SDK_PIN.contains("\"rollForward\": \"disable\""));
    assert!(BUILD.contains("New-Item -ItemType Directory -Force C:\\fixture-sdk"));
    assert!(BUILD.contains("https://dot.net/v1/dotnet-install.ps1"));
    assert!(BUILD.contains("-Version 7.0.410 -InstallDir C:\\fixture-sdk\\dotnet7"));
    assert!(BUILD.contains("New-Item -ItemType Directory -Force C:\\fixture-build\\feat017-net7"));
    assert!(BUILD.contains(
        "Copy-Item invoke_map_net7_x86_64.cs C:\\fixture-build\\feat017-net7\\Program.cs"
    ));
    assert!(BUILD.contains(
        "Copy-Item invoke_map_net7_x86_64.csproj.txt C:\\fixture-build\\feat017-net7\\feat017.csproj"
    ));
    assert!(BUILD.contains(
        "Copy-Item invoke_map_net7_x86_64.global.json.txt C:\\fixture-build\\feat017-net7\\global.json"
    ));
    assert!(BUILD.contains(
        "C:\\fixture-sdk\\dotnet7\\dotnet.exe publish feat017.csproj -r win-x64 -c Release -o publish --nologo"
    ));
    assert!(BUILD.contains("Push-Location C:\\fixture-build\\feat017-net7"));
    assert!(BUILD.contains("$env:OS = 'Windows_NT'"));
    assert!(BUILD.contains(
        "MSVC\\14.44.35207\\bin\\Hostx64\\x64\\dumpbin.exe' /headers publish\\feat017.exe"
    ));
    assert!(BUILD.contains(
        "MSVC\\14.44.35207\\bin\\Hostx64\\x64\\dumpbin.exe' /unwindinfo publish\\feat017.exe"
    ));
    assert!(BUILD.contains("$llvm = Get-Command llvm-objdump.exe -CommandType Application"));
    assert!(BUILD.contains("& $llvm.Source --version"));
    assert!(BUILD.contains("& $llvm.Source -d --start-address=0x1401418e0 --stop-address=0x1401418e4 publish\\feat017.exe"));
    assert!(BUILD.contains("Pop-Location"));
    let expected_start: u32 = compiler_method_rva("feat017_ManifestProbe__Add")?;
    let expected_end: u32 = evidence_rva("EndAddress: ")?;
    assert_eq!(evidence_rva("StartAddress: ")?, expected_start);
    assert_eq!((expected_start, expected_end), (0x0014_18e0, 0x0014_18e4));

    let pe: PeImage = parse(IMAGE)
        .map_err(|_: disrobe_pass_dotnet::Error| "NativeAOT fixture is not a PE image")?;
    assert_eq!(
        (pe.bitness, pe.machine),
        (PeBitness::Pe32Plus, AMD64_MACHINE)
    );
    let code_offset: usize = pe
        .rva_to_offset(expected_start)
        .ok_or("compiler method body is not file backed")?;
    assert_eq!(
        IMAGE.get(code_offset..code_offset + 4),
        Some([0x8d, 0x04, 0x11, 0xc3].as_slice())
    );

    let input: Artifact = Artifact::new(Rung::Raw, IMAGE.to_vec(), [0u8; 32]);
    let output: Artifact = match DOTNET_PASS.run(&input) {
        Ok(output) => output,
        Err(error) => panic!("{error}"),
    };
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .map_err(|_: serde_json::Error| "NativeAOT artifact is not JSON")?;
    let children: Vec<ChildArtifact> = DOTNET_PASS
        .extract_children(&input)
        .map_err(|_: disrobe_core::error::CoreError| "NativeAOT child extraction failed")?;
    assert_eq!(children.len(), 1);
    assert!(children[0].handle.is_terminal());
    assert_eq!(
        children[0].handle.relative_path,
        "nativeaot-net7-symbols.json"
    );
    let terminal_document: serde_json::Value = serde_json::from_slice(&children[0].bytes)
        .map_err(|_: serde_json::Error| "NativeAOT terminal artifact is not JSON")?;
    assert_eq!(terminal_document, document);
    assert_eq!(document["schema"], "disrobe.dotnet.native-aot-symbols/v1");
    assert_eq!(document["runtime"], "net7");
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
                .find(|candidate: &&serde_json::Value| candidate["record_offset"] == 3862)
        })
        .ok_or("compiler-emitted System.Int32 type record is absent")?;
    assert_eq!(int32["qualified_name"], "System.Int32");
    assert_eq!(
        method["signature"],
        serde_json::json!({
            "record_offset": 9274,
            "calling_convention": 1,
            "generic_parameter_count": 0,
            "return_type": {"kind": "definition", "record_offset": 3862},
            "parameter_types": [
                {"kind": "definition", "record_offset": 3862},
                {"kind": "definition", "record_offset": 3862}
            ],
            "vararg_parameter_types": []
        })
    );
    assert_eq!(method["entrypoint_rva"], expected_start);
    assert_eq!(method["code_range"]["start_rva"], expected_start);
    assert_eq!(method["code_range"]["end_rva"], expected_end);
    assert_eq!(method["body"]["status"], "recovered");
    assert_eq!(
        method["body"]["pseudo_c"],
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx + r_rdx * 1ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n"
    );

    let header: disrobe_pass_dotnet::aot::ReadyToRunHeader = detect(IMAGE)
        .ready_to_run
        .ok_or("compiler-emitted NativeAOT header is absent")?;
    assert_eq!((header.major_version, header.minor_version), (8, 0));
    let minor_offset: usize = usize::try_from(header.file_offset)
        .map_err(|_: std::num::TryFromIntError| "NativeAOT header offset does not fit usize")?
        .checked_add(6)
        .ok_or("NativeAOT minor-version offset overflowed")?;
    let minor_end: usize = minor_offset
        .checked_add(2)
        .ok_or("NativeAOT minor-version end overflowed")?;
    let mut unknown: Vec<u8> = IMAGE.to_vec();
    unknown
        .get_mut(minor_offset..minor_end)
        .ok_or("NativeAOT minor-version field is truncated")?
        .copy_from_slice(&1u16.to_le_bytes());
    let report: disrobe_pass_dotnet::aot::AotReport = detect(&unknown);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::UnsupportedVersion {
            major_version: 8,
            minor_version: 1,
        }
    );
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
    let unknown_input: Artifact = Artifact::new(Rung::Raw, unknown, [0u8; 32]);
    let error: disrobe_core::error::CoreError = match DOTNET_PASS.run(&unknown_input) {
        Ok(_output) => return Err("auto accepted unknown NativeAOT metadata version 8.1"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("DR-DOTNET-0914"));
    Ok(())
}
