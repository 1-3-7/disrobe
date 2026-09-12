#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::aot::{AotMetadataStatus, AotReport, detect};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use object::{Object as _, ObjectSection as _};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/invoke_map_net9_x86_64.exe");
const LINK_MAP: &str = include_str!("fixtures/native_aot/invoke_map_net9_x86_64.link.map.txt");

fn compiler_method_rva(symbol: &str) -> Result<u32, &'static str> {
    let base_text: &str = LINK_MAP
        .lines()
        .find_map(|line: &str| {
            line.split_once("Preferred load address is ")
                .map(|(_, value)| value)
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

fn section_file_offset(
    image: &[u8],
    section: &disrobe_pass_dotnet::aot::AotSection,
) -> Result<usize, &'static str> {
    let file: object::File<'_, &[u8]> =
        object::File::parse(image).map_err(|_: object::Error| "NativeAOT fixture is malformed")?;
    let address: u64 = file
        .relative_address_base()
        .checked_add(u64::from(section.start_rva))
        .ok_or("NativeAOT section address overflowed")?;
    for object_section in file.sections() {
        let Some((file_start, file_size)): Option<(u64, u64)> = object_section.file_range() else {
            continue;
        };
        let start: u64 = object_section.address();
        let end: u64 = start
            .checked_add(file_size)
            .ok_or("NativeAOT object section end overflowed")?;
        if address < start || address >= end {
            continue;
        }
        let offset: u64 = file_start
            .checked_add(
                address
                    .checked_sub(start)
                    .ok_or("NativeAOT section address underflowed")?,
            )
            .ok_or("NativeAOT section file offset overflowed")?;
        return usize::try_from(offset)
            .map_err(|_: std::num::TryFromIntError| "NativeAOT section offset does not fit usize");
    }
    Err("NativeAOT section is not file backed")
}

#[test]
fn auto_attaches_compiler_mapped_entrypoint_to_name_and_signature() -> Result<(), &'static str> {
    let expected_rva: u32 =
        compiler_method_rva("feat_017_nativeaot_manifest_probe_ManifestProbe__Add")?;
    assert_eq!(expected_rva, 0x0008_83b0);

    let report: AotReport = detect(IMAGE);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    let input: Artifact = Artifact::new(Rung::Raw, IMAGE.to_vec(), [0u8; 32]);
    let output: Artifact = DOTNET_PASS
        .run(&input)
        .map_err(|_: disrobe_core::error::CoreError| "NativeAOT auto route failed")?;
    let document: serde_json::Value = serde_json::from_slice(&output.envelope)
        .map_err(|_: serde_json::Error| "NativeAOT artifact is not JSON")?;
    let methods: &[serde_json::Value] = document["methods"]
        .as_array()
        .ok_or("NativeAOT artifact has no methods")?;
    let method: &serde_json::Value = methods
        .iter()
        .find(|method: &&serde_json::Value| {
            method["declaring_type"] == "ManifestProbe" && method["name"] == "Add"
        })
        .ok_or("compiler-emitted ManifestProbe.Add metadata is absent")?;
    assert!(!method["signature"].is_null());
    assert_eq!(method["entrypoint_rva"], expected_rva);
    Ok(())
}

#[test]
fn malformed_invoke_map_refuses_all_metadata_attribution_transactionally()
-> Result<(), &'static str> {
    let original: AotReport = detect(IMAGE);
    let invoke_section: &disrobe_pass_dotnet::aot::AotSection = original
        .ready_to_run
        .as_ref()
        .and_then(|header| header.section(306))
        .ok_or("compiler-emitted invoke map is absent")?;
    let invoke_offset: usize = section_file_offset(IMAGE, invoke_section)?;
    let mut malformed: Vec<u8> = IMAGE.to_vec();
    *malformed
        .get_mut(invoke_offset)
        .ok_or("compiler-emitted invoke map is not file backed")? = u8::MAX;

    let report: AotReport = detect(&malformed);
    let AotMetadataStatus::Rejected {
        section_offset,
        reason,
    } = report.metadata_attribution.status
    else {
        return Err("malformed invoke map did not reject metadata attribution");
    };
    assert_eq!(section_offset, Some(0));
    assert!(reason.contains("DR-DOTNET-0037"));
    assert!(report.metadata_attribution.types.is_empty());
    assert!(report.metadata_attribution.methods.is_empty());
    assert!(!report.recovered_names.is_empty());

    let input: Artifact = Artifact::new(Rung::Raw, malformed, [0u8; 32]);
    let error: disrobe_core::error::CoreError = DOTNET_PASS
        .run(&input)
        .expect_err("auto must refuse a malformed invoke map");
    assert!(error.to_string().contains("DR-DOTNET-0037"));
    Ok(())
}

#[test]
fn absent_invoke_map_retains_names_and_signatures_without_addresses() -> Result<(), &'static str> {
    let original: AotReport = detect(IMAGE);
    let mut header: disrobe_pass_dotnet::aot::ReadyToRunHeader = original
        .ready_to_run
        .ok_or("compiler-emitted NativeAOT header is absent")?;
    header.sections.retain(|section| section.id != 306);
    let attribution: disrobe_pass_dotnet::aot::AotMetadataAttribution =
        disrobe_pass_dotnet::aot::recover_metadata_attribution(IMAGE, &header).map_err(
            |_: disrobe_pass_dotnet::Error| "metadata recovery without invoke map failed",
        )?;
    assert_eq!(attribution.status, AotMetadataStatus::Recovered);
    assert!(!attribution.types.is_empty());
    assert!(!attribution.methods.is_empty());
    assert!(
        attribution
            .methods
            .iter()
            .all(|method| method.signature.is_some() && method.entrypoint_rva.is_none())
    );
    Ok(())
}
