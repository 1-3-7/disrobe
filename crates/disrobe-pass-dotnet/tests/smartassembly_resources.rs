use std::error::Error;

use disrobe_pass_dotnet::peel::smartassembly::peel_smartassembly;
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use disrobe_pass_dotnet::{metadata, pe, tables};

const PROTECTED: &[u8] = include_bytes!("fixtures/smartassembly_resources/SmartAssemblyCompat.dll");
const ORIGINAL: &[u8] = include_bytes!("fixtures/smartassembly_resources/Payload.clean.dll");

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn test_failure(message: &str) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message.to_string()))
}

#[test]
fn smartassembly_static_resource_recovers_original_assembly_byte_for_byte() -> TestResult {
    let report: PeelReport = peel_smartassembly(PROTECTED)?;
    assert_eq!(report.recovered_resources.len(), 1);
    let recovered = report
        .recovered_resources
        .iter()
        .find(|resource| resource.name == "[z]payload")
        .ok_or_else(|| test_failure("static resource missing"))?;
    assert_eq!(recovered.bytes, ORIGINAL);
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
    Ok(())
}

#[test]
fn smartassembly_keyed_resource_surfaces_unknown_marker() -> TestResult {
    let report: PeelReport = peel_smartassembly(PROTECTED)?;
    assert!(report.notes.iter().any(|note: &String| {
        note.contains("Unknown") && note.contains("[z]keyed") && note.contains("mode 0x03")
    }));
    Ok(())
}

#[test]
fn smartassembly_malformed_static_resource_surfaces_rejected_marker() -> TestResult {
    let report: PeelReport = peel_smartassembly(PROTECTED)?;
    assert!(report.notes.iter().any(|note: &String| {
        note.contains("rejected")
            && note.contains("[z]rejected")
            && note.contains("compressed part length is truncated")
    }));
    Ok(())
}

#[test]
fn malformed_unrelated_resource_does_not_hide_static_payload() -> TestResult {
    let mut image: Vec<u8> = PROTECTED.to_vec();
    let length_offset: usize = resource_length_offset(&image, "[z]rejected")?;
    let length_end: usize = length_offset
        .checked_add(4)
        .ok_or_else(|| test_failure("resource length offset overflow"))?;
    image
        .get_mut(length_offset..length_end)
        .ok_or_else(|| test_failure("resource length missing"))?
        .copy_from_slice(&u32::MAX.to_le_bytes());
    let report: PeelReport = peel_smartassembly(&image)?;
    assert_eq!(report.recovered_resources.len(), 1);
    let recovered = report
        .recovered_resources
        .first()
        .ok_or_else(|| test_failure("static resource missing"))?;
    assert_eq!(recovered.name, "[z]payload");
    assert_eq!(recovered.bytes, ORIGINAL);
    Ok(())
}

#[test]
fn recovery_reads_the_carrier_and_not_a_baked_in_payload() -> TestResult {
    let mut image: Vec<u8> = PROTECTED.to_vec();
    let length_offset: usize = resource_length_offset(&image, "[z]payload")?;
    let length_bytes: [u8; 4] = image
        .get(length_offset..length_offset.saturating_add(4))
        .ok_or_else(|| test_failure("resource length missing"))?
        .try_into()?;
    let payload_len: usize = usize::try_from(u32::from_le_bytes(length_bytes))?;
    let midpoint: usize = length_offset
        .checked_add(4)
        .and_then(|start: usize| start.checked_add(payload_len / 2))
        .ok_or_else(|| test_failure("payload midpoint overflow"))?;
    *image
        .get_mut(midpoint)
        .ok_or_else(|| test_failure("payload midpoint outside the image"))? ^= 0xFF;
    let recovered: Vec<Vec<u8>> = peel_smartassembly(&image)?
        .recovered_resources
        .into_iter()
        .filter(|resource| resource.name == "[z]payload")
        .map(|resource| resource.bytes)
        .collect();
    assert_ne!(
        recovered.first().map(Vec::as_slice),
        Some(ORIGINAL),
        "flipping one byte in the middle of the [z]payload DEFLATE stream must stop the peeler \
         reproducing the clean payload; an unchanged result would mean the recovery is not \
         reading the carrier"
    );
    Ok(())
}

fn resource_length_offset(image: &[u8], target_name: &str) -> TestResult<usize> {
    let parsed_pe: pe::PeImage = pe::parse(image)?;
    let clr: pe::ClrHeader = pe::parse_clr_header(image, &parsed_pe)?;
    let root: metadata::MetadataRoot = metadata::parse_metadata_root(image, &parsed_pe, &clr)?;
    let metadata_size: usize = usize::try_from(clr.metadata.size)?;
    let metadata_slice: &[u8] = parsed_pe.slice_at_rva(image, clr.metadata.rva, metadata_size)?;
    let table_header: metadata::StreamHeader = *root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .ok_or_else(|| test_failure("table stream missing"))?;
    let parsed_tables: tables::Tables = tables::parse_tables(metadata_slice, table_header)?;
    let strings_header: metadata::StreamHeader = *root
        .streams
        .get("#Strings")
        .ok_or_else(|| test_failure("strings heap missing"))?;
    let strings = metadata::read_strings_heap(metadata_slice, strings_header);
    let resource = parsed_tables
        .manifest_resources
        .iter()
        .find(|row| {
            strings
                .get(&row.name)
                .is_some_and(|name| name == target_name)
        })
        .ok_or_else(|| test_failure("resource row missing"))?;
    let header_rva: u32 = clr
        .resources
        .rva
        .checked_add(resource.offset)
        .ok_or_else(|| test_failure("resource RVA overflow"))?;
    parsed_pe
        .rva_to_offset(header_rva)
        .ok_or_else(|| test_failure("resource offset missing"))
}
