#![allow(clippy::expect_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_dotnet::Error;
use disrobe_pass_dotnet::aot::{
    AotMetadataStatus, AotMethod, AotReport, AotSection, AotType, ReadyToRunHeader, detect,
    recover_metadata_attribution,
};
use object::Object as _;
use object::ObjectSection as _;

const TRACKED_NATIVE_AOT_IMAGE: &[u8] =
    include_bytes!("../../../corpus/dotnet/megafile/EdgeCases.nativeaot.exe");

const TRACKED_PROBE_IMAGE: &[u8] =
    include_bytes!("fixtures/native_aot/names_probe_net9_x86_64.exe");

fn probe_app_image() -> Vec<u8> {
    let Some(path): Option<PathBuf> = std::env::var_os(SAMPLE_ENV).map(PathBuf::from) else {
        return TRACKED_PROBE_IMAGE.to_vec();
    };
    std::fs::read(path).expect("the image named by DISROBE_AOT_SAMPLE must be readable")
}

const SAMPLE_ENV: &str = "DISROBE_AOT_SAMPLE";

fn any_native_aot_image() -> Vec<u8> {
    let Some(path): Option<PathBuf> = std::env::var_os(SAMPLE_ENV).map(PathBuf::from) else {
        return TRACKED_NATIVE_AOT_IMAGE.to_vec();
    };
    std::fs::read(path).expect("the image named by DISROBE_AOT_SAMPLE must be readable")
}

fn section_file_offset(image: &[u8], section: &AotSection) -> Result<usize, &'static str> {
    let file: object::File<'_, &[u8]> =
        object::File::parse(image).map_err(|_: object::Error| "native image parse failed")?;
    let base: u64 = file.relative_address_base();
    let start_address: u64 = base
        .checked_add(u64::from(section.start_rva))
        .ok_or("section start address overflowed")?;
    let end_address: u64 = base
        .checked_add(u64::from(section.end_rva))
        .ok_or("section end address overflowed")?;
    for object_section in file.sections() {
        let address: u64 = object_section.address();
        let Some((file_start, file_size)): Option<(u64, u64)> = object_section.file_range() else {
            continue;
        };
        let section_end: u64 = address
            .checked_add(file_size)
            .ok_or("file-backed section end overflowed")?;
        if start_address < address || end_address > section_end {
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

#[test]
fn a_real_native_aot_image_is_recognized_by_its_ready_to_run_header() {
    let image: Vec<u8> = any_native_aot_image();
    let report: AotReport = detect(&image);
    let header: &ReadyToRunHeader = report
        .ready_to_run
        .as_ref()
        .expect("a native aot image must yield a ready-to-run header");
    assert!(
        report.is_native_aot,
        "the header alone must be enough to recognize the image"
    );
    assert!(
        header.major_version > 0 && header.major_version <= 64,
        "the recovered version must be plausible, got {}",
        header.major_version
    );
    assert!(
        header.sections.len() >= 8,
        "a real image carries a populated section table, got {}",
        header.sections.len()
    );
    assert!(
        header.sections.iter().any(|s: &AotSection| !s.is_empty()),
        "at least one section must span bytes"
    );
    for section in &header.sections {
        assert!(
            section.end_rva >= section.start_rva,
            "section {} runs backwards",
            section.id
        );
        assert!(
            usize::try_from(section.end_rva).unwrap_or(usize::MAX) <= image.len() * 2,
            "section {} lands implausibly far outside the image",
            section.id
        );
    }
    let signature: [u8; 4] = disrobe_pass_dotnet::aot::READY_TO_RUN_SIGNATURE.to_le_bytes();
    let first_raw_hit: usize = image
        .windows(4)
        .position(|w: &[u8]| w == signature)
        .expect("the signature must occur at least once");
    assert!(
        first_raw_hit < usize::try_from(header.file_offset).unwrap_or(usize::MAX),
        "this image carries an earlier signature match inside code at 0x{first_raw_hit:x}; \
         accepting it would mean the checks past the signature do nothing"
    );
    println!(
        "recovered ready-to-run header at 0x{:x}: version {}.{}, {} sections \
         (rejected an earlier signature match at 0x{:x})",
        header.file_offset,
        header.major_version,
        header.minor_version,
        header.sections.len(),
        first_raw_hit
    );
}

#[test]
fn the_pass_entry_point_reaches_a_verdict_on_a_real_native_aot_image() {
    let image: Vec<u8> = any_native_aot_image();
    match disrobe_pass_dotnet::pass::analyze(&image) {
        Ok(summary) => println!("pass reached a verdict: native_aot={}", summary.native_aot),
        Err(error) => panic!(
            "the pass refuses a real native aot image instead of reporting it: {error}. \
             detection that no entry point can reach is not a capability"
        ),
    }
}

#[test]
fn a_real_native_aot_image_yields_type_names_the_source_declared() {
    let image: Vec<u8> = probe_app_image();
    let report: AotReport = detect(&image);
    let names: &[String] = &report.recovered_names;
    assert!(
        names.len() >= 100,
        "a real image carries hundreds of metadata names, got {}",
        names.len()
    );
    for declared in ["Widget", "IGauge", "Thermometer"] {
        assert!(
            names.iter().any(|n: &String| n == declared),
            "the probe source declares `{declared}` and the metadata still carries it, \
             so the reader must surface it; recovered {} names",
            names.len()
        );
    }
    assert!(
        names.windows(2).all(|w: &[String]| w[0] < w[1]),
        "names must be sorted and deduplicated so a caller can search them"
    );
    println!(
        "recovered {} unique metadata names from a stripped native aot image",
        names.len()
    );
}

#[test]
fn a_real_native_aot_image_attributes_every_reachable_type_and_method_record() {
    let report: AotReport = detect(TRACKED_PROBE_IMAGE);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    assert_eq!(report.metadata_attribution.types.len(), 466);
    assert_eq!(report.metadata_attribution.methods.len(), 45);
    let types: BTreeMap<u32, &AotType> = report
        .metadata_attribution
        .types
        .iter()
        .map(|type_record: &AotType| (type_record.record_offset, type_record))
        .collect();
    assert!(
        report
            .metadata_attribution
            .types
            .iter()
            .all(|type_record: &AotType| type_record
                .enclosing_type_record_offset
                .is_none_or(|offset: u32| types.contains_key(&offset)))
    );
    let methods: BTreeMap<u32, &AotMethod> = report
        .metadata_attribution
        .methods
        .iter()
        .map(|method: &AotMethod| (method.record_offset, method))
        .collect();
    let type_method_edges: usize = report
        .metadata_attribution
        .types
        .iter()
        .map(|type_record: &AotType| type_record.method_record_offsets.len())
        .sum();
    assert_eq!(type_method_edges, 58);
    assert!(
        report
            .metadata_attribution
            .types
            .iter()
            .all(|type_record: &AotType| type_record
                .method_record_offsets
                .iter()
                .all(|offset: &u32| methods.contains_key(offset)))
    );
    let declared_population: Vec<&str> = {
        let mut names: Vec<&str> = report
            .metadata_attribution
            .types
            .iter()
            .filter(|type_record: &&AotType| {
                type_record.namespace.as_deref() == Some("DisrobeAotProbe")
            })
            .map(|type_record: &AotType| type_record.name.as_str())
            .collect();
        names.sort_unstable();
        names
    };
    assert_eq!(
        declared_population,
        vec!["IGauge", "Program", "Thermometer", "Widget"],
        "the probe namespace is pinned by name, not by count, so a type the source never \
         declared cannot hide inside a matching total"
    );
    let known_types: [(&str, usize); 4] = [
        ("Widget", 0),
        ("IGauge", 0),
        ("Thermometer", 0),
        ("Program", 1),
    ];
    for (name, method_count) in known_types {
        let matches: Vec<&AotType> = report
            .metadata_attribution
            .types
            .iter()
            .filter(|type_record: &&AotType| type_record.name == name)
            .collect();
        assert_eq!(matches.len(), 1);
        let type_record: &AotType = matches[0];
        assert_eq!(type_record.namespace.as_deref(), Some("DisrobeAotProbe"));
        assert_eq!(type_record.method_record_offsets.len(), method_count);
    }
    let program: &AotType = report
        .metadata_attribution
        .types
        .iter()
        .find(|type_record: &&AotType| type_record.name == "Program")
        .expect("Program must have one directly encoded type record");
    let main_offset: u32 = program.method_record_offsets[0];
    let main: &&AotMethod = methods
        .get(&main_offset)
        .expect("Program's method handle must resolve");
    assert_eq!(main.name, "Main");
    let attributed_names: BTreeSet<&str> = report
        .metadata_attribution
        .types
        .iter()
        .map(|type_record: &AotType| type_record.name.as_str())
        .chain(
            report
                .metadata_attribution
                .methods
                .iter()
                .map(|method: &AotMethod| method.name.as_str()),
        )
        .collect();
    let recovered_names: BTreeSet<&str> =
        report.recovered_names.iter().map(String::as_str).collect();
    assert_eq!(recovered_names.len(), 1880);
    assert_eq!(recovered_names.intersection(&attributed_names).count(), 422);
    assert_eq!(recovered_names.difference(&attributed_names).count(), 1458);
    assert!(recovered_names.contains("Read"));
    assert!(recovered_names.contains("ToString"));
    assert!(!attributed_names.contains("Read"));
    assert!(!attributed_names.contains("ToString"));
}

#[test]
fn tracked_native_aot_image_decodes_a_complete_attribution_graph() {
    let report: AotReport = detect(TRACKED_NATIVE_AOT_IMAGE);
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    assert_eq!(report.recovered_names.len(), 1747);
    assert_eq!(report.metadata_attribution.types.len(), 425);
    assert_eq!(report.metadata_attribution.methods.len(), 44);
    assert!(
        report
            .metadata_attribution
            .types
            .windows(2)
            .all(|records: &[AotType]| records[0].record_offset < records[1].record_offset)
    );
    assert!(
        report
            .metadata_attribution
            .methods
            .windows(2)
            .all(|records: &[AotMethod]| records[0].record_offset < records[1].record_offset)
    );
    let types: BTreeSet<u32> = report
        .metadata_attribution
        .types
        .iter()
        .map(|type_record: &AotType| type_record.record_offset)
        .collect();
    let methods: BTreeSet<u32> = report
        .metadata_attribution
        .methods
        .iter()
        .map(|method: &AotMethod| method.record_offset)
        .collect();
    let type_method_edges: usize = report
        .metadata_attribution
        .types
        .iter()
        .map(|type_record: &AotType| type_record.method_record_offsets.len())
        .sum();
    assert_eq!(type_method_edges, 57);
    assert!(
        report
            .metadata_attribution
            .types
            .iter()
            .all(|type_record: &AotType| type_record
                .method_record_offsets
                .iter()
                .all(|offset: &u32| methods.contains(offset))
                && type_record
                    .enclosing_type_record_offset
                    .is_none_or(|offset: u32| types.contains(&offset)))
    );
}

#[test]
fn metadata_attribution_refuses_an_unsupported_ready_to_run_version() {
    let image: Vec<u8> = any_native_aot_image();
    let report: AotReport = detect(&image);
    let mut header: ReadyToRunHeader = report
        .ready_to_run
        .expect("the fixture must carry a ready-to-run header");
    header.minor_version = 2;
    let attribution: disrobe_pass_dotnet::Result<disrobe_pass_dotnet::aot::AotMetadataAttribution> =
        recover_metadata_attribution(&image, &header);
    assert!(matches!(
        attribution,
        Ok(disrobe_pass_dotnet::aot::AotMetadataAttribution {
            status: AotMetadataStatus::UnsupportedVersion {
                major_version: 10,
                minor_version: 2
            },
            types,
            methods,
        }) if types.is_empty() && methods.is_empty()
    ));
}

#[test]
fn metadata_attribution_rejects_bad_magic_and_hostile_counts_transactionally() {
    let image: Vec<u8> = any_native_aot_image();
    let report: AotReport = detect(&image);
    let header: ReadyToRunHeader = report
        .ready_to_run
        .expect("the fixture must carry a ready-to-run header");
    let section: &AotSection = header
        .section(313)
        .expect("the fixture must carry section 313");
    let section_offset: usize =
        section_file_offset(&image, section).expect("section 313 must be file backed");
    let count_offset: usize = section_offset
        .checked_add(4)
        .expect("root collection offset must fit usize");
    let count_end: usize = count_offset
        .checked_add(5)
        .expect("root collection end must fit usize");
    let mut hostile_count: Vec<u8> = image.clone();
    let count_bytes: &mut [u8] = hostile_count
        .get_mut(count_offset..count_end)
        .expect("root collection bytes must be present");
    count_bytes.copy_from_slice(&[0x0f, 0xff, 0xff, 0xff, 0xff]);
    let count_result: disrobe_pass_dotnet::Result<
        disrobe_pass_dotnet::aot::AotMetadataAttribution,
    > = recover_metadata_attribution(&hostile_count, &header);
    assert!(matches!(
        count_result,
        Err(Error::InvalidAotMetadata { offset: 4, .. })
    ));

    let mut bad_magic: Vec<u8> = image;
    let signature_byte: &mut u8 = bad_magic
        .get_mut(section_offset)
        .expect("metadata signature byte must be present");
    *signature_byte = 0;
    let bad_report: AotReport = detect(&bad_magic);
    assert_eq!(
        bad_report.recovered_names, report.recovered_names,
        "a transactional refusal leaves the names the image still carries exactly as they were, \
         so a corrupted metadata signature must not add, drop or reorder one"
    );
    assert!(bad_report.metadata_attribution.types.is_empty());
    assert!(bad_report.metadata_attribution.methods.is_empty());
    assert!(matches!(
        bad_report.metadata_attribution.status,
        AotMetadataStatus::Rejected {
            section_offset: Some(0),
            ..
        }
    ));
}

#[test]
fn the_metadata_length_prefix_decodes_the_documented_widths() {
    use disrobe_pass_dotnet::aot::decode_metadata_unsigned;
    assert_eq!(decode_metadata_unsigned(&[0x0c], 0), Some((6, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x16], 0), Some((11, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x1e], 0), Some((15, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x00], 0), Some((0, 1)));
    assert_eq!(decode_metadata_unsigned(&[0x01, 0x01], 0), Some((64, 2)));
    assert_eq!(
        decode_metadata_unsigned(&[0x07, 0x00, 0x00, 0x01], 0),
        Some((0x10_0000, 4))
    );
    assert_eq!(
        decode_metadata_unsigned(&[0x0f, 0x78, 0x56, 0x34, 0x12], 0),
        Some((0x1234_5678, 5))
    );
    assert_eq!(decode_metadata_unsigned(&[0x01], 0), None);
    assert_eq!(decode_metadata_unsigned(&[0x07, 0x00, 0x00], 0), None);
    assert_eq!(decode_metadata_unsigned(&[0x0f, 0x78, 0x56, 0x34], 0), None);
    assert_eq!(decode_metadata_unsigned(&[], 0), None);
    assert_eq!(decode_metadata_unsigned(&[0x1f], 0), None);
}

#[test]
fn the_name_needles_alone_do_not_recognize_a_real_image() {
    let image: Vec<u8> = any_native_aot_image();
    let report: AotReport = detect(&image);
    assert!(
        report.recovered_symbols.is_empty(),
        "this records what the shipped needles actually match on a real image: {:?}",
        report.recovered_symbols
    );
}
