#![allow(clippy::expect_used, clippy::panic)]

use disrobe_binfmt::coverage::{ByteCoverage, CoverageRegion, RegionClass, file_byte_coverage};
use disrobe_binfmt::error::Error;
use disrobe_binfmt::native::NativeFormat;

const CORE_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
const COMPONENT_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

fn assert_exact_tiling(coverage: &ByteCoverage, bytes: &[u8]) {
    assert_eq!(coverage.format, NativeFormat::Wasm);
    assert_eq!(coverage.file_len, bytes.len() as u64);
    assert_eq!(coverage.claimed_bytes, bytes.len() as u64);
    assert_eq!(coverage.slack_bytes, 0);
    assert_eq!(coverage.unclaimed_bytes, 0);
    assert_eq!(coverage.truncated_bytes, 0);
    assert!((coverage.coverage_ratio - 1.0).abs() < f64::EPSILON);
    assert!(coverage.complete);
    assert!(!coverage.overlap_detected);

    let mut cursor: u64 = 0;
    for region in &coverage.regions {
        assert_eq!(region.start, cursor);
        assert!(region.end > region.start);
        assert!(region.claimant.is_some());
        cursor = region.end;
    }
    assert_eq!(cursor, bytes.len() as u64);
}

fn mapped(bytes: &[u8]) -> ByteCoverage {
    file_byte_coverage(bytes).expect("map a valid WebAssembly framing stream")
}

fn claimant<'coverage>(coverage: &'coverage ByteCoverage, name: &str) -> &'coverage CoverageRegion {
    coverage
        .regions
        .iter()
        .find(|region: &&CoverageRegion| region.claimant.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("missing coverage claimant {name}"))
}

#[test]
fn empty_core_and_component_binaries_claim_their_preambles() {
    for header in [CORE_HEADER, COMPONENT_HEADER] {
        let coverage: ByteCoverage = mapped(&header);
        assert_exact_tiling(&coverage, &header);
        assert_eq!(
            coverage.regions,
            [CoverageRegion {
                start: 0,
                end: 8,
                class: RegionClass::Header,
                claimant: Some("wasm-preamble".to_owned()),
            }]
        );
    }
}

#[test]
fn repeated_custom_code_data_table_and_future_sections_have_stable_ordinal_claims() {
    let mut bytes: Vec<u8> = CORE_HEADER.to_vec();
    bytes.extend_from_slice(&[
        0, 0, 0, 1, b'x', 1, 1, 0, 10, 2, 1, 0, 11, 1, 0, 42, 1, 0xaa,
    ]);

    let first: ByteCoverage = mapped(&bytes);
    let second: ByteCoverage = mapped(&bytes);
    assert_eq!(first, second);
    assert_exact_tiling(&first, &bytes);

    assert_eq!(
        claimant(&first, "section[0]:custom-header").class,
        RegionClass::Header
    );
    assert_eq!(
        claimant(&first, "section[1]:custom-payload").class,
        RegionClass::Data
    );
    assert_eq!(
        claimant(&first, "section[2]:type-payload").class,
        RegionClass::Table
    );
    assert_eq!(
        claimant(&first, "section[3]:code-payload").class,
        RegionClass::Code
    );
    assert_eq!(
        claimant(&first, "section[4]:data-payload").class,
        RegionClass::Data
    );
    assert_eq!(
        claimant(&first, "section[5]:unknown-42-payload").class,
        RegionClass::Data
    );
    assert!(
        first
            .regions
            .iter()
            .all(|region: &CoverageRegion| !region.is_empty())
    );
}

#[test]
fn every_core_and_component_section_id_tiles_without_semantic_validation() {
    let mut core: Vec<u8> = CORE_HEADER.to_vec();
    for id in 0u8..=13 {
        core.extend_from_slice(&[id, 1, id]);
    }
    core.extend_from_slice(&[0xff, 1, 0x5a]);

    let mut component: Vec<u8> = COMPONENT_HEADER.to_vec();
    for id in 0u8..=11 {
        component.extend_from_slice(&[id, 1, id]);
    }
    component.extend_from_slice(&[0xfe, 1, 0xa5]);

    assert_exact_tiling(&mapped(&core), &core);
    assert_exact_tiling(&mapped(&component), &component);
}

#[test]
fn one_through_five_byte_u32_lengths_are_accepted() {
    for width in 1usize..=5 {
        let mut bytes: Vec<u8> = CORE_HEADER.to_vec();
        bytes.push(0);
        bytes.extend(std::iter::repeat_n(0x80, width.saturating_sub(1)));
        bytes.push(0);

        let coverage: ByteCoverage = mapped(&bytes);
        assert_exact_tiling(&coverage, &bytes);
        assert_eq!(
            claimant(&coverage, "section[0]:custom-header").end,
            bytes.len() as u64
        );
    }
}

#[test]
fn truncated_preambles_and_unknown_framing_pairs_are_typed_errors() {
    for length in 0usize..8 {
        let error: Error = file_byte_coverage(&CORE_HEADER[..length])
            .expect_err("a partial WebAssembly preamble must fail");
        assert!(error.to_string().starts_with("DR-BINFMT-"));
    }

    for header in [
        [0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00],
        [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x00, 0x00],
        [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x02, 0x00],
    ] {
        let error: Error =
            file_byte_coverage(&header).expect_err("an unknown framing pair must fail");
        assert!(matches!(error, Error::CoverageUnsupported { .. }));
        assert!(error.to_string().contains("version"));
        assert!(error.to_string().contains("layer"));
    }
}

#[test]
fn incomplete_and_out_of_range_section_lengths_are_typed_errors() {
    let mut eof_after_id: Vec<u8> = CORE_HEADER.to_vec();
    eof_after_id.push(1);
    assert!(matches!(
        file_byte_coverage(&eof_after_id),
        Err(Error::Coverage(_))
    ));

    for continuation_count in 1usize..=5 {
        let mut bytes: Vec<u8> = CORE_HEADER.to_vec();
        bytes.push(1);
        bytes.extend(std::iter::repeat_n(0x80, continuation_count));
        assert!(matches!(
            file_byte_coverage(&bytes),
            Err(Error::Coverage(_))
        ));
    }

    for suffix in [
        vec![0x80, 0x80, 0x80, 0x80, 0x10],
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0],
        vec![2, 0],
    ] {
        let mut bytes: Vec<u8> = CORE_HEADER.to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&suffix);
        assert!(matches!(
            file_byte_coverage(&bytes),
            Err(Error::Coverage(_))
        ));
    }

    let mut maximum_u32: Vec<u8> = CORE_HEADER.to_vec();
    maximum_u32.extend_from_slice(&[1, 0xff, 0xff, 0xff, 0xff, 0x0f]);
    let error: Error = file_byte_coverage(&maximum_u32)
        .expect_err("the maximum u32 length needs its declared payload bytes");
    assert!(error.to_string().contains("past the"));
}

#[test]
fn the_shared_region_ceiling_bounds_section_walks() {
    let mut bytes: Vec<u8> = Vec::with_capacity(8 + 2 * 65_536);
    bytes.extend_from_slice(&CORE_HEADER);
    for _index in 0usize..65_536 {
        bytes.extend_from_slice(&[0, 0]);
    }

    let error: Error =
        file_byte_coverage(&bytes).expect_err("more than the shared region cap must fail");
    assert!(matches!(error, Error::Coverage(_)));
    assert!(error.to_string().contains("65536"));
}
