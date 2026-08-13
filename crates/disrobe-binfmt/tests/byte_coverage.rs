#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::requirement::{
    READELF, corpus_path, describe_run, locate, required_corpus, unmeasured,
};
use disrobe_binfmt::coverage::{
    BYTE_COVERAGE_SCHEMA, ByteCoverage, CoverageOverlap, CoverageRegion, RegionClass,
    TruncatedClaim, UnbackedClaim, UnbackedReason, file_byte_coverage,
};
use disrobe_binfmt::error::Error;
use disrobe_binfmt::native::NativeFormat;
use object::read::{Object as _, ObjectSection as _};

const FORMATS_DIR: &str = "native/formats";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    Mapped(NativeFormat),
    Rejected,
}

fn corpus_expectations() -> BTreeMap<&'static str, Expectation> {
    BTreeMap::from([
        ("avr_firmware.elf", Expectation::Mapped(NativeFormat::Elf32)),
        ("dwarf_v2.o", Expectation::Mapped(NativeFormat::Coff)),
        ("dwarf_v3.o", Expectation::Mapped(NativeFormat::Coff)),
        ("dwarf_v4.o", Expectation::Mapped(NativeFormat::Coff)),
        ("dwarf_v5.o", Expectation::Mapped(NativeFormat::Coff)),
        (
            "hello.auditable.exe",
            Expectation::Mapped(NativeFormat::Pe64),
        ),
        ("hello.coff.x64.o", Expectation::Mapped(NativeFormat::Coff)),
        ("hello.efi", Expectation::Mapped(NativeFormat::Pe64)),
        ("hello.elf64", Expectation::Mapped(NativeFormat::Elf64)),
        (
            "hello.macho64.o",
            Expectation::Mapped(NativeFormat::MachO64),
        ),
        ("hello.pe64.exe", Expectation::Mapped(NativeFormat::Pe64)),
        ("hello_lx.exe", Expectation::Rejected),
        ("hello_ne.exe", Expectation::Rejected),
        ("hello_os2_ne.exe", Expectation::Rejected),
        ("hello_reloc.ko.o", Expectation::Mapped(NativeFormat::Elf64)),
        ("hello_stabs.o", Expectation::Mapped(NativeFormat::Coff)),
        ("os2_ne_probe.c", Expectation::Rejected),
        ("PROVENANCE.txt", Expectation::Rejected),
    ])
}

fn assert_partition(coverage: &ByteCoverage, file_len: u64, subject: &str) {
    assert_eq!(
        coverage.schema, BYTE_COVERAGE_SCHEMA,
        "{subject}: the map must carry its versioned schema"
    );
    assert_eq!(
        coverage.file_len, file_len,
        "{subject}: the map must record the real file length"
    );
    assert!(
        !coverage.regions.is_empty(),
        "{subject}: a non-empty file must produce at least one region"
    );

    let mut cursor: u64 = 0;
    for region in &coverage.regions {
        assert_eq!(
            region.start, cursor,
            "{subject}: regions must tile the file without a hole or an overlap"
        );
        assert!(
            region.end > region.start,
            "{subject}: a zero-width region is never recorded"
        );
        cursor = region.end;
        if region.class == RegionClass::Unclaimed || region.class == RegionClass::Alignment {
            assert!(
                region.claimant.is_none(),
                "{subject}: an unclaimed or slack region names no claimant"
            );
        } else {
            assert!(
                region.claimant.is_some(),
                "{subject}: a claimed region always names its claimant"
            );
        }
    }
    assert_eq!(
        cursor, file_len,
        "{subject}: the last region must end at the real file length"
    );

    let total: u64 = coverage
        .claimed_bytes
        .checked_add(coverage.slack_bytes)
        .and_then(|value: u64| value.checked_add(coverage.unclaimed_bytes))
        .expect("the coverage totals must not overflow");
    assert_eq!(
        total, file_len,
        "{subject}: claimed + slack + unclaimed must equal the real file length"
    );
    assert!(
        coverage.coverage_ratio <= 1.0,
        "{subject}: a doubly claimed byte must never inflate the ratio past one"
    );
}

fn read_formats_dir() -> Vec<PathBuf> {
    let root: PathBuf = corpus_path(FORMATS_DIR);
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "corpus/{FORMATS_DIR} is tracked in git and this case grades nothing without it, \
                 so its absence is a damaged checkout: {error} ({})",
                root.display()
            )
        })
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry.expect("read a corpus directory entry").path()
        })
        .filter(|path: &PathBuf| path.is_file())
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_committed_format_fixture_is_mapped_or_named_as_unsupported() {
    let expectations: BTreeMap<&'static str, Expectation> = corpus_expectations();
    let paths: Vec<PathBuf> = read_formats_dir();
    assert!(
        !paths.is_empty(),
        "the committed format corpus must not be empty"
    );

    for path in &paths {
        let name: &str = path
            .file_name()
            .and_then(|value: &std::ffi::OsStr| value.to_str())
            .expect("a corpus file name is valid unicode");
        let expected: Expectation = *expectations.get(name).unwrap_or_else(|| {
            panic!(
                "corpus/{FORMATS_DIR}/{name} is not listed in this case, so a new fixture would \
                 pass without ever being measured; add it with its expected outcome"
            )
        });
        let bytes: Vec<u8> = std::fs::read(path).expect("read a committed corpus fixture");
        let outcome: Result<ByteCoverage, Error> = file_byte_coverage(&bytes);

        match (expected, outcome) {
            (Expectation::Mapped(format), Ok(coverage)) => {
                assert_eq!(
                    coverage.format, format,
                    "{name}: the map must record the format it walked"
                );
                assert_partition(&coverage, bytes.len() as u64, name);
            }
            (Expectation::Mapped(format), Err(error)) => {
                panic!("{name}: expected a {format:?} coverage map and got the error {error}");
            }
            (Expectation::Rejected, Ok(coverage)) => {
                panic!(
                    "{name}: expected a typed refusal and got a {:?} map",
                    coverage.format
                );
            }
            (Expectation::Rejected, Err(error)) => {
                let text: String = error.to_string();
                assert!(
                    text.starts_with("DR-BINFMT-"),
                    "{name}: a refusal must carry a diagnostic code: {text}"
                );
            }
        }
    }

    for name in expectations.keys() {
        let path: PathBuf = corpus_path(FORMATS_DIR).join(name);
        assert!(
            path.is_file(),
            "this case lists corpus/{FORMATS_DIR}/{name}, which is not in the checkout"
        );
    }
}

#[test]
fn a_linked_pe_is_covered_end_to_end() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.pe64.exe");
    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a linked PE32+ image");

    assert_partition(&coverage, bytes.len() as u64, "hello.pe64.exe");
    assert_eq!(
        coverage.unclaimed_bytes, 0,
        "every byte of a linked mingw PE is claimed by a header, a table or a section"
    );
    assert!(
        coverage.complete,
        "a fully claimed image with no overlap is complete"
    );
}

#[test]
fn a_linked_elf_is_covered_end_to_end() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.elf64");
    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a linked ELF64 image");

    assert_partition(&coverage, bytes.len() as u64, "hello.elf64");
    assert_eq!(
        coverage.unclaimed_bytes, 0,
        "every byte of a linked ELF64 is claimed, or is zero slack before the section table"
    );
}

#[test]
fn an_empty_input_is_a_typed_refusal() {
    let error: Error = file_byte_coverage(&[]).expect_err("an empty file has nothing to map");
    assert!(
        error.to_string().starts_with("DR-BINFMT-"),
        "an empty input must fail with a diagnostic code: {error}"
    );
}

fn region_named<'coverage>(
    coverage: &'coverage ByteCoverage,
    claimant: &str,
) -> Option<&'coverage CoverageRegion> {
    coverage
        .regions
        .iter()
        .find(|region: &&CoverageRegion| region.claimant.as_deref() == Some(claimant))
}

#[test]
fn the_pe_header_claims_are_named_and_ordered() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.pe64.exe");
    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a linked PE32+ image");

    for claimant in [
        "dos-header",
        "pe-signature",
        "coff-header",
        "optional-header",
        "data-directories",
        "section-table",
    ] {
        let region: &CoverageRegion = region_named(&coverage, claimant)
            .unwrap_or_else(|| panic!("the PE map must name a {claimant} region"));
        assert!(
            matches!(region.class, RegionClass::Header | RegionClass::Table),
            "{claimant} is a header or a table region, not {:?}",
            region.class
        );
    }

    let dos: &CoverageRegion = region_named(&coverage, "dos-header").expect("a DOS header region");
    assert_eq!(
        (dos.start, dos.end),
        (0, 64),
        "the DOS header is the first 64 bytes"
    );
}

fn path_exists(relative: &str) -> bool {
    let path: PathBuf = corpus_path(relative);
    Path::new(&path).is_file()
}

#[test]
fn the_corpus_paths_this_case_relies_on_are_committed() {
    for relative in [
        "native/formats/hello.pe64.exe",
        "native/formats/hello.elf64",
        "native/formats/hello.macho64.o",
        "native/formats/hello.coff.x64.o",
    ] {
        assert!(
            path_exists(relative),
            "corpus/{relative} is tracked in git and this file grades nothing without it"
        );
    }
}

const MAPPED_FIXTURES: [&str; 12] = [
    "avr_firmware.elf",
    "dwarf_v2.o",
    "dwarf_v3.o",
    "dwarf_v4.o",
    "dwarf_v5.o",
    "hello.auditable.exe",
    "hello.coff.x64.o",
    "hello.efi",
    "hello.elf64",
    "hello.macho64.o",
    "hello.pe64.exe",
    "hello_reloc.ko.o",
];

fn fixture(name: &str) -> Vec<u8> {
    required_corpus(&format!("{FORMATS_DIR}/{name}"))
}

fn claimants_over(coverage: &ByteCoverage, start: u64, end: u64) -> Vec<String> {
    coverage
        .regions
        .iter()
        .filter(|region: &&CoverageRegion| region.start < end && region.end > start)
        .map(|region: &CoverageRegion| {
            region
                .claimant
                .clone()
                .unwrap_or_else(|| region.class.label().to_owned())
        })
        .collect()
}

#[test]
fn every_section_an_independent_parser_reports_is_claimed_under_its_own_name() {
    let mut checked: usize = 0;

    for name in MAPPED_FIXTURES {
        let bytes: Vec<u8> = fixture(name);
        let coverage: ByteCoverage =
            file_byte_coverage(&bytes).unwrap_or_else(|error: Error| panic!("{name}: {error}"));
        let parsed: object::read::File<'_, &[u8]> = object::read::File::parse(bytes.as_slice())
            .unwrap_or_else(|error: object::Error| {
                panic!("{name}: the reference parser must read this fixture: {error}")
            });

        for section in parsed.sections() {
            let Some((offset, size)): Option<(u64, u64)> = section.file_range() else {
                continue;
            };
            if size == 0 {
                continue;
            }
            let section_name: String = section
                .name()
                .unwrap_or_else(|error: object::Error| {
                    panic!("{name}: a reference section name must decode: {error}")
                })
                .to_owned();
            let end: u64 = offset + size;
            let claimants: Vec<String> = claimants_over(&coverage, offset, end);
            assert!(
                !claimants.is_empty(),
                "{name}: the reference parser places {section_name} at {offset}..{end} and the \
                 map records no region there"
            );
            for claimant in &claimants {
                assert!(
                    claimant.starts_with("section:") && claimant.ends_with(&section_name),
                    "{name}: the reference parser places {section_name} at {offset}..{end}, and \
                     the map attributes part of it to {claimant}"
                );
            }
            checked += 1;
        }
    }

    assert!(
        checked >= 30,
        "the differential check must grade a real number of sections, and it graded {checked}"
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferenceSection {
    name: String,
    kind: String,
    offset: u64,
    size: u64,
}

fn parse_readelf(text: &str) -> Vec<ReferenceSection> {
    let mut sections: Vec<ReferenceSection> = Vec::new();
    for line in text.lines() {
        let trimmed: &str = line.trim();
        let Some(rest): Option<&str> = trimmed.strip_prefix('[') else {
            continue;
        };
        let Some((index_text, tail)): Option<(&str, &str)> = rest.split_once(']') else {
            continue;
        };
        let Ok(index): Result<u32, std::num::ParseIntError> = index_text.trim().parse::<u32>()
        else {
            continue;
        };
        if index == 0 {
            continue;
        }
        let fields: Vec<&str> = tail.split_whitespace().collect();
        let (Some(name), Some(kind), Some(offset_text), Some(size_text)): (
            Option<&&str>,
            Option<&&str>,
            Option<&&str>,
            Option<&&str>,
        ) = (fields.first(), fields.get(1), fields.get(3), fields.get(4)) else {
            continue;
        };
        let (Ok(offset), Ok(size)): (
            Result<u64, std::num::ParseIntError>,
            Result<u64, std::num::ParseIntError>,
        ) = (
            u64::from_str_radix(offset_text, 16),
            u64::from_str_radix(size_text, 16),
        ) else {
            continue;
        };
        sections.push(ReferenceSection {
            name: (*name).to_owned(),
            kind: (*kind).to_owned(),
            offset,
            size,
        });
    }
    sections
}

#[test]
fn an_independent_elf_reader_agrees_with_every_section_offset_the_map_claims() {
    let graded: &str = "the file offset every ELF section claims in the byte coverage map";
    let Ok(program): Result<PathBuf, String> = locate(&READELF) else {
        unmeasured(&READELF, graded, "no readelf was found on PATH");
        return;
    };

    let mut compared: usize = 0;
    for name in ["hello.elf64", "hello_reloc.ko.o", "avr_firmware.elf"] {
        let path: PathBuf = corpus_path(&format!("{FORMATS_DIR}/{name}"));
        let arguments: [&str; 2] = ["-S", "-W"];
        let output: Output = std::process::Command::new(&program)
            .args(arguments)
            .arg(&path)
            .output()
            .unwrap_or_else(|error: std::io::Error| {
                panic!("{name}: readelf must run: {error} ({})", program.display())
            });
        assert!(
            output.status.success(),
            "{name}: readelf must describe the fixture: {}",
            describe_run(&program, &arguments, &output)
        );
        let text: String = String::from_utf8_lossy(&output.stdout).into_owned();
        let reference: Vec<ReferenceSection> = parse_readelf(&text);
        assert!(
            reference.len() >= 3,
            "{name}: readelf reported {} usable section rows, so this case graded nothing:\n{text}",
            reference.len()
        );

        let bytes: Vec<u8> = fixture(name);
        let coverage: ByteCoverage =
            file_byte_coverage(&bytes).unwrap_or_else(|error: Error| panic!("{name}: {error}"));

        for section in &reference {
            if section.kind == "NOBITS" {
                let entry: Option<&UnbackedClaim> =
                    coverage.unbacked.iter().find(|claim: &&UnbackedClaim| {
                        claim.claimant == format!("section:{}", section.name)
                    });
                if section.size > 0 {
                    let claim: &UnbackedClaim = entry.unwrap_or_else(|| {
                        panic!(
                            "{name}: readelf reports {} as NOBITS with {} bytes, and the map does \
                             not name it as claiming no file bytes",
                            section.name, section.size
                        )
                    });
                    assert_eq!(
                        claim.reason,
                        UnbackedReason::NoFileBytes,
                        "{name}: a NOBITS section claims no file bytes"
                    );
                    assert_eq!(
                        claim.declared_size, section.size,
                        "{name}: the map must carry the size readelf reports for {}",
                        section.name
                    );
                    compared += 1;
                }
                continue;
            }
            if section.size == 0 {
                continue;
            }
            let end: u64 = section.offset + section.size;
            let claimants: Vec<String> = claimants_over(&coverage, section.offset, end);
            assert!(
                !claimants.is_empty(),
                "{name}: readelf places {} at {}..{end} and the map records no region there",
                section.name,
                section.offset
            );
            for claimant in &claimants {
                assert_eq!(
                    *claimant,
                    format!("section:{}", section.name),
                    "{name}: readelf places {} at {}..{end}, and the map attributes part of it to \
                     {claimant}",
                    section.name,
                    section.offset
                );
            }
            compared += 1;
        }
    }

    assert!(
        compared >= 15,
        "the readelf cross-check must grade a real number of sections, and it graded {compared}"
    );
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .expect("a PE field is present")
            .try_into()
            .expect("a two byte field"),
    )
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .expect("a PE field is present")
            .try_into()
            .expect("a four byte field"),
    )
}

fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes
        .get_mut(offset..offset + 2)
        .expect("a PE field is present")
        .copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes
        .get_mut(offset..offset + 4)
        .expect("a PE field is present")
        .copy_from_slice(&value.to_le_bytes());
}

fn pe_lfanew(bytes: &[u8]) -> usize {
    read_u32_le(bytes, 0x3C) as usize
}

fn pe_section_count(bytes: &[u8]) -> usize {
    usize::from(read_u16_le(bytes, pe_lfanew(bytes) + 6))
}

fn pe_section_table(bytes: &[u8]) -> usize {
    let lfanew: usize = pe_lfanew(bytes);
    lfanew + 24 + usize::from(read_u16_le(bytes, lfanew + 20))
}

fn pe_section_field(bytes: &[u8], index: usize, field: usize) -> usize {
    pe_section_table(bytes) + index * 40 + field
}

const RAW_SIZE_FIELD: usize = 16;
const RAW_OFFSET_FIELD: usize = 20;

#[test]
fn an_appended_blob_shows_as_one_unclaimed_range() {
    let original: Vec<u8> = fixture("hello.pe64.exe");
    let original_len: u64 = original.len() as u64;
    let mut appended: Vec<u8> = original;
    appended.extend(std::iter::repeat_n(0xA5u8, 4096));

    let coverage: ByteCoverage = file_byte_coverage(&appended).expect("map an overlaid PE");
    assert_partition(&coverage, appended.len() as u64, "hello.pe64.exe + overlay");

    let unclaimed: Vec<&CoverageRegion> = coverage.unclaimed_ranges();
    assert_eq!(
        unclaimed.len(),
        1,
        "an appended blob is exactly one unclaimed range, and the map reports {unclaimed:?}"
    );
    let range: &CoverageRegion = unclaimed.first().expect("one unclaimed range");
    assert_eq!(
        (range.start, range.end),
        (original_len, original_len + 4096),
        "the unclaimed range must be the appended blob itself"
    );
    assert_eq!(coverage.unclaimed_bytes, 4096);
    assert!(
        !coverage.complete,
        "an image with an unaccounted overlay is not complete"
    );
}

#[test]
fn a_shortened_section_leaves_its_hidden_tail_unclaimed() {
    let mut bytes: Vec<u8> = fixture("hello.pe64.exe");
    let raw_size: u32 = read_u32_le(&bytes, pe_section_field(&bytes, 0, RAW_SIZE_FIELD));
    let raw_offset: u32 = read_u32_le(&bytes, pe_section_field(&bytes, 0, RAW_OFFSET_FIELD));
    assert!(
        raw_size > 0x400,
        "this case needs a first section with room to hide a payload behind"
    );
    let hidden: u32 = 0x200;
    let shortened: u32 = raw_size - hidden;
    let size_field: usize = pe_section_field(&bytes, 0, RAW_SIZE_FIELD);
    write_u32_le(&mut bytes, size_field, shortened);
    let start: usize = (raw_offset + shortened) as usize;
    let end: usize = (raw_offset + raw_size) as usize;
    bytes
        .get_mut(start..end)
        .expect("the hidden window is inside the file")
        .fill(0xDE);

    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a shortened PE");
    assert_partition(
        &coverage,
        bytes.len() as u64,
        "hello.pe64.exe with a hidden tail",
    );

    let unclaimed: Vec<&CoverageRegion> = coverage.unclaimed_ranges();
    assert_eq!(
        unclaimed.len(),
        1,
        "the payload the section table no longer covers is one unclaimed range, and the map \
         reports {unclaimed:?}"
    );
    let range: &CoverageRegion = unclaimed.first().expect("one unclaimed range");
    assert_eq!(
        (range.start, range.end),
        (start as u64, end as u64),
        "the unclaimed range must be exactly the window the section table stopped covering"
    );
}

#[test]
fn a_section_without_a_file_offset_claims_nothing_and_is_named() {
    let mut bytes: Vec<u8> = fixture("hello.pe64.exe");
    let raw_size: u32 = read_u32_le(&bytes, pe_section_field(&bytes, 0, RAW_SIZE_FIELD));
    let raw_offset: u32 = read_u32_le(&bytes, pe_section_field(&bytes, 0, RAW_OFFSET_FIELD));
    let offset_field: usize = pe_section_field(&bytes, 0, RAW_OFFSET_FIELD);
    write_u32_le(&mut bytes, offset_field, 0);

    let coverage: ByteCoverage =
        file_byte_coverage(&bytes).expect("map a PE with an unbacked section");
    assert_partition(
        &coverage,
        bytes.len() as u64,
        "hello.pe64.exe with an unbacked section",
    );

    let entry: &UnbackedClaim = coverage
        .unbacked
        .iter()
        .find(|claim: &&UnbackedClaim| claim.reason == UnbackedReason::NoFileOffset)
        .expect("a section with PointerToRawData of zero must be named");
    assert_eq!(entry.declared_size, u64::from(raw_size));
    assert!(
        entry.claimant.starts_with("section:"),
        "the unbacked entry must name the section: {}",
        entry.claimant
    );

    let unclaimed: Vec<&CoverageRegion> = coverage.unclaimed_ranges();
    assert!(
        unclaimed.iter().any(|region: &&CoverageRegion| {
            region.start == u64::from(raw_offset) && region.end == u64::from(raw_offset + raw_size)
        }),
        "the bytes the unbacked section used to claim must surface as unclaimed: {unclaimed:?}"
    );
}

#[test]
fn a_real_pe_names_its_uninitialised_section_as_claiming_no_file_bytes() {
    let bytes: Vec<u8> = fixture("hello.pe64.exe");
    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a linked PE32+ image");
    let entry: &UnbackedClaim = coverage
        .unbacked
        .iter()
        .find(|claim: &&UnbackedClaim| claim.reason == UnbackedReason::NoFileBytes)
        .expect("a linked mingw PE carries a .bss with no file bytes");

    assert_eq!(entry.claimant, "section:.bss");
    assert!(
        entry.declared_size > 0,
        "an uninitialised section still declares a virtual size"
    );
}

#[test]
fn two_sections_that_share_raw_bytes_record_the_overlap() {
    let mut bytes: Vec<u8> = fixture("hello.pe64.exe");
    assert!(
        pe_section_count(&bytes) >= 2,
        "this case needs two sections"
    );
    let first_offset: u32 = read_u32_le(&bytes, pe_section_field(&bytes, 0, RAW_OFFSET_FIELD));
    let second_field: usize = pe_section_field(&bytes, 1, RAW_OFFSET_FIELD);
    write_u32_le(&mut bytes, second_field, first_offset);

    let coverage: ByteCoverage =
        file_byte_coverage(&bytes).expect("map a PE with overlapping sections");
    assert_partition(
        &coverage,
        bytes.len() as u64,
        "hello.pe64.exe with an overlap",
    );

    assert!(
        coverage.overlap_detected,
        "two sections that share raw bytes must be recorded, not silently resolved"
    );
    let overlap: &CoverageOverlap = coverage.overlaps.first().expect("one recorded overlap");
    assert_eq!(overlap.start, u64::from(first_offset));
    assert!(
        overlap.first.starts_with("section:") && overlap.second.starts_with("section:"),
        "an overlap names both claimants: {} and {}",
        overlap.first,
        overlap.second
    );
    assert_ne!(
        overlap.first, overlap.second,
        "an overlap must name two different claimants"
    );
    assert!(
        !coverage.complete,
        "an image with an overlap is not a complete accounting"
    );
    assert!(
        coverage.coverage_ratio <= 1.0,
        "a doubly claimed byte must never report more than complete coverage"
    );
}

#[test]
fn a_section_that_runs_past_the_end_is_clamped_and_recorded() {
    let mut bytes: Vec<u8> = fixture("hello.pe64.exe");
    let last: usize = pe_section_count(&bytes) - 1;
    let raw_offset: u64 = u64::from(read_u32_le(
        &bytes,
        pe_section_field(&bytes, last, RAW_OFFSET_FIELD),
    ));
    let declared: u32 = 0x1000_0000;
    let last_size_field: usize = pe_section_field(&bytes, last, RAW_SIZE_FIELD);
    write_u32_le(&mut bytes, last_size_field, declared);
    let file_len: u64 = bytes.len() as u64;

    let coverage: ByteCoverage =
        file_byte_coverage(&bytes).expect("map a PE with a truncated section");
    assert_partition(
        &coverage,
        file_len,
        "hello.pe64.exe with a truncated section",
    );

    let entry: &TruncatedClaim = coverage
        .truncated
        .iter()
        .find(|claim: &&TruncatedClaim| claim.start == raw_offset)
        .expect("a section that runs past the end must be recorded");
    assert_eq!(entry.declared_end, raw_offset + u64::from(declared));
    assert_eq!(entry.present_end, file_len);
    assert_eq!(entry.missing_bytes, entry.declared_end - file_len);
    assert_eq!(coverage.truncated_bytes, entry.missing_bytes);
}

#[test]
fn a_section_count_larger_than_the_file_is_a_typed_refusal() {
    let mut bytes: Vec<u8> = fixture("hello.pe64.exe");
    let lfanew: usize = pe_lfanew(&bytes);
    write_u16_le(&mut bytes, lfanew + 6, u16::MAX);

    let error: Error = file_byte_coverage(&bytes)
        .expect_err("a section table larger than the file must not be walked");
    assert!(
        error.to_string().contains("DR-BINFMT-0072"),
        "an impossible table count is a coverage refusal: {error}"
    );
}

#[test]
fn a_truncated_header_is_a_typed_refusal() {
    let bytes: Vec<u8> = fixture("hello.pe64.exe");
    for length in [1usize, 8, 65, 100, 200] {
        let window: Vec<u8> = bytes
            .get(..length)
            .expect("the fixture is longer than the window")
            .to_vec();
        let error: Error =
            file_byte_coverage(&window).expect_err("a truncated PE header must not map");
        assert!(
            error.to_string().starts_with("DR-BINFMT-"),
            "a {length} byte window must fail with a diagnostic code: {error}"
        );
    }
}

#[test]
fn two_runs_produce_the_same_intervals() {
    let formats: Vec<String> = MAPPED_FIXTURES
        .iter()
        .map(|name: &&str| format!("{FORMATS_DIR}/{name}"))
        .chain(
            LINKED_PE32_FIXTURES
                .iter()
                .map(|relative: &&str| (*relative).to_owned()),
        )
        .collect();

    for name in formats {
        let bytes: Vec<u8> = required_corpus(&name);
        let first: ByteCoverage = file_byte_coverage(&bytes).expect("map a fixture");
        let second: ByteCoverage = file_byte_coverage(&bytes).expect("map a fixture twice");
        assert_eq!(
            first.regions, second.regions,
            "{name}: interval order must not vary"
        );
        assert_eq!(
            serde_json::to_string(&first).expect("serialize a coverage map"),
            serde_json::to_string(&second).expect("serialize a coverage map twice"),
            "{name}: the serialized map must be reproducible"
        );
    }
}

#[test]
fn a_big_endian_elf_is_covered_end_to_end() {
    let mut object_file: object::write::Object<'_> = object::write::Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::PowerPc64,
        object::Endianness::Big,
    );
    let text: object::write::SectionId =
        object_file.section_id(object::write::StandardSection::Text);
    let _offset: u64 = object_file.append_section_data(text, &[0x60u8; 64], 16);
    let bytes: Vec<u8> = object_file.write().expect("write a big endian ELF");

    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a big endian ELF");
    assert_eq!(coverage.format, NativeFormat::Elf64);
    assert_partition(&coverage, bytes.len() as u64, "big endian ELF");
    assert_eq!(
        coverage.unclaimed_bytes, 0,
        "a linker written big endian ELF accounts for every byte"
    );
    assert!(
        region_named(&coverage, "section:.text").is_some(),
        "the big endian walk must resolve section names"
    );
}

#[test]
fn a_thirty_two_bit_macho_is_covered_end_to_end() {
    let mut object_file: object::write::Object<'_> = object::write::Object::new(
        object::BinaryFormat::MachO,
        object::Architecture::I386,
        object::Endianness::Little,
    );
    let text: object::write::SectionId =
        object_file.section_id(object::write::StandardSection::Text);
    let _offset: u64 = object_file.append_section_data(text, &[0x90u8; 48], 16);
    let bytes: Vec<u8> = object_file.write().expect("write a 32 bit Mach-O");

    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a 32 bit Mach-O");
    assert_eq!(coverage.format, NativeFormat::MachO32);
    assert_partition(&coverage, bytes.len() as u64, "Mach-O 32");
    assert_eq!(
        coverage.unclaimed_bytes, 0,
        "an assembler written Mach-O object accounts for every byte"
    );
    assert!(
        region_named(&coverage, "load-command:LC_SEGMENT").is_some(),
        "the 32 bit walk must name its segment load command"
    );
}

fn thin_macho(architecture: object::Architecture) -> Vec<u8> {
    let mut object_file: object::write::Object<'_> = object::write::Object::new(
        object::BinaryFormat::MachO,
        architecture,
        object::Endianness::Little,
    );
    let text: object::write::SectionId =
        object_file.section_id(object::write::StandardSection::Text);
    let _offset: u64 = object_file.append_section_data(text, &[0x90u8; 64], 16);
    object_file.write().expect("write a thin Mach-O slice")
}

#[test]
fn a_universal_binary_accounts_for_every_slice_and_its_padding() {
    let first: Vec<u8> = thin_macho(object::Architecture::I386);
    let second: Vec<u8> = thin_macho(object::Architecture::X86_64);
    let alignment: usize = 4096;
    let first_offset: usize = alignment;
    let second_offset: usize = (first_offset + first.len()).div_ceil(alignment) * alignment;
    let total: usize = second_offset + second.len();

    let mut bytes: Vec<u8> = vec![0u8; total];
    bytes[0..4].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    bytes[4..8].copy_from_slice(&2u32.to_be_bytes());
    let entries: [(u32, u32, usize, usize); 2] = [
        (7, 3, first_offset, first.len()),
        (0x0100_0007, 3, second_offset, second.len()),
    ];
    for (index, (cputype, cpusubtype, offset, size)) in entries.iter().enumerate() {
        let base: usize = 8 + index * 20;
        bytes[base..base + 4].copy_from_slice(&cputype.to_be_bytes());
        bytes[base + 4..base + 8].copy_from_slice(&cpusubtype.to_be_bytes());
        bytes[base + 8..base + 12].copy_from_slice(&(*offset as u32).to_be_bytes());
        bytes[base + 12..base + 16].copy_from_slice(&(*size as u32).to_be_bytes());
        bytes[base + 16..base + 20].copy_from_slice(&12u32.to_be_bytes());
    }
    bytes[first_offset..first_offset + first.len()].copy_from_slice(&first);
    bytes[second_offset..second_offset + second.len()].copy_from_slice(&second);

    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a universal binary");
    assert_eq!(coverage.format, NativeFormat::MachOFat);
    assert_partition(&coverage, bytes.len() as u64, "universal binary");
    assert_eq!(
        coverage.unclaimed_bytes, 0,
        "the padding between slices is zero filled alignment, not an unaccounted range"
    );
    assert!(
        coverage.slack_bytes > 0,
        "the alignment padding between slices must be recorded as slack, not as claimed bytes"
    );
    assert!(
        region_named(&coverage, "fat-header").is_some()
            && region_named(&coverage, "fat-arch-table").is_some(),
        "the fat walk must name its header and its architecture table"
    );
    let slices: usize = coverage
        .regions
        .iter()
        .filter(|region: &&CoverageRegion| {
            region
                .claimant
                .as_deref()
                .is_some_and(|claimant: &str| claimant.starts_with("slice:"))
        })
        .count();
    assert_eq!(slices, 2, "every architecture slice must be claimed");
}

#[test]
fn a_nested_directory_is_described_once_inside_its_section() {
    let mut examined: usize = 0;

    for name in ["hello.pe64.exe", "hello.auditable.exe", "hello.efi"] {
        let bytes: Vec<u8> = fixture(name);
        let Ok(parsed): Result<object::read::pe::PeFile64<'_, &[u8]>, object::Error> =
            object::read::pe::PeFile64::parse(bytes.as_slice())
        else {
            continue;
        };
        let sections: object::read::pe::SectionTable<'_> = parsed.section_table();
        let Some(directory): Option<&object::pe::ImageDataDirectory> = parsed
            .data_directories()
            .get(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG)
        else {
            continue;
        };
        let Ok((offset, size)): Result<(u32, u32), object::Error> = directory.file_range(&sections)
        else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a PE image");
        let claimants: Vec<String> =
            claimants_over(&coverage, u64::from(offset), u64::from(offset + size));
        assert!(
            !claimants.is_empty(),
            "{name}: the debug directory at {offset} is described by no region"
        );
        for claimant in &claimants {
            assert!(
                claimant.starts_with("section:"),
                "{name}: the debug directory lives inside a section, so the map must describe it \
                 at section granularity and not claim it twice, and it names {claimant}"
            );
        }
        examined += 1;
    }

    assert!(
        examined > 0,
        "no committed PE fixture carries a debug directory, so this case graded nothing"
    );
}

const LINKED_PE32_FIXTURES: [&str; 3] = [
    "native/packers/aspack/Clockres.original.exe",
    "native/packers/mew/Autologon.original.exe",
    "dotnet/HelloApp.dll",
];

#[test]
fn a_linked_pe32_is_covered_end_to_end() {
    for relative in LINKED_PE32_FIXTURES {
        let bytes: Vec<u8> = required_corpus(relative);
        let coverage: ByteCoverage =
            file_byte_coverage(&bytes).unwrap_or_else(|error: Error| panic!("{relative}: {error}"));

        assert_eq!(
            coverage.format,
            NativeFormat::Pe32,
            "{relative}: this case exists to walk the 32 bit optional header"
        );
        assert_partition(&coverage, bytes.len() as u64, relative);
        assert_eq!(
            coverage.unclaimed_bytes, 0,
            "{relative}: a linked 32 bit image accounts for every byte"
        );
    }
}

#[test]
fn every_section_an_independent_parser_reports_in_a_pe32_is_claimed_under_its_own_name() {
    let mut checked: usize = 0;

    for relative in LINKED_PE32_FIXTURES {
        let bytes: Vec<u8> = required_corpus(relative);
        let coverage: ByteCoverage =
            file_byte_coverage(&bytes).unwrap_or_else(|error: Error| panic!("{relative}: {error}"));
        let parsed: object::read::File<'_, &[u8]> = object::read::File::parse(bytes.as_slice())
            .unwrap_or_else(|error: object::Error| {
                panic!("{relative}: the reference parser must read this fixture: {error}")
            });

        for section in parsed.sections() {
            let Some((offset, size)): Option<(u64, u64)> = section.file_range() else {
                continue;
            };
            if size == 0 {
                continue;
            }
            let section_name: String = section
                .name()
                .unwrap_or_else(|error: object::Error| {
                    panic!("{relative}: a reference section name must decode: {error}")
                })
                .to_owned();
            let end: u64 = offset + size;
            for claimant in claimants_over(&coverage, offset, end) {
                assert!(
                    claimant.starts_with("section:") && claimant.ends_with(&section_name),
                    "{relative}: the reference parser places {section_name} at {offset}..{end}, \
                     and the map attributes part of it to {claimant}"
                );
            }
            checked += 1;
        }
    }

    assert!(
        checked >= 10,
        "the 32 bit differential check must grade a real number of sections, and it graded \
         {checked}"
    );
}

fn pe32_directory(bytes: &[u8], index: usize) -> (u32, u32) {
    let lfanew: usize = pe_lfanew(bytes);
    let base: usize = lfanew + 24 + 0x60 + index * 8;
    (read_u32_le(bytes, base), read_u32_le(bytes, base + 4))
}

#[test]
fn an_authenticode_signature_is_claimed_rather_than_left_unaccounted() {
    let relative: &str = "native/packers/aspack/Clockres.original.exe";
    let bytes: Vec<u8> = required_corpus(relative);
    let (offset, size): (u32, u32) =
        pe32_directory(&bytes, object::pe::IMAGE_DIRECTORY_ENTRY_SECURITY);
    assert!(
        offset > 0 && size > 0,
        "{relative} must carry a certificate table for this case to grade anything"
    );

    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a signed PE32");
    assert_partition(&coverage, bytes.len() as u64, relative);

    let region: &CoverageRegion =
        region_named(&coverage, "certificate-table").expect("the certificate table is claimed");
    assert_eq!(
        (region.start, region.end),
        (u64::from(offset), u64::from(offset + size)),
        "the certificate table claim must be the range the directory declares"
    );
    assert_eq!(
        region.class,
        RegionClass::Signature,
        "the certificate table is a signature region"
    );
    assert_eq!(
        coverage.unclaimed_bytes, 0,
        "a signature that follows the last section is a claim, not an unaccounted overlay"
    );
}

#[test]
fn a_packed_image_whose_certificate_table_points_past_the_end_is_recorded() {
    let relative: &str = "native/packers/aspack/Clockres.packed.aspack.exe";
    let bytes: Vec<u8> = required_corpus(relative);
    let file_len: u64 = bytes.len() as u64;
    let (offset, size): (u32, u32) =
        pe32_directory(&bytes, object::pe::IMAGE_DIRECTORY_ENTRY_SECURITY);
    assert!(
        u64::from(offset) >= file_len,
        "this case exists because the packer left a certificate table that no longer fits, and \
         the directory now points at {offset} in a {file_len} byte file"
    );

    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a packed PE32");
    assert_partition(&coverage, file_len, relative);

    let entry: &TruncatedClaim = coverage
        .truncated
        .iter()
        .find(|claim: &&TruncatedClaim| claim.claimant == "certificate-table")
        .expect("a directory that points past the end must be recorded, not clamped in silence");
    assert_eq!(entry.start, u64::from(offset));
    assert_eq!(entry.declared_end, u64::from(offset) + u64::from(size));
    assert_eq!(
        entry.present_end, entry.start,
        "a table that begins past the end has no present byte at all"
    );
    assert_eq!(
        entry.missing_bytes,
        u64::from(size),
        "the missing count is the declared table, not the distance to the end of the file"
    );
    assert!(
        region_named(&coverage, "certificate-table").is_none(),
        "a table that lies entirely past the end claims no byte of the file"
    );
}

#[test]
fn a_sixty_four_bit_universal_binary_accounts_for_every_slice() {
    let first: Vec<u8> = thin_macho(object::Architecture::I386);
    let second: Vec<u8> = thin_macho(object::Architecture::X86_64);
    let alignment: usize = 4096;
    let first_offset: usize = alignment;
    let second_offset: usize = (first_offset + first.len()).div_ceil(alignment) * alignment;
    let total: usize = second_offset + second.len();

    let mut bytes: Vec<u8> = vec![0u8; total];
    bytes[0..4].copy_from_slice(&0xCAFE_BABFu32.to_be_bytes());
    bytes[4..8].copy_from_slice(&2u32.to_be_bytes());
    let entries: [(u32, u32, usize, usize); 2] = [
        (7, 3, first_offset, first.len()),
        (0x0100_0007, 3, second_offset, second.len()),
    ];
    for (index, (cputype, cpusubtype, offset, size)) in entries.iter().enumerate() {
        let base: usize = 8 + index * 32;
        bytes[base..base + 4].copy_from_slice(&cputype.to_be_bytes());
        bytes[base + 4..base + 8].copy_from_slice(&cpusubtype.to_be_bytes());
        bytes[base + 8..base + 16].copy_from_slice(&(*offset as u64).to_be_bytes());
        bytes[base + 16..base + 24].copy_from_slice(&(*size as u64).to_be_bytes());
        bytes[base + 24..base + 28].copy_from_slice(&12u32.to_be_bytes());
    }
    bytes[first_offset..first_offset + first.len()].copy_from_slice(&first);
    bytes[second_offset..second_offset + second.len()].copy_from_slice(&second);

    let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a 64 bit universal binary");
    assert_eq!(coverage.format, NativeFormat::MachOFat);
    assert_partition(
        &coverage,
        bytes.len() as u64,
        "universal binary (64 bit table)",
    );
    assert_eq!(
        coverage.unclaimed_bytes, 0,
        "the 64 bit architecture table must be walked with 64 bit slice offsets"
    );
    let table: &CoverageRegion =
        region_named(&coverage, "fat-arch-table").expect("the architecture table is claimed");
    assert_eq!(
        table.len(),
        64,
        "two 64 bit architecture entries occupy 64 bytes"
    );
}

#[test]
fn an_elf_without_a_section_table_falls_back_to_its_load_segments() {
    let mut bytes: Vec<u8> = fixture("hello.elf64");
    bytes[40..48].copy_from_slice(&0u64.to_le_bytes());
    bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
    bytes[62..64].copy_from_slice(&0u16.to_le_bytes());

    let coverage: ByteCoverage =
        file_byte_coverage(&bytes).expect("map a stripped ELF with no section table");
    assert_partition(
        &coverage,
        bytes.len() as u64,
        "hello.elf64 without a section table",
    );
    assert!(
        coverage.regions.iter().any(|region: &CoverageRegion| {
            region
                .claimant
                .as_deref()
                .is_some_and(|claimant: &str| claimant.starts_with("segment:load#"))
        }),
        "an image with no section table must be described by its load segments: {:?}",
        coverage.regions
    );
    assert!(
        !coverage.overlap_detected,
        "the load segment fallback must not double claim the ELF header or the program headers"
    );
    assert!(
        coverage.unclaimed_bytes > 0,
        "the bytes only the discarded section table described must surface as unclaimed"
    );
}

#[test]
fn a_nested_directory_in_a_pe32_is_described_once_inside_its_section() {
    let mut examined: usize = 0;

    for relative in LINKED_PE32_FIXTURES {
        let bytes: Vec<u8> = required_corpus(relative);
        let Ok(parsed): Result<object::read::pe::PeFile32<'_, &[u8]>, object::Error> =
            object::read::pe::PeFile32::parse(bytes.as_slice())
        else {
            continue;
        };
        let sections: object::read::pe::SectionTable<'_> = parsed.section_table();
        let Some(directory): Option<&object::pe::ImageDataDirectory> = parsed
            .data_directories()
            .get(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG)
        else {
            continue;
        };
        let Ok((offset, size)): Result<(u32, u32), object::Error> = directory.file_range(&sections)
        else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let coverage: ByteCoverage = file_byte_coverage(&bytes).expect("map a PE32 image");
        let claimants: Vec<String> =
            claimants_over(&coverage, u64::from(offset), u64::from(offset + size));
        assert!(
            !claimants.is_empty(),
            "{relative}: the debug directory at {offset} is described by no region"
        );
        for claimant in &claimants {
            assert!(
                claimant.starts_with("section:"),
                "{relative}: the debug directory lives inside a section, so the map describes it \
                 at section granularity and never claims it twice, and it names {claimant}"
            );
        }
        examined += 1;
    }

    assert!(
        examined > 0,
        "no committed 32 bit PE fixture carries a debug directory, so this case graded nothing"
    );
}

#[test]
fn a_thirty_two_bit_elf_without_a_section_table_reads_its_load_segment_permissions() {
    let mut bytes: Vec<u8> = fixture("avr_firmware.elf");
    bytes[32..36].copy_from_slice(&0u32.to_le_bytes());
    bytes[48..50].copy_from_slice(&0u16.to_le_bytes());
    bytes[50..52].copy_from_slice(&0u16.to_le_bytes());

    let coverage: ByteCoverage =
        file_byte_coverage(&bytes).expect("map a 32 bit ELF with no section table");
    assert_eq!(coverage.format, NativeFormat::Elf32);
    assert_partition(
        &coverage,
        bytes.len() as u64,
        "avr_firmware.elf without a section table",
    );

    let executable: usize = coverage
        .regions
        .iter()
        .filter(|region: &&CoverageRegion| {
            region.class == RegionClass::Code
                && region
                    .claimant
                    .as_deref()
                    .is_some_and(|claimant: &str| claimant.starts_with("segment:load#"))
        })
        .count();
    assert!(
        executable > 0,
        "a firmware image carries an executable load segment, and the 32 bit program header walk \
         must read p_flags after p_memsz: {:?}",
        coverage.regions
    );
    assert!(
        !coverage.overlap_detected,
        "the 32 bit fallback must not double claim the ELF header or the program headers"
    );
}
