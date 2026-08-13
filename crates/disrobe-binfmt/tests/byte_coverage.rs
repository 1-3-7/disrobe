#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use common::requirement::{corpus_path, required_corpus};
use disrobe_binfmt::coverage::{
    BYTE_COVERAGE_SCHEMA, ByteCoverage, CoverageRegion, RegionClass, file_byte_coverage,
};
use disrobe_binfmt::error::Error;
use disrobe_binfmt::native::NativeFormat;

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
