#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::requirement::{corpus_path, required_corpus};
use disrobe_binfmt::error::Error;
use disrobe_binfmt::native::NativeFormat;
use disrobe_binfmt::rewrite::{
    DerivedKind, FileEdit, IMAGE_PLAN_SCHEMA, ImagePlan, PatchedImage, PlanCoverage, Structure,
    StructureKind, emit_native_image, patch_native_image, plan_native_image,
};
use disrobe_testkit::XorShift64;

const FORMATS_DIR: &str = "native/formats";
const PACKERS_DIR: &str = "native/packers";
const SCRUB_FILL: u8 = 0xCC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    RoundTrips(NativeFormat),
    Refused,
}

fn formats_expectations() -> BTreeMap<&'static str, Expectation> {
    BTreeMap::from([
        (
            "avr_firmware.elf",
            Expectation::RoundTrips(NativeFormat::Elf32),
        ),
        ("dwarf_v2.o", Expectation::RoundTrips(NativeFormat::Coff)),
        ("dwarf_v3.o", Expectation::RoundTrips(NativeFormat::Coff)),
        ("dwarf_v4.o", Expectation::RoundTrips(NativeFormat::Coff)),
        ("dwarf_v5.o", Expectation::RoundTrips(NativeFormat::Coff)),
        (
            "hello.auditable.exe",
            Expectation::RoundTrips(NativeFormat::Pe64),
        ),
        (
            "hello.coff.x64.o",
            Expectation::RoundTrips(NativeFormat::Coff),
        ),
        ("hello.efi", Expectation::RoundTrips(NativeFormat::Pe64)),
        ("hello.elf64", Expectation::RoundTrips(NativeFormat::Elf64)),
        (
            "hello.macho64.o",
            Expectation::RoundTrips(NativeFormat::MachO64),
        ),
        (
            "hello.pe64.exe",
            Expectation::RoundTrips(NativeFormat::Pe64),
        ),
        ("hello_lx.exe", Expectation::Refused),
        ("hello_ne.exe", Expectation::Refused),
        ("hello_os2_ne.exe", Expectation::Refused),
        (
            "hello_reloc.ko.o",
            Expectation::RoundTrips(NativeFormat::Elf64),
        ),
        ("hello_stabs.o", Expectation::RoundTrips(NativeFormat::Coff)),
        ("os2_ne_probe.c", Expectation::Refused),
        ("PROVENANCE.txt", Expectation::Refused),
    ])
}

fn variant_fixtures() -> Vec<(&'static str, NativeFormat)> {
    vec![
        ("native/formats/hello.pe64.exe", NativeFormat::Pe64),
        ("native/formats/hello.efi", NativeFormat::Pe64),
        ("native/formats/hello.elf64", NativeFormat::Elf64),
        ("native/formats/avr_firmware.elf", NativeFormat::Elf32),
        ("native/formats/hello.macho64.o", NativeFormat::MachO64),
        ("native/formats/hello.coff.x64.o", NativeFormat::Coff),
        ("mac/megafile/EdgeCases.fat", NativeFormat::MachOFat),
        (
            "mobile/macho-mac/SwiftHello.original",
            NativeFormat::MachO64,
        ),
        (
            "mobile/macho-mac/swiftshield-edgecases/SwiftEdgeCases.original",
            NativeFormat::MachO64,
        ),
        (
            "native/packers/aspack/AccessEnum.original.exe",
            NativeFormat::Pe32,
        ),
        (
            "binfmt/dotnet-single-file/expected/libcustom.dll",
            NativeFormat::Pe64,
        ),
        ("binfmt/elf-dynamic/sample.elf", NativeFormat::Elf64),
        ("binfmt/elf-overlay/hello.elf", NativeFormat::Elf64),
        ("native/discovery/disc.stripped.elf", NativeFormat::Elf64),
        ("native/discovery/disc.unstripped.elf", NativeFormat::Elf64),
        ("native/nim/hello.nim.elf", NativeFormat::Elf64),
        ("binfmt/cython/cymod.linux.so", NativeFormat::Elf64),
        ("native/d/hello.d.o.elf", NativeFormat::Elf64),
        ("native/formats/hello_stabs.o", NativeFormat::Coff),
        ("native/compilers/go/hello.go.exe", NativeFormat::Pe64),
    ]
}

fn assert_round_trip(bytes: &[u8], subject: &str) -> ImagePlan {
    let plan: ImagePlan = plan_native_image(bytes)
        .unwrap_or_else(|error: Error| panic!("{subject}: the image must plan: {error}"));
    assert_eq!(
        plan.schema(),
        IMAGE_PLAN_SCHEMA,
        "{subject}: the plan must carry its versioned schema"
    );
    assert_eq!(
        plan.file_len(),
        bytes.len() as u64,
        "{subject}: the plan must record the real file length"
    );

    let coverage: PlanCoverage = plan.coverage();
    assert!(
        coverage.is_complete(),
        "{subject}: structure {} plus opaque {} must account for every one of {} bytes",
        coverage.structure_bytes,
        coverage.opaque_bytes,
        coverage.file_len
    );
    assert!(
        coverage.structure_bytes > 0,
        "{subject}: a plan that types no byte is a byte copy, not a model"
    );

    let mut cursor: u64 = 0;
    for structure in plan.structures() {
        assert!(
            structure.start() >= cursor,
            "{subject}: `{}` at {} overlaps the structure ending at {cursor}",
            structure.kind().label(),
            structure.start()
        );
        assert!(
            !structure.is_empty(),
            "{subject}: `{}` models zero bytes",
            structure.kind().label()
        );
        assert_eq!(
            structure.len(),
            structure.body().encoded_len(),
            "{subject}: `{}` must re-encode to the length it was planned at",
            structure.kind().label()
        );
        cursor = structure.end();
    }
    assert!(
        cursor <= plan.file_len(),
        "{subject}: a structure runs past the image"
    );

    let emitted: Vec<u8> = plan
        .emit(bytes)
        .unwrap_or_else(|error: Error| panic!("{subject}: the image must re-emit: {error}"));
    assert_eq!(
        emitted.len(),
        bytes.len(),
        "{subject}: re-emission must not change the file length"
    );
    assert!(
        emitted == bytes,
        "{subject}: re-emission must reproduce the input byte for byte; first difference at {:?}",
        first_difference(&emitted, bytes)
    );

    let scrubbed: Vec<u8> = scrub_structures(bytes, &plan);
    let from_model: Vec<u8> = plan.emit(&scrubbed).unwrap_or_else(|error: Error| {
        panic!("{subject}: the scrubbed image must still re-emit: {error}")
    });
    assert!(
        from_model == bytes,
        "{subject}: every structure byte must come from the typed model rather than the source \
         buffer; first difference at {:?}",
        first_difference(&from_model, bytes)
    );

    plan
}

fn scrub_structures(bytes: &[u8], plan: &ImagePlan) -> Vec<u8> {
    let mut scrubbed: Vec<u8> = bytes.to_vec();
    for structure in plan.structures() {
        let start: usize = structure.start() as usize;
        let end: usize = structure.end() as usize;
        if let Some(window) = scrubbed.get_mut(start..end) {
            window.fill(SCRUB_FILL);
        }
    }
    scrubbed
}

fn first_difference(left: &[u8], right: &[u8]) -> Option<usize> {
    left.iter()
        .zip(right.iter())
        .position(|(a, b): (&u8, &u8)| a != b)
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
        .filter_map(|entry: std::io::Result<std::fs::DirEntry>| entry.ok())
        .map(|entry: std::fs::DirEntry| entry.path())
        .filter(|path: &PathBuf| path.is_file())
        .collect();
    paths.sort();
    paths
}

fn read_dir_recursive(relative: &str) -> Vec<PathBuf> {
    let root: PathBuf = corpus_path(relative);
    let mut pending: Vec<PathBuf> = vec![root.clone()];
    let mut files: Vec<PathBuf> = Vec::new();
    let mut visited: usize = 0;

    while let Some(directory) = pending.pop() {
        visited += 1;
        assert!(
            visited <= 4_096,
            "corpus/{relative} walk visited more than 4096 directories"
        );
        let entries: std::fs::ReadDir =
            std::fs::read_dir(&directory).unwrap_or_else(|error: std::io::Error| {
                panic!(
                    "corpus/{relative} is tracked in git and this case grades nothing without it, \
                     so its absence is a damaged checkout: {error} ({})",
                    root.display()
                )
            });
        for entry in entries.filter_map(|entry: std::io::Result<std::fs::DirEntry>| entry.ok()) {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn every_committed_format_fixture_round_trips_or_is_refused_by_name() {
    let expectations: BTreeMap<&'static str, Expectation> = formats_expectations();
    let paths: Vec<PathBuf> = read_formats_dir();
    assert!(
        paths.len() >= expectations.len(),
        "corpus/{FORMATS_DIR} holds {} file(s), fewer than the {} this case grades",
        paths.len(),
        expectations.len()
    );

    let mut round_tripped: usize = 0;
    let mut refused: usize = 0;
    for path in &paths {
        let name: String = path
            .file_name()
            .map(|value: &std::ffi::OsStr| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        let expectation: Expectation = *expectations.get(name.as_str()).unwrap_or_else(|| {
            panic!(
                "corpus/{FORMATS_DIR}/{name} is not named in this case's expectation table, so it \
                 would be graded by nothing; classify it as round-tripping or refused"
            )
        });
        let bytes: Vec<u8> = std::fs::read(path).unwrap_or_else(|error: std::io::Error| {
            panic!("corpus/{FORMATS_DIR}/{name} must be readable: {error}")
        });

        match expectation {
            Expectation::RoundTrips(format) => {
                let plan: ImagePlan = assert_round_trip(&bytes, &name);
                assert_eq!(
                    plan.format(),
                    format,
                    "{name}: the plan must name the format the table records"
                );
                round_tripped += 1;
            }
            Expectation::Refused => {
                let Err(error) = plan_native_image(&bytes) else {
                    panic!("{name}: this input has no typed model and must be refused")
                };
                assert!(
                    matches!(
                        error,
                        Error::Rewrite(_)
                            | Error::RewriteUnsupported { .. }
                            | Error::NativeParse(_)
                    ),
                    "{name}: a refusal must be typed, not `{error}`"
                );
                refused += 1;
            }
        }
    }

    assert_eq!(
        round_tripped + refused,
        paths.len(),
        "every file under corpus/{FORMATS_DIR} must be graded"
    );
    assert_eq!(
        round_tripped, 13,
        "corpus/{FORMATS_DIR} carries 13 images with a typed model and {round_tripped} \
         round-tripped"
    );
}

#[test]
fn every_native_format_variant_has_a_round_tripping_fixture() {
    let mut covered: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (relative, format) in variant_fixtures() {
        let bytes: Vec<u8> = required_corpus(relative);
        let plan: ImagePlan = assert_round_trip(&bytes, relative);
        assert_eq!(
            plan.format(),
            format,
            "{relative}: the plan must name the format this case records"
        );
        *covered.entry(plan.format().label()).or_insert(0) += 1;
    }

    for format in [
        NativeFormat::Pe32,
        NativeFormat::Pe64,
        NativeFormat::Elf32,
        NativeFormat::Elf64,
        NativeFormat::MachO64,
        NativeFormat::MachOFat,
        NativeFormat::Coff,
    ] {
        assert!(
            covered.get(format.label()).copied().unwrap_or(0) > 0,
            "`{}` has no round-tripping committed fixture in this case",
            format.label()
        );
    }
}

#[test]
fn a_thirty_two_bit_macho_written_by_an_outside_encoder_round_trips() {
    let bytes: Vec<u8> = write_macho(object::Architecture::I386);
    let plan: ImagePlan = assert_round_trip(&bytes, "object-written Mach-O 32");
    assert_eq!(plan.format(), NativeFormat::MachO32);
}

#[test]
fn a_big_endian_elf_written_by_an_outside_encoder_round_trips() {
    let bytes: Vec<u8> = write_elf(object::Architecture::PowerPc64, object::Endianness::Big);
    let plan: ImagePlan = assert_round_trip(&bytes, "object-written big endian ELF64");
    assert_eq!(plan.format(), NativeFormat::Elf64);

    let thirty_two: Vec<u8> = write_elf(object::Architecture::PowerPc, object::Endianness::Big);
    let narrow: ImagePlan = assert_round_trip(&thirty_two, "object-written big endian ELF32");
    assert_eq!(narrow.format(), NativeFormat::Elf32);
}

fn write_macho(architecture: object::Architecture) -> Vec<u8> {
    let mut object_file: object::write::Object<'_> = object::write::Object::new(
        object::BinaryFormat::MachO,
        architecture,
        object::Endianness::Little,
    );
    let text: object::write::SectionId =
        object_file.section_id(object::write::StandardSection::Text);
    let _offset: u64 = object_file.append_section_data(text, &[0x90u8; 48], 16);
    object_file.write().expect("write a Mach-O object")
}

fn write_elf(architecture: object::Architecture, endianness: object::Endianness) -> Vec<u8> {
    let mut object_file: object::write::Object<'_> =
        object::write::Object::new(object::BinaryFormat::Elf, architecture, endianness);
    let text: object::write::SectionId =
        object_file.section_id(object::write::StandardSection::Text);
    let _offset: u64 = object_file.append_section_data(text, &[0x60u8; 64], 16);
    object_file.write().expect("write an ELF object")
}

#[test]
fn a_committed_packer_corpus_round_trips_without_a_single_byte_of_drift() {
    let paths: Vec<PathBuf> = read_dir_recursive(PACKERS_DIR);
    let mut graded: usize = 0;
    let mut skipped_non_image: usize = 0;

    for path in &paths {
        let display: String = path.strip_prefix(corpus_path(PACKERS_DIR)).map_or_else(
            |_error: std::path::StripPrefixError| path.to_string_lossy().into_owned(),
            |rest: &std::path::Path| rest.to_string_lossy().replace('\\', "/"),
        );
        let bytes: Vec<u8> = std::fs::read(path).unwrap_or_else(|error: std::io::Error| {
            panic!("corpus/{PACKERS_DIR}/{display} must be readable: {error}")
        });
        if bytes.len() < 2 || bytes.first().copied() != Some(b'M') {
            skipped_non_image += 1;
            continue;
        }
        assert_round_trip(&bytes, &display);
        graded += 1;
    }

    assert!(
        graded >= 36,
        "corpus/{PACKERS_DIR} graded only {graded} packed image(s) out of {} file(s); the tree \
         tracks 36, so a smaller count is a damaged checkout and this case would measure almost \
         nothing",
        paths.len()
    );
    assert_eq!(
        graded + skipped_non_image,
        paths.len(),
        "every file under corpus/{PACKERS_DIR} must be graded or counted out"
    );
}

const SHT_NOBITS: u32 = 8;

#[test]
fn a_nobits_section_and_a_zero_length_section_round_trip() {
    let bytes: Vec<u8> = required_corpus("native/formats/avr_firmware.elf");
    let plan: ImagePlan = assert_round_trip(&bytes, "avr_firmware.elf");

    let mut nobits: usize = 0;
    let mut zero_length: usize = 0;
    for structure in plan.structures() {
        if let Structure::ElfSectionHeaders(table) = structure.body() {
            for entry in &table.entries {
                if entry.kind == SHT_NOBITS {
                    nobits += 1;
                } else if entry.size == 0 {
                    zero_length += 1;
                }
            }
        }
    }
    assert!(
        nobits > 0,
        "avr_firmware.elf must carry an SHT_NOBITS section for this case to grade anything"
    );
    assert!(
        zero_length > 0,
        "avr_firmware.elf must carry a zero length section for this case to grade anything"
    );
}

#[test]
fn a_pe_with_a_zero_length_section_round_trips() {
    let bytes: Vec<u8> = required_corpus("native/packers/aspack/AccessEnum.packed.aspack.exe");
    let plan: ImagePlan = assert_round_trip(&bytes, "AccessEnum.packed.aspack.exe");

    let mut zero_raw: usize = 0;
    for structure in plan.structures() {
        if let Structure::CoffSectionTable(table) = structure.body() {
            zero_raw += table
                .sections
                .iter()
                .filter(|section: &&disrobe_binfmt::rewrite::CoffSectionHeader| {
                    section.size_of_raw_data == 0
                })
                .count();
        }
    }
    assert!(
        zero_raw > 0,
        "the packed image must carry a section with no raw bytes for this case to grade anything"
    );
}

#[test]
fn a_signed_pe_with_an_overlay_round_trips_including_both() {
    let bytes: Vec<u8> = required_corpus("native/packers/aspack/AccessEnum.original.exe");
    let plan: ImagePlan = assert_round_trip(&bytes, "AccessEnum.original.exe");

    let mut certificate: Option<(u64, u64)> = None;
    let mut last_section_end: u64 = 0;
    for structure in plan.structures() {
        match structure.body() {
            Structure::PeDataDirectories(directories) => {
                if let Some(entry) = directories.entries.get(4)
                    && entry.virtual_address != 0
                    && entry.size != 0
                {
                    certificate = Some((u64::from(entry.virtual_address), u64::from(entry.size)));
                }
            }
            Structure::CoffSectionTable(table) => {
                for section in &table.sections {
                    last_section_end = last_section_end.max(
                        u64::from(section.pointer_to_raw_data)
                            .saturating_add(u64::from(section.size_of_raw_data)),
                    );
                }
            }
            _ => {}
        }
    }

    let (certificate_offset, certificate_size): (u64, u64) = certificate
        .expect("the fixture must carry an authenticode certificate for this case to grade it");
    assert!(
        certificate_offset.saturating_add(certificate_size) <= plan.file_len(),
        "the certificate table must live inside the image"
    );
    assert!(
        plan.file_len() > last_section_end,
        "the fixture must carry an overlay past its last section for this case to grade it"
    );
    assert!(
        plan.derived_values()
            .iter()
            .any(|value: &disrobe_binfmt::rewrite::DerivedValue| value.kind
                == DerivedKind::PeAuthenticode),
        "the plan must record the authenticode blob as a derived value it does not recompute"
    );
}

#[test]
fn a_stripped_elf_with_no_section_headers_round_trips() {
    for relative in [
        "binfmt/elf-dynamic/sample.elf",
        "binfmt/elf-overlay/hello.elf",
    ] {
        let bytes: Vec<u8> = required_corpus(relative);
        let plan: ImagePlan = assert_round_trip(&bytes, relative);
        let mut shoff: u64 = u64::MAX;
        for structure in plan.structures() {
            if let Structure::ElfHeader(header) = structure.body() {
                shoff = header.shoff;
            }
        }
        assert_eq!(
            shoff, 0,
            "{relative}: the fixture must declare no section header table for this case to grade \
             it"
        );
        assert!(
            !plan.structures().iter().any(
                |structure: &disrobe_binfmt::rewrite::PlannedStructure| structure.kind()
                    == StructureKind::ElfSectionHeaders
            ),
            "{relative}: a stripped image must plan no section header table"
        );
    }
}

#[test]
fn non_zero_alignment_padding_is_preserved_verbatim() {
    let mut examined: usize = 0;
    let mut carrying_non_zero_padding: usize = 0;

    for (relative, _format) in variant_fixtures() {
        let bytes: Vec<u8> = required_corpus(relative);
        let plan: ImagePlan = plan_native_image(&bytes)
            .unwrap_or_else(|error: Error| panic!("{relative}: the image must plan: {error}"));
        examined += 1;

        let mut cursor: u64 = 0;
        let mut non_zero_gap: bool = false;
        for structure in plan.structures() {
            if structure.start() > cursor {
                let gap: &[u8] = &bytes[cursor as usize..structure.start() as usize];
                if gap.iter().any(|value: &u8| *value != 0) {
                    non_zero_gap = true;
                }
            }
            cursor = structure.end();
        }
        if !non_zero_gap {
            continue;
        }
        carrying_non_zero_padding += 1;
        let emitted: Vec<u8> = plan
            .emit(&bytes)
            .unwrap_or_else(|error: Error| panic!("{relative}: the image must re-emit: {error}"));
        assert!(
            emitted == bytes,
            "{relative}: a gap holding non-zero bytes must be preserved verbatim"
        );
    }

    assert!(
        examined >= 20,
        "this case examined only {examined} fixture(s)"
    );
    assert!(
        carrying_non_zero_padding > 0,
        "none of the {examined} fixtures carries a gap with a non-zero byte, so this case graded \
         nothing"
    );
}

#[test]
fn a_pe_field_edit_changes_exactly_the_bytes_that_field_owns() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.pe64.exe");

    mutate_and_expect(&bytes, "pe dos header", |plan: &mut ImagePlan| {
        let start: u64 = structure_start(plan, StructureKind::PeDosHeader);
        for structure in plan.structures_mut() {
            if let Structure::PeDosHeader(header) = structure.body_mut() {
                header.cparhdr ^= 0xFFFF;
            }
        }
        (start + 8, start + 10)
    });

    mutate_and_expect(&bytes, "coff header timestamp", |plan: &mut ImagePlan| {
        let start: u64 = structure_start(plan, StructureKind::CoffHeader);
        for structure in plan.structures_mut() {
            if let Structure::CoffHeader(header) = structure.body_mut() {
                header.time_date_stamp = header.time_date_stamp.wrapping_add(1);
            }
        }
        (start + 4, start + 8)
    });

    mutate_and_expect(
        &bytes,
        "optional header entry point",
        |plan: &mut ImagePlan| {
            let start: u64 = structure_start(plan, StructureKind::PeOptionalHeader);
            for structure in plan.structures_mut() {
                if let Structure::PeOptionalHeader(header) = structure.body_mut() {
                    header.address_of_entry_point ^= 0xDEAD_BEEF;
                }
            }
            (start + 16, start + 20)
        },
    );

    mutate_and_expect(&bytes, "second data directory", |plan: &mut ImagePlan| {
        let start: u64 = structure_start(plan, StructureKind::PeDataDirectories);
        for structure in plan.structures_mut() {
            if let Structure::PeDataDirectories(directories) = structure.body_mut()
                && let Some(entry) = directories.entries.get_mut(1)
            {
                entry.size ^= 0x00FF_00FF;
            }
        }
        (start + 12, start + 16)
    });

    mutate_and_expect(
        &bytes,
        "first section characteristics",
        |plan: &mut ImagePlan| {
            let start: u64 = structure_start(plan, StructureKind::CoffSectionTable);
            for structure in plan.structures_mut() {
                if let Structure::CoffSectionTable(table) = structure.body_mut()
                    && let Some(section) = table.sections.first_mut()
                {
                    section.characteristics ^= 0x0000_0F00;
                }
            }
            (start + 36, start + 40)
        },
    );
}

#[test]
fn an_elf_field_edit_changes_exactly_the_bytes_that_field_owns() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.elf64");

    mutate_and_expect(&bytes, "elf entry point", |plan: &mut ImagePlan| {
        for structure in plan.structures_mut() {
            if let Structure::ElfHeader(header) = structure.body_mut() {
                header.entry ^= 0x0000_0000_00FF_0000;
            }
        }
        (24, 32)
    });

    mutate_and_expect(
        &bytes,
        "first program header vaddr",
        |plan: &mut ImagePlan| {
            let start: u64 = structure_start(plan, StructureKind::ElfProgramHeaders);
            for structure in plan.structures_mut() {
                if let Structure::ElfProgramHeaders(table) = structure.body_mut()
                    && let Some(entry) = table.entries.first_mut()
                {
                    entry.vaddr ^= 0x0000_0000_0F00_0000;
                }
            }
            (start + 16, start + 24)
        },
    );

    mutate_and_expect(
        &bytes,
        "second section name index",
        |plan: &mut ImagePlan| {
            let start: u64 = structure_start(plan, StructureKind::ElfSectionHeaders);
            for structure in plan.structures_mut() {
                if let Structure::ElfSectionHeaders(table) = structure.body_mut()
                    && let Some(entry) = table.entries.get_mut(1)
                {
                    entry.name ^= 0x0000_00F0;
                }
            }
            (start + 64, start + 68)
        },
    );
}

#[test]
fn a_macho_field_edit_changes_exactly_the_bytes_that_field_owns() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.macho64.o");

    mutate_and_expect(&bytes, "mach header flags", |plan: &mut ImagePlan| {
        for structure in plan.structures_mut() {
            if let Structure::MachHeader(header) = structure.body_mut() {
                header.flags ^= 0x0000_0F00;
            }
        }
        (24, 28)
    });

    mutate_and_expect(&bytes, "first segment vmsize", |plan: &mut ImagePlan| {
        let mut start: u64 = 0;
        for structure in plan.structures_mut() {
            let position: u64 = structure.start();
            if start != 0 {
                continue;
            }
            if let Structure::MachLoadCommand(command) = structure.body_mut()
                && let disrobe_binfmt::rewrite::MachCommandBody::Segment(segment) =
                    &mut command.body
            {
                start = position;
                segment.vmsize ^= 0x0000_0000_0000_0F00;
            }
        }
        assert!(start > 0, "the fixture must carry a segment load command");
        (start + 32, start + 40)
    });
}

#[test]
fn a_fat_arch_field_edit_changes_exactly_the_bytes_that_field_owns() {
    let bytes: Vec<u8> = required_corpus("mac/megafile/EdgeCases.fat");

    mutate_and_expect(
        &bytes,
        "second fat slice alignment",
        |plan: &mut ImagePlan| {
            let start: u64 = structure_start(plan, StructureKind::FatArchTable);
            for structure in plan.structures_mut() {
                if let Structure::FatArchTable(table) = structure.body_mut()
                    && let Some(entry) = table.entries.get_mut(1)
                {
                    entry.align ^= 0x0000_0001;
                }
            }
            (start + 36, start + 40)
        },
    );
}

fn structure_start(plan: &ImagePlan, kind: StructureKind) -> u64 {
    plan.structures()
        .iter()
        .find(|structure: &&disrobe_binfmt::rewrite::PlannedStructure| structure.kind() == kind)
        .map_or_else(
            || panic!("the fixture must carry a `{}` structure", kind.label()),
            disrobe_binfmt::rewrite::PlannedStructure::start,
        )
}

fn mutate_and_expect(
    bytes: &[u8],
    subject: &str,
    mutate: impl FnOnce(&mut ImagePlan) -> (u64, u64),
) {
    let mut plan: ImagePlan = plan_native_image(bytes)
        .unwrap_or_else(|error: Error| panic!("{subject}: the image must plan: {error}"));
    let (start, end): (u64, u64) = mutate(&mut plan);
    let emitted: Vec<u8> = plan
        .emit(bytes)
        .unwrap_or_else(|error: Error| panic!("{subject}: the edited plan must re-emit: {error}"));
    assert_eq!(
        emitted.len(),
        bytes.len(),
        "{subject}: a field edit must not change the file length"
    );

    let mut changed: Vec<usize> = Vec::new();
    for (offset, (left, right)) in emitted.iter().zip(bytes.iter()).enumerate() {
        if left != right {
            changed.push(offset);
        }
    }
    assert!(
        !changed.is_empty(),
        "{subject}: the field edit changed no byte, so the plan is not re-encoding this field"
    );
    let first: usize = changed.first().copied().unwrap_or_default();
    let last: usize = changed.last().copied().unwrap_or_default();
    assert!(
        first as u64 >= start && (last as u64) < end,
        "{subject}: the edit changed bytes {first}..={last}, outside the {start}..{end} the field \
         owns"
    );
}

#[test]
fn a_one_byte_patch_changes_exactly_one_byte_and_reports_the_stale_checksum() {
    let bytes: Vec<u8> = required_corpus("native/packers/aspack/AccessEnum.original.exe");
    let plan: ImagePlan = plan_native_image(&bytes).expect("plan a signed PE32 image");
    let target: u64 = section_payload_offset(&plan, &bytes);

    let original: u8 = bytes[target as usize];
    let patched: PatchedImage = patch_native_image(
        &bytes,
        &[FileEdit::new(target, vec![original.wrapping_add(1)])],
    )
    .expect("patch one byte of a signed PE32 image");

    assert_eq!(
        patched.bytes.len(),
        bytes.len(),
        "a one byte patch must not change the file length"
    );
    let differences: Vec<usize> = patched
        .bytes
        .iter()
        .zip(bytes.iter())
        .enumerate()
        .filter_map(|(offset, (left, right)): (usize, (&u8, &u8))| {
            (left != right).then_some(offset)
        })
        .collect();
    assert_eq!(
        differences,
        vec![target as usize],
        "a one byte patch must change exactly the patched offset"
    );
    assert_eq!(patched.report.bytes_changed, 1);
    assert_eq!(patched.report.applied.len(), 1);

    let kinds: Vec<DerivedKind> = patched
        .report
        .stale
        .iter()
        .map(|value: &disrobe_binfmt::rewrite::DerivedValue| value.kind)
        .collect();
    assert!(
        kinds.contains(&DerivedKind::PeChecksum),
        "a patched PE with a non-zero CheckSum must report it stale, got {kinds:?}"
    );
    assert!(
        kinds.contains(&DerivedKind::PeAuthenticode),
        "a patched PE with an authenticode certificate must report it stale, got {kinds:?}"
    );
}

#[test]
fn a_patched_macho_reports_its_code_signature_stale() {
    let bytes: Vec<u8> = required_corpus("mobile/macho-mac/SwiftHello.original");
    let plan: ImagePlan = plan_native_image(&bytes).expect("plan a signed Mach-O image");
    assert!(
        plan.derived_values()
            .iter()
            .any(|value: &disrobe_binfmt::rewrite::DerivedValue| value.kind
                == DerivedKind::MachCodeSignature),
        "the fixture must carry an LC_CODE_SIGNATURE for this case to grade anything"
    );

    let target: u64 = 0x2000;
    let original: u8 = bytes[target as usize];
    let patched: PatchedImage = patch_native_image(
        &bytes,
        &[FileEdit::new(target, vec![original.wrapping_add(0x11)])],
    )
    .expect("patch one byte of a signed Mach-O image");

    let kinds: Vec<DerivedKind> = patched
        .report
        .stale
        .iter()
        .map(|value: &disrobe_binfmt::rewrite::DerivedValue| value.kind)
        .collect();
    assert!(
        kinds.contains(&DerivedKind::MachCodeSignature),
        "an edit under the signed range must report the code signature stale, got {kinds:?}"
    );
}

#[test]
fn a_patched_elf_reports_its_build_identifier_stale() {
    let bytes: Vec<u8> = required_corpus("binfmt/dotnet-single-file/probe.v6.linux-x64");
    let plan: ImagePlan = plan_native_image(&bytes).expect("plan a linked ELF64 image");
    let carries_build_id: bool =
        plan.derived_values()
            .iter()
            .any(|value: &disrobe_binfmt::rewrite::DerivedValue| {
                value.kind == DerivedKind::ElfGnuBuildId
            });
    assert!(
        carries_build_id,
        "the fixture must carry a GNU build identifier note for this case to grade anything"
    );

    let target: u64 = plan.file_len() / 2;
    let original: u8 = bytes[target as usize];
    let patched: PatchedImage = patch_native_image(
        &bytes,
        &[FileEdit::new(target, vec![original.wrapping_add(3)])],
    )
    .expect("patch one byte of a linked ELF64 image");
    let kinds: Vec<DerivedKind> = patched
        .report
        .stale
        .iter()
        .map(|value: &disrobe_binfmt::rewrite::DerivedValue| value.kind)
        .collect();
    assert!(
        kinds.contains(&DerivedKind::ElfGnuBuildId),
        "an edit anywhere in the image must report the build identifier stale, got {kinds:?}"
    );
}

#[test]
fn a_patch_that_writes_the_same_bytes_reports_nothing_stale() {
    let bytes: Vec<u8> = required_corpus("native/packers/aspack/AccessEnum.original.exe");
    let plan: ImagePlan = plan_native_image(&bytes).expect("plan a signed PE32 image");
    let target: u64 = section_payload_offset(&plan, &bytes);
    let same: u8 = bytes[target as usize];

    let patched: PatchedImage = patch_native_image(&bytes, &[FileEdit::new(target, vec![same])])
        .expect("apply a no-op edit");
    assert_eq!(
        patched.bytes, bytes,
        "a no-op edit must reproduce the input"
    );
    assert_eq!(patched.report.bytes_changed, 0);
    assert!(
        patched.report.stale.is_empty(),
        "an edit that writes the byte already there invalidates nothing"
    );
}

fn section_payload_offset(plan: &ImagePlan, bytes: &[u8]) -> u64 {
    let mut cursor: u64 = 0;
    for structure in plan.structures() {
        cursor = cursor.max(structure.end());
    }
    assert!(
        cursor + 16 < bytes.len() as u64,
        "the fixture must carry payload past its typed structures"
    );
    cursor + 16
}

#[test]
fn overlapping_edits_are_refused() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.pe64.exe");
    let error: Error = patch_native_image(
        &bytes,
        &[
            FileEdit::new(600, vec![0u8; 8]),
            FileEdit::new(604, vec![0u8; 8]),
        ],
    )
    .expect_err("two edits that share a byte must be refused");
    assert!(
        matches!(error, Error::Rewrite(_)),
        "an overlapping edit must be a typed refusal, not `{error}`"
    );
}

#[test]
fn an_edit_past_the_image_is_refused() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.pe64.exe");
    let error: Error = patch_native_image(
        &bytes,
        &[FileEdit::new(bytes.len() as u64 - 1, vec![0u8; 8])],
    )
    .expect_err("an edit running past the image must be refused");
    assert!(matches!(error, Error::Rewrite(_)), "got `{error}`");
}

#[test]
fn a_declared_size_past_the_input_is_refused_without_a_large_allocation() {
    let mut bytes: Vec<u8> = required_corpus("native/formats/hello.elf64");
    let shnum_offset: usize = 60;
    bytes[shnum_offset..shnum_offset + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());

    let error: Error = plan_native_image(&bytes)
        .expect_err("a section header count past the file must be refused");
    assert!(
        matches!(error, Error::Rewrite(_) | Error::RewriteUnsupported { .. }),
        "an oversized table must be a typed refusal, not `{error}`"
    );
    let rendered: String = error.to_string();
    assert!(
        rendered.contains("section header table"),
        "the refusal must name the construct it could not model, got `{rendered}`"
    );
}

#[test]
fn a_load_command_table_past_the_input_is_refused() {
    let mut bytes: Vec<u8> = required_corpus("native/formats/hello.macho64.o");
    bytes[20..24].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());

    let error: Error =
        plan_native_image(&bytes).expect_err("a load command table past the file must be refused");
    assert!(
        matches!(error, Error::Rewrite(_) | Error::RewriteUnsupported { .. }),
        "got `{error}`"
    );
}

#[test]
fn a_non_standard_program_header_size_is_refused_by_name() {
    let mut bytes: Vec<u8> = required_corpus("native/formats/hello.elf64");
    bytes[54..56].copy_from_slice(&57u16.to_le_bytes());

    let error: Error = plan_native_image(&bytes)
        .expect_err("a program header this writer cannot model must be refused");
    let rendered: String = error.to_string();
    assert!(
        matches!(error, Error::RewriteUnsupported { .. }),
        "an unmodellable construct must be an unsupported refusal, not `{rendered}`"
    );
    assert!(
        rendered.contains("phentsize"),
        "the refusal must name the construct it could not model, got `{rendered}`"
    );
}

const BIGOBJ_CLASS_ID: [u8; 16] = [
    0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8,
];

#[test]
fn an_extended_coff_object_header_is_refused_by_name() {
    let mut bytes: Vec<u8> = required_corpus("native/formats/hello.coff.x64.o");
    bytes[0..2].copy_from_slice(&0x0000u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    bytes[12..28].copy_from_slice(&BIGOBJ_CLASS_ID);

    let error: Error =
        plan_native_image(&bytes).expect_err("the extended COFF header must be refused");
    let rendered: String = error.to_string();
    assert!(
        matches!(error, Error::RewriteUnsupported { .. }),
        "an unmodellable construct must be an unsupported refusal, not `{rendered}`"
    );
    assert!(
        rendered.contains("bigobj"),
        "the refusal must name the construct it could not model, got `{rendered}`"
    );
}

#[test]
fn a_structure_that_no_longer_fits_its_planned_span_is_refused_rather_than_emitted() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.pe64.exe");
    let mut plan: ImagePlan = plan_native_image(&bytes).expect("plan a PE32+ image");

    let mut widened: bool = false;
    for structure in plan.structures_mut() {
        if let Structure::CoffSectionTable(table) = structure.body_mut()
            && let Some(first) = table.sections.first().copied()
        {
            table.sections.push(first);
            widened = true;
        }
    }
    assert!(widened, "the fixture must carry a section table to widen");

    let error: Error = plan
        .emit(&bytes)
        .expect_err("a structure that outgrew its planned span must not be emitted");
    let rendered: String = error.to_string();
    assert!(
        matches!(error, Error::RewriteUnsupported { .. }),
        "an unreproducible plan must be an unsupported refusal, not `{rendered}`"
    );
    assert!(
        rendered.contains("coff-section-table"),
        "the refusal must name the structure that no longer fits, got `{rendered}`"
    );
}

#[test]
fn a_truncated_image_is_refused_at_every_prefix() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.elf64");
    for length in [1usize, 15, 51, 63, 100, 300] {
        let window: &[u8] = &bytes[..length.min(bytes.len())];
        let outcome: Result<ImagePlan, Error> = plan_native_image(window);
        assert!(
            outcome.is_err(),
            "a {length} byte prefix of an ELF64 image must not plan"
        );
    }
}

#[test]
fn an_empty_input_is_refused() {
    let error: Error = plan_native_image(&[]).expect_err("an empty input models no image");
    assert!(matches!(error, Error::Rewrite(_)), "got `{error}`");
}

#[test]
fn the_plan_is_reproducible_for_the_same_input() {
    for relative in [
        "native/formats/hello.pe64.exe",
        "native/formats/hello.elf64",
        "native/formats/hello.macho64.o",
        "mac/megafile/EdgeCases.fat",
    ] {
        let bytes: Vec<u8> = required_corpus(relative);
        let first: ImagePlan = plan_native_image(&bytes).expect("plan a fixture");
        let second: ImagePlan = plan_native_image(&bytes).expect("plan a fixture twice");
        assert!(first == second, "{relative}: planning must be reproducible");
        assert_eq!(
            first.emit(&bytes).expect("emit a fixture"),
            second.emit(&bytes).expect("emit a fixture twice"),
            "{relative}: re-emission must be reproducible"
        );
    }
}

#[test]
fn the_free_function_matches_the_plan_it_wraps() {
    let bytes: Vec<u8> = required_corpus("native/formats/hello.pe64.exe");
    let direct: Vec<u8> = emit_native_image(&bytes).expect("emit through the free function");
    assert_eq!(direct, bytes, "the free function must reproduce the input");
}

const MUTATION_SEEDS: u64 = 512;

#[test]
fn a_mutated_image_never_panics_and_never_re_emits_different_bytes() {
    let mut planned: usize = 0;
    let mut refused: usize = 0;

    for relative in [
        "native/formats/hello.pe64.exe",
        "native/formats/hello.elf64",
        "native/formats/avr_firmware.elf",
        "native/formats/hello.macho64.o",
        "native/formats/hello.coff.x64.o",
        "mac/megafile/EdgeCases.fat",
    ] {
        let bytes: Vec<u8> = required_corpus(relative);
        let mut rng: XorShift64 = XorShift64::new(0x4E41_5430_3239 ^ bytes.len() as u64);

        for case in 0..MUTATION_SEEDS {
            let mut mutated: Vec<u8> = bytes.clone();
            let truncate_to: usize = (rng.below(bytes.len() as u64 + 1)) as usize;
            if case % 4 == 0 {
                mutated.truncate(truncate_to);
            }
            let smears: u64 = 1 + rng.below(8);
            for _ in 0..smears {
                if mutated.is_empty() {
                    break;
                }
                let at: usize = (rng.below(mutated.len() as u64)) as usize;
                let value: u8 = (rng.next_u64() & 0xFF) as u8;
                if let Some(slot) = mutated.get_mut(at) {
                    *slot = value;
                }
            }

            match plan_native_image(&mutated) {
                Ok(plan) => {
                    planned += 1;
                    let coverage: PlanCoverage = plan.coverage();
                    assert!(
                        coverage.is_complete(),
                        "{relative} case {case}: a plan must account for every byte it admits"
                    );
                    let emitted: Vec<u8> = plan.emit(&mutated).unwrap_or_else(|error: Error| {
                        panic!("{relative} case {case}: an admitted image must re-emit: {error}")
                    });
                    assert!(
                        emitted == mutated,
                        "{relative} case {case}: an admitted image must re-emit byte for byte; \
                         first difference at {:?}",
                        first_difference(&emitted, &mutated)
                    );
                }
                Err(
                    Error::Rewrite(_) | Error::RewriteUnsupported { .. } | Error::NativeParse(_),
                ) => {
                    refused += 1;
                }
                Err(other) => {
                    panic!("{relative} case {case}: a refusal must be typed, not `{other}`")
                }
            }
        }
    }

    let total: usize = planned + refused;
    assert_eq!(
        total,
        6 * MUTATION_SEEDS as usize,
        "every mutated case must reach a typed outcome"
    );
    assert!(
        planned >= 100,
        "only {planned} of {total} mutated cases were admitted, so the round-trip half of this \
         case graded almost nothing"
    );
}
