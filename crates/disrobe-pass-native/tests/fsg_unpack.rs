#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod packer_fixture;

use disrobe_pass_native::error::Error;
use disrobe_pass_native::packers::pe_sections::{DataDirectory, PeImage, PeSection};
use disrobe_pass_native::packers::{FsgImport, FsgUnpackOutput, parse_pe_image, unpack_fsg};
use packer_fixture::{PackerFixture, load_fixture};

fn read_corpus(name: &str) -> Option<Vec<u8>> {
    load_fixture(PackerFixture {
        decoder: "FSG",
        family: "fsg",
        name,
    })
}

fn expect_fsg_anchors(out: &FsgUnpackOutput) {
    assert!(
        out.image_base == 0x0040_0000 || out.image_base == 0x0100_0000,
        "unexpected ImageBase 0x{:08X}",
        out.image_base
    );
    assert!(
        out.unpack_dest_va >= out.image_base,
        "unpack_dest_va must be inside image"
    );
    assert!(
        out.packed_stream_va >= out.image_base,
        "packed stream VA must be inside image"
    );
    assert!(
        out.import_meta_va >= out.image_base,
        "import-meta VA must be inside image"
    );
    assert!(
        !out.raw_image.is_empty(),
        "decompressed image must be non-empty"
    );
    assert!(
        out.raw_image.len() >= 0x1000,
        "decompressed image must be at least one page (got {} bytes)",
        out.raw_image.len()
    );
}

#[test]
fn test_fsg_aatools_setup_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_hash_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("Hash.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_ftp_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("ftp.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_rejects_non_fsg_pe() {
    let mut bytes: Vec<u8> = vec![0u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&0xC0u32.to_le_bytes());
    bytes[0xC0..0xC4].copy_from_slice(b"PE\0\0");
    bytes[0xC4..0xC6].copy_from_slice(&0x014Cu16.to_le_bytes());
    bytes[0xC6..0xC8].copy_from_slice(&1u16.to_le_bytes());
    bytes[0xD8..0xDA].copy_from_slice(&0xE0u16.to_le_bytes());
    bytes[0xDC..0xDE].copy_from_slice(&0x010Bu16.to_le_bytes());
    let r: Result<FsgUnpackOutput, Error> = unpack_fsg(&bytes);
    assert!(r.is_err(), "non-FSG PE must not unpack");
}

#[test]
fn test_fsg_unpacked_pe_runs_structural_check() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
    let starts_with_code: bool = out.raw_image.first().is_some_and(|&b: &u8| b != 0x00);
    assert!(
        starts_with_code,
        "first byte of unpacked image should not be NUL (would indicate bss-only output)"
    );
}

#[test]
fn test_fsg_synthetic_truncated_stream_errors_cleanly() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        return;
    };
    let truncated: Vec<u8> = packed[..0x250].to_vec();
    let r: Result<FsgUnpackOutput, Error> = unpack_fsg(&truncated);
    assert!(r.is_err(), "truncated stream must error, not panic or hang");
}

const STUB_MOV_EBX_IMM32: u8 = 0xBB;
const IMPORT_META_VA_SLOT: usize = 1;
const FSG_TABLE_END: u32 = 0x0002;

const fn section_named(name: [u8; 8], virtual_size: u32, virtual_address: u32) -> PeSection {
    PeSection {
        name,
        virtual_size,
        virtual_address,
        raw_size: 0,
        raw_pointer: 0,
        pointer_to_relocations: 0,
        characteristics: 0,
    }
}

const fn image_of(sections: Vec<PeSection>, size_of_headers: u32) -> PeImage {
    PeImage {
        pe_header_offset: 0x80,
        machine: 0x014C,
        size_of_optional_header: 0xE0,
        coff_characteristics: 0x0102,
        is_pe32_plus: false,
        entry_point_rva: 0x1000,
        image_base: 0x0040_0000,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: 0x2_0000,
        size_of_headers,
        data_directories: Vec::<DataDirectory>::new(),
        raw_data_directories: Vec::<DataDirectory>::new(),
        sections,
    }
}

fn import_meta_file_offset(packed: &[u8]) -> usize {
    let image: PeImage = parse_pe_image(packed).expect("the committed FSG sample parses as a PE");
    let stub_off: usize = image
        .file_offset_for_rva(image.entry_point_rva, packed.len())
        .expect("the entry-point stub is file backed");
    assert_eq!(
        packed[stub_off], STUB_MOV_EBX_IMM32,
        "the FSG 2.0 stub starts with mov ebx, imm32; the fixture layout moved",
    );
    let mut raw: [u8; 4] = [0u8; 4];
    raw.copy_from_slice(
        &packed[stub_off + IMPORT_META_VA_SLOT..stub_off + IMPORT_META_VA_SLOT + 4],
    );
    let import_meta_va: u32 = u32::from_le_bytes(raw);
    let rva: u32 = import_meta_va - u32::try_from(image.image_base).expect("32-bit image base");
    image
        .file_offset_for_rva(rva, packed.len())
        .expect("the FSG import metadata is file backed")
}

fn zero_raw_size_section(packed: &[u8]) -> PeSection {
    let image: PeImage = parse_pe_image(packed).expect("the committed FSG sample parses as a PE");
    image
        .sections
        .iter()
        .find(|section: &&PeSection| section.raw_size == 0 && section.virtual_size > 0)
        .cloned()
        .expect("the committed FSG sample declares a zero-raw-size section")
}

#[test]
fn a_name_rva_in_a_zero_raw_size_section_is_refused_rather_than_read_past_the_file() {
    let Some(packed): Option<Vec<u8>> = read_corpus("Hash.packed.fsg.exe") else {
        return;
    };
    let blank: PeSection = zero_raw_size_section(&packed);
    let hostile_rva: u32 = blank.virtual_address + 0xF002;
    assert!(
        hostile_rva - blank.virtual_address < blank.virtual_size,
        "the hostile RVA must sit inside the blank section's virtual span",
    );
    assert!(
        (hostile_rva - blank.virtual_address) as usize + blank.raw_pointer as usize > packed.len(),
        "the hostile RVA must translate past the end of the file under the old raw-size guard",
    );

    let meta_off: usize = import_meta_file_offset(&packed);
    let mut hostile: Vec<u8> = packed;
    let name_va: u32 = 0x0040_0000 + hostile_rva;
    assert_eq!(
        name_va & 0xFFFF,
        FSG_TABLE_END,
        "the planted name VA must alias to the FSG block-table end marker so the depack still runs",
    );
    hostile[meta_off..meta_off + 4].copy_from_slice(&name_va.to_le_bytes());

    let out: FsgUnpackOutput =
        unpack_fsg(&hostile).expect("a hostile import name must not stop the depack");
    assert!(
        out.iat_entries.is_empty(),
        "an import name that lands in a section with no file bytes must yield no import, got {:?}",
        out.iat_entries,
    );
    assert!(
        !out.raw_image.is_empty(),
        "the depacked image must still be produced",
    );
}

#[test]
fn a_name_rva_that_is_file_backed_still_reads_the_name_through_the_same_guard() {
    let Some(packed): Option<Vec<u8>> = read_corpus("Hash.packed.fsg.exe") else {
        return;
    };
    let meta_off: usize = import_meta_file_offset(&packed);
    let name_off: usize = 2;
    let planted: &[u8] = b"USER32.dll\0";

    let mut sample: Vec<u8> = packed;
    sample[name_off..name_off + planted.len()].copy_from_slice(planted);
    let name_va: u32 = 0x0040_0000 + u32::try_from(name_off).expect("header offset fits an RVA");
    assert_eq!(
        name_va & 0xFFFF,
        FSG_TABLE_END,
        "the planted name VA must alias to the FSG block-table end marker",
    );
    sample[meta_off..meta_off + 4].copy_from_slice(&name_va.to_le_bytes());

    let out: FsgUnpackOutput = unpack_fsg(&sample).expect("a file-backed import name must unpack");
    assert!(
        out.iat_entries
            .iter()
            .any(|entry: &FsgImport| entry.dll_name == "USER32.dll"),
        "the import walker must still read a name the guard admits, got {:?}",
        out.iat_entries,
    );
}

#[test]
fn a_block_destination_page_below_the_table_bias_is_refused_rather_than_wrapping() {
    let Some(packed): Option<Vec<u8>> = read_corpus("Hash.packed.fsg.exe") else {
        return;
    };
    let table_off: usize = import_meta_file_offset(&packed);
    let mut hostile: Vec<u8> = packed;
    hostile[table_off..table_off + 2].copy_from_slice(&0u16.to_le_bytes());

    let r: Result<FsgUnpackOutput, Error> = unpack_fsg(&hostile);

    let refused: Error = r.expect_err("a page index below the bias must be refused");
    assert!(
        refused.to_string().contains("DR-NATIVE-"),
        "the refusal must carry an error code, got {refused}",
    );
}

#[test]
fn every_declared_section_layout_translates_or_is_refused_and_none_reads_past_the_file() {
    let file_len: usize = 0x1000;

    let blank_tail: PeImage = image_of(
        vec![PeSection {
            raw_size: 0,
            raw_pointer: 0x200,
            ..section_named(*b".bss\0\0\0\0", 0x8000, 0x1000)
        }],
        0x200,
    );
    assert!(
        blank_tail.file_offset_for_rva(0x1000, file_len).is_err(),
        "a section with a zero raw size holds no file bytes at any offset",
    );
    assert!(blank_tail.file_offset_for_rva(0x7FFF, file_len).is_err());

    let no_virtual_size: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x400,
            raw_pointer: 0x200,
            ..section_named(*b".text\0\0\0", 0, 0x1000)
        }],
        0x200,
    );
    assert_eq!(
        no_virtual_size.file_offset_for_rva(0x1010, file_len).ok(),
        Some(0x210),
        "a zero virtual size still maps across the raw span",
    );

    let both_zero: PeImage = image_of(vec![section_named(*b".null\0\0\0", 0, 0x1000)], 0x200);
    assert!(both_zero.file_offset_for_rva(0x1000, file_len).is_err());

    let raw_over_virtual: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x600,
            raw_pointer: 0x200,
            ..section_named(*b".text\0\0\0", 0x100, 0x1000)
        }],
        0x200,
    );
    assert_eq!(
        raw_over_virtual.file_offset_for_rva(0x1500, file_len).ok(),
        Some(0x700),
    );

    let virtual_over_file: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x200,
            raw_pointer: 0x200,
            ..section_named(*b".data\0\0\0", 0x40_0000, 0x1000)
        }],
        0x200,
    );
    assert_eq!(
        virtual_over_file.file_offset_for_rva(0x1100, file_len).ok(),
        Some(0x300),
    );
    assert!(
        virtual_over_file
            .file_offset_for_rva(0x1200, file_len)
            .is_err(),
        "an RVA past the raw span of a huge virtual section has no file bytes",
    );

    let pointer_past_eof: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x200,
            raw_pointer: 0x10_0000,
            ..section_named(*b".far\0\0\0\0", 0x200, 0x1000)
        }],
        0x200,
    );
    assert!(
        pointer_past_eof
            .file_offset_for_rva(0x1000, file_len)
            .is_err()
    );

    let wrapping: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x100,
            raw_pointer: 0xFFFF_FFF0,
            ..section_named(*b".wrap\0\0\0", 0x100, 0x1000)
        }],
        0x200,
    );
    let wrapped: u32 = 0xFFFF_FFF0u32.wrapping_add(0x50);
    assert_eq!(wrapped, 0x40, "the wrap this case exercises");
    assert!(
        wrapping.file_offset_for_rva(0x1050, file_len).is_err(),
        "a raw pointer plus delta that wraps u32 must be refused, never folded to {wrapped:#x}",
    );

    let overlapping: PeImage = image_of(
        vec![
            PeSection {
                raw_size: 0x200,
                raw_pointer: 0x200,
                ..section_named(*b".first\0\0", 0x2000, 0x1000)
            },
            PeSection {
                raw_size: 0x200,
                raw_pointer: 0x600,
                ..section_named(*b".second\0", 0x2000, 0x1800)
            },
        ],
        0x200,
    );
    assert_eq!(
        overlapping.file_offset_for_rva(0x1900, file_len).ok(),
        None,
        "the first section wins and its raw span ends before the overlap",
    );
    assert_eq!(
        overlapping.file_offset_for_rva(0x1100, file_len).ok(),
        Some(0x300),
    );

    let unordered: PeImage = image_of(
        vec![
            PeSection {
                raw_size: 0x200,
                raw_pointer: 0x600,
                ..section_named(*b".high\0\0\0", 0x1000, 0x8000)
            },
            PeSection {
                raw_size: 0x200,
                raw_pointer: 0x200,
                ..section_named(*b".low\0\0\0\0", 0x1000, 0x1000)
            },
        ],
        0x200,
    );
    assert_eq!(
        unordered.file_offset_for_rva(0x8010, file_len).ok(),
        Some(0x610)
    );
    assert_eq!(
        unordered.file_offset_for_rva(0x1010, file_len).ok(),
        Some(0x210)
    );

    let zero_va: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x200,
            raw_pointer: 0x400,
            ..section_named(*b".at0\0\0\0\0", 0x200, 0)
        }],
        0x200,
    );
    assert_eq!(zero_va.file_offset_for_rva(0, file_len).ok(), Some(0x400));

    let no_sections: PeImage = image_of(Vec::<PeSection>::new(), 0x200);
    assert_eq!(
        no_sections.file_offset_for_rva(0x1F0, file_len).ok(),
        Some(0x1F0)
    );
    assert!(no_sections.file_offset_for_rva(0x200, file_len).is_err());
    assert!(no_sections.file_offset_for_rva(u32::MAX, file_len).is_err());

    let gap: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x200,
            raw_pointer: 0x200,
            ..section_named(*b".text\0\0\0", 0x200, 0x1000)
        }],
        0x200,
    );
    assert!(
        gap.file_offset_for_rva(0x800, file_len).is_err(),
        "the gap between the headers and the first section is mapped by nothing",
    );

    let headers_past_eof: PeImage = image_of(Vec::<PeSection>::new(), 0x8000);
    assert_eq!(
        headers_past_eof.file_offset_for_rva(0xFFF, file_len).ok(),
        Some(0xFFF),
    );
    assert!(
        headers_past_eof
            .file_offset_for_rva(0x1000, file_len)
            .is_err(),
        "a size-of-headers larger than the file must not admit an offset past the file",
    );

    let unaligned_headers: PeImage = image_of(Vec::<PeSection>::new(), 0x1D5);
    assert_eq!(
        unaligned_headers.file_offset_for_rva(0x1D4, file_len).ok(),
        Some(0x1D4),
    );
    assert!(
        unaligned_headers
            .file_offset_for_rva(0x1D5, file_len)
            .is_err()
    );

    let empty_file: PeImage = image_of(
        vec![PeSection {
            raw_size: 0x200,
            raw_pointer: 0,
            ..section_named(*b".text\0\0\0", 0x200, 0x1000)
        }],
        0x200,
    );
    assert!(empty_file.file_offset_for_rva(0x1000, 0).is_err());
    assert!(empty_file.file_offset_for_rva(0, 0).is_err());
}
