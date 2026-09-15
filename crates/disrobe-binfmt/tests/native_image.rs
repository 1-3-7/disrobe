#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use disrobe_binfmt::native_image::{NativeImage, NativeImageSection, parse_native_image};
use disrobe_binfmt::{Arch, ElfDynamic, Endian, Error, ParsedNativeFormat, parse_elf_dynamic};

const ELF_IMAGE: &[u8] = include_bytes!("../../../corpus/native/formats/hello.elf64");
const ELF_BSS_IMAGE: &[u8] = include_bytes!("../../../corpus/native/nim/hello.nim.elf");
const SECTIONLESS_ELF_IMAGE: &[u8] =
    include_bytes!("../../../corpus/binfmt/elf-dynamic/sample.elf");
const PE_IMAGE: &[u8] = include_bytes!("../../../corpus/native/packers/upx/hello.original.exe");
const PE32_IMAGE: &[u8] = include_bytes!("../../../corpus/native/packers/kkrunchy/hello.exe");
const MACHO_IMAGE: &[u8] = include_bytes!("../../disrobe-python/tests/fixtures/SwiftHello.macho");

struct ExpectedImage {
    format: ParsedNativeFormat,
    architecture: Arch,
    address: u64,
    file_offset: usize,
    size: usize,
    section_name: &'static str,
}

fn assert_mapping(bytes: &[u8], expected: &ExpectedImage) {
    let image: NativeImage<'_> = parse_native_image(bytes).expect("real native image should parse");
    let section: &NativeImageSection = image
        .section_at(expected.address)
        .expect("mapped address should have a section");
    let mapped: &[u8] = image
        .bytes_at(expected.address)
        .expect("mapped address should have file bytes");
    let file_end: usize = expected
        .file_offset
        .checked_add(expected.size)
        .expect("expected fixture range should fit usize");
    let expected_bytes: &[u8] = bytes
        .get(expected.file_offset..file_end)
        .expect("expected fixture range should be present");
    let size_u64: u64 = u64::try_from(expected.size).expect("expected fixture size should fit u64");
    let last_address: u64 = expected
        .address
        .checked_add(size_u64)
        .and_then(|value: u64| value.checked_sub(1))
        .expect("expected fixture address should be valid");
    let last_file_offset: usize = expected
        .file_offset
        .checked_add(expected.size)
        .and_then(|value: usize| value.checked_sub(1))
        .expect("expected fixture offset should be valid");
    let final_bytes: &[u8] = image
        .bytes_at(last_address)
        .expect("last section byte should be file-backed");
    let last_file_end: usize = last_file_offset
        .checked_add(1)
        .expect("expected final fixture range should fit");
    let section_end: u64 = expected
        .address
        .checked_add(size_u64)
        .expect("expected fixture section end should fit");
    let end_owner_address: Option<u64> = image
        .section_at(section_end)
        .map(|owner: &NativeImageSection| owner.address);

    assert_eq!(image.format(), expected.format);
    assert_eq!(image.architecture(), expected.architecture);
    assert_eq!(image.bits(), 64);
    assert_eq!(image.endian(), Endian::Little);
    assert_eq!(image.pointer_size(), 8);
    assert_eq!(section.name, expected.section_name);
    assert_eq!(section.address, expected.address);
    assert_eq!(section.size, size_u64);
    assert!(section.executable);
    assert_eq!(
        image.file_offset(expected.address),
        Some(u64::try_from(expected.file_offset).expect("expected fixture offset should fit u64"))
    );
    assert_eq!(mapped, expected_bytes);
    assert_eq!(mapped.len(), expected.size);
    assert_eq!(final_bytes.len(), 1);
    assert_ne!(end_owner_address, Some(expected.address));
    assert_eq!(
        final_bytes,
        bytes
            .get(last_file_offset..last_file_end)
            .expect("expected final fixture byte should be present")
    );
}

#[test]
fn elf_translation_round_trips_and_stops_at_text_boundary() {
    let expected: ExpectedImage = ExpectedImage {
        format: ParsedNativeFormat::Elf64,
        architecture: Arch::X86_64,
        address: 0x20_117c,
        file_offset: 0x17c,
        size: 31,
        section_name: ".text",
    };

    assert_mapping(ELF_IMAGE, &expected);
}

#[test]
fn pe_translation_round_trips_and_stops_at_text_boundary() {
    let expected: ExpectedImage = ExpectedImage {
        format: ParsedNativeFormat::Pe64,
        architecture: Arch::X86_64,
        address: 0x1_4000_1000,
        file_offset: 0x400,
        size: 0x11dc8,
        section_name: ".text",
    };

    assert_mapping(PE_IMAGE, &expected);
}

#[test]
fn macho_translation_round_trips_and_stops_at_text_boundary() {
    let expected: ExpectedImage = ExpectedImage {
        format: ParsedNativeFormat::MachO64,
        architecture: Arch::Aarch64,
        address: 0x1_0000_0f68,
        file_offset: 0xf68,
        size: 0x1144,
        section_name: "__text",
    };

    assert_mapping(MACHO_IMAGE, &expected);
}

#[test]
fn unmapped_addresses_reject_all_translation() {
    let images: [&[u8]; 3] = [ELF_IMAGE, PE_IMAGE, MACHO_IMAGE];

    for bytes in images {
        let image: NativeImage<'_> =
            parse_native_image(bytes).expect("real native image should parse");

        assert!(image.section_at(0).is_none());
        assert!(image.file_offset(0).is_none());
        assert!(image.bytes_at(0).is_none());
    }
}

#[test]
fn macho_zero_fill_section_has_no_file_backing() {
    let image: NativeImage<'_> =
        parse_native_image(MACHO_IMAGE).expect("real mach-o image should parse");
    let address: u64 = 0x1_0000_85c0;
    let section: &NativeImageSection = image
        .section_at(address)
        .expect("zerofill address should have a section");

    assert_eq!(section.name, "__bss");
    assert_eq!(section.size, 0x78);
    assert!(!section.executable);
    assert!(image.file_offset(address).is_none());
    assert!(image.bytes_at(address).is_none());
}

#[test]
fn elf_nobits_section_has_no_file_backing() {
    let image: NativeImage<'_> =
        parse_native_image(ELF_BSS_IMAGE).expect("real nim elf image should parse");
    let address: u64 = 0x102_74e0;
    let section: &NativeImageSection = image
        .section_at(address)
        .expect("nobits address should have a section");

    assert_eq!(section.name, ".bss");
    assert_eq!(section.size, 72);
    assert!(!section.executable);
    assert!(image.file_offset(address).is_none());
    assert!(image.bytes_at(address).is_none());
    assert!(image.section_at(0x102_50f0).is_none());
}

#[test]
fn pe_virtual_tail_has_no_file_backing() {
    let image: NativeImage<'_> = parse_native_image(PE_IMAGE).expect("real pe image should parse");
    let section_address: u64 = 0x1_4001_a000;
    let unbacked_address: u64 = section_address
        .checked_add(0x200)
        .expect("fixture address should not overflow");
    let section: &NativeImageSection = image
        .section_at(unbacked_address)
        .expect("virtual tail should remain in the declared section");
    let backed: &[u8] = image
        .bytes_at(section_address)
        .expect("section prefix should be file-backed");

    assert_eq!(section.name, ".data");
    assert_eq!(section.size, 0x270);
    assert_eq!(backed.len(), 0x200);
    assert!(image.file_offset(unbacked_address).is_none());
    assert!(image.bytes_at(unbacked_address).is_none());
}

#[test]
fn pe32_metadata_and_pointer_width_are_preserved() {
    let image: NativeImage<'_> =
        parse_native_image(PE32_IMAGE).expect("real pe32 image should parse");
    let address: u64 = 0x40_1000;
    let section: &NativeImageSection = image
        .section_at(address)
        .expect("pe32 text address should have a section");
    let mapped: &[u8] = image
        .bytes_at(address)
        .expect("pe32 text address should be file-backed");
    let file_end: usize = 0x200usize
        .checked_add(mapped.len())
        .expect("pe32 fixture range should fit");
    let expected: &[u8] = PE32_IMAGE
        .get(0x200..file_end)
        .expect("pe32 fixture range should be present");

    assert_eq!(image.format(), ParsedNativeFormat::Pe32);
    assert_eq!(image.architecture(), Arch::X86);
    assert_eq!(image.bits(), 32);
    assert_eq!(image.pointer_size(), 4);
    assert_eq!(section.name, ".text");
    assert_eq!(section.size, 0x1000);
    assert_eq!(image.file_offset(address), Some(0x200));
    assert_eq!(mapped, expected);
    assert_eq!(mapped.len(), 0x200);
}

#[test]
fn sectionless_elf_limits_public_queries_but_preserves_dynamic_parsing() {
    let image: NativeImage<'_> =
        parse_native_image(SECTIONLESS_ELF_IMAGE).expect("sectionless elf should parse");
    let string_table_address: u64 = 0x10b0;
    let dynamic: ElfDynamic =
        parse_elf_dynamic(SECTIONLESS_ELF_IMAGE).expect("dynamic segment should parse");

    assert!(image.sections().is_empty());
    assert!(image.section_at(string_table_address).is_none());
    assert!(image.file_offset(string_table_address).is_none());
    assert!(image.bytes_at(string_table_address).is_none());
    assert_eq!(
        dynamic.needed,
        vec!["libc.so.6".to_owned(), "libm.so.6".to_owned()]
    );
}

#[test]
fn truncated_real_images_are_rejected_without_panicking() {
    let elf_end: usize = ELF_IMAGE
        .len()
        .checked_sub(1)
        .expect("elf fixture should be nonempty");
    let pe_end: usize = PE_IMAGE
        .len()
        .checked_sub(1)
        .expect("pe fixture should be nonempty");
    let macho_end: usize = MACHO_IMAGE
        .len()
        .checked_sub(1)
        .expect("mach-o fixture should be nonempty");
    let elf: &[u8] = ELF_IMAGE
        .get(..elf_end)
        .expect("truncated elf range should exist");
    let pe: &[u8] = PE_IMAGE
        .get(..pe_end)
        .expect("truncated pe range should exist");
    let macho: &[u8] = MACHO_IMAGE
        .get(..macho_end)
        .expect("truncated mach-o range should exist");
    let truncated: [&[u8]; 3] = [elf, pe, macho];

    for bytes in truncated {
        assert!(matches!(
            parse_native_image(bytes),
            Err(Error::NativeParse(_))
        ));
    }
}

#[test]
fn overlapping_declared_sections_are_rejected() {
    let mut bytes: Vec<u8> = PE_IMAGE.to_vec();
    let pe_offset_u32: u32 =
        disrobe_bytes::read_u32_le_at(&bytes, 0x3c).expect("pe header offset should parse");
    let pe_offset: usize =
        usize::try_from(pe_offset_u32).expect("pe header offset should fit usize");
    let coff_offset: usize = pe_offset
        .checked_add(4)
        .expect("coff header offset should fit usize");
    let optional_size_offset: usize = coff_offset
        .checked_add(16)
        .expect("optional size offset should fit usize");
    let optional_size: u16 = disrobe_bytes::read_u16_le_at(&bytes, optional_size_offset)
        .expect("optional header size should parse");
    let section_table: usize = coff_offset
        .checked_add(20)
        .and_then(|value: usize| value.checked_add(usize::from(optional_size)))
        .expect("section table offset should fit usize");
    let first_virtual_address_offset: usize = section_table
        .checked_add(12)
        .expect("first section virtual address offset should fit");
    let second_virtual_address_offset: usize = section_table
        .checked_add(40)
        .and_then(|value: usize| value.checked_add(12))
        .expect("second section virtual address offset should fit");
    let first_virtual_address_end: usize = first_virtual_address_offset
        .checked_add(4)
        .expect("first section virtual address end should fit");
    let second_virtual_address_end: usize = second_virtual_address_offset
        .checked_add(4)
        .expect("second section virtual address end should fit");
    let first_virtual_address: [u8; 4] = bytes
        .get(first_virtual_address_offset..first_virtual_address_end)
        .expect("first section virtual address should be present")
        .try_into()
        .expect("virtual address should have four bytes");
    let second_virtual_address: &mut [u8] = bytes
        .get_mut(second_virtual_address_offset..second_virtual_address_end)
        .expect("second section virtual address should be present");

    second_virtual_address.copy_from_slice(&first_virtual_address);

    let error: Error =
        parse_native_image(&bytes).expect_err("overlapping sections should be rejected");
    let reason: Option<String> = match error {
        Error::NativeParse(value) => Some(value),
        _ => None,
    };

    assert!(
        reason
            .as_deref()
            .is_some_and(|value: &str| value.contains("overlap"))
    );
}
