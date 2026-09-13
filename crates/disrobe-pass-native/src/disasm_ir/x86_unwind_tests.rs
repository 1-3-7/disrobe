#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use gimli::write::{
    Address, CommonInformationEntry, EhFrame, EndianVec, FrameDescriptionEntry, FrameTable,
};
use object::write::{Object as WriteObject, SectionId, StandardSection};
use object::{Architecture, BinaryFormat, Endianness, SectionKind};

use super::*;

const CODE: &[u8] = &[0xc3, 0x90, 0x8d, 0x47, 0x02, 0xc3];

fn frame_data(ranges: &[(u64, u32)]) -> Vec<u8> {
    let mut frames: FrameTable = FrameTable::default();
    let cie: CommonInformationEntry = CommonInformationEntry::new(
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 1,
            address_size: 8,
        },
        1,
        -8,
        gimli::X86_64::RA,
    );
    let cie_id: gimli::write::CieId = frames.add_cie(cie);
    for &(address, length) in ranges {
        frames.add_fde(
            cie_id,
            FrameDescriptionEntry::new(Address::Constant(address), length),
        );
    }
    let mut frame: EhFrame<EndianVec<gimli::LittleEndian>> =
        EhFrame(EndianVec::new(gimli::LittleEndian));
    frames
        .write_eh_frame(&mut frame)
        .expect("write unwind table");
    frame.0.into_vec()
}

fn image_with_frame_data(data: &[u8]) -> Vec<u8> {
    let mut object: WriteObject<'_> =
        WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text: SectionId = object.section_id(StandardSection::Text);
    object.append_section_data(text, CODE, 1);
    let frames: SectionId =
        object.add_section(Vec::new(), b".eh_frame".to_vec(), SectionKind::ReadOnlyData);
    object.append_section_data(frames, data, 8);
    let mut image: Vec<u8> = object.write().expect("write image");
    image[16..18].copy_from_slice(&2_u16.to_le_bytes());
    image
}

fn starts(image: &[u8]) -> Vec<u64> {
    x86_unwind_starts(
        image,
        &[CodeWindow {
            address: 0,
            bytes: CODE,
        }],
    )
}

#[test]
fn linked_x86_unwind_records_recover_a_leaf_without_calls_or_a_frame_prologue() {
    let image: Vec<u8> = image_with_frame_data(&frame_data(&[(2, 4)]));
    assert_eq!(starts(&image), vec![2]);
    let payload: DisasmPayload = build_disasm_payload(&image).expect("build payload");
    assert!(payload.symbol_table.iter().any(|symbol: &DisasmSymbol| {
        symbol.address == 2 && symbol.kind == DisasmSymbolKind::Function
    }));

    let without_frames: Vec<u8> = image_with_frame_data(&[]);
    let control: DisasmPayload = build_disasm_payload(&without_frames).expect("build control");
    assert!(!control.symbol_table.iter().any(|symbol: &DisasmSymbol| {
        symbol.address == 2 && symbol.kind == DisasmSymbolKind::Function
    }));
}

#[test]
fn x86_unwind_ranges_must_fit_unique_executable_bytes() {
    for range in [(2, 0), (2, 1), (4, 4), (u64::MAX, 2)] {
        assert!(starts(&image_with_frame_data(&frame_data(&[range]))).is_empty());
    }
    let image: Vec<u8> = image_with_frame_data(&frame_data(&[(2, 4), (2, 4)]));
    assert_eq!(starts(&image), vec![2]);
    let overlapping: [CodeWindow<'_>; 2] = [
        CodeWindow {
            address: 0,
            bytes: CODE,
        },
        CodeWindow {
            address: 2,
            bytes: &CODE[2..],
        },
    ];
    assert!(x86_unwind_starts(&image, &overlapping).is_empty());
    assert!(
        x86_unwind_starts(
            &image,
            &[CodeWindow {
                address: u64::MAX,
                bytes: CODE
            }]
        )
        .is_empty()
    );
    assert!(
        x86_unwind_starts(
            &image,
            &[CodeWindow {
                address: 2,
                bytes: &[0x0f; 4]
            }]
        )
        .is_empty()
    );
}

#[test]
fn x86_unwind_records_require_a_linked_x86_64_image() {
    let mut relocatable: Vec<u8> = image_with_frame_data(&frame_data(&[(2, 4)]));
    relocatable[16..18].copy_from_slice(&1_u16.to_le_bytes());
    assert!(starts(&relocatable).is_empty());
    let mut aarch64: Vec<u8> = image_with_frame_data(&frame_data(&[(2, 4)]));
    aarch64[18..20].copy_from_slice(&183_u16.to_le_bytes());
    assert!(starts(&aarch64).is_empty());
}

#[test]
fn truncated_x86_unwind_records_never_invent_a_start() {
    let data: Vec<u8> = frame_data(&[(2, 4)]);
    for end in 0..data.len() {
        assert!(
            starts(&image_with_frame_data(&data[..end])).is_empty(),
            "end={end}"
        );
    }
}

#[test]
fn unwind_entry_budget_counts_cies_as_well_as_fdes() {
    let image: Vec<u8> = image_with_frame_data(&frame_data(&[(2, 4), (0, 1)]));
    let file: object::File<'_> = object::File::parse(image.as_slice()).expect("parse image");
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    unwind::visit_frame_ranges(&file, 0, 1, |address, length| {
        ranges.push((address, length))
    });
    assert!(ranges.is_empty());
    unwind::visit_frame_ranges(&file, 0, 2, |address, length| {
        ranges.push((address, length))
    });
    assert_eq!(ranges, vec![(2, 4)]);
}
