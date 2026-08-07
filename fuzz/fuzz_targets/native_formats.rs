#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;

use disrobe_binfmt::structural::{
    locate_zip_central_directory, validate_elf, validate_macho, validate_macho_fat, validate_pe,
    validate_zip,
};
use disrobe_binfmt::{
    ImportGraph, NativeFile, NativeImage, NativeImageSection, SectionInfo, SegmentInfo,
    import_graph_dot, locate_pe_header, parse_elf_dynamic, parse_native, parse_native_image,
};
use disrobe_fuzz::over_input_budget;

const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
const COFF_HEADER_BYTES: usize = 20;
const VA_PROBE_BYTES: usize = 16;

fn located_pe_header_is_a_real_header(data: &[u8]) {
    let Some(offset): Option<usize> = locate_pe_header(data) else {
        return;
    };
    let signature_end: Option<usize> = offset.checked_add(PE_SIGNATURE.len());
    let Some(signature_end) = signature_end else {
        panic!("locate_pe_header returned an offset whose signature range overflows usize");
    };
    assert_eq!(
        data.get(offset..signature_end),
        Some(PE_SIGNATURE.as_slice()),
        "locate_pe_header pointed at bytes that are not a PE signature"
    );
    let Some(coff_end): Option<usize> = signature_end.checked_add(COFF_HEADER_BYTES) else {
        panic!("locate_pe_header returned an offset whose COFF range overflows usize");
    };
    assert!(
        coff_end <= data.len(),
        "locate_pe_header accepted a header whose COFF fields run past the end of the input"
    );
}

fn located_zip_directory_stays_in_bounds(data: &[u8]) {
    let Some(offset): Option<usize> = locate_zip_central_directory(data) else {
        return;
    };
    assert!(
        offset < data.len(),
        "locate_zip_central_directory returned an offset at or past the end of the input"
    );
}

fn parsed_ranges_do_not_overflow(parsed: &NativeFile) {
    for section in &parsed.sections {
        let range: Option<u64> = section.address.checked_add(section.size);
        assert!(
            range.is_some(),
            "a parsed section range overflows the address space"
        );
    }
    for segment in &parsed.segments {
        let range: Option<u64> = segment.address.checked_add(segment.size);
        assert!(
            range.is_some(),
            "a parsed segment range overflows the address space"
        );
    }
}

fn drive_native_parse(data: &[u8]) {
    let Ok(parsed): disrobe_binfmt::Result<NativeFile> = parse_native(data) else {
        return;
    };
    parsed_ranges_do_not_overflow(&parsed);
    let graph: ImportGraph = ImportGraph::from_native(&parsed);
    let _ = black_box(graph.emit_dot());
    let _ = black_box(import_graph_dot(&parsed));
    let _: &[SectionInfo] = &parsed.sections;
    let _: &[SegmentInfo] = &parsed.segments;
}

fn image_resolution_stays_inside_the_input(data: &[u8]) {
    let Ok(image): disrobe_binfmt::Result<NativeImage<'_>> = parse_native_image(data) else {
        return;
    };
    let sections: &[NativeImageSection] = image.sections();
    for section in sections {
        let address: u64 = section.address;
        if let Some(offset) = image.file_offset(address) {
            assert!(
                offset < data.len() as u64,
                "file_offset resolved a section address to an offset past the end of the input"
            );
        }
        if let Some(view) = image.bytes_at(address) {
            assert!(
                view.len() as u64 <= section.size,
                "bytes_at returned more bytes than the section declares"
            );
        }
        let _ = black_box(image.section_at(address));
        let probe: u64 = address.wrapping_add(VA_PROBE_BYTES as u64);
        let _ = black_box(image.bytes_at(probe));
    }
}

fuzz_target!(|data: &[u8]| {
    if over_input_budget(data) {
        return;
    }
    let _ = black_box(validate_pe(data));
    let _ = black_box(validate_elf(data));
    let _ = black_box(validate_macho(data));
    let _ = black_box(validate_macho_fat(data));
    let _ = black_box(validate_zip(data));
    located_pe_header_is_a_real_header(data);
    located_zip_directory_stays_in_bounds(data);
    let _ = black_box(parse_elf_dynamic(data));
    drive_native_parse(data);
    image_resolution_stays_inside_the_input(data);
});
