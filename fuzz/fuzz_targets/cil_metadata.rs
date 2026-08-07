#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;

use disrobe_fuzz::over_input_budget;
use disrobe_nir_lift::lift_dotnet_pe as lift_pe;
use disrobe_pass_dotnet::cil::{Instruction, disassemble, parse_method_body};
use disrobe_pass_dotnet::metadata::{
    MetadataRoot, StreamHeader, decompress_uint, metadata_slice, metadata_stream_extent,
    parse_metadata_root, parse_table_stream, read_strings_heap, read_us_heap_strings,
};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse as parse_pe, parse_clr_header};

fn compressed_integers_consume_what_they_report(data: &[u8]) {
    let Some((_value, width)): Option<(u32, usize)> = decompress_uint(data) else {
        return;
    };
    assert!(
        width > 0 && width <= data.len(),
        "a compressed integer reported a width the input cannot hold"
    );
}

fn drive_method_bodies(data: &[u8]) {
    let _ = black_box(disassemble(data));
    let Ok(body): disrobe_pass_dotnet::Result<disrobe_pass_dotnet::cil::MethodBody> =
        parse_method_body(data)
    else {
        return;
    };
    let instructions: &[Instruction] = &body.instructions;
    for instruction in instructions {
        assert!(
            (instruction.offset as usize) <= data.len(),
            "a decoded method-body instruction sits past the end of the input"
        );
    }
}

fn drive_metadata_chain(data: &[u8]) {
    let Ok(image): disrobe_pass_dotnet::Result<PeImage> = parse_pe(data) else {
        return;
    };
    let Ok(clr): disrobe_pass_dotnet::Result<ClrHeader> = parse_clr_header(data, &image) else {
        return;
    };
    let Ok(root): disrobe_pass_dotnet::Result<MetadataRoot> =
        parse_metadata_root(data, &image, &clr)
    else {
        return;
    };
    let _ = black_box(metadata_stream_extent(&root));
    let Ok(metadata): disrobe_pass_dotnet::Result<&[u8]> =
        metadata_slice(data, &image, &clr, &root)
    else {
        return;
    };
    for header in root.streams.values() {
        let stream: StreamHeader = *header;
        let _ = black_box(parse_table_stream(metadata, stream));
        let _ = black_box(read_strings_heap(metadata, stream));
        let _ = black_box(read_us_heap_strings(metadata, stream));
    }
}

fuzz_target!(|data: &[u8]| {
    if over_input_budget(data) {
        return;
    }
    compressed_integers_consume_what_they_report(data);
    drive_method_bodies(data);
    drive_metadata_chain(data);
    let _ = black_box(lift_pe(data));
});
