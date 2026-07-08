#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use object::{Object as _, ObjectSection as _};

use super::{
    AbsentReason, CarvedModule, MINIDUMP_SIGNATURE, MINIDUMP_VERSION, MinidumpFile,
    STREAM_MEMORY64_LIST, STREAM_MODULE_LIST, STREAM_SYSTEM_INFO, carve_module, detect_minidump,
    minidump_extent, parse_minidump,
};

const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
const SIZE_OF_IMAGE: u32 = 0x3000;
const TEXT_VA: u32 = 0x1000;
const RDATA_VA: u32 = 0x2000;

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn build_mapped_pe64(text: &[u8], rdata: &[u8]) -> Vec<u8> {
    let mut image: Vec<u8> = vec![0u8; SIZE_OF_IMAGE as usize];
    image[0] = b'M';
    image[1] = b'Z';
    let pe_off: usize = 0x80;
    image[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    image[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");

    let coff: usize = pe_off + 4;
    image[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&0x00F0u16.to_le_bytes());
    image[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let opt: usize = coff + 20;
    image[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    image[opt + 16..opt + 20].copy_from_slice(&TEXT_VA.to_le_bytes());
    image[opt + 20..opt + 24].copy_from_slice(&TEXT_VA.to_le_bytes());
    image[opt + 24..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    image[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
    image[opt + 48..opt + 50].copy_from_slice(&6u16.to_le_bytes());
    image[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
    image[opt + 60..opt + 64].copy_from_slice(&0x0400u32.to_le_bytes());
    image[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    image[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    let sec_table: usize = opt + 0xF0;
    write_section(
        &mut image,
        sec_table,
        b".text",
        text.len() as u32,
        TEXT_VA,
        align_up(text.len(), 0x200) as u32,
        0x0400,
        0x6000_0020,
    );
    write_section(
        &mut image,
        sec_table + 40,
        b".rdata",
        rdata.len() as u32,
        RDATA_VA,
        align_up(rdata.len(), 0x200) as u32,
        0x0600,
        0x4000_0040,
    );

    image[TEXT_VA as usize..TEXT_VA as usize + text.len()].copy_from_slice(text);
    image[RDATA_VA as usize..RDATA_VA as usize + rdata.len()].copy_from_slice(rdata);
    image
}

#[allow(clippy::too_many_arguments)]
fn write_section(
    image: &mut [u8],
    at: usize,
    name: &[u8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw: u32,
    pointer_to_raw: u32,
    characteristics: u32,
) {
    image[at..at + name.len()].copy_from_slice(name);
    image[at + 8..at + 12].copy_from_slice(&virtual_size.to_le_bytes());
    image[at + 12..at + 16].copy_from_slice(&virtual_address.to_le_bytes());
    image[at + 16..at + 20].copy_from_slice(&size_of_raw.to_le_bytes());
    image[at + 20..at + 24].copy_from_slice(&pointer_to_raw.to_le_bytes());
    image[at + 36..at + 40].copy_from_slice(&characteristics.to_le_bytes());
}

fn minidump_string(name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&((units.len() * 2) as u32).to_le_bytes());
    for unit in &units {
        blob.extend_from_slice(&unit.to_le_bytes());
    }
    blob.extend_from_slice(&[0u8, 0u8]);
    blob
}

fn put_dir(buf: &mut [u8], at: usize, stream_type: u32, data_size: u32, rva: u32) {
    buf[at..at + 4].copy_from_slice(&stream_type.to_le_bytes());
    buf[at + 4..at + 8].copy_from_slice(&data_size.to_le_bytes());
    buf[at + 8..at + 12].copy_from_slice(&rva.to_le_bytes());
}

fn build_dump(
    module_name: &str,
    arch: u16,
    size_of_image: u32,
    regions: &[(u64, u64, Vec<u8>)],
) -> Vec<u8> {
    let mut sysinfo: Vec<u8> = vec![0u8; 56];
    sysinfo[0..2].copy_from_slice(&arch.to_le_bytes());
    let name_blob: Vec<u8> = minidump_string(module_name);

    let n_streams: u32 = 3;
    let dir_rva: u32 = super::HEADER_LEN as u32;
    let dir_len: u32 = n_streams * super::DIRECTORY_ENTRY_LEN as u32;
    let mut cursor: u32 = dir_rva + dir_len;

    let sysinfo_rva: u32 = cursor;
    cursor += sysinfo.len() as u32;
    let name_rva: u32 = cursor;
    cursor += name_blob.len() as u32;
    let module_list_rva: u32 = cursor;
    let module_list_len: u32 = 4 + super::MODULE_ENTRY_LEN as u32;
    cursor += module_list_len;
    let mem64_rva: u32 = cursor;
    let mem64_len: u32 = super::MEMORY64_LIST_HEADER_LEN as u32
        + super::MEMORY_DESCRIPTOR64_LEN as u32 * regions.len() as u32;
    cursor += mem64_len;
    let base_rva: u32 = cursor;

    let mut mem_data: Vec<u8> = Vec::new();
    for (_, _, bytes) in regions {
        mem_data.extend_from_slice(bytes);
    }

    let mut module: Vec<u8> = vec![0u8; super::MODULE_ENTRY_LEN];
    module[0..8].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    module[8..12].copy_from_slice(&size_of_image.to_le_bytes());
    module[20..24].copy_from_slice(&name_rva.to_le_bytes());

    let mut module_list: Vec<u8> = Vec::new();
    module_list.extend_from_slice(&1u32.to_le_bytes());
    module_list.extend_from_slice(&module);

    let mut mem64: Vec<u8> = Vec::new();
    mem64.extend_from_slice(&(regions.len() as u64).to_le_bytes());
    mem64.extend_from_slice(&u64::from(base_rva).to_le_bytes());
    for (start_va, declared, _) in regions {
        mem64.extend_from_slice(&start_va.to_le_bytes());
        mem64.extend_from_slice(&declared.to_le_bytes());
    }

    let total: usize = base_rva as usize + mem_data.len();
    let mut buf: Vec<u8> = vec![0u8; total];
    buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
    buf[4..8].copy_from_slice(&u32::from(MINIDUMP_VERSION).to_le_bytes());
    buf[8..12].copy_from_slice(&n_streams.to_le_bytes());
    buf[12..16].copy_from_slice(&dir_rva.to_le_bytes());

    let dir: usize = dir_rva as usize;
    put_dir(
        &mut buf,
        dir,
        STREAM_SYSTEM_INFO,
        sysinfo.len() as u32,
        sysinfo_rva,
    );
    put_dir(
        &mut buf,
        dir + 12,
        STREAM_MODULE_LIST,
        module_list.len() as u32,
        module_list_rva,
    );
    put_dir(
        &mut buf,
        dir + 24,
        STREAM_MEMORY64_LIST,
        mem64.len() as u32,
        mem64_rva,
    );

    buf[sysinfo_rva as usize..sysinfo_rva as usize + sysinfo.len()].copy_from_slice(&sysinfo);
    buf[name_rva as usize..name_rva as usize + name_blob.len()].copy_from_slice(&name_blob);
    buf[module_list_rva as usize..module_list_rva as usize + module_list.len()]
        .copy_from_slice(&module_list);
    buf[mem64_rva as usize..mem64_rva as usize + mem64.len()].copy_from_slice(&mem64);
    buf[base_rva as usize..base_rva as usize + mem_data.len()].copy_from_slice(&mem_data);
    buf
}

fn text_fixture() -> Vec<u8> {
    (0..0x400u32)
        .map(|i: u32| (i.wrapping_mul(31) & 0xFF) as u8)
        .collect()
}

fn rdata_fixture() -> Vec<u8> {
    b"disrobe minidump carve read-only data fixture".to_vec()
}

#[test]
fn detects_minidump_signature_and_rejects_others() {
    let text: Vec<u8> = text_fixture();
    let rdata: Vec<u8> = rdata_fixture();
    let image: Vec<u8> = build_mapped_pe64(&text, &rdata);
    let dump: Vec<u8> = build_dump("test.dll", 9, SIZE_OF_IMAGE, &[(IMAGE_BASE, 0x3000, image)]);
    assert!(detect_minidump(&dump));
    assert!(!detect_minidump(b"MZ\x90\x00 not a dump"));
    assert!(!detect_minidump(&[]));
    assert!(!detect_minidump(b"MDMPxxxx"));
}

#[test]
fn full_dump_carves_text_section_byte_identical() {
    let text: Vec<u8> = text_fixture();
    let rdata: Vec<u8> = rdata_fixture();
    let image: Vec<u8> = build_mapped_pe64(&text, &rdata);
    let dump: Vec<u8> = build_dump(
        "kernel32.dll",
        9,
        SIZE_OF_IMAGE,
        &[(IMAGE_BASE, 0x3000, image)],
    );

    let file: MinidumpFile = parse_minidump(&dump).expect("parse");
    assert_eq!(file.modules.len(), 1);
    assert_eq!(file.modules[0].base_of_image, IMAGE_BASE);
    assert_eq!(file.modules[0].name, "kernel32.dll");

    let carved: CarvedModule =
        carve_module(&file, &dump, &file.modules[0], 1 << 30).expect("carve");
    assert!(carved.coverage.complete, "coverage should be complete");
    assert!(carved.coverage.headers_present);
    assert!(carved.absent_ranges.is_empty());
    assert!((carved.coverage.coverage_ratio - 1.0).abs() < f64::EPSILON);

    let text_off: usize = TEXT_VA as usize;
    assert_eq!(
        &carved.image[text_off..text_off + text.len()],
        &text[..],
        ".text bytes must match the original on-disk section"
    );

    let report = carved.pe_emit.as_ref().expect("pe emit report");
    assert!(report.is_pe32_plus);
    assert!(
        report.structurally_valid,
        "object must validate the emitted PE"
    );
    assert_eq!(report.image_base_written, IMAGE_BASE);
    assert!(report.sections_rewritten >= 2);
}

#[test]
fn emitted_image_is_memory_aligned_and_object_reads_sections() {
    let text: Vec<u8> = text_fixture();
    let rdata: Vec<u8> = rdata_fixture();
    let image: Vec<u8> = build_mapped_pe64(&text, &rdata);
    let dump: Vec<u8> = build_dump("mod.dll", 9, SIZE_OF_IMAGE, &[(IMAGE_BASE, 0x3000, image)]);
    let file: MinidumpFile = parse_minidump(&dump).expect("parse");
    let carved: CarvedModule =
        carve_module(&file, &dump, &file.modules[0], 1 << 30).expect("carve");

    let parsed: object::read::File<'_> =
        object::read::File::parse(&carved.image[..]).expect("object parse emitted image");
    assert!(matches!(parsed.format(), object::BinaryFormat::Pe));
    let mut saw_text: bool = false;
    for section in parsed.sections() {
        if section.name().unwrap_or_default() == ".text" {
            saw_text = true;
            assert_eq!(section.data().expect("text data"), &text[..]);
            assert_eq!(section.address(), IMAGE_BASE + u64::from(TEXT_VA));
        }
    }
    assert!(
        saw_text,
        "object must resolve the .text section after rewrite"
    );

    let pe_off: usize = 0x80;
    let sec_table: usize = pe_off + 4 + 20 + 0xF0;
    let text_ptr_raw: u32 = u32::from_le_bytes(
        carved.image[sec_table + 20..sec_table + 24]
            .try_into()
            .expect("ptr slice"),
    );
    assert_eq!(
        text_ptr_raw, TEXT_VA,
        "PointerToRawData must be rewritten to VirtualAddress"
    );
}

#[test]
fn truncated_descriptor_is_reported_distinctly() {
    let text: Vec<u8> = text_fixture();
    let rdata: Vec<u8> = rdata_fixture();
    let image: Vec<u8> = build_mapped_pe64(&text, &rdata);
    let present: Vec<u8> = image[..0x2000].to_vec();
    let dump: Vec<u8> = build_dump(
        "trunc.dll",
        9,
        SIZE_OF_IMAGE,
        &[(IMAGE_BASE, 0x3000, present)],
    );
    let file: MinidumpFile = parse_minidump(&dump).expect("parse");
    let carved: CarvedModule =
        carve_module(&file, &dump, &file.modules[0], 1 << 30).expect("carve");

    assert!(!carved.coverage.complete);
    assert!(carved.coverage.headers_present);
    assert_eq!(carved.coverage.truncated_bytes, 0x1000);
    assert!(
        carved
            .absent_ranges
            .iter()
            .any(|r| r.reason == AbsentReason::TruncatedDescriptor
                && r.start_va == IMAGE_BASE + 0x2000
                && r.end_va == IMAGE_BASE + 0x3000)
    );
    let text_off: usize = TEXT_VA as usize;
    assert_eq!(&carved.image[text_off..text_off + text.len()], &text[..]);
}

#[test]
fn absent_headers_page_disables_reconstruction() {
    let text: Vec<u8> = text_fixture();
    let rdata: Vec<u8> = rdata_fixture();
    let image: Vec<u8> = build_mapped_pe64(&text, &rdata);
    let present: Vec<u8> = image[0x1000..0x3000].to_vec();
    let dump: Vec<u8> = build_dump(
        "paged.dll",
        9,
        SIZE_OF_IMAGE,
        &[(IMAGE_BASE + 0x1000, 0x2000, present)],
    );
    let file: MinidumpFile = parse_minidump(&dump).expect("parse");
    let carved: CarvedModule =
        carve_module(&file, &dump, &file.modules[0], 1 << 30).expect("carve");

    assert!(!carved.coverage.headers_present);
    assert!(carved.pe_emit.is_none());
    assert!(
        carved
            .absent_ranges
            .iter()
            .any(|r| r.reason == AbsentReason::NotPresentInDump
                && r.start_va == IMAGE_BASE
                && r.end_va == IMAGE_BASE + 0x1000)
    );
}

#[test]
fn extent_matches_end_of_memory_data() {
    let text: Vec<u8> = text_fixture();
    let rdata: Vec<u8> = rdata_fixture();
    let image: Vec<u8> = build_mapped_pe64(&text, &rdata);
    let dump: Vec<u8> = build_dump("ext.dll", 9, SIZE_OF_IMAGE, &[(IMAGE_BASE, 0x3000, image)]);
    let extent: usize = minidump_extent(&dump).expect("extent");
    assert_eq!(extent, dump.len());

    let mut padded: Vec<u8> = dump.clone();
    padded.extend(std::iter::repeat_n(0u8, 4096));
    assert_eq!(minidump_extent(&padded), Some(dump.len()));
}

#[test]
fn malformed_inputs_never_panic() {
    for len in 0usize..48 {
        let mut buf: Vec<u8> = vec![0u8; len];
        if len >= 4 {
            buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        }
        let _ = detect_minidump(&buf);
        let _ = parse_minidump(&buf);
        let _ = minidump_extent(&buf);
    }
    let mut wild: Vec<u8> = vec![0xFFu8; 512];
    wild[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
    wild[4..8].copy_from_slice(&u32::from(MINIDUMP_VERSION).to_le_bytes());
    wild[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let _ = parse_minidump(&wild);
    let _ = minidump_extent(&wild);
}

#[test]
fn rejects_zero_size_module() {
    let text: Vec<u8> = text_fixture();
    let rdata: Vec<u8> = rdata_fixture();
    let image: Vec<u8> = build_mapped_pe64(&text, &rdata);
    let dump: Vec<u8> = build_dump("zero.dll", 9, 0, &[(IMAGE_BASE, 0x3000, image)]);
    let file: MinidumpFile = parse_minidump(&dump).expect("parse");
    assert!(carve_module(&file, &dump, &file.modules[0], 1 << 30).is_err());
}
