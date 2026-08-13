#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::{Duration, Instant};

use disrobe_pass_nuitka::{NuitkaConstants, lift_native_bodies, parse_constants};

const TEXT_BYTES: usize = 0x1_0000;
const PDATA_ENTRIES: usize = 20_000;
const FILE_ALIGN: usize = 0x200;
const SECTION_ALIGN: usize = 0x1000;
const IMAGE_BASE: u64 = 0x1_4000_0000;
const WORK_CEILING: Duration = Duration::from_secs(3);

const fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn put_u16(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn overlapping_pdata_image() -> Vec<u8> {
    let text: Vec<u8> = vec![0x90u8; TEXT_BYTES];
    let text_rva: usize = SECTION_ALIGN;
    let pdata_rva: usize = text_rva + align_up(TEXT_BYTES, SECTION_ALIGN);

    let mut pdata: Vec<u8> = Vec::with_capacity(PDATA_ENTRIES * 12);
    let begin: u32 = u32::try_from(text_rva).expect("text rva fits u32");
    let end: u32 = u32::try_from(text_rva + TEXT_BYTES).expect("text end fits u32");
    for _ in 0..PDATA_ENTRIES {
        pdata.extend_from_slice(&begin.to_le_bytes());
        pdata.extend_from_slice(&end.to_le_bytes());
        pdata.extend_from_slice(&0u32.to_le_bytes());
    }

    let headers_size: usize = align_up(0x80 + 0x18 + 0xf0 + 2 * 0x28, FILE_ALIGN);
    let text_raw: usize = headers_size;
    let text_raw_size: usize = align_up(text.len(), FILE_ALIGN);
    let pdata_raw: usize = text_raw + text_raw_size;
    let pdata_raw_size: usize = align_up(pdata.len(), FILE_ALIGN);
    let total: usize = pdata_raw + pdata_raw_size;

    let mut buf: Vec<u8> = vec![0u8; total];
    buf[0] = b'M';
    buf[1] = b'Z';
    put_u32(&mut buf, 0x3c, 0x80);

    let pe: usize = 0x80;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff: usize = pe + 4;
    put_u16(&mut buf, coff, 0x8664);
    put_u16(&mut buf, coff + 2, 2);
    put_u16(&mut buf, coff + 16, 0xf0);
    put_u16(&mut buf, coff + 18, 0x0022);

    let opt: usize = coff + 20;
    put_u16(&mut buf, opt, 0x20b);
    put_u32(
        &mut buf,
        opt + 16,
        u32::try_from(text_rva).expect("entry fits"),
    );
    put_u64(&mut buf, opt + 24, IMAGE_BASE);
    put_u32(
        &mut buf,
        opt + 32,
        u32::try_from(SECTION_ALIGN).expect("section align fits"),
    );
    put_u32(
        &mut buf,
        opt + 36,
        u32::try_from(FILE_ALIGN).expect("file align fits"),
    );
    put_u16(&mut buf, opt + 40, 6);
    put_u16(&mut buf, opt + 68, 6);
    put_u32(
        &mut buf,
        opt + 56,
        u32::try_from(pdata_rva + align_up(pdata.len(), SECTION_ALIGN)).expect("image size fits"),
    );
    put_u32(
        &mut buf,
        opt + 60,
        u32::try_from(headers_size).expect("headers fit"),
    );
    put_u16(&mut buf, opt + 70, 3);
    put_u32(&mut buf, opt + 108, 16);
    put_u32(
        &mut buf,
        opt + 136,
        u32::try_from(pdata_rva).expect("pdata rva fits"),
    );
    put_u32(
        &mut buf,
        opt + 140,
        u32::try_from(pdata.len()).expect("pdata size fits"),
    );

    let sect: usize = opt + 0xf0;
    buf[sect..sect + 5].copy_from_slice(b".text");
    put_u32(
        &mut buf,
        sect + 8,
        u32::try_from(text.len()).expect("vsize"),
    );
    put_u32(&mut buf, sect + 12, u32::try_from(text_rva).expect("rva"));
    put_u32(
        &mut buf,
        sect + 16,
        u32::try_from(text_raw_size).expect("raw size"),
    );
    put_u32(&mut buf, sect + 20, u32::try_from(text_raw).expect("raw"));
    put_u32(&mut buf, sect + 36, 0x6000_0020);

    let sect2: usize = sect + 0x28;
    buf[sect2..sect2 + 6].copy_from_slice(b".pdata");
    put_u32(
        &mut buf,
        sect2 + 8,
        u32::try_from(pdata.len()).expect("pdata vsize"),
    );
    put_u32(&mut buf, sect2 + 12, u32::try_from(pdata_rva).expect("rva"));
    put_u32(
        &mut buf,
        sect2 + 16,
        u32::try_from(pdata_raw_size).expect("raw size"),
    );
    put_u32(&mut buf, sect2 + 20, u32::try_from(pdata_raw).expect("raw"));
    put_u32(&mut buf, sect2 + 36, 0x4000_0040);

    buf[text_raw..text_raw + text.len()].copy_from_slice(&text);
    buf[pdata_raw..pdata_raw + pdata.len()].copy_from_slice(&pdata);
    buf
}

#[test]
fn maximally_overlapping_exception_records_cannot_drive_unbounded_decoding() {
    let image: Vec<u8> = overlapping_pdata_image();
    let constants: NuitkaConstants = parse_constants(&image);
    let started: Instant = Instant::now();
    let recovery: Option<disrobe_pass_nuitka::NativeBodyRecovery> =
        lift_native_bodies(&image, Some(&constants));
    let elapsed: Duration = started.elapsed();

    eprintln!(
        "IMPL ENUMERATION BUDGET: {PDATA_ENTRIES} exception records each spanning the whole \
         {TEXT_BYTES}-byte .text finished in {elapsed:?}"
    );
    assert!(
        recovery.is_none(),
        "an image with no function-constructor cross-reference must yield no impl records"
    );
    assert!(
        elapsed < WORK_CEILING,
        "the constructor cross-reference took {elapsed:?}, above the {WORK_CEILING:?} ceiling; \
         without the decode budget this input drives {} instruction decodes",
        PDATA_ENTRIES * 20_000
    );
}

#[test]
fn overlapping_exception_records_produce_the_same_answer_twice() {
    let image: Vec<u8> = overlapping_pdata_image();
    let constants: NuitkaConstants = parse_constants(&image);
    let first: bool = lift_native_bodies(&image, Some(&constants)).is_none();
    let second: bool = lift_native_bodies(&image, Some(&constants)).is_none();
    assert_eq!(first, second, "the bounded enumeration must be repeatable");
}
