#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Read as _;

const LARGE_TEXT_BYTES: usize = 220 * 1024 * 1024;
const FILE_ALIGN: usize = 0x200;
const SECTION_ALIGN: u32 = 0x1000;
const IMAGE_BASE: u64 = 0x1_4000_0000;

const fn function_pattern() -> [u8; 16] {
    [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x10, 0x5d,
        0xc3,
    ]
}

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

fn synth_large_standalone() -> Vec<u8> {
    let mut rdata: Vec<u8> = Vec::new();
    rdata.extend_from_slice(b"__nuitka_version__\0");
    rdata.extend_from_slice(b"__compiled__\0");
    rdata.extend_from_slice(b"sample_app\\__init__.py\0");
    rdata.extend_from_slice(b"sample_app\\core.py\0");

    let pattern: [u8; 16] = function_pattern();
    let mut text: Vec<u8> = Vec::with_capacity(LARGE_TEXT_BYTES);
    while text.len() < LARGE_TEXT_BYTES {
        text.extend_from_slice(&pattern);
    }

    let headers_size: usize = align_up(0x40 + 0x18 + 0xf0 + 2 * 0x28, FILE_ALIGN);
    let text_raw: usize = headers_size;
    let text_raw_size: usize = align_up(text.len(), FILE_ALIGN);
    let rdata_raw: usize = text_raw + text_raw_size;
    let rdata_raw_size: usize = align_up(rdata.len(), FILE_ALIGN);
    let total: usize = rdata_raw + rdata_raw_size;

    let text_rva: u32 = SECTION_ALIGN;
    let text_vsize: u32 = u32::try_from(text.len()).expect("text fits u32");
    let rdata_rva: u32 = text_rva + align_up(text.len(), SECTION_ALIGN as usize) as u32;
    let rdata_vsize: u32 = u32::try_from(rdata.len()).expect("rdata fits u32");
    let image_size: u32 = rdata_rva + align_up(rdata.len(), SECTION_ALIGN as usize) as u32;

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
    put_u32(&mut buf, opt + 16, text_rva);
    put_u64(&mut buf, opt + 24, IMAGE_BASE);
    put_u32(&mut buf, opt + 32, SECTION_ALIGN);
    put_u32(&mut buf, opt + 36, FILE_ALIGN as u32);
    put_u16(&mut buf, opt + 40, 6);
    put_u16(&mut buf, opt + 68, 6);
    put_u32(&mut buf, opt + 56, image_size);
    put_u32(&mut buf, opt + 60, headers_size as u32);
    put_u16(&mut buf, opt + 70, 3);
    put_u32(&mut buf, opt + 108, 16);

    let sect: usize = opt + 0xf0;
    buf[sect..sect + 5].copy_from_slice(b".text");
    put_u32(&mut buf, sect + 8, text_vsize);
    put_u32(&mut buf, sect + 12, text_rva);
    put_u32(&mut buf, sect + 16, text_raw_size as u32);
    put_u32(&mut buf, sect + 20, text_raw as u32);
    put_u32(&mut buf, sect + 36, 0x6000_0020);

    let sect2: usize = sect + 0x28;
    buf[sect2..sect2 + 6].copy_from_slice(b".rdata");
    put_u32(&mut buf, sect2 + 8, rdata_vsize);
    put_u32(&mut buf, sect2 + 12, rdata_rva);
    put_u32(&mut buf, sect2 + 16, rdata_raw_size as u32);
    put_u32(&mut buf, sect2 + 20, rdata_raw as u32);
    put_u32(&mut buf, sect2 + 36, 0x4000_0040);

    buf[text_raw..text_raw + text.len()].copy_from_slice(&text);
    buf[rdata_raw..rdata_raw + rdata.len()].copy_from_slice(&rdata);
    buf
}

#[test]
fn large_standalone_native_disasm_is_bounded_and_completes() {
    let image: Vec<u8> = synth_large_standalone();
    assert!(
        image.len() > LARGE_TEXT_BYTES,
        "fixture has a multi-hundred-MB .text: {} bytes",
        image.len()
    );

    let detection: disrobe_pass_nuitka::Detection =
        disrobe_pass_nuitka::detect_in_bytes(&image).expect("detects as nuitka");
    assert!(
        matches!(
            detection.flavor,
            disrobe_pass_nuitka::NuitkaFlavor::Standalone
        ),
        "must route as standalone, got {:?}",
        detection.flavor
    );
    assert!(
        detection.onefile_payload_offset.is_none(),
        "no onefile payload in a standalone"
    );

    let out_path: std::path::PathBuf = std::env::temp_dir().join(format!(
        "disrobe-large-standalone-{}.asm",
        std::process::id()
    ));
    let disasm: disrobe_pass_nuitka::NativeDisasm =
        disrobe_pass_nuitka::disassemble_module_to_file("<standalone>", &image, &out_path)
            .expect("streamed disasm produced");

    assert!(disasm.truncated, "a 220MB .text exceeds the bounded window");
    assert!(
        disasm.text_bytes <= 96 * 1024 * 1024,
        "decoded window is bounded to the cap, got {} bytes",
        disasm.text_bytes
    );
    assert!(
        disasm.instruction_count > 1000,
        "real instructions streamed, got {}",
        disasm.instruction_count
    );

    let asm_len: u64 = std::fs::metadata(&out_path).expect("asm written").len();
    assert!(
        asm_len <= 300 * 1024 * 1024,
        "streamed asm is output-capped, got {asm_len} bytes"
    );
    let header: String = {
        let mut buf: String = String::new();
        let mut f: std::fs::File = std::fs::File::open(&out_path).expect("open asm");
        let mut chunk: [u8; 4096] = [0u8; 4096];
        let n: usize = f.read(&mut chunk).expect("read asm head");
        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
        buf
    };
    assert!(header.contains("push"), "real x86 mnemonics streamed");

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn large_standalone_stats_path_is_bounded() {
    let image: Vec<u8> = synth_large_standalone();
    let stats: disrobe_pass_nuitka::NativeDisasm =
        disrobe_pass_nuitka::disassemble_module_stats("<standalone>", &image)
            .expect("stats produced");
    assert!(stats.truncated);
    assert!(stats.text_bytes <= 96 * 1024 * 1024);
    assert!(stats.instruction_count > 1000);
}
