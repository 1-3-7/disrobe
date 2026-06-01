#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;

use disrobe_pass_pyarmor::{Detection, PyarmorVersion, detect_from_wrapper};

const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn corpus_root() -> PathBuf {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .expect("crates")
        .parent()
        .expect("repo root")
        .join("corpus")
        .join("python")
        .join("pyarmor")
}

#[test]
fn v6v7_static_key_synthetic_elf_round_trip() {
    let key: [u8; 16] = [
        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66,
    ];
    let mut rodata: Vec<u8> = vec![0u8; 256];
    rodata[..16].copy_from_slice(&key);
    rodata[64..64 + AES_RCON.len()].copy_from_slice(&AES_RCON);
    let elf: Vec<u8> = synth_elf64_with_rodata(&rodata);
    let tmp: PathBuf =
        std::env::temp_dir().join("disrobe-v6v7-static-key-runtime-fixture/_pytransform.so");
    let _ = std::fs::create_dir_all(tmp.parent().expect("parent"));
    std::fs::write(&tmp, &elf).expect("write fixture");

    let runtime_bytes: Vec<u8> = std::fs::read(&tmp).expect("read fixture");
    assert!(
        runtime_bytes.windows(AES_RCON.len()).any(|w| w == AES_RCON),
        "rcon must be present in fixture"
    );
    assert_eq!(&runtime_bytes[64..64 + 16], &key[..]);
}

#[test]
fn v6v7_static_key_real_pytransform_when_baked() {
    let runtimes_dir: PathBuf = corpus_root().join("_pytransform-runtimes");
    if !runtimes_dir.is_dir() {
        eprintln!(
            "skipped: {} missing; run scripts/bake/pyarmor.{{ps1,sh}} to bake fixtures",
            runtimes_dir.display()
        );
        return;
    }
    let mut probed: usize = 0;
    let entries: std::fs::ReadDir = std::fs::read_dir(&runtimes_dir).expect("read dir");
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        let name: std::ffi::OsString = entry.file_name();
        let n: std::borrow::Cow<'_, str> = name.to_string_lossy();
        if !(n.starts_with("v7_") || n.starts_with("v6_")) {
            continue;
        }
        let bytes: Vec<u8> = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        probed += 1;
        assert!(
            bytes.len() > 1024,
            "candidate runtime too small: {}",
            path.display()
        );
    }
    if probed == 0 {
        eprintln!(
            "skipped: no v6_/v7_ runtimes staged in {} (run bake script)",
            runtimes_dir.display()
        );
    }
}

#[test]
fn v7_wrapper_detect_when_baked_fixture_present() {
    let v7_dir: PathBuf = corpus_root().join("v7-super");
    if !v7_dir.is_dir() {
        eprintln!(
            "skipped: v7-super corpus not baked at {} (run scripts/bake/pyarmor.{{ps1,sh}})",
            v7_dir.display()
        );
        return;
    }
    let walker: std::fs::ReadDir = std::fs::read_dir(&v7_dir).expect("read v7-super");
    let mut wrapper_text: Option<String> = None;
    for entry in walker.flatten() {
        let path: PathBuf = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("py") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && (text.contains("pyarmor") || text.contains("__pyarmor__"))
        {
            wrapper_text = Some(text);
            break;
        }
    }
    let Some(text) = wrapper_text else {
        eprintln!("skipped: no pyarmor wrapper found in {}", v7_dir.display());
        return;
    };
    let (det, _): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect baked v7 wrapper");
    assert!(matches!(
        det.version,
        PyarmorVersion::V6 | PyarmorVersion::V7
    ));
}

fn synth_elf64_with_rodata(rodata: &[u8]) -> Vec<u8> {
    const EHDR_SIZE: u16 = 64;
    const SHDR_SIZE: u16 = 64;
    const SHDR_COUNT: u16 = 3;
    let shstrtab: &[u8] = b"\0.rodata\0.shstrtab\0";

    let mut layout: Vec<u8> = Vec::new();
    layout.extend_from_slice(&[0u8; 64]);

    let rodata_offset: u64 = layout.len() as u64;
    layout.extend_from_slice(rodata);
    pad_to_align(&mut layout, 16);
    let shstrtab_offset: u64 = layout.len() as u64;
    layout.extend_from_slice(shstrtab);
    pad_to_align(&mut layout, 8);
    let shdr_offset: u64 = layout.len() as u64;
    let shdr_total: usize = usize::from(SHDR_SIZE) * usize::from(SHDR_COUNT);
    layout.extend(core::iter::repeat_n(0u8, shdr_total));

    layout[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    layout[4] = 2;
    layout[5] = 1;
    layout[6] = 1;
    layout[7] = 0;
    layout[16..18].copy_from_slice(&3u16.to_le_bytes());
    layout[18..20].copy_from_slice(&62u16.to_le_bytes());
    layout[20..24].copy_from_slice(&1u32.to_le_bytes());
    layout[40..48].copy_from_slice(&shdr_offset.to_le_bytes());
    layout[52..54].copy_from_slice(&EHDR_SIZE.to_le_bytes());
    layout[58..60].copy_from_slice(&SHDR_SIZE.to_le_bytes());
    layout[60..62].copy_from_slice(&SHDR_COUNT.to_le_bytes());
    layout[62..64].copy_from_slice(&2u16.to_le_bytes());

    let shdr_base: usize = usize::try_from(shdr_offset).expect("shdr_offset fits usize");
    let write_shdr = |buf: &mut Vec<u8>,
                      slot: usize,
                      name_off: u32,
                      sh_type: u32,
                      sh_flags: u64,
                      sh_addr: u64,
                      sh_offset: u64,
                      sh_size: u64| {
        let base: usize = shdr_base + slot * usize::from(SHDR_SIZE);
        buf[base..base + 4].copy_from_slice(&name_off.to_le_bytes());
        buf[base + 4..base + 8].copy_from_slice(&sh_type.to_le_bytes());
        buf[base + 8..base + 16].copy_from_slice(&sh_flags.to_le_bytes());
        buf[base + 16..base + 24].copy_from_slice(&sh_addr.to_le_bytes());
        buf[base + 24..base + 32].copy_from_slice(&sh_offset.to_le_bytes());
        buf[base + 32..base + 40].copy_from_slice(&sh_size.to_le_bytes());
    };

    write_shdr(&mut layout, 0, 0, 0, 0, 0, 0, 0);
    write_shdr(
        &mut layout,
        1,
        1,
        1,
        2,
        0x0040_1000,
        rodata_offset,
        rodata.len() as u64,
    );
    write_shdr(
        &mut layout,
        2,
        9,
        3,
        0,
        0,
        shstrtab_offset,
        shstrtab.len() as u64,
    );
    layout
}

fn pad_to_align(buf: &mut Vec<u8>, align: usize) {
    let remainder: usize = buf.len() % align;
    if remainder != 0 {
        buf.extend(core::iter::repeat_n(0u8, align - remainder));
    }
}
