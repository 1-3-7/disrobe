#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use disrobe_pass_native::packers::pe_sections::parse_pe_image;
use disrobe_pass_native::{analyze_elf_dynamic, detect_format, minimal_pe32};

fn no_panic<T, F: FnOnce() -> T>(label: &str, f: F) -> T {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| panic!("parser panicked on adversarial input: {label}"))
}

const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z: u64 = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn craft_pe(mutate: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x400];
    buf[0] = b'M';
    buf[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe_off: usize = e_lfanew as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
    let coff_off: usize = pe_off + 4;
    buf[coff_off..coff_off + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xF0u16.to_le_bytes());
    let opt_off: usize = coff_off + 20;
    buf[opt_off..opt_off + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    mutate(&mut buf);
    buf
}

#[test]
fn detect_format_never_panics_on_truncation_and_junk() {
    let seeds: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x7F],
        b"\x7FEL".to_vec(),
        b"\x7FELF".to_vec(),
        b"\x7FELF\x09".to_vec(),
        b"MZ".to_vec(),
        vec![0xCF, 0xFA, 0xED],
        vec![0xCA, 0xFE, 0xBA, 0xBE],
        vec![
            0x4C, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    ];
    for (i, seed) in seeds.iter().enumerate() {
        let _ = no_panic(&format!("detect seed {i}"), || detect_format(seed));
    }
}

#[test]
fn detect_format_mz_pe_offset_extremes_never_panic() {
    for lfanew in [0u32, 1, 0x3C, 0x40, 0xFFFF_FFF0, 0xFFFF_FFFF] {
        let mut buf: Vec<u8> = vec![0u8; 0x100];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());
        let _ = no_panic(&format!("mz lfanew {lfanew:#x}"), || detect_format(&buf));
    }
}

#[test]
fn pe_image_hostile_counts_return_err_not_panic_or_oom() {
    let baseline: Vec<u8> = minimal_pe32();
    assert!(parse_pe_image(&baseline).is_ok());

    let huge_sections: Vec<u8> = craft_pe(|buf: &mut Vec<u8>| {
        let coff_off: usize = 0x84;
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    });
    let r1 = no_panic("pe 0xFFFF sections in 1KB", || {
        parse_pe_image(&huge_sections)
    });
    assert!(r1.is_err(), "65535 sections in a 1KB file must be rejected");

    let huge_dirs: Vec<u8> = craft_pe(|buf: &mut Vec<u8>| {
        let opt_off: usize = 0x98;
        buf[opt_off + 108..opt_off + 112].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    });
    let r2 = no_panic("pe 0xFFFFFFFF data dirs", || parse_pe_image(&huge_dirs));
    let _ = r2;

    let huge_opt: Vec<u8> = craft_pe(|buf: &mut Vec<u8>| {
        let coff_off: usize = 0x84;
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xFFFFu16.to_le_bytes());
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    });
    let r3 = no_panic("pe 0xFFFF opt header + sections", || {
        parse_pe_image(&huge_opt)
    });
    assert!(r3.is_err());

    for cut in [0usize, 1, 0x3C, 0x40, 0x80, 0x84, 0x90, 0x98, 0x100, 0x180] {
        let truncated: Vec<u8> = baseline.iter().copied().take(cut).collect();
        let r = no_panic(&format!("pe truncated at {cut}"), || {
            parse_pe_image(&truncated)
        });
        let _ = r;
    }
}

#[test]
fn elf_hostile_headers_return_none_not_panic_or_hang() {
    for cut in [4usize, 5, 6, 16, 40, 52, 56, 63, 64] {
        let mut buf: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
        buf.resize(cut, 0);
        let _ = no_panic(&format!("elf64 truncated at {cut}"), || {
            analyze_elf_dynamic(&buf)
        });
    }

    let mut huge_phnum: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
    huge_phnum.resize(64, 0);
    huge_phnum[54..56].copy_from_slice(&56u16.to_le_bytes());
    huge_phnum[56..58].copy_from_slice(&0xFFFFu16.to_le_bytes());
    huge_phnum[32..40].copy_from_slice(&0x40u64.to_le_bytes());
    let r = no_panic("elf 0xFFFF phnum in 64B", || {
        analyze_elf_dynamic(&huge_phnum)
    });
    assert!(r.is_some());

    let mut huge_phoff: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
    huge_phoff.resize(64, 0);
    huge_phoff[54..56].copy_from_slice(&56u16.to_le_bytes());
    huge_phoff[56..58].copy_from_slice(&8u16.to_le_bytes());
    huge_phoff[32..40].copy_from_slice(&0xFFFF_FFFF_FFFF_FFF0u64.to_le_bytes());
    let _ = no_panic("elf phoff near usize::MAX", || {
        analyze_elf_dynamic(&huge_phoff)
    });

    let mut bad_dynamic: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
    bad_dynamic.resize(256, 0);
    bad_dynamic[54..56].copy_from_slice(&56u16.to_le_bytes());
    bad_dynamic[56..58].copy_from_slice(&1u16.to_le_bytes());
    bad_dynamic[32..40].copy_from_slice(&64u64.to_le_bytes());
    bad_dynamic[64..68].copy_from_slice(&2u32.to_le_bytes());
    bad_dynamic[72..80].copy_from_slice(&0u64.to_le_bytes());
    bad_dynamic[96..104].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    let _ = no_panic("elf dynamic filesz=u64::MAX", || {
        analyze_elf_dynamic(&bad_dynamic)
    });

    let mut elf32_junk: Vec<u8> = b"\x7FELF\x01\x02\x01\x00".to_vec();
    elf32_junk.resize(52, 0xAB);
    elf32_junk[0] = 0x7F;
    elf32_junk[1] = b'E';
    elf32_junk[2] = b'L';
    elf32_junk[3] = b'F';
    elf32_junk[4] = 1;
    elf32_junk[5] = 2;
    let _ = no_panic("elf32 big-endian junk body", || {
        analyze_elf_dynamic(&elf32_junk)
    });
}

#[test]
fn elf_pt_load_mapping_max_file_offset_never_panics() {
    let mut buf: Vec<u8> = vec![0u8; 1024];
    buf[0..4].copy_from_slice(b"\x7FELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&3u16.to_le_bytes());
    buf[32..40].copy_from_slice(&64u64.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    buf[56..58].copy_from_slice(&2u16.to_le_bytes());

    let ph0: usize = 64;
    buf[ph0..ph0 + 4].copy_from_slice(&1u32.to_le_bytes());
    buf[ph0 + 4..ph0 + 8].copy_from_slice(&5u32.to_le_bytes());
    buf[ph0 + 8..ph0 + 16].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    buf[ph0 + 16..ph0 + 24].copy_from_slice(&0x1000u64.to_le_bytes());
    buf[ph0 + 24..ph0 + 32].copy_from_slice(&0x1000u64.to_le_bytes());
    buf[ph0 + 32..ph0 + 40].copy_from_slice(&0x100u64.to_le_bytes());
    buf[ph0 + 40..ph0 + 48].copy_from_slice(&0x100u64.to_le_bytes());
    buf[ph0 + 48..ph0 + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    let ph1: usize = 120;
    buf[ph1..ph1 + 4].copy_from_slice(&2u32.to_le_bytes());
    buf[ph1 + 4..ph1 + 8].copy_from_slice(&6u32.to_le_bytes());
    buf[ph1 + 8..ph1 + 16].copy_from_slice(&512u64.to_le_bytes());
    buf[ph1 + 16..ph1 + 24].copy_from_slice(&0x2000u64.to_le_bytes());
    buf[ph1 + 32..ph1 + 40].copy_from_slice(&48u64.to_le_bytes());

    let dyn_off: usize = 512;
    buf[dyn_off..dyn_off + 8].copy_from_slice(&25u64.to_le_bytes());
    buf[dyn_off + 8..dyn_off + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    buf[dyn_off + 16..dyn_off + 24].copy_from_slice(&27u64.to_le_bytes());
    buf[dyn_off + 24..dyn_off + 32].copy_from_slice(&16u64.to_le_bytes());
    buf[dyn_off + 32..dyn_off + 40].copy_from_slice(&0u64.to_le_bytes());
    buf[dyn_off + 40..dyn_off + 48].copy_from_slice(&0u64.to_le_bytes());

    let report = no_panic("elf pt_load offset u64::MAX", || analyze_elf_dynamic(&buf));
    let report = report.expect("header still parses");
    assert!(
        report.init_array.is_empty(),
        "an init-array pointer mapped past the image must yield no entries"
    );
}

#[test]
fn random_bytes_smoke_never_panics() {
    let mut state: u64 = 0x0BAD_C0DE_DEAD_BEEF;
    for case in 0..6000u32 {
        let len: usize = (splitmix64(&mut state) % 512) as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((splitmix64(&mut state) & 0xFF) as u8);
        }
        if case % 4 == 0 && buf.len() >= 4 {
            buf[0] = b'M';
            buf[1] = b'Z';
        }
        if case % 4 == 1 && buf.len() >= 5 {
            buf[0] = 0x7F;
            buf[1] = b'E';
            buf[2] = b'L';
            buf[3] = b'F';
            buf[4] = if case % 2 == 0 { 1 } else { 2 };
        }
        let b: Vec<u8> = buf.clone();
        let _ = no_panic(&format!("random detect {case}"), || detect_format(&b));
        let b2: Vec<u8> = buf.clone();
        let _ = no_panic(&format!("random pe {case}"), || parse_pe_image(&b2));
        let b3: Vec<u8> = buf;
        let _ = no_panic(&format!("random elf {case}"), || analyze_elf_dynamic(&b3));
    }
}
