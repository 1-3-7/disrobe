#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use disrobe_pass_native::{
    ObfuscatorFamily, ObfuscatorHit, StringIndicator, detect_obfuscator_indicators,
    detect_obfuscators,
};
use iced_x86::code_asm::{CodeAssembler, CodeLabel, dword_ptr, eax, rbp};

use crate::prerequisite;

const IMAGE_BASE: u64 = 0x40_0000;
const CODE_OFFSET: usize = 0x1000;

fn elf64_executable(code: &[u8], rodata: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0xFF; CODE_OFFSET];
    buf[..64].fill(0);
    buf[0..4].copy_from_slice(b"\x7FELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    buf[18..20].copy_from_slice(&0x3E_u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    let entry: u64 = IMAGE_BASE + CODE_OFFSET as u64;
    buf[24..32].copy_from_slice(&entry.to_le_bytes());
    buf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    buf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    buf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    buf[58..60].copy_from_slice(&64_u16.to_le_bytes());
    buf.extend_from_slice(code);
    buf.extend_from_slice(rodata);
    let file_size: u64 = buf.len() as u64;
    let phdr: usize = 64;
    buf[phdr..phdr + 56].fill(0);
    buf[phdr..phdr + 4].copy_from_slice(&1_u32.to_le_bytes());
    buf[phdr + 4..phdr + 8].copy_from_slice(&5_u32.to_le_bytes());
    buf[phdr + 16..phdr + 24].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    buf[phdr + 24..phdr + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    buf[phdr + 32..phdr + 40].copy_from_slice(&file_size.to_le_bytes());
    buf[phdr + 40..phdr + 48].copy_from_slice(&file_size.to_le_bytes());
    buf[phdr + 48..phdr + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    buf
}

fn families(hits: &[ObfuscatorHit]) -> Vec<ObfuscatorFamily> {
    hits.iter().map(|h: &ObfuscatorHit| h.family).collect()
}

#[test]
fn a_busybox_like_elf_holding_the_watchdog_path_gets_no_mirai_family() {
    let code: [u8; 3] = [0x31, 0xC0, 0xC3];
    let rodata: &[u8] =
        b"usage: watchdog [-t N[ms]] [-T N[ms]] [-F] DEV\0/dev/watchdog\0ModuleConfig\0switch_var\0";
    let bytes: Vec<u8> = elf64_executable(&code, rodata);
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(&bytes);
    let claimed: Vec<ObfuscatorFamily> = families(&hits);
    for family in [
        ObfuscatorFamily::Mirai,
        ObfuscatorFamily::Trickbot,
        ObfuscatorFamily::OllvmFlattening,
    ] {
        assert!(
            !claimed.contains(&family),
            "{} is a string any watchdog applet, config loader or compiler test carries; it is \
             an indicator, never a {} family claim: {hits:?}",
            family.label(),
            family.label(),
        );
    }
    let indicators: Vec<StringIndicator> = detect_obfuscator_indicators(&bytes);
    for needle in ["/dev/watchdog", "ModuleConfig", "switch_var"] {
        let expected: u64 = bytes
            .windows(needle.len())
            .position(|w: &[u8]| w == needle.as_bytes())
            .expect("fixture carries the needle") as u64;
        assert!(
            indicators
                .iter()
                .any(|i: &StringIndicator| i.matched_offset == expected),
            "{needle} must still surface as an indicator at {expected:#x}: {indicators:?}"
        );
    }
}

fn flattened_function(base: u64) -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut dispatcher: CodeLabel = asm.create_label();
    let mut case_a: CodeLabel = asm.create_label();
    let mut case_b: CodeLabel = asm.create_label();
    let mut case_c: CodeLabel = asm.create_label();
    asm.mov(dword_ptr(rbp - 4), 0i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut dispatcher).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 0i32).unwrap();
    asm.je(case_a).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 1i32).unwrap();
    asm.je(case_b).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 2i32).unwrap();
    asm.je(case_c).unwrap();
    asm.ret().unwrap();
    asm.set_label(&mut case_a).unwrap();
    asm.mov(eax, 1i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 1i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case_b).unwrap();
    asm.add(eax, 7i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 2i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case_c).unwrap();
    asm.ret().unwrap();
    asm.assemble(base).expect("assemble")
}

#[test]
fn the_structural_cff_check_decodes_from_the_entry_point() {
    let code: Vec<u8> = flattened_function(IMAGE_BASE + CODE_OFFSET as u64);
    let bytes: Vec<u8> = elf64_executable(&code, b"\0");
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(&bytes);
    assert!(
        families(&hits).contains(&ObfuscatorFamily::OllvmFlattening),
        "the dispatcher sits at the entry point, 4 KiB past the ELF header that offset 0 \
         decodes: {hits:?}"
    );
}

#[test]
fn the_same_dispatcher_off_the_entry_path_is_not_claimed() {
    let mut code: Vec<u8> = vec![0x31, 0xC0, 0xC3];
    code.resize(0x40, 0xCC);
    code.extend_from_slice(&flattened_function(IMAGE_BASE + CODE_OFFSET as u64 + 0x40));
    let bytes: Vec<u8> = elf64_executable(&code, b"\0");
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(&bytes);
    assert!(
        !families(&hits).contains(&ObfuscatorFamily::OllvmFlattening),
        "the structural check follows code from the entry point, which returns before the \
         dispatcher: {hits:?}"
    );
}

#[test]
fn compiler_output_decoded_from_its_entry_is_not_claimed_flattened() {
    const GRADED: &str = "the no-flattening control on compiler output";
    let local: [&str; 2] = [
        "corpus/native/unbind/notepad.pe64.exe",
        "corpus/native/unbind/kernel32.pe32.dll",
    ];
    let committed: [&str; 4] = [
        "corpus/native/d/clean_control.exe",
        "corpus/native/formats/hello.pe64.exe",
        "corpus/native/obfuscators/obfuscxx/sample.clean.exe",
        "corpus/native/obfuscators/obfusheader/sample.clean.exe",
    ];
    let images: Vec<(&str, Vec<u8>)> = local
        .into_iter()
        .filter_map(|relative: &str| Some((relative, prerequisite::local_only(relative, GRADED)?)))
        .chain(
            committed
                .into_iter()
                .map(|relative: &str| (relative, prerequisite::committed(relative))),
        )
        .collect();
    for (relative, bytes) in images {
        let hits: Vec<ObfuscatorHit> = detect_obfuscators(&bytes);
        assert!(
            !families(&hits).contains(&ObfuscatorFamily::OllvmFlattening),
            "{relative}: a switch inside a loop in ordinary startup code is a compare tree with \
             back-edges, but no case assigns the next case's state: {hits:?}"
        );
    }
}
