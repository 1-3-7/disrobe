#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use disrobe_pass_native::{
    AsProtectRecovery, MorphineRecovery, Packer, UnpackerStatus, detect_packers, morphine_layout,
    unpack_asprotect, unpack_morphine,
};

const SEC_TABLE_OFFSET: usize = 0x80 + 4 + 20 + 0xE0;

fn build_pe(secs: &[(&[u8], u32, &[u8])], entry_rva: u32) -> Vec<u8> {
    let header_len: usize = 0x400;
    let mut buf: Vec<u8> = vec![0u8; header_len];
    buf[0] = b'M';
    buf[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe_off: usize = e_lfanew as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
    let coff_off: usize = pe_off + 4;
    buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[coff_off + 2..coff_off + 4].copy_from_slice(&(secs.len() as u16).to_le_bytes());
    buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xE0u16.to_le_bytes());
    let opt_off: usize = coff_off + 20;
    buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
    buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    let mut raw_cursor: usize = header_len;
    let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
    for (i, (name, va, data)) in secs.iter().enumerate() {
        let off: usize = SEC_TABLE_OFFSET + i * 40;
        let mut name_buf: [u8; 8] = [0u8; 8];
        name_buf[..name.len()].copy_from_slice(name);
        buf[off..off + 8].copy_from_slice(&name_buf);
        buf[off + 8..off + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
        buf[off + 16..off + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
        buf[off + 20..off + 24].copy_from_slice(&(raw_cursor as u32).to_le_bytes());
        bodies.push((raw_cursor, (*data).to_vec()));
        raw_cursor += data.len();
    }
    buf.resize(raw_cursor.max(header_len), 0);
    for (off, data) in bodies {
        buf[off..off + data.len()].copy_from_slice(&data);
    }
    buf
}

#[test]
fn asprotect_detect_stays_green_and_status_is_deferred() {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[16..16 + b".asprotect".len()].copy_from_slice(b".asprotect");
    assert!(
        detect_packers(&buf)
            .iter()
            .any(|h| h.packer == Packer::AsProtect),
        "ASProtect detection must stay green",
    );
    assert_eq!(
        Packer::AsProtect.unpacker_status(),
        UnpackerStatus::StubEvalPending,
        "ASProtect ships detect + structural scaffold; byte-recovery is a deferred sourcing tail, \
         so its dispatch status stays StubEvalPending, never a fake Implemented",
    );
}

#[test]
fn morphine_detect_stays_green_and_status_is_deferred() {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[16..16 + b"morphine".len()].copy_from_slice(b"morphine");
    assert!(
        detect_packers(&buf)
            .iter()
            .any(|h| h.packer == Packer::Morphine),
        "Morphine detection must stay green",
    );
    assert_eq!(
        Packer::Morphine.unpacker_status(),
        UnpackerStatus::StubEvalPending,
    );
}

#[test]
fn asprotect_scaffold_reports_zero_floor_and_sourcing_tail() {
    let pe: Vec<u8> = build_pe(
        &[
            (b".text", 0x1000, &[0xCC; 16]),
            (b".aspr", 0x2000, &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00]),
        ],
        0x2000,
    );
    let recovery: AsProtectRecovery = unpack_asprotect(&pe).expect("scaffold runs");
    let AsProtectRecovery::SourcingTail {
        emulator_ready,
        floor_basis_points,
        sourcing_tail,
        layout,
    } = recovery;
    assert!(emulator_ready, "stub_emu environment initialized");
    assert_eq!(
        floor_basis_points, 0,
        "honest 0% byte-recovery floor with no in-corpus sample",
    );
    assert_eq!(layout.stub_section_name, b".aspr");
    assert!(sourcing_tail.contains("no ASProtect sample"));
}

#[test]
fn morphine_scaffold_reports_zero_floor_and_sourcing_tail() {
    let pe: Vec<u8> = build_pe(&[(b".text", 0x1000, &[0x90; 16])], 0x1000);
    let recovery: MorphineRecovery = unpack_morphine(&pe).expect("scaffold runs");
    let MorphineRecovery::SourcingTail {
        emulator_ready,
        floor_basis_points,
        sourcing_tail,
        ..
    } = recovery;
    assert!(emulator_ready);
    assert_eq!(floor_basis_points, 0);
    assert!(sourcing_tail.contains("no Morphine sample"));
    let layout = morphine_layout(&pe).expect("layout");
    assert_eq!(layout.section_count, 1);
}

#[test]
fn scaffolds_reject_non_pe_without_fabricating_recovery() {
    assert!(unpack_asprotect(b"not a pe").is_err());
    assert!(unpack_morphine(b"not a pe").is_err());
}
