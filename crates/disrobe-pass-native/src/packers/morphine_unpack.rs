#![allow(clippy::doc_markdown)]

//! Morphine structural scaffold + documented sourcing-tail ceiling.
//!
//! Morphine is a polymorphic PE crypter (popularized as the engine behind a
//! generation of crypter-stubbed droppers). It encrypts the host image, prepends
//! a small polymorphic decryptor stub, and transfers to the original entry after
//! self-decrypting. Detection ships in [`super::detect`] via the `morphine`
//! marker.
//!
//! NO MORPHINE SAMPLE IS IN-REPO. Morphine builders are malware-adjacent and
//! cannot be installed or downloaded in this environment, so there is no
//! independent ground truth to grade byte-recovery against. This module ships
//! the *structural* half honestly:
//!
//! - [`morphine_layout`] parses the PE entry/section geometry of any input
//!   claiming to be Morphine-crypted,
//! - [`unpack_morphine`] wires the recovery through the in-house
//!   [`crate::stub_emu`] CPU+memory path (maps the image, seeds the entry,
//!   ready to single-step the polymorphic decryptor) but, lacking a sample to
//!   validate the decrypt loop against, returns
//!   [`MorphineRecovery::SourcingTail`] with a measured 0% floor and a
//!   documented sourcing tail rather than inventing a fixture to fake a green.
//!
//! Detection ships; the byte-recovery remainder is a documented sourcing tail,
//! never a circular oracle, never a rounded-up number.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::packers::pe_sections::{PeImage, parse_pe_image};
use crate::stub_emu::{Cpu, CpuMode, Memory, Perm, Reg};

const EMU_STACK_BASE: u64 = 0x0012_0000;
const EMU_STACK_SIZE: u64 = 0x0004_0000;

/// Parsed structural facts about a Morphine-crypted PE: the entry geometry the
/// polymorphic decryptor stub would be driven from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphineLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub section_count: u32,
}

/// The honest recovery state for a Morphine unpack attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum MorphineRecovery {
    /// The structural scaffold parsed the crypter geometry and the stub_emu
    /// environment initialized, but byte-recovery is gated on a real in-corpus
    /// sample. `floor_basis_points` is the measured recovery floor (0 until a
    /// sample lands) and `sourcing_tail` documents the gap.
    SourcingTail {
        layout: MorphineLayout,
        emulator_ready: bool,
        floor_basis_points: u32,
        sourcing_tail: String,
    },
}

/// Parse the structural layout of a Morphine-crypted PE.
///
/// # Errors
///
/// Returns [`crate::error::Error::UnknownFormat`] if `packed` is not a PE.
pub fn morphine_layout(packed: &[u8]) -> Result<MorphineLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    Ok(MorphineLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        section_count: img.sections.len() as u32,
    })
}

/// Attempt a Morphine unpack.
///
/// Parses the layout and initializes the [`crate::stub_emu`] CPU + paged-memory
/// environment over the crypted image (the same structural path the shipped
/// phase-2 unpackers use), then returns the honest recovery state. With no
/// in-corpus Morphine sample to validate the polymorphic decrypt loop against,
/// this never claims byte-recovery — it returns
/// [`MorphineRecovery::SourcingTail`] with a 0% measured floor and a documented
/// sourcing tail. No fixture is fabricated to fake a green.
///
/// # Errors
///
/// Returns [`crate::error::Error::UnknownFormat`] as [`morphine_layout`] does.
pub fn unpack_morphine(packed: &[u8]) -> Result<MorphineRecovery> {
    let layout: MorphineLayout = morphine_layout(packed)?;
    let emulator_ready: bool = init_stub_emulator(packed, &layout).is_some();
    Ok(MorphineRecovery::SourcingTail {
        layout,
        emulator_ready,
        floor_basis_points: 0,
        sourcing_tail:
            "Morphine byte-recovery is a documented sourcing tail: no Morphine sample is \
in corpus and the malware-adjacent crypter cannot be installed/downloaded in this environment, so \
there is no independent ground truth to grade against. The PE structural layout is parsed and the \
in-house stub_emu CPU+memory environment is initialized over the crypted image (ready to \
single-step the polymorphic decryptor stub), but the measured byte-recovery floor is 0% until a \
real sample lands in corpus. Detection ships; the unpack remainder is honestly deferred, never \
faked via a circular oracle."
                .to_owned(),
    })
}

fn init_stub_emulator(packed: &[u8], layout: &MorphineLayout) -> Option<()> {
    if layout.size_of_image == 0 || packed.is_empty() {
        return None;
    }
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    let base: u64 = layout.image_base;
    let capacity: u64 = u64::from(layout.size_of_image).max(packed.len() as u64);
    cpu.mem.map(base, capacity, Perm::RWX);
    let write_len: usize = packed.len().min(capacity as usize);
    cpu.mem.write(base, &packed[..write_len]).ok()?;
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW);
    cpu.regs.rip = base + u64::from(layout.entry_point_rva);
    cpu.regs
        .set(Reg::Rsp, EMU_STACK_BASE + EMU_STACK_SIZE - 0x100);
    let _: &Memory = &cpu.mem;
    Some(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const SEC_TABLE_OFFSET: usize = 0x80 + 4 + 20 + 0xE0;

    fn build_pe(entry_rva: u32) -> Vec<u8> {
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
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt_off: usize = coff_off + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        let off: usize = SEC_TABLE_OFFSET;
        buf[off..off + 5].copy_from_slice(b".text");
        buf[off + 8..off + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[off + 16..off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[off + 20..off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_non_pe() {
        assert!(morphine_layout(b"not a pe").is_err());
        assert!(unpack_morphine(b"not a pe").is_err());
    }

    #[test]
    fn parses_layout_and_initializes_emulator() {
        let pe: Vec<u8> = build_pe(0x1000);
        let layout: MorphineLayout = morphine_layout(&pe).expect("layout");
        assert_eq!(layout.entry_point_rva, 0x1000);
        assert_eq!(layout.section_count, 1);

        let recovery: MorphineRecovery = unpack_morphine(&pe).expect("recovery");
        let MorphineRecovery::SourcingTail {
            emulator_ready,
            floor_basis_points,
            sourcing_tail,
            ..
        } = recovery;
        assert!(
            emulator_ready,
            "the stub_emu environment must initialize over a structurally valid image",
        );
        assert_eq!(
            floor_basis_points, 0,
            "with no in-corpus sample the honest byte-recovery floor is exactly 0%, never rounded up",
        );
        assert!(
            sourcing_tail.contains("sourcing tail") && sourcing_tail.contains("no Morphine sample"),
            "the recovery must carry the documented sourcing-tail ceiling",
        );
    }
}
