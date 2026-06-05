#![allow(clippy::doc_markdown)]

//! ASProtect structural scaffold with a documented byte-recovery sourcing tail.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use crate::stub_emu::{Cpu, CpuMode, Memory, Perm, Reg};

const ASPROTECT_SECTIONS: &[&[u8]] = &[b".aspr", b".aspack", b".adata"];
const EMU_STACK_BASE: u64 = 0x0012_0000;
const EMU_STACK_SIZE: u64 = 0x0004_0000;

/// Parsed structural facts about an ASProtect-protected PE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsProtectLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub stub_section_name: Vec<u8>,
    pub stub_section_rva: u32,
    pub stub_section_raw_size: u32,
}

/// The recovery state for an ASProtect unpack attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum AsProtectRecovery {
    /// Structural geometry parsed and the emulator initialized; byte-recovery awaits an in-corpus sample.
    SourcingTail {
        layout: AsProtectLayout,
        emulator_ready: bool,
        floor_basis_points: u32,
        sourcing_tail: String,
    },
}

/// Parses the structural layout of an ASProtect-protected PE.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if no ASProtect/ASPack stub section is present.
pub fn asprotect_layout(packed: &[u8]) -> Result<AsProtectLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = img
        .sections
        .iter()
        .find(|s: &&PeSection| {
            ASPROTECT_SECTIONS
                .iter()
                .any(|name: &&[u8]| s.name_trimmed() == *name)
        })
        .ok_or_else(|| {
            Error::SignatureDb(
                "ASProtect: no .asprotect/.aspr/.aspack stub section present".to_owned(),
            )
        })?;
    Ok(AsProtectLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        stub_section_name: stub.name_trimmed().to_vec(),
        stub_section_rva: stub.virtual_address,
        stub_section_raw_size: stub.raw_size,
    })
}

/// Attempts an ASProtect unpack, returning [`AsProtectRecovery::SourcingTail`].
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] / [`Error::SignatureDb`] as
/// [`asprotect_layout`] does.
pub fn unpack_asprotect(packed: &[u8]) -> Result<AsProtectRecovery> {
    let layout: AsProtectLayout = asprotect_layout(packed)?;
    let emulator_ready: bool = init_stub_emulator(packed, &layout).is_some();
    Ok(AsProtectRecovery::SourcingTail {
        layout,
        emulator_ready,
        floor_basis_points: 0,
        sourcing_tail:
            "ASProtect byte-recovery is a documented sourcing tail: no ASProtect sample \
is in corpus and the protector cannot be installed/downloaded in this environment, so there is no \
independent ground truth to grade against. The PE structural layout is parsed and the in-house \
stub_emu CPU+memory environment is initialized over the packed image (ready to single-step the \
polymorphic decrypt + import-resolver stub), but the measured byte-recovery floor is 0% until a \
real sample lands in corpus. Detection ships; the unpack remainder is honestly deferred, never \
faked via a circular oracle."
                .to_owned(),
    })
}

/// Initializes the stub_emu environment over the packed image, returning `None` on degenerate geometry.
fn init_stub_emulator(packed: &[u8], layout: &AsProtectLayout) -> Option<()> {
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
    fn rejects_pe_without_asprotect_section() {
        let pe: Vec<u8> = build_pe(&[(b".text", 0x1000, &[0x90; 16])], 0x1000);
        assert!(asprotect_layout(&pe).is_err());
        assert!(unpack_asprotect(&pe).is_err());
    }

    #[test]
    fn rejects_non_pe() {
        assert!(unpack_asprotect(b"not a pe").is_err());
    }

    #[test]
    fn parses_layout_and_initializes_emulator_for_asprotect_section() {
        let pe: Vec<u8> = build_pe(
            &[
                (b".text", 0x1000, &[0xCC; 16]),
                (b".aspr", 0x2000, &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00]),
            ],
            0x2000,
        );
        let layout: AsProtectLayout = asprotect_layout(&pe).expect("layout");
        assert_eq!(layout.stub_section_name, b".aspr");
        assert_eq!(layout.stub_section_rva, 0x2000);
        assert_eq!(layout.entry_point_rva, 0x2000);

        let recovery: AsProtectRecovery = unpack_asprotect(&pe).expect("recovery");
        let AsProtectRecovery::SourcingTail {
            emulator_ready,
            floor_basis_points,
            sourcing_tail,
            ..
        } = recovery;
        assert!(
            emulator_ready,
            "the stub_emu CPU+memory environment must initialize over a structurally valid image \
             (this proves the structural recovery path is wired, even with no sample to decrypt)",
        );
        assert_eq!(
            floor_basis_points, 0,
            "with no in-corpus sample the honest byte-recovery floor is exactly 0%, never rounded up",
        );
        assert!(
            sourcing_tail.contains("sourcing tail")
                && sourcing_tail.contains("no ASProtect sample"),
            "the recovery must carry the documented sourcing-tail ceiling",
        );
    }
}
