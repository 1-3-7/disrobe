#![allow(clippy::doc_markdown)]

//! Themida / WinLicense detect-and-carve.
//!
//! Detection of Themida ships in [`super::detect`] via the `.themida` and
//! `.winlice` section signatures and the grey-zone status
//! [`super::UnpackerStatus::GreyZoneDetectAndCarve`]. This module adds the carve
//! half, mirroring [`super::vmprotect_carve`]: it extracts the Themida/WinLicense
//! protected-section blobs, reconstructs each section header (RVA / virtual size
//! / raw size / decoded permissions), and surfaces the import-directory geometry
//! the protector leaves behind.
//!
//! FULL DEVIRTUALIZATION IS DEFERRED. Themida (Oreans) wraps protected code in
//! one of several mutually-exclusive virtual machines (CISC/RISC/FISH/TIGER
//! variants) whose handler dispatch is per-build randomized and whose entry is
//! guarded by anti-debug / anti-VM checks. Recovering the original x86 requires a
//! dedicated Themida VM-devirt pass that is out of scope here. This carve never
//! claims to recover original code — it surfaces the protected-section geometry
//! so a future devirt pass has a structured starting point. The honest ceiling
//! is documented on [`ThemidaCarve::limitation`].

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::pe_sections::{DataDirectory, PeImage, PeSection, parse_pe_image};
use crate::packers::vmprotect_carve::{CarvedVmpSection, SectionPerms};

const THEMIDA_SECTION: &[u8] = b".themida";
const WINLICENSE_SECTION: &[u8] = b".winlice";
const IMPORT_DIRECTORY_INDEX: usize = 1;

/// Which Oreans product the carved protected section belongs to, inferred from
/// the section name (the two products share the same packer engine and section
/// layout; only the section tag differs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OreansProduct {
    Themida,
    WinLicense,
}

/// The result of a Themida / WinLicense detect-and-carve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThemidaCarve {
    pub product: OreansProduct,
    pub protected_sections: Vec<CarvedVmpSection>,
    pub import_directory: Option<DataDirectory>,
    pub limitation: String,
}

impl ThemidaCarve {
    /// Total number of bytes carved out of all protected sections.
    #[must_use]
    pub fn carved_blob_bytes(&self) -> usize {
        self.protected_sections
            .iter()
            .map(|s: &CarvedVmpSection| s.blob.len())
            .sum()
    }
}

/// Detect-and-carve a Themida / WinLicense-protected PE.
///
/// Extracts the `.themida` (or `.winlice`) protected-section blob, reconstructs
/// the section header geometry and decoded permissions, and surfaces the import
/// directory the protector leaves in the PE. Does NOT devirtualize: the
/// protected code remains Themida VM bytecode and is surfaced verbatim for a
/// future devirt pass.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if no `.themida`/`.winlice` section is present.
pub fn carve_themida(packed: &[u8]) -> Result<ThemidaCarve> {
    let img: PeImage = parse_pe_image(packed)?;
    let product: OreansProduct = if img.section_by_name(THEMIDA_SECTION).is_some() {
        OreansProduct::Themida
    } else if img.section_by_name(WINLICENSE_SECTION).is_some() {
        OreansProduct::WinLicense
    } else {
        return Err(Error::SignatureDb(
            "Themida: no .themida/.winlice section present - not a Themida/WinLicense image"
                .to_owned(),
        ));
    };
    let protected_sections: Vec<CarvedVmpSection> = img
        .sections
        .iter()
        .filter(|s: &&PeSection| {
            let n: &[u8] = s.name_trimmed();
            n == THEMIDA_SECTION || n == WINLICENSE_SECTION
        })
        .map(|s: &PeSection| carve_section(packed, s))
        .collect();
    let import_directory: Option<DataDirectory> = img
        .data_directories
        .get(IMPORT_DIRECTORY_INDEX)
        .copied()
        .filter(|d: &DataDirectory| d.virtual_address != 0 && d.size != 0);
    Ok(ThemidaCarve {
        product,
        protected_sections,
        import_directory,
        limitation: "Themida/WinLicense carve: protected section(s) (.themida/.winlice) extracted \
verbatim and section headers reconstructed; the import-directory geometry is surfaced. The original \
x86 is lifted into one of Themida's randomized VMs (CISC/RISC/FISH/TIGER) and is NOT recovered here \
- full devirtualization is deferred to a dedicated VM-devirt pass. Detect-and-carve only."
            .to_owned(),
    })
}

fn carve_section(image: &[u8], sec: &PeSection) -> CarvedVmpSection {
    let blob: Vec<u8> = match sec.raw_range(image.len()) {
        Some((start, end)) => image[start..end].to_vec(),
        None => {
            let start: usize = (sec.raw_pointer as usize).min(image.len());
            image[start..].to_vec()
        }
    };
    CarvedVmpSection {
        name: sec.name_trimmed().to_vec(),
        virtual_address: sec.virtual_address,
        virtual_size: sec.virtual_size,
        raw_size: sec.raw_size,
        raw_pointer: sec.raw_pointer,
        perms: SectionPerms::from_characteristics_public(sec.characteristics),
        blob,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const SEC_TABLE_OFFSET: usize = 0x80 + 4 + 20 + 0xE0;
    const SCN_READ: u32 = 0x4000_0000;
    const SCN_WRITE: u32 = 0x8000_0000;
    const SCN_EXECUTE: u32 = 0x2000_0000;

    fn build_pe(secs: &[(&[u8], u32, u32, &[u8])]) -> Vec<u8> {
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
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_off + 92..opt_off + 96].copy_from_slice(&16u32.to_le_bytes());
        let mut raw_cursor: usize = header_len;
        let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, (name, va, characteristics, data)) in secs.iter().enumerate() {
            let off: usize = SEC_TABLE_OFFSET + i * 40;
            let mut name_buf: [u8; 8] = [0u8; 8];
            name_buf[..name.len()].copy_from_slice(name);
            buf[off..off + 8].copy_from_slice(&name_buf);
            buf[off + 8..off + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
            buf[off + 16..off + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&(raw_cursor as u32).to_le_bytes());
            buf[off + 36..off + 40].copy_from_slice(&characteristics.to_le_bytes());
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
    fn rejects_pe_without_themida_section() {
        let pe: Vec<u8> = build_pe(&[(b".text", 0x1000, SCN_READ | SCN_EXECUTE, &[0x90; 16])]);
        assert!(carve_themida(&pe).is_err());
    }

    #[test]
    fn rejects_non_pe() {
        assert!(carve_themida(b"definitely not a pe").is_err());
    }

    #[test]
    fn carves_themida_section_with_reconstructed_geometry() {
        let themida_body: Vec<u8> = (0u8..96).collect();
        let pe: Vec<u8> = build_pe(&[
            (b".text", 0x1000, SCN_READ | SCN_EXECUTE, &[0xCC; 16]),
            (
                b".themida",
                0x2000,
                SCN_READ | SCN_WRITE | SCN_EXECUTE,
                &themida_body,
            ),
        ]);
        let carve: ThemidaCarve = carve_themida(&pe).expect("carve");
        assert_eq!(carve.product, OreansProduct::Themida);
        assert_eq!(carve.protected_sections.len(), 1);
        let sec: &CarvedVmpSection = &carve.protected_sections[0];
        assert_eq!(sec.name, b".themida");
        assert_eq!(sec.virtual_address, 0x2000, "RVA reconstructed from header");
        assert_eq!(
            sec.blob, themida_body,
            "the carved blob is the verbatim on-disk protected section, byte-for-byte (non-circular: \
             compared against the independently-built section body, not a re-emit through any builder)",
        );
        assert!(sec.perms.read && sec.perms.write && sec.perms.execute);
        assert_eq!(carve.carved_blob_bytes(), 96);
        assert!(
            carve.limitation.contains("devirtualization is deferred"),
            "carve must honestly document the deferred devirt ceiling",
        );
    }

    #[test]
    fn carves_winlicense_section_and_classifies_product() {
        let body: Vec<u8> = vec![0xEE; 48];
        let pe: Vec<u8> = build_pe(&[
            (b".text", 0x1000, SCN_READ | SCN_EXECUTE, &[0x00; 16]),
            (b".winlice", 0x2000, SCN_READ | SCN_EXECUTE, &body),
        ]);
        let carve: ThemidaCarve = carve_themida(&pe).expect("carve");
        assert_eq!(
            carve.product,
            OreansProduct::WinLicense,
            "a .winlice section must classify as WinLicense, not Themida",
        );
        assert_eq!(carve.protected_sections[0].blob, body);
    }
}
