#![allow(clippy::doc_markdown)]

//! VMProtect detect-and-carve, surfacing `.vmpN` section geometry and a rebuilt import table.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::pe_sections::{DataDirectory, PeImage, PeSection, parse_pe_image};

const VMP_SECTION_PREFIX: &[u8] = b".vmp";
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMPORT_DIRECTORY_INDEX: usize = 1;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;

/// Decoded section permissions for a carved protected section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SectionPerms {
    #[must_use]
    const fn from_characteristics(c: u32) -> Self {
        Self {
            read: c & IMAGE_SCN_MEM_READ != 0,
            write: c & IMAGE_SCN_MEM_WRITE != 0,
            execute: c & IMAGE_SCN_MEM_EXECUTE != 0,
        }
    }

    /// Decodes PE section `Characteristics` flags into read/write/execute permissions.
    #[must_use]
    pub const fn from_characteristics_public(c: u32) -> Self {
        Self::from_characteristics(c)
    }
}

/// A carved VMProtect section: reconstructed header geometry plus the verbatim protected blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarvedVmpSection {
    pub name: Vec<u8>,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub perms: SectionPerms,
    pub blob: Vec<u8>,
}

/// A single import reconstructed from the surviving Import Directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticImport {
    pub dll: String,
    pub first_thunk_rva: u32,
    pub original_first_thunk_rva: u32,
}

/// The result of a VMProtect detect-and-carve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmProtectCarve {
    pub vmp_sections: Vec<CarvedVmpSection>,
    pub synthetic_imports: Vec<SyntheticImport>,
    pub import_directory: Option<DataDirectory>,
    pub limitation: String,
}

impl VmProtectCarve {
    /// Total number of bytes carved out of all `.vmpN` protected sections.
    #[must_use]
    pub fn carved_blob_bytes(&self) -> usize {
        self.vmp_sections
            .iter()
            .map(|s: &CarvedVmpSection| s.blob.len())
            .sum()
    }
}

/// Detect-and-carves a VMProtect-protected PE without devirtualizing.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if no `.vmpN` section is present.
pub fn carve_vmprotect(packed: &[u8]) -> Result<VmProtectCarve> {
    let img: PeImage = parse_pe_image(packed)?;
    let vmp_sections: Vec<CarvedVmpSection> = img
        .sections
        .iter()
        .filter(|s: &&PeSection| s.name_trimmed().starts_with(VMP_SECTION_PREFIX))
        .map(|s: &PeSection| carve_section(packed, s))
        .collect();
    if vmp_sections.is_empty() {
        return Err(Error::SignatureDb(
            "VMProtect: no .vmpN section present - not a VMProtect image".to_owned(),
        ));
    }
    let import_directory: Option<DataDirectory> = img
        .data_directories
        .get(IMPORT_DIRECTORY_INDEX)
        .copied()
        .filter(|d: &DataDirectory| d.virtual_address != 0 && d.size != 0);
    let synthetic_imports: Vec<SyntheticImport> = import_directory
        .map_or_else(Vec::new, |dir: DataDirectory| {
            rebuild_imports(packed, &img, dir)
        });
    Ok(VmProtectCarve {
        vmp_sections,
        synthetic_imports,
        import_directory,
        limitation: "VMProtect carve: protected sections (.vmpN) extracted verbatim and section \
headers reconstructed; the import table is rebuilt from the surviving Import Directory. The \
original x86 is lifted to a polymorphic stack-machine bytecode and is NOT recovered here - full \
devirtualization is deferred to a dedicated VM-devirt pass. Detect-and-carve only."
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
        perms: SectionPerms::from_characteristics(sec.characteristics),
        blob,
    }
}

/// Reconstructs (dll, thunk-RVA) tuples from the surviving Import Directory.
fn rebuild_imports(image: &[u8], pe: &PeImage, dir: DataDirectory) -> Vec<SyntheticImport> {
    let mut out: Vec<SyntheticImport> = Vec::new();
    let mut cursor_rva: u32 = dir.virtual_address;
    let end_rva: u32 = dir.virtual_address.saturating_add(dir.size);
    while cursor_rva + IMPORT_DESCRIPTOR_SIZE as u32 <= end_rva {
        let Some(off): Option<usize> = rva_to_offset(pe, cursor_rva) else {
            break;
        };
        if off + IMPORT_DESCRIPTOR_SIZE > image.len() {
            break;
        }
        let original_first_thunk: u32 = read_u32(image, off);
        let name_rva: u32 = read_u32(image, off + 12);
        let first_thunk: u32 = read_u32(image, off + 16);
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let dll: String = rva_to_offset(pe, name_rva)
            .map_or_else(String::new, |name_off: usize| read_cstr(image, name_off));
        out.push(SyntheticImport {
            dll,
            first_thunk_rva: first_thunk,
            original_first_thunk_rva: original_first_thunk,
        });
        cursor_rva += IMPORT_DESCRIPTOR_SIZE as u32;
    }
    out
}

fn rva_to_offset(pe: &PeImage, rva: u32) -> Option<usize> {
    let sec: &PeSection = pe.section_containing_rva(rva)?;
    let delta: u32 = rva.checked_sub(sec.virtual_address)?;
    if delta >= sec.raw_size.max(sec.virtual_size) {
        return None;
    }
    (sec.raw_pointer as usize).checked_add(delta as usize)
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    if off + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn read_cstr(b: &[u8], off: usize) -> String {
    let end: usize = b[off..]
        .iter()
        .position(|c: &u8| *c == 0)
        .map_or(b.len(), |p: usize| off + p);
    String::from_utf8_lossy(&b[off..end]).into_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const SEC_TABLE_OFFSET: usize = 0x80 + 4 + 20 + 0xE0;

    fn build_vmp_pe(secs: &[(&[u8], u32, u32, &[u8])], import_dir: Option<(u32, u32)>) -> Vec<u8> {
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
        if let Some((rva, size)) = import_dir {
            let import_dir_off: usize = opt_off + 96 + IMPORT_DIRECTORY_INDEX * 8;
            buf[import_dir_off..import_dir_off + 4].copy_from_slice(&rva.to_le_bytes());
            buf[import_dir_off + 4..import_dir_off + 8].copy_from_slice(&size.to_le_bytes());
        }
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
    fn rejects_pe_without_vmp_section() {
        let pe: Vec<u8> = build_vmp_pe(
            &[(
                b".text",
                0x1000,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                &[0x90; 16],
            )],
            None,
        );
        assert!(carve_vmprotect(&pe).is_err());
    }

    #[test]
    fn rejects_non_pe() {
        assert!(carve_vmprotect(b"not a pe at all").is_err());
    }

    #[test]
    fn carves_vmp0_and_vmp1_with_reconstructed_geometry() {
        let vmp0_body: Vec<u8> = (0u8..64).collect();
        let vmp1_body: Vec<u8> = (64u8..128).collect();
        let pe: Vec<u8> = build_vmp_pe(
            &[
                (
                    b".text",
                    0x1000,
                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                    &[0xCC; 16],
                ),
                (
                    b".vmp0",
                    0x2000,
                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                    &vmp0_body,
                ),
                (
                    b".vmp1",
                    0x3000,
                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                    &vmp1_body,
                ),
            ],
            None,
        );
        let carve: VmProtectCarve = carve_vmprotect(&pe).expect("carve");
        assert_eq!(carve.vmp_sections.len(), 2, "both .vmp0 and .vmp1 carved");

        let vmp0: &CarvedVmpSection = &carve.vmp_sections[0];
        assert_eq!(vmp0.name, b".vmp0");
        assert_eq!(
            vmp0.virtual_address, 0x2000,
            "RVA reconstructed from header"
        );
        assert_eq!(
            vmp0.blob, vmp0_body,
            "the carved blob is the verbatim on-disk protected section, byte-for-byte (non-circular: \
             compared against the independently-constructed section body, not a re-emit)",
        );
        assert!(vmp0.perms.execute && vmp0.perms.read && !vmp0.perms.write);

        let vmp1: &CarvedVmpSection = &carve.vmp_sections[1];
        assert_eq!(vmp1.virtual_address, 0x3000);
        assert_eq!(vmp1.blob, vmp1_body);
        assert!(vmp1.perms.write && vmp1.perms.read && !vmp1.perms.execute);

        assert_eq!(carve.carved_blob_bytes(), 128);
        assert!(
            carve.limitation.contains("devirtualization is deferred"),
            "carve must honestly document the deferred devirt ceiling",
        );
    }

    #[test]
    fn rebuilds_imports_from_surviving_import_directory() {
        let dll_name: &[u8] = b"kernel32.dll\0";
        let mut idata: Vec<u8> = vec![0u8; IMPORT_DESCRIPTOR_SIZE * 2 + 16];
        idata[0..4].copy_from_slice(&0x4050u32.to_le_bytes());
        let name_rva: u32 = 0x4000 + (IMPORT_DESCRIPTOR_SIZE as u32 * 2);
        idata[12..16].copy_from_slice(&name_rva.to_le_bytes());
        idata[16..20].copy_from_slice(&0x4060u32.to_le_bytes());
        let name_off: usize = IMPORT_DESCRIPTOR_SIZE * 2;
        idata[name_off..name_off + dll_name.len()].copy_from_slice(dll_name);

        let pe: Vec<u8> = build_vmp_pe(
            &[
                (
                    b".vmp0",
                    0x1000,
                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                    &[0xAB; 32],
                ),
                (b".idata", 0x4000, IMAGE_SCN_MEM_READ, &idata),
            ],
            Some((0x4000, IMPORT_DESCRIPTOR_SIZE as u32 * 2)),
        );
        let carve: VmProtectCarve = carve_vmprotect(&pe).expect("carve");
        assert!(carve.import_directory.is_some());
        assert_eq!(carve.synthetic_imports.len(), 1, "one descriptor rebuilt");
        assert_eq!(
            carve.synthetic_imports[0].dll, "kernel32.dll",
            "the DLL name is recovered from the surviving Import Directory name RVA",
        );
        assert_eq!(carve.synthetic_imports[0].first_thunk_rva, 0x4060);
    }

    #[test]
    fn perms_decoding_is_exact() {
        let rwx: SectionPerms = SectionPerms::from_characteristics(
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
        );
        assert!(rwx.read && rwx.write && rwx.execute);
        let none: SectionPerms = SectionPerms::from_characteristics(0);
        assert!(!none.read && !none.write && !none.execute);
    }
}
