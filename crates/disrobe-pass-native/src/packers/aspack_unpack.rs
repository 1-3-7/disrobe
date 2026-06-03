use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, find_subsequence, parse_pe_image};

const ASPACK_SECTION: &[u8] = b".aspack";
const ASPACK_ADATA_SECTION: &[u8] = b".adata";
const ASPACK_EP_STUB: &[u8] = &[
    0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
];
const ORIGINAL_SECTION_NAMES: &[&[u8]] = &[
    b".text", b".rdata", b".data", b".rsrc", b".reloc", b".idata", b".edata", b".tls", b".bss",
    b"CODE", b"DATA",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AspackRecovery {
    /// PE structure + OBJ table parsed; encrypted/compressed content carved but
    /// not byte-decoded (modified `aPLib` dialect requires stub emulation).
    StructuralCarve,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CarvedBlock {
    pub source_section: Vec<u8>,
    pub file_offset: usize,
    pub bytes: Vec<u8>,
    /// Classic-`aPLib` decode match against the original, in percent. `ASPack`
    /// 2.x uses a modified `aPLib` dialect, so this is 0 by construction -
    /// recorded honestly, never inflated.
    pub classic_aplib_decode_pct: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AspackReport {
    pub recovery: AspackRecovery,
    pub ep_stub_matched: bool,
    pub aspack_section_present: bool,
    pub adata_section_present: bool,
    pub entry_point_rva: u32,
    pub recovered_object_table: Vec<RecoveredObject>,
    pub carved_blocks: Vec<CarvedBlock>,
    pub limitation_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredObject {
    pub name: Vec<u8>,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
}

/// Structurally recover an `ASPack` 2.x packed PE.
///
/// `ASPack` 2.x leaves the host section table intact (the original `.text`/
/// `.rdata`/`.data`/`.rsrc` headers survive, with their bodies `aPLib`-compressed
/// under a modified dialect) and appends an `.aspack`/`.adata` stub pair. This
/// function performs honest structural recovery: it parses the PE, reconstructs
/// the object (section) table, and carves each compressed content block. It does
/// NOT byte-decode the payload - classic `aPLib` decode is 0% against `ASPack`'s
/// modified dialect, so each block is reported as `StructuralCarve` with a 0%
/// classic-decode score, pending a `stub_emu` second pass (future work).
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if no `ASPack` stub/EP marker is present.
pub fn unpack_aspack(packed: &[u8]) -> Result<AspackReport> {
    let img: PeImage = parse_pe_image(packed)?;
    let aspack_present: bool = img.section_by_name(ASPACK_SECTION).is_some();
    let adata_present: bool = img.section_by_name(ASPACK_ADATA_SECTION).is_some();
    let ep_stub_matched: bool = ep_stub_present(packed, &img);
    if !aspack_present && !ep_stub_matched {
        return Err(Error::SignatureDb(
            "ASPack: neither .aspack section nor EP stub present - not an ASPack image".to_owned(),
        ));
    }
    let recovered_object_table: Vec<RecoveredObject> = img
        .sections
        .iter()
        .filter(|s: &&PeSection| {
            let name: &[u8] = s.name_trimmed();
            name != ASPACK_SECTION && name != ASPACK_ADATA_SECTION
        })
        .map(|s: &PeSection| RecoveredObject {
            name: s.name_trimmed().to_vec(),
            virtual_address: s.virtual_address,
            virtual_size: s.virtual_size,
            raw_size: s.raw_size,
            raw_pointer: s.raw_pointer,
        })
        .collect();
    let mut carved_blocks: Vec<CarvedBlock> = Vec::new();
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        let is_content: bool = ORIGINAL_SECTION_NAMES.contains(&name);
        if !is_content {
            continue;
        }
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        if start >= end {
            continue;
        }
        carved_blocks.push(CarvedBlock {
            source_section: name.to_vec(),
            file_offset: start,
            bytes: packed[start..end].to_vec(),
            classic_aplib_decode_pct: 0.0,
        });
    }
    Ok(AspackReport {
        recovery: AspackRecovery::StructuralCarve,
        ep_stub_matched,
        aspack_section_present: aspack_present,
        adata_section_present: adata_present,
        entry_point_rva: img.entry_point_rva,
        recovered_object_table,
        carved_blocks,
        limitation_note: "ASPack 2.x compresses content sections with a modified aPLib dialect; \
classic-aPLib decode yields 0%. Structural recovery only (PE header + reconstructed object table \
+ carved compressed blocks). Full byte recovery requires a stub_emu second pass (StubEvalPending)."
            .to_owned(),
    })
}

fn ep_stub_present(packed: &[u8], img: &PeImage) -> bool {
    if let Some(sec) = img.section_containing_rva(img.entry_point_rva) {
        let file_off: usize =
            sec.raw_pointer as usize + (img.entry_point_rva - sec.virtual_address) as usize;
        if packed.get(file_off..file_off + ASPACK_EP_STUB.len()) == Some(ASPACK_EP_STUB) {
            return true;
        }
    }
    find_subsequence(packed, ASPACK_EP_STUB).is_some()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_aspack_pe() {
        let buf: Vec<u8> = build_pe(&[(b".text", 0x1000, &[0u8; 16])], 0x1000);
        assert!(unpack_aspack(&buf).is_err());
    }

    #[test]
    fn structural_recovery_carves_content_and_reports_zero_classic_decode() {
        let mut text: Vec<u8> = ASPACK_EP_STUB.to_vec();
        text.resize(64, 0xCC);
        let buf: Vec<u8> = build_pe(
            &[
                (b".text", 0x1000, &text),
                (b".rsrc", 0x2000, &[0x11; 32]),
                (b".aspack", 0x3000, &[0x60, 0xE8, 0x03]),
            ],
            0x1000,
        );
        let report: AspackReport = unpack_aspack(&buf).expect("unpack");
        assert_eq!(report.recovery, AspackRecovery::StructuralCarve);
        assert!(report.aspack_section_present);
        assert!(report.ep_stub_matched);
        assert!(
            report
                .recovered_object_table
                .iter()
                .any(|o: &RecoveredObject| o.name == b".text"),
        );
        assert!(
            !report
                .recovered_object_table
                .iter()
                .any(|o: &RecoveredObject| o.name == b".aspack"),
            "aspack stub must be excluded from the reconstructed object table",
        );
        assert!(!report.carved_blocks.is_empty());
        for block in &report.carved_blocks {
            assert!(
                block.classic_aplib_decode_pct.abs() < f64::EPSILON,
                "classic-aPLib decode must be honestly 0 for ASPack's modified dialect",
            );
        }
    }

    fn build_pe(secs: &[(&[u8], u32, &[u8])], ep: u32) -> Vec<u8> {
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
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&ep.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        let sec_table: usize = opt_off + 0xE0;
        let mut raw_cursor: usize = header_len;
        let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, (name, va, data)) in secs.iter().enumerate() {
            let off: usize = sec_table + i * 40;
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
        buf.resize(raw_cursor, 0);
        for (off, data) in bodies {
            buf[off..off + data.len()].copy_from_slice(&data);
        }
        buf
    }
}
