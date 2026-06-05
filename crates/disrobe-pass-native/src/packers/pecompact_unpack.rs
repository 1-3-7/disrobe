use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, find_subsequence, parse_pe_image};

const PEC2_MARKER: &[u8] = b"PEC2";
const PECOMPACT2_MARKER: &[u8] = b"PECompact2";
const PECOMPACT_SEH_STUB: &[u8] = &[
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25,
    0x00, 0x00, 0x00, 0x00,
];
const PECOMPACT_SEH_MASK: &[u8] = &[
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PecompactRecovery {
    StructuralCarve,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PecompactReport {
    pub recovery: PecompactRecovery,
    pub pec2_marker_offset: Option<usize>,
    pub pecompact2_marker_offset: Option<usize>,
    pub seh_stub_matched: bool,
    pub entry_point_rva: u32,
    pub carved_code: Vec<CarvedCode>,
    pub limitation_note: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CarvedCode {
    pub source_section: Vec<u8>,
    pub file_offset: usize,
    pub bytes: Vec<u8>,
    /// `PEC`/`LZMA` classic decode match against the original, in percent.
    pub classic_decode_pct: f64,
}

/// Structurally recovers a `PECompact` 2.x packed PE, carving code without byte-decoding.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if no `PECompact` marker/stub is present.
pub fn unpack_pecompact(packed: &[u8]) -> Result<PecompactReport> {
    let img: PeImage = parse_pe_image(packed)?;
    let pec2_off: Option<usize> = find_subsequence(packed, PEC2_MARKER);
    let pecompact2_off: Option<usize> = find_subsequence(packed, PECOMPACT2_MARKER);
    let seh_matched: bool = seh_stub_present(packed, &img);
    if pec2_off.is_none() && pecompact2_off.is_none() && !seh_matched {
        return Err(Error::SignatureDb(
            "PECompact: no PEC2/PECompact2 marker and no SEH stub - not a PECompact image"
                .to_owned(),
        ));
    }
    let mut carved_code: Vec<CarvedCode> = Vec::new();
    for sec in &img.sections {
        let executable: bool = sec.characteristics & 0x2000_0000 != 0;
        if !executable {
            continue;
        }
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        if start >= end {
            continue;
        }
        carved_code.push(CarvedCode {
            source_section: sec.name_trimmed().to_vec(),
            file_offset: start,
            bytes: packed[start..end].to_vec(),
            classic_decode_pct: 0.0,
        });
    }
    Ok(PecompactReport {
        recovery: PecompactRecovery::StructuralCarve,
        pec2_marker_offset: pec2_off,
        pecompact2_marker_offset: pecompact2_off,
        seh_stub_matched: seh_matched,
        entry_point_rva: img.entry_point_rva,
        carved_code,
        limitation_note: "PECompact 2.x installs an SEH decompressor stub and uses an in-stub \
codec that does not decode as the classic PEC/LZMA stream (classic decode 0%). Structural \
recovery only (PEC2/PECompact2 markers + SEH stub + carved executable section). Full byte \
recovery requires a stub_emu second pass (StubEvalPending)."
            .to_owned(),
    })
}

fn seh_stub_present(packed: &[u8], img: &PeImage) -> bool {
    if let Some(sec) = img.section_containing_rva(img.entry_point_rva) {
        let file_off: usize =
            sec.raw_pointer as usize + (img.entry_point_rva - sec.virtual_address) as usize;
        if masked_match_at(packed, file_off) {
            return true;
        }
    }
    let limit: usize = packed.len().saturating_sub(PECOMPACT_SEH_STUB.len());
    (0..=limit).any(|i: usize| masked_match_at(packed, i))
}

fn masked_match_at(packed: &[u8], off: usize) -> bool {
    let Some(window): Option<&[u8]> = packed.get(off..off + PECOMPACT_SEH_STUB.len()) else {
        return false;
    };
    window
        .iter()
        .zip(PECOMPACT_SEH_STUB.iter())
        .zip(PECOMPACT_SEH_MASK.iter())
        .all(|((b, pat), mask): ((&u8, &u8), &u8)| (b & mask) == (pat & mask))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pecompact_pe() {
        let buf: Vec<u8> = build_pe(&[(b".text", 0x1000, &[0u8; 16], 0xE000_0020)], 0x1000);
        assert!(unpack_pecompact(&buf).is_err());
    }

    #[test]
    fn structural_recovery_locates_markers_and_carves_code() {
        let mut text: Vec<u8> = PECOMPACT_SEH_STUB.to_vec();
        text[1] = 0x64;
        text[2] = 0xC5;
        text.extend_from_slice(b"PEC2");
        text.resize(128, 0xCC);
        text.extend_from_slice(b"PECompact2");
        let buf: Vec<u8> = build_pe(
            &[
                (b".text", 0x1000, &text, 0xE000_0020),
                (b".rsrc", 0x2000, &[0x11; 32], 0xC000_0040),
            ],
            0x1000,
        );
        let report: PecompactReport = unpack_pecompact(&buf).expect("unpack");
        assert_eq!(report.recovery, PecompactRecovery::StructuralCarve);
        assert!(report.pec2_marker_offset.is_some());
        assert!(report.pecompact2_marker_offset.is_some());
        assert!(report.seh_stub_matched);
        assert!(!report.carved_code.is_empty());
        for c in &report.carved_code {
            assert!(
                c.classic_decode_pct.abs() < f64::EPSILON,
                "PEC/LZMA classic decode must be honestly 0",
            );
        }
        assert!(
            report
                .carved_code
                .iter()
                .all(|c: &CarvedCode| c.source_section != b".rsrc"),
            "only executable sections are carved as code",
        );
    }

    fn build_pe(secs: &[(&[u8], u32, &[u8], u32)], ep: u32) -> Vec<u8> {
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
        for (i, (name, va, data, chars)) in secs.iter().enumerate() {
            let off: usize = sec_table + i * 40;
            let mut name_buf: [u8; 8] = [0u8; 8];
            name_buf[..name.len()].copy_from_slice(name);
            buf[off..off + 8].copy_from_slice(&name_buf);
            buf[off + 8..off + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
            buf[off + 16..off + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&(raw_cursor as u32).to_le_bytes());
            buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
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
