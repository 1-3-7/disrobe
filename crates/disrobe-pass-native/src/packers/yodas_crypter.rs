use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, find_subsequence, parse_pe_image};

const YODAS_CRYPTER_SECTION: &[u8] = b"yC";
const VERBATIM_SECTION_NAMES: &[&[u8]] = &[b".rsrc", b".reloc"];
const YC2_MARKER: &[u8] = b"yC2.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionRecovery {
    ByteIdentical,
    EncryptedCarve,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSection {
    pub name: Vec<u8>,
    pub virtual_address: u32,
    pub recovery: SectionRecovery,
    pub compared_bytes: usize,
    pub matching_bytes: usize,
    pub bytes: Vec<u8>,
}

impl RecoveredSection {
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn plaintext_pct(&self) -> f64 {
        if self.compared_bytes == 0 {
            return 0.0;
        }
        100.0 * self.matching_bytes as f64 / self.compared_bytes as f64
    }

    #[must_use]
    pub fn is_byte_identical(&self) -> bool {
        self.recovery == SectionRecovery::ByteIdentical
            && self.compared_bytes > 0
            && self.matching_bytes == self.compared_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YodasCrypterReport {
    pub has_yc2_marker: bool,
    pub stub_section_present: bool,
    pub recovered_sections: Vec<RecoveredSection>,
    pub limitation_note: String,
}

impl YodasCrypterReport {
    #[must_use]
    pub fn byte_identical_sections(&self) -> Vec<&RecoveredSection> {
        self.recovered_sections
            .iter()
            .filter(|s: &&RecoveredSection| s.is_byte_identical())
            .collect()
    }

    #[must_use]
    pub fn encrypted_sections(&self) -> Vec<&RecoveredSection> {
        self.recovered_sections
            .iter()
            .filter(|s: &&RecoveredSection| s.recovery == SectionRecovery::EncryptedCarve)
            .collect()
    }
}

/// Recovers a Yoda's Crypter 1.x/2.0 packed PE against its independent original.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if the `yC` stub section is absent.
pub fn unpack_yodas_crypter(packed: &[u8], original: &[u8]) -> Result<YodasCrypterReport> {
    let packed_img: PeImage = parse_pe_image(packed)?;
    let original_img: PeImage = parse_pe_image(original)?;
    let stub_present: bool = packed_img.section_by_name(YODAS_CRYPTER_SECTION).is_some();
    if !stub_present {
        return Err(Error::SignatureDb(
            "Yoda's Crypter: yC stub section absent - not a Yoda's Crypter image".to_owned(),
        ));
    }
    let has_marker: bool = find_subsequence(packed, YC2_MARKER).is_some();
    let mut recovered: Vec<RecoveredSection> = Vec::with_capacity(original_img.sections.len());
    for orig_sec in &original_img.sections {
        let name: Vec<u8> = orig_sec.name_trimmed().to_vec();
        let Some(packed_sec): Option<&PeSection> = packed_img.section_by_name(&name) else {
            continue;
        };
        let orig_raw: &[u8] = raw_bytes(original, orig_sec);
        let packed_raw: &[u8] = raw_bytes(packed, packed_sec);
        let compare_len: usize = orig_raw.len().min(packed_raw.len());
        let matching: usize = count_matching(&orig_raw[..compare_len], &packed_raw[..compare_len]);
        let is_verbatim: bool = VERBATIM_SECTION_NAMES.contains(&name.as_slice());
        let recovery: SectionRecovery = if is_verbatim {
            SectionRecovery::ByteIdentical
        } else {
            SectionRecovery::EncryptedCarve
        };
        let bytes: Vec<u8> = packed_raw[..compare_len].to_vec();
        recovered.push(RecoveredSection {
            name,
            virtual_address: orig_sec.virtual_address,
            recovery,
            compared_bytes: compare_len,
            matching_bytes: matching,
            bytes,
        });
    }
    Ok(YodasCrypterReport {
        has_yc2_marker: has_marker,
        stub_section_present: stub_present,
        recovered_sections: recovered,
        limitation_note: "Yoda's Crypter stores .rsrc/.reloc verbatim (byte-identical recovery) \
and stream-encrypts .text/.rdata/.data via the yC stub. Code/data are EncryptedCarve only; full \
plaintext requires yC stub emulation (future work). Reported plaintext fractions are measured raw \
overlap with the independent original, not rounded."
            .to_owned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YodasCrypterCarve {
    pub stub_section_present: bool,
    pub has_yc2_marker: bool,
    /// Verbatim-recovered sections (`.rsrc`/`.reloc`) carved byte-for-byte from the packed file.
    pub verbatim_sections: Vec<(Vec<u8>, Vec<u8>)>,
    /// The recovered partial image; encrypted code/data remain carved pending `yC` stub emulation.
    pub recovered_image: Vec<u8>,
}

/// Packed-only recovery carving the verbatim (`.rsrc`/`.reloc`) sections for the chain dispatch.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if the `yC` stub section is absent.
pub fn recover_yodas_crypter_carve(packed: &[u8]) -> Result<YodasCrypterCarve> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub_present: bool = img.section_by_name(YODAS_CRYPTER_SECTION).is_some();
    if !stub_present {
        return Err(Error::SignatureDb(
            "Yoda's Crypter: yC stub section absent - not a Yoda's Crypter image".to_owned(),
        ));
    }
    let has_marker: bool = find_subsequence(packed, YC2_MARKER).is_some();
    let mut verbatim_sections: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        let is_verbatim: bool = VERBATIM_SECTION_NAMES.contains(&name);
        if !is_verbatim {
            continue;
        }
        let body: &[u8] = raw_bytes(packed, sec);
        verbatim_sections.push((name.to_vec(), body.to_vec()));
    }
    Ok(YodasCrypterCarve {
        stub_section_present: stub_present,
        has_yc2_marker: has_marker,
        verbatim_sections,
        recovered_image: packed.to_vec(),
    })
}

#[inline]
fn raw_bytes<'a>(image: &'a [u8], sec: &PeSection) -> &'a [u8] {
    match sec.raw_range(image.len()) {
        Some((start, end)) => &image[start..end],
        None => {
            let start: usize = (sec.raw_pointer as usize).min(image.len());
            &image[start..]
        }
    }
}

#[inline]
fn count_matching(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .filter(|(x, y): &(&u8, &u8)| x == y)
        .count()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_image_without_yc_section() {
        let mut packed: Vec<u8> = build_pe_with_sections(&[(b".text", 0x1000, &[0u8; 16])]);
        let original: Vec<u8> = packed.clone();
        packed.truncate(packed.len());
        let r: Result<YodasCrypterReport> = unpack_yodas_crypter(&packed, &original);
        assert!(r.is_err(), "no yC section must reject");
    }

    #[test]
    fn verbatim_section_is_byte_identical() {
        let rsrc: [u8; 32] = core::array::from_fn(|i: usize| (i as u8).wrapping_mul(7));
        let original: Vec<u8> =
            build_pe_with_sections(&[(b".rsrc", 0x1000, &rsrc), (b".text", 0x2000, &[0xAA; 32])]);
        let packed: Vec<u8> = build_pe_with_sections(&[
            (b".rsrc", 0x1000, &rsrc),
            (b".text", 0x2000, &[0x11; 32]),
            (b"yC", 0x3000, &[0x60, 0xE8]),
        ]);
        let report: YodasCrypterReport = unpack_yodas_crypter(&packed, &original).expect("unpack");
        let rsrc_sec: &RecoveredSection = report
            .recovered_sections
            .iter()
            .find(|s: &&RecoveredSection| s.name == b".rsrc")
            .expect(".rsrc recovered");
        assert!(rsrc_sec.is_byte_identical());
        assert!((rsrc_sec.plaintext_pct() - 100.0).abs() < f64::EPSILON);
        let text_sec: &RecoveredSection = report
            .recovered_sections
            .iter()
            .find(|s: &&RecoveredSection| s.name == b".text")
            .expect(".text recovered");
        assert_eq!(text_sec.recovery, SectionRecovery::EncryptedCarve);
        assert!(text_sec.plaintext_pct() < 100.0);
    }

    fn build_pe_with_sections(secs: &[(&[u8], u32, &[u8])]) -> Vec<u8> {
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
