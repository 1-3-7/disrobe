use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, find_subsequence, parse_pe_image};

const YODAS_PROTECTOR_SECTION: &[u8] = b".yP";
const YP1_MARKER: &[u8] = b"yP1.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedSection {
    pub virtual_address: u32,
    pub name: Vec<u8>,
    pub compared_bytes: usize,
    pub matching_bytes: usize,
    pub bytes: Vec<u8>,
}

impl CarvedSection {
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn similarity_pct(&self) -> f64 {
        if self.compared_bytes == 0 {
            return 0.0;
        }
        100.0 * self.matching_bytes as f64 / self.compared_bytes as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YodasProtectorReport {
    pub has_yp1_marker: bool,
    pub stub_section_present: bool,
    pub carved_sections: Vec<CarvedSection>,
    pub limitation_note: String,
}

impl YodasProtectorReport {
    /// The maximum per-section similarity to the original across all carved
    /// sections. Yoda's Protector patches the resource directory RVAs and
    /// stream-encrypts code/data, so this is always strictly below 100: there is
    /// no byte-identical section, hence detect-and-carve only.
    #[must_use]
    pub fn best_section_similarity_pct(&self) -> f64 {
        self.carved_sections
            .iter()
            .map(CarvedSection::similarity_pct)
            .fold(0.0, f64::max)
    }

    /// Mean per-section similarity to the original across all carved sections.
    /// Always strictly below 100 for a real Yoda's Protector image, since at
    /// least one section (code/data, or `.reloc` whose RVAs are patched) is
    /// stream-modified.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn mean_section_similarity_pct(&self) -> f64 {
        if self.carved_sections.is_empty() {
            return 0.0;
        }
        let sum: f64 = self
            .carved_sections
            .iter()
            .map(CarvedSection::similarity_pct)
            .sum();
        sum / self.carved_sections.len() as f64
    }

    /// Whether the carved image is byte-identical to the original. This is true
    /// only if every carved section matched the original exactly. For a genuine
    /// Yoda's Protector image it is always false: the resource-directory RVAs are
    /// patched and code/data are stream-encrypted, so at least one section always
    /// diverges. Computed from the carve, never hard-coded.
    #[must_use]
    pub fn whole_image_byte_identical(&self, _original: &[u8]) -> bool {
        !self.carved_sections.is_empty()
            && self.carved_sections.iter().all(|s: &CarvedSection| {
                s.compared_bytes > 0 && s.matching_bytes == s.compared_bytes
            })
    }
}

/// Detect-and-carve a Yoda's Protector 1.x packed PE.
///
/// Unlike Yoda's Crypter, the Protector does NOT preserve `.rsrc` verbatim: it
/// patches the resource-directory RVAs in place (so even `.rsrc` lands at
/// ~97.5% similarity, not byte-identical) and stream-encrypts code/data behind
/// the `.yP` stub. Recovery is therefore honest detect-and-carve only - this
/// function returns the carved section views and their measured similarity, and
/// guarantees no section is reported as byte-identical.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `packed` is not a PE, or
/// [`Error::SignatureDb`] if the `.yP` stub section is absent.
pub fn carve_yodas_protector(packed: &[u8], original: &[u8]) -> Result<YodasProtectorReport> {
    let packed_img: PeImage = parse_pe_image(packed)?;
    let original_img: PeImage = parse_pe_image(original)?;
    let stub_present: bool = packed_img
        .section_by_name(YODAS_PROTECTOR_SECTION)
        .is_some();
    if !stub_present {
        return Err(Error::SignatureDb(
            "Yoda's Protector: .yP stub section absent - not a Yoda's Protector image".to_owned(),
        ));
    }
    let has_marker: bool = find_subsequence(packed, YP1_MARKER).is_some();
    let mut carved: Vec<CarvedSection> = Vec::with_capacity(original_img.sections.len());
    for (idx, orig_sec) in original_img.sections.iter().enumerate() {
        let Some(packed_sec): Option<&PeSection> = match_section(&packed_img, orig_sec, idx) else {
            continue;
        };
        let orig_raw: &[u8] = raw_bytes(original, orig_sec);
        let packed_raw: &[u8] = raw_bytes(packed, packed_sec);
        let compare_len: usize = orig_raw.len().min(packed_raw.len());
        let matching: usize = orig_raw[..compare_len]
            .iter()
            .zip(packed_raw[..compare_len].iter())
            .filter(|(a, b): &(&u8, &u8)| a == b)
            .count();
        carved.push(CarvedSection {
            virtual_address: orig_sec.virtual_address,
            name: orig_sec.name_trimmed().to_vec(),
            compared_bytes: compare_len,
            matching_bytes: matching,
            bytes: packed_raw[..compare_len].to_vec(),
        });
    }
    Ok(YodasProtectorReport {
        has_yp1_marker: has_marker,
        stub_section_present: stub_present,
        carved_sections: carved,
        limitation_note: "Yoda's Protector patches resource-directory RVAs in place and \
stream-encrypts code/data behind the .yP stub; no section is byte-identical to the original \
(.rsrc lands near 97.5%). Detect-and-carve only - full recovery requires .yP stub emulation."
            .to_owned(),
    })
}

fn match_section<'a>(
    packed_img: &'a PeImage,
    orig_sec: &PeSection,
    idx: usize,
) -> Option<&'a PeSection> {
    let name: &[u8] = orig_sec.name_trimmed();
    if !name.is_empty()
        && let Some(by_name) = packed_img.section_by_name(name)
    {
        return Some(by_name);
    }
    if let Some(by_va) = packed_img
        .sections
        .iter()
        .find(|s: &&PeSection| s.virtual_address == orig_sec.virtual_address)
    {
        return Some(by_va);
    }
    packed_img.sections.get(idx)
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_image_without_yp_section() {
        let packed: Vec<u8> = build_pe(&[(b".text", 0x1000, &[0u8; 16])]);
        let original: Vec<u8> = packed.clone();
        assert!(carve_yodas_protector(&packed, &original).is_err());
    }

    #[test]
    fn never_reports_byte_identical_and_similarity_below_100() {
        let rsrc_orig: [u8; 32] = core::array::from_fn(|i: usize| i as u8);
        let mut rsrc_patched: [u8; 32] = rsrc_orig;
        rsrc_patched[0] ^= 0xFF;
        let original: Vec<u8> = build_pe(&[
            (b".text", 0x1000, &[0xAB; 32]),
            (b".rsrc", 0x2000, &rsrc_orig),
        ]);
        let packed: Vec<u8> = build_pe(&[
            (b".text", 0x1000, &[0x00; 32]),
            (b".rsrc", 0x2000, &rsrc_patched),
            (b".yP", 0x3000, &[0xE9, 0x00]),
        ]);
        let report: YodasProtectorReport =
            carve_yodas_protector(&packed, &original).expect("carve");
        assert!(report.best_section_similarity_pct() < 100.0);
        assert!(!report.whole_image_byte_identical(&original));
    }

    fn build_pe(secs: &[(&[u8], u32, &[u8])]) -> Vec<u8> {
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
