use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use crate::stub_emu::mem::MAX_MAP_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SectionRole {
    Content,

    LoaderRebuilt,

    Stub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GranuleRecovery {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub role: SectionRole,

    pub compared: usize,

    pub matching: usize,

    pub first_mismatch_rel: Option<u32>,

    pub mismatch_runs: u32,
}

impl GranuleRecovery {
    #[must_use]
    pub fn recovery_pct(&self) -> f64 {
        if self.compared == 0 {
            return 0.0;
        }
        100.0 * self.matching as f64 / self.compared as f64
    }

    #[must_use]
    pub const fn is_byte_identical(&self) -> bool {
        self.compared > 0 && self.matching == self.compared
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionRecoveryReport {
    pub sections: Vec<GranuleRecovery>,

    pub content_matching: usize,

    pub content_compared: usize,
}

impl SectionRecoveryReport {
    #[must_use]
    pub fn content_recovery_pct(&self) -> f64 {
        if self.content_compared == 0 {
            return 0.0;
        }
        100.0 * self.content_matching as f64 / self.content_compared as f64
    }

    #[must_use]
    pub fn mismatching_content_sections(&self) -> Vec<&GranuleRecovery> {
        let mut rows: Vec<&GranuleRecovery> = self
            .sections
            .iter()
            .filter(|s: &&GranuleRecovery| {
                s.role == SectionRole::Content && !s.is_byte_identical() && s.compared > 0
            })
            .collect();
        rows.sort_by(|a: &&GranuleRecovery, b: &&GranuleRecovery| {
            a.recovery_pct()
                .partial_cmp(&b.recovery_pct())
                .unwrap_or(core::cmp::Ordering::Equal)
        });
        rows
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut out: String = String::with_capacity(self.sections.len() * 64);
        for s in &self.sections {
            out.push_str(&format!(
                "{:<10} va=0x{:08x} vsz=0x{:06x} role={:?} {}/{} ({:.2}%) runs={} first_mm={}\n",
                s.name,
                s.virtual_address,
                s.virtual_size,
                s.role,
                s.matching,
                s.compared,
                s.recovery_pct(),
                s.mismatch_runs,
                s.first_mismatch_rel
                    .map_or_else(|| "-".to_owned(), |v: u32| format!("0x{v:x}")),
            ));
        }
        out.push_str(&format!(
            "CONTENT {}/{} ({:.2}%)\n",
            self.content_matching,
            self.content_compared,
            self.content_recovery_pct(),
        ));
        out
    }
}

const LOADER_REBUILT: &[&[u8]] = &[b".reloc", b".idata"];

const KNOWN_CONTENT: &[&[u8]] = &[
    b".text", b".rdata", b".data", b".rsrc", b".didat", b".pdata", b".CRT", b".tls", b".xdata",
    b".edata", b".gfids", b".00cfg",
];

fn classify_section(name: &[u8], stub_names: &[&[u8]]) -> SectionRole {
    if stub_names.contains(&name) {
        return SectionRole::Stub;
    }
    if LOADER_REBUILT.contains(&name) {
        return SectionRole::LoaderRebuilt;
    }
    if KNOWN_CONTENT.contains(&name) || name.starts_with(b".text") {
        return SectionRole::Content;
    }
    SectionRole::LoaderRebuilt
}

pub const EMULATED_IMAGE_EXPANSION_LIMIT: u64 = 4096;
const EMULATED_IMAGE_FLOOR_BYTES: u64 = 0x1_0000;

#[must_use]
pub fn last_section_end_va(img: &PeImage) -> u64 {
    img.sections
        .iter()
        .map(|s: &PeSection| {
            u64::from(s.virtual_address).saturating_add(u64::from(s.virtual_size.max(s.raw_size)))
        })
        .max()
        .unwrap_or(0)
}

#[must_use]
pub fn emulated_image_capacity(img: &PeImage, file_len: usize) -> u64 {
    let declared: u64 = u64::from(img.size_of_image).max(last_section_end_va(img));
    let justified: u64 = u64::try_from(file_len)
        .unwrap_or(u64::MAX)
        .saturating_mul(EMULATED_IMAGE_EXPANSION_LIMIT)
        .max(EMULATED_IMAGE_FLOOR_BYTES);
    declared.min(justified).min(MAX_MAP_BYTES)
}

pub fn build_loaded_image(original: &[u8], capacity: usize) -> Result<Vec<u8>> {
    let img: PeImage = parse_pe_image(original)?;
    let bounded: usize = capacity.min(MAX_MAP_BYTES as usize);
    let mut buf: Vec<u8> = vec![0u8; bounded];
    let hdr: usize = 0x1000.min(original.len()).min(bounded);
    buf[..hdr].copy_from_slice(&original[..hdr]);
    for sec in &img.sections {
        let dst: usize = sec.virtual_address as usize;
        if dst >= bounded {
            continue;
        }
        let raw_avail: usize =
            (sec.raw_size as usize).min(original.len().saturating_sub(sec.raw_pointer as usize));
        let copy: usize = raw_avail.min(sec.virtual_size as usize).min(bounded - dst);
        if copy == 0 {
            continue;
        }
        let src: usize = sec.raw_pointer as usize;
        buf[dst..dst + copy].copy_from_slice(&original[src..src + copy]);
    }
    Ok(buf)
}

pub fn section_recovery_report(
    original: &[u8],
    recovered: &[u8],
    stub_names: &[&[u8]],
) -> Result<SectionRecoveryReport> {
    let img: PeImage = parse_pe_image(original)?;
    let baseline: Vec<u8> = build_loaded_image(original, recovered.len())?;
    let compare_len: usize = recovered.len().min(baseline.len());

    let mut rows: Vec<GranuleRecovery> = Vec::with_capacity(img.sections.len());
    let mut content_matching: usize = 0;
    let mut content_compared: usize = 0;

    for sec in &img.sections {
        let name_bytes: &[u8] = sec.name_trimmed();
        let role: SectionRole = classify_section(name_bytes, stub_names);
        let off: usize = sec.virtual_address as usize;
        let span_end: usize = (off + sec.virtual_size as usize).min(compare_len);
        let span: SpanStats = compare_span(recovered, &baseline, off, span_end);
        if role == SectionRole::Content {
            content_matching += span.matching;
            content_compared += span.compared;
        }
        rows.push(GranuleRecovery {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            virtual_address: sec.virtual_address,
            virtual_size: sec.virtual_size,
            raw_size: sec.raw_size,
            role,
            compared: span.compared,
            matching: span.matching,
            first_mismatch_rel: span.first_mismatch_rel,
            mismatch_runs: span.mismatch_runs,
        });
    }

    Ok(SectionRecoveryReport {
        sections: rows,
        content_matching,
        content_compared,
    })
}

struct SpanStats {
    matching: usize,
    compared: usize,
    first_mismatch_rel: Option<u32>,
    mismatch_runs: u32,
}

fn compare_span(recovered: &[u8], reference: &[u8], lo: usize, hi: usize) -> SpanStats {
    let mut matching: usize = 0;
    let mut compared: usize = 0;
    let mut first_mismatch_rel: Option<u32> = None;
    let mut mismatch_runs: u32 = 0;
    let mut in_run: bool = false;
    let end: usize = hi.min(recovered.len()).min(reference.len());
    let mut j: usize = lo;
    while j < end {
        compared += 1;
        if recovered[j] == reference[j] {
            matching += 1;
            in_run = false;
        } else {
            if first_mismatch_rel.is_none() {
                first_mismatch_rel = Some((j - lo) as u32);
            }
            if !in_run {
                mismatch_runs += 1;
                in_run = true;
            }
        }
        j += 1;
    }
    SpanStats {
        matching,
        compared,
        first_mismatch_rel,
        mismatch_runs,
    }
}

pub fn file_image_section_report(
    original: &[u8],
    recovered: &[u8],
    file_align: usize,
    stub_names: &[&[u8]],
) -> Result<SectionRecoveryReport> {
    let img: PeImage = parse_pe_image(original)?;
    let mut rows: Vec<GranuleRecovery> = Vec::with_capacity(img.sections.len());
    let mut content_matching: usize = 0;
    let mut content_compared: usize = 0;

    for sec in &img.sections {
        let name_bytes: &[u8] = sec.name_trimmed();
        let role: SectionRole = classify_section(name_bytes, stub_names);
        let raw_off: usize = sec.raw_pointer as usize;
        let raw_sz: usize = sec.raw_size as usize;
        let span: SpanStats = if raw_off >= file_align {
            let dec_lo: usize = raw_off - file_align;
            let dec_hi: usize = dec_lo + raw_sz;
            compare_span_offset(recovered, original, dec_lo, dec_hi, raw_off)
        } else {
            SpanStats {
                matching: 0,
                compared: 0,
                first_mismatch_rel: None,
                mismatch_runs: 0,
            }
        };
        if role == SectionRole::Content {
            content_matching += span.matching;
            content_compared += span.compared;
        }
        rows.push(GranuleRecovery {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            virtual_address: sec.raw_pointer,
            virtual_size: sec.virtual_size,
            raw_size: sec.raw_size,
            role,
            compared: span.compared,
            matching: span.matching,
            first_mismatch_rel: span.first_mismatch_rel,
            mismatch_runs: span.mismatch_runs,
        });
    }

    Ok(SectionRecoveryReport {
        sections: rows,
        content_matching,
        content_compared,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IatReconstructionReport {
    pub slots_examined: usize,
    pub slots_rewritten: usize,
}

const IMPORT_BY_ORDINAL_FLAG: u32 = 0x8000_0000;

#[must_use]
pub fn reconstruct_import_address_table(
    recovered: &mut [u8],
    resolved_synth_to_original: &BTreeMap<u32, u32>,
) -> IatReconstructionReport {
    let mut report: IatReconstructionReport = IatReconstructionReport::default();
    if resolved_synth_to_original.is_empty() || recovered.len() < 4 {
        return report;
    }
    let scan_end: usize = recovered.len() - 4;
    let mut off: usize = 0;
    while off <= scan_end {
        let value: u32 = u32::from_le_bytes([
            recovered[off],
            recovered[off + 1],
            recovered[off + 2],
            recovered[off + 3],
        ]);
        let Some(&original): Option<&u32> = resolved_synth_to_original.get(&value) else {
            off += 4;
            continue;
        };
        report.slots_examined += 1;
        let acceptable: bool = if original & IMPORT_BY_ORDINAL_FLAG != 0 {
            true
        } else {
            is_valid_import_by_name(recovered, original)
        };
        if acceptable {
            recovered[off..off + 4].copy_from_slice(&original.to_le_bytes());
            report.slots_rewritten += 1;
        }
        off += 4;
    }
    report
}

fn is_valid_import_by_name(image: &[u8], name_entry_rva: u32) -> bool {
    let name_off: usize = name_entry_rva as usize + 2;
    if name_off >= image.len() {
        return false;
    }
    let mut len: usize = 0;
    let mut k: usize = name_off;
    while k < image.len() && image[k] != 0 {
        if !image[k].is_ascii_graphic() {
            return false;
        }
        len += 1;
        k += 1;
        if len > 255 {
            return false;
        }
    }
    len >= 2
}

fn compare_span_offset(
    recovered: &[u8],
    original: &[u8],
    dec_lo: usize,
    dec_hi: usize,
    orig_lo: usize,
) -> SpanStats {
    let mut matching: usize = 0;
    let mut compared: usize = 0;
    let mut first_mismatch_rel: Option<u32> = None;
    let mut mismatch_runs: u32 = 0;
    let mut in_run: bool = false;
    let len: usize = (dec_hi - dec_lo)
        .min(recovered.len().saturating_sub(dec_lo))
        .min(original.len().saturating_sub(orig_lo));
    for k in 0..len {
        compared += 1;
        if recovered[dec_lo + k] == original[orig_lo + k] {
            matching += 1;
            in_run = false;
        } else {
            if first_mismatch_rel.is_none() {
                first_mismatch_rel = Some(k as u32);
            }
            if !in_run {
                mismatch_runs += 1;
                in_run = true;
            }
        }
    }
    SpanStats {
        matching,
        compared,
        first_mismatch_rel,
        mismatch_runs,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn pe_with_sections(secs: &[(&[u8], u32, u32, &[u8])]) -> Vec<u8> {
        let opt_size: usize = 0xE0;
        let sec_off: usize = 0x80 + 4 + 20 + opt_size;
        let file_len: usize = 0x4000;
        let mut buf: Vec<u8> = vec![0u8; file_len];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff: usize = pe_off + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(secs.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        for (i, (name, va, raw_off, body)) in secs.iter().enumerate() {
            let base: usize = sec_off + i * 40;
            buf[base..base + name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
            buf[base + 8..base + 12].copy_from_slice(&(body.len() as u32).to_le_bytes());
            buf[base + 12..base + 16].copy_from_slice(&va.to_le_bytes());
            buf[base + 16..base + 20].copy_from_slice(&(body.len() as u32).to_le_bytes());
            buf[base + 20..base + 24].copy_from_slice(&raw_off.to_le_bytes());
            let ro: usize = *raw_off as usize;
            buf[ro..ro + body.len()].copy_from_slice(body);
        }
        buf
    }

    #[test]
    fn identical_recovery_is_100_content() {
        let body_text: [u8; 16] = [0xAA; 16];
        let body_reloc: [u8; 16] = [0xBB; 16];
        let orig: Vec<u8> = pe_with_sections(&[
            (b".text", 0x1000, 0x400, &body_text),
            (b".reloc", 0x2000, 0x600, &body_reloc),
        ]);
        let recovered: Vec<u8> = build_loaded_image(&orig, 0x4000).expect("baseline");
        let report: SectionRecoveryReport =
            section_recovery_report(&orig, &recovered, &[]).expect("report");
        assert!((report.content_recovery_pct() - 100.0).abs() < f64::EPSILON);
        let text: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".text")
            .expect(".text row");
        assert_eq!(text.role, SectionRole::Content);
        assert!(text.is_byte_identical());
        let reloc: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".reloc")
            .expect(".reloc row");
        assert_eq!(reloc.role, SectionRole::LoaderRebuilt);
    }

    #[test]
    fn mismatch_in_content_section_is_isolated() {
        let body_text: [u8; 32] = [0xAA; 32];
        let orig: Vec<u8> = pe_with_sections(&[
            (b".text", 0x1000, 0x400, &body_text),
            (b".data", 0x2000, 0x600, &[0xCC; 16]),
        ]);
        let mut recovered: Vec<u8> = build_loaded_image(&orig, 0x4000).expect("baseline");
        recovered[0x1000 + 4] ^= 0xFF;
        recovered[0x1000 + 5] ^= 0xFF;
        recovered[0x1000 + 20] ^= 0xFF;
        let report: SectionRecoveryReport =
            section_recovery_report(&orig, &recovered, &[]).expect("report");
        let worst: Vec<&GranuleRecovery> = report.mismatching_content_sections();
        assert_eq!(worst.len(), 1);
        assert_eq!(worst[0].name, ".text");
        assert_eq!(worst[0].first_mismatch_rel, Some(4));
        assert_eq!(worst[0].mismatch_runs, 2);
        let data: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".data")
            .expect(".data row");
        assert!(data.is_byte_identical());
    }

    #[test]
    fn stub_section_excluded_from_content() {
        let orig: Vec<u8> = pe_with_sections(&[
            (b".text", 0x1000, 0x400, &[0xAA; 16]),
            (b".aspack", 0x2000, 0x600, &[0x00; 16]),
        ]);
        let recovered: Vec<u8> = build_loaded_image(&orig, 0x4000).expect("baseline");
        let report: SectionRecoveryReport =
            section_recovery_report(&orig, &recovered, &[b".aspack"]).expect("report");
        let stub: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".aspack")
            .expect(".aspack row");
        assert_eq!(stub.role, SectionRole::Stub);
        assert!((report.content_recovery_pct() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn file_image_report_aligns_by_raw_offset() {
        let body_text: [u8; 32] = [0xAA; 32];
        let orig: Vec<u8> = pe_with_sections(&[
            (b".text", 0x1000, 0x400, &body_text),
            (b".data", 0x2000, 0x600, &[0xCC; 16]),
        ]);
        let file_align: usize = 0x400;
        let mut recovered: Vec<u8> = vec![0u8; orig.len() - file_align];
        recovered.copy_from_slice(&orig[file_align..]);
        let report: SectionRecoveryReport =
            file_image_section_report(&orig, &recovered, file_align, &[]).expect("file report");
        assert!((report.content_recovery_pct() - 100.0).abs() < f64::EPSILON);
        let text: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".text")
            .expect(".text row");
        assert_eq!(text.virtual_address, 0x400);
        assert!(text.is_byte_identical());
    }

    #[test]
    fn iat_reconstruction_rewrites_synth_slots_to_name_rvas() {
        let mut image: Vec<u8> = vec![0u8; 0x200];
        let name_rva: u32 = 0x100;
        image[name_rva as usize] = 0x00;
        image[name_rva as usize + 1] = 0x00;
        image[name_rva as usize + 2..name_rva as usize + 2 + 8].copy_from_slice(b"WriteFil");
        let synth: u32 = 0xFE01_0030;
        let iat_off: usize = 0x40;
        image[iat_off..iat_off + 4].copy_from_slice(&synth.to_le_bytes());
        let mut map: BTreeMap<u32, u32> = BTreeMap::new();
        map.insert(synth, name_rva);
        let report: IatReconstructionReport = reconstruct_import_address_table(&mut image, &map);
        assert_eq!(report.slots_rewritten, 1);
        let written: u32 = u32::from_le_bytes([
            image[iat_off],
            image[iat_off + 1],
            image[iat_off + 2],
            image[iat_off + 3],
        ]);
        assert_eq!(
            written, name_rva,
            "synth slot must become the name-entry RVA"
        );
    }

    #[test]
    fn iat_reconstruction_skips_unmapped_or_unprintable_targets() {
        let mut image: Vec<u8> = vec![0u8; 0x80];
        let synth: u32 = 0xFE01_0000;
        image[0x10..0x14].copy_from_slice(&synth.to_le_bytes());
        let mut map: BTreeMap<u32, u32> = BTreeMap::new();
        map.insert(synth, 0x0040);
        let report: IatReconstructionReport = reconstruct_import_address_table(&mut image, &map);
        assert_eq!(
            report.slots_rewritten, 0,
            "a slot pointing at a non-printable / zero name region must not be rewritten",
        );
        assert_eq!(
            u32::from_le_bytes([image[0x10], image[0x11], image[0x12], image[0x13]]),
            synth,
            "unverified slot must be left untouched, never fabricated",
        );
    }

    #[test]
    fn file_image_report_isolates_zeroed_iat_zone() {
        let mut data_body: [u8; 32] = [0xCC; 32];
        data_body[..8].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let orig: Vec<u8> = pe_with_sections(&[
            (b".text", 0x1000, 0x400, &[0xAA; 32]),
            (b".data", 0x2000, 0x600, &data_body),
        ]);
        let file_align: usize = 0x400;
        let mut recovered: Vec<u8> = vec![0u8; orig.len() - file_align];
        recovered.copy_from_slice(&orig[file_align..]);
        for b in &mut recovered[(0x600 - file_align)..(0x600 - file_align + 8)] {
            *b = 0;
        }
        let report: SectionRecoveryReport =
            file_image_section_report(&orig, &recovered, file_align, &[]).expect("file report");
        let text: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".text")
            .expect(".text row");
        assert!(
            text.is_byte_identical(),
            ".text (pure code) must stay byte-identical even when .data IAT zone is zeroed",
        );
        let worst: Vec<&GranuleRecovery> = report.mismatching_content_sections();
        assert_eq!(worst.len(), 1);
        assert_eq!(worst[0].name, ".data");
        assert_eq!(worst[0].first_mismatch_rel, Some(0));
    }
}
