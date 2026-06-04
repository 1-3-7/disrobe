//! Section-granule recovery comparison for lossless packers.
//!
//! Lossless packers (MPRESS / `ASPack` / `PECompact` / `NSPack` / MEW / FSG) compress
//! the original image and restore it - in principle - byte-for-byte. When a
//! recovered memory image falls short of 100%, the residual is almost never
//! uniform: it concentrates in a handful of sections the runtime loader
//! *rebuilds* rather than restores from the compressed body (`.reloc` fixups,
//! `.idata`/`.rdata` IAT thunk slots, `.rsrc` resource directories the stub
//! re-lays). A whole-image percentage hides that structure.
//!
//! [`section_recovery_report`] decomposes a recovered VA-indexed image against
//! the **independent pre-packed original** at section granularity, so callers
//! can see exactly which section is responsible for a mismatch and decide
//! whether it is a genuine decoder bug (a content section under 100%) or an
//! expected loader-rebuilt zone (excluded from the content oracle).
//!
//! The oracle is non-circular by construction: the baseline is the original's
//! own loaded layout ([`build_loaded_image`]), derived only from the
//! independent `original.exe`, never from the packed sample or the recovered
//! output. This mirrors the convention already used by the ASPack/PECompact
//! phase-2 content oracle, lifted here so every lossless packer shares one
//! audited comparator.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

/// How a section is treated by the content oracle.
///
/// The distinction is load-bearing: a [`SectionRole::Content`] section under
/// 100% is a decoder defect to be closed; a [`SectionRole::LoaderRebuilt`] or
/// [`SectionRole::Stub`] section is expected to diverge because its bytes are
/// synthesised by the runtime loader/stub and are physically absent from the
/// compressed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SectionRole {
    /// `.text`/`.rdata`/`.data`/`.rsrc`/`.didat` - restored verbatim from the
    /// compressed body; counted toward the content-recovery oracle.
    Content,
    /// `.reloc`/`.idata` and any name the caller flags - rebuilt by the loader
    /// (relocations applied, IAT thunks resolved to live pointers); excluded
    /// from the content oracle but still reported.
    LoaderRebuilt,
    /// The packer's own stub/metadata section (`.aspack`/`nsp0`/`MEW...`);
    /// has no original counterpart and is excluded from the content oracle.
    Stub,
}

/// Per-section recovery row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GranuleRecovery {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub role: SectionRole,
    /// Bytes compared in this section (clamped to the smaller of recovered and
    /// baseline length).
    pub compared: usize,
    /// Bytes that matched the original's loaded baseline.
    pub matching: usize,
    /// Offset of the first mismatching byte within the section, as a section-
    /// relative delta, or `None` when the section is byte-identical.
    pub first_mismatch_rel: Option<u32>,
    /// Count of contiguous mismatch runs - a single large run signals decoder
    /// drift at one point; many scattered runs signal IAT/reloc-slot patching.
    pub mismatch_runs: u32,
}

impl GranuleRecovery {
    /// Percentage of compared bytes that matched, `0.0` when nothing compared.
    #[must_use]
    pub fn recovery_pct(&self) -> f64 {
        if self.compared == 0 {
            return 0.0;
        }
        100.0 * self.matching as f64 / self.compared as f64
    }

    /// True when the section is byte-identical to the original over its
    /// compared span.
    #[must_use]
    pub const fn is_byte_identical(&self) -> bool {
        self.compared > 0 && self.matching == self.compared
    }
}

/// Whole-image section breakdown of a recovered memory image against the
/// independent original's loaded layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionRecoveryReport {
    pub sections: Vec<GranuleRecovery>,
    /// Sum of matched bytes across [`SectionRole::Content`] sections only.
    pub content_matching: usize,
    /// Sum of compared bytes across [`SectionRole::Content`] sections only.
    pub content_compared: usize,
}

impl SectionRecoveryReport {
    /// Content-only recovery percentage - the non-circular oracle excluding
    /// loader-rebuilt and stub sections.
    #[must_use]
    pub fn content_recovery_pct(&self) -> f64 {
        if self.content_compared == 0 {
            return 0.0;
        }
        100.0 * self.content_matching as f64 / self.content_compared as f64
    }

    /// The content sections that are not byte-identical, worst first - the
    /// direct answer to "which section is costing me the last few percent".
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

    /// Render a compact one-line-per-section table for diagnostics.
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

/// Sections rebuilt by the Windows loader rather than restored from the
/// compressed body. Excluded from the content oracle across all packers.
const LOADER_REBUILT: &[&[u8]] = &[b".reloc", b".idata"];

/// Default content section names. A section not in this set, not loader-rebuilt,
/// and not flagged as a stub is still classified [`SectionRole::Content`] when
/// it is a standard PE content name; otherwise it is treated as
/// [`SectionRole::LoaderRebuilt`] to keep the oracle conservative (a section we
/// cannot positively identify as content is never allowed to inflate the score).
const KNOWN_CONTENT: &[&[u8]] = &[
    b".text", b".rdata", b".data", b".rsrc", b".didat", b".pdata", b".CRT", b".tls", b".xdata",
    b".edata", b".gfids", b".00cfg",
];

/// Classify a section by name given the caller's packer-specific stub names.
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

/// Build a PE's loaded memory image: copy the headers plus each section's raw
/// body to its virtual address, exactly as the Windows loader maps a
/// freshly-linked PE.
///
/// This is the non-circular baseline - derived only from the independent
/// `original` bytes. `capacity` bounds the output (use the recovered image's
/// `size_of_image`/last-section-end so both images share one coordinate space).
///
/// # Errors
///
/// Propagates [`crate::error::Error`] from PE parsing of `original`.
pub fn build_loaded_image(original: &[u8], capacity: usize) -> Result<Vec<u8>> {
    let img: PeImage = parse_pe_image(original)?;
    let mut buf: Vec<u8> = vec![0u8; capacity];
    let hdr: usize = 0x1000.min(original.len()).min(capacity);
    buf[..hdr].copy_from_slice(&original[..hdr]);
    for sec in &img.sections {
        let dst: usize = sec.virtual_address as usize;
        if dst >= capacity {
            continue;
        }
        let raw_avail: usize =
            (sec.raw_size as usize).min(original.len().saturating_sub(sec.raw_pointer as usize));
        let copy: usize = raw_avail.min(sec.virtual_size as usize).min(capacity - dst);
        if copy == 0 {
            continue;
        }
        let src: usize = sec.raw_pointer as usize;
        buf[dst..dst + copy].copy_from_slice(&original[src..src + copy]);
    }
    Ok(buf)
}

/// Compare a recovered VA-indexed memory image against the independent original
/// at section granularity.
///
/// `recovered` is the unpacker's loaded image (`recovered_memory_image` /
/// `raw_image`), indexed by virtual address from `image_base`. `original` is the
/// independent pre-packed `original.exe`. `stub_names` are the packer's own
/// section names (`.aspack`, `nsp0`, the MEW stub name, ...) which have no
/// original counterpart and must not count toward the oracle.
///
/// Section geometry is taken from the **original's** section table (the packed
/// sample's table is destroyed/rewritten by the packer), so each original
/// section is located at its own VA inside the recovered image and compared
/// against the original's loaded baseline at the same VA.
///
/// # Errors
///
/// Propagates [`crate::error::Error`] from PE parsing of `original`.
pub fn section_recovery_report(
    original: &[u8],
    recovered: &[u8],
    stub_names: &[&[u8]],
) -> Result<SectionRecoveryReport> {
    let img: PeImage = parse_pe_image(original)?;
    let capacity: usize = recovered.len().max(loaded_capacity(&img));
    let baseline: Vec<u8> = build_loaded_image(original, capacity)?;
    let compare_len: usize = recovered.len().min(baseline.len());

    let mut rows: Vec<GranuleRecovery> = Vec::with_capacity(img.sections.len());
    let mut content_matching: usize = 0;
    let mut content_compared: usize = 0;

    for sec in &img.sections {
        let name_bytes: &[u8] = sec.name_trimmed();
        let role: SectionRole = classify_section(name_bytes, stub_names);
        let off: usize = sec.virtual_address as usize;
        let span_end: usize = (off + sec.virtual_size as usize).min(compare_len);
        let (mut matching, mut compared): (usize, usize) = (0, 0);
        let mut first_mismatch_rel: Option<u32> = None;
        let mut mismatch_runs: u32 = 0;
        let mut in_run: bool = false;
        if off < span_end {
            for j in off..span_end {
                compared += 1;
                if recovered[j] == baseline[j] {
                    matching += 1;
                    in_run = false;
                } else {
                    if first_mismatch_rel.is_none() {
                        first_mismatch_rel = Some((j - off) as u32);
                    }
                    if !in_run {
                        mismatch_runs += 1;
                        in_run = true;
                    }
                }
            }
        }
        if role == SectionRole::Content {
            content_matching += matching;
            content_compared += compared;
        }
        rows.push(GranuleRecovery {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            virtual_address: sec.virtual_address,
            virtual_size: sec.virtual_size,
            raw_size: sec.raw_size,
            role,
            compared,
            matching,
            first_mismatch_rel,
            mismatch_runs,
        });
    }

    Ok(SectionRecoveryReport {
        sections: rows,
        content_matching,
        content_compared,
    })
}

fn loaded_capacity(img: &PeImage) -> usize {
    let last: u64 = img
        .sections
        .iter()
        .map(|s: &PeSection| {
            u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size))
        })
        .max()
        .unwrap_or(0);
    u64::from(img.size_of_image).max(last) as usize
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
}
