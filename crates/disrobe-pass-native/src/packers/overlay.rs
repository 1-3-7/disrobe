use std::path::Path;

use disrobe_binfmt::{
    ContainerKind, ExtractionQuota, ExtractionResult, detect_container, extract_to_with_quota,
};
use serde::{Deserialize, Serialize};

use crate::entropy::shannon_entropy_bits;
use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, parse_pe_image};

const SECURITY_DIRECTORY_INDEX: usize = 4;
const HIGH_ENTROPY_BITS: f64 = 7.2;
const MIN_HIGH_ENTROPY_SAMPLE: usize = 256;
const WIN_CERT_HEADER_LEN: usize = 8;
const MIN_ARCHIVE_PROBE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveKind {
    Zip,
    Cab,
    SevenZ,
    Rar,
    Gzip,
    Xz,
    Bzip2,
    Zstd,
    Tar,
}

impl ArchiveKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Cab => "cab",
            Self::SevenZ => "7z",
            Self::Rar => "rar",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Bzip2 => "bzip2",
            Self::Zstd => "zstd",
            Self::Tar => "tar",
        }
    }

    const fn from_container(kind: ContainerKind) -> Option<Self> {
        match kind {
            ContainerKind::Zip
            | ContainerKind::Jar
            | ContainerKind::War
            | ContainerKind::Apk
            | ContainerKind::Xpi
            | ContainerKind::Whl
            | ContainerKind::Egg
            | ContainerKind::Crx
            | ContainerKind::Nupkg
            | ContainerKind::Vsix
            | ContainerKind::Pyz => Some(Self::Zip),
            ContainerKind::Cab => Some(Self::Cab),
            ContainerKind::SevenZ => Some(Self::SevenZ),
            ContainerKind::Rar => Some(Self::Rar),
            ContainerKind::TarGz | ContainerKind::Gzip => Some(Self::Gzip),
            ContainerKind::TarXz | ContainerKind::Xz => Some(Self::Xz),
            ContainerKind::TarBz2 | ContainerKind::Bzip2 => Some(Self::Bzip2),
            ContainerKind::TarZst | ContainerKind::Zstd => Some(Self::Zstd),
            ContainerKind::Tar => Some(Self::Tar),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertType {
    PkcsSignedData,
    X509,
    Reserved1,
    PkcsPkcs7,
    Other,
}

impl CertType {
    const fn from_w_cert_type(value: u16) -> Self {
        match value {
            0x0001 => Self::X509,
            0x0002 => Self::PkcsSignedData,
            0x0003 => Self::Reserved1,
            0x0004 => Self::PkcsPkcs7,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum OverlayClass {
    ConstantPadding {
        fill_byte: u8,
        length: u64,
    },
    AppendedArchive {
        archive: ArchiveKind,
        length: u64,
    },
    Authenticode {
        declared_length: u32,
        revision: u16,
        cert_type: CertType,
        length: u64,
    },
    HighEntropyUnknown {
        entropy_bits: f64,
        length: u64,
    },
    Unknown {
        length: u64,
    },
}

impl OverlayClass {
    #[must_use]
    pub const fn length(&self) -> u64 {
        match self {
            Self::ConstantPadding { length, .. }
            | Self::AppendedArchive { length, .. }
            | Self::Authenticode { length, .. }
            | Self::HighEntropyUnknown { length, .. }
            | Self::Unknown { length } => *length,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlaySegment {
    pub offset: u64,
    pub class: OverlayClass,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeOverlayReport {
    pub file_len: u64,
    pub image_end: u64,
    pub overlay_offset: u64,
    pub overlay_len: u64,
    pub inflation_ratio: f64,
    pub segments: Vec<OverlaySegment>,
    pub normalized_len: u64,
    pub has_appended_archive: bool,
}

impl PeOverlayReport {
    #[must_use]
    pub const fn has_overlay(&self) -> bool {
        self.overlay_len > 0
    }
}

#[must_use]
pub fn compute_image_end(image: &PeImage, file_len: usize) -> u64 {
    let mut end: u64 = 0;
    for section in &image.sections {
        let raw_end: u64 = u64::from(section.raw_pointer) + u64::from(section.raw_size);
        if raw_end > end {
            end = raw_end;
        }
    }
    end.min(file_len as u64)
}

#[derive(Debug, Clone, Copy)]
struct CertRegion {
    start: usize,
    end: usize,
    declared_size: u32,
}

fn certificate_region(image: &PeImage, file_len: usize) -> Option<CertRegion> {
    let dir: &crate::packers::pe_sections::DataDirectory =
        image.data_directories.get(SECURITY_DIRECTORY_INDEX)?;
    if dir.virtual_address == 0 || dir.size == 0 {
        return None;
    }
    let start: usize = dir.virtual_address as usize;
    let end: usize = start.checked_add(dir.size as usize)?;
    if end > file_len {
        return None;
    }
    Some(CertRegion {
        start,
        end,
        declared_size: dir.size,
    })
}

fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let s: &[u8] = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    let s: &[u8] = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn constant_fill(window: &[u8]) -> Option<u8> {
    let first: u8 = *window.first()?;
    if window.iter().all(|&b: &u8| b == first) {
        Some(first)
    } else {
        None
    }
}

const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const EOCD_FIXED_LEN: usize = 22;

fn classify_archive(window: &[u8]) -> Option<ArchiveKind> {
    if window.len() < MIN_ARCHIVE_PROBE {
        return None;
    }
    let kind: ContainerKind = detect_container(window)?;
    ArchiveKind::from_container(kind)
}

fn zip_structural_end(window: &[u8]) -> Option<usize> {
    if !window.starts_with(&[0x50, 0x4B, 0x03, 0x04])
        && !window.starts_with(&[0x50, 0x4B, 0x05, 0x06])
    {
        return None;
    }
    let mut best: Option<usize> = None;
    let mut from: usize = 0;
    while let Some(rel) = window[from..]
        .windows(4)
        .position(|w: &[u8]| w == EOCD_SIGNATURE)
    {
        let at: usize = from + rel;
        if at + EOCD_FIXED_LEN <= window.len() {
            let comment_len: usize = read_u16_le(window, at + 20).unwrap_or(0) as usize;
            let end: usize = at + EOCD_FIXED_LEN + comment_len;
            if end <= window.len() {
                best = Some(end);
            }
        }
        from = at + 4;
    }
    best
}

fn archive_true_len(window: &[u8], archive: ArchiveKind) -> usize {
    match archive {
        ArchiveKind::Zip => zip_structural_end(window).unwrap_or(window.len()),
        other => crate::packers::overlay_extent::archive_true_extent(window, other)
            .unwrap_or(window.len()),
    }
}

fn classify_opaque(window: &[u8]) -> OverlayClass {
    let length: u64 = window.len() as u64;
    if window.len() >= MIN_HIGH_ENTROPY_SAMPLE {
        let bits: f64 = shannon_entropy_bits(window);
        if bits >= HIGH_ENTROPY_BITS {
            return OverlayClass::HighEntropyUnknown {
                entropy_bits: bits,
                length,
            };
        }
    }
    OverlayClass::Unknown { length }
}

fn classify_window_into(window: &[u8], base_offset: u64, out: &mut Vec<OverlaySegment>) {
    let mut cursor: usize = 0;
    while cursor < window.len() {
        let rest: &[u8] = &window[cursor..];
        let offset: u64 = base_offset + cursor as u64;
        if let Some(fill) = constant_fill(rest) {
            out.push(OverlaySegment {
                offset,
                class: OverlayClass::ConstantPadding {
                    fill_byte: fill,
                    length: rest.len() as u64,
                },
            });
            return;
        }
        if let Some(archive) = classify_archive(rest) {
            let true_len: usize = archive_true_len(rest, archive).clamp(1, rest.len());
            out.push(OverlaySegment {
                offset,
                class: OverlayClass::AppendedArchive {
                    archive,
                    length: true_len as u64,
                },
            });
            cursor += true_len;
            continue;
        }
        out.push(OverlaySegment {
            offset,
            class: classify_opaque(rest),
        });
        return;
    }
}

fn classify_authenticode(bytes: &[u8], cert: CertRegion) -> Option<OverlayClass> {
    let header: &[u8] = bytes.get(cert.start..cert.start + WIN_CERT_HEADER_LEN)?;
    let dw_length: u32 = read_u32_le(header, 0)?;
    let revision: u16 = read_u16_le(header, 4)?;
    let w_cert_type: u16 = read_u16_le(header, 6)?;
    let span: usize = cert.end - cert.start;
    if dw_length < WIN_CERT_HEADER_LEN as u32 || dw_length > cert.declared_size {
        return None;
    }
    if revision != 0x0100 && revision != 0x0200 {
        return None;
    }
    Some(OverlayClass::Authenticode {
        declared_length: dw_length,
        revision,
        cert_type: CertType::from_w_cert_type(w_cert_type),
        length: span as u64,
    })
}

fn segment_overlay(bytes: &[u8], image: &PeImage, image_end: usize) -> Vec<OverlaySegment> {
    let file_len: usize = bytes.len();
    let mut cuts: Vec<usize> = vec![image_end, file_len];
    let cert: Option<CertRegion> = certificate_region(image, file_len);
    if let Some(region) = cert
        && region.start >= image_end
        && region.end <= file_len
    {
        cuts.push(region.start);
        cuts.push(region.end);
    }
    cuts.sort_unstable();
    cuts.dedup();

    let mut segments: Vec<OverlaySegment> = Vec::new();
    for pair in cuts.windows(2) {
        let start: usize = pair[0];
        let end: usize = pair[1];
        if end <= start {
            continue;
        }
        let window: &[u8] = &bytes[start..end];
        if let Some(region) = cert
            && region.start == start
            && region.end == end
            && let Some(auth) = classify_authenticode(bytes, region)
        {
            segments.push(OverlaySegment {
                offset: start as u64,
                class: auth,
            });
        } else {
            classify_window_into(window, start as u64, &mut segments);
        }
    }
    segments
}

pub fn analyze_pe_overlay(bytes: &[u8]) -> Result<PeOverlayReport> {
    let image: PeImage = parse_pe_image(bytes)?;
    let file_len: usize = bytes.len();
    let image_end_u64: u64 = compute_image_end(&image, file_len);
    let image_end: usize = image_end_u64 as usize;
    let overlay_len: u64 = (file_len as u64).saturating_sub(image_end_u64);
    let segments: Vec<OverlaySegment> = if overlay_len > 0 {
        segment_overlay(bytes, &image, image_end)
    } else {
        Vec::new()
    };
    let has_appended_archive: bool = segments
        .iter()
        .any(|s: &OverlaySegment| matches!(s.class, OverlayClass::AppendedArchive { .. }));
    let inflation_ratio: f64 = if image_end_u64 == 0 {
        0.0
    } else {
        file_len as f64 / image_end_u64 as f64
    };
    Ok(PeOverlayReport {
        file_len: file_len as u64,
        image_end: image_end_u64,
        overlay_offset: image_end_u64,
        overlay_len,
        inflation_ratio,
        segments,
        normalized_len: image_end_u64,
        has_appended_archive,
    })
}

#[must_use]
pub fn carve_overlay(bytes: &[u8]) -> Option<&[u8]> {
    let image: PeImage = parse_pe_image(bytes).ok()?;
    let image_end: usize = compute_image_end(&image, bytes.len()) as usize;
    if image_end >= bytes.len() {
        return None;
    }
    bytes.get(image_end..)
}

pub fn normalize_pe(bytes: &[u8]) -> Result<Vec<u8>> {
    let image: PeImage = parse_pe_image(bytes)?;
    let image_end: usize = compute_image_end(&image, bytes.len()) as usize;
    let mut out: Vec<u8> = bytes
        .get(..image_end)
        .ok_or(Error::Truncated {
            needed: image_end,
            had: bytes.len(),
        })?
        .to_vec();
    zero_security_directory(&mut out)?;
    parse_pe_image(&out)?;
    Ok(out)
}

fn zero_security_directory(bytes: &mut [u8]) -> Result<()> {
    let e_lfanew: usize = read_u32_le(bytes, 0x3C).ok_or(Error::UnknownFormat)? as usize;
    let coff_off: usize = e_lfanew.checked_add(4).ok_or(Error::UnknownFormat)?;
    let opt_hdr_off: usize = coff_off + 20;
    let opt_magic: u16 = read_u16_le(bytes, opt_hdr_off).ok_or(Error::UnknownFormat)?;
    let dir_count_off: usize = match opt_magic {
        0x010B => opt_hdr_off + 92,
        0x020B => opt_hdr_off + 108,
        _ => return Err(Error::UnknownFormat),
    };
    let dir_table_off: usize = dir_count_off + 4;
    let entry: usize = dir_table_off + SECURITY_DIRECTORY_INDEX * 8;
    if let Some(slot) = bytes.get_mut(entry..entry + 8) {
        slot.fill(0);
    }
    Ok(())
}

pub fn route_overlay_archive(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<Option<ExtractionResult>> {
    let Some(overlay): Option<&[u8]> = carve_overlay(bytes) else {
        return Ok(None);
    };
    let Some(kind): Option<ContainerKind> = detect_container(overlay) else {
        return Ok(None);
    };
    if ArchiveKind::from_container(kind).is_none() {
        return Ok(None);
    }
    let result: ExtractionResult = extract_to_with_quota(kind, overlay, out_dir, quota)
        .map_err(|e: disrobe_binfmt::Error| Error::ObjectParse(format!("overlay-archive: {e}")))?;
    Ok(Some(result))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn pe_with_one_section(raw_size: u32) -> Vec<u8> {
        let opt_size: usize = 0xE0;
        let sec_table: usize = 0x80 + 4 + 20 + opt_size;
        let raw_ptr: usize = sec_table + 40 + 0x10;
        let total: usize = raw_ptr + raw_size as usize;
        let mut buf: Vec<u8> = vec![0u8; total];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe_off: usize = 0x80;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
        let coff: usize = pe_off + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        let sec: usize = sec_table;
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&raw_size.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&raw_size.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&(raw_ptr as u32).to_le_bytes());
        buf
    }

    #[test]
    fn clean_pe_has_no_overlay() {
        let pe: Vec<u8> = pe_with_one_section(0x200);
        let report: PeOverlayReport = analyze_pe_overlay(&pe).expect("analyze");
        assert_eq!(report.overlay_len, 0);
        assert_eq!(report.image_end, report.file_len);
        assert!(report.segments.is_empty());
    }

    #[test]
    fn constant_padding_is_classified() {
        let mut pe: Vec<u8> = pe_with_one_section(0x200);
        let base: usize = pe.len();
        pe.extend(std::iter::repeat_n(0u8, 4096));
        let report: PeOverlayReport = analyze_pe_overlay(&pe).expect("analyze");
        assert_eq!(report.overlay_len, 4096);
        assert_eq!(report.overlay_offset, base as u64);
        assert_eq!(report.segments.len(), 1);
        assert!(matches!(
            report.segments[0].class,
            OverlayClass::ConstantPadding {
                fill_byte: 0,
                length: 4096
            }
        ));
    }

    #[test]
    fn appended_zip_is_detected() {
        let mut pe: Vec<u8> = pe_with_one_section(0x200);
        pe.extend_from_slice(b"PK\x03\x04");
        pe.extend(std::iter::repeat_n(0u8, 64));
        let report: PeOverlayReport = analyze_pe_overlay(&pe).expect("analyze");
        assert!(report.has_appended_archive);
        assert!(report.segments.iter().any(|s: &OverlaySegment| matches!(
            s.class,
            OverlayClass::AppendedArchive {
                archive: ArchiveKind::Zip,
                ..
            }
        )));
    }

    #[test]
    fn normalized_pe_strips_overlay_and_reparses() {
        let mut pe: Vec<u8> = pe_with_one_section(0x200);
        let clean_len: usize = pe.len();
        pe.extend(std::iter::repeat_n(0xCCu8, 1024));
        let normalized: Vec<u8> = normalize_pe(&pe).expect("normalize");
        assert_eq!(normalized.len(), clean_len);
        assert_eq!(&normalized[..], &pe[..clean_len]);
        parse_pe_image(&normalized).expect("re-parse");
    }

    #[test]
    fn carve_returns_exact_tail() {
        let mut pe: Vec<u8> = pe_with_one_section(0x200);
        let tail: &[u8] = b"appended-tail-bytes";
        pe.extend_from_slice(tail);
        let carved: &[u8] = carve_overlay(&pe).expect("carve");
        assert_eq!(carved, tail);
    }
}
