use serde::Serialize;

use crate::lang::r_rds::RdsObject;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PE_MAGIC: [u8; 2] = [b'M', b'Z'];
const MACHO_64_LE: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
const MACHO_32_LE: [u8; 4] = [0xce, 0xfa, 0xed, 0xfe];
const MACHO_64_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xcf];
const MACHO_32_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xce];
const PE_LFANEW_MIN: usize = 0x40usize;
const PE_NT_SIGNATURE: [u8; 4] = [b'P', b'E', 0x00, 0x00];

pub const NATIVE_ROUTE_PASS_ID: &str = "disrobe-pass-native";

const RCPP_CLASS_MARKERS: &[&str] = &[
    "Rcpp_",
    "C++Object",
    "Rcpp::",
    "RcppExports",
    ".Call",
    "Module",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeImageFormat {
    Elf,
    Pe,
    MachO,
}

impl NativeImageFormat {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::Pe => "pe",
            Self::MachO => "mach-o",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmbeddedNativeImage {
    pub format: NativeImageFormat,
    pub offset: usize,
    pub length: usize,
    pub route_pass_id: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RcppFingerprint {
    pub uses_rcpp: bool,
    pub linking_to_rcpp: bool,
    pub class_markers: Vec<String>,
    pub embedded_images: Vec<EmbeddedNativeImage>,
}

impl RcppFingerprint {
    #[must_use]
    pub fn is_rcpp(&self) -> bool {
        self.uses_rcpp || self.linking_to_rcpp || !self.class_markers.is_empty()
    }
}

#[must_use]
pub fn detect_markers(strings: &[String]) -> Vec<String> {
    let mut found: Vec<String> = strings
        .iter()
        .filter(|s: &&String| RCPP_CLASS_MARKERS.iter().any(|m: &&str| s.contains(m)))
        .cloned()
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[must_use]
pub fn description_links_rcpp(strings: &[String]) -> bool {
    strings.iter().any(|s: &String| {
        let t: &str = s.trim();
        t.starts_with("LinkingTo:") && t.contains("Rcpp")
    })
}

#[must_use]
pub fn scan_native_images(blob: &[u8]) -> Vec<EmbeddedNativeImage> {
    let mut images: Vec<EmbeddedNativeImage> = Vec::new();
    let mut i: usize = 0usize;
    while i < blob.len() {
        let Some(format): Option<NativeImageFormat> = magic_at(blob, i) else {
            i += 1;
            continue;
        };
        let Some(next_start): Option<usize> = i.checked_add(1) else {
            break;
        };
        let next_magic: usize = next_magic_offset(blob, next_start);
        let header_extent: Option<usize> = image_extent(blob, i, format);
        let length: usize =
            header_extent.map_or(next_magic - i, |extent: usize| extent.min(next_magic - i));
        let Some(end): Option<usize> = i.checked_add(length) else {
            break;
        };
        let Some(bytes): Option<&[u8]> = blob.get(i..end) else {
            break;
        };
        images.push(EmbeddedNativeImage {
            format,
            offset: i,
            length,
            route_pass_id: NATIVE_ROUTE_PASS_ID,
            bytes: bytes.to_vec(),
        });
        let Some(min_advance): Option<usize> = i.checked_add(4) else {
            break;
        };
        i = end.max(min_advance);
    }
    images
}

fn next_magic_offset(blob: &[u8], start: usize) -> usize {
    let mut j: usize = start;
    while j < blob.len() {
        if magic_at(blob, j).is_some() {
            return j;
        }
        j += 1;
    }
    blob.len()
}

fn image_extent(blob: &[u8], offset: usize, format: NativeImageFormat) -> Option<usize> {
    let image: &[u8] = blob.get(offset..)?;
    let extent: usize = match format {
        NativeImageFormat::Elf => elf_file_extent(image)?,
        NativeImageFormat::Pe => pe_file_extent(image)?,
        NativeImageFormat::MachO => return None,
    };
    if extent == 0 || extent > image.len() {
        None
    } else {
        Some(extent)
    }
}

fn read_u16(image: &[u8], at: usize, le: bool) -> Option<u64> {
    let end: usize = at.checked_add(2)?;
    let b: &[u8; 2] = image.get(at..end)?.try_into().ok()?;
    Some(u64::from(if le {
        u16::from_le_bytes(*b)
    } else {
        u16::from_be_bytes(*b)
    }))
}

fn read_u32(image: &[u8], at: usize, le: bool) -> Option<u64> {
    let end: usize = at.checked_add(4)?;
    let b: &[u8; 4] = image.get(at..end)?.try_into().ok()?;
    Some(u64::from(if le {
        u32::from_le_bytes(*b)
    } else {
        u32::from_be_bytes(*b)
    }))
}

fn read_u64(image: &[u8], at: usize, le: bool) -> Option<u64> {
    let end: usize = at.checked_add(8)?;
    let b: &[u8; 8] = image.get(at..end)?.try_into().ok()?;
    Some(if le {
        u64::from_le_bytes(*b)
    } else {
        u64::from_be_bytes(*b)
    })
}

const SHT_NOBITS: u64 = 8;

fn elf_file_extent(image: &[u8]) -> Option<usize> {
    let class: u8 = *image.get(4)?;
    let le: bool = *image.get(5)? == 1u8;
    let is64: bool = class == 2u8;
    if class != 1u8 && class != 2u8 {
        return None;
    }
    let (shoff, shentsize_off, shnum_off, phoff, phentsize_off, phnum_off): (
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) = if is64 {
        (0x28, 0x3a, 0x3c, 0x20, 0x36, 0x38)
    } else {
        (0x20, 0x2e, 0x30, 0x1c, 0x2a, 0x2c)
    };
    let shoff: u64 = if is64 {
        read_u64(image, shoff, le)?
    } else {
        read_u32(image, shoff, le)?
    };
    let phoff: u64 = if is64 {
        read_u64(image, phoff, le)?
    } else {
        read_u32(image, phoff, le)?
    };
    let shentsize: u64 = read_u16(image, shentsize_off, le)?;
    let shnum: u64 = read_u16(image, shnum_off, le)?;
    let phentsize: u64 = read_u16(image, phentsize_off, le)?;
    let phnum: u64 = read_u16(image, phnum_off, le)?;
    let sht_end: u64 = shoff.checked_add(shentsize.checked_mul(shnum)?)?;
    let pht_end: u64 = phoff.checked_add(phentsize.checked_mul(phnum)?)?;
    let mut extent: u64 = sht_end.max(pht_end);
    let sh_size_off: usize = if is64 { 0x20 } else { 0x14 };
    let sh_offset_off: usize = if is64 { 0x18 } else { 0x10 };
    let sh_type_off: usize = 0x4;
    for idx in 0..shnum {
        let entry: usize = usize::try_from(shoff.checked_add(idx.checked_mul(shentsize)?)?).ok()?;
        let sh_type_at: usize = entry.checked_add(sh_type_off)?;
        let sh_type: u64 = read_u32(image, sh_type_at, le)?;
        if sh_type == SHT_NOBITS {
            continue;
        }
        let sh_offset_at: usize = entry.checked_add(sh_offset_off)?;
        let s_off: u64 = if is64 {
            read_u64(image, sh_offset_at, le)?
        } else {
            read_u32(image, sh_offset_at, le)?
        };
        let sh_size_at: usize = entry.checked_add(sh_size_off)?;
        let s_size: u64 = if is64 {
            read_u64(image, sh_size_at, le)?
        } else {
            read_u32(image, sh_size_at, le)?
        };
        extent = extent.max(s_off.checked_add(s_size)?);
    }
    usize::try_from(extent).ok()
}

fn pe_file_extent(image: &[u8]) -> Option<usize> {
    let lfanew: usize = usize::try_from(read_u32(image, 0x3c, true)?).ok()?;
    let coff: usize = lfanew.checked_add(4)?;
    let num_sections_at: usize = coff.checked_add(2)?;
    let num_sections: u64 = read_u16(image, num_sections_at, true)?;
    let opt_header_size_at: usize = coff.checked_add(16)?;
    let opt_header_size: u64 = read_u16(image, opt_header_size_at, true)?;
    let section_table_base: usize = coff.checked_add(20)?;
    let section_table: usize =
        section_table_base.checked_add(usize::try_from(opt_header_size).ok()?)?;
    let mut extent: u64 = u64::try_from(section_table).ok()?;
    for idx in 0..num_sections {
        let offset: usize = usize::try_from(idx.checked_mul(40)?).ok()?;
        let entry: usize = section_table.checked_add(offset)?;
        let raw_size_at: usize = entry.checked_add(16)?;
        let raw_size: u64 = read_u32(image, raw_size_at, true)?;
        let raw_ptr_at: usize = entry.checked_add(20)?;
        let raw_ptr: u64 = read_u32(image, raw_ptr_at, true)?;
        extent = extent.max(raw_ptr.checked_add(raw_size)?);
    }
    usize::try_from(extent).ok()
}

fn magic_at(blob: &[u8], i: usize) -> Option<NativeImageFormat> {
    if has_at(blob, i, &ELF_MAGIC) {
        return Some(NativeImageFormat::Elf);
    }
    if has_at(blob, i, &MACHO_64_LE)
        || has_at(blob, i, &MACHO_32_LE)
        || has_at(blob, i, &MACHO_64_BE)
        || has_at(blob, i, &MACHO_32_BE)
    {
        return Some(NativeImageFormat::MachO);
    }
    if is_pe_at(blob, i) {
        return Some(NativeImageFormat::Pe);
    }
    None
}

fn is_pe_at(blob: &[u8], i: usize) -> bool {
    if !has_at(blob, i, &PE_MAGIC) {
        return false;
    }
    let Some(lfanew_pos): Option<usize> = i.checked_add(0x3c) else {
        return false;
    };
    let Some(lfanew_end): Option<usize> = lfanew_pos.checked_add(4) else {
        return false;
    };
    let Some(raw_lfanew): Option<&[u8]> = blob.get(lfanew_pos..lfanew_end) else {
        return false;
    };
    let Ok(raw_lfanew): core::result::Result<&[u8; 4], _> = raw_lfanew.try_into() else {
        return false;
    };
    let lfanew: usize = u32::from_le_bytes(*raw_lfanew) as usize;
    if lfanew < PE_LFANEW_MIN {
        return false;
    }
    let Some(nt_signature): Option<usize> = i.checked_add(lfanew) else {
        return false;
    };
    has_at(blob, nt_signature, &PE_NT_SIGNATURE)
}

#[inline]
fn has_at(blob: &[u8], i: usize, magic: &[u8]) -> bool {
    let Some(end): Option<usize> = i.checked_add(magic.len()) else {
        return false;
    };
    blob.get(i..end).is_some_and(|bytes: &[u8]| bytes == magic)
}

#[must_use]
pub fn fingerprint(obj: &RdsObject, raw_blob: &[u8]) -> RcppFingerprint {
    let mut pool: Vec<String> = Vec::with_capacity(
        obj.string_values.len() + obj.symbols.len() + obj.names.len() + obj.class.len(),
    );
    pool.extend(obj.string_values.iter().cloned());
    pool.extend(obj.symbols.iter().cloned());
    pool.extend(obj.names.iter().cloned());
    pool.extend(obj.class.iter().cloned());

    let class_markers: Vec<String> = detect_markers(&pool);
    let uses_rcpp: bool =
        !class_markers.is_empty() || pool.iter().any(|s: &String| s.contains("Rcpp"));
    let linking_to_rcpp: bool = description_links_rcpp(&pool);
    let embedded_images: Vec<EmbeddedNativeImage> = scan_native_images(raw_blob);

    RcppFingerprint {
        uses_rcpp,
        linking_to_rcpp,
        class_markers,
        embedded_images,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn elf_stub() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&ELF_MAGIC);
        v.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
        v.extend_from_slice(&[0u8; 56]);
        v
    }

    fn pe_stub() -> Vec<u8> {
        let mut v: Vec<u8> = vec![0u8; 0x80];
        v[0] = b'M';
        v[1] = b'Z';
        let lfanew: u32 = 0x40u32;
        v[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
        v[0x40..0x44].copy_from_slice(&PE_NT_SIGNATURE);
        v
    }

    #[test]
    fn detects_rcpp_class_markers() {
        let pool: Vec<String> = vec![
            "Rcpp::CharacterVector".to_owned(),
            "plain_string".to_owned(),
            "RcppExports".to_owned(),
        ];
        let markers: Vec<String> = detect_markers(&pool);
        assert!(markers.iter().any(|m: &String| m.contains("Rcpp::")));
        assert!(markers.iter().any(|m: &String| m == "RcppExports"));
        assert!(!markers.iter().any(|m: &String| m == "plain_string"));
    }

    #[test]
    fn detects_linkingto_rcpp() {
        assert!(description_links_rcpp(&[
            "LinkingTo: Rcpp (>= 1.0.0)".to_owned()
        ]));
        assert!(!description_links_rcpp(&["LinkingTo: BH".to_owned()]));
    }

    #[test]
    fn scans_elf_and_routes_to_native() {
        let mut blob: Vec<u8> = b"padding\x00\x00".to_vec();
        let off: usize = blob.len();
        blob.extend_from_slice(&elf_stub());
        let images: Vec<EmbeddedNativeImage> = scan_native_images(&blob);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].format, NativeImageFormat::Elf);
        assert_eq!(images[0].offset, off);
        assert_eq!(images[0].route_pass_id, "disrobe-pass-native");
        assert_eq!(&images[0].bytes[..4], &ELF_MAGIC);
    }

    #[test]
    fn scans_pe_with_valid_nt_signature() {
        let blob: Vec<u8> = pe_stub();
        let images: Vec<EmbeddedNativeImage> = scan_native_images(&blob);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].format, NativeImageFormat::Pe);
    }

    #[test]
    fn rejects_bare_mz_without_pe_signature() {
        let mut blob: Vec<u8> = vec![0u8; 0x80];
        blob[0] = b'M';
        blob[1] = b'Z';
        assert!(scan_native_images(&blob).is_empty());
    }
}
