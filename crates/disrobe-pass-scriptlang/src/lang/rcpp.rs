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
        if let Some(format) = magic_at(blob, i) {
            let length: usize = blob.len() - i;
            images.push(EmbeddedNativeImage {
                format,
                offset: i,
                length,
                route_pass_id: NATIVE_ROUTE_PASS_ID,
                bytes: blob[i..].to_vec(),
            });
            i += 4;
        } else {
            i += 1;
        }
    }
    images
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
    let lfanew_pos: usize = i + 0x3c;
    if lfanew_pos + 4 > blob.len() {
        return false;
    }
    let lfanew: usize = u32::from_le_bytes([
        blob[lfanew_pos],
        blob[lfanew_pos + 1],
        blob[lfanew_pos + 2],
        blob[lfanew_pos + 3],
    ]) as usize;
    if lfanew < PE_LFANEW_MIN {
        return false;
    }
    has_at(blob, i + lfanew, &PE_NT_SIGNATURE)
}

#[inline]
fn has_at(blob: &[u8], i: usize, magic: &[u8]) -> bool {
    blob.len() >= i + magic.len() && &blob[i..i + magic.len()] == magic
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
