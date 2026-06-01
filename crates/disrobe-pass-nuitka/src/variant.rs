use std::path::Path;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::onefile_locator::{LocatedOnefile, locate_onefile_payload};
use crate::signed::{AuthenticodeSummary, detect_authenticode};
use crate::util::find_subslice;

/// Loader/runtime strings verified present in a real Nuitka 4.1.1 `--standalone` exe and
/// `--module` pyd. Internal C-API symbol names from older revisions are stripped from
/// optimised release output and are intentionally absent here.
const NUITKA_CORE_MARKERS: &[&[u8]] = &[
    b"__nuitka_version__",
    b"nuitka_module_loader",
    b"nuitka_distribution",
    b"nuitka_resource_reader",
    b"nuitka_empty_function",
    b"Nuitka_Err_NormalizeException",
    b"__compiled__",
];
const MODULE_EXTENSION_MARKERS: &[&[u8]] = &[
    b"PyInit_",
    b"PyMODINIT_FUNC",
    b"PyModuleDef",
    b"PyModule_Create2",
];
const STANDALONE_MARKERS: &[&[u8]] = &[
    b"nuitka_distribution_patch",
    b"nuitka_types_patch",
    b"NUITKA_PACKAGE_HOME",
    b"LD_LIBRARY_PATH",
    b"NUITKA_ONEFILE_PARENT",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NuitkaVariant {
    OnefileKax,
    OnefileKay,
    Standalone,
    Module,
    SignedPe,
    Wheel,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    MachOFat,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariantClassification {
    pub variant: NuitkaVariant,
    pub binary_format: BinaryFormat,
    pub onefile_offset: Option<usize>,
    pub onefile_compressed: bool,
    pub authenticode: Option<AuthenticodeSummary>,
    pub module_init_count: u32,
    pub standalone_hits: u32,
    pub core_marker_hits: u32,
}

pub fn classify_in_file(path: &Path) -> Result<VariantClassification> {
    let bytes: Vec<u8> = std::fs::read(path)?;
    classify(&bytes)
}

pub fn classify(bytes: &[u8]) -> Result<VariantClassification> {
    if bytes.is_empty() {
        return Err(Error::NotNuitka);
    }
    let binary_format: BinaryFormat = sniff_binary_format(bytes);
    let (onefile_offset, onefile_compressed): (Option<usize>, bool) = locate_onefile(bytes);
    let authenticode: Option<AuthenticodeSummary> = if matches!(binary_format, BinaryFormat::Pe) {
        detect_authenticode(bytes).ok().flatten()
    } else {
        None
    };
    let module_init_count: u32 = count_module_inits(bytes);
    let standalone_hits: u32 = count_standalone_markers(bytes);
    let core_marker_hits: u32 = count_core_markers(bytes);

    let variant: NuitkaVariant = decide_variant(
        binary_format,
        onefile_offset,
        onefile_compressed,
        authenticode.is_some(),
        module_init_count,
        standalone_hits,
        core_marker_hits,
    );

    if matches!(variant, NuitkaVariant::Unknown)
        && core_marker_hits == 0
        && onefile_offset.is_none()
    {
        return Err(Error::NotNuitka);
    }

    Ok(VariantClassification {
        variant,
        binary_format,
        onefile_offset,
        onefile_compressed,
        authenticode,
        module_init_count,
        standalone_hits,
        core_marker_hits,
    })
}

const fn decide_variant(
    binary_format: BinaryFormat,
    onefile_offset: Option<usize>,
    onefile_compressed: bool,
    signed: bool,
    module_init_count: u32,
    standalone_hits: u32,
    core_marker_hits: u32,
) -> NuitkaVariant {
    if onefile_offset.is_some() {
        if signed {
            return NuitkaVariant::SignedPe;
        }
        return if onefile_compressed {
            NuitkaVariant::OnefileKay
        } else {
            NuitkaVariant::OnefileKax
        };
    }
    if signed && core_marker_hits >= 2 {
        return NuitkaVariant::SignedPe;
    }
    if core_marker_hits == 0 {
        return NuitkaVariant::Unknown;
    }
    if is_module_format(binary_format) && module_init_count >= 1 && standalone_hits == 0 {
        return NuitkaVariant::Module;
    }
    if standalone_hits >= 1 || core_marker_hits >= 3 {
        return NuitkaVariant::Standalone;
    }
    NuitkaVariant::Unknown
}

#[inline]
const fn is_module_format(binary_format: BinaryFormat) -> bool {
    matches!(
        binary_format,
        BinaryFormat::Pe | BinaryFormat::Elf | BinaryFormat::MachO
    )
}

fn sniff_binary_format(bytes: &[u8]) -> BinaryFormat {
    if bytes.len() < 4 {
        return BinaryFormat::Other;
    }
    let head4: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match head4 {
        [b'M', b'Z', _, _] => BinaryFormat::Pe,
        [0x7F, b'E', b'L', b'F'] => BinaryFormat::Elf,
        [0xFE, 0xED, 0xFA, 0xCE | 0xCF] | [0xCE | 0xCF, 0xFA, 0xED, 0xFE] => BinaryFormat::MachO,
        [0xCA, 0xFE, 0xBA, 0xBE] | [0xBE, 0xBA, 0xFE, 0xCA] => BinaryFormat::MachOFat,
        _ => BinaryFormat::Other,
    }
}

fn locate_onefile(bytes: &[u8]) -> (Option<usize>, bool) {
    match locate_onefile_payload(bytes) {
        Some(LocatedOnefile { offset, compressed }) => (Some(offset), compressed),
        None => (None, false),
    }
}

fn count_core_markers(bytes: &[u8]) -> u32 {
    let mut hits: u32 = 0u32;
    for needle in NUITKA_CORE_MARKERS {
        if find_subslice(bytes, needle).is_some() {
            hits += 1;
        }
    }
    hits
}

fn count_module_inits(bytes: &[u8]) -> u32 {
    let mut hits: u32 = 0u32;
    for needle in MODULE_EXTENSION_MARKERS {
        if find_subslice(bytes, needle).is_some() {
            hits += 1;
        }
    }
    hits
}

fn count_standalone_markers(bytes: &[u8]) -> u32 {
    let mut hits: u32 = 0u32;
    for needle in STANDALONE_MARKERS {
        if find_subslice(bytes, needle).is_some() {
            hits += 1;
        }
    }
    hits
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

    fn write_kax_name(out: &mut Vec<u8>, name: &str) {
        for unit in name.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0u8, 0u8]);
    }

    #[test]
    fn empty_input_errors() {
        let Err(err): Result<VariantClassification> = classify(b"") else {
            panic!("empty must error");
        };
        assert!(matches!(err, Error::NotNuitka));
    }

    #[test]
    fn kax_payload_in_pe_classifies_onefile_kax() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[0..2].copy_from_slice(b"MZ");
        let payload_at: usize = bytes.len();
        bytes.extend_from_slice(b"KAX");
        write_kax_name(&mut bytes, "hello.exe");
        bytes.extend_from_slice(&4u64.to_le_bytes());
        bytes.extend_from_slice(b"MZ\x90\x00");
        bytes.extend_from_slice(&[0u8, 0u8]);
        let c: VariantClassification = classify(&bytes).expect("KAX");
        assert_eq!(c.variant, NuitkaVariant::OnefileKax);
        assert_eq!(c.binary_format, BinaryFormat::Pe);
        assert_eq!(c.onefile_offset, Some(payload_at));
        assert!(!c.onefile_compressed);
    }

    #[test]
    fn kay_payload_in_elf_classifies_onefile_kay() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        bytes.extend_from_slice(b"KAY");
        bytes.extend_from_slice(&ZSTD_MAGIC);
        bytes.extend_from_slice(&[0u8; 32]);
        let c: VariantClassification = classify(&bytes).expect("KAY");
        assert_eq!(c.variant, NuitkaVariant::OnefileKay);
        assert_eq!(c.binary_format, BinaryFormat::Elf);
        assert!(c.onefile_compressed);
    }

    #[test]
    fn module_variant_when_no_onefile_no_standalone_with_pyinit() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..107].copy_from_slice(b"PyInit_");
        bytes[200..218].copy_from_slice(b"__nuitka_version__");
        bytes[400..412].copy_from_slice(b"__compiled__");
        let c: VariantClassification = classify(&bytes).expect("module");
        assert_eq!(c.variant, NuitkaVariant::Module);
    }

    #[test]
    fn standalone_when_distribution_patch_marker_present() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..125].copy_from_slice(b"nuitka_distribution_patch");
        bytes[300..318].copy_from_slice(b"__nuitka_version__");
        let c: VariantClassification = classify(&bytes).expect("standalone");
        assert_eq!(c.variant, NuitkaVariant::Standalone);
    }

    #[test]
    fn macho_format_sniff() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        bytes[100..118].copy_from_slice(b"__nuitka_version__");
        bytes[200..225].copy_from_slice(b"nuitka_distribution_patch");
        let c: VariantClassification = classify(&bytes).expect("macho");
        assert_eq!(c.binary_format, BinaryFormat::MachO);
    }

    #[test]
    fn non_nuitka_bytes_error() {
        let bytes: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
        let res: Result<VariantClassification> = classify(&bytes);
        if let Ok(c) = res {
            assert!(matches!(c.variant, NuitkaVariant::Unknown));
            assert_eq!(c.core_marker_hits, 0);
        }
    }

    #[test]
    fn coincidental_ka_garbage_skipped_until_validated_payload() {
        let mut bytes: Vec<u8> = vec![0u8; 256];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..103].copy_from_slice(b"KAZ");
        bytes[110..113].copy_from_slice(b"KAY");
        bytes[113..117].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let real_at: usize = bytes.len();
        bytes.extend_from_slice(b"KAY");
        bytes.extend_from_slice(&ZSTD_MAGIC);
        bytes.extend_from_slice(&[0u8; 16]);
        let c: VariantClassification = classify(&bytes).expect("validated KAY found");
        assert_eq!(c.variant, NuitkaVariant::OnefileKay);
        assert_eq!(c.onefile_offset, Some(real_at));
    }
}
