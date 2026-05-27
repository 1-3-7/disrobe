use std::path::Path;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::signed::{AuthenticodeSummary, detect_authenticode};
use crate::util::find_subslice;

const ONEFILE_MAGIC_PREFIX: &[u8; 2] = b"KA";
const NUITKA_CORE_MARKERS: &[&[u8]] = &[
    b"Nuitka_FunctionObject",
    b"Nuitka_GeneratorObject",
    b"Nuitka_CellObject",
    b"loadConstantsBlob",
    b"createGlobalConstants",
    b"MAKE_FUNCTION_",
    b"impl___main__",
    b"__nuitka_version__",
    b"nuitka_module_loader",
    b"nuitka_distribution",
    b"nuitka_resource_reader",
    b"nuitka_empty_function",
    b"Nuitka_Err_NormalizeException",
];
const MODULE_EXTENSION_MARKERS: &[&[u8]] = &[
    b"PyInit_",
    b"PyMODINIT_FUNC",
    b"PyModuleDef",
    b"PyModule_Create2",
];
const STANDALONE_MARKERS: &[&[u8]] = &[
    b".dist/",
    b"__main__.exe",
    b"/python_pe_loader",
    b"LD_LIBRARY_PATH",
    b"nuitka_distribution_patch",
    b"nuitka_types_patch",
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
    let mut cursor: usize = 0usize;
    while cursor + 3 <= bytes.len() {
        let Some(rel): Option<usize> = find_subslice(&bytes[cursor..], ONEFILE_MAGIC_PREFIX) else {
            return (None, false);
        };
        let abs: usize = cursor + rel;
        if abs + 3 > bytes.len() {
            return (None, false);
        }
        match bytes[abs + 2] {
            b'X' => return (Some(abs), false),
            b'Y' => return (Some(abs), true),
            _ => cursor = abs + 2,
        }
    }
    (None, false)
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

    #[test]
    fn empty_input_errors() {
        let Err(err): Result<VariantClassification> = classify(b"") else {
            panic!("empty must error");
        };
        assert!(matches!(err, Error::NotNuitka));
    }

    #[test]
    fn kax_payload_in_pe_classifies_onefile_kax() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[1024..1027].copy_from_slice(b"KAX");
        bytes[2000..2017].copy_from_slice(b"loadConstantsBlob");
        let c: VariantClassification = classify(&bytes).expect("KAX");
        assert_eq!(c.variant, NuitkaVariant::OnefileKax);
        assert_eq!(c.binary_format, BinaryFormat::Pe);
        assert_eq!(c.onefile_offset, Some(1024));
        assert!(!c.onefile_compressed);
    }

    #[test]
    fn kay_payload_in_elf_classifies_onefile_kay() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        bytes[1024..1027].copy_from_slice(b"KAY");
        bytes[2000..2014].copy_from_slice(b"MAKE_FUNCTION_");
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
        bytes[200..217].copy_from_slice(b"loadConstantsBlob");
        let c: VariantClassification = classify(&bytes).expect("module");
        assert_eq!(c.variant, NuitkaVariant::Module);
    }

    #[test]
    fn standalone_when_dist_marker_present() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..106].copy_from_slice(b".dist/");
        bytes[200..217].copy_from_slice(b"loadConstantsBlob");
        let c: VariantClassification = classify(&bytes).expect("standalone");
        assert_eq!(c.variant, NuitkaVariant::Standalone);
    }

    #[test]
    fn macho_format_sniff() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        bytes[200..206].copy_from_slice(b".dist/");
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
    fn invalid_third_magic_byte_skips_and_continues() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..103].copy_from_slice(b"KAZ");
        bytes[500..503].copy_from_slice(b"KAY");
        bytes[1000..1017].copy_from_slice(b"loadConstantsBlob");
        let c: VariantClassification = classify(&bytes).expect("second KAY found");
        assert_eq!(c.variant, NuitkaVariant::OnefileKay);
        assert_eq!(c.onefile_offset, Some(500));
    }
}
