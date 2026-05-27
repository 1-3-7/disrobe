use std::path::Path;

use serde::Serialize;

use crate::buildinfo::{BuildInfo, scan_build_info};
use crate::error::Result;
use crate::markers::{DecompReadyMarkers, scan_c_source_markers};
use crate::plugin::{PluginScan, scan_plugins};
use crate::signed::AuthenticodeSummary;
use crate::variant::{NuitkaVariant, VariantClassification, classify, classify_in_file};

const MANIFEST_SCHEMA: &str = "disrobe.nuitka.manifest/v0";

#[derive(Debug, Clone, Serialize)]
pub struct NuitkaVariantManifest {
    pub schema: String,
    pub kind: NuitkaVariant,
    pub nuitka_version: Option<String>,
    pub python_version: Option<String>,
    pub plugins_detected: PluginScan,
    pub signed: bool,
    pub authenticode: Option<AuthenticodeSummary>,
    pub variant: VariantClassification,
    pub build_info: Option<BuildInfo>,
    pub decomp_markers: Option<DecompReadyMarkers>,
    pub byte_len: u64,
}

pub fn build_manifest_from_file(path: &Path) -> Result<NuitkaVariantManifest> {
    let variant: VariantClassification = classify_in_file(path)?;
    let bytes: Vec<u8> = std::fs::read(path)?;
    Ok(build_manifest_inner(&bytes, variant))
}

pub fn build_manifest(bytes: &[u8]) -> Result<NuitkaVariantManifest> {
    let variant: VariantClassification = classify(bytes)?;
    Ok(build_manifest_inner(bytes, variant))
}

fn build_manifest_inner(bytes: &[u8], variant: VariantClassification) -> NuitkaVariantManifest {
    let build_info: Option<BuildInfo> = scan_build_info(bytes).ok();
    let decomp_markers: Option<DecompReadyMarkers> = scan_c_source_markers(bytes).ok();
    let plugins_detected: PluginScan = scan_plugins(bytes);
    let authenticode: Option<AuthenticodeSummary> = variant.authenticode.clone();
    let signed: bool = authenticode.is_some();

    let nuitka_version: Option<String> = build_info
        .as_ref()
        .and_then(|b: &BuildInfo| b.raw_version.clone());
    let python_version: Option<String> = build_info
        .as_ref()
        .and_then(|b: &BuildInfo| b.python_version.clone());

    NuitkaVariantManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        kind: variant.variant,
        nuitka_version,
        python_version,
        plugins_detected,
        signed,
        authenticode,
        variant,
        build_info,
        decomp_markers,
        byte_len: bytes.len() as u64,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::variant::NuitkaVariant;

    #[test]
    fn manifest_from_synthetic_kay_blob() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        bytes[1024..1027].copy_from_slice(b"KAY");
        bytes[2000..2017].copy_from_slice(b"loadConstantsBlob");
        bytes[2200..2221].copy_from_slice(b"Nuitka_FunctionObject");
        let m: NuitkaVariantManifest = build_manifest(&bytes).expect("manifest");
        assert_eq!(m.kind, NuitkaVariant::OnefileKay);
        assert_eq!(m.schema, "disrobe.nuitka.manifest/v0");
        assert!(!m.signed);
        assert!(m.decomp_markers.is_some());
    }

    #[test]
    fn manifest_for_module_variant() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..107].copy_from_slice(b"PyInit_");
        bytes[200..217].copy_from_slice(b"loadConstantsBlob");
        bytes[400..421].copy_from_slice(b"Nuitka_FunctionObject");
        let m: NuitkaVariantManifest = build_manifest(&bytes).expect("manifest");
        assert_eq!(m.kind, NuitkaVariant::Module);
        assert!(m.byte_len == 4096);
    }

    #[test]
    fn manifest_includes_plugin_hits() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..106].copy_from_slice(b".dist/");
        bytes[200..217].copy_from_slice(b"loadConstantsBlob");
        bytes[300..317].copy_from_slice(b"nuitka_anti_bloat");
        bytes[1000..1010].copy_from_slice(b"numpy.core");
        bytes[1500..1517].copy_from_slice(b"_multiarray_umath");
        let m: NuitkaVariantManifest = build_manifest(&bytes).expect("manifest");
        assert!(m.plugins_detected.total >= 2);
        assert_eq!(m.kind, NuitkaVariant::Standalone);
    }

    #[test]
    fn manifest_serialises_to_json() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[100..106].copy_from_slice(b".dist/");
        bytes[200..217].copy_from_slice(b"loadConstantsBlob");
        let m: NuitkaVariantManifest = build_manifest(&bytes).expect("manifest");
        let json: String = serde_json::to_string(&m).expect("json");
        assert!(json.contains("disrobe.nuitka.manifest/v0"));
        assert!(json.contains("standalone"));
    }
}
