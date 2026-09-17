use serde::{Deserialize, Serialize};

use crate::apk_sig::{ApkSignatureReport, CertificateInfo};
use crate::arsc::{ResourceTable, parse_arsc};
use crate::axml::{AxmlTree, parse as parse_axml};
use crate::dex::{DexFile, parse as parse_dex};
use crate::error::{Error, Result};
use crate::jar::{ApkExtract, extract_apk};
use crate::jni::{JniSurfaceReport, analyze as analyze_jni};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceEntrySummary {
    pub id: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkResourceReport {
    pub manifest_xml: Option<String>,
    pub package: Option<String>,
    pub resource_table_present: bool,
    pub package_count: usize,
    pub resource_entry_count: usize,
    pub resources: Vec<ResourceEntrySummary>,
    pub certificates: Vec<CertificateInfo>,
    pub dex_count: usize,
    pub native_lib_count: usize,
    pub jni: JniSurfaceReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkReconstruction {
    pub r_txt: String,
    pub r_java: String,
    pub values_xml: std::collections::BTreeMap<String, String>,
}

impl ApkReconstruction {
    pub fn from_apk(bytes: &[u8]) -> Result<Self> {
        let extract: ApkExtract = extract_apk(bytes)?;
        let table: ResourceTable = match extract.resources_arsc.as_deref() {
            Some(arsc) => parse_arsc(arsc)?,
            None => return Err(Error::BadArscChunk(0)),
        };
        let package: String = extract
            .manifest_bytes
            .as_deref()
            .and_then(|m: &[u8]| parse_axml(m).ok())
            .as_ref()
            .and_then(extract_package)
            .unwrap_or_default();
        Ok(Self {
            r_txt: table.r_txt(),
            r_java: table.r_java(&package),
            values_xml: table.values_xml(),
        })
    }
}

pub fn decode_manifest(manifest_bytes: &[u8], table: Option<&ResourceTable>) -> Result<String> {
    let tree: AxmlTree = parse_axml(manifest_bytes)?;
    Ok(match table {
        Some(t) => tree.to_xml_with_resolver(Some(t)),
        None => tree.to_xml(),
    })
}

fn extract_package(tree: &AxmlTree) -> Option<String> {
    for node in &tree.events {
        if let crate::axml::AxmlNode::StartElement {
            name, attributes, ..
        } = node
            && name == "manifest"
        {
            for attr in attributes {
                if attr.name == "package" {
                    return attr.raw_value.clone();
                }
            }
        }
    }
    None
}

pub fn analyze_apk(bytes: &[u8]) -> Result<ApkResourceReport> {
    let extract: ApkExtract = extract_apk(bytes)?;
    let table: Option<ResourceTable> = match extract.resources_arsc.as_deref() {
        Some(arsc) => Some(parse_arsc(arsc)?),
        None => None,
    };

    let mut manifest_xml: Option<String> = None;
    let mut package: Option<String> = None;
    if let Some(manifest) = extract.manifest_bytes.as_deref() {
        let tree: AxmlTree = parse_axml(manifest)?;
        package = extract_package(&tree);
        manifest_xml = Some(match table.as_ref() {
            Some(t) => tree.to_xml_with_resolver(Some(t)),
            None => tree.to_xml(),
        });
    }

    let signatures: ApkSignatureReport =
        crate::apk_sig::verify(bytes).unwrap_or_else(|_| ApkSignatureReport::default());
    let certificates: Vec<CertificateInfo> =
        signatures.certificates().into_iter().cloned().collect();

    let parsed_dexes: Vec<(String, DexFile, Vec<u8>)> = extract
        .dex_files
        .iter()
        .filter_map(|(name, raw): (&String, &Vec<u8>)| {
            parse_dex(raw)
                .ok()
                .map(|d: DexFile| (name.clone(), d, raw.clone()))
        })
        .collect();
    let dex_refs: Vec<(&str, &DexFile, &[u8])> = parsed_dexes
        .iter()
        .map(|(name, dex, raw): &(String, DexFile, Vec<u8>)| (name.as_str(), dex, raw.as_slice()))
        .collect();
    let lib_refs: Vec<(&str, &[u8])> = extract
        .native_libs
        .iter()
        .map(|(path, raw): (&String, &Vec<u8>)| (path.as_str(), raw.as_slice()))
        .collect();
    let jni: JniSurfaceReport = analyze_jni(&dex_refs, &lib_refs);
    let dex_count: usize = extract.dex_files.len();
    let native_lib_count: usize = extract.native_libs.len();

    let (package_count, resource_entry_count, resources): (
        usize,
        usize,
        Vec<ResourceEntrySummary>,
    ) = match table.as_ref() {
        Some(t) => {
            let resources: Vec<ResourceEntrySummary> = t
                .id_map()
                .into_iter()
                .map(|(id, name): (u32, String)| ResourceEntrySummary { id, name })
                .collect();
            (t.packages.len(), t.entry_count(), resources)
        }
        None => (0, 0, Vec::new()),
    };

    Ok(ApkResourceReport {
        manifest_xml,
        package,
        resource_table_present: table.is_some(),
        package_count,
        resource_entry_count,
        resources,
        certificates,
        dex_count,
        native_lib_count,
        jni,
    })
}

pub fn analyze_manifest_bytes(manifest_bytes: &[u8], arsc_bytes: Option<&[u8]>) -> Result<String> {
    if manifest_bytes
        .first_chunk::<2>()
        .map(|c: &[u8; 2]| u16::from_le_bytes(*c))
        != Some(0x0003)
    {
        return Err(Error::BadAxmlMagic);
    }
    let table: Option<ResourceTable> = match arsc_bytes {
        Some(arsc) => Some(parse_arsc(arsc)?),
        None => None,
    };
    decode_manifest(manifest_bytes, table.as_ref())
}
