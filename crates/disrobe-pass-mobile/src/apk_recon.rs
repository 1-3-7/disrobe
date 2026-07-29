use std::collections::BTreeSet;
use std::io::{Cursor, Read};

use disrobe_core::recon::ioc::{Indicator, extract as ioc_extract};
use disrobe_core::recon::secret_scan::{Finding, scan_bytes};
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::apk_signing::{self, ApkSigningBlockReport};
use crate::arsc::{self, ArscResources};
use crate::axml::{self, AndroidManifestSummary, AxmlDocument};
use crate::error::Result;
use crate::res_decode::{self, ResDecodeReport};

const MAX_TEXT_ASSET: u64 = 16 << 20;
pub(crate) const MAX_PROTECTOR_CARVE_SCAN: u64 = 64 << 20;
const MAX_EMBEDDED_DEX_CARVES: usize = 16;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const DEX_MAGIC_PREFIX: &[u8; 4] = b"dex\n";
const DEX_MAGIC_LEN: usize = 8;
const DEX_FILE_SIZE_OFFSET: usize = 32;
const DEX_FILE_SIZE_LEN: usize = 4;
const MACHO_MAGICS: [[u8; 4]; 5] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xca, 0xfe, 0xba, 0xbe],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteTarget {
    DalvikDex,
    NativeElf,
    NativeMachO,
    DotNetAssembly,
    HermesBytecode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutedChild {
    pub container_path: String,
    pub target: RouteTarget,
    pub size: u64,
    pub abi: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLibrary {
    pub container_path: String,
    pub abi: Option<String>,
    pub size: u64,
    pub is_elf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectorArtifactKind {
    NativeRuntime,
    PackedPayload,
    EmbeddedDex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectorArtifact {
    pub protector: AppProtector,
    pub kind: ProtectorArtifactKind,
    pub container_path: String,
    pub size: u64,
    pub abi: Option<String>,
    pub route: Option<RouteTarget>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfacedSecret {
    pub container_path: String,
    pub code: String,
    pub kind: String,
    pub redacted_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfacedEndpoint {
    pub container_path: String,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppProtector {
    None,
    DexStringEncryption,
    NativePacker,
    CommercialShield,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectorWall {
    pub protector: AppProtector,
    pub evidence: String,
    pub recoverable: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkReconReport {
    pub manifest: Option<AndroidManifestSummary>,
    pub manifest_decoded: bool,
    pub manifest_xml: Option<String>,
    pub resources: Option<ArscReconSummary>,
    pub resources_decoded: ResDecodeReport,
    pub native_libraries: Vec<NativeLibrary>,
    pub abis: Vec<String>,
    pub ios_frameworks: Vec<String>,
    pub ios_dylibs: Vec<String>,
    pub routed_children: Vec<RoutedChild>,
    pub secrets: Vec<SurfacedSecret>,
    pub endpoints: Vec<SurfacedEndpoint>,
    pub protector_walls: Vec<ProtectorWall>,
    pub protector_artifacts: Vec<ProtectorArtifact>,
    pub signing: ApkSigningBlockReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArscReconSummary {
    pub package_names: Vec<String>,
    pub value_string_count: usize,
    pub type_names: Vec<String>,
    pub resource_count: usize,
    pub resolved_resources: Vec<ResolvedResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedResource {
    pub id: String,
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct EmbeddedDexCarve {
    pub container_path: String,
    pub offset: usize,
    pub len: usize,
    pub xor_key: Option<u8>,
    pub evidence: String,
}

#[must_use]
fn abi_of(path: &str) -> Option<String> {
    let mut parts: std::str::Split<'_, char> = path.split('/');
    if parts.next()? != "lib" {
        return None;
    }
    let abi: &str = parts.next()?;
    if matches!(
        abi,
        "arm64-v8a" | "armeabi-v7a" | "armeabi" | "x86" | "x86_64" | "mips" | "mips64"
    ) {
        Some(abi.to_owned())
    } else {
        None
    }
}

fn is_text_asset(path: &str) -> bool {
    let lower: String = path.to_ascii_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".json")
        || lower.ends_with(".xml")
        || lower.ends_with(".html")
        || lower.ends_with(".htm")
        || lower.ends_with(".css")
        || lower.ends_with(".txt")
        || lower.ends_with(".properties")
        || lower.ends_with(".env")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".plist")
        || lower.ends_with(".cfg")
        || lower.ends_with(".conf")
        || lower.ends_with(".pem")
        || lower.ends_with(".map")
}

fn is_macho_magic(magic: [u8; 4]) -> bool {
    MACHO_MAGICS.contains(&magic)
}

pub fn analyze(bytes: &[u8]) -> Result<ApkReconReport> {
    crate::debug::dbg_section("mobile.apk-recon");
    crate::debug::dbg_kv("input_len", || bytes.len().to_string());
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let count: usize = crate::checked_zip_entry_count(archive.len())?;
    crate::debug::dbg_kv("zip_entries", || count.to_string());

    let mut names: Vec<(usize, String, u64)> = Vec::with_capacity(count);
    for i in 0..count {
        if let Ok(f) = archive.by_index(i) {
            names.push((i, f.name().to_owned(), f.size()));
        }
    }

    let mut manifest: Option<AndroidManifestSummary> = None;
    let mut manifest_decoded: bool = false;
    let mut manifest_doc: Option<AxmlDocument> = None;
    let mut resources: Option<ArscReconSummary> = None;
    let mut arsc_table: Option<ArscResources> = None;
    let mut native_libraries: Vec<NativeLibrary> = Vec::new();
    let mut abis: BTreeSet<String> = BTreeSet::new();
    let mut ios_frameworks: BTreeSet<String> = BTreeSet::new();
    let mut ios_dylibs: BTreeSet<String> = BTreeSet::new();
    let mut routed_children: Vec<RoutedChild> = Vec::new();
    let mut secrets: Vec<SurfacedSecret> = Vec::new();
    let mut endpoints: Vec<SurfacedEndpoint> = Vec::new();
    let mut protector_walls: Vec<ProtectorWall> = Vec::new();
    let mut protector_artifacts: Vec<ProtectorArtifact> = Vec::new();

    for (index, name, size) in &names {
        let name: &str = name.as_str();
        let size: u64 = *size;

        if name == "AndroidManifest.xml" {
            if let Ok(raw) = read_entry(&mut archive, *index, size)
                && let Ok(doc) = axml::parse(&raw)
            {
                let summary: AndroidManifestSummary = axml::summarise_manifest(&doc);
                manifest = Some(summary);
                manifest_decoded = true;
                scan_text(name, &raw, &mut secrets, &mut endpoints);
                doc_endpoints(name, &doc, &mut endpoints);
                manifest_doc = Some(doc);
            }
            continue;
        }

        if name == "resources.arsc" {
            if let Ok(raw) = read_entry(&mut archive, *index, size)
                && let Ok(table) = arsc::parse(&raw)
            {
                resources = Some(summarise_arsc(&table));
                scan_arsc_values(name, &table, &mut secrets, &mut endpoints);
                arsc_table = Some(table);
            }
            continue;
        }

        if let Some(abi) = abi_of(name) {
            abis.insert(abi.clone());
            let head: [u8; 4] = read_head(&mut archive, *index);
            let is_elf: bool = head == ELF_MAGIC;
            native_libraries.push(NativeLibrary {
                container_path: name.to_owned(),
                abi: Some(abi.clone()),
                size,
                is_elf,
            });
            if is_protector_native(name) {
                protector_artifacts.push(ProtectorArtifact {
                    protector: AppProtector::CommercialShield,
                    kind: ProtectorArtifactKind::NativeRuntime,
                    container_path: name.to_owned(),
                    size,
                    abi: Some(abi.clone()),
                    route: is_elf.then_some(RouteTarget::NativeElf),
                    evidence: "commercial shield native runtime entry".to_owned(),
                });
            }
            if is_elf {
                routed_children.push(RoutedChild {
                    container_path: name.to_owned(),
                    target: RouteTarget::NativeElf,
                    size,
                    abi: Some(abi),
                });
            }
            if is_protector_native(name)
                && size <= MAX_PROTECTOR_CARVE_SCAN
                && let Ok(raw) = read_entry(&mut archive, *index, size)
            {
                carve_embedded_dex(name, &raw, &mut routed_children, &mut protector_artifacts);
            }
            continue;
        }

        if crate::pass::is_top_level_dex_name(name) {
            routed_children.push(RoutedChild {
                container_path: name.to_owned(),
                target: RouteTarget::DalvikDex,
                size,
                abi: None,
            });
            continue;
        }

        if name.contains(".framework/")
            && let Some(fw) = framework_name(name)
        {
            ios_frameworks.insert(fw);
        }
        if name.ends_with(".dylib") {
            ios_dylibs.insert(name.to_owned());
        }

        if name.ends_with(".dll") && name.starts_with("assemblies/") {
            routed_children.push(RoutedChild {
                container_path: name.to_owned(),
                target: RouteTarget::DotNetAssembly,
                size,
                abi: None,
            });
        }

        if name.ends_with(".hbc") || name.ends_with(".hbcbundle") {
            routed_children.push(RoutedChild {
                container_path: name.to_owned(),
                target: RouteTarget::HermesBytecode,
                size,
                abi: None,
            });
        }

        let app_executable: bool =
            name.contains(".app/") && !name.ends_with('/') && !file_segment_has_extension(name);
        if app_executable && is_macho_magic(read_head(&mut archive, *index)) {
            routed_children.push(RoutedChild {
                container_path: name.to_owned(),
                target: RouteTarget::NativeMachO,
                size,
                abi: None,
            });
        }

        if is_text_asset(name)
            && size <= MAX_TEXT_ASSET
            && let Ok(raw) = read_entry(&mut archive, *index, size)
        {
            scan_text(name, &raw, &mut secrets, &mut endpoints);
        }

        if is_packed_payload_name(name) {
            protector_artifacts.push(ProtectorArtifact {
                protector: AppProtector::CommercialShield,
                kind: ProtectorArtifactKind::PackedPayload,
                container_path: name.to_owned(),
                size,
                abi: None,
                route: None,
                evidence: "known commercial shield payload entry".to_owned(),
            });
        }

        if size <= MAX_PROTECTOR_CARVE_SCAN
            && !crate::pass::is_top_level_dex_name(name)
            && let Ok(raw) = read_entry(&mut archive, *index, size)
        {
            carve_embedded_dex(name, &raw, &mut routed_children, &mut protector_artifacts);
        }
    }

    detect_protectors(
        &names,
        manifest.as_ref(),
        &protector_artifacts,
        &mut protector_walls,
    );

    let manifest_xml: Option<String> = manifest_doc
        .as_ref()
        .map(|doc: &AxmlDocument| doc.to_xml_with_resources(arsc_table.as_ref()));

    let resources_decoded: ResDecodeReport =
        res_decode::decode_archive(&mut archive, &names, arsc_table.as_ref());

    let signing: ApkSigningBlockReport = apk_signing::parse(bytes);

    dedup_secrets(&mut secrets);
    dedup_endpoints(&mut endpoints);
    dedup_protector_artifacts(&mut protector_artifacts);
    routed_children
        .sort_by(|a: &RoutedChild, b: &RoutedChild| a.container_path.cmp(&b.container_path));

    crate::debug::dbg_kv("manifest_decoded", || manifest_decoded.to_string());
    crate::debug::dbg_kv("res_binary_xml_decoded", || {
        resources_decoded.binary_xml_count.to_string()
    });
    crate::debug::dbg_kv("res_values_resources", || {
        resources_decoded.values_resource_count.to_string()
    });
    crate::debug::dbg_kv("native_libraries", || native_libraries.len().to_string());
    crate::debug::dbg_kv("secrets_surfaced", || secrets.len().to_string());
    crate::debug::dbg_kv("endpoints_surfaced", || endpoints.len().to_string());
    crate::debug::dbg_kv("protector_walls", || protector_walls.len().to_string());
    crate::debug::dbg_kv("protector_artifacts", || {
        protector_artifacts.len().to_string()
    });
    crate::debug::dbg_kv("signing_block_present", || {
        signing.signing_block_present.to_string()
    });
    crate::debug::dbg_kv("signing_schemes", || signing.schemes.len().to_string());
    Ok(ApkReconReport {
        manifest,
        manifest_decoded,
        manifest_xml,
        resources,
        resources_decoded,
        native_libraries,
        abis: abis.into_iter().collect(),
        ios_frameworks: ios_frameworks.into_iter().collect(),
        ios_dylibs: ios_dylibs.into_iter().collect(),
        routed_children,
        secrets,
        endpoints,
        protector_walls,
        protector_artifacts,
        signing,
    })
}

fn read_entry(archive: &mut ZipArchive<Cursor<&[u8]>>, index: usize, size: u64) -> Result<Vec<u8>> {
    let f: zip::read::ZipFile<'_> = archive.by_index(index)?;
    let name: String = f.name().to_owned();
    if size != f.size() {
        return Err(crate::error::Error::Zip(format!(
            "zip entry {name} size changed while reading"
        )));
    }
    crate::read_zip_file_bounded(f, &name)
}

fn read_head(archive: &mut ZipArchive<Cursor<&[u8]>>, index: usize) -> [u8; 4] {
    let mut head: [u8; 4] = [0u8; 4];
    if let Ok(mut f) = archive.by_index(index) {
        let _ = f.read_exact(&mut head);
    }
    head
}

fn framework_name(path: &str) -> Option<String> {
    let idx: usize = path.find(".framework/")?;
    let before: &str = &path[..idx];
    let name: &str = before.rsplit('/').next().unwrap_or(before);
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

const MAX_RESOLVED_RESOURCES: usize = 4096;

fn summarise_arsc(table: &ArscResources) -> ArscReconSummary {
    let package_names: Vec<String> = table
        .packages
        .iter()
        .map(|p: &arsc::ArscPackageSummary| p.name.clone())
        .collect();
    let mut type_names: BTreeSet<String> = BTreeSet::new();
    for p in &table.packages {
        for t in &p.type_names {
            if !t.is_empty() {
                type_names.insert(t.clone());
            }
        }
    }
    let mut resolved_resources: Vec<ResolvedResource> = Vec::new();
    for p in &table.packages {
        for e in &p.entries {
            if resolved_resources.len() >= MAX_RESOLVED_RESOURCES {
                break;
            }
            resolved_resources.push(ResolvedResource {
                id: format!("0x{:08x}", e.id),
                name: format!("{}:{}", p.name, e.qualified_name()),
                value: e.value.clone(),
            });
        }
    }
    ArscReconSummary {
        package_names,
        value_string_count: table.value_strings.len(),
        type_names: type_names.into_iter().collect(),
        resource_count: table.resource_count(),
        resolved_resources,
    }
}

fn scan_text(
    container_path: &str,
    raw: &[u8],
    secrets: &mut Vec<SurfacedSecret>,
    endpoints: &mut Vec<SurfacedEndpoint>,
) {
    for f in scan_bytes(raw, Some(container_path)) {
        push_secret(container_path, &f, secrets);
    }
    for ind in ioc_extract(raw) {
        if ind.kind.is_network() {
            push_endpoint(container_path, &ind, endpoints);
        }
    }
}

fn scan_arsc_values(
    container_path: &str,
    table: &ArscResources,
    secrets: &mut Vec<SurfacedSecret>,
    endpoints: &mut Vec<SurfacedEndpoint>,
) {
    let joined: String = table.value_strings.join("\n");
    let raw: &[u8] = joined.as_bytes();
    for f in scan_bytes(raw, Some(container_path)) {
        push_secret(container_path, &f, secrets);
    }
    for ind in ioc_extract(raw) {
        if ind.kind.is_network() {
            push_endpoint(container_path, &ind, endpoints);
        }
    }
}

fn doc_endpoints(container_path: &str, doc: &AxmlDocument, endpoints: &mut Vec<SurfacedEndpoint>) {
    for el in doc.root.descendants() {
        for attr in &el.attributes {
            for ind in ioc_extract(attr.value.as_bytes()) {
                if ind.kind.is_network() {
                    push_endpoint(container_path, &ind, endpoints);
                }
            }
        }
    }
}

fn file_segment_has_extension(path: &str) -> bool {
    path.rsplit('/').next().unwrap_or("").contains('.')
}

fn is_protector_native(path: &str) -> bool {
    path.ends_with("/libjiagu.so")
        || path.ends_with("/libjiagu_art.so")
        || path.ends_with("/libjiagu_x86.so")
        || path.ends_with("/libexec.so")
        || path.ends_with("/libexecmain.so")
        || path.ends_with("/libsecexe.so")
        || path.ends_with("/libsecmain.so")
        || path.ends_with("/libDexHelper.so")
}

fn is_packed_payload_name(path: &str) -> bool {
    path == "assets/o0oo00o0o.dat" || path == "assets/0OO00l111l1l"
}

fn carve_embedded_dex(
    container_path: &str,
    raw: &[u8],
    routed_children: &mut Vec<RoutedChild>,
    protector_artifacts: &mut Vec<ProtectorArtifact>,
) {
    for carve in find_embedded_dex_carves(container_path, raw) {
        let size: u64 = carve.len as u64;
        routed_children.push(RoutedChild {
            container_path: carve.container_path.clone(),
            target: RouteTarget::DalvikDex,
            size,
            abi: None,
        });
        protector_artifacts.push(ProtectorArtifact {
            protector: AppProtector::CommercialShield,
            kind: ProtectorArtifactKind::EmbeddedDex,
            container_path: carve.container_path,
            size,
            abi: None,
            route: Some(RouteTarget::DalvikDex),
            evidence: carve.evidence,
        });
    }
}

pub(crate) fn find_embedded_dex_carves(container_path: &str, raw: &[u8]) -> Vec<EmbeddedDexCarve> {
    let mut out: Vec<EmbeddedDexCarve> = Vec::new();
    collect_plain_dex_carves(container_path, raw, &mut out);
    collect_xor_dex_carves(container_path, raw, &mut out);
    out
}

pub(crate) fn materialize_embedded_dex(raw: &[u8], carve: &EmbeddedDexCarve) -> Vec<u8> {
    let end: usize = carve.offset + carve.len;
    let mut out: Vec<u8> = raw[carve.offset..end].to_vec();
    if let Some(key) = carve.xor_key {
        for b in &mut out {
            *b ^= key;
        }
    }
    out
}

fn collect_plain_dex_carves(container_path: &str, raw: &[u8], out: &mut Vec<EmbeddedDexCarve>) {
    let mut search_from: usize = 0;
    while out.len() < MAX_EMBEDDED_DEX_CARVES && search_from + DEX_MAGIC_LEN <= raw.len() {
        let Some(relative): Option<usize> = raw[search_from..]
            .windows(DEX_MAGIC_LEN)
            .position(is_dex_magic)
        else {
            break;
        };
        let offset: usize = search_from + relative;
        if let Some(len) = embedded_dex_len(raw, offset, None) {
            out.push(EmbeddedDexCarve {
                container_path: format!("{container_path}@0x{offset:x}"),
                offset,
                len,
                xor_key: None,
                evidence: "embedded dex magic carved from packed entry".to_owned(),
            });
            search_from = offset.saturating_add(len.max(DEX_MAGIC_LEN));
        } else {
            search_from = offset.saturating_add(DEX_MAGIC_LEN);
        }
    }
}

fn collect_xor_dex_carves(container_path: &str, raw: &[u8], out: &mut Vec<EmbeddedDexCarve>) {
    let mut offset: usize = 0;
    while out.len() < MAX_EMBEDDED_DEX_CARVES && offset + DEX_MAGIC_LEN <= raw.len() {
        let key: u8 = raw[offset] ^ DEX_MAGIC_PREFIX[0];
        if key != 0
            && is_xor_dex_magic(raw, offset, key)
            && let Some(len) = embedded_dex_len(raw, offset, Some(key))
        {
            out.push(EmbeddedDexCarve {
                container_path: format!("{container_path}@xor{key:02x}@0x{offset:x}"),
                offset,
                len,
                xor_key: Some(key),
                evidence: format!("single-byte xor decoded embedded dex with key 0x{key:02x}"),
            });
            offset = offset.saturating_add(len.max(DEX_MAGIC_LEN));
        } else {
            offset += 1;
        }
    }
}

fn is_dex_magic(window: &[u8]) -> bool {
    window.len() == DEX_MAGIC_LEN
        && &window[..DEX_MAGIC_PREFIX.len()] == DEX_MAGIC_PREFIX
        && window[4].is_ascii_digit()
        && window[5].is_ascii_digit()
        && window[6].is_ascii_digit()
        && window[7] == 0
}

fn is_xor_dex_magic(raw: &[u8], offset: usize, key: u8) -> bool {
    if offset + DEX_MAGIC_LEN > raw.len() {
        return false;
    }
    let window: &[u8] = &raw[offset..offset + DEX_MAGIC_LEN];
    window[0] ^ key == DEX_MAGIC_PREFIX[0]
        && window[1] ^ key == DEX_MAGIC_PREFIX[1]
        && window[2] ^ key == DEX_MAGIC_PREFIX[2]
        && window[3] ^ key == DEX_MAGIC_PREFIX[3]
        && (window[4] ^ key).is_ascii_digit()
        && (window[5] ^ key).is_ascii_digit()
        && (window[6] ^ key).is_ascii_digit()
        && window[7] ^ key == 0
}

fn embedded_dex_len(raw: &[u8], offset: usize, xor_key: Option<u8>) -> Option<usize> {
    let file_size_offset: usize = offset.checked_add(DEX_FILE_SIZE_OFFSET)?;
    let file_size_end: usize = file_size_offset.checked_add(DEX_FILE_SIZE_LEN)?;
    if file_size_end > raw.len() {
        return None;
    }
    let mut size_bytes: [u8; DEX_FILE_SIZE_LEN] = [
        raw[file_size_offset],
        raw[file_size_offset + 1],
        raw[file_size_offset + 2],
        raw[file_size_offset + 3],
    ];
    if let Some(key) = xor_key {
        for b in &mut size_bytes {
            *b ^= key;
        }
    }
    let declared: u32 = u32::from_le_bytes(size_bytes);
    let declared_len: usize = declared as usize;
    if declared_len >= DEX_MAGIC_LEN && offset.checked_add(declared_len)? <= raw.len() {
        Some(declared_len)
    } else {
        None
    }
}

fn push_secret(container_path: &str, f: &Finding, out: &mut Vec<SurfacedSecret>) {
    out.push(SurfacedSecret {
        container_path: container_path.to_owned(),
        code: f.code.clone(),
        kind: format!("{:?}", f.kind),
        redacted_preview: f.preview.clone(),
    });
}

const ENDPOINT_NOISE: &[&str] = &[
    "http://schemas.android.com/apk/res/android",
    "http://schemas.android.com/apk/res-auto",
    "http://schemas.android.com/tools",
    "http://schemas.android.com/aapt",
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/XML/1998/namespace",
    "http://www.w3.org/2000/xmlns/",
    "http://apache.org/cordova",
];

fn is_endpoint_noise(value: &str) -> bool {
    ENDPOINT_NOISE.contains(&value)
        || value.starts_with("http://schemas.android.com/")
        || value.starts_with("http://www.w3.org/")
}

fn push_endpoint(container_path: &str, ind: &Indicator, out: &mut Vec<SurfacedEndpoint>) {
    if is_endpoint_noise(ind.value.as_str()) {
        return;
    }
    out.push(SurfacedEndpoint {
        container_path: container_path.to_owned(),
        kind: ind.kind.label().to_owned(),
        value: ind.value.clone(),
    });
}

fn dedup_secrets(out: &mut Vec<SurfacedSecret>) {
    out.sort_by(|a: &SurfacedSecret, b: &SurfacedSecret| {
        a.container_path
            .cmp(&b.container_path)
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.redacted_preview.cmp(&b.redacted_preview))
    });
    out.dedup_by(|a: &mut SurfacedSecret, b: &mut SurfacedSecret| {
        a.container_path == b.container_path
            && a.code == b.code
            && a.redacted_preview == b.redacted_preview
    });
}

fn dedup_endpoints(out: &mut Vec<SurfacedEndpoint>) {
    out.sort_by(|a: &SurfacedEndpoint, b: &SurfacedEndpoint| {
        a.container_path
            .cmp(&b.container_path)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.value.cmp(&b.value))
    });
    out.dedup_by(|a: &mut SurfacedEndpoint, b: &mut SurfacedEndpoint| {
        a.container_path == b.container_path && a.kind == b.kind && a.value == b.value
    });
}

fn dedup_protector_artifacts(out: &mut Vec<ProtectorArtifact>) {
    out.sort_by(|a: &ProtectorArtifact, b: &ProtectorArtifact| {
        a.container_path
            .cmp(&b.container_path)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    out.dedup_by(|a: &mut ProtectorArtifact, b: &mut ProtectorArtifact| {
        a.container_path == b.container_path && a.kind == b.kind && a.evidence == b.evidence
    });
}

fn detect_protectors(
    names: &[(usize, String, u64)],
    manifest: Option<&AndroidManifestSummary>,
    artifacts: &[ProtectorArtifact],
    out: &mut Vec<ProtectorWall>,
) {
    let has = |needle: &str| -> bool {
        names
            .iter()
            .any(|(_, n, _): &(usize, String, u64)| n.contains(needle))
    };

    if has("/libjiagu.so") || has("/libjiagu_art.so") || has("/libjiagu_x86.so") {
        out.push(ProtectorWall {
            protector: AppProtector::CommercialShield,
            evidence: "libjiagu native runtime present".to_owned(),
            recoverable: false,
            note: "commercial shielding runtime decrypts the real dex at process start; \
                   static analysis surfaces helper libraries and any carved payload dex, but the original plaintext app dex still requires the runtime key path"
                .to_owned(),
        });
    }
    if has("/libexec.so") && has("/libexecmain.so") {
        out.push(ProtectorWall {
            protector: AppProtector::CommercialShield,
            evidence: "libexec.so + libexecmain.so loader pair present".to_owned(),
            recoverable: false,
            note: "runtime-unpacking shield; native helpers are surfaced for follow-up, while the original dex is reconstructed only at runtime".to_owned(),
        });
    }
    if has("/libsecexe.so") || has("/libsecmain.so") || has("/libDexHelper.so") {
        out.push(ProtectorWall {
            protector: AppProtector::CommercialShield,
            evidence: "secneo/bangcle native helper present".to_owned(),
            recoverable: false,
            note: "anti-tamper shield; static pass surfaces native helpers and payload entries, while class decryption still depends on runtime key material".to_owned(),
        });
    }
    let recovered_packed_payload: bool = artifacts.iter().any(|a: &ProtectorArtifact| {
        a.kind == ProtectorArtifactKind::EmbeddedDex
            && is_packed_payload_artifact_path(&a.container_path)
    });
    if (has("assets/o0oo00o0o.dat") || has("assets/0OO00l111l1l")) && !recovered_packed_payload {
        out.push(ProtectorWall {
            protector: AppProtector::CommercialShield,
            evidence: "obfuscated encrypted-payload asset present".to_owned(),
            recoverable: false,
            note: "packed asset did not decode to a valid declared dex through plain or single-byte xor probes; remaining key material is runtime-only".to_owned(),
        });
    }

    if let Some(m) = manifest {
        let stub_app: bool = m.activities.iter().chain(m.services.iter()).any(
            |c: &crate::axml::ComponentSummary| {
                c.name.contains("StubApp") || c.name.contains("ProxyApplication")
            },
        );
        if stub_app
            && out
                .iter()
                .all(|w: &ProtectorWall| w.protector != AppProtector::CommercialShield)
        {
            out.push(ProtectorWall {
                protector: AppProtector::CommercialShield,
                evidence: "manifest declares a stub/proxy bootstrap application".to_owned(),
                recoverable: false,
                note: "packer bootstrap that loads the real application after runtime decryption"
                    .to_owned(),
            });
        }
    }
}

fn is_packed_payload_artifact_path(path: &str) -> bool {
    path.starts_with("assets/o0oo00o0o.dat@") || path.starts_with("assets/0OO00l111l1l@")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn abi_extraction() {
        assert_eq!(
            abi_of("lib/arm64-v8a/libfoo.so").as_deref(),
            Some("arm64-v8a")
        );
        assert_eq!(abi_of("lib/x86_64/libbar.so").as_deref(), Some("x86_64"));
        assert_eq!(abi_of("assets/lib/arm64-v8a/x.so"), None);
        assert_eq!(abi_of("lib/unknown-abi/x.so"), None);
    }

    #[test]
    fn framework_name_extraction() {
        assert_eq!(
            framework_name("Payload/A.app/Frameworks/Realm.framework/Realm").as_deref(),
            Some("Realm")
        );
        assert_eq!(framework_name("no/framework/here"), None);
    }

    #[test]
    fn text_asset_predicate() {
        assert!(is_text_asset("assets/config.json"));
        assert!(is_text_asset("res/raw/app.properties"));
        assert!(!is_text_asset("lib/arm64-v8a/libfoo.so"));
        assert!(!is_text_asset("classes.dex"));
    }
}
