use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;

use serde::Serialize;

use disrobe_pass_native::AuditableCrate;
use disrobe_vulnmatch::{PackageType, PackageUrlError, build_package_url};

const BOM_FORMAT: &str = "CycloneDX";
const SPEC_VERSION: &str = "1.5";
const BOM_VERSION: u32 = 1;
const TOOL_NAME: &str = "disrobe";
const SHA256_ALG: &str = "SHA-256";
const BLAKE3_ALG: &str = "BLAKE3";
const CARGO_AUDITABLE_SOURCE_PROPERTY: &str = "cargo-auditable:source";
const CARGO_COMPONENT_REF_PREFIX: &str = "urn:disrobe:cargo:";
const CARGO_COMPONENT_IDENTITY_DOMAIN: &[u8] = b"disrobe:cyclonedx:cargo-component:v1\0";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
const MAX_CYCLONEDX_PACKAGES: usize = 16_384;
const MAX_CYCLONEDX_COMPONENTS: usize = MAX_CYCLONEDX_PACKAGES + 1;
const MAX_CYCLONEDX_COMPONENT_TEXT_BYTES: usize = 24 * 1024 * 1024;
const MAX_CYCLONEDX_OUTPUT_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug)]
pub(crate) enum CycloneDxError {
    PackageUrl(PackageUrlError),
    TooManyPackages {
        actual: usize,
        limit: usize,
    },
    TooManyComponents {
        actual: usize,
        limit: usize,
    },
    ComponentTextTooLong {
        actual: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        context: &'static str,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
        unit: &'static str,
    },
    OutputTooLong {
        actual: usize,
        limit: usize,
    },
    Serialize(serde_json::Error),
}

impl fmt::Display for CycloneDxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageUrl(error) => write!(formatter, "package URL: {error}"),
            Self::TooManyPackages { actual, limit } => {
                write!(
                    formatter,
                    "package count is {actual}, exceeding the {limit}-package limit"
                )
            }
            Self::TooManyComponents { actual, limit } => {
                write!(
                    formatter,
                    "component count is {actual}, exceeding the {limit}-component limit"
                )
            }
            Self::ComponentTextTooLong { actual, limit } => write!(
                formatter,
                "component text is {actual} bytes, exceeding the {limit}-byte limit"
            ),
            Self::ArithmeticOverflow { context } => write!(formatter, "{context} overflowed"),
            Self::AllocationFailed {
                context,
                requested,
                unit,
            } => {
                write!(
                    formatter,
                    "{context} allocation of {requested} {unit} failed"
                )
            }
            Self::OutputTooLong { actual, limit } => write!(
                formatter,
                "output would reach {actual} bytes, exceeding the {limit}-byte limit"
            ),
            Self::Serialize(error) => write!(formatter, "serialization failed: {error}"),
        }
    }
}

impl std::error::Error for CycloneDxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackageUrl(error) => Some(error),
            Self::Serialize(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PackageUrlError> for CycloneDxError {
    fn from(error: PackageUrlError) -> Self {
        Self::PackageUrl(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycloneDxWriteFailure {
    Limit { actual: usize },
}

struct BoundedCycloneDxSizer {
    bytes: usize,
    failure: Option<CycloneDxWriteFailure>,
}

impl BoundedCycloneDxSizer {
    const fn new() -> Self {
        Self {
            bytes: 0,
            failure: None,
        }
    }

    const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Write for BoundedCycloneDxSizer {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let required: usize = self.bytes.checked_add(buffer.len()).ok_or_else(|| {
            self.failure = Some(CycloneDxWriteFailure::Limit { actual: usize::MAX });
            std::io::Error::other("CycloneDX output size overflowed")
        })?;
        if required > MAX_CYCLONEDX_OUTPUT_BYTES {
            self.failure = Some(CycloneDxWriteFailure::Limit { actual: required });
            return Err(std::io::Error::other("CycloneDX output limit exceeded"));
        }
        self.bytes = required;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CycloneDxBom {
    pub(crate) bom_format: &'static str,
    pub(crate) spec_version: &'static str,
    pub(crate) version: u32,
    pub(crate) metadata: Metadata,
    pub(crate) components: Vec<Component>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) timestamp: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tools: Vec<Tool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Tool {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ComponentType {
    Library,
    Application,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub(crate) struct Component {
    #[serde(rename = "type")]
    pub(crate) component_type: ComponentType,
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) purl: Option<String>,
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub(crate) bom_ref: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) hashes: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) properties: Vec<Property>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Hash {
    pub(crate) alg: &'static str,
    pub(crate) content: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Property {
    pub(crate) name: &'static str,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuditableComponentIdentity {
    digest: [u8; 32],
    input_index: usize,
}

impl Tool {
    #[inline]
    pub(crate) const fn disrobe() -> Self {
        Self {
            name: TOOL_NAME,
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

fn canonical_auditable_source(source: Option<&str>) -> Option<&str> {
    match source {
        None
        | Some(
            ""
            | "crates.io"
            | "registry+https://github.com/rust-lang/crates.io-index"
            | "sparse+https://index.crates.io"
            | "sparse+https://index.crates.io/",
        ) => None,
        Some(value) => Some(value),
    }
}

fn update_identity_field(hasher: &mut blake3::Hasher, value: &[u8]) -> Result<(), CycloneDxError> {
    let length: u64 =
        u64::try_from(value.len()).map_err(|_| CycloneDxError::ArithmeticOverflow {
            context: "CycloneDX component identity field length",
        })?;
    hasher.update(&length.to_le_bytes());
    hasher.update(value);
    Ok(())
}

fn auditable_component_digest(
    purl: &str,
    canonical_source: Option<&str>,
) -> Result<[u8; 32], CycloneDxError> {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    hasher.update(CARGO_COMPONENT_IDENTITY_DOMAIN);
    update_identity_field(&mut hasher, purl.as_bytes())?;
    match canonical_source {
        Some(source) => {
            hasher.update(&[1]);
            update_identity_field(&mut hasher, source.as_bytes())?;
        }
        None => {
            hasher.update(&[0]);
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn auditable_purl(krate: &AuditableCrate) -> Result<String, CycloneDxError> {
    let qualifiers: BTreeMap<String, String> = BTreeMap::new();
    Ok(build_package_url(
        PackageType::Cargo,
        None,
        &krate.name,
        Some(&krate.version),
        &qualifiers,
        None,
    )?)
}

fn same_auditable_component(
    left: &AuditableCrate,
    right: &AuditableCrate,
) -> Result<bool, CycloneDxError> {
    let left_purl: String = auditable_purl(left)?;
    let right_purl: String = auditable_purl(right)?;
    Ok(left_purl == right_purl
        && canonical_auditable_source(left.source.as_deref())
            == canonical_auditable_source(right.source.as_deref()))
}

fn source_qualified_bom_ref(
    purl: &str,
    source: Option<&str>,
    identity_digest: [u8; 32],
) -> Result<String, CycloneDxError> {
    if source.is_none() {
        return clone_component_text(purl);
    }
    let requested: usize = CARGO_COMPONENT_REF_PREFIX.len().checked_add(64).ok_or(
        CycloneDxError::ArithmeticOverflow {
            context: "CycloneDX component reference length",
        },
    )?;
    let mut reference: String = String::new();
    reference
        .try_reserve_exact(requested)
        .map_err(|_| CycloneDxError::AllocationFailed {
            context: "CycloneDX component reference",
            requested,
            unit: "bytes",
        })?;
    reference.push_str(CARGO_COMPONENT_REF_PREFIX);
    for byte in identity_digest {
        reference.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        reference.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    Ok(reference)
}

pub(crate) fn component_from_crate(krate: &AuditableCrate) -> Result<Component, CycloneDxError> {
    let purl: String = auditable_purl(krate)?;
    let source: Option<&str> = canonical_auditable_source(krate.source.as_deref());
    let identity_digest: [u8; 32] = auditable_component_digest(&purl, source)?;
    let bom_ref: String = source_qualified_bom_ref(&purl, source, identity_digest)?;
    let mut properties: Vec<Property> = Vec::new();
    if let Some(value) = source {
        properties
            .try_reserve_exact(1)
            .map_err(|_| CycloneDxError::AllocationFailed {
                context: "CycloneDX component property vector",
                requested: 1,
                unit: "properties",
            })?;
        properties.push(Property {
            name: CARGO_AUDITABLE_SOURCE_PROPERTY,
            value: clone_component_text(value)?,
        });
    }
    Ok(Component {
        component_type: ComponentType::Library,
        name: clone_component_text(&krate.name)?,
        version: Some(clone_component_text(&krate.version)?),
        purl: Some(purl),
        bom_ref: Some(bom_ref),
        hashes: Vec::new(),
        properties,
    })
}

pub(crate) fn application_component(
    name: String,
    sha256_hex: String,
    blake3_hex: String,
) -> Component {
    Component {
        component_type: ComponentType::Application,
        name,
        version: None,
        purl: None,
        bom_ref: None,
        hashes: vec![
            Hash {
                alg: SHA256_ALG,
                content: sha256_hex,
            },
            Hash {
                alg: BLAKE3_ALG,
                content: blake3_hex,
            },
        ],
        properties: Vec::new(),
    }
}

fn unique_auditable_component_indices(
    crates: &[AuditableCrate],
) -> Result<Vec<usize>, CycloneDxError> {
    let identity_requested: usize = crates
        .len()
        .checked_mul(std::mem::size_of::<AuditableComponentIdentity>())
        .ok_or(CycloneDxError::ArithmeticOverflow {
            context: "CycloneDX component identity allocation size",
        })?;
    let mut identities: Vec<AuditableComponentIdentity> = Vec::new();
    identities
        .try_reserve_exact(crates.len())
        .map_err(|_| CycloneDxError::AllocationFailed {
            context: "CycloneDX component identity vector",
            requested: identity_requested,
            unit: "bytes",
        })?;
    for (input_index, krate) in crates.iter().enumerate() {
        let purl: String = auditable_purl(krate)?;
        let source: Option<&str> = canonical_auditable_source(krate.source.as_deref());
        identities.push(AuditableComponentIdentity {
            digest: auditable_component_digest(&purl, source)?,
            input_index,
        });
    }
    identities.sort_unstable_by(
        |left: &AuditableComponentIdentity, right: &AuditableComponentIdentity| {
            left.digest
                .cmp(&right.digest)
                .then(left.input_index.cmp(&right.input_index))
        },
    );

    let index_requested: usize = crates
        .len()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or(CycloneDxError::ArithmeticOverflow {
            context: "CycloneDX unique component index allocation size",
        })?;
    let mut unique: Vec<usize> = Vec::new();
    unique
        .try_reserve_exact(crates.len())
        .map_err(|_| CycloneDxError::AllocationFailed {
            context: "CycloneDX unique component index vector",
            requested: index_requested,
            unit: "bytes",
        })?;
    let mut group_start: usize = 0;
    while group_start < identities.len() {
        let digest: [u8; 32] = identities[group_start].digest;
        let mut group_end: usize = group_start + 1;
        while group_end < identities.len() && identities[group_end].digest == digest {
            group_end += 1;
        }
        let unique_group_start: usize = unique.len();
        for identity in &identities[group_start..group_end] {
            let candidate: &AuditableCrate = &crates[identity.input_index];
            let mut duplicate: bool = false;
            for index in &unique[unique_group_start..] {
                if same_auditable_component(candidate, &crates[*index])? {
                    duplicate = true;
                    break;
                }
            }
            if !duplicate {
                unique.push(identity.input_index);
            }
        }
        group_start = group_end;
    }
    unique.sort_unstable();
    Ok(unique)
}

impl CycloneDxBom {
    pub(crate) fn from_crates(
        timestamp: Option<String>,
        root: Option<Component>,
        crates: &[AuditableCrate],
    ) -> Result<Self, CycloneDxError> {
        if crates.len() > MAX_CYCLONEDX_PACKAGES {
            return Err(CycloneDxError::TooManyPackages {
                actual: crates.len(),
                limit: MAX_CYCLONEDX_PACKAGES,
            });
        }
        let unique_indices: Vec<usize> = unique_auditable_component_indices(crates)?;
        let component_count: usize = unique_indices
            .len()
            .checked_add(usize::from(root.is_some()))
            .ok_or(CycloneDxError::ArithmeticOverflow {
                context: "CycloneDX component count",
            })?;
        if component_count > MAX_CYCLONEDX_COMPONENTS {
            return Err(CycloneDxError::TooManyComponents {
                actual: component_count,
                limit: MAX_CYCLONEDX_COMPONENTS,
            });
        }
        let mut components: Vec<Component> = Vec::new();
        components.try_reserve_exact(component_count).map_err(|_| {
            CycloneDxError::AllocationFailed {
                context: "CycloneDX component vector",
                requested: component_count,
                unit: "components",
            }
        })?;
        let mut component_text_bytes: usize = 0;
        if let Some(app) = root {
            component_text_bytes = checked_component_text_total(component_text_bytes, &app)?;
            components.push(app);
        }
        for index in unique_indices {
            let krate: &AuditableCrate = &crates[index];
            let component: Component = component_from_crate(krate)?;
            component_text_bytes = checked_component_text_total(component_text_bytes, &component)?;
            components.push(component);
        }
        Ok(Self {
            bom_format: BOM_FORMAT,
            spec_version: SPEC_VERSION,
            version: BOM_VERSION,
            metadata: Metadata {
                timestamp,
                tools: vec![Tool::disrobe()],
            },
            components,
        })
    }
}

pub(crate) fn to_pretty_json(bom: &CycloneDxBom) -> Result<Vec<u8>, CycloneDxError> {
    let mut sizer: BoundedCycloneDxSizer = BoundedCycloneDxSizer::new();
    if let Err(error) = serde_json::to_writer_pretty(&mut sizer, bom) {
        return match sizer.failure {
            Some(CycloneDxWriteFailure::Limit { actual }) => Err(CycloneDxError::OutputTooLong {
                actual,
                limit: MAX_CYCLONEDX_OUTPUT_BYTES,
            }),
            None => Err(CycloneDxError::Serialize(error)),
        };
    }
    let output_bytes: usize = sizer.bytes();
    let mut output: Vec<u8> = Vec::new();
    output
        .try_reserve_exact(output_bytes)
        .map_err(|_| CycloneDxError::AllocationFailed {
            context: "CycloneDX output",
            requested: output_bytes,
            unit: "bytes",
        })?;
    serde_json::to_writer_pretty(&mut output, bom).map_err(CycloneDxError::Serialize)?;
    if output.len() > MAX_CYCLONEDX_OUTPUT_BYTES {
        return Err(CycloneDxError::OutputTooLong {
            actual: output.len(),
            limit: MAX_CYCLONEDX_OUTPUT_BYTES,
        });
    }
    Ok(output)
}

fn clone_component_text(value: &str) -> Result<String, CycloneDxError> {
    let mut output: String = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| CycloneDxError::AllocationFailed {
            context: "CycloneDX component text",
            requested: value.len(),
            unit: "bytes",
        })?;
    output.push_str(value);
    Ok(output)
}

fn checked_component_text_total(
    current: usize,
    component: &Component,
) -> Result<usize, CycloneDxError> {
    let component_bytes: usize = [
        component.name.len(),
        component.version.as_ref().map_or(0, String::len),
        component.purl.as_ref().map_or(0, String::len),
        component.bom_ref.as_ref().map_or(0, String::len),
        component
            .hashes
            .iter()
            .try_fold(0usize, |total: usize, hash: &Hash| {
                total
                    .checked_add(hash.alg.len())
                    .and_then(|length: usize| length.checked_add(hash.content.len()))
            })
            .ok_or(CycloneDxError::ArithmeticOverflow {
                context: "CycloneDX hash text size",
            })?,
        component
            .properties
            .iter()
            .try_fold(0usize, |total: usize, property: &Property| {
                total
                    .checked_add(property.name.len())
                    .and_then(|length: usize| length.checked_add(property.value.len()))
            })
            .ok_or(CycloneDxError::ArithmeticOverflow {
                context: "CycloneDX property text size",
            })?,
    ]
    .into_iter()
    .try_fold(0usize, |total: usize, length: usize| {
        total.checked_add(length)
    })
    .ok_or(CycloneDxError::ArithmeticOverflow {
        context: "CycloneDX component text size",
    })?;
    let total: usize =
        current
            .checked_add(component_bytes)
            .ok_or(CycloneDxError::ArithmeticOverflow {
                context: "CycloneDX aggregate component text size",
            })?;
    if total > MAX_CYCLONEDX_COMPONENT_TEXT_BYTES {
        return Err(CycloneDxError::ComponentTextTooLong {
            actual: total,
            limit: MAX_CYCLONEDX_COMPONENT_TEXT_BYTES,
        });
    }
    Ok(total)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn krate(name: &str, version: &str) -> AuditableCrate {
        AuditableCrate {
            name: name.to_owned(),
            version: version.to_owned(),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
        }
    }

    fn to_value(bom: &CycloneDxBom) -> Value {
        serde_json::to_value(bom).expect("serialize cyclonedx bom")
    }

    #[test]
    fn full_shape_is_faithful() {
        let root: Component =
            application_component("hello".to_owned(), "a".repeat(64), "b".repeat(64));
        let crates: Vec<AuditableCrate> = vec![krate("serde", "1.0.0"), krate("anyhow", "1.0.86")];
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(None, Some(root), &crates).expect("valid crate purls");
        let v: Value = to_value(&bom);

        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        assert_eq!(v["version"], 1);
        assert!(v["version"].is_u64());

        let tool: &Value = &v["metadata"]["tools"][0];
        assert_eq!(tool["name"], "disrobe");
        assert!(tool["version"].is_string());

        let components: &Vec<Value> = v["components"].as_array().expect("components array");
        assert_eq!(components.len(), 3);

        let app: &Value = &components[0];
        assert_eq!(app["type"], "application");
        assert_eq!(app["name"], "hello");
        assert_eq!(app["hashes"][0]["alg"], "SHA-256");
        assert!(app["hashes"][0]["content"].is_string());
        assert_eq!(app["hashes"][1]["alg"], "BLAKE3");

        let lib: &Value = &components[1];
        assert_eq!(lib["type"], "library");
        assert_eq!(lib["name"], "serde");
        assert_eq!(lib["version"], "1.0.0");
        assert_eq!(lib["purl"], "pkg:cargo/serde@1.0.0");
        assert_eq!(lib["bom-ref"], "pkg:cargo/serde@1.0.0");
    }

    #[test]
    fn empty_crates_is_valid_bom() {
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(None, None, &[]).expect("empty crate list");
        let v: Value = to_value(&bom);
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        assert!(v["version"].is_u64());
        assert_eq!(v["components"].as_array().expect("components").len(), 0);
        assert_eq!(v["metadata"]["tools"][0]["name"], "disrobe");
    }

    #[test]
    fn timestamp_present_when_supplied() {
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(Some("2026-06-01T00:00:00Z".to_owned()), None, &[])
                .expect("empty crate list");
        let v: Value = to_value(&bom);
        assert_eq!(v["metadata"]["timestamp"], "2026-06-01T00:00:00Z");
    }

    #[test]
    fn timestamp_omitted_when_absent() {
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(None, None, &[]).expect("empty crate list");
        let v: Value = to_value(&bom);
        assert!(v["metadata"].get("timestamp").is_none());
    }

    #[test]
    fn purl_is_faithful() {
        let component: Component =
            component_from_crate(&krate("anyhow", "1.0.86")).expect("valid crate purl");
        assert_eq!(component.purl.as_deref(), Some("pkg:cargo/anyhow@1.0.86"));
        let encoded: Component = component_from_crate(&krate("name/with space", "1.0+build"))
            .expect("encodable crate purl");
        assert_eq!(
            encoded.purl.as_deref(),
            Some("pkg:cargo/name%2Fwith%20space@1.0%2Bbuild")
        );
        assert!(CycloneDxBom::from_crates(None, None, &[krate("", "1.0")]).is_err());
    }

    #[test]
    fn distinct_auditable_sources_have_unique_refs_and_source_properties() {
        let crates: Vec<AuditableCrate> = vec![
            AuditableCrate {
                name: "shared".to_owned(),
                version: "1.0.0".to_owned(),
                source: Some("registry+https://packages.example.invalid/index".to_owned()),
            },
            AuditableCrate {
                name: "shared".to_owned(),
                version: "1.0.0".to_owned(),
                source: Some("git+https://example.invalid/shared?rev=abc".to_owned()),
            },
        ];
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(None, None, &crates).expect("valid source identities");
        let value: Value = to_value(&bom);
        let components: &Vec<Value> = value["components"].as_array().expect("components array");

        assert_eq!(components.len(), 2);
        assert_eq!(components[0]["purl"], "pkg:cargo/shared@1.0.0");
        assert_eq!(components[1]["purl"], "pkg:cargo/shared@1.0.0");
        assert_ne!(components[0]["bom-ref"], components[1]["bom-ref"]);
        assert_eq!(
            components[0]["properties"][0],
            serde_json::json!({
                "name": "cargo-auditable:source",
                "value": "registry+https://packages.example.invalid/index"
            })
        );
        assert_eq!(
            components[1]["properties"][0],
            serde_json::json!({
                "name": "cargo-auditable:source",
                "value": "git+https://example.invalid/shared?rev=abc"
            })
        );
    }

    #[test]
    fn exact_auditable_package_duplicates_collapse_to_one_component() {
        let duplicate: AuditableCrate = krate("serde", "1.0.203");
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(None, None, &[duplicate.clone(), duplicate])
                .expect("exact duplicate should collapse");

        assert_eq!(bom.components.len(), 1);
    }

    #[test]
    fn crates_io_source_spellings_share_the_bare_purl_identity() {
        let crates: Vec<AuditableCrate> = [
            "crates.io",
            "registry+https://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io",
        ]
        .into_iter()
        .map(|source: &str| AuditableCrate {
            name: "serde".to_owned(),
            version: "1.0.203".to_owned(),
            source: Some(source.to_owned()),
        })
        .collect();
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(None, None, &crates).expect("valid crates.io identities");
        let value: Value = to_value(&bom);
        let components: &Vec<Value> = value["components"].as_array().expect("components array");

        assert_eq!(components.len(), 1);
        assert_eq!(components[0]["purl"], "pkg:cargo/serde@1.0.203");
        assert_eq!(components[0]["bom-ref"], "pkg:cargo/serde@1.0.203");
        assert!(components[0].get("properties").is_none());
    }

    #[test]
    fn component_count_is_bounded_before_bom_allocation() {
        let crates: Vec<AuditableCrate> = vec![krate("a", "1"); 16_385];
        assert!(matches!(
            CycloneDxBom::from_crates(None, None, &crates),
            Err(CycloneDxError::TooManyPackages {
                actual: 16_385,
                limit: 16_384
            })
        ));
    }

    #[test]
    fn aggregate_component_text_is_bounded() {
        let encoded_name: String = "\0".repeat(16_000);
        let crates: Vec<AuditableCrate> = (0..230)
            .map(|index: usize| krate(&encoded_name, &index.to_string()))
            .collect();
        assert!(matches!(
            CycloneDxBom::from_crates(None, None, &crates),
            Err(CycloneDxError::ComponentTextTooLong { .. })
        ));
    }

    #[test]
    fn library_component_omits_hashes() {
        let c: Component =
            component_from_crate(&krate("serde", "1.0.0")).expect("valid crate purl");
        let v: Value = serde_json::to_value(&c).expect("serialize component");
        assert!(v.get("hashes").is_none());
        assert!(v.get("version").is_some());
    }

    #[test]
    fn component_type_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(ComponentType::Library).expect("lib"),
            Value::String("library".to_owned())
        );
        assert_eq!(
            serde_json::to_value(ComponentType::Application).expect("app"),
            Value::String("application".to_owned())
        );
    }
}
