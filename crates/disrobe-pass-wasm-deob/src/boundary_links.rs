use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BOUNDARY_LINKS_SCHEMA_VERSION: u32 = 1;
pub const MAX_BOUNDARY_LINKS_JSON_BYTES: usize = 1_048_576;
pub const MAX_BOUNDARY_LINKS: usize = 2_048;
pub const MAX_BOUNDARY_LINK_STRING_BYTES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct BoundaryLanguage(String);

impl BoundaryLanguage {
    pub fn new(value: String) -> Result<Self, BoundaryLinksError> {
        if value.len() > MAX_BOUNDARY_LINK_STRING_BYTES || !is_canonical_language(&value) {
            return Err(BoundaryLinksError::InvalidLanguage { value });
        }
        Ok(Self(value))
    }

    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn javascript() -> Self {
        Self("javascript".to_owned())
    }

    pub(crate) fn webassembly() -> Self {
        Self("webassembly".to_owned())
    }
}

impl<'de> Deserialize<'de> for BoundaryLanguage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundarySymbolKind {
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryIdentitySource {
    BoundaryField,
    NameSection,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundarySymbol {
    pub language: BoundaryLanguage,
    pub kind: BoundarySymbolKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    pub identity_source: BoundaryIdentitySource,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum BoundaryEvidence {
    WasmImport { module: String, field: String },
    WasmExport { field: String },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryLink {
    pub source: BoundarySymbol,
    pub target: BoundarySymbol,
    pub evidence: BoundaryEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryLinks {
    schema_version: u32,
    links: Vec<BoundaryLink>,
}

#[derive(Debug, Deserialize)]
struct BoundaryLinksVersion {
    schema_version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryLinksWire {
    schema_version: u32,
    links: Vec<BoundaryLink>,
}

#[derive(Debug, Deserialize)]
struct BoundaryLinksLanguageWire {
    links: Vec<BoundaryLinkLanguageWire>,
}

#[derive(Debug, Deserialize)]
struct BoundaryLinkLanguageWire {
    source: BoundarySymbolLanguageWire,
    target: BoundarySymbolLanguageWire,
}

#[derive(Debug, Deserialize)]
struct BoundarySymbolLanguageWire {
    language: String,
}

#[derive(Debug, Error)]
pub enum BoundaryLinksError {
    #[error("boundary language `{value}` is not a canonical language tag")]
    InvalidLanguage { value: String },
    #[error("boundary link {link_index} has a noncanonical {endpoint} language tag")]
    NonCanonicalLanguage {
        link_index: usize,
        endpoint: &'static str,
    },
    #[error("boundary-links input has {size} bytes, exceeding the {maximum}-byte limit")]
    InputTooLarge { size: usize, maximum: usize },
    #[error("boundary-links input has {count} links, exceeding the {maximum}-link limit")]
    TooManyLinks { count: usize, maximum: usize },
    #[error(
        "boundary link {link_index} field {field} has {size} bytes, exceeding the {maximum}-byte limit"
    )]
    StringTooLong {
        link_index: usize,
        field: &'static str,
        size: usize,
        maximum: usize,
    },
    #[error("boundary link {link_index} has an empty {endpoint} name")]
    EmptySymbolName {
        link_index: usize,
        endpoint: &'static str,
    },
    #[error("boundary link {link_index} does not cross languages")]
    SameLanguage { link_index: usize },
    #[error("boundary link {link_index} has evidence inconsistent with its endpoints")]
    InconsistentEvidence { link_index: usize },
    #[error("unsupported boundary-links schema version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("invalid boundary-links JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl BoundaryLinks {
    pub fn new(mut links: Vec<BoundaryLink>) -> Result<Self, BoundaryLinksError> {
        validate_link_count(links.len())?;
        validate_links(&links)?;
        links.sort_unstable();
        links.dedup();
        Ok(Self {
            schema_version: BOUNDARY_LINKS_SCHEMA_VERSION,
            links,
        })
    }

    #[inline]
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[inline]
    #[must_use]
    pub fn links(&self) -> &[BoundaryLink] {
        &self.links
    }

    pub fn to_json(&self) -> Result<Vec<u8>, BoundaryLinksError> {
        let encoded: Vec<u8> = serde_json::to_vec(self)?;
        validate_input_size(encoded.len())?;
        Ok(encoded)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, BoundaryLinksError> {
        validate_input_size(bytes.len())?;
        let version: BoundaryLinksVersion = serde_json::from_slice(bytes)?;
        if version.schema_version != BOUNDARY_LINKS_SCHEMA_VERSION {
            return Err(BoundaryLinksError::UnsupportedVersion {
                version: version.schema_version,
            });
        }
        let languages: BoundaryLinksLanguageWire = serde_json::from_slice(bytes)?;
        validate_link_count(languages.links.len())?;
        for (link_index, link) in languages.links.iter().enumerate() {
            validate_language(&link.source.language, link_index, "source")?;
            validate_language(&link.target.language, link_index, "target")?;
        }
        let wire: BoundaryLinksWire = serde_json::from_slice(bytes)?;
        if wire.schema_version != BOUNDARY_LINKS_SCHEMA_VERSION {
            return Err(BoundaryLinksError::UnsupportedVersion {
                version: wire.schema_version,
            });
        }
        validate_link_count(wire.links.len())?;
        Self::new(wire.links)
    }
}

impl Default for BoundaryLinks {
    fn default() -> Self {
        Self {
            schema_version: BOUNDARY_LINKS_SCHEMA_VERSION,
            links: Vec::new(),
        }
    }
}

fn validate_links(links: &[BoundaryLink]) -> Result<(), BoundaryLinksError> {
    for (link_index, link) in links.iter().enumerate() {
        validate_symbol(&link.source, link_index, "source")?;
        validate_symbol(&link.target, link_index, "target")?;
        match &link.evidence {
            BoundaryEvidence::WasmImport { module, field } => {
                validate_string(module, link_index, "evidence.module")?;
                validate_string(field, link_index, "evidence.field")?;
            }
            BoundaryEvidence::WasmExport { field } => {
                validate_string(field, link_index, "evidence.field")?;
            }
        }
        if link.source.language == link.target.language {
            return Err(BoundaryLinksError::SameLanguage { link_index });
        }
        let evidence_is_consistent: bool = match &link.evidence {
            BoundaryEvidence::WasmImport { module, field } => {
                link.source.language.as_str() == "javascript"
                    && link.target.language.as_str() == "webassembly"
                    && link.source.kind == BoundarySymbolKind::Function
                    && link.target.kind == BoundarySymbolKind::Function
                    && link.source.module.as_ref() == Some(module)
                    && link.source.name == *field
                    && link.source.index.is_none()
                    && link.target.index.is_some()
            }
            BoundaryEvidence::WasmExport { field } => {
                link.source.language.as_str() == "webassembly"
                    && link.target.language.as_str() == "javascript"
                    && link.source.kind == BoundarySymbolKind::Function
                    && link.target.kind == BoundarySymbolKind::Function
                    && link.source.index.is_some()
                    && link.target.index.is_none()
                    && link.target.name == *field
            }
        };
        if !evidence_is_consistent {
            return Err(BoundaryLinksError::InconsistentEvidence { link_index });
        }
    }
    Ok(())
}

fn validate_symbol(
    symbol: &BoundarySymbol,
    link_index: usize,
    endpoint: &'static str,
) -> Result<(), BoundaryLinksError> {
    validate_language(symbol.language.as_str(), link_index, endpoint)?;
    if let Some(module) = &symbol.module {
        validate_string(
            module,
            link_index,
            if endpoint == "source" {
                "source.module"
            } else {
                "target.module"
            },
        )?;
    }
    validate_string(
        &symbol.name,
        link_index,
        if endpoint == "source" {
            "source.name"
        } else {
            "target.name"
        },
    )?;
    if symbol.name.is_empty() {
        return Err(BoundaryLinksError::EmptySymbolName {
            link_index,
            endpoint,
        });
    }
    Ok(())
}

fn validate_language(
    language: &str,
    link_index: usize,
    endpoint: &'static str,
) -> Result<(), BoundaryLinksError> {
    validate_string(
        language,
        link_index,
        if endpoint == "source" {
            "source.language"
        } else {
            "target.language"
        },
    )?;
    if !is_canonical_language(language) {
        return Err(BoundaryLinksError::NonCanonicalLanguage {
            link_index,
            endpoint,
        });
    }
    Ok(())
}

const fn validate_input_size(size: usize) -> Result<(), BoundaryLinksError> {
    if size > MAX_BOUNDARY_LINKS_JSON_BYTES {
        return Err(BoundaryLinksError::InputTooLarge {
            size,
            maximum: MAX_BOUNDARY_LINKS_JSON_BYTES,
        });
    }
    Ok(())
}

const fn validate_link_count(count: usize) -> Result<(), BoundaryLinksError> {
    if count > MAX_BOUNDARY_LINKS {
        return Err(BoundaryLinksError::TooManyLinks {
            count,
            maximum: MAX_BOUNDARY_LINKS,
        });
    }
    Ok(())
}

const fn validate_string(
    value: &str,
    link_index: usize,
    field: &'static str,
) -> Result<(), BoundaryLinksError> {
    if value.len() > MAX_BOUNDARY_LINK_STRING_BYTES {
        return Err(BoundaryLinksError::StringTooLong {
            link_index,
            field,
            size: value.len(),
            maximum: MAX_BOUNDARY_LINK_STRING_BYTES,
        });
    }
    Ok(())
}

fn is_canonical_language(value: &str) -> bool {
    let mut bytes: std::slice::Iter<'_, u8> = value.as_bytes().iter();
    let Some(first): Option<&u8> = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && bytes.all(|byte: &u8| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'+' | b'-' | b'_')
        })
}
