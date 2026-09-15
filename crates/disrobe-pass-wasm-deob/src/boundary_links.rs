use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasmparser::{AbstractHeapType, HeapType, UnpackedIndex, ValType};

use crate::signature::sanitize_identifier;

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
    Memory,
    Table,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryConfidence {
    Certain,
    High,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundaryWasmAbstractHeapType {
    Func,
    Extern,
    Any,
    Eq,
    I31,
    Struct,
    Array,
    None,
    NoExtern,
    NoFunc,
    Exn,
    NoExn,
    Cont,
    NoCont,
}

impl BoundaryWasmAbstractHeapType {
    const fn from_wasm(value: AbstractHeapType) -> Self {
        match value {
            AbstractHeapType::Func => Self::Func,
            AbstractHeapType::Extern => Self::Extern,
            AbstractHeapType::Any => Self::Any,
            AbstractHeapType::Eq => Self::Eq,
            AbstractHeapType::I31 => Self::I31,
            AbstractHeapType::Struct => Self::Struct,
            AbstractHeapType::Array => Self::Array,
            AbstractHeapType::None => Self::None,
            AbstractHeapType::NoExtern => Self::NoExtern,
            AbstractHeapType::NoFunc => Self::NoFunc,
            AbstractHeapType::Exn => Self::Exn,
            AbstractHeapType::NoExn => Self::NoExn,
            AbstractHeapType::Cont => Self::Cont,
            AbstractHeapType::NoCont => Self::NoCont,
        }
    }
    const fn as_str(self, nullable: bool) -> &'static str {
        match self {
            Self::Func => "funcref",
            Self::Extern => "externref",
            Self::Any => "anyref",
            Self::Eq => "eqref",
            Self::I31 => "i31ref",
            Self::Struct => "structref",
            Self::Array => "arrayref",
            Self::None if nullable => "nullref",
            Self::None => "none",
            Self::NoExtern if nullable => "nullexternref",
            Self::NoExtern => "noextern",
            Self::NoFunc if nullable => "nullfuncref",
            Self::NoFunc => "nofunc",
            Self::Exn => "exnref",
            Self::NoExn if nullable => "nullexnref",
            Self::NoExn => "noexn",
            Self::Cont => "contref",
            Self::NoCont if nullable => "nullcontref",
            Self::NoCont => "nocont",
        }
    }

    fn parse(value: &str, nullable: bool) -> Option<Self> {
        match value {
            "funcref" => Some(Self::Func),
            "externref" => Some(Self::Extern),
            "anyref" => Some(Self::Any),
            "eqref" => Some(Self::Eq),
            "i31ref" => Some(Self::I31),
            "structref" => Some(Self::Struct),
            "arrayref" => Some(Self::Array),
            "nullref" if nullable => Some(Self::None),
            "none" if !nullable => Some(Self::None),
            "nullexternref" if nullable => Some(Self::NoExtern),
            "noextern" if !nullable => Some(Self::NoExtern),
            "nullfuncref" if nullable => Some(Self::NoFunc),
            "nofunc" if !nullable => Some(Self::NoFunc),
            "exnref" => Some(Self::Exn),
            "nullexnref" if nullable => Some(Self::NoExn),
            "noexn" if !nullable => Some(Self::NoExn),
            "contref" => Some(Self::Cont),
            "nullcontref" if nullable => Some(Self::NoCont),
            "nocont" if !nullable => Some(Self::NoCont),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundaryWasmReferenceType {
    Abstract {
        heap_type: BoundaryWasmAbstractHeapType,
        nullable: bool,
        shared: bool,
    },
    Indexed {
        type_index: u32,
        nullable: bool,
        exact: bool,
    },
}

impl BoundaryWasmReferenceType {
    pub(crate) fn from_wasm(value: wasmparser::RefType) -> Result<Self, String> {
        let nullable: bool = value.is_nullable();
        match value.heap_type() {
            HeapType::Abstract { shared, ty } => Ok(Self::Abstract {
                heap_type: BoundaryWasmAbstractHeapType::from_wasm(ty),
                nullable,
                shared,
            }),
            HeapType::Concrete(UnpackedIndex::Module(type_index)) => Ok(Self::Indexed {
                type_index,
                nullable,
                exact: false,
            }),
            HeapType::Exact(UnpackedIndex::Module(type_index)) => Ok(Self::Indexed {
                type_index,
                nullable,
                exact: true,
            }),
            HeapType::Concrete(UnpackedIndex::RecGroup(type_index)) => Err(format!(
                "WebAssembly recursion-group reference index {type_index} cannot appear in a module boundary type"
            )),
            HeapType::Exact(UnpackedIndex::RecGroup(type_index)) => Err(format!(
                "WebAssembly exact recursion-group reference index {type_index} cannot appear in a module boundary type"
            )),
            HeapType::Concrete(UnpackedIndex::Id(_)) | HeapType::Exact(UnpackedIndex::Id(_)) => {
                Err("WebAssembly canonical reference identifiers cannot appear in a module boundary type".to_owned())
            }
        }
    }

    fn as_wire(self) -> String {
        match self {
            Self::Abstract {
                heap_type,
                nullable: true,
                shared: false,
            } => heap_type.as_str(true).to_owned(),
            Self::Abstract {
                heap_type,
                nullable: true,
                shared: true,
            } => format!("(shared {})", heap_type.as_str(true)),
            Self::Abstract {
                heap_type,
                nullable: false,
                shared: false,
            } => format!("(ref {})", heap_type.as_str(false)),
            Self::Abstract {
                heap_type,
                nullable: false,
                shared: true,
            } => format!("(ref (shared {}))", heap_type.as_str(false)),
            Self::Indexed {
                type_index,
                nullable,
                exact,
            } => {
                let nullability: &str = if nullable { " null" } else { "" };
                if exact {
                    format!("(ref{nullability} (exact {type_index}))")
                } else {
                    format!("(ref{nullability} {type_index})")
                }
            }
        }
    }

    fn parse(value: &str) -> Option<Self> {
        if let Some(heap_type) = BoundaryWasmAbstractHeapType::parse(value, true) {
            return Some(Self::Abstract {
                heap_type,
                nullable: true,
                shared: false,
            });
        }
        if let Some(content) = value
            .strip_prefix("(shared ")
            .and_then(|value: &str| value.strip_suffix(')'))
        {
            if let Some(heap_type) = BoundaryWasmAbstractHeapType::parse(content, true) {
                return Some(Self::Abstract {
                    heap_type,
                    nullable: true,
                    shared: true,
                });
            }
        }
        let content: &str = value.strip_prefix("(ref ")?.strip_suffix(')')?;
        let (shared, content): (bool, &str) = content
            .strip_prefix("(shared ")
            .and_then(|value: &str| value.strip_suffix(')'))
            .map_or((false, content), |value: &str| (true, value));
        let (nullable, content): (bool, &str) = content
            .strip_prefix("null ")
            .map_or((false, content), |value: &str| (true, value));
        let (exact, content): (bool, &str) = content
            .strip_prefix("(exact ")
            .and_then(|value: &str| value.strip_suffix(')'))
            .map_or((false, content), |value: &str| (true, value));
        if !shared {
            if let Some(heap_type) = BoundaryWasmAbstractHeapType::parse(content, nullable) {
                return Some(Self::Abstract {
                    heap_type,
                    nullable,
                    shared,
                });
            }
        }
        (!shared)
            .then(|| content.parse::<u32>().ok())
            .flatten()
            .map(|type_index: u32| Self::Indexed {
                type_index,
                nullable,
                exact,
            })
    }
}

impl Serialize for BoundaryWasmReferenceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_wire())
    }
}

impl<'de> Deserialize<'de> for BoundaryWasmReferenceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        Self::parse(&value)
            .ok_or_else(|| serde::de::Error::custom("unknown WebAssembly reference type"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundaryWasmValueType {
    I32,
    I64,
    F32,
    F64,
    V128,
    Reference(BoundaryWasmReferenceType),
}

impl BoundaryWasmValueType {
    pub(crate) fn from_wasm(value: ValType) -> Result<Self, String> {
        match value {
            ValType::I32 => Ok(Self::I32),
            ValType::I64 => Ok(Self::I64),
            ValType::F32 => Ok(Self::F32),
            ValType::F64 => Ok(Self::F64),
            ValType::V128 => Ok(Self::V128),
            ValType::Ref(reference) => {
                BoundaryWasmReferenceType::from_wasm(reference).map(Self::Reference)
            }
        }
    }
    fn as_wire(self) -> String {
        match self {
            Self::I32 => "i32".to_owned(),
            Self::I64 => "i64".to_owned(),
            Self::F32 => "f32".to_owned(),
            Self::F64 => "f64".to_owned(),
            Self::V128 => "v128".to_owned(),
            Self::Reference(reference) => reference.as_wire(),
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "i32" => Some(Self::I32),
            "i64" => Some(Self::I64),
            "f32" => Some(Self::F32),
            "f64" => Some(Self::F64),
            "v128" => Some(Self::V128),
            _ => BoundaryWasmReferenceType::parse(value).map(Self::Reference),
        }
    }
}

impl Serialize for BoundaryWasmValueType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_wire())
    }
}

impl<'de> Deserialize<'de> for BoundaryWasmValueType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        Self::parse(&value)
            .ok_or_else(|| serde::de::Error::custom("unknown WebAssembly value type"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum BoundaryWasmType {
    Memory {
        minimum: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        maximum: Option<u64>,
        memory64: bool,
        shared: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        page_size_log2: Option<u32>,
    },
    Table {
        element_type: BoundaryWasmReferenceType,
        minimum: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        maximum: Option<u64>,
        table64: bool,
        shared: bool,
    },
    Global {
        value_type: BoundaryWasmValueType,
        mutable: bool,
        shared: bool,
    },
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
    WasmImport {
        module: String,
        field: String,
    },
    WasmExport {
        field: String,
    },
    ResourceImport {
        module: String,
        field: String,
        index: u32,
        resource_type: BoundaryWasmType,
    },
    ResourceExport {
        field: String,
        index: u32,
        resource_type: BoundaryWasmType,
    },
}

impl BoundaryEvidence {
    #[must_use]
    pub const fn confidence(&self) -> BoundaryConfidence {
        match self {
            Self::WasmImport { .. }
            | Self::WasmExport { .. }
            | Self::ResourceImport { .. }
            | Self::ResourceExport { .. } => BoundaryConfidence::Certain,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryLink {
    pub source: BoundarySymbol,
    pub target: BoundarySymbol,
    pub evidence: BoundaryEvidence,
}

impl BoundaryLink {
    pub fn new(
        source: BoundarySymbol,
        target: BoundarySymbol,
        evidence: BoundaryEvidence,
        confidence: BoundaryConfidence,
    ) -> Result<Self, BoundaryLinksError> {
        let link: Self = Self {
            source,
            target,
            evidence,
        };
        if confidence != link.confidence() {
            return Err(BoundaryLinksError::InconsistentEvidence { link_index: 0 });
        }
        Ok(link)
    }

    #[must_use]
    pub const fn confidence(&self) -> BoundaryConfidence {
        self.evidence.confidence()
    }
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
    links: Vec<BoundaryLinkWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryLinkWire {
    source: BoundarySymbol,
    target: BoundarySymbol,
    evidence: BoundaryEvidence,
    #[serde(default)]
    confidence: Option<BoundaryConfidence>,
}

impl BoundaryLinkWire {
    fn into_link(self) -> Result<BoundaryLink, BoundaryLinksError> {
        let confidence: BoundaryConfidence = self
            .confidence
            .unwrap_or_else(|| self.evidence.confidence());
        BoundaryLink::new(self.source, self.target, self.evidence, confidence)
    }
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
        let links: Vec<BoundaryLink> = wire
            .links
            .into_iter()
            .enumerate()
            .map(|(link_index, wire): (usize, BoundaryLinkWire)| {
                wire.into_link()
                    .map_err(|error: BoundaryLinksError| match error {
                        BoundaryLinksError::InconsistentEvidence { .. } => {
                            BoundaryLinksError::InconsistentEvidence { link_index }
                        }
                        error => error,
                    })
            })
            .collect::<Result<_, _>>()?;
        Self::new(links)
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
            BoundaryEvidence::ResourceImport {
                module,
                field,
                resource_type,
                ..
            } => {
                validate_string(module, link_index, "evidence.module")?;
                validate_string(field, link_index, "evidence.field")?;
                validate_wasm_type(resource_type, link_index)?;
            }
            BoundaryEvidence::ResourceExport {
                field,
                resource_type,
                ..
            } => {
                validate_string(field, link_index, "evidence.field")?;
                validate_wasm_type(resource_type, link_index)?;
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
            BoundaryEvidence::ResourceImport {
                module,
                field,
                index,
                resource_type,
            } => {
                link.source.language.as_str() == "javascript"
                    && link.target.language.as_str() == "webassembly"
                    && link.source.kind == wasm_type_symbol_kind(resource_type)
                    && link.target.kind == wasm_type_symbol_kind(resource_type)
                    && link.source.module.as_ref() == Some(module)
                    && link.source.name == *field
                    && link.source.index.is_none()
                    && link.target.index == Some(*index)
                    && link.target.name == sanitize_identifier(field)
            }
            BoundaryEvidence::ResourceExport {
                field,
                index,
                resource_type,
            } => {
                link.source.language.as_str() == "webassembly"
                    && link.target.language.as_str() == "javascript"
                    && link.source.kind == wasm_type_symbol_kind(resource_type)
                    && link.target.kind == wasm_type_symbol_kind(resource_type)
                    && link.source.index == Some(*index)
                    && link.source.name == sanitize_identifier(field)
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

fn validate_wasm_type(
    resource_type: &BoundaryWasmType,
    link_index: usize,
) -> Result<(), BoundaryLinksError> {
    match resource_type {
        BoundaryWasmType::Memory {
            minimum,
            maximum,
            memory64,
            shared,
            page_size_log2,
        } => {
            let page_size_log2: u32 = page_size_log2.unwrap_or(16);
            let maximum_pages: u64 = memory_page_limit(*memory64, page_size_log2);
            if maximum.is_some_and(|maximum: u64| maximum < *minimum)
                || (*shared && maximum.is_none())
                || !matches!(page_size_log2, 0 | 16)
                || *minimum > maximum_pages
                || maximum.is_some_and(|maximum: u64| maximum > maximum_pages)
            {
                return Err(BoundaryLinksError::InconsistentEvidence { link_index });
            }
            Ok(())
        }
        BoundaryWasmType::Table {
            minimum,
            maximum,
            table64,
            shared,
            element_type,
            ..
        } => {
            if maximum.is_some_and(|maximum: u64| maximum < *minimum)
                || (!*table64
                    && (*minimum > u64::from(u32::MAX)
                        || maximum.is_some_and(|maximum: u64| maximum > u64::from(u32::MAX))))
                || (*shared && reference_is_known_unshared(*element_type))
            {
                return Err(BoundaryLinksError::InconsistentEvidence { link_index });
            }
            Ok(())
        }
        BoundaryWasmType::Global { .. } => Ok(()),
    }
}

const fn memory_page_limit(memory64: bool, page_size_log2: u32) -> u64 {
    match (memory64, page_size_log2) {
        (false, 0) => 4_294_967_295,
        (false, 16) => 65_536,
        (true, 0) => u64::MAX,
        (true, 16) => 281_474_976_710_656,
        _ => 0,
    }
}

const fn reference_is_known_unshared(reference: BoundaryWasmReferenceType) -> bool {
    matches!(
        reference,
        BoundaryWasmReferenceType::Abstract { shared: false, .. }
    )
}

const fn wasm_type_symbol_kind(resource_type: &BoundaryWasmType) -> BoundarySymbolKind {
    match resource_type {
        BoundaryWasmType::Memory { .. } => BoundarySymbolKind::Memory,
        BoundaryWasmType::Table { .. } => BoundarySymbolKind::Table,
        BoundaryWasmType::Global { .. } => BoundarySymbolKind::Global,
    }
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
