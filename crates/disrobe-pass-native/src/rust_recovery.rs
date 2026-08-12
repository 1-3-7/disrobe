use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

const MAX_AUDITABLE_COMPRESSED_BYTES: usize = 4 * 1024 * 1024;
const MAX_AUDITABLE_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const MAX_AUDITABLE_PACKAGES: usize = 16_384;
const MAX_AUDITABLE_PACKAGE_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_AUDITABLE_JSON_DEPTH: usize = 32;
const MAX_AUDITABLE_JSON_CONTAINER_ENTRIES: usize = 65_536;
const MAX_AUDITABLE_JSON_WORK_ITEMS: usize = 1_048_576;
const MAX_AUDITABLE_JSON_STRING_BYTES: usize = 9 * 1024 * 1024;
const MAX_AUDITABLE_JSON_ESCAPED_STRING_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemangledSymbol {
    pub mangled: String,
    pub demangled: String,
    pub scheme: DemangleScheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DemangleScheme {
    RustLegacy,
    RustV0,
    Unknown,
}

pub fn demangle(mangled: &str) -> Result<DemangledSymbol> {
    let try_result: core::result::Result<rustc_demangle::Demangle<'_>, _> =
        rustc_demangle::try_demangle(mangled);
    let scheme: DemangleScheme = if mangled.starts_with("_R") || mangled.starts_with("R") {
        DemangleScheme::RustV0
    } else if mangled.starts_with("_Z") || mangled.starts_with("__Z") {
        DemangleScheme::RustLegacy
    } else {
        DemangleScheme::Unknown
    };
    match try_result {
        Ok(d) => Ok(DemangledSymbol {
            mangled: mangled.to_owned(),
            demangled: d.to_string(),
            scheme,
        }),
        Err(_e) => Err(Error::Demangle {
            lang: "rust",
            message: format!("not a valid Rust mangled symbol: {mangled}"),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanicSignature {
    pub address: u64,
    pub kind: PanicKind,
    pub call_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PanicKind {
    CorePanicking,
    StdPanic,
    FormatArgs,
    UnwindResume,
    Unknown,
}

#[must_use]
pub fn detect_panic_signatures(symbols: &[&str]) -> Vec<PanicSignature> {
    let mut out: Vec<PanicSignature> = Vec::new();
    for (i, s) in symbols.iter().enumerate() {
        let kind: PanicKind = if s.contains("core::panicking::panic") {
            PanicKind::CorePanicking
        } else if s.contains("std::panic") {
            PanicKind::StdPanic
        } else if s.contains("core::fmt::Arguments::new") || s.contains("core::fmt::format") {
            PanicKind::FormatArgs
        } else if s.contains("_Unwind_Resume") || s.contains("rust_eh_personality") {
            PanicKind::UnwindResume
        } else {
            continue;
        };
        out.push(PanicSignature {
            address: i as u64,
            kind,
            call_target: Some((*s).to_owned()),
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableEntry {
    pub address: u64,
    pub function: String,
    pub trait_name: Option<String>,
}

#[must_use]
pub fn recover_trait_vtables(symbols: &[&str]) -> Vec<VtableEntry> {
    let mut out: Vec<VtableEntry> = Vec::new();
    for (i, s) in symbols.iter().enumerate() {
        if !s.contains("$LT$") && !s.contains("vtable") && !s.contains(" as ") {
            continue;
        }
        let trait_name: Option<String> = extract_trait_name(s);
        out.push(VtableEntry {
            address: i as u64,
            function: (*s).to_owned(),
            trait_name,
        });
    }
    out
}

fn extract_trait_name(symbol: &str) -> Option<String> {
    let legacy_after_as: Option<&str> = symbol.split("$u20$as$u20$").nth(1);
    if let Some(after_as) = legacy_after_as {
        return after_as
            .split("$GT$")
            .next()
            .map(str::trim)
            .filter(|t: &&str| !t.is_empty())
            .map(str::to_owned);
    }
    let lt: usize = symbol.find('<')?;
    let inner: &str = &symbol[lt + 1..];
    let close: usize = matching_angle_close(inner)?;
    let impl_clause: &str = &inner[..close];
    let (_, after_as): (&str, &str) = impl_clause.rsplit_once(" as ")?;
    let trimmed: &str = after_as.split('<').next().unwrap_or(after_as).trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn matching_angle_close(s: &str) -> Option<usize> {
    let mut depth: u32 = 0;
    for (idx, ch) in s.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' if depth == 0 => return Some(idx),
            '>' => depth -= 1,
            _ => {}
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumDiscriminant {
    pub type_name: String,
    pub variants: BTreeMap<u64, String>,
}

#[must_use]
pub fn recover_enum_discriminants(symbols: &[&str]) -> Vec<EnumDiscriminant> {
    let mut by_ty: BTreeMap<String, BTreeMap<u64, String>> = BTreeMap::new();
    for (i, s) in symbols.iter().enumerate() {
        if !s.contains("::") {
            continue;
        }
        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() < 2 {
            continue;
        }
        let ty: String = parts[..parts.len() - 1].join("::");
        let variant: String = (*parts.last().unwrap_or(&"")).to_owned();
        if variant.is_empty() {
            continue;
        }
        by_ty.entry(ty).or_default().insert(i as u64, variant);
    }
    by_ty
        .into_iter()
        .map(|(type_name, variants)| EnumDiscriminant {
            type_name,
            variants,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonomorphizationGroup {
    pub generic_origin: String,
    pub instances: BTreeSet<String>,
}

#[must_use]
pub fn group_monomorphizations(symbols: &[&str]) -> Vec<MonomorphizationGroup> {
    let mut by_origin: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for s in symbols {
        let Some(origin): Option<String> = monomorphization_origin(s) else {
            continue;
        };
        by_origin.entry(origin).or_default().insert((*s).to_owned());
    }
    by_origin
        .into_iter()
        .filter(|(_origin, set)| set.len() > 1)
        .map(|(generic_origin, instances)| MonomorphizationGroup {
            generic_origin,
            instances,
        })
        .collect()
}

fn monomorphization_origin(symbol: &str) -> Option<String> {
    let cut: usize = symbol
        .find("$LT$")
        .map(|i: usize| (i, "$LT$".len()))
        .into_iter()
        .chain(symbol.find('<').map(|i: usize| (i, '<'.len_utf8())))
        .min_by_key(|(i, _len): &(usize, usize)| *i)
        .map(|(i, _len): (usize, usize)| i)?;
    let stem: &str = symbol[..cut].trim_end_matches("::");
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditableSbom {
    pub format_version: u32,
    pub crates: Vec<AuditableCrate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditableCrate {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
}

fn parse_pe_auditable_section(bytes: &[u8]) -> Result<AuditableSbom> {
    let image: PeImage = parse_pe_image(bytes)?;
    let section: &PeSection = image
        .section_by_name(b".dep-v0")
        .ok_or_else(|| Error::SignatureDb("PE image has no .dep-v0 section".to_owned()))?;
    let section_bytes: usize = if section.virtual_size == 0 {
        section.raw_size as usize
    } else {
        section.virtual_size.min(section.raw_size) as usize
    };
    if section_bytes > MAX_AUDITABLE_COMPRESSED_BYTES {
        return Err(Error::SignatureDb(format!(
            ".dep-v0 compressed payload is {section_bytes} bytes, exceeding the {MAX_AUDITABLE_COMPRESSED_BYTES}-byte limit"
        )));
    }
    let start: usize = section.raw_pointer as usize;
    let end: usize = start
        .checked_add(section_bytes)
        .ok_or_else(|| Error::SignatureDb(".dep-v0 section byte range overflowed".to_owned()))?;
    let compressed: &[u8] = bytes.get(start..end).ok_or(Error::Truncated {
        needed: end,
        had: bytes.len(),
    })?;
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(compressed);
    let allocation_limit: usize = MAX_AUDITABLE_DECOMPRESSED_BYTES
        .checked_add(1)
        .ok_or_else(|| Error::SignatureDb("auditable output limit overflowed".to_owned()))?;
    let read_limit: u64 = u64::try_from(allocation_limit)
        .map_err(|_| Error::SignatureDb("auditable output limit cannot fit u64".to_owned()))?;
    let mut decompressed: Vec<u8> = Vec::new();
    decompressed
        .try_reserve_exact(allocation_limit)
        .map_err(|_| {
            Error::SignatureDb(format!(
                ".dep-v0 output allocation of {allocation_limit} bytes failed"
            ))
        })?;
    decoder
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut decompressed)
        .map_err(|error: std::io::Error| {
            Error::SignatureDb(format!(".dep-v0 zlib decode failed: {error}"))
        })?;
    if decompressed.len() > MAX_AUDITABLE_DECOMPRESSED_BYTES {
        return Err(Error::SignatureDb(format!(
            ".dep-v0 decompressed payload exceeds the {MAX_AUDITABLE_DECOMPRESSED_BYTES}-byte limit"
        )));
    }
    parse_auditable_json(&decompressed)
}

pub fn parse_auditable_section(bytes: &[u8]) -> Result<AuditableSbom> {
    if bytes.starts_with(b"MZ") {
        return parse_pe_auditable_section(bytes);
    }
    if bytes.len() > MAX_AUDITABLE_DECOMPRESSED_BYTES {
        return Err(Error::SignatureDb(format!(
            "auditable decompressed payload is {} bytes, exceeding the {MAX_AUDITABLE_DECOMPRESSED_BYTES}-byte limit",
            bytes.len()
        )));
    }
    parse_auditable_json(bytes)
}

fn parse_auditable_json(bytes: &[u8]) -> Result<AuditableSbom> {
    if bytes.starts_with(&[0x1F, 0x8B]) {
        return Err(Error::SignatureDb(
            "auditable section gzip wrapper not handled in v0.1; pre-inflate before invocation"
                .to_owned(),
        ));
    }
    validate_auditable_json_string_allocations(bytes)?;
    let preflight: AuditablePreflight = preflight_auditable_json(bytes)?;
    decode_auditable_json(bytes, preflight.format_version, preflight.package_count)
}

fn validate_auditable_json_string_allocations(bytes: &[u8]) -> Result<()> {
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        cursor += 1;
        let mut decoded_bytes: usize = 0;
        let mut escaped: bool = false;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'"' => {
                    cursor += 1;
                    break;
                }
                b'\\' => {
                    escaped = true;
                    let Some(escape): Option<&u8> = bytes.get(cursor + 1) else {
                        cursor = bytes.len();
                        break;
                    };
                    if *escape == b'u'
                        && let Some(code_unit) = json_hex_quad(bytes, cursor + 2)
                    {
                        let pair_start: usize = cursor + 6;
                        if (0xD800..=0xDBFF).contains(&code_unit)
                            && bytes.get(pair_start..pair_start + 2) == Some(b"\\u")
                            && let Some(low) = json_hex_quad(bytes, pair_start + 2)
                            && (0xDC00..=0xDFFF).contains(&low)
                        {
                            decoded_bytes = checked_escaped_string_length(decoded_bytes, 4)?;
                            cursor += 12;
                        } else {
                            let encoded_bytes: usize =
                                char::from_u32(u32::from(code_unit)).map_or(3, char::len_utf8);
                            decoded_bytes =
                                checked_escaped_string_length(decoded_bytes, encoded_bytes)?;
                            cursor += 6;
                        }
                    } else {
                        decoded_bytes = checked_escaped_string_length(decoded_bytes, 1)?;
                        cursor += 2;
                    }
                }
                _ => {
                    decoded_bytes = checked_escaped_string_length(decoded_bytes, 1)?;
                    cursor += 1;
                }
            }
            if escaped && decoded_bytes > MAX_AUDITABLE_JSON_ESCAPED_STRING_BYTES {
                return Err(Error::SignatureDb(format!(
                    "auditable escaped JSON string is {decoded_bytes} bytes, exceeding the {MAX_AUDITABLE_JSON_ESCAPED_STRING_BYTES}-byte limit"
                )));
            }
        }
    }
    Ok(())
}

fn checked_escaped_string_length(current: usize, additional: usize) -> Result<usize> {
    current.checked_add(additional).ok_or_else(|| {
        Error::SignatureDb("auditable escaped JSON string byte count overflowed".to_owned())
    })
}

fn json_hex_quad(bytes: &[u8], start: usize) -> Option<u16> {
    let end: usize = start.checked_add(4)?;
    bytes
        .get(start..end)?
        .iter()
        .try_fold(0u16, |value: u16, byte: &u8| {
            let digit: u16 = match byte {
                b'0'..=b'9' => u16::from(*byte - b'0'),
                b'a'..=b'f' => u16::from(*byte - b'a' + 10),
                b'A'..=b'F' => u16::from(*byte - b'A' + 10),
                _ => return None,
            };
            value.checked_mul(16)?.checked_add(digit)
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
enum AuditableJsonField {
    Format,
    Packages,
    Name,
    Version,
    Source,
    #[serde(other)]
    Other,
}

impl AuditableJsonField {
    fn from_name(value: &str) -> Self {
        match value {
            "format" => Self::Format,
            "packages" => Self::Packages,
            "name" => Self::Name,
            "version" => Self::Version,
            "source" => Self::Source,
            _ => Self::Other,
        }
    }
}

struct AuditableMapSeed<V>(V);

impl<'de, V> DeserializeSeed<'de> for AuditableMapSeed<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn deserialize<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(self.0)
    }
}

struct AuditableSeqSeed<V>(V);

impl<'de, V> DeserializeSeed<'de> for AuditableSeqSeed<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn deserialize<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self.0)
    }
}

struct AuditableStrSeed<V>(V);

impl<'de, V> DeserializeSeed<'de> for AuditableStrSeed<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn deserialize<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(self.0)
    }
}

#[derive(Default)]
struct AuditableJsonBudget {
    work_items: usize,
    string_bytes: usize,
}

impl AuditableJsonBudget {
    fn check_depth<E>(depth: usize) -> core::result::Result<(), E>
    where
        E: serde::de::Error,
    {
        if depth > MAX_AUDITABLE_JSON_DEPTH {
            return Err(E::custom(format!(
                "auditable JSON nesting depth is {depth}, exceeding the {MAX_AUDITABLE_JSON_DEPTH}-level limit"
            )));
        }
        Ok(())
    }

    fn record_work<E>(&mut self) -> core::result::Result<(), E>
    where
        E: serde::de::Error,
    {
        let actual: usize = self
            .work_items
            .checked_add(1)
            .ok_or_else(|| E::custom("auditable JSON work item count overflowed"))?;
        if actual > MAX_AUDITABLE_JSON_WORK_ITEMS {
            return Err(E::custom(format!(
                "auditable JSON work is {actual} items, exceeding the {MAX_AUDITABLE_JSON_WORK_ITEMS}-item limit"
            )));
        }
        self.work_items = actual;
        Ok(())
    }

    fn record_string<E>(&mut self, bytes: usize) -> core::result::Result<(), E>
    where
        E: serde::de::Error,
    {
        let actual: usize = self
            .string_bytes
            .checked_add(bytes)
            .ok_or_else(|| E::custom("auditable JSON string byte count overflowed"))?;
        if actual > MAX_AUDITABLE_JSON_STRING_BYTES {
            return Err(E::custom(format!(
                "auditable JSON string bytes are {actual}, exceeding the {MAX_AUDITABLE_JSON_STRING_BYTES}-byte limit"
            )));
        }
        self.string_bytes = actual;
        Ok(())
    }
}

struct BoundedAuditableFieldSeed<'budget> {
    budget: &'budget mut AuditableJsonBudget,
}

impl<'de> DeserializeSeed<'de> for BoundedAuditableFieldSeed<'_> {
    type Value = AuditableJsonField;

    fn deserialize<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(BoundedAuditableFieldVisitor {
            budget: self.budget,
        })
    }
}

struct BoundedAuditableFieldVisitor<'budget> {
    budget: &'budget mut AuditableJsonBudget,
}

impl BoundedAuditableFieldVisitor<'_> {
    fn field<E>(self, value: &str) -> core::result::Result<AuditableJsonField, E>
    where
        E: serde::de::Error,
    {
        self.budget.record_string::<E>(value.len())?;
        Ok(AuditableJsonField::from_name(value))
    }
}

impl<'de> Visitor<'de> for BoundedAuditableFieldVisitor<'_> {
    type Value = AuditableJsonField;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable JSON object field")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.field(value)
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.field(value)
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.field(&value)
    }
}

struct BoundedAuditableJsonSeed<'budget> {
    budget: &'budget mut AuditableJsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedAuditableJsonSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        AuditableJsonBudget::check_depth::<D::Error>(self.depth)?;
        deserializer.deserialize_any(BoundedAuditableJsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedAuditableJsonVisitor<'budget> {
    budget: &'budget mut AuditableJsonBudget,
    depth: usize,
}

impl BoundedAuditableJsonVisitor<'_> {
    fn string<E>(self, value: &str) -> core::result::Result<(), E>
    where
        E: serde::de::Error,
    {
        self.budget.record_string::<E>(value.len())
    }
}

impl<'de> Visitor<'de> for BoundedAuditableJsonVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded auditable JSON")
    }

    fn visit_bool<E>(self, _value: bool) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.string(value)
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.string(value)
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.string(&value)
    }

    fn visit_none<E>(self) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        BoundedAuditableJsonSeed {
            budget: self.budget,
            depth: self.depth,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut count: usize = 0;
        while sequence
            .next_element_seed(BoundedAuditableJsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?
            .is_some()
        {
            count = count.checked_add(1).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom(
                    "auditable JSON array entry count overflowed",
                )
            })?;
            if count > MAX_AUDITABLE_JSON_CONTAINER_ENTRIES {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "auditable JSON array entry count is {count}, exceeding the {MAX_AUDITABLE_JSON_CONTAINER_ENTRIES}-entry limit"
                )));
            }
            self.budget.record_work::<A::Error>()?;
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut count: usize = 0;
        while map
            .next_key_seed(AuditableStrSeed(AuditableStringLengthVisitor {
                budget: &mut *self.budget,
            }))?
            .is_some()
        {
            count = count.checked_add(1).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom(
                    "auditable JSON object member count overflowed",
                )
            })?;
            if count > MAX_AUDITABLE_JSON_CONTAINER_ENTRIES {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "auditable JSON object member count is {count}, exceeding the {MAX_AUDITABLE_JSON_CONTAINER_ENTRIES}-entry limit"
                )));
            }
            self.budget.record_work::<A::Error>()?;
            map.next_value_seed(BoundedAuditableJsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

struct AuditableStringLengthVisitor<'budget> {
    budget: &'budget mut AuditableJsonBudget,
}

impl<'de> Visitor<'de> for AuditableStringLengthVisitor<'_> {
    type Value = usize;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable package string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.budget.record_string::<E>(value.len())?;
        Ok(value.len())
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.budget.record_string::<E>(value.len())?;
        Ok(value.len())
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.budget.record_string::<E>(value.len())?;
        Ok(value.len())
    }
}

struct AuditablePackageShape {
    name: usize,
    version: usize,
    source: usize,
}

struct AuditablePackageShapeVisitor<'budget> {
    budget: &'budget mut AuditableJsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for AuditablePackageShapeVisitor<'_> {
    type Value = AuditablePackageShape;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable package object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut count: usize = 0;
        let mut name_bytes: Option<usize> = None;
        let mut version_bytes: Option<usize> = None;
        let mut source_bytes: usize = 0;
        let mut source_seen: bool = false;
        while let Some(field) = map.next_key_seed(BoundedAuditableFieldSeed {
            budget: &mut *self.budget,
        })? {
            count = count.checked_add(1).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom(
                    "auditable JSON object member count overflowed",
                )
            })?;
            if count > MAX_AUDITABLE_JSON_CONTAINER_ENTRIES {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "auditable JSON object member count is {count}, exceeding the {MAX_AUDITABLE_JSON_CONTAINER_ENTRIES}-entry limit"
                )));
            }
            self.budget.record_work::<A::Error>()?;
            match field {
                AuditableJsonField::Name => {
                    let value: usize =
                        map.next_value_seed(AuditableStrSeed(AuditableStringLengthVisitor {
                            budget: &mut *self.budget,
                        }))?;
                    if name_bytes.replace(value).is_some() {
                        return Err(<A::Error as serde::de::Error>::custom(
                            "duplicate auditable package name field",
                        ));
                    }
                }
                AuditableJsonField::Version => {
                    let value: usize =
                        map.next_value_seed(AuditableStrSeed(AuditableStringLengthVisitor {
                            budget: &mut *self.budget,
                        }))?;
                    if version_bytes.replace(value).is_some() {
                        return Err(<A::Error as serde::de::Error>::custom(
                            "duplicate auditable package version field",
                        ));
                    }
                }
                AuditableJsonField::Source => {
                    let value: usize =
                        map.next_value_seed(AuditableStrSeed(AuditableStringLengthVisitor {
                            budget: &mut *self.budget,
                        }))?;
                    if source_seen {
                        return Err(<A::Error as serde::de::Error>::custom(
                            "duplicate auditable package source field",
                        ));
                    }
                    source_bytes = value;
                    source_seen = true;
                }
                _ => {
                    map.next_value_seed(BoundedAuditableJsonSeed {
                        budget: &mut *self.budget,
                        depth: self.depth + 1,
                    })?;
                }
            }
        }
        let name_bytes: usize = name_bytes
            .ok_or_else(|| <A::Error as serde::de::Error>::custom("package missing name"))?;
        let version_bytes: usize = version_bytes
            .ok_or_else(|| <A::Error as serde::de::Error>::custom("package missing version"))?;
        Ok(AuditablePackageShape {
            name: name_bytes,
            version: version_bytes,
            source: source_bytes,
        })
    }
}

#[derive(Default)]
struct AuditablePreflight {
    format_version: u32,
    package_count: usize,
    package_text_bytes: usize,
}

struct AuditablePackagesPreflightVisitor<'preflight> {
    preflight: &'preflight mut AuditablePreflight,
    budget: &'preflight mut AuditableJsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for AuditablePackagesPreflightVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable package array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        AuditableJsonBudget::check_depth::<A::Error>(self.depth + 1)?;
        while let Some(shape) =
            sequence.next_element_seed(AuditableMapSeed(AuditablePackageShapeVisitor {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            }))?
        {
            self.budget.record_work::<A::Error>()?;
            let package_count: usize =
                self.preflight.package_count.checked_add(1).ok_or_else(|| {
                    <A::Error as serde::de::Error>::custom("auditable package count overflowed")
                })?;
            if package_count > MAX_AUDITABLE_PACKAGES {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "auditable package count is {package_count}, exceeding the {MAX_AUDITABLE_PACKAGES}-package limit"
                )));
            }
            let package_bytes: usize = shape
                .name
                .checked_add(shape.version)
                .and_then(|bytes: usize| bytes.checked_add(shape.source))
                .ok_or_else(|| {
                    <A::Error as serde::de::Error>::custom("auditable package text size overflowed")
                })?;
            let package_text_bytes: usize = self
                .preflight
                .package_text_bytes
                .checked_add(package_bytes)
                .ok_or_else(|| {
                    <A::Error as serde::de::Error>::custom(
                        "auditable aggregate package text size overflowed",
                    )
                })?;
            if package_text_bytes > MAX_AUDITABLE_PACKAGE_TEXT_BYTES {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "auditable package text is {package_text_bytes} bytes, exceeding the {MAX_AUDITABLE_PACKAGE_TEXT_BYTES}-byte limit"
                )));
            }
            self.preflight.package_count = package_count;
            self.preflight.package_text_bytes = package_text_bytes;
        }
        Ok(())
    }
}

struct AuditablePreflightVisitor<'budget> {
    budget: &'budget mut AuditableJsonBudget,
}

impl<'de> Visitor<'de> for AuditablePreflightVisitor<'_> {
    type Value = AuditablePreflight;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut count: usize = 0;
        let mut preflight: AuditablePreflight = AuditablePreflight::default();
        let mut format_seen: bool = false;
        let mut packages_seen: bool = false;
        while let Some(field) = map.next_key_seed(BoundedAuditableFieldSeed {
            budget: &mut *self.budget,
        })? {
            count = count.checked_add(1).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom(
                    "auditable JSON object member count overflowed",
                )
            })?;
            if count > MAX_AUDITABLE_JSON_CONTAINER_ENTRIES {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "auditable JSON object member count is {count}, exceeding the {MAX_AUDITABLE_JSON_CONTAINER_ENTRIES}-entry limit"
                )));
            }
            self.budget.record_work::<A::Error>()?;
            match field {
                AuditableJsonField::Format => {
                    if format_seen {
                        return Err(<A::Error as serde::de::Error>::custom(
                            "duplicate auditable format field",
                        ));
                    }
                    let raw: u64 = map.next_value().map_err(|_| {
                        <A::Error as serde::de::Error>::custom(
                            "auditable format version is not an unsigned integer",
                        )
                    })?;
                    preflight.format_version = u32::try_from(raw).map_err(|_| {
                        <A::Error as serde::de::Error>::custom(
                            "auditable format version exceeds u32",
                        )
                    })?;
                    format_seen = true;
                }
                AuditableJsonField::Packages => {
                    if packages_seen {
                        return Err(<A::Error as serde::de::Error>::custom(
                            "duplicate auditable packages field",
                        ));
                    }
                    AuditableJsonBudget::check_depth::<A::Error>(2)?;
                    map.next_value_seed(AuditableSeqSeed(AuditablePackagesPreflightVisitor {
                        preflight: &mut preflight,
                        budget: &mut *self.budget,
                        depth: 2,
                    }))?;
                    packages_seen = true;
                }
                _ => {
                    map.next_value_seed(BoundedAuditableJsonSeed {
                        budget: &mut *self.budget,
                        depth: 2,
                    })?;
                }
            }
        }
        if !packages_seen {
            return Err(<A::Error as serde::de::Error>::custom(
                "missing 'packages' array",
            ));
        }
        Ok(preflight)
    }
}

fn preflight_auditable_json(bytes: &[u8]) -> Result<AuditablePreflight> {
    let mut budget: AuditableJsonBudget = AuditableJsonBudget::default();
    AuditableJsonBudget::check_depth::<serde_json::Error>(1)
        .map_err(|error: serde_json::Error| Error::SignatureDb(error.to_string()))?;
    let mut deserializer: serde_json::Deserializer<serde_json::de::SliceRead<'_>> =
        serde_json::Deserializer::from_slice(bytes);
    let preflight: AuditablePreflight = AuditableMapSeed(AuditablePreflightVisitor {
        budget: &mut budget,
    })
    .deserialize(&mut deserializer)
    .map_err(|error: serde_json::Error| Error::SignatureDb(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error: serde_json::Error| Error::SignatureDb(error.to_string()))?;
    Ok(preflight)
}

struct FallibleAuditableStringVisitor;

impl FallibleAuditableStringVisitor {
    fn clone<E>(value: &str) -> core::result::Result<String, E>
    where
        E: serde::de::Error,
    {
        let mut output: String = String::new();
        output.try_reserve_exact(value.len()).map_err(|_| {
            E::custom(format!(
                "auditable text allocation of {} bytes failed",
                value.len()
            ))
        })?;
        output.push_str(value);
        Ok(output)
    }
}

impl<'de> Visitor<'de> for FallibleAuditableStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable package string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::clone(value)
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::clone(value)
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(value)
    }
}

struct AuditableCrateVisitor;

impl<'de> Visitor<'de> for AuditableCrateVisitor {
    type Value = AuditableCrate;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable package object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;
        let mut source: Option<String> = None;
        while let Some(field) = map.next_key::<AuditableJsonField>()? {
            match field {
                AuditableJsonField::Name => {
                    let value: String =
                        map.next_value_seed(AuditableStrSeed(FallibleAuditableStringVisitor))?;
                    name = Some(value);
                }
                AuditableJsonField::Version => {
                    let value: String =
                        map.next_value_seed(AuditableStrSeed(FallibleAuditableStringVisitor))?;
                    version = Some(value);
                }
                AuditableJsonField::Source => {
                    let value: String =
                        map.next_value_seed(AuditableStrSeed(FallibleAuditableStringVisitor))?;
                    source = Some(value);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let name: String =
            name.ok_or_else(|| <A::Error as serde::de::Error>::custom("package missing name"))?;
        let version: String = version
            .ok_or_else(|| <A::Error as serde::de::Error>::custom("package missing version"))?;
        Ok(AuditableCrate {
            name,
            version,
            source,
        })
    }
}

struct AuditableCratesDecodeVisitor<'crates> {
    crates: &'crates mut Vec<AuditableCrate>,
}

impl<'de> Visitor<'de> for AuditableCratesDecodeVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable package array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(krate) =
            sequence.next_element_seed(AuditableMapSeed(AuditableCrateVisitor))?
        {
            self.crates.push(krate);
        }
        Ok(())
    }
}

struct AuditableDecodeVisitor {
    format_version: u32,
    package_count: usize,
    crates: Vec<AuditableCrate>,
}

impl<'de> Visitor<'de> for AuditableDecodeVisitor {
    type Value = AuditableSbom;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an auditable JSON object")
    }

    fn visit_map<A>(mut self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(field) = map.next_key::<AuditableJsonField>()? {
            if field == AuditableJsonField::Packages {
                map.next_value_seed(AuditableSeqSeed(AuditableCratesDecodeVisitor {
                    crates: &mut self.crates,
                }))?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        if self.crates.len() != self.package_count {
            return Err(<A::Error as serde::de::Error>::custom(format!(
                "auditable package count changed from {} to {} during decoding",
                self.package_count,
                self.crates.len()
            )));
        }
        Ok(AuditableSbom {
            format_version: self.format_version,
            crates: self.crates,
        })
    }
}

fn decode_auditable_json(
    bytes: &[u8],
    format_version: u32,
    package_count: usize,
) -> Result<AuditableSbom> {
    let mut crates: Vec<AuditableCrate> = Vec::new();
    crates.try_reserve_exact(package_count).map_err(|_| {
        Error::SignatureDb(format!(
            "auditable package allocation for {package_count} entries failed"
        ))
    })?;
    let mut deserializer: serde_json::Deserializer<serde_json::de::SliceRead<'_>> =
        serde_json::Deserializer::from_slice(bytes);
    let sbom: AuditableSbom = AuditableMapSeed(AuditableDecodeVisitor {
        format_version,
        package_count,
        crates,
    })
    .deserialize(&mut deserializer)
    .map_err(|error: serde_json::Error| Error::SignatureDb(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error: serde_json::Error| Error::SignatureDb(error.to_string()))?;
    Ok(sbom)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn demangle_v0() {
        let d: DemangledSymbol = demangle("_RNvCs9ltgdHTiPiY_3foo3bar").expect("demangle v0");
        assert_eq!(d.scheme, DemangleScheme::RustV0);
        assert!(d.demangled.contains("bar"));
    }

    #[test]
    fn demangle_legacy() {
        let d: DemangledSymbol = demangle("_ZN3foo3barE").expect("legacy");
        assert_eq!(d.scheme, DemangleScheme::RustLegacy);
        assert!(d.demangled.contains("bar"));
    }

    #[test]
    fn panic_signatures_detect_core_panicking() {
        let syms: [&str; 2] = [
            "core::panicking::panic_fmt::h0",
            "core::fmt::Arguments::new_v1::h1",
        ];
        let out: Vec<PanicSignature> = detect_panic_signatures(&syms);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, PanicKind::CorePanicking);
        assert_eq!(out[1].kind, PanicKind::FormatArgs);
    }

    #[test]
    fn vtable_recovery_finds_trait_impls() {
        let syms: [&str; 1] =
            ["_ZN54_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h0E"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].trait_name.as_deref(), Some("core..fmt..Debug"));
    }

    #[test]
    fn vtable_recovery_extracts_trait_from_v0_demangled() {
        let syms: [&str; 1] = ["<alloc::vec::Vec<T> as core::fmt::Debug>::fmt"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].trait_name.as_deref(),
            Some("core::fmt::Debug"),
            "v0-demangled trait impls must yield the trait name, not None",
        );
    }

    #[test]
    fn vtable_recovery_handles_generic_trait_in_v0_form() {
        let syms: [&str; 1] = ["<std::collections::HashMap<K, V> as core::ops::Index<Q>>::index"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].trait_name.as_deref(),
            Some("core::ops::Index"),
            "the generic trait's args must be trimmed from the recovered name",
        );
    }

    #[test]
    fn vtable_recovery_inherent_impl_has_no_trait() {
        let syms: [&str; 1] = ["<core::option::Option<T>>::unwrap"];
        let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
        assert!(
            out.is_empty() || out[0].trait_name.is_none(),
            "an inherent impl (no `as Trait`) must not fabricate a trait name",
        );
    }

    #[test]
    fn enum_disc_groups_variants_by_type() {
        let syms: [&str; 3] = ["my::Color::Red", "my::Color::Green", "my::Color::Blue"];
        let out: Vec<EnumDiscriminant> = recover_enum_discriminants(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].type_name, "my::Color");
        assert_eq!(out[0].variants.len(), 3);
    }

    #[test]
    fn mono_grouper_finds_generic_origins() {
        let syms: [&str; 3] = [
            "core::option::Option$LT$u32$GT$::unwrap",
            "core::option::Option$LT$u64$GT$::unwrap",
            "lone_function::run",
        ];
        let out: Vec<MonomorphizationGroup> = group_monomorphizations(&syms);
        assert_eq!(out.len(), 1);
        assert!(out[0].generic_origin.contains("Option"));
        assert!(out[0].instances.len() >= 2);
    }

    #[test]
    fn mono_grouper_handles_v0_demangled_generics() {
        let syms: [&str; 3] = [
            "core::option::Option<u32>::unwrap",
            "core::option::Option<u64>::unwrap",
            "lone_function::run",
        ];
        let out: Vec<MonomorphizationGroup> = group_monomorphizations(&syms);
        assert_eq!(
            out.len(),
            1,
            "v0-demangled monomorphizations must group by their generic origin",
        );
        assert_eq!(out[0].generic_origin, "core::option::Option");
        assert_eq!(out[0].instances.len(), 2);
    }

    #[test]
    fn mono_grouper_prefers_earliest_bracket_across_encodings() {
        assert_eq!(
            monomorphization_origin("a::b<T>::c").as_deref(),
            Some("a::b"),
        );
        assert_eq!(
            monomorphization_origin("a::b$LT$T$GT$::c").as_deref(),
            Some("a::b"),
        );
        assert!(monomorphization_origin("a::b::c").is_none());
    }

    #[test]
    fn auditable_sbom_parses_minimal_json() {
        let blob: &[u8] = br#"{"packages":[{"name":"serde","version":"1.0.0"},{"name":"x","version":"0.1.0","source":"crates.io"}]}"#;
        let sbom: AuditableSbom = parse_auditable_section(blob).expect("parse");
        assert_eq!(sbom.crates.len(), 2);
        assert_eq!(sbom.crates[0].name, "serde");
        assert_eq!(sbom.crates[1].source.as_deref(), Some("crates.io"));
    }
}
